//! quota-sql-aggregation-migration: quota accounting over a
//! reservation-event Document collection, with live usage computed by a
//! `SUM`/`GROUP BY` SQL view (`pillar-sqlviews`), gated by a CP fence
//! (`pillar_streamdb::cofold::StrictCofold`) so the hard quota ceiling stays
//! an exactly-once invariant rather than an eventually-consistent AP
//! counter.
//!
//! Per ROI Priority 1 data-layer doctrine: `pillar-quota-ledger`'s
//! [`pillar_quota_ledger::QuotaLedger::reserved`]/`available` compute usage
//! by scanning an in-memory `BTreeMap` of outstanding reservations on every
//! call, and durability rides a raw-byte `pillar_streamdb::OpLog` op rather
//! than a structured Document. This module migrates that accounting onto:
//!
//! 1. A `reservation_events` Document collection — every admit/release
//!    writes one event Document (`budget`, `candidate`, `amount` fields),
//!    keyed by a monotonically increasing per-budget slot.
//! 2. A `pillar-sqlviews` `SUM(amount) WHERE budget = ?` view over that
//!    collection computing live usage as a genuine SQL-shaped query, not an
//!    in-memory scan (`usage()` below; `pillar sql`-queryable via the same
//!    `create_view`/`aggregate_sum` catalog primitives every other view
//!    uses).
//! 3. A CP fence (`StrictCofold<AmountQuotaCeiling>`) gating every event
//!    write: the hard per-budget ceiling is enforced by the co-partitioned,
//!    epoch-fenced reducer (exactly-once/CP), never by an eventually-
//!    consistent counter that could double-admit across a partition.
//!
//! No change to the admission decision surface: `pillar_manifest::admission`
//! keeps calling `admit`/`release`/`usage`-shaped operations; only the
//! internal accounting substrate changes.

use std::collections::BTreeMap;

use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};
use pillar_keyedstore::{Hlc, KeyedStore, Value};
use pillar_sqlviews::{aggregate_sum, create_view, Filter, ViewDef};
use pillar_streamdb::cofold::{CoFoldError, CoFoldInvariant, StrictCofold};

/// The Document collection every reservation admit/release event is written
/// into — the durable substitute for `pillar-quota-ledger`'s raw `OpLog`
/// string ops.
pub const RESERVATION_EVENTS_COLLECTION: &str = "reservation_events";

/// The catalog name of the live-usage SQL view this module ships
/// (`pillar sql`-queryable, per the task's requirement).
pub const QUOTA_USAGE_VIEW: &str = "quota_usage_by_budget";

/// A per-budget hard ceiling over the RUNNING SUM of admitted amounts
/// (never merely a count): a positive delta (an admit) is refused outright
/// once it would push the key's running sum strictly above `ceiling`. A
/// non-positive delta (a release) always advances the state — a release can
/// never itself violate a ceiling.
#[derive(Clone, Debug)]
pub struct AmountQuotaCeiling {
    ceiling: u64,
    sums: BTreeMap<Vec<u8>, u64>,
}

impl AmountQuotaCeiling {
    /// A fresh reducer enforcing `ceiling` as the hard per-budget cap on the
    /// running sum of admitted amounts.
    #[must_use]
    pub fn new(ceiling: u64) -> Self {
        AmountQuotaCeiling {
            ceiling,
            sums: BTreeMap::new(),
        }
    }

    /// The current running sum admitted for `key` (0 if never admitted).
    #[must_use]
    pub fn sum(&self, key: &[u8]) -> u64 {
        *self.sums.get(key).unwrap_or(&0)
    }
}

/// Encode a signed delta as the payload `try_admit` frames: a release is
/// carried as a negation flag byte + the magnitude, so the invariant can
/// tell an increment from a decrement without a second channel.
fn encode_delta(amount: u64, is_release: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(if is_release { 1 } else { 0 });
    buf.extend_from_slice(&amount.to_be_bytes());
    buf
}

fn decode_delta(payload: &[u8]) -> Option<(u64, bool)> {
    if payload.len() != 9 {
        return None;
    }
    let is_release = payload[0] == 1;
    let mut amt = [0u8; 8];
    amt.copy_from_slice(&payload[1..9]);
    Some((u64::from_be_bytes(amt), is_release))
}

impl CoFoldInvariant for AmountQuotaCeiling {
    fn admit(&mut self, key: &[u8], payload: &[u8]) -> Result<(), CoFoldError> {
        let (amount, is_release) =
            decode_delta(payload).ok_or_else(|| CoFoldError::QuotaExceeded {
                key: key.to_vec(),
                ceiling: self.ceiling,
                attempted: self.sum(key),
            })?;
        let current = self.sum(key);
        if is_release {
            self.sums
                .insert(key.to_vec(), current.saturating_sub(amount));
            return Ok(());
        }
        let next = current + amount;
        if next > self.ceiling {
            return Err(CoFoldError::QuotaExceeded {
                key: key.to_vec(),
                ceiling: self.ceiling,
                attempted: next,
            });
        }
        self.sums.insert(key.to_vec(), next);
        Ok(())
    }
}

/// Errors this module's ledger surface can produce.
#[derive(Debug, PartialEq, Eq)]
pub enum SqlQuotaError {
    /// The CP fence refused the admission (not fenced, or over the hard
    /// ceiling — see [`CoFoldError`]).
    Fence(CoFoldError),
}

/// The SQL-aggregation-backed quota ledger: a `reservation_events`
/// collection folded through a `SUM(amount) WHERE budget = ?` view for live
/// usage, with every write gated by a `StrictCofold<AmountQuotaCeiling>` CP
/// fence keyed by `budget`.
pub struct SqlQuotaLedger {
    store: KeyedStore,
    cofold: StrictCofold<AmountQuotaCeiling>,
    next_slot: BTreeMap<Vec<u8>, u64>,
    logical_clock: u64,
}

impl SqlQuotaLedger {
    /// A fresh ledger enforcing `ceiling` as the hard per-budget quota
    /// ceiling, with the `quota_usage_by_budget` view registered in the
    /// catalog up front (so it is `pillar sql`-queryable immediately).
    #[must_use]
    pub fn new(ceiling: u64) -> Self {
        let mut store = KeyedStore::new();
        create_view(
            &mut store,
            QUOTA_USAGE_VIEW,
            ViewDef::over(RESERVATION_EVENTS_COLLECTION),
            Hlc::new(0, 0, "quota-sql-aggregation-migration"),
        );
        SqlQuotaLedger {
            store,
            cofold: StrictCofold::new(AmountQuotaCeiling::new(ceiling)),
            next_slot: BTreeMap::new(),
            logical_clock: 0,
        }
    }

    /// Acquire the CP fencing epoch for `budget`'s partition through
    /// `lease`, exactly like [`StrictCofold::acquire`]. Must succeed before
    /// [`Self::admit`]/[`Self::release`] will admit any write for `budget`.
    pub fn acquire(
        &mut self,
        budget: &[u8],
        lease: &mut LeaseRegister,
        candidate: &NodeId,
        epoch: Epoch,
    ) -> bool {
        self.cofold.acquire(budget, lease, candidate, epoch)
    }

    fn next_id(&mut self, budget: &[u8]) -> String {
        let slot = self.next_slot.entry(budget.to_vec()).or_insert(0);
        let id = format!("{}-{slot}", String::from_utf8_lossy(budget));
        *slot += 1;
        id
    }

    fn write_event(&mut self, budget: &[u8], candidate: &NodeId, amount: u64, is_release: bool) {
        let id = self.next_id(budget);
        self.logical_clock += 1;
        let hlc = Hlc::new(self.logical_clock, 0, candidate.0.clone());
        let signed = if is_release {
            -(amount as i64)
        } else {
            amount as i64
        };
        self.store.doc_put_field(
            RESERVATION_EVENTS_COLLECTION,
            &id,
            "budget",
            Value::Scalar(budget.to_vec()),
            hlc.clone(),
        );
        self.store.doc_put_field(
            RESERVATION_EVENTS_COLLECTION,
            &id,
            "candidate",
            Value::Scalar(candidate.0.clone().into_bytes()),
            hlc.clone(),
        );
        self.store.doc_put_field(
            RESERVATION_EVENTS_COLLECTION,
            &id,
            "amount",
            Value::Scalar(signed.to_string().into_bytes()),
            hlc,
        );
    }

    /// Admit a reservation of `amount` against `budget` on behalf of
    /// `candidate`, under the previously-[`Self::acquire`]d fencing `epoch`.
    /// Refuses (never merely warns) if the running sum for `budget` would
    /// exceed the hard ceiling, or if the caller does not hold the fence.
    /// On success, appends a `reservation_events` Document — the durable,
    /// SQL-queryable substitute for `pillar-quota-ledger`'s raw op-log entry.
    pub fn admit(
        &mut self,
        budget: &[u8],
        epoch: Epoch,
        candidate: &NodeId,
        amount: u64,
    ) -> Result<(), SqlQuotaError> {
        self.cofold
            .try_admit(budget, epoch, encode_delta(amount, false))
            .map_err(SqlQuotaError::Fence)?;
        self.write_event(budget, candidate, amount, false);
        Ok(())
    }

    /// Release a previously admitted `amount` against `budget`. A release
    /// can never itself violate the ceiling (it only ever decreases the
    /// running sum), but it still rides the SAME CP fence as `admit` so the
    /// co-partitioned total order — and therefore the view's derived
    /// usage — stays consistent with the fenced writer.
    pub fn release(
        &mut self,
        budget: &[u8],
        epoch: Epoch,
        candidate: &NodeId,
        amount: u64,
    ) -> Result<(), SqlQuotaError> {
        self.cofold
            .try_admit(budget, epoch, encode_delta(amount, true))
            .map_err(SqlQuotaError::Fence)?;
        self.write_event(budget, candidate, amount, true);
        Ok(())
    }

    /// Live usage for `budget`: `SELECT SUM(amount) FROM reservation_events
    /// WHERE budget = ?` — a real SQL aggregation query over the Document
    /// collection (`pillar_sqlviews::aggregate_sum`), never an in-memory
    /// `BTreeMap` scan. Admits contribute `+amount`, releases `-amount`, so
    /// the sum is always the CURRENT outstanding usage.
    #[must_use]
    pub fn usage(&self, budget: &[u8]) -> i64 {
        aggregate_sum(
            &self.store,
            RESERVATION_EVENTS_COLLECTION,
            "amount",
            Some(&Filter {
                field: "budget".to_string(),
                value: budget.to_vec(),
            }),
        )
    }

    /// Usage for every budget that has ever had an event, grouped —
    /// `SELECT budget, SUM(amount) FROM reservation_events GROUP BY budget`.
    #[must_use]
    pub fn usage_by_budget(&self) -> Vec<(Vec<u8>, i64)> {
        pillar_sqlviews::aggregate_group_by_sum(
            &self.store,
            RESERVATION_EVENTS_COLLECTION,
            "budget",
            "amount",
        )
    }

    /// The catalog-registered view's rows, materialized: proves the
    /// `pillar sql`-queryable view (`QUOTA_USAGE_VIEW`) is a real, live fold
    /// over the reservation-event collection, not a fixture.
    #[must_use]
    pub fn view_rows(&self) -> Vec<pillar_sqlviews::Row> {
        pillar_sqlviews::materialize_view(&self.store, QUOTA_USAGE_VIEW).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fenced_ledger(
        ceiling: u64,
        budget: &[u8],
        candidate: &NodeId,
    ) -> (SqlQuotaLedger, LeaseRegister, Epoch) {
        let mut ledger = SqlQuotaLedger::new(ceiling);
        let mut lease = LeaseRegister::new(1);
        let epoch = Epoch(1);
        lease
            .grant(NodeId::from("v1"), candidate.clone(), epoch)
            .unwrap();
        assert!(ledger.acquire(budget, &mut lease, candidate, epoch));
        (ledger, lease, epoch)
    }

    /// Core migration proof: usage is computed by a real SQL `SUM` view
    /// over a reservation-event Document collection (not an in-memory
    /// scan), and it stays correct across an admit + a partial release.
    #[test]
    fn quota_sql_aggregation_migration() {
        let candidate = NodeId::from("node-a");
        let budget = b"budget-1".to_vec();
        let (mut ledger, _lease, epoch) = fenced_ledger(100, &budget, &candidate);

        assert_eq!(ledger.usage(&budget), 0);

        ledger.admit(&budget, epoch, &candidate, 30).unwrap();
        assert_eq!(ledger.usage(&budget), 30);

        ledger.admit(&budget, epoch, &candidate, 20).unwrap();
        assert_eq!(ledger.usage(&budget), 50);

        ledger.release(&budget, epoch, &candidate, 10).unwrap();
        assert_eq!(ledger.usage(&budget), 40);

        // The reservation-event Document collection is real and queryable
        // by both a direct `aggregate_sum` and the registered catalog view.
        let rows = ledger.view_rows();
        assert_eq!(rows.len(), 3, "one Document per admit/release event");
        assert_eq!(ledger.usage_by_budget(), vec![(budget.clone(), 40)]);
    }

    /// The hard ceiling is a CP invariant enforced by the fence itself
    /// (exactly-once), never an eventually-consistent counter that could be
    /// raced past: an admit that would exceed the ceiling is refused
    /// outright and the SQL view's usage never reflects the refused amount.
    #[test]
    fn hard_ceiling_is_cp_fenced_not_ap() {
        let candidate = NodeId::from("node-a");
        let budget = b"budget-2".to_vec();
        let (mut ledger, _lease, epoch) = fenced_ledger(50, &budget, &candidate);

        ledger.admit(&budget, epoch, &candidate, 40).unwrap();
        let refused = ledger.admit(&budget, epoch, &candidate, 20);
        assert_eq!(
            refused,
            Err(SqlQuotaError::Fence(CoFoldError::QuotaExceeded {
                key: budget.clone(),
                ceiling: 50,
                attempted: 60,
            }))
        );
        // The refused amount never entered the durable event collection, so
        // the SQL view's usage is still exactly the admitted 40 — no
        // over-budget state ever became observable.
        assert_eq!(ledger.usage(&budget), 40);
    }

    /// A write from an unfenced candidate (never acquired the epoch for this
    /// budget) is refused before it ever reaches the invariant or the event
    /// collection — proving the fence, not the invariant alone, gates every
    /// write.
    #[test]
    fn unfenced_writer_is_refused() {
        let candidate = NodeId::from("node-a");
        let budget = b"budget-3".to_vec();
        let mut ledger = SqlQuotaLedger::new(100);

        let refused = ledger.admit(&budget, Epoch(1), &candidate, 10);
        assert!(matches!(
            refused,
            Err(SqlQuotaError::Fence(CoFoldError::NotFenced { .. }))
        ));
        assert_eq!(ledger.usage(&budget), 0);
    }

    /// Two independent budgets are entirely independent partitions: a
    /// ceiling refusal on one never affects the other's usage or fencing —
    /// the CP fence is scoped per key, never a global lock.
    #[test]
    fn budgets_are_independent_partitions() {
        let candidate = NodeId::from("node-a");
        let budget_a = b"budget-a".to_vec();
        let budget_b = b"budget-b".to_vec();
        let mut ledger = SqlQuotaLedger::new(10);
        let mut lease = LeaseRegister::new(1);
        let epoch = Epoch(1);
        lease
            .grant(NodeId::from("v1"), candidate.clone(), epoch)
            .unwrap();
        assert!(ledger.acquire(&budget_a, &mut lease, &candidate, epoch));
        assert!(ledger.acquire(&budget_b, &mut lease, &candidate, epoch));

        ledger.admit(&budget_a, epoch, &candidate, 10).unwrap();
        assert!(ledger.admit(&budget_a, epoch, &candidate, 1).is_err());
        // budget-b is untouched by budget-a's saturation.
        ledger.admit(&budget_b, epoch, &candidate, 5).unwrap();
        assert_eq!(ledger.usage(&budget_b), 5);

        let mut grouped = ledger.usage_by_budget();
        grouped.sort();
        let mut expected = vec![(budget_a, 10), (budget_b, 5)];
        expected.sort();
        assert_eq!(grouped, expected);
    }
}
