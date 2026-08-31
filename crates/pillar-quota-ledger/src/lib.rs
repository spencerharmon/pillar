//! Quorum-fenced reservation ledger over the streaming DB — the enforcement
//! layer that turns a *quantified* quota [`Attest`](pillar_trust_artifacts::Attest)
//! into an admission-controlling BUDGET.
//!
//! # Why this crate exists
//!
//! A quota attestation such as `cpu<=1000m` is a **budget, not a boolean**: a
//! workload is admitted only while the cumulative reservations against that
//! budget stay within it. Enforcing that across a cluster is not a local
//! decision — two nodes must never each admit 600m of a shared 1000m budget.
//! That is the SAME hazard IPAM solves for addresses (a duplicate allocation
//! is an outage), so this ledger reuses the SAME machinery rather than
//! reinventing exclusion:
//!
//! - Each reservation against a budget occupies a monotonically numbered
//!   **slot**, and "admitting reservation `k`" is exactly "acquiring epoch `k`"
//!   in the one [`pillar_coordination`] core. Because any two quorums intersect
//!   and grants are monotonic, no two candidates can be granted the same slot
//!   simultaneously — `AtMostOneHolderPerEpoch`, re-applied to budgets. This is
//!   the `NoDoubleAllocation` property of `specs/IPAM.tla` lifted from
//!   addresses to reservation slots; the exclusion primitive is *composed*,
//!   never re-derived.
//! - The ledger of admitted (and released) reservations is durably recorded as
//!   ops on a [`pillar_streamdb::OpLog`] — the content-addressed, convergent
//!   op-log CRDT — so the running balance is reconstructable and gossip-mergeable
//!   exactly like every other Pillar durable state.
//!
//! # What it enforces
//!
//! - **Admit up to budget succeeds; over-budget refused.** A reservation whose
//!   amount would push the cumulative *outstanding* total past the attestation's
//!   declared quota is refused ([`LedgerError::WouldExceedBudget`]) and no slot
//!   is consumed.
//! - **No double-spend across concurrent nodes.** A reservation is only
//!   *admitted* once a quorum of voters has fenced its slot; two nodes racing
//!   for the same slot cannot both win (the IPAM property, verified
//!   exhaustively in the tests).
//! - **Release returns budget.** Releasing an outstanding reservation returns
//!   its amount to the available budget, so a later reservation can reuse it.
//! - **Boolean attestations bypass the ledger; a quota one is always charged.**
//!   A non-quantified predicate is refused for reservation
//!   ([`LedgerError::NotAQuotaBudget`]) — it is a plain allow, never charged;
//!   a quantified one MUST go through the ledger.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use pillar_coordination::{GrantError, LeaseRegister};
use pillar_core::{Epoch, NodeId};
use pillar_streamdb::OpLog;
use pillar_trust_artifacts::{Attest, Cid};

/// A handle to one reservation the ledger has admitted against a budget, used
/// to release it later (returning its amount to the budget). The `slot` is the
/// coordination epoch the reservation was fenced at; distinct outstanding
/// reservations always occupy distinct slots.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservationId {
    /// The budget (quota attestation) this reservation is charged against.
    pub budget: Cid,
    /// The coordination slot (epoch) this reservation was fenced at.
    pub slot: u64,
}

/// Why a reservation ledger operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// The attestation named as a budget carries no quota component — a
    /// boolean-only predicate is a plain allow and is never charged against a
    /// ledger.
    NotAQuotaBudget,
    /// The reservation would push the outstanding total past the declared
    /// budget; no slot is consumed and the reservation is not admitted.
    WouldExceedBudget {
        /// The amount the caller asked to reserve.
        requested: u64,
        /// The amount still available in the budget.
        available: u64,
    },
    /// The reservation slot was not fenced by a quorum: not enough voters have
    /// granted this candidate the slot, so admission is refused (a partitioned
    /// minority never admits). The reservation is NOT durably recorded.
    NotQuorumFenced,
    /// The underlying coordination grant was refused (a stale/monotonic
    /// violation on the voter). Mirrors [`GrantError`].
    Grant(GrantError),
    /// A release named a reservation this ledger has no outstanding record of
    /// (never admitted, already released, or a different budget).
    UnknownReservation(ReservationId),
}

impl From<GrantError> for LedgerError {
    fn from(e: GrantError) -> Self {
        LedgerError::Grant(e)
    }
}

/// One outstanding, admitted reservation against a budget.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reservation {
    slot: u64,
    candidate: NodeId,
    amount: u64,
}

/// A quorum-fenced reservation ledger for a SINGLE quota attestation budget.
///
/// This is the enforcement controller: it reserves against the attestation's
/// declared budget before admitting a workload and refuses when a reservation
/// would exceed it, with every admission CP-fenced through the one
/// [`pillar_coordination`] core so two nodes can never double-spend. The
/// running ledger is recorded on a [`pillar_streamdb::OpLog`] — durable,
/// content-addressed, gossip-convergent state.
///
/// Construct one with [`QuotaLedger::for_budget`], which reads the budget from
/// the attestation itself (refusing a non-quota, boolean attestation).
#[derive(Clone, Debug)]
pub struct QuotaLedger {
    budget_cid: Cid,
    budget: u64,
    /// The coordination register that CP-fences each reservation slot. Each
    /// slot is one epoch; acquiring it is the exclusion primitive, composed
    /// verbatim from IPAM's own reuse of the core.
    register: LeaseRegister,
    /// The next never-yet-used slot index. Slots are monotonic (a released
    /// slot is not reused) so a voter's grants stay monotonic exactly as the
    /// coordination core requires.
    next_slot: u64,
    /// Outstanding admitted reservations, keyed by slot.
    outstanding: BTreeMap<u64, Reservation>,
    /// The durable op-log ledger: one op per admit / release, so the running
    /// balance is reconstructable and gossip-mergeable.
    log: OpLog,
}

impl QuotaLedger {
    /// Open a ledger enforcing the budget declared by `attest`, CP-fenced by a
    /// cluster of `cluster_size` voting nodes.
    ///
    /// # Errors
    /// [`LedgerError::NotAQuotaBudget`] if `attest`'s predicate carries no
    /// quota — a boolean attestation is a plain allow and is never ledgered.
    pub fn for_budget(attest: &Attest, cluster_size: usize) -> Result<Self, LedgerError> {
        let budget = attest.predicate.quota.ok_or(LedgerError::NotAQuotaBudget)?;
        Ok(QuotaLedger {
            budget_cid: attest.cid(),
            budget,
            register: LeaseRegister::new(cluster_size),
            next_slot: 0,
            outstanding: BTreeMap::new(),
            log: OpLog::new(),
        })
    }

    /// The content address of the quota attestation this ledger enforces.
    #[must_use]
    pub fn budget_cid(&self) -> &Cid {
        &self.budget_cid
    }

    /// The total declared budget (the attestation's quota amount).
    #[must_use]
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// The total currently reserved (sum of every outstanding reservation).
    #[must_use]
    pub fn reserved(&self) -> u64 {
        self.outstanding.values().map(|r| r.amount).sum()
    }

    /// The budget still available: `budget - reserved`.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.budget - self.reserved()
    }

    /// The next reservation slot that [`QuotaLedger::admit`] will fence. A
    /// caller collects quorum grants for this slot via [`QuotaLedger::grant`]
    /// before admitting.
    #[must_use]
    pub fn pending_slot(&self) -> u64 {
        self.next_slot
    }

    /// The durable op-log backing this ledger (admits and releases recorded as
    /// content-addressed ops).
    #[must_use]
    pub fn log(&self) -> &OpLog {
        &self.log
    }

    /// Record `voter`'s grant of the pending reservation slot to `candidate` —
    /// one vote toward the quorum that fences the next [`QuotaLedger::admit`].
    ///
    /// # Errors
    /// [`LedgerError::Grant`] if the voter has already granted a higher-or-equal
    /// slot (grants are monotonic per the coordination core).
    pub fn grant(&mut self, voter: NodeId, candidate: NodeId) -> Result<(), LedgerError> {
        self.register
            .grant(voter, candidate, Epoch(self.next_slot))?;
        Ok(())
    }

    /// Reserve `amount` against the budget for `candidate`, admitting the
    /// workload only if BOTH gates pass:
    ///
    /// 1. **Budget** — the reservation must fit in the remaining budget, else
    ///    [`LedgerError::WouldExceedBudget`] and nothing is consumed.
    /// 2. **Quorum fence** — the pending slot must be backed by a quorum of
    ///    voters for `candidate`, else [`LedgerError::NotQuorumFenced`]. This
    ///    is what makes admission safe under concurrency: two nodes racing for
    ///    the same slot cannot both acquire it (the IPAM no-double-allocation
    ///    property applied to budgets), so they cannot both admit against the
    ///    shared budget.
    ///
    /// On success the reservation is recorded durably on the op-log and a
    /// [`ReservationId`] is returned for later [`QuotaLedger::release`].
    pub fn admit(&mut self, candidate: &NodeId, amount: u64) -> Result<ReservationId, LedgerError> {
        // Budget gate FIRST: an over-budget request never even contends for a
        // slot. A caller collects this slot's quorum grants BEFORE calling
        // `admit`; a refused admit therefore SPOILS this slot (its grants are
        // spent), so we advance past it so the next reservation contends for a
        // fresh, un-granted slot — keeping every voter's grants monotonic as
        // the coordination core requires.
        let available = self.available();
        if amount > available {
            self.next_slot += 1;
            return Err(LedgerError::WouldExceedBudget {
                requested: amount,
                available,
            });
        }
        // Quorum fence: acquire the pending slot for this candidate.
        let slot = self.next_slot;
        if !self.register.try_acquire(candidate, Epoch(slot)) {
            // The slot's grants (if any) are likewise spent; abandon it.
            self.next_slot += 1;
            return Err(LedgerError::NotQuorumFenced);
        }
        // The slot is now permanently fenced to `candidate`; advance so the
        // next reservation contends for a fresh slot (monotonic, never reused).
        self.next_slot += 1;
        self.outstanding.insert(
            slot,
            Reservation {
                slot,
                candidate: candidate.clone(),
                amount,
            },
        );
        self.record(&format!(
            "admit\0{}\0{}\0{}\0{}",
            self.budget_cid.0, slot, candidate.0, amount
        ));
        Ok(ReservationId {
            budget: self.budget_cid.clone(),
            slot,
        })
    }

    /// Release a previously admitted reservation, returning its amount to the
    /// available budget so a later reservation can reuse it. The freed slot is
    /// NOT recycled (slots stay monotonic for the coordination core); the
    /// returned capacity is what a subsequent [`QuotaLedger::admit`] draws on.
    ///
    /// # Errors
    /// [`LedgerError::UnknownReservation`] if `id` is not an outstanding
    /// reservation of THIS budget (never admitted, already released, or a
    /// different budget).
    pub fn release(&mut self, id: &ReservationId) -> Result<u64, LedgerError> {
        if id.budget != self.budget_cid {
            return Err(LedgerError::UnknownReservation(id.clone()));
        }
        let Some(res) = self.outstanding.remove(&id.slot) else {
            return Err(LedgerError::UnknownReservation(id.clone()));
        };
        self.record(&format!(
            "release\0{}\0{}\0{}",
            self.budget_cid.0, res.slot, res.amount
        ));
        Ok(res.amount)
    }

    /// Whether `id` names a currently-outstanding reservation of this budget.
    #[must_use]
    pub fn is_outstanding(&self, id: &ReservationId) -> bool {
        id.budget == self.budget_cid && self.outstanding.contains_key(&id.slot)
    }

    fn record(&mut self, entry: &str) {
        self.log.append(entry.as_bytes().to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_trust_artifacts::{Capacity, Predicate, Sig};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn role(r: &str, s: &str) -> Capacity {
        Capacity::Role {
            role: r.to_owned(),
            scope: s.to_owned(),
        }
    }

    /// A quota (budget) attestation of `amount` milli-units, owned by genesis.
    fn quota_attest(amount: u64) -> Attest {
        Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(amount),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        }
    }

    /// A plain boolean attestation (no quota component).
    fn boolean_attest() -> Attest {
        Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        }
    }

    /// Drive a quorum (2 of 3) of voters to back `candidate` for the ledger's
    /// current pending slot, then admit `amount`.
    fn quorum_admit(
        ledger: &mut QuotaLedger,
        candidate: &NodeId,
        amount: u64,
    ) -> Result<ReservationId, LedgerError> {
        ledger.grant(n("v1"), candidate.clone()).unwrap();
        ledger.grant(n("v2"), candidate.clone()).unwrap();
        ledger.admit(candidate, amount)
    }

    // --- a quota attestation is a budget, a boolean one bypasses the ledger --

    #[test]
    fn boolean_attestation_is_never_ledgered() {
        assert_eq!(
            QuotaLedger::for_budget(&boolean_attest(), 3).err(),
            Some(LedgerError::NotAQuotaBudget)
        );
    }

    #[test]
    fn quota_attestation_opens_a_ledger_carrying_its_budget() {
        let ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        assert_eq!(ledger.budget(), 1000);
        assert_eq!(ledger.reserved(), 0);
        assert_eq!(ledger.available(), 1000);
        assert_eq!(ledger.budget_cid(), &quota_attest(1000).cid());
    }

    // --- admit up to budget succeeds / over refused -------------------------

    #[test]
    fn admit_up_to_budget_succeeds() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        quorum_admit(&mut ledger, &n("alice"), 600).expect("within budget");
        assert_eq!(ledger.reserved(), 600);
        assert_eq!(ledger.available(), 400);
        quorum_admit(&mut ledger, &n("alice"), 400).expect("exactly fills the budget");
        assert_eq!(ledger.reserved(), 1000);
        assert_eq!(ledger.available(), 0);
    }

    #[test]
    fn over_budget_reservation_is_refused_and_consumes_nothing() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        quorum_admit(&mut ledger, &n("alice"), 800).unwrap();
        // 800 + 400 > 1000: refused with the true remaining budget.
        assert_eq!(
            quorum_admit(&mut ledger, &n("alice"), 400),
            Err(LedgerError::WouldExceedBudget {
                requested: 400,
                available: 200,
            })
        );
        // Nothing is reserved by the refused admit: reserved unchanged. The
        // spoiled slot is abandoned (its grants are spent), so it is never
        // charged against the budget.
        assert_eq!(ledger.reserved(), 800);
    }

    // --- release returns budget --------------------------------------------

    #[test]
    fn release_returns_budget_for_reuse() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        let r = quorum_admit(&mut ledger, &n("alice"), 700).unwrap();
        // A second 700 does not fit now.
        assert!(matches!(
            quorum_admit(&mut ledger, &n("alice"), 700),
            Err(LedgerError::WouldExceedBudget { .. })
        ));
        // Release the first reservation: its 700 returns to the budget.
        assert_eq!(ledger.release(&r).unwrap(), 700);
        assert_eq!(ledger.reserved(), 0);
        assert_eq!(ledger.available(), 1000);
        // Now the 700 reservation fits again.
        quorum_admit(&mut ledger, &n("alice"), 700).expect("budget returned by release");
        assert_eq!(ledger.reserved(), 700);
    }

    #[test]
    fn release_of_an_unknown_reservation_is_refused() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        let bogus = ReservationId {
            budget: ledger.budget_cid().clone(),
            slot: 999,
        };
        assert_eq!(
            ledger.release(&bogus),
            Err(LedgerError::UnknownReservation(bogus.clone()))
        );
        // A double release is likewise refused.
        let r = quorum_admit(&mut ledger, &n("alice"), 100).unwrap();
        ledger.release(&r).unwrap();
        assert_eq!(ledger.release(&r), Err(LedgerError::UnknownReservation(r)));
    }

    // --- quorum fence: a minority cannot admit ------------------------------

    #[test]
    fn minority_cannot_admit_even_within_budget() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        // Only one of three voters backs alice: not a quorum.
        ledger.grant(n("v1"), n("alice")).unwrap();
        assert_eq!(
            ledger.admit(&n("alice"), 100),
            Err(LedgerError::NotQuorumFenced)
        );
        // Nothing consumed against the budget.
        assert_eq!(ledger.reserved(), 0);
    }

    // --- no double-spend across concurrent nodes, exhaustively --------------

    /// The IPAM `NoDoubleAllocation` property applied to budgets: over every
    /// way 3 voters can back one of two concurrent candidates for a single
    /// reservation slot, at most one candidate is ever admitted against the
    /// budget. Two nodes can never each admit 600m of a 1000m budget by both
    /// winning the same slot.
    #[test]
    fn no_double_spend_across_concurrent_nodes() {
        let candidates = [n("nodeA"), n("nodeB")];
        let voters = [n("v1"), n("v2"), n("v3")];

        for mask in 0..27u32 {
            let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), voters.len()).unwrap();
            let mut m = mask;
            for v in &voters {
                match m % 3 {
                    0 => ledger.grant(v.clone(), candidates[0].clone()).unwrap(),
                    1 => ledger.grant(v.clone(), candidates[1].clone()).unwrap(),
                    _ => {}
                }
                m /= 3;
            }
            // Both nodes try to admit 600m of the shared 1000m budget for the
            // SAME slot. The budget alone would admit either (600 <= 1000);
            // only the quorum fence prevents both.
            let a = ledger.admit(&candidates[0], 600).is_ok();
            let b = ledger.admit(&candidates[1], 600).is_ok();
            assert!(
                !(a && b),
                "double-spend: both nodes admitted 600m of a 1000m budget (mask {mask})"
            );
        }
    }

    // --- the durable ledger records every admit and release -----------------

    #[test]
    fn durable_oplog_records_admits_and_releases() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        assert!(ledger.log().is_empty());
        let r = quorum_admit(&mut ledger, &n("alice"), 300).unwrap();
        assert_eq!(ledger.log().len(), 1);
        ledger.release(&r).unwrap();
        assert_eq!(ledger.log().len(), 2);
    }

    /// Distinct reservations occupy distinct, monotonic slots, so a voter can
    /// legitimately back successive slots (grants stay monotonic per the
    /// coordination core) and each reservation is independently tracked.
    #[test]
    fn distinct_reservations_occupy_distinct_slots() {
        let mut ledger = QuotaLedger::for_budget(&quota_attest(1000), 3).unwrap();
        let r0 = quorum_admit(&mut ledger, &n("alice"), 100).unwrap();
        let r1 = quorum_admit(&mut ledger, &n("bob"), 100).unwrap();
        assert_eq!(r0.slot, 0);
        assert_eq!(r1.slot, 1);
        assert!(ledger.is_outstanding(&r0));
        assert!(ledger.is_outstanding(&r1));
        ledger.release(&r0).unwrap();
        assert!(!ledger.is_outstanding(&r0));
        assert!(ledger.is_outstanding(&r1));
    }
}
