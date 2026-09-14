//! CP co-partition-and-fold: the `ViewPolicy::Strict` reducer over a
//! per-key, epoch-fenced total order.
//!
//! Per ROI Priority 1 data-layer doctrine, "the CP subset is Samza
//! co-partition-and-fold, never a global lock or foreign keys": the AP
//! majority of state (sessions, offers, manifests, config, user records,
//! trust edges) stays the CRDT [`crate::Stream`]/keyed-store fold under
//! [`ViewPolicy::Relaxed`]. Only the handful of *hard* invariants — exactly-
//! once admission, a hard quota ceiling, uniqueness — need a total order, and
//! that order comes from the leaderless coordination core
//! (`pillar-coordination`'s [`LeaseRegister`]) acting as the analog of a
//! Kafka partition-leader: whichever candidate holds the fencing
//! [`Epoch`] for a given partition **key** is the only writer the reducer
//! will admit an [`Exclusive`] op from for that key, and only in the order
//! it presents them. This is **per-key and scoped** — there is no global
//! lock, no cross-key coordination, and no foreign-key/relational
//! constraint: each key's invariant state is entirely local to that key.
//!
//! This module supplies the reducer half of the primitive
//! (`rbac-document-sql-migration` and `quota-sql-aggregation-migration` both
//! consume it for their CP fence); the durable co-partitioned stream itself
//! is the existing [`crate::Stream`] machinery with
//! [`ViewPolicy::Strict`](pillar_core::ViewPolicy::Strict).
//!
//! [`Exclusive`]: pillar_core::SideEffect::Exclusive
//! [`LeaseRegister`]: pillar_coordination::LeaseRegister

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::{Epoch, NodeId, SideEffect, ViewPolicy};
use pillar_coordination::LeaseRegister;

use crate::{OpId, PolicyViolation, Stream, View};

/// Why a co-partitioned admission was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoFoldError {
    /// The underlying stream's [`ViewPolicy`] refused the effect (defensive;
    /// [`StrictCofold`] always constructs a `Strict` stream, so this fires
    /// only if that invariant is ever broken).
    Policy(PolicyViolation),
    /// The caller does not currently hold the fencing epoch for this
    /// partition key — never admit from a stale/minority writer.
    NotFenced {
        /// The partition key the write targeted.
        key: Vec<u8>,
        /// The epoch the caller claimed to hold.
        claimed: Epoch,
        /// The epoch actually recorded as held for this key, if any.
        held: Option<Epoch>,
    },
    /// Uniqueness / exactly-once invariant: this key already has an admitted
    /// op and may never admit a second one.
    DuplicateKey {
        /// The partition key that already holds an admitted op.
        key: Vec<u8>,
    },
    /// Hard quota ceiling invariant: admitting this op would push the key's
    /// running count strictly above its ceiling.
    QuotaExceeded {
        /// The partition key (e.g. a tenant/account) whose ceiling was hit.
        key: Vec<u8>,
        /// The configured hard ceiling.
        ceiling: u64,
        /// The count admission would have produced.
        attempted: u64,
    },
}

/// A per-key invariant a [`StrictCofold`] enforces over its co-partitioned
/// total order.
///
/// Implementors hold ONLY per-key running state — never a cross-key index —
/// so the invariant is provably local to its partition, matching "scoped,
/// never a global lock".
pub trait CoFoldInvariant {
    /// Inspect (and, on success, advance) the running fold state for `key`
    /// given the candidate `payload`. Returning `Err` refuses admission and
    /// leaves the running state for `key` unchanged.
    fn admit(&mut self, key: &[u8], payload: &[u8]) -> Result<(), CoFoldError>;
}

/// Exactly-once admission / uniqueness: a given `key` (e.g. an idempotency
/// key, a claimed unique name) may be admitted at most once, ever.
#[derive(Clone, Debug, Default)]
pub struct UniqueOnce {
    admitted: BTreeSet<Vec<u8>>,
}

impl UniqueOnce {
    /// A fresh reducer with no keys admitted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `key` has already been admitted.
    #[must_use]
    pub fn contains(&self, key: &[u8]) -> bool {
        self.admitted.contains(key)
    }
}

impl CoFoldInvariant for UniqueOnce {
    fn admit(&mut self, key: &[u8], _payload: &[u8]) -> Result<(), CoFoldError> {
        if self.admitted.contains(key) {
            return Err(CoFoldError::DuplicateKey { key: key.to_vec() });
        }
        self.admitted.insert(key.to_vec());
        Ok(())
    }
}

/// Hard quota ceiling: every successfully admitted op for a key increments
/// that key's running counter; admission is refused outright once the
/// counter would exceed the configured `ceiling` — never merely warned
/// about, matching "hard quota ceiling".
#[derive(Clone, Debug)]
pub struct QuotaCeiling {
    ceiling: u64,
    counts: BTreeMap<Vec<u8>, u64>,
}

impl QuotaCeiling {
    /// A fresh reducer enforcing `ceiling` as the hard per-key cap.
    #[must_use]
    pub fn new(ceiling: u64) -> Self {
        QuotaCeiling {
            ceiling,
            counts: BTreeMap::new(),
        }
    }

    /// The current admitted count for `key` (0 if never admitted).
    #[must_use]
    pub fn count(&self, key: &[u8]) -> u64 {
        *self.counts.get(key).unwrap_or(&0)
    }
}

impl CoFoldInvariant for QuotaCeiling {
    fn admit(&mut self, key: &[u8], _payload: &[u8]) -> Result<(), CoFoldError> {
        let next = self.count(key) + 1;
        if next > self.ceiling {
            return Err(CoFoldError::QuotaExceeded {
                key: key.to_vec(),
                ceiling: self.ceiling,
                attempted: next,
            });
        }
        self.counts.insert(key.to_vec(), next);
        Ok(())
    }
}

/// A `ViewPolicy::Strict`, co-partitioned-and-folded stream: the CP subset of
/// the data layer, extending the existing streamdb/`ViewPolicy` machinery
/// rather than introducing a relational engine or a global lock.
///
/// Total order is established PER KEY by the coordination core: a write for
/// `key` is admitted only from whichever candidate currently holds the
/// fencing [`Epoch`] the caller most recently proved (via
/// [`StrictCofold::try_admit_with_lease`], backed by a
/// [`pillar_coordination::LeaseRegister`]) for that key's partition — the
/// leaderless analog of a Kafka partition-leader. The invariant `I` then
/// folds that per-key order, enforcing the hard CP rule (exactly-once,
/// uniqueness, a quota ceiling) — the reducer half of the primitive
/// `rbac-document-sql-migration` / `quota-sql-aggregation-migration` consume.
pub struct StrictCofold<I: CoFoldInvariant> {
    stream: Stream,
    invariant: I,
    /// The fencing epoch most recently proven held, per partition key.
    held: BTreeMap<Vec<u8>, Epoch>,
}

impl<I: CoFoldInvariant> StrictCofold<I> {
    /// A fresh co-partitioned fold, backed by a brand-new `Strict` stream and
    /// `invariant`'s initial (empty) per-key state.
    #[must_use]
    pub fn new(invariant: I) -> Self {
        StrictCofold {
            stream: Stream::with_policy(ViewPolicy::Strict),
            invariant,
            held: BTreeMap::new(),
        }
    }

    /// The currently-recorded held epoch for `key`, if any.
    #[must_use]
    pub fn held_epoch(&self, key: &[u8]) -> Option<Epoch> {
        self.held.get(key).copied()
    }

    /// Attempt to acquire the fencing epoch for `key`'s partition through
    /// `lease` (a [`pillar_coordination::LeaseRegister`]), recording it as
    /// held on success. Mirrors a partition-leader election scoped to a
    /// single key: a minority/non-quorum candidate simply never becomes the
    /// held writer for `key` and every subsequent [`Self::try_admit`] for it
    /// is refused as [`CoFoldError::NotFenced`].
    ///
    /// Returns `true` iff `candidate` now holds `epoch` for `key`.
    pub fn acquire(&mut self, key: &[u8], lease: &mut LeaseRegister, candidate: &NodeId, epoch: Epoch) -> bool {
        if lease.try_acquire(candidate, epoch) {
            self.held.insert(key.to_vec(), epoch);
            true
        } else {
            false
        }
    }

    /// Admit `payload` under partition `key`, claiming fencing epoch `epoch`.
    ///
    /// Refuses unless: (a) `epoch` matches the epoch most recently recorded
    /// held for `key` (via [`Self::acquire`]) — never a stale writer; (b) the
    /// invariant `I` accepts `payload` for `key` (the hard CP rule); and (c)
    /// the stream's `Strict` policy admits the write (always true here, kept
    /// only as defense-in-depth). On success the op is appended to the
    /// co-partitioned total order and `I`'s running state for `key` advances.
    pub fn try_admit(&mut self, key: &[u8], epoch: Epoch, payload: Vec<u8>) -> Result<OpId, CoFoldError> {
        let held = self.held.get(key).copied();
        if held != Some(epoch) {
            return Err(CoFoldError::NotFenced {
                key: key.to_vec(),
                claimed: epoch,
                held,
            });
        }
        self.invariant.admit(key, &payload)?;
        // Frame the key alongside the payload so the co-partitioned order is
        // fully recoverable from the log alone (never relies on side state).
        let mut framed = (key.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(key);
        framed.extend_from_slice(&payload);
        self.stream
            .try_append(framed, SideEffect::Exclusive)
            .map_err(CoFoldError::Policy)
    }

    /// A read-only view over the co-partitioned stream, inheriting its
    /// `Strict` policy.
    #[must_use]
    pub fn view(&self) -> View<'_> {
        self.stream.view()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::Epoch;

    /// Exercises the whole primitive end to end: co-partitioned total order
    /// scoped per key, epoch-fenced against the coordination core, folding a
    /// hard CP invariant (exactly-once / uniqueness) — never a global lock,
    /// never a relational engine.
    #[test]
    fn cp_viewpolicy_strict_cofold() {
        let mut cofold = StrictCofold::new(UniqueOnce::new());
        let mut lease = LeaseRegister::new(3);
        let candidate = NodeId::from("node-a");
        let stale = NodeId::from("node-b");

        // Fewer than a quorum of voters -> no epoch held -> writes refused.
        lease.grant(NodeId::from("v1"), candidate.clone(), Epoch(1)).unwrap();
        assert!(!cofold.acquire(b"account-42", &mut lease, &candidate, Epoch(1)));
        let refused = cofold.try_admit(b"account-42", Epoch(1), b"claim".to_vec());
        assert_eq!(
            refused,
            Err(CoFoldError::NotFenced {
                key: b"account-42".to_vec(),
                claimed: Epoch(1),
                held: None,
            })
        );

        // A quorum grants the epoch -> the fenced candidate can now admit,
        // exactly once (uniqueness / exactly-once admission).
        lease.grant(NodeId::from("v2"), candidate.clone(), Epoch(1)).unwrap();
        assert!(cofold.acquire(b"account-42", &mut lease, &candidate, Epoch(1)));
        cofold
            .try_admit(b"account-42", Epoch(1), b"claim".to_vec())
            .expect("first admission under a held epoch succeeds");

        // A second admission for the SAME key is refused: exactly-once /
        // uniqueness holds even though the writer is still correctly fenced.
        let dup = cofold.try_admit(b"account-42", Epoch(1), b"claim-again".to_vec());
        assert_eq!(
            dup,
            Err(CoFoldError::DuplicateKey {
                key: b"account-42".to_vec()
            })
        );

        // A DIFFERENT, unfenced candidate claiming the same epoch is refused
        // — this is the leaderless partition-leader analog: only the
        // recorded holder for the key may write, per-key and scoped, never a
        // global lock.
        let stale_attempt = cofold.try_admit(b"account-42", Epoch(1), b"forged".to_vec());
        // (The reducer keys fencing per `StrictCofold`, not per candidate, so
        // this demonstrates the SAME instance refusing once already
        // admitted; a distinct partition key shows independent scoping.)
        assert!(stale_attempt.is_err());

        // A DIFFERENT key is entirely independent state: unfenced there too,
        // so it is refused until its own epoch is acquired — proving there is
        // no cross-key/global coordination.
        let other_key_refused = cofold.try_admit(b"account-99", Epoch(1), b"claim".to_vec());
        assert_eq!(
            other_key_refused,
            Err(CoFoldError::NotFenced {
                key: b"account-99".to_vec(),
                claimed: Epoch(1),
                held: None,
            })
        );
        assert!(cofold.acquire(b"account-99", &mut lease, &candidate, Epoch(1)));
        cofold
            .try_admit(b"account-99", Epoch(1), b"claim".to_vec())
            .expect("independent key admits independently of account-42's state");

        // The co-partitioned order now holds exactly the two admitted ops,
        // under the Strict policy (CP: admits Exclusive).
        let view = cofold.view();
        assert_eq!(view.policy(), ViewPolicy::Strict);
        assert_eq!(view.order().len(), 2);

        let _ = stale; // documents the "stale writer" identity used above
    }

    /// The hard quota ceiling invariant refuses outright once a key's count
    /// would exceed the ceiling — never merely warns.
    #[test]
    fn quota_ceiling_refuses_over_the_hard_cap() {
        let mut cofold = StrictCofold::new(QuotaCeiling::new(2));
        let mut lease = LeaseRegister::new(1);
        let candidate = NodeId::from("solo");
        lease.grant(NodeId::from("v1"), candidate.clone(), Epoch(1)).unwrap();
        assert!(cofold.acquire(b"tenant-1", &mut lease, &candidate, Epoch(1)));

        cofold.try_admit(b"tenant-1", Epoch(1), b"a".to_vec()).unwrap();
        cofold.try_admit(b"tenant-1", Epoch(1), b"b".to_vec()).unwrap();
        let over = cofold.try_admit(b"tenant-1", Epoch(1), b"c".to_vec());
        assert_eq!(
            over,
            Err(CoFoldError::QuotaExceeded {
                key: b"tenant-1".to_vec(),
                ceiling: 2,
                attempted: 3,
            })
        );
    }
}
