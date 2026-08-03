//! Quorum-fenced lease — the Rust refinement of `specs/CoordinationCore.tla`.
//!
//! A candidate becomes the holder of an [`Epoch`] only once a strict majority
//! of voters has granted it that epoch. Because any two majorities intersect
//! and each voter grants at most one candidate per epoch (grants are
//! monotonic), no two candidates can ever hold the same epoch. That property —
//! `AtMostOneHolderPerEpoch` in the TLA+ model — is what lets a controller
//! treat "I hold epoch e" as the right to perform an exclusive, non-idempotent
//! side effect (see `docs/consistency-model.md`).
//!
//! This crate models the decision logic only; distribution of grants over the
//! streaming DB / gossip layer is a separate component.

use std::collections::HashMap;

use pillar_core::{Epoch, NodeId};

/// Why a grant was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// The voter has already granted at an epoch >= the requested one. Grants
    /// are monotonic (mirrors `e > grantedEpoch[v]` in the spec).
    StaleEpoch {
        /// The highest epoch this voter has already granted in.
        current: Epoch,
    },
}

/// Accumulates voter grants and decides lease acquisition for a cluster of a
/// known size. A minority partition simply never accumulates a majority and so
/// never acquires — no coordinator is consulted.
#[derive(Clone, Debug)]
pub struct LeaseRegister {
    cluster_size: usize,
    /// voter -> (highest granted epoch, candidate backed at that epoch)
    grants: HashMap<NodeId, (Epoch, NodeId)>,
    /// epoch -> acquired holder
    holders: HashMap<Epoch, NodeId>,
}

impl LeaseRegister {
    /// Create a register for a cluster of `cluster_size` voting nodes.
    #[must_use]
    pub fn new(cluster_size: usize) -> Self {
        Self {
            cluster_size,
            grants: HashMap::new(),
            holders: HashMap::new(),
        }
    }

    /// Number of votes constituting a strict majority.
    #[must_use]
    fn is_quorum(&self, votes: usize) -> bool {
        2 * votes > self.cluster_size
    }

    /// Record `voter`'s grant of `epoch` to `candidate`.
    ///
    /// # Errors
    /// Returns [`GrantError::StaleEpoch`] if the voter has already granted at an
    /// epoch greater than or equal to `epoch`.
    pub fn grant(
        &mut self,
        voter: NodeId,
        candidate: NodeId,
        epoch: Epoch,
    ) -> Result<(), GrantError> {
        if let Some((current, _)) = self.grants.get(&voter) {
            if epoch <= *current {
                return Err(GrantError::StaleEpoch { current: *current });
            }
        }
        self.grants.insert(voter, (epoch, candidate));
        Ok(())
    }

    /// Attempt to acquire the lease for `candidate` at `epoch`.
    ///
    /// Returns `true` iff a majority of voters currently back `candidate` at
    /// `epoch`. Idempotent: re-acquiring an already-held epoch by its holder
    /// returns `true`; the quorum-intersection invariant guarantees a different
    /// candidate can never succeed at an epoch already held.
    pub fn try_acquire(&mut self, candidate: &NodeId, epoch: Epoch) -> bool {
        if let Some(existing) = self.holders.get(&epoch) {
            return existing == candidate;
        }
        let votes = self
            .grants
            .values()
            .filter(|(e, c)| *e == epoch && c == candidate)
            .count();
        if self.is_quorum(votes) {
            self.holders.insert(epoch, candidate.clone());
            true
        } else {
            false
        }
    }

    /// The current holder of `epoch`, if any.
    #[must_use]
    pub fn holder(&self, epoch: Epoch) -> Option<&NodeId> {
        self.holders.get(&epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    #[test]
    fn majority_grants_acquire() {
        let mut r = LeaseRegister::new(3);
        r.grant(n("n1"), n("n1"), Epoch(1)).unwrap();
        r.grant(n("n2"), n("n1"), Epoch(1)).unwrap();
        assert!(r.try_acquire(&n("n1"), Epoch(1)));
        assert_eq!(r.holder(Epoch(1)), Some(&n("n1")));
    }

    #[test]
    fn minority_cannot_acquire() {
        // One vote of three is not a majority: a partitioned minority starves.
        let mut r = LeaseRegister::new(3);
        r.grant(n("n1"), n("n1"), Epoch(1)).unwrap();
        assert!(!r.try_acquire(&n("n1"), Epoch(1)));
        assert_eq!(r.holder(Epoch(1)), None);
    }

    #[test]
    fn grants_are_monotonic() {
        let mut r = LeaseRegister::new(3);
        r.grant(n("n2"), n("n1"), Epoch(2)).unwrap();
        assert_eq!(
            r.grant(n("n2"), n("n3"), Epoch(1)),
            Err(GrantError::StaleEpoch { current: Epoch(2) })
        );
        assert_eq!(
            r.grant(n("n2"), n("n3"), Epoch(2)),
            Err(GrantError::StaleEpoch { current: Epoch(2) })
        );
        r.grant(n("n2"), n("n3"), Epoch(3)).unwrap();
    }

    /// `AtMostOneHolderPerEpoch` from `specs/CoordinationCore.tla`, exercised
    /// exhaustively over every way 3 voters can grant one epoch to one of two
    /// candidates. No assignment lets both candidates acquire.
    #[test]
    fn at_most_one_holder_per_epoch_exhaustive() {
        let voters = [n("n1"), n("n2"), n("n3")];
        let candidates = [n("cA"), n("cB")];
        let epoch = Epoch(1);

        // Each voter independently backs cA, cB, or abstains: 3^3 = 27 worlds.
        for mask in 0..27u32 {
            let mut r = LeaseRegister::new(voters.len());
            let mut m = mask;
            for v in &voters {
                match m % 3 {
                    0 => {
                        r.grant(v.clone(), candidates[0].clone(), epoch).unwrap();
                    }
                    1 => {
                        r.grant(v.clone(), candidates[1].clone(), epoch).unwrap();
                    }
                    _ => {} // abstain
                }
                m /= 3;
            }
            let a = r.try_acquire(&candidates[0], epoch);
            let b = r.try_acquire(&candidates[1], epoch);
            assert!(
                !(a && b),
                "split brain: both candidates acquired epoch {epoch:?} (mask {mask})"
            );
        }
    }
}
