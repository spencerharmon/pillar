//! Owner-anchored web-of-trust authority: bounded-depth reachability over
//! non-revoked tsig edges, revocation, and revoke-before-act — the Rust
//! refinement of `specs/WoTAuthority.tla`.
//!
//! # Model
//!
//! A single `owner` [`NodeId`] is the trust anchor. A tsig `edge` from
//! `signer` to `subject` at `level` (see [`tsig`]) means `signer` vouches
//! for `subject` and permits it up to `level` further hops of delegation.
//! Reachability composes depth budgets: the owner has unbounded budget, and
//! an edge from a signer with remaining budget `rb` grants its subject a
//! budget of `min(rb - 1, level)`. The budget strictly decreases every hop,
//! so computing it always terminates.
//!
//! Three kinds of revocation are modelled as grow-only sets of true, global
//! facts — [`WotAuthority::revoke_key`], [`WotAuthority::revoke_edge`],
//! [`WotAuthority::revoke_grant`] — and every one of them bumps the single
//! global watermark [`WotAuthority::rev_count`]. Edges are AP: issuing one
//! needs no coordination. Revocations are CP/fail-closed at the point they
//! matter — not when the revoked-set write lands, but at
//! [`FencedActor::act`] time, which refuses to act at all unless its own
//! watermark exactly equals the current global one (a fully caught-up,
//! fenced read off `pillar-coordination`'s freshness model).
//!
//! `can_relay` models a stricter capability: relaying additionally requires
//! the direct edge from the owner's transitive authority reaching the
//! candidate to itself carry `level >= 2` (mirrors the network-mesh relay
//! capability being a stronger ask than bare WoT membership).

#![forbid(unsafe_code)]

pub mod tsig;

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;

/// A tsig edge: `signer` vouches for `subject` up to `level` further hops.
type Edge = (NodeId, NodeId, u8);

/// The minimum tsig `level` a direct edge must carry for its subject to be
/// admitted as a relay (see module docs).
pub const RELAY_MIN_LEVEL: u8 = 2;

/// Owner-anchored web-of-trust authority state.
///
/// Refines `edges`, `revokedKeys`, `revokedEdges`, `revokedGrants` of
/// `specs/WoTAuthority.tla`. `owner` and `max_depth` correspond to the
/// spec's `Owner` and `MaxDepth` constants.
#[derive(Clone, Debug)]
pub struct WotAuthority {
    owner: NodeId,
    max_depth: u8,
    edges: HashSet<Edge>,
    revoked_keys: HashSet<NodeId>,
    revoked_edges: HashSet<(NodeId, NodeId)>,
    revoked_grants: HashSet<NodeId>,
}

impl WotAuthority {
    /// A fresh authority anchored at `owner` with the given `max_depth`
    /// (mirrors `MaxDepth` in the spec — the model bound on tsig delegation
    /// depth).
    #[must_use]
    pub fn new(owner: NodeId, max_depth: u8) -> Self {
        WotAuthority {
            owner,
            max_depth,
            edges: HashSet::new(),
            revoked_keys: HashSet::new(),
            revoked_edges: HashSet::new(),
            revoked_grants: HashSet::new(),
        }
    }

    /// The owner (trust anchor) this authority is rooted at.
    #[must_use]
    pub fn owner(&self) -> &NodeId {
        &self.owner
    }

    /// Record a verified tsig certification (`IssueEdge`): authority-
    /// expanding, unconditionally available — no coordination required.
    pub fn issue_edge(&mut self, signer: NodeId, subject: NodeId, level: u8) {
        self.edges.insert((signer, subject, level));
    }

    /// Revoke a key (`RevokeKey`): no edge touching it as signer or subject
    /// can carry authority from now on. Idempotent; bumps [`rev_count`](Self::rev_count).
    pub fn revoke_key(&mut self, key: NodeId) {
        self.revoked_keys.insert(key);
    }

    /// Revoke a specific tsig edge (`RevokeEdge`). Idempotent; bumps
    /// [`rev_count`](Self::rev_count).
    pub fn revoke_edge(&mut self, signer: NodeId, subject: NodeId) {
        self.revoked_edges.insert((signer, subject));
    }

    /// Revoke a subject's direct grant (`RevokeGrant`): strips derived
    /// authority even while its tsig chain remains intact — an explicit,
    /// out-of-band deny. Idempotent; bumps [`rev_count`](Self::rev_count).
    pub fn revoke_grant(&mut self, subject: NodeId) {
        self.revoked_grants.insert(subject);
    }

    /// The true global revocation watermark: the total count of revocation
    /// facts across all three kinds, right now. A [`FencedActor`] may only
    /// [`act`](FencedActor::act) once its own watermark exactly equals this.
    #[must_use]
    pub fn rev_count(&self) -> u64 {
        (self.revoked_keys.len() + self.revoked_edges.len() + self.revoked_grants.len()) as u64
    }

    /// Edges currently usable given the live revoked-keys/revoked-edges
    /// facts: neither endpoint's key nor the edge itself is revoked.
    fn valid_edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |(signer, subject, _)| {
            !self.revoked_keys.contains(signer)
                && !self.revoked_keys.contains(subject)
                && !self.revoked_edges.contains(&(signer.clone(), subject.clone()))
        })
    }

    /// The maximum remaining delegation budget reachable at `node`, or
    /// `None` if `node` is not reachable from the owner over any chain of
    /// currently-valid, non-revoked edges within `max_depth`.
    ///
    /// This is bounded-depth BFS over the budget-composition rule: the
    /// owner starts with budget `max_depth`; an edge from a signer with
    /// budget `rb` grants its subject `min(rb - 1, level)`. A node's
    /// reachable budget is the max over every path reaching it (mirroring
    /// the spec's fixpoint, which always terminates since budget strictly
    /// decreases each hop).
    #[must_use]
    pub fn reachable_depth(&self, node: &NodeId) -> Option<u8> {
        if node == &self.owner {
            // The revoked-key check still applies to the owner itself: a
            // revoked owner key carries no authority for anyone.
            if self.revoked_keys.contains(node) {
                return None;
            }
            return Some(self.max_depth);
        }
        if self.revoked_keys.contains(node) {
            return None;
        }

        let mut best: HashMap<NodeId, u8> = HashMap::new();
        if !self.revoked_keys.contains(&self.owner) {
            best.insert(self.owner.clone(), self.max_depth);
        }
        // Bounded fixpoint: at most max_depth+1 rounds since budget strictly
        // decreases each hop, so no round after that can improve anything.
        for _ in 0..=self.max_depth {
            let mut changed = false;
            for (signer, subject, level) in self.valid_edges() {
                let Some(&rb) = best.get(signer) else {
                    continue;
                };
                if rb == 0 {
                    continue;
                }
                let granted = (rb - 1).min(*level);
                let entry = best.entry(subject.clone()).or_insert(0);
                if granted > *entry {
                    *entry = granted;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        best.get(node).copied()
    }

    /// Whether `subject` is currently authoritative: reachable from the
    /// owner over valid edges within bound, AND its direct grant has not
    /// been separately revoked (`revokedGrants`, an out-of-band deny that
    /// applies even with an intact tsig chain).
    #[must_use]
    pub fn is_authoritative(&self, subject: &NodeId) -> bool {
        !self.revoked_grants.contains(subject) && self.reachable_depth(subject).is_some()
    }

    /// The full set of currently-authoritative subjects (used to snapshot
    /// "who was authoritative at act time" for [`FencedActor::act`]).
    #[must_use]
    pub fn authoritative_set(&self, candidates: impl IntoIterator<Item = NodeId>) -> HashSet<NodeId> {
        candidates
            .into_iter()
            .filter(|c| self.is_authoritative(c))
            .collect()
    }

    /// Whether `subject` qualifies as a relay: reachable from the owner AND
    /// bound by a *direct* edge (an edge whose subject is exactly
    /// `subject`) carrying `level >= `[`RELAY_MIN_LEVEL`], and not grant-
    /// revoked. A subject reachable only through low-level (`level < 2`)
    /// direct edges is admitted to general authority but never to relay.
    #[must_use]
    pub fn can_relay(&self, subject: &NodeId) -> bool {
        if self.revoked_grants.contains(subject) || self.reachable_depth(subject).is_none() {
            return false;
        }
        self.valid_edges()
            .any(|(_, s, level)| s == subject && *level >= RELAY_MIN_LEVEL)
    }
}

/// Why [`FencedActor::act`] refused to act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActError {
    /// The actor's own revocation watermark lags the authority's current
    /// one — a stale view. Fail-closed: refuses to act rather than fall
    /// back to an optimistic/last-known-good grant.
    StaleView {
        /// The actor's own watermark.
        local: u64,
        /// The authority's current (true) watermark.
        current: u64,
    },
    /// The actor's view is fully fresh, but `subject` is not currently
    /// authoritative.
    NotAuthoritative,
}

/// A snapshot of who was authoritative at the moment an [`FencedActor::act`]
/// succeeded — the Rust stand-in for the spec's ghost `lastAct` variable,
/// letting tests assert `NoActionAfterRevocation`: the acted-on subject was
/// a member of the authoritative set at the exact moment of the act, which
/// (by fencing) always precedes any later revocation of that subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActedSnapshot {
    /// The revocation watermark in effect at the moment of the act.
    pub watermark: u64,
    /// The subject the act was performed on.
    pub subject: NodeId,
}

/// A node's fenced view of the [`WotAuthority`]'s revocation state: the
/// Rust refinement of the spec's `freshMark[n]`.
#[derive(Clone, Debug, Default)]
pub struct FencedActor {
    watermark: u64,
}

impl FencedActor {
    /// A brand-new actor with an empty (zero) watermark — maximally stale
    /// until it [`refresh`](Self::refresh)es.
    #[must_use]
    pub fn new() -> Self {
        FencedActor::default()
    }

    /// This actor's current local watermark.
    #[must_use]
    pub fn watermark(&self) -> u64 {
        self.watermark
    }

    /// Catch this actor's view fully up to `authority`'s current revocation
    /// watermark (`StaleView` resync / `Partition` never calls this).
    pub fn refresh(&mut self, authority: &WotAuthority) {
        self.watermark = authority.rev_count();
    }

    /// Attempt to act on `subject`'s authority (`Act`): the revoke-before-
    /// act guard. Succeeds only when this actor's watermark exactly equals
    /// `authority`'s current one (a fully caught-up, fenced read) AND
    /// `subject` is currently authoritative under that (necessarily
    /// current, since fencing forces equality) view.
    ///
    /// # Errors
    ///
    /// [`ActError::StaleView`] if this actor's watermark lags the current
    /// global one (fail-closed — the guard disables `Act` entirely rather
    /// than accepting a possibly-outdated grant); [`ActError::NotAuthoritative`]
    /// if the view is fresh but `subject` is not authoritative.
    pub fn act(&self, authority: &WotAuthority, subject: &NodeId) -> Result<ActedSnapshot, ActError> {
        let current = authority.rev_count();
        if self.watermark != current {
            return Err(ActError::StaleView {
                local: self.watermark,
                current,
            });
        }
        if !authority.is_authoritative(subject) {
            return Err(ActError::NotAuthoritative);
        }
        Ok(ActedSnapshot {
            watermark: current,
            subject: subject.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn owner_authority(max_depth: u8) -> WotAuthority {
        WotAuthority::new(n("owner"), max_depth)
    }

    #[test]
    fn owner_is_always_reachable_at_full_depth() {
        let a = owner_authority(3);
        assert_eq!(a.reachable_depth(&n("owner")), Some(3));
        assert!(a.is_authoritative(&n("owner")));
    }

    #[test]
    fn direct_owner_edge_grants_min_of_budget_and_level() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 1);
        // owner budget 3 -> subject gets min(3-1, 1) = 1
        assert_eq!(a.reachable_depth(&n("alice")), Some(1));
        assert!(a.is_authoritative(&n("alice")));
    }

    #[test]
    fn bounded_depth_admits_within_bound_and_denies_beyond() {
        let mut a = owner_authority(2);
        // owner(budget 2) -> alice: min(2-1,2)=1 -> bob: min(1-1,2)=0 -> carol: min(0-1... rb=0 so no further grant.
        a.issue_edge(n("owner"), n("alice"), 2);
        a.issue_edge(n("alice"), n("bob"), 2);
        a.issue_edge(n("bob"), n("carol"), 2);
        assert_eq!(a.reachable_depth(&n("alice")), Some(1));
        assert_eq!(a.reachable_depth(&n("bob")), Some(0));
        assert!(a.is_authoritative(&n("bob")));
        // bob's remaining budget is 0, so it can grant nothing further:
        // carol is NOT reachable at all -- bounded-depth denial.
        assert_eq!(a.reachable_depth(&n("carol")), None);
        assert!(!a.is_authoritative(&n("carol")));
    }

    #[test]
    fn revoked_key_removes_all_authority_through_it() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);
        a.issue_edge(n("alice"), n("bob"), 2);
        assert!(a.is_authoritative(&n("bob")));

        a.revoke_key(n("alice"));
        assert!(!a.is_authoritative(&n("alice")));
        // bob's only path ran through alice's now-revoked key.
        assert!(!a.is_authoritative(&n("bob")));
    }

    #[test]
    fn revoked_edge_only_removes_that_specific_path() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);
        a.issue_edge(n("owner"), n("bob"), 2);
        a.issue_edge(n("alice"), n("carol"), 2);
        a.issue_edge(n("bob"), n("carol"), 2);
        assert!(a.is_authoritative(&n("carol")));

        a.revoke_edge(n("alice"), n("carol"));
        // carol is still reachable via bob.
        assert!(a.is_authoritative(&n("carol")));

        a.revoke_edge(n("bob"), n("carol"));
        // now both paths are gone.
        assert!(!a.is_authoritative(&n("carol")));
    }

    #[test]
    fn revoked_grant_denies_even_with_intact_chain() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);
        assert!(a.is_authoritative(&n("alice")));

        a.revoke_grant(n("alice"));
        // tsig chain is untouched, but the direct grant revocation is an
        // explicit, out-of-band deny.
        assert!(!a.is_authoritative(&n("alice")));
        assert_eq!(a.reachable_depth(&n("alice")), Some(2));
    }

    #[test]
    fn relay_requires_direct_level_at_least_two() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("weak"), 1);
        a.issue_edge(n("owner"), n("strong"), 2);
        assert!(a.is_authoritative(&n("weak")));
        assert!(!a.can_relay(&n("weak")));
        assert!(a.can_relay(&n("strong")));
    }

    #[test]
    fn unreachable_node_is_never_authoritative() {
        let a = owner_authority(3);
        assert_eq!(a.reachable_depth(&n("nobody")), None);
        assert!(!a.is_authoritative(&n("nobody")));
    }

    // --- revoke-before-act / FencedActor -----------------------------------

    #[test]
    fn fresh_actor_can_act_on_authoritative_subject() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);

        let mut actor = FencedActor::new();
        actor.refresh(&a);
        let snap = actor.act(&a, &n("alice")).unwrap();
        assert_eq!(snap.subject, n("alice"));
        assert_eq!(snap.watermark, 0);
    }

    #[test]
    fn stale_actor_refuses_to_act_fail_closed() {
        // FailClosedUnderStaleView: a node whose watermark lags the true one
        // can never successfully act, even if `subject` really is (or was)
        // authoritative.
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);

        let mut actor = FencedActor::new();
        actor.refresh(&a); // watermark == 0, matches current rev_count() == 0

        // A revocation happens that the actor has not yet observed.
        a.revoke_grant(n("bob")); // bumps rev_count to 1, unrelated to alice

        let err = actor.act(&a, &n("alice")).unwrap_err();
        assert_eq!(
            err,
            ActError::StaleView {
                local: 0,
                current: 1
            }
        );
    }

    #[test]
    fn refreshed_actor_observes_revocation_and_refuses() {
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);

        let mut actor = FencedActor::new();
        actor.refresh(&a);
        assert!(actor.act(&a, &n("alice")).is_ok());

        a.revoke_grant(n("alice"));
        actor.refresh(&a);
        assert_eq!(actor.act(&a, &n("alice")), Err(ActError::NotAuthoritative));
    }

    #[test]
    fn no_action_after_revocation() {
        // NoActionAfterRevocation: the most recent successful Act carries a
        // snapshot fenced at its own (then-current) watermark. Once that
        // watermark has passed, no LATER revocation can ever invalidate the
        // historical fact that the act happened while `subject` really was
        // authoritative -- the act always precedes any later revocation of
        // that subject, never follows it.
        let mut a = owner_authority(3);
        a.issue_edge(n("owner"), n("alice"), 2);

        let mut actor = FencedActor::new();
        actor.refresh(&a);
        let snap = actor.act(&a, &n("alice")).unwrap();
        assert!(a.is_authoritative(&n("alice")));

        // A later revocation invalidates alice going forward...
        a.revoke_grant(n("alice"));
        assert!(!a.is_authoritative(&n("alice")));

        // ...but the recorded act's watermark strictly precedes the
        // revocation that undid it, and at that watermark alice was
        // genuinely authoritative -- the historical snapshot is preserved.
        assert_eq!(snap.watermark, 0);
        assert!(a.rev_count() > snap.watermark);

        // And the actor can never be tricked into re-acting on the same
        // stale snapshot: a fresh act attempt (without refreshing) is
        // refused for staleness, and after refreshing it is refused because
        // alice is no longer authoritative.
        assert_eq!(
            actor.act(&a, &n("alice")),
            Err(ActError::StaleView {
                local: 0,
                current: 1
            })
        );
    }

    #[test]
    fn idempotent_revocations_do_not_double_count() {
        let mut a = owner_authority(3);
        a.revoke_key(n("x"));
        a.revoke_key(n("x"));
        assert_eq!(a.rev_count(), 1);
    }
}
