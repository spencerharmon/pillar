//! Core Pillar types shared across crates.
//!
//! Nothing here reaches the network or the filesystem; these are the value
//! types that the formally-specified protocols operate over. Keeping them
//! dependency-free keeps the model/implementation correspondence auditable.

use std::fmt;

/// A participating node identity.
///
/// In production a node is authenticated by an OpenPGP node-subkey; this
/// newtype carries the stable fingerprint string used as its identity in the
/// coordination protocol. It deliberately does not embed key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_owned())
    }
}

/// A monotonic fencing token.
///
/// Corresponds to `Epochs` in `specs/CoordinationCore.tla`. A higher epoch
/// fences all lower ones: downstream consumers must reject actions carrying a
/// stale epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The initial epoch.
    pub const ZERO: Epoch = Epoch(0);

    /// The next epoch after this one.
    #[must_use]
    pub fn next(self) -> Epoch {
        Epoch(self.0 + 1)
    }
}

/// How a resource's side effects behave, which determines the minimum
/// consistency a view over it may declare.
///
/// This is the classification a controller author MUST make (see
/// `docs/consistency-model.md`). The platform refuses to run an [`Exclusive`]
/// action under a [`ViewPolicy::Relaxed`] view.
///
/// [`Exclusive`]: SideEffect::Exclusive
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideEffect {
    /// Non-idempotent and/or requires exactly-one execution: firing a cronjob
    /// that emails customers, claiming a public DNS name, allocating a unique
    /// address, running a stateful singleton. Requires the CP coordination
    /// core.
    Exclusive,
    /// Idempotent / convergent / cheaply reclaimable: a stateless replica, an
    /// ECMP-absorbed route advertisement, an allocation that is later GC'd.
    /// Spurious duplication is tolerable; may run under a relaxed view.
    Convergent,
}

/// The consistency policy a view opts into for its underlying stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewPolicy {
    /// Quorum-fenced: exclusive actions are gated on the coordination core.
    /// A minority partition refuses to act.
    Strict,
    /// Eventually-consistent (CRDT) merge; no exclusivity guarantee.
    Relaxed,
}

impl ViewPolicy {
    /// Whether this policy is permitted to authorize the given side effect.
    ///
    /// Safe-by-default: only a [`Strict`] view may authorize an [`Exclusive`]
    /// action.
    ///
    /// [`Strict`]: ViewPolicy::Strict
    /// [`Exclusive`]: SideEffect::Exclusive
    #[must_use]
    pub fn admits(self, effect: SideEffect) -> bool {
        match (self, effect) {
            (ViewPolicy::Strict, _) => true,
            (ViewPolicy::Relaxed, SideEffect::Convergent) => true,
            (ViewPolicy::Relaxed, SideEffect::Exclusive) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_monotonic() {
        assert!(Epoch::ZERO < Epoch::ZERO.next());
        assert_eq!(Epoch::ZERO.next(), Epoch(1));
    }

    #[test]
    fn relaxed_view_refuses_exclusive_effects() {
        // The guardrail from docs/consistency-model.md, in code.
        assert!(!ViewPolicy::Relaxed.admits(SideEffect::Exclusive));
        assert!(ViewPolicy::Relaxed.admits(SideEffect::Convergent));
        assert!(ViewPolicy::Strict.admits(SideEffect::Exclusive));
        assert!(ViewPolicy::Strict.admits(SideEffect::Convergent));
    }
}
