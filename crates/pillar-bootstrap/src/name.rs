//! Best-effort, peer-sourced cell-**name** uniqueness pre-check — the single
//! validation contract every create-cell surface (CLI + web UI) shares, moved
//! here from `pillar-web` so the two can never diverge.
//!
//! Semantics are deliberately best-effort, mirroring the platform's "if no
//! peer serves a stream it is unavailable regardless" rule: a name is claimed
//! ONLY when a peer actually serves a cell-name pointer for it. A name
//! unreachable because no peer answers is treated as FREE — the check catches
//! the common accidental collision at create time; it is NOT a global
//! strong-uniqueness guarantee.

use pillar_core::NodeId;

use crate::BootstrapError;

/// The clear, surfaced message for [`BootstrapError::CellNameInUse`] — one
/// string, so the CLI and the web UI display the SAME wording.
pub const CELL_NAME_IN_USE_MESSAGE: &str = "cell name already in use — choose another";

/// A best-effort, peer-sourced check of whether a proposed cell NAME is
/// already claimed on the pillar network, resolving the pillar-scoped
/// IPNS/cell-name pointer for the name through the SAME peer-sourced
/// resolution the node already uses (the node is on the swarm at bootstrap
/// time).
///
/// This is the ONE validation contract shared by every create-cell surface.
/// An implementation MUST fail open (return [`CellNameStatus::Free`]) on an
/// unreachable / no-peer-serving name, never refuse a create merely because
/// the network could not be reached.
pub trait CellNameRegistry {
    /// Resolve `name` on the network. Returns [`CellNameStatus::Claimed`] only
    /// if a peer actually serves a cell-name pointer for `name`; otherwise —
    /// including when no peer answers — [`CellNameStatus::Free`].
    fn lookup(&self, name: &NodeId) -> CellNameStatus;
}

/// The best-effort resolution outcome for a proposed cell name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellNameStatus {
    /// A peer serves a cell-name pointer for this name — it is taken.
    Claimed,
    /// No peer serves a pointer for this name (reachable-and-absent OR simply
    /// unreachable) — treat as FREE per the best-effort rule.
    Free,
}

impl<F> CellNameRegistry for F
where
    F: Fn(&NodeId) -> CellNameStatus,
{
    fn lookup(&self, name: &NodeId) -> CellNameStatus {
        (self)(name)
    }
}

/// An in-memory [`CellNameRegistry`] over a fixed set of already-claimed names
/// — the deterministic stand-in the tests drive (a real node resolves the
/// pointer over the swarm). Names NOT in the set resolve
/// [`CellNameStatus::Free`], modelling both a genuinely-free name and an
/// unreachable one identically, per the best-effort rule.
#[derive(Clone, Debug, Default)]
pub struct InMemoryCellNameRegistry {
    claimed: std::collections::BTreeSet<NodeId>,
}

impl InMemoryCellNameRegistry {
    /// An empty registry — every name resolves FREE (models a node whose swarm
    /// view serves no cell-name pointers yet).
    #[must_use]
    pub fn new() -> Self {
        InMemoryCellNameRegistry::default()
    }

    /// Mark `name` as already claimed on the network.
    pub fn claim(&mut self, name: impl Into<NodeId>) {
        self.claimed.insert(name.into());
    }
}

impl CellNameRegistry for InMemoryCellNameRegistry {
    fn lookup(&self, name: &NodeId) -> CellNameStatus {
        if self.claimed.contains(name) {
            CellNameStatus::Claimed
        } else {
            CellNameStatus::Free
        }
    }
}

/// The ONE shared pre-create cell-name validation both surfaces (CLI + web UI)
/// call before generating the cell key. Consults `registry` for `name` and
/// returns [`BootstrapError::CellNameInUse`] iff a peer serves a pointer for
/// it; `Ok(())` when the name is free (including unreachable — best-effort).
///
/// # Errors
///
/// [`BootstrapError::CellNameInUse`] if the network already claims `name`.
pub fn check_cell_name_available(
    registry: &(impl CellNameRegistry + ?Sized),
    name: &NodeId,
) -> Result<(), BootstrapError> {
    match registry.lookup(name) {
        CellNameStatus::Claimed => Err(BootstrapError::CellNameInUse),
        CellNameStatus::Free => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claimed_name_is_refused_and_a_free_name_passes() {
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("taken");
        assert_eq!(
            check_cell_name_available(&registry, &NodeId::from("taken")),
            Err(BootstrapError::CellNameInUse)
        );
        assert_eq!(
            check_cell_name_available(&registry, &NodeId::from("open")),
            Ok(())
        );
    }

    #[test]
    fn an_unreachable_name_fails_open_as_free() {
        // A registry answering Free for everything models an unreachable /
        // no-peer-serving name — best-effort: treat as FREE.
        let registry = |_: &NodeId| CellNameStatus::Free;
        assert_eq!(
            check_cell_name_available(&registry, &NodeId::from("unreachable")),
            Ok(())
        );
    }
}
