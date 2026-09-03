//! Swarm-aware cross-cell migration — ROI P1 "Versioning, compatibility &
//! safe rollout" — "Automated migration: swarm-aware" (operator, 2026-08-31).
//!
//! [`migration`](crate::migration) coordinates a rolling schema migration
//! WITHIN a single cell; this module coordinates the ANALOGOUS problem
//! ACROSS the federation of cells. Cells at different versions negotiate on
//! the wire (via `compat-negotiation-impl`'s
//! [`pillar_crypto::negotiate_surface`]) and interoperate within the N-1+
//! window; a cell that has not yet completed its own
//! [`crate::migration::MigrationCoordinator`] rolling update (a "laggard") is
//! never cut off from the swarm — it keeps exchanging cross-cell messages on
//! whatever surfaces both sides still share, even while excluded from a
//! brand-new surface neither side's window covers yet.
//!
//! # Model
//!
//! * **Per-cell declared surface versions** — [`FederationCoordinator::declare_cell_version`]
//!   records a cell's current running version of a named cross-cell surface
//!   (e.g. `"cross-cell-broadcast"`), exactly the wire declaration
//!   `compat-negotiation-impl` already defines for a single peer, applied
//!   per [`CellId`] instead.
//! * **Cross-cell exchange gate** — [`FederationCoordinator::can_exchange`]
//!   negotiates a single required surface between two cells' declared
//!   versions; `Ok(())` ("linked") lets a cross-cell message/broadcast on
//!   that surface flow, [`pillar_crypto::NegotiationRefused`] cleanly excludes
//!   it — the two cells stay reachable on every OTHER surface they still
//!   share, they are never disconnected wholesale.
//! * **Shared-subset reachability** — [`FederationCoordinator::reachable_surfaces`]
//!   returns exactly the surfaces two cells can currently interoperate on,
//!   so a caller can keep routing everything else even when one particular
//!   surface (e.g. a brand-new one introduced by a migration) is refused.
//! * **Append-only, content-addressed safety** — cross-cell messages are
//!   modelled as appends to a shared [`pillar_streamdb::OpLog`]
//!   ([`FederationCoordinator::record_exchange`]); because the log is
//!   append-only and content-addressed, a misbehaving or out-of-window peer
//!   can at worst have its append refused by [`FederationCoordinator::can_exchange`]
//!   before ever reaching the log — it can never corrupt entries already
//!   recorded by a correctly-versioned peer.
//! * **Mid-federation cutover** — a cell that completes its own
//!   `cell-aware-migration-impl` rollout simply calls
//!   [`FederationCoordinator::declare_cell_version`] again with its new
//!   version; because negotiation is a pure per-pair function of the two
//!   CURRENTLY declared versions, an in-flight exchange with a still-lagging
//!   peer already in progress on a shared surface is completely unaffected —
//!   only a FRESH negotiation on the surface the migrating cell just bumped
//!   is re-evaluated against the new value.

use std::collections::BTreeMap;

use pillar_crypto::{negotiate_surface, CompatWindow, NegotiationRefused, SurfaceVersion};
use pillar_key_distribution::CellId;
use pillar_streamdb::{MerkleRoot, OpLog};

/// Coordinates cross-cell version negotiation and migration across the
/// federation: which surfaces any two cells can currently interoperate on,
/// and a shared append-only record of the exchanges that were allowed
/// through.
#[derive(Debug, Default)]
pub struct FederationCoordinator {
    window: BTreeMap<&'static str, CompatWindow>,
    /// Per-cell, per-surface declared running version.
    declared: BTreeMap<CellId, BTreeMap<&'static str, SurfaceVersion>>,
    /// Append-only, content-addressed record of cross-cell exchanges that
    /// were actually let through. Shared by the whole federation: no single
    /// cell's log is ever mutated by another cell's write.
    exchange_log: OpLog,
}

impl FederationCoordinator {
    /// A federation coordinator with no cells or surfaces declared yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or update) the compat window enforced for `surface`.
    /// Distinct surfaces MAY carry distinct windows (e.g. a brand-new
    /// surface introduced by an in-flight migration can be given a tighter
    /// window than a long-stable one); calling this again for the same
    /// surface overwrites the prior window.
    pub fn set_window(&mut self, surface: &'static str, window: CompatWindow) {
        self.window.insert(surface, window);
    }

    /// The compat window in force for `surface`, if one has been set.
    #[must_use]
    pub fn window_for(&self, surface: &str) -> Option<CompatWindow> {
        self.window.get(surface).copied()
    }

    /// Declare `cell`'s currently running version of `surface`. A repeated
    /// call (e.g. once `cell` completes its own
    /// [`crate::migration::MigrationCoordinator`] cutover) overwrites the
    /// prior value; every FUTURE negotiation call uses the new one, but an
    /// exchange already recorded under the old value is untouched — a
    /// mid-federation cutover never disrupts an in-flight exchange with a
    /// still-lagging peer.
    pub fn declare_cell_version(
        &mut self,
        cell: CellId,
        surface: &'static str,
        version: SurfaceVersion,
    ) {
        self.declared.entry(cell).or_default().insert(surface, version);
    }

    /// `cell`'s currently declared version of `surface`, if any.
    #[must_use]
    pub fn declared_version(&self, cell: &CellId, surface: &str) -> Option<SurfaceVersion> {
        self.declared.get(cell).and_then(|m| m.get(surface).copied())
    }

    /// Whether `a` and `b` can currently exchange messages on `surface`: both
    /// must have declared a version of it, AND those versions must fall
    /// within `surface`'s registered compat window ([`Self::set_window`]).
    /// Cleanly refuses — never silently mis-links — when either condition
    /// fails, so a cell missing the surface entirely or outside the window
    /// is EXCLUDED from just that surface while remaining reachable on any
    /// other surface both sides still share.
    ///
    /// # Errors
    /// Returns [`FederationError::NoWindow`] if `surface` was never
    /// registered via [`Self::set_window`], [`FederationError::NotDeclared`]
    /// if either cell never declared a version of `surface`, or
    /// [`FederationError::Refused`] if both declared but fall outside the
    /// window.
    pub fn can_exchange(
        &self,
        a: &CellId,
        b: &CellId,
        surface: &'static str,
    ) -> Result<(), FederationError> {
        let window = self
            .window_for(surface)
            .ok_or(FederationError::NoWindow(surface))?;
        let va = self
            .declared_version(a, surface)
            .ok_or_else(|| FederationError::NotDeclared(surface, a.clone()))?;
        let vb = self
            .declared_version(b, surface)
            .ok_or_else(|| FederationError::NotDeclared(surface, b.clone()))?;
        negotiate_surface(surface, va, vb, window).map_err(FederationError::Refused)
    }

    /// The subset of `candidate_surfaces` that `a` and `b` can currently
    /// exchange on — the "shared subset both sides support" a laggard cell
    /// keeps reaching the rest of the federation through even while excluded
    /// from a brand-new surface.
    pub fn reachable_surfaces(
        &self,
        a: &CellId,
        b: &CellId,
        candidate_surfaces: &[&'static str],
    ) -> Vec<&'static str> {
        candidate_surfaces
            .iter()
            .copied()
            .filter(|&s| self.can_exchange(a, b, s).is_ok())
            .collect()
    }

    /// Attempt a cross-cell exchange on `surface`: gates on
    /// [`Self::can_exchange`], and only on success appends `payload` to the
    /// shared, append-only, content-addressed exchange log. A refused
    /// exchange never reaches the log at all — a misbehaving or
    /// out-of-window peer cannot corrupt history it was never allowed to
    /// write to.
    ///
    /// # Errors
    /// Propagates [`Self::can_exchange`]'s error when the exchange is
    /// refused.
    pub fn record_exchange(
        &mut self,
        a: &CellId,
        b: &CellId,
        surface: &'static str,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(), FederationError> {
        self.can_exchange(a, b, surface)?;
        self.exchange_log.append(payload.into());
        Ok(())
    }

    /// The current root of the shared exchange log — every exchange that
    /// was ever let through, in append order, unaffected by any refused
    /// attempt.
    #[must_use]
    pub fn exchange_log_root(&self) -> MerkleRoot {
        self.exchange_log.root()
    }

    /// Number of exchanges recorded so far.
    #[must_use]
    pub fn exchange_count(&self) -> usize {
        self.exchange_log.len()
    }
}

/// A cross-cell exchange or negotiation attempt could not proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FederationError {
    /// `surface` was never registered with a compat window
    /// ([`FederationCoordinator::set_window`]).
    NoWindow(&'static str),
    /// The named cell never declared a version of `surface`.
    NotDeclared(&'static str, CellId),
    /// Both cells declared `surface` but fall outside its compat window.
    Refused(NegotiationRefused),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::NoWindow(surface) => {
                write!(f, "surface {surface:?} has no registered compat window")
            }
            FederationError::NotDeclared(surface, cell) => {
                write!(f, "cell {cell:?} never declared a version for surface {surface:?}")
            }
            FederationError::Refused(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for FederationError {}

#[cfg(test)]
mod tests {
    use super::*;

    const BROADCAST: &str = "cross-cell-broadcast";
    const NEW_SURFACE: &str = "cross-cell-new-view-sync";

    fn cell(name: &str) -> CellId {
        CellId::from(name)
    }

    fn fed() -> FederationCoordinator {
        let mut fc = FederationCoordinator::new();
        fc.set_window(BROADCAST, CompatWindow(1));
        fc.set_window(NEW_SURFACE, CompatWindow(1));
        fc
    }

    // A federation of cells at versions N and N-1 continues to exchange
    // cross-cell messages/broadcasts correctly during a staggered rollout.
    #[test]
    fn staggered_rollout_still_exchanges_within_window() {
        let mut fc = fed();
        fc.declare_cell_version(cell("cell-a"), BROADCAST, SurfaceVersion(5));
        fc.declare_cell_version(cell("cell-b"), BROADCAST, SurfaceVersion(4));

        assert!(fc.can_exchange(&cell("cell-a"), &cell("cell-b"), BROADCAST).is_ok());
        fc.record_exchange(&cell("cell-a"), &cell("cell-b"), BROADCAST, b"hello".to_vec())
            .unwrap();
        assert_eq!(fc.exchange_count(), 1);
    }

    // A cell outside the compat window is cleanly excluded from new-surface
    // interactions while remaining reachable on the shared subset both
    // sides support.
    #[test]
    fn out_of_window_cell_excluded_from_new_surface_but_reachable_on_shared_subset() {
        let mut fc = fed();
        // Both cells still agree on the long-stable broadcast surface.
        fc.declare_cell_version(cell("cell-a"), BROADCAST, SurfaceVersion(5));
        fc.declare_cell_version(cell("cell-b"), BROADCAST, SurfaceVersion(5));
        // cell-a has already adopted the brand-new surface; cell-b is two
        // versions behind on it (outside window=1).
        fc.declare_cell_version(cell("cell-a"), NEW_SURFACE, SurfaceVersion(2));
        fc.declare_cell_version(cell("cell-b"), NEW_SURFACE, SurfaceVersion(0));

        let err = fc
            .can_exchange(&cell("cell-a"), &cell("cell-b"), NEW_SURFACE)
            .unwrap_err();
        assert!(matches!(err, FederationError::Refused(_)));

        // But the shared, still-in-window surface keeps working.
        assert!(fc.can_exchange(&cell("cell-a"), &cell("cell-b"), BROADCAST).is_ok());

        let candidates: [&'static str; 2] = [BROADCAST, NEW_SURFACE];
        let reachable = fc.reachable_surfaces(&cell("cell-a"), &cell("cell-b"), &candidates);
        assert_eq!(reachable, vec![BROADCAST]);

        // The refused surface never reaches the shared log.
        let err = fc
            .record_exchange(&cell("cell-a"), &cell("cell-b"), NEW_SURFACE, b"nope".to_vec())
            .unwrap_err();
        assert!(matches!(err, FederationError::Refused(_)));
        assert_eq!(fc.exchange_count(), 0);
    }

    // A cell that completes its own cell-aware cutover mid-federation does
    // not disrupt in-flight cross-cell exchanges with still-lagging peers:
    // an exchange already recorded under the OLD declared version stays in
    // the log untouched, and the shared surface with a still-lagging (but
    // in-window) peer keeps working after the bump.
    #[test]
    fn mid_federation_cutover_does_not_disrupt_lagging_peers() {
        let mut fc = fed();
        fc.declare_cell_version(cell("cell-a"), BROADCAST, SurfaceVersion(4));
        fc.declare_cell_version(cell("cell-b"), BROADCAST, SurfaceVersion(4));
        fc.declare_cell_version(cell("cell-c"), BROADCAST, SurfaceVersion(3));

        // In-flight exchange between a and b before cell-a's cutover.
        fc.record_exchange(&cell("cell-a"), &cell("cell-b"), BROADCAST, b"pre-cutover".to_vec())
            .unwrap();
        let root_before = fc.exchange_log_root();
        assert_eq!(fc.exchange_count(), 1);

        // cell-a completes its own cell-aware-migration-impl rollout and
        // bumps to the new version.
        fc.declare_cell_version(cell("cell-a"), BROADCAST, SurfaceVersion(5));

        // The already-recorded exchange (append-only, content-addressed) is
        // completely unaffected by the bump.
        assert_eq!(fc.exchange_count(), 1);
        assert_eq!(fc.exchange_log_root(), root_before);

        // cell-a <-> cell-c (still on version 3, diff=2) now falls outside
        // window=1 and is refused on this surface...
        assert!(fc.can_exchange(&cell("cell-a"), &cell("cell-c"), BROADCAST).is_err());
        // ...but cell-a can still record a FRESH exchange with cell-b, still
        // within window (diff=1) after the bump.
        fc.record_exchange(&cell("cell-a"), &cell("cell-b"), BROADCAST, b"post-cutover".to_vec())
            .unwrap();
        assert_eq!(fc.exchange_count(), 2);

        // cell-b <-> cell-c remain reachable throughout (diff=1, in window),
        // proving cell-a's cutover never cut off the still-lagging pair.
        assert!(fc.can_exchange(&cell("cell-b"), &cell("cell-c"), BROADCAST).is_ok());
    }
}
