//! Cell-aware rolling migration — ROI P1 "Versioning, compatibility & safe
//! rollout" — "Automated migration: cell-aware" (operator, 2026-08-31).
//!
//! Within a single [`crate::Cell`], a materialized-view schema bump is a
//! ROLLING update, never a flag-day: mixed-version members coexist while the
//! new view is built by REPLAYING the cell's append-only op log
//! ([`pillar_streamdb::OpLog`]) alongside the still-live old view. The
//! [`MigrationCoordinator`] tracks each member's declared per-surface version
//! (via `compat-negotiation-impl`'s [`pillar_crypto::negotiate_surface`]) and
//! drives the cutover to the new view ONLY once every currently-LIVE member
//! has declared it can serve the new version — never orphaning a
//! not-yet-upgraded member (served by neither view) — while a dead/silent
//! member cannot permanently block cutover past its own liveness timeout.
//!
//! # Model
//!
//! * **Old / new view** — [`MigrationCoordinator::old_log`] keeps serving
//!   every member until cutover; [`MigrationCoordinator::begin_build_new_view`]
//!   builds the new view by replaying (cloning) the CURRENT op set into a
//!   second [`pillar_streamdb::OpLog`], after which every further append is
//!   applied to BOTH logs so they stay in lock-step.
//! * **Per-member declared support** — [`MigrationCoordinator::declare_member_version`]
//!   negotiates a member's declared [`pillar_crypto::SurfaceVersion`] for the
//!   migrating surface against the new schema version; a member within the
//!   compat window is recorded as new-view-capable.
//! * **Liveness** — a purely LOGICAL clock (`u64` ticks), matching this
//!   crate's existing deterministic, wall-clock-free style. A member is LIVE
//!   iff it has heartbeated within [`MigrationCoordinator::liveness_timeout`]
//!   ticks of the coordinator's current tick; a silent member falls out of
//!   the cutover-readiness computation once its timeout elapses, so it can
//!   never permanently block the rollout.
//! * **Cutover** — [`MigrationCoordinator::attempt_cutover`] succeeds only
//!   when [`MigrationCoordinator::ready_for_cutover`] holds (the new view was
//!   built AND every live member has declared new-view support); on success
//!   the old view's resources are reclaimed (its log cleared) and every
//!   member (including a not-yet-declared but now-dead one, should it later
//!   revive) is served from the new view.
//! * **No orphan** — [`MigrationCoordinator::view_for`] always resolves to a
//!   view for any known member: the old view until it declares support (or
//!   forever if cutover never happens while it's silent), the new view once
//!   it has declared support or once cutover has completed.

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_crypto::{negotiate_surface, CompatWindow, SurfaceVersion};
use pillar_streamdb::OpLog;

/// Which materialized view a member currently reads from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewChoice {
    /// The pre-migration view (still-current schema).
    Old,
    /// The post-migration view (new schema), built by replaying the log.
    New,
}

/// A migration coordination error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// [`MigrationCoordinator::attempt_cutover`] was called before
    /// [`MigrationCoordinator::ready_for_cutover`] held — either the new view
    /// has not been built yet, or at least one currently-LIVE member has not
    /// yet declared support for the new version.
    NotReady,
    /// [`MigrationCoordinator::begin_build_new_view`] was called after the
    /// new view was already built (or after cutover already completed).
    AlreadyBuilding,
}

/// Drives an in-cell rolling migration of a single materialized-view surface
/// from its current schema version to a target one, per member declared
/// compat-negotiated support and liveness.
#[derive(Debug)]
pub struct MigrationCoordinator {
    surface: &'static str,
    target_version: SurfaceVersion,
    window: CompatWindow,
    liveness_timeout: u64,
    members: BTreeSet<NodeId>,
    old_log: OpLog,
    new_log: Option<OpLog>,
    declared_new_support: BTreeSet<NodeId>,
    last_seen: BTreeMap<NodeId, u64>,
    now: u64,
    cut_over: bool,
}

impl MigrationCoordinator {
    /// Start a migration coordinator for `surface` toward `target_version`,
    /// negotiated within `window`, tracking the given initial `members`. Every
    /// member starts implicitly live at tick 0. No new view is built yet
    /// ([`MigrationCoordinator::begin_build_new_view`] starts it).
    #[must_use]
    pub fn new(
        surface: &'static str,
        target_version: SurfaceVersion,
        window: CompatWindow,
        liveness_timeout: u64,
        members: impl IntoIterator<Item = NodeId>,
    ) -> Self {
        let members: BTreeSet<NodeId> = members.into_iter().collect();
        let last_seen = members.iter().map(|m| (m.clone(), 0)).collect();
        MigrationCoordinator {
            surface,
            target_version,
            window,
            liveness_timeout,
            members,
            old_log: OpLog::new(),
            new_log: None,
            declared_new_support: BTreeSet::new(),
            last_seen,
            now: 0,
            cut_over: false,
        }
    }

    /// Add a member to track (e.g. a node admitted mid-migration). Starts
    /// live as of the coordinator's current tick.
    pub fn add_member(&mut self, node: NodeId) {
        self.last_seen.insert(node.clone(), self.now);
        self.members.insert(node);
    }

    /// Append a payload to the append-only log. Applied to the old view
    /// always, and additionally REPLAYED into the new view once one has been
    /// built, so both views stay in lock-step until cutover reclaims the old
    /// one.
    pub fn append(&mut self, payload: impl Into<Vec<u8>>) {
        let payload = payload.into();
        self.old_log.append(payload.clone());
        if let Some(new_log) = self.new_log.as_mut() {
            new_log.append(payload);
        }
    }

    /// Begin building the new view: replays (clones) the CURRENT op set of
    /// the old view into a fresh log stamped for the new schema. Future
    /// [`MigrationCoordinator::append`] calls apply to both logs from this
    /// point on, so the new view never misses an op appended after the build
    /// started.
    ///
    /// # Errors
    /// Returns [`MigrationError::AlreadyBuilding`] if a new view already
    /// exists (including after cutover).
    pub fn begin_build_new_view(&mut self) -> Result<(), MigrationError> {
        if self.new_log.is_some() {
            return Err(MigrationError::AlreadyBuilding);
        }
        self.new_log = Some(self.old_log.clone());
        Ok(())
    }

    /// Whether the new view has been built (regardless of cutover).
    #[must_use]
    pub fn new_view_built(&self) -> bool {
        self.new_log.is_some()
    }

    /// Declare `node`'s running version of the migrating surface, negotiating
    /// it against [`MigrationCoordinator::target_version`] within the compat
    /// window. On success `node` is recorded as able to serve the new view;
    /// on refusal it stays served by the old view (never recorded, never
    /// silently promoted). Also counts as a heartbeat (a node's negotiation
    /// message is itself a liveness signal, matching the `admit_versioned`
    /// exchange this task depends on).
    ///
    /// # Errors
    /// Returns the [`pillar_crypto::NegotiationRefused`] refusal when `node`'s
    /// declared version falls outside the compat window of
    /// [`MigrationCoordinator::target_version`].
    pub fn declare_member_version(
        &mut self,
        node: &NodeId,
        declared: SurfaceVersion,
    ) -> Result<(), pillar_crypto::NegotiationRefused> {
        self.heartbeat(node);
        negotiate_surface(self.surface, self.target_version, declared, self.window)?;
        self.declared_new_support.insert(node.clone());
        Ok(())
    }

    /// Record a liveness heartbeat for `node` at the coordinator's current
    /// tick.
    pub fn heartbeat(&mut self, node: &NodeId) {
        self.last_seen.insert(node.clone(), self.now);
    }

    /// Advance the coordinator's logical clock to `tick` (never backward —
    /// a `tick` older than the current one is ignored).
    pub fn advance_time(&mut self, tick: u64) {
        if tick > self.now {
            self.now = tick;
        }
    }

    /// Whether `node` is currently considered LIVE: it has heartbeated (or
    /// declared its version, which heartbeats implicitly) within
    /// [`MigrationCoordinator::liveness_timeout`] ticks of now. An unknown
    /// node is never live.
    #[must_use]
    pub fn is_live(&self, node: &NodeId) -> bool {
        match self.last_seen.get(node) {
            Some(seen) => self.now.saturating_sub(*seen) <= self.liveness_timeout,
            None => false,
        }
    }

    /// The subset of tracked members currently considered live.
    #[must_use]
    pub fn live_members(&self) -> BTreeSet<NodeId> {
        self.members
            .iter()
            .filter(|m| self.is_live(m))
            .cloned()
            .collect()
    }

    /// Whether the migration is ready to cut over: the new view has been
    /// built AND every currently-live member has declared new-view support.
    /// A silent (non-live) member is EXCLUDED from this check, so it can
    /// never permanently block cutover past its own liveness timeout.
    #[must_use]
    pub fn ready_for_cutover(&self) -> bool {
        if self.cut_over {
            return true;
        }
        self.new_log.is_some()
            && self
                .live_members()
                .iter()
                .all(|m| self.declared_new_support.contains(m))
    }

    /// Whether cutover has already completed.
    #[must_use]
    pub fn is_cut_over(&self) -> bool {
        self.cut_over
    }

    /// Attempt the cutover to the new view. On success, reclaims the old
    /// view's resources (clears its log) and every member is thereafter
    /// served from the new view.
    ///
    /// # Errors
    /// Returns [`MigrationError::NotReady`] if
    /// [`MigrationCoordinator::ready_for_cutover`] does not currently hold.
    pub fn attempt_cutover(&mut self) -> Result<(), MigrationError> {
        if !self.ready_for_cutover() {
            return Err(MigrationError::NotReady);
        }
        if !self.cut_over {
            self.cut_over = true;
            // Reclaim the old view's resources now that every live member is
            // served by the new one.
            self.old_log = OpLog::new();
        }
        Ok(())
    }

    /// Which view `node` should currently be served from — never `None` for
    /// a tracked member, so no member is ever orphaned (served by neither
    /// view) mid-upgrade.
    #[must_use]
    pub fn view_for(&self, node: &NodeId) -> Option<ViewChoice> {
        if !self.members.contains(node) {
            return None;
        }
        if self.cut_over {
            return Some(ViewChoice::New);
        }
        match &self.new_log {
            None => Some(ViewChoice::Old),
            Some(_) => {
                if self.declared_new_support.contains(node) {
                    Some(ViewChoice::New)
                } else {
                    Some(ViewChoice::Old)
                }
            }
        }
    }

    /// Read the materialized order `node` currently sees, per
    /// [`MigrationCoordinator::view_for`]. `None` only for an unknown member.
    #[must_use]
    pub fn read_view(&self, node: &NodeId) -> Option<&OpLog> {
        match self.view_for(node)? {
            ViewChoice::Old => Some(&self.old_log),
            ViewChoice::New => self.new_log.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SURFACE: &str = "materialized-view";

    fn node(name: &str) -> NodeId {
        NodeId::from(name)
    }

    fn coordinator(members: &[&str]) -> MigrationCoordinator {
        MigrationCoordinator::new(
            SURFACE,
            SurfaceVersion(2),
            CompatWindow(1),
            /* liveness_timeout */ 5,
            members.iter().map(|n| node(n)),
        )
    }

    // A simulated 3-node cell with one node upgraded first still serves
    // reads correctly from BOTH the old and newly-built view for the lagging
    // two nodes, and the cutover is deferred while any live member has not
    // declared new-version support.
    #[test]
    fn mixed_version_members_are_served_correctly_and_cutover_is_deferred() {
        let mut mc = coordinator(&["n1", "n2", "n3"]);
        mc.append(b"op-a".to_vec());

        mc.begin_build_new_view().unwrap();
        // A second op appended after the new view was built lands in both.
        mc.append(b"op-b".to_vec());

        // n1 upgrades first.
        mc.declare_member_version(&node("n1"), SurfaceVersion(2))
            .unwrap();

        // n1 reads the new view; n2/n3 (lagging) still read the old view.
        assert_eq!(mc.view_for(&node("n1")), Some(ViewChoice::New));
        assert_eq!(mc.view_for(&node("n2")), Some(ViewChoice::Old));
        assert_eq!(mc.view_for(&node("n3")), Some(ViewChoice::Old));

        // Both views agree on the same op set (correct reads for everyone).
        assert_eq!(
            mc.read_view(&node("n1")).unwrap().root(),
            mc.read_view(&node("n2")).unwrap().root()
        );

        // Cutover deferred: n2/n3 (still live) have not declared support.
        assert!(!mc.ready_for_cutover());
        assert_eq!(mc.attempt_cutover(), Err(MigrationError::NotReady));
        assert!(!mc.is_cut_over());
    }

    // Once every live member declares support, cutover proceeds and old-view
    // resources are reclaimed.
    #[test]
    fn cutover_proceeds_once_every_live_member_declares_support() {
        let mut mc = coordinator(&["n1", "n2", "n3"]);
        mc.append(b"op-a".to_vec());
        mc.begin_build_new_view().unwrap();

        for n in ["n1", "n2", "n3"] {
            mc.declare_member_version(&node(n), SurfaceVersion(2))
                .unwrap();
        }

        assert!(mc.ready_for_cutover());
        mc.attempt_cutover().unwrap();
        assert!(mc.is_cut_over());

        // Old-view resources reclaimed: every member now served by the new
        // view, and the old log is empty.
        for n in ["n1", "n2", "n3"] {
            assert_eq!(mc.view_for(&node(n)), Some(ViewChoice::New));
        }
        assert!(mc.old_log.is_empty());
        // The new view still holds the op appended before cutover.
        assert_eq!(mc.new_log.as_ref().unwrap().len(), 1);
    }

    // A node that goes silent (drops out) does not permanently block
    // cutover past its own liveness timeout — it is simply excluded from the
    // live-member readiness check, never orphaned by the old view being
    // reclaimed (the old view is reclaimed only via the same cutover check
    // that already accounts for it being non-live).
    #[test]
    fn a_silent_member_does_not_permanently_block_cutover() {
        let mut mc = coordinator(&["n1", "n2", "n3"]);
        mc.append(b"op-a".to_vec());
        mc.begin_build_new_view().unwrap();

        // n1, n2 upgrade; n3 goes silent (never heartbeats again).
        mc.declare_member_version(&node("n1"), SurfaceVersion(2))
            .unwrap();
        mc.declare_member_version(&node("n2"), SurfaceVersion(2))
            .unwrap();

        // Still within the liveness window: n3 still counts as live, blocks
        // cutover.
        mc.advance_time(3);
        assert!(mc.is_live(&node("n3")));
        assert!(!mc.ready_for_cutover());

        // Past n3's liveness timeout (timeout=5, last seen at tick 0):
        // it drops out of the live-member set and no longer blocks cutover.
        mc.advance_time(6);
        assert!(!mc.is_live(&node("n3")));
        assert!(mc.ready_for_cutover());
        mc.attempt_cutover().unwrap();
        assert!(mc.is_cut_over());

        // n3, though it never declared support, is never orphaned: cutover
        // serves it (and everyone) from the new view rather than leaving it
        // stranded on the now-reclaimed old view.
        assert_eq!(mc.view_for(&node("n3")), Some(ViewChoice::New));
    }

    // An unknown node resolves to no view (distinct from an orphaned KNOWN
    // member, which never happens).
    #[test]
    fn unknown_node_has_no_view() {
        let mc = coordinator(&["n1"]);
        assert_eq!(mc.view_for(&node("ghost")), None);
        assert!(mc.read_view(&node("ghost")).is_none());
    }

    // A member declaring a version outside the compat window is refused and
    // stays served by the old view (never silently promoted to the new
    // one), matching admit_versioned's "refused, never admitted" shape.
    #[test]
    fn an_incompatible_declared_version_is_refused_and_stays_on_old_view() {
        let mut mc = coordinator(&["n1"]);
        mc.begin_build_new_view().unwrap();
        let err = mc
            .declare_member_version(&node("n1"), SurfaceVersion(0))
            .unwrap_err();
        assert_eq!(err.surface, SURFACE);
        assert_eq!(mc.view_for(&node("n1")), Some(ViewChoice::Old));
    }

    // Building the new view twice is refused.
    #[test]
    fn begin_build_new_view_twice_is_refused() {
        let mut mc = coordinator(&["n1"]);
        mc.begin_build_new_view().unwrap();
        assert_eq!(
            mc.begin_build_new_view(),
            Err(MigrationError::AlreadyBuilding)
        );
    }
}
