//! `pillar rollout`: drives the four safe-rollout invariants the ROI P1
//! "Versioning, compatibility & safe rollout" family names — a real,
//! in-process, cross-crate driver that exercises the REAL primitives shipped by
//! `compat-negotiation-impl`, `cell-aware-migration-impl` /
//! `swarm-aware-migration-impl`, and `cell-health-readiness-probe`, exactly as
//! `pillar onboard` drives the real identity/trust path.
//!
//! The black-box integration harness (`scripts/pillar-integration`) cannot link
//! a pillar crate; the CLI/HTTP/wire surfaces exposed no verb that ran a
//! negotiation, a migration, a cutover, or a rollback. This verb is that
//! missing EXTERNAL surface: the harness runs the real published image's
//! `pillar rollout` in a throwaway container (no crate linkage) and observes one
//! `ok: <step>` line per passing invariant.
//!
//! Every step prints one `ok: <step>` line on success; any step failing an
//! invariant prints `FAIL: <step>: <why>` and the whole command exits non-zero
//! — so the rig fails loud on the first broken invariant (data loss, a bypassed
//! readiness gate, a corrupted rollback) rather than a generic non-zero.

use pillar_cells::migration::{MigrationError, ViewChoice};
use pillar_cells::{FederationCoordinator, MigrationCoordinator};
use pillar_core::NodeId;
use pillar_crypto::{negotiate_surface, CompatWindow, SurfaceVersion};
use pillar_key_distribution::CellId;

use crate::health::{NodeReadiness, ReadinessReport};

/// Runs the full rollout sequence. Returns `Ok(())` if every invariant holds,
/// `Err(<diagnostic>)` naming the first violated one.
pub fn run() -> Result<(), String> {
    step_mixed_version_negotiation()?;
    step_no_data_loss_migration()?;
    step_readiness_gates_cutover()?;
    step_clean_rollback()?;
    step_no_traffic_before_ready()?;
    Ok(())
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

const SURFACE: &str = "materialized-view";

/// Step 1 — mixed-version negotiation over the N-1+ compat window: an in-window
/// N-1 peer links, a same-version peer links, an out-of-window N-2 peer is
/// cleanly REFUSED with a typed refusal carrying the concrete versions +
/// window, never a silent mis-link.
fn step_mixed_version_negotiation() -> Result<(), String> {
    const STEP: &str = "mixed-version-negotiation";
    let window = CompatWindow(1);
    let running = SurfaceVersion(2);

    // same-version peer links.
    negotiate_surface(SURFACE, running, SurfaceVersion(2), window)
        .map_err(|e| fail(STEP, format!("a same-version peer was refused: {e}")))?;
    // in-window N-1 peer links.
    negotiate_surface(SURFACE, running, SurfaceVersion(1), window)
        .map_err(|e| fail(STEP, format!("an in-window N-1 peer was refused: {e}")))?;

    // out-of-window N-2 peer must be REFUSED, and the refusal must carry the
    // concrete versions + window (never a silent mis-link).
    match negotiate_surface(SURFACE, running, SurfaceVersion(0), window) {
        Ok(()) => {
            return Err(fail(
                STEP,
                "an out-of-window N-2 peer was WRONGLY linked (silent mis-link)",
            ))
        }
        Err(refused) => {
            if refused.local != running
                || refused.remote != SurfaceVersion(0)
                || refused.window != window
                || refused.surface != SURFACE
            {
                return Err(fail(
                    STEP,
                    format!("refusal did not carry the concrete versions/window: {refused:?}"),
                ));
            }
        }
    }
    ok(STEP);
    Ok(())
}

/// Step 2 — no-data-loss migration: a real `MigrationCoordinator` builds the
/// new view by REPLAYING the append-only op log; the new view's
/// content-addressed Merkle root equals the old view's over the same op set, a
/// mid-build append reaches BOTH views in lock-step, and after cutover the
/// surviving view still carries every op (no op dropped).
fn step_no_data_loss_migration() -> Result<(), String> {
    const STEP: &str = "no-data-loss-migration";
    let n1 = NodeId::from("n1");
    let n2 = NodeId::from("n2");
    let n3 = NodeId::from("n3");
    let mut mc = MigrationCoordinator::new(
        SURFACE,
        SurfaceVersion(2),
        CompatWindow(1),
        /* liveness_timeout */ 5,
        vec![n1.clone(), n2.clone(), n3.clone()],
    );

    // Real op log with a few ops before the new view is built.
    mc.append(b"op-a".to_vec());
    mc.append(b"op-b".to_vec());

    mc.begin_build_new_view()
        .map_err(|e| fail(STEP, format!("could not begin building the new view: {e:?}")))?;

    // A mid-build append must reach BOTH views in lock-step.
    mc.append(b"op-c".to_vec());

    // Bring one member onto the new view so we can read both views concurrently.
    mc.declare_member_version(&n1, SurfaceVersion(2))
        .map_err(|e| fail(STEP, format!("n1 declared version was refused: {e}")))?;

    let new_root = mc
        .read_view(&n1)
        .ok_or_else(|| fail(STEP, "n1 has no view to read (orphaned)"))?
        .root();
    let old_root = mc
        .read_view(&n2)
        .ok_or_else(|| fail(STEP, "n2 has no view to read (orphaned)"))?
        .root();
    if new_root != old_root {
        return Err(fail(
            STEP,
            "the new view's Merkle root DIFFERS from the old view's over the same op set (data lost across the replay/lock-step)",
        ));
    }
    let op_count_before_cutover = mc
        .read_view(&n1)
        .ok_or_else(|| fail(STEP, "n1 has no view (orphaned)"))?
        .len();
    if op_count_before_cutover != 3 {
        return Err(fail(
            STEP,
            format!("expected 3 ops in the migrated view, found {op_count_before_cutover}"),
        ));
    }

    // Bring the remaining live members over and cut over; the surviving view
    // must still carry every op.
    mc.declare_member_version(&n2, SurfaceVersion(2))
        .map_err(|e| fail(STEP, format!("n2 declared version was refused: {e}")))?;
    mc.declare_member_version(&n3, SurfaceVersion(2))
        .map_err(|e| fail(STEP, format!("n3 declared version was refused: {e}")))?;
    mc.attempt_cutover()
        .map_err(|e| fail(STEP, format!("cutover failed though every live member declared support: {e:?}")))?;

    let surviving = mc
        .read_view(&n3)
        .ok_or_else(|| fail(STEP, "n3 orphaned after cutover"))?;
    if surviving.len() != 3 {
        return Err(fail(
            STEP,
            format!("post-cutover surviving view dropped ops (has {}, expected 3)", surviving.len()),
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 3 — readiness gates cutover: an undeclared-but-live member reads the
/// OLD view and BLOCKS cutover (`ready_for_cutover()==false`,
/// `attempt_cutover()` errors `NotReady`), then unblocks only once it declares
/// an in-window version — the gate that stops a still-un-upgraded node from
/// being served the new view early.
fn step_readiness_gates_cutover() -> Result<(), String> {
    const STEP: &str = "readiness-gates-cutover";
    let n1 = NodeId::from("n1");
    let n2 = NodeId::from("n2");
    let mut mc = MigrationCoordinator::new(
        SURFACE,
        SurfaceVersion(2),
        CompatWindow(1),
        /* liveness_timeout */ 100,
        vec![n1.clone(), n2.clone()],
    );
    mc.append(b"op-a".to_vec());
    mc.begin_build_new_view()
        .map_err(|e| fail(STEP, format!("could not begin building the new view: {e:?}")))?;

    // n1 upgrades; n2 stays undeclared but LIVE.
    mc.declare_member_version(&n1, SurfaceVersion(2))
        .map_err(|e| fail(STEP, format!("n1 declared version was refused: {e}")))?;

    // The undeclared-but-live member must still read the OLD view...
    if mc.view_for(&n2) != Some(ViewChoice::Old) {
        return Err(fail(
            STEP,
            "an undeclared-but-live member was served the NEW view early (readiness gate bypassed)",
        ));
    }
    // ...and BLOCK cutover.
    if mc.ready_for_cutover() {
        return Err(fail(
            STEP,
            "cutover reported ready while a live member had not declared support (gate bypassed)",
        ));
    }
    match mc.attempt_cutover() {
        Err(MigrationError::NotReady) => {}
        Ok(()) => {
            return Err(fail(
                STEP,
                "attempt_cutover SUCCEEDED while a live member had not declared support (gate bypassed)",
            ))
        }
        Err(other) => return Err(fail(STEP, format!("unexpected cutover error: {other:?}"))),
    }

    // Now n2 declares an in-window version — the gate unblocks.
    mc.declare_member_version(&n2, SurfaceVersion(2))
        .map_err(|e| fail(STEP, format!("n2 declared version was refused: {e}")))?;
    if !mc.ready_for_cutover() {
        return Err(fail(
            STEP,
            "cutover still blocked after every live member declared support",
        ));
    }
    mc.attempt_cutover()
        .map_err(|e| fail(STEP, format!("cutover failed after the gate cleared: {e:?}")))?;
    ok(STEP);
    Ok(())
}

/// Step 4 — clean rollback: a real `FederationCoordinator` records an exchange
/// (snapshotting its content-addressed log root), bumps cell A's surface
/// version forward, then ROLLS BACK to the prior version: the declared version
/// is restored EXACTLY, prior in-window peers interoperate again, and the
/// already-recorded exchange + its log root are UNTOUCHED by the churn.
fn step_clean_rollback() -> Result<(), String> {
    const STEP: &str = "clean-rollback";
    const BROADCAST: &str = "cross-cell-broadcast";
    let a = CellId::from("cell-a");
    let b = CellId::from("cell-b");
    let mut fc = FederationCoordinator::new();
    fc.set_window(BROADCAST, CompatWindow(1));

    let prior = SurfaceVersion(4);
    fc.declare_cell_version(a.clone(), BROADCAST, prior);
    fc.declare_cell_version(b.clone(), BROADCAST, SurfaceVersion(4));

    // Record a real exchange and snapshot the content-addressed log root.
    fc.record_exchange(&a, &b, BROADCAST, b"pre-rollback".to_vec())
        .map_err(|e| fail(STEP, format!("in-window peers could not exchange: {e}")))?;
    let root_before = fc.exchange_log_root();
    let count_before = fc.exchange_count();

    // Bump cell A forward.
    fc.declare_cell_version(a.clone(), BROADCAST, SurfaceVersion(5));
    // b is now diff=1 (still in window) but let's verify a real bump happened.
    if fc.declared_version(&a, BROADCAST) != Some(SurfaceVersion(5)) {
        return Err(fail(STEP, "the forward bump did not take effect"));
    }

    // ROLL BACK to the prior version.
    fc.declare_cell_version(a.clone(), BROADCAST, prior);
    if fc.declared_version(&a, BROADCAST) != Some(prior) {
        return Err(fail(
            STEP,
            "rollback did not restore the prior declared version exactly",
        ));
    }

    // Prior in-window peers interoperate again.
    fc.can_exchange(&a, &b, BROADCAST)
        .map_err(|e| fail(STEP, format!("prior in-window peer cannot interoperate after rollback: {e}")))?;

    // The already-recorded exchange + its content-addressed root are UNTOUCHED.
    if fc.exchange_count() != count_before {
        return Err(fail(
            STEP,
            format!("rollback churn changed the exchange count ({} != {count_before})", fc.exchange_count()),
        ));
    }
    if fc.exchange_log_root() != root_before {
        return Err(fail(
            STEP,
            "rollback churn CORRUPTED the content-addressed exchange log root (history not preserved)",
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 5 — no traffic before ready: the real `NodeReadiness::evaluate()`
/// decision (the one `/readyz` serves) keeps a bound-port-only node and a
/// partially-healthy node OUT of service, flipping Ready only once every
/// substantive condition holds.
fn step_no_traffic_before_ready() -> Result<(), String> {
    const STEP: &str = "no-traffic-before-ready";

    // A bound-port-only node: nothing loaded yet — must NOT be ready.
    let bound_only = NodeReadiness {
        identity_loaded: false,
        views_rehydrated: false,
        wot_root_verified: false,
    };
    if bound_only.is_ready() {
        return Err(fail(
            STEP,
            "a bound-port-only node reported Ready (would serve traffic before readiness)",
        ));
    }

    // A partially-healthy node (identity + views up, WoT root unverified) must
    // STILL be out of service, and the failing condition must be named.
    let partial = NodeReadiness {
        identity_loaded: true,
        views_rehydrated: true,
        wot_root_verified: false,
    };
    match partial.evaluate() {
        ReadinessReport::Ready => {
            return Err(fail(
                STEP,
                "a partially-healthy node reported Ready (readiness gate bypassed)",
            ))
        }
        ReadinessReport::NotReady(cond) => {
            if cond.token() != "wot-root-verified" {
                return Err(fail(
                    STEP,
                    format!("wrong failing condition named: {}", cond.token()),
                ));
            }
        }
    }

    // Only once every substantive condition holds does the node flip Ready.
    let all_ready = NodeReadiness {
        identity_loaded: true,
        views_rehydrated: true,
        wot_root_verified: true,
    };
    if !all_ready.is_ready() {
        return Err(fail(
            STEP,
            "a fully-healthy node did NOT report Ready (would never come into service)",
        ));
    }
    ok(STEP);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sequence_passes() {
        run().expect("rollout sequence holds every invariant");
    }

    #[test]
    fn each_step_passes_individually() {
        step_mixed_version_negotiation().unwrap();
        step_no_data_loss_migration().unwrap();
        step_readiness_gates_cutover().unwrap();
        step_clean_rollback().unwrap();
        step_no_traffic_before_ready().unwrap();
    }
}
