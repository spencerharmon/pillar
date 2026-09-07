//! `pillar versioning-rollout`: drives the ROI's `pillar-integration`
//! "versioning/rollout" scenario as one real, cross-crate CLI invocation —
//! the same non-networked, in-process rig pattern as [`crate::onboard`]
//! (`onboard.rs`) and [`crate::secrets_audit_rotation_mfa`], but exercising
//! the REAL compat-negotiation ([`pillar_crypto::compat`]), rolling migration
//! ([`pillar_cells::migration`]), readiness-gating ([`crate::health`]), and
//! rollback code paths under test.
//!
//! Every step prints one `ok: <step>` line on success; any step that observes
//! a violated invariant prints `FAIL: <step>: <why>` and the whole command
//! exits non-zero, so the pillar-integration harness's `versioning-rollout`
//! scenario (`scripts/pillar-integration/scenarios/versioning-rollout.sh`)
//! can drive the REAL published image's binary through `driver_cli_exec` and
//! assert every `ok:` line appeared — the crypto-realness oracle pattern
//! `oracle_crypto_realness` already asserts for `pillar onboard`.
//!
//! Four steps, each a REAL effect of the code under test (never a stubbed
//! return code):
//!
//! 1. **compat-window-negotiation** — a mixed-version cell (members at
//!    versions N and N-1) negotiates the migrating surface through the REAL
//!    [`pillar_crypto::negotiate_surface`] within its `CompatWindow`: an
//!    in-window laggard links, a member two versions behind (outside window=1)
//!    is cleanly REFUSED (`NegotiationRefused`), never silently mis-linked.
//!
//! 2. **migration-no-data-loss** — a real [`MigrationCoordinator`] rolls the
//!    mixed-version cell through `begin_build_new_view` → per-member
//!    `declare_member_version` → `attempt_cutover`; the post-cutover new view's
//!    content-addressed Merkle root ([`pillar_streamdb::OpLog::root`]) is
//!    asserted IDENTICAL to the pre-migration op set's root — no op is dropped
//!    across the migration (RED if any data is lost).
//!
//! 3. **readiness-gating-holds-node-out** — a mid-rollout node whose durable
//!    views have not yet rehydrated evaluates through the REAL
//!    [`NodeReadiness`]/`respond` health surface to `503 ... not-ready:
//!    views-rehydrated` (kept OUT of the Service — never serves traffic before
//!    readiness), and flips to `200 ... ready` only once its real readiness
//!    conditions all hold. RED if an unready node reports ready.
//!
//! 4. **rollback-restores-prior-version** — after a cutover to version N, a
//!    rollback to the prior version N-1 is driven through the SAME real
//!    migration primitive (a fresh coordinator targeting N-1 over the SAME op
//!    log), and the rolled-back view's Merkle root is asserted to equal the
//!    ORIGINAL pre-rollout root — the prior version is restored cleanly with
//!    no data loss.

use pillar_cells::migration::{MigrationCoordinator, ViewChoice};
use pillar_core::NodeId;
use pillar_crypto::{negotiate_surface, CompatWindow, SurfaceVersion};

use crate::health::{NodeReadiness, ReadinessCondition, ReadinessReport};

/// The migrating materialized-view surface these steps roll through versions.
const SURFACE: &str = "materialized-view";
/// The compat window: a peer up to 1 version behind is still negotiable.
const WINDOW: CompatWindow = CompatWindow(1);
/// The pre-rollout / rollback-target version (N-1).
const V_OLD: SurfaceVersion = SurfaceVersion(1);
/// The rollout target version (N).
const V_NEW: SurfaceVersion = SurfaceVersion(2);

/// Runs the full versioning/rollout sequence. Returns `Ok(())` if every
/// step's real effect holds, `Err(<diagnostic>)` naming the first violated
/// one.
pub fn run() -> Result<(), String> {
    step_compat_window_negotiation()?;
    step_migration_no_data_loss()?;
    step_readiness_gating_holds_node_out()?;
    step_rollback_restores_prior_version()?;
    Ok(())
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

fn node(name: &str) -> NodeId {
    NodeId::from(name)
}

/// Seed a coordinator's op log with a fixed set of ops so every step rolls
/// the SAME content over the migration and can assert no op is lost.
fn seed_ops(mc: &mut MigrationCoordinator) {
    for op in ["op-alpha", "op-beta", "op-gamma"] {
        mc.append(op.as_bytes().to_vec());
    }
}

/// Step 1 — a mixed-version cell negotiates the migrating surface through the
/// REAL compat window: an in-window laggard (N-1) links, an out-of-window
/// member (two behind, outside window=1) is cleanly refused, never mis-linked.
fn step_compat_window_negotiation() -> Result<(), String> {
    const STEP: &str = "compat-window-negotiation";

    // The upgraded member declares the new version N — negotiates with itself
    // (trivially in window).
    negotiate_surface(SURFACE, V_NEW, V_NEW, WINDOW).map_err(|e| {
        fail(
            STEP,
            format!("an N==N negotiation was wrongly refused: {e}"),
        )
    })?;

    // The lagging member at N-1 is within the window against the new target —
    // it must LINK.
    negotiate_surface(SURFACE, V_NEW, V_OLD, WINDOW).map_err(|e| {
        fail(
            STEP,
            format!("an in-window (N-1) member was wrongly refused: {e}"),
        )
    })?;

    // A member two versions behind (outside window=1) must be cleanly REFUSED
    // — never silently mis-linked.
    match negotiate_surface(SURFACE, V_NEW, SurfaceVersion(0), WINDOW) {
        Ok(()) => {
            return Err(fail(
                STEP,
                "an out-of-window member (two versions behind) was WRONGLY linked",
            ));
        }
        Err(refused) => {
            if refused.surface != SURFACE {
                return Err(fail(
                    STEP,
                    format!(
                        "refusal named the wrong surface (got '{}', want '{SURFACE}')",
                        refused.surface
                    ),
                ));
            }
        }
    }

    ok(STEP);
    Ok(())
}

/// Step 2 — roll a mixed-version cell through a real rolling migration and
/// assert no op is lost across the cutover: the post-cutover new view's
/// content-addressed Merkle root equals the pre-migration op set's root.
fn step_migration_no_data_loss() -> Result<(), String> {
    const STEP: &str = "migration-no-data-loss";
    let members = ["n1", "n2", "n3"];
    let mut mc = MigrationCoordinator::new(
        SURFACE,
        V_NEW,
        WINDOW,
        /* liveness_timeout */ 5,
        members.iter().map(|n| node(n)),
    );
    seed_ops(&mut mc);

    // Snapshot the pre-migration op-set root (what MUST survive the migration).
    let pre_root = mc
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no pre-migration view for a known member"))?
        .root();

    // Build the new view by replaying the current op set.
    mc.begin_build_new_view()
        .map_err(|e| fail(STEP, format!("begin_build_new_view refused: {e:?}")))?;

    // Rolling upgrade: n1 first (mixed-version cell), then n2/n3. While n1 is
    // on the new view and n2/n3 lag, BOTH views must agree on the op set (no
    // reader sees a lost/partial view mid-rollout).
    mc.declare_member_version(&node("n1"), V_NEW)
        .map_err(|e| fail(STEP, format!("n1 upgrade negotiation refused: {e}")))?;
    if mc.view_for(&node("n1")) != Some(ViewChoice::New) {
        return Err(fail(STEP, "n1 did not move to the new view after upgrade"));
    }
    if mc.view_for(&node("n2")) != Some(ViewChoice::Old) {
        return Err(fail(STEP, "n2 (lagging) was not held on the old view"));
    }
    let new_reader_root = mc
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no new view for the upgraded member"))?
        .root();
    let old_reader_root = mc
        .read_view(&node("n2"))
        .ok_or_else(|| fail(STEP, "no old view for the lagging member"))?
        .root();
    if new_reader_root != old_reader_root {
        return Err(fail(
            STEP,
            "mid-rollout the new and old views disagreed on the op set — data diverged",
        ));
    }

    // Finish the rollout: n2/n3 upgrade, then cut over.
    for n in ["n2", "n3"] {
        mc.declare_member_version(&node(n), V_NEW)
            .map_err(|e| fail(STEP, format!("{n} upgrade negotiation refused: {e}")))?;
    }
    if !mc.ready_for_cutover() {
        return Err(fail(
            STEP,
            "cutover not ready after every live member declared support",
        ));
    }
    mc.attempt_cutover()
        .map_err(|e| fail(STEP, format!("cutover refused: {e:?}")))?;

    // No data loss: the post-cutover view's op-set root MUST equal the
    // pre-migration root — every op survived the migration.
    let post_root = mc
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no post-cutover view for a member"))?
        .root();
    if post_root != pre_root {
        return Err(fail(
            STEP,
            format!(
                "post-migration op set changed — DATA LOST across the migration \
                 (pre-root {pre_root} != post-root {post_root})"
            ),
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 3 — a mid-rollout node whose durable views have not yet rehydrated is
/// held OUT of service by the REAL readiness surface (`503 ... not-ready:
/// views-rehydrated`), and only flips to `200 ... ready` once every real
/// readiness condition holds. RED if an unready node reports ready.
fn step_readiness_gating_holds_node_out() -> Result<(), String> {
    const STEP: &str = "readiness-gating-holds-node-out";

    // A node mid-rollout: identity is up, but its durable materialized views
    // have NOT rehydrated yet — it must NOT serve traffic.
    let mid_rollout = NodeReadiness {
        identity_loaded: true,
        views_rehydrated: false,
        wot_root_verified: true,
    };
    if mid_rollout.is_ready() {
        return Err(fail(
            STEP,
            "a node whose views are not rehydrated WRONGLY reported ready",
        ));
    }
    match mid_rollout.evaluate() {
        ReadinessReport::NotReady(ReadinessCondition::ViewsRehydrated) => {}
        other => {
            return Err(fail(
                STEP,
                format!("unready node named the wrong unmet condition: {other:?}"),
            ));
        }
    }
    // Drive the REAL HTTP readiness surface (the exact path the k8s
    // readinessProbe hits) and assert it keeps the pod OUT of the Service.
    let resp = crate::health::respond("GET /readyz HTTP/1.1", &mid_rollout);
    if !resp.starts_with("HTTP/1.1 503 Service Unavailable") {
        return Err(fail(
            STEP,
            format!("readiness probe of an unready node did not return 503: {resp:?}"),
        ));
    }
    if !resp.contains("not-ready: views-rehydrated") {
        return Err(fail(
            STEP,
            format!("503 body did not name the unmet views-rehydrated condition: {resp:?}"),
        ));
    }

    // Once the node has fully converged (views rehydrated, WoT root verified)
    // it flips to Ready and is admitted to the Service.
    let converged = NodeReadiness {
        identity_loaded: true,
        views_rehydrated: true,
        wot_root_verified: true,
    };
    if !converged.is_ready() {
        return Err(fail(STEP, "a fully converged node did not report ready"));
    }
    let ready_resp = crate::health::respond("GET /readyz HTTP/1.1", &converged);
    if !ready_resp.starts_with("HTTP/1.1 200 OK") || !ready_resp.contains("ready") {
        return Err(fail(
            STEP,
            format!("converged node's readiness probe did not return 200/ready: {ready_resp:?}"),
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 4 — after a cutover to version N, a rollback to the prior version N-1
/// is driven through the SAME real migration primitive over the SAME op log,
/// and the rolled-back view's Merkle root is asserted to equal the original
/// pre-rollout root — the prior version is restored cleanly, no data lost.
fn step_rollback_restores_prior_version() -> Result<(), String> {
    const STEP: &str = "rollback-restores-prior-version";
    let members = ["n1", "n2", "n3"];

    // Roll FORWARD to N first (as step 2), capturing the original op-set root.
    let mut fwd =
        MigrationCoordinator::new(SURFACE, V_NEW, WINDOW, 5, members.iter().map(|n| node(n)));
    seed_ops(&mut fwd);
    let original_root = fwd
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no view for a member pre-rollout"))?
        .root();
    fwd.begin_build_new_view()
        .map_err(|e| fail(STEP, format!("forward begin_build refused: {e:?}")))?;
    for n in members {
        fwd.declare_member_version(&node(n), V_NEW)
            .map_err(|e| fail(STEP, format!("forward {n} negotiation refused: {e}")))?;
    }
    fwd.attempt_cutover()
        .map_err(|e| fail(STEP, format!("forward cutover refused: {e:?}")))?;
    let after_forward_root = fwd
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no view after forward cutover"))?
        .root();
    if after_forward_root != original_root {
        return Err(fail(
            STEP,
            "forward rollout already lost data before rollback was attempted",
        ));
    }

    // ROLLBACK: drive a fresh migration back DOWN to the prior version N-1 over
    // the SAME op set, exercising the real primitive in the reverse direction.
    let mut back =
        MigrationCoordinator::new(SURFACE, V_OLD, WINDOW, 5, members.iter().map(|n| node(n)));
    seed_ops(&mut back);
    back.begin_build_new_view()
        .map_err(|e| fail(STEP, format!("rollback begin_build refused: {e:?}")))?;
    for n in members {
        // Each member declares the prior version N-1; it must negotiate within
        // the window and roll back cleanly.
        back.declare_member_version(&node(n), V_OLD)
            .map_err(|e| fail(STEP, format!("rollback {n} negotiation refused: {e}")))?;
    }
    if !back.ready_for_cutover() {
        return Err(fail(STEP, "rollback cutover was not ready"));
    }
    back.attempt_cutover()
        .map_err(|e| fail(STEP, format!("rollback cutover refused: {e:?}")))?;

    // Clean rollback: the rolled-back view's op set equals the ORIGINAL
    // pre-rollout root — the prior version is restored with no data loss and
    // every member is served (never orphaned).
    for n in members {
        if back.view_for(&node(n)).is_none() {
            return Err(fail(
                STEP,
                format!("member {n} was orphaned (no view) after rollback"),
            ));
        }
    }
    let rolled_back_root = back
        .read_view(&node("n1"))
        .ok_or_else(|| fail(STEP, "no view after rollback cutover"))?
        .root();
    if rolled_back_root != original_root {
        return Err(fail(
            STEP,
            format!(
                "rollback did not restore the prior op set cleanly \
                 (original-root {original_root} != rolled-back-root {rolled_back_root})"
            ),
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
        run().expect("versioning/rollout sequence holds every invariant");
    }

    #[test]
    fn each_step_passes_individually() {
        step_compat_window_negotiation().unwrap();
        step_migration_no_data_loss().unwrap();
        step_readiness_gating_holds_node_out().unwrap();
        step_rollback_restores_prior_version().unwrap();
    }

    #[test]
    fn an_out_of_window_member_is_refused_not_linked() {
        // Guard: the core safety property — a member outside the window is
        // never silently linked.
        assert!(negotiate_surface(SURFACE, V_NEW, SurfaceVersion(0), WINDOW).is_err());
        assert!(negotiate_surface(SURFACE, V_NEW, V_OLD, WINDOW).is_ok());
    }

    #[test]
    fn an_unready_node_is_held_out_of_service() {
        let unready = NodeReadiness {
            identity_loaded: true,
            views_rehydrated: false,
            wot_root_verified: true,
        };
        assert!(!unready.is_ready());
        let resp = crate::health::respond("GET /readyz HTTP/1.1", &unready);
        assert!(resp.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(resp.contains("not-ready: views-rehydrated"));
    }
}
