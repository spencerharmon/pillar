//! Integration tests for the feature-realness gate.
//!
//! These pin every tooth RED-against-a-fixture and GREEN-against-a-real-one, and
//! run the static scan against the ACTUAL workspace tree (which must be clean).

use pillar_realness_gate::plan_lint::{
    feature_done_without_real_io, parse_plan, same_reconcile_feature_done, verb_claim_offenses,
};
use pillar_realness_gate::scan::{scan_source, scan_workspace, workspace_root_path};

// ---------------------------------------------------------------------------
// Tooth 1 — static realness scan: RED fixtures, GREEN fixtures.
// ---------------------------------------------------------------------------

/// A fixture containing all three offender shapes: a no-op-reports-success
/// reconcile, a stand-in payload used as real data, and a modeled `run` with no
/// syscall. The scan MUST flag it (RED).
const RED_STATIC: &str = r#"
pub struct Controller;

impl Controller {
    /// no-op reconcile: reports success without touching the apiserver.
    pub fn reconcile(&self) -> Result<(), ()> {
        Ok(())
    }

    /// The layer bytes we ship for a workload image.
    pub fn image_layer(&self) -> Vec<u8> {
        b"oci-image-layer-payload".to_vec()
    }

    /// Model a workload run without ever spawning a process.
    pub fn run(&self, name: &str) -> String {
        let modeled = self.run(name); // no real process is spawned
        modeled
    }
}
"#;

/// The GREEN counterpart: a real reconcile with a side effect, a real payload,
/// and a `run` backed by a real process spawn.
const GREEN_STATIC: &str = r#"
use std::process::{Child, Command};

pub struct Controller {
    applied: Vec<String>,
}

impl Controller {
    /// Apply the desired state to the apiserver, recording the mutation.
    pub fn reconcile(&mut self, desired: &str) -> Result<(), std::io::Error> {
        self.applied.push(desired.to_string());
        Ok(())
    }

    /// Spawn the workload as a real child process.
    pub fn run(&self, bin: &str, args: &[String]) -> std::io::Result<Child> {
        Command::new(bin).args(args).spawn()
    }
}
"#;

#[test]
fn tooth1_red_fixture_is_flagged() {
    let offenses = scan_source("fixture/red_static.rs", RED_STATIC);
    assert!(
        offenses.iter().any(|o| o.kind == "noop-reports-success"),
        "no-op-reports-success not flagged: {offenses:?}"
    );
    assert!(
        offenses
            .iter()
            .any(|o| o.kind.starts_with("placeholder-payload")),
        "stand-in payload not flagged: {offenses:?}"
    );
    assert!(
        offenses
            .iter()
            .any(|o| o.kind.starts_with("modeled-verb-no-syscall")),
        "modeled run not flagged: {offenses:?}"
    );
}

#[test]
fn tooth1_green_fixture_is_clean() {
    let offenses = scan_source("fixture/green_static.rs", GREEN_STATIC);
    assert!(
        offenses.is_empty(),
        "the real (green) fixture was wrongly flagged: {offenses:?}"
    );
}

/// THE GATE. The real workspace tree must contain no unannotated
/// placeholder/model-as-feature offense in shipping code.
#[test]
fn workspace_shipping_code_is_real() {
    let root = workspace_root_path();
    let offenses = scan_workspace(&root);
    if !offenses.is_empty() {
        let mut msg = String::from(
            "feature-realness gate: a claimed-delivered feature path contains a \
             model-as-feature offense (a no-op reconcile that reports success, a \
             stand-in/placeholder payload used as real data, or a modeled \
             run/fetch/bind/resolve/forward verb with no real syscall in the same \
             file). Deliver the real effect, or — for a genuine non-security \
             routing hash — annotate the exact line `// non-security: <why>`; \
             `#[cfg(test)]` fixtures are exempt.\n\n",
        );
        for o in &offenses {
            msg.push_str(&format!(
                "  {}:{}  [{}]\n      {}\n",
                o.file, o.line_no, o.kind, o.line
            ));
        }
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// Tooth 2 — verb-claim => acceptance-Check lint.
// ---------------------------------------------------------------------------

#[test]
fn tooth2_flags_verb_claim_with_unit_check_passes_acceptance() {
    let plan = "\
## workload-run-modeled [TODO] <!-- attempts=0 deps=none weight=64 -->
The controller runs the workload as a real process on the node.
Check: cargo test -p pillar-controller

## workload-run-real [TODO] <!-- attempts=1 deps=none weight=64 -->
The controller runs the workload as a real process on the node.
Check: cargo test -p pillar-e2e --test workload_run
";
    let tasks = parse_plan(plan);
    let offenses = verb_claim_offenses(&tasks);
    assert_eq!(offenses.len(), 1, "{offenses:?}");
    assert_eq!(offenses[0].task, "workload-run-modeled");
    assert_eq!(offenses[0].kind, "verb-claim-unit-check");
}

// ---------------------------------------------------------------------------
// Tooth 3a — no attempts=0 feature-DONE.
// ---------------------------------------------------------------------------

#[test]
fn tooth3_rejects_same_reconcile_feature_done() {
    let plan = "\
## workload-run [DONE] <!-- attempts=0 deps=none weight=64 -->
The controller runs the workload as a real process.
Check: cargo test -p pillar-e2e --test workload_run

## doc-only [DONE] <!-- attempts=0 deps=none weight=8 -->
A pure documentation refresh, no observable effect.
check=none
";
    let tasks = parse_plan(plan);
    let offenses = same_reconcile_feature_done(&tasks);
    assert_eq!(offenses.len(), 1, "{offenses:?}");
    assert_eq!(offenses[0].task, "workload-run");
    assert_eq!(offenses[0].kind, "attempts0-feature-done");
}

#[test]
fn tooth3_allows_feature_done_after_attempts() {
    let plan = "\
## workload-run [DONE] <!-- attempts=2 deps=none weight=64 -->
The controller runs the workload as a real process.
Check: cargo test -p pillar-e2e --test workload_run
";
    let tasks = parse_plan(plan);
    assert!(same_reconcile_feature_done(&tasks).is_empty());
}

// ---------------------------------------------------------------------------
// Tooth 3b — feature-DONE whose Check output shows no real I/O.
// ---------------------------------------------------------------------------

#[test]
fn tooth3b_flags_feature_done_with_no_real_io_evidence() {
    let plan = "\
## workload-run [DONE] <!-- attempts=2 deps=none weight=64 -->
runs the workload.
Check: cargo test -p pillar-e2e --test workload_run
";
    let tasks = parse_plan(plan);
    let no_io = vec![(
        "workload-run".to_string(),
        "running 1 test\ntest modeled_run ... ok\ntest result: ok. 1 passed".to_string(),
    )];
    let offenses = feature_done_without_real_io(&tasks, &no_io);
    assert_eq!(offenses.len(), 1, "{offenses:?}");
    assert_eq!(offenses[0].kind, "feature-done-no-real-io");

    let with_io = vec![(
        "workload-run".to_string(),
        "child pid=48213 listening on 127.0.0.1:34871; echoed datagram ok".to_string(),
    )];
    assert!(feature_done_without_real_io(&tasks, &with_io).is_empty());
}
