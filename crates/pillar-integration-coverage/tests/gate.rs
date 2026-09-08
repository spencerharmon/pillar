//! Integration tests for the `pillar-integration` coverage gate, pinning the
//! exact fixture behaviors named by the `pillar-integration-coverage-gate`
//! task:
//!
//! * a fixture with a deliberately-orphaned surface (present in the inventory,
//!   claimed by zero scenarios) FAILS Gate 1;
//! * the same fixture with the surface claimed by a scenario carrying a
//!   realness oracle PASSES Gate 1;
//! * a fixture with a scenario skipped past its declared deadline FAILS
//!   Gate 3.

use pillar_integration_coverage::{
    gate1_holds, gate3_holds, orphan_surface_offenses, skip_deadline_offenses, ScenarioClaim,
    ScenarioSkip,
};
use pillar_surface_inventory::{SurfaceEntry, SurfaceKind};

fn inventory_with_one_route(id: &str) -> Vec<SurfaceEntry> {
    vec![SurfaceEntry {
        id: id.to_string(),
        kind: SurfaceKind::HttpRoute,
        signature: format!("GET {id}"),
    }]
}

#[test]
fn orphaned_surface_fixture_fails_gate1() {
    // The surface is present in the inventory but no scenario claims it.
    let inventory = inventory_with_one_route("http:GET /workloads");
    let scenarios: Vec<ScenarioClaim> = vec![];

    assert!(!gate1_holds(&inventory, &scenarios));
    let offenses = orphan_surface_offenses(&inventory, &scenarios);
    assert!(
        offenses
            .iter()
            .any(|o| o.kind == "orphan-surface" && o.detail.contains("http:GET /workloads")),
        "{offenses:?}"
    );
}

#[test]
fn claimed_by_scenario_with_oracle_fixture_passes_gate1() {
    // The identical surface, now claimed by a scenario that names a concrete
    // realness oracle.
    let inventory = inventory_with_one_route("http:GET /workloads");
    let scenarios = vec![ScenarioClaim {
        scenario_id: "workload-runtime-scenario".to_string(),
        claims: vec!["http:GET /workloads".to_string()],
        realness_oracle: Some("spawned-pid".to_string()),
        skip: None,
    }];

    assert!(gate1_holds(&inventory, &scenarios));
    assert!(orphan_surface_offenses(&inventory, &scenarios).is_empty());
}

#[test]
fn scenario_skipped_past_deadline_fails_gate3() {
    let scenarios = vec![ScenarioClaim {
        scenario_id: "chaos-fault-scenario".to_string(),
        claims: vec!["wire:op-x".to_string()],
        realness_oracle: Some("digest-verified-fetch".to_string()),
        skip: Some(ScenarioSkip {
            reason: "upstream flake under investigation".to_string(),
            deadline: "2026-01-01".to_string(),
        }),
    }];

    // "today" is well past the declared deadline.
    let today = "2026-09-07";
    assert!(!gate3_holds(&scenarios, today));
    let offenses = skip_deadline_offenses(&scenarios, today);
    assert_eq!(offenses.len(), 1, "{offenses:?}");
    assert_eq!(offenses[0].kind, "skip-past-deadline");
    assert!(offenses[0].detail.contains("chaos-fault-scenario"));
}

#[test]
fn scenario_skipped_before_deadline_does_not_fail_gate3() {
    let scenarios = vec![ScenarioClaim {
        scenario_id: "soak-stress-scenario".to_string(),
        claims: vec!["wire:op-y".to_string()],
        realness_oracle: Some("listening-port".to_string()),
        skip: Some(ScenarioSkip {
            reason: "flaky under high load, tracked".to_string(),
            deadline: "2099-01-01".to_string(),
        }),
    }];

    assert!(gate3_holds(&scenarios, "2026-09-07"));
}
