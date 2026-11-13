//! Real scenario registration checks, not a claim that the full inventory is covered.

use pillar_integration_coverage::{gate1_holds, orphan_surface_offenses, registered_scenarios};
use pillar_surface_inventory::emit_production;
use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn genesis_failover_has_a_script_and_an_unskipped_cid_oracle() {
    let scenarios = registered_scenarios();
    let matching: Vec<_> = scenarios
        .iter()
        .filter(|s| s.scenario_id == "cell-join-genesis-failover")
        .collect();
    assert_eq!(matching.len(), 1, "register genesis failover exactly once");
    let scenario = matching[0];
    assert_eq!(scenario.skip, None, "genesis failover must not be skipped");
    assert_eq!(
        scenario.realness_oracle.as_deref(),
        Some("cid-identical-reads-after-genesis-termination")
    );
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/pillar-integration/scenarios")
        .join(format!("{}.sh", scenario.scenario_id));
    assert!(script.is_file(), "missing scenario: {}", script.display());
}

#[test]
fn registered_claims_exist_in_the_real_served_inventory() {
    let inventory = emit_production().surface_inventory;
    let mut ids = BTreeSet::new();
    for scenario in registered_scenarios() {
        assert!(
            ids.insert(scenario.scenario_id.clone()),
            "duplicate scenario"
        );
        assert!(!scenario.claims.is_empty(), "empty scenario claim");
        let mut claims = BTreeSet::new();
        for claim in &scenario.claims {
            assert!(claims.insert(claim), "duplicate claim: {claim}");
            assert!(
                inventory.iter().any(|entry| &entry.id == claim),
                "{} claims an unserved surface: {claim}",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn removing_genesis_failover_orphans_its_targeted_surfaces() {
    let inventory = emit_production().surface_inventory;
    // Independent of the ledger so deleting a claim cannot shrink the test's scope.
    let targets = [
        "cli:bootstrap",
        "cli:login",
        "cli:config",
        "cli:kv",
        "cli:doc",
        "cli:sql",
        "cli:object",
        "cli:apply",
        "cli:get",
        "http:GET /bootstrap/status",
        "http:POST /bootstrap/create-cell",
        "http:POST /bootstrap/create-user",
        "http:POST /bootstrap/request/node",
        "http:POST /bootstrap/request/approve",
        "http:POST /bootstrap/request/retrieve",
        "http:GET /nonce",
        "http:POST /login",
        "http:POST /portal/profile/cli-config",
        "http:GET /portal/status",
        "http:POST /portal/layout",
        "http:GET /portal/layout",
        "http:POST /portal/obs/dashboard",
        "http:GET /portal/obs/dashboard/get",
    ];
    let targeted: Vec<_> = inventory
        .iter()
        .filter(|entry| targets.contains(&entry.id.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        targeted.len(),
        targets.len(),
        "targeted surfaces must exist"
    );

    let mut scenarios = registered_scenarios();
    assert!(gate1_holds(&targeted, &scenarios));
    assert!(
        !gate1_holds(&inventory, &scenarios),
        "this narrow ledger must not claim whole-inventory coverage"
    );

    scenarios.retain(|s| s.scenario_id != "cell-join-genesis-failover");
    assert!(!gate1_holds(&targeted, &scenarios));
    let offenses = orphan_surface_offenses(&targeted, &scenarios);
    assert_eq!(offenses.len(), targets.len(), "{offenses:?}");
    for target in targets {
        assert!(
            offenses
                .iter()
                .any(|offense| offense.kind == "orphan-surface"
                    && offense.detail.contains(&format!("`{target}`"))),
            "removing the scenario must orphan {target}: {offenses:?}"
        );
    }
}
