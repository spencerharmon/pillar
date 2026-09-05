//! Acceptance test — `pillar-integration` portal-cli-parity (Rust half).
//!
//! Asserts the machine-checked web-portal / CLI **surface parity** contract
//! ([`pillar_surface_inventory::surface_parity`]), driven off the REAL served
//! CLI-verb and portal-route tables — the same registries the surface-
//! inventory emitter reads — never a hand-maintained checklist:
//!
//! 1. GREEN today: every served CLI verb and every served portal route family
//!    pairs against a currently-served counterpart (or is recorded, with a
//!    reason, as intentionally single-surface), so [`parity_gaps`] is empty
//!    (`parity_is_green_against_the_real_served_surfaces`).
//! 2. RED on a real gap: injecting a CLI verb with no portal counterpart, or a
//!    portal route with no CLI counterpart, into the tables the detector reads
//!    makes [`parity_gaps_of`] report exactly that gap — proving the check is a
//!    real detected diff, not a checklist that silently passes
//!    (`a_cli_verb_without_a_portal_route_is_a_detected_gap`,
//!    `a_portal_route_without_a_cli_verb_is_a_detected_gap`).
//! 3. The in-binary `pillar surface-inventory` emitter
//!    ([`pillar_cli::surface_inventory::emit_json`]) — the black-box source the
//!    shell scenario consumes — agrees with the canonical
//!    `pillar-surface-inventory` emitter, so the JSON the real image serves
//!    cannot drift from the registry-driven inventory
//!    (`the_binary_inventory_matches_the_canonical_emitter`).
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-e2e --test portal_cli_parity
//! --features acceptance`.

#![cfg(feature = "acceptance")]

use pillar_surface_inventory::surface_parity::{parity_gaps, parity_gaps_of, ParityGap};
use pillar_surface_inventory::{cli_verb_entries, http_route_entries, SurfaceEntry, SurfaceKind};

#[test]
fn parity_is_green_against_the_real_served_surfaces() {
    let gaps = parity_gaps();
    assert!(
        gaps.is_empty(),
        "portal-cli parity must be GREEN against the real served surfaces, but found gaps:\n{}",
        gaps.iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn a_cli_verb_without_a_portal_route_is_a_detected_gap() {
    // Feed the detector the real routes but a CLI table with an EXTRA verb
    // that no rule covers: it must report exactly that verb as unmapped.
    let mut cli = cli_verb_entries();
    cli.push(SurfaceEntry {
        id: "cli:frobnicate".to_owned(),
        kind: SurfaceKind::CliVerb,
        signature: "pillar frobnicate".to_owned(),
    });
    let routes = http_route_entries();
    let gaps = parity_gaps_of(&cli, &routes);
    assert!(
        gaps.contains(&ParityGap::CliVerbUnmapped("frobnicate".to_owned())),
        "an added CLI verb with no portal counterpart must be a detected gap; got {gaps:?}"
    );
}

#[test]
fn a_portal_route_without_a_cli_verb_is_a_detected_gap() {
    let cli = cli_verb_entries();
    let mut routes = http_route_entries();
    routes.push(SurfaceEntry {
        id: "http:GET /zzz-orphan-route".to_owned(),
        kind: SurfaceKind::HttpRoute,
        signature: "GET /zzz-orphan-route".to_owned(),
    });
    let gaps = parity_gaps_of(&cli, &routes);
    assert!(
        gaps.contains(&ParityGap::PortalRouteUnmapped(
            "/zzz-orphan-route".to_owned()
        )),
        "an added portal route with no CLI counterpart must be a detected gap; got {gaps:?}"
    );
}

#[test]
fn the_binary_inventory_matches_the_canonical_emitter() {
    // The JSON the real image serves (via `pillar surface-inventory` / the
    // GET /surface-inventory route) is `pillar_cli::surface_inventory`; the
    // canonical registry-driven emitter is `pillar_surface_inventory`. Their
    // entry SETS (by id+kind) must be identical, so the black-box source the
    // shell scenario reads cannot drift from the canonical inventory.
    let binary_json = pillar_cli::surface_inventory::emit_json();
    let binary: serde_json::Value =
        serde_json::from_str(&binary_json).expect("binary inventory is valid JSON");
    assert_eq!(
        binary["schema"], "pillar-integration/v1",
        "binary inventory carries the pillar-integration/v1 schema"
    );

    let mut binary_ids: Vec<String> = binary["surface_inventory"]
        .as_array()
        .expect("surface_inventory is an array")
        .iter()
        .map(|e| {
            format!(
                "{}|{}",
                e["kind"].as_str().unwrap(),
                e["id"].as_str().unwrap()
            )
        })
        .collect();
    binary_ids.sort();

    let canonical = pillar_surface_inventory::emit_production();
    let mut canonical_ids: Vec<String> = canonical
        .surface_inventory
        .iter()
        .map(|e| {
            let kind = match e.kind {
                SurfaceKind::CliVerb => "cli-verb",
                SurfaceKind::HttpRoute => "http-route",
                SurfaceKind::ManifestKind => "manifest-kind",
                SurfaceKind::WireOp => "wire-op",
            };
            format!("{kind}|{}", e.id)
        })
        .collect();
    canonical_ids.sort();

    assert_eq!(
        binary_ids, canonical_ids,
        "the in-binary surface inventory must match the canonical registry-driven emitter"
    );
}
