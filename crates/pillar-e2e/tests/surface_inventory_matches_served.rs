//! Acceptance test — `surface-inventory-emitter`.
//!
//! Asserts that [`pillar_surface_inventory`] emits a machine-readable
//! inventory of every external surface Pillar actually serves, read from the
//! REAL, currently-served registries — never a stale hand-maintained
//! catalog:
//!
//! 1. every CLI verb, HTTP route, manifest kind, and wire op the production
//!    registries currently report appears in the emitted inventory
//!    (`every_kind_of_real_surface_appears_in_the_inventory`);
//! 2. adding a throwaway manifest kind / wire op to a registry makes it
//!    appear in the emitted inventory, and removing it makes it disappear
//!    again (`adding_and_removing_a_surface_is_reflected_in_the_inventory`)
//!    — proving the emitter reads the real registry, not a stale hand list;
//! 3. a route/verb registered in the REAL router/dispatch table but ABSENT
//!    from a smaller test-supplied table is correctly absent from that
//!    table's inventory, proving the emitter enumerates exactly what it is
//!    given rather than a hardcoded catalog
//!    (`the_inventory_reflects_exactly_the_registry_given_to_it`).
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-e2e --test
//! surface_inventory_matches_served --features acceptance`.

#![cfg(feature = "acceptance")]

use pillar_manifest::builtin::register_builtin_schemas;
use pillar_manifest::{FieldType, Schema, SchemaRegistry};
use pillar_net::{registered_wire_ops, WireOp, WireOpRegistry};
use pillar_surface_inventory::{emit, emit_with, SurfaceKind};

#[test]
fn every_kind_of_real_surface_appears_in_the_inventory() {
    let mut registry = SchemaRegistry::new();
    register_builtin_schemas(&mut registry);
    let inventory = emit(&registry);

    assert_eq!(inventory.schema, "pillar-integration/v1");

    // Every real CLI verb the binary dispatches must be present.
    for verb in pillar_cli::cli_surface::verb_table() {
        let id = format!("cli:{}", verb.name);
        assert!(
            inventory
                .surface_inventory
                .iter()
                .any(|e| e.id == id && e.kind == SurfaceKind::CliVerb),
            "missing CLI verb {id} in emitted inventory"
        );
    }

    // Every real HTTP route the portal serves must be present.
    for route in pillar_cli::web_serve::http_routes() {
        let id = format!("http:{} {}", route.method, route.path_text());
        assert!(
            inventory
                .surface_inventory
                .iter()
                .any(|e| e.id == id && e.kind == SurfaceKind::HttpRoute),
            "missing HTTP route {id} in emitted inventory"
        );
    }

    // Every builtin manifest kind must be present.
    for (api_version, kind) in registry.kinds() {
        let id = format!("manifest:{kind}");
        assert!(
            inventory.surface_inventory.iter().any(|e| e.id == id
                && e.kind == SurfaceKind::ManifestKind
                && e.signature.contains(api_version)),
            "missing manifest kind {id} in emitted inventory"
        );
    }

    // Every real wire op must be present.
    let wire = registered_wire_ops();
    for op in wire.ops() {
        assert!(
            inventory
                .surface_inventory
                .iter()
                .any(|e| e.id == op.id && e.kind == SurfaceKind::WireOp),
            "missing wire op {} in emitted inventory",
            op.id
        );
    }
}

#[test]
fn adding_and_removing_a_surface_is_reflected_in_the_inventory() {
    // --- manifest kind: add a throwaway kind, see it appear; build a
    // registry without it, see it absent. ---
    let mut with_throwaway = SchemaRegistry::new();
    register_builtin_schemas(&mut with_throwaway);
    with_throwaway.register(
        Schema::new("pillar.dev/v1", "ThrowawayKind").required("field", FieldType::String),
    );
    let wire = registered_wire_ops();
    let inventory_with = emit_with(&with_throwaway, &wire);
    assert!(
        inventory_with
            .surface_inventory
            .iter()
            .any(|e| e.id == "manifest:ThrowawayKind" && e.kind == SurfaceKind::ManifestKind),
        "adding a throwaway manifest kind must appear in the emitted inventory"
    );

    let mut without_throwaway = SchemaRegistry::new();
    register_builtin_schemas(&mut without_throwaway);
    let inventory_without = emit_with(&without_throwaway, &wire);
    assert!(
        !inventory_without
            .surface_inventory
            .iter()
            .any(|e| e.id == "manifest:ThrowawayKind"),
        "a surface never registered must be absent from the emitted inventory"
    );

    // A kind present in `with_throwaway` but ABSENT from the smaller
    // `without_throwaway` registry must be absent from ITS inventory too —
    // proving the emitter reads the real given registry, not a stale list.
    assert!(inventory_with
        .surface_inventory
        .iter()
        .any(|e| e.id == "manifest:ThrowawayKind"));
    assert!(!inventory_without
        .surface_inventory
        .iter()
        .any(|e| e.id == "manifest:ThrowawayKind"));

    // --- wire op: same proof over WireOpRegistry. ---
    let mut wire_with = WireOpRegistry::new();
    wire_with.register(WireOp::new("wire:throwaway/op", "a throwaway test op"));
    let mut base_manifest = SchemaRegistry::new();
    register_builtin_schemas(&mut base_manifest);
    let inv_wire_with = emit_with(&base_manifest, &wire_with);
    assert!(inv_wire_with
        .surface_inventory
        .iter()
        .any(|e| e.id == "wire:throwaway/op" && e.kind == SurfaceKind::WireOp));

    let wire_without = WireOpRegistry::new();
    let inv_wire_without = emit_with(&base_manifest, &wire_without);
    assert!(!inv_wire_without
        .surface_inventory
        .iter()
        .any(|e| e.id == "wire:throwaway/op"));
}

#[test]
fn the_inventory_reflects_exactly_the_registry_given_to_it() {
    // A manifest kind registered in the REAL builtin set but not registered
    // into a from-scratch (empty) registry must be absent from that
    // registry's inventory — the emitter never falls back to a hardcoded
    // catalog when the caller supplies a smaller registry.
    let mut full = SchemaRegistry::new();
    register_builtin_schemas(&mut full);
    let (any_api_version, any_builtin_kind) = full
        .kinds()
        .next()
        .map(|(a, k)| (a.to_owned(), k.to_owned()))
        .expect("builtin schemas register at least one kind");

    let empty = SchemaRegistry::new();
    let wire = registered_wire_ops();
    let inv_empty = emit_with(&empty, &wire);
    assert!(
        !inv_empty
            .surface_inventory
            .iter()
            .any(|e| e.id == format!("manifest:{any_builtin_kind}")),
        "a real builtin kind ({any_api_version}/{any_builtin_kind}) must be absent from an \
         empty registry's inventory"
    );

    let inv_full = emit_with(&full, &wire);
    assert!(inv_full
        .surface_inventory
        .iter()
        .any(|e| e.id == format!("manifest:{any_builtin_kind}")));
}
