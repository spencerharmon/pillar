//! Emits a machine-readable inventory (the `pillar-integration/v1` schema
//! from `pillar-integration-spec`) of every external surface pillar actually
//! serves — every CLI verb, HTTP route, manifest kind, and wire-protocol op —
//! read from the REAL, currently-served registries:
//!
//! - CLI verbs: [`pillar_cli::cli_surface::verb_table`] — the exact table
//!   `pillar`'s `main()` dispatches argv through.
//! - HTTP routes: [`pillar_cli::web_serve::http_routes`] — the exact table
//!   the portal's router dispatches from.
//! - Manifest kinds: [`pillar_manifest::SchemaRegistry::kinds`] — the real
//!   per-kind schema registry, populated with the builtin schemas by
//!   [`pillar_manifest::builtin::register_builtin_schemas`] (a caller can
//!   pass any registry, e.g. one with extra/fewer schemas registered).
//! - Wire ops: [`pillar_net::WireOpRegistry`] — the real, registered
//!   request/response protocols (populated for production use by
//!   [`pillar_net::registered_wire_ops`]).
//!
//! There is no separate hand-maintained catalog: an entry appears here
//! if and only if the corresponding real registry currently reports it.

use pillar_manifest::SchemaRegistry;

pub mod surface_parity;

/// The kind of surface a [`SurfaceEntry`] describes — mirrors the
/// `pillar-integration/v1` schema's `VALID_KINDS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceKind {
    /// A CLI verb.
    CliVerb,
    /// An HTTP route.
    HttpRoute,
    /// A manifest kind.
    ManifestKind,
    /// A wire-protocol op.
    WireOp,
}

/// One entry in the emitted surface inventory.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SurfaceEntry {
    /// A stable identifier for this surface.
    pub id: String,
    /// The kind of surface this entry describes.
    pub kind: SurfaceKind,
    /// A human-readable signature (verb usage, method+path, apiVersion/kind,
    /// or wire-protocol shape).
    pub signature: String,
}

/// The `pillar-integration/v1` surface-inventory document — the
/// machine-readable inventory the conformance rig consumes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SurfaceInventory {
    /// Always `"pillar-integration/v1"`.
    pub schema: String,
    /// Every external surface pillar actually serves.
    pub surface_inventory: Vec<SurfaceEntry>,
}

/// The `pillar-integration/v1` schema tag this crate emits.
pub const SCHEMA: &str = "pillar-integration/v1";

/// Every CLI verb the `pillar` binary actually dispatches, read from the
/// real verb table ([`pillar_cli::cli_surface::verb_table`]).
#[must_use]
pub fn cli_verb_entries() -> Vec<SurfaceEntry> {
    pillar_cli::cli_surface::verb_table()
        .iter()
        .map(|v| SurfaceEntry {
            id: format!("cli:{}", v.name),
            kind: SurfaceKind::CliVerb,
            signature: format!("pillar {}", v.name),
        })
        .collect()
}

/// Every HTTP route the portal actually serves, read from the real route
/// table ([`pillar_cli::web_serve::http_routes`]).
#[must_use]
pub fn http_route_entries() -> Vec<SurfaceEntry> {
    pillar_cli::web_serve::http_routes()
        .iter()
        .map(|r| SurfaceEntry {
            id: format!("http:{} {}", r.method, r.path_text()),
            kind: SurfaceKind::HttpRoute,
            signature: format!("{} {}", r.method, r.path_text()),
        })
        .collect()
}

/// Every manifest kind registered in `registry`, read from its real
/// `(apiVersion, kind)` table ([`SchemaRegistry::kinds`]).
#[must_use]
pub fn manifest_kind_entries(registry: &SchemaRegistry) -> Vec<SurfaceEntry> {
    registry
        .kinds()
        .map(|(api_version, kind)| SurfaceEntry {
            id: format!("manifest:{kind}"),
            kind: SurfaceKind::ManifestKind,
            signature: format!("apiVersion={api_version} kind={kind}"),
        })
        .collect()
}

/// Every wire op registered in `registry`, read from the real
/// [`pillar_net::WireOpRegistry`].
#[must_use]
pub fn wire_op_entries(registry: &pillar_net::WireOpRegistry) -> Vec<SurfaceEntry> {
    registry
        .ops()
        .map(|op| SurfaceEntry {
            id: op.id.clone(),
            kind: SurfaceKind::WireOp,
            signature: op.signature.clone(),
        })
        .collect()
}

/// The full surface inventory for a production build: every real CLI verb,
/// HTTP route, and wire op this crate's dependencies register, plus every
/// manifest kind in `manifest_registry` (the caller supplies the registry so
/// tests can exercise an augmented/reduced one without touching production
/// wiring).
#[must_use]
pub fn emit(manifest_registry: &SchemaRegistry) -> SurfaceInventory {
    emit_with(manifest_registry, &pillar_net::registered_wire_ops())
}

/// Like [`emit`], but the caller also supplies the wire-op registry (so a
/// test can exercise an augmented/reduced one without touching production
/// wiring).
#[must_use]
pub fn emit_with(
    manifest_registry: &SchemaRegistry,
    wire_registry: &pillar_net::WireOpRegistry,
) -> SurfaceInventory {
    let mut surface_inventory = Vec::new();
    surface_inventory.extend(cli_verb_entries());
    surface_inventory.extend(http_route_entries());
    surface_inventory.extend(manifest_kind_entries(manifest_registry));
    surface_inventory.extend(wire_op_entries(wire_registry));
    SurfaceInventory {
        schema: SCHEMA.to_owned(),
        surface_inventory,
    }
}

/// The production surface inventory: the builtin manifest-kind schemas
/// ([`pillar_manifest::builtin::register_builtin_schemas`]) plus every real
/// CLI verb / HTTP route / wire op.
#[must_use]
pub fn emit_production() -> SurfaceInventory {
    let mut registry = SchemaRegistry::new();
    pillar_manifest::builtin::register_builtin_schemas(&mut registry);
    emit(&registry)
}
