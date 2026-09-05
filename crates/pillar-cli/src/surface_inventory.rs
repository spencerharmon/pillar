//! In-process emitter of the `pillar-integration/v1` **surface inventory** —
//! the machine-readable list of every external surface THIS binary actually
//! serves (every CLI verb, HTTP route, manifest kind, and wire-protocol op),
//! read from the SAME live registries the binary dispatches through:
//!
//! - CLI verbs  ← [`crate::cli_surface::verb_table`]
//! - HTTP routes ← [`crate::web_serve::http_routes`]
//! - manifest kinds ← [`pillar_manifest::builtin::register_builtin_schemas`]
//! - wire ops   ← [`pillar_net::registered_wire_ops`]
//!
//! It exists so an EXTERNAL, black-box caller (the `pillar-integration`
//! harness) can obtain the real surface inventory FROM the real published image
//! — via the `surface-inventory` CLI verb (this module's [`emit_json`]) or the
//! `GET /surface-inventory` portal route — and drive the web-portal/CLI parity
//! assertion against it, instead of hand-maintaining a catalog.
//!
//! The shape is byte-identical to `pillar_surface_inventory::SurfaceInventory`
//! (`pillar-surface-inventory` is a thin projection of these SAME registries);
//! that crate's acceptance test asserts the two agree, so this in-binary
//! projection cannot drift from the canonical emitter. It lives HERE (not in
//! `pillar-surface-inventory`) only because `pillar-cli` cannot depend on a
//! crate that depends on it.

use serde::Serialize;

/// One entry in the emitted inventory — the `pillar-integration/v1` entry
/// shape (`id`, `kind`, `signature`).
#[derive(Serialize)]
struct Entry {
    id: String,
    kind: &'static str,
    signature: String,
}

/// The `pillar-integration/v1` document.
#[derive(Serialize)]
struct Inventory {
    schema: &'static str,
    surface_inventory: Vec<Entry>,
}

/// The `pillar-integration/v1` schema tag.
pub const SCHEMA: &str = "pillar-integration/v1";

/// Build every surface entry this binary currently serves, read from the live
/// registries (never a hand-maintained catalog).
fn entries() -> Vec<Entry> {
    let mut out = Vec::new();

    // CLI verbs — the exact table main() dispatches argv through.
    for v in crate::cli_surface::verb_table() {
        out.push(Entry {
            id: format!("cli:{}", v.name),
            kind: "cli-verb",
            signature: format!("pillar {}", v.name),
        });
    }

    // HTTP routes — the exact table the portal router dispatches from.
    for r in crate::web_serve::http_routes() {
        out.push(Entry {
            id: format!("http:{} {}", r.method, r.path_text()),
            kind: "http-route",
            signature: format!("{} {}", r.method, r.path_text()),
        });
    }

    // Manifest kinds — the real builtin schema registry.
    let mut registry = pillar_manifest::SchemaRegistry::new();
    pillar_manifest::builtin::register_builtin_schemas(&mut registry);
    for (api_version, kind) in registry.kinds() {
        out.push(Entry {
            id: format!("manifest:{kind}"),
            kind: "manifest-kind",
            signature: format!("apiVersion={api_version} kind={kind}"),
        });
    }

    // Wire ops — the real registered request/response protocols.
    for op in pillar_net::registered_wire_ops().ops() {
        out.push(Entry {
            id: op.id.clone(),
            kind: "wire-op",
            signature: op.signature.clone(),
        });
    }

    out
}

/// Emit the full `pillar-integration/v1` surface inventory as pretty JSON.
#[must_use]
pub fn emit_json() -> String {
    let inv = Inventory {
        schema: SCHEMA,
        surface_inventory: entries(),
    };
    serde_json::to_string_pretty(&inv).unwrap_or_else(|_| "{}".to_owned())
}
