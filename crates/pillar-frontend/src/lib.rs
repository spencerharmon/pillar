//! The `pillar` web portal foundation — a Yew (client-side-rendered) single
//! page application styled with `stylist` (CSS-in-Rust). `trunk` compiles
//! this crate to `wasm32-unknown-unknown`, runs `wasm-bindgen` to emit the JS
//! glue, and bundles the stylist-emitted CSS — producing the wasm/js/css
//! static assets a two-stage nix build embeds into the one `pillar` binary.
//! No npm/Node is involved at any stage.
//!
//! The actual app — the login screen, the auth session, the client router,
//! and every portal panel (identity, members, sessions, trust-graph,
//! custody, request-inbox, resource/workload, topology, observability) —
//! lives in the host-testable `pillar-web-frontend` crate; this crate's only
//! job is to mount its `Shell` to the wasm entrypoint.

/// The wasm entrypoint `trunk`/`wasm-bindgen` invokes on load: mount the
/// portal app shell (`pillar-web-frontend::router::Shell`) to the document
/// body.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    yew::Renderer::<pillar_web_frontend::router::Shell>::new().render();
}

