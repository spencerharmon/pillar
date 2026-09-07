//! Build script wiring the SECOND stage of the two-stage frontend build.
//!
//! Stage 1 (nix `packages.<system>.pillar-frontend`, flake.nix) compiles the
//! Yew + WebAssembly portal (crate `pillar-frontend`) with `trunk` into a
//! static asset bundle (`index.html`, `pillar-frontend_bg.wasm`,
//! `pillar-frontend.js`, `portal.css`). Stage 2 — this crate — embeds those
//! assets into the ONE `pillar` binary via `include_bytes!`
//! (see `src/web_serve.rs`), so the running node serves the portal with no
//! filesystem dependency and NO npm/Node anywhere in the build.
//!
//! `include_bytes!` needs a compile-time path. This script resolves the dist
//! directory and exports it as the `PILLAR_FRONTEND_DIST` compile-time env var
//! the source `concat!`s against:
//!   * if the caller sets `PILLAR_FRONTEND_DIST` (the nix `pillar` build points
//!     it at stage 1's `${pillar-frontend}` store path), that path is embedded;
//!   * otherwise the committed in-crate fallback bundle
//!     (`src/frontend_dist/`) is embedded, so a plain `cargo build`/`cargo
//!     test` is self-contained and reproducible without running trunk.

use std::path::PathBuf;

fn main() {
    // Re-run if the override or the committed fallback bundle changes.
    println!("cargo:rerun-if-env-changed=PILLAR_FRONTEND_DIST");
    println!("cargo:rerun-if-changed=src/frontend_dist");

    let dist = match std::env::var_os("PILLAR_FRONTEND_DIST") {
        Some(p) => PathBuf::from(p),
        None => {
            let manifest =
                std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
            PathBuf::from(manifest).join("src").join("frontend_dist")
        }
    };

    // Fail LOUDLY if the required assets are missing — never embed nothing.
    for asset in [
        "index.html",
        "pillar-frontend_bg.wasm",
        "pillar-frontend.js",
        "portal.css",
    ] {
        let p = dist.join(asset);
        assert!(
            p.is_file(),
            "frontend asset {p:?} not found — stage-1 `nix build .#pillar-frontend` \
             bundle (or the committed src/frontend_dist fallback) is incomplete"
        );
    }

    println!("cargo:rustc-env=PILLAR_FRONTEND_DIST={}", dist.display());
}
