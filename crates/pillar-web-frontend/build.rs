//! Stamps the exact build commit into a compile-time `PILLAR_GIT_SHA` env the
//! portal footer (`crate::footer`) renders next to the crate version.
//!
//! Two supply paths, in priority order:
//!   1. `PILLAR_GIT_SHA` env — injected by the reproducible nix build
//!      (`flake.nix` sets it on the `pillar-frontend` derivation from the
//!      flake's own `self.rev`). That build deliberately strips `.git` from its
//!      source and its sandbox has no `git` binary, so the commit CANNOT be
//!      read from the tree there; it must be handed in.
//!   2. `git rev-parse HEAD` — for a plain working-checkout build (dev
//!      `trunk serve`, host `cargo test -p pillar-web-frontend`, the CI
//!      `cargo test --all` lane), where `.git` is present and `git` is on PATH.
//!
//! There is deliberately NO sentinel fallback: if neither path yields a real
//! commit the build FAILS loudly rather than stamp a blank/`unknown` sha into
//! the shipped UI.

use std::process::Command;

fn main() {
    // A changed injected sha (nix, per-commit) must re-run this script.
    println!("cargo:rerun-if-env-changed=PILLAR_GIT_SHA");

    let sha = std::env::var("PILLAR_GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(git_head_sha)
        .unwrap_or_else(|| {
            panic!(
                "pillar-web-frontend build.rs: cannot determine the build commit \
                 for the UI footer. Neither PILLAR_GIT_SHA (the nix build injects \
                 it from the flake `self.rev`) nor `git rev-parse HEAD` (a \
                 working-checkout build) yielded a commit. Refusing to stamp a \
                 placeholder sha into the portal."
            )
        });

    println!("cargo:rustc-env=PILLAR_GIT_SHA={}", short_sha(&sha));
}

/// Read `HEAD` from the surrounding git checkout, if any. Returns `None` when
/// `git` is absent or the directory is not a repository (the nix build case,
/// which supplies the sha via the env var instead).
fn git_head_sha() -> Option<String> {
    // Re-run when HEAD moves, best-effort: the crate builds from
    // `crates/pillar-web-frontend`, so the workspace `.git` is two levels up.
    // Missing paths are simply not watched (the nix build has no `.git`).
    let head = "../../.git/HEAD";
    if std::path::Path::new(head).exists() {
        println!("cargo:rerun-if-changed={head}");
    }

    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

/// Normalize to a 12-char short commit for display (matching the beehived
/// footer's `<short-commit>` convention). A pure 40-char hex sha is truncated;
/// any value carrying a non-hex marker (e.g. nix's `<sha>-dirty` for an
/// uncommitted local build) is kept whole so the marker survives and a dirty
/// build is never mistaken for a clean release.
fn short_sha(sha: &str) -> String {
    if sha.len() >= 12 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        sha[..12].to_string()
    } else {
        sha.to_string()
    }
}
