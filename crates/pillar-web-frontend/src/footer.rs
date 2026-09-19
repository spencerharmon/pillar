//! The build-stamp footer shown on EVERY portal page — the console, the public
//! entry, AND the login screen — so an operator viewing any page can read
//! precisely which build is live. It mirrors the `beehive vX.Y.Z
//! (<short-commit>)` stamp the beehived web UI carries.
//!
//! [`VERSION`] is the workspace `[workspace.package] version` (compile-time
//! `CARGO_PKG_VERSION`); [`COMMIT`] is the short git sha `build.rs` stamps into
//! `PILLAR_GIT_SHA` (from the nix build's `self.rev`, or `git rev-parse HEAD`
//! for a working-checkout build). Both are compile-time constants, so
//! [`build_stamp`] is pure and host-testable with a plain `cargo test` — no DOM.
//!
//! Versioning discipline (see the hive `LOCALS.md` "pillar" versioning
//! section): the version is PATCH-first — it climbs `0.1.1`, `0.1.2`, … for all
//! normal, forward-compatible work, and the minor/major are bumped ONLY on a
//! deliberate operator decision (a genuine breaking change to the `pillar`
//! binary, which is expected to essentially never happen).

/// The released semantic version of this build (the workspace crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The short commit sha this bundle was built from (stamped by `build.rs`).
pub const COMMIT: &str = env!("PILLAR_GIT_SHA");

/// The one-line build stamp rendered in the footer, e.g.
/// `pillar v0.1.0 (1c4d9d5abc12)`.
pub fn build_stamp() -> String {
    format!("pillar v{VERSION} ({COMMIT})")
}

#[cfg(feature = "yew")]
pub use yew_impl::Footer;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::build_stamp;
    use yew::prelude::*;

    /// A slim, muted footer stamped with [`super::build_stamp`]. Mounted once
    /// in the app [`crate::router::Shell`], AFTER the router `Switch`, so it
    /// renders on every route — the console, the public entry, and the login
    /// screen alike. Styled by the `.pillar-build-footer` rule in
    /// [`crate::styles::global`] (fixed to the viewport corner, `pointer-events:
    /// none`, so it is present on every page without intercepting clicks).
    #[function_component(Footer)]
    pub fn footer() -> Html {
        html! {
            <footer class="pillar-build-footer">{ build_stamp() }</footer>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_stamp_carries_the_real_version_and_a_nonempty_commit() {
        let stamp = build_stamp();
        assert_eq!(
            stamp,
            format!("pillar v{VERSION} ({COMMIT})"),
            "footer stamp format drifted"
        );
        assert!(
            stamp.starts_with(&format!("pillar v{}", env!("CARGO_PKG_VERSION"))),
            "footer stamp must lead with the real crate version: {stamp}"
        );
        assert!(stamp.ends_with(')'));
    }

    #[test]
    fn commit_sha_is_a_real_stamp_never_a_placeholder() {
        // build.rs refuses to emit a blank/`unknown` sha, so the shipped footer
        // can never carry a facade commit. Guard that invariant here.
        // `COMMIT` is a compile-time const (clippy::const_is_empty knows its
        // value) — the assertion is a DELIBERATE anti-facade tripwire, kept so a
        // future change that weakens build.rs's guarantee trips this test.
        #[allow(clippy::const_is_empty)]
        {
            assert!(!COMMIT.is_empty(), "footer commit sha is empty");
        }
        assert_ne!(COMMIT, "unknown", "footer commit sha is a placeholder");
        // A pure-hex sha is displayed as a 12-char short; a dirty-local marker
        // (…-dirty) is allowed to be longer. Either way it must be non-trivial.
        assert!(
            COMMIT.len() >= 7,
            "footer commit sha is implausibly short: {COMMIT}"
        );
    }

    #[test]
    fn version_holds_the_0_1_x_line_until_a_deliberate_bump() {
        // Semver discipline (hive LOCALS.md): pillar starts at 0.1.0 and bumps
        // PATCH forever; the minor/major move ONLY on a deliberate operator
        // decision. This tripwire fails a spurious/accidental minor-or-major
        // bump. When the operator DELIBERATELY bumps, update this expectation
        // together with the LOCALS.md discipline note.
        assert!(
            VERSION.starts_with("0.1."),
            "pillar version is {VERSION}, off the disciplined 0.1.x line. If this \
             is a deliberate operator bump, update this test and the LOCALS.md \
             'pillar' versioning section; otherwise it is an accidental bump."
        );
    }
}
