//! Compatibility negotiation over the N-1+ backward-compat window.
//!
//! ROI P1 "Versioning, compatibility & safe rollout" — "Compatibility
//! contract: check, negotiate, N-1+" (operator, 2026-08-31) — refines
//! `specs/VersioningCompat.tla`'s `Negotiate` action and its
//! `NegotiationRefusesIncompatible` / `N1WindowHonored` invariants as
//! executable Rust. [`version`](crate::version) provides the PER-SURFACE
//! stamp + single-sided bounds check (`SurfaceVersion::check_supported`);
//! THIS module provides the TWO-SIDED primitive every wire negotiation
//! (pillar-UDP peers, libp2p transports, HTTP/QUIC ingest clients, cell
//! members) shares: given each party's DECLARED running version of a
//! surface, decide whether they are within the compat window `N` — link if
//! so, cleanly REFUSE (never silently mis-parse/mis-link) if not — plus the
//! complementary startup self-check that stops a binary from shipping a
//! build that would orphan a peer still legitimately inside the window.
//!
//! The two-party check is intentionally a pure, allocation-free function of
//! two [`SurfaceVersion`]s and a [`CompatWindow`] — precisely
//! `VersioningCompat.tla`'s `Negotiate(p, q, s)` guard
//! (`Diff(peerVer[p][s], peerVer[q][s]) <= N`) — so every transport can call
//! it identically regardless of its own wire encoding. [`DeclaredVersions`]
//! layers a per-surface SET on top (a peer/client/cell-member typically
//! declares several independently-versioned surfaces before interoperating),
//! and [`negotiate_all`] requires every surface a caller names to link.

use std::collections::BTreeMap;
use std::fmt;

use crate::version::SurfaceVersion;

/// The backward-compatibility window: the maximum tolerated ABSOLUTE
/// difference between two peers' running versions of the SAME surface for
/// them to still be considered compatible ("N-1+": a peer up to `N` versions
/// behind — or ahead of — the other side is still negotiable).
///
/// Mirrors `specs/VersioningCompat.tla`'s `N` constant exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompatWindow(pub u16);

impl fmt::Display for CompatWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "N={}", self.0)
    }
}

/// Symmetric absolute difference between two versions — the TLA spec's
/// `Diff(a, b) == IF a >= b THEN a - b ELSE b - a`, reused everywhere two
/// declared versions are compared.
#[must_use]
fn diff(a: SurfaceVersion, b: SurfaceVersion) -> u16 {
    a.0.abs_diff(b.0)
}

/// A negotiation attempt on a single surface was cleanly REFUSED because the
/// two declared versions fall outside the compat window — never a silent
/// mis-link and never confused with a decode/parse error
/// ([`VersionError::Malformed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiationRefused {
    /// The surface the refusal occurred on.
    pub surface: &'static str,
    /// This side's declared running version of `surface`.
    pub local: SurfaceVersion,
    /// The peer's declared running version of `surface`.
    pub remote: SurfaceVersion,
    /// The compat window both sides were checked against.
    pub window: CompatWindow,
}

impl fmt::Display for NegotiationRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "compat negotiation refused on surface {:?}: local {} vs remote {} exceeds window {}",
            self.surface, self.local, self.remote, self.window
        )
    }
}

impl std::error::Error for NegotiationRefused {}

/// A required surface neither party declared, so negotiation cannot even be
/// attempted — distinct from [`NegotiationRefused`] (both sides answered but
/// disagreed): this is "one side never spoke for the surface at all".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceNotDeclared {
    /// The surface neither/either party failed to declare.
    pub surface: &'static str,
    /// Whether the LOCAL side is missing the declaration (`false` means the
    /// remote side is the one missing it).
    pub missing_local: bool,
}

impl fmt::Display for SurfaceNotDeclared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} party never declared a version for required surface {:?}",
            if self.missing_local { "local" } else { "remote" },
            self.surface
        )
    }
}

impl std::error::Error for SurfaceNotDeclared {}

/// Either failure mode a multi-surface negotiation ([`negotiate_all`]) can
/// hit: a required surface missing from a declaration, or an actual
/// out-of-window refusal. Both are DISTINCT from a decode/parse error
/// ([`VersionError::Malformed`]) upstream of this module — a peer whose
/// declaration bytes were unparseable never reaches negotiation at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiationError {
    /// A required surface was never declared by one party.
    NotDeclared(SurfaceNotDeclared),
    /// Both parties declared the surface but fall outside the compat window.
    Refused(NegotiationRefused),
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NegotiationError::NotDeclared(e) => e.fmt(f),
            NegotiationError::Refused(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Negotiate compatibility for ONE surface between two declared versions.
///
/// This is exactly `VersioningCompat.tla`'s `Negotiate(p, q, s)` guard:
/// `Ok(())` ("linked") iff `Diff(local, remote) <= window`, and
/// [`NegotiationRefused`] ("refused") otherwise. Symmetric in `local`/`remote`
/// (matching the spec's symmetric `Diff`), so it does not matter which side
/// calls it or in which order.
///
/// # Errors
/// Returns [`NegotiationRefused`] when the two versions differ by more than
/// `window`.
pub fn negotiate_surface(
    surface: &'static str,
    local: SurfaceVersion,
    remote: SurfaceVersion,
    window: CompatWindow,
) -> Result<(), NegotiationRefused> {
    if diff(local, remote) <= window.0 {
        Ok(())
    } else {
        Err(NegotiationRefused {
            surface,
            local,
            remote,
            window,
        })
    }
}

/// One party's declared running version per independently-versioned surface
/// — the wire payload a pillar-UDP peer / libp2p peer / HTTP-QUIC client /
/// cell member exchanges BEFORE interoperating (the ROI's "parties exchange
/// declared per-surface version sets" clause).
///
/// Keyed by a stable surface name (e.g. `"pillar-udp"`, `"pillar-message"`,
/// `"http-ingest-api"`, `"cell-membership"`) rather than a closed enum, so a
/// new surface can be added without touching this module.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredVersions(BTreeMap<&'static str, SurfaceVersion>);

impl DeclaredVersions {
    /// An empty declaration (no surface stamped yet).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare this party's running version of `surface`. A repeated
    /// declaration for the same surface overwrites the prior value.
    pub fn declare(&mut self, surface: &'static str, version: SurfaceVersion) -> &mut Self {
        self.0.insert(surface, version);
        self
    }

    /// The declared version of `surface`, if any.
    #[must_use]
    pub fn get(&self, surface: &str) -> Option<SurfaceVersion> {
        self.0.get(surface).copied()
    }

    /// Every surface declared, in stable (sorted) order.
    pub fn surfaces(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.keys().copied()
    }
}

/// Negotiate EVERY surface in `required` between two [`DeclaredVersions`]
/// sets, the same window applied to each. Fails on the FIRST surface (in
/// `required`'s order) that either party never declared, or that both
/// declared but falls outside `window` — an incompatible pair on ANY needed
/// surface is refused cleanly, matching the ROI's "an incompatible pair
/// (outside the N-1+ window on any needed surface) is refused cleanly"
/// requirement.
///
/// # Errors
/// Returns [`NegotiationError::NotDeclared`] if either party is missing a
/// required surface, or [`NegotiationError::Refused`] if a required surface's
/// declared versions fall outside `window`.
pub fn negotiate_all(
    local: &DeclaredVersions,
    remote: &DeclaredVersions,
    required: &[&'static str],
    window: CompatWindow,
) -> Result<(), NegotiationError> {
    for &surface in required {
        let l = local.get(surface).ok_or(NegotiationError::NotDeclared(SurfaceNotDeclared {
            surface,
            missing_local: true,
        }))?;
        let r = remote
            .get(surface)
            .ok_or(NegotiationError::NotDeclared(SurfaceNotDeclared {
                surface,
                missing_local: false,
            }))?;
        negotiate_surface(surface, l, r, window).map_err(NegotiationError::Refused)?;
    }
    Ok(())
}

/// A binary would drop support for a version that a legitimately in-window
/// peer may still be running — its own startup self-check FAILS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupSelfCheckFailed {
    /// The surface whose support floor would regress.
    pub surface: &'static str,
    /// The current swarm-released version of `surface` this build assumes.
    pub current_release: SurfaceVersion,
    /// The compat window in force.
    pub window: CompatWindow,
    /// The OLDEST version this build would still support (its proposed new
    /// `min`).
    pub proposed_min: SurfaceVersion,
    /// The oldest version that MUST remain supported for the window to hold
    /// (`current_release - window`, floored at 0).
    pub required_floor: SurfaceVersion,
}

impl fmt::Display for StartupSelfCheckFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "startup self-check failed for surface {:?}: this build would only support down to {} \
             but the {} compat window (release {}) requires supporting down to {}",
            self.surface, self.proposed_min, self.window, self.current_release, self.required_floor
        )
    }
}

impl std::error::Error for StartupSelfCheckFailed {}

/// The startup self-check: a binary that would DROP support for a version
/// still legitimately inside the `[current_release - window, current_release]`
/// N-1+ window fails to start.
///
/// Mirrors `specs/VersioningCompat.tla`'s `Bump(s)` guard from the OTHER
/// side: `Bump` never releases a version that would push an already-in-window
/// peer out of it; this is the complementary check run by a BUILD, not a
/// release — a binary must never narrow its own supported floor past the
/// window's requirement, or an in-window peer it used to interoperate with
/// would suddenly be orphaned.
///
/// # Errors
/// Returns [`StartupSelfCheckFailed`] if `proposed_min` is newer than
/// `current_release - window` (i.e. the build would no longer support some
/// version still inside the window).
pub fn startup_self_check(
    surface: &'static str,
    current_release: SurfaceVersion,
    proposed_min: SurfaceVersion,
    window: CompatWindow,
) -> Result<(), StartupSelfCheckFailed> {
    let required_floor = SurfaceVersion(current_release.0.saturating_sub(window.0));
    if proposed_min.0 > required_floor.0 {
        Err(StartupSelfCheckFailed {
            surface,
            current_release,
            window,
            proposed_min,
            required_floor,
        })
    } else {
        Ok(())
    }
}

/// Convenience: run [`startup_self_check`] then, only on success, the
/// existing per-value [`SurfaceVersion::check_supported`] bounds are
/// unaffected — this is purely the additive compat-window gate, layered on
/// top of (never replacing) the surface's own `[min, max]` parse-time check.
///
/// A [`VersionError`] can never arise from this function itself (no bytes are
/// parsed here); the type parameter exists only so callers that thread a
/// single error enum through both checks can convert uniformly.
pub fn require_supported_and_in_window(
    surface: &'static str,
    found: SurfaceVersion,
    min: SurfaceVersion,
    max: SurfaceVersion,
    current_release: SurfaceVersion,
    window: CompatWindow,
) -> Result<(), NegotiationError> {
    // The ordinary per-value bounds check first (distinct parse-vs-unsupported
    // semantics preserved by the caller's own decode path); here we fold an
    // `Unsupported` outcome into the same negotiation-refused shape so a
    // caller that already threads `NegotiationError` has one type to match.
    if found.check_supported(min, max).is_err() {
        return Err(NegotiationError::Refused(NegotiationRefused {
            surface,
            local: max,
            remote: found,
            window,
        }));
    }
    negotiate_surface(surface, found, current_release, window)
        .map_err(NegotiationError::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "test-surface";

    // --- negotiate_surface mirrors Negotiate(p, q, s) exactly ---

    #[test]
    fn within_window_links() {
        let n2 = CompatWindow(2);
        assert!(negotiate_surface(S, SurfaceVersion(5), SurfaceVersion(5), n2).is_ok());
        assert!(negotiate_surface(S, SurfaceVersion(5), SurfaceVersion(3), n2).is_ok());
        assert!(negotiate_surface(S, SurfaceVersion(5), SurfaceVersion(7), n2).is_ok());
    }

    #[test]
    fn outside_window_is_refused_cleanly() {
        let n2 = CompatWindow(2);
        let err = negotiate_surface(S, SurfaceVersion(5), SurfaceVersion(2), n2).unwrap_err();
        assert_eq!(
            err,
            NegotiationRefused {
                surface: S,
                local: SurfaceVersion(5),
                remote: SurfaceVersion(2),
                window: n2,
            }
        );
    }

    #[test]
    fn negotiation_outcome_is_symmetric() {
        // Diff is symmetric, so swapping local/remote must not change the
        // outcome — matching the spec's symmetric Diff(a, b).
        let n1 = CompatWindow(1);
        assert_eq!(
            negotiate_surface(S, SurfaceVersion(3), SurfaceVersion(1), n1),
            negotiate_surface(S, SurfaceVersion(1), SurfaceVersion(3), n1).map_err(|mut e| {
                std::mem::swap(&mut e.local, &mut e.remote);
                e
            })
        );
    }

    #[test]
    fn zero_window_requires_exact_match() {
        let n0 = CompatWindow(0);
        assert!(negotiate_surface(S, SurfaceVersion(4), SurfaceVersion(4), n0).is_ok());
        assert!(negotiate_surface(S, SurfaceVersion(4), SurfaceVersion(5), n0).is_err());
    }

    // --- NegotiationRefusesIncompatible: every refusal really is out-of-window,
    // every link really is in-window (exhaustive over a bounded range) ---

    #[test]
    fn every_outcome_over_bounded_range_matches_the_window_predicate() {
        let window = CompatWindow(2);
        for a in 0u16..=6 {
            for b in 0u16..=6 {
                let outcome = negotiate_surface(S, SurfaceVersion(a), SurfaceVersion(b), window);
                let should_link = a.abs_diff(b) <= window.0;
                assert_eq!(
                    outcome.is_ok(),
                    should_link,
                    "a={a} b={b} window={window:?}"
                );
            }
        }
    }

    // --- DeclaredVersions / negotiate_all ---

    #[test]
    fn negotiate_all_requires_every_named_surface_to_link() {
        let mut local = DeclaredVersions::new();
        local.declare("udp", SurfaceVersion(3)).declare("http", SurfaceVersion(1));
        let mut remote = DeclaredVersions::new();
        remote.declare("udp", SurfaceVersion(3)).declare("http", SurfaceVersion(1));

        assert!(negotiate_all(&local, &remote, &["udp", "http"], CompatWindow(1)).is_ok());
    }

    #[test]
    fn negotiate_all_refuses_on_the_first_incompatible_surface() {
        let mut local = DeclaredVersions::new();
        local.declare("udp", SurfaceVersion(5)).declare("http", SurfaceVersion(1));
        let mut remote = DeclaredVersions::new();
        remote.declare("udp", SurfaceVersion(0)).declare("http", SurfaceVersion(1));

        let err = negotiate_all(&local, &remote, &["udp", "http"], CompatWindow(1)).unwrap_err();
        assert_eq!(
            err,
            NegotiationError::Refused(NegotiationRefused {
                surface: "udp",
                local: SurfaceVersion(5),
                remote: SurfaceVersion(0),
                window: CompatWindow(1),
            })
        );
    }

    #[test]
    fn negotiate_all_reports_a_missing_declaration_distinctly_from_a_refusal() {
        let mut local = DeclaredVersions::new();
        local.declare("udp", SurfaceVersion(1));
        let remote = DeclaredVersions::new(); // never declared "udp"

        let err = negotiate_all(&local, &remote, &["udp"], CompatWindow(2)).unwrap_err();
        assert_eq!(
            err,
            NegotiationError::NotDeclared(SurfaceNotDeclared {
                surface: "udp",
                missing_local: false,
            })
        );
        assert!(!matches!(err, NegotiationError::Refused(_)));
    }

    #[test]
    fn declared_versions_get_returns_none_for_undeclared_surface() {
        let d = DeclaredVersions::new();
        assert_eq!(d.get("anything"), None);
    }

    // --- startup self-check ---

    #[test]
    fn self_check_passes_when_the_proposed_min_still_covers_the_window() {
        // release=10, window=2 => floor=8. Supporting down to 8 (or older) is fine.
        assert!(startup_self_check(
            S,
            SurfaceVersion(10),
            SurfaceVersion(8),
            CompatWindow(2)
        )
        .is_ok());
        assert!(startup_self_check(
            S,
            SurfaceVersion(10),
            SurfaceVersion(5),
            CompatWindow(2)
        )
        .is_ok());
    }

    #[test]
    fn self_check_fails_when_the_binary_would_drop_an_in_window_version() {
        // release=10, window=2 => floor=8. Proposing min=9 drops support for
        // version 8, which is still legitimately in-window.
        let err =
            startup_self_check(S, SurfaceVersion(10), SurfaceVersion(9), CompatWindow(2))
                .unwrap_err();
        assert_eq!(
            err,
            StartupSelfCheckFailed {
                surface: S,
                current_release: SurfaceVersion(10),
                window: CompatWindow(2),
                proposed_min: SurfaceVersion(9),
                required_floor: SurfaceVersion(8),
            }
        );
    }

    #[test]
    fn self_check_floor_saturates_at_zero_near_genesis() {
        // release=1, window=5 => floor saturates at 0, never underflows.
        assert!(startup_self_check(
            S,
            SurfaceVersion(1),
            SurfaceVersion(0),
            CompatWindow(5)
        )
        .is_ok());
    }

    // --- require_supported_and_in_window: layers the window on top of the
    // existing per-value bounds check without replacing it ---

    #[test]
    fn require_supported_and_in_window_rejects_an_out_of_bounds_value_first() {
        let err = require_supported_and_in_window(
            S,
            SurfaceVersion(9),
            SurfaceVersion(1),
            SurfaceVersion(2),
            SurfaceVersion(2),
            CompatWindow(5),
        )
        .unwrap_err();
        assert!(matches!(err, NegotiationError::Refused(_)));
    }

    #[test]
    fn require_supported_and_in_window_rejects_a_value_outside_the_negotiation_window() {
        // found=1 is within [min=1,max=5] but the release is far ahead (10) and
        // the window (1) does not reach back to 1.
        let err = require_supported_and_in_window(
            S,
            SurfaceVersion(1),
            SurfaceVersion(1),
            SurfaceVersion(5),
            SurfaceVersion(10),
            CompatWindow(1),
        )
        .unwrap_err();
        assert_eq!(
            err,
            NegotiationError::Refused(NegotiationRefused {
                surface: S,
                local: SurfaceVersion(1),
                remote: SurfaceVersion(10),
                window: CompatWindow(1),
            })
        );
    }

    #[test]
    fn require_supported_and_in_window_accepts_a_compatible_value() {
        assert!(require_supported_and_in_window(
            S,
            SurfaceVersion(9),
            SurfaceVersion(1),
            SurfaceVersion(10),
            SurfaceVersion(10),
            CompatWindow(2),
        )
        .is_ok());
    }
}
