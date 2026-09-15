//! Acceptance test — `um-jit-privilege-elevation` (ROI Priority 1 "User
//! management & lifecycle" roadmap C2).
//!
//! Proves just-in-time privilege elevation is BOUNDED, never standing: an
//! elevation is (a) CAPPED by its granter's own effective authority — it can
//! never exceed its granter — and (b) TIME-BOUNDED — once wall-clock passes
//! its window it AUTO-DROPS with no revoke, no sweeper, no further action, so
//! the subject's effective authority falls back to what it held before. This
//! is the executable image of the `JitElevationIsBounded` invariant proven
//! exhaustively by `specs/GrantAuthority.tla`, driven through the real
//! `pillar_cli::jit_elevation::AuthorityLedger` API.
//!
//! The REGRESSION this proves: a JIT elevation that either exceeded its
//! granter or outlived its expiry would be a PERMANENT privilege escalation —
//! precisely the "standing privilege" this roadmap item exists to prevent.
//! The `jit_elevation_is_bounded()` predicate over the whole ledger must hold
//! at every wall-clock tick, and an expired elevation must contribute nothing
//! to its subject's effective authority.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test jit_privilege_elevation --features acceptance`.

#![cfg(feature = "acceptance")]

use pillar_cli::jit_elevation::{AuthorityLedger, ElevationError, MAX_LEVEL};

#[test]
fn jit_elevation_is_granter_capped_and_auto_drops() {
    // Trust anchor holds the top of the lattice unconditionally; a bare
    // subject holds NO ambient authority.
    let mut ledger = AuthorityLedger::new(Some("owner"));
    assert_eq!(ledger.eff_auth("owner"), MAX_LEVEL);
    assert_eq!(
        ledger.eff_auth("bob"),
        0,
        "no ambient authority without a live grant"
    );

    // alice holds a standing level-4 grant from the owner.
    let alice_grant = ledger.grant("owner", "alice", 4, 1_000).unwrap();
    assert!(ledger.admits(alice_grant));
    assert_eq!(ledger.eff_auth("alice"), 4);

    // --- CAP: alice cannot JIT-elevate bob ABOVE her own effective
    // authority. A request over the cap is refused — a JIT elevation never
    // exceeds its granter (JitElevationIsBounded, clause a).
    match ledger.jit_elevate("alice", "bob", 5, 100) {
        Err(ElevationError::ExceedsGranter {
            requested: 5,
            granter_level: 4,
        }) => {}
        other => panic!("over-cap elevation must be refused, got {other:?}"),
    }
    // A lateral/demoting request (not strictly raising bob) is likewise not an
    // elevation.
    ledger.grant("owner", "bob", 2, 1_000).unwrap();
    match ledger.jit_elevate("alice", "bob", 2, 100) {
        Err(ElevationError::NotAnElevation {
            requested: 2,
            subject_level: 2,
        }) => {}
        other => panic!("a non-raising request must be refused, got {other:?}"),
    }

    // --- BOUNDED WINDOW: alice JIT-elevates bob to level 4 (her cap) through
    // tick 50. It admits WHILE live and raises bob's effective authority.
    let elevation = ledger.jit_elevate("alice", "bob", 4, 50).unwrap();
    assert!(ledger.admits(elevation));
    assert_eq!(
        ledger.eff_auth("bob"),
        4,
        "bob is elevated inside the window"
    );
    assert!(
        ledger.jit_elevation_is_bounded(),
        "invariant holds while the elevation is live"
    );

    // Through the inclusive expiry the elevation is still live.
    ledger.tick_to(50);
    assert!(ledger.admits(elevation));
    assert_eq!(ledger.eff_auth("bob"), 4);

    // --- AUTO-DROP: one tick past expiry the elevation silently stops
    // admitting — no revoke was issued, no daemon swept it. bob falls back to
    // his standing level-2 grant. This is the "never standing" guarantee
    // (JitElevationIsBounded, clause b).
    ledger.tick_to(51);
    assert!(
        !ledger.admits(elevation),
        "the elevation auto-drops past its window"
    );
    assert_eq!(
        ledger.eff_auth("bob"),
        2,
        "bob falls back to standing authority; the elevation is gone"
    );
    assert!(
        ledger.jit_elevation_is_bounded(),
        "invariant still holds after auto-drop"
    );

    // The clock never rewinds: an attempt to wind back cannot revive the
    // expired elevation.
    ledger.tick_to(10);
    assert!(
        !ledger.admits(elevation),
        "monotone clock: expired elevation is never revived"
    );
}

#[test]
fn jit_elevation_is_bounded_holds_at_every_tick() {
    // A mix of grants and JIT elevations with staggered expiries; the whole-
    // ledger invariant must hold at EVERY wall-clock tick, mirroring the TLA+
    // `JitElevationIsBounded` state predicate across the reachable state
    // space.
    let mut ledger = AuthorityLedger::new(Some("owner"));
    ledger.grant("owner", "a", 6, 1_000).unwrap();
    let short = ledger.jit_elevate("a", "b", 6, 3).unwrap();
    let long = ledger.jit_elevate("owner", "c", 8, 9).unwrap();

    for t in 0..=12 {
        ledger.tick_to(t);
        assert!(
            ledger.jit_elevation_is_bounded(),
            "JitElevationIsBounded must hold at now={t}"
        );
    }

    // Both elevations have auto-dropped by the end.
    assert!(!ledger.admits(short));
    assert!(!ledger.admits(long));
    assert_eq!(ledger.eff_auth("b"), 0);
    assert_eq!(ledger.eff_auth("c"), 0);
}

#[test]
fn expiry_in_the_past_is_refused() {
    let mut ledger = AuthorityLedger::new(Some("owner"));
    ledger.tick_to(20);
    match ledger.jit_elevate("owner", "d", 5, 19) {
        Err(ElevationError::ExpiryInPast {
            expiry: 19,
            now: 20,
        }) => {}
        other => panic!("an already-dead elevation must be refused, got {other:?}"),
    }
}
