//! Acceptance test — `um-expiring-role-grants` (ROI Priority 1 "User
//! management & lifecycle" roadmap C1).
//!
//! Proves role/group bindings with an expiry AUTO-LAPSE fail-closed: once
//! wall-clock passes a binding's expiry it contributes NOTHING to the
//! subject's effective role/group set — no revoke, no sweeper, no further
//! action required. This is the executable image of the
//! `ExpiredGrantNeverAdmits` invariant proven exhaustively by
//! `specs/GrantAuthority.tla`, driven through the real
//! `pillar_cli::expiring_role_grants::ExpiringRoleGrantLedger` API.
//!
//! The REGRESSION this proves: a role/group binding that outlived its
//! expiry (or that an explicit revoke failed to immediately drop) would be
//! a STANDING grant — precisely the "never fail-open" defect this roadmap
//! item exists to prevent. `expired_grant_never_admits()` over the whole
//! ledger must hold at every wall-clock tick, and an expired binding's role/
//! group name must be absent from `effective_roles`/`effective_groups`.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test expiring_role_grants --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::BTreeSet;

use pillar_cli::expiring_role_grants::{ExpiringRoleGrantLedger, RoleGrantError};

#[test]
fn expiring_role_grant_auto_lapses_at_expiry_fail_closed() {
    let mut ledger = ExpiringRoleGrantLedger::new();
    assert!(
        ledger.effective_roles("alice").is_empty(),
        "no ambient role without a live binding"
    );

    // An admin binds alice to billing-admin through tick 100.
    let grant = ledger
        .assign_role("owner", "alice", "billing-admin", 100)
        .unwrap();
    assert!(ledger.admits(grant));
    assert_eq!(
        ledger.effective_roles("alice"),
        BTreeSet::from(["billing-admin".to_owned()]),
        "the binding is live and contributes its role"
    );
    assert!(ledger.expired_grant_never_admits());

    // Through the inclusive expiry the binding is still live.
    ledger.tick_to(100);
    assert!(ledger.admits(grant));
    assert_eq!(
        ledger.effective_roles("alice"),
        BTreeSet::from(["billing-admin".to_owned()])
    );

    // --- AUTO-LAPSE: one tick past expiry the binding silently stops
    // admitting — no revoke was issued, no daemon swept it.
    ledger.tick_to(101);
    assert!(
        !ledger.admits(grant),
        "the binding auto-lapses past its window"
    );
    assert!(
        ledger.effective_roles("alice").is_empty(),
        "an expired role grant contributes nothing, fail-closed"
    );
    assert!(
        ledger.expired_grant_never_admits(),
        "invariant still holds after auto-lapse"
    );

    // The clock never rewinds: winding it back cannot revive the lapsed
    // binding.
    ledger.tick_to(10);
    assert!(
        !ledger.admits(grant),
        "monotone clock: expired binding is never revived"
    );
}

#[test]
fn expiring_group_membership_lapse_drops_inherited_membership() {
    let mut ledger = ExpiringRoleGrantLedger::new();
    let membership = ledger
        .assign_group("owner", "bob", "support-team", 5)
        .unwrap();
    assert_eq!(
        ledger.effective_groups("bob"),
        BTreeSet::from(["support-team".to_owned()])
    );

    ledger.tick_to(6);
    assert!(!ledger.admits(membership));
    assert!(
        ledger.effective_groups("bob").is_empty(),
        "an expired group membership contributes nothing, fail-closed"
    );
    assert!(ledger.expired_grant_never_admits());
}

#[test]
fn explicit_revoke_fail_closes_immediately_without_waiting_for_expiry() {
    let mut ledger = ExpiringRoleGrantLedger::new();
    let grant = ledger
        .assign_role("owner", "carol", "support-role", 1_000)
        .unwrap();
    assert!(ledger.admits(grant));

    ledger.revoke(grant);
    assert!(!ledger.admits(grant), "revocation fail-closes immediately");
    assert!(ledger.effective_roles("carol").is_empty());
    assert!(ledger.expired_grant_never_admits());
}

#[test]
fn expiry_in_the_past_is_refused() {
    let mut ledger = ExpiringRoleGrantLedger::new();
    ledger.tick_to(20);
    match ledger.assign_role("owner", "dave", "role-x", 19) {
        Err(RoleGrantError::ExpiryInPast {
            expiry: 19,
            now: 20,
        }) => {}
        other => panic!("an already-dead binding must be refused, got {other:?}"),
    }
}

#[test]
fn expired_grant_never_admits_holds_at_every_tick_across_a_mixed_ledger() {
    // A mix of role and group bindings with staggered expiries; the whole-
    // ledger invariant must hold at EVERY wall-clock tick, mirroring the
    // TLA+ `ExpiredGrantNeverAdmits` state predicate across the reachable
    // state space.
    let mut ledger = ExpiringRoleGrantLedger::new();
    let short_role = ledger.assign_role("owner", "a", "role-a", 3).unwrap();
    let short_group = ledger.assign_group("owner", "b", "group-b", 6).unwrap();
    let long_role = ledger.assign_role("owner", "c", "role-c", 1_000).unwrap();

    for t in 0..=12 {
        ledger.tick_to(t);
        assert!(
            ledger.expired_grant_never_admits(),
            "ExpiredGrantNeverAdmits must hold at now={t}"
        );
    }

    assert!(!ledger.admits(short_role));
    assert!(!ledger.admits(short_group));
    assert!(ledger.admits(long_role));
    assert!(ledger.effective_roles("a").is_empty());
    assert!(ledger.effective_groups("b").is_empty());
    assert_eq!(
        ledger.effective_roles("c"),
        BTreeSet::from(["role-c".to_owned()])
    );
}
