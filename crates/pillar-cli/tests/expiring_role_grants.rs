//! Acceptance test — `um-expiring-role-grants` (ROI P1 "User management &
//! lifecycle" roadmap C1: expiring role grants).
//!
//! Proves that a role/group binding carrying an ABSOLUTE expiry AUTO-LAPSES
//! fail-closed: once wall-clock passes the expiry the grant contributes
//! nothing to the subject's effective capabilities, and the SAME shared
//! `pillar_rbac::RbacDecider` path every other capability check rides refuses
//! the capability — never a bespoke bypass. This is the Rust refinement of
//! `specs/GrantAuthority.tla`'s `ExpiredGrantNeverAdmits` invariant the C1
//! story is gated on, driven directly over the real
//! `pillar_iam::expiring_grants` engine (`GrantSet`/`GrantOp`,
//! `effective_capabilities_at`, `authorize_capability_at`) the portal/CLI
//! embed — not a mock.
//!
//! The REGRESSION this proves: before this task a role/group binding was a
//! bare, permanent membership (`rbac_bridge`), so a time-limited grant either
//! did not exist or would have had to be manually revoked on a timer; after
//! it, an expired grant is DERIVED-dead at every read (`now > expiry`), so it
//! admits nothing with no per-grant write — and a plain permanent (`None`
//! expiry) binding still behaves exactly as before.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test expiring_role_grants --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::{BTreeMap, BTreeSet};

use pillar_iam::expiring_grants::{
    authorize_capability_at, effective_capabilities_at, GrantOp, GrantSet,
};
use pillar_iam::rbac_bridge::{ManagedGroup, Role};
use pillar_iam::{apply_op, replay, UserOp};
use pillar_rbac::{Capability, Decision, ExplicitGrant, GrantEffect, StepUpPolicy};
use pillar_wot_authority::WotAuthority;

const CRED_MANAGE: &str = "iam:credentials:manage";
const USERS_WRITE: &str = "iam:users:write";

fn roles() -> BTreeMap<String, Role> {
    let mut roles = BTreeMap::new();
    roles.insert(
        "billing-admin".to_owned(),
        Role::new("billing-admin", [CRED_MANAGE]),
    );
    roles.insert(
        "support-role".to_owned(),
        Role::new("support-role", [USERS_WRITE]),
    );
    roles
}

fn groups() -> BTreeMap<String, ManagedGroup> {
    let mut groups = BTreeMap::new();
    groups.insert(
        "support-team".to_owned(),
        ManagedGroup::new("support-team", ["support-role"]),
    );
    groups
}

fn one_user(handle: &str) -> BTreeMap<String, UserRecordAlias> {
    // Re-exported UserRecord via replay; keep the alias local for readability.
    replay([UserOp::Invite {
        handle: handle.to_owned(),
        display_name: handle.to_owned(),
        email: format!("{handle}@example.com"),
        force_password_change: true,
        require_passkey_enrollment: false,
        at: 1,
    }])
}

// `replay` returns `BTreeMap<String, pillar_iam::UserRecord>`; alias so the
// helper signature reads cleanly without importing the concrete type name.
type UserRecordAlias = pillar_iam::UserRecord;

/// A role grant with an absolute expiry auto-lapses: live before the expiry,
/// dead one tick after — and the transition needs no revoke write, only a
/// clock advance (the `ExpiredGrantNeverAdmits` refinement).
#[test]
fn an_expiring_role_grant_auto_lapses_fail_closed() {
    let records = one_user("alice");
    let roles = roles();
    let groups = groups();

    // Admin grants alice `billing-admin` until tick 100.
    let grants = GrantSet::replay([GrantOp::GrantRole {
        handle: "alice".to_owned(),
        name: "billing-admin".to_owned(),
        expires_at: Some(100),
    }]);

    // Before + at the expiry: the capability is present (inclusive-open).
    for now in [1_u64, 50, 100] {
        assert_eq!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", now),
            BTreeSet::from([CRED_MANAGE.to_owned()]),
            "grant must be LIVE at tick {now} (<= expiry)"
        );
    }

    // One tick past the expiry: the grant has auto-lapsed — nothing admitted,
    // no revoke was ever issued.
    assert!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 101).is_empty(),
        "an expired grant must contribute NOTHING — ExpiredGrantNeverAdmits"
    );
}

/// The auto-lapse is enforced through the SAME shared `RbacDecider` every
/// other Pillar capability check uses: a live grant authorises the capability,
/// an expired one is denied fail-closed — never a bespoke, decider-bypassing
/// check.
#[test]
fn expiry_is_enforced_through_the_shared_decider() {
    let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
    let policies: [pillar_rbac::PolicyEvent; 0] = [];
    let step_up = StepUpPolicy::default();
    let records = one_user("alice");
    let roles = roles();
    let groups = groups();
    let grants = GrantSet::replay([GrantOp::GrantRole {
        handle: "alice".to_owned(),
        name: "billing-admin".to_owned(),
        expires_at: Some(100),
    }]);

    let decide = |now: u64| {
        authorize_capability_at(
            &authority,
            &policies,
            &[],
            &records,
            &grants,
            &roles,
            &groups,
            &step_up,
            "alice",
            CRED_MANAGE,
            now,
            None,
        )
    };

    assert_eq!(decide(50), Decision::Allow, "live grant → Allow");
    assert_eq!(
        decide(101),
        Decision::Deny,
        "expired grant → Deny (fail-closed) via the shared decider"
    );

    // A capability nobody's live grant covers denies at every tick — the
    // fail-closed floor is never weakened by the expiry machinery.
    assert_eq!(
        authorize_capability_at(
            &authority,
            &policies,
            &[],
            &records,
            &grants,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:groups:write",
            50,
            None,
        ),
        Decision::Deny,
        "an ungranted capability stays denied"
    );
}

/// An expiring GROUP binding lapses exactly like a role binding, and a
/// permanent (`None` expiry) binding never lapses — the pre-C1 bare-membership
/// semantics preserved as a strict subset.
#[test]
fn group_grants_lapse_and_permanent_grants_persist() {
    let records = one_user("bob");
    let roles = roles();
    let groups = groups();

    let grants = GrantSet::replay([
        // A time-limited group membership (inherits support-role's capability).
        GrantOp::GrantGroup {
            handle: "bob".to_owned(),
            name: "support-team".to_owned(),
            expires_at: Some(10),
        },
    ]);
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "bob", 10),
        BTreeSet::from([USERS_WRITE.to_owned()]),
        "live group grant inherits its attached role's capability"
    );
    assert!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "bob", 11).is_empty(),
        "an expired group binding lapses fail-closed"
    );

    // A permanent grant never lapses.
    let permanent = GrantSet::replay([GrantOp::GrantRole {
        handle: "bob".to_owned(),
        name: "billing-admin".to_owned(),
        expires_at: None,
    }]);
    assert_eq!(
        effective_capabilities_at(&records, &permanent, &roles, &groups, "bob", u64::MAX),
        BTreeSet::from([CRED_MANAGE.to_owned()]),
        "a None-expiry grant is permanent (pre-C1 semantics)"
    );
}

/// An explicit deny still wins over a LIVE expiring grant (fail-closed
/// precedence is preserved), and an early revoke lapses a grant before its
/// expiry.
#[test]
fn explicit_deny_and_early_revoke_both_win() {
    let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
    let policies: [pillar_rbac::PolicyEvent; 0] = [];
    let step_up = StepUpPolicy::default();
    let records = one_user("alice");
    let roles = roles();
    let groups = groups();

    // Live long-lived grant, but an explicit deny present.
    let grants = GrantSet::replay([GrantOp::GrantRole {
        handle: "alice".to_owned(),
        name: "billing-admin".to_owned(),
        expires_at: Some(1_000),
    }]);
    let deny = [ExplicitGrant {
        subject: pillar_core::NodeId::from("alice"),
        capability: Capability::from(CRED_MANAGE),
        effect: GrantEffect::Deny,
    }];
    assert_eq!(
        authorize_capability_at(
            &authority,
            &policies,
            &deny,
            &records,
            &grants,
            &roles,
            &groups,
            &step_up,
            "alice",
            CRED_MANAGE,
            50,
            None,
        ),
        Decision::Deny,
        "an explicit deny wins over a live expiring grant"
    );

    // Early revoke lapses the grant before its expiry.
    let revoked = GrantSet::replay([
        GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(1_000),
        },
        GrantOp::RevokeRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
        },
    ]);
    assert!(
        effective_capabilities_at(&records, &revoked, &roles, &groups, "alice", 10).is_empty(),
        "an explicitly revoked grant admits nothing even before its expiry"
    );
}

/// A grant may be RENEWED (re-issued with a longer expiry): the renewed expiry
/// governs, so the binding stays live past the original deadline — the C1
/// extension leg — while an un-renewed grant lapses on schedule.
#[test]
fn renewal_extends_the_expiry() {
    let records = one_user("alice");
    let roles = roles();
    let groups = groups();

    let grants = GrantSet::replay([
        GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(100),
        },
        GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(500),
        },
    ]);
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 300),
        BTreeSet::from([CRED_MANAGE.to_owned()]),
        "the renewed (longer) expiry governs — grant is live at tick 300"
    );
    assert!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 501).is_empty(),
        "past the renewed expiry the grant still auto-lapses fail-closed"
    );
}

/// The expiring-grant projection composes with the record's existing
/// permanent bindings: a directly-assigned (permanent) role via `UserOp` and a
/// separately expiring grant union while live, and only the expiring one
/// lapses.
#[test]
fn expiring_grant_composes_with_permanent_record_roles() {
    let mut records = one_user("alice");
    // A permanent, directly-assigned role on the record itself.
    apply_op(
        &mut records,
        UserOp::RoleAssign {
            handle: "alice".to_owned(),
            role: "support-role".to_owned(),
            at: 2,
        },
    );
    let roles = roles();
    let groups = groups();

    // Plus an expiring billing-admin grant.
    let grants = GrantSet::replay([GrantOp::GrantRole {
        handle: "alice".to_owned(),
        name: "billing-admin".to_owned(),
        expires_at: Some(100),
    }]);

    // While live: union of both.
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 50),
        BTreeSet::from([CRED_MANAGE.to_owned(), USERS_WRITE.to_owned()]),
        "the permanent record role and the live expiring grant union"
    );
    // After lapse: only the permanent role survives.
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 101),
        BTreeSet::from([USERS_WRITE.to_owned()]),
        "only the expiring grant lapses; the permanent record role persists"
    );
}
