//! Acceptance test — `um-scoped-delegated-administration` (ROI P1 "User
//! management & lifecycle" roadmap C3).
//!
//! Proves `pillar_iam::scoped_delegated_administration` lets a granter
//! delegate a SUBSET of its own user-admin authority — both which
//! capabilities a delegate may exercise and which
//! [`pillar_iam::ManagedGroup`] of users it may exercise them over — to a
//! subject, gated on `um-grant-authority-spec`'s `GrantNeverExceedsGranter`
//! invariant (`specs/GrantAuthority.tla`): a delegated grant can never
//! exceed the granter's own capabilities, and a re-delegation can never
//! widen scope beyond the granter's own scope. Driven directly over the
//! library `pillar_cli` embeds — the same
//! `pillar_iam`/`pillar_rbac`/`pillar_wot_authority` primitives the portal
//! and CLI surfaces build on — exactly the style `iam_cli.rs` already
//! establishes for the roles/groups/oauth surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test scoped_delegated_administration --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use pillar_core::NodeId;
use pillar_iam::{
    apply_op, delegate_scoped_admin, is_authorized_for_target, replay, GranterScope, ManagedGroup,
    Role, ScopeGrantError, UserOp,
};
use pillar_rbac::{Capability, GrantEffect};

fn allow(subject: &str, capability: &str) -> pillar_rbac::ExplicitGrant {
    pillar_rbac::ExplicitGrant {
        subject: NodeId::from(subject),
        capability: Capability::from(capability),
        effect: GrantEffect::Allow,
    }
}

fn roles() -> BTreeMap<String, Role> {
    let mut roles = BTreeMap::new();
    roles.insert(
        "support-role".to_owned(),
        Role::new("support-role", ["iam:users:write"]),
    );
    roles.insert(
        "billing-admin".to_owned(),
        Role::new("billing-admin", ["iam:credentials:manage"]),
    );
    roles
}

fn groups() -> BTreeMap<String, ManagedGroup> {
    let mut groups = BTreeMap::new();
    groups.insert(
        "emea-support".to_owned(),
        ManagedGroup::new("emea-support", Vec::<String>::new()),
    );
    groups.insert(
        "apac-support".to_owned(),
        ManagedGroup::new("apac-support", Vec::<String>::new()),
    );
    groups
}

/// alice: root admin (unscoped, direct `iam:users:write`).
/// bob: a user in `emea-support`.
/// carol: a user in `apac-support`.
fn users() -> BTreeMap<String, pillar_iam::UserRecord> {
    let mut records = replay([
        UserOp::Invite {
            handle: "bob".to_owned(),
            display_name: "Bob".to_owned(),
            email: "bob@example.com".to_owned(),
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        },
        UserOp::Invite {
            handle: "carol".to_owned(),
            display_name: "Carol".to_owned(),
            email: "carol@example.com".to_owned(),
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        },
    ]);
    apply_op(
        &mut records,
        UserOp::GroupAdd {
            handle: "bob".to_owned(),
            group: "emea-support".to_owned(),
            at: 2,
        },
    );
    apply_op(
        &mut records,
        UserOp::GroupAdd {
            handle: "carol".to_owned(),
            group: "apac-support".to_owned(),
            at: 2,
        },
    );
    records
}

/// End-to-end: alice (unscoped root admin) delegates `iam:users:write`
/// scoped to ONLY `emea-support` to a new regional-support-lead. The
/// delegate can administer bob (in-scope) but is REFUSED for carol
/// (out-of-scope, in `apac-support`) even though both share the same
/// capability requirement — the scope cap, not just the capability cap,
/// gates every target.
#[test]
fn scoped_delegate_administers_only_its_delegated_group() {
    let records = users();
    let roles = roles();
    let groups = groups();
    let extra = [allow("alice", "iam:users:write")];

    let grant = delegate_scoped_admin(
        &records,
        &roles,
        &groups,
        &extra,
        "alice",
        &GranterScope::Unscoped,
        "regional-lead",
        &BTreeSet::from(["iam:users:write".to_owned()]),
        &BTreeSet::from(["emea-support".to_owned()]),
    )
    .expect("alice may delegate a scoped subset of her own authority");

    assert!(
        is_authorized_for_target(&grant, &records, "iam:users:write", "bob"),
        "the delegate must administer bob (in emea-support, the delegated scope)"
    );
    assert!(
        !is_authorized_for_target(&grant, &records, "iam:users:write", "carol"),
        "the delegate must NOT administer carol (apac-support, outside the delegated scope)"
    );
}

/// The core `GrantNeverExceedsGranter` regression: a granter can never
/// delegate a CAPABILITY it does not itself hold, no matter how the request
/// is scoped.
#[test]
fn delegated_capability_can_never_exceed_the_granters_own() {
    let records = users();
    let roles = roles();
    let groups = groups();
    // alice holds only iam:users:write -- never iam:credentials:manage.
    let extra = [allow("alice", "iam:users:write")];

    let err = delegate_scoped_admin(
        &records,
        &roles,
        &groups,
        &extra,
        "alice",
        &GranterScope::Unscoped,
        "regional-lead",
        &BTreeSet::from(["iam:credentials:manage".to_owned()]),
        &BTreeSet::from(["emea-support".to_owned()]),
    )
    .expect_err("a capability alice never held must be refused, not silently granted");
    assert_eq!(
        err,
        ScopeGrantError::CapabilityExceedsGranter("iam:credentials:manage".to_owned())
    );
}

/// A scoped delegate re-delegating further can never WIDEN its own scope —
/// authority strictly descends the delegation lattice, exactly
/// `GrantAuthority.tla`'s cap on every C-tier grant primitive.
#[test]
fn a_scoped_delegate_can_never_widen_scope_when_re_delegating() {
    let records = users();
    let roles = roles();
    let groups = groups();
    let extra = [allow("regional-lead", "iam:users:write")];
    let lead_scope = GranterScope::Scoped(BTreeSet::from(["emea-support".to_owned()]));

    let err = delegate_scoped_admin(
        &records,
        &roles,
        &groups,
        &extra,
        "regional-lead",
        &lead_scope,
        "shift-cover",
        &BTreeSet::from(["iam:users:write".to_owned()]),
        &BTreeSet::from(["emea-support".to_owned(), "apac-support".to_owned()]),
    )
    .expect_err("a scope-bounded delegate cannot re-delegate a wider scope than it holds");
    assert_eq!(
        err,
        ScopeGrantError::ScopeExceedsGranter("apac-support".to_owned())
    );

    // Re-delegating the SAME (or a narrower) scope succeeds.
    let grant = delegate_scoped_admin(
        &records,
        &roles,
        &groups,
        &extra,
        "regional-lead",
        &lead_scope,
        "shift-cover",
        &BTreeSet::from(["iam:users:write".to_owned()]),
        &BTreeSet::from(["emea-support".to_owned()]),
    )
    .expect("a same-or-narrower re-delegation must succeed");
    assert!(is_authorized_for_target(
        &grant,
        &records,
        "iam:users:write",
        "bob"
    ));
    assert!(!is_authorized_for_target(
        &grant,
        &records,
        "iam:users:write",
        "carol"
    ));
}

/// A scope group that does not exist is refused fail-closed, never
/// silently accepted as a phantom scope.
#[test]
fn delegating_to_an_unknown_group_is_refused() {
    let records = users();
    let roles = roles();
    let groups = groups();
    let extra = [allow("alice", "iam:users:write")];

    let err = delegate_scoped_admin(
        &records,
        &roles,
        &groups,
        &extra,
        "alice",
        &GranterScope::Unscoped,
        "regional-lead",
        &BTreeSet::from(["iam:users:write".to_owned()]),
        &BTreeSet::from(["nonexistent-team".to_owned()]),
    )
    .expect_err("a nonexistent scope group must be refused");
    assert_eq!(
        err,
        ScopeGrantError::UnknownGroup("nonexistent-team".to_owned())
    );
}
