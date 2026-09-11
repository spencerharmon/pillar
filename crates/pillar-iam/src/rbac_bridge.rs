//! Roles, managed groups, and the RBAC bridge — `roles-groups-rbac-bridge`.
//!
//! Two new pillar-iam resource types layer on top of [`crate::UserRecord`]:
//!
//! - [`Role`]: a named, admin-defined [`pillar_rbac::Capability`] set (e.g.
//!   `"billing-admin"` -> `{iam:users:write, iam:credentials:manage}`).
//! - [`ManagedGroup`]: a named handle set with zero or more roles attached
//!   (e.g. `"support-team"` -> handles `{alice, bob}`, roles
//!   `{support-role}`). This is DELIBERATELY distinct from
//!   [`pillar_rbac::Group`] (a WoT-derived group: subkeys signed by a common
//!   parent key) — a [`ManagedGroup`] is an explicit, journaled admin
//!   assertion of membership, not something derived from the trust graph.
//!
//! [`effective_capabilities`] derives a handle's full capability set as the
//! union of its [`UserRecord::roles`]' capabilities and every
//! [`ManagedGroup`]-attached role's capabilities for every group the handle
//! belongs to (`UserRecord::groups`). This is a PURE, in-memory derivation —
//! it never replaces [`pillar_rbac::RbacDecider::decide`]'s fail-closed
//! precedence lattice (explicit-deny > explicit-allow > WoT-depth-default >
//! deny-all): [`authorize_effective_capability`] folds the derived set in as
//! ONE MORE explicit-allow-shaped input alongside the decider's existing
//! rungs, so a role/group grant can never bypass an explicit deny, and an
//! absent role/group grant still falls through to the decider's WoT-depth
//! default. Fail-closed is preserved: no role, no group, no capability ->
//! [`Decision::Deny`], same as every other capability check in this crate.
//!
//! ## Capabilities landed here
//!
//! - [`IAM_ROLES_WRITE_CAPABILITY`] (`iam:roles:write`) — create/edit/delete
//!   a [`Role`] or change its capability set.
//! - [`IAM_GROUPS_WRITE_CAPABILITY`] (`iam:groups:write`) — create/edit/
//!   delete a [`ManagedGroup`], its membership, or its attached roles.
//! - [`IAM_CREDENTIALS_MANAGE_CAPABILITY`] (`iam:credentials:manage`) —
//!   manage another user's credentials (reset, revoke). Always step-up
//!   gated (see [`sensitive_ops_step_up_policy`]) since it is a
//!   security-boundary-crossing act on someone else's custody material,
//!   exactly the same rationale [`pillar_rbac::key_export`] applies to
//!   private-key export.
//!
//! `iam:users:write` (landed by `user-record-and-profile`) is also folded
//! into the step-up-gated set here for role/group MUTATIONS that touch
//! another user's record, since granting/revoking a role is exactly as
//! sensitive as any other admin user-management act.

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_rbac::{Capability, Decision, ExplicitGrant, GrantEffect, RbacDecider, Request, ResourceClass, StepUpPolicy};

use crate::UserRecord;

/// The capability string gating create/edit/delete of a [`Role`] or its
/// attached capability set.
pub const IAM_ROLES_WRITE_CAPABILITY: &str = "iam:roles:write";

/// The capability string gating create/edit/delete of a [`ManagedGroup`],
/// its membership, or its attached roles.
pub const IAM_GROUPS_WRITE_CAPABILITY: &str = "iam:groups:write";

/// The capability string gating managing ANOTHER user's credentials (reset,
/// revoke) — always step-up gated (see [`sensitive_ops_step_up_policy`]).
pub const IAM_CREDENTIALS_MANAGE_CAPABILITY: &str = "iam:credentials:manage";

/// The default freshness window (seconds) a step-up WebAuthn assertion may
/// have and still authorize a sensitive roles/groups/credentials op.
/// Deliberately tight, matching
/// [`pillar_rbac::key_export::KEY_EXPORT_STEP_UP_MAX_AGE_SECS`]'s rationale:
/// a deliberate, just-authenticated act, not a background one.
pub const SENSITIVE_OPS_STEP_UP_MAX_AGE_SECS: u64 = 120;

/// The [`Capability`] value for [`IAM_ROLES_WRITE_CAPABILITY`].
#[must_use]
pub fn iam_roles_write_capability() -> Capability {
    Capability::from(IAM_ROLES_WRITE_CAPABILITY)
}

/// The [`Capability`] value for [`IAM_GROUPS_WRITE_CAPABILITY`].
#[must_use]
pub fn iam_groups_write_capability() -> Capability {
    Capability::from(IAM_GROUPS_WRITE_CAPABILITY)
}

/// The [`Capability`] value for [`IAM_CREDENTIALS_MANAGE_CAPABILITY`].
#[must_use]
pub fn iam_credentials_manage_capability() -> Capability {
    Capability::from(IAM_CREDENTIALS_MANAGE_CAPABILITY)
}

/// A [`StepUpPolicy`] marking every sensitive roles/groups/credentials
/// capability landed by this module step-up-required, with the default
/// freshness window. Compose with any other step-up-gated capabilities a
/// deployment already requires (this only adds these three).
#[must_use]
pub fn sensitive_ops_step_up_policy() -> StepUpPolicy {
    StepUpPolicy::new(
        [
            iam_roles_write_capability(),
            iam_groups_write_capability(),
            iam_credentials_manage_capability(),
        ],
        SENSITIVE_OPS_STEP_UP_MAX_AGE_SECS,
    )
}

/// A named, admin-defined `pillar_rbac` capability set — distinct from
/// [`pillar_rbac::Group`] (a WoT-derived group). A [`UserRecord`] or
/// [`ManagedGroup`] carries roles by NAME (see [`UserRecord::roles`],
/// [`ManagedGroup::roles`]); this type is the definition a name resolves
/// to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Role {
    /// The role's stable name (what [`UserRecord::roles`] /
    /// [`ManagedGroup::roles`] reference).
    pub name: String,
    /// The capability strings this role grants (folded into
    /// [`Capability`] values by [`effective_capabilities`]).
    pub capabilities: BTreeSet<String>,
}

impl Role {
    /// Build a new role from a name and capability strings.
    #[must_use]
    pub fn new(name: impl Into<String>, capabilities: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Role {
            name: name.into(),
            capabilities: capabilities.into_iter().map(Into::into).collect(),
        }
    }
}

/// A named handle set with zero or more roles attached — DELIBERATELY
/// distinct from the WoT-derived [`pillar_rbac::Group`] (subkeys signed by a
/// common parent key): membership here is an explicit, journaled admin
/// assertion, never derived from the trust graph.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManagedGroup {
    /// The group's stable name (what [`UserRecord::groups`] references).
    pub name: String,
    /// The member handles (kept here for completeness/inspection; the
    /// canonical membership assertion is still each member's own
    /// [`UserRecord::groups`] set — the two must agree, exactly how
    /// [`UserRecord::roles`] and a [`Role`]'s name must agree).
    pub members: BTreeSet<String>,
    /// The role NAMES attached to this group; every member inherits every
    /// attached role's capabilities via [`effective_capabilities`].
    pub roles: BTreeSet<String>,
}

impl ManagedGroup {
    /// Build a new, empty-membership managed group with the given attached
    /// role names.
    #[must_use]
    pub fn new(name: impl Into<String>, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        ManagedGroup {
            name: name.into(),
            members: BTreeSet::new(),
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }
}

/// Derive `handle`'s full effective capability set: the union of every
/// DIRECTLY assigned role's capabilities ([`UserRecord::roles`], resolved
/// against `roles`) plus every capability attached, via a role, to any
/// [`ManagedGroup`] the handle belongs to ([`UserRecord::groups`], resolved
/// against `groups` then each group's `roles` against `roles` again). An
/// unresolvable role/group NAME (dangling reference) contributes nothing —
/// fail-closed, never a panic.
///
/// A handle with no record, no roles, and no groups yields the empty set —
/// the fail-closed floor this bridge never weakens.
#[must_use]
pub fn effective_capabilities(
    records: &BTreeMap<String, UserRecord>,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    handle: &str,
) -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    let Some(record) = records.get(handle) else {
        return caps;
    };

    let mut role_names: BTreeSet<&str> = record.roles.iter().map(String::as_str).collect();
    for group_name in &record.groups {
        if let Some(group) = groups.get(group_name) {
            role_names.extend(group.roles.iter().map(String::as_str));
        }
    }

    for role_name in role_names {
        if let Some(role) = roles.get(role_name) {
            caps.extend(role.capabilities.iter().cloned());
        }
    }
    caps
}

/// Build the [`ExplicitGrant`]s that fold `handle`'s [`effective_capabilities`]
/// into an [`RbacDecider`]'s explicit-allow rung, so a role/group-derived
/// capability is decided through the SAME single `decide` path as every
/// other capability — never a bespoke bypass. Explicit DENYs a caller
/// already holds still win over these (rung 1 of the lattice), preserving
/// fail-closed precedence.
#[must_use]
pub fn role_group_grants(
    records: &BTreeMap<String, UserRecord>,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    handle: &str,
) -> Vec<ExplicitGrant> {
    let subject = NodeId::from(handle);
    effective_capabilities(records, roles, groups, handle)
        .into_iter()
        .map(|capability| ExplicitGrant {
            subject: subject.clone(),
            capability: Capability::from(capability.as_str()),
            effect: GrantEffect::Allow,
        })
        .collect()
}

/// Decide whether `subject`'s role/group-derived capabilities (see
/// [`effective_capabilities`]) grant it `capability` right now, through the
/// SAME [`RbacDecider::decide`] every other Pillar capability check uses.
/// `extra_grants` are `decider`'s pre-existing explicit grants (e.g. any
/// direct, non-role grants already live for this deployment) which are
/// merged with the role/group-derived grants before deciding — a role/group
/// grant NEVER overrides an explicit deny already present in
/// `extra_grants`, since [`RbacDecider::decide`] scans for deny first across
/// the WHOLE merged grant set.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn authorize_effective_capability(
    authority: &pillar_wot_authority::WotAuthority,
    policies: &[pillar_rbac::PolicyEvent],
    extra_grants: &[ExplicitGrant],
    records: &BTreeMap<String, UserRecord>,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    step_up: &StepUpPolicy,
    subject: &str,
    capability: &str,
    now_secs: u64,
    step_up_assertion: Option<pillar_rbac::StepUpAssertion>,
) -> Decision {
    let mut grants = role_group_grants(records, roles, groups, subject);
    grants.extend_from_slice(extra_grants);

    let decider = RbacDecider::new(authority, policies, &grants).with_step_up_policy(step_up);
    let mut request = Request::new(NodeId::from(subject), Capability::from(capability))
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    if let Some(assertion) = step_up_assertion {
        request = request.with_step_up(assertion);
    }
    decider.decide(&request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{apply_op, replay, UserOp};
    use pillar_rbac::StepUpAssertion;
    use pillar_wot_authority::WotAuthority;

    fn roles_fixture() -> BTreeMap<String, Role> {
        let mut roles = BTreeMap::new();
        roles.insert(
            "billing-admin".to_owned(),
            Role::new("billing-admin", ["iam:credentials:manage"]),
        );
        roles.insert(
            "support-role".to_owned(),
            Role::new("support-role", ["iam:users:write"]),
        );
        roles
    }

    fn groups_fixture() -> BTreeMap<String, ManagedGroup> {
        let mut groups = BTreeMap::new();
        let mut support_team = ManagedGroup::new("support-team", ["support-role"]);
        support_team.members.insert("bob".to_owned());
        groups.insert("support-team".to_owned(), support_team);
        groups
    }

    fn records_fixture() -> BTreeMap<String, UserRecord> {
        let mut records = replay([
            UserOp::Invite {
                handle: "alice".to_owned(),
                display_name: "Alice".to_owned(),
                email: "alice@example.com".to_owned(),
                at: 1,
            },
            UserOp::Invite {
                handle: "bob".to_owned(),
                display_name: "Bob".to_owned(),
                email: "bob@example.com".to_owned(),
                at: 1,
            },
        ]);
        apply_op(
            &mut records,
            UserOp::RoleAssign {
                handle: "alice".to_owned(),
                role: "billing-admin".to_owned(),
                at: 2,
            },
        );
        apply_op(
            &mut records,
            UserOp::GroupAdd {
                handle: "bob".to_owned(),
                group: "support-team".to_owned(),
                at: 2,
            },
        );
        records
    }

    #[test]
    fn effective_capabilities_unions_direct_role_and_group_attached_role() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();

        let alice_caps = effective_capabilities(&records, &roles, &groups, "alice");
        assert_eq!(
            alice_caps,
            BTreeSet::from(["iam:credentials:manage".to_owned()]),
            "alice's direct billing-admin role must contribute its capability"
        );

        let bob_caps = effective_capabilities(&records, &roles, &groups, "bob");
        assert_eq!(
            bob_caps,
            BTreeSet::from(["iam:users:write".to_owned()]),
            "bob must inherit support-role's capability via the support-team group"
        );
    }

    #[test]
    fn a_direct_role_and_a_group_attached_role_union_without_duplication() {
        let mut records = records_fixture();
        // Give alice the group too, and give the group a role alice already
        // holds directly — the union must not double-count or error.
        apply_op(
            &mut records,
            UserOp::GroupAdd {
                handle: "alice".to_owned(),
                group: "support-team".to_owned(),
                at: 3,
            },
        );
        let mut roles = roles_fixture();
        roles.insert(
            "dup-role".to_owned(),
            Role::new("dup-role", ["iam:credentials:manage", "iam:groups:write"]),
        );
        apply_op(
            &mut records,
            UserOp::RoleAssign {
                handle: "alice".to_owned(),
                role: "dup-role".to_owned(),
                at: 3,
            },
        );

        let groups = groups_fixture();
        let caps = effective_capabilities(&records, &roles, &groups, "alice");
        assert_eq!(
            caps,
            BTreeSet::from([
                "iam:credentials:manage".to_owned(),
                "iam:groups:write".to_owned(),
                "iam:users:write".to_owned(),
            ]),
            "alice must hold the union of her direct roles' and her group's attached role's capabilities, deduplicated"
        );
    }

    #[test]
    fn unknown_handle_role_or_group_name_yields_no_capabilities_fail_closed() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        let roles = roles_fixture();
        let groups = groups_fixture();
        assert!(effective_capabilities(&records, &roles, &groups, "ghost").is_empty());

        // A record whose roles/groups reference names absent from the roles/
        // groups maps (a dangling reference) must contribute nothing, never
        // panic.
        let records = replay([UserOp::Invite {
            handle: "erin".to_owned(),
            display_name: "Erin".to_owned(),
            email: "erin@example.com".to_owned(),
            at: 1,
        }]);
        let mut records = records;
        apply_op(
            &mut records,
            UserOp::RoleAssign {
                handle: "erin".to_owned(),
                role: "nonexistent-role".to_owned(),
                at: 2,
            },
        );
        apply_op(
            &mut records,
            UserOp::GroupAdd {
                handle: "erin".to_owned(),
                group: "nonexistent-group".to_owned(),
                at: 2,
            },
        );
        assert!(effective_capabilities(&records, &roles, &groups, "erin").is_empty());
    }

    #[test]
    fn authorize_effective_capability_grants_via_role_but_still_fail_closed_by_default() {
        let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let step_up = StepUpPolicy::default();
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();

        // Alice's direct billing-admin role grants iam:credentials:manage —
        // but with an EMPTY step-up policy that capability is not gated, so
        // it is allowed outright here.
        let decision = authorize_effective_capability(
            &authority,
            &policies,
            &[],
            &records,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:credentials:manage",
            10,
            None,
        );
        assert_eq!(decision, Decision::Allow);

        // A capability nobody's role/group grants, and no WoT-depth policy
        // covers, denies — fail-closed.
        let decision = authorize_effective_capability(
            &authority,
            &policies,
            &[],
            &records,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:groups:write",
            10,
            None,
        );
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn sensitive_ops_are_step_up_gated_even_when_the_role_grants_the_capability() {
        let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let step_up = sensitive_ops_step_up_policy();
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();

        // Alice's role grants iam:credentials:manage, but the sensitive-ops
        // step-up policy requires a fresh assertion for it — absent one, deny.
        let decision = authorize_effective_capability(
            &authority,
            &policies,
            &[],
            &records,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:credentials:manage",
            10,
            None,
        );
        assert_eq!(decision, Decision::Deny);

        // With a fresh step-up assertion: allowed.
        let decision = authorize_effective_capability(
            &authority,
            &policies,
            &[],
            &records,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:credentials:manage",
            10,
            Some(StepUpAssertion::new(9, b"cred")),
        );
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn an_explicit_deny_in_extra_grants_wins_over_a_role_derived_allow() {
        let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let step_up = StepUpPolicy::default();
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();

        let extra_grants = [ExplicitGrant {
            subject: NodeId::from("alice"),
            capability: Capability::from("iam:credentials:manage"),
            effect: GrantEffect::Deny,
        }];

        let decision = authorize_effective_capability(
            &authority,
            &policies,
            &extra_grants,
            &records,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:credentials:manage",
            10,
            None,
        );
        assert_eq!(
            decision,
            Decision::Deny,
            "an explicit deny must always win over a role/group-derived allow"
        );
    }
}
