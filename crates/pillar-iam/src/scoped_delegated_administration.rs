//! Scoped delegated administration — `um-scoped-delegated-administration`.
//!
//! Refines `specs/GrantAuthority.tla`'s C3 "scoped delegated administration"
//! story on top of the `roles-groups-rbac-bridge` primitives
//! ([`crate::Role`], [`crate::ManagedGroup`], [`crate::effective_capabilities`]).
//! A [`ScopedGrant`] lets a granter delegate a SUBSET of its own user-admin
//! authority — both which CAPABILITIES the delegate may exercise and which
//! [`crate::ManagedGroup`]s of users it may exercise them over — to a
//! subject, and [`delegate_scoped_admin`] enforces the SAME
//! `GrantNeverExceedsGranter` invariant the TLA+ spec proves for every other
//! C-tier grant primitive:
//!
//! - **Capability cap**: every capability in the delegated set must already
//!   be in the granter's own [`crate::effective_capabilities`] (folded with
//!   any extra direct grants the host supplies, e.g. an unconditional
//!   `iam:users:write`). A granter can never hand out a capability it does
//!   not itself hold.
//! - **Scope cap**: every group named in the delegated scope must already be
//!   in the granter's OWN administrable scope (see [`GranterScope`]) — an
//!   [`GranterScope::Unscoped`] granter (one holding the capability outright,
//!   not via a prior scoped delegation) may scope to any group that exists;
//!   a [`GranterScope::Scoped`] granter (one whose own authority is itself a
//!   [`ScopedGrant`]) may only re-delegate a SUBSET of its own scope groups
//!   — delegation can never widen scope, exactly as a grant can never exceed
//!   its granter's level in `GrantAuthority.tla`.
//!
//! [`is_authorized_for_target`] then decides whether a concrete
//! `(subject, capability, target handle)` triple is admitted by a
//! [`ScopedGrant`]: the capability must be in the grant's delegated set AND
//! the target handle must belong (via [`crate::UserRecord::groups`]) to at
//! least one of the grant's scope groups — so a scoped admin's authority
//! never reaches a user outside its delegated groups, no matter how broad
//! its capability set.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::rbac_bridge::{effective_capabilities, ManagedGroup, Role};
use crate::UserRecord;
use pillar_rbac::ExplicitGrant;

/// A granter's OWN administrable scope, at the moment it attempts to
/// delegate. `Unscoped` means the granter holds its user-admin authority
/// directly (not itself the subject of a prior [`ScopedGrant`]) and may
/// delegate any subset of the groups that exist. `Scoped` means the
/// granter's own authority is already bounded to the named groups (it is
/// itself a scoped delegate), so it may only re-delegate a SUBSET of that
/// same set — never widen it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GranterScope {
    /// The granter holds full (unscoped) user-admin authority.
    Unscoped,
    /// The granter's own authority is bounded to exactly these groups.
    Scoped(BTreeSet<String>),
}

/// A delegated grant of a SUBSET of user-admin authority, scoped to a set of
/// [`ManagedGroup`]s. Never mutated in place — a re-delegation, revocation,
/// or widening request always produces a fresh [`ScopedGrant`] via
/// [`delegate_scoped_admin`] (or is refused), mirroring the grow-only,
/// re-derive-don't-mutate discipline `specs/GrantAuthority.tla` models.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedGrant {
    /// The handle that issued this grant.
    pub granter: String,
    /// The handle this grant delegates authority to.
    pub subject: String,
    /// The capability strings this grant admits — always a subset of the
    /// granter's own effective capabilities at issue time.
    pub capabilities: BTreeSet<String>,
    /// The [`ManagedGroup`] names this grant's authority is scoped to —
    /// always a subset of the granter's own administrable scope at issue
    /// time.
    pub scope_groups: BTreeSet<String>,
}

/// Why a [`delegate_scoped_admin`] request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeGrantError {
    /// A requested capability is not in the granter's own effective
    /// capability set — a grant may never exceed its granter
    /// (`GrantNeverExceedsGranter`).
    CapabilityExceedsGranter(String),
    /// A requested scope group is not in the granter's own administrable
    /// scope — scope may never widen across a delegation hop.
    ScopeExceedsGranter(String),
    /// A requested scope group name does not resolve to any known
    /// [`ManagedGroup`] — fail-closed, never a phantom scope.
    UnknownGroup(String),
    /// The request named zero capabilities or zero scope groups — an
    /// unscoped-and-uncapabilitied "grant" is meaningless and refused
    /// rather than silently admitting nothing forever.
    EmptyRequest,
}

impl std::fmt::Display for ScopeGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeGrantError::CapabilityExceedsGranter(c) => {
                write!(f, "capability '{c}' exceeds the granter's own authority")
            }
            ScopeGrantError::ScopeExceedsGranter(g) => {
                write!(f, "scope group '{g}' exceeds the granter's own scope")
            }
            ScopeGrantError::UnknownGroup(g) => write!(f, "unknown managed group '{g}'"),
            ScopeGrantError::EmptyRequest => {
                write!(f, "a scoped grant must name at least one capability and one scope group")
            }
        }
    }
}

impl std::error::Error for ScopeGrantError {}

/// Attempt to delegate a SUBSET of `granter`'s own user-admin authority to
/// `subject`, structurally capped exactly like `GrantAuthority.tla`'s
/// `Grant` action: every requested capability must already be in the
/// granter's [`effective_capabilities`] (folded with `extra_granter_caps` —
/// e.g. a host-supplied direct `iam:users:write` grant that predates any
/// role/group bridge), and every requested scope group must already be
/// within `granter_scope`. Refuses (never silently truncates) on the first
/// violation, an unknown group, or an empty request.
#[allow(clippy::too_many_arguments)]
pub fn delegate_scoped_admin(
    records: &BTreeMap<String, UserRecord>,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    extra_granter_caps: &[ExplicitGrant],
    granter: &str,
    granter_scope: &GranterScope,
    subject: &str,
    requested_capabilities: &BTreeSet<String>,
    requested_scope_groups: &BTreeSet<String>,
) -> Result<ScopedGrant, ScopeGrantError> {
    if requested_capabilities.is_empty() || requested_scope_groups.is_empty() {
        return Err(ScopeGrantError::EmptyRequest);
    }

    // Capability cap: the union of the granter's role/group-derived
    // capabilities and any extra direct grants the host supplies.
    let mut granter_caps = effective_capabilities(records, roles, groups, granter);
    for grant in extra_granter_caps {
        if grant.subject.0 == granter && matches!(grant.effect, pillar_rbac::GrantEffect::Allow) {
            granter_caps.insert(grant.capability.0.clone());
        }
    }
    for capability in requested_capabilities {
        if !granter_caps.contains(capability) {
            return Err(ScopeGrantError::CapabilityExceedsGranter(capability.clone()));
        }
    }

    // Every requested group must actually exist.
    for group_name in requested_scope_groups {
        if !groups.contains_key(group_name) {
            return Err(ScopeGrantError::UnknownGroup(group_name.clone()));
        }
    }

    // Scope cap: an Unscoped granter may scope to any existing group; a
    // Scoped granter may only re-delegate a subset of its own scope.
    if let GranterScope::Scoped(granter_groups) = granter_scope {
        for group_name in requested_scope_groups {
            if !granter_groups.contains(group_name) {
                return Err(ScopeGrantError::ScopeExceedsGranter(group_name.clone()));
            }
        }
    }

    Ok(ScopedGrant {
        granter: granter.to_owned(),
        subject: subject.to_owned(),
        capabilities: requested_capabilities.clone(),
        scope_groups: requested_scope_groups.clone(),
    })
}

/// Decide whether `grant` admits `capability` against `target_handle`: the
/// capability must be in the grant's delegated set AND the target handle
/// must belong (via [`UserRecord::groups`]) to at least one of the grant's
/// scope groups. Fail-closed: a target with no record, or belonging to none
/// of the grant's scope groups, is refused regardless of capability.
#[must_use]
pub fn is_authorized_for_target(
    grant: &ScopedGrant,
    records: &BTreeMap<String, UserRecord>,
    capability: &str,
    target_handle: &str,
) -> bool {
    if !grant.capabilities.contains(capability) {
        return false;
    }
    let Some(target) = records.get(target_handle) else {
        return false;
    };
    target
        .groups
        .iter()
        .any(|g| grant.scope_groups.contains(g))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{apply_op, replay, UserOp};

    fn roles_fixture() -> BTreeMap<String, Role> {
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

    fn groups_fixture() -> BTreeMap<String, ManagedGroup> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "support-team".to_owned(),
            ManagedGroup::new("support-team", Vec::<String>::new()),
        );
        groups.insert(
            "billing-team".to_owned(),
            ManagedGroup::new("billing-team", Vec::<String>::new()),
        );
        groups
    }

    fn records_fixture() -> BTreeMap<String, UserRecord> {
        let mut records = replay([
            UserOp::Invite {
                handle: "carol".to_owned(),
                display_name: "Carol".to_owned(),
                email: "carol@example.com".to_owned(),
                force_password_change: true,
                require_passkey_enrollment: false,
                at: 1,
            },
            UserOp::Invite {
                handle: "dave".to_owned(),
                display_name: "Dave".to_owned(),
                email: "dave@example.com".to_owned(),
                force_password_change: true,
                require_passkey_enrollment: false,
                at: 1,
            },
        ]);
        apply_op(
            &mut records,
            UserOp::GroupAdd {
                handle: "carol".to_owned(),
                group: "support-team".to_owned(),
                at: 2,
            },
        );
        apply_op(
            &mut records,
            UserOp::GroupAdd {
                handle: "dave".to_owned(),
                group: "billing-team".to_owned(),
                at: 2,
            },
        );
        records
    }

    fn allow(subject: &str, capability: &str) -> ExplicitGrant {
        ExplicitGrant {
            subject: pillar_core::NodeId::from(subject),
            capability: pillar_rbac::Capability::from(capability),
            effect: pillar_rbac::GrantEffect::Allow,
        }
    }

    #[test]
    fn unscoped_granter_may_delegate_a_subset_of_its_own_capabilities_and_scope() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let extra = [allow("alice", "iam:users:write")];

        let grant = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "alice",
            &GranterScope::Unscoped,
            "eve",
            &BTreeSet::from(["iam:users:write".to_owned()]),
            &BTreeSet::from(["support-team".to_owned()]),
        )
        .expect("alice may delegate a subset of her own authority");

        assert!(is_authorized_for_target(&grant, &records, "iam:users:write", "carol"));
        assert!(
            !is_authorized_for_target(&grant, &records, "iam:users:write", "dave"),
            "dave is outside the delegated scope (billing-team, not support-team)"
        );
    }

    #[test]
    fn a_grant_can_never_exceed_the_granters_own_capabilities() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        // alice holds only iam:users:write, never iam:credentials:manage.
        let extra = [allow("alice", "iam:users:write")];

        let err = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "alice",
            &GranterScope::Unscoped,
            "eve",
            &BTreeSet::from(["iam:credentials:manage".to_owned()]),
            &BTreeSet::from(["support-team".to_owned()]),
        )
        .expect_err("a capability alice does not hold must be refused");
        assert_eq!(
            err,
            ScopeGrantError::CapabilityExceedsGranter("iam:credentials:manage".to_owned())
        );
    }

    #[test]
    fn a_scoped_granter_can_never_widen_scope_on_re_delegation() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let extra = [allow("eve", "iam:users:write")];
        let eve_scope = GranterScope::Scoped(BTreeSet::from(["support-team".to_owned()]));

        // eve (herself scoped to support-team only) tries to re-delegate to
        // frank over billing-team too -- must be refused: authority strictly
        // descends the lattice, exactly GrantAuthority.tla's cap.
        let err = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "eve",
            &eve_scope,
            "frank",
            &BTreeSet::from(["iam:users:write".to_owned()]),
            &BTreeSet::from(["support-team".to_owned(), "billing-team".to_owned()]),
        )
        .expect_err("eve cannot widen scope beyond her own support-team-only grant");
        assert_eq!(
            err,
            ScopeGrantError::ScopeExceedsGranter("billing-team".to_owned())
        );

        // A same-or-narrower re-delegation succeeds.
        let grant = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "eve",
            &eve_scope,
            "frank",
            &BTreeSet::from(["iam:users:write".to_owned()]),
            &BTreeSet::from(["support-team".to_owned()]),
        )
        .expect("a same-or-narrower re-delegation must succeed");
        assert!(is_authorized_for_target(&grant, &records, "iam:users:write", "carol"));
    }

    #[test]
    fn an_unknown_scope_group_is_refused() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let extra = [allow("alice", "iam:users:write")];

        let err = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "alice",
            &GranterScope::Unscoped,
            "eve",
            &BTreeSet::from(["iam:users:write".to_owned()]),
            &BTreeSet::from(["nonexistent-team".to_owned()]),
        )
        .expect_err("a nonexistent group must be refused, not silently accepted");
        assert_eq!(err, ScopeGrantError::UnknownGroup("nonexistent-team".to_owned()));
    }

    #[test]
    fn an_empty_request_is_refused() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let extra = [allow("alice", "iam:users:write")];

        let err = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "alice",
            &GranterScope::Unscoped,
            "eve",
            &BTreeSet::new(),
            &BTreeSet::from(["support-team".to_owned()]),
        )
        .expect_err("an empty capability set must be refused");
        assert_eq!(err, ScopeGrantError::EmptyRequest);
    }

    #[test]
    fn scoped_grant_never_authorizes_a_target_outside_its_scope_groups() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let extra = [allow("alice", "iam:users:write")];

        let grant = delegate_scoped_admin(
            &records,
            &roles,
            &groups,
            &extra,
            "alice",
            &GranterScope::Unscoped,
            "eve",
            &BTreeSet::from(["iam:users:write".to_owned()]),
            &BTreeSet::from(["support-team".to_owned()]),
        )
        .expect("delegation succeeds");

        // A handle with no record at all is refused, fail-closed.
        assert!(!is_authorized_for_target(&grant, &records, "iam:users:write", "ghost"));
        // A capability outside the grant's set is refused even for an
        // in-scope target.
        assert!(!is_authorized_for_target(&grant, &records, "iam:credentials:manage", "carol"));
    }
}
