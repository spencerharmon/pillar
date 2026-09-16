//! Expiring role/group grants — `um-expiring-role-grants` (ROI P1 "User
//! management & lifecycle" roadmap C1).
//!
//! The [`rbac_bridge`](crate::rbac_bridge) models a role/group binding as a
//! bare membership: a name is in [`UserRecord::roles`](crate::UserRecord::roles)
//! /[`UserRecord::groups`](crate::UserRecord::groups) or it is not, and it
//! stays until an admin explicitly revokes it. This module layers the C1
//! story on top: a role or group binding may carry an ABSOLUTE expiry tick,
//! after which it AUTO-LAPSES — it contributes nothing to the subject's
//! effective capabilities, forever, with no per-grant revoke write.
//!
//! This is the Rust refinement of `specs/GrantAuthority.tla`'s
//! `ExpiredGrantNeverAdmits`: a grant whose `expiry` has passed is absent from
//! the subject's live-grant set and therefore can never raise its authority.
//! Time is a wall-clock tick supplied by the caller (`now_secs`), exactly like
//! the spec's `now`; expiry is DERIVED (`now > expiry` => dead), so a single
//! clock advance can lapse many grants at once with no mutation — and the
//! derivation is applied at EVERY read, so a lapsed grant can never be admitted
//! through any path.
//!
//! Fail-closed is preserved end to end:
//!
//! - An expired grant is dropped BEFORE the capability set is derived, so an
//!   expired role never contributes a capability (the direct
//!   `ExpiredGrantNeverAdmits` refinement).
//! - The surviving (live) grants are folded through the SAME
//!   [`rbac_bridge::authorize_effective_capability`](crate::rbac_bridge::authorize_effective_capability)
//!   path every other capability check uses — an expiring grant is never a
//!   bespoke bypass, and an explicit deny still wins over a live grant.
//! - A grant with NO expiry (`expires_at = None`) is permanent, matching the
//!   pre-C1 bare-membership semantics exactly, so this module is a strict
//!   superset of the bridge.
//!
//! A [`GrantSet`] is the durable state: it is rebuilt ONLY by folding
//! [`GrantOp`]s through [`GrantSet::apply`]/[`GrantSet::replay`], the same
//! journaled-op discipline [`UserOp`](crate::UserOp) follows, so live and
//! replayed authority can never diverge.

use std::collections::{BTreeMap, BTreeSet};

use pillar_rbac::{Decision, ExplicitGrant, StepUpPolicy};
use pillar_wot_authority::WotAuthority;

use crate::rbac_bridge::{authorize_effective_capability, ManagedGroup, Role};
use crate::UserRecord;

/// One expiring binding of a role or group to a subject handle.
///
/// `expires_at` is an ABSOLUTE wall-clock tick (seconds), inclusive-open
/// exactly like the spec's `expiry`: the grant is LIVE while `now_secs <=
/// expires_at` and DEAD (auto-lapsed) once `now_secs > expires_at`. `None`
/// means it never expires (a permanent binding).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExpiringGrant {
    /// The role or group NAME this grant binds (resolved against the roles/
    /// groups maps by [`effective_capabilities_at`]).
    pub name: String,
    /// The absolute expiry tick; `None` = never expires.
    pub expires_at: Option<u64>,
}

impl ExpiringGrant {
    /// A grant that lapses at the given absolute tick.
    #[must_use]
    pub fn until(name: impl Into<String>, expires_at: u64) -> Self {
        ExpiringGrant {
            name: name.into(),
            expires_at: Some(expires_at),
        }
    }

    /// A permanent grant (never lapses) — the pre-C1 bare-membership shape.
    #[must_use]
    pub fn permanent(name: impl Into<String>) -> Self {
        ExpiringGrant {
            name: name.into(),
            expires_at: None,
        }
    }

    /// Whether this grant is LIVE at `now_secs` — not past its expiry.
    /// Inclusive-open: live while `now_secs <= expires_at`. A `None` expiry is
    /// always live. This is the Rust `IsLive` predicate `ExpiredGrantNeverAdmits`
    /// is stated over.
    #[must_use]
    pub fn is_live(&self, now_secs: u64) -> bool {
        match self.expires_at {
            None => true,
            Some(expiry) => now_secs <= expiry,
        }
    }
}

/// A subject's expiring role and group bindings — the durable state for the
/// C1 story, rebuilt ONLY by replaying [`GrantOp`]s (never mutated directly),
/// exactly the [`apply_op`](crate::apply_op)/[`replay`](crate::replay)
/// discipline [`UserOp`](crate::UserOp) follows.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantSet {
    /// Per-handle expiring role bindings, keyed by role name (a later grant of
    /// the same name replaces the earlier — e.g. an extension re-issues a
    /// longer expiry).
    role_grants: BTreeMap<String, BTreeMap<String, ExpiringGrant>>,
    /// Per-handle expiring group bindings, keyed by group name.
    group_grants: BTreeMap<String, BTreeMap<String, ExpiringGrant>>,
}

/// One journaled mutation of the expiring-grant state. Folded through
/// [`GrantSet::apply`] both live and on replay — the SAME mutator either way,
/// so state can never diverge.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GrantOp {
    /// Grant `handle` the role `name`, lapsing at `expires_at` (`None` =
    /// permanent). Re-granting the same name replaces the prior binding (a
    /// renewal/extension).
    GrantRole {
        /// The subject handle being granted the role.
        handle: String,
        /// The role name granted.
        name: String,
        /// Absolute expiry tick; `None` = permanent.
        expires_at: Option<u64>,
    },
    /// Explicitly revoke a role grant BEFORE its expiry (the C3-shaped
    /// early-revoke leg). A no-op if absent.
    RevokeRole {
        /// The subject handle whose role grant is revoked.
        handle: String,
        /// The role name to revoke.
        name: String,
    },
    /// Grant `handle` the group `name`, lapsing at `expires_at`.
    GrantGroup {
        /// The subject handle being granted the group membership.
        handle: String,
        /// The group name granted.
        name: String,
        /// Absolute expiry tick; `None` = permanent.
        expires_at: Option<u64>,
    },
    /// Explicitly revoke a group grant before its expiry.
    RevokeGroup {
        /// The subject handle whose group grant is revoked.
        handle: String,
        /// The group name to revoke.
        name: String,
    },
}

impl GrantSet {
    /// An empty grant set.
    #[must_use]
    pub fn new() -> Self {
        GrantSet::default()
    }

    /// Fold ONE [`GrantOp`] into the set — idempotent-safe to call live and on
    /// replay.
    pub fn apply(&mut self, op: GrantOp) {
        match op {
            GrantOp::GrantRole {
                handle,
                name,
                expires_at,
            } => {
                self.role_grants
                    .entry(handle)
                    .or_default()
                    .insert(name.clone(), ExpiringGrant { name, expires_at });
            }
            GrantOp::RevokeRole { handle, name } => {
                if let Some(grants) = self.role_grants.get_mut(&handle) {
                    grants.remove(&name);
                }
            }
            GrantOp::GrantGroup {
                handle,
                name,
                expires_at,
            } => {
                self.group_grants
                    .entry(handle)
                    .or_default()
                    .insert(name.clone(), ExpiringGrant { name, expires_at });
            }
            GrantOp::RevokeGroup { handle, name } => {
                if let Some(grants) = self.group_grants.get_mut(&handle) {
                    grants.remove(&name);
                }
            }
        }
    }

    /// Rebuild a grant set from an ordered [`GrantOp`] sequence.
    #[must_use]
    pub fn replay(ops: impl IntoIterator<Item = GrantOp>) -> Self {
        let mut set = GrantSet::new();
        for op in ops {
            set.apply(op);
        }
        set
    }

    /// Every handle that has AT LEAST ONE recorded role or group grant (live or
    /// lapsed) — the subjects an access-review campaign must sweep. Deduped and
    /// deterministically ordered (the union of the role- and group-grant maps'
    /// keys, both `BTreeMap`-ordered).
    #[must_use]
    pub fn granted_handles(&self) -> BTreeSet<String> {
        self.role_grants
            .keys()
            .chain(self.group_grants.keys())
            .cloned()
            .collect()
    }

    /// Every role grant recorded for `handle`, live or lapsed (inspection).
    #[must_use]
    pub fn role_grants(&self, handle: &str) -> Vec<&ExpiringGrant> {
        self.role_grants
            .get(handle)
            .map(|g| g.values().collect())
            .unwrap_or_default()
    }

    /// The role NAMES that are LIVE for `handle` at `now_secs` — every lapsed
    /// grant is dropped (the `ExpiredGrantNeverAdmits` refinement).
    #[must_use]
    pub fn live_role_names(&self, handle: &str, now_secs: u64) -> BTreeSet<String> {
        self.role_grants
            .get(handle)
            .into_iter()
            .flat_map(|g| g.values())
            .filter(|grant| grant.is_live(now_secs))
            .map(|grant| grant.name.clone())
            .collect()
    }

    /// The group NAMES that are LIVE for `handle` at `now_secs`.
    #[must_use]
    pub fn live_group_names(&self, handle: &str, now_secs: u64) -> BTreeSet<String> {
        self.group_grants
            .get(handle)
            .into_iter()
            .flat_map(|g| g.values())
            .filter(|grant| grant.is_live(now_secs))
            .map(|grant| grant.name.clone())
            .collect()
    }
}

/// Project `handle`'s LIVE (unexpired) expiring role/group grants onto a
/// [`UserRecord`] at `now_secs`, producing a record whose `roles`/`groups`
/// sets are EXACTLY the still-live bindings, on top of the record's existing
/// permanent bindings. Every lapsed grant is absent — the direct
/// `ExpiredGrantNeverAdmits` refinement, applied before any capability is
/// derived from the record.
#[must_use]
pub fn record_with_live_grants(base: &UserRecord, grants: &GrantSet, now_secs: u64) -> UserRecord {
    let mut record = base.clone();
    record
        .roles
        .extend(grants.live_role_names(&base.handle, now_secs));
    record
        .groups
        .extend(grants.live_group_names(&base.handle, now_secs));
    record
}

/// Derive `handle`'s effective capabilities at `now_secs`, honouring expiry:
/// a lapsed role/group grant contributes NOTHING (fail-closed). Live grants
/// are unioned with the record's permanent bindings and resolved against
/// `roles`/`groups` through the SAME
/// [`effective_capabilities`](crate::rbac_bridge::effective_capabilities)
/// derivation the bridge uses.
#[must_use]
pub fn effective_capabilities_at(
    records: &BTreeMap<String, UserRecord>,
    grants: &GrantSet,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    handle: &str,
    now_secs: u64,
) -> BTreeSet<String> {
    let Some(base) = records.get(handle) else {
        return BTreeSet::new();
    };
    let projected = record_with_live_grants(base, grants, now_secs);
    let mut projected_records = records.clone();
    projected_records.insert(handle.to_owned(), projected);
    crate::rbac_bridge::effective_capabilities(&projected_records, roles, groups, handle)
}

/// Decide, at `now_secs`, whether `subject`'s effective capabilities — with
/// every expired grant already auto-lapsed — grant it `capability`, through
/// the SAME [`RbacDecider`](pillar_rbac::RbacDecider) path every other Pillar
/// capability check uses. An expired grant can never admit; an explicit deny in
/// `extra_grants` still wins over a live grant.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn authorize_capability_at(
    authority: &WotAuthority,
    policies: &[pillar_rbac::PolicyEvent],
    extra_grants: &[ExplicitGrant],
    records: &BTreeMap<String, UserRecord>,
    grants: &GrantSet,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    step_up: &StepUpPolicy,
    subject: &str,
    capability: &str,
    now_secs: u64,
    step_up_assertion: Option<pillar_rbac::StepUpAssertion>,
) -> Decision {
    let Some(base) = records.get(subject) else {
        // No record → no live grant → fail closed through the decider with an
        // empty projected record, exactly the bridge's unknown-handle floor.
        return authorize_effective_capability(
            authority,
            policies,
            extra_grants,
            records,
            roles,
            groups,
            step_up,
            subject,
            capability,
            now_secs,
            step_up_assertion,
        );
    };
    let projected = record_with_live_grants(base, grants, now_secs);
    let mut projected_records = records.clone();
    projected_records.insert(subject.to_owned(), projected);
    authorize_effective_capability(
        authority,
        policies,
        extra_grants,
        &projected_records,
        roles,
        groups,
        step_up,
        subject,
        capability,
        now_secs,
        step_up_assertion,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{replay, UserOp};
    use pillar_rbac::{Capability, ExplicitGrant, GrantEffect};

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
        groups.insert(
            "support-team".to_owned(),
            ManagedGroup::new("support-team", ["support-role"]),
        );
        groups
    }

    fn records_fixture() -> BTreeMap<String, UserRecord> {
        replay([UserOp::Invite {
            handle: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            email: "alice@example.com".to_owned(),
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        }])
    }

    #[test]
    fn a_live_role_grant_admits_its_capability() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(100),
        }]);

        // At tick 50 the grant is live → its capability is present.
        let caps = effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 50);
        assert_eq!(caps, BTreeSet::from(["iam:credentials:manage".to_owned()]));
    }

    #[test]
    fn an_expired_role_grant_admits_nothing_fail_closed() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(100),
        }]);

        // Inclusive-open boundary: live at exactly the expiry tick.
        assert_eq!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 100),
            BTreeSet::from(["iam:credentials:manage".to_owned()]),
            "a grant is live at exactly its expiry tick"
        );
        // One tick past expiry: the grant has auto-lapsed — nothing admitted.
        assert!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 101).is_empty(),
            "an expired grant must contribute NOTHING (ExpiredGrantNeverAdmits)"
        );
    }

    #[test]
    fn an_expired_group_grant_admits_nothing() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([GrantOp::GrantGroup {
            handle: "alice".to_owned(),
            name: "support-team".to_owned(),
            expires_at: Some(10),
        }]);

        assert_eq!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 10),
            BTreeSet::from(["iam:users:write".to_owned()]),
        );
        assert!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 11).is_empty(),
            "an expired group binding lapses exactly like a role binding"
        );
    }

    #[test]
    fn a_permanent_grant_never_lapses() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: None,
        }]);
        assert_eq!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", u64::MAX),
            BTreeSet::from(["iam:credentials:manage".to_owned()]),
            "a None-expiry grant is permanent"
        );
    }

    #[test]
    fn re_granting_extends_the_expiry() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([
            GrantOp::GrantRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
                expires_at: Some(100),
            },
            // A renewal re-issues a longer expiry (replaces the prior binding).
            GrantOp::GrantRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
                expires_at: Some(500),
            },
        ]);
        assert_eq!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 300),
            BTreeSet::from(["iam:credentials:manage".to_owned()]),
            "the renewed (longer) expiry governs"
        );
    }

    #[test]
    fn an_early_revoke_lapses_a_grant_before_its_expiry() {
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([
            GrantOp::GrantRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
                expires_at: Some(1000),
            },
            GrantOp::RevokeRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
            },
        ]);
        assert!(
            effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 10).is_empty(),
            "an explicitly revoked grant admits nothing even before its expiry"
        );
    }

    #[test]
    fn authorize_honours_expiry_through_the_shared_decider() {
        let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let step_up = StepUpPolicy::default();
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
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
                "iam:credentials:manage",
                now,
                None,
            )
        };
        assert_eq!(decide(50), Decision::Allow, "live grant → allow");
        assert_eq!(
            decide(101),
            Decision::Deny,
            "expired grant → deny (fail-closed) through the shared decider"
        );
    }

    #[test]
    fn an_explicit_deny_wins_over_a_live_expiring_grant() {
        let authority = WotAuthority::new(pillar_core::NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let step_up = StepUpPolicy::default();
        let records = records_fixture();
        let roles = roles_fixture();
        let groups = groups_fixture();
        let grants = GrantSet::replay([GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(1000),
        }]);
        let extra = [ExplicitGrant {
            subject: pillar_core::NodeId::from("alice"),
            capability: Capability::from("iam:credentials:manage"),
            effect: GrantEffect::Deny,
        }];
        let decision = authorize_capability_at(
            &authority,
            &policies,
            &extra,
            &records,
            &grants,
            &roles,
            &groups,
            &step_up,
            "alice",
            "iam:credentials:manage",
            50,
            None,
        );
        assert_eq!(
            decision,
            Decision::Deny,
            "an explicit deny must win over a live expiring grant, same as the bridge"
        );
    }

    #[test]
    fn replay_rebuilds_identical_state() {
        let ops = [
            GrantOp::GrantRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
                expires_at: Some(100),
            },
            GrantOp::GrantGroup {
                handle: "alice".to_owned(),
                name: "support-team".to_owned(),
                expires_at: None,
            },
        ];
        let a = GrantSet::replay(ops.iter().cloned());
        let b = GrantSet::replay(ops.iter().cloned());
        assert_eq!(a, b, "replay is deterministic");
        assert_eq!(
            a.live_role_names("alice", 50),
            BTreeSet::from(["billing-admin".to_owned()])
        );
        assert_eq!(a.live_role_names("alice", 101), BTreeSet::new());
        assert_eq!(
            a.live_group_names("alice", u64::MAX),
            BTreeSet::from(["support-team".to_owned()])
        );
    }
}
