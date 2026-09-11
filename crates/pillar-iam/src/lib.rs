//! Pillar IAM — the user record and its capability-gated write surface.
//!
//! Refines `specs/UserLifecycle.tla` (see `docs/tasks/user-record-and-profile.md`
//! in the beehive layer). [`UserRecord`] is the crate's central type: handle,
//! display name, email, [`UserStatus`], roles, groups, `force_password_change`,
//! `password_changed_at`, and timestamps. It is never mutated directly — the
//! ONLY way a record changes is by folding a [`UserOp`] (a signed, journaled
//! mutation) through [`apply_op`]/[`replay`], exactly the pattern
//! `pillar-cli`'s `WebAuthContext::PortalOp`/`record`/`replay`/`apply_replayed`
//! already establishes for the rest of the portal's state. This crate
//! deliberately subsumes the legacy `members: BTreeMap<String, String>` (handle
//! -> role) map: a [`UserRecord`]'s `roles` set carries every role the legacy
//! map held, so replaying the SAME op sequence a legacy `AddMember`/
//! `SetMemberRole` stream produced rebuilds the identical handle/role pairing
//! (see the `replay_rebuilds_...` test below) — a clean upgrade, no new
//! datastore, no dropped history.
//!
//! Every WRITE is a [`UserOp`] applied through [`apply_op`] — never a bare
//! in-memory mutation of [`UserRecord`]'s fields. The host embedding this
//! crate (e.g. `pillar-cli`'s web portal) is responsible for signing the op's
//! serialized payload (via `pillar_crypto::sign`) and appending it to its
//! durable journal exactly like every other `PortalOp`; this crate is
//! host-agnostic (no I/O, no HTTP types) so it can be unit-tested in full
//! isolation and reused by both the CLI and the web portal.
//!
//! Capability gating: admin actions (invite, list, show, and any other
//! mutation of a record other than the acting user's own profile) require the
//! [`IAM_USERS_WRITE_CAPABILITY`] capability, decided by the SAME
//! [`pillar_rbac::RbacDecider`] every other Pillar capability check uses (see
//! [`authorize_users_write`]) — never a parallel authorization mechanism.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_rbac::{Capability, Decision, RbacDecider, Request, ResourceClass};

pub mod rbac_bridge;
pub use rbac_bridge::{
    authorize_effective_capability, effective_capabilities, iam_credentials_manage_capability,
    iam_groups_write_capability, iam_roles_write_capability, role_group_grants, sensitive_ops_step_up_policy,
    ManagedGroup, Role, IAM_CREDENTIALS_MANAGE_CAPABILITY, IAM_GROUPS_WRITE_CAPABILITY, IAM_ROLES_WRITE_CAPABILITY,
    SENSITIVE_OPS_STEP_UP_MAX_AGE_SECS,
};

/// The capability string gating every admin write to the user/IAM surface
/// (invite, list, show, role/group edits performed on someone OTHER than the
/// acting user). A three-segment `namespace:resource:verb` capability, the
/// same convention `portal:members:write` already uses.
pub const IAM_USERS_WRITE_CAPABILITY: &str = "iam:users:write";

/// The [`Capability`] value for [`IAM_USERS_WRITE_CAPABILITY`].
#[must_use]
pub fn iam_users_write_capability() -> Capability {
    Capability::from(IAM_USERS_WRITE_CAPABILITY)
}

/// Decide whether `subject` may perform an admin user-management act (invite,
/// list, show, or edit ANOTHER user's record) right now. A single call so the
/// CLI, the web portal, and any future admin surface can never diverge on who
/// is allowed — exactly [`pillar_rbac::key_export::authorize_key_export`]'s
/// pattern applied to the IAM surface.
#[must_use]
pub fn authorize_users_write(decider: &RbacDecider<'_>, subject: NodeId, now_secs: u64) -> Decision {
    let request = Request::new(subject, iam_users_write_capability())
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    decider.decide(&request)
}

/// A user's lifecycle status. Refines `specs/UserLifecycle.tla`'s `Status`
/// (minus `"none"`, which here is simply "no record exists yet").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum UserStatus {
    /// Created by an admin invite; always carries `force_password_change =
    /// true` until the invitee completes their first self password change
    /// (`specs/UserLifecycle.tla`'s `InvitedForcesChange`).
    Invited,
    /// A normal, logged-in-capable user.
    Active,
    /// Disabled: holds no live session (`DisabledNeverActive`). Disabled !=
    /// deleted — the record and its history are retained. (The disable/enable
    /// transition itself is `user-disable-enable`'s admit-path gate; this
    /// crate carries the status field and the `StatusChange` op it is
    /// recorded through.)
    Disabled,
}

/// The user record: the crate's central type, rebuilt ONLY by replaying
/// [`UserOp`]s through [`apply_op`] — never mutated directly.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserRecord {
    /// The stable login handle (the legacy members map's key).
    pub handle: String,
    /// The user-chosen display name.
    pub display_name: String,
    /// The user's contact email.
    pub email: String,
    /// The lifecycle status.
    pub status: UserStatus,
    /// Directly assigned role names (subsumes the legacy members map's
    /// handle -> role pairing; a legacy single role becomes a one-element
    /// set here).
    pub roles: BTreeSet<String>,
    /// Named group memberships (`roles-groups-rbac-bridge` derives effective
    /// capabilities over these).
    pub groups: BTreeSet<String>,
    /// Set on invite and by an admin `RequireChange`; cleared on the user's
    /// own completed password change.
    pub force_password_change: bool,
    /// The wall-clock stamp of the last completed self password change, if
    /// any.
    pub password_changed_at: Option<u64>,
    /// The wall-clock stamp this record was created (invited) at.
    pub created_at: u64,
    /// The wall-clock stamp of the last mutation applied to this record.
    pub updated_at: u64,
}

/// One durable IAM mutation. Journaled by the host exactly like a `PortalOp`
/// (signed, content-addressed, appended, replayed on boot) and folded through
/// [`apply_op`]. Every variant carries exactly the material a deterministic
/// replay needs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UserOp {
    /// An admin invite: creates a NEW record in [`UserStatus::Invited`] with
    /// `force_password_change = true` (`specs/UserLifecycle.tla`'s
    /// `Invite`/`InvitedForcesChange`). A no-op (via [`apply_op`]) if the
    /// handle already has a record — invite is create-only; use
    /// [`UserOp::ProfileUpdate`] to edit an existing one.
    Invite {
        handle: String,
        display_name: String,
        email: String,
        at: u64,
    },
    /// A profile edit (self `PUT /portal/profile`, or an admin edit): updates
    /// `display_name`/`email` on an EXISTING record.
    ProfileUpdate {
        handle: String,
        display_name: String,
        email: String,
        at: u64,
    },
    /// Records a completed self password change: clears
    /// `force_password_change` and stamps `password_changed_at`
    /// (`CompletePasswordChange`).
    PasswordChanged { handle: String, at: u64 },
    /// Admin sets the forced-change label (`RequireChange`).
    RequireChange { handle: String, at: u64 },
    RoleAssign { handle: String, role: String, at: u64 },
    RoleRevoke { handle: String, role: String, at: u64 },
    GroupAdd { handle: String, group: String, at: u64 },
    GroupRemove { handle: String, group: String, at: u64 },
    /// Admin disable/enable (carried here so a replay of a disable/enable op
    /// stream — landed by `user-disable-enable` — folds through the same
    /// [`apply_op`] path as every other IAM mutation).
    StatusChange { handle: String, status: UserStatus, at: u64 },
}

impl UserOp {
    /// The handle this op mutates — every variant names exactly one.
    #[must_use]
    pub fn handle(&self) -> &str {
        match self {
            UserOp::Invite { handle, .. }
            | UserOp::ProfileUpdate { handle, .. }
            | UserOp::PasswordChanged { handle, .. }
            | UserOp::RequireChange { handle, .. }
            | UserOp::RoleAssign { handle, .. }
            | UserOp::RoleRevoke { handle, .. }
            | UserOp::GroupAdd { handle, .. }
            | UserOp::GroupRemove { handle, .. }
            | UserOp::StatusChange { handle, .. } => handle,
        }
    }
}

/// Fold ONE [`UserOp`] into `records`, exactly the `apply_replayed` pattern.
/// Idempotent-safe to call both live (right after a successful signed act)
/// and during replay (folding the persisted journal back on boot) — it is the
/// SAME mutator either way, so live and replayed state can never diverge.
pub fn apply_op(records: &mut BTreeMap<String, UserRecord>, op: UserOp) {
    match op {
        UserOp::Invite {
            handle,
            display_name,
            email,
            at,
        } => {
            records.entry(handle.clone()).or_insert_with(|| UserRecord {
                handle,
                display_name,
                email,
                status: UserStatus::Invited,
                roles: BTreeSet::new(),
                groups: BTreeSet::new(),
                force_password_change: true,
                password_changed_at: None,
                created_at: at,
                updated_at: at,
            });
        }
        UserOp::ProfileUpdate {
            handle,
            display_name,
            email,
            at,
        } => {
            if let Some(record) = records.get_mut(&handle) {
                record.display_name = display_name;
                record.email = email;
                record.updated_at = at;
            }
        }
        UserOp::PasswordChanged { handle, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.force_password_change = false;
                record.password_changed_at = Some(at);
                record.updated_at = at;
            }
        }
        UserOp::RequireChange { handle, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.force_password_change = true;
                record.updated_at = at;
            }
        }
        UserOp::RoleAssign { handle, role, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.roles.insert(role);
                record.updated_at = at;
            }
        }
        UserOp::RoleRevoke { handle, role, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.roles.remove(&role);
                record.updated_at = at;
            }
        }
        UserOp::GroupAdd { handle, group, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.groups.insert(group);
                record.updated_at = at;
            }
        }
        UserOp::GroupRemove { handle, group, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.groups.remove(&group);
                record.updated_at = at;
            }
        }
        UserOp::StatusChange { handle, status, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.status = status;
                record.updated_at = at;
            }
        }
    }
}

/// Rebuild the full user-record map from an ordered [`UserOp`] sequence — the
/// crate's replay entry point, mirroring `WebAuthContext::replay`'s "sort by
/// stamped causal order, then fold" shape (ordering is the HOST's
/// responsibility; this function applies `ops` in the order given).
#[must_use]
pub fn replay(ops: impl IntoIterator<Item = UserOp>) -> BTreeMap<String, UserRecord> {
    let mut records = BTreeMap::new();
    for op in ops {
        apply_op(&mut records, op);
    }
    records
}

/// Error building an [`UserOp::Invite`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteError {
    /// The handle already has a record — invite is create-only.
    AlreadyExists,
}

/// Build the op for an admin invite. Pure: does not mutate `records`, does not
/// sign or journal anything — the caller applies the returned op via
/// [`apply_op`] AFTER signing + durably journaling it, exactly like every
/// other portal act.
pub fn invite_user(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    display_name: String,
    email: String,
    at: u64,
) -> Result<UserOp, InviteError> {
    if records.contains_key(handle) {
        return Err(InviteError::AlreadyExists);
    }
    Ok(UserOp::Invite {
        handle: handle.to_owned(),
        display_name,
        email,
        at,
    })
}

/// Error building a [`UserOp::ProfileUpdate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// No record exists for this handle yet (must be invited/bootstrapped
    /// first).
    NotFound,
}

/// The `GET /portal/profile` view: self display name + email (never roles,
/// groups, or the forced-change label — the profile endpoint is intentionally
/// narrow; the admin surface exposes the rest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileView {
    pub handle: String,
    pub display_name: String,
    pub email: String,
}

/// `GET /portal/profile` read path.
pub fn view_profile(records: &BTreeMap<String, UserRecord>, handle: &str) -> Option<ProfileView> {
    records.get(handle).map(|record| ProfileView {
        handle: record.handle.clone(),
        display_name: record.display_name.clone(),
        email: record.email.clone(),
    })
}

/// Build the op for a `PUT /portal/profile` self edit (display name + email
/// only). Pure — see [`invite_user`]'s doc for the sign-then-apply contract
/// the caller must follow.
pub fn update_profile(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    display_name: String,
    email: String,
    at: u64,
) -> Result<UserOp, ProfileError> {
    if !records.contains_key(handle) {
        return Err(ProfileError::NotFound);
    }
    Ok(UserOp::ProfileUpdate {
        handle: handle.to_owned(),
        display_name,
        email,
        at,
    })
}

/// The admin `list` view: every record's handle, status, and roles — the
/// `GET /portal/users` surface (`iam:users:write`-gated at the host's
/// dispatch layer via [`authorize_users_write`]).
#[must_use]
pub fn list_users(records: &BTreeMap<String, UserRecord>) -> Vec<&UserRecord> {
    records.values().collect()
}

/// The admin `show` view: one record in full, or `None` for an unknown
/// handle.
#[must_use]
pub fn show_user<'a>(records: &'a BTreeMap<String, UserRecord>, handle: &str) -> Option<&'a UserRecord> {
    records.get(handle)
}

#[cfg(test)]
mod user_record {
    use super::*;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
    use pillar_crypto::Seed;

    // A minimal stand-in for the legacy `members: BTreeMap<String, String>`
    // (handle -> role) map `WebAuthContext` carried before this crate, used
    // only to prove the replay-equivalence property below.
    fn legacy_members() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("alice".to_owned(), "admin".to_owned());
        m.insert("bob".to_owned(), "member".to_owned());
        m
    }

    #[test]
    fn replay_rebuilds_user_records_matching_legacy_members_map_for_overlapping_fields() {
        let legacy = legacy_members();

        // A captured op sequence: an invite followed by the SAME role
        // assignment the legacy `AddMember`/`SetMemberRole` stream would have
        // produced for each handle.
        let mut ops = Vec::new();
        let mut at = 0u64;
        for (handle, role) in &legacy {
            at += 1;
            ops.push(UserOp::Invite {
                handle: handle.clone(),
                display_name: handle.clone(),
                email: format!("{handle}@example.com"),
                at,
            });
            at += 1;
            ops.push(UserOp::RoleAssign {
                handle: handle.clone(),
                role: role.clone(),
                at,
            });
        }

        let records = replay(ops);

        assert_eq!(
            records.len(),
            legacy.len(),
            "replay must produce exactly one record per legacy member"
        );
        for (handle, role) in &legacy {
            let record = records
                .get(handle)
                .unwrap_or_else(|| panic!("missing replayed record for {handle}"));
            assert_eq!(&record.handle, handle);
            assert!(
                record.roles.contains(role),
                "replayed record for {handle} must carry the legacy role {role}"
            );
        }
    }

    #[test]
    fn invite_creates_a_record_in_invited_status_with_forced_password_change() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        let op = invite_user(
            &records,
            "carol",
            "Carol".to_owned(),
            "carol@example.com".to_owned(),
            100,
        )
        .expect("invite of a fresh handle must succeed");

        let records = replay([op]);
        let carol = records.get("carol").expect("carol must be recorded");
        assert_eq!(carol.status, UserStatus::Invited);
        assert!(
            carol.force_password_change,
            "an invited user must carry force_password_change = true"
        );
    }

    #[test]
    fn inviting_an_existing_handle_is_refused() {
        let records = replay([UserOp::Invite {
            handle: "dave".to_owned(),
            display_name: "Dave".to_owned(),
            email: "dave@example.com".to_owned(),
            at: 1,
        }]);
        assert_eq!(
            invite_user(&records, "dave", "Dave2".to_owned(), "d2@example.com".to_owned(), 2),
            Err(InviteError::AlreadyExists)
        );
    }

    #[test]
    fn portal_profile_round_trips_a_display_name_and_email_edit_as_a_signed_op() {
        let mut records = replay([UserOp::Invite {
            handle: "erin".to_owned(),
            display_name: "Erin".to_owned(),
            email: "erin@old.example.com".to_owned(),
            at: 1,
        }]);

        let before = view_profile(&records, "erin").expect("erin must have a profile");
        assert_eq!(before.display_name, "Erin");
        assert_eq!(before.email, "erin@old.example.com");

        // Build the PUT /portal/profile op, sign its serialized payload the
        // same way every other portal act is signed, then apply it exactly
        // as the host would after a successful signature verification.
        let op = update_profile(
            &records,
            "erin",
            "Erin Q".to_owned(),
            "erin@new.example.com".to_owned(),
            2,
        )
        .expect("profile update of an existing handle must succeed");

        let seed = Seed::from_bytes(b"pillar-iam-test-seed::erin".to_vec());
        let (public, secret) = signing_keypair_from_seed(&seed).expect("keygen");
        let payload = serde_json::to_vec(&op).expect("op must serialize");
        let signature = sign(&secret, &payload).expect("sign");
        verify(&public, &payload, &signature).expect("the signed profile-update payload must verify");

        apply_op(&mut records, op);

        let after = view_profile(&records, "erin").expect("erin must still have a profile");
        assert_eq!(after.display_name, "Erin Q");
        assert_eq!(after.email, "erin@new.example.com");
    }

    #[test]
    fn updating_an_unknown_handle_is_refused() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        assert_eq!(
            update_profile(&records, "ghost", "Ghost".to_owned(), "g@example.com".to_owned(), 1),
            Err(ProfileError::NotFound)
        );
    }

    #[test]
    fn admin_write_capability_is_required_and_gated_by_the_shared_rbac_decider() {
        use pillar_rbac::{ExplicitGrant, GrantEffect};
        use pillar_wot_authority::WotAuthority;

        let authority = WotAuthority::new(NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let grants = [ExplicitGrant {
            subject: NodeId::from("admin"),
            capability: iam_users_write_capability(),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&authority, &policies, &grants);

        assert_eq!(
            authorize_users_write(&decider, NodeId::from("admin"), 1),
            Decision::Allow
        );
        assert_eq!(
            authorize_users_write(&decider, NodeId::from("stranger"), 1),
            Decision::Deny
        );
    }

    #[test]
    fn list_and_show_expose_replayed_records() {
        let records = replay([UserOp::Invite {
            handle: "finn".to_owned(),
            display_name: "Finn".to_owned(),
            email: "finn@example.com".to_owned(),
            at: 1,
        }]);
        assert_eq!(list_users(&records).len(), 1);
        assert!(show_user(&records, "finn").is_some());
        assert!(show_user(&records, "nobody").is_none());
    }
}
