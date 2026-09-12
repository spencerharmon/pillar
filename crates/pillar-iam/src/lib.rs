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
    iam_groups_write_capability, iam_roles_write_capability, role_group_grants,
    sensitive_ops_step_up_policy, ManagedGroup, Role, IAM_CREDENTIALS_MANAGE_CAPABILITY,
    IAM_GROUPS_WRITE_CAPABILITY, IAM_ROLES_WRITE_CAPABILITY, SENSITIVE_OPS_STEP_UP_MAX_AGE_SECS,
};

pub mod password_lifecycle;
pub use password_lifecycle::{
    admit_gated_action, complete_self_password_change, evaluate_login_password_age,
    invite_user_with_temp_password, seal_operational_key, unseal_operational_key, AdmitError,
    GatedAction, InviteWithPasswordError, PasswordChangeError, SealedOperationalKey,
};

pub mod admin_credentials;
pub use admin_credentials::{
    admin_issue_enrollment_invite, admin_list_credentials, admin_revoke_credential,
    authorize_credentials_manage, AdminAuthContext, AdminCredentialError, EnrollmentInvite,
};

pub mod admin_reset;
pub use admin_reset::{admin_reset_password, AdminResetError};

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
pub fn authorize_users_write(
    decider: &RbacDecider<'_>,
    subject: NodeId,
    now_secs: u64,
) -> Decision {
    let request = Request::new(subject, iam_users_write_capability())
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    decider.decide(&request)
}

/// A user's lifecycle status. Refines `specs/UserLifecycle.tla`'s `Status`
/// (minus `"none"`, which here is simply "no record exists yet").
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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
    /// Set on invite when the admin requires the invitee to enrol a WebAuthn
    /// passkey before the account is usable for anything else; cleared when
    /// the user's first credential registers (`UserOp::PasskeyEnrolled`). An
    /// onboarding required action independent of and symmetric to
    /// `force_password_change` (`specs/UserLifecycle.tla`'s `requirePasskey`/
    /// `RequiredPasskeyContained`). Defaults `false` for pre-options records.
    #[serde(default)]
    pub require_passkey_enrollment: bool,
    /// The wall-clock stamp of the last completed self password change, if
    /// any.
    pub password_changed_at: Option<u64>,
    /// The wall-clock stamp this record was created (invited) at.
    pub created_at: u64,
    /// The wall-clock stamp of the last mutation applied to this record.
    pub updated_at: u64,
    /// The user's operational key, AEAD-sealed under a KEK derived (via the
    /// SAME `argon2id` custody backend `pillar_crypto::kdf`/`custody` ship)
    /// from the user's current password. Provisioned on invite (sealed under
    /// the admin-chosen temp password) and re-sealed on every completed self
    /// password change (`password_lifecycle::complete_self_password_change`).
    /// `None` only for a record that predates this field / has no
    /// operational key yet.
    pub sealed_operational_key: Option<SealedOperationalKey>,
    /// Operational keys that have been superseded and RETIRED (never silently
    /// dropped) — an admin password reset
    /// (`admin-password-reset-reprovision`) moves the record's prior live key
    /// here when it installs a fresh one, the crate-local reflection of the
    /// identity-rotation / WoT-revocation machinery `key-rotation` owns. A
    /// retired key is never the record's live key and never unlocks a live
    /// session again; it is kept only for the audit trail.
    pub retired_operational_keys: Vec<SealedOperationalKey>,
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
        /// Whether the invitee must change their password on first login (the
        /// forced-change required action). Journaled with a `true` default so
        /// a pre-options invite (always forced) replays with identical
        /// semantics.
        #[serde(default = "invite_default_force_change")]
        force_password_change: bool,
        /// Whether the invitee must enrol a WebAuthn passkey before the
        /// account is usable (the required-passkey action). Defaults `false`
        /// for pre-options journals.
        #[serde(default)]
        require_passkey_enrollment: bool,
        at: u64,
    },
    /// Clears the required-passkey onboarding action once the user's first
    /// WebAuthn credential registers (`specs/UserLifecycle.tla`'s
    /// `EnrollPasskey`). A no-op (via [`apply_op`]) if the handle is unknown.
    PasskeyEnrolled { handle: String, at: u64 },
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
    RoleAssign {
        handle: String,
        role: String,
        at: u64,
    },
    RoleRevoke {
        handle: String,
        role: String,
        at: u64,
    },
    GroupAdd {
        handle: String,
        group: String,
        at: u64,
    },
    GroupRemove {
        handle: String,
        group: String,
        at: u64,
    },
    /// Admin disable/enable (carried here so a replay of a disable/enable op
    /// stream — landed by `user-disable-enable` — folds through the same
    /// [`apply_op`] path as every other IAM mutation).
    StatusChange {
        handle: String,
        status: UserStatus,
        at: u64,
    },
    /// Sets (or replaces) the record's sealed operational key —
    /// [`password_lifecycle`]'s provisioning primitive. Used at invite time
    /// (sealed under the admin-chosen temp password) and by a completed self
    /// password change's re-seal step; kept as its own variant (rather than
    /// folded only into `Invite`) so an admin re-provision
    /// (`admin-password-reset-reprovision`) can reuse the same op.
    ProvisionOperationalKey {
        handle: String,
        sealed: SealedOperationalKey,
        at: u64,
    },
    /// An admin-driven password reset (`admin-password-reset-reprovision`):
    /// RETIRE the record's current live operational key (moving it to
    /// [`UserRecord::retired_operational_keys`]), install `sealed` — a
    /// genuinely NEW key sealed under the admin-chosen new password — as the
    /// live key, and set `force_password_change`. Built by
    /// [`admin_reset::admin_reset_password`] (step-up-gated
    /// `iam:credentials:manage`); it never re-derives or exposes the old key
    /// and never touches the user's WebAuthn credentials.
    AdminReset {
        handle: String,
        sealed: SealedOperationalKey,
        at: u64,
    },
}

impl UserOp {
    /// The handle this op mutates — every variant names exactly one.
    #[must_use]
    pub fn handle(&self) -> &str {
        match self {
            UserOp::Invite { handle, .. }
            | UserOp::PasskeyEnrolled { handle, .. }
            | UserOp::ProfileUpdate { handle, .. }
            | UserOp::PasswordChanged { handle, .. }
            | UserOp::RequireChange { handle, .. }
            | UserOp::RoleAssign { handle, .. }
            | UserOp::RoleRevoke { handle, .. }
            | UserOp::GroupAdd { handle, .. }
            | UserOp::GroupRemove { handle, .. }
            | UserOp::StatusChange { handle, .. }
            | UserOp::ProvisionOperationalKey { handle, .. }
            | UserOp::AdminReset { handle, .. } => handle,
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
            force_password_change,
            require_passkey_enrollment,
            at,
        } => {
            records.entry(handle.clone()).or_insert_with(|| UserRecord {
                handle,
                display_name,
                email,
                status: UserStatus::Invited,
                roles: BTreeSet::new(),
                groups: BTreeSet::new(),
                force_password_change,
                require_passkey_enrollment,
                password_changed_at: None,
                created_at: at,
                updated_at: at,
                sealed_operational_key: None,
                retired_operational_keys: Vec::new(),
            });
        }
        UserOp::PasskeyEnrolled { handle, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.require_passkey_enrollment = false;
                record.updated_at = at;
            }
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
        UserOp::ProvisionOperationalKey { handle, sealed, at } => {
            if let Some(record) = records.get_mut(&handle) {
                record.sealed_operational_key = Some(sealed);
                record.updated_at = at;
            }
        }
        UserOp::AdminReset { handle, sealed, at } => {
            if let Some(record) = records.get_mut(&handle) {
                admin_reset::apply_admin_reset(record, sealed, at);
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
    force_password_change: bool,
    require_passkey_enrollment: bool,
    at: u64,
) -> Result<UserOp, InviteError> {
    if records.contains_key(handle) {
        return Err(InviteError::AlreadyExists);
    }
    Ok(UserOp::Invite {
        handle: handle.to_owned(),
        display_name,
        email,
        force_password_change,
        require_passkey_enrollment,
        at,
    })
}

/// Serde default for [`UserOp::Invite`]'s `force_password_change` field:
/// `true`, so a pre-options journal (whose invites carried no such field and
/// were unconditionally forced) replays with identical forced-change
/// semantics.
fn invite_default_force_change() -> bool {
    true
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
pub fn show_user<'a>(
    records: &'a BTreeMap<String, UserRecord>,
    handle: &str,
) -> Option<&'a UserRecord> {
    records.get(handle)
}

// ---------------------------------------------------------------------------
// user-disable-enable: admit gate + admin disable/enable ops + live-session
// revocation. Refines `specs/UserLifecycle.tla`'s `DisabledNeverActive`: a
// disabled account holds no live session and cannot unlock a credential.
// Disabled != deleted — the record and its full op history are retained; only
// the `status` field flips (through the SAME [`UserOp::StatusChange`]/[`apply_op`]
// path as every other IAM mutation), and every live session/token is revoked
// immediately by reusing the `session-registry-impl` revocation path
// ([`pillar_identity::session_registry::SessionRegistry::revoke_all`]).

/// The wire/error code an admit denial returns for a disabled account — the
/// `403 ACCOUNT-DISABLED` the ROI names. Hosts map [`AdmitDenied::AccountDisabled`]
/// to HTTP 403 carrying this code.
pub const ACCOUNT_DISABLED_CODE: &str = "ACCOUNT-DISABLED";

/// Why [`admit_credential_unlock`] refused. The admit gate runs BEFORE any
/// credential unlock (`specs/UserLifecycle.tla`'s `DisabledNeverActive`): a
/// disabled — or entirely unknown — account never reaches the password/
/// credential check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitDenied {
    /// No record exists for this handle — admit refuses (there is nothing to
    /// unlock a credential for).
    NoSuchUser,
    /// The account is [`UserStatus::Disabled`]. Hosts return `403` with
    /// [`ACCOUNT_DISABLED_CODE`].
    AccountDisabled,
}

impl AdmitDenied {
    /// The stable error code a host surfaces for this denial (the disabled
    /// case is the ROI's `ACCOUNT-DISABLED`).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            AdmitDenied::NoSuchUser => "NO-SUCH-USER",
            AdmitDenied::AccountDisabled => ACCOUNT_DISABLED_CODE,
        }
    }
}

/// The admit-path status gate: decide whether `handle` may proceed to a
/// credential unlock right now. Called by the login/admit path BEFORE the
/// credential (password/token) check — a [`UserStatus::Disabled`] account is
/// refused with [`AdmitDenied::AccountDisabled`] (host → `403 ACCOUNT-DISABLED`),
/// and an unknown handle with [`AdmitDenied::NoSuchUser`]. An
/// [`UserStatus::Invited`] or [`UserStatus::Active`] account is admitted (the
/// forced-password-change flow is a separate, later gate).
///
/// # Errors
///
/// See [`AdmitDenied`].
pub fn admit_credential_unlock(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
) -> Result<(), AdmitDenied> {
    match records.get(handle) {
        None => Err(AdmitDenied::NoSuchUser),
        Some(record) if record.status == UserStatus::Disabled => Err(AdmitDenied::AccountDisabled),
        Some(_) => Ok(()),
    }
}

/// Error building a disable/enable [`UserOp::StatusChange`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusChangeError {
    /// No record exists for this handle.
    NotFound,
    /// The record is already in the requested target status — the op would be
    /// a no-op, so it is refused (a disable of an already-disabled account, or
    /// an enable of an already-enabled one).
    AlreadyInStatus,
}

/// Build the signed op for an admin **disable** (`iam:users:write`-gated at the
/// host's dispatch layer via [`authorize_users_write`]). Pure — the caller
/// signs + journals the returned op, applies it via [`apply_op`], then
/// **immediately** revokes every live session/token for the handle via
/// [`revoke_all_sessions`] (see [`disable_user_and_revoke`], which does both).
///
/// # Errors
///
/// [`StatusChangeError::NotFound`] for an unknown handle;
/// [`StatusChangeError::AlreadyInStatus`] if already disabled.
pub fn disable_user(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    at: u64,
) -> Result<UserOp, StatusChangeError> {
    status_change_op(records, handle, UserStatus::Disabled, at)
}

/// Build the signed op for an admin **enable** (re-activate a disabled
/// account). `iam:users:write`-gated exactly like [`disable_user`]. Enabling
/// does NOT restore any prior session — the user must log in afresh (a new
/// mint), so no revocation/mint side effect is needed here.
///
/// # Errors
///
/// [`StatusChangeError::NotFound`] for an unknown handle;
/// [`StatusChangeError::AlreadyInStatus`] if already active.
pub fn enable_user(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    at: u64,
) -> Result<UserOp, StatusChangeError> {
    status_change_op(records, handle, UserStatus::Active, at)
}

fn status_change_op(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    status: UserStatus,
    at: u64,
) -> Result<UserOp, StatusChangeError> {
    let record = records.get(handle).ok_or(StatusChangeError::NotFound)?;
    if record.status == status {
        return Err(StatusChangeError::AlreadyInStatus);
    }
    Ok(UserOp::StatusChange {
        handle: handle.to_owned(),
        status,
        at,
    })
}

/// Immediately revoke EVERY live session/token for `handle` — the disable-time
/// side effect the ROI requires ("disabling revokes every live session/token
/// immediately"). This is a thin, deliberate reuse of the
/// `session-registry-impl` revocation path
/// ([`pillar_identity::session_registry::SessionRegistry::revoke_all`]): one
/// epoch-stamped sweep so every already-admitted bearer action fails closed on
/// its next fenced admit. Never a parallel revocation mechanism.
pub fn revoke_all_sessions(
    registry: &mut pillar_identity::session_registry::SessionRegistry,
    handle: &str,
) {
    registry.revoke_all(handle);
}

/// Disable `handle` end-to-end: apply the (already signed + journaled)
/// [`UserOp::StatusChange`] to `records` AND immediately revoke every live
/// session for the handle. The caller builds the op with [`disable_user`],
/// signs + journals it, then hands it here with the live session registry. The
/// two effects are inseparable — a disabled account that still held a live
/// session would violate `DisabledNeverActive`.
pub fn disable_user_and_revoke(
    records: &mut BTreeMap<String, UserRecord>,
    registry: &mut pillar_identity::session_registry::SessionRegistry,
    op: UserOp,
) {
    let handle = op.handle().to_owned();
    apply_op(records, op);
    revoke_all_sessions(registry, &handle);
}

#[cfg(test)]
mod disable_enable {
    use super::*;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
    use pillar_crypto::Seed;
    use pillar_identity::session_registry::{AdmitError, SessionRegistry, SessionView};

    fn invited(handle: &str) -> UserOp {
        UserOp::Invite {
            handle: handle.to_owned(),
            display_name: handle.to_owned(),
            email: format!("{handle}@example.com"),
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        }
    }

    // Admit gate: an ACTIVE (or invited) account passes the status gate; a
    // DISABLED one is refused with the ROI's `403 ACCOUNT-DISABLED`; an
    // unknown handle is refused too. Refines `DisabledNeverActive`.
    #[test]
    fn disable_enable_admit_gate_refuses_disabled_with_account_disabled_code() {
        let mut records = replay([invited("alice")]);
        // Invited passes the status gate (forced-change is a later gate).
        assert_eq!(admit_credential_unlock(&records, "alice"), Ok(()));

        // Unknown handle refused.
        assert_eq!(
            admit_credential_unlock(&records, "ghost"),
            Err(AdmitDenied::NoSuchUser)
        );

        // Disable, then the admit gate refuses with ACCOUNT-DISABLED.
        let op = disable_user(&records, "alice", 5).expect("disable of an active handle succeeds");
        apply_op(&mut records, op);
        assert_eq!(records["alice"].status, UserStatus::Disabled);
        assert_eq!(
            admit_credential_unlock(&records, "alice"),
            Err(AdmitDenied::AccountDisabled)
        );
        assert_eq!(
            admit_credential_unlock(&records, "alice")
                .unwrap_err()
                .code(),
            "ACCOUNT-DISABLED"
        );

        // Re-enable restores admission.
        let op = enable_user(&records, "alice", 6).expect("enable of a disabled handle succeeds");
        apply_op(&mut records, op);
        assert_eq!(records["alice"].status, UserStatus::Active);
        assert_eq!(admit_credential_unlock(&records, "alice"), Ok(()));
    }

    // Disabling revokes every live session immediately, reusing the
    // session-registry revocation path: an action admitted before disable
    // fails closed after, on a refreshed fenced view.
    #[test]
    fn disable_enable_revokes_every_live_session_immediately() {
        let mut records = replay([invited("bob")]);
        // Bob logs in twice (two live sessions).
        let mut registry = SessionRegistry::new();
        registry.mint("bob", "s1", 0, 1000);
        registry.mint("bob", "s2", 0, 1000);

        // Both admit while active.
        let mut view = SessionView::new();
        view.refresh(&registry);
        assert!(view.admit(&registry, "bob", "s1", 10).is_ok());
        assert!(view.admit(&registry, "bob", "s2", 10).is_ok());

        // Admin disables bob → apply the StatusChange AND revoke every session.
        let op = disable_user(&records, "bob", 5).expect("disable succeeds");
        disable_user_and_revoke(&mut records, &mut registry, op);
        assert_eq!(records["bob"].status, UserStatus::Disabled);

        // A refreshed fenced view now refuses BOTH sessions (revoked sweep).
        view.refresh(&registry);
        assert_eq!(
            view.admit(&registry, "bob", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert_eq!(
            view.admit(&registry, "bob", "s2", 10),
            Err(AdmitError::Revoked)
        );
        // No live session survives for the disabled principal.
        assert!(registry.ls("bob", 10).is_empty());
    }

    // disable/enable are iam:users:write-gated signed ops: the op payload
    // signs + verifies exactly like every other portal act, and the gate uses
    // the SAME shared RBAC decider.
    #[test]
    fn disable_enable_is_a_users_write_gated_signed_op() {
        use pillar_rbac::{ExplicitGrant, GrantEffect};
        use pillar_wot_authority::WotAuthority;

        let records = replay([invited("carol")]);

        // Gate: only an iam:users:write holder may perform the write.
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

        // The disable op is a signed, verifiable payload like any portal act.
        let op = disable_user(&records, "carol", 5).expect("disable succeeds");
        let seed = Seed::from_bytes(b"pillar-iam-test-seed::carol-disable".to_vec());
        let (public, secret) = signing_keypair_from_seed(&seed).expect("keygen");
        let payload = serde_json::to_vec(&op).expect("op serializes");
        let signature = sign(&secret, &payload).expect("sign");
        verify(&public, &payload, &signature).expect("the signed disable op must verify");
    }

    // Disabled != deleted: the record and its history survive a disable, and a
    // no-op transition (disable-of-disabled / enable-of-active) is refused.
    #[test]
    fn disable_enable_retains_record_and_refuses_noops() {
        let mut records = replay([
            invited("dave"),
            UserOp::RoleAssign {
                handle: "dave".to_owned(),
                role: "member".to_owned(),
                at: 2,
            },
        ]);

        // enable-of-non-disabled (invited) is a refused no-op only when
        // already Active; here dave is Invited, so activate him first.
        let op =
            enable_user(&records, "dave", 3).expect("enable of an invited handle activates it");
        apply_op(&mut records, op);
        assert_eq!(records["dave"].status, UserStatus::Active);
        // Now enable-of-already-active is a refused no-op.
        assert_eq!(
            enable_user(&records, "dave", 4),
            Err(StatusChangeError::AlreadyInStatus)
        );
        // unknown handle → NotFound.
        assert_eq!(
            disable_user(&records, "ghost", 3),
            Err(StatusChangeError::NotFound)
        );

        // Disable retains the record (handle + roles + history), only status flips.
        let op = disable_user(&records, "dave", 5).expect("disable succeeds");
        apply_op(&mut records, op);
        let dave = show_user(&records, "dave").expect("disabled != deleted; record retained");
        assert_eq!(dave.status, UserStatus::Disabled);
        assert!(
            dave.roles.contains("member"),
            "history/roles retained on disable"
        );

        // disable-of-already-disabled is a refused no-op.
        assert_eq!(
            disable_user(&records, "dave", 6),
            Err(StatusChangeError::AlreadyInStatus)
        );
    }
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
                force_password_change: true,
                require_passkey_enrollment: false,
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
            true,
            false,
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
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        }]);
        assert_eq!(
            invite_user(
                &records,
                "dave",
                "Dave2".to_owned(),
                "d2@example.com".to_owned(),
                true,
                false,
                2
            ),
            Err(InviteError::AlreadyExists)
        );
    }

    #[test]
    fn portal_profile_round_trips_a_display_name_and_email_edit_as_a_signed_op() {
        let mut records = replay([UserOp::Invite {
            handle: "erin".to_owned(),
            display_name: "Erin".to_owned(),
            email: "erin@old.example.com".to_owned(),
            force_password_change: true,
            require_passkey_enrollment: false,
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
        verify(&public, &payload, &signature)
            .expect("the signed profile-update payload must verify");

        apply_op(&mut records, op);

        let after = view_profile(&records, "erin").expect("erin must still have a profile");
        assert_eq!(after.display_name, "Erin Q");
        assert_eq!(after.email, "erin@new.example.com");
    }

    #[test]
    fn updating_an_unknown_handle_is_refused() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        assert_eq!(
            update_profile(
                &records,
                "ghost",
                "Ghost".to_owned(),
                "g@example.com".to_owned(),
                1
            ),
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
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        }]);
        assert_eq!(list_users(&records).len(), 1);
        assert!(show_user(&records, "finn").is_some());
        assert!(show_user(&records, "nobody").is_none());
    }
}
