//! Password self-change, invite-provisioned operational keys, and the
//! forced-change containment guard.
//!
//! Refines `specs/UserLifecycle.tla`'s `InvitedForcesChange`/
//! `ForcedChangeContained`:
//!
//! * **Invite** provisions the user's operational key AEAD-sealed under a
//!   key-encryption key (KEK) derived from an admin-chosen temp password (the
//!   SAME `argon2id` KDF + AEAD custody path `pillar_crypto::kdf`/
//!   `pillar_crypto::custody::PasswordCustody` already ship — no parallel
//!   crypto). The record is created `Invited` with `force_password_change =
//!   true` ([`crate::invite_user`]).
//! * **Self password change** ([`complete_self_password_change`]) proves
//!   knowledge of the CURRENT password by unsealing the operational key with
//!   it (a wrong current password fails the AEAD tag, fail-closed), re-seals
//!   under the new password, and clears `force_password_change` — the
//!   [`crate::UserOp::ProvisionOperationalKey`] + [`crate::UserOp::PasswordChanged`]
//!   op pair.
//! * **Containment** ([`admit_gated_action`]) refuses every capability-gated
//!   act while `force_password_change` is set, EXCEPT the two self-service
//!   acts an invited/forced user needs to escape containment: reading/
//!   updating its own profile and completing its own password change. This is
//!   the SHARED admit/dispatch gate `user-disable-enable` extends with its
//!   own `disabled` check — one gate, not a per-endpoint check.
//! * **`max_password_age`** ([`evaluate_login_password_age`]) is an optional,
//!   cell-wide policy: a login whose password has gone stale past the
//!   configured age is handed a [`crate::UserOp::RequireChange`] op to apply
//!   BEFORE the session proceeds, so an over-age login is forced-change on
//!   next admit exactly like an admin-set `RequireChange` — the SAME
//!   `force_password_change` field and the SAME containment gate, not a
//!   parallel mechanism.

use std::collections::BTreeMap;

use pillar_core::NodeId;
use pillar_crypto::{Ciphertext, CryptoError, KdfParams, Salt};
use pillar_rbac::{Decision, ExplicitGrant, PolicyEvent, RbacDecider, Request, ResourceClass, StepUpAssertion};
use pillar_wot_authority::WotAuthority;

use crate::rbac_bridge::{iam_credentials_manage_capability, sensitive_ops_step_up_policy};
use crate::{invite_user, InviteError, UserOp, UserRecord};

/// AEAD associated-data domain separator for the sealed operational key —
/// keeps this artifact's ciphertext bound to its purpose and never
/// interchangeable with a node's custody-sealed secret or any other sealed
/// artifact in the codebase.
const OPERATIONAL_KEY_AAD: &[u8] = b"pillar-iam/operational-key-v1";

/// At-rest form of a password-sealed operational key. A `serde`-friendly
/// mirror of `pillar_crypto`'s `KdfParams`/`Salt`/`Ciphertext` fields (those
/// crypto newtypes intentionally do not derive `Serialize` — see
/// `pillar_crypto::types`), so a [`crate::UserRecord`] carrying one can still
/// be journaled/replayed like every other `UserOp`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedOperationalKey {
    /// Argon2id memory cost (KiB) used to derive the KEK.
    pub mem_kib: u32,
    /// Argon2id iteration count used to derive the KEK.
    pub iterations: u32,
    /// Argon2id parallelism used to derive the KEK.
    pub parallelism: u32,
    /// KEK output length in bytes.
    pub output_len: usize,
    /// Per-record KDF salt.
    pub salt: Vec<u8>,
    /// The operational key, AEAD-sealed under the derived KEK.
    pub wrapped: Vec<u8>,
}

/// AEAD-seal `operational_key` under a KEK derived (argon2id) from
/// `password`. A fresh random salt is drawn every call, so re-sealing the
/// SAME key under the SAME password twice never yields the same
/// [`SealedOperationalKey`] (no nonce/salt reuse across a re-seal).
pub fn seal_operational_key(
    operational_key: &[u8],
    password: &[u8],
) -> Result<SealedOperationalKey, CryptoError> {
    use rand_core::{OsRng, RngCore};

    let params = KdfParams::default();
    let mut salt_bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = Salt::from_bytes(salt_bytes.clone());

    let kek = pillar_crypto::kdf::derive_key(password, &salt, &params)?;
    let wrapped =
        pillar_crypto::aead::seal_symmetric(&kek, operational_key, OPERATIONAL_KEY_AAD)?;

    Ok(SealedOperationalKey {
        mem_kib: params.mem_kib,
        iterations: params.iterations,
        parallelism: params.parallelism,
        output_len: params.output_len,
        salt: salt_bytes,
        wrapped: wrapped.into_bytes(),
    })
}

/// Recover the plaintext operational key from `sealed` given `password`. A
/// wrong password derives a wrong KEK and the AEAD open fails closed with
/// [`CryptoError::DecryptionFailed`] — never a bogus key.
pub fn unseal_operational_key(
    sealed: &SealedOperationalKey,
    password: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let params = KdfParams {
        mem_kib: sealed.mem_kib,
        iterations: sealed.iterations,
        parallelism: sealed.parallelism,
        output_len: sealed.output_len,
    };
    let salt = Salt::from_bytes(sealed.salt.clone());
    let kek = pillar_crypto::kdf::derive_key(password, &salt, &params)?;
    let ciphertext = Ciphertext::from_bytes(sealed.wrapped.clone());
    pillar_crypto::aead::open_symmetric(&kek, &ciphertext, OPERATIONAL_KEY_AAD)
}

/// Error building an invite that provisions a sealed operational key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteWithPasswordError {
    /// The handle already has a record — invite is create-only.
    Invite(InviteError),
    /// Sealing the operational key under the temp password failed.
    Crypto(CryptoError),
}

/// Build the op pair for an admin invite that ALSO provisions the invitee's
/// operational key, sealed under an admin-chosen temp password
/// (`specs/UserLifecycle.tla`'s `Invite`/`InvitedForcesChange`). Pure — see
/// [`crate::invite_user`]'s doc for the sign-then-apply contract the caller
/// must follow for EACH returned op, in order.
pub fn invite_user_with_temp_password(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    display_name: String,
    email: String,
    temp_password: &[u8],
    operational_key: &[u8],
    at: u64,
) -> Result<[UserOp; 2], InviteWithPasswordError> {
    let invite_op = invite_user(records, handle, display_name, email, at)
        .map_err(InviteWithPasswordError::Invite)?;
    let sealed = seal_operational_key(operational_key, temp_password)
        .map_err(InviteWithPasswordError::Crypto)?;
    let provision_op = UserOp::ProvisionOperationalKey {
        handle: handle.to_owned(),
        sealed,
        at,
    };
    Ok([invite_op, provision_op])
}

/// Error completing a self password change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordChangeError {
    /// No record exists for this handle.
    UnknownUser,
    /// The record has no sealed operational key yet (never invited with one).
    NoOperationalKey,
    /// `current_password` did not unseal the operational key — either it is
    /// wrong, or the record's sealed material is corrupt.
    IncorrectCurrentPassword,
    /// Re-sealing the (correctly unsealed) operational key under the new
    /// password failed.
    RewrapFailed(CryptoError),
}

/// Complete a self password change (`specs/UserLifecycle.tla`'s
/// `CompletePasswordChange`): prove knowledge of `current_password` by
/// unsealing the record's operational key with it, re-seal that SAME key
/// material under `new_password`, and clear `force_password_change`. Pure —
/// the caller applies the returned ops, in order, after signing + journaling
/// each exactly like every other portal act.
pub fn complete_self_password_change(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    current_password: &[u8],
    new_password: &[u8],
    at: u64,
) -> Result<[UserOp; 2], PasswordChangeError> {
    let record = records.get(handle).ok_or(PasswordChangeError::UnknownUser)?;
    let sealed = record
        .sealed_operational_key
        .as_ref()
        .ok_or(PasswordChangeError::NoOperationalKey)?;

    let operational_key = unseal_operational_key(sealed, current_password)
        .map_err(|_| PasswordChangeError::IncorrectCurrentPassword)?;

    let resealed = seal_operational_key(&operational_key, new_password)
        .map_err(PasswordChangeError::RewrapFailed)?;

    Ok([
        UserOp::ProvisionOperationalKey {
            handle: handle.to_owned(),
            sealed: resealed,
            at,
        },
        UserOp::PasswordChanged {
            handle: handle.to_owned(),
            at,
        },
    ])
}

/// Error building an admin-driven password reset
/// ([`admin_reset_password`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminResetError {
    /// No record exists for this handle.
    UnknownUser,
    /// Sealing the new operational key under the new password failed.
    Crypto(CryptoError),
}

/// Build the op pair for an ADMIN-driven password reset
/// (`admin-password-reset-reprovision`): generates a BRAND NEW operational
/// key (`new_operational_key` — the caller draws fresh random key material;
/// this function never re-derives or exposes the retiring key) sealed under
/// `new_password`, and forces the account through a password change on next
/// admit. Pure — the caller applies the returned ops, in order, after
/// signing + journaling each exactly like every other portal act, and must
/// gate the call on [`authorize_admin_password_reset`] first (the
/// step-up-gated `iam:credentials:manage` capability).
///
/// This retires the OLD sealed operational key through the SAME
/// [`UserOp::ProvisionOperationalKey`] op the invite and self-change paths
/// already use — the old sealed material is simply overwritten/replaced by
/// [`crate::apply_op`], the existing key-rotation machinery, never a
/// parallel retirement mechanism. It never touches the user's already-
/// registered WebAuthn/passkey credentials: those live in a separate
/// credential store this crate does not own, and this op pair only rotates
/// the password-sealed operational key + the forced-change label.
///
/// # Errors
///
/// [`AdminResetError::UnknownUser`] if `handle` has no record;
/// [`AdminResetError::Crypto`] if sealing the new key fails.
pub fn admin_reset_password(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    new_password: &[u8],
    new_operational_key: &[u8],
    at: u64,
) -> Result<[UserOp; 2], AdminResetError> {
    if !records.contains_key(handle) {
        return Err(AdminResetError::UnknownUser);
    }

    let sealed = seal_operational_key(new_operational_key, new_password)
        .map_err(AdminResetError::Crypto)?;

    Ok([
        UserOp::ProvisionOperationalKey {
            handle: handle.to_owned(),
            sealed,
            at,
        },
        UserOp::RequireChange {
            handle: handle.to_owned(),
            at,
        },
    ])
}

/// Decide whether `subject` may perform an admin-driven password reset
/// ([`admin_reset_password`]) right now — the step-up-gated
/// `iam:credentials:manage` capability, decided through the SAME
/// [`RbacDecider::decide`] every other Pillar capability check uses (see
/// [`crate::rbac_bridge::authorize_effective_capability`]'s doc for the
/// precedence lattice this preserves). A single call so every admin surface
/// (CLI, web portal) can never diverge on who may reset another user's
/// password, and a stale/absent step-up assertion is refused exactly like
/// every other sensitive roles/groups/credentials act
/// ([`sensitive_ops_step_up_policy`]).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn authorize_admin_password_reset(
    authority: &WotAuthority,
    policies: &[PolicyEvent],
    extra_grants: &[ExplicitGrant],
    subject: NodeId,
    now_secs: u64,
    step_up_assertion: Option<StepUpAssertion>,
) -> Decision {
    let step_up = sensitive_ops_step_up_policy();
    let decider = RbacDecider::new(authority, policies, extra_grants).with_step_up_policy(&step_up);
    let mut request = Request::new(subject, iam_credentials_manage_capability())
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    if let Some(assertion) = step_up_assertion {
        request = request.with_step_up(assertion);
    }
    decider.decide(&request)
}

/// A capability-gated act being admitted through the SHARED admit/dispatch
/// gate ([`admit_gated_action`]) — the same gate `user-disable-enable`
/// extends with its own `disabled` check, not a per-endpoint check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatedAction {
    /// Reading or updating the acting user's OWN profile (`GET`/`PUT
    /// /portal/profile`). Always permitted, even while contained — an
    /// invited/forced user must be able to see its own profile.
    OwnProfile,
    /// Completing the acting user's OWN password change
    /// ([`complete_self_password_change`]). Always permitted, even while
    /// contained — it is the ONLY way OUT of containment.
    OwnPasswordChange,
    /// Any other capability-gated act (`iam:users:write`, or any future
    /// capability) — refused while the acting user is contained.
    Other,
}

/// Why a gated act was refused admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// No record exists for this handle.
    UnknownUser,
    /// `force_password_change` is set and `action` is not one of the two
    /// exempted self-service acts (`specs/UserLifecycle.tla`'s
    /// `ForcedChangeContained`). The host surfaces this as
    /// `403 PASSWORD-CHANGE-REQUIRED`.
    PasswordChangeRequired,
}

/// The SHARED admit/dispatch gate: decide whether `handle` may perform
/// `action` right now, given its current forced-password-change containment
/// state. Called on EVERY capability-gated act (however the capability was
/// granted) — never a per-endpoint check — exactly like
/// [`crate::authorize_users_write`] is the single RBAC decision point for
/// admin writes. `user-disable-enable` extends this SAME function with its
/// `disabled` precondition rather than adding a parallel gate.
pub fn admit_gated_action(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    action: GatedAction,
    now: u64,
    max_password_age_secs: Option<u64>,
) -> Result<(), AdmitError> {
    let record = records.get(handle).ok_or(AdmitError::UnknownUser)?;
    let contained = record.force_password_change || is_password_over_age(record, now, max_password_age_secs);
    if contained && !matches!(action, GatedAction::OwnProfile | GatedAction::OwnPasswordChange) {
        return Err(AdmitError::PasswordChangeRequired);
    }
    Ok(())
}

/// True when `max_password_age_secs` is configured and the record's password
/// (or, absent any change yet, its creation) is older than that age as of
/// `now`.
fn is_password_over_age(record: &UserRecord, now: u64, max_password_age_secs: Option<u64>) -> bool {
    let Some(max_age) = max_password_age_secs else {
        return false;
    };
    let last_changed = record.password_changed_at.unwrap_or(record.created_at);
    now.saturating_sub(last_changed) > max_age
}

/// Evaluate a login attempt against the optional cell-wide
/// `max_password_age_secs` policy. Returns `Ok(Some(op))` — a
/// [`UserOp::RequireChange`] — when the record's password has gone stale past
/// the configured age, so the over-age login is forced-change on THIS admit
/// (`specs/UserLifecycle.tla`'s over-age-login rule, same `force_password_
/// change` field and the SAME [`admit_gated_action`] containment gate an
/// admin-set `RequireChange` uses — never a parallel mechanism). The caller
/// applies the returned op (sign + journal + [`crate::apply_op`]) BEFORE
/// admitting the session. `Ok(None)` means no forced-change transition is
/// needed on this login (it may already be set from a prior op — this
/// function never CLEARS the flag).
pub fn evaluate_login_password_age(
    records: &BTreeMap<String, UserRecord>,
    handle: &str,
    now: u64,
    max_password_age_secs: Option<u64>,
) -> Result<Option<UserOp>, AdmitError> {
    let record = records.get(handle).ok_or(AdmitError::UnknownUser)?;
    if record.force_password_change {
        return Ok(None);
    }
    if is_password_over_age(record, now, max_password_age_secs) {
        return Ok(Some(UserOp::RequireChange {
            handle: handle.to_owned(),
            at: now,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{apply_op, replay, UserStatus};

    fn provisioned_invite(handle: &str, temp_password: &[u8], key: &[u8], at: u64) -> BTreeMap<String, UserRecord> {
        let records = BTreeMap::new();
        let ops = invite_user_with_temp_password(
            &records,
            handle,
            format!("{handle} display"),
            format!("{handle}@example.com"),
            temp_password,
            key,
            at,
        )
        .expect("invite with temp password must succeed");
        replay(ops)
    }

    #[test]
    fn invite_provisions_a_sealed_operational_key_and_forces_password_change() {
        let records = provisioned_invite("alice", b"temp-pw-0001", b"alice-operational-key-material", 10);
        let alice = records.get("alice").expect("alice must be recorded");
        assert_eq!(alice.status, UserStatus::Invited);
        assert!(alice.force_password_change);
        assert!(
            alice.sealed_operational_key.is_some(),
            "invite must provision a sealed operational key"
        );

        let unsealed = unseal_operational_key(
            alice.sealed_operational_key.as_ref().unwrap(),
            b"temp-pw-0001",
        )
        .expect("the temp password must unseal the provisioned key");
        assert_eq!(unsealed, b"alice-operational-key-material");
    }

    #[test]
    fn self_password_change_reseals_the_same_key_and_clears_forced_change() {
        let mut records = provisioned_invite("bob", b"temp-pw-0002", b"bob-operational-key-material", 20);

        let ops = complete_self_password_change(&records, "bob", b"temp-pw-0002", b"bobs-new-password!", 30)
            .expect("a correct current password must complete the change");
        for op in ops {
            apply_op(&mut records, op);
        }

        let bob = records.get("bob").expect("bob must still be recorded");
        assert!(
            !bob.force_password_change,
            "a completed self password change must clear force_password_change"
        );
        assert_eq!(bob.password_changed_at, Some(30));

        // The operational key survives the re-seal unchanged, now reachable
        // ONLY via the new password.
        let unsealed = unseal_operational_key(bob.sealed_operational_key.as_ref().unwrap(), b"bobs-new-password!")
            .expect("the new password must unseal the resealed key");
        assert_eq!(unsealed, b"bob-operational-key-material");

        assert!(
            unseal_operational_key(bob.sealed_operational_key.as_ref().unwrap(), b"temp-pw-0002").is_err(),
            "the old temp password must no longer unseal the resealed key"
        );
    }

    #[test]
    fn self_password_change_with_a_wrong_current_password_is_refused() {
        let records = provisioned_invite("carol", b"temp-pw-0003", b"carol-operational-key-material", 40);

        let result = complete_self_password_change(&records, "carol", b"wrong-password", b"new-password", 50);
        assert_eq!(result, Err(PasswordChangeError::IncorrectCurrentPassword));

        // Refusal must be side-effect-free: force_password_change stays set.
        let carol = records.get("carol").unwrap();
        assert!(carol.force_password_change);
    }

    #[test]
    fn contained_user_may_only_use_its_own_profile_and_password_change_acts() {
        let records = provisioned_invite("dave", b"temp-pw-0004", b"dave-operational-key-material", 60);

        assert_eq!(
            admit_gated_action(&records, "dave", GatedAction::OwnProfile, 61, None),
            Ok(()),
            "an invited/contained user must be able to read/update its own profile"
        );
        assert_eq!(
            admit_gated_action(&records, "dave", GatedAction::OwnPasswordChange, 61, None),
            Ok(()),
            "an invited/contained user must be able to complete its own password change"
        );
        assert_eq!(
            admit_gated_action(&records, "dave", GatedAction::Other, 61, None),
            Err(AdmitError::PasswordChangeRequired),
            "every OTHER capability-gated act must be refused while contained"
        );
    }

    #[test]
    fn a_successful_self_change_uncontains_the_session() {
        let mut records = provisioned_invite("erin", b"temp-pw-0005", b"erin-operational-key-material", 70);
        let ops = complete_self_password_change(&records, "erin", b"temp-pw-0005", b"erins-new-password!", 80)
            .expect("correct current password must complete the change");
        for op in ops {
            apply_op(&mut records, op);
        }

        assert_eq!(
            admit_gated_action(&records, "erin", GatedAction::Other, 90, None),
            Ok(()),
            "a successful self password change must un-contain the session"
        );
    }

    #[test]
    fn max_password_age_forces_the_flag_on_an_over_age_login() {
        // finn changed their password at t=0 and is no longer freshly
        // invited (force_password_change already cleared by a prior change).
        let mut records = provisioned_invite("finn", b"temp-pw-0006", b"finn-operational-key-material", 0);
        let ops = complete_self_password_change(&records, "finn", b"temp-pw-0006", b"finns-second-password!", 0)
            .expect("initial self change must succeed");
        for op in ops {
            apply_op(&mut records, op);
        }
        assert!(!records.get("finn").unwrap().force_password_change);

        let max_age_secs = 100;
        let now_within_age = 50;
        assert_eq!(
            evaluate_login_password_age(&records, "finn", now_within_age, Some(max_age_secs)),
            Ok(None),
            "a login within max_password_age must not force a change"
        );

        let now_over_age = 500;
        let forced_op = evaluate_login_password_age(&records, "finn", now_over_age, Some(max_age_secs))
            .expect("evaluation must succeed")
            .expect("an over-age login must yield a RequireChange op");
        assert_eq!(
            forced_op,
            UserOp::RequireChange {
                handle: "finn".to_owned(),
                at: now_over_age,
            }
        );

        apply_op(&mut records, forced_op);
        assert!(
            records.get("finn").unwrap().force_password_change,
            "applying the over-age RequireChange op must set force_password_change"
        );
        assert_eq!(
            admit_gated_action(&records, "finn", GatedAction::Other, now_over_age, Some(max_age_secs)),
            Err(AdmitError::PasswordChangeRequired),
            "an over-age login must be contained on its next admit exactly like an admin RequireChange"
        );
    }

    #[test]
    fn admit_gated_action_on_an_unknown_handle_is_refused() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        assert_eq!(
            admit_gated_action(&records, "ghost", GatedAction::Other, 1, None),
            Err(AdmitError::UnknownUser)
        );
    }

    #[test]
    fn admin_reset_provisions_a_brand_new_key_and_forces_password_change() {
        let mut records = provisioned_invite("gina", b"temp-pw-0007", b"gina-original-operational-key", 5);

        // Gina completes her own change first, so the "old" key the admin
        // reset must retire is the SELF-CHOSEN one, not the invite temp one.
        let ops = complete_self_password_change(&records, "gina", b"temp-pw-0007", b"ginas-own-password!", 6)
            .expect("self change must succeed");
        for op in ops {
            apply_op(&mut records, op);
        }
        assert!(!records["gina"].force_password_change);

        let reset_ops = admin_reset_password(
            &records,
            "gina",
            b"admin-set-temp-password",
            b"gina-BRAND-NEW-operational-key",
            7,
        )
        .expect("admin reset of a known handle must succeed");
        for op in reset_ops {
            apply_op(&mut records, op);
        }

        let gina = records.get("gina").expect("gina must still be recorded");
        assert!(
            gina.force_password_change,
            "an admin reset must force a password change on next admit"
        );

        // The new admin-set password unseals the BRAND NEW key material —
        // never the old operational key.
        let unsealed = unseal_operational_key(
            gina.sealed_operational_key.as_ref().unwrap(),
            b"admin-set-temp-password",
        )
        .expect("the admin-set password must unseal the newly provisioned key");
        assert_eq!(unsealed, b"gina-BRAND-NEW-operational-key");
        assert_ne!(
            unsealed, b"gina-original-operational-key",
            "the admin reset must never re-derive or expose the retiring key"
        );

        // The retired key material is unreachable through EITHER prior
        // password — the old subkey is retired, not merely shadowed.
        assert!(
            unseal_operational_key(gina.sealed_operational_key.as_ref().unwrap(), b"temp-pw-0007").is_err(),
            "the original invite temp password must no longer unseal anything"
        );
        assert!(
            unseal_operational_key(gina.sealed_operational_key.as_ref().unwrap(), b"ginas-own-password!").is_err(),
            "the user's own prior self-chosen password must no longer unseal anything"
        );

        // The reset is contained exactly like every other forced-change
        // state: only self-profile/self-password-change acts admit.
        assert_eq!(
            admit_gated_action(&records, "gina", GatedAction::Other, 8, None),
            Err(AdmitError::PasswordChangeRequired)
        );
    }

    #[test]
    fn admin_reset_of_an_unknown_handle_is_refused() {
        let records: BTreeMap<String, UserRecord> = BTreeMap::new();
        assert_eq!(
            admin_reset_password(&records, "ghost", b"new-pw", b"new-key", 1),
            Err(AdminResetError::UnknownUser)
        );
    }

    #[test]
    fn admin_reset_requires_the_step_up_gated_iam_credentials_manage_capability() {
        use pillar_rbac::{GrantEffect, PolicyEvent};

        let authority = WotAuthority::new(NodeId::from("root"), 5);
        let policies: [PolicyEvent; 0] = [];
        let grants = [ExplicitGrant {
            subject: NodeId::from("admin"),
            capability: iam_credentials_manage_capability(),
            effect: GrantEffect::Allow,
        }];

        // No step-up assertion: the sensitive-ops policy refuses even a
        // subject holding the capability outright.
        assert_eq!(
            authorize_admin_password_reset(&authority, &policies, &grants, NodeId::from("admin"), 10, None),
            Decision::Deny,
            "admin credential reset must require a fresh step-up assertion"
        );

        // A fresh step-up assertion admits it.
        assert_eq!(
            authorize_admin_password_reset(
                &authority,
                &policies,
                &grants,
                NodeId::from("admin"),
                10,
                Some(StepUpAssertion::new(9, b"cred")),
            ),
            Decision::Allow
        );

        // A subject with no grant at all is refused regardless of step-up.
        assert_eq!(
            authorize_admin_password_reset(
                &authority,
                &policies,
                &grants,
                NodeId::from("stranger"),
                10,
                Some(StepUpAssertion::new(9, b"cred")),
            ),
            Decision::Deny
        );
    }
}
