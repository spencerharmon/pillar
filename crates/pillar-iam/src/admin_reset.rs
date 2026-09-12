//! Admin-driven password reset with operational-key re-provisioning —
//! `admin-password-reset-reprovision`.
//!
//! An admin who holds the step-up-gated [`crate::IAM_CREDENTIALS_MANAGE_CAPABILITY`]
//! capability may reset ANOTHER user's password. Unlike a self password change
//! ([`crate::complete_self_password_change`]), the admin does NOT know — and
//! never learns — the user's old password, so it CANNOT unseal the user's
//! existing operational key. A reset therefore CANNOT re-seal the same key
//! under a new password; instead it:
//!
//! 1. **Generates a genuinely NEW operational key** (fresh random material),
//!    sealed under the admin-CHOSEN new password. The old operational key is
//!    never re-derived, never unsealed, and never exposed to the admin.
//! 2. **Retires the OLD sealed subkey** via the record's retired-key list
//!    (the crate-local reflection of the existing identity-rotation /
//!    WoT-revocation machinery `key-rotation` owns): the superseded ciphertext
//!    is moved to [`UserRecord::retired_operational_keys`] and NO LONGER the
//!    record's live key, so the user's OLD password can never again unlock an
//!    operational key. It is retired, not silently dropped — the audit trail
//!    keeps the superseded material.
//! 3. **Preserves the user's WebAuthn/passkey credentials.** Those live in the
//!    `webauthn-rp-endpoints` [`pillar_web::webauthn::RelyingParty`] registry,
//!    filed per-handle and INDEPENDENT of the password-sealed operational key.
//!    A reset touches only the operational key on the [`UserRecord`]; it never
//!    revokes, lists, or re-registers a WebAuthn credential — so every already-
//!    registered passkey still lists and asserts after a reset.
//! 4. **Sets `force_password_change`.** The user is contained on next admit
//!    (the SAME [`crate::admit_gated_action`] gate) until they complete a self
//!    password change off the admin-chosen password.
//!
//! Authorization is the SAME [`crate::authorize_credentials_manage`] gate the
//! rest of the admin-credentials surface uses: `iam:credentials:manage`, always
//! step-up (`sensitive-ops-step-up`), through the shared
//! [`pillar_rbac::RbacDecider`]. No capability or a stale/absent step-up
//! assertion denies fail-closed. An admin may never reset their OWN password
//! through this surface (that is the self-service path).
//!
//! The plaintext new password is admin-CHOSEN and typed once into the request;
//! it is never returned to the admin, and the new operational key is generated
//! and sealed server-side without ever being handed back in a form the admin
//! can read.

use std::collections::BTreeMap;

use pillar_crypto::CryptoError;

use crate::admin_credentials::{AdminAuthContext, AdminCredentialError};
use crate::password_lifecycle::{seal_operational_key, SealedOperationalKey};
use crate::{UserOp, UserRecord};

/// The byte length of a freshly generated operational key. Matches the AEAD
/// symmetric-key size the custody path seals under.
const NEW_OPERATIONAL_KEY_LEN: usize = 32;

/// Why an admin password reset was refused. Every arm is a fail-closed refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminResetError {
    /// The acting admin lacks `iam:credentials:manage` right now, or presented
    /// no fresh step-up assertion for it. Fail-closed authorization denial.
    NotAuthorized,
    /// The admin targeted their OWN handle. Resetting one's own password is the
    /// self-service surface, not this admin one.
    SelfTargetForbidden,
    /// No record exists for the target handle.
    UnknownUser,
    /// Sealing the freshly generated operational key under the new password
    /// failed.
    Crypto(CryptoError),
}

impl From<AdminCredentialError> for AdminResetError {
    fn from(err: AdminCredentialError) -> Self {
        match err {
            AdminCredentialError::NotAuthorized => AdminResetError::NotAuthorized,
            AdminCredentialError::SelfTargetForbidden => AdminResetError::SelfTargetForbidden,
            // The reset surface never triggers the credential-specific arms.
            AdminCredentialError::NoSuchCredential
            | AdminCredentialError::LastCredentialNeedsConfirmation => {
                AdminResetError::NotAuthorized
            }
        }
    }
}

/// Generate a fresh random operational key. A reset never re-derives or exposes
/// the user's OLD key — it provisions genuinely new material.
fn generate_operational_key() -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut key = vec![0u8; NEW_OPERATIONAL_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Build the op for an admin-driven password reset. Pure — it authorizes,
/// generates a NEW operational key sealed under `new_password`, and returns the
/// single [`UserOp::AdminReset`] op the caller signs + journals + applies via
/// [`crate::apply_op`] exactly like every other portal act.
///
/// The op, when applied, RETIRES the target's current sealed operational key
/// (moving it to [`UserRecord::retired_operational_keys`]), installs the new
/// sealed key as the record's live key, and sets `force_password_change`. It
/// does NOT touch the target's WebAuthn credentials — those are preserved.
///
/// Authorization is the SAME step-up-gated `iam:credentials:manage` decision
/// the rest of the admin-credentials surface uses ([`AdminAuthContext`]).
///
/// # Errors
///
/// [`AdminResetError::NotAuthorized`] / [`AdminResetError::SelfTargetForbidden`]
/// on the gate; [`AdminResetError::UnknownUser`] if `target` has no record;
/// [`AdminResetError::Crypto`] if sealing the new key fails.
pub fn admin_reset_password(
    auth: &AdminAuthContext<'_>,
    records: &BTreeMap<String, UserRecord>,
    target: &str,
    new_password: &[u8],
    at: u64,
) -> Result<UserOp, AdminResetError> {
    // Reuse the shared credential-manage gate (self-target + step-up + cap).
    auth.admit_reset(target)?;

    let record = records.get(target).ok_or(AdminResetError::UnknownUser)?;
    // The old sealed key (if any) is retired by the op's apply path; we only
    // need to confirm the record exists here. The admin never unseals it.
    let _ = &record.sealed_operational_key;

    // A genuinely NEW operational key, sealed under the admin-chosen password.
    // The old key is never re-derived or exposed.
    let new_key = generate_operational_key();
    let sealed = seal_operational_key(&new_key, new_password).map_err(AdminResetError::Crypto)?;

    Ok(UserOp::AdminReset {
        handle: target.to_owned(),
        sealed,
        at,
    })
}

/// Fold an [`UserOp::AdminReset`] into `record`: retire the current live
/// operational key (append it to [`UserRecord::retired_operational_keys`]),
/// install `sealed` as the new live key, and set `force_password_change`. Kept
/// here beside the reset logic so the apply path and the op-builder stay
/// together; [`crate::apply_op`] delegates to it.
pub(crate) fn apply_admin_reset(record: &mut UserRecord, sealed: SealedOperationalKey, at: u64) {
    if let Some(old) = record.sealed_operational_key.take() {
        // Retire, never silently drop: keep the superseded ciphertext.
        record.retired_operational_keys.push(old);
    }
    record.sealed_operational_key = Some(sealed);
    record.force_password_change = true;
    record.updated_at = at;
}

impl AdminAuthContext<'_> {
    /// Run the shared credential-manage gate for a reset (self-target guard +
    /// step-up-gated `iam:credentials:manage`), mapping its refusal into an
    /// [`AdminResetError`].
    fn admit_reset(&self, target: &str) -> Result<(), AdminResetError> {
        self.authorize_target(target).map_err(AdminResetError::from)
    }
}

#[cfg(test)]
mod admin_reset {
    use super::*;
    use std::collections::BTreeMap;

    use pillar_core::NodeId;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
    use pillar_crypto::webauthn::ed25519_public_key_to_cose;
    use pillar_crypto::Seed;
    use pillar_rbac::StepUpAssertion;
    use pillar_wot_authority::WotAuthority;

    use pillar_web::webauthn::RelyingParty;

    use crate::password_lifecycle::{
        complete_self_password_change, invite_user_with_temp_password, unseal_operational_key,
    };
    use crate::rbac_bridge::{ManagedGroup, Role, IAM_CREDENTIALS_MANAGE_CAPABILITY};
    use crate::{apply_op, replay, UserOp, UserRecord};

    const TTL: u64 = 300;

    fn authority() -> WotAuthority {
        WotAuthority::new(NodeId::from("root"), 5)
    }

    // Roles fixture granting the admin iam:credentials:manage.
    fn roles() -> BTreeMap<String, Role> {
        let mut roles = BTreeMap::new();
        roles.insert(
            "cred-admin".to_owned(),
            Role::new("cred-admin", [IAM_CREDENTIALS_MANAGE_CAPABILITY]),
        );
        roles
    }

    // A target invited with a known temp password + operational key, plus an
    // admin holding cred-admin.
    fn setup() -> BTreeMap<String, UserRecord> {
        let base: BTreeMap<String, UserRecord> = BTreeMap::new();
        let target_ops = invite_user_with_temp_password(
            &base,
            "target",
            "Target".to_owned(),
            "target@example.com".to_owned(),
            b"old-temp-password",
            b"targets-original-operational-key",
            true,
            false,
            1,
        )
        .expect("invite target with temp password");
        let mut records = replay(target_ops);
        // The target completes its first self change so it has a NON-forced,
        // settled state before the admin reset (proves the reset re-forces).
        let ops = complete_self_password_change(
            &records,
            "target",
            b"old-temp-password",
            b"user-chosen-pw",
            2,
        )
        .expect("target self-change");
        for op in ops {
            apply_op(&mut records, op);
        }
        // The admin account + role grant.
        apply_op(
            &mut records,
            UserOp::Invite {
                handle: "admin".to_owned(),
                display_name: "Admin".to_owned(),
                email: "admin@example.com".to_owned(),
                force_password_change: true,
                require_passkey_enrollment: false,
                at: 1,
            },
        );
        apply_op(
            &mut records,
            UserOp::RoleAssign {
                handle: "admin".to_owned(),
                role: "cred-admin".to_owned(),
                at: 2,
            },
        );
        records
    }

    fn ctx<'a>(
        authority: &'a WotAuthority,
        records: &'a BTreeMap<String, UserRecord>,
        roles: &'a BTreeMap<String, Role>,
        groups: &'a BTreeMap<String, ManagedGroup>,
        step_up: Option<StepUpAssertion>,
    ) -> AdminAuthContext<'a> {
        AdminAuthContext {
            authority,
            policies: &[],
            extra_grants: &[],
            records,
            roles,
            groups,
            admin: "admin",
            now_secs: 10,
            step_up_assertion: step_up,
        }
    }

    // Register a WebAuthn credential in the shared registry for `handle`,
    // exactly as webauthn-rp-endpoints' register ceremony persists it.
    fn register(rp: &mut RelyingParty, handle: &str, cred: &[u8], seed: &str) {
        let (public, _secret) =
            signing_keypair_from_seed(&Seed::from_bytes(seed.as_bytes().to_vec())).expect("kg");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x40 | 0x01); // AT + UP
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred);
        auth_data.extend_from_slice(&cose);
        use ciborium::value::Value;
        let att = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut attestation = Vec::new();
        ciborium::into_writer(&att, &mut attestation).expect("enc");
        let ch = rp.begin("sess", "cell-A", 1000, TTL);
        rp.register_finish(
            "sess",
            "cell-A",
            1000,
            0,
            &ch,
            &attestation,
            [7u8; 32],
            handle,
            "key",
            "pillar.local",
        )
        .expect("register");
    }

    // Core property: after an admin reset, the OLD operational key no longer
    // unlocks (retired via the reset), while the new password unlocks a
    // genuinely NEW key (different material from the old one).
    #[test]
    fn admin_reset_installs_a_new_key_and_retires_the_old_one() {
        let authority = authority();
        let mut records = setup();
        let roles = roles();
        let groups = BTreeMap::new();

        // The target's live key BEFORE the reset unlocks under its own password.
        let old_sealed = records["target"].sealed_operational_key.clone().unwrap();
        let old_key = unseal_operational_key(&old_sealed, b"user-chosen-pw")
            .expect("the user's own password unseals the old key before reset");

        // Admin resets with a fresh step-up assertion.
        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"reset")),
        );
        let op = admin_reset_password(&auth, &records, "target", b"admin-chosen-new-pw", 20)
            .expect("authorized admin reset must succeed");
        apply_op(&mut records, op);

        let target = &records["target"];

        // force_password_change is re-set by the reset.
        assert!(
            target.force_password_change,
            "an admin reset must set force_password_change"
        );

        // The NEW live key unlocks ONLY under the admin-chosen new password.
        let new_sealed = target.sealed_operational_key.clone().unwrap();
        let new_key = unseal_operational_key(&new_sealed, b"admin-chosen-new-pw")
            .expect("the admin-chosen new password unseals the newly provisioned key");

        // The key material is GENUINELY NEW — not a re-seal of the old key.
        assert_ne!(
            new_key, old_key,
            "an admin reset generates a genuinely new operational key, never re-derives the old"
        );

        // The OLD password no longer unlocks the live key (it was retired).
        assert!(
            unseal_operational_key(&new_sealed, b"user-chosen-pw").is_err(),
            "the user's OLD password must no longer unlock the live operational key after reset"
        );

        // The old subkey is retired (kept for audit), not silently dropped.
        assert_eq!(
            target.retired_operational_keys.len(),
            1,
            "the superseded operational key is retired, not dropped"
        );
        assert_eq!(
            target.retired_operational_keys[0], old_sealed,
            "the retired key is exactly the superseded sealed material"
        );
    }

    // The user's WebAuthn/passkey credentials survive an admin reset: they are
    // filed independently in the RelyingParty registry and never touched.
    #[test]
    fn admin_reset_preserves_webauthn_credentials() {
        let authority = authority();
        let mut records = setup();
        let roles = roles();
        let groups = BTreeMap::new();

        // The target has two registered passkeys before the reset.
        let mut rp = RelyingParty::new();
        register(&mut rp, "target", b"passkey-1", "auth-1");
        register(&mut rp, "target", b"passkey-2", "auth-2");
        let before: Vec<Vec<u8>> = rp
            .user_credentials("target")
            .into_iter()
            .map(|c| c.credential_id.clone())
            .collect();
        assert_eq!(before.len(), 2);

        // Admin resets the password (touches only the operational key).
        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"reset")),
        );
        let op = admin_reset_password(&auth, &records, "target", b"admin-chosen-new-pw", 20)
            .expect("reset succeeds");
        apply_op(&mut records, op);

        // The registry is untouched — every passkey still lists...
        let after: Vec<Vec<u8>> = rp
            .user_credentials("target")
            .into_iter()
            .map(|c| c.credential_id.clone())
            .collect();
        assert_eq!(
            after, before,
            "an admin reset must preserve every already-registered WebAuthn credential"
        );
        // ...and still asserts (the record is live in the registry).
        assert!(
            rp.user_owns_credential("target", b"passkey-1"),
            "a preserved passkey still owns/asserts after a reset"
        );
        assert!(rp.user_owns_credential("target", b"passkey-2"));
    }

    // The reset is denied without iam:credentials:manage AND without a fresh
    // step-up assertion; self-targeting is forbidden.
    #[test]
    fn admin_reset_requires_capability_and_fresh_step_up() {
        let authority = authority();
        let records = setup();
        let roles = roles();
        let groups = BTreeMap::new();

        // No step-up assertion → denied (this capability is ALWAYS step-up gated).
        let auth = ctx(&authority, &records, &roles, &groups, None);
        assert_eq!(
            admin_reset_password(&auth, &records, "target", b"new-pw", 20),
            Err(AdminResetError::NotAuthorized),
            "a reset without a fresh step-up assertion must be denied"
        );

        // A subject WITHOUT the capability is denied even with a fresh assertion.
        let stranger_ctx = AdminAuthContext {
            authority: &authority,
            policies: &[],
            extra_grants: &[],
            records: &records,
            roles: &roles,
            groups: &groups,
            admin: "target", // target holds no cred-admin role
            now_secs: 10,
            step_up_assertion: Some(StepUpAssertion::new(9, b"reset")),
        };
        assert_eq!(
            admin_reset_password(&stranger_ctx, &records, "admin", b"new-pw", 20),
            Err(AdminResetError::NotAuthorized),
            "a subject lacking iam:credentials:manage cannot reset, even with a step-up"
        );

        // Self-target is forbidden even when otherwise authorized.
        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"reset")),
        );
        assert_eq!(
            admin_reset_password(&auth, &records, "admin", b"new-pw", 20),
            Err(AdminResetError::SelfTargetForbidden),
            "an admin may never reset their own password through this admin surface"
        );

        // Unknown target → UnknownUser (when otherwise authorized).
        assert_eq!(
            admin_reset_password(&auth, &records, "ghost", b"new-pw", 20),
            Err(AdminResetError::UnknownUser)
        );
    }

    // The AdminReset op is a signed, verifiable, journal-able payload like every
    // other IAM op, and replays deterministically through apply_op.
    #[test]
    fn admin_reset_op_is_a_signed_replayable_op() {
        let authority = authority();
        let records = setup();
        let roles = roles();
        let groups = BTreeMap::new();

        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"reset")),
        );
        let op = admin_reset_password(&auth, &records, "target", b"admin-chosen-new-pw", 20)
            .expect("reset succeeds");

        // Signs + verifies like any other portal act.
        let seed = Seed::from_bytes(b"pillar-iam-test::admin-reset".to_vec());
        let (public, secret) = signing_keypair_from_seed(&seed).expect("keygen");
        let payload = serde_json::to_vec(&op).expect("op serializes");
        let sig = sign(&secret, &payload).expect("sign");
        verify(&public, &payload, &sig).expect("the signed admin-reset op must verify");

        // Replaying the same op sequence reproduces the identical state.
        let mut a = records.clone();
        let mut b = records.clone();
        apply_op(&mut a, op.clone());
        apply_op(&mut b, op);
        assert_eq!(
            a["target"], b["target"],
            "apply_op is deterministic for AdminReset"
        );
    }

    // After a reset, the user escapes containment by completing a self password
    // change off the admin-chosen password — proving the new key is fully usable.
    #[test]
    fn admin_reset_new_key_supports_a_subsequent_self_change() {
        let authority = authority();
        let mut records = setup();
        let roles = roles();
        let groups = BTreeMap::new();

        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"reset")),
        );
        let op = admin_reset_password(&auth, &records, "target", b"admin-chosen-new-pw", 20)
            .expect("reset succeeds");
        apply_op(&mut records, op);
        assert!(records["target"].force_password_change);

        // The user changes off the admin-chosen password to their own.
        let ops = complete_self_password_change(
            &records,
            "target",
            b"admin-chosen-new-pw",
            b"users-fresh-password",
            30,
        )
        .expect("the admin-chosen password must unseal the reset key for a self change");
        for op in ops {
            apply_op(&mut records, op);
        }
        assert!(
            !records["target"].force_password_change,
            "completing the self change off the reset password clears containment"
        );
        let sealed = records["target"].sealed_operational_key.clone().unwrap();
        assert!(
            unseal_operational_key(&sealed, b"users-fresh-password").is_ok(),
            "the user's fresh password unseals the key after the reset + self change"
        );
    }
}
