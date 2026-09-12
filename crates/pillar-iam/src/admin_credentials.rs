//! Admin credential management — `admin-manage-user-credentials`.
//!
//! A capability-gated (`iam:credentials:manage`, ALWAYS step-up) surface for an
//! admin to LIST and REVOKE **another** user's WebAuthn/passkey credentials, and
//! to ISSUE an enrollment invite for a new hardware key. It is a thin,
//! authorization-first wrapper over `webauthn-rp-endpoints`' shared credential
//! registry ([`pillar_web::webauthn::RelyingParty`]) — it never opens a second
//! credential store or a parallel authorization mechanism.
//!
//! ## The three admin acts and their invariants
//!
//! - **list** ([`admin_list_credentials`]) — read every live credential of a
//!   target handle. Read-only, but still `iam:credentials:manage`+step-up gated:
//!   another user's registered-authenticator inventory is custody metadata.
//! - **revoke** ([`admin_revoke_credential`]) — fail-closed delete of one of the
//!   target's credentials, reusing [`RelyingParty::revoke`] (grow-only,
//!   `RevokedKeyNeverAdmits`). The **last-key confirmation guard** still applies:
//!   revoking the target's SOLE remaining credential is refused
//!   ([`AdminCredentialError::LastCredentialNeedsConfirmation`]) unless the admin
//!   passes `confirm_last = true` — a lost/stolen sole key must stay revocable
//!   (else the account is unrecoverable) but never by accident. This reuses the
//!   SAME "is this the last key" definition the self-service surface enforces
//!   ([`RelyingParty::is_last_credential`]), so admin and user can never diverge.
//! - **enroll invite** ([`admin_issue_enrollment_invite`]) — an admin can NEVER
//!   register a hardware key on the target's behalf: minting a credential
//!   requires the target user's OWN authenticator completing the registration
//!   ceremony. The admin act is therefore only an *invitation* — a signed,
//!   journaled [`EnrollmentInvite`] the target later redeems by driving the real
//!   `webauthn-rp-endpoints` register ceremony from their own device.
//!
//! ## Authorization
//!
//! Every act runs through [`authorize_credentials_manage`], which is
//! [`crate::rbac_bridge::authorize_effective_capability`] pinned to
//! `iam:credentials:manage` with [`crate::sensitive_ops_step_up_policy`] — the
//! SAME shared [`pillar_rbac::RbacDecider`] and step-up lattice every other
//! sensitive Pillar act uses (fail-closed: no capability, or a stale/absent
//! step-up assertion → [`pillar_rbac::Decision::Deny`]). An admin may never
//! manage their OWN credentials through this surface (that is the self-service
//! path); [`AdminCredentialError::SelfTargetForbidden`] guards it.

use std::collections::BTreeMap;

use pillar_rbac::{Decision, ExplicitGrant, PolicyEvent, StepUpAssertion};
use pillar_wot_authority::WotAuthority;

use pillar_web::webauthn::{CredentialRecord, RelyingParty};

use crate::rbac_bridge::{
    authorize_effective_capability, sensitive_ops_step_up_policy, ManagedGroup, Role,
    IAM_CREDENTIALS_MANAGE_CAPABILITY,
};
use crate::UserRecord;

/// Why an admin credential-management act was refused. Every arm is a
/// fail-closed refusal — the surface never acts on ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminCredentialError {
    /// The acting admin lacks `iam:credentials:manage` right now, or presented
    /// no fresh step-up assertion for it. Fail-closed authorization denial.
    NotAuthorized,
    /// The admin targeted their OWN handle. Managing one's own credentials is
    /// the self-service surface, not this admin one.
    SelfTargetForbidden,
    /// No credential with the given id is a live credential of the target
    /// handle (unknown id, or it belongs to someone else).
    NoSuchCredential,
    /// The revoke would remove the target's SOLE remaining credential and the
    /// admin did not pass `confirm_last = true`. Re-issue with confirmation to
    /// proceed (a lost sole key must stay revocable, but never by accident).
    LastCredentialNeedsConfirmation,
}

/// A signed, journaled admin invitation for the target user to enroll a NEW
/// hardware key from their OWN authenticator. This is the ONLY credential-
/// creation act an admin can perform: it grants no credential itself — the
/// target must later complete the real `webauthn-rp-endpoints` register
/// ceremony on their device to mint the credential. Modeled as its own op so
/// the host signs + journals it exactly like every other IAM mutation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentInvite {
    /// The user who may redeem this invite (whose own authenticator must
    /// complete the ceremony).
    pub target_handle: String,
    /// The admin handle that issued the invite (for the audit trail).
    pub issued_by: String,
    /// Unix seconds the invite was issued.
    pub issued_at: u64,
    /// Unix seconds the invite stops being redeemable.
    pub expires_at: u64,
}

impl EnrollmentInvite {
    /// Whether the invite is still redeemable at `now` (issued, not expired).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now <= self.expires_at
    }
}

/// Decide whether `admin` may manage another user's credentials right now:
/// `iam:credentials:manage`, step-up gated with the shared sensitive-ops
/// policy, through the SAME [`authorize_effective_capability`] path every other
/// role/group-derived capability check uses. Fail-closed — no capability or a
/// stale/absent step-up assertion denies.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn authorize_credentials_manage(
    authority: &WotAuthority,
    policies: &[PolicyEvent],
    extra_grants: &[ExplicitGrant],
    records: &BTreeMap<String, UserRecord>,
    roles: &BTreeMap<String, Role>,
    groups: &BTreeMap<String, ManagedGroup>,
    admin: &str,
    now_secs: u64,
    step_up_assertion: Option<StepUpAssertion>,
) -> Decision {
    let step_up = sensitive_ops_step_up_policy();
    authorize_effective_capability(
        authority,
        policies,
        extra_grants,
        records,
        roles,
        groups,
        &step_up,
        admin,
        IAM_CREDENTIALS_MANAGE_CAPABILITY,
        now_secs,
        step_up_assertion,
    )
}

/// The bundle of inputs the shared RBAC gate needs, so the three admin acts can
/// each run the SAME authorization without a huge argument list.
pub struct AdminAuthContext<'a> {
    /// The WoT authority the decider consults.
    pub authority: &'a WotAuthority,
    /// Any pre-existing policy events.
    pub policies: &'a [PolicyEvent],
    /// Any pre-existing explicit grants (an explicit deny here still wins).
    pub extra_grants: &'a [ExplicitGrant],
    /// The user records (for role/group-derived capability resolution).
    pub records: &'a BTreeMap<String, UserRecord>,
    /// The role definitions.
    pub roles: &'a BTreeMap<String, Role>,
    /// The managed-group definitions.
    pub groups: &'a BTreeMap<String, ManagedGroup>,
    /// The acting admin's handle.
    pub admin: &'a str,
    /// The wall-clock time of the act.
    pub now_secs: u64,
    /// The admin's fresh step-up assertion (required — this capability is
    /// always step-up gated).
    pub step_up_assertion: Option<StepUpAssertion>,
}

impl AdminAuthContext<'_> {
    /// Run the shared gate and the self-target guard: `Ok(())` iff the admin is
    /// authorized AND `target` is not the admin's own handle. Reused by the
    /// admin-reset surface (`admin-password-reset-reprovision`) so it can never
    /// diverge from the credential surface's authorization.
    pub(crate) fn authorize_target(&self, target: &str) -> Result<(), AdminCredentialError> {
        self.admit(target)
    }

    /// Run the shared gate and the self-target guard: `Ok(())` iff the admin is
    /// authorized AND `target` is not the admin's own handle.
    fn admit(&self, target: &str) -> Result<(), AdminCredentialError> {
        if self.admin == target {
            return Err(AdminCredentialError::SelfTargetForbidden);
        }
        match authorize_credentials_manage(
            self.authority,
            self.policies,
            self.extra_grants,
            self.records,
            self.roles,
            self.groups,
            self.admin,
            self.now_secs,
            self.step_up_assertion.clone(),
        ) {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(AdminCredentialError::NotAuthorized),
        }
    }
}

/// LIST every live credential of `target` — the admin inventory read. Gated:
/// the admin must be authorized and `target` must not be the admin's own
/// handle. The records are cloned so the caller holds no borrow on the registry.
///
/// # Errors
///
/// [`AdminCredentialError::NotAuthorized`] / [`AdminCredentialError::SelfTargetForbidden`].
pub fn admin_list_credentials(
    auth: &AdminAuthContext<'_>,
    rp: &RelyingParty,
    target: &str,
) -> Result<Vec<CredentialRecord>, AdminCredentialError> {
    auth.admit(target)?;
    Ok(rp.user_credentials(target).into_iter().cloned().collect())
}

/// REVOKE one of `target`'s credentials by id, reusing
/// [`RelyingParty::revoke`] (fail-closed, grow-only). The last-key confirmation
/// guard applies: revoking the target's SOLE remaining credential is refused
/// unless `confirm_last = true`.
///
/// # Errors
///
/// [`AdminCredentialError::NotAuthorized`] / [`AdminCredentialError::SelfTargetForbidden`]
/// on the gate; [`AdminCredentialError::NoSuchCredential`] if `credential_id`
/// is not a live credential of `target`;
/// [`AdminCredentialError::LastCredentialNeedsConfirmation`] if it is the
/// target's last key and `confirm_last` is `false`.
pub fn admin_revoke_credential(
    auth: &AdminAuthContext<'_>,
    rp: &mut RelyingParty,
    target: &str,
    credential_id: &[u8],
    confirm_last: bool,
) -> Result<(), AdminCredentialError> {
    auth.admit(target)?;
    // Ownership check: the credential must be a live credential of the target
    // (never one belonging to someone else, never an unknown id).
    if !rp.user_owns_credential(target, credential_id) {
        return Err(AdminCredentialError::NoSuchCredential);
    }
    // Last-key confirmation guard — the SAME definition the self-service
    // surface uses.
    if rp.is_last_credential(target, credential_id) && !confirm_last {
        return Err(AdminCredentialError::LastCredentialNeedsConfirmation);
    }
    rp.revoke(credential_id);
    Ok(())
}

/// Issue an enrollment invite for `target` to add a NEW hardware key from their
/// OWN authenticator. An admin can NEVER mint a credential directly — this
/// returns only the invite the target later redeems by driving the real
/// register ceremony. The caller signs + journals the returned invite exactly
/// like every other IAM op.
///
/// # Errors
///
/// [`AdminCredentialError::NotAuthorized`] / [`AdminCredentialError::SelfTargetForbidden`].
pub fn admin_issue_enrollment_invite(
    auth: &AdminAuthContext<'_>,
    target: &str,
    ttl_secs: u64,
) -> Result<EnrollmentInvite, AdminCredentialError> {
    auth.admit(target)?;
    Ok(EnrollmentInvite {
        target_handle: target.to_owned(),
        issued_by: auth.admin.to_owned(),
        issued_at: auth.now_secs,
        expires_at: auth.now_secs.saturating_add(ttl_secs),
    })
}

#[cfg(test)]
mod admin_credentials {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use pillar_core::NodeId;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
    use pillar_crypto::webauthn::ed25519_public_key_to_cose;
    use pillar_crypto::Seed;
    use pillar_rbac::{ExplicitGrant, GrantEffect};

    use crate::rbac_bridge::iam_credentials_manage_capability;
    use crate::{replay, UserOp};

    const TTL: u64 = 300;

    // Build a target handle plus a registered credential in the shared
    // registry, exactly the shape webauthn-rp-endpoints' register ceremony
    // persists. We register through the real `register_finish` ceremony so we
    // reuse the SAME store admin acts operate on.
    fn authenticator(label: &str) -> Vec<u8> {
        let (public, _secret) =
            signing_keypair_from_seed(&Seed::from_bytes(label.as_bytes().to_vec())).expect("kg");
        ed25519_public_key_to_cose(&public).expect("cose")
    }

    fn attestation(cose: &[u8], credential_id: &[u8]) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x40 | 0x01); // AT + UP
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose);
        use ciborium::value::Value;
        let att = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&att, &mut out).expect("enc");
        out
    }

    fn register(rp: &mut RelyingParty, user_handle: &str, cred: &[u8], seed: &str) {
        let cose = authenticator(seed);
        let ch = rp.begin("sess", "cell-A", 1000, TTL);
        rp.register_finish(
            "sess",
            "cell-A",
            1000,
            0,
            &ch,
            &attestation(&cose, cred),
            [7u8; 32],
            user_handle,
            "key",
            "pillar.local",
        )
        .expect("register");
    }

    fn records() -> BTreeMap<String, UserRecord> {
        replay([
            UserOp::Invite {
                handle: "admin".to_owned(),
                display_name: "Admin".to_owned(),
                email: "admin@example.com".to_owned(),
                force_password_change: true,
                require_passkey_enrollment: false,
                at: 1,
            },
            UserOp::Invite {
                handle: "target".to_owned(),
                display_name: "Target".to_owned(),
                email: "target@example.com".to_owned(),
                force_password_change: true,
                require_passkey_enrollment: false,
                at: 1,
            },
        ])
    }

    // A role fixture granting the admin iam:credentials:manage.
    fn roles() -> BTreeMap<String, Role> {
        let mut roles = BTreeMap::new();
        roles.insert(
            "cred-admin".to_owned(),
            Role::new("cred-admin", [IAM_CREDENTIALS_MANAGE_CAPABILITY]),
        );
        roles
    }

    fn admin_records() -> BTreeMap<String, UserRecord> {
        let mut records = records();
        crate::apply_op(
            &mut records,
            UserOp::RoleAssign {
                handle: "admin".to_owned(),
                role: "cred-admin".to_owned(),
                at: 2,
            },
        );
        records
    }

    fn authority() -> WotAuthority {
        WotAuthority::new(NodeId::from("root"), 5)
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

    // The gate: a fresh step-up assertion admits; no assertion denies (the
    // capability is ALWAYS step-up gated); a subject without the capability
    // denies fail-closed.
    #[test]
    fn admin_credentials_authorization_requires_capability_and_fresh_step_up() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();

        // With the role AND a fresh step-up assertion → Allow.
        let d = authorize_credentials_manage(
            &authority,
            &[],
            &[],
            &records,
            &roles,
            &groups,
            "admin",
            10,
            Some(StepUpAssertion::new(9, b"cred")),
        );
        assert_eq!(d, Decision::Allow);

        // Same role, but NO step-up assertion → Deny (always step-up gated).
        let d = authorize_credentials_manage(
            &authority,
            &[],
            &[],
            &records,
            &roles,
            &groups,
            "admin",
            10,
            None,
        );
        assert_eq!(d, Decision::Deny);

        // A handle WITHOUT the capability → Deny even with a fresh assertion.
        let d = authorize_credentials_manage(
            &authority,
            &[],
            &[],
            &records,
            &roles,
            &groups,
            "target",
            10,
            Some(StepUpAssertion::new(9, b"cred")),
        );
        assert_eq!(d, Decision::Deny);
    }

    // An explicit deny in extra_grants beats the role-derived allow — the
    // shared lattice's fail-closed precedence is preserved through this surface.
    #[test]
    fn admin_credentials_explicit_deny_beats_role_allow() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();
        let extra = [ExplicitGrant {
            subject: NodeId::from("admin"),
            capability: iam_credentials_manage_capability(),
            effect: GrantEffect::Deny,
        }];
        let d = authorize_credentials_manage(
            &authority,
            &[],
            &extra,
            &records,
            &roles,
            &groups,
            "admin",
            10,
            Some(StepUpAssertion::new(9, b"cred")),
        );
        assert_eq!(d, Decision::Deny);
    }

    // list returns every live credential of the target; an unauthorized admin
    // (no step-up) is refused; targeting one's own handle is refused.
    #[test]
    fn admin_credentials_list_is_gated_and_reads_the_shared_registry() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();
        let mut rp = RelyingParty::new();
        register(&mut rp, "target", b"cred-1", "auth-1");
        register(&mut rp, "target", b"cred-2", "auth-2");

        // Authorized (fresh step-up) → both credentials.
        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"c")),
        );
        let creds = admin_list_credentials(&auth, &rp, "target").expect("authorized list");
        let ids: BTreeSet<Vec<u8>> = creds.iter().map(|c| c.credential_id.clone()).collect();
        assert_eq!(
            ids,
            BTreeSet::from([b"cred-1".to_vec(), b"cred-2".to_vec()]),
            "list must return every live credential of the target from the shared registry"
        );

        // No step-up → NotAuthorized.
        let auth = ctx(&authority, &records, &roles, &groups, None);
        assert_eq!(
            admin_list_credentials(&auth, &rp, "target"),
            Err(AdminCredentialError::NotAuthorized)
        );

        // Self-target → forbidden even when otherwise authorized.
        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"c")),
        );
        assert_eq!(
            admin_list_credentials(&auth, &rp, "admin"),
            Err(AdminCredentialError::SelfTargetForbidden)
        );
    }

    // revoke removes one of several credentials (reusing RelyingParty::revoke,
    // fail-closed); an unknown/foreign id is NoSuchCredential.
    #[test]
    fn admin_credentials_revoke_deletes_a_credential_and_fails_closed_forever() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();
        let mut rp = RelyingParty::new();
        register(&mut rp, "target", b"cred-1", "auth-1");
        register(&mut rp, "target", b"cred-2", "auth-2");

        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"c")),
        );

        // Revoke cred-1 (not the last key → no confirmation needed).
        admin_revoke_credential(&auth, &mut rp, "target", b"cred-1", false).expect("revoke");
        assert!(rp.record(b"cred-1").is_none(), "revoked credential is gone");
        // The revoke is grow-only/fail-closed: it can never be re-registered.
        let cose = authenticator("auth-1");
        let ch = rp.begin("sess", "cell-A", 1000, TTL);
        assert!(
            rp.register_finish(
                "sess",
                "cell-A",
                1000,
                0,
                &ch,
                &attestation(&cose, b"cred-1"),
                [7u8; 32],
                "target",
                "key",
                "pillar.local",
            )
            .is_err(),
            "a revoked credential never re-registers (RevokedKeyNeverAdmits)"
        );
        assert!(
            rp.record(b"cred-1").is_none(),
            "a revoked credential stays gone"
        );

        // Unknown id → NoSuchCredential.
        assert_eq!(
            admin_revoke_credential(&auth, &mut rp, "target", b"ghost", false),
            Err(AdminCredentialError::NoSuchCredential)
        );

        // A credential belonging to a DIFFERENT user is not revocable via this
        // target (ownership check).
        register(&mut rp, "other", b"other-cred", "auth-x");
        assert_eq!(
            admin_revoke_credential(&auth, &mut rp, "target", b"other-cred", false),
            Err(AdminCredentialError::NoSuchCredential)
        );
    }

    // The last-key confirmation guard: revoking the target's SOLE credential is
    // refused without confirm_last, but succeeds WITH it — reusing the same
    // is_last_credential definition the self-service surface uses.
    #[test]
    fn admin_credentials_last_key_revoke_needs_explicit_confirmation() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();
        let mut rp = RelyingParty::new();
        register(&mut rp, "target", b"only-cred", "auth-1");

        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"c")),
        );

        // Without confirmation → refused, credential retained.
        assert_eq!(
            admin_revoke_credential(&auth, &mut rp, "target", b"only-cred", false),
            Err(AdminCredentialError::LastCredentialNeedsConfirmation)
        );
        assert!(
            rp.record(b"only-cred").is_some(),
            "the sole key is retained when confirmation is withheld"
        );

        // With explicit confirmation → the lost/stolen sole key is revocable.
        admin_revoke_credential(&auth, &mut rp, "target", b"only-cred", true)
            .expect("confirmed last-key revoke succeeds");
        assert!(
            rp.record(b"only-cred").is_none(),
            "confirmed last-key revoke deletes it"
        );
    }

    // An admin can only ISSUE an enrollment invite — never mint a credential.
    // The invite is a signed, journaled, time-bounded artifact; the registry is
    // untouched (the target must complete the ceremony from their own device).
    #[test]
    fn admin_credentials_enroll_is_an_invite_never_a_direct_registration() {
        let authority = authority();
        let records = admin_records();
        let roles = roles();
        let groups = BTreeMap::new();
        let rp_before = RelyingParty::new();

        let auth = ctx(
            &authority,
            &records,
            &roles,
            &groups,
            Some(StepUpAssertion::new(9, b"c")),
        );
        let invite = admin_issue_enrollment_invite(&auth, "target", TTL).expect("issue invite");
        assert_eq!(invite.target_handle, "target");
        assert_eq!(invite.issued_by, "admin");
        assert!(
            invite.is_valid_at(10),
            "issued invite is valid at issue time"
        );
        assert!(invite.is_valid_at(10 + TTL), "valid up to expiry");
        assert!(!invite.is_valid_at(10 + TTL + 1), "expired after its TTL");

        // Crucially: no credential was created — the admin cannot register on
        // the target's behalf; the target must use their OWN authenticator.
        assert!(
            rp_before.user_credentials("target").is_empty(),
            "issuing an invite mints no credential"
        );

        // The invite is a signed, verifiable payload like every other IAM op.
        let seed = Seed::from_bytes(b"pillar-iam-test::enroll-invite".to_vec());
        let (public, secret) = signing_keypair_from_seed(&seed).expect("keygen");
        let payload = serde_json::to_vec(&invite).expect("invite serializes");
        let sig = sign(&secret, &payload).expect("sign");
        verify(&public, &payload, &sig).expect("the signed enrollment invite must verify");

        // An unauthorized admin (no step-up) cannot issue an invite either.
        let auth = ctx(&authority, &records, &roles, &groups, None);
        assert_eq!(
            admin_issue_enrollment_invite(&auth, "target", TTL),
            Err(AdminCredentialError::NotAuthorized)
        );
    }
}
