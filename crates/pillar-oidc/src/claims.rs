//! Scope-gated OIDC claims mapping from the `pillar-iam` user record.
//!
//! Refines the `oidc-claims-from-user-record` task (ROI Priority 0 IAM epic).
//! This module is the pure projection of a [`pillar_iam::UserRecord`] plus the
//! session's authentication method into an OIDC claims set, gated by the
//! client's GRANTED scopes:
//!
//! | Scope | Claims released |
//! |---|---|
//! | `openid` (always) | `sub` (the stable handle) |
//! | `profile` | `name` (the display name) |
//! | `email` | `email`, `email_verified` |
//! | `roles` (pillar-specific) | `roles`, `groups` (resolved from the record) |
//!
//! A claim is NEVER released for a scope the client was not granted: a token
//! issued under bare `openid` carries only `sub`; `name`/`email` require
//! `profile`/`email`; `roles`/`groups` require the pillar `roles` scope. This
//! is the OIDC §5.4 "Claims using Scope Values" discipline made structural — a
//! claim can only ever appear if its gating scope is in the granted set.
//!
//! `acr`/`amr` reflect HOW the session was authenticated (per `stepup-mfa`):
//! `amr` reports `webauthn` (and an elevated `acr`) ONLY when a genuine
//! WebAuthn assertion gated the session, and `pwd`-only (with the baseline
//! `acr`) when only a password was used. These two authentication-context
//! claims are always present (they describe the token itself, not the user's
//! profile) and are independent of the profile/email/roles scope gates.

use std::collections::BTreeSet;

use pillar_iam::UserRecord;
use serde::{Deserialize, Serialize};

/// The `openid` scope — mandatory for any OIDC request; releases `sub`.
pub const SCOPE_OPENID: &str = "openid";
/// The `profile` scope — releases the `name` claim.
pub const SCOPE_PROFILE: &str = "profile";
/// The `email` scope — releases `email` + `email_verified`.
pub const SCOPE_EMAIL: &str = "email";
/// The pillar-specific `roles` scope — releases `roles` + `groups`.
pub const SCOPE_ROLES: &str = "roles";

/// `acr` value for a session whose ONLY factor was a password.
pub const ACR_PASSWORD: &str = "urn:pillar:acr:pwd";
/// `acr` value for a session a genuine WebAuthn assertion gated
/// (`stepup-mfa`).
pub const ACR_WEBAUTHN: &str = "urn:pillar:acr:mfa";

/// `amr` value for a password factor (RFC 8176 `pwd`).
pub const AMR_PWD: &str = "pwd";
/// `amr` value for a WebAuthn assertion (RFC 8176 `webauthn`).
pub const AMR_WEBAUTHN: &str = "webauthn";

/// How the session that a token is being minted for was authenticated. Drives
/// the `acr`/`amr` authentication-context claims (per `stepup-mfa`): a genuine
/// WebAuthn assertion is the ONLY thing that yields `amr = [pwd, webauthn]`
/// and the elevated `acr` — a password-only session can never claim
/// `webauthn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Only a password was verified for this session.
    PasswordOnly,
    /// A password AND a genuine WebAuthn assertion gated this session (the
    /// `stepup-mfa` second factor).
    PasswordAndWebAuthn,
}

impl AuthMethod {
    /// The `acr` (authentication context class reference) this method yields.
    #[must_use]
    pub fn acr(self) -> &'static str {
        match self {
            AuthMethod::PasswordOnly => ACR_PASSWORD,
            AuthMethod::PasswordAndWebAuthn => ACR_WEBAUTHN,
        }
    }

    /// The `amr` (authentication methods references) list this method yields —
    /// `webauthn` appears ONLY for a genuine assertion, never for a
    /// password-only session.
    #[must_use]
    pub fn amr(self) -> Vec<String> {
        match self {
            AuthMethod::PasswordOnly => vec![AMR_PWD.to_string()],
            AuthMethod::PasswordAndWebAuthn => {
                vec![AMR_PWD.to_string(), AMR_WEBAUTHN.to_string()]
            }
        }
    }

    /// Whether a genuine WebAuthn assertion gated this session.
    #[must_use]
    pub fn used_webauthn(self) -> bool {
        matches!(self, AuthMethod::PasswordAndWebAuthn)
    }
}

/// The OIDC claims released for a token, after scope gating. Every
/// profile/email/roles claim is `Option`/`Vec` and is populated ONLY when its
/// gating scope was granted; `sub`, `acr`, and `amr` are always present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSet {
    /// The stable subject identifier (the user handle). Always present
    /// (`openid`).
    pub sub: String,
    /// The display name — present ONLY under the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The contact email — present ONLY under the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email is verified — present ONLY under the `email` scope.
    /// Pillar user records carry an admin-provisioned email, treated as
    /// verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// The user's directly assigned roles — present ONLY under the pillar
    /// `roles` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// The user's group memberships — present ONLY under the pillar `roles`
    /// scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// Authentication context class reference — always present; elevated when
    /// a WebAuthn assertion gated the session.
    pub acr: String,
    /// Authentication methods references — always present; contains
    /// `webauthn` ONLY for a genuine assertion.
    pub amr: Vec<String>,
}

/// Project a user record + the session's authentication method into a
/// scope-gated OIDC claims set.
///
/// `granted` is the set of scopes the client actually holds (the intersection
/// of requested and consented scopes, as enforced by the authorize/token
/// endpoints). A claim is released ONLY when its gating scope is in `granted`;
/// a scope not present can never leak its claim. `acr`/`amr` are always
/// populated from `auth` (they describe the token, not the profile) and are
/// NOT gated by any scope.
#[must_use]
pub fn map_claims(
    record: &UserRecord,
    granted: &BTreeSet<String>,
    auth: AuthMethod,
) -> ClaimSet {
    let has = |scope: &str| granted.contains(scope);

    ClaimSet {
        sub: record.handle.clone(),
        name: has(SCOPE_PROFILE).then(|| record.display_name.clone()),
        email: has(SCOPE_EMAIL).then(|| record.email.clone()),
        email_verified: has(SCOPE_EMAIL).then_some(true),
        roles: has(SCOPE_ROLES).then(|| record.roles.iter().cloned().collect()),
        groups: has(SCOPE_ROLES).then(|| record.groups.iter().cloned().collect()),
        acr: auth.acr().to_string(),
        amr: auth.amr(),
    }
}

#[cfg(test)]
mod claims_mapping {
    use super::*;
    use pillar_iam::UserStatus;

    fn scopes(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn alice() -> UserRecord {
        UserRecord {
            handle: "alice".to_string(),
            display_name: "Alice Example".to_string(),
            email: "alice@example.com".to_string(),
            status: UserStatus::Active,
            roles: ["admin".to_string(), "editor".to_string()]
                .into_iter()
                .collect(),
            groups: ["staff".to_string()].into_iter().collect(),
            force_password_change: false,
            password_changed_at: Some(100),
            created_at: 0,
            updated_at: 0,
            sealed_operational_key: None,
            retired_operational_keys: Vec::new(),
        }
    }

    #[test]
    fn claims_mapping_openid_only_releases_sub_and_nothing_else() {
        let claims = map_claims(&alice(), &scopes(&["openid"]), AuthMethod::PasswordOnly);
        assert_eq!(claims.sub, "alice");
        // No profile/email/roles scope => none of those claims released.
        assert_eq!(claims.name, None);
        assert_eq!(claims.email, None);
        assert_eq!(claims.email_verified, None);
        assert_eq!(claims.roles, None);
        assert_eq!(claims.groups, None);
    }

    #[test]
    fn claims_mapping_profile_email_releases_name_and_email() {
        let claims = map_claims(
            &alice(),
            &scopes(&["openid", "profile", "email"]),
            AuthMethod::PasswordOnly,
        );
        assert_eq!(claims.name.as_deref(), Some("Alice Example"));
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        // But WITHOUT the pillar `roles` scope, roles/groups still do not leak.
        assert_eq!(claims.roles, None);
        assert_eq!(claims.groups, None);
    }

    #[test]
    fn claims_mapping_profile_alone_does_not_release_email() {
        let claims = map_claims(
            &alice(),
            &scopes(&["openid", "profile"]),
            AuthMethod::PasswordOnly,
        );
        assert_eq!(claims.name.as_deref(), Some("Alice Example"));
        // `profile` must not drag `email` along.
        assert_eq!(claims.email, None);
        assert_eq!(claims.email_verified, None);
    }

    #[test]
    fn claims_mapping_roles_and_groups_only_under_roles_scope() {
        // Without the roles scope: absent even though the record has them.
        let without = map_claims(
            &alice(),
            &scopes(&["openid", "profile", "email"]),
            AuthMethod::PasswordOnly,
        );
        assert_eq!(without.roles, None);
        assert_eq!(without.groups, None);

        // With the pillar `roles` scope: resolved from the record.
        let with = map_claims(
            &alice(),
            &scopes(&["openid", "roles"]),
            AuthMethod::PasswordOnly,
        );
        assert_eq!(
            with.roles,
            Some(vec!["admin".to_string(), "editor".to_string()])
        );
        assert_eq!(with.groups, Some(vec!["staff".to_string()]));
    }

    #[test]
    fn claims_mapping_amr_reports_webauthn_only_for_a_real_assertion() {
        // Password-only session: never `webauthn`, baseline acr.
        let pwd = map_claims(&alice(), &scopes(&["openid"]), AuthMethod::PasswordOnly);
        assert_eq!(pwd.amr, vec!["pwd".to_string()]);
        assert!(!pwd.amr.contains(&"webauthn".to_string()));
        assert_eq!(pwd.acr, ACR_PASSWORD);

        // WebAuthn-gated session: `webauthn` present, elevated acr.
        let mfa = map_claims(
            &alice(),
            &scopes(&["openid"]),
            AuthMethod::PasswordAndWebAuthn,
        );
        assert_eq!(mfa.amr, vec!["pwd".to_string(), "webauthn".to_string()]);
        assert!(mfa.amr.contains(&"webauthn".to_string()));
        assert_eq!(mfa.acr, ACR_WEBAUTHN);
    }

    #[test]
    fn claims_mapping_auth_context_is_not_scope_gated() {
        // acr/amr describe the token, not the profile: present even under
        // bare `openid` with no profile/email/roles scopes.
        let claims =
            map_claims(&alice(), &scopes(&["openid"]), AuthMethod::PasswordAndWebAuthn);
        assert_eq!(claims.acr, ACR_WEBAUTHN);
        assert!(claims.amr.contains(&"webauthn".to_string()));
        assert_eq!(claims.name, None);
    }
}
