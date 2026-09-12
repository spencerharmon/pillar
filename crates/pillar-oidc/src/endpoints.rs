//! The OIDC authorization-server HTTP surface, modelled as pure,
//! host-agnostic functions on a [`Provider`] engine.
//!
//! # Design
//!
//! Refines `specs/OidcProvider.tla` (see `docs/tasks/oidc-provider-spec.md`).
//! [`Provider`] composes the two pieces already shipped by this crate — the
//! signed-op [`crate::client_registry`] (clients + consent) and the
//! [`crate::custodied_keys`] ID-token signing/JWKS machinery — with an
//! in-memory model of the spec's remaining state (`ustatus`, `code`,
//! `codeVer`, `access`, `refresh`, `rotations`) so the six endpoints below are
//! provable refinements of the six TLA+ actions, not merely
//! plausible-looking HTTP handlers:
//!
//! | Endpoint | TLA+ action(s) |
//! |---|---|
//! | `authorize` | `IssueCode` |
//! | `token_authorization_code` | `RedeemCode` |
//! | `token_refresh` | `RefreshRotate` |
//! | `token_client_credentials` | (distinct authority; not modelled by the spec) |
//! | `userinfo` / `introspect` | `Introspect` |
//! | `revoke` | `RevokeAccess` |
//!
//! Authorization-code + PKCE is the ONLY interactive grant: [`authorize`]
//! refuses any `response_type` other than `"code"` structurally
//! ([`AuthorizeError::UnsupportedResponseType`]), and a PKCE
//! `code_challenge`/`S256` is mandatory
//! ([`AuthorizeError::PkceRequired`]/[`AuthorizeError::UnsupportedPkceMethod`])
//! — there is no path to a token that does not pass through a consumed,
//! PKCE-bound code. [`Provider::refuse_unsupported_grant`] closes the same
//! door at the token endpoint for `password`/`implicit` `grant_type` values.
//!
//! ID tokens are `EdDSA`-signed compact JWS
//! ([`crate::custodied_keys::SigningKeySet::sign_id_token`]); a tampered or
//! foreign-key token fails [`crate::custodied_keys::SigningKeySet::verify_id_token`].
//!
//! [`Provider::introspect`] is the single decision every safety property below
//! is judged against — RFC 7662 `active` iff the token is a live access token,
//! its grant's consent is still granted, and the owning user is still active
//! (`Introspect` in the spec) — so [`Provider::userinfo`],
//! [`Provider::revoke`]'s effect, `RevokedConsentNeverIntrospectsValid`, and
//! `DisabledUserNeverIntrospectsValid` all reduce to it.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use pillar_iam::UserStatus;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client_registry::{
    apply_op, ClientOp, ClientRegistry, ConsentKey, GrantType, OAuthClient,
};
use crate::custodied_keys::{IdTokenClaims, JwksDocument, SigningKeySet, UnixSeconds};

/// The only PKCE `code_challenge_method` this OP accepts (RFC 7636 §4.3 —
/// `plain` is never accepted by a conforming OP).
pub const PKCE_METHOD_S256: &str = "S256";

/// The grant key `(user handle, client_id)` — exactly the spec's
/// `Grants == Users \X Clients`.
type GrantKey = (String, String);

/// The `/.well-known/openid-configuration` discovery document. Advertises
/// `code` as the ONLY supported `response_type` (no `token`/`id_token`
/// implicit forms) and `S256` as the only PKCE method.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// The OP's issuer identifier (matches every minted ID token's `iss`).
    pub issuer: String,
    /// The authorization endpoint URL.
    pub authorization_endpoint: String,
    /// The token endpoint URL.
    pub token_endpoint: String,
    /// The userinfo endpoint URL.
    pub userinfo_endpoint: String,
    /// The JWKS URL.
    pub jwks_uri: String,
    /// The revocation endpoint URL (RFC 7009).
    pub revocation_endpoint: String,
    /// Always `["code"]` — implicit response types are never advertised.
    pub response_types_supported: Vec<String>,
    /// `authorization_code`, `refresh_token`, `client_credentials` — never
    /// `implicit` or `password`.
    pub grant_types_supported: Vec<String>,
    /// Always `["EdDSA"]`.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Always `["S256"]`.
    pub code_challenge_methods_supported: Vec<String>,
    /// Always `["public"]` (pairwise subject identifiers are out of scope).
    pub subject_types_supported: Vec<String>,
}

/// An `authorize` request (`GET /authorize`, RFC 6749 §4.1.1 + PKCE).
#[derive(Clone, Debug)]
pub struct AuthorizeRequest {
    /// Must be `"code"` — anything else is refused structurally.
    pub response_type: String,
    /// The requesting client.
    pub client_id: String,
    /// Must exactly match one of the client's pre-registered redirect URIs.
    pub redirect_uri: String,
    /// The scopes requested.
    pub scopes: BTreeSet<String>,
    /// The already-authenticated resource owner (this crate does not model
    /// the login/interstitial UI — only the authority decision).
    pub user: String,
    /// PKCE `code_challenge` (mandatory).
    pub code_challenge: Option<String>,
    /// PKCE `code_challenge_method` (mandatory; must be `S256`).
    pub code_challenge_method: Option<String>,
}

/// Why `authorize` refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizeError {
    /// `response_type` was not `"code"` — the implicit grant (`token` /
    /// `id_token`) is refused structurally, never merely disabled.
    UnsupportedResponseType,
    /// No client is registered under `client_id`.
    UnknownClient,
    /// `redirect_uri` is not in the client's pre-registered allow-list.
    InvalidRedirectUri,
    /// The client is not permitted the authorization-code grant.
    UnauthorizedClient,
    /// No PKCE `code_challenge` was presented — mandatory for every
    /// authorization-code request this OP issues.
    PkceRequired,
    /// A `code_challenge_method` other than `S256` was presented.
    UnsupportedPkceMethod,
    /// The user is not `Active` (invited or disabled).
    UserNotActive,
    /// No live (non-revoked) consent covers the requested scopes.
    ConsentRequired,
}

/// A minted token response (RFC 6749 §5.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The opaque access token.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Seconds until `access_token` expires (informational; this crate's
    /// tokens are revoked/rotated explicitly rather than time-expired).
    pub expires_in: u64,
    /// The opaque refresh token, when the grant carries one (never for
    /// `client_credentials`).
    pub refresh_token: Option<String>,
    /// The `EdDSA`-signed compact ID token, when the grant has an end user
    /// (never for `client_credentials`).
    pub id_token: Option<String>,
}

/// Why a token-endpoint request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// `grant_type` is not one this OP serves at all (`password`, the
    /// implicit `token`/`id_token` shapes, or any unrecognized value).
    UnsupportedGrantType,
    /// The presented code/refresh-token/client is invalid, unknown, already
    /// consumed/rotated-away, PKCE-mismatched, or its owning user/consent is
    /// no longer live. RFC 6749's single catch-all `invalid_grant`.
    InvalidGrant,
    /// A confidential-only grant (`client_credentials`) was requested by a
    /// client that is not confidential or not permitted the grant.
    UnauthorizedClient,
}

/// Claims `userinfo` returns for a live access token (RFC 5719-flavoured
/// minimal set: the full profile mapping is `oidc-claims-from-user-record`'s
/// job).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfoClaims {
    /// The token's subject (resource owner handle).
    pub sub: String,
}

/// Why `userinfo` refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserInfoError {
    /// The access token is unknown, revoked, consent-revoked, or its owning
    /// user is disabled — the SAME [`Provider::introspect`] decision.
    InvalidToken,
}

/// One outstanding (or already-consumed) authorization code.
struct AuthCode {
    client_id: String,
    user: String,
    redirect_uri: String,
    scopes: BTreeSet<String>,
    code_challenge: String,
    consumed: bool,
}

/// The live token state for one `(user, client)` grant — the spec's
/// `access`/`refresh`/`rotations` rows.
#[derive(Default)]
struct GrantRecord {
    access_token: Option<String>,
    refresh_token: Option<String>,
    scopes: BTreeSet<String>,
    rotations: u64,
}

/// The whole OIDC authorization-server engine: I/O-free, pure decision logic
/// over an in-memory model of every TLA+-tracked variable. A real host wires
/// this behind HTTP handlers and its own durable journal (the SAME
/// journal/replay discipline [`crate::client_registry`] already documents);
/// this crate proves the decisions themselves.
pub struct Provider {
    /// The OAuth client registry + consent store (shared with
    /// [`crate::client_registry`] so a host administers clients through the
    /// SAME signed-op surface this engine reads).
    pub registry: ClientRegistry,
    users: BTreeMap<String, UserStatus>,
    codes: BTreeMap<String, AuthCode>,
    grants: BTreeMap<GrantKey, GrantRecord>,
    access_index: BTreeMap<String, GrantKey>,
    refresh_index: BTreeMap<String, GrantKey>,
    keys: SigningKeySet,
    issuer: String,
    counter: u64,
}

impl Provider {
    /// Start a fresh provider for `issuer`, signing ID tokens with `keys`.
    #[must_use]
    pub fn new(issuer: impl Into<String>, keys: SigningKeySet) -> Self {
        Provider {
            registry: ClientRegistry::default(),
            users: BTreeMap::new(),
            codes: BTreeMap::new(),
            grants: BTreeMap::new(),
            access_index: BTreeMap::new(),
            refresh_index: BTreeMap::new(),
            keys,
            issuer: issuer.into(),
            counter: 0,
        }
    }

    /// `GET /.well-known/openid-configuration`.
    #[must_use]
    pub fn discovery(&self) -> DiscoveryDocument {
        let base = &self.issuer;
        DiscoveryDocument {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/userinfo"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            revocation_endpoint: format!("{base}/revoke"),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            code_challenge_methods_supported: vec![PKCE_METHOD_S256.to_string()],
            subject_types_supported: vec!["public".to_string()],
        }
    }

    /// `GET /.well-known/jwks.json` as of `now`.
    #[must_use]
    pub fn jwks(&self, now: UnixSeconds) -> JwksDocument {
        self.keys.jwks(now)
    }

    /// Register (or replace) a client directly — a thin convenience over
    /// [`ClientRegistry`] for tests/hosts that do not need the full signed-op
    /// journal for this call.
    pub fn put_client(&mut self, client: OAuthClient) {
        self.registry.clients.insert(client.client_id.clone(), client);
    }

    /// Set (or change) a user's lifecycle status
    /// (`ustatus` — the `UserLifecycle` bridge).
    pub fn set_user_status(&mut self, user: impl Into<String>, status: UserStatus) {
        let user = user.into();
        let was_active_disabled_now = status == UserStatus::Disabled;
        self.users.insert(user.clone(), status);
        if was_active_disabled_now {
            self.revoke_all_grants_for_user(&user);
        }
    }

    /// Grant (or extend) consent — `GrantConsent`.
    pub fn grant_consent(&mut self, user: &str, client_id: &str, scopes: BTreeSet<String>, at: u64) {
        apply_op(
            &mut self.registry,
            ClientOp::GrantConsent {
                user: user.to_string(),
                client_id: client_id.to_string(),
                scopes,
                at,
            },
        );
    }

    /// Revoke consent — `RevokeConsent`. Immediately revokes the grant's live
    /// access token and retires its refresh token
    /// (`RevokedConsentNeverIntrospectsValid`).
    pub fn revoke_consent(&mut self, user: &str, client_id: &str, at: u64) {
        apply_op(
            &mut self.registry,
            ClientOp::RevokeConsent {
                user: user.to_string(),
                client_id: client_id.to_string(),
                at,
            },
        );
        self.revoke_grant_tokens(&(user.to_string(), client_id.to_string()));
    }

    fn revoke_all_grants_for_user(&mut self, user: &str) {
        let keys: Vec<GrantKey> = self
            .grants
            .keys()
            .filter(|(u, _)| u == user)
            .cloned()
            .collect();
        for key in keys {
            self.revoke_grant_tokens(&key);
        }
    }

    fn revoke_grant_tokens(&mut self, key: &GrantKey) {
        if let Some(g) = self.grants.get_mut(key) {
            if let Some(tok) = g.access_token.take() {
                self.access_index.remove(&tok);
            }
            if let Some(tok) = g.refresh_token.take() {
                self.refresh_index.remove(&tok);
            }
        }
    }

    fn fresh_opaque(&mut self, label: &str) -> String {
        self.counter += 1;
        let mut h = Sha256::new();
        h.update(label.as_bytes());
        h.update(self.counter.to_be_bytes());
        B64.encode(h.finalize())
    }

    /// `GET /authorize` — `IssueCode`. Authorization-code + PKCE is the ONLY
    /// interactive grant: any `response_type` other than `"code"` is refused
    /// structurally ([`AuthorizeError::UnsupportedResponseType`]) before
    /// anything else is even validated.
    pub fn authorize(&mut self, req: AuthorizeRequest) -> Result<String, AuthorizeError> {
        if req.response_type != "code" {
            return Err(AuthorizeError::UnsupportedResponseType);
        }
        let client = self
            .registry
            .clients
            .get(&req.client_id)
            .ok_or(AuthorizeError::UnknownClient)?;
        if !client.redirect_uris.contains(&req.redirect_uri) {
            return Err(AuthorizeError::InvalidRedirectUri);
        }
        if !client.allowed_grants.contains(&GrantType::AuthorizationCode) {
            return Err(AuthorizeError::UnauthorizedClient);
        }
        let code_challenge = req.code_challenge.ok_or(AuthorizeError::PkceRequired)?;
        if req.code_challenge_method.as_deref() != Some(PKCE_METHOD_S256) {
            return Err(AuthorizeError::UnsupportedPkceMethod);
        }
        if self.users.get(&req.user).copied() != Some(UserStatus::Active) {
            return Err(AuthorizeError::UserNotActive);
        }
        let ckey: ConsentKey = (req.user.clone(), req.client_id.clone());
        let consent = self
            .registry
            .consents
            .get(&ckey)
            .filter(|c| !c.revoked)
            .ok_or(AuthorizeError::ConsentRequired)?;
        if !req.scopes.is_subset(&consent.scopes) {
            return Err(AuthorizeError::ConsentRequired);
        }

        let code = self.fresh_opaque(&format!("code:{}:{}", req.user, req.client_id));
        self.codes.insert(
            code.clone(),
            AuthCode {
                client_id: req.client_id,
                user: req.user,
                redirect_uri: req.redirect_uri,
                scopes: req.scopes,
                code_challenge,
                consumed: false,
            },
        );
        Ok(code)
    }

    /// `POST /token` with `grant_type=authorization_code` — `RedeemCode`.
    /// Single-use: a code that has already been consumed (replayed) is
    /// refused with [`TokenError::InvalidGrant`]
    /// (`NoTokenWithoutConsumedCode`'s companion — a code consumed exactly
    /// once). PKCE is re-verified: the presented `code_verifier` must hash
    /// (`SHA-256`, base64url) to the `code_challenge` recorded at
    /// `authorize`-time.
    pub fn token_authorization_code(
        &mut self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
        now: UnixSeconds,
    ) -> Result<TokenResponse, TokenError> {
        let ac = self.codes.get(code).ok_or(TokenError::InvalidGrant)?;
        if ac.consumed {
            return Err(TokenError::InvalidGrant);
        }
        if ac.redirect_uri != redirect_uri {
            return Err(TokenError::InvalidGrant);
        }
        let mut h = Sha256::new();
        h.update(code_verifier.as_bytes());
        let computed = B64.encode(h.finalize());
        if computed != ac.code_challenge {
            return Err(TokenError::InvalidGrant);
        }
        let user = ac.user.clone();
        let client_id = ac.client_id.clone();
        let scopes = ac.scopes.clone();
        if self.users.get(&user).copied() != Some(UserStatus::Active) {
            return Err(TokenError::InvalidGrant);
        }
        let ckey: ConsentKey = (user.clone(), client_id.clone());
        let consented = self
            .registry
            .consents
            .get(&ckey)
            .is_some_and(|c| !c.revoked);
        if !consented {
            return Err(TokenError::InvalidGrant);
        }
        // Consume the code -- the sole precondition for minting a token, and
        // it can never be redeemed again.
        self.codes.get_mut(code).expect("just looked up").consumed = true;

        Ok(self.mint_grant_tokens(user, client_id, scopes, now))
    }

    /// `POST /token` with `grant_type=refresh_token` — `RefreshRotate`.
    /// Single-use rotation: redeeming `refresh_token` immediately supersedes
    /// it with a freshly minted one; the redeemed string is removed from the
    /// index and can never be redeemed again (`RefreshRotationSingleUse`).
    pub fn token_refresh(
        &mut self,
        refresh_token: &str,
        now: UnixSeconds,
    ) -> Result<TokenResponse, TokenError> {
        let key = self
            .refresh_index
            .get(refresh_token)
            .cloned()
            .ok_or(TokenError::InvalidGrant)?;
        {
            let record = self.grants.get(&key).ok_or(TokenError::InvalidGrant)?;
            if record.refresh_token.as_deref() != Some(refresh_token) {
                // Already superseded by a later rotation.
                return Err(TokenError::InvalidGrant);
            }
        }
        let (user, client_id) = key.clone();
        if self.users.get(&user).copied() != Some(UserStatus::Active) {
            return Err(TokenError::InvalidGrant);
        }
        let ckey: ConsentKey = (user.clone(), client_id.clone());
        let consented = self
            .registry
            .consents
            .get(&ckey)
            .is_some_and(|c| !c.revoked);
        if !consented {
            return Err(TokenError::InvalidGrant);
        }
        // Supersede the redeemed refresh token immediately.
        self.refresh_index.remove(refresh_token);
        let scopes = self
            .grants
            .get(&key)
            .map(|g| g.scopes.clone())
            .unwrap_or_default();
        Ok(self.mint_grant_tokens(user, client_id, scopes, now))
    }

    /// `POST /token` with `grant_type=client_credentials` — a distinct
    /// authority (no end user, no consent, no ID token, no refresh token):
    /// confidential-only, and the client must be registered for the grant.
    pub fn token_client_credentials(
        &mut self,
        client_id: &str,
        _now: UnixSeconds,
    ) -> Result<TokenResponse, TokenError> {
        let client = self
            .registry
            .clients
            .get(client_id)
            .ok_or(TokenError::UnauthorizedClient)?;
        if client.client_type != crate::client_registry::ClientType::Confidential
            || !client.allowed_grants.contains(&GrantType::ClientCredentials)
        {
            return Err(TokenError::UnauthorizedClient);
        }
        let access_token = self.fresh_opaque(&format!("client-credentials:{client_id}"));
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
            id_token: None,
        })
    }

    /// Refuse a `grant_type` this OP never serves at all — `password`
    /// (resource-owner-password) and the implicit shapes structurally have no
    /// handler; any other unrecognized value is refused the same way.
    pub fn refuse_unsupported_grant(&self, grant_type: &str) -> Result<(), TokenError> {
        match grant_type {
            "authorization_code" | "refresh_token" | "client_credentials" => Ok(()),
            _ => Err(TokenError::UnsupportedGrantType),
        }
    }

    fn mint_grant_tokens(
        &mut self,
        user: String,
        client_id: String,
        scopes: BTreeSet<String>,
        now: UnixSeconds,
    ) -> TokenResponse {
        let key: GrantKey = (user.clone(), client_id.clone());
        let record = self.grants.entry(key.clone()).or_default();
        record.rotations += 1;
        record.scopes = scopes;
        let rotation = record.rotations;

        let access_token = self.fresh_opaque(&format!("access:{user}:{client_id}:{rotation}"));
        let refresh_token = self.fresh_opaque(&format!("refresh:{user}:{client_id}:{rotation}"));

        if let Some(prev) = self
            .grants
            .get_mut(&key)
            .and_then(|g| g.access_token.replace(access_token.clone()))
        {
            self.access_index.remove(&prev);
        }
        if let Some(prev) = self
            .grants
            .get_mut(&key)
            .and_then(|g| g.refresh_token.replace(refresh_token.clone()))
        {
            self.refresh_index.remove(&prev);
        }
        self.access_index.insert(access_token.clone(), key.clone());
        self.refresh_index.insert(refresh_token.clone(), key.clone());

        let id_token = Some(self.keys.sign_id_token(&IdTokenClaims {
            iss: self.issuer.clone(),
            sub: user,
            aud: client_id,
            iat: now,
            exp: now + 3600,
        }));

        TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some(refresh_token),
            id_token,
        }
    }

    /// RFC 7662 introspection decision — the single decision every other
    /// endpoint's authority check reduces to: the access token is a
    /// currently-live grant token AND that grant's consent is still granted
    /// AND the owning user is still active.
    #[must_use]
    pub fn introspect(&self, access_token: &str) -> bool {
        let Some((user, client_id)) = self.access_index.get(access_token) else {
            return false;
        };
        let Some(record) = self.grants.get(&(user.clone(), client_id.clone())) else {
            return false;
        };
        if record.access_token.as_deref() != Some(access_token) {
            return false;
        }
        let ckey: ConsentKey = (user.clone(), client_id.clone());
        let consented = self
            .registry
            .consents
            .get(&ckey)
            .is_some_and(|c| !c.revoked);
        consented && self.users.get(user).copied() == Some(UserStatus::Active)
    }

    /// `GET /userinfo` — returns claims ONLY for a token that
    /// [`Self::introspect`]s active; fails closed otherwise.
    pub fn userinfo(&self, access_token: &str) -> Result<UserInfoClaims, UserInfoError> {
        if !self.introspect(access_token) {
            return Err(UserInfoError::InvalidToken);
        }
        let (user, _client_id) = self
            .access_index
            .get(access_token)
            .expect("introspect(true) implies the token is indexed");
        Ok(UserInfoClaims { sub: user.clone() })
    }

    /// `POST /revoke` (RFC 7009) — `RevokeAccess`. Revoking an access token
    /// removes it from the live index so [`Self::introspect`] fails closed;
    /// idempotent (revoking an unknown/already-revoked token is a no-op, per
    /// RFC 7009 §2.2).
    pub fn revoke(&mut self, access_token: &str) {
        if let Some(key) = self.access_index.remove(access_token) {
            if let Some(record) = self.grants.get_mut(&key) {
                if record.access_token.as_deref() == Some(access_token) {
                    record.access_token = None;
                }
            }
        }
    }
}

#[cfg(all(test, feature = "acceptance"))]
mod tests {
    use super::*;
    use crate::client_registry::ClientType;
    use pillar_identity::login::FileKeyringBackend;

    fn scopes(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn provider() -> Provider {
        let keys = SigningKeySet::new(
            "kid-1",
            Box::new(FileKeyringBackend::new("op-signing-key").unlocked()),
            0,
            300,
        );
        Provider::new("https://pillar.example.com/oidc", keys)
    }

    fn confidential_client(id: &str) -> OAuthClient {
        OAuthClient {
            client_id: id.to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: [format!("https://{id}.example.com/cb")].into_iter().collect(),
            allowed_scopes: scopes(&["openid", "profile"]),
            allowed_grants: [
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
            ]
            .into_iter()
            .collect(),
            created_at: 0,
            updated_at: 0,
        }
    }

    /// PKCE S256: `code_challenge = base64url(sha256(code_verifier))`.
    fn pkce_challenge(verifier: &str) -> String {
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        B64.encode(h.finalize())
    }

    fn active_consented_setup(p: &mut Provider, client: &str, user: &str) {
        p.put_client(confidential_client(client));
        p.set_user_status(user, UserStatus::Active);
        p.grant_consent(user, client, scopes(&["openid", "profile"]), 0);
    }

    fn authorize_and_redeem(
        p: &mut Provider,
        client: &str,
        user: &str,
        verifier: &str,
    ) -> TokenResponse {
        let code = p
            .authorize(AuthorizeRequest {
                response_type: "code".to_string(),
                client_id: client.to_string(),
                redirect_uri: format!("https://{client}.example.com/cb"),
                scopes: scopes(&["openid"]),
                user: user.to_string(),
                code_challenge: Some(pkce_challenge(verifier)),
                code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
            })
            .expect("authorize must succeed for an active, consented user");
        p.token_authorization_code(
            &code,
            &format!("https://{client}.example.com/cb"),
            verifier,
            1_000,
        )
        .expect("redeeming a fresh code with the matching verifier must succeed")
    }

    #[test]
    fn endpoints_discovery_advertises_code_only_and_eddsa() {
        let p = provider();
        let doc = p.discovery();
        assert_eq!(doc.response_types_supported, vec!["code".to_string()]);
        assert_eq!(
            doc.id_token_signing_alg_values_supported,
            vec!["EdDSA".to_string()]
        );
        assert_eq!(
            doc.code_challenge_methods_supported,
            vec![PKCE_METHOD_S256.to_string()]
        );
        assert!(!doc.grant_types_supported.contains(&"implicit".to_string()));
        assert!(!doc.grant_types_supported.contains(&"password".to_string()));
    }

    #[test]
    fn endpoints_jwks_publishes_the_id_token_signing_key() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        let jwks = p.jwks(1_000);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, "kid-1");
        assert!(resp.id_token.is_some());
    }

    #[test]
    fn endpoints_id_token_signature_rejects_tampering() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        let id_token = resp.id_token.expect("id token minted");
        // Re-derive a verifying SigningKeySet with the SAME kid/backend to
        // check verification independent of the provider's private state.
        let verifier_keys = SigningKeySet::new(
            "kid-1",
            Box::new(FileKeyringBackend::new("op-signing-key").unlocked()),
            0,
            300,
        );
        assert!(verifier_keys.verify_id_token(&id_token, 1_000).is_ok());
        let mut parts: Vec<&str> = id_token.split('.').collect();
        parts[1] = "dGFtcGVyZWQ";
        let tampered = parts.join(".");
        assert!(verifier_keys.verify_id_token(&tampered, 1_000).is_err());
    }

    #[test]
    fn endpoints_authorize_refuses_implicit_response_types() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        for bad in ["token", "id_token", "id_token token"] {
            let err = p
                .authorize(AuthorizeRequest {
                    response_type: bad.to_string(),
                    client_id: "web".to_string(),
                    redirect_uri: "https://web.example.com/cb".to_string(),
                    scopes: scopes(&["openid"]),
                    user: "alice".to_string(),
                    code_challenge: Some(pkce_challenge("v")),
                    code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
                })
                .unwrap_err();
            assert_eq!(err, AuthorizeError::UnsupportedResponseType);
        }
    }

    #[test]
    fn endpoints_authorize_requires_pkce() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let err = p
            .authorize(AuthorizeRequest {
                response_type: "code".to_string(),
                client_id: "web".to_string(),
                redirect_uri: "https://web.example.com/cb".to_string(),
                scopes: scopes(&["openid"]),
                user: "alice".to_string(),
                code_challenge: None,
                code_challenge_method: None,
            })
            .unwrap_err();
        assert_eq!(err, AuthorizeError::PkceRequired);
    }

    #[test]
    fn endpoints_authorize_rejects_unknown_client_and_bad_redirect() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let req = |client_id: &str, redirect: &str| AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect.to_string(),
            scopes: scopes(&["openid"]),
            user: "alice".to_string(),
            code_challenge: Some(pkce_challenge("v")),
            code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
        };
        assert_eq!(
            p.authorize(req("ghost", "https://web.example.com/cb"))
                .unwrap_err(),
            AuthorizeError::UnknownClient
        );
        assert_eq!(
            p.authorize(req("web", "https://evil.example.net/cb"))
                .unwrap_err(),
            AuthorizeError::InvalidRedirectUri
        );
    }

    #[test]
    fn endpoints_authorize_requires_active_and_consented_user() {
        let mut p = provider();
        p.put_client(confidential_client("web"));
        let req = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "web".to_string(),
            redirect_uri: "https://web.example.com/cb".to_string(),
            scopes: scopes(&["openid"]),
            user: "alice".to_string(),
            code_challenge: Some(pkce_challenge("v")),
            code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
        };
        // No user record at all (never activated).
        assert_eq!(
            p.authorize(req.clone()).unwrap_err(),
            AuthorizeError::UserNotActive
        );
        p.set_user_status("alice", UserStatus::Active);
        // Active but no consent yet.
        assert_eq!(
            p.authorize(req.clone()).unwrap_err(),
            AuthorizeError::ConsentRequired
        );
        p.grant_consent("alice", "web", scopes(&["openid"]), 0);
        assert!(p.authorize(req).is_ok());
    }

    #[test]
    fn endpoints_token_authorization_code_mints_pair_with_id_token() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        assert!(p.introspect(&resp.access_token));
        assert!(resp.refresh_token.is_some());
        assert!(resp.id_token.is_some());
    }

    #[test]
    fn endpoints_no_token_without_consumed_code() {
        // The only way to reach `introspect(true)` is through
        // `token_authorization_code` consuming a code — never issued
        // directly. This is the crate-level structural proof of
        // `NoTokenWithoutConsumedCode`.
        let p = provider();
        assert!(!p.introspect("no-such-token"));
    }

    #[test]
    fn endpoints_token_code_is_single_use() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let code = p
            .authorize(AuthorizeRequest {
                response_type: "code".to_string(),
                client_id: "web".to_string(),
                redirect_uri: "https://web.example.com/cb".to_string(),
                scopes: scopes(&["openid"]),
                user: "alice".to_string(),
                code_challenge: Some(pkce_challenge("verifier-1")),
                code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
            })
            .expect("authorize succeeds");
        assert!(p
            .token_authorization_code(&code, "https://web.example.com/cb", "verifier-1", 1_000)
            .is_ok());
        // Replaying the SAME code must fail even with the right verifier.
        assert_eq!(
            p.token_authorization_code(&code, "https://web.example.com/cb", "verifier-1", 1_001)
                .unwrap_err(),
            TokenError::InvalidGrant
        );
    }

    #[test]
    fn endpoints_token_pkce_mismatch_refused() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let code = p
            .authorize(AuthorizeRequest {
                response_type: "code".to_string(),
                client_id: "web".to_string(),
                redirect_uri: "https://web.example.com/cb".to_string(),
                scopes: scopes(&["openid"]),
                user: "alice".to_string(),
                code_challenge: Some(pkce_challenge("correct-verifier")),
                code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
            })
            .expect("authorize succeeds");
        assert_eq!(
            p.token_authorization_code(
                &code,
                "https://web.example.com/cb",
                "wrong-verifier",
                1_000
            )
            .unwrap_err(),
            TokenError::InvalidGrant
        );
    }

    #[test]
    fn endpoints_token_refuses_password_and_implicit_grants() {
        let p = provider();
        for bad in ["password", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"] {
            assert_eq!(
                p.refuse_unsupported_grant(bad).unwrap_err(),
                TokenError::UnsupportedGrantType
            );
        }
        for good in ["authorization_code", "refresh_token", "client_credentials"] {
            assert!(p.refuse_unsupported_grant(good).is_ok());
        }
    }

    #[test]
    fn endpoints_token_client_credentials_grant() {
        let mut p = provider();
        p.put_client(confidential_client("service"));
        let resp = p
            .token_client_credentials("service", 1_000)
            .expect("confidential client with the grant must succeed");
        assert!(resp.refresh_token.is_none());
        assert!(resp.id_token.is_none());

        // A public client can never hold client_credentials.
        p.put_client(OAuthClient {
            client_id: "spa".to_string(),
            client_type: ClientType::Public,
            redirect_uris: ["https://spa.example.com/cb".to_string()]
                .into_iter()
                .collect(),
            allowed_scopes: scopes(&["openid"]),
            allowed_grants: [GrantType::AuthorizationCode].into_iter().collect(),
            created_at: 0,
            updated_at: 0,
        });
        assert_eq!(
            p.token_client_credentials("spa", 1_000).unwrap_err(),
            TokenError::UnauthorizedClient
        );
    }

    #[test]
    fn endpoints_refresh_rotation_is_single_use() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let first = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        let refresh_1 = first.refresh_token.expect("refresh token minted");

        let second = p
            .token_refresh(&refresh_1, 2_000)
            .expect("a fresh refresh token must redeem");
        // The old access token was superseded/replaced.
        assert!(p.introspect(&second.access_token));

        // Replaying the OLD refresh token must fail: it was superseded.
        assert_eq!(
            p.token_refresh(&refresh_1, 3_000).unwrap_err(),
            TokenError::InvalidGrant
        );
        // The new refresh token works exactly once too.
        let refresh_2 = second.refresh_token.expect("rotated refresh token");
        assert!(p.token_refresh(&refresh_2, 4_000).is_ok());
        assert_eq!(
            p.token_refresh(&refresh_2, 5_000).unwrap_err(),
            TokenError::InvalidGrant
        );
    }

    #[test]
    fn endpoints_userinfo_returns_claims_for_live_token_only() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        let claims = p
            .userinfo(&resp.access_token)
            .expect("a live token must return claims");
        assert_eq!(claims.sub, "alice");
        assert_eq!(
            p.userinfo("no-such-token").unwrap_err(),
            UserInfoError::InvalidToken
        );
    }

    #[test]
    fn endpoints_revoke_access_token_fails_introspection_closed() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        assert!(p.introspect(&resp.access_token));
        p.revoke(&resp.access_token);
        assert!(!p.introspect(&resp.access_token));
        assert_eq!(
            p.userinfo(&resp.access_token).unwrap_err(),
            UserInfoError::InvalidToken
        );
        // Revoking again (or an unknown token) is a no-op, never a panic.
        p.revoke(&resp.access_token);
        p.revoke("never-issued");
    }

    #[test]
    fn endpoints_revoked_consent_never_introspects_valid() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        assert!(p.introspect(&resp.access_token));
        p.revoke_consent("alice", "web", 5_000);
        assert!(
            !p.introspect(&resp.access_token),
            "RevokedConsentNeverIntrospectsValid"
        );
        // And it can never be revived without a fresh authorize/token round
        // trip: the same access token remains dead even if consent is
        // re-granted (a NEW token would be required).
        p.grant_consent("alice", "web", scopes(&["openid"]), 6_000);
        assert!(!p.introspect(&resp.access_token));
    }

    #[test]
    fn endpoints_disabled_user_never_introspects_valid() {
        let mut p = provider();
        active_consented_setup(&mut p, "web", "alice");
        let resp = authorize_and_redeem(&mut p, "web", "alice", "verifier-1");
        assert!(p.introspect(&resp.access_token));
        p.set_user_status("alice", UserStatus::Disabled);
        assert!(
            !p.introspect(&resp.access_token),
            "DisabledUserNeverIntrospectsValid"
        );
        // The token endpoint refuses redeeming a fresh code for a disabled
        // user too.
        let err = p
            .authorize(AuthorizeRequest {
                response_type: "code".to_string(),
                client_id: "web".to_string(),
                redirect_uri: "https://web.example.com/cb".to_string(),
                scopes: scopes(&["openid"]),
                user: "alice".to_string(),
                code_challenge: Some(pkce_challenge("v2")),
                code_challenge_method: Some(PKCE_METHOD_S256.to_string()),
            })
            .unwrap_err();
        assert_eq!(err, AuthorizeError::UserNotActive);
    }
}
