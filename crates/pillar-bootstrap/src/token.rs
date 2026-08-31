//! Temporary login-token issuance and the `PILLAR_DOMAIN` / `PILLAR_TOKEN`
//! env contract, refining `specs/LoginToken.tla`.
//!
//! `pillar login` obtains a short-lived bearer token for a user and exports it
//! as `PILLAR_DOMAIN` + `PILLAR_TOKEN`; every later CLI command reads those
//! env vars ([`TokenStore::from_env`]) and presents the token — never the
//! long-lived key — for authn/authz.
//!
//! The token is minted ONLY by the key-distribution server ([`TokenIssuer`]),
//! and ONLY after valid credentials are forwarded to it. A web portal MAY be
//! deployed separately from the key-distribution server: it does not mint,
//! it FORWARDS the presented credentials to the server
//! ([`TokenIssuer::forward_and_mint`]) which is the sole minter. Tokens are
//! bound to `(user, domain, expiry)`, never honored past expiry or revocation.
//!
//! No real crypto (codebase convention): the token value is a deterministic
//! stand-in bearer string; the PROTOCOL — mint only on a forwarded valid
//! credential, fail-closed on expiry/revocation, bound to one user+domain — is
//! modelled precisely.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

fn digest(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// The env var carrying the logged-in cell domain.
pub const PILLAR_DOMAIN_ENV: &str = "PILLAR_DOMAIN";
/// The env var carrying the temporary auth token.
pub const PILLAR_TOKEN_ENV: &str = "PILLAR_TOKEN";

/// A minted temporary login token bound to a user, a domain, and an expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginToken {
    value: String,
    user: String,
    domain: String,
    expiry: u64,
}

impl LoginToken {
    /// The opaque bearer value (exported as `PILLAR_TOKEN`).
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
    /// The user this token authenticates.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
    /// The cell domain this token is bound to (exported as `PILLAR_DOMAIN`).
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }
    /// The absolute expiry time.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
}

/// Why a token operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginTokenError {
    /// The forwarded credentials did not verify for the user.
    BadCredential,
    /// The requested TTL was zero (an expiry not strictly after `now`).
    NonPositiveTtl,
    /// The presented token is unknown to the server.
    UnknownToken,
    /// The token has expired (`now >= expiry`).
    Expired,
    /// The token was revoked.
    Revoked,
    /// The token is valid but bound to a different domain than presented.
    WrongDomain,
}

impl std::fmt::Display for LoginTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            LoginTokenError::BadCredential => "invalid credentials",
            LoginTokenError::NonPositiveTtl => "token time-to-live must be positive",
            LoginTokenError::UnknownToken => "unknown or missing token — run `pillar login`",
            LoginTokenError::Expired => "token expired — run `pillar login` again",
            LoginTokenError::Revoked => "token revoked — run `pillar login` again",
            LoginTokenError::WrongDomain => "token is not valid for this domain",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for LoginTokenError {}

#[derive(Clone, Debug)]
struct MintedRecord {
    user: String,
    domain: String,
    expiry: u64,
    revoked: bool,
}

/// The key-distribution server: the SOLE minter and verifier of login tokens.
///
/// It holds each user's registered login credential (a stand-in for the
/// server-side unlock check), mints a token only after valid credentials are
/// forwarded, and verifies presented tokens fail-closed on expiry/revocation.
#[derive(Clone, Debug, Default)]
pub struct TokenIssuer {
    credentials: HashMap<String, String>,
    minted: HashMap<String, MintedRecord>,
    revoked: HashSet<String>,
    serial: u64,
}

impl TokenIssuer {
    /// A server with no users registered.
    #[must_use]
    pub fn new() -> Self {
        TokenIssuer::default()
    }

    /// Register a user's login credential (the factor the server verifies a
    /// forwarded login against). In a real deployment this is the node-side
    /// custody unlock; here it is the registered secret.
    pub fn register_user(&mut self, user: impl Into<String>, credential: impl Into<String>) {
        self.credentials.insert(user.into(), credential.into());
    }

    /// Forward presented credentials to the server and mint a token on success.
    ///
    /// This is the entry point a **portal** calls: the portal does not mint, it
    /// forwards `presented` here. Mints a token bound to `(user, domain)` with
    /// `expiry = now + ttl`.
    ///
    /// # Errors
    ///
    /// [`LoginTokenError::BadCredential`] if `presented` does not match the
    /// user's registered credential; [`LoginTokenError::NonPositiveTtl`] if
    /// `ttl == 0`.
    pub fn forward_and_mint(
        &mut self,
        user: &str,
        domain: &str,
        presented: &str,
        now: u64,
        ttl: u64,
    ) -> Result<LoginToken, LoginTokenError> {
        if ttl == 0 {
            return Err(LoginTokenError::NonPositiveTtl);
        }
        match self.credentials.get(user) {
            Some(expected) if expected == presented => {}
            _ => return Err(LoginTokenError::BadCredential),
        }
        self.serial += 1;
        let expiry = now + ttl;
        let value = format!(
            "pt_{:016x}",
            digest(&[
                "pillar-login-token-v1",
                user,
                domain,
                &expiry.to_string(),
                &self.serial.to_string(),
            ])
        );
        self.minted.insert(
            value.clone(),
            MintedRecord {
                user: user.to_owned(),
                domain: domain.to_owned(),
                expiry,
                revoked: false,
            },
        );
        Ok(LoginToken {
            value,
            user: user.to_owned(),
            domain: domain.to_owned(),
            expiry,
        })
    }

    /// Verify a presented token for `domain` at time `now`, returning the
    /// authenticated user on success. Fail-closed on unknown/expired/revoked
    /// tokens and on a domain mismatch.
    ///
    /// # Errors
    ///
    /// The matching [`LoginTokenError`] for the first failing check.
    pub fn verify(&self, token: &str, domain: &str, now: u64) -> Result<String, LoginTokenError> {
        let record = self
            .minted
            .get(token)
            .ok_or(LoginTokenError::UnknownToken)?;
        if record.revoked || self.revoked.contains(token) {
            return Err(LoginTokenError::Revoked);
        }
        if now >= record.expiry {
            return Err(LoginTokenError::Expired);
        }
        if record.domain != domain {
            return Err(LoginTokenError::WrongDomain);
        }
        Ok(record.user.clone())
    }

    /// Revoke a minted token; it can no longer authenticate.
    pub fn revoke(&mut self, token: &str) {
        self.revoked.insert(token.to_owned());
        if let Some(record) = self.minted.get_mut(token) {
            record.revoked = true;
        }
    }
}

/// The CLI-side holder of the `PILLAR_DOMAIN` / `PILLAR_TOKEN` credentials a
/// `pillar login` produced. Reads them from the process environment (or any
/// provided map, for testing) and presents the token to a [`TokenIssuer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenStore {
    domain: String,
    token: String,
}

impl TokenStore {
    /// A store holding an explicit domain + token (what `pillar login` writes).
    #[must_use]
    pub fn new(domain: impl Into<String>, token: impl Into<String>) -> Self {
        TokenStore {
            domain: domain.into(),
            token: token.into(),
        }
    }

    /// The env assignments `pillar login` prints for the shell to `eval`
    /// (`export PILLAR_DOMAIN=… PILLAR_TOKEN=…`).
    #[must_use]
    pub fn export_lines(&self) -> String {
        format!(
            "export {}={}\nexport {}={}\n",
            PILLAR_DOMAIN_ENV, self.domain, PILLAR_TOKEN_ENV, self.token
        )
    }

    /// Build a store from a `(name -> value)` env lookup (the process env, or a
    /// test map). Returns `None` unless BOTH vars are present and non-empty —
    /// the CLI then knows the user must run `pillar login` first.
    #[must_use]
    pub fn from_env(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let domain = lookup(PILLAR_DOMAIN_ENV).filter(|s| !s.is_empty())?;
        let token = lookup(PILLAR_TOKEN_ENV).filter(|s| !s.is_empty())?;
        Some(TokenStore { domain, token })
    }

    /// The bound domain (`PILLAR_DOMAIN`).
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The token value (`PILLAR_TOKEN`).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Authenticate this store's token against `issuer` at time `now`,
    /// returning the authenticated user.
    ///
    /// # Errors
    ///
    /// See [`TokenIssuer::verify`].
    pub fn authenticate(&self, issuer: &TokenIssuer, now: u64) -> Result<String, LoginTokenError> {
        issuer.verify(&self.token, &self.domain, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> TokenIssuer {
        let mut i = TokenIssuer::new();
        i.register_user("spencer@pillar", "correct horse battery staple");
        i
    }

    #[test]
    fn forwarded_valid_credential_mints_a_bound_token_and_authenticates() {
        let mut i = issuer();
        let token = i
            .forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                10,
            )
            .expect("mint");
        assert_eq!(token.user(), "spencer@pillar");
        assert_eq!(token.domain(), "spencer-cell");
        assert_eq!(token.expiry(), 10);

        let store = TokenStore::new(token.domain(), token.value());
        assert_eq!(store.authenticate(&i, 5).unwrap(), "spencer@pillar");
    }

    #[test]
    fn a_bad_credential_never_mints() {
        let mut i = issuer();
        assert_eq!(
            i.forward_and_mint("spencer@pillar", "spencer-cell", "wrong", 0, 10),
            Err(LoginTokenError::BadCredential)
        );
        // An unregistered user likewise never mints.
        assert_eq!(
            i.forward_and_mint("nobody@pillar", "spencer-cell", "anything", 0, 10),
            Err(LoginTokenError::BadCredential)
        );
    }

    #[test]
    fn an_expired_token_fails_closed() {
        let mut i = issuer();
        let token = i
            .forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                10,
            )
            .unwrap();
        let store = TokenStore::new(token.domain(), token.value());
        // now == expiry is already expired.
        assert_eq!(store.authenticate(&i, 10), Err(LoginTokenError::Expired));
        assert_eq!(store.authenticate(&i, 11), Err(LoginTokenError::Expired));
    }

    #[test]
    fn a_revoked_token_fails_closed() {
        let mut i = issuer();
        let token = i
            .forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                10,
            )
            .unwrap();
        i.revoke(token.value());
        let store = TokenStore::new(token.domain(), token.value());
        assert_eq!(store.authenticate(&i, 5), Err(LoginTokenError::Revoked));
    }

    #[test]
    fn a_token_is_bound_to_its_domain() {
        let mut i = issuer();
        let token = i
            .forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                10,
            )
            .unwrap();
        assert_eq!(
            i.verify(token.value(), "some-other-cell", 5),
            Err(LoginTokenError::WrongDomain)
        );
    }

    #[test]
    fn zero_ttl_is_refused() {
        let mut i = issuer();
        assert_eq!(
            i.forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                0
            ),
            Err(LoginTokenError::NonPositiveTtl)
        );
    }

    #[test]
    fn from_env_requires_both_vars() {
        let full = |name: &str| match name {
            "PILLAR_DOMAIN" => Some("spencer-cell".to_owned()),
            "PILLAR_TOKEN" => Some("pt_abc".to_owned()),
            _ => None,
        };
        assert_eq!(
            TokenStore::from_env(full),
            Some(TokenStore::new("spencer-cell", "pt_abc"))
        );
        let missing = |name: &str| match name {
            "PILLAR_DOMAIN" => Some("spencer-cell".to_owned()),
            _ => None,
        };
        assert_eq!(TokenStore::from_env(missing), None);
        let empty = |name: &str| match name {
            "PILLAR_DOMAIN" => Some(String::new()),
            "PILLAR_TOKEN" => Some("pt_abc".to_owned()),
            _ => None,
        };
        assert_eq!(TokenStore::from_env(empty), None);
    }

    #[test]
    fn export_lines_emit_both_env_vars() {
        let store = TokenStore::new("spencer-cell", "pt_abc");
        let lines = store.export_lines();
        assert!(lines.contains("export PILLAR_DOMAIN=spencer-cell"));
        assert!(lines.contains("export PILLAR_TOKEN=pt_abc"));
    }
}
