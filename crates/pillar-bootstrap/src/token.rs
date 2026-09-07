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
//! Real crypto: the bearer value is a self-describing ed25519-signed record
//! (serial + expiry + user + domain, hex-encoded, followed by the issuer's
//! signature over that payload). Verification recomputes the signature
//! against the issuer's own `pillar-crypto` keypair, so a token cannot be
//! minted — nor a captured one tampered with — without holding the issuer's
//! real signing key; a forged or altered token fails `verify` closed. Serial-
//! keyed revocation and the embedded expiry give the same fail-closed
//! expiry/replay behavior as before, now backed by a real signature instead
//! of an opaque hash.

use std::collections::HashMap;
use std::collections::HashSet;

use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify as crypto_verify};
use pillar_crypto::{Seed, Signature, SigningPublicKey, SigningSecretKey};

/// Hex-encode `bytes` (lowercase, no separators).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Hex-decode `s`; `None` on any malformed input (odd length, non-hex digit).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// The fields bound into a minted token, encoded as a flat, length-prefixed
/// byte payload so the signature covers exactly these values.
struct TokenPayload {
    serial: u64,
    expiry: u64,
    user: String,
    domain: String,
}

impl TokenPayload {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        let user_bytes = self.user.as_bytes();
        out.extend_from_slice(&(user_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(user_bytes);
        let domain_bytes = self.domain.as_bytes();
        out.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(domain_bytes);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 + 8 + 4 {
            return None;
        }
        let mut pos = 0usize;
        let serial = u64::from_be_bytes(bytes.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let expiry = u64::from_be_bytes(bytes.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let user_len = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        let user = String::from_utf8(bytes.get(pos..pos + user_len)?.to_vec()).ok()?;
        pos += user_len;
        let domain_len = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        let domain = String::from_utf8(bytes.get(pos..pos + domain_len)?.to_vec()).ok()?;
        pos += domain_len;
        if pos != bytes.len() {
            return None;
        }
        Some(TokenPayload {
            serial,
            expiry,
            user,
            domain,
        })
    }
}

/// Encode a signed token as `pt2.<hex payload>.<hex signature>`.
fn encode_token(payload: &TokenPayload, sig: &Signature) -> String {
    format!(
        "pt2.{}.{}",
        hex_encode(&payload.encode()),
        hex_encode(sig.as_bytes())
    )
}

/// Decode + verify a `pt2.…` token against `public`. `None` on any malformed
/// token OR a signature that does not verify — a forged/tampered token is
/// indistinguishable from garbage, and both are rejected identically.
fn decode_and_verify_token(token: &str, public: &SigningPublicKey) -> Option<TokenPayload> {
    let rest = token.strip_prefix("pt2.")?;
    let (payload_hex, sig_hex) = rest.split_once('.')?;
    let payload_bytes = hex_decode(payload_hex)?;
    let sig_bytes = hex_decode(sig_hex)?;
    let payload = TokenPayload::decode(&payload_bytes)?;
    let signature = Signature::from_bytes(sig_bytes);
    crypto_verify(public, &payload_bytes, &signature).ok()?;
    Some(payload)
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

/// The key-distribution server: the SOLE minter and verifier of login tokens.
///
/// It holds each user's registered login credential (a stand-in for the
/// server-side unlock check), mints a token only after valid credentials are
/// forwarded, and verifies presented tokens fail-closed on expiry/revocation.
/// Minting SIGNS the token payload with a real ed25519 key generated fresh
/// for this issuer (from OS entropy, via `pillar_crypto`); verification
/// checks that signature against the issuer's own public key, so a token
/// cannot be minted, nor a captured one altered, without holding the real
/// signing key.
#[derive(Clone, Debug)]
pub struct TokenIssuer {
    credentials: HashMap<String, String>,
    /// Revoked serials (each minted token embeds a unique serial).
    revoked: HashSet<u64>,
    serial: u64,
    signing_key: SigningSecretKey,
    verifying_key: SigningPublicKey,
}

impl Default for TokenIssuer {
    fn default() -> Self {
        TokenIssuer::new()
    }
}

impl TokenIssuer {
    /// A server with no users registered, holding a freshly generated
    /// ed25519 signing keypair (seeded from OS entropy).
    #[must_use]
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut seed_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut seed_bytes);
        let seed = Seed::from_bytes(seed_bytes.to_vec());
        let (verifying_key, signing_key) =
            signing_keypair_from_seed(&seed).expect("ed25519 keygen from a 32-byte seed");
        TokenIssuer {
            credentials: HashMap::new(),
            revoked: HashSet::new(),
            serial: 0,
            signing_key,
            verifying_key,
        }
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
        let payload = TokenPayload {
            serial: self.serial,
            expiry,
            user: user.to_owned(),
            domain: domain.to_owned(),
        };
        let payload_bytes = payload.encode();
        let sig = sign(&self.signing_key, &payload_bytes)
            .expect("signing with our own freshly generated key never fails");
        let value = encode_token(&payload, &sig);
        Ok(LoginToken {
            value,
            user: user.to_owned(),
            domain: domain.to_owned(),
            expiry,
        })
    }

    /// Verify a presented token for `domain` at time `now`, returning the
    /// authenticated user on success. Fail-closed on unknown/forged/expired/
    /// revoked tokens and on a domain mismatch.
    ///
    /// A token is authenticated ONLY by its ed25519 signature against this
    /// issuer's own key ([`decode_and_verify_token`]): a malformed token, one
    /// signed by a different key, or one whose payload was tampered with all
    /// fail identically as [`LoginTokenError::UnknownToken`] — this server
    /// never minted it.
    ///
    /// # Errors
    ///
    /// The matching [`LoginTokenError`] for the first failing check.
    pub fn verify(&self, token: &str, domain: &str, now: u64) -> Result<String, LoginTokenError> {
        let payload = decode_and_verify_token(token, &self.verifying_key)
            .ok_or(LoginTokenError::UnknownToken)?;
        if self.revoked.contains(&payload.serial) {
            return Err(LoginTokenError::Revoked);
        }
        if now >= payload.expiry {
            return Err(LoginTokenError::Expired);
        }
        if payload.domain != domain {
            return Err(LoginTokenError::WrongDomain);
        }
        Ok(payload.user)
    }

    /// Revoke a minted token; it can no longer authenticate. A token that does
    /// not verify against this issuer (forged, or minted by a different
    /// issuer) is silently ignored — there is no real serial to revoke.
    pub fn revoke(&mut self, token: &str) {
        if let Some(payload) = decode_and_verify_token(token, &self.verifying_key) {
            self.revoked.insert(payload.serial);
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
    fn a_tampered_token_is_rejected() {
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
        // Flip a hex digit in the payload (e.g. change the bound user/domain
        // bytes) — the signature no longer matches the mutated payload.
        let mutated = {
            let mut chars: Vec<char> = token.value().chars().collect();
            let flip_at = chars
                .iter()
                .position(|c| *c == '.')
                .expect("has a separator")
                + 1;
            chars[flip_at] = if chars[flip_at] == '0' { '1' } else { '0' };
            chars.into_iter().collect::<String>()
        };
        assert_eq!(
            i.verify(&mutated, "spencer-cell", 5),
            Err(LoginTokenError::UnknownToken),
            "a tampered payload must fail signature verification"
        );
    }

    #[test]
    fn a_forged_token_from_another_issuer_is_rejected() {
        let victim = issuer();
        let mut attacker = TokenIssuer::new();
        attacker.register_user("spencer@pillar", "correct horse battery staple");
        // The attacker runs their OWN issuer (their own signing key) and mints
        // a token for the same user/domain — this must not authenticate
        // against the victim issuer, which never minted it and does not hold
        // the attacker's signing key.
        let forged = attacker
            .forward_and_mint(
                "spencer@pillar",
                "spencer-cell",
                "correct horse battery staple",
                0,
                10,
            )
            .unwrap();
        assert_eq!(
            victim.verify(forged.value(), "spencer-cell", 5),
            Err(LoginTokenError::UnknownToken),
            "a token minted by a different issuer's key must never verify"
        );
        // Sanity: the same forged token DOES verify against its own issuer.
        assert_eq!(
            attacker.verify(forged.value(), "spencer-cell", 5),
            Ok("spencer@pillar".to_owned())
        );
    }

    #[test]
    fn a_garbage_string_is_never_mistaken_for_a_token() {
        let i = issuer();
        assert_eq!(
            i.verify("not-a-real-token", "spencer-cell", 0),
            Err(LoginTokenError::UnknownToken)
        );
        assert_eq!(
            i.verify("pt2.deadbeef.deadbeef", "spencer-cell", 0),
            Err(LoginTokenError::UnknownToken)
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
