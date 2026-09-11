//! The OP's custodied ID-token signing key.
//!
//! # Design
//!
//! The OIDC provider (OP) signs ID tokens with an ed25519 key exactly like
//! every other Pillar signing key: through
//! [`pillar_identity::login::SignerBackend`], the SAME pluggable custody trait
//! node and cell keys already use (`file-keyring` / `tpm` / `passkey` /
//! `password`). The OP never holds a bare on-disk secret — [`ManagedKey`]
//! stores only a `Box<dyn SignerBackend>` plus the backend's already-public
//! verifying key; signing a token asks the backend to sign a challenge (the
//! JWS signing input), and verification never touches the backend at all
//! (only the public key), so swapping the configured backend changes only
//! *which backend produced* a signature, never the verification outcome.
//!
//! [`SigningKeySet`] tracks the current signing key plus any prior key still
//! inside its **rotation-grace window**: [`SigningKeySet::rotate`] retires the
//! current key (recording *when*) and installs a new current key, but a token
//! signed by the retired key continues to verify — and the retired key
//! continues to appear in the [`JwksDocument`] — until `now` passes
//! `retired_at + grace`. Past that instant the retired key is gone from both
//! the JWKS and verification: [`SigningKeySet::verify_id_token`] rejects a
//! token signed by a key retired past its grace window with
//! [`VerifyIdTokenError::KeyExpired`].

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use pillar_crypto::SigningPublicKey;
use pillar_identity::login::{SignerBackend, verify_backend_signature};
use serde::{Deserialize, Serialize};

/// Unix-seconds timestamp. Tests drive this directly so rotation-grace
/// behaviour is deterministic and does not depend on wall-clock time.
pub type UnixSeconds = i64;

/// A single managed signing key: an opaque custody backend plus the metadata
/// needed to publish/retire it. The backend is never inspected for key
/// material — only [`SignerBackend::sign_challenge`] (to sign) and
/// [`SignerBackend::public_key`] (to publish/verify) are ever called on it.
struct ManagedKey {
    kid: String,
    backend: Box<dyn SignerBackend + Send + Sync>,
    public_key: SigningPublicKey,
    activated_at: UnixSeconds,
    /// `Some(t)` once this key has been rotated out; retained (still
    /// verifiable, still published) until `t + grace_seconds`.
    retired_at: Option<UnixSeconds>,
}

/// A published JWKS entry (RFC 7517, EdDSA/OKP shape — `crv = "Ed25519"`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type; always `"OKP"` (octet key pair) for an ed25519 key.
    pub kty: String,
    /// Curve; always `"Ed25519"`.
    pub crv: String,
    /// Key use; always `"sig"` (this key only ever signs).
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm; always `"EdDSA"`.
    pub alg: String,
    /// The key id this JWK publishes, matching the `kid` in a token's header.
    pub kid: String,
    /// base64url(no-pad)-encoded raw ed25519 public key.
    pub x: String,
}

/// The `{"keys": [...]}` JWKS document Pillar's OP publishes at
/// `/.well-known/jwks.json` (endpoint wiring lands in `oidc-provider-endpoints`;
/// this crate produces the document itself).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwksDocument {
    /// The published keys: current plus any prior key still in its
    /// rotation-grace window.
    pub keys: Vec<Jwk>,
}

impl JwksDocument {
    /// Whether `kid` appears in this published document.
    #[must_use]
    pub fn contains_kid(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid == kid)
    }
}

/// Minimal ID-token claim set this task exercises. The full OIDC claims
/// mapping (scope-gated profile/email/roles, acr/amr) is
/// `oidc-claims-from-user-record`'s job; here `sub`/`iss`/`aud`/`iat`/`exp`
/// are enough to prove the signing-key custody and rotation-grace behaviour.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// Issuer: the OP's own identifier.
    pub iss: String,
    /// Subject: the stable user identifier this token was issued for.
    pub sub: String,
    /// Audience: the client this token was issued to.
    pub aud: String,
    /// Issued-at, unix seconds.
    pub iat: UnixSeconds,
    /// Expiry, unix seconds.
    pub exp: UnixSeconds,
}

/// JWS header naming the signing key's `kid` and its algorithm (always
/// `EdDSA` here — Pillar's OP signs only with ed25519).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JwsHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Why a rotation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRotationError {
    /// The new key's `kid` collides with an already-tracked key (current or
    /// still-in-grace prior).
    DuplicateKid(String),
}

/// Why ID-token verification failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyIdTokenError {
    /// The compact-serialization token was not well-formed
    /// (`header.payload.signature`, all base64url).
    Malformed,
    /// The token's `kid` names no key this set has ever tracked.
    UnknownKey(String),
    /// The token's `kid` names a key that was retired, and `now` is past its
    /// `retired_at + grace` window — the whole point of this task: a token
    /// signed by a retired key past grace must fail verification.
    KeyExpired,
    /// The ed25519 signature itself did not verify (wrong key or tampered
    /// token).
    BadSignature,
}

/// The OP's tracked signing keys: exactly one CURRENT key plus zero or more
/// RETIRED keys still inside their rotation-grace window.
pub struct SigningKeySet {
    /// Rotation-grace window: how long a retired key keeps verifying and
    /// keeps appearing in the JWKS after [`SigningKeySet::rotate`] retires it.
    grace_seconds: UnixSeconds,
    /// Insertion order preserved (oldest first) purely for deterministic
    /// JWKS ordering; lookups go through `by_kid`.
    order: Vec<String>,
    by_kid: HashMap<String, ManagedKey>,
    current_kid: String,
}

impl SigningKeySet {
    /// Start a fresh key set with `backend` as the sole, current key,
    /// activated at `now`. `grace_seconds` bounds how long a FUTURE rotation's
    /// retired key stays valid.
    #[must_use]
    pub fn new(
        kid: impl Into<String>,
        backend: Box<dyn SignerBackend + Send + Sync>,
        now: UnixSeconds,
        grace_seconds: UnixSeconds,
    ) -> Self {
        let kid = kid.into();
        let public_key = backend.public_key();
        let key = ManagedKey {
            kid: kid.clone(),
            backend,
            public_key,
            activated_at: now,
            retired_at: None,
        };
        let mut by_kid = HashMap::new();
        by_kid.insert(kid.clone(), key);
        SigningKeySet {
            grace_seconds,
            order: vec![kid.clone()],
            by_kid,
            current_kid: kid,
        }
    }

    /// The `kid` of the current signing key.
    #[must_use]
    pub fn current_kid(&self) -> &str {
        &self.current_kid
    }

    /// When `kid` was activated as a signing key (current or retired),
    /// unix seconds, if this set has ever tracked it.
    #[must_use]
    pub fn activated_at(&self, kid: &str) -> Option<UnixSeconds> {
        self.by_kid.get(kid).map(|k| k.activated_at)
    }

    /// Retire the current key (recording `now` as its `retired_at`) and
    /// install `backend`/`kid` as the new current key. The just-retired key
    /// keeps verifying, and keeps publishing in the JWKS, until
    /// `now + grace_seconds`.
    ///
    /// # Errors
    ///
    /// [`KeyRotationError::DuplicateKid`] if `kid` collides with any
    /// already-tracked key.
    pub fn rotate(
        &mut self,
        kid: impl Into<String>,
        backend: Box<dyn SignerBackend + Send + Sync>,
        now: UnixSeconds,
    ) -> Result<(), KeyRotationError> {
        let kid = kid.into();
        if self.by_kid.contains_key(&kid) {
            return Err(KeyRotationError::DuplicateKid(kid));
        }
        if let Some(cur) = self.by_kid.get_mut(&self.current_kid) {
            cur.retired_at = Some(now);
        }
        let public_key = backend.public_key();
        let new_key = ManagedKey {
            kid: kid.clone(),
            backend,
            public_key,
            activated_at: now,
            retired_at: None,
        };
        self.by_kid.insert(kid.clone(), new_key);
        self.order.push(kid.clone());
        self.current_kid = kid;
        Ok(())
    }

    /// Drop any tracked key whose grace window has fully elapsed as of `now`
    /// (`retired_at + grace_seconds < now`). The current key is never pruned
    /// (it has no `retired_at`). Not required for correctness (expired keys
    /// already fail verification and never publish), but keeps the set from
    /// growing unbounded across many rotations.
    pub fn prune_expired(&mut self, now: UnixSeconds) {
        let grace = self.grace_seconds;
        self.order.retain(|kid| {
            let expired = self
                .by_kid
                .get(kid)
                .and_then(|k| k.retired_at)
                .is_some_and(|retired_at| retired_at + grace < now);
            if expired {
                self.by_kid.remove(kid);
            }
            !expired
        });
    }

    /// Whether `kid` is currently publishable: it is the current key, or it
    /// is a retired key still inside its grace window as of `now`.
    fn is_publishable(&self, key: &ManagedKey, now: UnixSeconds) -> bool {
        match key.retired_at {
            None => true,
            Some(retired_at) => now <= retired_at + self.grace_seconds,
        }
    }

    /// Render the JWKS document as of `now`: the current key plus any prior
    /// key still inside its rotation-grace window. A key retired past grace
    /// is omitted.
    #[must_use]
    pub fn jwks(&self, now: UnixSeconds) -> JwksDocument {
        let keys = self
            .order
            .iter()
            .filter_map(|kid| self.by_kid.get(kid))
            .filter(|k| self.is_publishable(k, now))
            .map(|k| Jwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                key_use: "sig".to_string(),
                alg: "EdDSA".to_string(),
                kid: k.kid.clone(),
                x: B64.encode(k.public_key.as_bytes()),
            })
            .collect();
        JwksDocument { keys }
    }

    /// Sign `claims` with the CURRENT key, producing a compact
    /// `header.payload.signature` JWS (all three segments base64url,
    /// no padding) — an EdDSA-signed ID token.
    #[must_use]
    pub fn sign_id_token(&self, claims: &IdTokenClaims) -> String {
        let current = self
            .by_kid
            .get(&self.current_kid)
            .expect("current_kid always names a tracked key");
        let header = JwsHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
            kid: current.kid.clone(),
        };
        let header_b64 =
            B64.encode(serde_json::to_vec(&header).expect("header always serializes"));
        let payload_b64 =
            B64.encode(serde_json::to_vec(claims).expect("claims always serialize"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        // The backend never exposes key material here — only the opaque
        // signer-backend wire token, which itself carries a genuine
        // detached ed25519 signature over `signing_input`
        // (`pillar_identity::login::SignerBackend::sign_challenge`).
        let backend_token = current
            .backend
            .sign_challenge(&signing_input)
            .expect("the OP's own signing key must always be able to sign");
        let sig_b64 = B64.encode(backend_token.as_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Verify a compact ID token produced by [`Self::sign_id_token`] as of
    /// `now`. Succeeds only if: the token is well-formed, its `kid` names a
    /// key this set has ever tracked, that key is not retired past its grace
    /// window, and the ed25519 signature verifies against that key's public
    /// key.
    ///
    /// This is the CI-visible proof that signing-key custody is pluggable:
    /// verification depends only on the tracked key's PUBLIC key, never on
    /// which [`SignerBackend`] produced the signature, so swapping the
    /// configured backend for a given `kid` changes nothing about
    /// verification.
    pub fn verify_id_token(
        &self,
        token: &str,
        now: UnixSeconds,
    ) -> Result<IdTokenClaims, VerifyIdTokenError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VerifyIdTokenError::Malformed);
        };

        let header_bytes = B64
            .decode(header_b64)
            .map_err(|_| VerifyIdTokenError::Malformed)?;
        let header: JwsHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| VerifyIdTokenError::Malformed)?;

        let key = self
            .by_kid
            .get(header.kid.as_str())
            .ok_or_else(|| VerifyIdTokenError::UnknownKey(header.kid.clone()))?;

        if let Some(retired_at) = key.retired_at {
            if now > retired_at + self.grace_seconds {
                return Err(VerifyIdTokenError::KeyExpired);
            }
        }

        let sig_bytes = B64
            .decode(sig_b64)
            .map_err(|_| VerifyIdTokenError::Malformed)?;
        let backend_token =
            String::from_utf8(sig_bytes).map_err(|_| VerifyIdTokenError::Malformed)?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        if !verify_backend_signature(&key.public_key, &signing_input, &backend_token) {
            return Err(VerifyIdTokenError::BadSignature);
        }

        let payload_bytes = B64
            .decode(payload_b64)
            .map_err(|_| VerifyIdTokenError::Malformed)?;
        serde_json::from_slice(&payload_bytes).map_err(|_| VerifyIdTokenError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_identity::login::{FileKeyringBackend, PasswordBackend, TpmBackend};

    fn claims(now: UnixSeconds) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://pillar.example.com/oidc".to_string(),
            sub: "user-alice".to_string(),
            aud: "client-webapp".to_string(),
            iat: now,
            exp: now + 3600,
        }
    }

    #[test]
    fn signing_key_resolves_through_the_pluggable_custody_trait() {
        // Same behaviour (a verifiable ID token), three different custody
        // backends behind the SAME SignerBackend trait — swapping the
        // backend changes only which backend produced the signature, never
        // the verification outcome.
        let now = 1_000;
        for backend in [
            Box::new(FileKeyringBackend::new("op-signing-key").unlocked())
                as Box<dyn SignerBackend + Send + Sync>,
            Box::new(TpmBackend::new("op-signing-key")) as Box<dyn SignerBackend + Send + Sync>,
            Box::new(PasswordBackend::new("op-signing-key"))
                as Box<dyn SignerBackend + Send + Sync>,
        ] {
            let keys = SigningKeySet::new("kid-1", backend, now, 300);
            let token = keys.sign_id_token(&claims(now));
            let verified = keys
                .verify_id_token(&token, now)
                .expect("a freshly signed token must verify");
            assert_eq!(verified, claims(now));
        }
    }

    #[test]
    fn jwks_lists_current_and_a_still_valid_prior_key_during_rotation_window() {
        let now = 10_000;
        let grace = 300;
        let mut keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            grace,
        );
        keys.rotate(
            "kid-b",
            Box::new(FileKeyringBackend::new("b").unlocked()),
            now + 100,
        )
        .expect("rotation to a fresh kid must succeed");

        // Immediately after rotation, both keys are still published: the
        // retired kid-a is still inside its grace window.
        let jwks = keys.jwks(now + 150);
        assert!(jwks.contains_kid("kid-a"), "retired key still in grace");
        assert!(jwks.contains_kid("kid-b"), "new current key published");
        assert_eq!(jwks.keys.len(), 2);

        // A token signed by the now-retired key still verifies during grace.
        let old_token = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            grace,
        )
        .sign_id_token(&claims(now));
        assert!(keys.verify_id_token(&old_token, now + 150).is_ok());
    }

    #[test]
    fn a_token_signed_by_a_retired_key_past_grace_fails_verification() {
        let now = 20_000;
        let grace = 300;
        let mut keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            grace,
        );
        let token = keys.sign_id_token(&claims(now));

        keys.rotate(
            "kid-b",
            Box::new(FileKeyringBackend::new("b").unlocked()),
            now + 10,
        )
        .expect("rotation must succeed");

        // Still within grace: the retired key's token verifies and its key
        // still publishes.
        let still_in_grace = now + 10 + grace;
        assert!(keys.verify_id_token(&token, still_in_grace).is_ok());
        assert!(keys.jwks(still_in_grace).contains_kid("kid-a"));

        // Past grace: verification fails and the key is no longer published.
        let past_grace = now + 10 + grace + 1;
        assert_eq!(
            keys.verify_id_token(&token, past_grace),
            Err(VerifyIdTokenError::KeyExpired)
        );
        assert!(
            !keys.jwks(past_grace).contains_kid("kid-a"),
            "a key retired past grace must not be published"
        );
    }

    #[test]
    fn an_unknown_kid_and_a_tampered_signature_are_both_rejected() {
        let now = 30_000;
        let keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            300,
        );
        let token = keys.sign_id_token(&claims(now));

        let mut parts: Vec<&str> = token.split('.').collect();
        // Corrupt the payload without re-signing: signature must now fail.
        parts[1] = "dGFtcGVyZWQ"; // base64url("tampered") without padding
        let tampered = parts.join(".");
        assert_eq!(
            keys.verify_id_token(&tampered, now),
            Err(VerifyIdTokenError::BadSignature)
        );

        let other = SigningKeySet::new(
            "kid-z",
            Box::new(FileKeyringBackend::new("z").unlocked()),
            now,
            300,
        );
        let foreign_token = other.sign_id_token(&claims(now));
        assert!(matches!(
            keys.verify_id_token(&foreign_token, now),
            Err(VerifyIdTokenError::UnknownKey(_))
        ));
    }

    #[test]
    fn activated_at_reports_when_a_key_was_installed() {
        let now = 45_000;
        let mut keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            300,
        );
        assert_eq!(keys.activated_at("kid-a"), Some(now));
        assert_eq!(keys.activated_at("kid-nonexistent"), None);

        keys.rotate(
            "kid-b",
            Box::new(FileKeyringBackend::new("b").unlocked()),
            now + 50,
        )
        .expect("rotate");
        assert_eq!(keys.activated_at("kid-b"), Some(now + 50));
        // Retiring kid-a does not change ITS activation time.
        assert_eq!(keys.activated_at("kid-a"), Some(now));
    }

    #[test]
    fn rotating_to_a_duplicate_kid_is_refused() {        let now = 40_000;
        let mut keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            300,
        );
        let err = keys
            .rotate(
                "kid-a",
                Box::new(FileKeyringBackend::new("a2").unlocked()),
                now + 1,
            )
            .unwrap_err();
        assert_eq!(err, KeyRotationError::DuplicateKid("kid-a".to_string()));
    }

    #[test]
    fn prune_expired_removes_only_keys_whose_grace_has_fully_elapsed() {
        let now = 50_000;
        let grace = 300;
        let mut keys = SigningKeySet::new(
            "kid-a",
            Box::new(FileKeyringBackend::new("a").unlocked()),
            now,
            grace,
        );
        keys.rotate(
            "kid-b",
            Box::new(FileKeyringBackend::new("b").unlocked()),
            now + 10,
        )
        .expect("rotate");

        keys.prune_expired(now + 10 + grace); // still exactly in grace
        assert!(keys.by_kid.contains_key("kid-a"));

        keys.prune_expired(now + 10 + grace + 1); // now past grace
        assert!(!keys.by_kid.contains_key("kid-a"));
        assert!(keys.by_kid.contains_key("kid-b"), "current key never pruned");
    }
}
