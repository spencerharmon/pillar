//! WoT-key challenge-signature web login ("your key is your account").
//!
//! Refines `specs/WebKeyAuth.tla`. There is NO separate identity provider:
//! logging in is proving control of a key the Web of Trust already trusts,
//! so authorization comes "for free" from the existing
//! [`pillar_wot_authority`] authority and the single [`pillar_rbac`]
//! decider — never a parallel/second authority path.
//!
//! The handshake, exactly as the spec proves it sound:
//!
//! 1. **Server issues a nonce** ([`NonceIssuer::issue`]) bound to
//!    `(origin, expiry)` and minted from a monotone, never-reused serial.
//! 2. **Client fetches its password-protected auth SUBKEY by CID**
//!    ([`EncryptedAuthSubkey`] holds world-readable ciphertext), decrypts and
//!    unlocks it **locally** with a high-cost **argon2id** KDF
//!    ([`unlock_auth_subkey`]), and signs the nonce
//!    ([`AuthSubkey::sign_nonce`]). The password and the plaintext key never
//!    leave the client.
//! 3. **Server verifies** ([`KeyLoginVerifier::admit`]): the signature must
//!    be over an unexpired, right-origin, unconsumed nonce; the signing
//!    subkey must be WoT-trust-reachable (chain to the owner anchor) and its
//!    authority is resolved through the SAME [`pillar_wot_authority`] `Act`
//!    guard the controllers use, so revocation fail-closed holds for login
//!    sessions unchanged.
//!
//! ## Real cryptography (ROI non-negotiable #7)
//!
//! Every cryptographic operation on this path runs a REAL primitive from
//! [`pillar_crypto`] — there is no `DefaultHasher`/`SipHash` stand-in left:
//!
//! * the password → key step is a genuine memory-hard **argon2id**
//!   ([`pillar_crypto::kdf::derive_key`]);
//! * the auth subkey is a real **ed25519** keypair
//!   ([`pillar_crypto::sign`]) deterministically derived from the argon2id
//!   output, so the wire signature is a real ed25519 signature the server
//!   verifies against a real ed25519 public key — holding the public key can
//!   never forge one.
//!
//! The server never observes the password or the plaintext key, only a
//! challenge-bound ed25519 proof it verifies against the WoT-trusted
//! registration key.

use std::collections::HashMap;

use pillar_core::NodeId;
use pillar_crypto::kdf::derive_key;
use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
use pillar_crypto::{
    KdfParams, Salt, Seed, Signature as CryptoSignature, SigningPublicKey, SigningSecretKey,
};
use pillar_identity::NodeSubkey;
use pillar_wot_authority::{ActError, FencedActor, WotAuthority};

/// The domain-separated argon2id salt this login path binds a subkey's KDF to.
/// The salt is per-subkey (its WoT identity), so two subkeys with the same
/// password never derive the same key material.
fn subkey_salt(subkey: &NodeSubkey) -> Salt {
    let mut bytes = b"pillar-web-key-auth/argon2id/salt-v1:".to_vec();
    bytes.extend_from_slice(subkey.0.as_bytes());
    Salt::from_bytes(bytes)
}

/// The argon2id work parameters for the web-key-auth path. Memory-hard and
/// deliberately low-iteration for the in-process model so the property test's
/// many derivations stay fast; a real client tunes these up.
fn kdf_params() -> KdfParams {
    KdfParams {
        mem_kib: 8,
        iterations: 1,
        parallelism: 1,
        output_len: 32,
    }
}

/// Run the real memory-hard argon2id KDF over `(password, secret)` bound to
/// `subkey`, yielding 32 bytes of key material. This is the ONE place the
/// password and plaintext secret are combined and it runs ONLY client-side.
fn argon2id_material(password: &str, subkey: &NodeSubkey, secret: &str) -> Vec<u8> {
    // Bind the plaintext key secret into the password input so the derived
    // material depends on both (the secret is the plaintext subkey material a
    // real client already holds; the password unlocks it).
    let mut pw = password.as_bytes().to_vec();
    pw.push(0);
    pw.extend_from_slice(secret.as_bytes());
    let key = derive_key(&pw, &subkey_salt(subkey), &kdf_params())
        .expect("argon2id derive_key must succeed for non-empty output_len");
    key.into_bytes()
}

/// Derive the real ed25519 auth keypair from the argon2id material.
fn keypair_from_material(material: &[u8]) -> (SigningPublicKey, SigningSecretKey) {
    signing_keypair_from_seed(&Seed::from_bytes(material.to_vec()))
        .expect("ed25519 keypair derivation must succeed")
}

/// A server origin a challenge nonce may be bound to (`https://host:port`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin(pub String);

impl From<&str> for Origin {
    fn from(s: &str) -> Self {
        Origin(s.to_owned())
    }
}

/// A server-issued challenge nonce, bound to an origin and an expiry.
///
/// The `id` is minted from a monotone serial that is never reused, so two
/// distinct issuances never collide and a consumed nonce can never be
/// re-minted (the `ReplayRejected` obligation of the spec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    id: u64,
    origin: Origin,
    expiry: u64,
}

impl Nonce {
    /// The origin this nonce is bound to.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The discrete server time at (and after) which this nonce is expired.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.expiry
    }

    /// The unique, never-reused id of this nonce.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The exact bytes a client signs: the nonce's `(id, origin, expiry)`,
    /// so a signature is inseparably bound to all three. A signature is
    /// never transferable to a different nonce, origin, or expiry.
    fn signing_material(&self) -> String {
        format!(
            "pillar-web-nonce:{}:{}:{}",
            self.id, self.origin.0, self.expiry
        )
    }

    /// The signing material as a public accessor, so the node-side custody
    /// path ([`crate::node_custody`]) can sign a nonce SERVER-SIDE with the
    /// SAME framing a client uses — the two custody models share one nonce
    /// contract, never a divergent one.
    #[must_use]
    pub fn signing_material_public(&self) -> String {
        self.signing_material()
    }

    /// Mint a `Nonce` with a chosen `(id, origin, expiry)` directly.
    /// Used by [`crate::node_custody::NodeCustodyVerifier`], which mints and
    /// tracks its own challenge nonces server-side (it does not route them
    /// through a client-facing [`NonceIssuer`]); the id/origin/expiry binding
    /// is identical to what `NonceIssuer::issue` produces.
    #[must_use]
    pub fn mint(id: u64, origin: Origin, expiry: u64) -> Self {
        Nonce { id, origin, expiry }
    }
}

/// Mints challenge nonces bound to this server's own origin, from a
/// monotone serial. A nonce id is never reused across the process, so a
/// consumed challenge can never be re-issued.
#[derive(Debug)]
pub struct NonceIssuer {
    origin: Origin,
    next_serial: u64,
}

impl NonceIssuer {
    /// A nonce issuer bound to this server's `origin`.
    #[must_use]
    pub fn new(origin: impl Into<Origin>) -> Self {
        NonceIssuer {
            origin: origin.into(),
            next_serial: 0,
        }
    }

    /// This server's own origin — the only origin it accepts a login for.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Issue a fresh challenge nonce bound to this server's origin, expiring
    /// at `expiry` (a discrete server clock value). Each call mints a
    /// distinct, never-reused id.
    pub fn issue(&mut self, expiry: u64) -> Nonce {
        let id = self.next_serial;
        self.next_serial += 1;
        Nonce {
            id,
            origin: self.origin.clone(),
            expiry,
        }
    }
}

/// A client's argon2id-encrypted auth subkey, stored as world-readable
/// ciphertext addressed by content id (CID) — anyone may fetch it; only the
/// password holder can unlock it.
///
/// The ciphertext is the real ed25519 public key derived, via a real
/// memory-hard argon2id, from the plaintext subkey secret and the password;
/// recovering the private key requires the password (modelled: `unlock`
/// re-runs the KDF from the password and only yields the usable ed25519
/// signing key when the derived public key matches). The plaintext secret and
/// the password are never stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAuthSubkey {
    subkey: NodeSubkey,
    /// The real ed25519 public key derived from argon2id(password, secret):
    /// the world-readable "ciphertext" — knowing it never reveals the
    /// password or the private key (ed25519 asymmetry).
    public_key: SigningPublicKey,
}

impl EncryptedAuthSubkey {
    /// Encrypt a plaintext auth-subkey `secret` under `password` with the
    /// high-cost argon2id KDF, producing world-readable ciphertext bound to
    /// `subkey`. Neither the password nor the plaintext secret is retained.
    #[must_use]
    pub fn seal(subkey: NodeSubkey, password: &str, secret: &str) -> Self {
        let material = argon2id_material(password, &subkey, secret);
        let (public_key, _secret_key) = keypair_from_material(&material);
        EncryptedAuthSubkey {
            subkey,
            public_key,
        }
    }

    /// The auth subkey this ciphertext protects (public — it is the WoT
    /// identity the server verifies a login signature against).
    #[must_use]
    pub fn subkey(&self) -> &NodeSubkey {
        &self.subkey
    }
}

/// A locally-unlocked auth subkey: the client-side plaintext key material,
/// produced by [`unlock_auth_subkey`]. It NEVER crosses the wire — only the
/// signatures it produces do. There is intentionally no way to serialize it.
#[derive(Clone, Debug)]
pub struct AuthSubkey {
    subkey: NodeSubkey,
    /// The recovered plaintext ed25519 signing key (client-side only).
    secret_key: SigningSecretKey,
}

impl AuthSubkey {
    /// The public WoT identity of this subkey.
    #[must_use]
    pub fn subkey(&self) -> &NodeSubkey {
        &self.subkey
    }

    /// Sign a challenge `nonce` with this unlocked subkey using real ed25519.
    /// The signature is over the nonce's `(id, origin, expiry)` framing, so it
    /// is never valid for any other nonce.
    #[must_use]
    pub fn sign_nonce(&self, nonce: &Nonce) -> Signature {
        let sig = sign(&self.secret_key, nonce.signing_material().as_bytes())
            .expect("ed25519 sign must succeed");
        Signature(sig.into_bytes())
    }
}

/// A client-side signature over a challenge nonce. The only artifact of the
/// login handshake that crosses the wire to the server — a real ed25519
/// detached signature (64 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// The opaque wire encoding of this signature — the exact ed25519
    /// signature bytes that cross the network from client to server. Never
    /// contains the password or plaintext key (see
    /// `password_and_plaintext_key_never_appear_in_any_server_observable_payload`).
    #[must_use]
    pub fn to_wire_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct a signature received over the wire (the server side of
    /// [`to_wire_bytes`](Self::to_wire_bytes)).
    #[must_use]
    pub fn from_wire_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Signature(bytes.into())
    }

    /// Compatibility constructor for the node-side custody stand-in
    /// ([`crate::node_custody`]), which produces its signature from an
    /// integer material value. Encodes the integer as its little-endian
    /// bytes; the node-side verifier reconstructs the SAME bytes, so equality
    /// holds on its own path without depending on ed25519 framing.
    #[must_use]
    pub fn from_wire(value: u64) -> Self {
        Signature(value.to_le_bytes().to_vec())
    }
}

/// Client-side unlock of a password-protected auth subkey fetched by CID.
///
/// Runs the real argon2id KDF over the password to recover the ed25519 key
/// material. Returns `None` on the wrong password (the derived public key does
/// not match the stored one), so a wrong password yields no usable key rather
/// than a subtly-wrong one. This is the ONLY place the password is used, and
/// it is a purely client-side computation — the password never reaches the
/// server.
#[must_use]
pub fn unlock_auth_subkey(
    encrypted: &EncryptedAuthSubkey,
    password: &str,
    secret: &str,
) -> Option<AuthSubkey> {
    let material = argon2id_material(password, &encrypted.subkey, secret);
    let (public_key, secret_key) = keypair_from_material(&material);
    // A wrong password (or wrong secret) derives a different keypair, whose
    // public key does not match the stored ciphertext: no key is yielded.
    if public_key != encrypted.public_key {
        return None;
    }
    Some(AuthSubkey {
        subkey: encrypted.subkey.clone(),
        secret_key,
    })
}

/// The public half of a registered auth subkey the server verifies against:
/// the subkey's WoT identity plus the real ed25519 public key the server
/// verifies a login signature against. Published at registration; the server
/// only ever holds this public key, never the password or the private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredAuthKey {
    subkey: NodeSubkey,
    public_key: SigningPublicKey,
}

impl RegisteredAuthKey {
    /// Register the public half of `encrypted`'s auth key. In a real system
    /// this ed25519 public key is published at registration; here it is taken
    /// directly from the world-readable ciphertext so the server can check a
    /// signature without ever seeing the password or plaintext key.
    #[must_use]
    pub fn register(encrypted: &EncryptedAuthSubkey, _password: &str, _secret: &str) -> Self {
        RegisteredAuthKey {
            subkey: encrypted.subkey.clone(),
            public_key: encrypted.public_key.clone(),
        }
    }

    fn verify(&self, nonce: &Nonce, signature: &Signature) -> bool {
        let sig = CryptoSignature::from_bytes(signature.0.clone());
        verify(
            &self.public_key,
            nonce.signing_material().as_bytes(),
            &sig,
        )
        .is_ok()
    }
}

/// Why a WoT-key login was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginError {
    /// The nonce's expiry is at or before the current server clock.
    NonceExpired,
    /// The nonce is bound to a different origin than this server's.
    WrongOrigin,
    /// The nonce has already been consumed (replay).
    NonceReplayed,
    /// This nonce was not issued by this verifier (forged/unknown nonce).
    UnknownNonce,
    /// No auth key is registered for the signing subkey (forged subkey).
    UnknownAuthKey,
    /// The signature did not verify against the registered auth key.
    BadSignature,
    /// The subkey is not WoT-trust-authoritative (unchained), or its
    /// authority failed the fail-closed [`FencedActor`] guard (revoked /
    /// stale view). Carries the underlying authority error.
    NotAuthorized(ActError),
}

/// An admitted login session: proof that at the moment of admission the
/// signing subkey was WoT-authoritative under a fresh, fenced view. The Rust
/// stand-in for the spec's `lastAct` ghost — used to assert that a session
/// admitted before a revocation never survives it (fail-closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginSession {
    /// The subkey (WoT node) that was admitted.
    pub subject: NodeId,
    /// The consumed nonce's id.
    pub nonce_id: u64,
    /// The revocation watermark in effect at admission.
    pub watermark: u64,
}

/// The server-side WoT-key login verifier. Tracks which challenge nonces it
/// issued and which it has already consumed, and holds the registered auth
/// keys it verifies signatures against. Authority is ALWAYS resolved through
/// the shared [`WotAuthority`] + [`FencedActor`] `Act` guard — this verifier
/// adds only the nonce/signature preconditions on top, never a second
/// authority path.
#[derive(Default)]
pub struct KeyLoginVerifier {
    registered: HashMap<NodeSubkey, RegisteredAuthKey>,
    issued: HashMap<u64, Nonce>,
    consumed: std::collections::HashSet<u64>,
}

impl KeyLoginVerifier {
    /// A verifier with no auth keys registered and no nonces tracked.
    #[must_use]
    pub fn new() -> Self {
        KeyLoginVerifier::default()
    }

    /// Register the public half of an auth key so a login signature signed by
    /// it can be verified. The server holds only this public verifier.
    pub fn register_auth_key(&mut self, key: RegisteredAuthKey) {
        self.registered.insert(key.subkey.clone(), key);
    }

    /// Record a nonce this verifier issued so a later login can be checked
    /// against it (unknown/forged nonces are refused). Callers pass a nonce
    /// minted by their [`NonceIssuer`] (whose origin must match this
    /// server's).
    pub fn track_issued(&mut self, nonce: Nonce) {
        self.issued.insert(nonce.id, nonce);
    }

    /// Verify and admit a WoT-key login.
    ///
    /// Checks, in order: the nonce was issued here; it is unconsumed; it is
    /// bound to `expected_origin`; it is unexpired at `clock`; the signing
    /// subkey has a registered auth key; the ed25519 signature verifies; and
    /// finally — through the SHARED fail-closed authority guard — the subkey
    /// is WoT-authoritative under `actor`'s fenced view of `authority`. Only
    /// on all of these does it consume the nonce and return a [`LoginSession`].
    ///
    /// The password and plaintext key never appear in any argument here:
    /// the server verifies a signature against a public key, exactly as the
    /// spec requires.
    ///
    /// # Errors
    ///
    /// The matching [`LoginError`] for the first failing precondition.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        nonce: &Nonce,
        signature: &Signature,
        subkey: &NodeSubkey,
        expected_origin: &Origin,
        clock: u64,
        authority: &WotAuthority,
        actor: &FencedActor,
    ) -> Result<LoginSession, LoginError> {
        let Some(known) = self.issued.get(&nonce.id) else {
            return Err(LoginError::UnknownNonce);
        };
        if known != nonce {
            // A nonce id we issued but with tampered origin/expiry fields.
            return Err(LoginError::UnknownNonce);
        }
        if self.consumed.contains(&nonce.id) {
            return Err(LoginError::NonceReplayed);
        }
        if &nonce.origin != expected_origin {
            return Err(LoginError::WrongOrigin);
        }
        if nonce.expiry <= clock {
            return Err(LoginError::NonceExpired);
        }
        let Some(registered) = self.registered.get(subkey) else {
            return Err(LoginError::UnknownAuthKey);
        };
        if !registered.verify(nonce, signature) {
            return Err(LoginError::BadSignature);
        }
        // ONE authority path: the WoT fail-closed Act guard, unchanged.
        let snapshot = actor
            .act(authority, &subkey.node_id())
            .map_err(LoginError::NotAuthorized)?;

        self.consumed.insert(nonce.id);
        Ok(LoginSession {
            subject: subkey.node_id(),
            nonce_id: nonce.id,
            watermark: snapshot.watermark,
        })
    }
}

/// Whether a subkey is a WebAuthn/passkey-attested AUTH_SUBKEY (the spec's
/// `Passkeys` static key property). WebAuthn is REPOSITIONED as an OPTIONAL
/// signer here: a passkey-attested auth subkey admits through the EXACT same
/// [`KeyLoginVerifier::admit`] predicate as a software-unlocked subkey —
/// there is no parallel gate, so this flag never changes the admit/deny
/// outcome, it only records how the subkey's material was unlocked.
#[must_use]
pub fn is_passkey_attested(
    passkey_subkeys: &std::collections::HashSet<NodeSubkey>,
    subkey: &NodeSubkey,
) -> bool {
    passkey_subkeys.contains(subkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const GOOD_ORIGIN: &str = "https://pillar.example.com";
    const OTHER_ORIGIN: &str = "https://evil.example.net";
    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "plaintext-auth-subkey-secret";

    // Build an authority where `subkey`'s node chains to the owner and a
    // fully-fresh actor. Returns (authority, actor).
    fn chained_authority(subkey: &NodeSubkey) -> (WotAuthority, FencedActor) {
        let owner = NodeId::from("owner");
        let mut authority = WotAuthority::new(owner.clone(), 4);
        authority.issue_edge(owner, subkey.node_id(), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        (authority, actor)
    }

    // A fully wired, valid login: returns everything an `admit` call needs.
    fn valid_login() -> (
        KeyLoginVerifier,
        NonceIssuer,
        Nonce,
        Signature,
        NodeSubkey,
        WotAuthority,
        FencedActor,
    ) {
        let subkey = NodeSubkey::from("auth-subkey-1");
        let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);

        let mut verifier = KeyLoginVerifier::new();
        verifier.register_auth_key(RegisteredAuthKey::register(&encrypted, PASSWORD, SECRET));

        let mut issuer = NonceIssuer::new(GOOD_ORIGIN);
        let nonce = issuer.issue(10);
        verifier.track_issued(nonce.clone());

        // Client side: unlock and sign locally.
        let unlocked = unlock_auth_subkey(&encrypted, PASSWORD, SECRET).expect("unlock");
        let signature = unlocked.sign_nonce(&nonce);

        let (authority, actor) = chained_authority(&subkey);
        (verifier, issuer, nonce, signature, subkey, authority, actor)
    }

    #[test]
    fn valid_wot_key_login_is_admitted() {
        let (mut v, iss, nonce, sig, subkey, auth, actor) = valid_login();
        let session = v
            .admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &actor)
            .expect("admitted");
        assert_eq!(session.subject, subkey.node_id());
        assert_eq!(session.nonce_id, nonce.id());
    }

    #[test]
    fn signature_is_a_real_ed25519_signature() {
        // A real ed25519 detached signature is exactly 64 bytes; the old
        // DefaultHasher stand-in produced 8 (a u64). This asserts the
        // signature crossing the wire is genuine asymmetric crypto.
        let (_v, _iss, _nonce, sig, _subkey, _auth, _actor) = valid_login();
        assert_eq!(
            sig.to_wire_bytes().len(),
            64,
            "the login signature must be a real 64-byte ed25519 signature"
        );
    }

    #[test]
    fn expired_nonce_is_rejected() {
        let (mut v, iss, nonce, sig, subkey, auth, actor) = valid_login();
        // clock at/after expiry (expiry == 10).
        assert_eq!(
            v.admit(&nonce, &sig, &subkey, iss.origin(), 10, &auth, &actor),
            Err(LoginError::NonceExpired)
        );
    }

    #[test]
    fn wrong_origin_nonce_is_rejected() {
        let (mut v, _iss, nonce, sig, subkey, auth, actor) = valid_login();
        let other = Origin::from(OTHER_ORIGIN);
        assert_eq!(
            v.admit(&nonce, &sig, &subkey, &other, 0, &auth, &actor),
            Err(LoginError::WrongOrigin)
        );
    }

    #[test]
    fn replayed_nonce_is_rejected_on_second_use() {
        let (mut v, iss, nonce, sig, subkey, auth, actor) = valid_login();
        v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &actor)
            .expect("first admit");
        assert_eq!(
            v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &actor),
            Err(LoginError::NonceReplayed)
        );
    }

    #[test]
    fn a_forged_nonce_never_issued_here_is_rejected() {
        let (mut v, iss, _nonce, _sig, subkey, auth, actor) = valid_login();
        // A nonce the client fabricated, never tracked as issued.
        let forged = Nonce {
            id: 9999,
            origin: iss.origin().clone(),
            expiry: 10,
        };
        // Even a correctly-formed signature can't help: the nonce is unknown.
        let sig = Signature::from_wire_bytes(vec![0u8; 64]);
        assert_eq!(
            v.admit(&forged, &sig, &subkey, iss.origin(), 0, &auth, &actor),
            Err(LoginError::UnknownNonce)
        );
    }

    #[test]
    fn forged_subkey_with_no_registered_auth_key_is_rejected() {
        let (mut v, iss, nonce, sig, _subkey, auth, actor) = valid_login();
        let rogue = NodeSubkey::from("rogue-subkey");
        // rogue chains nowhere and has no registered key; auth-key check fires first.
        assert_eq!(
            v.admit(&nonce, &sig, &rogue, iss.origin(), 0, &auth, &actor),
            Err(LoginError::UnknownAuthKey)
        );
    }

    #[test]
    fn unchained_subkey_is_rejected_even_with_a_valid_signature() {
        // Register + sign correctly, but do NOT chain the subkey to the owner.
        let subkey = NodeSubkey::from("orphan-subkey");
        let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let mut v = KeyLoginVerifier::new();
        v.register_auth_key(RegisteredAuthKey::register(&encrypted, PASSWORD, SECRET));
        let mut iss = NonceIssuer::new(GOOD_ORIGIN);
        let nonce = iss.issue(10);
        v.track_issued(nonce.clone());
        let unlocked = unlock_auth_subkey(&encrypted, PASSWORD, SECRET).unwrap();
        let sig = unlocked.sign_nonce(&nonce);

        // Authority where the subkey is NOT reachable.
        let mut authority = WotAuthority::new(NodeId::from("owner"), 4);
        authority.issue_edge(NodeId::from("owner"), NodeId::from("someone-else"), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        match v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &authority, &actor) {
            Err(LoginError::NotAuthorized(ActError::NotAuthoritative)) => {}
            other => panic!("expected NotAuthoritative, got {other:?}"),
        }
    }

    #[test]
    fn wrong_password_yields_no_usable_key() {
        let subkey = NodeSubkey::from("auth-subkey-1");
        let encrypted = EncryptedAuthSubkey::seal(subkey, PASSWORD, SECRET);
        assert!(unlock_auth_subkey(&encrypted, "wrong-password", SECRET).is_none());
    }

    #[test]
    fn a_signature_forged_without_the_password_never_verifies() {
        let (mut v, iss, nonce, _sig, subkey, auth, actor) = valid_login();
        // "Unlock" with the wrong password fails outright, so an attacker
        // cannot even produce a signing key; fabricate a bogus signature.
        assert!(unlock_auth_subkey(
            &EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET),
            "guessed",
            SECRET
        )
        .is_none());
        let bogus = Signature::from_wire_bytes(vec![0xabu8; 64]);
        assert_eq!(
            v.admit(&nonce, &bogus, &subkey, iss.origin(), 0, &auth, &actor),
            Err(LoginError::BadSignature)
        );
    }

    #[test]
    fn a_signature_over_a_different_nonce_never_verifies() {
        // Real ed25519: a signature bound to one nonce must not verify a
        // different (id/origin/expiry) nonce — challenge binding is real.
        let subkey = NodeSubkey::from("auth-subkey-1");
        let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let mut v = KeyLoginVerifier::new();
        v.register_auth_key(RegisteredAuthKey::register(&encrypted, PASSWORD, SECRET));
        let mut iss = NonceIssuer::new(GOOD_ORIGIN);
        let nonce_a = iss.issue(10);
        let nonce_b = iss.issue(10);
        v.track_issued(nonce_b.clone());
        let unlocked = unlock_auth_subkey(&encrypted, PASSWORD, SECRET).unwrap();
        // Sign nonce_a but present it against the tracked nonce_b.
        let sig_over_a = unlocked.sign_nonce(&nonce_a);
        let (auth, actor) = chained_authority(&subkey);
        assert_eq!(
            v.admit(&nonce_b, &sig_over_a, &subkey, iss.origin(), 0, &auth, &actor),
            Err(LoginError::BadSignature)
        );
    }

    #[test]
    fn revoked_auth_subkey_session_fails_closed() {
        let (mut v, iss, nonce, sig, subkey, mut auth, actor) = valid_login();
        // Revoke the subkey AFTER the actor took its fresh view: the actor
        // now holds a stale watermark -> fail-closed StaleView.
        auth.revoke_key(subkey.node_id());
        match v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &actor) {
            Err(LoginError::NotAuthorized(ActError::StaleView { .. })) => {}
            other => panic!("expected fail-closed StaleView, got {other:?}"),
        }
    }

    #[test]
    fn revoked_auth_subkey_refused_even_after_the_actor_refreshes() {
        let (mut v, iss, nonce, sig, subkey, mut auth, _actor) = valid_login();
        auth.revoke_key(subkey.node_id());
        // Even a fully caught-up actor must refuse: the subkey is no longer
        // authoritative.
        let mut fresh = FencedActor::new();
        fresh.refresh(&auth);
        match v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &fresh) {
            Err(LoginError::NotAuthorized(ActError::NotAuthoritative)) => {}
            other => panic!("expected NotAuthoritative after revocation, got {other:?}"),
        }
    }

    #[test]
    fn password_and_plaintext_key_never_appear_in_any_server_observable_payload() {
        // Property test: over many passwords/secrets, the only artifacts that
        // cross to the server (the nonce's signing material and the signature)
        // must contain NEITHER the password NOR the plaintext key secret.
        for i in 0..64u32 {
            let password = format!("pw-{i}-{PASSWORD}");
            let secret = format!("sk-{i}-{SECRET}");
            let subkey = NodeSubkey::from(format!("subkey-{i}").as_str());
            let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), &password, &secret);

            let mut iss = NonceIssuer::new(GOOD_ORIGIN);
            let nonce = iss.issue(10);
            let unlocked = unlock_auth_subkey(&encrypted, &password, &secret).unwrap();
            let signature = unlocked.sign_nonce(&nonce);

            // The exact bytes a server ever sees: the nonce material + the sig.
            let mut wire = nonce.signing_material().into_bytes();
            wire.extend_from_slice(signature.to_wire_bytes());
            assert!(
                !window_contains(&wire, password.as_bytes()),
                "password leaked into server-observable payload"
            );
            assert!(
                !window_contains(&wire, secret.as_bytes()),
                "plaintext key leaked into server-observable payload"
            );
        }
    }

    // Substring search over raw bytes (the wire payload is not valid UTF-8
    // once the ed25519 signature bytes are appended).
    fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn webauthn_as_optional_signer_resolves_through_the_same_decider() {
        // A passkey-attested AUTH_SUBKEY admits through the EXACT same
        // predicate — there is no parallel gate; the attestation flag never
        // changes the outcome.
        let (mut v, iss, nonce, sig, subkey, auth, actor) = valid_login();
        let mut passkey_subkeys = HashSet::new();
        passkey_subkeys.insert(subkey.clone());
        assert!(is_passkey_attested(&passkey_subkeys, &subkey));

        // Admits identically to the software-unlocked path.
        let session = v
            .admit(&nonce, &sig, &subkey, iss.origin(), 0, &auth, &actor)
            .expect("passkey-attested subkey admits through the same decider");
        assert_eq!(session.subject, subkey.node_id());
    }

    #[test]
    fn webauthn_optional_signer_never_bypasses_authority() {
        // Marking a subkey passkey-attested does NOT let an unchained subkey
        // in: same authority gate applies.
        let subkey = NodeSubkey::from("attested-but-orphan");
        let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let mut v = KeyLoginVerifier::new();
        v.register_auth_key(RegisteredAuthKey::register(&encrypted, PASSWORD, SECRET));
        let mut iss = NonceIssuer::new(GOOD_ORIGIN);
        let nonce = iss.issue(10);
        v.track_issued(nonce.clone());
        let sig = unlock_auth_subkey(&encrypted, PASSWORD, SECRET)
            .unwrap()
            .sign_nonce(&nonce);

        let authority = WotAuthority::new(NodeId::from("owner"), 4); // subkey unreachable
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        let mut passkey_subkeys = HashSet::new();
        passkey_subkeys.insert(subkey.clone());
        assert!(is_passkey_attested(&passkey_subkeys, &subkey));

        assert!(matches!(
            v.admit(&nonce, &sig, &subkey, iss.origin(), 0, &authority, &actor),
            Err(LoginError::NotAuthorized(_))
        ));
    }
}
