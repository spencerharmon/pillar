//! OpenPGP key-type hierarchy and node-admission handshake — the Rust
//! refinement of `specs/Registration.tla`.
//!
//! # Model
//!
//! Pillar authenticates a node by an OpenPGP key hierarchy:
//!
//! ```text
//!   USER_PRIMARY  --signs-->  NODE_SUBKEY
//! ```
//!
//! A [`UserPrimary`] is enrolled with Pillar out-of-band (a *registration*);
//! only then is it an *authorized* primary. A [`NodeSubkey`] carries a
//! signature minted by *some* primary — possibly a rogue, unregistered one,
//! since minting a signature requires no authorization (mirrors the
//! deliberately-unguarded `IssueSubkey` action in the spec).
//!
//! A node joins the cluster via a [`Registry::handshake`]. Admission is
//! granted **iff** the presented subkey carries a genuine signature that
//! chains to a primary that is *currently registered*. This is the Rust
//! embodiment of the two safety theorems TLC proves over the model:
//!
//! * `AdmissionRequiresAuthorizedChain` — an admitted subkey is signed by a
//!   registered primary (no forged / unauthorized-primary admission), and
//! * `NoAmbientAuthority` — an unsigned subkey is never admitted (bare
//!   possession of a subkey identity confers no authority).
//!
//! Unlike a pure model, admission here is enforced by **real cryptography**:
//! a [`Signature`] is a genuine ed25519 subkey-binding certification produced
//! by [`PrimaryKeypair`] (which holds the issuer's *secret* key) and verified
//! by [`Registry`] against the issuer's *public* key. A party that does not
//! hold a primary's secret key cannot forge a certification for it, so the
//! admission *policy* the spec constrains is backed by the asymmetry of the
//! signature scheme rather than by an unverified assertion.
//!
//! A [`UserPrimary`] is the fingerprint of a real ed25519 public key (its
//! domain-separated SHA-256 digest), so the identity id is bound to the key
//! material it authenticates: you cannot register a fingerprint and then admit
//! subkeys under it without also holding the matching secret key that produced
//! their bindings.

#![forbid(unsafe_code)]

pub mod capability;
pub mod global_identity;
pub mod login;
pub mod session_registry;

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;
use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
use pillar_crypto::{Seed, Signature as CryptoSignature, SigningPublicKey, SigningSecretKey};

/// The fingerprint of a user's OpenPGP **primary** key — the root of a
/// Pillar user identity. Registering one authorizes it to admit nodes.
///
/// The fingerprint is the domain-separated SHA-256 digest of the primary's
/// ed25519 public key (hex-encoded), so it is bound to real key material: a
/// [`PrimaryKeypair`] projects to exactly one [`UserPrimary`], and no party
/// can produce certifications that verify under a fingerprint without holding
/// the secret key whose public half hashes to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserPrimary(pub String);

impl From<&str> for UserPrimary {
    fn from(s: &str) -> Self {
        UserPrimary(s.to_owned())
    }
}

/// Derive the [`UserPrimary`] fingerprint of an ed25519 public key: the
/// hex-encoded, domain-separated SHA-256 of its bytes.
fn fingerprint(public: &SigningPublicKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-identity/primary/fingerprint-v1");
    h.update(public.as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A user primary's real ed25519 keypair: the secret half that mints
/// subkey-binding certifications and the public half that verifies them.
///
/// This is the holder of secret key material — it is what an authorized
/// operator possesses. Its [`primary`](Self::primary) fingerprint is the
/// public [`UserPrimary`] identity registered with a [`Registry`]; only the
/// holder of this keypair can produce a [`Signature`] that admission will
/// accept under that fingerprint.
#[derive(Clone)]
pub struct PrimaryKeypair {
    public: SigningPublicKey,
    secret: SigningSecretKey,
    primary: UserPrimary,
}

impl PrimaryKeypair {
    /// Derive a primary keypair deterministically from secret `seed` material.
    ///
    /// The seed is genuine secret material (in production drawn from an OS
    /// CSPRNG via [`generate`](Self::generate)); distinct seeds yield distinct
    /// keypairs and thus distinct [`UserPrimary`] fingerprints.
    #[must_use]
    pub fn from_secret_seed(seed: &Seed) -> Self {
        let (public, secret) = signing_keypair_from_seed(seed)
            .expect("a signing seed always yields an ed25519 keypair");
        let primary = UserPrimary(fingerprint(&public));
        PrimaryKeypair {
            public,
            secret,
            primary,
        }
    }

    /// Mint a fresh primary keypair from cryptographically-random secret seed
    /// material (32 bytes from the OS CSPRNG).
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_secret_seed(&Seed::from_bytes(bytes.to_vec()))
    }

    /// This keypair's public [`UserPrimary`] fingerprint — the identity to
    /// register.
    #[must_use]
    pub fn primary(&self) -> UserPrimary {
        self.primary.clone()
    }

    /// This keypair's ed25519 public (verifying) key.
    #[must_use]
    pub fn public(&self) -> &SigningPublicKey {
        &self.public
    }

    /// Produce a real ed25519 subkey-binding certification over `subkey`.
    ///
    /// Only the holder of this secret key can produce a signature that
    /// [`Registry::verify`] will accept under this keypair's fingerprint.
    #[must_use]
    pub fn certify(&self, subkey: &NodeSubkey) -> Signature {
        let sig = sign(&self.secret, &binding_message(subkey, &self.primary))
            .expect("signing a binding message always succeeds");
        Signature {
            subkey: subkey.clone(),
            issuer: self.primary.clone(),
            issuer_public: self.public.clone(),
            sig,
        }
    }
}

/// The canonical bytes an issuer signs to bind `subkey` to primary `issuer`:
/// a domain-separated message tying both fingerprints together so a signature
/// over one binding is never valid for another subkey or primary.
fn binding_message(subkey: &NodeSubkey, issuer: &UserPrimary) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"pillar-identity/subkey-binding-v1\n");
    m.extend_from_slice(issuer.0.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(subkey.0.as_bytes());
    m
}

/// The fingerprint of an OpenPGP **node subkey** — a per-node identity that
/// must chain to a user primary to carry any authority.
///
/// On admission a subkey becomes the node's [`NodeId`] in the coordination
/// protocol; [`NodeSubkey::node_id`] performs that projection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeSubkey(pub String);

impl NodeSubkey {
    /// The [`NodeId`] this subkey acts as once admitted.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId(self.0.clone())
    }
}

impl From<&str> for NodeSubkey {
    fn from(s: &str) -> Self {
        NodeSubkey(s.to_owned())
    }
}

/// A **real** ed25519 certification binding a [`NodeSubkey`] to the
/// [`UserPrimary`] that signed it — the Rust embodiment of a verified OpenPGP
/// subkey-binding signature.
///
/// It carries the issuer's ed25519 public key and a detached signature over
/// the canonical [`binding_message`]. [`Registry::issue_subkey`] re-verifies
/// the signature (and that the public key hashes to the claimed fingerprint)
/// before recording it, so a `Signature` present in a registry is one that
/// cryptographically checks out — an attacker without the issuer's secret key
/// cannot construct one that will be accepted. It says nothing about whether
/// the issuer is *authorized*; that is the registry's decision at
/// [`handshake`](Registry::handshake) time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    subkey: NodeSubkey,
    issuer: UserPrimary,
    issuer_public: SigningPublicKey,
    sig: CryptoSignature,
}

impl Signature {
    /// The subkey this signature certifies.
    #[must_use]
    pub fn subkey(&self) -> &NodeSubkey {
        &self.subkey
    }

    /// The user primary that produced the certification.
    #[must_use]
    pub fn issuer(&self) -> &UserPrimary {
        &self.issuer
    }

    /// Verify this certification cryptographically: the carried public key
    /// must hash to the claimed issuer fingerprint AND must have actually
    /// signed the subkey-binding message. Returns `false` for a forged or
    /// tampered certification.
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        if fingerprint(&self.issuer_public) != self.issuer.0 {
            return false;
        }
        verify(
            &self.issuer_public,
            &binding_message(&self.subkey, &self.issuer),
            &self.sig,
        )
        .is_ok()
    }
}

/// Why a handshake was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The presented subkey carries no known signature — bare possession of a
    /// subkey identity confers no authority (`NoAmbientAuthority`).
    Unchained,
    /// The subkey is signed, but by a primary that is not currently
    /// registered — a forged / unauthorized-primary chain
    /// (`AdmissionRequiresAuthorizedChain`).
    UnauthorizedIssuer {
        /// The primary that actually signed the subkey.
        issuer: UserPrimary,
    },
}

/// The identity registry: which user primaries are authorized, which subkeys
/// carry a verified signature, and which subkeys have been admitted.
///
/// Refines the `registered` / `signedBy` / `admitted` variables of
/// `specs/Registration.tla`. The [`handshake`](Registry::handshake) guard is
/// the sole path to admission and is exactly the spec's admission policy.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    registered: HashSet<UserPrimary>,
    /// subkey -> the primary that signed it (a verified certification)
    signed_by: HashMap<NodeSubkey, UserPrimary>,
    admitted: HashSet<NodeSubkey>,
}

impl Registry {
    /// An empty registry: nothing registered, signed, or admitted.
    #[must_use]
    pub fn new() -> Self {
        Registry::default()
    }

    /// Enroll a user primary as an authorized Pillar identity (`Register`).
    ///
    /// Any primary may register; admission depends on this having happened,
    /// not on any prerequisite for registration itself.
    pub fn register(&mut self, primary: UserPrimary) {
        self.registered.insert(primary);
    }

    /// Whether `primary` is currently a registered (authorized) identity.
    #[must_use]
    pub fn is_registered(&self, primary: &UserPrimary) -> bool {
        self.registered.contains(primary)
    }

    /// Record a subkey-binding certification (`IssueSubkey`).
    ///
    /// The certification is **cryptographically verified** first: a `Signature`
    /// whose carried public key does not hash to its claimed issuer, or whose
    /// ed25519 signature does not check out over the canonical binding message,
    /// is a forgery and is silently dropped (never recorded, so it can never
    /// admit anything). This is the asymmetry guarantee — a party without a
    /// primary's secret key cannot inject a binding under that primary's
    /// fingerprint.
    ///
    /// Recording is deliberately unguarded by *registration*: a rogue,
    /// *unregistered* primary that DOES hold its own secret key can still mint
    /// a genuine signature over a subkey. That authentic-but-unauthorized
    /// binding must never be sufficient for admission — the
    /// [`handshake`](Self::handshake) guard enforces that separately.
    ///
    /// Returns `true` if the certification was authentic and recorded, `false`
    /// if it was a forgery and rejected.
    pub fn issue_subkey(&mut self, signature: Signature) -> bool {
        if !signature.is_authentic() {
            return false;
        }
        self.signed_by
            .insert(signature.subkey.clone(), signature.issuer);
        true
    }

    /// Whether `subkey` has already been admitted.
    #[must_use]
    pub fn is_admitted(&self, subkey: &NodeSubkey) -> bool {
        self.admitted.contains(subkey)
    }

    /// Verify a handshake's admission chain **without** mutating the registry.
    ///
    /// Admits iff the subkey carries a genuine signature (`Unchained`
    /// otherwise) chaining to a currently registered primary
    /// (`UnauthorizedIssuer` otherwise). This is the pure admission policy;
    /// [`handshake`](Self::handshake) is its stateful wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Unchained`] for an unsigned subkey and
    /// [`AdmissionError::UnauthorizedIssuer`] when the signing primary is not
    /// registered.
    pub fn verify(&self, subkey: &NodeSubkey) -> Result<NodeId, AdmissionError> {
        match self.signed_by.get(subkey) {
            None => Err(AdmissionError::Unchained),
            Some(issuer) if self.registered.contains(issuer) => Ok(subkey.node_id()),
            Some(issuer) => Err(AdmissionError::UnauthorizedIssuer {
                issuer: issuer.clone(),
            }),
        }
    }

    /// Present a subkey for admission (`Handshake`): the only action that can
    /// grow the admitted set.
    ///
    /// On success the subkey is admitted and its [`NodeId`] returned. The guard
    /// is [`verify`](Self::verify): a genuine signature chaining to a currently
    /// registered primary. Admitting an already-admitted subkey is idempotent.
    ///
    /// # Errors
    ///
    /// Propagates [`verify`](Self::verify)'s errors; the registry is left
    /// unchanged when admission is refused.
    pub fn handshake(&mut self, subkey: &NodeSubkey) -> Result<NodeId, AdmissionError> {
        let node = self.verify(subkey)?;
        self.admitted.insert(subkey.clone());
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic real primary keypair from a label (its fingerprint is
    /// derived from the ed25519 public key, not the label).
    fn keypair(label: &str) -> PrimaryKeypair {
        PrimaryKeypair::from_secret_seed(&Seed::from_bytes(
            format!("pillar-identity-test-primary::{label}").into_bytes(),
        ))
    }

    fn subkey(s: &str) -> NodeSubkey {
        NodeSubkey::from(s)
    }

    #[test]
    fn chained_subkey_of_registered_primary_is_admitted() {
        // A user primary enrolls, signs a node subkey, and the node presents
        // it: admission succeeds and yields the node's identity.
        let mut reg = Registry::new();
        let alice = keypair("alice-primary");
        let node = subkey("alice-node-1");

        reg.register(alice.primary());
        assert!(reg.issue_subkey(alice.certify(&node)));

        assert_eq!(reg.handshake(&node), Ok(node.node_id()));
        assert!(reg.is_admitted(&node));
    }

    #[test]
    fn subkey_signed_by_unregistered_primary_is_rejected() {
        // A rogue primary holds its own secret key and mints a GENUINE
        // signature (IssueSubkey is unguarded by registration) but never
        // registers: the chain does not resolve to an authorized user, so the
        // handshake is refused and nothing is admitted.
        let mut reg = Registry::new();
        let rogue = keypair("rogue-primary");
        let node = subkey("rogue-node");

        assert!(reg.issue_subkey(rogue.certify(&node)));

        assert_eq!(
            reg.handshake(&node),
            Err(AdmissionError::UnauthorizedIssuer {
                issuer: rogue.primary()
            })
        );
        assert!(!reg.is_admitted(&node));
    }

    #[test]
    fn forged_certification_is_never_recorded_or_admitted() {
        // The real-crypto guarantee: an attacker who does NOT hold a primary's
        // secret key cannot inject a binding under that primary's fingerprint.
        // We take a genuine signature from the attacker's OWN keypair and
        // relabel its issuer to the victim's fingerprint (and even swap in the
        // victim's public key) — issue_subkey re-verifies and rejects it, so it
        // is never recorded and the subkey stays unadmittable.
        let mut reg = Registry::new();
        let victim = keypair("victim-primary");
        let attacker = keypair("attacker-primary");
        reg.register(victim.primary());
        let node = subkey("attacker-node");

        // Genuine attacker signature, then forge the issuer fingerprint to the
        // victim's — the public key no longer hashes to the claimed issuer.
        let mut forged = attacker.certify(&node);
        forged.issuer = victim.primary();
        assert!(!forged.is_authentic());
        assert!(!reg.issue_subkey(forged));

        // Or claim the victim's public key without holding its secret: the
        // signature was not produced by that key, so verification fails.
        let mut forged2 = attacker.certify(&node);
        forged2.issuer = victim.primary();
        forged2.issuer_public = victim.public().clone();
        assert!(!forged2.is_authentic());
        assert!(!reg.issue_subkey(forged2));

        // Nothing was recorded, so the node cannot be admitted at all.
        assert_eq!(reg.handshake(&node), Err(AdmissionError::Unchained));
        assert!(!reg.is_admitted(&node));
    }

    #[test]
    fn tampered_binding_message_never_verifies() {
        // A signature genuinely produced over subkey A must not verify as a
        // certification of a different subkey B: the binding message ties the
        // signature to exactly one (issuer, subkey) pair.
        let alice = keypair("alice-primary");
        let node_a = subkey("node-a");
        let node_b = subkey("node-b");
        let mut sig = alice.certify(&node_a);
        assert!(sig.is_authentic());
        sig.subkey = node_b;
        assert!(!sig.is_authentic());
    }

    #[test]
    fn unchained_subkey_is_rejected() {
        // NoAmbientAuthority: an unsigned subkey — mere possession of a subkey
        // identity — can never be admitted.
        let mut reg = Registry::new();
        let node = subkey("orphan-node");

        assert_eq!(reg.handshake(&node), Err(AdmissionError::Unchained));
        assert!(!reg.is_admitted(&node));
    }

    #[test]
    fn deregistration_scenario_only_registered_primary_admits() {
        // Two primaries sign subkeys; only the registered one's node is
        // admitted, proving admission tracks authorization, not signing.
        let mut reg = Registry::new();
        let authorized = keypair("authorized");
        let unauthorized = keypair("unauthorized");
        let good = subkey("good-node");
        let bad = subkey("bad-node");

        reg.register(authorized.primary());
        assert!(reg.issue_subkey(authorized.certify(&good)));
        assert!(reg.issue_subkey(unauthorized.certify(&bad)));

        assert_eq!(reg.handshake(&good), Ok(good.node_id()));
        assert_eq!(
            reg.handshake(&bad),
            Err(AdmissionError::UnauthorizedIssuer {
                issuer: unauthorized.primary()
            })
        );
    }

    #[test]
    fn verify_does_not_mutate_admitted_set() {
        // The pure policy check leaves the registry untouched.
        let mut reg = Registry::new();
        let alice = keypair("alice");
        let node = subkey("node");
        reg.register(alice.primary());
        assert!(reg.issue_subkey(alice.certify(&node)));

        assert!(reg.verify(&node).is_ok());
        assert!(!reg.is_admitted(&node));
    }
}
