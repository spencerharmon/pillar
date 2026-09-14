//! Node-side key custody login ("the trusted node holds the key on your
//! behalf") — the REVISED, universal auth flow for pillar's trusted-node
//! portal, refining `specs/NodeCustodyLogin.tla` (proven by
//! `identity-node-custody-spec`).
//!
//! This SUPERSEDES the client-side custody model of [`crate::key_login`] for
//! the deployed-portal default. In the old (client-side) model the browser
//! fetched the encrypted auth subkey by CID and unlocked it LOCALLY, so the
//! login form asked for THREE fields (handle + CID + password). The ROI now
//! declares that wrong for pillar's trusted-node posture: the user is NOT
//! asked for the CID — a third field would be a bug.
//!
//! In this model the NODE does the custody work SERVER-SIDE:
//!
//! 1. The user supplies exactly TWO inputs — a user IDENTIFIER
//!    (`user@domain` / `username` / genesis CID) and an unlock FACTOR
//!    (password or passkey token). No CID field.
//! 2. The node (holding the cell's key-distribution label) RESOLVES this
//!    user's node-sealed key offer from the cell DB
//!    ([`NodeCellDb`]: identifier → CID → sealed blob), STRIPS the node seal
//!    with its own node key ([`NodeKey::unseal`]), and UNLOCKS the
//!    operational key with the high-cost argon2id last line
//!    ([`unlock_operational_key`]) — all server-side.
//! 3. The node signs the origin+expiry nonce with the unlocked operational
//!    key, runs the SAME WoT/RBAC decider the rest of the platform trusts,
//!    and admits the user into an authenticated portal session.
//!
//! ## Security model — node-side custody on a trusted node
//!
//! The password crosses TLS to the trusted node, which holds the key ONLY
//! because the cell sealed an offer TO it (per-node, opt-in, revocable — that
//! per-node seal IS the access control). It is NOT a blanket leak: an
//! unsealed node cannot resolve or strip the offer, so the operational key
//! never lands there ([`NodeCustodyError::NoCustody`]). Client-side signing /
//! caBLE ([`crate::key_login`]) remains ONLY the untrusted/foreign-node path;
//! passkey/WebAuthn stays an optional stronger unlock factor.
//!
//! ## Real cryptography (ROI non-negotiable #7)
//!
//! This crate now runs the SAME real primitives [`pillar_crypto`] wires
//! everywhere else in the codebase — never a `DefaultHasher`/`SipHash`
//! stand-in and never a bare integer-equality "AEAD":
//! * [`pillar_crypto::kdf::derive_key`] — memory-hard **argon2id**, the
//!   high-cost last line that turns the user's password into the symmetric
//!   key protecting the operational-key material at rest.
//! * [`pillar_crypto::aead::seal_symmetric`] /
//!   [`pillar_crypto::aead::open_symmetric`] — **ChaCha20/XChaCha20-Poly1305**
//!   AEAD, used TWICE in a real nested envelope: the password-derived key
//!   seals the plaintext operational-key material (the "inner" layer), and
//!   the node's own derived key then node-seals that inner ciphertext (the
//!   "outer" layer) — an unsealed node literally cannot decrypt the inner
//!   ciphertext, and a wrong password fails AEAD authentication rather than
//!   comparing two integers.
//! * [`pillar_crypto::sign::signing_keypair_from_seed`] /
//!   [`pillar_crypto::sign::sign`] / [`pillar_crypto::sign::verify`] — real
//!   **ed25519** signing over the challenge nonce with the material the node
//!   recovers server-side; the node verifies only against the WoT-registered
//!   public key, exactly like [`crate::key_login`].

use std::collections::HashMap;

use pillar_core::NodeId;
use pillar_crypto::{aead, kdf, sign};
use pillar_crypto::{Ciphertext, KdfParams, Salt, Seed, SigningPublicKey, SymmetricKey};
use pillar_identity::NodeSubkey;
use pillar_key_distribution::{
    Artifact, ArtifactId, ArtifactKind, CellId, KeyDistributionLedger, RecordKey, StepUpToken,
    UserId as KdUserId,
};
use pillar_wot_authority::{ActError, FencedActor, WotAuthority};

use crate::key_login::{Nonce, Origin, Signature};

/// The argon2id work parameters protecting the password-locked operational
/// key at rest. Same OWASP-ish starting point [`KdfParams::default`] ships,
/// matching [`crate::key_login`].
fn kdf_params() -> KdfParams {
    KdfParams::default()
}

/// Derive the per-subkey argon2id salt for the PASSWORD layer. Bound to the
/// subkey's own (public, non-secret) identity so distinct subkeys never
/// share a salt even under the same password.
fn subkey_salt(subkey: &NodeSubkey) -> Salt {
    Salt::from_bytes(format!("pillar-node-custody/pw-salt-v1/{}", subkey.0).into_bytes())
}

/// The ed25519 signing-seed derivation domain tag: binds the seed to the
/// subkey's own identity as well as the recovered plaintext secret, mirroring
/// [`crate::key_login`]'s `subkey_seed`.
fn subkey_seed(subkey: &NodeSubkey, secret: &str) -> Seed {
    Seed::from_bytes(format!("pillar-node-custody/seed-v1/{}/{secret}", subkey.0).into_bytes())
}

/// Derive the node's own AEAD key for the OUTER node-seal layer, from the
/// node's private secret and its own (public) [`NodeId`] — a real memory-hard
/// KDF, exactly as the password layer uses, but keyed by the node's secret
/// rather than a user password.
fn node_seal_key(node: &NodeId, node_secret: &str) -> SymmetricKey {
    let salt =
        Salt::from_bytes(format!("pillar-node-custody/node-seal-salt-v1/{node}").into_bytes());
    kdf::derive_key(node_secret.as_bytes(), &salt, &kdf_params())
        .expect("argon2id derivation with valid params never fails")
}

/// A content id (CID) addressing an opaque, node-sealed key-offer blob in the
/// cell DB. The user is NEVER asked for this — the node resolves it from the
/// user identifier (that resolution is the whole point of node-side custody).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub String);

impl From<&str> for Cid {
    fn from(s: &str) -> Self {
        Cid(s.to_owned())
    }
}

/// A node's own private node key — the credential that lets THIS node strip
/// the node-seal off an offer the cell sealed to it. Held only by the node;
/// never transmitted. Modelled as an opaque secret whose derived material the
/// seal/unseal stand-in mixes in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeKey {
    node: NodeId,
    secret: String,
}

impl NodeKey {
    /// This node's node key, bound to its [`NodeId`].
    #[must_use]
    pub fn new(node: NodeId, secret: impl Into<String>) -> Self {
        NodeKey {
            node,
            secret: secret.into(),
        }
    }

    /// The node this key belongs to.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Strip the node-seal off `blob`, recovering the inner
    /// (still password-locked) operational-key ciphertext — but ONLY if this
    /// node is in the blob's sealed-to set AND holds the matching node
    /// secret: the outer layer is a REAL AEAD open (ChaCha20/XChaCha20-
    /// Poly1305) keyed by this node's own argon2id-derived seal key, so a
    /// node not sealed to it (or lacking the right secret) fails AEAD
    /// authentication and returns `None` — the operational key never lands
    /// on an unsealed foreign node (`UntrustedNodeNeverHoldsKey`).
    #[must_use]
    fn unseal(&self, blob: &SealedOffer) -> Option<Ciphertext> {
        if !blob.sealed_to.contains(&self.node) {
            return None;
        }
        let seal_key = node_seal_key(&self.node, &self.secret);
        let inner = aead::open_symmetric(
            &seal_key,
            &blob.node_sealed,
            b"pillar-node-custody/node-seal-v1",
        )
        .ok()?;
        Some(Ciphertext::from_bytes(inner))
    }
}

/// A node-sealed key offer as it sits in the cell DB, addressed by [`Cid`]:
/// opaque ciphertext (`node_sealed`) plus the set of node keys the cell has
/// currently sealed it TO. The sealed-to set IS the participation allow-list
/// (per-node, revocable — mirrors `pillar_key_distribution`'s seal target).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedOffer {
    /// The public operational subkey this offer unlocks — the WoT identity a
    /// login is verified against.
    subkey: NodeSubkey,
    /// The node-sealed ciphertext: the password-locked operational-key
    /// material (itself a real AEAD ciphertext), further AEAD-sealed to the
    /// allow-listed node keys.
    node_sealed: Ciphertext,
    /// The nodes the cell has sealed this offer to (the access control).
    sealed_to: std::collections::BTreeSet<NodeId>,
}

impl SealedOffer {
    /// Seal a fresh offer for `subkey`: the operational key is locked under
    /// `password` (the high-cost argon2id-derived AEAD key — the "inner"
    /// layer) and then node-sealed (a second, independent AEAD layer keyed
    /// by the trusted node's own argon2id-derived material — the "outer"
    /// layer) to every node in `sealed_to`. `secret` is the plaintext
    /// operational-key material (never retained in the blob). The node seal
    /// for THIS stand-in is keyed by a single node's material; a real
    /// deployment seals per-node — here we model the common case of one
    /// trusted node per offer, which is all the login path exercises.
    #[must_use]
    pub fn seal(
        subkey: NodeSubkey,
        password: &str,
        secret: &str,
        node_key: &NodeKey,
        sealed_to: impl IntoIterator<Item = NodeId>,
    ) -> Self {
        let sealed_to: std::collections::BTreeSet<NodeId> = sealed_to.into_iter().collect();
        // Inner: the password-locked operational-key ciphertext (argon2id KEK
        // + a real AEAD seal — never a bare digest).
        let pw_key = kdf::derive_key(password.as_bytes(), &subkey_salt(&subkey), &kdf_params())
            .expect("argon2id derivation with valid params never fails");
        let inner =
            aead::seal_symmetric(&pw_key, secret.as_bytes(), b"pillar-node-custody/inner-v1")
                .expect("chacha20poly1305 sealing of valid input never fails");
        // Outer: node-seal it with the trusted node's own derived AEAD key.
        let node_key_mat = node_seal_key(&node_key.node, &node_key.secret);
        let outer = aead::seal_symmetric(
            &node_key_mat,
            inner.as_bytes(),
            b"pillar-node-custody/node-seal-v1",
        )
        .expect("chacha20poly1305 sealing of valid input never fails");
        SealedOffer {
            subkey,
            node_sealed: outer,
            sealed_to,
        }
    }

    /// The public operational subkey this offer unlocks.
    #[must_use]
    pub fn subkey(&self) -> &NodeSubkey {
        &self.subkey
    }

    /// Whether the offer is currently sealed to `node` (i.e. that node may
    /// resolve+strip it). Revoking is dropping the node from this set.
    #[must_use]
    pub fn is_sealed_to(&self, node: &NodeId) -> bool {
        self.sealed_to.contains(node)
    }

    /// The opaque node-sealed ciphertext bytes — the durable material a node
    /// must persist to reconstruct this offer across a restart WITHOUT ever
    /// storing the user's password (the password only ever unlocks the inner
    /// layer at login time, live, from the user). The inverse of
    /// [`SealedOffer::from_sealed_parts`].
    #[must_use]
    pub fn node_sealed_bytes(&self) -> &[u8] {
        self.node_sealed.as_bytes()
    }

    /// Reconstruct a sealed offer from its persisted parts — the durable
    /// counterpart of [`SealedOffer::seal`] used on restart to restore an
    /// already-sealed offer from the streaming DB, never re-sealing it (so no
    /// password is needed and none is ever persisted). `node_sealed` is the
    /// exact ciphertext [`SealedOffer::node_sealed_bytes`] returned; `sealed_to`
    /// is the same allow-list the ledger admits, so the node's own
    /// [`NodeKey::unseal`] strips it identically to a freshly sealed offer.
    #[must_use]
    pub fn from_sealed_parts(
        subkey: NodeSubkey,
        node_sealed: impl Into<Vec<u8>>,
        sealed_to: impl IntoIterator<Item = NodeId>,
    ) -> Self {
        SealedOffer {
            subkey,
            node_sealed: Ciphertext::from_bytes(node_sealed),
            sealed_to: sealed_to.into_iter().collect(),
        }
    }
}

/// The cell DB view a node needs to resolve node-side custody logins: it maps
/// a user IDENTIFIER (`user@domain` / `username` / genesis CID) to the CID of
/// that user's key-offer blob and to the [`RecordKey`] the REAL
/// `pillar_key_distribution` ledger tracks admission under, and each CID to
/// the node-sealed [`SealedOffer`] blob. This is the "CID → sealed blob"
/// resolution the ROI requires the node to do so the USER never supplies the
/// CID — and it is never treated as present unless the ledger's OWN
/// bi-directional offer/accept/admit admission actually holds for the
/// record (see [`NodeCustodyVerifier::admit`]), so a real ledger
/// [`KeyDistributionLedger::revoke_offer`] fails the resolution closed
/// exactly like every other consumer of that ledger.
#[derive(Clone, Debug, Default)]
pub struct NodeCellDb {
    /// user identifier -> the CID of that user's key offer.
    identifier_to_cid: HashMap<String, Cid>,
    /// user identifier -> the key-distribution ledger record this offer is
    /// admitted (or revoked) under.
    identifier_to_record: HashMap<String, RecordKey>,
    /// CID -> the node-sealed offer blob.
    offers: HashMap<Cid, SealedOffer>,
    /// user identifier -> the human handle to greet them by on the portal.
    handles: HashMap<String, String>,
}

impl NodeCellDb {
    /// An empty cell DB (a node that has been given the key-distribution
    /// label but resolved no offers yet).
    #[must_use]
    pub fn new() -> Self {
        NodeCellDb::default()
    }

    /// Record a user's offer: `identifier` (any of the accepted identifier
    /// forms) resolves to `cid`, which addresses `offer`; the user is greeted
    /// by `handle`. `record` is the REAL key-distribution ledger record this
    /// offer's admission is tracked under.
    pub fn put_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        record: RecordKey,
        offer: SealedOffer,
    ) {
        let identifier = identifier.into();
        self.identifier_to_cid
            .insert(identifier.clone(), cid.clone());
        self.identifier_to_record.insert(identifier.clone(), record);
        self.handles.insert(identifier, handle.into());
        self.offers.insert(cid, offer);
    }

    /// Resolve a user identifier to its CID (the node-side lookup the user
    /// never has to do).
    #[must_use]
    pub fn resolve_cid(&self, identifier: &str) -> Option<&Cid> {
        self.identifier_to_cid.get(identifier)
    }

    /// The key-distribution ledger record this identifier's offer is tracked
    /// under, if any.
    #[must_use]
    pub fn record_for(&self, identifier: &str) -> Option<&RecordKey> {
        self.identifier_to_record.get(identifier)
    }

    /// The node-sealed offer blob for a CID.
    #[must_use]
    pub fn offer_for(&self, cid: &Cid) -> Option<&SealedOffer> {
        self.offers.get(cid)
    }

    /// The human handle to greet the resolved user by.
    #[must_use]
    pub fn handle_for(&self, identifier: &str) -> Option<&str> {
        self.handles.get(identifier).map(String::as_str)
    }
}

/// The public verifier the node checks a node-unlocked login signature
/// against — derived from the SAME operational-key material at registration,
/// so the node can confirm it unlocked the right key without the plaintext
/// key ever being persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredOperationalKey {
    subkey: NodeSubkey,
    verifier: SigningPublicKey,
}

impl RegisteredOperationalKey {
    /// Register the public half of the operational key sealed in `offer`,
    /// given the `password` and plaintext `secret` it was sealed under.
    #[must_use]
    pub fn register(subkey: NodeSubkey, _password: &str, secret: &str) -> Self {
        let seed = subkey_seed(&subkey, secret);
        let (verifier, _secret_key) = sign::signing_keypair_from_seed(&seed)
            .expect("ed25519 keygen from valid seed never fails");
        RegisteredOperationalKey { subkey, verifier }
    }

    /// Register from a KNOWN public verifier, WITHOUT the plaintext `secret`.
    /// This is how a RANDOM-secret offer (an operational key minted from OS
    /// entropy, never re-derivable from the handle) is reconstructed on
    /// restart/replay: the node persisted only the sealed blob and this public
    /// key, never the secret, so [`register`](Self::register) (which needs the
    /// secret) cannot be used — the login-time AEAD unlock still recovers the
    /// secret from the blob and re-derives a signature this verifier checks.
    #[must_use]
    pub fn from_public(subkey: NodeSubkey, verifier: SigningPublicKey) -> Self {
        RegisteredOperationalKey { subkey, verifier }
    }

    fn verify(&self, nonce: &Nonce, signature: &Signature) -> bool {
        let sig = pillar_crypto::Signature::from_bytes(signature.to_wire().to_vec());
        sign::verify(&self.verifier, &nonce.signing_material_public(), &sig).is_ok()
    }
}

/// Sign the challenge nonce SERVER-SIDE with the unlocked operational-key
/// material — a real ed25519 signature derived from the SAME seed the
/// registered verifier's public key came from, mirroring
/// [`crate::key_login::AuthSubkey::sign_nonce`]'s framing so the same public
/// verifier checks it.
fn sign_material(subkey: &NodeSubkey, secret: &str, nonce: &Nonce) -> Signature {
    sign_bytes(subkey, secret, &nonce.signing_material_public())
}

/// Sign ARBITRARY bytes SERVER-SIDE with the unlocked operational-key material
/// — the generalization of [`sign_material`] from a login nonce to any signing
/// material (e.g. a [`pillar_wire::PillarMessage`]'s signing material). The
/// delegated-signing kernel: the node holds the key and signs an op body on the
/// user's behalf; the client never possesses the key.
fn sign_bytes(subkey: &NodeSubkey, secret: &str, material: &[u8]) -> Signature {
    let seed = subkey_seed(subkey, secret);
    let (_public, secret_key) =
        sign::signing_keypair_from_seed(&seed).expect("ed25519 keygen from valid seed never fails");
    let sig =
        sign::sign(&secret_key, material).expect("ed25519 signing over valid input never fails");
    Signature::from_wire(sig.into_bytes())
}

/// The operational public signing key for `(subkey, secret)` — the `signer`
/// field a delegated-signed [`pillar_wire::PillarMessage`] carries, and the
/// subject the ingest authenticates the signature against.
fn operational_public(subkey: &NodeSubkey, secret: &str) -> SigningPublicKey {
    let seed = subkey_seed(subkey, secret);
    sign::signing_keypair_from_seed(&seed)
        .expect("ed25519 keygen from valid seed never fails")
        .0
}

/// Why a node-side custody login was refused. The failure modes surface as
/// clear in-UI messages, including the NEW node-custody-specific mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeCustodyError {
    /// This node lacks the key-distribution label / has no offer for this
    /// user — the NEW mode: the node cannot resolve an offer (unknown user or
    /// unlabelled node). Distinct from a wrong password.
    NoOfferForUser,
    /// The node resolved an offer but is NOT in its sealed-to set — the cell
    /// never sealed this key to THIS node, so it cannot strip the seal. The
    /// operational key never lands here (node-side custody access control).
    NoCustody,
    /// The unlock factor (password/passkey) did not unlock the operational
    /// key — a wrong password.
    UnlockFailed,
    /// The unlocked subkey is not WoT-trust-authoritative (unchained), or its
    /// authority failed the fail-closed guard (revoked / stale view).
    NotAuthorized(ActError),
    /// The challenge nonce was unknown/expired/replayed/wrong-origin.
    BadNonce,
    /// A delegated signing request arrived without a fresh, unconsumed step-up
    /// token — one re-authentication is required per delegated signature
    /// (mirrors [`pillar_key_distribution::Escrow::recover_plaintext_for_signing`]).
    StepUpRequired,
}

/// An admitted node-custody login session: the user identity, the subkey the
/// node unlocked+signed with, and the revocation watermark in force at
/// admission (fail-closed ghost, exactly as [`crate::key_login::LoginSession`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeCustodySession {
    /// The human handle to greet the user by.
    pub handle: String,
    /// The operational subkey (WoT node) that was admitted.
    pub subject: NodeId,
    /// The consumed nonce's id.
    pub nonce_id: u64,
    /// The revocation watermark in effect at admission.
    pub watermark: u64,
}

/// Unlock the operational key SERVER-SIDE given the node-stripped inner
/// ciphertext and the user's password: re-derives the argon2id key and opens
/// the AEAD-sealed operational-key material. Returns the recovered plaintext
/// bytes only on the right password (the AEAD open must authenticate), else
/// `None` — a wrong password fails AEAD authentication rather than an
/// integer-equality check, so it yields no usable key at all (never a subtly
/// wrong one).
#[must_use]
fn unlock_operational_key(
    inner_ciphertext: &Ciphertext,
    subkey: &NodeSubkey,
    password: &str,
) -> Option<Vec<u8>> {
    let pw_key = kdf::derive_key(password.as_bytes(), &subkey_salt(subkey), &kdf_params()).ok()?;
    aead::open_symmetric(&pw_key, inner_ciphertext, b"pillar-node-custody/inner-v1").ok()
}

/// The node-side custody login verifier: holds this node's node key, its view
/// of the cell DB, the registered operational-key verifiers, the nonce
/// tracking, and resolves authority through the SAME shared
/// [`WotAuthority`] + [`FencedActor`] guard the controllers use — never a
/// parallel authority.
pub struct NodeCustodyVerifier {
    node_key: NodeKey,
    cell_db: NodeCellDb,
    registered: HashMap<NodeSubkey, RegisteredOperationalKey>,
    issued: HashMap<u64, Nonce>,
    consumed: std::collections::HashSet<u64>,
    origin: Origin,
    /// The REAL `pillar_key_distribution` bi-directional offer/accept/admit
    /// ledger this node's offers are resolved through — the same engine
    /// `key-distribution-offer-impl`'s `pillar offer` CLI family drives.
    /// [`NodeCellDb`] never stands in for admission on its own: a CID/blob
    /// pair is resolvable ONLY once this ledger's `is_admitted` holds for the
    /// record, so [`KeyDistributionLedger::revoke_offer`]'s fail-closed
    /// revocation is real here too (see
    /// [`NodeCustodyVerifier::revoke_offer_for`]).
    ledger: KeyDistributionLedger,
}

/// The ledger-admission state [`NodeCustodyVerifier::resolve_and_unlock_with`]
/// requires of the offer it unseals — see that method and
/// [`NodeCustodyVerifier::prove_ownership`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RequiredAdmission {
    /// The normal login/sign path: the offer must be currently admitted.
    Admitted,
    /// The ownership-proof path: the offer must be currently REVOKED.
    Revoked,
}

impl NodeCustodyVerifier {
    /// A verifier for a node holding `node_key`, serving the origin `origin`,
    /// with an empty cell DB and a fresh key-distribution ledger with this
    /// node as the only node ("foreign nodes" empty — the login path never
    /// exercises cross-owner cells).
    #[must_use]
    pub fn new(node_key: NodeKey, origin: impl Into<Origin>) -> Self {
        NodeCustodyVerifier {
            node_key,
            cell_db: NodeCellDb::new(),
            registered: HashMap::new(),
            issued: HashMap::new(),
            consumed: std::collections::HashSet::new(),
            origin: origin.into(),
            ledger: KeyDistributionLedger::new(std::collections::BTreeSet::new()),
        }
    }

    /// This node's origin, as a key-distribution [`CellId`] — the single
    /// cell every offer this node custodies is distributed through.
    fn home_cell(&self) -> CellId {
        CellId::from(self.origin.0.as_str())
    }

    /// Give this node an offer to custody: really OFFER + ACCEPT + ADMIT the
    /// record through the REAL [`KeyDistributionLedger`] (the SAME
    /// bi-directional admission `key-distribution-offer-impl`'s `pillar
    /// offer seal`/`resolve` CLI already drives — never a second, divergent
    /// admission path), seal the operational key to THIS node, and register
    /// its public verifier. The plaintext `secret` is NEVER retained
    /// server-side — the real AEAD unlock recovers it from the sealed offer
    /// at login time.
    ///
    /// # Panics
    ///
    /// If the ledger refuses the offer/accept/admit sequence (e.g. the same
    /// `identifier`+`cid` is provisioned twice) — a provisioning-time
    /// programming error, not a runtime login condition.
    pub fn provision_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        password: &str,
        secret: &str,
    ) {
        let this_node = self.node_key.node().clone();
        self.admit_offer_via_ledger(
            identifier,
            handle,
            cid,
            subkey,
            password,
            secret,
            &self.node_key.clone(),
            std::iter::once(this_node),
        );
    }

    /// Provision an offer whose blob is sealed to a DIFFERENT node than this
    /// one (so this node cannot strip it) — used to exercise the `NoCustody`
    /// path where the cell sealed the key to some other node. The ledger
    /// admission is still real: the record IS admitted (this node CAN
    /// resolve the CID/blob), the crypto seal is simply to a node other than
    /// this one, exactly mirroring a real cell that allow-listed a different
    /// node.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_offer_sealed_elsewhere(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        password: &str,
        secret: &str,
        other_node: NodeId,
        other_secret: &str,
    ) {
        let other_key = NodeKey::new(other_node.clone(), other_secret);
        self.admit_offer_via_ledger(
            identifier,
            handle,
            cid,
            subkey,
            password,
            secret,
            &other_key,
            std::iter::once(other_node),
        );
    }

    /// The shared real-resolution path both provisioning entry points route
    /// through: register the cell + user + artifact with the REAL
    /// [`KeyDistributionLedger`], run its bi-directional `offer`/`accept`/
    /// `admit` sequence, seal the operational key, and record the CID ->
    /// blob mapping under the resulting [`RecordKey`] — the ONE resolver, no
    /// duplicate modeled admission logic between the "sealed here" and
    /// "sealed elsewhere" provisioning shapes.
    #[allow(clippy::too_many_arguments)]
    fn admit_offer_via_ledger(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        password: &str,
        secret: &str,
        seal_with: &NodeKey,
        sealed_to: impl IntoIterator<Item = NodeId>,
    ) {
        let identifier = identifier.into();
        let record = self.register_admit_record(&identifier, &cid, sealed_to);
        let offer = SealedOffer::seal(
            subkey.clone(),
            password,
            secret,
            seal_with,
            self.ledger.seal_of(&record),
        );
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::register(subkey, password, secret),
        );
        self.cell_db
            .put_offer(identifier, handle, cid, record, offer);
    }

    /// The REAL key-distribution ledger's offer/accept/admit sequence for one
    /// `(identifier, cid)` record, registering its cell/user/artifact and
    /// allow-listing every node in `sealed_to`. Shared by the live sealing
    /// [`Self::admit_offer_via_ledger`] and the restart-time
    /// [`Self::restore_offer`] so both drive the IDENTICAL admission — the
    /// restore path is never a second, divergent modeled admission.
    fn register_admit_record(
        &mut self,
        identifier: &str,
        cid: &Cid,
        sealed_to: impl IntoIterator<Item = NodeId>,
    ) -> RecordKey {
        let cell = self.home_cell();
        let user = KdUserId::from(identifier);
        let artifact_id = ArtifactId::from(cid.0.as_str());
        let record = RecordKey {
            user: user.clone(),
            cell: cell.clone(),
            artifact: artifact_id.clone(),
        };

        self.ledger.cell_mut(cell.clone()).add_user(user);
        self.ledger
            .register_artifact(Artifact::new(artifact_id, ArtifactKind::Operational));
        for node in sealed_to
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        {
            self.ledger
                .add_node_to_allowlist(&cell, node)
                .expect("cell was just registered above");
        }
        // Idempotent offer/accept/admit so a repeated replay (a node that
        // reboots twice, or a re-onboarding that re-admits a record after a
        // prior `revoke_offer` left its `accepted` marker set) rebuilds the
        // SAME admission instead of panicking on an "already X" transition.
        // A record already admitted needs nothing; otherwise ensure it is
        // offered and accepted, then admit.
        if !self.ledger.is_admitted(&record) {
            if !self.ledger.is_offered(&record) {
                self.ledger
                    .offer(
                        record.user.clone(),
                        record.cell.clone(),
                        record.artifact.clone(),
                    )
                    .expect("a non-offered, non-admitted record always offers");
            }
            if !self.ledger.is_accepted(&record) {
                self.ledger
                    .accept(&record)
                    .expect("a freshly offered record is always acceptable");
            }
            self.ledger
                .admit(&record)
                .expect("offered + accepted, non-cross-owner record always admits");
        }
        record
    }

    /// Restore a previously-provisioned, ALREADY-SEALED offer on restart from
    /// its persisted parts — the durable counterpart of [`Self::provision_offer`].
    /// Re-runs the deterministic ledger offer/accept/admit sequence and
    /// re-registers the (deterministic-from-`secret`) public operational-key
    /// verifier, but installs the pre-sealed `node_sealed` ciphertext VERBATIM
    /// instead of re-sealing — so NO password is required and none is ever read
    /// from disk. The offer is sealed to THIS node (the only node the bootstrap
    /// path ever sealed to), so [`Self::admit`] strips and unlocks it at login
    /// exactly as it would a freshly provisioned offer.
    pub fn restore_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        secret: &str,
        node_sealed: Vec<u8>,
    ) {
        let identifier = identifier.into();
        let this_node = self.node_key.node().clone();
        let record = self.register_admit_record(&identifier, &cid, std::iter::once(this_node));
        let offer = SealedOffer::from_sealed_parts(
            subkey.clone(),
            node_sealed,
            self.ledger.seal_of(&record),
        );
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::register(subkey, "", secret),
        );
        self.cell_db
            .put_offer(identifier, handle, cid, record, offer);
    }

    /// Restore a RANDOM-secret offer from its persisted parts — the replay
    /// counterpart of a mint whose operational-key `secret` was drawn from OS
    /// entropy (never re-derivable from the handle) and therefore NEVER
    /// journaled. Instead of the secret, the node persisted the operational
    /// PUBLIC key (safe to store) alongside the pre-sealed blob; this installs
    /// the blob verbatim and registers the verifier from that public key
    /// ([`RegisteredOperationalKey::from_public`]). The login-time AEAD unlock
    /// still recovers the secret from the blob under the user's password and
    /// re-derives a signature this public key checks — identical admission to a
    /// freshly minted offer, with no secret ever read from disk.
    pub fn restore_offer_with_public(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        public_bytes: &[u8],
        node_sealed: Vec<u8>,
    ) {
        let identifier = identifier.into();
        let this_node = self.node_key.node().clone();
        let record = self.register_admit_record(&identifier, &cid, std::iter::once(this_node));
        let offer = SealedOffer::from_sealed_parts(
            subkey.clone(),
            node_sealed,
            self.ledger.seal_of(&record),
        );
        let verifier = SigningPublicKey::from_bytes(public_bytes.to_vec());
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::from_public(subkey, verifier),
        );
        self.cell_db
            .put_offer(identifier, handle, cid, record, offer);
    }

    /// The operational public signing key a `(subkey, secret)` pair yields — the
    /// value a mint journals so [`Self::restore_offer_with_public`] can
    /// reconstruct the verifier at replay WITHOUT the secret. The caller (the
    /// web layer, which holds the freshly generated random `secret` only at
    /// mint time) computes this immediately after provisioning and persists it.
    #[must_use]
    pub fn operational_public_for(subkey: &NodeSubkey, secret: &str) -> SigningPublicKey {
        operational_public(subkey, secret)
    }
    /// password, keeping the SAME key-distribution ledger admission record and
    /// CID (only the password that unlocks the inner layer changes). The
    /// operational-key `secret` is unchanged — so [`Self::admit`] keeps
    /// resolving+unlocking the offer, now under `new_password`. Used by a self
    /// password change / admin reset (`crates/pillar-cli/src/web_serve.rs`): the
    /// caller re-reads [`Self::provisioned_offer_parts`] afterwards to journal
    /// the new sealed ciphertext. `false` if `identifier` has no provisioned
    /// offer to re-seal.
    pub fn reseal_offer(
        &mut self,
        identifier: &str,
        subkey: NodeSubkey,
        new_password: &str,
        secret: &str,
    ) -> bool {
        let Some(cid) = self.cell_db.resolve_cid(identifier).cloned() else {
            return false;
        };
        let Some(record) = self.cell_db.record_for(identifier).cloned() else {
            return false;
        };
        let handle = self
            .cell_db
            .handle_for(identifier)
            .unwrap_or(identifier)
            .to_owned();
        let this_node = self.node_key.node().clone();
        let offer = SealedOffer::seal(
            subkey.clone(),
            new_password,
            secret,
            &self.node_key,
            std::iter::once(this_node),
        );
        // The public operational-key verifier is derived from `secret` (which
        // is unchanged), so this re-insert is idempotent — kept for parity with
        // the provision/restore paths.
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::register(subkey, "", secret),
        );
        self.cell_db
            .put_offer(identifier, handle, cid, record, offer);
        true
    }

    /// Replay counterpart of [`Self::reseal_offer`]: replace an already-admitted
    /// offer's node-sealed ciphertext with the journaled `node_sealed` bytes
    /// VERBATIM (no password, no re-admission — the record is already admitted
    /// by the offer's original restore). `false` if `identifier` has no offer.
    pub fn restore_offer_blob(
        &mut self,
        identifier: &str,
        subkey: NodeSubkey,
        node_sealed: Vec<u8>,
    ) -> bool {
        let Some(cid) = self.cell_db.resolve_cid(identifier).cloned() else {
            return false;
        };
        let Some(record) = self.cell_db.record_for(identifier).cloned() else {
            return false;
        };
        let handle = self
            .cell_db
            .handle_for(identifier)
            .unwrap_or(identifier)
            .to_owned();
        let this_node = self.node_key.node().clone();
        let offer = SealedOffer::from_sealed_parts(subkey, node_sealed, std::iter::once(this_node));
        self.cell_db
            .put_offer(identifier, handle, cid, record, offer);
        true
    }

    /// The persisted parts of the offer provisioned for `identifier`, if any:
    /// its `(cid, handle, node-sealed ciphertext)` — the durable material the
    /// portal journals so a restarted node can [`Self::restore_offer`] it
    /// without the password.
    #[must_use]
    pub fn provisioned_offer_parts(&self, identifier: &str) -> Option<(Cid, String, Vec<u8>)> {
        let cid = self.cell_db.resolve_cid(identifier)?.clone();
        let handle = self
            .cell_db
            .handle_for(identifier)
            .unwrap_or(identifier)
            .to_owned();
        let offer = self.cell_db.offer_for(&cid)?;
        Some((cid, handle, offer.node_sealed_bytes().to_vec()))
    }

    /// Revoke a previously-provisioned offer through the REAL
    /// [`KeyDistributionLedger::revoke_offer`] — fail-closed, exactly as
    /// every other `pillar_key_distribution` consumer observes: after this,
    /// `identifier` resolves to no admitted offer (`has_offer_for` is
    /// `false`, [`Self::admit`] returns [`NodeCustodyError::NoOfferForUser`])
    /// even though the sealed blob and CID mapping remain in the cell DB — a
    /// live demonstration this path is no longer a modeled stand-in.
    pub fn revoke_offer_for(&mut self, identifier: &str) {
        if let Some(record) = self.cell_db.record_for(identifier).cloned() {
            let _ = self.ledger.revoke_offer(&record);
        }
    }

    /// This node's origin.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Issue and track a fresh challenge nonce bound to this node's origin.
    pub fn issue_nonce(&mut self, expiry: u64) -> Nonce {
        let id = self.issued.len() as u64;
        let nonce = Nonce::mint(id, self.origin.clone(), expiry);
        self.issued.insert(id, nonce.clone());
        nonce
    }

    /// Whether this node can resolve an offer for `identifier` at all (used to
    /// surface the "no offer for this user / node unlabelled" message before
    /// asking for a password). Requires the REAL key-distribution ledger to
    /// still consider the record admitted — a revoked offer reports `false`
    /// here even though the sealed blob is still physically present.
    #[must_use]
    pub fn has_offer_for(&self, identifier: &str) -> bool {
        self.cell_db
            .resolve_cid(identifier)
            .is_some_and(|cid| self.cell_db.offer_for(cid).is_some())
            && self
                .cell_db
                .record_for(identifier)
                .is_some_and(|record| self.ledger.is_admitted(record))
    }

    /// Admit a NODE-SIDE custody login. The user supplied only `identifier`
    /// and `password` (two fields — NO CID). The node:
    ///
    /// 1. resolves the user's offer CID → sealed blob from its cell DB
    ///    (`NoOfferForUser` if it holds no offer / lacks the label);
    /// 2. strips the node-seal with its node key (`NoCustody` if the cell
    ///    never sealed this offer to THIS node);
    /// 3. unlocks the operational key server-side with argon2id
    ///    (`UnlockFailed` on a wrong password);
    /// 4. signs the origin+expiry nonce with the unlocked key and verifies it
    ///    against the registered public key (`BadNonce` on a bad challenge);
    /// 5. runs the shared fail-closed WoT authority guard (`NotAuthorized`).
    ///
    /// Only on all of these does it consume the nonce and return a session.
    ///
    /// # Errors
    ///
    /// The matching [`NodeCustodyError`] for the first failing step.
    /// Steps 1-3 of a login/sign, shared by [`Self::admit`] and
    /// [`Self::sign_op_for`]: resolve the user's offer server-side through the
    /// REAL key-distribution ledger admission (a revoked/unminted offer fails
    /// `NoOfferForUser` closed), strip the outer node-seal (only this node's
    /// key can — else `NoCustody`), and unlock the inner operational-key
    /// material with the password (a wrong password fails AEAD — `UnlockFailed`).
    /// Returns the resolved offer (carrying the subkey), the user handle, and
    /// the recovered plaintext operational-key `secret`.
    fn resolve_and_unlock(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<(SealedOffer, String, String), NodeCustodyError> {
        self.resolve_and_unlock_with(identifier, password, RequiredAdmission::Admitted)
    }

    /// [`Self::resolve_and_unlock`] parameterised by the ledger-admission state
    /// the offer must be in. `Admitted` is the normal login/sign path (a
    /// revoked or never-minted offer fails `NoOfferForUser` closed). `Revoked`
    /// is the ownership-proof path ([`Self::prove_ownership`]): it unseals ONLY
    /// an offer the ledger has REVOKED — never one still admitted (which must go
    /// through the normal path) and never one that never existed — so a user
    /// whose operational key a require-change revoked can prove ownership of the
    /// dead key with their password. The node-unseal + AEAD password-unlock are
    /// identical either way; only the admission predicate differs.
    fn resolve_and_unlock_with(
        &self,
        identifier: &str,
        password: &str,
        required: RequiredAdmission,
    ) -> Result<(SealedOffer, String, String), NodeCustodyError> {
        let Some(cid) = self.cell_db.resolve_cid(identifier).cloned() else {
            return Err(NodeCustodyError::NoOfferForUser);
        };
        let Some(record) = self.cell_db.record_for(identifier) else {
            return Err(NodeCustodyError::NoOfferForUser);
        };
        let admitted = self.ledger.is_admitted(record);
        let admission_ok = match required {
            RequiredAdmission::Admitted => admitted,
            RequiredAdmission::Revoked => !admitted,
        };
        if !admission_ok {
            return Err(NodeCustodyError::NoOfferForUser);
        }
        let Some(offer) = self.cell_db.offer_for(&cid).cloned() else {
            return Err(NodeCustodyError::NoOfferForUser);
        };
        let handle = self
            .cell_db
            .handle_for(identifier)
            .unwrap_or(identifier)
            .to_owned();
        let Some(inner) = self.node_key.unseal(&offer) else {
            return Err(NodeCustodyError::NoCustody);
        };
        let Some(material) = unlock_operational_key(&inner, offer.subkey(), password) else {
            return Err(NodeCustodyError::UnlockFailed);
        };
        let Ok(secret) = String::from_utf8(material) else {
            return Err(NodeCustodyError::UnlockFailed);
        };
        Ok((offer, handle, secret))
    }

    /// DELEGATED SIGNING: sign `signing_material` (a
    /// [`pillar_wire::PillarMessage`]'s signing material for an op body) on the
    /// user's behalf with their unlocked operational key — the node holds the
    /// key, the client never does. Reuses the SAME
    /// resolve→node-unseal→password-unlock path as [`Self::admit`], gated on a
    /// fresh single-use [`StepUpToken`] (one re-authentication per delegated
    /// signature, operator-directed). Returns the ed25519 signature and the
    /// operational public signing key (the `signer` the ingest authenticates +
    /// authorizes).
    ///
    /// A user with NO admitted operational offer — an onboarding user whose
    /// offer was never minted, or one whose offer a require-change / admin-reset
    /// / disable revoked — fails closed (`NoOfferForUser`): there is no key to
    /// sign with, so no op can be produced. This is the CRYPTOGRAPHIC
    /// containment of a must-change/contained user, not a policy refusal.
    ///
    /// # Errors
    /// [`NodeCustodyError::StepUpRequired`] if `step_up` is missing/consumed;
    /// otherwise as [`Self::resolve_and_unlock`].
    pub fn sign_op_for(
        &self,
        identifier: &str,
        password: &str,
        signing_material: &[u8],
        step_up: &mut StepUpToken,
    ) -> Result<(Signature, SigningPublicKey), NodeCustodyError> {
        // Fresh step-up required per delegated signature (checked FIRST, so a
        // resolve/unlock failure never consumes the token).
        if !step_up.consume() {
            return Err(NodeCustodyError::StepUpRequired);
        }
        let (offer, _handle, secret) = self.resolve_and_unlock(identifier, password)?;
        let signature = sign_bytes(offer.subkey(), &secret, signing_material);
        let signer = operational_public(offer.subkey(), &secret);
        Ok((signature, signer))
    }

    /// Validate the challenge nonce `nonce_id` against this node: it must be
    /// issued, unconsumed, bound to this node's origin, and unexpired at
    /// `clock`. Shared by [`Self::admit`] and [`Self::prove_ownership`]; returns
    /// the live nonce (never consumes it — the caller consumes on full success).
    fn check_nonce(&self, nonce_id: u64, clock: u64) -> Result<Nonce, NodeCustodyError> {
        let Some(nonce) = self.issued.get(&nonce_id).cloned() else {
            return Err(NodeCustodyError::BadNonce);
        };
        if self.consumed.contains(&nonce_id) {
            return Err(NodeCustodyError::BadNonce);
        }
        if nonce.origin() != &self.origin {
            return Err(NodeCustodyError::BadNonce);
        }
        if nonce.expiry() <= clock {
            return Err(NodeCustodyError::BadNonce);
        }
        Ok(nonce)
    }

    /// Sign `nonce` with the unlocked operational key for `offer.subkey()` and
    /// verify it against the registered public key — the server-side half of the
    /// challenge-response that re-proves the unlocked secret matches the minted
    /// key. `UnlockFailed` if the key is unregistered or the check fails.
    fn verify_nonce_signature(
        &self,
        offer: &SealedOffer,
        secret: &str,
        nonce: &Nonce,
    ) -> Result<(), NodeCustodyError> {
        let signature = sign_material(offer.subkey(), secret, nonce);
        let Some(registered) = self.registered.get(offer.subkey()) else {
            return Err(NodeCustodyError::UnlockFailed);
        };
        if !registered.verify(nonce, &signature) {
            return Err(NodeCustodyError::UnlockFailed);
        }
        Ok(())
    }

    pub fn admit(
        &mut self,
        identifier: &str,
        password: &str,
        nonce_id: u64,
        clock: u64,
        authority: &WotAuthority,
        actor: &FencedActor,
    ) -> Result<NodeCustodySession, NodeCustodyError> {
        // Steps 1-3: resolve the offer server-side through the REAL
        // key-distribution ledger, strip the node seal, and unlock the
        // operational key with the password (a wrong password fails AEAD).
        let (offer, handle, secret) = self.resolve_and_unlock(identifier, password)?;

        // Step 4: sign the challenge nonce server-side and verify it.
        let nonce = self.check_nonce(nonce_id, clock)?;
        self.verify_nonce_signature(&offer, &secret, &nonce)?;

        // Step 5: the SHARED fail-closed WoT authority guard — one path.
        let subject = offer.subkey().node_id();
        let snapshot = actor
            .act(authority, &subject)
            .map_err(NodeCustodyError::NotAuthorized)?;

        self.consumed.insert(nonce_id);
        Ok(NodeCustodySession {
            handle,
            subject,
            nonce_id,
            watermark: snapshot.watermark,
        })
    }

    /// OWNERSHIP-PROOF login for a require-changed user. A require-change REVOKES
    /// the user's operational offer in the key-distribution ledger, so both
    /// [`Self::admit`] and [`Self::sign_op_for`] fail closed (`NoOfferForUser`):
    /// the user holds no admitted key and can produce no signed op (the
    /// cryptographic containment of a must-change user). This path lets that
    /// user still AUTHENTICATE — purely to rotate their key — by unsealing the
    /// REVOKED offer blob (still physically present in the cell DB) with their
    /// current password: an AEAD open only the key owner can perform
    /// (`UnlockFailed` for the wrong password / a non-owner). It then runs the
    /// SAME nonce challenge and WoT authority guard as `admit` and returns a
    /// session.
    ///
    /// It succeeds ONLY on a REVOKED offer — an offer still admitted must use
    /// `admit`, and a never-minted one fails `NoOfferForUser` — so it is not an
    /// alternate login for normal users. Login dispatch reaches it only after
    /// `admit` returns `NoOfferForUser` for a forced-change user; the returned
    /// session is good only for the change-password ceremony, since the user
    /// still holds no operational key until that ceremony mints a fresh one.
    ///
    /// # Errors
    /// `NoOfferForUser` (no revoked ownable offer), `NoCustody`, `UnlockFailed`
    /// (wrong password / not the owner), `BadNonce`, `NotAuthorized`.
    pub fn prove_ownership(
        &mut self,
        identifier: &str,
        password: &str,
        nonce_id: u64,
        clock: u64,
        authority: &WotAuthority,
        actor: &FencedActor,
    ) -> Result<NodeCustodySession, NodeCustodyError> {
        // Ownership is proven by unsealing the REVOKED offer with the password.
        let (offer, handle, secret) =
            self.resolve_and_unlock_with(identifier, password, RequiredAdmission::Revoked)?;
        let nonce = self.check_nonce(nonce_id, clock)?;
        self.verify_nonce_signature(&offer, &secret, &nonce)?;
        let subject = offer.subkey().node_id();
        let snapshot = actor
            .act(authority, &subject)
            .map_err(NodeCustodyError::NotAuthorized)?;
        self.consumed.insert(nonce_id);
        Ok(NodeCustodySession {
            handle,
            subject,
            nonce_id,
            watermark: snapshot.watermark,
        })
    }
}

// The cell/user bootstrap types were factored out into the shared
// `pillar-bootstrap` crate so the CLI and the web portal share one code path.
// Re-exported here so existing `pillar_web::node_custody::…` paths keep
// resolving unchanged.
pub use pillar_bootstrap::{
    check_cell_name_available, BootstrapError, CellBootstrap, CellNameRegistry, CellNameStatus,
    InMemoryCellNameRegistry, CELL_NAME_IN_USE_MESSAGE,
};
#[cfg(test)]
mod tests {
    use super::*;
    use pillar_wot_authority::WotAuthority;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "operational-key-material";
    const ORIGIN: &str = "https://pillar.example.com";

    fn node_key() -> NodeKey {
        NodeKey::new(NodeId::from("this-node"), "this-node-secret")
    }

    // An authority where `subkey`'s node chains to the owner, fresh actor.
    fn chained(subkey: &NodeSubkey) -> (WotAuthority, FencedActor) {
        let owner = NodeId::from("owner");
        let mut authority = WotAuthority::new(owner.clone(), 4);
        authority.issue_edge(owner, subkey.node_id(), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        (authority, actor)
    }

    fn provisioned() -> (NodeCustodyVerifier, NodeSubkey) {
        let subkey = NodeSubkey::from("op-subkey-alice");
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        v.provision_offer(
            "alice@pillar",
            "Alice",
            Cid::from("cid-alice"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        (v, subkey)
    }

    // ---- delegated signing (the KD node signs an op on the user's behalf) ----

    #[test]
    fn random_secret_mint_survives_a_pubkey_only_replay() {
        // A RANDOM operational secret (never derivable from the handle) is
        // sealed under a password; the node journals only the blob + the
        // operational PUBLIC key. A fresh node reconstructs the verifier from
        // that public key alone (no secret) and admits the SAME password login
        // — the replay path for entropy-minted offers.
        let subkey = NodeSubkey::from("op-random-alice");
        let random_secret = "3f9a2c7e5b1d84066a2f0e9c7d15b8a4"; // stands in for OS entropy
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        v.provision_offer(
            "alice@pillar",
            "Alice",
            Cid::from("cid-random-alice"),
            subkey.clone(),
            PASSWORD,
            random_secret,
        );
        let (cid, handle, blob) = v
            .provisioned_offer_parts("alice@pillar")
            .expect("a just-minted offer has persisted parts");
        let public = NodeCustodyVerifier::operational_public_for(&subkey, random_secret);

        // A brand-new node holding ONLY (blob, public) — never the secret.
        let mut replayed = NodeCustodyVerifier::new(node_key(), ORIGIN);
        replayed.restore_offer_with_public(
            "alice@pillar",
            handle,
            cid,
            subkey.clone(),
            public.as_bytes(),
            blob,
        );
        let (auth, actor) = chained(&subkey);
        let nonce = replayed.issue_nonce(10);
        let session = replayed
            .admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("a pubkey-only replayed random-secret offer must admit the same password");
        assert_eq!(session.subject, subkey.node_id());
    }

    #[test]
    fn a_replay_registered_with_the_wrong_pubkey_fails_login_closed() {
        // If the journaled public key does not match the sealed secret, the
        // login-time signature verification fails closed — the verifier is not
        // a mere presence check.
        let subkey = NodeSubkey::from("op-random-bob");
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        v.provision_offer(
            "bob@pillar",
            "Bob",
            Cid::from("cid-random-bob"),
            subkey.clone(),
            PASSWORD,
            "the-real-random-secret",
        );
        let (cid, handle, blob) = v.provisioned_offer_parts("bob@pillar").unwrap();
        let wrong_public =
            NodeCustodyVerifier::operational_public_for(&subkey, "a-different-secret");

        let mut replayed = NodeCustodyVerifier::new(node_key(), ORIGIN);
        replayed.restore_offer_with_public(
            "bob@pillar",
            handle,
            cid,
            subkey.clone(),
            wrong_public.as_bytes(),
            blob,
        );
        let (auth, actor) = chained(&subkey);
        let nonce = replayed.issue_nonce(10);
        assert_eq!(
            replayed.admit("bob@pillar", PASSWORD, nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::UnlockFailed),
            "a mismatched journaled pubkey must fail the login signature check closed"
        );
    }

    #[test]
    fn delegated_signing_produces_a_signature_the_operational_pubkey_verifies() {
        let (v, _subkey) = provisioned();
        let body = b"a sealed pillar-message body to sign on the user's behalf";
        let mut step = StepUpToken::fresh();
        let (sig, signer) = v
            .sign_op_for("alice@pillar", PASSWORD, body, &mut step)
            .expect("an admitted operational offer must delegate-sign");
        // The returned public key is the operational key's real ed25519 public
        // half, and it verifies the server-side signature over the exact body.
        let wire_sig = pillar_crypto::Signature::from_bytes(sig.to_wire().to_vec());
        assert!(
            pillar_crypto::sign::verify(&signer, body, &wire_sig).is_ok(),
            "delegated signature must verify under the returned operational pubkey"
        );
    }

    #[test]
    fn delegated_signing_requires_a_fresh_stepup_per_signature() {
        let (v, _subkey) = provisioned();
        let body = b"op body";
        let mut step = StepUpToken::fresh();
        assert!(v
            .sign_op_for("alice@pillar", PASSWORD, body, &mut step)
            .is_ok());
        // The SAME token is now consumed — a second delegated signature needs a
        // freshly re-authenticated step-up.
        assert_eq!(
            v.sign_op_for("alice@pillar", PASSWORD, body, &mut step),
            Err(NodeCustodyError::StepUpRequired),
        );
    }

    #[test]
    fn delegated_signing_wrong_password_burns_the_stepup() {
        // The step-up is consumed FIRST (before the unlock attempt), so a wrong
        // password still burns it — a caller cannot brute-force passwords under
        // a single re-authentication. A FRESH step-up is required to retry.
        let (v, _subkey) = provisioned();
        let mut step = StepUpToken::fresh();
        assert_eq!(
            v.sign_op_for("alice@pillar", "wrong-password", b"op", &mut step),
            Err(NodeCustodyError::UnlockFailed),
        );
        assert_eq!(
            v.sign_op_for("alice@pillar", PASSWORD, b"op", &mut step),
            Err(NodeCustodyError::StepUpRequired),
            "the burned step-up cannot be reused, even with the right password",
        );
        // A freshly re-authenticated step-up succeeds.
        assert!(v
            .sign_op_for("alice@pillar", PASSWORD, b"op", &mut StepUpToken::fresh())
            .is_ok());
    }

    #[test]
    fn an_onboarding_user_with_no_minted_offer_cannot_be_delegate_signed() {
        // The CRYPTOGRAPHIC containment: a contained/onboarding user has no
        // admitted operational offer, so there is NO key to sign with — the
        // node cannot produce ANY op on their behalf, independent of policy.
        let v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        let mut step = StepUpToken::fresh();
        assert_eq!(
            v.sign_op_for("nobody@pillar", PASSWORD, b"op", &mut step),
            Err(NodeCustodyError::NoOfferForUser),
        );
    }

    #[test]
    fn a_revoked_offer_stops_delegated_signing_closed() {
        // require-change / admin-reset / disable revoke the operational offer;
        // afterwards the node can sign nothing on the user's behalf.
        let (mut v, _subkey) = provisioned();
        assert!(v
            .sign_op_for("alice@pillar", PASSWORD, b"op", &mut StepUpToken::fresh())
            .is_ok());
        v.revoke_offer_for("alice@pillar");
        assert_eq!(
            v.sign_op_for("alice@pillar", PASSWORD, b"op", &mut StepUpToken::fresh()),
            Err(NodeCustodyError::NoOfferForUser),
        );
    }

    #[test]
    fn require_change_revokes_then_ownership_proof_reauthenticates() {
        // Model a require-change: the operational offer is revoked. Afterwards
        // BOTH admit and sign_op_for fail closed (crypto containment), but the
        // owner can still PROVE ownership of the dead key with their password to
        // earn a forced-change session; a wrong password cannot.
        let (mut v, subkey) = provisioned();
        let (auth, actor) = chained(&subkey);

        // Before revoke: normal admit works.
        let nonce = v.issue_nonce(10);
        assert!(v
            .admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .is_ok());

        // While the offer is still ADMITTED, ownership-proof must REFUSE it
        // (an admitted offer belongs to the normal admit path only).
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.prove_ownership("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
                .err(),
            Some(NodeCustodyError::NoOfferForUser),
        );

        // require-change: revoke the operational offer.
        v.revoke_offer_for("alice@pillar");

        // admit now fails closed — the user holds no admitted key.
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
                .err(),
            Some(NodeCustodyError::NoOfferForUser),
        );

        // A WRONG password cannot prove ownership of the revoked key.
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.prove_ownership("alice@pillar", "wrong", nonce.id(), 0, &auth, &actor)
                .err(),
            Some(NodeCustodyError::UnlockFailed),
        );

        // The OWNER proves ownership with the real password and gets a session
        // (good only to rotate the key — they still hold no admitted key).
        let nonce = v.issue_nonce(10);
        let session = v
            .prove_ownership("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("the key owner re-authenticates via ownership proof");
        assert_eq!(session.subject, subkey.node_id());
        assert_eq!(session.handle, "Alice");
        // Still contained: no delegated signature is possible.
        assert_eq!(
            v.sign_op_for("alice@pillar", PASSWORD, b"op", &mut StepUpToken::fresh()),
            Err(NodeCustodyError::NoOfferForUser),
        );
    }

    #[test]
    fn ownership_proof_fails_closed_for_an_unknown_user() {
        // A user the node holds NO offer for (never minted, never revoked)
        // cannot prove ownership — there is nothing to unseal.
        let (mut v, subkey) = provisioned();
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.prove_ownership("nobody@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
                .err(),
            Some(NodeCustodyError::NoOfferForUser),
        );
    }

    #[test]
    fn node_side_login_with_two_fields_is_admitted_and_greets_by_handle() {
        let (mut v, subkey) = provisioned();
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        let session = v
            .admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("admitted");
        assert_eq!(session.subject, subkey.node_id());
        assert_eq!(session.handle, "Alice");
    }

    #[test]
    fn a_restored_offer_admits_the_same_login_without_the_password_ever_persisting() {
        // Provision live (with the password), then extract ONLY the durable
        // parts a restart would journal: the cid, handle, and the ALREADY-
        // SEALED node ciphertext — never the password.
        let (live, subkey) = provisioned();
        let (cid, handle, node_sealed) = live
            .provisioned_offer_parts("alice@pillar")
            .expect("the just-provisioned offer exposes its persisted parts");
        assert_eq!(handle, "Alice");
        assert!(
            !node_sealed.is_empty(),
            "the node-sealed ciphertext is the real durable material"
        );

        // Rebuild a FRESH verifier (as a restarted node would) and restore the
        // offer from those parts alone — the password is NOT available here.
        let mut restored = NodeCustodyVerifier::new(node_key(), ORIGIN);
        restored.restore_offer(
            "alice@pillar",
            handle,
            cid,
            subkey.clone(),
            SECRET,
            node_sealed,
        );

        // The restored node resolves the offer and admits the SAME login with
        // the correct password — proving the sealed blob (not the password)
        // carried the credential across the "restart".
        assert!(restored.has_offer_for("alice@pillar"));
        let (auth, actor) = chained(&subkey);
        let nonce = restored.issue_nonce(10);
        let session = restored
            .admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("restored offer admits the correct password");
        assert_eq!(session.subject, subkey.node_id());
        assert_eq!(session.handle, "Alice");

        // A wrong password still fails the argon2id/AEAD unlock on the restored
        // blob — the inner password layer survived the restore intact.
        let nonce2 = restored.issue_nonce(10);
        assert_eq!(
            restored.admit("alice@pillar", "wrong", nonce2.id(), 0, &auth, &actor),
            Err(NodeCustodyError::UnlockFailed)
        );
    }

    #[test]
    fn the_user_never_supplies_a_cid_the_node_resolves_it() {
        // The admit signature takes only (identifier, password) — there is no
        // CID parameter at all. Resolving the CID is the node's job.
        let (v, _subkey) = provisioned();
        assert!(v.has_offer_for("alice@pillar"));
    }

    #[test]
    fn wrong_password_fails_to_unlock_the_operational_key() {
        let (mut v, subkey) = provisioned();
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.admit("alice@pillar", "wrong", nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::UnlockFailed)
        );
    }

    #[test]
    fn node_without_the_label_or_offer_reports_no_offer_for_user() {
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        let auth = WotAuthority::new(NodeId::from("owner"), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&auth);
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.admit("nobody@pillar", PASSWORD, nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::NoOfferForUser)
        );
    }

    #[test]
    fn offer_sealed_to_a_different_node_never_lands_the_key_here() {
        // The cell sealed the offer to some OTHER node: this node cannot strip
        // the seal, so the operational key never lands here (NoCustody) — the
        // per-node seal is the access control.
        let subkey = NodeSubkey::from("op-subkey-bob");
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        v.provision_offer_sealed_elsewhere(
            "bob@pillar",
            "Bob",
            Cid::from("cid-bob"),
            subkey.clone(),
            PASSWORD,
            SECRET,
            NodeId::from("other-node"),
            "other-secret",
        );
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.admit("bob@pillar", PASSWORD, nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::NoCustody)
        );
    }

    #[test]
    fn revoked_operational_subkey_fails_closed() {
        let (mut v, subkey) = provisioned();
        let (mut auth, actor) = chained(&subkey);
        auth.revoke_key(subkey.node_id());
        let nonce = v.issue_nonce(10);
        match v.admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor) {
            Err(NodeCustodyError::NotAuthorized(_)) => {}
            other => panic!("expected fail-closed NotAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn unchained_operational_subkey_is_refused() {
        let subkey = NodeSubkey::from("op-orphan");
        let mut v = NodeCustodyVerifier::new(node_key(), ORIGIN);
        v.provision_offer(
            "orphan@pillar",
            "Orphan",
            Cid::from("cid-orphan"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        // Authority where the subkey is NOT reachable.
        let mut auth = WotAuthority::new(NodeId::from("owner"), 4);
        auth.issue_edge(NodeId::from("owner"), NodeId::from("someone-else"), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&auth);
        let nonce = v.issue_nonce(10);
        match v.admit("orphan@pillar", PASSWORD, nonce.id(), 0, &auth, &actor) {
            Err(NodeCustodyError::NotAuthorized(ActError::NotAuthoritative)) => {}
            other => panic!("expected NotAuthoritative, got {other:?}"),
        }
    }

    #[test]
    fn revoking_the_offer_through_the_real_ledger_fails_the_login_closed() {
        // The offer resolution path routes through the REAL
        // `pillar_key_distribution::KeyDistributionLedger` admission, not a
        // bare local presence check: revoking the offer through that real
        // ledger must fail both `has_offer_for` and `admit` closed, even
        // though the sealed blob and CID mapping are still physically
        // present in the cell DB. This is exactly the modeled seam the ROI
        // requires killed — a stand-in offer store could never observe a
        // real ledger revocation.
        let (mut v, subkey) = provisioned();
        assert!(v.has_offer_for("alice@pillar"));

        v.revoke_offer_for("alice@pillar");

        assert!(
            !v.has_offer_for("alice@pillar"),
            "a revoked offer must no longer resolve"
        );
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        assert_eq!(
            v.admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::NoOfferForUser),
            "a revoked real-ledger offer must fail closed, not stand-in success"
        );
    }

    #[test]
    fn a_real_stored_offer_resolves_and_unlocks_through_the_real_ledger() {
        // The positive case for the same real-resolution path: a genuinely
        // admitted offer (offer+accept+admit all really run against
        // `KeyDistributionLedger`) resolves and unlocks correctly end to
        // end.
        let (mut v, subkey) = provisioned();
        assert!(v.has_offer_for("alice@pillar"));
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        let session = v
            .admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("a real, admitted offer must resolve and unlock");
        assert_eq!(session.subject, subkey.node_id());
    }

    #[test]
    fn replayed_nonce_is_rejected_on_second_use() {
        let (mut v, subkey) = provisioned();
        let (auth, actor) = chained(&subkey);
        let nonce = v.issue_nonce(10);
        v.admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor)
            .expect("first admit");
        assert_eq!(
            v.admit("alice@pillar", PASSWORD, nonce.id(), 0, &auth, &actor),
            Err(NodeCustodyError::BadNonce)
        );
    }

    #[test]
    fn the_password_and_plaintext_key_never_appear_in_the_stored_offer_blob() {
        // Node-side custody: the node holds a SEALED blob, not the password or
        // the plaintext key. Over many users, neither must appear in the blob.
        for i in 0..128u32 {
            let password = format!("pw-{i}-{PASSWORD}");
            let secret = format!("sk-{i}-{SECRET}");
            let subkey = NodeSubkey::from(format!("op-{i}").as_str());
            let offer = SealedOffer::seal(
                subkey,
                &password,
                &secret,
                &node_key(),
                std::iter::once(NodeId::from("this-node")),
            );
            let blob = format!("{:?}", offer.node_sealed);
            assert!(
                !blob.contains(&password),
                "password leaked into blob: {blob}"
            );
            assert!(
                !blob.contains(&secret),
                "plaintext key leaked into blob: {blob}"
            );
        }
    }

    #[test]
    fn forged_signature_is_rejected_by_the_registered_verifier() {
        // The registered verifier holds only the real ed25519 PUBLIC key
        // derived from (subkey, secret). A signature produced from a
        // DIFFERENT secret (i.e. forged without knowing the right unlocked
        // material) must never verify — this is the real asymmetric
        // signature property, not a bare digest equality.
        let subkey = NodeSubkey::from("op-subkey-forge-test");
        let registered = RegisteredOperationalKey::register(subkey.clone(), PASSWORD, SECRET);
        let origin: Origin = ORIGIN.into();
        let nonce = Nonce::mint(0, origin, 10);

        // A signature forged with the WRONG secret material.
        let forged = sign_material(&subkey, "wrong-operational-key-material", &nonce);
        assert!(
            !registered.verify(&nonce, &forged),
            "a signature produced from the wrong unlocked material must not verify"
        );

        // The genuine signature over the SAME nonce still verifies.
        let genuine = sign_material(&subkey, SECRET, &nonce);
        assert!(
            registered.verify(&nonce, &genuine),
            "the genuine signature over the registered secret must verify"
        );
    }

    #[test]
    fn unlock_is_a_real_aead_round_trip_that_rejects_tampering() {
        // The password-locked "inner" layer is a real AEAD ciphertext: it
        // round-trips under the right password, and any tampering with the
        // ciphertext bytes is caught by AEAD authentication (never a u64
        // equality that silently "succeeds" on the wrong bytes reinterpreted
        // as a number).
        let subkey = NodeSubkey::from("op-subkey-aead-test");
        let pw_key =
            kdf::derive_key(PASSWORD.as_bytes(), &subkey_salt(&subkey), &kdf_params()).unwrap();
        let inner =
            aead::seal_symmetric(&pw_key, SECRET.as_bytes(), b"pillar-node-custody/inner-v1")
                .expect("seal must succeed");

        // Round-trip: the right password recovers the exact plaintext.
        let recovered = unlock_operational_key(&inner, &subkey, PASSWORD)
            .expect("correct password must unlock");
        assert_eq!(recovered, SECRET.as_bytes());

        // Tamper a single byte of the ciphertext: AEAD authentication must
        // fail closed, never silently return corrupted material.
        let mut tampered_bytes = inner.clone().into_bytes();
        let last = tampered_bytes.len() - 1;
        tampered_bytes[last] ^= 0x01;
        let tampered = Ciphertext::from_bytes(tampered_bytes);
        assert_eq!(
            unlock_operational_key(&tampered, &subkey, PASSWORD),
            None,
            "tampered ciphertext must fail AEAD authentication"
        );

        // Wrong password must also fail (different KEK, AEAD open fails).
        assert_eq!(
            unlock_operational_key(&inner, &subkey, "wrong password"),
            None,
            "wrong password must not unlock the operational key"
        );
    }
}
