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
}

/// The cell DB view a node needs to resolve node-side custody logins: it maps
/// a user IDENTIFIER (`user@domain` / `username` / genesis CID) to the CID of
/// that user's key-offer blob, and each CID to the node-sealed [`SealedOffer`]
/// blob. This is the "CID → sealed blob" resolution the ROI requires the node
/// to do so the USER never supplies the CID.
#[derive(Clone, Debug, Default)]
pub struct NodeCellDb {
    /// user identifier -> the CID of that user's key offer.
    identifier_to_cid: HashMap<String, Cid>,
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
    /// by `handle`.
    pub fn put_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        offer: SealedOffer,
    ) {
        let identifier = identifier.into();
        self.identifier_to_cid
            .insert(identifier.clone(), cid.clone());
        self.handles.insert(identifier, handle.into());
        self.offers.insert(cid, offer);
    }

    /// Resolve a user identifier to its CID (the node-side lookup the user
    /// never has to do).
    #[must_use]
    pub fn resolve_cid(&self, identifier: &str) -> Option<&Cid> {
        self.identifier_to_cid.get(identifier)
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
    let seed = subkey_seed(subkey, secret);
    let (_public, secret_key) =
        sign::signing_keypair_from_seed(&seed).expect("ed25519 keygen from valid seed never fails");
    let sig = sign::sign(&secret_key, &nonce.signing_material_public())
        .expect("ed25519 signing over valid input never fails");
    Signature::from_wire(sig.into_bytes())
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
}

impl NodeCustodyVerifier {
    /// A verifier for a node holding `node_key`, serving the origin `origin`,
    /// with an empty cell DB.
    #[must_use]
    pub fn new(node_key: NodeKey, origin: impl Into<Origin>) -> Self {
        NodeCustodyVerifier {
            node_key,
            cell_db: NodeCellDb::new(),
            registered: HashMap::new(),
            issued: HashMap::new(),
            consumed: std::collections::HashSet::new(),
            origin: origin.into(),
        }
    }

    /// Give this node an offer to custody: record it in the cell DB under
    /// `identifier`/`cid` and register the operational key's public
    /// verifier. The plaintext `secret` is NEVER retained server-side — the
    /// real AEAD unlock recovers it from the sealed offer at login time. In a
    /// real node the label + offer arrive via `pillar_key_distribution`; this
    /// is the login path's view of that state.
    pub fn provision_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: NodeSubkey,
        password: &str,
        secret: &str,
    ) {
        let offer = SealedOffer::seal(
            subkey.clone(),
            password,
            secret,
            &self.node_key,
            std::iter::once(self.node_key.node().clone()),
        );
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::register(subkey, password, secret),
        );
        self.cell_db.put_offer(identifier, handle, cid, offer);
    }

    /// Provision an offer whose blob is sealed to a DIFFERENT node than this
    /// one (so this node cannot strip it) — used to model the `NoCustody`
    /// path where the cell sealed the key to some other node.
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
        let offer = SealedOffer::seal(
            subkey.clone(),
            password,
            secret,
            &other_key,
            std::iter::once(other_node),
        );
        self.registered.insert(
            subkey.clone(),
            RegisteredOperationalKey::register(subkey, password, secret),
        );
        self.cell_db.put_offer(identifier, handle, cid, offer);
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
    /// asking for a password).
    #[must_use]
    pub fn has_offer_for(&self, identifier: &str) -> bool {
        self.cell_db
            .resolve_cid(identifier)
            .is_some_and(|cid| self.cell_db.offer_for(cid).is_some())
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
    pub fn admit(
        &mut self,
        identifier: &str,
        password: &str,
        nonce_id: u64,
        clock: u64,
        authority: &WotAuthority,
        actor: &FencedActor,
    ) -> Result<NodeCustodySession, NodeCustodyError> {
        // Step 1: resolve the offer server-side (the user never gave a CID).
        let Some(cid) = self.cell_db.resolve_cid(identifier).cloned() else {
            return Err(NodeCustodyError::NoOfferForUser);
        };
        let Some(offer) = self.cell_db.offer_for(&cid).cloned() else {
            return Err(NodeCustodyError::NoOfferForUser);
        };
        let handle = self
            .cell_db
            .handle_for(identifier)
            .unwrap_or(identifier)
            .to_owned();

        // Step 2: strip the node seal — only if the cell sealed to this node
        // (a real AEAD open; an unsealed/foreign node fails authentication).
        let Some(inner) = self.node_key.unseal(&offer) else {
            return Err(NodeCustodyError::NoCustody);
        };

        // Step 3: unlock the operational key server-side — a real argon2id
        // KEK + AEAD open; a wrong password fails AEAD authentication.
        let Some(material) = unlock_operational_key(&inner, offer.subkey(), password) else {
            return Err(NodeCustodyError::UnlockFailed);
        };
        let Ok(secret) = String::from_utf8(material) else {
            return Err(NodeCustodyError::UnlockFailed);
        };

        // Step 4: sign the challenge nonce server-side and verify it.
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
        let signature = sign_material(offer.subkey(), &secret, &nonce);
        let Some(registered) = self.registered.get(offer.subkey()) else {
            return Err(NodeCustodyError::UnlockFailed);
        };
        if !registered.verify(&nonce, &signature) {
            return Err(NodeCustodyError::UnlockFailed);
        }

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
