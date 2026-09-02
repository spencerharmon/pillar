//! Capability-scoped controller subkeys and PGP-encrypted controller
//! secrets — ROI P1 method #3.
//!
//! # Model
//!
//! A *controller* is a service a node may run (e.g. a coordination
//! controller, a stream ingester). Where [`crate::Registry`] answers "is
//! this node admitted at all?", this module answers two narrower questions
//! at the *authority boundary* a controller enforces on its own actions:
//!
//! 1. **Never ambient authority.** A [`ControllerSubkey`] carries no
//!    authority merely by being admitted — it must be an explicit,
//!    minted [`Grant`] naming exactly the [`Capability`] set the controller
//!    permits. [`CapabilityRegistry::authorize`] is the sole gate: an
//!    admitted-but-ungranted (or granted-a-different-capability) subkey is
//!    refused just as surely as an unadmitted one ([`ScopeError::OutOfScope`]
//!    / [`ScopeError::NotAdmitted`]).
//! 2. **Controller secrets are readable only by nodes running that
//!    controller.** [`EncryptedSecret`] is a real X25519-sealed envelope
//!    (via [`pillar_crypto::seal`]) addressed to an explicit recipient set.
//!    Each recipient is a node's PUBLISHED public sealing key
//!    ([`NodeSealingKey::public`], looked up in a [`NodeSealingDirectory`]);
//!    the matching SECRET seed is held only by that node
//!    ([`NodeSealingKey`]) and is genuine secret material — it is NEVER
//!    derived from the node's (public) [`NodeId`], so no other party can
//!    reconstruct it from public information.
//!    [`EncryptedSecret::decrypt`] recovers the plaintext only for the holder
//!    of a recipient's secret seed (an authentic Diffie-Hellman unseal, not a
//!    set membership check on the plaintext ID); any other node — including
//!    one that is otherwise fully admitted — learns nothing and gets
//!    [`DecryptError::NotARecipient`].

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;
use pillar_crypto::seal::{seal_to_recipients, sealing_keypair_from_seed, unseal};
use pillar_crypto::{SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed};

use crate::{AdmissionError, NodeSubkey, Registry};

/// A node's sealing identity: a real X25519 keypair whose SECRET half is held
/// ONLY by the node.
///
/// The secret seed is genuine secret material. It is **never** derived from the
/// node's (public) [`NodeId`], so no other party — even one that knows the
/// node's id and its published [`public`](Self::public) key — can reconstruct
/// it. In production the seed is the node's custody-held secret (see the node
/// custody backends); [`generate`](Self::generate) mints a fresh random seed
/// for a node that has none yet, and [`from_secret_seed`](Self::from_secret_seed)
/// rebuilds the identity from an already-held seed (e.g. loaded from custody).
#[derive(Clone)]
pub struct NodeSealingKey {
    /// Secret seed material — held only by the node, never published, never
    /// derived from the public [`NodeId`].
    secret_seed: Seed,
    /// The public sealing key derived from `secret_seed`; safe to publish.
    public: SealingPublicKey,
}

impl NodeSealingKey {
    /// Build a node sealing identity from real secret seed material (e.g. the
    /// node's custody-held secret).
    ///
    /// # Errors
    ///
    /// Propagates [`pillar_crypto::CryptoError`] if `secret_seed` cannot yield
    /// a sealing keypair.
    pub fn from_secret_seed(secret_seed: Seed) -> pillar_crypto::Result<Self> {
        let (public, _secret) = sealing_keypair_from_seed(&secret_seed)?;
        Ok(Self {
            secret_seed,
            public,
        })
    }

    /// Mint a fresh node sealing identity from cryptographically-random secret
    /// seed material (32 bytes from the OS CSPRNG).
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_secret_seed(Seed::from_bytes(bytes.to_vec()))
            .expect("a random 32-byte seed always yields a sealing keypair")
    }

    /// This node's PUBLIC sealing key — safe to publish; senders seal to it.
    #[must_use]
    pub fn public(&self) -> &SealingPublicKey {
        &self.public
    }

    /// The node's SECRET sealing key, recomputed from the held secret seed.
    fn secret(&self) -> pillar_crypto::Result<SealingSecretKey> {
        let (_public, secret) = sealing_keypair_from_seed(&self.secret_seed)?;
        Ok(secret)
    }
}

/// A directory of nodes' PUBLISHED public sealing keys, keyed by [`NodeId`].
///
/// A node publishes its [`NodeSealingKey::public`] here; a sender seals a
/// controller secret to a set of node ids by looking their public keys up. The
/// directory holds ONLY public keys — never secret material — so it is safe to
/// replicate. A node id with no published key cannot be sealed to: there is no
/// key to seal to, and none may be fabricated from the id.
#[derive(Clone, Debug, Default)]
pub struct NodeSealingDirectory {
    published: HashMap<NodeId, SealingPublicKey>,
}

impl NodeSealingDirectory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        NodeSealingDirectory::default()
    }

    /// Publish `node`'s public sealing key (taken from its [`NodeSealingKey`]).
    pub fn publish(&mut self, node: NodeId, key: &NodeSealingKey) {
        self.published.insert(node, key.public().clone());
    }

    /// The published public sealing key for `node`, if any.
    #[must_use]
    pub fn public_key(&self, node: &NodeId) -> Option<&SealingPublicKey> {
        self.published.get(node)
    }
}

/// One specific, named action a controller subkey may be granted to perform.
///
/// Capabilities are opaque strings from this module's point of view — the
/// controller defines its own vocabulary (e.g. `"stream:append"`,
/// `"coordination:grant-epoch"`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability(pub String);

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_owned())
    }
}

/// Why an action was refused at the controller's authority boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeError {
    /// The presented subkey is not admitted at all — propagated from
    /// [`crate::Registry::verify`]. A subkey with no verified admission
    /// chain can carry no capability, scoped or otherwise.
    NotAdmitted(AdmissionError),
    /// The subkey is admitted, but was never granted the requested
    /// capability — the out-of-scope-action-refused case. Bare admission
    /// confers no capability (never ambient authority).
    OutOfScope {
        /// The capability the action required but was not granted.
        action: Capability,
    },
}

/// Tracks which [`Capability`] set each admitted subkey has been explicitly
/// granted, layered on top of an identity [`Registry`].
///
/// A subkey with no entry here has *no* capabilities: granting is additive
/// and explicit ([`grant`](Self::grant)), never implied by admission.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    /// subkey -> the capability set explicitly minted for it
    grants: HashMap<NodeSubkey, HashSet<Capability>>,
}

impl CapabilityRegistry {
    /// An empty registry: no subkey has been granted anything.
    #[must_use]
    pub fn new() -> Self {
        CapabilityRegistry::default()
    }

    /// Explicitly grant `capability` to `subkey` (additive; idempotent).
    ///
    /// Granting does not itself admit the subkey — [`authorize`](Self::authorize)
    /// still requires the identity [`Registry`] to admit it independently.
    pub fn grant(&mut self, subkey: NodeSubkey, capability: Capability) {
        self.grants.entry(subkey).or_default().insert(capability);
    }

    /// Whether `subkey` currently holds `capability`.
    #[must_use]
    pub fn has(&self, subkey: &NodeSubkey, capability: &Capability) -> bool {
        self.grants
            .get(subkey)
            .is_some_and(|caps| caps.contains(capability))
    }

    /// Authorize `subkey` to perform `action` against `identity` — the sole
    /// gate at a controller's authority boundary.
    ///
    /// Succeeds **iff** `identity` admits the subkey (a genuine signature
    /// chaining to a registered primary) *and* this registry has explicitly
    /// granted it `action`. Either condition failing alone refuses the
    /// action: an admitted subkey with no matching grant is
    /// [`ScopeError::OutOfScope`] (out-of-scope action refused, never
    /// ambient authority), and an unadmitted subkey is
    /// [`ScopeError::NotAdmitted`] regardless of any grant on record.
    ///
    /// # Errors
    ///
    /// See [`ScopeError`].
    pub fn authorize(
        &self,
        identity: &Registry,
        subkey: &NodeSubkey,
        action: &Capability,
    ) -> Result<NodeId, ScopeError> {
        let node = identity.verify(subkey).map_err(ScopeError::NotAdmitted)?;
        if self.has(subkey, action) {
            Ok(node)
        } else {
            Err(ScopeError::OutOfScope {
                action: action.clone(),
            })
        }
    }
}

/// Why a decryption attempt failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// `node` is not among the recipients this secret was sealed to — the
    /// X25519 unseal genuinely fails (no shared secret recovers the wrapped
    /// content key), not merely a set-membership check on an ID.
    NotARecipient,
    /// The envelope was corrupt or the recovered plaintext was not valid
    /// UTF-8 (should not occur for a genuinely-sealed secret).
    Malformed,
}

/// Why a seal attempt failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// A named recipient has no published sealing key in the directory, so
    /// there is nothing to seal to (and no key may be fabricated from its id).
    UnknownRecipient(NodeId),
    /// No recipients were supplied.
    NoRecipients,
}

/// A controller secret sealed (X25519 + AEAD, via [`pillar_crypto::seal`]) to
/// an explicit recipient set: the nodes running the controller that owns it.
///
/// Each recipient is a node's PUBLISHED public sealing key (resolved from a
/// [`NodeSealingDirectory`]); the envelope carries no plaintext and can only be
/// opened by a holder of one of those recipients' secret seeds
/// ([`NodeSealingKey`]).
#[derive(Clone, Debug)]
pub struct EncryptedSecret {
    envelope: SealedEnvelope,
}

impl EncryptedSecret {
    /// Seal `payload` so only the named `recipients` — resolved to their
    /// PUBLISHED public sealing keys in `directory` — can ever decrypt it.
    ///
    /// # Errors
    ///
    /// [`SealError::UnknownRecipient`] if a recipient has not published a
    /// sealing key; [`SealError::NoRecipients`] if `recipients` is empty.
    pub fn seal<'a>(
        payload: impl AsRef<str>,
        recipients: impl IntoIterator<Item = &'a NodeId>,
        directory: &NodeSealingDirectory,
    ) -> Result<Self, SealError> {
        let mut recipient_keys = Vec::new();
        for node in recipients {
            let key = directory
                .public_key(node)
                .ok_or_else(|| SealError::UnknownRecipient(node.clone()))?;
            recipient_keys.push(key.clone());
        }
        if recipient_keys.is_empty() {
            return Err(SealError::NoRecipients);
        }
        let envelope = seal_to_recipients(payload.as_ref().as_bytes(), &recipient_keys)
            .expect("sealing to a non-empty recipient set always succeeds");
        Ok(EncryptedSecret { envelope })
    }

    /// Attempt to decrypt as the holder of `node_key`'s SECRET seed.
    ///
    /// Succeeds only when `node_key` is one of the sealed recipients — i.e. it
    /// is a node running the controller this secret belongs to. Any other node,
    /// foreign to that controller, is refused even if it is otherwise fully
    /// admitted by the identity registry: readability is enforced by a genuine
    /// X25519 Diffie-Hellman unseal, and the required secret seed cannot be
    /// reconstructed from any public information.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NotARecipient`] when `node_key` was not among
    /// the sealed recipients, or [`DecryptError::Malformed`] if the envelope is
    /// corrupt or the recovered plaintext is not valid UTF-8.
    pub fn decrypt(&self, node_key: &NodeSealingKey) -> Result<String, DecryptError> {
        let secret = node_key.secret().map_err(|_| DecryptError::Malformed)?;
        let plaintext = unseal(&self.envelope, &secret).map_err(|_| DecryptError::NotARecipient)?;
        String::from_utf8(plaintext).map_err(|_| DecryptError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrimaryKeypair;

    fn keypair(label: &str) -> PrimaryKeypair {
        PrimaryKeypair::from_secret_seed(&Seed::from_bytes(
            format!("pillar-identity-cap-test-primary::{label}").into_bytes(),
        ))
    }

    fn subkey(s: &str) -> NodeSubkey {
        NodeSubkey::from(s)
    }

    fn admitted_registry() -> (Registry, NodeSubkey, NodeSubkey) {
        // Two nodes, both admitted under the same registered primary: one
        // runs the controller (and will be granted its capability / sealed
        // its secret), the other is a foreign, equally-admitted node.
        let mut reg = Registry::new();
        let alice = keypair("alice-primary");
        let controller_node = subkey("controller-node");
        let foreign_node = subkey("foreign-node");

        reg.register(alice.primary());
        assert!(reg.issue_subkey(alice.certify(&controller_node)));
        assert!(reg.issue_subkey(alice.certify(&foreign_node)));
        reg.handshake(&controller_node).unwrap();
        reg.handshake(&foreign_node).unwrap();

        (reg, controller_node, foreign_node)
    }

    #[test]
    fn granted_in_scope_action_is_authorized() {
        let (identity, controller_node, _foreign_node) = admitted_registry();
        let action = Capability::from("stream:append");

        let mut caps = CapabilityRegistry::new();
        caps.grant(controller_node.clone(), action.clone());

        assert_eq!(
            caps.authorize(&identity, &controller_node, &action),
            Ok(controller_node.node_id())
        );
    }

    #[test]
    fn out_of_scope_action_is_refused() {
        // An admitted subkey granted ONE capability must not be able to
        // perform a DIFFERENT, ungranted one: bare admission (or even a
        // narrower grant) never confers ambient authority over an
        // out-of-scope action.
        let (identity, controller_node, _foreign_node) = admitted_registry();
        let granted = Capability::from("stream:append");
        let out_of_scope = Capability::from("stream:delete-all");

        let mut caps = CapabilityRegistry::new();
        caps.grant(controller_node.clone(), granted);

        assert_eq!(
            caps.authorize(&identity, &controller_node, &out_of_scope),
            Err(ScopeError::OutOfScope {
                action: out_of_scope
            })
        );
    }

    #[test]
    fn ungranted_admitted_subkey_has_no_ambient_authority() {
        // Fully admitted, but never granted anything: still refused.
        let (identity, controller_node, _foreign_node) = admitted_registry();
        let action = Capability::from("coordination:grant-epoch");
        let caps = CapabilityRegistry::new();

        assert_eq!(
            caps.authorize(&identity, &controller_node, &action),
            Err(ScopeError::OutOfScope { action })
        );
    }

    #[test]
    fn unadmitted_subkey_is_refused_regardless_of_grant() {
        let identity = Registry::new();
        let unadmitted = subkey("never-admitted");
        let action = Capability::from("stream:append");

        let mut caps = CapabilityRegistry::new();
        caps.grant(unadmitted.clone(), action.clone());

        assert_eq!(
            caps.authorize(&identity, &unadmitted, &action),
            Err(ScopeError::NotAdmitted(AdmissionError::Unchained))
        );
    }

    #[test]
    fn controller_node_can_decrypt_its_own_secret() {
        let (_identity, controller_node, _foreign_node) = admitted_registry();
        let controller_id = controller_node.node_id();
        let controller_key = NodeSealingKey::generate();
        let mut dir = NodeSealingDirectory::new();
        dir.publish(controller_id.clone(), &controller_key);

        let secret = EncryptedSecret::seal("db-password", [&controller_id], &dir).unwrap();

        assert_eq!(
            secret.decrypt(&controller_key),
            Ok("db-password".to_string())
        );
    }

    #[test]
    fn foreign_node_cannot_decrypt() {
        // A node that is fully admitted to the cluster, but is NOT running
        // the controller the secret belongs to (not in the sealed recipient
        // set), must be refused decryption. It holds its OWN secret seed, not
        // the controller's.
        let (_identity, controller_node, foreign_node) = admitted_registry();
        let controller_id = controller_node.node_id();
        let foreign_id = foreign_node.node_id();
        let controller_key = NodeSealingKey::generate();
        let foreign_key = NodeSealingKey::generate();
        let mut dir = NodeSealingDirectory::new();
        dir.publish(controller_id.clone(), &controller_key);
        dir.publish(foreign_id, &foreign_key);

        let secret = EncryptedSecret::seal("db-password", [&controller_id], &dir).unwrap();

        assert_eq!(
            secret.decrypt(&foreign_key),
            Err(DecryptError::NotARecipient)
        );
    }

    #[test]
    fn sealing_key_is_not_derivable_from_the_public_node_id() {
        // Regression against the placeholder that seeded a node's sealing
        // keypair from `format!("...node/{}", node.0)` — i.e. from the node's
        // PUBLIC id — so ANYONE who knew the (public) id could reconstruct the
        // secret key and decrypt. Prove the real scheme defeats exactly that
        // attack: an adversary who knows the node's public id (and even its
        // published public key) cannot recover the plaintext.
        let (_identity, controller_node, _foreign_node) = admitted_registry();
        let controller_id = controller_node.node_id();
        let controller_key = NodeSealingKey::generate();
        let mut dir = NodeSealingDirectory::new();
        dir.publish(controller_id.clone(), &controller_key);

        let secret = EncryptedSecret::seal("db-password", [&controller_id], &dir).unwrap();

        // The legitimate holder decrypts.
        assert_eq!(
            secret.decrypt(&controller_key),
            Ok("db-password".to_string())
        );

        // The adversary recomputes the OLD public-id-derived seed verbatim and
        // builds a sealing key from it — the exact placeholder key. It is NOT
        // the node's real secret, so the unseal fails closed.
        let forged_seed = Seed::from_bytes(
            format!("pillar-controller-secret/node/{}", controller_id.0).into_bytes(),
        );
        let forged_key = NodeSealingKey::from_secret_seed(forged_seed).unwrap();
        assert_eq!(
            secret.decrypt(&forged_key),
            Err(DecryptError::NotARecipient)
        );

        // And the real published public key is unrelated to the placeholder's:
        // the node's identity carries no dependence on the public-id-derived
        // keypair at all.
        let placeholder_seed = Seed::from_bytes(
            format!("pillar-controller-secret/node/{}", controller_id.0).into_bytes(),
        );
        let placeholder = NodeSealingKey::from_secret_seed(placeholder_seed).unwrap();
        assert_ne!(controller_key.public(), placeholder.public());
    }

    #[test]
    fn sealing_to_an_unpublished_recipient_is_refused() {
        // A recipient with no published sealing key cannot be sealed to — no
        // key may be fabricated from its id.
        let (_identity, controller_node, _foreign_node) = admitted_registry();
        let controller_id = controller_node.node_id();
        let dir = NodeSealingDirectory::new();

        assert_eq!(
            EncryptedSecret::seal("db-password", [&controller_id], &dir).unwrap_err(),
            SealError::UnknownRecipient(controller_id)
        );
    }
}
