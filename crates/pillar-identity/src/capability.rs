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
//!    controller.** [`EncryptedSecret`] models a PGP-encrypted payload sealed
//!    to an explicit recipient set (the stand-in for "encrypted to these
//!    nodes' subkeys"). [`EncryptedSecret::decrypt`] succeeds only for a
//!    node in that set; any other node — including one that is otherwise
//!    fully admitted — cannot decrypt it.
//!
//! As with the rest of this crate, no real key material or crypto library is
//! involved: [`EncryptedSecret`] stands in for a verified PGP recipient list
//! so the *authorization policy* is auditable in isolation from the crypto
//! that will later produce the actual ciphertext.

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;

use crate::{AdmissionError, NodeSubkey, Registry};

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
    /// `node` is not among the recipients this secret was sealed to.
    NotARecipient,
}

/// A controller secret PGP-encrypted to an explicit recipient set: the
/// nodes running the controller that owns it.
///
/// Stands in for a real OpenPGP message encrypted to those nodes' public
/// subkeys — no key material or ciphertext format is modelled, only the
/// recipient-gated read policy the real encryption would enforce.
#[derive(Clone, Debug)]
pub struct EncryptedSecret {
    payload: String,
    recipients: HashSet<NodeId>,
}

impl EncryptedSecret {
    /// Seal `payload` so only `recipients` can ever decrypt it.
    pub fn seal(payload: impl Into<String>, recipients: impl IntoIterator<Item = NodeId>) -> Self {
        EncryptedSecret {
            payload: payload.into(),
            recipients: recipients.into_iter().collect(),
        }
    }

    /// Attempt to decrypt as `node`.
    ///
    /// Succeeds only when `node` is in the sealed recipient set — i.e. it is
    /// a node running the controller this secret belongs to. Any other node,
    /// foreign to that controller, is refused even if it is otherwise fully
    /// admitted by the identity registry: controller-secret readability is
    /// scoped independently of general cluster admission.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NotARecipient`] when `node` was not among the
    /// sealed recipients.
    pub fn decrypt(&self, node: &NodeId) -> Result<&str, DecryptError> {
        if self.recipients.contains(node) {
            Ok(&self.payload)
        } else {
            Err(DecryptError::NotARecipient)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signature;

    fn primary(s: &str) -> crate::UserPrimary {
        crate::UserPrimary::from(s)
    }

    fn subkey(s: &str) -> NodeSubkey {
        NodeSubkey::from(s)
    }

    fn admitted_registry() -> (Registry, NodeSubkey, NodeSubkey) {
        // Two nodes, both admitted under the same registered primary: one
        // runs the controller (and will be granted its capability / sealed
        // its secret), the other is a foreign, equally-admitted node.
        let mut reg = Registry::new();
        let alice = primary("alice-primary");
        let controller_node = subkey("controller-node");
        let foreign_node = subkey("foreign-node");

        reg.register(alice.clone());
        reg.issue_subkey(Signature::new(controller_node.clone(), alice.clone()));
        reg.issue_subkey(Signature::new(foreign_node.clone(), alice));
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
        let secret = EncryptedSecret::seal("db-password", [controller_node.node_id()]);

        assert_eq!(secret.decrypt(&controller_node.node_id()), Ok("db-password"));
    }

    #[test]
    fn foreign_node_cannot_decrypt() {
        // A node that is fully admitted to the cluster, but is NOT running
        // the controller the secret belongs to (not in the sealed recipient
        // set), must be refused decryption.
        let (_identity, controller_node, foreign_node) = admitted_registry();
        let secret = EncryptedSecret::seal("db-password", [controller_node.node_id()]);

        assert_eq!(
            secret.decrypt(&foreign_node.node_id()),
            Err(DecryptError::NotARecipient)
        );
    }
}
