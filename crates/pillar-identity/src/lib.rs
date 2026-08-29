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
//! Like the rest of the modelled core, this crate carries no key material and
//! touches neither the network nor the filesystem: [`Signature`] stands in for
//! a verified OpenPGP certification so the admission *policy* — the part the
//! spec constrains — is auditable in isolation from the crypto library that
//! will later produce/verify the actual packets.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod capability;
pub mod login;

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;

/// The fingerprint of a user's OpenPGP **primary** key — the root of a
/// Pillar user identity. Registering one authorizes it to admit nodes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserPrimary(pub String);

impl From<&str> for UserPrimary {
    fn from(s: &str) -> Self {
        UserPrimary(s.to_owned())
    }
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

/// A certification binding a [`NodeSubkey`] to the [`UserPrimary`] that signed
/// it — the Rust stand-in for a *verified* OpenPGP subkey-binding signature.
///
/// Constructing one asserts the signature has been cryptographically
/// verified: the `issuer` genuinely produced this certification over `subkey`.
/// It says nothing about whether the issuer is *authorized*; that is the
/// registry's decision at [`handshake`](Registry::handshake) time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    subkey: NodeSubkey,
    issuer: UserPrimary,
}

impl Signature {
    /// Record a verified certification of `subkey` by `issuer`.
    #[must_use]
    pub fn new(subkey: NodeSubkey, issuer: UserPrimary) -> Self {
        Signature { subkey, issuer }
    }

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

    /// Record a verified subkey-binding certification (`IssueSubkey`).
    ///
    /// Deliberately unguarded by registration: a rogue, *unregistered* primary
    /// can still mint a signature over a subkey. That signature alone must
    /// never be sufficient for admission — the [`handshake`](Self::handshake)
    /// guard enforces that.
    pub fn issue_subkey(&mut self, signature: Signature) {
        self.signed_by
            .insert(signature.subkey.clone(), signature.issuer);
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

    fn primary(s: &str) -> UserPrimary {
        UserPrimary::from(s)
    }

    fn subkey(s: &str) -> NodeSubkey {
        NodeSubkey::from(s)
    }

    #[test]
    fn chained_subkey_of_registered_primary_is_admitted() {
        // A user primary enrolls, signs a node subkey, and the node presents
        // it: admission succeeds and yields the node's identity.
        let mut reg = Registry::new();
        let alice = primary("alice-primary");
        let node = subkey("alice-node-1");

        reg.register(alice.clone());
        reg.issue_subkey(Signature::new(node.clone(), alice.clone()));

        assert_eq!(reg.handshake(&node), Ok(node.node_id()));
        assert!(reg.is_admitted(&node));
    }

    #[test]
    fn subkey_signed_by_unregistered_primary_is_rejected() {
        // A rogue primary can mint a signature (IssueSubkey is unguarded) but
        // never registers: the chain does not resolve to an authorized user,
        // so the forged handshake is refused and nothing is admitted.
        let mut reg = Registry::new();
        let rogue = primary("rogue-primary");
        let node = subkey("rogue-node");

        reg.issue_subkey(Signature::new(node.clone(), rogue.clone()));

        assert_eq!(
            reg.handshake(&node),
            Err(AdmissionError::UnauthorizedIssuer { issuer: rogue })
        );
        assert!(!reg.is_admitted(&node));
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
        let authorized = primary("authorized");
        let unauthorized = primary("unauthorized");
        let good = subkey("good-node");
        let bad = subkey("bad-node");

        reg.register(authorized.clone());
        reg.issue_subkey(Signature::new(good.clone(), authorized));
        reg.issue_subkey(Signature::new(bad.clone(), unauthorized.clone()));

        assert_eq!(reg.handshake(&good), Ok(good.node_id()));
        assert_eq!(
            reg.handshake(&bad),
            Err(AdmissionError::UnauthorizedIssuer {
                issuer: unauthorized
            })
        );
    }

    #[test]
    fn verify_does_not_mutate_admitted_set() {
        // The pure policy check leaves the registry untouched.
        let mut reg = Registry::new();
        let alice = primary("alice");
        let node = subkey("node");
        reg.register(alice.clone());
        reg.issue_subkey(Signature::new(node.clone(), alice));

        assert!(reg.verify(&node).is_ok());
        assert!(!reg.is_admitted(&node));
    }
}
