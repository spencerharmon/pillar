//! A native sealed-secret store (ROI P0 "synergy everywhere" — security &
//! availability, Tier 2, `sealed-secret-store`): workloads request secrets;
//! access is RBAC + WoT gated by [`crate::RbacDecider`] (this crate's own
//! single decider — no second, bespoke authorization check); secrets are
//! sealed **per recipient set** by reusing `pillar_crypto::seal` — the exact
//! same public-key recipient-sealing primitive `pillar-key-distribution`'s
//! `SealedArtifact` and `pillar-cells`' `VisClass::RecipientSealed`/
//! `CellEncrypted` are themselves built on (see those crates' docs) — rather
//! than inventing a second, bespoke secret-encryption path. (This crate
//! cannot depend on `pillar-key-distribution` or `pillar-cells` directly: both
//! transitively depend back on `pillar-rbac` via
//! `pillar-net -> pillar-ipam -> pillar-topology -> pillar-trust-artifacts ->
//! pillar-rbac`, so a direct edge would be a cyclic package dependency Cargo
//! refuses to build. Depending on the shared `pillar-crypto` primitive both
//! of those crates ALSO depend on is the reuse this module can safely make —
//! the same sealing math, the same envelope format, zero re-derivation.)
//!
//! # Model
//!
//! * A [`SecretStore`] holds, per secret id, only a
//!   [`pillar_crypto::types::SealedEnvelope`] — the exact real X25519+AEAD
//!   sealed envelope `pillar_crypto::seal::seal_to_recipients` produces
//!   elsewhere in the codebase — so a secret's ciphertext is never
//!   observable in plaintext from the store directly.
//! * [`SecretStore::seal_for_members`] derives the seal's recipient public
//!   keys from a caller-supplied member/key mapping (e.g. a cell's current
//!   membership set, resolved by the caller against `pillar_cells::Cell` in
//!   a higher layer that can depend on both crates) — per-cell sealing,
//!   without this crate re-deriving cell membership itself.
//! * [`SecretStore::request_secret`] is the single gated path: it first
//!   calls [`crate::RbacDecider::decide`] (RBAC + WoT) and REFUSES
//!   ([`SecretRequestError::Unauthorized`]) before ever touching the sealed
//!   envelope on anything but [`crate::Decision::Allow`] — fail-closed,
//!   exactly like the rest of this crate's decisions. Only on `Allow` does
//!   it attempt [`pillar_crypto::seal::unseal`] with the caller-supplied
//!   secret key, which itself succeeds only for a genuine cryptographic
//!   recipient — so an RBAC-authorized-but-non-recipient caller still
//!   cannot unseal (a second, independent fail-closed layer, not merely
//!   relied upon).

use std::collections::BTreeMap;
use std::fmt;

use pillar_core::NodeId;
use pillar_crypto::seal;
use pillar_crypto::{CryptoError, SealedEnvelope, SealingPublicKey, SealingSecretKey};

use crate::{Decision, RbacDecider, Request};

/// A secret's identity within a [`SecretStore`] — a store-local handle, not
/// itself a source of authority (authority comes from the RBAC request).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretId(pub String);

impl From<&str> for SecretId {
    fn from(s: &str) -> Self {
        SecretId(s.to_owned())
    }
}

/// A recipient node's sealing keypair, exactly the shape `pillar-key-
/// distribution`'s `NodeSealingKey` provides elsewhere: a [`NodeId`]
/// addressing handle plus the real X25519 public/secret pair from
/// `pillar_crypto::seal::sealing_keypair_from_seed`. Kept crate-local (not
/// re-exported from `pillar-key-distribution`, per this module's docs) so
/// this crate reuses only the shared `pillar-crypto` primitive, never a
/// cyclic edge to `pillar-key-distribution` itself.
#[derive(Clone, Debug)]
pub struct NodeSealingKey {
    node: NodeId,
    public: SealingPublicKey,
    secret: SealingSecretKey,
}

impl NodeSealingKey {
    /// Derive a node's sealing keypair from arbitrary seed material (in
    /// production, the node's device-subkey secret) — deterministic in the
    /// seed; distinct seeds yield cryptographically independent keypairs.
    ///
    /// # Errors
    /// Propagates a `pillar_crypto` key-derivation failure.
    pub fn from_seed(node: NodeId, seed: &[u8]) -> Result<Self, CryptoError> {
        let seed = pillar_crypto::Seed::from_bytes(seed.to_vec());
        let (public, secret) = seal::sealing_keypair_from_seed(&seed)?;
        Ok(NodeSealingKey {
            node,
            public,
            secret,
        })
    }

    /// This node's addressing handle.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// This node's X25519 sealing public key (the actual cryptographic
    /// recipient).
    #[must_use]
    pub fn public(&self) -> &SealingPublicKey {
        &self.public
    }
}

/// Every failure mode of a gated secret request — each a value the caller
/// fails the single request closed with, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretRequestError {
    /// The RBAC + WoT decision refused this subject/capability — the
    /// fail-closed default. Carries no further detail than the decision
    /// itself (never leaks WHY, only that access is denied).
    Unauthorized,
    /// No secret is stored under the requested id.
    NotFound,
    /// The request was authorized, but the supplied sealing key is not a
    /// genuine cryptographic recipient of the sealed envelope (or a
    /// lower-level crypto failure) — the independent, second fail-closed
    /// layer beneath the RBAC gate.
    Seal(CryptoError),
}

impl fmt::Display for SecretRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRequestError::Unauthorized => write!(f, "unauthorized"),
            SecretRequestError::NotFound => write!(f, "secret not found"),
            SecretRequestError::Seal(e) => write!(f, "unseal failed: {e}"),
        }
    }
}

impl std::error::Error for SecretRequestError {}

/// A native, per-cell sealed-secret store: workloads request secrets by
/// [`SecretId`]; every request is RBAC + WoT gated
/// ([`SecretStore::request_secret`]) before the already-sealed envelope is
/// ever touched. Holds ONLY real [`SealedEnvelope`]s (produced by
/// `pillar_crypto::seal::seal_to_recipients`) — never plaintext — so a
/// secret is sealed at rest by construction, not by caller discipline.
#[derive(Debug, Default)]
pub struct SecretStore {
    secrets: BTreeMap<SecretId, SealedEnvelope>,
}

impl SecretStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        SecretStore {
            secrets: BTreeMap::new(),
        }
    }

    /// Seal `plaintext` under `id`, sealed to exactly `recipients` — the raw
    /// form for callers that already know the exact recipient key set.
    ///
    /// # Errors
    /// Propagates a `pillar_crypto` sealing failure.
    pub fn seal(
        &mut self,
        id: SecretId,
        plaintext: &[u8],
        recipients: &[NodeSealingKey],
    ) -> Result<(), CryptoError> {
        let pks: Vec<SealingPublicKey> = recipients.iter().map(|r| r.public.clone()).collect();
        let envelope = seal::seal_to_recipients(plaintext, &pks)?;
        self.secrets.insert(id, envelope);
        Ok(())
    }

    /// Seal `plaintext` under `id`, sealed to exactly the members named in
    /// `members` — per-cell sealing where the caller (a layer able to
    /// depend on both this crate and `pillar_cells`) resolves a
    /// `pillar_cells::Cell`'s current membership into the corresponding
    /// sealing keys and passes them here. A member absent from `keys` is
    /// silently excluded from the seal (it has no key to seal to), never
    /// causes an error, since a cell may have members whose sealing keys
    /// this caller does not hold.
    ///
    /// # Errors
    /// Propagates a `pillar_crypto` sealing failure.
    pub fn seal_for_members(
        &mut self,
        id: SecretId,
        plaintext: &[u8],
        members: &[NodeId],
        keys: &[NodeSealingKey],
    ) -> Result<(), CryptoError> {
        let recipients: Vec<NodeSealingKey> = keys
            .iter()
            .filter(|k| members.contains(&k.node))
            .cloned()
            .collect();
        self.seal(id, plaintext, &recipients)
    }

    /// The raw ciphertext envelope bytes stored under `id`, if any — the
    /// only thing observable from the store directly. Never the plaintext:
    /// this is what proves "sealed at rest, never observable in plaintext
    /// from the storage layer directly, only through the gated unseal
    /// path".
    #[must_use]
    pub fn ciphertext_bytes(&self, id: &SecretId) -> Option<&[u8]> {
        self.secrets.get(id).map(SealedEnvelope::as_bytes)
    }

    /// Whether a secret is stored under `id`.
    #[must_use]
    pub fn contains(&self, id: &SecretId) -> bool {
        self.secrets.contains_key(id)
    }

    /// The single gated request+unseal path: decide `request` via
    /// `decider` (RBAC + WoT, per [`crate::RbacDecider::decide`]'s
    /// four-rung precedence lattice) and, ONLY on
    /// [`crate::Decision::Allow`], attempt to unseal the secret stored
    /// under `id` with `key`. Refuses
    /// ([`SecretRequestError::Unauthorized`]) before touching the sealed
    /// envelope on anything but `Allow` — fail-closed by construction, not
    /// caller discipline. An authorized caller whose `key` is not a genuine
    /// recipient still fails, independently, via
    /// [`pillar_crypto::seal::unseal`].
    ///
    /// # Errors
    /// [`SecretRequestError::Unauthorized`] if the RBAC + WoT decision is
    /// [`crate::Decision::Deny`]; [`SecretRequestError::NotFound`] if no
    /// secret is stored under `id`; [`SecretRequestError::Seal`] if `key`
    /// is not a genuine recipient or a lower-level crypto failure occurs.
    pub fn request_secret(
        &self,
        decider: &RbacDecider<'_>,
        request: &Request,
        id: &SecretId,
        key: &NodeSealingKey,
    ) -> Result<Vec<u8>, SecretRequestError> {
        if decider.decide(request) != Decision::Allow {
            return Err(SecretRequestError::Unauthorized);
        }
        let envelope = self.secrets.get(id).ok_or(SecretRequestError::NotFound)?;
        seal::unseal(envelope, &key.secret).map_err(SecretRequestError::Seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, PolicyEvent, PolicyTarget, ResourceClass};
    use pillar_wot_authority::WotAuthority;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn key(node: &str, seed: u8) -> NodeSealingKey {
        NodeSealingKey::from_seed(n(node), &[seed; 32]).unwrap()
    }

    // An authorized workload (RBAC + WoT satisfied) can request+unseal a
    // per-cell secret sealed to it via its membership.
    #[test]
    fn authorized_workload_can_request_and_unseal_a_per_cell_secret() {
        let alice_key = key("alice", 1);
        let mut store = SecretStore::new();
        store
            .seal_for_members(
                SecretId::from("db-password"),
                b"hunter2",
                &[n("alice")],
                &[alice_key.clone()],
            )
            .unwrap();

        // alice is deeply-enough trusted per an explicit node policy.
        let mut authority = WotAuthority::new(n("owner"), 5);
        authority.issue_edge(n("owner"), n("alice"), 5);
        let cap = Capability::from("secret:read");
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: cap.clone(),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&authority, &policies, &grants);
        let request = Request::new(n("alice"), cap).with_resource_class(ResourceClass::Storage);

        let plaintext = store
            .request_secret(&decider, &request, &SecretId::from("db-password"), &alice_key)
            .expect("authorized recipient must unseal");
        assert_eq!(plaintext, b"hunter2");
    }

    // An unauthorized requester (fails the RBAC+WoT decision) is refused —
    // fail closed.
    #[test]
    fn unauthorized_requester_is_refused_fail_closed() {
        let alice_key = key("alice", 1);
        let mallory_key = key("mallory", 2);
        let mut store = SecretStore::new();
        store
            .seal_for_members(
                SecretId::from("db-password"),
                b"hunter2",
                &[n("alice"), n("mallory")],
                &[alice_key, mallory_key.clone()],
            )
            .unwrap();

        // mallory is unreachable in the WoT graph at all (no depth default
        // satisfied) and has no explicit grant -> deny-all.
        let authority = WotAuthority::new(n("owner"), 5);
        let cap = Capability::from("secret:read");
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: cap.clone(),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&authority, &policies, &grants);
        let request =
            Request::new(n("mallory"), cap).with_resource_class(ResourceClass::Storage);

        let err = store
            .request_secret(
                &decider,
                &request,
                &SecretId::from("db-password"),
                &mallory_key,
            )
            .unwrap_err();
        assert_eq!(err, SecretRequestError::Unauthorized);
    }

    // An explicit deny wins even when the requester DOES hold the
    // cryptographic recipient key — RBAC gates BEFORE the crypto layer, so
    // possession of the key alone is never sufficient.
    #[test]
    fn explicit_deny_refuses_even_a_genuine_key_holder() {
        let alice_key = key("alice", 1);
        let mut store = SecretStore::new();
        store
            .seal_for_members(
                SecretId::from("db-password"),
                b"hunter2",
                &[n("alice")],
                &[alice_key.clone()],
            )
            .unwrap();

        let mut authority = WotAuthority::new(n("owner"), 5);
        authority.issue_edge(n("owner"), n("alice"), 5);
        let cap = Capability::from("secret:read");
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: cap.clone(),
            depth_threshold: 0,
        }];
        let grants = vec![crate::ExplicitGrant {
            subject: n("alice"),
            capability: cap.clone(),
            effect: crate::GrantEffect::Deny,
        }];
        let decider = RbacDecider::new(&authority, &policies, &grants);
        let request = Request::new(n("alice"), cap).with_resource_class(ResourceClass::Storage);

        let err = store
            .request_secret(&decider, &request, &SecretId::from("db-password"), &alice_key)
            .unwrap_err();
        assert_eq!(err, SecretRequestError::Unauthorized);
    }

    // A secret is sealed at rest: the raw ciphertext envelope bytes never
    // contain the plaintext, and the store exposes no other way to read a
    // secret's content except through the gated unseal path.
    #[test]
    fn secret_is_sealed_at_rest_never_observable_in_plaintext() {
        let alice_key = key("alice", 1);
        let mut store = SecretStore::new();
        let plaintext: &[u8] = b"correct horse battery staple";
        store
            .seal_for_members(SecretId::from("s"), plaintext, &[n("alice")], &[alice_key])
            .unwrap();

        let ciphertext = store
            .ciphertext_bytes(&SecretId::from("s"))
            .expect("stored secret must be present");
        // The plaintext must never appear verbatim in the stored ciphertext.
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|w| w == plaintext),
            "plaintext must never be directly observable in the sealed envelope bytes"
        );
    }

    // A missing secret id is refused as NotFound (not a panic), even for an
    // otherwise-authorized request.
    #[test]
    fn missing_secret_is_not_found() {
        let store = SecretStore::new();
        let alice_key = key("alice", 1);
        let mut authority = WotAuthority::new(n("owner"), 5);
        authority.issue_edge(n("owner"), n("alice"), 5);
        let cap = Capability::from("secret:read");
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: cap.clone(),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&authority, &policies, &grants);
        let request = Request::new(n("alice"), cap).with_resource_class(ResourceClass::Storage);

        let err = store
            .request_secret(&decider, &request, &SecretId::from("nope"), &alice_key)
            .unwrap_err();
        assert_eq!(err, SecretRequestError::NotFound);
    }

    // seal_for_members excludes a non-member's key from the recipient set
    // even if a caller mistakenly supplies it: a non-member cannot unseal.
    #[test]
    fn seal_for_members_excludes_non_members() {
        // "outsider" is never in the members list.
        let alice_key = key("alice", 1);
        let outsider_key = key("outsider", 9);

        let mut store = SecretStore::new();
        store
            .seal_for_members(
                SecretId::from("s"),
                b"secret",
                &[n("alice")],
                &[alice_key, outsider_key.clone()],
            )
            .unwrap();

        let mut authority = WotAuthority::new(n("owner"), 5);
        authority.issue_edge(n("owner"), n("outsider"), 5);
        let cap = Capability::from("secret:read");
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("outsider")),
            capability: cap.clone(),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&authority, &policies, &grants);
        // outsider is RBAC-authorized (has a policy) but was never sealed to
        // (not a member) -> unseal itself fails independently.
        let request =
            Request::new(n("outsider"), cap).with_resource_class(ResourceClass::Storage);
        let err = store
            .request_secret(&decider, &request, &SecretId::from("s"), &outsider_key)
            .unwrap_err();
        assert!(matches!(err, SecretRequestError::Seal(_)));
    }
}
