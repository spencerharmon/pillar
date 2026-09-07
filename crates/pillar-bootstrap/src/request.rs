//! The node/user bootstrap **request → approval** lifecycle, refining
//! `specs/BootstrapRequest.tla`.
//!
//! A fresh node or a new user joins an existing cell by submitting a
//! [`BootstrapRequest`] carrying its identifying information. An existing,
//! authorized cell member reviews the queue ([`BootstrapRequestQueue::pending`])
//! and approves ([`BootstrapRequestQueue::approve`]) or rejects it. On a NODE
//! approval an existing node seals the cell key to the newly-approved node and
//! returns the CID of the sealed blob ([`SealedCellKey`]); on a USER approval
//! the new user's operational-key offer is escrowed. Key material is delivered
//! ONLY to an approved request whose approver is an authorized member — the
//! exact invariants TLC proves.
//!
//! The seal is REAL cryptography: `pillar_crypto::seal` (X25519 key-agreement
//! wrapping a fresh ChaCha20-Poly1305 content key, the same seal contract
//! `cells-confidentiality-impl`/`key-distribution-offer-impl` already use).
//! Only a holder of the approved node's derived sealing secret key can
//! recover the cell key; a non-recipient (including the cell's own key) is
//! refused cryptographically — `CryptoError::NotARecipient` — not by
//! bookkeeping, and a tampered envelope fails AEAD authentication.

use std::collections::{BTreeSet, HashMap};

use pillar_core::NodeId;
use pillar_crypto::seal::{seal_to_recipients, sealing_keypair_from_seed, unseal};
use pillar_crypto::{CryptoError, SealedEnvelope, SealingSecretKey, Seed};
use sha2::{Digest, Sha256};

use crate::custody::CustodyKind;

/// Derive a node's real X25519 sealing keypair deterministically from its
/// [`NodeId`] label (in production, the node's device-subkey secret would
/// seed this instead). Deterministic in the id; distinct ids yield
/// cryptographically independent keypairs. Public so a new node (or a test)
/// can derive its own secret key to [`SealedCellKey::unseal`] the cell key
/// sealed to it.
///
/// # Errors
/// Propagates a `pillar_crypto` key-derivation failure.
pub fn sealing_keypair_for(
    node: &NodeId,
) -> Result<(pillar_crypto::SealingPublicKey, SealingSecretKey), CryptoError> {
    let seed =
        Seed::from_bytes(format!("pillar-bootstrap/node-sealing-key-v1::{}", node.0).into_bytes());
    sealing_keypair_from_seed(&seed)
}

/// Derive the plaintext cell-key material sealed to an approved node. A real
/// deployment seals the actual cell secret key bytes; this derives a
/// deterministic stand-in plaintext from the cell id so the same cell always
/// seals the same key material (the PLAINTEXT is a stand-in — the seal is not).
fn cell_key_plaintext(cell: &NodeId) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"pillar-bootstrap/cell-key-plaintext-v1");
    h.update(cell.0.as_bytes());
    h.finalize().to_vec()
}

/// Content id (hex SHA-256) of a sealed envelope's bytes, addressing the
/// sealed blob a new node fetches.
fn envelope_cid(envelope: &SealedEnvelope) -> String {
    let mut h = Sha256::new();
    h.update(envelope.as_bytes());
    format!("bafy-cellkey-{:x}", h.finalize())
}

/// A monotonic request id, unique within a queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BootstrapRequestId(pub u64);

impl std::fmt::Display for BootstrapRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "req-{}", self.0)
    }
}

/// The two kinds of bootstrap request (`BootstrapRequest.tla` `Kinds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapRequestKind {
    /// A fresh node joining the cell: on approval the cell key is sealed to it.
    Node,
    /// A new user joining the cell: on approval its op-key offer is escrowed.
    User,
}

/// The lifecycle state of a request (`BootstrapRequest.tla` `States`, minus
/// the pre-submit `absent`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    /// Submitted, awaiting a decision.
    Pending,
    /// Approved by an authorized member; key material delivered.
    Approved,
    /// Rejected by an authorized member; no key material.
    Rejected,
}

/// Identifying information a joining node advertises with its request — the
/// "all identifying information" the node sends: peer id, public/private
/// addresses (whatever libp2p already has), version, OS, and public-key CID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The node's libp2p peer id.
    pub peer_id: String,
    /// Publicly reachable multiaddrs libp2p observed/holds for the node.
    pub public_addrs: Vec<String>,
    /// Private/LAN multiaddrs libp2p holds for the node.
    pub private_addrs: Vec<String>,
    /// The pillar/node software version string.
    pub version: String,
    /// The node's operating system identifier.
    pub os: String,
    /// The CID of the node's published public key.
    pub public_key_cid: String,
}

impl NodeIdentity {
    /// A node identity with only a peer id known (addresses/versions filled in
    /// as libp2p discovers them).
    #[must_use]
    pub fn new(peer_id: impl Into<String>) -> Self {
        NodeIdentity {
            peer_id: peer_id.into(),
            public_addrs: Vec::new(),
            private_addrs: Vec::new(),
            version: String::new(),
            os: String::new(),
            public_key_cid: String::new(),
        }
    }
}

/// The sealed cell key returned to an approved NODE: an existing node
/// REAL-sealed (X25519 + AEAD, `pillar_crypto::seal`) the cell key to the new
/// node; this carries the content id of that sealed blob, the recipient-
/// sealed envelope itself, the node it is sealed to, and the member that
/// sealed it. Only a holder of `sealed_to`'s derived secret key can
/// [`SealedCellKey::unseal`] it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedCellKey {
    /// The content id of the sealed cell-key blob (what the new node fetches).
    pub cid: String,
    /// The real recipient-sealed envelope bytes (opaque to a non-recipient).
    envelope: SealedEnvelope,
    /// The node the cell key was sealed to (the approved requester).
    pub sealed_to: NodeId,
    /// The existing cell member that sealed it.
    pub sealed_by: NodeId,
}

impl SealedCellKey {
    /// Recover the sealed cell-key plaintext using `sealed_to`'s derived
    /// sealing secret key. Fails cryptographically
    /// ([`CryptoError::NotARecipient`]) for any other key, and on a tampered
    /// envelope ([`CryptoError::DecryptionFailed`]) — AEAD authentication.
    ///
    /// # Errors
    /// Propagates the underlying `pillar_crypto` unseal failure.
    pub fn unseal(&self, secret: &SealingSecretKey) -> Result<Vec<u8>, CryptoError> {
        unseal(&self.envelope, secret)
    }

    /// The raw sealed-envelope bytes (as stored/fetched by the new node).
    #[must_use]
    pub fn envelope_bytes(&self) -> &[u8] {
        self.envelope.as_bytes()
    }
}

/// A single bootstrap request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapRequest {
    id: BootstrapRequestId,
    kind: BootstrapRequestKind,
    /// The cell domain being joined.
    domain: NodeId,
    /// The requester's identity as a WoT node (its key).
    subject: NodeId,
    /// A joining node's advertised identity (present for [`BootstrapRequestKind::Node`]).
    identity: Option<NodeIdentity>,
    /// The custody mechanism the requester chose for its key.
    custody: CustodyKind,
    /// Operator labels attached to the request/key.
    labels: Vec<String>,
    state: RequestState,
    approver: Option<NodeId>,
}

impl BootstrapRequest {
    /// The request id.
    #[must_use]
    pub fn id(&self) -> BootstrapRequestId {
        self.id
    }
    /// The request kind.
    #[must_use]
    pub fn kind(&self) -> BootstrapRequestKind {
        self.kind
    }
    /// The cell domain being joined.
    #[must_use]
    pub fn domain(&self) -> &NodeId {
        &self.domain
    }
    /// The requester's node/key identity.
    #[must_use]
    pub fn subject(&self) -> &NodeId {
        &self.subject
    }
    /// The joining node's advertised identity, if any.
    #[must_use]
    pub fn identity(&self) -> Option<&NodeIdentity> {
        self.identity.as_ref()
    }
    /// The chosen custody mechanism.
    #[must_use]
    pub fn custody(&self) -> CustodyKind {
        self.custody
    }
    /// The operator labels attached.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }
    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> RequestState {
        self.state
    }
    /// The member that decided this request, if decided.
    #[must_use]
    pub fn approver(&self) -> Option<&NodeId> {
        self.approver.as_ref()
    }
}

/// Why a request operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// No request with the given id exists in this queue.
    UnknownRequest,
    /// The request is not `Pending` — it was already approved/rejected
    /// (terminal; `BootstrapRequest.tla` `ApprovalIsTerminal`).
    NotPending,
    /// The approver is not an authorized existing cell member — approval
    /// requires an authorized member (never a self-approval, never an
    /// outsider).
    NotAuthorizedMember,
}

/// The queue of bootstrap requests for one cell, with the set of authorized
/// members that may decide them. Refines `BootstrapRequest.tla`.
#[derive(Clone, Debug)]
pub struct BootstrapRequestQueue {
    cell: NodeId,
    members: BTreeSet<NodeId>,
    requests: Vec<BootstrapRequest>,
    next_id: u64,
    sealed: HashMap<BootstrapRequestId, SealedCellKey>,
    escrowed: BTreeSet<BootstrapRequestId>,
}

impl BootstrapRequestQueue {
    /// A queue for `cell`, whose requests may be decided by any node in
    /// `members` (the existing authorized cell members).
    #[must_use]
    pub fn new(cell: NodeId, members: impl IntoIterator<Item = NodeId>) -> Self {
        BootstrapRequestQueue {
            cell,
            members: members.into_iter().collect(),
            requests: Vec::new(),
            next_id: 0,
            sealed: HashMap::new(),
            escrowed: BTreeSet::new(),
        }
    }

    /// The cell this queue serves.
    #[must_use]
    pub fn cell(&self) -> &NodeId {
        &self.cell
    }

    /// Add an authorized member permitted to decide requests. Used by a node
    /// front-end whose "authorized existing member" set IS its authenticated
    /// (logged-in, WoT-authoritative) users: a valid login session's subject
    /// is admitted as a member before it approves.
    pub fn add_member(&mut self, member: NodeId) {
        self.members.insert(member);
    }

    /// Whether `node` is an authorized member of this queue.
    #[must_use]
    pub fn is_member(&self, node: &NodeId) -> bool {
        self.members.contains(node)
    }

    /// Submit a NODE bootstrap request carrying identifying info.
    pub fn submit_node(
        &mut self,
        subject: NodeId,
        identity: NodeIdentity,
        custody: CustodyKind,
        labels: Vec<String>,
    ) -> BootstrapRequestId {
        self.submit(
            BootstrapRequestKind::Node,
            subject,
            Some(identity),
            custody,
            labels,
        )
    }

    /// Submit a USER bootstrap request.
    pub fn submit_user(
        &mut self,
        subject: NodeId,
        custody: CustodyKind,
        labels: Vec<String>,
    ) -> BootstrapRequestId {
        self.submit(BootstrapRequestKind::User, subject, None, custody, labels)
    }

    fn submit(
        &mut self,
        kind: BootstrapRequestKind,
        subject: NodeId,
        identity: Option<NodeIdentity>,
        custody: CustodyKind,
        labels: Vec<String>,
    ) -> BootstrapRequestId {
        let id = BootstrapRequestId(self.next_id);
        self.next_id += 1;
        self.requests.push(BootstrapRequest {
            id,
            kind,
            domain: self.cell.clone(),
            subject,
            identity,
            custody,
            labels,
            state: RequestState::Pending,
            approver: None,
        });
        id
    }

    /// Every request, in submission order.
    #[must_use]
    pub fn all(&self) -> &[BootstrapRequest] {
        &self.requests
    }

    /// The pending requests awaiting a decision (`pillar bootstrap request
    /// list` shows these).
    #[must_use]
    pub fn pending(&self) -> Vec<&BootstrapRequest> {
        self.requests
            .iter()
            .filter(|r| r.state == RequestState::Pending)
            .collect()
    }

    fn index_of(&self, id: BootstrapRequestId) -> Result<usize, RequestError> {
        self.requests
            .iter()
            .position(|r| r.id == id)
            .ok_or(RequestError::UnknownRequest)
    }

    /// Approve a pending request as authorized member `member`. On a NODE
    /// approval the cell key is sealed to the requester and the resulting
    /// [`SealedCellKey`] (CID) is returned; on a USER approval the offer is
    /// escrowed and `Ok(None)` is returned.
    ///
    /// # Errors
    ///
    /// [`RequestError::UnknownRequest`] if `id` is unknown;
    /// [`RequestError::NotPending`] if it was already decided;
    /// [`RequestError::NotAuthorizedMember`] if `member` is not an authorized
    /// existing cell member.
    pub fn approve(
        &mut self,
        id: BootstrapRequestId,
        member: &NodeId,
    ) -> Result<Option<SealedCellKey>, RequestError> {
        if !self.members.contains(member) {
            return Err(RequestError::NotAuthorizedMember);
        }
        let idx = self.index_of(id)?;
        if self.requests[idx].state != RequestState::Pending {
            return Err(RequestError::NotPending);
        }
        self.requests[idx].state = RequestState::Approved;
        self.requests[idx].approver = Some(member.clone());

        match self.requests[idx].kind {
            BootstrapRequestKind::Node => {
                let subject = self.requests[idx].subject.clone();
                // An existing node REAL-seals the cell key to the approved
                // node's derived X25519 sealing public key (recipient-sealed,
                // AEAD-authenticated — only that node's secret key can unseal).
                let (recipient_pub, _recipient_secret) = sealing_keypair_for(&subject)
                    .expect("deterministic sealing keypair derivation cannot fail");
                let plaintext = cell_key_plaintext(&self.cell);
                let envelope = seal_to_recipients(&plaintext, &[recipient_pub])
                    .expect("sealing to a valid recipient key cannot fail");
                let cid = envelope_cid(&envelope);
                let sealed = SealedCellKey {
                    cid,
                    envelope,
                    sealed_to: subject,
                    sealed_by: member.clone(),
                };
                self.sealed.insert(id, sealed.clone());
                Ok(Some(sealed))
            }
            BootstrapRequestKind::User => {
                self.escrowed.insert(id);
                Ok(None)
            }
        }
    }

    /// Reject a pending request as authorized member `member`. No key material
    /// is ever delivered (fail-closed).
    ///
    /// # Errors
    ///
    /// As [`Self::approve`], minus the seal.
    pub fn reject(&mut self, id: BootstrapRequestId, member: &NodeId) -> Result<(), RequestError> {
        if !self.members.contains(member) {
            return Err(RequestError::NotAuthorizedMember);
        }
        let idx = self.index_of(id)?;
        if self.requests[idx].state != RequestState::Pending {
            return Err(RequestError::NotPending);
        }
        self.requests[idx].state = RequestState::Rejected;
        self.requests[idx].approver = Some(member.clone());
        Ok(())
    }

    /// The sealed cell key delivered to an approved node request, if any.
    #[must_use]
    pub fn sealed_cell_key(&self, id: BootstrapRequestId) -> Option<&SealedCellKey> {
        self.sealed.get(&id)
    }

    /// Whether an approved user request's offer was escrowed.
    #[must_use]
    pub fn is_escrowed(&self, id: BootstrapRequestId) -> bool {
        self.escrowed.contains(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue() -> BootstrapRequestQueue {
        BootstrapRequestQueue::new(
            NodeId::from("spencer-cell"),
            [NodeId::from("m1"), NodeId::from("m2")],
        )
    }

    fn node_identity() -> NodeIdentity {
        let mut id = NodeIdentity::new("12D3KooWpeer");
        id.public_addrs = vec!["/ip4/203.0.113.7/tcp/4001".into()];
        id.private_addrs = vec!["/ip4/192.168.1.20/tcp/4001".into()];
        id.version = "pillar 0.0.0".into();
        id.os = "linux".into();
        id.public_key_cid = "bafy-nodekey".into();
        id
    }

    #[test]
    fn approving_a_node_request_seals_the_cell_key_only_to_that_node() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec!["edge".into()],
        );
        let sealed = q
            .approve(id, &NodeId::from("m1"))
            .expect("approved")
            .expect("node approval returns a sealed cell key");
        assert_eq!(sealed.sealed_to, NodeId::from("new-node"));
        assert_eq!(sealed.sealed_by, NodeId::from("m1"));
        assert!(sealed.cid.starts_with("bafy-cellkey-"));
        // SealOnlyToApprovedNode: the request is approved + node-kind.
        let req = q.all().iter().find(|r| r.id() == id).unwrap();
        assert_eq!(req.state(), RequestState::Approved);
        assert_eq!(req.kind(), BootstrapRequestKind::Node);
    }

    #[test]
    fn the_seal_round_trips_real_plaintext_through_real_aead() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        let sealed = q
            .approve(id, &NodeId::from("m1"))
            .expect("approved")
            .expect("node approval returns a sealed cell key");
        let (_pk, secret) = sealing_keypair_for(&NodeId::from("new-node")).expect("keygen");
        let expected = cell_key_plaintext(&NodeId::from("spencer-cell"));
        assert_eq!(
            sealed.unseal(&secret).as_deref(),
            Ok(expected.as_slice()),
            "the approved node must recover the real plaintext cell key"
        );
    }

    #[test]
    fn a_non_recipient_node_cannot_unseal_the_cell_key() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        let sealed = q
            .approve(id, &NodeId::from("m1"))
            .expect("approved")
            .expect("sealed");
        // A different node's derived secret is not a recipient.
        let (_pk, other_secret) =
            sealing_keypair_for(&NodeId::from("some-other-node")).expect("keygen");
        assert_eq!(
            sealed.unseal(&other_secret),
            Err(CryptoError::NotARecipient),
            "a non-recipient node must be refused cryptographically"
        );
        // Nor can the existing member/cell key itself unseal it.
        let (_pk, member_secret) = sealing_keypair_for(&NodeId::from("m1")).expect("keygen");
        assert_eq!(
            sealed.unseal(&member_secret),
            Err(CryptoError::NotARecipient)
        );
    }

    #[test]
    fn a_tampered_sealed_cell_key_is_rejected() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        let sealed = q
            .approve(id, &NodeId::from("m1"))
            .expect("approved")
            .expect("sealed");
        let (_pk, secret) = sealing_keypair_for(&NodeId::from("new-node")).expect("keygen");
        // Flip a byte deep in the ciphertext payload — AEAD must reject it.
        let mut bytes = sealed.envelope_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = SealedCellKey {
            cid: sealed.cid.clone(),
            envelope: SealedEnvelope::from_bytes(bytes),
            sealed_to: sealed.sealed_to.clone(),
            sealed_by: sealed.sealed_by.clone(),
        };
        assert!(
            tampered.unseal(&secret).is_err(),
            "a tampered envelope must fail AEAD authentication, not silently decrypt"
        );
    }

    #[test]
    fn approving_a_user_request_escrows_the_offer_and_returns_no_cell_key() {
        let mut q = queue();
        let id = q.submit_user(NodeId::from("new-user"), CustodyKind::Password, vec![]);
        let sealed = q.approve(id, &NodeId::from("m2")).expect("approved");
        assert!(sealed.is_none(), "a user approval seals no cell key");
        assert!(q.is_escrowed(id));
    }

    #[test]
    fn an_unauthorized_member_cannot_approve() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        // The requester cannot self-approve; an outsider cannot approve.
        assert_eq!(
            q.approve(id, &NodeId::from("new-node")),
            Err(RequestError::NotAuthorizedMember)
        );
        assert_eq!(
            q.approve(id, &NodeId::from("outsider")),
            Err(RequestError::NotAuthorizedMember)
        );
        // No key was sealed.
        assert!(q.sealed_cell_key(id).is_none());
    }

    #[test]
    fn a_rejected_request_never_gets_key_material() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        q.reject(id, &NodeId::from("m1")).expect("rejected");
        assert!(q.sealed_cell_key(id).is_none());
        assert!(!q.is_escrowed(id));
        // RejectedNeverGetsKey + terminal: a later approve is refused.
        assert_eq!(
            q.approve(id, &NodeId::from("m1")),
            Err(RequestError::NotPending)
        );
    }

    #[test]
    fn approval_is_terminal_no_second_seal() {
        let mut q = queue();
        let id = q.submit_node(
            NodeId::from("new-node"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        q.approve(id, &NodeId::from("m1")).expect("approved");
        assert_eq!(
            q.approve(id, &NodeId::from("m2")),
            Err(RequestError::NotPending)
        );
    }

    #[test]
    fn pending_lists_only_undecided_requests_and_carries_identity() {
        let mut q = queue();
        let a = q.submit_node(
            NodeId::from("node-a"),
            node_identity(),
            CustodyKind::Tpm,
            vec![],
        );
        let _b = q.submit_user(NodeId::from("user-b"), CustodyKind::Password, vec![]);
        assert_eq!(q.pending().len(), 2);
        q.approve(a, &NodeId::from("m1")).unwrap();
        let pending = q.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].subject(), &NodeId::from("user-b"));
        // The node request carried full identifying info.
        let node_req = q.all().iter().find(|r| r.id() == a).unwrap();
        assert_eq!(node_req.identity().unwrap().peer_id, "12D3KooWpeer");
    }

    #[test]
    fn unknown_request_is_reported() {
        let mut q = queue();
        assert_eq!(
            q.approve(BootstrapRequestId(99), &NodeId::from("m1")),
            Err(RequestError::UnknownRequest)
        );
    }

    #[test]
    fn an_added_member_may_approve() {
        // A node front-end admits an authenticated user as a member, then it
        // may decide requests.
        let mut q = queue();
        let id = q.submit_user(NodeId::from("new-user"), CustodyKind::Password, vec![]);
        assert!(!q.is_member(&NodeId::from("spencer")));
        assert_eq!(
            q.approve(id, &NodeId::from("spencer")),
            Err(RequestError::NotAuthorizedMember)
        );
        q.add_member(NodeId::from("spencer"));
        assert!(q.is_member(&NodeId::from("spencer")));
        assert!(q.approve(id, &NodeId::from("spencer")).is_ok());
    }
}
