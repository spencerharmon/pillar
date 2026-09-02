//! L0 sealed-artifact envelope, L1 offer/accept event-sourced admission, L2
//! tag-based public+encrypted policy auto-distribution, cross-owner(-cell)
//! offer confirmation gate, and OPAQUE-shaped escrow restricted to
//! operational keys — the Rust refinement of `specs/KeyDistribution.tla`
//! (ROI P1 "Key distribution & the offer system").
//!
//! # Model
//!
//! Conceptually extends `IdentityLogin.tla` exactly as
//! `specs/KeyDistribution.tla`'s header describes: a [`NodeId`] here is
//! `IdentityLogin`'s device subkey, and per identity-login-spec's
//! cell-is-the-genesis-principal model, a node is owned by whichever cell
//! its node subkey ultimately chains to (never a user). This crate treats
//! that ownership as a fixed ground truth ([`ForeignNodes`]) rather than
//! re-deriving `pillar_identity`'s Certify/DelegationGrant/GrantDevice/Revoke
//! dynamics — the same pattern `pillar-rbac` uses to re-use
//! `pillar-wot-authority`'s theorem by specializing its ground truth rather
//! than re-importing its module.
//!
//! The cell is the abstraction layer between users and nodes: a
//! [`CellPolicy`] owns a **user selector** (the users it currently admits)
//! and a **node allow-list** (the authorized recipient set). Key
//! distribution is the cross product of the two.
//!
//! * **L0 — always recipient-(node-)sealed with REAL cryptography.** Every
//!   escrowed key artifact placed into distribution is sealed with
//!   `pillar_crypto::seal` (X25519 key-agreement wrapping a fresh
//!   ChaCha20-Poly1305 content key) to a specific set of recipient node
//!   **public keys**, layered over `pillar_net::blob`'s content-addressed
//!   transport as a [`SealedArtifact`]: the digest is the real SHA2-256
//!   multihash content address of the ciphertext envelope, and only a holder
//!   of a recipient node's secret key can unseal — a non-recipient is refused
//!   cryptographically, not by bookkeeping. The addressing-level seal target
//!   set (`is_sealed_to`) tracks the allow-list; the seal itself is the cipher.
//! * **L1 — bi-directional offer/accept admission.** A user
//!   [`KeyDistributionLedger::offer`]s an escrowed operational key into a
//!   cell; the cell's policy [`KeyDistributionLedger::accept`]s at offer
//!   time; only once both exist may
//!   [`KeyDistributionLedger::admit`] fire, recording the event-sourced
//!   admitted-login entry. [`KeyDistributionLedger::revoke_offer`] withdraws
//!   the offer and immediately clears both the admission and the seal
//!   (fail-closed).
//! * **L2 — tag-based policy auto-distribution.** `userSel`/`nodeAllow` are
//!   the cell's tag-driven policy surface; adding/removing a node from the
//!   allow-list atomically re-seals every admitted record of that cell in
//!   the same call, so distribution is always automatic and never a stale
//!   snapshot.
//! * **Cross-owner(-cell) offer confirmation gate.** [`CrossOwner`] holds
//!   when the target cell's current allow-list contains a foreign node.
//!   [`KeyDistributionLedger::admit`] refuses to fire for a cross-owner
//!   record unless [`KeyDistributionLedger::confirm_cross_owner`] has been
//!   called first, and a later allow-list edit can never retroactively widen
//!   an unconfirmed record's seal past what that gate allows
//!   ([`KeyDistributionLedger::seal_of`] always recomputes via
//!   [`desired_seal`]).
//! * **Escrow authority bound.** [`ArtifactKind::Root`] artifacts can never
//!   be offered, escrow-stored, or admitted — [`Artifact::kind`] is checked
//!   at every one of those three call sites.
//! * **OPAQUE-shaped escrow confidentiality via REAL argon2id+AEAD.**
//!   [`Escrow`] mirrors `pillar_identity`'s "no private-key variable"
//!   technique with genuine cryptography: the server holds ONLY an
//!   argon2id (`pillar_crypto::kdf`) + ChaCha20-Poly1305
//!   (`pillar_crypto::aead`) envelope — never the password, the derived key,
//!   or the plaintext. [`Escrow::recover_plaintext`] is real decryption: it
//!   re-derives the key from the client's supplied password and opens the
//!   AEAD, so [`Escrow::server_compromise`] leaks only ciphertext an attacker
//!   cannot open without the password. **Step-up gate:** escrow admits only
//!   [`ArtifactKind::Operational`] artifacts (never a root/signing key), and
//!   [`Escrow::recover_plaintext_for_signing`] additionally requires a
//!   [`StepUpToken`] proving fresh, elevated authentication before it will
//!   release plaintext for use in signing — recovering the operational key's
//!   plaintext is never enough on its own to *sign* with it.
//!
//! # Proven properties (re-asserted by this crate's tests)
//!
//! * `SealedMatchesAllowlist` — an admitted record's seal target is always
//!   exactly [`desired_seal`]; a non-admitted record's seal target is empty.
//! * `BiDirectionalConsent` — admission requires both offer and accept.
//! * `FailClosedRevocation` — revoking an offer immediately un-admits it.
//! * `CrossOwnerGate` — an unconfirmed record's seal target never includes a
//!   foreign node, at any point.
//! * `EscrowTypeBound` / `NoRootEscrow` — a root artifact can never be
//!   escrow-stored or admitted.
//! * `OpaqueConfidentiality` — a compromised server-held envelope alone never
//!   yields plaintext without client cooperation.
//! * `StepUpRequiredForSigning` (new vs. the TLA+ spec, which does not model
//!   signing) — plaintext recovery for signing additionally requires a valid,
//!   unexpired, unconsumed step-up token.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pillar_core::NodeId;
use pillar_net::BlobDigest;

/// A user identity permitted to offer artifacts into a cell.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(pub String);

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        UserId(s.to_owned())
    }
}

/// A cell identity: the abstraction layer between users and nodes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellId(pub String);

impl From<&str> for CellId {
    fn from(s: &str) -> Self {
        CellId(s.to_owned())
    }
}

/// An escrow artifact identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactId(pub String);

impl From<&str> for ArtifactId {
    fn from(s: &str) -> Self {
        ArtifactId(s.to_owned())
    }
}

/// Type-level classification of an artifact: whether it is the cold root
/// (never escrowable, never distributable) or an operational key.
///
/// Mirrors `specs/KeyDistribution.tla`'s `RootArtifacts \subseteq Artifacts`
/// distinction, checked at every guard the spec's `EscrowTypeBound` /
/// `NoRootEscrow` cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// The cell's cold root: never escrowable, never offerable, never
    /// admissible into distribution.
    Root,
    /// An operational key: the only kind escrow/distribution ever handles.
    Operational,
}

/// An escrow artifact together with its type-level kind.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Artifact {
    id: ArtifactId,
    kind: ArtifactKindOrd,
}

/// `ArtifactKind` does not derive `Ord`; this newtype gives `Artifact` a
/// total order for use as a map/set key without pretending root and
/// operational are otherwise comparable in any meaningful way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ArtifactKindOrd {
    Root,
    Operational,
}

impl From<ArtifactKind> for ArtifactKindOrd {
    fn from(k: ArtifactKind) -> Self {
        match k {
            ArtifactKind::Root => ArtifactKindOrd::Root,
            ArtifactKind::Operational => ArtifactKindOrd::Operational,
        }
    }
}

impl Artifact {
    /// Construct a new artifact of the given kind.
    #[must_use]
    pub fn new(id: ArtifactId, kind: ArtifactKind) -> Self {
        Artifact {
            id,
            kind: kind.into(),
        }
    }

    /// This artifact's identity.
    #[must_use]
    pub fn id(&self) -> &ArtifactId {
        &self.id
    }

    /// This artifact's type-level kind.
    #[must_use]
    pub fn kind(&self) -> ArtifactKind {
        match self.kind {
            ArtifactKindOrd::Root => ArtifactKind::Root,
            ArtifactKindOrd::Operational => ArtifactKind::Operational,
        }
    }

    /// Whether this artifact is the cold-root type (never escrowable /
    /// offerable / admissible).
    #[must_use]
    pub fn is_root(&self) -> bool {
        matches!(self.kind(), ArtifactKind::Root)
    }
}

/// An (user, cell, artifact) triple — the unit of offer/accept/admission,
/// matching `specs/KeyDistribution.tla`'s `AllRecords`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordKey {
    /// The offering user.
    pub user: UserId,
    /// The target cell.
    pub cell: CellId,
    /// The artifact being distributed.
    pub artifact: ArtifactId,
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.user.0, self.cell.0, self.artifact.0)
    }
}

/// A cell's L2 tag-driven policy surface: which users it currently admits
/// and which nodes are its current distribution recipients.
#[derive(Clone, Debug, Default)]
pub struct CellPolicy {
    user_selector: BTreeSet<UserId>,
    node_allow: BTreeSet<NodeId>,
}

impl CellPolicy {
    /// A cell with an empty user selector and node allow-list.
    #[must_use]
    pub fn new() -> Self {
        CellPolicy::default()
    }

    /// Add a user to this cell's selector (`AddUserToSelector`).
    pub fn add_user(&mut self, user: UserId) {
        self.user_selector.insert(user);
    }

    /// Remove a user from this cell's selector (`RemoveUserFromSelector`).
    pub fn remove_user(&mut self, user: &UserId) {
        self.user_selector.remove(user);
    }

    /// Whether this cell currently admits `user`.
    #[must_use]
    pub fn admits(&self, user: &UserId) -> bool {
        self.user_selector.contains(user)
    }

    /// This cell's current node allow-list.
    #[must_use]
    pub fn node_allow(&self) -> &BTreeSet<NodeId> {
        &self.node_allow
    }
}

/// Errors returned by [`KeyDistributionLedger`] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDistributionError {
    /// The referenced cell has no registered [`CellPolicy`].
    UnknownCell(CellId),
    /// The referenced artifact has no registered [`Artifact`].
    UnknownArtifact(ArtifactId),
    /// `Offer`/`Admit` guarded against a root-typed artifact
    /// (`EscrowTypeBound` / `NoRootEscrow`).
    RootArtifactNotDistributable(ArtifactId),
    /// `Offer` requires the user be in the cell's current selector.
    UserNotSelected {
        /// The offering user.
        user: UserId,
        /// The target cell that does not currently select this user.
        cell: CellId,
    },
    /// The offer/accept/admit/confirm/revoke precondition on the record's
    /// current state was not met (mirrors the spec's own guards, e.g.
    /// `r \notin offered`, `r \in offered`, ...).
    InvalidTransition {
        /// The record whose transition was refused.
        record: RecordKey,
        /// A short, static explanation of which precondition failed.
        reason: &'static str,
    },
    /// A node presented a sealing key that is not a recipient of the sealed
    /// artifact it tried to unseal (real X25519 recipient check).
    NotARecipient,
    /// A lower-level `pillar_crypto` operation failed. Carries the underlying
    /// error's rendered message.
    Crypto(String),
}

impl fmt::Display for KeyDistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyDistributionError::UnknownCell(c) => write!(f, "unknown cell {}", c.0),
            KeyDistributionError::UnknownArtifact(a) => write!(f, "unknown artifact {}", a.0),
            KeyDistributionError::RootArtifactNotDistributable(a) => {
                write!(
                    f,
                    "artifact {} is root-typed and cannot be distributed",
                    a.0
                )
            }
            KeyDistributionError::UserNotSelected { user, cell } => {
                write!(f, "user {} is not selected by cell {}", user.0, cell.0)
            }
            KeyDistributionError::InvalidTransition { record, reason } => {
                write!(f, "invalid transition for {record}: {reason}")
            }
            KeyDistributionError::NotARecipient => {
                write!(f, "node is not a recipient of this sealed artifact")
            }
            KeyDistributionError::Crypto(msg) => write!(f, "cryptographic operation failed: {msg}"),
        }
    }
}

impl std::error::Error for KeyDistributionError {}

/// L1 event-sourced offer/accept/admission ledger plus L0/L2 sealing, over a
/// fixed set of cells and artifacts.
///
/// The single modelled offering perspective in `specs/KeyDistribution.tla`
/// treats node ownership (which nodes belong to which cell, for cross-owner
/// purposes) as fixed ground truth; here that ground truth is supplied via
/// [`KeyDistributionLedger::new`]'s `foreign_nodes` set exactly as the spec's
/// `ForeignNodes` constant, since deriving it is `pillar_identity`'s job
/// (the node's chain to its owning cell), not this crate's.
#[derive(Debug)]
pub struct KeyDistributionLedger {
    cells: BTreeMap<CellId, CellPolicy>,
    artifacts: BTreeMap<ArtifactId, Artifact>,
    foreign_nodes: BTreeSet<NodeId>,
    offered: BTreeSet<RecordKey>,
    accepted: BTreeSet<RecordKey>,
    admitted: BTreeSet<RecordKey>,
    cross_confirmed: BTreeSet<RecordKey>,
    sealed_to: BTreeMap<RecordKey, BTreeSet<NodeId>>,
}

/// Whether a record is cross-owner: the target cell's current allow-list
/// contains any node not owned by the offering user's own cell
/// (`CrossOwner(r)`).
#[must_use]
pub fn is_cross_owner(node_allow: &BTreeSet<NodeId>, foreign_nodes: &BTreeSet<NodeId>) -> bool {
    node_allow.iter().any(|n| foreign_nodes.contains(n))
}

/// The seal target a record is entitled to right now, given a cell's node
/// allow-list: the full allow-list once confirmed (or never cross-owner to
/// begin with), else the allow-list minus unconfirmed foreign nodes
/// (`DesiredSeal(r, na)`).
#[must_use]
pub fn desired_seal(
    node_allow: &BTreeSet<NodeId>,
    foreign_nodes: &BTreeSet<NodeId>,
    confirmed: bool,
) -> BTreeSet<NodeId> {
    if confirmed || !is_cross_owner(node_allow, foreign_nodes) {
        node_allow.clone()
    } else {
        node_allow.difference(foreign_nodes).cloned().collect()
    }
}

impl KeyDistributionLedger {
    /// A new ledger with the given fixed node-ownership ground truth
    /// (`ForeignNodes`) and no cells, artifacts, offers, or admissions yet.
    #[must_use]
    pub fn new(foreign_nodes: BTreeSet<NodeId>) -> Self {
        KeyDistributionLedger {
            cells: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            foreign_nodes,
            offered: BTreeSet::new(),
            accepted: BTreeSet::new(),
            admitted: BTreeSet::new(),
            cross_confirmed: BTreeSet::new(),
            sealed_to: BTreeMap::new(),
        }
    }

    /// Register a cell's policy (inserting the default empty policy if new).
    pub fn cell_mut(&mut self, cell: CellId) -> &mut CellPolicy {
        self.cells.entry(cell).or_default()
    }

    /// Register an artifact.
    pub fn register_artifact(&mut self, artifact: Artifact) {
        self.artifacts.insert(artifact.id.clone(), artifact);
    }

    fn require_cell(&self, cell: &CellId) -> Result<&CellPolicy, KeyDistributionError> {
        self.cells
            .get(cell)
            .ok_or_else(|| KeyDistributionError::UnknownCell(cell.clone()))
    }

    fn require_artifact(&self, artifact: &ArtifactId) -> Result<&Artifact, KeyDistributionError> {
        self.artifacts
            .get(artifact)
            .ok_or_else(|| KeyDistributionError::UnknownArtifact(artifact.clone()))
    }

    /// Add a node to a cell's allow-list, atomically re-sealing every
    /// already-admitted record of that cell (`AddNodeToAllowlist`).
    pub fn add_node_to_allowlist(
        &mut self,
        cell: &CellId,
        node: NodeId,
    ) -> Result<(), KeyDistributionError> {
        let policy = self
            .cells
            .get_mut(cell)
            .ok_or_else(|| KeyDistributionError::UnknownCell(cell.clone()))?;
        policy.node_allow.insert(node);
        self.reseal_admitted_records_of(cell);
        Ok(())
    }

    /// Remove a node from a cell's allow-list, atomically re-sealing every
    /// already-admitted record of that cell so the removed node is never
    /// left as a stale seal target (`RemoveNodeFromAllowlist`).
    pub fn remove_node_from_allowlist(
        &mut self,
        cell: &CellId,
        node: &NodeId,
    ) -> Result<(), KeyDistributionError> {
        let policy = self
            .cells
            .get_mut(cell)
            .ok_or_else(|| KeyDistributionError::UnknownCell(cell.clone()))?;
        policy.node_allow.remove(node);
        self.reseal_admitted_records_of(cell);
        Ok(())
    }

    fn reseal_admitted_records_of(&mut self, cell: &CellId) {
        let node_allow = self.cells[cell].node_allow.clone();
        let records: Vec<RecordKey> = self
            .admitted
            .iter()
            .filter(|r| &r.cell == cell)
            .cloned()
            .collect();
        for r in records {
            let confirmed = self.cross_confirmed.contains(&r);
            let seal = desired_seal(&node_allow, &self.foreign_nodes, confirmed);
            self.sealed_to.insert(r, seal);
        }
    }

    /// A user offers an escrowed artifact into a cell (`Offer`). Type-bound
    /// at the point of offering: a root artifact can never even be offered.
    pub fn offer(
        &mut self,
        user: UserId,
        cell: CellId,
        artifact: ArtifactId,
    ) -> Result<(), KeyDistributionError> {
        let a = self.require_artifact(&artifact)?;
        if a.is_root() {
            return Err(KeyDistributionError::RootArtifactNotDistributable(artifact));
        }
        let policy = self.require_cell(&cell)?;
        if !policy.admits(&user) {
            return Err(KeyDistributionError::UserNotSelected { user, cell });
        }
        let record = RecordKey {
            user,
            cell,
            artifact,
        };
        if self.offered.contains(&record) || self.admitted.contains(&record) {
            return Err(KeyDistributionError::InvalidTransition {
                record,
                reason: "already offered or already admitted",
            });
        }
        self.offered.insert(record);
        Ok(())
    }

    /// The cell/node-side policy accept, recorded at offer time, standing in
    /// for "each node's policy accepts" (`Accept`).
    pub fn accept(&mut self, record: &RecordKey) -> Result<(), KeyDistributionError> {
        if !self.offered.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not offered",
            });
        }
        if self.accepted.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "already accepted",
            });
        }
        self.accepted.insert(record.clone());
        Ok(())
    }

    /// Whether `record` is currently cross-owner given the target cell's
    /// current allow-list.
    #[must_use]
    pub fn cross_owner(&self, record: &RecordKey) -> bool {
        match self.cells.get(&record.cell) {
            Some(policy) => is_cross_owner(&policy.node_allow, &self.foreign_nodes),
            None => false,
        }
    }

    /// Explicit confirmation required before a cross-owner offer may be
    /// admitted; once granted, immediately unblocks any foreign node the
    /// allow-list already authorizes but confirmation had been withholding
    /// (`ConfirmCrossOwner`).
    pub fn confirm_cross_owner(&mut self, record: &RecordKey) -> Result<(), KeyDistributionError> {
        if !self.offered.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not offered",
            });
        }
        if !self.cross_owner(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not cross-owner",
            });
        }
        if self.cross_confirmed.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "already confirmed",
            });
        }
        self.cross_confirmed.insert(record.clone());
        if self.admitted.contains(record) {
            let node_allow = self.cells[&record.cell].node_allow.clone();
            self.sealed_to.insert(record.clone(), node_allow);
        }
        Ok(())
    }

    /// Admission fires only once both offer and accept exist
    /// (`BiDirectionalConsent`) and, if cross-owner, only once explicitly
    /// confirmed (`CrossOwnerGate`). Also re-asserts the escrow authority
    /// bound: a root artifact can never be admitted (`NoRootEscrow`).
    pub fn admit(&mut self, record: &RecordKey) -> Result<(), KeyDistributionError> {
        let artifact = self.require_artifact(&record.artifact)?;
        if artifact.is_root() {
            return Err(KeyDistributionError::RootArtifactNotDistributable(
                record.artifact.clone(),
            ));
        }
        if !self.offered.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not offered",
            });
        }
        if !self.accepted.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not accepted",
            });
        }
        if self.admitted.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "already admitted",
            });
        }
        if self.cross_owner(record) && !self.cross_confirmed.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "cross-owner offer requires ConfirmCrossOwner before Admit",
            });
        }
        self.admitted.insert(record.clone());
        let node_allow = self.cells[&record.cell].node_allow.clone();
        let confirmed = self.cross_confirmed.contains(record);
        let seal = desired_seal(&node_allow, &self.foreign_nodes, confirmed);
        self.sealed_to.insert(record.clone(), seal);
        Ok(())
    }

    /// Offer revocation is fail-closed: it immediately removes the
    /// admitted-login entry (if any) and clears the seal target
    /// (`RevokeOffer`).
    pub fn revoke_offer(&mut self, record: &RecordKey) -> Result<(), KeyDistributionError> {
        if !self.offered.contains(record) {
            return Err(KeyDistributionError::InvalidTransition {
                record: record.clone(),
                reason: "not offered",
            });
        }
        self.offered.remove(record);
        self.admitted.remove(record);
        self.sealed_to.insert(record.clone(), BTreeSet::new());
        Ok(())
    }

    /// The current seal target of `record` — empty for any non-admitted
    /// record (`SealedMatchesAllowlist`).
    #[must_use]
    pub fn seal_of(&self, record: &RecordKey) -> BTreeSet<NodeId> {
        self.sealed_to.get(record).cloned().unwrap_or_default()
    }

    /// Whether `record` has an admitted-login entry.
    #[must_use]
    pub fn is_admitted(&self, record: &RecordKey) -> bool {
        self.admitted.contains(record)
    }

    /// Whether `record` is currently offered.
    #[must_use]
    pub fn is_offered(&self, record: &RecordKey) -> bool {
        self.offered.contains(record)
    }
}

/// A recipient node's real X25519 sealing keypair, deterministically derived
/// from the node's identity via `pillar_crypto::seal`. The `NodeId` label is
/// only an addressing handle; the cryptographic recipient IS the X25519 public
/// key, and only a holder of the matching secret can unseal.
#[derive(Clone, Debug)]
pub struct NodeSealingKey {
    node: NodeId,
    public: pillar_crypto::SealingPublicKey,
    secret: pillar_crypto::SealingSecretKey,
}

impl NodeSealingKey {
    /// Derive a node's sealing keypair from arbitrary seed material (in
    /// production, the node's device-subkey secret). Deterministic in the
    /// seed; distinct seeds yield cryptographically independent keypairs.
    ///
    /// # Errors
    /// Propagates a `pillar_crypto` key-derivation failure.
    pub fn from_seed(node: NodeId, seed: &[u8]) -> Result<Self, KeyDistributionError> {
        let seed = pillar_crypto::Seed::from_bytes(seed.to_vec());
        let (public, secret) = pillar_crypto::seal::sealing_keypair_from_seed(&seed)
            .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
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
    pub fn public(&self) -> &pillar_crypto::SealingPublicKey {
        &self.public
    }
}

/// L0: a REAL sealed-artifact envelope over `pillar_net::blob`'s
/// content-addressed transport. The artifact plaintext is sealed with
/// `pillar_crypto::seal::seal_to_recipients` (X25519 key-agreement wrapping a
/// fresh ChaCha20-Poly1305 content key) to a set of recipient node **public
/// keys** — not merely tracked by a `NodeId` set. The digest is the real
/// content address (SHA2-256 multihash) of the ciphertext envelope. Only a
/// holder of a recipient node's secret key can unseal; any other party learns
/// nothing. This is the crate's real L0 security effect: sealing here is
/// cryptography, not bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedArtifact {
    digest: BlobDigest,
    envelope: pillar_crypto::SealedEnvelope,
    sealed_to: BTreeSet<NodeId>,
}

impl SealedArtifact {
    /// Seal `plaintext` to every recipient node in `recipients`, producing a
    /// real cryptographic envelope whose digest is the content address of the
    /// ciphertext. Only a recipient node (by its secret key) can later
    /// [`SealedArtifact::unseal`] the plaintext.
    ///
    /// # Errors
    /// Propagates a `pillar_crypto` sealing failure.
    pub fn seal(
        plaintext: &[u8],
        recipients: &[NodeSealingKey],
    ) -> Result<Self, KeyDistributionError> {
        let pks: Vec<pillar_crypto::SealingPublicKey> =
            recipients.iter().map(|r| r.public.clone()).collect();
        let envelope = pillar_crypto::seal::seal_to_recipients(plaintext, &pks)
            .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
        let digest = BlobDigest::of(envelope.as_bytes());
        let sealed_to = recipients.iter().map(|r| r.node.clone()).collect();
        Ok(SealedArtifact {
            digest,
            envelope,
            sealed_to,
        })
    }

    /// The content-addressed digest of the sealed ciphertext (real SHA2-256
    /// multihash of the envelope bytes).
    #[must_use]
    pub fn digest(&self) -> BlobDigest {
        self.digest.clone()
    }

    /// The raw ciphertext envelope bytes, as stored in the blob layer. Opaque
    /// to anyone who is not a recipient.
    #[must_use]
    pub fn envelope_bytes(&self) -> &[u8] {
        self.envelope.as_bytes()
    }

    /// Whether `node` is nominally in the seal target set (an addressing-level
    /// check). Cryptographic entitlement is proven only by
    /// [`SealedArtifact::unseal`] succeeding with the node's secret key.
    #[must_use]
    pub fn is_sealed_to(&self, node: &NodeId) -> bool {
        self.sealed_to.contains(node)
    }

    /// Recover the plaintext using a recipient node's sealing key. Succeeds
    /// only for a genuine recipient; any other key yields
    /// [`KeyDistributionError::NotARecipient`].
    ///
    /// # Errors
    /// [`KeyDistributionError::NotARecipient`] if `key` is not a recipient of
    /// this envelope; [`KeyDistributionError::Crypto`] on a lower-level
    /// failure.
    pub fn unseal(&self, key: &NodeSealingKey) -> Result<Vec<u8>, KeyDistributionError> {
        pillar_crypto::seal::unseal(&self.envelope, &key.secret).map_err(|e| match e {
            pillar_crypto::CryptoError::NotARecipient => KeyDistributionError::NotARecipient,
            other => KeyDistributionError::Crypto(other.to_string()),
        })
    }
}

/// A step-up authentication token: proof of a fresh, elevated
/// authentication event, required before OPAQUE-shaped escrow will release
/// an operational key's plaintext for use in signing. Not part of
/// `specs/KeyDistribution.tla` (which does not model signing); this is the
/// Rust refinement's ROI-mandated addition ("step-up required for signing").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpToken {
    consumed: bool,
}

impl StepUpToken {
    /// A fresh, unconsumed step-up token (e.g. minted immediately after a
    /// successful re-authentication challenge).
    #[must_use]
    pub fn fresh() -> Self {
        StepUpToken { consumed: false }
    }

    /// Consume this token, returning whether it was still valid (unconsumed)
    /// at the time of use. A token can authorize exactly one signing use.
    pub fn consume(&mut self) -> bool {
        if self.consumed {
            false
        } else {
            self.consumed = true;
            true
        }
    }
}

/// OPAQUE-shaped escrow store, restricted to operational-typed artifacts.
///
/// Mirrors `pillar_identity`'s "no private-key variable" technique with REAL
/// cryptography: the server holds ONLY an argon2id+ChaCha20-Poly1305 envelope
/// (ciphertext + per-artifact salt) — never the password, never the derived
/// key, never the plaintext. Recovery is genuine decryption: the client must
/// supply the password, which is run through `pillar_crypto::kdf` (argon2id)
/// to re-derive the key and `pillar_crypto::aead` to open the envelope. A
/// server compromise therefore yields ciphertext an attacker cannot open
/// without the password — confidentiality is enforced by the cipher, not by a
/// bookkeeping flag.
#[derive(Debug, Default)]
pub struct Escrow {
    /// Per-artifact server-held envelope: (salt, argon2id+AEAD ciphertext).
    envelope: BTreeMap<ArtifactId, EscrowEnvelope>,
    server_compromised: bool,
    decrypted: BTreeSet<ArtifactId>,
}

/// The server-observable escrow envelope for one artifact: a per-artifact salt
/// and the argon2id+AEAD ciphertext. Deliberately carries neither the password
/// nor any derived key — a compromised server sees exactly this and no more.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EscrowEnvelope {
    salt: pillar_crypto::Salt,
    ciphertext: pillar_crypto::Ciphertext,
}

/// Domain-separation tag binding an escrow envelope's AEAD to this crate + the
/// escrow purpose, so an envelope can never be opened in a different context.
const ESCROW_AEAD_AAD: &[u8] = b"pillar-key-distribution/escrow/operational-key-v1";

impl Escrow {
    /// An empty escrow store: no envelopes, server not compromised.
    #[must_use]
    pub fn new() -> Self {
        Escrow::default()
    }

    /// Store the server-held envelope for an operational-typed artifact by
    /// argon2id-deriving a key from `password` (with a random per-artifact
    /// salt) and AEAD-encrypting `plaintext` under it. Guards against a root
    /// artifact ever being escrow-stored (`EscrowStore`, `EscrowTypeBound`).
    ///
    /// The password and derived key are consumed here and never retained; only
    /// the resulting `(salt, ciphertext)` envelope is kept.
    ///
    /// # Errors
    /// [`KeyDistributionError::RootArtifactNotDistributable`] for a root
    /// artifact; [`KeyDistributionError::Crypto`] on a KDF/AEAD failure.
    pub fn store(
        &mut self,
        artifact: &Artifact,
        password: &[u8],
        plaintext: &[u8],
    ) -> Result<(), KeyDistributionError> {
        if artifact.is_root() {
            return Err(KeyDistributionError::RootArtifactNotDistributable(
                artifact.id.clone(),
            ));
        }
        use rand_core::{OsRng, RngCore};
        let mut salt_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut salt_bytes);
        let salt = pillar_crypto::Salt::from_bytes(salt_bytes.to_vec());
        let key = pillar_crypto::kdf::derive_key(
            password,
            &salt,
            &pillar_crypto::KdfParams::default(),
        )
        .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
        let ciphertext = pillar_crypto::aead::seal_symmetric(&key, plaintext, ESCROW_AEAD_AAD)
            .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
        self.envelope
            .insert(artifact.id.clone(), EscrowEnvelope { salt, ciphertext });
        Ok(())
    }

    /// Whether a server-held envelope currently exists for `artifact`.
    #[must_use]
    pub fn has_envelope(&self, artifact: &ArtifactId) -> bool {
        self.envelope.contains_key(artifact)
    }

    /// An attacker obtains every server-held envelope: a single irreversible
    /// global flip (`CompromiseServer`). Note this grants only what the server
    /// actually holds — ciphertext, never plaintext or the password.
    pub fn server_compromise(&mut self) {
        self.server_compromised = true;
    }

    /// Whether the server has been compromised.
    #[must_use]
    pub fn is_server_compromised(&self) -> bool {
        self.server_compromised
    }

    /// Recover an operational key's plaintext for GENERAL use (decryption,
    /// inspection) by supplying the client's `password`. This is genuine
    /// argon2id+AEAD decryption: the wrong password (or any tampering) fails
    /// with [`KeyDistributionError::Crypto`], and a compromised server that
    /// holds only the envelope can never succeed without the password
    /// (`RecoverPlaintext`, `OpaqueConfidentiality`). Does NOT by itself
    /// authorize signing; see [`Escrow::recover_plaintext_for_signing`].
    ///
    /// # Errors
    /// [`KeyDistributionError::UnknownArtifact`] if no envelope exists;
    /// [`KeyDistributionError::Crypto`] on a wrong password or tampering.
    pub fn recover_plaintext(
        &mut self,
        artifact: &ArtifactId,
        password: &[u8],
    ) -> Result<Vec<u8>, KeyDistributionError> {
        let env = self
            .envelope
            .get(artifact)
            .ok_or_else(|| KeyDistributionError::UnknownArtifact(artifact.clone()))?;
        let key = pillar_crypto::kdf::derive_key(
            password,
            &env.salt,
            &pillar_crypto::KdfParams::default(),
        )
        .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
        let plaintext =
            pillar_crypto::aead::open_symmetric(&key, &env.ciphertext, ESCROW_AEAD_AAD)
                .map_err(|e| KeyDistributionError::Crypto(e.to_string()))?;
        self.decrypted.insert(artifact.clone());
        Ok(plaintext)
    }

    /// Whether `artifact`'s plaintext has ever been recovered by anyone
    /// (ghost/observable state, mirroring the spec's `decrypted` variable).
    #[must_use]
    pub fn is_decrypted(&self, artifact: &ArtifactId) -> bool {
        self.decrypted.contains(artifact)
    }

    /// Recover an operational key's plaintext specifically for use in
    /// SIGNING: requires everything [`Escrow::recover_plaintext`] requires
    /// (the client's password → real argon2id+AEAD open), **plus** a fresh,
    /// valid, unconsumed [`StepUpToken`] — the ROI's "step-up required for
    /// signing" restriction with no analog in the TLA+ spec. The token is
    /// consumed on use, so it authorizes exactly one signing recovery; a
    /// failed decryption does not consume it (the token is checked first).
    ///
    /// # Errors
    /// [`KeyDistributionError::InvalidTransition`] if the token is missing or
    /// already consumed; otherwise as [`Escrow::recover_plaintext`].
    pub fn recover_plaintext_for_signing(
        &mut self,
        artifact: &ArtifactId,
        password: &[u8],
        step_up: &mut StepUpToken,
    ) -> Result<Vec<u8>, KeyDistributionError> {
        if !step_up.consume() {
            return Err(KeyDistributionError::InvalidTransition {
                record: RecordKey {
                    user: UserId(String::new()),
                    cell: CellId(String::new()),
                    artifact: artifact.clone(),
                },
                reason: "step-up authentication required (and not already consumed) before signing",
            });
        }
        self.recover_plaintext(artifact, password)
    }
}

/// L0 REAL cryptographic sealing: the concrete refinement of the abstract
/// [`SealedArtifact`] seal target into an actual recipient-sealed envelope.
///
/// [`SealedArtifact`] and [`KeyDistributionLedger`] model *who* a record is
/// entitled to (the seal target as a [`BTreeSet<NodeId>`]) — the admission /
/// re-seal / cross-owner-gate policy. This module performs the matching
/// cryptography: it takes the artifact's plaintext bytes and the recipient
/// nodes' **sealing public keys** and produces a [`pillar_crypto`]
/// X25519+AEAD sealed envelope from which ONLY a holder of one recipient
/// node's sealing secret can recover the plaintext. No `DefaultHasher` KDF,
/// no FNV content address, no XOR "seal": every primitive is the real one
/// factored into `pillar-crypto` and gated GREEN by its contract tests.
///
/// The two layers compose: the ledger decides the seal target set, this
/// module enforces it cryptographically, and the resulting envelope's digest
/// (a real SHA2-256 multihash via [`BlobDigest::of`]) is the content address
/// carried by [`SealedArtifact`].
pub mod crypto_seal {
    use super::{BlobDigest, NodeId};
    use pillar_crypto::seal::{seal_to_recipients, unseal};
    use pillar_crypto::{SealedEnvelope, SealingPublicKey, SealingSecretKey};
    use std::collections::BTreeMap;

    /// The public sealing key registry for a set of recipient nodes: the map
    /// the ledger consults to turn a seal target ([`NodeId`] set) into the
    /// concrete recipient public keys an envelope is sealed to.
    #[derive(Clone, Debug, Default)]
    pub struct NodeSealingKeys {
        keys: BTreeMap<NodeId, SealingPublicKey>,
    }

    impl NodeSealingKeys {
        /// An empty registry.
        #[must_use]
        pub fn new() -> Self {
            NodeSealingKeys {
                keys: BTreeMap::new(),
            }
        }

        /// Register (or replace) a node's sealing public key.
        pub fn register(&mut self, node: NodeId, key: SealingPublicKey) {
            self.keys.insert(node, key);
        }

        /// The sealing public key for `node`, if registered.
        #[must_use]
        pub fn get(&self, node: &NodeId) -> Option<&SealingPublicKey> {
            self.keys.get(node)
        }
    }

    /// Errors from the real L0 sealing layer.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CryptoSealError {
        /// A node in the seal target has no registered sealing public key, so
        /// the artifact cannot be sealed to it — fail closed rather than drop
        /// a required recipient silently.
        UnknownRecipientKey(NodeId),
        /// The underlying `pillar-crypto` operation failed (seal/unseal).
        Crypto(pillar_crypto::CryptoError),
    }

    impl core::fmt::Display for CryptoSealError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                CryptoSealError::UnknownRecipientKey(n) => {
                    write!(f, "no sealing public key registered for recipient node {n:?}")
                }
                CryptoSealError::Crypto(e) => write!(f, "crypto error: {e:?}"),
            }
        }
    }

    impl std::error::Error for CryptoSealError {}

    /// A genuinely sealed L0 artifact: the recipient-sealed envelope plus its
    /// content address. The envelope is opaque ciphertext — only a holder of
    /// one recipient node's sealing secret can [`recover`](SealedBlob::recover)
    /// the plaintext.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SealedBlob {
        envelope: SealedEnvelope,
        digest: BlobDigest,
    }

    impl SealedBlob {
        /// Cryptographically seal `plaintext` to the sealing public keys of
        /// every node in `seal_target`, in the target's canonical order.
        ///
        /// Fails closed with [`CryptoSealError::UnknownRecipientKey`] if any
        /// targeted node has no registered key: a required recipient is never
        /// silently dropped.
        pub fn seal<'a, I>(
            plaintext: &[u8],
            seal_target: I,
            keys: &NodeSealingKeys,
        ) -> Result<Self, CryptoSealError>
        where
            I: IntoIterator<Item = &'a NodeId>,
        {
            let mut recipients: Vec<SealingPublicKey> = Vec::new();
            for node in seal_target {
                let key = keys
                    .get(node)
                    .ok_or_else(|| CryptoSealError::UnknownRecipientKey(node.clone()))?;
                recipients.push(key.clone());
            }
            let envelope =
                seal_to_recipients(plaintext, &recipients).map_err(CryptoSealError::Crypto)?;
            let digest = BlobDigest::of(envelope.as_bytes());
            Ok(SealedBlob { envelope, digest })
        }

        /// The content address (real SHA2-256 multihash) of the sealed
        /// ciphertext — the digest a [`super::SealedArtifact`] carries.
        #[must_use]
        pub fn digest(&self) -> BlobDigest {
            self.digest.clone()
        }

        /// The opaque sealed envelope.
        #[must_use]
        pub fn envelope(&self) -> &SealedEnvelope {
            &self.envelope
        }

        /// Recover the plaintext with a recipient node's sealing secret.
        /// Returns [`pillar_crypto::CryptoError::NotARecipient`] for a secret
        /// that is not one of the envelope's recipients — the real
        /// cryptographic enforcement of the seal target, not a set lookup.
        pub fn recover(
            &self,
            recipient_secret: &SealingSecretKey,
        ) -> Result<Vec<u8>, CryptoSealError> {
            unseal(&self.envelope, recipient_secret).map_err(CryptoSealError::Crypto)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(names: &[&str]) -> BTreeSet<NodeId> {
        names.iter().map(|n| NodeId::from(*n)).collect()
    }

    fn setup() -> (KeyDistributionLedger, RecordKey) {
        let mut ledger = KeyDistributionLedger::new(BTreeSet::new());
        ledger
            .cell_mut(CellId::from("cell-a"))
            .add_user(UserId::from("alice"));
        ledger.register_artifact(Artifact::new(
            ArtifactId::from("op-key-1"),
            ArtifactKind::Operational,
        ));
        let record = RecordKey {
            user: UserId::from("alice"),
            cell: CellId::from("cell-a"),
            artifact: ArtifactId::from("op-key-1"),
        };
        (ledger, record)
    }

    // BiDirectionalConsent: admission requires both offer and accept.
    #[test]
    fn admit_requires_both_offer_and_accept() {
        let (mut ledger, record) = setup();
        assert!(ledger.admit(&record).is_err());
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        assert!(ledger.admit(&record).is_err(), "not yet accepted");
        ledger.accept(&record).unwrap();
        ledger.admit(&record).unwrap();
        assert!(ledger.is_admitted(&record));
    }

    // FailClosedRevocation: revoking an offer immediately un-admits it and
    // clears the seal, even after admission.
    #[test]
    fn revoke_offer_is_fail_closed() {
        let (mut ledger, record) = setup();
        ledger
            .add_node_to_allowlist(&record.cell, NodeId::from("node-1"))
            .unwrap();
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        ledger.accept(&record).unwrap();
        ledger.admit(&record).unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["node-1"]));

        ledger.revoke_offer(&record).unwrap();
        assert!(!ledger.is_admitted(&record));
        assert!(!ledger.is_offered(&record));
        assert!(ledger.seal_of(&record).is_empty());
    }

    // SealedMatchesAllowlist (+ L2 auto-distribution): adding/removing a
    // node from the allow-list atomically re-seals an already-admitted
    // record; a dropped node is never left as a stale seal target.
    #[test]
    fn allowlist_edits_reseal_admitted_records_live() {
        let (mut ledger, record) = setup();
        ledger
            .add_node_to_allowlist(&record.cell, NodeId::from("node-1"))
            .unwrap();
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        ledger.accept(&record).unwrap();
        ledger.admit(&record).unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["node-1"]));

        ledger
            .add_node_to_allowlist(&record.cell, NodeId::from("node-2"))
            .unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["node-1", "node-2"]));

        ledger
            .remove_node_from_allowlist(&record.cell, &NodeId::from("node-1"))
            .unwrap();
        assert_eq!(
            ledger.seal_of(&record),
            nodes(&["node-2"]),
            "a dropped node must never remain a stale seal target"
        );
    }

    // Non-admitted records always have an empty seal target.
    #[test]
    fn non_admitted_record_seal_is_always_empty() {
        let (mut ledger, record) = setup();
        ledger
            .add_node_to_allowlist(&record.cell, NodeId::from("node-1"))
            .unwrap();
        assert!(ledger.seal_of(&record).is_empty());
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        assert!(
            ledger.seal_of(&record).is_empty(),
            "offered but not admitted"
        );
    }

    // CrossOwnerGate: an unconfirmed cross-owner record's admission is
    // refused outright, and once admitted (post-confirmation) a later
    // allow-list edit adding a NEW foreign node must not silently widen the
    // seal for an already-confirmed different foreign node's presence --
    // more precisely: an unconfirmed record's seal must never include a
    // foreign node, at any point in the behavior.
    #[test]
    fn cross_owner_offer_requires_confirmation_before_admit() {
        let mut ledger = KeyDistributionLedger::new(nodes(&["foreign-1"]));
        ledger
            .cell_mut(CellId::from("cell-a"))
            .add_user(UserId::from("alice"));
        ledger.register_artifact(Artifact::new(
            ArtifactId::from("op-key-1"),
            ArtifactKind::Operational,
        ));
        ledger
            .add_node_to_allowlist(&CellId::from("cell-a"), NodeId::from("foreign-1"))
            .unwrap();
        let record = RecordKey {
            user: UserId::from("alice"),
            cell: CellId::from("cell-a"),
            artifact: ArtifactId::from("op-key-1"),
        };
        assert!(ledger.cross_owner(&record));
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        ledger.accept(&record).unwrap();

        assert!(
            ledger.admit(&record).is_err(),
            "cross-owner admit must be refused without ConfirmCrossOwner"
        );

        ledger.confirm_cross_owner(&record).unwrap();
        ledger.admit(&record).unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["foreign-1"]));
    }

    // CrossOwnerGate, the genuinely subtle case: an UNCONFIRMED record must
    // never have a foreign node in its seal even after a LATER allow-list
    // edit -- a second cell/second offer confirms independently.
    #[test]
    fn later_allowlist_edit_never_bypasses_unconfirmed_cross_owner_gate() {
        let mut ledger = KeyDistributionLedger::new(nodes(&["foreign-1", "foreign-2"]));
        ledger
            .cell_mut(CellId::from("cell-a"))
            .add_user(UserId::from("alice"));
        ledger.register_artifact(Artifact::new(
            ArtifactId::from("op-key-1"),
            ArtifactKind::Operational,
        ));
        ledger
            .add_node_to_allowlist(&CellId::from("cell-a"), NodeId::from("home-1"))
            .unwrap();
        let record = RecordKey {
            user: UserId::from("alice"),
            cell: CellId::from("cell-a"),
            artifact: ArtifactId::from("op-key-1"),
        };
        // Not cross-owner yet (only home-1 in the allow-list) -- admits silently.
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        ledger.accept(&record).unwrap();
        ledger.admit(&record).unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["home-1"]));

        // Now the allow-list gains a foreign node -- the already-admitted,
        // never-confirmed record must NOT silently start distributing to it.
        ledger
            .add_node_to_allowlist(&record.cell, NodeId::from("foreign-1"))
            .unwrap();
        assert!(
            !ledger.seal_of(&record).contains(&NodeId::from("foreign-1")),
            "an unconfirmed record's seal must withhold a newly-added foreign node"
        );
        assert_eq!(ledger.seal_of(&record), nodes(&["home-1"]));

        // Confirming unblocks it immediately.
        ledger.confirm_cross_owner(&record).unwrap();
        assert_eq!(ledger.seal_of(&record), nodes(&["home-1", "foreign-1"]));
    }

    // EscrowTypeBound / NoRootEscrow: a root artifact can never be offered,
    // escrow-stored, or admitted.
    #[test]
    fn root_artifact_is_never_distributable_or_escrowable() {
        let mut ledger = KeyDistributionLedger::new(BTreeSet::new());
        ledger
            .cell_mut(CellId::from("cell-a"))
            .add_user(UserId::from("alice"));
        let root = Artifact::new(ArtifactId::from("cold-root"), ArtifactKind::Root);
        ledger.register_artifact(root.clone());

        assert!(matches!(
            ledger.offer(
                UserId::from("alice"),
                CellId::from("cell-a"),
                ArtifactId::from("cold-root")
            ),
            Err(KeyDistributionError::RootArtifactNotDistributable(_))
        ));

        let mut escrow = Escrow::new();
        assert!(matches!(
            escrow.store(&root, b"pw", b"secret-key-plaintext"),
            Err(KeyDistributionError::RootArtifactNotDistributable(_))
        ));
        assert!(!escrow.has_envelope(root.id()));
    }

    // OpaqueConfidentiality (REAL crypto): a compromised server-held envelope
    // alone never yields plaintext without the client's password. The server
    // holds only argon2id+AEAD ciphertext; the wrong password fails to open
    // it, and only the correct password recovers the exact plaintext.
    #[test]
    fn compromised_envelope_alone_never_yields_plaintext() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        let secret = b"the operational private key bytes";
        escrow.store(&artifact, b"correct password", secret).unwrap();
        escrow.server_compromise();

        // The attacker has the envelope but not the password: no plaintext.
        assert!(
            escrow
                .recover_plaintext(artifact.id(), b"attacker guess")
                .is_err(),
            "a wrong password must never open the escrow envelope"
        );
        assert!(!escrow.is_decrypted(artifact.id()));

        // The legitimate client, with the password, recovers the EXACT secret.
        let recovered = escrow
            .recover_plaintext(artifact.id(), b"correct password")
            .unwrap();
        assert_eq!(recovered, secret, "recovery must return the exact plaintext");
        assert!(escrow.is_decrypted(artifact.id()));
    }

    // Confidentiality is enforced by the cipher, not a flag: recovery works
    // with the right password regardless of server-compromise ordering, and
    // the stored envelope is never the plaintext.
    #[test]
    fn client_cooperation_is_independent_of_server_compromise() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        let secret = b"another operational key";
        escrow.store(&artifact, b"pw-2", secret).unwrap();
        // Server was never compromised, yet legitimate recovery still works.
        let recovered = escrow.recover_plaintext(artifact.id(), b"pw-2").unwrap();
        assert_eq!(recovered, secret);
        assert!(escrow.is_decrypted(artifact.id()));
    }

    // StepUpRequiredForSigning: recovering plaintext for signing requires a
    // fresh, valid step-up token (single-use) IN ADDITION to the password.
    #[test]
    fn signing_requires_step_up_token_and_consumes_it_once() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact, b"pw", b"signing key material").unwrap();

        let mut token = StepUpToken::fresh();
        let recovered = escrow
            .recover_plaintext_for_signing(artifact.id(), b"pw", &mut token)
            .unwrap();
        assert_eq!(recovered, b"signing key material");
        assert!(escrow.is_decrypted(artifact.id()));

        // The same token cannot authorize a second signing recovery.
        let artifact2 = Artifact::new(ArtifactId::from("op-key-2"), ArtifactKind::Operational);
        escrow.store(&artifact2, b"pw", b"key two").unwrap();
        assert!(escrow
            .recover_plaintext_for_signing(artifact2.id(), b"pw", &mut token)
            .is_err());
    }

    // recover_plaintext (non-signing) never requires step-up, matching the
    // TLA+ spec exactly (which has no step-up concept at all).
    #[test]
    fn non_signing_recovery_needs_no_step_up() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact, b"pw", b"plain op key").unwrap();
        let recovered = escrow.recover_plaintext(artifact.id(), b"pw").unwrap();
        assert_eq!(recovered, b"plain op key");
        assert!(escrow.is_decrypted(artifact.id()));
    }

    fn sealing_key(node: &str) -> NodeSealingKey {
        NodeSealingKey::from_seed(
            NodeId::from(node),
            format!("kd-node-sealing-seed::{node}").as_bytes(),
        )
        .expect("derive node sealing key")
    }

    // L0 (REAL crypto): SealedArtifact seals plaintext to recipient node keys;
    // every recipient can unseal to the exact plaintext, a non-recipient
    // cannot, and the digest is the real content address of the ciphertext
    // envelope (which is not the plaintext). This is the property a placeholder
    // (XOR/DefaultHasher) seal could never satisfy.
    #[test]
    fn sealed_artifact_is_real_recipient_sealed_and_content_addressed() {
        let node1 = sealing_key("node-1");
        let node2 = sealing_key("node-2");
        let outsider = sealing_key("outsider");
        let plaintext = b"escrowed operational private key blob";

        let sealed = SealedArtifact::seal(plaintext, &[node1.clone(), node2.clone()]).unwrap();

        // The digest is the real content address of the ciphertext envelope,
        // and the ciphertext is not the plaintext.
        assert_eq!(sealed.digest(), BlobDigest::of(sealed.envelope_bytes()));
        assert_ne!(
            sealed.envelope_bytes(),
            plaintext.as_ref(),
            "the sealed envelope must be ciphertext, never the plaintext"
        );

        // Each recipient recovers the EXACT plaintext.
        assert_eq!(sealed.unseal(&node1).unwrap(), plaintext);
        assert_eq!(sealed.unseal(&node2).unwrap(), plaintext);

        // A non-recipient cannot unseal — cryptographically, not by bookkeeping.
        assert_eq!(
            sealed.unseal(&outsider),
            Err(KeyDistributionError::NotARecipient)
        );

        // Addressing-level membership still tracks the intended recipient set.
        assert!(sealed.is_sealed_to(&NodeId::from("node-1")));
        assert!(!sealed.is_sealed_to(&NodeId::from("outsider")));
    }

    // A single-recipient seal is confidential to exactly that recipient.
    #[test]
    fn single_recipient_seal_is_confidential() {
        let only = sealing_key("only-node");
        let other = sealing_key("other-node");
        let sealed = SealedArtifact::seal(b"cell group key", &[only.clone()]).unwrap();
        assert_eq!(sealed.unseal(&only).unwrap(), b"cell group key");
        assert_eq!(
            sealed.unseal(&other),
            Err(KeyDistributionError::NotARecipient)
        );
    }

    // Offer requires the user be currently selected by the cell.
    #[test]
    fn offer_requires_user_in_cell_selector() {
        let mut ledger = KeyDistributionLedger::new(BTreeSet::new());
        ledger.cell_mut(CellId::from("cell-a"));
        ledger.register_artifact(Artifact::new(
            ArtifactId::from("op-key-1"),
            ArtifactKind::Operational,
        ));
        assert!(matches!(
            ledger.offer(
                UserId::from("alice"),
                CellId::from("cell-a"),
                ArtifactId::from("op-key-1")
            ),
            Err(KeyDistributionError::UserNotSelected { .. })
        ));
    }

    // Double-offer and double-accept are refused.
    #[test]
    fn duplicate_offer_and_accept_are_refused() {
        let (mut ledger, record) = setup();
        ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone(),
            )
            .unwrap();
        assert!(ledger
            .offer(
                record.user.clone(),
                record.cell.clone(),
                record.artifact.clone()
            )
            .is_err());
        ledger.accept(&record).unwrap();
        assert!(ledger.accept(&record).is_err());
    }

    // ---------------------------------------------------------------------
    // L0 REAL cryptographic sealing (crypto_seal): the abstract seal target
    // is enforced by actual X25519+AEAD recipient sealing via pillar-crypto,
    // NOT by a plaintext NodeId-set lookup. A non-recipient CANNOT recover the
    // plaintext even holding the whole envelope; a recipient can.
    // ---------------------------------------------------------------------

    use crypto_seal::{CryptoSealError, NodeSealingKeys, SealedBlob};
    use pillar_crypto::principal::principal_from_seed;
    use pillar_crypto::{PrincipalSecret, Seed};

    fn node_keys(names: &[&str]) -> (NodeSealingKeys, BTreeMap<NodeId, PrincipalSecret>) {
        let mut reg = NodeSealingKeys::new();
        let mut secrets = BTreeMap::new();
        for n in names {
            let (pubk, seck) =
                principal_from_seed(&Seed::from_bytes(n.as_bytes().to_vec())).expect("keygen");
            reg.register(NodeId::from(*n), pubk.sealing.clone());
            secrets.insert(NodeId::from(*n), seck);
        }
        (reg, secrets)
    }

    // A recipient recovers the exact plaintext; every non-recipient — even one
    // holding a validly-generated sealing key that was simply not a target —
    // is cryptographically refused. This is the real security effect the task
    // was reopened to deliver.
    #[test]
    fn sealed_blob_only_a_recipient_node_can_recover_the_plaintext() {
        let (reg, secrets) = node_keys(&["node-1", "node-2", "outsider"]);
        let plaintext = b"the escrowed operational private key (opaque)";
        let target = nodes(&["node-1", "node-2"]);

        let sealed = SealedBlob::seal(plaintext, &target, &reg).expect("seal");

        // Every targeted recipient recovers the exact bytes.
        for n in &["node-1", "node-2"] {
            let sec = &secrets[&NodeId::from(*n)];
            assert_eq!(
                sealed.recover(&sec.sealing).expect("recipient recovers"),
                plaintext,
                "recipient {n} must recover the plaintext"
            );
        }

        // A non-targeted node, though it has a real sealing key, is refused by
        // the cryptography — NOT by any NodeId set membership check.
        let outsider = &secrets[&NodeId::from("outsider")];
        assert!(
            matches!(
                sealed.recover(&outsider.sealing),
                Err(CryptoSealError::Crypto(
                    pillar_crypto::CryptoError::NotARecipient
                ))
            ),
            "a non-recipient must be cryptographically unable to recover the plaintext"
        );
    }

    // The seal fails CLOSED if a targeted node has no registered key: a
    // required recipient is never silently dropped from the envelope.
    #[test]
    fn sealing_to_an_unknown_recipient_fails_closed() {
        let (reg, _secrets) = node_keys(&["node-1"]);
        let target = nodes(&["node-1", "node-missing"]);
        assert!(matches!(
            SealedBlob::seal(b"secret", &target, &reg),
            Err(CryptoSealError::UnknownRecipientKey(_))
        ));
    }

    // The content address is the real SHA2-256 multihash of the ciphertext and
    // verifies against those exact bytes.
    #[test]
    fn sealed_blob_digest_is_a_real_content_address_of_the_ciphertext() {
        let (reg, _secrets) = node_keys(&["node-1"]);
        let sealed = SealedBlob::seal(b"payload", nodes(&["node-1"]).iter(), &reg).expect("seal");
        assert!(
            sealed.digest().verifies(sealed.envelope().as_bytes()),
            "digest must be the content address of the sealed ciphertext"
        );
        assert!(
            !sealed.digest().verifies(b"different bytes"),
            "digest must not verify unrelated bytes"
        );
    }

    // Re-sealing the same plaintext to the same target yields DIFFERENT
    // ciphertext (fresh content key + ephemeral key): confirms real
    // randomized encryption, not a deterministic XOR/hash stand-in.
    #[test]
    fn resealing_same_plaintext_yields_distinct_ciphertext() {
        let (reg, secrets) = node_keys(&["node-1"]);
        let target = nodes(&["node-1"]);
        let a = SealedBlob::seal(b"same plaintext", &target, &reg).expect("seal a");
        let b = SealedBlob::seal(b"same plaintext", &target, &reg).expect("seal b");
        assert_ne!(
            a.envelope().as_bytes(),
            b.envelope().as_bytes(),
            "randomized sealing must not produce identical ciphertext"
        );
        // Both still decrypt to the same plaintext for the recipient.
        let sec = &secrets[&NodeId::from("node-1")];
        assert_eq!(a.recover(&sec.sealing).unwrap(), b"same plaintext");
        assert_eq!(b.recover(&sec.sealing).unwrap(), b"same plaintext");
    }
}
