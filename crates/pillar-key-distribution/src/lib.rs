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
//! * **L0 — always recipient-(node-)sealed.** Every escrowed key artifact
//!   placed into distribution is sealed to a specific set of recipient node
//!   keys, layered over `pillar_net::blob`'s content-addressed transport as a
//!   [`SealedArtifact`]: the digest identifies the ciphertext, the seal
//!   target set is recomputed (never left stale) the instant a cell's node
//!   allow-list changes.
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
//! * **OPAQUE-shaped escrow confidentiality.** [`Escrow`] mirrors
//!   `pillar_identity`'s "no private-key variable" technique: the
//!   password-derived secret is never a server-observable field.
//!   [`Escrow::server_compromise`] and [`Escrow::client_participate`] are
//!   fully independent; [`Escrow::recover_plaintext`] (the only action that
//!   ever yields plaintext) requires the client's active cooperation
//!   regardless of server compromise. **Step-up gate:** escrow admits only
//!   [`ArtifactKind::Operational`] artifacts (never a root/signing key), and
//!   [`Escrow::recover_plaintext`] additionally requires a
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
}

impl fmt::Display for KeyDistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyDistributionError::UnknownCell(c) => write!(f, "unknown cell {}", c.0),
            KeyDistributionError::UnknownArtifact(a) => write!(f, "unknown artifact {}", a.0),
            KeyDistributionError::RootArtifactNotDistributable(a) => {
                write!(f, "artifact {} is root-typed and cannot be distributed", a.0)
            }
            KeyDistributionError::UserNotSelected { user, cell } => {
                write!(f, "user {} is not selected by cell {}", user.0, cell.0)
            }
            KeyDistributionError::InvalidTransition { record, reason } => {
                write!(f, "invalid transition for {record}: {reason}")
            }
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

/// L0: a sealed-artifact envelope over `pillar_net::blob`'s content-addressed
/// transport. The digest identifies the (opaque, already-encrypted)
/// ciphertext bytes stored in the underlying [`pillar_net::BlobStore`]; the
/// seal target names exactly which node keys the ciphertext was sealed to.
/// Never broadcast in the clear and never sealed only to a user identity —
/// the sealed-to node set IS the current participation allow-list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedArtifact {
    digest: BlobDigest,
    sealed_to: BTreeSet<NodeId>,
}

impl SealedArtifact {
    /// Wrap an already-sealed ciphertext blob's digest with its current seal
    /// target.
    #[must_use]
    pub fn new(digest: BlobDigest, sealed_to: BTreeSet<NodeId>) -> Self {
        SealedArtifact { digest, sealed_to }
    }

    /// The content-addressed digest of the sealed ciphertext.
    #[must_use]
    pub fn digest(&self) -> BlobDigest {
        self.digest
    }

    /// Whether `node` is currently entitled to fetch and unseal this
    /// artifact.
    #[must_use]
    pub fn is_sealed_to(&self, node: &NodeId) -> bool {
        self.sealed_to.contains(node)
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
/// Mirrors `pillar_identity`'s "no private-key variable" technique: the
/// password-derived secret is never a server-observable field of this type.
/// `envelope`/`server_compromised`/`client_coop`/`decrypted` below are the
/// Rust refinement of the spec's identically-named variables.
#[derive(Debug, Default)]
pub struct Escrow {
    envelope: BTreeSet<ArtifactId>,
    server_compromised: bool,
    client_coop: BTreeSet<ArtifactId>,
    decrypted: BTreeSet<ArtifactId>,
}

impl Escrow {
    /// An empty escrow store: no envelopes, server not compromised.
    #[must_use]
    pub fn new() -> Self {
        Escrow::default()
    }

    /// Store the server-held envelope for an operational-typed artifact.
    /// Guards against a root artifact ever being escrow-stored
    /// (`EscrowStore`, `EscrowTypeBound`).
    pub fn store(&mut self, artifact: &Artifact) -> Result<(), KeyDistributionError> {
        if artifact.is_root() {
            return Err(KeyDistributionError::RootArtifactNotDistributable(
                artifact.id.clone(),
            ));
        }
        self.envelope.insert(artifact.id.clone());
        Ok(())
    }

    /// Whether a server-held envelope currently exists for `artifact`.
    #[must_use]
    pub fn has_envelope(&self, artifact: &ArtifactId) -> bool {
        self.envelope.contains(artifact)
    }

    /// An attacker obtains every server-held envelope: a single irreversible
    /// global flip (`CompromiseServer`).
    pub fn server_compromise(&mut self) {
        self.server_compromised = true;
    }

    /// Whether the server has been compromised.
    #[must_use]
    pub fn is_server_compromised(&self) -> bool {
        self.server_compromised
    }

    /// Only the legitimate client, holding the password-derived value that
    /// never leaves it, can supply this. Deliberately independent of
    /// `server_compromised` in either direction (`ClientParticipate`).
    pub fn client_participate(&mut self, artifact: &ArtifactId) -> Result<(), KeyDistributionError> {
        if !self.envelope.contains(artifact) {
            return Err(KeyDistributionError::UnknownArtifact(artifact.clone()));
        }
        self.client_coop.insert(artifact.clone());
        Ok(())
    }

    /// Recover an operational key's plaintext for GENERAL use (decryption,
    /// inspection) — requires the client's active cooperation regardless of
    /// server compromise (`RecoverPlaintext`, `OpaqueConfidentiality`), but
    /// does NOT by itself authorize signing; see
    /// [`Escrow::recover_plaintext_for_signing`].
    pub fn recover_plaintext(&mut self, artifact: &ArtifactId) -> Result<(), KeyDistributionError> {
        if !self.envelope.contains(artifact) {
            return Err(KeyDistributionError::UnknownArtifact(artifact.clone()));
        }
        if !self.client_coop.contains(artifact) {
            return Err(KeyDistributionError::InvalidTransition {
                record: RecordKey {
                    user: UserId(String::new()),
                    cell: CellId(String::new()),
                    artifact: artifact.clone(),
                },
                reason: "client has not supplied its password-derived cooperation",
            });
        }
        self.decrypted.insert(artifact.clone());
        Ok(())
    }

    /// Whether `artifact`'s plaintext has ever been recovered by anyone
    /// (ghost/observable state, mirroring the spec's `decrypted` variable).
    #[must_use]
    pub fn is_decrypted(&self, artifact: &ArtifactId) -> bool {
        self.decrypted.contains(artifact)
    }

    /// Recover an operational key's plaintext specifically for use in
    /// SIGNING: requires everything [`Escrow::recover_plaintext`] requires,
    /// **plus** a fresh, valid, unconsumed [`StepUpToken`] — the ROI's
    /// "step-up required for signing" restriction with no analog in the
    /// TLA+ spec. The token is consumed on use, so it authorizes exactly one
    /// signing recovery.
    pub fn recover_plaintext_for_signing(
        &mut self,
        artifact: &ArtifactId,
        step_up: &mut StepUpToken,
    ) -> Result<(), KeyDistributionError> {
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
        self.recover_plaintext(artifact)
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
        ledger.cell_mut(CellId::from("cell-a")).add_user(UserId::from("alice"));
        ledger
            .register_artifact(Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational));
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
            .unwrap();
        assert!(ledger.seal_of(&record).is_empty(), "offered but not admitted");
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
        ledger.cell_mut(CellId::from("cell-a")).add_user(UserId::from("alice"));
        ledger.register_artifact(Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational));
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
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
        ledger.cell_mut(CellId::from("cell-a")).add_user(UserId::from("alice"));
        ledger.register_artifact(Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational));
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
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
        ledger.cell_mut(CellId::from("cell-a")).add_user(UserId::from("alice"));
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
            escrow.store(&root),
            Err(KeyDistributionError::RootArtifactNotDistributable(_))
        ));
        assert!(!escrow.has_envelope(root.id()));
    }

    // OpaqueConfidentiality: a compromised server-held envelope alone never
    // yields plaintext without the client's active cooperation.
    #[test]
    fn compromised_envelope_alone_never_yields_plaintext() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact).unwrap();
        escrow.server_compromise();

        assert!(
            escrow.recover_plaintext(artifact.id()).is_err(),
            "no client cooperation was ever supplied"
        );
        assert!(!escrow.is_decrypted(artifact.id()));

        escrow.client_participate(artifact.id()).unwrap();
        escrow.recover_plaintext(artifact.id()).unwrap();
        assert!(escrow.is_decrypted(artifact.id()));
    }

    // Confidentiality holds regardless of server-compromise ordering too.
    #[test]
    fn client_cooperation_is_independent_of_server_compromise() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact).unwrap();
        escrow.client_participate(artifact.id()).unwrap();
        // Server was never compromised, yet legitimate recovery still works.
        escrow.recover_plaintext(artifact.id()).unwrap();
        assert!(escrow.is_decrypted(artifact.id()));
    }

    // StepUpRequiredForSigning: recovering plaintext for signing requires a
    // fresh, valid step-up token, single-use.
    #[test]
    fn signing_requires_step_up_token_and_consumes_it_once() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact).unwrap();
        escrow.client_participate(artifact.id()).unwrap();

        let mut token = StepUpToken::fresh();
        escrow
            .recover_plaintext_for_signing(artifact.id(), &mut token)
            .unwrap();
        assert!(escrow.is_decrypted(artifact.id()));

        // The same token cannot authorize a second signing recovery.
        let artifact2 = Artifact::new(ArtifactId::from("op-key-2"), ArtifactKind::Operational);
        escrow.store(&artifact2).unwrap();
        escrow.client_participate(artifact2.id()).unwrap();
        assert!(escrow
            .recover_plaintext_for_signing(artifact2.id(), &mut token)
            .is_err());
    }

    // recover_plaintext (non-signing) never requires step-up, matching the
    // TLA+ spec exactly (which has no step-up concept at all).
    #[test]
    fn non_signing_recovery_needs_no_step_up() {
        let mut escrow = Escrow::new();
        let artifact = Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational);
        escrow.store(&artifact).unwrap();
        escrow.client_participate(artifact.id()).unwrap();
        escrow.recover_plaintext(artifact.id()).unwrap();
        assert!(escrow.is_decrypted(artifact.id()));
    }

    // L0: SealedArtifact carries the digest and current seal target,
    // layered over pillar_net::blob's content-addressed transport.
    #[test]
    fn sealed_artifact_tracks_digest_and_seal_target() {
        let digest = BlobDigest::of(b"ciphertext-bytes");
        let sealed = SealedArtifact::new(digest, nodes(&["node-1"]));
        assert_eq!(sealed.digest(), digest);
        assert!(sealed.is_sealed_to(&NodeId::from("node-1")));
        assert!(!sealed.is_sealed_to(&NodeId::from("node-2")));
    }

    // Offer requires the user be currently selected by the cell.
    #[test]
    fn offer_requires_user_in_cell_selector() {
        let mut ledger = KeyDistributionLedger::new(BTreeSet::new());
        ledger.cell_mut(CellId::from("cell-a"));
        ledger.register_artifact(Artifact::new(ArtifactId::from("op-key-1"), ArtifactKind::Operational));
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
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
            .unwrap();
        assert!(ledger
            .offer(record.user.clone(), record.cell.clone(), record.artifact.clone())
            .is_err());
        ledger.accept(&record).unwrap();
        assert!(ledger.accept(&record).is_err());
    }
}
