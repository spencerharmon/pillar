//! Content-addressed op-log CRDT — the Rust refinement of `specs/StreamingDB.tla`.
//!
//! Each op is identified by its content address (a hash of its payload), so an
//! op's identity is a pure function of its bytes: two nodes holding the same
//! op necessarily agree on its identity. The log itself is a grow-only set of
//! such ops — a state-based CRDT (CvRDT) whose merge is set union
//! (commutative, associative, idempotent) — modelling `Write`/`Gossip` in the
//! spec. On top of the log sits a deterministic materialized view: a
//! per-partition order (`Order` in the spec) and Merkle root (`Root`) that are
//! pure functions of the delivered op *set*, never of the path/order by which
//! ops were appended or gossiped in.
//!
//! A [`Snapshot`] is a content-addressed compaction of a log at a point in
//! time. A fresh peer bootstraps by taking a snapshot plus the log "tail"
//! appended since — [`OpLog::bootstrap`] — and ends up holding exactly the
//! same op set (and therefore the same materialized view) as a peer that
//! received every op individually, matching `NoLostWrite` /
//! `LogSubsetOfWritten` in the spec: compaction never loses an op, it only
//! repackages the set.

use std::collections::BTreeMap;
use std::fmt;

use pillar_core::{SideEffect, ViewPolicy};

/// The current schema version of the durable materialized-view surface — the
/// serializable [`Snapshot`] that carries a compacted op-log's materialized
/// view (Merkle root + op set) to a bootstrapping peer.
///
/// This is its OWN independent version line, unrelated to the event-envelope,
/// manifest, or any other surface's `v1`: it advances only when the
/// `Snapshot`/materialized-view schema itself changes shape (per ROI P1
/// "Versioning, compatibility & safe rollout" / the `IndependentVersioning`
/// property in `specs/VersioningCompat.tla`).
pub const SCHEMA_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);

/// The lowest materialized-view schema version this build can still read. Kept
/// as its own constant (currently == [`SCHEMA_VERSION`]) so a future build can
/// widen the accepted window (`MIN_SCHEMA_VERSION..=SCHEMA_VERSION`) without
/// touching the stamping side.
pub const MIN_SCHEMA_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);

mod persist;
pub use persist::{PersistError, PersistentStream};

pub mod cofold;
pub use cofold::{CoFoldError, CoFoldInvariant, QuotaCeiling, StrictCofold, UniqueOnce};

// SignedSegment/Cid/HeadRecord/Visibility/ContentStore/IpfsBackend moved DOWN
// to `pillar-wire` (the shared wire/persistence substrate every one of
// pillar-streamdb/pillar-observability/pillar-net rides) per
// `docs/papers/pillar-message-format.md` §3. Re-exported here, under the
// SAME module paths (`crate::store::*`, `crate::ipfs_backend::*`) so every
// existing internal (`crate::store::Cid`) and external (`pillar_streamdb::
// store::Cid`) call site keeps working unchanged — no behavior change.
pub mod store {
    //! Re-export of [`pillar_wire::store`] — see the `pillar-wire` crate docs.
    pub use pillar_wire::store::*;
}
pub use store::{
    Cid, ContentStore, HeadRecord, SegmentSource, SignedSegment, StoreError, Visibility,
};

pub mod ipfs_backend {
    //! Re-export of [`pillar_wire::ipfs_backend`] — see the `pillar-wire`
    //! crate docs.
    pub use pillar_wire::ipfs_backend::*;
}
pub use ipfs_backend::IpfsBackend;
#[cfg(feature = "ipfs")]
pub use ipfs_backend::{cid_to_cidv1_raw, cidv1_raw_to_cid, NativeIpfsBackend};

mod ipfs_persist;
pub use ipfs_persist::{IpfsPersistError, IpfsPersistentStream};

pub mod pillarmsg;
pub use pillarmsg::{
    decode_stream_op_segment_payload, encode_stream_op_segment_payload, open_stream_op,
    seal_stream_op, Confidentiality, StreamOpMessageError,
};

/// A collection's declared confidentiality/visibility-class policy
/// (`public-visibility-class`) — the CollectionPolicy attribute a catalog
/// visibility-class report surfaces as user-viewable/editable. It carries
/// ONLY the confidentiality axis today (which
/// [`pillarmsg::Confidentiality`] an [`IpfsPersistentStream`] backing the
/// collection is constructed/rehydrated with); node PLACEMENT (which nodes
/// hold the collection) is a separate, orthogonal policy
/// (`pillar_net::CollectionPlacement`, `data-placement-collection-tags`).
///
/// Defaults to [`Confidentiality::CellEncrypted`] — the ROI's stated
/// default — so a collection is opt-IN to `public`, never opt-out of
/// confidentiality by omission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct CollectionPolicy {
    /// This collection's confidentiality class.
    pub confidentiality: Confidentiality,
}

impl CollectionPolicy {
    /// The default `cell-encrypted` collection policy.
    #[must_use]
    pub fn cell_encrypted() -> Self {
        CollectionPolicy {
            confidentiality: Confidentiality::CellEncrypted,
        }
    }

    /// A `public` (unsealed) collection policy: no AEAD/cell-group-key
    /// confidentiality seal, world-readable, but per-op signing and
    /// content-addressing are unaffected — see [`Confidentiality::Public`].
    #[must_use]
    pub fn public() -> Self {
        CollectionPolicy {
            confidentiality: Confidentiality::Public,
        }
    }

    /// Whether this collection's records carry no confidentiality seal.
    #[must_use]
    pub fn is_public(&self) -> bool {
        matches!(self.confidentiality, Confidentiality::Public)
    }
}

/// A durable op-log both persistent stream implementations satisfy, so
/// transport-level sync ([`pillar_net::apply_op_sync`]) can drive EITHER the
/// local-fs [`PersistentStream`] or the IPFS-backed [`IpfsPersistentStream`]
/// through one code path. It exposes exactly what op-sync needs: read the
/// current op set, and admit a convergent op (persisting it through whichever
/// durability layer backs the implementor).
pub trait OpSyncTarget {
    /// The current materialized op-log (for `have`/gap computation).
    fn log(&self) -> &OpLog;
    /// Append `payload` as a [`SideEffect::Convergent`] op, persisting it. A
    /// policy refusal or durability fault leaves the set unchanged (the caller
    /// re-reads [`OpSyncTarget::log`] to count what was actually admitted).
    fn append_convergent(&mut self, payload: Vec<u8>);
}

impl OpSyncTarget for PersistentStream {
    fn log(&self) -> &OpLog {
        self.stream().log()
    }
    fn append_convergent(&mut self, payload: Vec<u8>) {
        let _ = self.append(payload, SideEffect::Convergent);
    }
}

impl OpSyncTarget for IpfsPersistentStream {
    fn log(&self) -> &OpLog {
        self.stream().log()
    }
    fn append_convergent(&mut self, payload: Vec<u8>) {
        let _ = self.append(payload, SideEffect::Convergent);
    }
}

pub mod geo_replication;
pub use geo_replication::{RemoteReplica, ReplicationError, ReplicationGrant, ReplicationTrust};

/// A content address: the identity of an [`Op`], derived purely from its
/// payload bytes via a **collision-resistant cryptographic** hash.
///
/// Mirrors `Ops \subseteq Nat` in the spec, where an op's id IS its content
/// address — two ops with the same id necessarily have the same content. Here
/// that identity is a real SHA2-256 multihash (see [`content_address`]), not a
/// checksum: a non-cryptographic hash (FNV, SipHash, `DefaultHasher`) is *not*
/// a content address, because an adversary can forge a distinct payload sharing
/// the same address and thereby impersonate an op across gossip. The underlying
/// bytes are the self-describing multihash produced by
/// [`pillar_crypto::content::content_address`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpId(pub pillar_crypto::ContentId);

impl OpId {
    /// The raw multihash bytes of this content address.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The content address as lowercase hex of its multihash bytes — the
    /// canonical string form used in URLs, wire encodings, and logs.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.as_bytes().len() * 2);
        for b in self.as_bytes() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parse a content address from its lowercase-hex string form (the inverse
    /// of [`OpId::to_hex`]). Returns `None` for any non-hex / odd-length input.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.is_empty() || s.len() % 2 != 0 {
            return None;
        }
        let raw = s.as_bytes();
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i < raw.len() {
            let hi = (raw[i] as char).to_digit(16)?;
            let lo = (raw[i + 1] as char).to_digit(16)?;
            bytes.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        Some(OpId(pillar_crypto::ContentId::from_bytes(bytes)))
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// `ContentId` is an opaque byte container that is `Eq + Hash` but deliberately
// not `Ord` (the crypto layer treats it as opaque). The op-log keys a
// `BTreeMap` on the content address to get a deterministic, content-derived
// per-partition order (`Order`/`SortSet` in the spec), so we impose a total
// order here by lexicographic comparison of the multihash bytes — a pure
// function of content, identical on every node.
impl PartialOrd for OpId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OpId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

/// Deterministic, collision-resistant content address of an arbitrary byte
/// payload.
///
/// This is the SAME pure bytes->identity function the op-log uses for
/// [`OpId`], exposed so other Pillar layers (e.g. content-addressed blob /
/// OCI-layer distribution over the network transport) derive a blob's digest
/// with the identical, canonical content-addressing rather than reinventing
/// one. Two nodes holding the same bytes necessarily agree on the address, and
/// — because it delegates to [`pillar_crypto::content::content_address`] (a
/// real SHA2-256 multihash) — no adversary can construct a distinct payload
/// sharing the address.
#[must_use]
pub fn content_address(bytes: &[u8]) -> pillar_crypto::ContentId {
    // The crypto content-addressing function is infallible for an in-memory
    // byte slice (it computes a SHA2-256 digest); surface any error as a panic
    // rather than threading a `Result` through the CRDT identity, since a
    // failure here would mean the crypto primitive itself is broken.
    pillar_crypto::content::content_address(bytes)
        .expect("SHA2-256 content addressing is infallible for an in-memory payload")
}

/// A single appended operation: its content-addressed id plus its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    id: OpId,
    payload: Vec<u8>,
}

impl Op {
    /// Build an op from its payload, deriving its content-addressed id.
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        let id = OpId(content_address(&payload));
        Op { id, payload }
    }

    /// The op's content address.
    #[must_use]
    pub fn id(&self) -> OpId {
        self.id.clone()
    }

    /// The op's raw payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A caller-supplied superseding policy for [`OpLog::compact_reclaiming`].
///
/// The generic [`OpLog`] is payload-opaque — it has no idea whether one op's
/// bytes "supersede" another's — so real space reclamation is only safe when
/// a caller who DOES understand its own payload semantics (e.g. the keyed
/// store's per-field last-writer-wins fold) supplies one. Implement this
/// trait to say which ops compete (`group_key`) and, among competitors, which
/// one wins (`priority`); [`OpLog::compact_reclaiming`] discards every
/// non-winner.
pub trait ReclaimPolicy {
    /// The competing group this op belongs to (e.g. a keyed store's
    /// `(collection, id, field)`), or `None` if this op is not subject to
    /// reclamation under this policy — such an op is NEVER discarded.
    fn group_key(&self, op: &Op) -> Option<Vec<u8>>;

    /// A byte-lexicographically comparable priority within `group_key`'s
    /// group: strictly higher bytes win. Only ever called for an op
    /// `group_key` returned `Some` for. Must encode the SAME total order the
    /// caller's own fold uses to pick a winner (e.g. the keyed store's HLC
    /// `happens_after`), or compaction and the live fold could disagree on
    /// which op is authoritative.
    fn priority(&self, op: &Op) -> Vec<u8>;
}

/// A grow-only, content-addressed op-log: `log[n]` in the spec.
///
/// Backed by a `BTreeMap` keyed on [`OpId`] so the per-partition materialized
/// [`OpLog::order`] falls out of the map's natural iteration order — the
/// implementation of the spec's `SortSet`/`Order`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpLog {
    ops: BTreeMap<OpId, Op>,
}

impl OpLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        OpLog::default()
    }

    /// Append `payload` as a fresh op and return its content address.
    ///
    /// Idempotent by construction: appending the same payload twice yields
    /// the same [`OpId`] and leaves the set unchanged (`Write` in the spec is
    /// only enabled for an op the node does not yet hold; here re-appending
    /// simply no-ops rather than being disallowed, since the log is a set).
    pub fn append(&mut self, payload: impl Into<Vec<u8>>) -> OpId {
        let op = Op::new(payload.into());
        let id = op.id.clone();
        self.ops.entry(id.clone()).or_insert(op);
        id
    }

    /// Whether this log already holds `id`.
    #[must_use]
    pub fn contains(&self, id: &OpId) -> bool {
        self.ops.contains_key(id)
    }

    /// Number of ops held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the log holds no ops.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Merge `other`'s ops into `self` — `Gossip` in the spec: set union, the
    /// CvRDT join. Commutative, associative, and idempotent: merging the same
    /// source repeatedly, or in any order, converges to the same set.
    pub fn merge(&mut self, other: &OpLog) {
        for (id, op) in &other.ops {
            self.ops.entry(id.clone()).or_insert_with(|| op.clone());
        }
    }

    /// The deterministic per-partition materialized order: ops sorted by
    /// content address, ascending. A pure function of the op *set* — `Order`
    /// in the spec.
    #[must_use]
    pub fn order(&self) -> Vec<&Op> {
        self.ops.values().collect()
    }

    /// The set of content addresses currently held.
    pub fn ids(&self) -> impl Iterator<Item = OpId> + '_ {
        self.ops.keys().cloned()
    }

    /// The Merkle root: a **cryptographic** hash-chain fold over the
    /// content-ordered ops. Deterministic in the op set alone (the order is
    /// itself derived from each op's content address) — `Root`/`FoldRoot` in
    /// the spec. Two nodes holding the same set always compute the same root,
    /// regardless of gossip path, and — because each fold step is a real
    /// SHA2-256 over `(accumulator || op-address)` — the root is a
    /// collision-resistant commitment to the exact set, not a reversible/
    /// forgeable arithmetic mix.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        fold_root(&self.order())
    }

    /// Compact this log into a content-addressed [`Snapshot`] of its current
    /// state. The snapshot carries the full op set (compaction repackages,
    /// never discards) so a peer that bootstraps from it plus the log's tail
    /// ends up with exactly this set.
    ///
    /// This is the conservative, payload-opaque compaction: the generic log
    /// has no notion of "superseded" for an arbitrary byte payload, so it
    /// never discards. A caller whose payloads carry their OWN superseding
    /// semantics (per-key last-writer-wins, tombstones — e.g. the keyed
    /// store's per-field fold) reclaims real space with
    /// [`OpLog::compact_reclaiming`] instead.
    #[must_use]
    pub fn compact(&self) -> Snapshot {
        Snapshot::new(self.root(), self.ops.clone())
    }

    /// Compact this log into a [`Snapshot`] that DISCARDS any op fully
    /// subsumed by `policy` — the space-reclaiming counterpart of
    /// [`OpLog::compact`].
    ///
    /// `policy` groups ops that compete over the same logical slot (e.g. a
    /// keyed store's `(collection, id, field)`) and, within a group, orders
    /// them by priority (e.g. HLC); every op EXCEPT the highest-priority one
    /// in its group is safely discardable, because no fold over the
    /// surviving set can ever observe it: the fold `specs/KeyedStore.tla`
    /// proves (`DeterministicLWWTiebreak`) is a pure function of the
    /// *winning* op per group, and dropping every other op for that group
    /// cannot change any read of the winner. An op `policy` assigns no group
    /// to (`ReclaimPolicy::group_key` returns `None`) is NEVER discarded —
    /// exactly [`OpLog::compact`]'s behavior for that op.
    ///
    /// Because [`OpLog::bootstrap`] simply unions a snapshot's ops with a
    /// tail, and the per-group winner of `kept ∪ tail` always equals the
    /// per-group winner of `discarded ∪ kept ∪ tail` (the discarded ops were,
    /// by construction, never the max within their group at snapshot time,
    /// and adding MORE candidates to a max computation cannot make a
    /// strictly-smaller candidate the max), a peer that bootstraps from this
    /// snapshot plus the tail reconstructs the IDENTICAL per-group winner —
    /// and therefore the identical materialized keyed-store view — as a peer
    /// that replayed every op individually. No per-op verifiability,
    /// convergence, or CAP-policy guarantee is weakened: every surviving op
    /// is still content-addressed and individually verifiable, and the
    /// resulting op set still folds to a real, deterministic Merkle root.
    #[must_use]
    pub fn compact_reclaiming(&self, policy: &dyn ReclaimPolicy) -> Snapshot {
        // group_key -> (priority, OpId) of the current best-known winner.
        // OpId is included in the comparison purely as a deterministic
        // tiebreak so the result never depends on BTreeMap iteration nuance.
        let mut winners: BTreeMap<Vec<u8>, (Vec<u8>, OpId)> = BTreeMap::new();
        let mut kept: BTreeMap<OpId, Op> = BTreeMap::new();

        for op in self.ops.values() {
            match policy.group_key(op) {
                None => {
                    // Not subject to reclamation: always kept.
                    kept.insert(op.id.clone(), op.clone());
                }
                Some(key) => {
                    let candidate = (policy.priority(op), op.id.clone());
                    match winners.get(&key) {
                        Some(current_best) if *current_best >= candidate => {}
                        _ => {
                            winners.insert(key, candidate);
                        }
                    }
                }
            }
        }
        for (_, (_, winner_id)) in winners {
            if let Some(op) = self.ops.get(&winner_id) {
                kept.insert(winner_id, op.clone());
            }
        }

        let root = fold_root(&kept.values().collect::<Vec<_>>());
        Snapshot::new(root, kept)
    }

    /// Bootstrap a fresh log from a [`Snapshot`] plus the tail of ops
    /// appended since it was taken. Equivalent to replaying every op
    /// individually: the resulting log holds exactly `snapshot`'s ops union
    /// `tail`'s ops, so it converges to the same materialized view (order,
    /// root) as a peer that received the full history via gossip.
    #[must_use]
    pub fn bootstrap(snapshot: &Snapshot, tail: &[Op]) -> Self {
        let mut log = OpLog {
            ops: snapshot.ops.clone(),
        };
        for op in tail {
            log.ops.entry(op.id.clone()).or_insert_with(|| op.clone());
        }
        log
    }

    /// Bootstrap from a [`Snapshot`] plus tail, but FIRST reject a snapshot
    /// stamped with a materialized-view schema version this build does not
    /// understand.
    ///
    /// This is the fallible loading path: it distinguishes a
    /// stamped-but-unknown-FUTURE view-schema ([`BootstrapError::Unsupported`],
    /// carrying the underlying [`pillar_crypto::VersionError::Unsupported`])
    /// from the Merkle-root corruption path — the two failure modes the ROI
    /// requires be kept apart. On an accepted version it is identical to
    /// [`OpLog::bootstrap`].
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::Unsupported`] if the snapshot's
    /// [`Snapshot::schema_version`] falls outside
    /// `MIN_SCHEMA_VERSION..=SCHEMA_VERSION`.
    pub fn bootstrap_checked(snapshot: &Snapshot, tail: &[Op]) -> Result<Self, BootstrapError> {
        snapshot
            .check_schema_version()
            .map_err(BootstrapError::Unsupported)?;
        Ok(OpLog::bootstrap(snapshot, tail))
    }
}

/// A failure reconstructing an [`OpLog`] from a [`Snapshot`] via
/// [`OpLog::bootstrap_checked`].
///
/// Deliberately keeps an unknown-FUTURE materialized-view schema version
/// ([`BootstrapError::Unsupported`]) as its OWN variant, distinct from any
/// corrupt/mismatched-Merkle-root failure: a newer-peer snapshot is a
/// negotiable compatibility signal, not corruption (ROI P1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The snapshot parsed cleanly but carries a materialized-view schema
    /// version outside `MIN_SCHEMA_VERSION..=SCHEMA_VERSION` — most importantly
    /// a version NEWER than this build understands. Wraps the shared
    /// [`pillar_crypto::VersionError`] (always its `Unsupported` case here).
    Unsupported(pillar_crypto::VersionError),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::Unsupported(e) => {
                write!(
                    f,
                    "snapshot has an unsupported materialized-view schema: {e}"
                )
            }
        }
    }
}

impl std::error::Error for BootstrapError {}

/// A cryptographic Merkle root: a collision-resistant commitment to an op
/// *set*, produced by [`OpLog::root`].
///
/// The bytes are a real SHA2-256 digest of the content-ordered op addresses,
/// so two roots are equal iff (with cryptographic confidence) the two logs hold
/// the same op set. A `u64` arithmetic fold (the previous FNV/modular-mix
/// placeholder) could not offer this: distinct sets collide trivially under a
/// 64-bit non-cryptographic mix.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MerkleRoot(Vec<u8>);

impl MerkleRoot {
    /// The raw digest bytes of this Merkle root.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The Merkle root as lowercase hex — its canonical string form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Fold the content-ordered ops into a cryptographic Merkle root.
///
/// The fold is a hash chain: starting from the SHA2-256 of a fixed domain-
/// separation tag, each op folds in as `H(accumulator || op-content-address)`.
/// Because the ops are already in content-derived order and each address is
/// itself a collision-resistant hash of the op's bytes, the resulting root is a
/// deterministic, collision-resistant commitment to the op *set* — identical on
/// every node holding that set, and infeasible to forge a colliding set for.
fn fold_root(ops: &[&Op]) -> MerkleRoot {
    use sha2::{Digest, Sha256};
    // Domain separation so a streamdb Merkle root can never be confused with a
    // bare content address of the same bytes.
    let mut acc: Vec<u8> = Sha256::digest(b"pillar-streamdb-merkle-root-v1").to_vec();
    for op in ops {
        let mut hasher = Sha256::new();
        hasher.update(&acc);
        hasher.update(op.id.as_bytes());
        acc = hasher.finalize().to_vec();
    }
    MerkleRoot(acc)
}

/// A content-addressed compaction of an [`OpLog`] at a point in time.
///
/// Carries the full set of ops it summarizes (never a lossy digest alone) so
/// that [`OpLog::bootstrap`] from a snapshot plus a subsequent tail
/// reconstructs the identical op set a continuously-gossiped peer would hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    root: MerkleRoot,
    ops: BTreeMap<OpId, Op>,
    /// The materialized-view schema version this snapshot was produced under.
    ///
    /// Deliberately NOT folded into `root` / the content address: the Merkle
    /// root is a commitment to the op *set* (`Root`/`FoldRoot` in the spec),
    /// and the whole convergence contract (`DeterministicMerkleRoot`,
    /// `bootstrap_from_snapshot_and_tail_matches_full_history`) is that two
    /// peers holding the same op set compute the same root regardless of how
    /// they packaged it. Mixing the packaging-format version into that
    /// commitment would make a snapshot's root differ from the live log's root
    /// for the identical set, breaking that equality. The schema version is a
    /// property of the CARRIER, not of the summarized state, so it is checked
    /// separately ([`Snapshot::check_schema_version`]) rather than being made
    /// tamper-evident through the set commitment.
    schema_version: pillar_crypto::SurfaceVersion,
}

impl Snapshot {
    /// Construct a snapshot over `root` + `ops`, stamping it with the current
    /// [`SCHEMA_VERSION`] of the materialized-view surface. The single
    /// construction helper so every production and test call site stamps
    /// identically.
    #[must_use]
    fn new(root: MerkleRoot, ops: BTreeMap<OpId, Op>) -> Self {
        Snapshot {
            root,
            ops,
            schema_version: SCHEMA_VERSION,
        }
    }

    /// The Merkle root this snapshot was taken at.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        self.root.clone()
    }

    /// The materialized-view schema version stamped on this snapshot.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        self.schema_version
    }

    /// Verify this snapshot's materialized-view schema version is one this
    /// build can interpret (`MIN_SCHEMA_VERSION..=SCHEMA_VERSION`).
    ///
    /// A stamped-but-unknown FUTURE version yields
    /// [`pillar_crypto::VersionError::Unsupported`] — distinct from any
    /// corruption / Merkle-root-mismatch failure, so a newer-peer snapshot is
    /// treated as a negotiable compatibility signal, not corruption.
    ///
    /// # Errors
    ///
    /// Returns [`pillar_crypto::VersionError::Unsupported`] if the stamp falls
    /// outside `MIN_SCHEMA_VERSION..=SCHEMA_VERSION`.
    pub fn check_schema_version(&self) -> Result<(), pillar_crypto::VersionError> {
        self.schema_version
            .check_supported(MIN_SCHEMA_VERSION, SCHEMA_VERSION)
    }

    /// Number of ops summarized by this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the snapshot summarizes no ops.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// A stream (equivalently, a single partition) admitting ops under a
/// [`ViewPolicy`].
///
/// The policy attaches to the stream itself, not to any individual view: it
/// is the safe-by-default admission gate declared once for the resource
/// (`docs/consistency-model.md`), and every [`View`] taken over the stream
/// inherits it (`Stream::view`). Unspecified -> [`ViewPolicy::Strict`] (CP):
/// [`Stream::new`] defaults to the safe side of the CAP choice so a caller
/// who forgets to classify a resource gets the conservative behavior, never
/// a silently-relaxed one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stream {
    log: OpLog,
    policy: Option<ViewPolicy>,
}

/// A stream/view's declared policy defaulted because none was specified.
/// Mirrors "unspecified -> CP" in `docs/consistency-model.md`.
const DEFAULT_POLICY: ViewPolicy = ViewPolicy::Strict;

impl Stream {
    /// A fresh, empty stream with no explicit policy: safe-by-default,
    /// admitting only what [`ViewPolicy::Strict`] admits (i.e. everything),
    /// per the CP-unless-declared-otherwise rule.
    #[must_use]
    pub fn new() -> Self {
        Stream {
            log: OpLog::new(),
            policy: None,
        }
    }

    /// A fresh, empty stream/partition with an explicit declared policy.
    #[must_use]
    pub fn with_policy(policy: ViewPolicy) -> Self {
        Stream {
            log: OpLog::new(),
            policy: Some(policy),
        }
    }

    /// This stream's effective policy: the declared one, or
    /// [`ViewPolicy::Strict`] if none was ever declared (safe-by-default).
    #[must_use]
    pub fn policy(&self) -> ViewPolicy {
        self.policy.unwrap_or(DEFAULT_POLICY)
    }

    /// Declare (or change) this stream's policy.
    pub fn set_policy(&mut self, policy: ViewPolicy) {
        self.policy = Some(policy);
    }

    /// Append `payload` as a fresh op, refusing the write if this stream's
    /// policy does not admit `effect`.
    ///
    /// This is the real-stream admission wiring for
    /// `pillar_core::ViewPolicy::admits`: a non-idempotent
    /// ([`SideEffect::Exclusive`]) effect is refused outright on a stream
    /// whose (possibly defaulted) policy is [`ViewPolicy::Relaxed`] (AP),
    /// never merely warned about.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyViolation`] if `effect` is not admitted by this
    /// stream's policy; the log is left unchanged.
    pub fn try_append(
        &mut self,
        payload: impl Into<Vec<u8>>,
        effect: SideEffect,
    ) -> Result<OpId, PolicyViolation> {
        let policy = self.policy();
        if !policy.admits(effect) {
            return Err(PolicyViolation { policy, effect });
        }
        Ok(self.log.append(payload))
    }

    /// Merge another stream's log into this one (the underlying CvRDT
    /// `Gossip` join). Policy is a local admission concern, not part of the
    /// replicated state, so merging never changes `self`'s declared policy.
    pub fn merge(&mut self, other: &Stream) {
        self.log.merge(&other.log);
    }

    /// A read-only [`View`] over this stream, inheriting its current
    /// effective policy.
    #[must_use]
    pub fn view(&self) -> View<'_> {
        View {
            log: &self.log,
            policy: self.policy(),
        }
    }

    /// The underlying op-log, for read access that does not need the policy
    /// (e.g. gossip/snapshot plumbing).
    #[must_use]
    pub fn log(&self) -> &OpLog {
        &self.log
    }

    /// Mutable access to the underlying op-log, for the durable backend
    /// ([`PersistentStream`]) to record an op whose admission it has already
    /// enforced and whose bytes it has already persisted. Not a general-purpose
    /// bypass of [`Stream::try_append`]'s policy gate.
    pub(crate) fn log_mut(&mut self) -> &mut OpLog {
        &mut self.log
    }
}

/// A read-only view over a [`Stream`], carrying the policy it inherited from
/// that stream at the time it was taken.
///
/// Views never declare their own policy: the whole point of attaching the
/// policy to the stream/partition is that every consumer of that stream sees
/// the same admission rule, so a view cannot silently opt itself into a more
/// permissive class than its stream allows.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    log: &'a OpLog,
    policy: ViewPolicy,
}

impl View<'_> {
    /// The policy this view inherited from its stream.
    #[must_use]
    pub fn policy(&self) -> ViewPolicy {
        self.policy
    }

    /// Whether an action with the given side effect may run against this
    /// view, per the inherited policy.
    #[must_use]
    pub fn admits(&self, effect: SideEffect) -> bool {
        self.policy.admits(effect)
    }

    /// The view's materialized order, delegating to the underlying log.
    #[must_use]
    pub fn order(&self) -> Vec<&Op> {
        self.log.order()
    }

    /// The view's Merkle root, delegating to the underlying log.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        self.log.root()
    }

    /// The materialized-view schema version this live view advertises — the
    /// same [`SCHEMA_VERSION`] a [`Snapshot`] materialized from it would carry.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        SCHEMA_VERSION
    }
}

/// A [`SideEffect`] refused by a stream/view's [`ViewPolicy`].
///
/// Constructed only by [`Stream::try_append`] when the effective policy does
/// not [`ViewPolicy::admits`] the requested effect (safe-by-default: this is
/// always an `Exclusive` effect meeting a `Relaxed` policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyViolation {
    policy: ViewPolicy,
    effect: SideEffect,
}

impl PolicyViolation {
    /// Construct a policy violation for a refused effect. Used by the durable
    /// backend ([`PersistentStream`]) to surface the same refusal the in-memory
    /// [`Stream::try_append`] raises.
    pub(crate) fn new(policy: ViewPolicy, effect: SideEffect) -> Self {
        PolicyViolation { policy, effect }
    }

    /// The policy that refused the effect.
    #[must_use]
    pub fn policy(&self) -> ViewPolicy {
        self.policy
    }

    /// The refused effect.
    #[must_use]
    pub fn effect(&self) -> SideEffect {
        self.effect
    }
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} side effect refused under {:?} view policy",
            self.effect, self.policy
        )
    }
}

impl std::error::Error for PolicyViolation {}

#[cfg(test)]
mod tests {
    use super::*;

    /// ROI non-negotiable #7 (real cryptography only): the content address is a
    /// REAL collision-resistant cryptographic multihash, NOT a 64-bit checksum.
    /// This test pins the two properties a placeholder (FNV/SipHash/`DefaultHasher`
    /// u64) could never satisfy, so a regression back to a checksum id fails here:
    ///   * the address is a self-describing SHA2-256 multihash: `0x12 0x20`
    ///     (code=sha2-256, len=32) followed by the 32-byte digest — 34 bytes,
    ///     far wider than any 8-byte checksum;
    ///   * it is byte-for-byte the SAME address `pillar_crypto::content::content_address`
    ///     computes (no private/second hash), tying the CRDT identity to the audited
    ///     real-crypto crate.
    #[test]
    fn content_address_is_a_real_cryptographic_multihash_not_a_checksum() {
        let payload = b"pillar streamdb op".to_vec();
        let id = OpId(content_address(&payload));
        // 34-byte sha2-256 multihash, not a <=8-byte checksum.
        assert_eq!(
            id.as_bytes().len(),
            34,
            "must be a 256-bit multihash, not a u64 checksum"
        );
        assert!(id.as_bytes().len() >= 32);
        assert_eq!(id.as_bytes()[0], 0x12, "multicodec sha2-256");
        assert_eq!(id.as_bytes()[1], 0x20, "digest length 32 bytes");
        // Exactly the crypto crate's real content address — no second/private hash.
        let expected =
            pillar_crypto::content::content_address(&payload).expect("real content address");
        assert_eq!(
            id.0, expected,
            "streamdb reuses the audited real-crypto content address"
        );
        // Avalanche: a one-byte change flips the address.
        let mut flipped = payload.clone();
        flipped[0] ^= 0x01;
        assert_ne!(id, OpId(content_address(&flipped)));
    }

    /// The Merkle root is a real cryptographic (SHA2-256) commitment, not a
    /// 64-bit arithmetic fold: 32 bytes wide, and it changes when the op SET
    /// changes (collision-resistant over the set).
    #[test]
    fn merkle_root_is_a_real_cryptographic_commitment() {
        let mut a = OpLog::new();
        a.append(b"x".to_vec());
        a.append(b"y".to_vec());
        let mut b = a.clone();
        b.append(b"z".to_vec());
        assert_eq!(
            a.root().as_bytes().len(),
            32,
            "sha2-256 digest, not a u64 fold"
        );
        assert_ne!(a.root(), b.root(), "root commits to the op set");
        // Deterministic over the set regardless of append order.
        let mut a2 = OpLog::new();
        a2.append(b"y".to_vec());
        a2.append(b"x".to_vec());
        assert_eq!(a.root(), a2.root());
    }

    /// `DeterministicMerkleRoot` precursor: the content address is a pure
    /// function of the payload bytes alone.
    #[test]
    fn content_address_is_deterministic() {
        let a = Op::new(b"hello".to_vec());
        let b = Op::new(b"hello".to_vec());
        let c = Op::new(b"world".to_vec());
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
    }

    /// `NoLostWrite` / `LogSubsetOfWritten`: appending is monotonic, and every
    /// appended op remains held.
    #[test]
    fn append_is_monotonic_and_retains_every_op() {
        let mut log = OpLog::new();
        let before: Vec<OpId> = log.ids().collect();
        let id1 = log.append(b"a".to_vec());
        assert!(before.iter().all(|id| log.contains(id)));
        assert!(log.contains(&id1));
        let id2 = log.append(b"b".to_vec());
        assert!(log.contains(&id1));
        assert!(log.contains(&id2));
        assert_eq!(log.len(), 2);
    }

    /// Re-appending the same payload is a no-op on the set (matches the
    /// CRDT's idempotent merge semantics extended to local writes).
    #[test]
    fn append_is_idempotent() {
        let mut log = OpLog::new();
        let id1 = log.append(b"dup".to_vec());
        let id2 = log.append(b"dup".to_vec());
        assert_eq!(id1, id2);
        assert_eq!(log.len(), 1);
    }

    /// `Gossip` / CvRDT merge: set union, commutative and idempotent, and it
    /// never removes an op already held (`MonotonicLog`).
    #[test]
    fn merge_is_commutative_and_monotonic() {
        let mut a = OpLog::new();
        a.append(b"a1".to_vec());
        a.append(b"a2".to_vec());

        let mut b = OpLog::new();
        b.append(b"b1".to_vec());

        let a_before_ids: Vec<OpId> = a.ids().collect();

        let mut merged_ab = a.clone();
        merged_ab.merge(&b);
        let mut merged_ba = b.clone();
        merged_ba.merge(&a);

        // Monotonic: everything `a` held before merging is still held after.
        assert!(a_before_ids.iter().all(|id| merged_ab.contains(id)));

        // Commutative: merging a into b or b into a converges to the same set.
        assert_eq!(
            merged_ab.ids().collect::<Vec<_>>(),
            merged_ba.ids().collect::<Vec<_>>()
        );

        // Idempotent: merging again changes nothing.
        let mut merged_twice = merged_ab.clone();
        merged_twice.merge(&b);
        assert_eq!(merged_twice, merged_ab);
    }

    /// `DeterministicMerkleRoot` + `PerPartitionOrder`: two nodes that end up
    /// holding the same op set — regardless of the order ops were appended or
    /// the gossip path that delivered them — agree on both the materialized
    /// order and the Merkle root.
    #[test]
    fn same_op_set_converges_to_same_order_and_root() {
        let mut node_a = OpLog::new();
        node_a.append(b"x".to_vec());
        node_a.append(b"y".to_vec());
        node_a.append(b"z".to_vec());

        // node_b builds the identical set via a different append order and a
        // different gossip path (through an intermediary), not a direct copy.
        let mut node_b = OpLog::new();
        node_b.append(b"z".to_vec());
        node_b.append(b"x".to_vec());
        let mut intermediary = OpLog::new();
        intermediary.append(b"y".to_vec());
        node_b.merge(&intermediary);

        assert_eq!(
            node_a.order().iter().map(|op| op.id()).collect::<Vec<_>>(),
            node_b.order().iter().map(|op| op.id()).collect::<Vec<_>>()
        );
        assert_eq!(node_a.root(), node_b.root());
    }

    /// `AllConverged` / `Convergence`: after bidirectional gossip, every node
    /// reaches the same log, hence the same root.
    #[test]
    fn bidirectional_gossip_converges() {
        let mut node_a = OpLog::new();
        node_a.append(b"only-a".to_vec());
        let mut node_b = OpLog::new();
        node_b.append(b"only-b".to_vec());

        let a_snapshot = node_a.clone();
        node_a.merge(&node_b);
        node_b.merge(&a_snapshot);

        assert_eq!(
            node_a.ids().collect::<Vec<_>>(),
            node_b.ids().collect::<Vec<_>>()
        );
        assert_eq!(node_a.root(), node_b.root());
    }

    /// `NoLostWrite` / `LogSubsetOfWritten` across compaction: a fresh peer
    /// that bootstraps from a snapshot plus the tail appended since holds
    /// exactly the same op set — and therefore the same materialized view —
    /// as a peer that received every op individually via gossip. Compaction
    /// never loses an op.
    #[test]
    fn bootstrap_from_snapshot_and_tail_matches_full_history() {
        let mut source = OpLog::new();
        source.append(b"pre-1".to_vec());
        source.append(b"pre-2".to_vec());

        // Snapshot the log at this point, then keep appending — the tail.
        let snapshot = source.compact();
        let tail_op_1 = Op::new(b"post-1".to_vec());
        let tail_op_2 = Op::new(b"post-2".to_vec());
        source.append(tail_op_1.payload().to_vec());
        source.append(tail_op_2.payload().to_vec());

        // A fresh peer bootstraps from snapshot + tail only, never seeing
        // the pre-snapshot ops individually.
        let fresh_peer = OpLog::bootstrap(&snapshot, &[tail_op_1, tail_op_2]);

        assert_eq!(fresh_peer.len(), source.len());
        assert_eq!(
            fresh_peer.ids().collect::<Vec<_>>(),
            source.ids().collect::<Vec<_>>()
        );
        assert_eq!(fresh_peer.root(), source.root());
        assert_eq!(
            fresh_peer
                .order()
                .iter()
                .map(|op| op.id())
                .collect::<Vec<_>>(),
            source.order().iter().map(|op| op.id()).collect::<Vec<_>>()
        );
    }

    /// A snapshot summarizes every op present when it was taken (compaction
    /// repackages, it does not discard).
    #[test]
    fn snapshot_carries_the_full_op_set_at_the_time() {
        let mut log = OpLog::new();
        log.append(b"1".to_vec());
        log.append(b"2".to_vec());
        log.append(b"3".to_vec());

        let snapshot = log.compact();
        assert_eq!(snapshot.len(), log.len());
        assert_eq!(snapshot.root(), log.root());
        assert!(!snapshot.is_empty());
    }

    /// A normally-produced snapshot carries the current materialized-view
    /// schema version, and validates as supported.
    #[test]
    fn snapshot_carries_current_schema_version_and_validates() {
        let mut log = OpLog::new();
        log.append(b"v".to_vec());
        let snapshot = log.compact();
        assert_eq!(snapshot.schema_version(), SCHEMA_VERSION);
        assert_eq!(snapshot.check_schema_version(), Ok(()));
    }

    /// A live view advertises the same materialized-view schema version a
    /// snapshot materialized from it would carry.
    #[test]
    fn view_advertises_current_schema_version() {
        let stream = Stream::new();
        assert_eq!(stream.view().schema_version(), SCHEMA_VERSION);
    }

    /// A snapshot re-stamped to a FUTURE materialized-view schema version is
    /// rejected as `Unsupported` — NOT `Malformed` — keeping a newer-peer
    /// snapshot distinct from corruption (ROI P1), both by
    /// [`Snapshot::check_schema_version`] and the fallible bootstrap path.
    #[test]
    fn snapshot_stamped_with_future_schema_version_is_rejected_distinctly() {
        let mut log = OpLog::new();
        log.append(b"a".to_vec());
        let mut snapshot = log.compact();
        // Re-stamp to a version newer than this build understands.
        snapshot.schema_version = pillar_crypto::SurfaceVersion(SCHEMA_VERSION.0 + 1);

        let err = snapshot.check_schema_version().unwrap_err();
        assert_eq!(
            err,
            pillar_crypto::VersionError::Unsupported {
                found: pillar_crypto::SurfaceVersion(SCHEMA_VERSION.0 + 1),
                min: MIN_SCHEMA_VERSION,
                max: SCHEMA_VERSION,
            }
        );
        // Provably a different variant than a parse error.
        assert_ne!(err, pillar_crypto::VersionError::Malformed);

        // The fallible loading path surfaces it as its own distinct variant.
        assert_eq!(
            OpLog::bootstrap_checked(&snapshot, &[]),
            Err(BootstrapError::Unsupported(err))
        );
    }

    /// The current schema version validates Ok, and the checked bootstrap path
    /// accepts a normally-produced snapshot (behaving like plain bootstrap).
    #[test]
    fn current_schema_version_validates_and_bootstraps() {
        let mut source = OpLog::new();
        source.append(b"pre".to_vec());
        let snapshot = source.compact();
        assert_eq!(snapshot.check_schema_version(), Ok(()));

        let restored = OpLog::bootstrap_checked(&snapshot, &[]).expect("current version accepted");
        assert_eq!(restored.root(), source.root());
        assert_eq!(
            restored.ids().collect::<Vec<_>>(),
            source.ids().collect::<Vec<_>>()
        );
    }

    /// An empty log's snapshot bootstraps back to an empty, converged log.
    #[test]
    fn bootstrap_from_empty_snapshot_is_empty() {
        let empty = OpLog::new();
        let snapshot = empty.compact();
        let restored = OpLog::bootstrap(&snapshot, &[]);
        assert!(restored.is_empty());
        assert_eq!(restored.root(), empty.root());
    }

    /// Toy [`ReclaimPolicy`]: payloads are `"<key>:<priority>:<body>"`; ops
    /// sharing `key` compete, higher `priority` (as a decimal string, decoded
    /// then re-encoded big-endian so lexicographic byte order matches
    /// numeric order) wins.
    struct KeyPriorityPolicy;
    impl ReclaimPolicy for KeyPriorityPolicy {
        fn group_key(&self, op: &Op) -> Option<Vec<u8>> {
            let s = std::str::from_utf8(op.payload()).ok()?;
            let key = s.split(':').next()?;
            Some(key.as_bytes().to_vec())
        }
        fn priority(&self, op: &Op) -> Vec<u8> {
            let s = std::str::from_utf8(op.payload()).unwrap();
            let prio: u64 = s.split(':').nth(1).unwrap().parse().unwrap();
            prio.to_be_bytes().to_vec()
        }
    }

    /// `compact_reclaiming` DISCARDS every op except the highest-priority one
    /// per group — genuine space reclamation, not mere repackaging: once a
    /// key has been superseded, the snapshot is strictly smaller than the
    /// full op count.
    #[test]
    fn compact_reclaiming_discards_superseded_ops_in_the_same_group() {
        let mut log = OpLog::new();
        log.append(b"k:1:old".to_vec());
        log.append(b"k:2:new".to_vec());
        log.append(b"other:1:unrelated".to_vec());
        assert_eq!(log.len(), 3);

        let snapshot = log.compact_reclaiming(&KeyPriorityPolicy);
        // Only the winner for "k" (priority 2) and the sole "other" op
        // survive — the superseded "k:1:old" is reclaimed.
        assert_eq!(snapshot.len(), 2, "superseded op must be discarded");
        assert!(snapshot.len() < log.len());
    }

    /// An op the policy assigns no group to is NEVER discarded — exactly
    /// [`OpLog::compact`]'s conservative behavior for that op.
    #[test]
    fn compact_reclaiming_never_discards_an_ungrouped_op() {
        struct NoGroups;
        impl ReclaimPolicy for NoGroups {
            fn group_key(&self, _op: &Op) -> Option<Vec<u8>> {
                None
            }
            fn priority(&self, _op: &Op) -> Vec<u8> {
                unreachable!("group_key always returns None")
            }
        }
        let mut log = OpLog::new();
        log.append(b"a".to_vec());
        log.append(b"b".to_vec());
        let snapshot = log.compact_reclaiming(&NoGroups);
        assert_eq!(snapshot.len(), log.len());
    }

    /// `bootstrap` from a RECLAIMING snapshot plus the tail appended since
    /// reconstructs the IDENTICAL per-group winner as continuing to hold
    /// full history — the reclaimed op's absence never changes any read,
    /// exactly as `OpLog::compact_reclaiming`'s contract requires. This is
    /// the reclaiming counterpart of
    /// `bootstrap_from_snapshot_and_tail_matches_full_history`, proving the
    /// space savings (`snapshot.len() + tail.len() < full history len`) come
    /// with no loss of the materialized view.
    #[test]
    fn bootstrap_from_reclaiming_snapshot_matches_full_history_winner() {
        let mut source = OpLog::new();
        source.append(b"k:1:old".to_vec());
        source.append(b"k:2:mid".to_vec());
        // Snapshot AFTER two competing writes for "k" — only "k:2:mid"
        // should survive.
        let snapshot = source.compact_reclaiming(&KeyPriorityPolicy);
        assert!(
            snapshot.len() < source.len(),
            "the superseded k:1:old must be reclaimed"
        );

        // Keep writing — a THIRD, still-higher-priority write for "k", plus
        // an unrelated op — forming the tail.
        let tail_op_1 = Op::new(b"k:3:newest".to_vec());
        let tail_op_2 = Op::new(b"other:1:unrelated".to_vec());
        source.append(tail_op_1.payload().to_vec());
        source.append(tail_op_2.payload().to_vec());

        let fresh_peer = OpLog::bootstrap(&snapshot, &[tail_op_1, tail_op_2]);

        // Full history (never compacted) as the ground truth.
        let mut full_history = OpLog::new();
        full_history.append(b"k:1:old".to_vec());
        full_history.append(b"k:2:mid".to_vec());
        full_history.append(b"k:3:newest".to_vec());
        full_history.append(b"other:1:unrelated".to_vec());

        // The reclaiming peer holds strictly fewer ops than full history...
        assert!(fresh_peer.len() < full_history.len());
        // ...yet the per-group WINNER (the materialized view a keyed-store
        // fold reads) is identical: the same "k" winner and "other" winner
        // survive under both.
        let winner_for = |log: &OpLog, key: &str| -> Option<String> {
            log.order()
                .into_iter()
                .filter(|op| {
                    std::str::from_utf8(op.payload())
                        .unwrap()
                        .starts_with(&format!("{key}:"))
                })
                .max_by_key(|op| {
                    std::str::from_utf8(op.payload())
                        .unwrap()
                        .split(':')
                        .nth(1)
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                })
                .map(|op| std::str::from_utf8(op.payload()).unwrap().to_string())
        };
        assert_eq!(winner_for(&fresh_peer, "k"), winner_for(&full_history, "k"));
        assert_eq!(
            winner_for(&fresh_peer, "other"),
            winner_for(&full_history, "other")
        );
    }

    /// Safe-by-default: a stream with no declared policy behaves as
    /// [`ViewPolicy::Strict`] (CP) — it admits an exclusive, non-idempotent
    /// effect rather than silently defaulting to the relaxed/AP class.
    #[test]
    fn unspecified_stream_policy_defaults_to_strict_cp() {
        let mut stream = Stream::new();
        assert_eq!(stream.policy(), ViewPolicy::Strict);
        assert!(stream
            .try_append(b"claim-dns-name".to_vec(), SideEffect::Exclusive)
            .is_ok());
    }

    /// The core admission wiring: a non-idempotent (exclusive) effect is
    /// refused outright against a real stream whose policy is
    /// [`ViewPolicy::Relaxed`] (AP) — the write never lands in the log.
    #[test]
    fn relaxed_stream_refuses_exclusive_effect_and_leaves_log_unchanged() {
        let mut stream = Stream::with_policy(ViewPolicy::Relaxed);
        let result = stream.try_append(b"fire-cronjob".to_vec(), SideEffect::Exclusive);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.policy(), ViewPolicy::Relaxed);
        assert_eq!(violation.effect(), SideEffect::Exclusive);
        assert!(stream.log().is_empty());
    }

    /// A convergent (idempotent) effect is admitted under a relaxed stream
    /// and actually appends.
    #[test]
    fn relaxed_stream_admits_convergent_effect() {
        let mut stream = Stream::with_policy(ViewPolicy::Relaxed);
        let result = stream.try_append(b"replica-heartbeat".to_vec(), SideEffect::Convergent);
        assert!(result.is_ok());
        assert_eq!(stream.log().len(), 1);
    }

    /// A strict stream admits both effect classes.
    #[test]
    fn strict_stream_admits_both_effect_classes() {
        let mut strict = Stream::with_policy(ViewPolicy::Strict);
        assert!(strict
            .try_append(b"a".to_vec(), SideEffect::Exclusive)
            .is_ok());
        assert!(strict
            .try_append(b"b".to_vec(), SideEffect::Convergent)
            .is_ok());
    }

    /// Views attach no policy of their own: a view taken over a stream
    /// inherits exactly that stream's effective policy (declared or
    /// defaulted), so a consumer can never observe a more permissive class
    /// than the stream/partition declared.
    #[test]
    fn view_inherits_policy_from_its_stream() {
        let mut default_stream = Stream::new();
        default_stream
            .try_append(b"x".to_vec(), SideEffect::Convergent)
            .unwrap();
        let default_view = default_stream.view();
        assert_eq!(default_view.policy(), ViewPolicy::Strict);
        assert!(default_view.admits(SideEffect::Exclusive));

        let mut relaxed_stream = Stream::with_policy(ViewPolicy::Relaxed);
        relaxed_stream
            .try_append(b"y".to_vec(), SideEffect::Convergent)
            .unwrap();
        let relaxed_view = relaxed_stream.view();
        assert_eq!(relaxed_view.policy(), ViewPolicy::Relaxed);
        assert!(!relaxed_view.admits(SideEffect::Exclusive));
        assert!(relaxed_view.admits(SideEffect::Convergent));

        // The view's data still reflects the stream's real materialized
        // state, not just its policy.
        assert_eq!(relaxed_view.order().len(), 1);
        assert_eq!(relaxed_view.root(), relaxed_stream.log().root());
    }

    /// Changing a stream's declared policy after the fact is reflected by a
    /// freshly-taken view (views are a lens, not a policy snapshot copy that
    /// can drift from the stream).
    #[test]
    fn view_reflects_current_stream_policy_after_change() {
        let mut stream = Stream::new();
        assert_eq!(stream.view().policy(), ViewPolicy::Strict);
        stream.set_policy(ViewPolicy::Relaxed);
        assert_eq!(stream.view().policy(), ViewPolicy::Relaxed);
    }

    /// Merging streams (the CRDT gossip join) never changes the receiving
    /// stream's declared policy — policy is a local admission concern, not
    /// replicated state.
    #[test]
    fn merge_does_not_change_policy() {
        let mut relaxed = Stream::with_policy(ViewPolicy::Relaxed);
        relaxed
            .try_append(b"r".to_vec(), SideEffect::Convergent)
            .unwrap();

        let mut strict = Stream::with_policy(ViewPolicy::Strict);
        strict
            .try_append(b"s".to_vec(), SideEffect::Exclusive)
            .unwrap();

        relaxed.merge(&strict);
        assert_eq!(relaxed.policy(), ViewPolicy::Relaxed);
        assert_eq!(relaxed.log().len(), 2);
    }
}
