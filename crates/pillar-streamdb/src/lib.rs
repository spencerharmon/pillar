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

/// A content address: the identity of an [`Op`], derived purely from its
/// payload bytes.
///
/// Mirrors `Ops \subseteq Nat` in the spec, where an op's id IS its content
/// address — two ops with the same id necessarily have the same content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

/// Deterministic content address of an arbitrary byte payload.
///
/// This is the SAME pure bytes->identity function the op-log uses for
/// [`OpId`], exposed so other Pillar layers (e.g. content-addressed blob /
/// OCI-layer distribution over the network transport) derive a blob's digest
/// with the identical, canonical content-addressing rather than reinventing
/// one. Two nodes holding the same bytes necessarily agree on the address.
#[must_use]
pub fn content_address(bytes: &[u8]) -> u64 {
    content_hash(bytes)
}

/// Deterministic content hash (FNV-1a, 64-bit). Dependency-free and stable
/// across runs/platforms, which is all the CRDT needs: a pure function from
/// bytes to an identity, not cryptographic collision resistance.
fn content_hash(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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
        let id = OpId(content_hash(&payload));
        Op { id, payload }
    }

    /// The op's content address.
    #[must_use]
    pub fn id(&self) -> OpId {
        self.id
    }

    /// The op's raw payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
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
        let id = op.id;
        self.ops.entry(id).or_insert(op);
        id
    }

    /// Whether this log already holds `id`.
    #[must_use]
    pub fn contains(&self, id: OpId) -> bool {
        self.ops.contains_key(&id)
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
            self.ops.entry(*id).or_insert_with(|| op.clone());
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
        self.ops.keys().copied()
    }

    /// The Merkle root: a hash-chain fold over the content-ordered ops.
    /// Deterministic in the op set alone (the order is itself derived from
    /// content) — `Root`/`FoldRoot` in the spec. Two nodes holding the same
    /// set always compute the same root, regardless of gossip path.
    #[must_use]
    pub fn root(&self) -> u64 {
        fold_root(&self.order())
    }

    /// Compact this log into a content-addressed [`Snapshot`] of its current
    /// state. The snapshot carries the full op set (compaction repackages,
    /// never discards) so a peer that bootstraps from it plus the log's tail
    /// ends up with exactly this set.
    #[must_use]
    pub fn compact(&self) -> Snapshot {
        Snapshot {
            root: self.root(),
            ops: self.ops.clone(),
        }
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
            log.ops.entry(op.id).or_insert_with(|| op.clone());
        }
        log
    }
}

fn fold_root(ops: &[&Op]) -> u64 {
    const FOLD_PRIME: u64 = 31;
    const FOLD_MODULUS: u64 = 1_000_003;
    ops.iter().rev().fold(0u64, |acc, op| {
        (op.id.0.wrapping_add(FOLD_PRIME.wrapping_mul(acc))) % FOLD_MODULUS
    })
}

/// A content-addressed compaction of an [`OpLog`] at a point in time.
///
/// Carries the full set of ops it summarizes (never a lossy digest alone) so
/// that [`OpLog::bootstrap`] from a snapshot plus a subsequent tail
/// reconstructs the identical op set a continuously-gossiped peer would hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    root: u64,
    ops: BTreeMap<OpId, Op>,
}

impl Snapshot {
    /// The Merkle root this snapshot was taken at.
    #[must_use]
    pub fn root(&self) -> u64 {
        self.root
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
    pub fn root(&self) -> u64 {
        self.log.root()
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
        assert!(before.iter().all(|id| log.contains(*id)));
        assert!(log.contains(id1));
        let id2 = log.append(b"b".to_vec());
        assert!(log.contains(id1));
        assert!(log.contains(id2));
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
        assert!(a_before_ids.iter().all(|id| merged_ab.contains(*id)));

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

    /// An empty log's snapshot bootstraps back to an empty, converged log.
    #[test]
    fn bootstrap_from_empty_snapshot_is_empty() {
        let empty = OpLog::new();
        let snapshot = empty.compact();
        let restored = OpLog::bootstrap(&snapshot, &[]);
        assert!(restored.is_empty());
        assert_eq!(restored.root(), empty.root());
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
