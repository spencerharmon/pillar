//! Configurable-size immutable timeseries blocks + bounded, lossless
//! retention/compaction — property 1 of `specs/Observability.tla`.
//!
//! Signals are grouped into **immutable blocks of a configurable capacity**
//! (this is deliberately NOT state-stream snapshotting: a block is a
//! fixed-size, sealed, append-*only-until-full* container of raw signal
//! events, never a rolled-up materialized view). Once a block reaches its
//! capacity it *seals* and is thereafter never mutated — new signals open a
//! fresh block. Retention acts at block granularity: a sealed block is
//! droppable ([`TimeseriesStore::compact`]) only once the logical clock has
//! passed the LATEST retention deadline of every event it holds — never early
//! (`tick >= expiry`), and dropping repackages nothing it did not hold (the
//! store's held set stays a subset of everything ever written, exactly
//! `StreamingDB`'s `LogSubsetOfWritten`).
//!
//! Retention is implemented here and now. Per-signal / per-label retention +
//! downsampling is expressed as a built-in [`crate::retention`] resource (a
//! manifest, not a hardcoded config flag) layered over this compaction — see
//! [`RETENTION_NOTE`].

use std::collections::BTreeMap;

use pillar_streamdb::content_address;

use crate::metadata::LabelSet;

/// ROI P0 "synergy everywhere" scope note, surfaced in code so the model is
/// unambiguous: retention (drop-whole-block past expiry) is implemented, AND
/// per-signal / per-label retention + downsampling is now expressed as a
/// built-in resource ([`crate::retention::RetentionPolicy`]) over this same
/// compaction — a manifest, never a bespoke config flag.
pub const RETENTION_NOTE: &str =
    "retention implemented (drop sealed blocks past per-event expiry); \
     per-signal/per-label retention + downsampling expressed as a built-in \
     RetentionPolicy resource over the same compaction (ROI P0 2026-08-31)";

/// The kinds of observability signal, each one more entry kind on the same
/// content-addressed op-log (see `docs/observability.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalKind {
    /// A metric point (name, labels, value, timestamp).
    Metric,
    /// A structured log line.
    Log,
    /// A trace span (composes into traces via the parent-id DAG).
    TraceSpan,
    /// A profiling sample (stack/cpu/alloc).
    ProfileSample,
    /// A *sampled* reference to a real occurrence — the only kind gated by the
    /// sampling policy (see [`crate::SamplingPolicy`]).
    MetadataSample,
}

/// A signal's content-addressed identity — its `EventId` in the spec, derived
/// purely from its payload bytes via the SAME real cryptographic
/// content-addressing (SHA2-256 multihash) the op-log uses, so two nodes
/// holding the same signal agree on its id and no adversary can forge a
/// distinct payload sharing it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignalId(pub pillar_streamdb::OpId);

impl SignalId {
    /// The raw multihash bytes of this content address.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The content address as lowercase hex — the same on-disk/wire form
    /// `pillar_streamdb::OpId` uses, so a persisted materialized view can
    /// round-trip signal ids without a second encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// The inverse of [`SignalId::to_hex`]. Returns `None` for any string that
    /// is not valid hex (defensive against on-disk corruption).
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        Some(SignalId(pillar_streamdb::OpId::from_hex(s)?))
    }

    /// A deterministic test-only content address derived from a numeric seed —
    /// a real SHA2-256 multihash of the seed bytes, so tests get distinct,
    /// stable ids without hand-constructing a placeholder integer id.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_test_seed(seed: u64) -> Self {
        SignalId(pillar_streamdb::OpId(content_address(&seed.to_le_bytes())))
    }
}

impl PartialOrd for SignalId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SignalId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

/// A single observability signal event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    id: SignalId,
    kind: SignalKind,
    payload: Vec<u8>,
    /// The signal's labels — the dimensions a [`crate::retention::LabelSelector`]
    /// matches on. Empty for an unlabeled signal.
    labels: LabelSet,
    /// Retention deadline: the tick at/after which this event MAY be compacted.
    /// Fixed at write time and never changed (spec: `expiry[e] = tick + window`).
    expiry: u64,
}

impl Signal {
    /// Build an unlabeled signal, deriving its content-addressed id and fixing
    /// its retention deadline at `write_tick + retention_window`.
    #[must_use]
    pub fn new(
        kind: SignalKind,
        payload: impl Into<Vec<u8>>,
        write_tick: u64,
        retention_window: u64,
    ) -> Self {
        Signal::new_labeled(kind, payload, LabelSet::new(), write_tick, retention_window)
    }

    /// Build a labeled signal. Identity is still a pure function of the payload
    /// bytes (labels are a retention/selector dimension, not part of the
    /// content address), so two writes of the same payload dedupe regardless of
    /// their labels.
    #[must_use]
    pub fn new_labeled(
        kind: SignalKind,
        payload: impl Into<Vec<u8>>,
        labels: LabelSet,
        write_tick: u64,
        retention_window: u64,
    ) -> Self {
        let payload = payload.into();
        let id = SignalId(pillar_streamdb::OpId(content_address(&payload)));
        Signal {
            id,
            kind,
            payload,
            labels,
            expiry: write_tick.saturating_add(retention_window),
        }
    }

    /// The signal's labels.
    #[must_use]
    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    /// The signal's content address.
    #[must_use]
    pub fn id(&self) -> SignalId {
        self.id.clone()
    }

    /// The signal's kind.
    #[must_use]
    pub fn kind(&self) -> SignalKind {
        self.kind
    }

    /// The signal's raw payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The tick at/after which this signal may be compacted.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
}

/// An immutable, configurable-size block of signal events.
///
/// A block admits signals until it reaches `capacity`, then *seals*: a sealed
/// block is never mutated again (only dropped whole by retention). Its
/// [`TimeseriesBlock::latest_expiry`] is the max retention deadline over every
/// event it holds — the point past which the WHOLE block is compactable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeseriesBlock {
    capacity: usize,
    signals: BTreeMap<SignalId, Signal>,
    sealed: bool,
    latest_expiry: u64,
}

impl TimeseriesBlock {
    /// A fresh, open block of the given (nonzero) capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0` (a zero-capacity block could never hold a
    /// signal — a configuration error, not a runtime condition).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "timeseries block capacity must be > 0");
        TimeseriesBlock {
            capacity,
            signals: BTreeMap::new(),
            sealed: false,
            latest_expiry: 0,
        }
    }

    /// The block's configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of signals held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signals.len()
    }

    /// Whether the block holds no signals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    /// Whether the block is sealed (full and immutable).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Whether the block holds `id`.
    #[must_use]
    pub fn contains(&self, id: &SignalId) -> bool {
        self.signals.contains_key(id)
    }

    /// The maximum retention deadline over every event in this block — the
    /// tick past which the whole block may be dropped.
    #[must_use]
    pub fn latest_expiry(&self) -> u64 {
        self.latest_expiry
    }

    /// The block's signals in content-address order (a pure function of the
    /// set, matching the op-log's deterministic materialized order).
    pub fn signals(&self) -> impl Iterator<Item = &Signal> {
        self.signals.values()
    }

    /// Try to admit `signal` into this block. Returns `false` (leaving the
    /// block unchanged) if the block is already sealed or full — the caller
    /// then opens a fresh block. Idempotent on the content-addressed set:
    /// re-admitting a held signal is a no-op that still returns `true`.
    fn admit(&mut self, signal: Signal) -> bool {
        if self.sealed {
            return false;
        }
        if !self.signals.contains_key(&signal.id) && self.signals.len() >= self.capacity {
            // Full: seal and refuse. (Reached only when the block filled on a
            // prior admit; `push` seals eagerly, so this is a belt-and-braces
            // guard.)
            self.sealed = true;
            return false;
        }
        self.latest_expiry = self.latest_expiry.max(signal.expiry);
        self.signals.entry(signal.id.clone()).or_insert(signal);
        if self.signals.len() >= self.capacity {
            self.sealed = true;
        }
        true
    }
}

/// A store of configurable-size immutable timeseries blocks with bounded,
/// lossless retention.
///
/// Signals append into the current open block; when it seals, a fresh block
/// opens. [`TimeseriesStore::compact`] drops whole sealed blocks whose every
/// event has passed its retention deadline — never early, never fabricating.
#[derive(Clone, Debug)]
pub struct TimeseriesStore {
    block_capacity: usize,
    retention_window: u64,
    /// Per-signal / per-label retention + downsampling, expressed as a built-in
    /// resource (a manifest, not a config flag). Applied at write time to
    /// compute each signal's effective retention deadline and admission.
    policies: crate::retention::RetentionPolicySet,
    /// Sealed, immutable blocks awaiting eventual retention.
    sealed: Vec<TimeseriesBlock>,
    /// The current open block accepting appends.
    open: TimeseriesBlock,
    /// Ghost, grow-only: every signal id ever written into this store — the
    /// spec's `written`. Used to prove `LogSubsetOfWritten`.
    written: BTreeMap<SignalId, u64>,
    /// The logical write tick each signal id was admitted at — used by
    /// `psl` range/correlate evaluation (time-window filtering/grouping),
    /// distinct from `expiry` (which is `write_tick + effective retention
    /// window`, not invertible in general once per-signal policies vary).
    write_ticks: BTreeMap<SignalId, u64>,
    /// Downsample bookkeeping: per `(kind, downsample bucket key)` the tick of
    /// the last admitted representative, so a policy with a downsample interval
    /// admits at most one signal per bucket window (coarser aggregate).
    downsample_last: BTreeMap<(SignalKind, String), u64>,
}

impl TimeseriesStore {
    /// A fresh store with a configurable block capacity and default retention
    /// window (in ticks) and no retention policies.
    ///
    /// # Panics
    ///
    /// Panics if `block_capacity == 0`.
    #[must_use]
    pub fn new(block_capacity: usize, retention_window: u64) -> Self {
        TimeseriesStore {
            block_capacity,
            retention_window,
            policies: crate::retention::RetentionPolicySet::empty(),
            sealed: Vec::new(),
            open: TimeseriesBlock::new(block_capacity),
            written: BTreeMap::new(),
            write_ticks: BTreeMap::new(),
            downsample_last: BTreeMap::new(),
        }
    }

    /// Install the store's retention/downsampling policy set (the built-in
    /// resource). Replaces any previously installed set. Only affects signals
    /// written AFTER this call — a signal's retention deadline is fixed at
    /// write time, never rewritten (retention is lossless).
    pub fn set_policies(&mut self, policies: crate::retention::RetentionPolicySet) {
        self.policies = policies;
    }

    /// The installed retention/downsampling policy set.
    #[must_use]
    pub fn policies(&self) -> &crate::retention::RetentionPolicySet {
        &self.policies
    }

    /// The configured immutable-block capacity.
    #[must_use]
    pub fn block_capacity(&self) -> usize {
        self.block_capacity
    }

    /// The configured retention window in ticks.
    #[must_use]
    pub fn retention_window(&self) -> u64 {
        self.retention_window
    }

    /// Number of sealed blocks currently retained (excludes the open block).
    #[must_use]
    pub fn sealed_block_count(&self) -> usize {
        self.sealed.len()
    }

    /// Write a signal of `kind` with `payload` at logical time `write_tick`,
    /// fixing its retention deadline at `write_tick + retention_window`.
    /// Returns the content-addressed id.
    ///
    /// Rolls the current block over to a fresh one when it seals, so blocks
    /// stay at the configured capacity.
    pub fn write(
        &mut self,
        kind: SignalKind,
        payload: impl Into<Vec<u8>>,
        write_tick: u64,
    ) -> SignalId {
        self.write_labeled(kind, payload, LabelSet::new(), write_tick)
            .expect("unlabeled write is never downsampled away")
    }

    /// Write a labeled signal of `kind` at logical time `write_tick`, applying
    /// the installed [`crate::retention::RetentionPolicySet`]:
    ///
    /// - **Retention** — the effective window is the SHORTEST window over every
    ///   policy whose `(kind, selector)` matches this signal, falling back to
    ///   the store's default `retention_window` when no policy matches. So a
    ///   policy for a given signal kind + label selector genuinely shortens
    ///   that data's lifetime, while a signal outside every selector keeps the
    ///   default (no over-broad application).
    /// - **Downsampling** — if a matching policy declares a downsample
    ///   interval, at most one representative signal is admitted per
    ///   `interval`-tick bucket for that policy's `(kind, selector-key)`;
    ///   a signal falling in an already-represented bucket is dropped
    ///   (returns `None`) rather than stored, coarsening the retained series.
    ///
    /// Returns the content-addressed id, or `None` when the signal was
    /// downsampled away.
    pub fn write_labeled(
        &mut self,
        kind: SignalKind,
        payload: impl Into<Vec<u8>>,
        labels: LabelSet,
        write_tick: u64,
    ) -> Option<SignalId> {
        let matched = self.policies.effective(kind, &labels);
        let window = matched.window.unwrap_or(self.retention_window);

        // Downsampling: drop a signal that falls in an already-represented
        // bucket for its matching policy.
        if let Some((bucket_key, interval)) = matched.downsample {
            if let Some(bucket) = write_tick.checked_div(interval) {
                let key = (kind, format!("{bucket_key}:{bucket}"));
                if self.downsample_last.contains_key(&key) {
                    return None;
                }
                self.downsample_last.insert(key, write_tick);
            }
        }

        let signal = Signal::new_labeled(kind, payload, labels, write_tick, window);
        let id = signal.id.clone();
        let expiry = signal.expiry;
        self.written.entry(id.clone()).or_insert(expiry);
        self.write_ticks.entry(id.clone()).or_insert(write_tick);
        if !self.open.admit(signal.clone()) {
            // Current block was sealed/full: retire it and open a fresh one.
            let full = std::mem::replace(&mut self.open, TimeseriesBlock::new(self.block_capacity));
            if !full.is_empty() {
                self.sealed.push(full);
            }
            // The fresh block always admits (it is empty and open).
            let _ = self.open.admit(signal);
        }
        Some(id)
    }

    /// Whether `id` is currently materialized (held in some block).
    #[must_use]
    pub fn contains(&self, id: &SignalId) -> bool {
        self.open.contains(id) || self.sealed.iter().any(|b| b.contains(id))
    }

    /// Whether `id` was ever written into this store (grow-only ghost).
    #[must_use]
    pub fn was_written(&self, id: &SignalId) -> bool {
        self.written.contains_key(id)
    }

    /// Total signals currently held across every block.
    #[must_use]
    pub fn held_len(&self) -> usize {
        self.open.len() + self.sealed.iter().map(TimeseriesBlock::len).sum::<usize>()
    }

    /// Every signal id currently held (open + sealed blocks).
    pub fn held_ids(&self) -> impl Iterator<Item = SignalId> + '_ {
        self.held_signals().map(Signal::id)
    }

    /// Every signal currently held (open + sealed blocks).
    pub fn held_signals(&self) -> impl Iterator<Item = &Signal> + '_ {
        self.open
            .signals()
            .chain(self.sealed.iter().flat_map(TimeseriesBlock::signals))
    }

    /// **Retention compaction.** Drop every SEALED block whose latest event
    /// has passed its retention deadline (`tick >= latest_expiry`). Returns
    /// the number of blocks dropped.
    ///
    /// - Never early: a block is dropped only once the clock has passed the
    ///   retention deadline of *every* event it holds.
    /// - Never fabricating: dropping only removes held events; the held set
    ///   stays a subset of `written`.
    /// - The open block is never compacted (it may still admit fresh signals
    ///   and its events may not have expired).
    pub fn compact(&mut self, tick: u64) -> usize {
        let before = self.sealed.len();
        self.sealed
            .retain(|block| tick < block.latest_expiry() || !block.is_sealed());
        before - self.sealed.len()
    }

    /// The retention deadline set for a written signal, if any (the spec's
    /// `expiry[e]`).
    #[must_use]
    pub fn expiry_of(&self, id: &SignalId) -> Option<u64> {
        self.written.get(id).copied()
    }

    /// The logical write tick a held/written signal was admitted at, if
    /// known — the timestamp `psl` range/correlate evaluation filters and
    /// groups on.
    #[must_use]
    pub fn write_tick_of(&self, id: &SignalId) -> Option<u64> {
        self.write_ticks.get(id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block seals exactly at its configured capacity and thereafter refuses
    /// new signals — immutability of a sealed block.
    #[test]
    fn block_seals_at_configured_capacity_and_is_immutable_after() {
        let mut store = TimeseriesStore::new(2, 10);
        assert_eq!(store.block_capacity(), 2);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);
        store.write(SignalKind::Metric, b"m2".to_vec(), 0);
        // Two writes fill a capacity-2 block: it seals, next write opens block 2.
        store.write(SignalKind::Metric, b"m3".to_vec(), 0);
        assert_eq!(store.sealed_block_count(), 1);
        assert_eq!(store.held_len(), 3);
    }

    /// `LogSubsetOfWritten`: every id currently held was genuinely written —
    /// the store never fabricates a signal.
    #[test]
    fn held_set_is_always_a_subset_of_written() {
        let mut store = TimeseriesStore::new(4, 5);
        let a = store.write(SignalKind::Log, b"a".to_vec(), 0);
        let b = store.write(SignalKind::Log, b"b".to_vec(), 1);
        for id in store.held_ids() {
            assert!(store.was_written(&id));
        }
        assert!(store.was_written(&a));
        assert!(store.was_written(&b));
    }

    /// `Compact` guard: a sealed block is NOT droppable before the clock has
    /// passed its latest event's retention deadline (never early).
    #[test]
    fn compaction_never_drops_a_block_before_its_expiry() {
        let mut store = TimeseriesStore::new(1, 10);
        // capacity 1 -> the first write seals its block immediately.
        let id = store.write(SignalKind::Metric, b"x".to_vec(), 0);
        store.write(SignalKind::Metric, b"open".to_vec(), 0); // opens fresh block
        assert_eq!(store.sealed_block_count(), 1);
        assert_eq!(store.expiry_of(&id), Some(10));

        // Before expiry (tick 9 < 10): nothing dropped, event still present.
        assert_eq!(store.compact(9), 0);
        assert!(store.contains(&id));
    }

    /// `NoLossBeforeExpiry` corollary: once (and only once) the clock passes a
    /// sealed block's deadline, retention drops it — losslessly (it held only
    /// expired events).
    #[test]
    fn compaction_drops_a_sealed_block_once_past_its_expiry() {
        let mut store = TimeseriesStore::new(1, 10);
        let id = store.write(SignalKind::Metric, b"x".to_vec(), 0);
        store.write(SignalKind::Metric, b"open".to_vec(), 0);
        assert!(store.contains(&id));

        // At tick 10 (>= expiry 10) the sealed block is compactable.
        let dropped = store.compact(10);
        assert_eq!(dropped, 1);
        assert!(!store.contains(&id));
        // But it was still genuinely written — retention drops, never rewrites
        // history.
        assert!(store.was_written(&id));
    }

    /// The open block is never compacted — its events may not have expired and
    /// it may still admit fresh signals.
    #[test]
    fn compaction_never_touches_the_open_block() {
        let mut store = TimeseriesStore::new(8, 3);
        let id = store.write(SignalKind::Log, b"live".to_vec(), 0);
        // Far past the retention window, but the block never sealed.
        assert_eq!(store.compact(1000), 0);
        assert!(store.contains(&id));
    }

    /// Retention is implemented, and per-signal / per-label retention +
    /// downsampling is now a built-in resource over the same compaction — the
    /// note documents that ROI P0 scope.
    #[test]
    fn retention_note_documents_the_deferred_resampling_scope() {
        assert!(RETENTION_NOTE.contains("retention implemented"));
        assert!(RETENTION_NOTE.contains("RetentionPolicy resource"));
    }

    /// Content addressing: the same payload yields the same signal id (writes
    /// are deterministically deduplicated on identity).
    #[test]
    fn same_payload_yields_same_signal_id() {
        let a = Signal::new(SignalKind::Metric, b"same".to_vec(), 0, 10);
        let b = Signal::new(SignalKind::Metric, b"same".to_vec(), 5, 20);
        assert_eq!(a.id(), b.id());
    }
}
