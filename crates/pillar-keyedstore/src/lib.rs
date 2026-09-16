//! Pillar keyed store — the Rust refinement of `specs/KeyedStore.tla`.
//!
//! Two typed surfaces over **one** fold engine on the existing streamdb op
//! log (no parallel store):
//!
//! * **K/V** — opaque value, key-only point access. Modeled as the degenerate
//!   [`Document`] with exactly one field (the spec's "K/V = Document with an
//!   opaque value + key-only access").
//! * **Document** — structured, field-queryable value. Nested field access
//!   lets the SQL-view layer project over individual fields.
//!
//! Both surfaces are the SAME per-field last-writer-wins (LWW) fold over the
//! grow-only, content-addressed streamdb [`OpLog`]: every `put`/`tombstone` op
//! carries a Hybrid Logical Clock (HLC) stamp, and same-field conflicts
//! resolve by HIGHEST HLC with a DETERMINISTIC tiebreak on the author id —
//! never wall-clock order, never `OpLog::order`/content-address order. This is
//! exactly the fold `specs/KeyedStore.tla` proves (`DeterministicLWWTiebreak`,
//! `TombstoneWins`, `NoLostUpdateUnderConcurrentPut`, `HLCMonotonicPerField`).
//!
//! Durability is the existing streamdb IPFS-backed op-log persistence
//! ([`PersistentStore`]) — there is NO second storage engine. Each keyed op is
//! serialized to a streamdb op payload; the fold is re-derived over the op set
//! on read, so it converges regardless of gossip/replay order.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use pillar_streamdb::{Op, OpLog, PersistError, PersistentStream, Snapshot};

/// A Hybrid Logical Clock stamp: `(physical, logical, author)`.
///
/// `physical`/`logical` form the actual clock value; `author` is the
/// DETERMINISTIC tiebreak key used only when two ops carry the identical
/// `(physical, logical)` pair — never wall-clock order, never op-log order.
/// This mirrors `HLCs` in `specs/KeyedStore.tla`, and [`Hlc::happens_after`]
/// mirrors the spec's `HLCBefore` comparator (physical, then logical, then a
/// stable total order over authors).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hlc {
    /// Physical-time component (monotonic wall-clock reading at origination).
    pub physical: u64,
    /// Logical component — ticks within a single physical instant.
    pub logical: u64,
    /// Author identity — the deterministic tiebreak key when `(physical,
    /// logical)` collide. Ordered by its byte string (a stable total order).
    pub author: String,
}

impl Hlc {
    /// Build an HLC stamp.
    #[must_use]
    pub fn new(physical: u64, logical: u64, author: impl Into<String>) -> Self {
        Hlc {
            physical,
            logical,
            author: author.into(),
        }
    }

    /// `true` iff `self` strictly wins over `other` under the deterministic
    /// LWW comparator: higher physical, then higher logical, then higher
    /// author id (a stable total order over authors). Total and irreflexive —
    /// a pure function of the two HLC values, exactly `HLCBefore(other, self)`
    /// in the spec.
    #[must_use]
    pub fn happens_after(&self, other: &Hlc) -> bool {
        (self.physical, self.logical, &self.author) > (other.physical, other.logical, &other.author)
    }
}

/// A field value in a document: either an opaque scalar (a K/V value or a leaf
/// field) or a nested map of sub-fields, so the Document surface is
/// field-queryable to arbitrary depth for the SQL-view projection layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    /// An opaque byte payload — the whole K/V value, or a document leaf field.
    Scalar(Vec<u8>),
    /// A nested structured value: sub-field name -> value.
    Nested(BTreeMap<String, Value>),
}

impl Value {
    /// Follow a dotted field path (e.g. `a.b.c`) into a structured value,
    /// returning the value at that path if present. An empty path returns
    /// `self`. Used by the SQL-view layer to project over nested fields.
    #[must_use]
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        if path.is_empty() {
            return Some(self);
        }
        let mut cur = self;
        for seg in path.split('.') {
            match cur {
                Value::Nested(m) => cur = m.get(seg)?,
                Value::Scalar(_) => return None,
            }
        }
        Some(cur)
    }
}

/// The single field name used for the K/V surface — the spec's `onlyField`.
const KV_FIELD: &str = "";

/// The kind of a keyed op: a put (carries a value) or a tombstone (deletes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum OpKind {
    Put(Value),
    Tomb,
}

/// A single HLC-stamped keyed operation, serialized into one streamdb op-log
/// payload. Its content address IS its identity (the spec's content-addressed
/// op identity), so two logically distinct ops never collide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KeyedOp {
    collection: String,
    id: String,
    field: String,
    hlc: Hlc,
    kind: OpKind,
}

impl KeyedOp {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("KeyedOp serializes")
    }

    fn decode(bytes: &[u8]) -> Option<KeyedOp> {
        serde_json::from_slice(bytes).ok()
    }
}

/// The keyed store: K/V + Document surfaces over ONE per-field-LWW fold of the
/// streamdb op log. All state lives in the underlying op set — the fold is
/// re-derived on every read, so it is a pure function of the delivered ops.
///
/// This is the in-memory engine; [`PersistentStore`] wraps it over the
/// existing streamdb IPFS-backed durability.
#[derive(Clone, Debug, Default)]
pub struct KeyedStore {
    log: OpLog,
}

impl KeyedStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        KeyedStore { log: OpLog::new() }
    }

    /// Build a store over an existing op log (e.g. one loaded from disk).
    #[must_use]
    pub fn from_log(log: OpLog) -> Self {
        KeyedStore { log }
    }

    /// Borrow the underlying op log (for persistence / gossip).
    #[must_use]
    pub fn log(&self) -> &OpLog {
        &self.log
    }

    /// Merge another store's op set in (the CvRDT gossip join). The fold is
    /// re-derived over the union — never reordered.
    pub fn merge(&mut self, other: &KeyedStore) {
        self.log.merge(&other.log);
    }

    /// Decode every op in the log targeting `(collection, id, field)`.
    fn ops_for<'a>(
        &'a self,
        collection: &'a str,
        id: &'a str,
        field: &'a str,
    ) -> impl Iterator<Item = KeyedOp> + 'a {
        self.log.order().into_iter().filter_map(move |op| {
            let k = KeyedOp::decode(op.payload())?;
            (k.collection == collection && k.id == id && k.field == field).then_some(k)
        })
    }

    /// The winning op for `(collection, id, field)`: the one whose HLC no
    /// other op for that field beats. `None` when the field has no op. Pure in
    /// the op set — mirrors `Winner` in the spec.
    fn winner(&self, collection: &str, id: &str, field: &str) -> Option<KeyedOp> {
        let mut best: Option<KeyedOp> = None;
        for op in self.ops_for(collection, id, field) {
            match &best {
                Some(b) if !op.hlc.happens_after(&b.hlc) => {}
                _ => best = Some(op),
            }
        }
        best
    }

    /// The live value of a field, or `None` if unset or tombstoned. Mirrors
    /// `FieldIsLive`/`FieldValue`.
    fn field_value(&self, collection: &str, id: &str, field: &str) -> Option<Value> {
        match self.winner(collection, id, field)?.kind {
            OpKind::Put(v) => Some(v),
            OpKind::Tomb => None,
        }
    }

    // ------------------------------------------------------------------
    // K/V surface — a Document with exactly one field (the spec's onlyField).
    // ------------------------------------------------------------------

    /// K/V put: stamp an opaque value for `key` in `collection` at `hlc`.
    /// Returns the appended op's content address.
    pub fn kv_put(
        &mut self,
        collection: &str,
        key: &str,
        value: Vec<u8>,
        hlc: Hlc,
    ) -> pillar_streamdb::OpId {
        self.append_op(KeyedOp {
            collection: collection.to_string(),
            id: key.to_string(),
            field: KV_FIELD.to_string(),
            hlc,
            kind: OpKind::Put(Value::Scalar(value)),
        })
    }

    /// K/V tombstone: delete `key` in `collection` at `hlc`.
    pub fn kv_delete(&mut self, collection: &str, key: &str, hlc: Hlc) -> pillar_streamdb::OpId {
        self.append_op(KeyedOp {
            collection: collection.to_string(),
            id: key.to_string(),
            field: KV_FIELD.to_string(),
            hlc,
            kind: OpKind::Tomb,
        })
    }

    /// K/V get: the live opaque value for `key`, or `None` if unset/deleted.
    #[must_use]
    pub fn kv_get(&self, collection: &str, key: &str) -> Option<Vec<u8>> {
        match self.field_value(collection, key, KV_FIELD)? {
            Value::Scalar(v) => Some(v),
            Value::Nested(_) => None,
        }
    }

    /// Every currently-live K/V key in `collection` — the enumeration
    /// primitive the `pillar kv` CLI / portal K/V browse surface projects
    /// over. Pure derived state over the op set: a key appears iff its
    /// winning op (highest HLC on the K/V field) is a `Put`, never a
    /// tombstone. Sorted for a stable, deterministic browse listing.
    #[must_use]
    pub fn kv_keys(&self, collection: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .log
            .order()
            .into_iter()
            .filter_map(|op| KeyedOp::decode(op.payload()))
            .filter(|k| k.collection == collection && k.field == KV_FIELD)
            .map(|k| k.id)
            .collect();
        ids.sort();
        ids.dedup();
        ids.into_iter()
            .filter(|id| self.kv_get(collection, id).is_some())
            .collect()
    }

    /// Every collection name that currently has at least one live op (K/V or
    /// Document field) anywhere in the log — backs a top-level `pillar kv
    /// collections` browse listing.
    #[must_use]
    pub fn collections(&self) -> Vec<String> {
        let mut cols: Vec<String> = self
            .log
            .order()
            .into_iter()
            .filter_map(|op| KeyedOp::decode(op.payload()))
            .map(|k| k.collection)
            .collect();
        cols.sort();
        cols.dedup();
        cols
    }

    // ------------------------------------------------------------------
    // Document surface — per-field structured, field-queryable values.
    // ------------------------------------------------------------------

    /// Document put: stamp `value` for `field` of document `id` at `hlc`.
    /// Each field is folded independently (per-field LWW), so concurrent
    /// writes to DIFFERENT fields never conflict.
    pub fn doc_put_field(
        &mut self,
        collection: &str,
        id: &str,
        field: &str,
        value: Value,
        hlc: Hlc,
    ) -> pillar_streamdb::OpId {
        self.append_op(KeyedOp {
            collection: collection.to_string(),
            id: id.to_string(),
            field: field.to_string(),
            hlc,
            kind: OpKind::Put(value),
        })
    }

    /// Document tombstone: delete `field` of document `id` at `hlc`.
    pub fn doc_delete_field(
        &mut self,
        collection: &str,
        id: &str,
        field: &str,
        hlc: Hlc,
    ) -> pillar_streamdb::OpId {
        self.append_op(KeyedOp {
            collection: collection.to_string(),
            id: id.to_string(),
            field: field.to_string(),
            hlc,
            kind: OpKind::Tomb,
        })
    }

    /// Document get: the live value of `field` of document `id`, or `None`.
    #[must_use]
    pub fn doc_get_field(&self, collection: &str, id: &str, field: &str) -> Option<Value> {
        self.field_value(collection, id, field)
    }

    /// Every document id in `collection` that currently has at least one live
    /// field (K/V or Document) -- the enumeration primitive the SQL-view
    /// layer folds a collection through to materialize a view over it. Pure
    /// derived state over the op set, sorted for a deterministic fold order.
    #[must_use]
    pub fn doc_ids(&self, collection: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .log
            .order()
            .into_iter()
            .filter_map(|op| KeyedOp::decode(op.payload()))
            .filter(|k| k.collection == collection)
            .map(|k| k.id)
            .collect();
        ids.sort();
        ids.dedup();
        ids.into_iter()
            .filter(|id| !self.doc_fields(collection, id).is_empty())
            .collect()
    }

    /// The set of live field names of document `id` in `collection`.
    #[must_use]
    pub fn doc_fields(&self, collection: &str, id: &str) -> Vec<String> {
        let mut fields: Vec<String> = self
            .log
            .order()
            .into_iter()
            .filter_map(|op| KeyedOp::decode(op.payload()))
            .filter(|k| k.collection == collection && k.id == id)
            .map(|k| k.field)
            .collect();
        fields.sort();
        fields.dedup();
        fields
            .into_iter()
            .filter(|f| self.field_value(collection, id, f).is_some())
            .collect()
    }

    /// Field-queryable projection for the SQL-view layer: the live value at a
    /// dotted `field_path` of document `id` (nested field access). A leading
    /// segment selects the top-level field; the remainder walks into a
    /// [`Value::Nested`] value.
    #[must_use]
    pub fn doc_query(&self, collection: &str, id: &str, field_path: &str) -> Option<Value> {
        let (top, rest) = match field_path.split_once('.') {
            Some((t, r)) => (t, r),
            None => (field_path, ""),
        };
        let v = self.field_value(collection, id, top)?;
        v.get_path(rest).cloned()
    }

    /// Append one keyed op to the in-memory log.
    fn append_op(&mut self, op: KeyedOp) -> pillar_streamdb::OpId {
        self.log.append(op.encode())
    }

    // ------------------------------------------------------------------
    // Space-reclaiming compaction — the per-field LWW/tombstone
    // instantiation of `OpLog::compact_reclaiming`.
    // ------------------------------------------------------------------

    /// Compact this store's op log into a [`Snapshot`] that DISCARDS every
    /// op superseded under the per-field LWW/tombstone fold — genuine space
    /// reclamation, not mere repackaging: once a field has been written more
    /// than once (or tombstoned then never revived), `snapshot.len() <
    /// self.log().len()`.
    ///
    /// Correctness: exactly one op survives per `(collection, id, field)` —
    /// the one [`Hlc::happens_after`] never beats, i.e. the SAME op
    /// [`KeyedStore::winner`] would pick — so [`KeyedStore::from_log`] over a
    /// [`OpLog::bootstrap`] of this snapshot plus any subsequent tail folds
    /// to the IDENTICAL live value for every field as the un-compacted
    /// history: a discarded op could only ever have been out-voted at read
    /// time, so its absence changes no `kv_get`/`doc_get_field` result. No
    /// per-op verifiability, convergence, or CAP posture guarantee is
    /// weakened — the surviving op for each field remains fully
    /// content-addressed and individually verifiable.
    #[must_use]
    pub fn compact_reclaiming(&self) -> Snapshot {
        self.log.compact_reclaiming(&KeyedFieldReclaimPolicy)
    }

    /// Rebuild a store from a [`Snapshot`] (as produced by
    /// [`KeyedStore::compact_reclaiming`] or [`OpLog::compact`]) plus the log
    /// tail appended since — the keyed-store counterpart of
    /// [`OpLog::bootstrap`], folding straight to a usable [`KeyedStore`].
    #[must_use]
    pub fn bootstrap(snapshot: &Snapshot, tail: &[Op]) -> Self {
        KeyedStore::from_log(OpLog::bootstrap(snapshot, tail))
    }
}

/// The [`pillar_streamdb::ReclaimPolicy`] instantiating streamdb's generic
/// reclaiming compaction with the keyed store's own per-field LWW/tombstone
/// superseding rule: ops targeting the same `(collection, id, field)`
/// compete, and the one with the highest [`Hlc`] (per
/// [`Hlc::happens_after`]) wins — identical to [`KeyedStore::winner`]'s own
/// comparator, so compaction and the live fold can never disagree on which
/// op is authoritative.
struct KeyedFieldReclaimPolicy;

impl pillar_streamdb::ReclaimPolicy for KeyedFieldReclaimPolicy {
    fn group_key(&self, op: &Op) -> Option<Vec<u8>> {
        let k = KeyedOp::decode(op.payload())?;
        // A simple length-prefixed concatenation avoids any ambiguity from a
        // field/id/collection name containing the separator byte.
        let mut key = Vec::new();
        for part in [k.collection.as_bytes(), k.id.as_bytes(), k.field.as_bytes()] {
            key.extend_from_slice(&(part.len() as u64).to_be_bytes());
            key.extend_from_slice(part);
        }
        Some(key)
    }

    fn priority(&self, op: &Op) -> Vec<u8> {
        // KeyedOp::decode already succeeded in `group_key` for this op (the
        // trait contract only calls `priority` after `group_key` returned
        // `Some`); an op that fails to decode here would be a payload that
        // is not actually a `KeyedOp`, which cannot happen through this
        // policy's own `group_key`.
        let k = KeyedOp::decode(op.payload()).expect("payload decoded by group_key");
        // Fixed-width big-endian physical/logical preserves numeric order
        // under byte-lexicographic comparison; the author bytes then break
        // ties exactly as `Hlc::happens_after`'s `&other.author` compare
        // does (`String`'s `Ord` is byte-lexicographic).
        let mut bytes = Vec::with_capacity(8 + 8 + k.hlc.author.len());
        bytes.extend_from_slice(&k.hlc.physical.to_be_bytes());
        bytes.extend_from_slice(&k.hlc.logical.to_be_bytes());
        bytes.extend_from_slice(k.hlc.author.as_bytes());
        bytes
    }
}

/// The keyed store persisted over the existing streamdb IPFS-backed op-log
/// durability ([`PersistentStream`]) — NO second storage engine. Every keyed
/// op is durably written under its content address before the write returns;
/// reopening the underlying stream reloads the exact op set and re-derives the
/// same fold.
pub struct PersistentStore {
    stream: PersistentStream,
}

impl PersistentStore {
    /// Open (creating if absent) a durable keyed store rooted at `root_dir`,
    /// loading any persisted ops. Rides the existing streamdb persistence —
    /// the same content-addressed on-disk op set, no parallel store.
    ///
    /// # Errors
    ///
    /// Propagates [`PersistError`] from the underlying streamdb store.
    pub fn open(root_dir: impl Into<std::path::PathBuf>) -> Result<Self, PersistError> {
        Ok(PersistentStore {
            stream: PersistentStream::open(root_dir)?,
        })
    }

    /// A read-only view of the folded keyed store over the currently loaded
    /// op set.
    #[must_use]
    pub fn store(&self) -> KeyedStore {
        KeyedStore::from_log(self.stream.stream().log().clone())
    }

    /// Durably K/V put and return the op address.
    ///
    /// # Errors
    ///
    /// Propagates [`PersistError`] if the op cannot be persisted.
    pub fn kv_put(
        &mut self,
        collection: &str,
        key: &str,
        value: Vec<u8>,
        hlc: Hlc,
    ) -> Result<pillar_streamdb::OpId, PersistError> {
        let op = KeyedOp {
            collection: collection.to_string(),
            id: key.to_string(),
            field: KV_FIELD.to_string(),
            hlc,
            kind: OpKind::Put(Value::Scalar(value)),
        };
        self.append_op(op)
    }

    /// Durably put a document field.
    ///
    /// # Errors
    ///
    /// Propagates [`PersistError`] if the op cannot be persisted.
    pub fn doc_put_field(
        &mut self,
        collection: &str,
        id: &str,
        field: &str,
        value: Value,
        hlc: Hlc,
    ) -> Result<pillar_streamdb::OpId, PersistError> {
        let op = KeyedOp {
            collection: collection.to_string(),
            id: id.to_string(),
            field: field.to_string(),
            hlc,
            kind: OpKind::Put(value),
        };
        self.append_op(op)
    }

    fn append_op(&mut self, op: KeyedOp) -> Result<pillar_streamdb::OpId, PersistError> {
        // Keyed ops are CvRDT-convergent (set-union merge), so they carry the
        // Convergent side effect — admitted under both Strict and Relaxed
        // policies.
        // Keyed ops are CvRDT-convergent (set-union merge), so they carry the
        // Convergent side effect — admitted under both Strict and Relaxed
        // policies.
        self.stream
            .append(op.encode(), pillar_core::SideEffect::Convergent)
    }
}

#[cfg(test)]
mod keyed_store {
    use super::*;

    fn hlc(p: u64, l: u64, a: &str) -> Hlc {
        Hlc::new(p, l, a)
    }

    #[test]
    fn kv_put_get_roundtrip() {
        let mut s = KeyedStore::new();
        s.kv_put("c", "k", b"v1".to_vec(), hlc(1, 0, "n1"));
        assert_eq!(s.kv_get("c", "k"), Some(b"v1".to_vec()));
        assert_eq!(s.kv_get("c", "missing"), None);
    }

    #[test]
    fn kv_lww_higher_hlc_wins_regardless_of_apply_order() {
        // Two writes; the higher HLC must win no matter which is applied last.
        let mut a = KeyedStore::new();
        a.kv_put("c", "k", b"old".to_vec(), hlc(1, 0, "n1"));
        a.kv_put("c", "k", b"new".to_vec(), hlc(2, 0, "n1"));

        let mut b = KeyedStore::new();
        b.kv_put("c", "k", b"new".to_vec(), hlc(2, 0, "n1"));
        b.kv_put("c", "k", b"old".to_vec(), hlc(1, 0, "n1"));

        assert_eq!(a.kv_get("c", "k"), Some(b"new".to_vec()));
        assert_eq!(b.kv_get("c", "k"), Some(b"new".to_vec()));
    }

    #[test]
    fn deterministic_author_tiebreak_on_equal_clock() {
        // Same (physical, logical): the higher author id wins, deterministically.
        let mut s = KeyedStore::new();
        s.kv_put("c", "k", b"from-n1".to_vec(), hlc(5, 3, "n1"));
        s.kv_put("c", "k", b"from-n2".to_vec(), hlc(5, 3, "n2"));
        assert_eq!(s.kv_get("c", "k"), Some(b"from-n2".to_vec()));
    }

    #[test]
    fn tombstone_wins_when_highest_hlc() {
        let mut s = KeyedStore::new();
        s.kv_put("c", "k", b"v".to_vec(), hlc(1, 0, "n1"));
        s.kv_delete("c", "k", hlc(2, 0, "n1"));
        assert_eq!(
            s.kv_get("c", "k"),
            None,
            "tombstone with higher HLC deletes"
        );
    }

    #[test]
    fn later_put_supersedes_earlier_tombstone() {
        // A tombstone that is NOT the winner leaves the field live — same fold.
        let mut s = KeyedStore::new();
        s.kv_delete("c", "k", hlc(1, 0, "n1"));
        s.kv_put("c", "k", b"revived".to_vec(), hlc(2, 0, "n1"));
        assert_eq!(s.kv_get("c", "k"), Some(b"revived".to_vec()));
    }

    #[test]
    fn no_lost_update_concurrent_put_winner_is_a_real_write() {
        // Two nodes concurrently put DIFFERENT values, then merge. The winner
        // is one of the two writes (higher HLC), never a third/blended value.
        let mut n1 = KeyedStore::new();
        n1.kv_put("c", "k", b"n1-val".to_vec(), hlc(3, 0, "n1"));
        let mut n2 = KeyedStore::new();
        n2.kv_put("c", "k", b"n2-val".to_vec(), hlc(4, 0, "n2"));

        n1.merge(&n2);
        n2.merge(&n1);

        // Both converge to the SAME winner, and it is one of the real writes.
        let w1 = n1.kv_get("c", "k").unwrap();
        let w2 = n2.kv_get("c", "k").unwrap();
        assert_eq!(w1, w2, "merge converges");
        assert_eq!(w1, b"n2-val".to_vec(), "higher HLC wins");
        assert!(w1 == b"n1-val".to_vec() || w1 == b"n2-val".to_vec());
    }

    #[test]
    fn merge_is_order_independent() {
        let mut base = KeyedStore::new();
        base.kv_put("c", "k", b"base".to_vec(), hlc(1, 0, "n1"));

        let mut x = base.clone();
        x.kv_put("c", "k", b"x".to_vec(), hlc(2, 0, "n1"));
        let mut y = base.clone();
        y.kv_put("c", "k", b"y".to_vec(), hlc(2, 1, "n1"));

        let mut a = x.clone();
        a.merge(&y);
        let mut b = y.clone();
        b.merge(&x);
        assert_eq!(a.kv_get("c", "k"), b.kv_get("c", "k"));
    }

    #[test]
    fn document_fields_are_independent_lww() {
        // Per-field LWW: concurrent writes to different fields never conflict.
        let mut s = KeyedStore::new();
        s.doc_put_field(
            "docs",
            "d1",
            "name",
            Value::Scalar(b"alice".to_vec()),
            hlc(1, 0, "n1"),
        );
        s.doc_put_field(
            "docs",
            "d1",
            "age",
            Value::Scalar(b"30".to_vec()),
            hlc(1, 0, "n1"),
        );
        // Overwrite only `age`.
        s.doc_put_field(
            "docs",
            "d1",
            "age",
            Value::Scalar(b"31".to_vec()),
            hlc(2, 0, "n1"),
        );

        assert_eq!(
            s.doc_get_field("docs", "d1", "name"),
            Some(Value::Scalar(b"alice".to_vec())),
            "name field untouched by age update"
        );
        assert_eq!(
            s.doc_get_field("docs", "d1", "age"),
            Some(Value::Scalar(b"31".to_vec())),
        );
        assert_eq!(
            s.doc_fields("docs", "d1"),
            vec!["age".to_string(), "name".to_string()]
        );
    }

    #[test]
    fn document_tombstone_removes_field_from_live_set() {
        let mut s = KeyedStore::new();
        s.doc_put_field(
            "docs",
            "d1",
            "a",
            Value::Scalar(b"1".to_vec()),
            hlc(1, 0, "n1"),
        );
        s.doc_put_field(
            "docs",
            "d1",
            "b",
            Value::Scalar(b"2".to_vec()),
            hlc(1, 0, "n1"),
        );
        s.doc_delete_field("docs", "d1", "a", hlc(2, 0, "n1"));
        assert_eq!(s.doc_get_field("docs", "d1", "a"), None);
        assert_eq!(s.doc_fields("docs", "d1"), vec!["b".to_string()]);
    }

    #[test]
    fn nested_field_query_for_sql_view_projection() {
        let mut inner = BTreeMap::new();
        inner.insert("city".to_string(), Value::Scalar(b"paris".to_vec()));
        inner.insert("zip".to_string(), Value::Scalar(b"75001".to_vec()));
        let addr = Value::Nested(inner);

        let mut s = KeyedStore::new();
        s.doc_put_field("docs", "d1", "address", addr.clone(), hlc(1, 0, "n1"));

        assert_eq!(s.doc_query("docs", "d1", "address"), Some(addr));
        assert_eq!(
            s.doc_query("docs", "d1", "address.city"),
            Some(Value::Scalar(b"paris".to_vec())),
        );
        assert_eq!(s.doc_query("docs", "d1", "address.missing"), None);
    }

    #[test]
    fn kv_keys_lists_only_live_keys_sorted() {
        let mut s = KeyedStore::new();
        s.kv_put("sessions", "b", b"1".to_vec(), hlc(1, 0, "n1"));
        s.kv_put("sessions", "a", b"2".to_vec(), hlc(1, 0, "n1"));
        s.kv_put("sessions", "c", b"3".to_vec(), hlc(1, 0, "n1"));
        s.kv_delete("sessions", "c", hlc(2, 0, "n1"));
        assert_eq!(
            s.kv_keys("sessions"),
            vec!["a".to_string(), "b".to_string()],
            "tombstoned key is excluded, remaining keys sorted"
        );
        assert!(s.kv_keys("other-collection").is_empty());
    }

    #[test]
    fn collections_lists_every_collection_with_a_live_or_tombstoned_op() {
        let mut s = KeyedStore::new();
        s.kv_put("sessions", "a", b"1".to_vec(), hlc(1, 0, "n1"));
        s.doc_put_field(
            "key-offers",
            "o1",
            "state",
            Value::Scalar(b"offered".to_vec()),
            hlc(1, 0, "n1"),
        );
        assert_eq!(
            s.collections(),
            vec!["key-offers".to_string(), "sessions".to_string()]
        );
    }

    #[test]
    fn hlc_comparator_total_order() {
        assert!(
            hlc(2, 0, "n1").happens_after(&hlc(1, 9, "n9")),
            "physical dominates"
        );
        assert!(
            hlc(1, 5, "n1").happens_after(&hlc(1, 4, "n9")),
            "logical dominates within physical"
        );
        assert!(
            hlc(1, 1, "n2").happens_after(&hlc(1, 1, "n1")),
            "author breaks a full tie"
        );
        assert!(
            !hlc(1, 1, "n1").happens_after(&hlc(1, 1, "n1")),
            "irreflexive"
        );
    }

    #[test]
    fn compact_reclaiming_discards_superseded_writes_and_shrinks_the_log() {
        // Three writes to the SAME field, plus one write to a different
        // field — only two ops (the winners of each field) should survive.
        let mut s = KeyedStore::new();
        s.kv_put("c", "k", b"v1".to_vec(), hlc(1, 0, "n1"));
        s.kv_put("c", "k", b"v2".to_vec(), hlc(2, 0, "n1"));
        s.kv_put("c", "k", b"v3".to_vec(), hlc(3, 0, "n1"));
        s.kv_put("c", "other", b"unrelated".to_vec(), hlc(1, 0, "n1"));
        assert_eq!(s.log().len(), 4);

        let snapshot = s.compact_reclaiming();
        assert_eq!(
            snapshot.len(),
            2,
            "only the winner for each field should survive compaction"
        );
        assert!(snapshot.len() < s.log().len(), "must reclaim real space");
    }

    #[test]
    fn bootstrap_from_reclaiming_snapshot_yields_identical_keyed_view() {
        let mut s = KeyedStore::new();
        s.kv_put("c", "k", b"old".to_vec(), hlc(1, 0, "n1"));
        s.kv_put("c", "k", b"newer".to_vec(), hlc(2, 0, "n1"));
        s.doc_put_field(
            "docs",
            "d1",
            "a",
            Value::Scalar(b"1".to_vec()),
            hlc(1, 0, "n1"),
        );
        s.doc_put_field(
            "docs",
            "d1",
            "a",
            Value::Scalar(b"2".to_vec()),
            hlc(2, 0, "n1"),
        );
        s.doc_delete_field("docs", "d1", "b", hlc(1, 0, "n1"));

        let snapshot = s.compact_reclaiming();
        assert!(snapshot.len() < s.log().len());

        // A tail write appended AFTER the snapshot was taken.
        let tail_op = Op::new(
            KeyedOp {
                collection: "c".to_string(),
                id: "k".to_string(),
                field: KV_FIELD.to_string(),
                hlc: hlc(3, 0, "n1"),
                kind: OpKind::Put(Value::Scalar(b"newest".to_vec())),
            }
            .encode(),
        );

        let restored = KeyedStore::bootstrap(&snapshot, &[tail_op]);

        // Identical live values to what the un-compacted store (plus the
        // same tail write) would show.
        s.kv_put("c", "k", b"newest".to_vec(), hlc(3, 0, "n1"));
        assert_eq!(restored.kv_get("c", "k"), s.kv_get("c", "k"));
        assert_eq!(
            restored.doc_get_field("docs", "d1", "a"),
            s.doc_get_field("docs", "d1", "a")
        );
        assert_eq!(
            restored.doc_get_field("docs", "d1", "b"),
            s.doc_get_field("docs", "d1", "b")
        );
    }

    #[test]
    fn persistent_store_reloads_folded_state() {
        let dir =
            std::env::temp_dir().join(format!("pillar-keyedstore-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut ps = PersistentStore::open(&dir).unwrap();
            ps.kv_put("c", "k", b"durable".to_vec(), hlc(1, 0, "n1"))
                .unwrap();
            ps.doc_put_field(
                "docs",
                "d1",
                "f",
                Value::Scalar(b"fv".to_vec()),
                hlc(1, 0, "n1"),
            )
            .unwrap();
        }

        // Reopen: the same op set reloads and re-derives the same fold.
        let ps = PersistentStore::open(&dir).unwrap();
        let s = ps.store();
        assert_eq!(s.kv_get("c", "k"), Some(b"durable".to_vec()));
        assert_eq!(
            s.doc_get_field("docs", "d1", "f"),
            Some(Value::Scalar(b"fv".to_vec())),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
