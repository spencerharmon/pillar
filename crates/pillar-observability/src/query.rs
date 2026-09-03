//! Raw-query + materialized-view caching over the message bus.
//!
//! A raw query over a [`crate::TimeseriesStore`] materializes a view (a
//! filtered, content-ordered slice of held signals). Because the underlying
//! op-set is content-addressed, its Merkle-style root is a pure function of
//! the held set — so a materialized view can be *cached keyed on that root*
//! and reused verbatim as long as the set has not changed, and recomputed
//! only when it has. This is the caching the ROI P3 addendum asks for: raw
//! queries and their materialized views served over the message bus without
//! recomputing an unchanged view.
//!
//! The cache is keyed on `(query, root)`, so two peers that hold the same op
//! set answer the same raw query identically (the same convergence property
//! the op-log's deterministic root gives every materialized view).
//!
//! [`PersistedMaterializedView`] generalizes this SAME `(query, root)`-keyed
//! mechanism into a **named, durable** resource: a Dashboard panel or
//! RecordingRule can reference a materialized view by name, and that view
//! survives a process restart, re-deriving from the exact same key the live
//! [`ViewCache`] uses — never a bespoke blob store, never a second
//! invalidation path.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::block::{Signal, SignalId, SignalKind, TimeseriesStore};

/// A raw query over held signals: filter by kind (or all kinds).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    kind: Option<SignalKind>,
}

impl Query {
    /// A query matching every held signal regardless of kind.
    #[must_use]
    pub fn all() -> Self {
        Query { kind: None }
    }

    /// A query matching only signals of `kind`.
    #[must_use]
    pub fn of_kind(kind: SignalKind) -> Self {
        Query { kind: Some(kind) }
    }

    /// Whether this query matches `signal`.
    #[must_use]
    fn matches(&self, signal: &Signal) -> bool {
        match self.kind {
            None => true,
            Some(k) => signal.kind() == k,
        }
    }

    /// A stable, on-disk string encoding of this query — the same key a
    /// [`PersistedMaterializedView`] persists so a reload can recognize
    /// whether the persisted view matches the query it was materialized for.
    #[must_use]
    fn encode(&self) -> String {
        match self.kind {
            None => "all".to_string(),
            Some(k) => format!("kind:{}", k.encode()),
        }
    }

    /// The inverse of [`Query::encode`]. Returns `None` for any string that
    /// was not produced by `encode` (defensive against on-disk corruption).
    #[must_use]
    fn decode(s: &str) -> Option<Self> {
        if s == "all" {
            return Some(Query { kind: None });
        }
        let kind = s.strip_prefix("kind:")?;
        Some(Query {
            kind: Some(SignalKind::decode(kind)?),
        })
    }
}

impl SignalKind {
    /// A stable, on-disk string encoding of this kind.
    #[must_use]
    fn encode(self) -> &'static str {
        match self {
            SignalKind::Metric => "metric",
            SignalKind::Log => "log",
            SignalKind::TraceSpan => "trace_span",
            SignalKind::ProfileSample => "profile_sample",
            SignalKind::MetadataSample => "metadata_sample",
        }
    }

    /// The inverse of [`SignalKind::encode`].
    #[must_use]
    fn decode(s: &str) -> Option<Self> {
        Some(match s {
            "metric" => SignalKind::Metric,
            "log" => SignalKind::Log,
            "trace_span" => SignalKind::TraceSpan,
            "profile_sample" => SignalKind::ProfileSample,
            "metadata_sample" => SignalKind::MetadataSample,
            _ => return None,
        })
    }
}

/// The content-addressed identity of a store's current held set: a pure
/// function of that set (order-independent, matching the op-log's Merkle
/// root), used as the cache key so an unchanged set answers from cache.
#[must_use]
fn held_root(store: &TimeseriesStore) -> Vec<u8> {
    // Order-independent fold over held ids: a cryptographic hash of each id's
    // multihash bytes, combined by XOR — a pure function of the SET, never the
    // append/gossip path.
    use sha2::{Digest, Sha256};
    let mut acc = [0u8; 32];
    for id in store.held_ids() {
        let h = Sha256::digest(id.as_bytes());
        for (a, b) in acc.iter_mut().zip(h.iter()) {
            *a ^= *b;
        }
    }
    acc.to_vec()
}

/// A materialized-view cache for raw queries, keyed on `(query, held-set
/// root)`. A cache hit means the query and the underlying content-addressed
/// set are both unchanged, so the previously-materialized view is reused
/// verbatim rather than recomputed.
#[derive(Clone, Debug, Default)]
pub struct ViewCache {
    entries: HashMap<(Query, Vec<u8>), Vec<SignalId>>,
    hits: u64,
    misses: u64,
}

impl ViewCache {
    /// A fresh, empty cache.
    #[must_use]
    pub fn new() -> Self {
        ViewCache::default()
    }

    /// Number of cache hits observed so far.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of cache misses (recomputations) observed so far.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Materialize `query` over `store`, serving from cache when the query and
    /// the store's content-addressed held set are both unchanged.
    ///
    /// Returns the matching signal ids in content-address order (the
    /// deterministic materialized view). On a cache miss the view is computed
    /// and stored keyed on the current held-set root; on a hit the cached view
    /// is returned without recomputation.
    pub fn materialize(&mut self, store: &TimeseriesStore, query: Query) -> Vec<SignalId> {
        let root = held_root(store);
        let key = (query, root);
        if let Some(view) = self.entries.get(&key) {
            self.hits += 1;
            return view.clone();
        }
        self.misses += 1;
        let mut ids: Vec<SignalId> = store
            .held_signals()
            .filter(|s| query.matches(s))
            .map(|s| s.id())
            .collect();
        ids.sort_unstable();
        self.entries.insert(key, ids.clone());
        ids
    }
}

/// A named, durably-persisted materialized view: the SAME `(query,
/// held-set-root)` cache key [`ViewCache`] uses, generalized into a resource a
/// Dashboard panel or RecordingRule can reference by `name` and that survives
/// a process restart.
///
/// No bespoke blob store: the persisted record is exactly the query, the
/// held-set root it was computed against, and the resulting signal ids —
/// reusing [`Query::encode`]/[`SignalKind::encode`] and the same content-
/// addressed [`SignalId`]/`OpId` hex form the rest of Pillar persists with.
/// Reopening re-derives from the persisted `(query, root)` key exactly as a
/// live [`ViewCache`] would: if the store's CURRENT root still matches the
/// persisted root, the persisted view is reused verbatim (a restart is not a
/// forced recompute); if the root has since changed (a stale root), the view
/// is invalidated and recomputed — the same invalidation the live cache
/// already implements, never a second/divergent rule.
#[derive(Debug)]
pub struct PersistedMaterializedView {
    name: String,
    root_dir: PathBuf,
}

/// The single file a named view persists to: `<root_dir>/<name>.view`.
fn view_path(root_dir: &Path, name: &str) -> PathBuf {
    root_dir.join(format!("{name}.view"))
}

impl PersistedMaterializedView {
    /// Open (creating the containing directory if absent) the named
    /// materialized-view resource rooted at `root_dir`. Opening does no I/O
    /// beyond ensuring the directory exists — the persisted record (if any) is
    /// read lazily by [`materialize`](Self::materialize).
    ///
    /// # Errors
    ///
    /// Returns [`ViewPersistError`] if `root_dir` cannot be created.
    pub fn open(name: impl Into<String>, root_dir: impl Into<PathBuf>) -> Result<Self, ViewPersistError> {
        let root_dir = root_dir.into();
        fs::create_dir_all(&root_dir).map_err(|source| ViewPersistError::Io {
            path: root_dir.clone(),
            source,
        })?;
        Ok(PersistedMaterializedView {
            name: name.into(),
            root_dir,
        })
    }

    /// This view's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The directory this view persists under.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Materialize `query` over `store` under this view's durable name.
    ///
    /// Keyed exactly as [`ViewCache::materialize`] on `(query, held-set
    /// root)`: if a persisted record for this name exists AND its query and
    /// root both match the current call, the persisted view is returned
    /// without recomputation — including across a process restart, since the
    /// record lives on disk, not in a live cache. Otherwise (no record yet, or
    /// a stale root / different query) the view is recomputed from `store` and
    /// the fresh record is durably persisted (atomic write, so a crash
    /// mid-write never leaves a torn record).
    ///
    /// # Errors
    ///
    /// Returns [`ViewPersistError`] if the persisted record cannot be read or
    /// written, or is corrupt (fails closed rather than silently trusting a
    /// tampered/partial file).
    pub fn materialize(
        &self,
        store: &TimeseriesStore,
        query: Query,
    ) -> Result<Vec<SignalId>, ViewPersistError> {
        let root = held_root(store);
        let path = view_path(&self.root_dir, &self.name);

        if let Some(record) = self.read_record(&path)? {
            if record.query == query && record.root == root {
                return Ok(record.ids);
            }
            // Stale root (or a differently-defined view under this name):
            // fall through and recompute — the same invalidation rule the
            // live ViewCache already applies, never a divergent one.
        }

        let mut ids: Vec<SignalId> = store
            .held_signals()
            .filter(|s| query.matches(s))
            .map(|s| s.id())
            .collect();
        ids.sort_unstable();

        self.write_record(&path, &query, &root, &ids)?;
        Ok(ids)
    }

    /// Read and parse the persisted record at `path`, if any file exists
    /// there yet. Returns `Ok(None)` for "no record persisted" (never an
    /// error — a brand-new named view has nothing to load).
    fn read_record(&self, path: &Path) -> Result<Option<ViewRecord>, ViewPersistError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ViewPersistError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };
        let text = String::from_utf8(bytes).map_err(|_| ViewPersistError::Corrupt {
            path: path.to_path_buf(),
            reason: "not valid utf-8".to_string(),
        })?;
        let mut lines = text.lines();
        let query_line = lines.next().ok_or_else(|| ViewPersistError::Corrupt {
            path: path.to_path_buf(),
            reason: "missing query line".to_string(),
        })?;
        let query = Query::decode(query_line).ok_or_else(|| ViewPersistError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unrecognized query encoding {query_line:?}"),
        })?;
        let root_line = lines.next().ok_or_else(|| ViewPersistError::Corrupt {
            path: path.to_path_buf(),
            reason: "missing root line".to_string(),
        })?;
        let root = hex_decode(root_line).ok_or_else(|| ViewPersistError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unrecognized root encoding {root_line:?}"),
        })?;
        let mut ids = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let id = SignalId::from_hex(line).ok_or_else(|| ViewPersistError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("unrecognized signal id encoding {line:?}"),
            })?;
            ids.push(id);
        }
        Ok(Some(ViewRecord { query, root, ids }))
    }

    /// Atomically persist a fresh record: write to a temp file then `rename`
    /// into place, so a crash mid-write never leaves a torn/partial record
    /// under this view's name.
    fn write_record(
        &self,
        path: &Path,
        query: &Query,
        root: &[u8],
        ids: &[SignalId],
    ) -> Result<(), ViewPersistError> {
        let mut out = String::new();
        out.push_str(&query.encode());
        out.push('\n');
        out.push_str(&hex_encode(root));
        out.push('\n');
        for id in ids {
            out.push_str(&id.to_hex());
            out.push('\n');
        }

        let tmp_path = path.with_extension("view.tmp");
        fs::write(&tmp_path, out.as_bytes()).map_err(|source| ViewPersistError::Io {
            path: tmp_path.clone(),
            source,
        })?;
        fs::rename(&tmp_path, path).map_err(|source| ViewPersistError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

/// A parsed on-disk materialized-view record.
struct ViewRecord {
    query: Query,
    root: Vec<u8>,
    ids: Vec<SignalId>,
}

/// Lowercase-hex encode arbitrary bytes (the held-set root), matching the hex
/// form [`SignalId`]/`OpId` already use elsewhere in Pillar.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The inverse of [`hex_encode`].
fn hex_decode(s: &str) -> Option<Vec<u8>> {
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
    Some(bytes)
}

/// A failure persisting or loading a [`PersistedMaterializedView`]'s record.
#[derive(Debug)]
pub enum ViewPersistError {
    /// An I/O error touching a specific path.
    Io {
        /// The filesystem path the failing operation targeted.
        path: PathBuf,
        /// The underlying I/O failure.
        source: io::Error,
    },
    /// The persisted record at `path` could not be parsed.
    Corrupt {
        /// The offending record file.
        path: PathBuf,
        /// Why the record was rejected.
        reason: String,
    },
}

impl fmt::Display for ViewPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViewPersistError::Io { path, source } => write!(
                f,
                "materialized-view persistence I/O error at {}: {source}",
                path.display()
            ),
            ViewPersistError::Corrupt { path, reason } => write!(
                f,
                "corrupt materialized view at {}: {reason}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ViewPersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ViewPersistError::Io { source, .. } => Some(source),
            ViewPersistError::Corrupt { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repeated query over an unchanged store is served from cache (a hit),
    /// not recomputed.
    #[test]
    fn unchanged_store_is_served_from_cache() {
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);
        store.write(SignalKind::Log, b"l1".to_vec(), 0);

        let mut cache = ViewCache::new();
        let first = cache.materialize(&store, Query::all());
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.hits(), 0);

        let second = cache.materialize(&store, Query::all());
        assert_eq!(second, first);
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 1); // not recomputed
    }

    /// Writing a new signal changes the content-addressed root, so the same
    /// query misses (is recomputed) and reflects the new set.
    #[test]
    fn changed_store_invalidates_the_cached_view() {
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);

        let mut cache = ViewCache::new();
        let before = cache.materialize(&store, Query::all());
        assert_eq!(before.len(), 1);

        store.write(SignalKind::Metric, b"m2".to_vec(), 0);
        let after = cache.materialize(&store, Query::all());
        assert_eq!(cache.misses(), 2); // recomputed
        assert_eq!(after.len(), 2);
    }

    /// A kind-filtered query returns only matching signals.
    #[test]
    fn kind_filtered_query_returns_only_matching_signals() {
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);
        store.write(SignalKind::Log, b"l1".to_vec(), 0);
        store.write(SignalKind::Log, b"l2".to_vec(), 0);

        let mut cache = ViewCache::new();
        let logs = cache.materialize(&store, Query::of_kind(SignalKind::Log));
        assert_eq!(logs.len(), 2);
        let metrics = cache.materialize(&store, Query::of_kind(SignalKind::Metric));
        assert_eq!(metrics.len(), 1);
    }

    /// The materialized view is deterministic in the SET: two stores that end
    /// up holding the same signals (built via different write orders) answer
    /// the same raw query identically.
    #[test]
    fn same_set_answers_the_same_view_regardless_of_write_order() {
        let mut a = TimeseriesStore::new(8, 100);
        a.write(SignalKind::Metric, b"x".to_vec(), 0);
        a.write(SignalKind::Metric, b"y".to_vec(), 0);
        a.write(SignalKind::Metric, b"z".to_vec(), 0);

        let mut b = TimeseriesStore::new(8, 100);
        b.write(SignalKind::Metric, b"z".to_vec(), 0);
        b.write(SignalKind::Metric, b"x".to_vec(), 0);
        b.write(SignalKind::Metric, b"y".to_vec(), 0);

        let mut ca = ViewCache::new();
        let mut cb = ViewCache::new();
        assert_eq!(
            ca.materialize(&a, Query::all()),
            cb.materialize(&b, Query::all())
        );
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "pillar-observability-view-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        p
    }

    /// Two peers holding the SAME op-set and the same NAMED persisted
    /// materialized view answer it IDENTICALLY — no per-peer drift. Each peer
    /// gets its OWN persisted-view directory (a named view is a per-node
    /// durable resource, not itself gossiped), but because the cache key is
    /// the content-addressed `(query, root)` — never anything peer-local —
    /// both independently recompute and persist the exact same view.
    #[test]
    fn two_peers_with_same_opset_answer_the_same_named_view_identically() {
        let mut a = TimeseriesStore::new(8, 100);
        a.write(SignalKind::Metric, b"x".to_vec(), 0);
        a.write(SignalKind::Log, b"y".to_vec(), 0);

        let mut b = TimeseriesStore::new(8, 100);
        // Different write order — same resulting op-set.
        b.write(SignalKind::Log, b"y".to_vec(), 0);
        b.write(SignalKind::Metric, b"x".to_vec(), 0);

        let root_a = tmp_root("peer-a");
        let root_b = tmp_root("peer-b");
        let view_a = PersistedMaterializedView::open("dashboard-panel-1", &root_a).unwrap();
        let view_b = PersistedMaterializedView::open("dashboard-panel-1", &root_b).unwrap();

        let ids_a = view_a.materialize(&a, Query::all()).unwrap();
        let ids_b = view_b.materialize(&b, Query::all()).unwrap();
        assert_eq!(ids_a, ids_b, "same op-set must materialize identically");

        fs::remove_dir_all(&root_a).ok();
        fs::remove_dir_all(&root_b).ok();
    }

    /// A named materialized view persists across a process restart and is
    /// re-derivable from the same `(query, root)` key: reopening the SAME
    /// named view (a fresh `PersistedMaterializedView` value, standing in for
    /// a fresh process) over an UNCHANGED store returns the persisted view
    /// without needing the original in-memory cache to still be alive.
    #[test]
    fn named_view_persists_across_a_process_restart() {
        let root = tmp_root("restart");
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"cpu".to_vec(), 0);
        store.write(SignalKind::Log, b"boot".to_vec(), 0);

        let first_ids = {
            let view = PersistedMaterializedView::open("recording-rule-cpu", &root).unwrap();
            view.materialize(&store, Query::all()).unwrap()
        }; // `view` dropped — nothing but the on-disk record remains

        // Simulate a process restart: a brand-new `PersistedMaterializedView`
        // opened fresh over the same root_dir/name.
        let reopened = PersistedMaterializedView::open("recording-rule-cpu", &root).unwrap();
        let reloaded_ids = reopened.materialize(&store, Query::all()).unwrap();

        assert_eq!(reloaded_ids, first_ids);
        assert_eq!(reloaded_ids.len(), 2);

        fs::remove_dir_all(&root).ok();
    }

    /// A stale root correctly invalidates the persisted view exactly as the
    /// live query cache already does — writing a new signal changes the
    /// content-addressed root, so the persisted record (keyed on the OLD
    /// root) is recognized as stale and recomputed, never served verbatim.
    #[test]
    fn stale_root_invalidates_the_persisted_view_like_the_live_cache() {
        let root = tmp_root("stale");
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);

        let view = PersistedMaterializedView::open("dashboard-panel-2", &root).unwrap();
        let before = view.materialize(&store, Query::all()).unwrap();
        assert_eq!(before.len(), 1);

        // The root changes — the persisted record now names a stale root.
        store.write(SignalKind::Metric, b"m2".to_vec(), 0);
        let after = view.materialize(&store, Query::all()).unwrap();
        assert_eq!(after.len(), 2, "stale root must be recomputed, not served stale");

        // A live ViewCache over the same evolved store agrees exactly — no
        // divergent invalidation logic between the live cache and the
        // persisted view.
        let mut live_cache = ViewCache::new();
        let live = live_cache.materialize(&store, Query::all());
        assert_eq!(after, live);

        fs::remove_dir_all(&root).ok();
    }

    /// A different query under the SAME name is also treated as a
    /// cache-miss-equivalent: it must not be served the other query's
    /// persisted view.
    #[test]
    fn different_query_under_same_name_is_recomputed_not_misapplied() {
        let root = tmp_root("requery");
        let mut store = TimeseriesStore::new(8, 100);
        store.write(SignalKind::Metric, b"m1".to_vec(), 0);
        store.write(SignalKind::Log, b"l1".to_vec(), 0);
        store.write(SignalKind::Log, b"l2".to_vec(), 0);

        let view = PersistedMaterializedView::open("reused-name", &root).unwrap();
        let all = view.materialize(&store, Query::all()).unwrap();
        assert_eq!(all.len(), 3);

        let logs_only = view
            .materialize(&store, Query::of_kind(SignalKind::Log))
            .unwrap();
        assert_eq!(logs_only.len(), 2);

        fs::remove_dir_all(&root).ok();
    }
}
