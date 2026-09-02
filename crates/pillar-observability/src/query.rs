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

use std::collections::HashMap;

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
}
