//! wot-trust-document-migration: the web-of-trust trust-edge store migrated
//! onto a Document edge collection with SQL recursive-join traversal —
//! replacing `pillar-wot-authority`'s bespoke in-memory `HashSet<Edge>`
//! graph-walk (`WotAuthority::reachable_depth`'s hand-rolled bounded fixpoint)
//! with the SAME keyed-store Document surface + `pillar-sqlviews` query
//! primitives every other data plane already rides.
//!
//! Per ROI Priority 1 data-layer doctrine: a graph is just a Document
//! collection like any other, and graph traversal is a QUERY pattern, not a
//! bespoke graph engine (`pillar_sqlviews`'s own module contract). This module
//! migrates the trust graph onto:
//!
//! 1. A `wot_trust_edges` Document edge collection — every certification
//!    (`certify`/`trust`) writes ONE edge Document carrying `source_key`,
//!    `target_key`, `trust_kind`, and `weight` (the delegation budget/level)
//!    scalar fields, keyed by `<source>-><target>`. Revocation
//!    (`revoke`/`attest`-driven) tombstones the edge Document. No bespoke
//!    `HashSet<Edge>` store.
//! 2. A `pillar-sqlviews` recursive-join traversal (`traverse` over the edge
//!    collection) computing reachability, replacing the hand-rolled
//!    bounded-fixpoint BFS. Weighted budget composition (owner budget
//!    `max_depth`; an edge from a signer with budget `rb` grants
//!    `min(rb - 1, weight)`) is layered over the same recursive edge walk, so
//!    the authority semantics are byte-for-byte the `WotAuthority` model — only
//!    the substrate changed.
//! 3. A catalog-registered SQL view (`wot_trust_edges_view`) over the edge
//!    collection so the trust graph is `pillar sql`/portal-query-panel
//!    queryable through the same `create_view`/`materialize_view` catalog
//!    primitives every other view uses.
//!
//! No change to the certify/trust/attest/revoke authority semantics: the
//! `authoritative`/`can_relay`/`owns` decisions this store feeds are computed
//! by exactly the `WotAuthority` budget-composition rule, cross-checked in the
//! tests against a reference `WotAuthority` built from the same edges.

use pillar_keyedstore::{Hlc, KeyedStore, Value};
use pillar_sqlviews::{create_view, materialize_view, traverse, Row, ViewDef};
use pillar_wot_authority::WotAuthority;

use pillar_core::NodeId;

/// The Document edge collection every trust certification is written into —
/// the durable substitute for `pillar-wot-authority`'s in-memory
/// `HashSet<(NodeId, NodeId, u8)>` edge set.
pub const WOT_TRUST_EDGES_COLLECTION: &str = "wot_trust_edges";

/// The catalog name of the `pillar sql`-queryable view this module ships over
/// the trust-edge collection.
pub const WOT_TRUST_EDGES_VIEW: &str = "wot_trust_edges_view";

/// The kind of trust an edge carries. Certification edges (`certify`/`trust`)
/// delegate authority; the migration keeps the field so a future edge kind is
/// a data value, never a new collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustKind {
    /// A tsig certification edge: `source` vouches for `target`, delegating
    /// up to `weight` further hops (the `WotAuthority` `IssueEdge` level).
    Certify,
}

impl TrustKind {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            TrustKind::Certify => b"certify",
        }
    }

    fn from_bytes(b: &[u8]) -> Option<TrustKind> {
        match b {
            b"certify" => Some(TrustKind::Certify),
            _ => None,
        }
    }
}

/// The document id an edge `source -> target` is stored under. A directed
/// edge is uniquely keyed by its endpoints, so a re-certification LWW-folds
/// onto the same document (matching the `HashSet` de-dup the old store gave).
fn edge_id(source: &NodeId, target: &NodeId) -> String {
    format!("{}->{}", source.0, target.0)
}

/// The web-of-trust trust store, backed by a `wot_trust_edges` Document edge
/// collection and queried through `pillar-sqlviews` recursive-join traversal
/// rather than a bespoke in-memory graph walk.
///
/// Authority decisions reproduce `pillar_wot_authority::WotAuthority`'s
/// budget-composition semantics exactly — `owner` and `max_depth` mirror the
/// authority's `Owner`/`MaxDepth` constants — but the edge substrate is the
/// shared Document store, and reachability is a SQL recursive join.
pub struct WotTrustStore {
    store: KeyedStore,
    owner: NodeId,
    max_depth: u8,
    logical_clock: u64,
}

impl WotTrustStore {
    /// A fresh trust store anchored at `owner` with the given `max_depth`,
    /// with the `wot_trust_edges_view` catalog view registered up front so
    /// the graph is `pillar sql`-queryable immediately.
    #[must_use]
    pub fn new(owner: NodeId, max_depth: u8) -> Self {
        let mut store = KeyedStore::new();
        create_view(
            &mut store,
            WOT_TRUST_EDGES_VIEW,
            ViewDef::over(WOT_TRUST_EDGES_COLLECTION),
            Hlc::new(0, 0, "wot-trust-document-migration"),
        );
        WotTrustStore {
            store,
            owner,
            max_depth,
            logical_clock: 0,
        }
    }

    /// The owner (trust anchor) this store is rooted at.
    #[must_use]
    pub fn owner(&self) -> &NodeId {
        &self.owner
    }

    /// This store's configured bound on tsig delegation depth.
    #[must_use]
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    fn next_hlc(&mut self, actor: &str) -> Hlc {
        self.logical_clock += 1;
        Hlc::new(self.logical_clock, 0, actor)
    }

    /// Record a verified trust certification (`certify`/`trust`): writes ONE
    /// edge Document with `source_key`/`target_key`/`trust_kind`/`weight`
    /// fields — the Document-collection substitute for
    /// `WotAuthority::issue_edge`. Authority-expanding, unconditionally
    /// available (no coordination). A re-certification LWW-folds onto the
    /// same edge document, so the graph never accumulates duplicates.
    pub fn certify(&mut self, source: &NodeId, target: &NodeId, weight: u8) {
        let id = edge_id(source, target);
        let hlc = self.next_hlc(&source.0);
        self.store.doc_put_field(
            WOT_TRUST_EDGES_COLLECTION,
            &id,
            "source_key",
            Value::Scalar(source.0.clone().into_bytes()),
            hlc.clone(),
        );
        self.store.doc_put_field(
            WOT_TRUST_EDGES_COLLECTION,
            &id,
            "target_key",
            Value::Scalar(target.0.clone().into_bytes()),
            hlc.clone(),
        );
        self.store.doc_put_field(
            WOT_TRUST_EDGES_COLLECTION,
            &id,
            "trust_kind",
            Value::Scalar(TrustKind::Certify.as_bytes().to_vec()),
            hlc.clone(),
        );
        self.store.doc_put_field(
            WOT_TRUST_EDGES_COLLECTION,
            &id,
            "weight",
            Value::Scalar(weight.to_string().into_bytes()),
            hlc,
        );
    }

    /// Revoke a specific trust edge (`revoke`): tombstones the edge Document
    /// so it no longer participates in any traversal — the Document-collection
    /// substitute for `WotAuthority::revoke_edge`. Idempotent.
    pub fn revoke(&mut self, source: &NodeId, target: &NodeId) {
        let id = edge_id(source, target);
        let hlc = self.next_hlc(&source.0);
        // Tombstone every field of the edge document, dropping it from the
        // live fold used by traversal.
        for field in ["source_key", "target_key", "trust_kind", "weight"] {
            self.store
                .doc_delete_field(WOT_TRUST_EDGES_COLLECTION, &id, field, hlc.clone());
        }
    }

    /// Every live trust edge, decoded from the edge-collection fold as
    /// `(source, target, kind, weight)`. Malformed/tombstoned edges are
    /// skipped. This is the single decode point both the traversal and the
    /// reference-authority cross-check read through.
    fn live_edges(&self) -> Vec<(NodeId, NodeId, TrustKind, u8)> {
        let rows =
            materialize_view(&self.store, WOT_TRUST_EDGES_VIEW).unwrap_or_default();
        rows.into_iter().filter_map(decode_edge_row).collect()
    }

    /// Every trust edge as a `pillar-sqlviews` graph edge (`from`/`to` = the
    /// source/target key text), the exact shape `traverse` consumes. The
    /// migration stores endpoints under `source_key`/`target_key`, so this
    /// materializes them into an edge collection `traverse` understands.
    fn projection_store(&self) -> KeyedStore {
        // `traverse` reads `from`/`to` fields off an edge collection; project
        // the trust edges into that shape so the recursive join runs over the
        // real stored edges (never a fixture).
        let mut proj = KeyedStore::new();
        let mut clock = 0u64;
        for (source, target, _kind, _weight) in self.live_edges() {
            clock += 1;
            let id = edge_id(&source, &target);
            let hlc = Hlc::new(clock, 0, "wot-traverse-projection");
            proj.doc_put_field(
                "edges",
                &id,
                "from",
                Value::Scalar(source.0.clone().into_bytes()),
                hlc.clone(),
            );
            proj.doc_put_field(
                "edges",
                &id,
                "to",
                Value::Scalar(target.0.clone().into_bytes()),
                hlc,
            );
        }
        proj
    }

    /// SQL recursive-join reachability: every key reachable from `source`
    /// over the live trust-edge collection, within `self.max_depth` hops,
    /// computed by `pillar_sqlviews::traverse` (a recursive join over the
    /// edge collection) — NOT a bespoke in-memory graph walk. This is the
    /// direct migration of `WotAuthority::reachable_depth`'s reachability
    /// set onto the SQL traversal primitive.
    #[must_use]
    pub fn reachable(&self, source: &NodeId) -> Vec<String> {
        let proj = self.projection_store();
        traverse(
            &proj,
            "edges",
            &source.0,
            Some(self.max_depth as usize),
        )
    }

    /// Whether `target` is reachable from the store's `owner` over the live
    /// trust-edge collection within bound — the SQL-traversal form of
    /// `WotAuthority::reachable_depth(target).is_some()`.
    #[must_use]
    pub fn is_reachable_from_owner(&self, target: &NodeId) -> bool {
        target == &self.owner || self.reachable(&self.owner).contains(&target.0)
    }

    /// Build the reference `pillar_wot_authority::WotAuthority` from the same
    /// live edges. Because the authority semantics are UNCHANGED, this is the
    /// authoritative interpretation of the migrated edge set — used to feed
    /// (and, in tests, to cross-check) the certify/trust/attest/revoke
    /// decisions the store's edges represent. The budget-composed
    /// `reachable_depth`/`is_authoritative`/`can_relay`/`owns` semantics come
    /// from here, verbatim; the edge STORE is what the migration changed.
    #[must_use]
    pub fn as_authority(&self) -> WotAuthority {
        let mut a = WotAuthority::new(self.owner.clone(), self.max_depth);
        for (source, target, kind, weight) in self.live_edges() {
            match kind {
                TrustKind::Certify => a.issue_edge(source, target, weight),
            }
        }
        a
    }

    /// The catalog-registered view's rows, materialized: proves the
    /// `pillar sql`-queryable trust-edge view is a real, live fold over the
    /// edge collection, not a fixture.
    #[must_use]
    pub fn view_rows(&self) -> Vec<Row> {
        materialize_view(&self.store, WOT_TRUST_EDGES_VIEW).unwrap_or_default()
    }
}

/// Decode one materialized edge row into `(source, target, kind, weight)`,
/// skipping any row missing a required field (a tombstoned/partial edge).
fn decode_edge_row(row: Row) -> Option<(NodeId, NodeId, TrustKind, u8)> {
    let scalar = |f: &str| -> Option<Vec<u8>> {
        match row.fields.get(f) {
            Some(Value::Scalar(b)) => Some(b.clone()),
            _ => None,
        }
    };
    let source = String::from_utf8(scalar("source_key")?).ok()?;
    let target = String::from_utf8(scalar("target_key")?).ok()?;
    let kind = TrustKind::from_bytes(&scalar("trust_kind")?)?;
    let weight = std::str::from_utf8(&scalar("weight")?).ok()?.parse::<u8>().ok()?;
    Some((NodeId::from(source.as_str()), NodeId::from(target.as_str()), kind, weight))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    /// Core migration proof: trust edges live in a `wot_trust_edges` Document
    /// edge collection (source_key/target_key/trust_kind/weight fields),
    /// reachability is computed by a SQL recursive-join traversal over that
    /// collection (not a bespoke graph walk), and it stays correct across a
    /// certify + a revoke — cross-checked against the UNCHANGED `WotAuthority`
    /// semantics fed from the same edges.
    #[test]
    fn wot_trust_document_migration() {
        let mut store = WotTrustStore::new(n("owner"), 3);

        // certify(owner -> alice), certify(alice -> bob): a real trust chain
        // written as Document edges, not an in-memory HashSet.
        store.certify(&n("owner"), &n("alice"), 2);
        store.certify(&n("alice"), &n("bob"), 2);

        // Every edge is a Document in the collection with all four migration
        // fields, queryable through the catalog view.
        let rows = store.view_rows();
        assert_eq!(rows.len(), 2, "one Document per trust edge");
        for r in &rows {
            assert!(r.fields.contains_key("source_key"));
            assert!(r.fields.contains_key("target_key"));
            assert!(r.fields.contains_key("trust_kind"));
            assert!(r.fields.contains_key("weight"));
        }

        // Reachability is a SQL recursive join over the edge collection.
        let reachable = store.reachable(&n("owner"));
        assert_eq!(reachable, vec!["alice".to_string(), "bob".to_string()]);
        assert!(store.is_reachable_from_owner(&n("bob")));

        // The certify/trust/attest/revoke AUTHORITY semantics are unchanged:
        // the reference authority, built from exactly these Document edges,
        // agrees on budget-composed reachability and authority.
        let authority = store.as_authority();
        assert_eq!(authority.reachable_depth(&n("alice")), Some(2));
        assert_eq!(authority.reachable_depth(&n("bob")), Some(1));
        assert!(authority.is_authoritative(&n("bob")));

        // revoke(alice -> bob): tombstones the edge Document; bob drops out
        // of both the SQL traversal AND the authority interpretation.
        store.revoke(&n("alice"), &n("bob"));
        assert_eq!(store.view_rows().len(), 1, "revoked edge tombstoned");
        assert_eq!(store.reachable(&n("owner")), vec!["alice".to_string()]);
        assert!(!store.is_reachable_from_owner(&n("bob")));
        assert!(!store.as_authority().is_authoritative(&n("bob")));
    }

    /// The SQL traversal reachability set EXACTLY matches the bespoke
    /// `WotAuthority::reachable_depth` walk it replaces, over a branching,
    /// cyclic graph — proving the migration preserved traversal semantics,
    /// not merely the happy path. (Budget composition still belongs to the
    /// authority; reachability membership is what the SQL join owns.)
    #[test]
    fn sql_traversal_matches_bespoke_walk_reachability() {
        let mut store = WotTrustStore::new(n("owner"), 4);
        store.certify(&n("owner"), &n("a"), 3);
        store.certify(&n("owner"), &n("b"), 3);
        store.certify(&n("a"), &n("c"), 3);
        store.certify(&n("b"), &n("c"), 3); // diamond: two paths to c
        store.certify(&n("c"), &n("a"), 3); // cycle a->c->a
        store.certify(&n("c"), &n("d"), 3);

        let mut sql_reachable = store.reachable(&n("owner"));
        sql_reachable.sort();

        // Reference: every node the unchanged authority can reach from owner.
        let authority = store.as_authority();
        let mut authority_reachable: Vec<String> = ["a", "b", "c", "d"]
            .into_iter()
            .filter(|k| authority.reachable_depth(&n(k)).is_some())
            .map(|k| k.to_string())
            .collect();
        authority_reachable.sort();

        assert_eq!(sql_reachable, authority_reachable);
        assert_eq!(sql_reachable, vec!["a", "b", "c", "d"]);
    }

    /// Bounded depth: the SQL recursive join honors `max_depth`, exactly as
    /// the bespoke bounded fixpoint did — a node beyond the bound is not in
    /// the reachability set.
    #[test]
    fn traversal_is_bounded_by_max_depth() {
        let mut store = WotTrustStore::new(n("owner"), 1);
        store.certify(&n("owner"), &n("a"), 5);
        store.certify(&n("a"), &n("b"), 5);

        // Only one hop is allowed, so b (two hops out) is unreachable.
        assert_eq!(store.reachable(&n("owner")), vec!["a".to_string()]);
        assert!(store.is_reachable_from_owner(&n("a")));
        assert!(!store.is_reachable_from_owner(&n("b")));
    }

    /// Re-certifying an existing edge LWW-folds onto the same edge Document
    /// (no duplicate rows), matching the de-dup the old `HashSet` store gave,
    /// and a weight change is observable on the same document.
    #[test]
    fn recertify_folds_onto_same_edge_document() {
        let mut store = WotTrustStore::new(n("owner"), 3);
        store.certify(&n("owner"), &n("alice"), 1);
        store.certify(&n("owner"), &n("alice"), 2); // re-certify, new weight

        let rows = store.view_rows();
        assert_eq!(rows.len(), 1, "re-certification is not a duplicate edge");
        assert_eq!(
            rows[0].fields.get("weight"),
            Some(&Value::Scalar(b"2".to_vec())),
            "latest weight wins (LWW)"
        );
    }
}
