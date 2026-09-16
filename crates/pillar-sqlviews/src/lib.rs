//! Pillar SQL views — the Rust refinement of `specs/SqlViews.tla`.
//!
//! SQL is a **derived-read** layer over the keyed [`KeyedStore`] Document
//! store: it owns NO storage of its own and introduces NO second view engine.
//!
//! * **DDL is not special** — `CREATE MATERIALIZED VIEW`/`CREATE TABLE`
//!   writes a document into the `__catalog` system collection via the
//!   existing keyed-store Document surface, exactly like any other collection
//!   write (spec section 3.1, `CatalogColl`/`CatalogOp`). The catalog IS data.
//! * **No side index** — a row's key is `(collection, id)`; views are folded
//!   directly from the source collection's live rows, reusing the SAME
//!   per-field LWW fold `pillar-keyedstore`/`pillar-streamdb` already
//!   implement (`materialized-view-persistence`) rather than a parallel
//!   store.
//! * **Zero-migration schema change** — creating a NEW view over an existing
//!   collection just writes a new `__catalog` doc and folds it from the
//!   unchanged source log; every other view over the same source is
//!   untouched (spec `NoMigrationOnNewView`).
//! * **Counters and graph traversal are QUERY patterns**, not separate
//!   stores: `aggregate_sum`/`aggregate_group_by` and `traverse` all read
//!   through the same [`KeyedStore`] projection, never a bespoke engine.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use pillar_keyedstore::{Hlc, KeyedStore, Value};

/// The system collection DDL writes into (spec section 3.1). Kept out of
/// ordinary collection names so a data write and a catalog write are never
/// confused with each other.
pub const CATALOG_COLLECTION: &str = "__catalog";

/// The single catalog field a view/table definition is stored under, mirrors
/// the spec's `(viewId, "def")` catalog key.
const CATALOG_DEF_FIELD: &str = "def";

/// A query filter: an equality predicate over one field of a source row —
/// the smallest faithful instance of "project/filter over a collection"
/// (spec section 3.4). `None` means "no filter, all rows pass".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Filter {
    /// The field path to test (dotted, for nested projection).
    pub field: String,
    /// The scalar value the field must equal to pass the filter.
    pub value: Vec<u8>,
}

/// A materialized view (or, degenerately, a `CREATE TABLE`-style catalog
/// entry with no filter/projection) definition: names its source collection
/// plus an optional equality filter and an optional column projection.
/// Stored, whole, as ONE catalog document — DDL is data, not a schema
/// migration (spec section 3.1/3.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewDef {
    /// The collection this view is folded over.
    pub source: String,
    /// An optional equality filter narrowing which source rows materialize.
    pub filter: Option<Filter>,
    /// An optional column projection — only these field paths are kept in
    /// the materialized row. `None` keeps every live field.
    pub project: Option<Vec<String>>,
}

impl ViewDef {
    /// A view with no filter and no projection — every live row/field of
    /// `source` passes through unchanged (the `CREATE TABLE`-shaped case).
    #[must_use]
    pub fn over(source: impl Into<String>) -> Self {
        ViewDef {
            source: source.into(),
            filter: None,
            project: None,
        }
    }

    /// Narrow this view to rows where `field` equals `value`.
    #[must_use]
    pub fn filtered_eq(mut self, field: impl Into<String>, value: Vec<u8>) -> Self {
        self.filter = Some(Filter {
            field: field.into(),
            value,
        });
        self
    }

    /// Narrow this view's materialized rows to only the named field paths.
    #[must_use]
    pub fn projecting(mut self, fields: impl IntoIterator<Item = String>) -> Self {
        self.project = Some(fields.into_iter().collect());
        self
    }

    fn encode(&self) -> Value {
        Value::Scalar(serde_json::to_vec(self).expect("ViewDef serializes"))
    }

    fn decode(v: &Value) -> Option<ViewDef> {
        match v {
            Value::Scalar(b) => serde_json::from_slice(b).ok(),
            Value::Nested(_) => None,
        }
    }
}

/// A single materialized row: the source document id plus its live fields
/// (post projection). A pure fold result — never mutated in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The source collection's document id this row was folded from.
    pub id: String,
    /// The row's live field values (post filter/projection).
    pub fields: BTreeMap<String, Value>,
}

/// `CREATE MATERIALIZED VIEW <name> ...` — writes `def` as ONE document into
/// the `__catalog` collection, keyed by `name` (spec section 3.1: the catalog
/// is data). Creating a view over EXISTING data requires no migration: it is
/// folded on read from the unchanged source log (`materialize`), and never
/// disturbs any other view already defined over the same source (spec
/// `NoMigrationOnNewView`).
pub fn create_view(store: &mut KeyedStore, name: &str, def: ViewDef, hlc: Hlc) {
    store.doc_put_field(
        CATALOG_COLLECTION,
        name,
        CATALOG_DEF_FIELD,
        def.encode(),
        hlc,
    );
}

/// `DROP VIEW <name>` — tombstones the catalog document. The source
/// collection's rows are entirely unaffected (the catalog write/delete and
/// the rows it describes live on separate keys of the same log).
pub fn drop_view(store: &mut KeyedStore, name: &str, hlc: Hlc) {
    store.doc_delete_field(CATALOG_COLLECTION, name, CATALOG_DEF_FIELD, hlc);
}

/// Look up a view's definition from the catalog, or `None` if it does not
/// exist (never created, or dropped).
#[must_use]
pub fn view_def(store: &KeyedStore, name: &str) -> Option<ViewDef> {
    let v = store.doc_get_field(CATALOG_COLLECTION, name, CATALOG_DEF_FIELD)?;
    ViewDef::decode(&v)
}

/// Every view name currently live in the catalog.
#[must_use]
pub fn list_views(store: &KeyedStore) -> Vec<String> {
    store
        .doc_ids(CATALOG_COLLECTION)
        .into_iter()
        .filter(|id| view_def(store, id).is_some())
        .collect()
}

/// Materialize a view by folding its `def.source` collection through the
/// SAME per-field LWW fold `pillar-keyedstore` already implements — no
/// second view engine, no side index. A view's rows are a PURE function of
/// its catalog definition and the current fold of its source collection
/// (spec `ViewIsPureFoldOfSources`): re-run this any time to get the
/// up-to-date rows, there is no separately-stored materialization to go
/// stale.
#[must_use]
pub fn materialize(store: &KeyedStore, def: &ViewDef) -> Vec<Row> {
    project_collection(
        store,
        &def.source,
        def.filter.as_ref(),
        def.project.as_deref(),
    )
}

/// Materialize the view named `name` by looking it up in the catalog first.
/// `None` if the view does not exist.
#[must_use]
pub fn materialize_view(store: &KeyedStore, name: &str) -> Option<Vec<Row>> {
    Some(materialize(store, &view_def(store, name)?))
}

/// The projection/filter primitive every view (and every query pattern below)
/// is built from: read every live document id of `collection`, keep only
/// those passing `filter` (if any), and keep only `project`'s field paths (if
/// any) in the resulting row.
fn project_collection(
    store: &KeyedStore,
    collection: &str,
    filter: Option<&Filter>,
    project: Option<&[String]>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for id in store.doc_ids(collection) {
        if let Some(f) = filter {
            match store.doc_query(collection, &id, &f.field) {
                Some(Value::Scalar(v)) if v == f.value => {}
                _ => continue,
            }
        }
        let field_names: Vec<String> = match project {
            Some(p) => p.to_vec(),
            None => store.doc_fields(collection, &id),
        };
        let mut fields = BTreeMap::new();
        for f in field_names {
            if let Some(v) = store.doc_query(collection, &id, &f) {
                fields.insert(f, v);
            }
        }
        rows.push(Row { id, fields });
    }
    rows
}

/// Read a row field as an integer, for aggregation. Values are stored as
/// UTF-8 decimal text scalars; a non-integer/absent field contributes 0.
fn field_as_i64(row: &Row, field: &str) -> i64 {
    row.fields
        .get(field)
        .and_then(|v| match v {
            Value::Scalar(b) => std::str::from_utf8(b).ok()?.parse::<i64>().ok(),
            Value::Nested(_) => None,
        })
        .unwrap_or(0)
}

/// `SELECT SUM(field) FROM collection [WHERE filter]` — a counter, expressed
/// as a QUERY over the same fold every other view uses (spec section: SUM is
/// a query pattern, not a separate store).
#[must_use]
pub fn aggregate_sum(
    store: &KeyedStore,
    collection: &str,
    field: &str,
    filter: Option<&Filter>,
) -> i64 {
    project_collection(
        store,
        collection,
        filter,
        Some(std::slice::from_ref(&field.to_string())),
    )
    .iter()
    .map(|r| field_as_i64(r, field))
    .sum()
}

/// `SELECT group_field, SUM(sum_field) FROM collection GROUP BY group_field`
/// — a counter grouped by a field's value, again a pure query over the
/// existing fold. Returns groups sorted by key for a deterministic result.
#[must_use]
pub fn aggregate_group_by_sum(
    store: &KeyedStore,
    collection: &str,
    group_field: &str,
    sum_field: &str,
) -> Vec<(Vec<u8>, i64)> {
    let rows = project_collection(
        store,
        collection,
        None,
        Some(&[group_field.to_string(), sum_field.to_string()]),
    );
    let mut groups: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    for row in &rows {
        let key = match row.fields.get(group_field) {
            Some(Value::Scalar(b)) => b.clone(),
            _ => continue,
        };
        *groups.entry(key).or_insert(0) += field_as_i64(row, sum_field);
    }
    groups.into_iter().collect()
}

/// A directed edge in an edge collection: `from` -> `to`, stored as a
/// document with `from`/`to` scalar fields (a graph is just a Document
/// collection like any other — no separate graph store).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The source document id of the edge.
    pub from: String,
    /// The destination document id of the edge.
    pub to: String,
}

/// Read every live edge out of `edge_collection`. Edge documents carry
/// `from`/`to` scalar fields; malformed/incomplete edge documents are
/// skipped.
fn read_edges(store: &KeyedStore, edge_collection: &str) -> Vec<Edge> {
    project_collection(store, edge_collection, None, None)
        .into_iter()
        .filter_map(|row| {
            let from = match row.fields.get("from") {
                Some(Value::Scalar(b)) => String::from_utf8(b.clone()).ok()?,
                _ => return None,
            };
            let to = match row.fields.get("to") {
                Some(Value::Scalar(b)) => String::from_utf8(b.clone()).ok()?,
                _ => return None,
            };
            Some(Edge { from, to })
        })
        .collect()
}

/// Graph traversal — a recursive join over an edge collection: starting from
/// `start`, follow edges up to `max_depth` hops and return every reachable
/// node id (excluding `start` itself), sorted and deduplicated. This is a
/// QUERY pattern over the same keyed-store fold as everything else — no
/// second graph engine, no side index. `max_depth = None` traverses to a
/// fixpoint (bounded automatically by the finite reachable set).
#[must_use]
pub fn traverse(
    store: &KeyedStore,
    edge_collection: &str,
    start: &str,
    max_depth: Option<usize>,
) -> Vec<String> {
    let edges = read_edges(store, edge_collection);
    let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut frontier = vec![start.to_string()];
    let mut depth = 0;
    loop {
        if let Some(max) = max_depth {
            if depth >= max {
                break;
            }
        }
        let mut next = Vec::new();
        for node in &frontier {
            for e in &edges {
                if &e.from == node && !visited.contains(&e.to) && e.to != start {
                    visited.insert(e.to.clone());
                    next.push(e.to.clone());
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
        depth += 1;
    }
    visited.into_iter().collect()
}

#[cfg(test)]
mod sql_views {
    use super::*;

    fn hlc(p: u64) -> Hlc {
        Hlc::new(p, 0, "n1")
    }

    fn put(store: &mut KeyedStore, coll: &str, id: &str, field: &str, val: &[u8], t: u64) {
        store.doc_put_field(coll, id, field, Value::Scalar(val.to_vec()), hlc(t));
    }

    #[test]
    fn create_view_writes_catalog_as_data() {
        // DDL is not special: CREATE VIEW writes a plain doc into __catalog,
        // exactly like any other collection write (spec section 3.1).
        let mut store = KeyedStore::new();
        let def = ViewDef::over("users").filtered_eq("active", b"1".to_vec());
        create_view(&mut store, "active_users", def.clone(), hlc(1));

        assert_eq!(view_def(&store, "active_users"), Some(def));
        assert!(store
            .collections()
            .contains(&CATALOG_COLLECTION.to_string()));
        assert_eq!(list_views(&store), vec!["active_users".to_string()]);
    }

    #[test]
    fn view_is_pure_fold_of_source_no_side_index() {
        // A view's rows are a pure function of its def + the current fold of
        // its source collection (spec ViewIsPureFoldOfSources) -- no
        // separately stored materialization to go stale.
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u1", "active", b"1", 1);
        put(&mut store, "users", "u1", "name", b"alice", 1);
        put(&mut store, "users", "u2", "active", b"0", 1);

        let def = ViewDef::over("users").filtered_eq("active", b"1".to_vec());
        create_view(&mut store, "active_users", def, hlc(2));

        let rows = materialize_view(&store, "active_users").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "u1");
        assert_eq!(
            rows[0].fields.get("name"),
            Some(&Value::Scalar(b"alice".to_vec()))
        );

        // Writing MORE data to the same source is picked up on the next fold
        // -- no migration, no stale cache.
        put(&mut store, "users", "u3", "active", b"1", 3);
        let rows2 = materialize_view(&store, "active_users").unwrap();
        assert_eq!(rows2.len(), 2);
    }

    #[test]
    fn no_migration_on_new_view_old_view_untouched() {
        // Creating a NEW view over existing data folds from the unchanged
        // log and never disturbs an existing view over the same source
        // (spec NoMigrationOnNewView).
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u1", "active", b"1", 1);
        put(&mut store, "users", "u2", "active", b"0", 1);

        let all_view = ViewDef::over("users");
        create_view(&mut store, "all_users", all_view, hlc(2));
        let before = materialize_view(&store, "all_users").unwrap();

        // A brand new view, over the SAME source and existing data.
        let active_view = ViewDef::over("users").filtered_eq("active", b"1".to_vec());
        create_view(&mut store, "active_users", active_view, hlc(3));

        let after = materialize_view(&store, "all_users").unwrap();
        assert_eq!(
            before, after,
            "existing view unaffected by a new sibling view's creation"
        );
        assert_eq!(materialize_view(&store, "active_users").unwrap().len(), 1);
    }

    #[test]
    fn catalog_change_never_mutates_ordinary_rows() {
        // Appending a catalog op never changes the folded value of an
        // ordinary data field (spec CatalogChangeNeverMutatesRow) -- catalog
        // writes and the rows they describe are on separate keys of the same
        // log.
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u1", "name", b"alice", 1);
        let before = store.doc_get_field("users", "u1", "name");

        create_view(&mut store, "some_view", ViewDef::over("users"), hlc(2));

        assert_eq!(store.doc_get_field("users", "u1", "name"), before);
    }

    #[test]
    fn drop_view_removes_it_from_catalog_but_not_source() {
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u1", "name", b"alice", 1);
        create_view(&mut store, "v1", ViewDef::over("users"), hlc(2));
        assert!(view_def(&store, "v1").is_some());

        drop_view(&mut store, "v1", hlc(3));
        assert_eq!(view_def(&store, "v1"), None);
        assert_eq!(
            store.doc_get_field("users", "u1", "name"),
            Some(Value::Scalar(b"alice".to_vec()))
        );
    }

    #[test]
    fn projection_keeps_only_named_columns() {
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u1", "name", b"alice", 1);
        put(&mut store, "users", "u1", "age", b"30", 1);

        let def = ViewDef::over("users").projecting(["name".to_string()]);
        let rows = materialize(&store, &def);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].fields.contains_key("name"));
        assert!(!rows[0].fields.contains_key("age"));
    }

    #[test]
    fn aggregate_sum_is_a_query_pattern_over_the_same_fold() {
        let mut store = KeyedStore::new();
        put(&mut store, "orders", "o1", "amount", b"10", 1);
        put(&mut store, "orders", "o2", "amount", b"25", 1);
        put(&mut store, "orders", "o3", "amount", b"5", 1);

        assert_eq!(aggregate_sum(&store, "orders", "amount", None), 40);
    }

    #[test]
    fn aggregate_sum_respects_filter() {
        let mut store = KeyedStore::new();
        put(&mut store, "orders", "o1", "amount", b"10", 1);
        put(&mut store, "orders", "o1", "region", b"eu", 1);
        put(&mut store, "orders", "o2", "amount", b"25", 1);
        put(&mut store, "orders", "o2", "region", b"us", 1);

        let f = Filter {
            field: "region".to_string(),
            value: b"eu".to_vec(),
        };
        assert_eq!(aggregate_sum(&store, "orders", "amount", Some(&f)), 10);
    }

    #[test]
    fn group_by_sum_groups_and_sums_deterministically() {
        let mut store = KeyedStore::new();
        put(&mut store, "orders", "o1", "amount", b"10", 1);
        put(&mut store, "orders", "o1", "region", b"eu", 1);
        put(&mut store, "orders", "o2", "amount", b"25", 1);
        put(&mut store, "orders", "o2", "region", b"us", 1);
        put(&mut store, "orders", "o3", "amount", b"5", 1);
        put(&mut store, "orders", "o3", "region", b"eu", 1);

        let groups = aggregate_group_by_sum(&store, "orders", "region", "amount");
        assert_eq!(
            groups,
            vec![(b"eu".to_vec(), 15), (b"us".to_vec(), 25)],
            "sorted by group key, summed per group"
        );
    }

    #[test]
    fn traverse_follows_edges_recursively() {
        // Graph traversal is a recursive join over an edge collection -- a
        // query pattern, not a separate graph store.
        let mut store = KeyedStore::new();
        put(&mut store, "edges", "e1", "from", b"a", 1);
        put(&mut store, "edges", "e1", "to", b"b", 1);
        put(&mut store, "edges", "e2", "from", b"b", 1);
        put(&mut store, "edges", "e2", "to", b"c", 1);
        put(&mut store, "edges", "e3", "from", b"a", 1);
        put(&mut store, "edges", "e3", "to", b"d", 1);

        let reachable = traverse(&store, "edges", "a", None);
        assert_eq!(
            reachable,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn traverse_respects_max_depth() {
        let mut store = KeyedStore::new();
        put(&mut store, "edges", "e1", "from", b"a", 1);
        put(&mut store, "edges", "e1", "to", b"b", 1);
        put(&mut store, "edges", "e2", "from", b"b", 1);
        put(&mut store, "edges", "e2", "to", b"c", 1);

        let one_hop = traverse(&store, "edges", "a", Some(1));
        assert_eq!(one_hop, vec!["b".to_string()], "stops after one hop");

        let two_hop = traverse(&store, "edges", "a", Some(2));
        assert_eq!(two_hop, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn traverse_over_cyclic_graph_terminates() {
        // A cycle must not loop forever -- visited-set dedup terminates it.
        let mut store = KeyedStore::new();
        put(&mut store, "edges", "e1", "from", b"a", 1);
        put(&mut store, "edges", "e1", "to", b"b", 1);
        put(&mut store, "edges", "e2", "from", b"b", 1);
        put(&mut store, "edges", "e2", "to", b"a", 1);

        let reachable = traverse(&store, "edges", "a", None);
        assert_eq!(reachable, vec!["b".to_string()]);
    }

    #[test]
    fn doc_ids_backs_view_row_enumeration() {
        let mut store = KeyedStore::new();
        put(&mut store, "users", "u2", "name", b"bob", 1);
        put(&mut store, "users", "u1", "name", b"alice", 1);
        assert_eq!(
            store.doc_ids("users"),
            vec!["u1".to_string(), "u2".to_string()]
        );
    }
}
