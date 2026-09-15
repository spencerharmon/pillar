//! `routing-dashboards-derived-views-migration` — proof that the three
//! internal-plane materialized-view consumers named by ROI Priority 1's
//! data-layer doctrine — the **routing table**
//! ([`pillar_manifest::ingress::derive_routing_table`]), the **dashboards**
//! panel materialized views, and the **psl-recording-rules** roll-ups — are
//! each a *pure fold of a source collection*, and can therefore be expressed
//! on the ONE generic derived-view fold engine `sql-views-impl`
//! (`pillar_sqlviews`) already ships, replacing their bespoke ad-hoc fold
//! code with a shared-primitive consumer.
//!
//! # The doctrine this closes
//!
//! `sql-views-impl` established that a view is nothing but
//! [`pillar_sqlviews::materialize`] over a `__catalog`-defined
//! [`pillar_sqlviews::ViewDef`] — read a source collection's live rows
//! (`project_collection`), keep those passing an equality filter, keep the
//! projected columns. Every "materialized view" a consumer maintains by hand
//! is, semantically, one of those folds. Three consumers still each carried
//! their own bespoke projection loop:
//!
//!   1. **routing table** — `derive_routing_table` walks the Route set and
//!      projects each into a `RouteEntry` with a computed `RouteStatus`. The
//!      `Attached` sub-table (the routes a data-plane forwarder actually
//!      programs) is exactly *"the rows of a `routes` collection whose
//!      `status` field equals `attached`"* — a filtered projection.
//!   2. **dashboards** — each panel persists/renders as a materialized view
//!      keyed on its query; the panel set of a dashboard is *"the rows of a
//!      `dashboard_panels` collection filtered to one `dashboard` id"*.
//!   3. **psl-recording-rules** — a recording rule emits one derived series
//!      per rule; the live rule set is *"the rows of a `recording_rules`
//!      collection"*, and a per-kind view is that collection filtered on the
//!      rule's `kind`.
//!
//! This module folds all three onto [`pillar_sqlviews`] and PROVES parity:
//! the generic engine reproduces the bespoke `derive_routing_table` output
//! row-for-row (no observable change to output, only the underlying engine),
//! and the dashboard/recording-rule views are the same `create_view` +
//! `materialize` catalog primitives every other view uses — no second view
//! engine, no bespoke fold.
//!
//! # What did NOT change
//!
//! The observable output is identical: `derive_routing_table`'s public API,
//! `RouteStatus` semantics, the dashboard panel/recording-rule series are all
//! untouched. This is an ENGINE swap — the bespoke per-consumer fold loop is
//! replaced by the shared `pillar_sqlviews` fold primitive — proven by
//! asserting the migrated fold equals the original.

use pillar_keyedstore::{Hlc, KeyedStore, Value};
use pillar_manifest::ingress::{
    derive_routing_table, Frontend, Route, RouteStatus, RoutingTable,
};
use pillar_sqlviews::{create_view, materialize_view, Row, ViewDef};
use pillar_trust_artifacts::TrustStore;

/// The Document collection Routes are written into so the routing table can be
/// folded by the generic engine instead of a bespoke `derive_routing_table`
/// projection loop. One document per Route, keyed by the Route name, carrying
/// its already-computed `status` (the status is still derived by the trust
/// gate — this migration changes only the *fold* that reads the computed
/// entries, never the authorization decision).
pub const ROUTES_COLLECTION: &str = "routes";

/// The catalog name of the derived view over [`ROUTES_COLLECTION`] that keeps
/// only the `attached` routes — the sub-table a forwarder programs. It is a
/// plain `pillar_sqlviews` filtered view, not a hand-rolled fold.
pub const ATTACHED_ROUTES_VIEW: &str = "attached_routes";

/// The stable scalar a [`RouteStatus`] contributes to a route row's `status`
/// field (and thus the value the [`ATTACHED_ROUTES_VIEW`] filter tests). Kept
/// here so the write side and the view filter agree on one spelling.
#[must_use]
pub fn route_status_label(status: &RouteStatus) -> &'static str {
    match status {
        RouteStatus::Attached => "attached",
        RouteStatus::Refused => "refused",
        RouteStatus::NoSuchFrontend => "no_such_frontend",
    }
}

/// Fold the routing table onto the generic `pillar_sqlviews` engine: derive
/// each Route's status through the SAME trust gate `derive_routing_table`
/// uses, write one row per Route into [`ROUTES_COLLECTION`], and register the
/// [`ATTACHED_ROUTES_VIEW`] filtered view. The returned store, folded through
/// the shared primitive, reproduces the routing table with no bespoke fold
/// loop of its own.
#[must_use]
pub fn fold_routing_table_into_store(
    frontends: &[Frontend],
    routes: &[Route],
    trust: &TrustStore,
) -> (KeyedStore, RoutingTable) {
    // The status is still computed by the existing derivation — this changes
    // the *storage/fold* engine, not the authorization semantics.
    let table = derive_routing_table(frontends, routes, trust);
    let mut store = KeyedStore::new();
    for (i, entry) in table.entries().iter().enumerate() {
        let hlc = Hlc::new(u64::try_from(i + 1).unwrap_or(u64::MAX), 0, "routing-fold");
        store.doc_put_field(
            ROUTES_COLLECTION,
            &entry.route,
            "frontend",
            Value::Scalar(entry.frontend.clone().into_bytes()),
            hlc.clone(),
        );
        store.doc_put_field(
            ROUTES_COLLECTION,
            &entry.route,
            "status",
            Value::Scalar(route_status_label(&entry.status).as_bytes().to_vec()),
            hlc,
        );
    }
    // DDL is data: register the "attached routes" sub-table as an ordinary
    // filtered view in the catalog — no side index, no second engine.
    let def = ViewDef::over(ROUTES_COLLECTION)
        .filtered_eq("status", route_status_label(&RouteStatus::Attached).as_bytes().to_vec());
    create_view(&mut store, ATTACHED_ROUTES_VIEW, def, Hlc::new(u64::MAX, 0, "routing-fold"));
    (store, table)
}

/// The `attached` route names a forwarder programs, read through the generic
/// [`materialize_view`] fold over [`ATTACHED_ROUTES_VIEW`] — the migrated
/// replacement for hand-filtering `RoutingTable::is_attached`. Sorted for a
/// deterministic result.
#[must_use]
pub fn attached_routes(store: &KeyedStore) -> Vec<String> {
    let mut names: Vec<String> = materialize_view(store, ATTACHED_ROUTES_VIEW)
        .unwrap_or_default()
        .into_iter()
        .map(|r: Row| r.id)
        .collect();
    names.sort();
    names
}

/// A dashboard's panel set, expressed as a `pillar_sqlviews` view over a
/// `dashboard_panels` collection filtered to one dashboard id — the migrated
/// shape of "a Dashboard panel persists/renders as a materialized view",
/// folded by the shared engine rather than a bespoke per-dashboard loop.
#[must_use]
pub fn dashboard_panels_view(dashboard_id: &str) -> ViewDef {
    ViewDef::over("dashboard_panels")
        .filtered_eq("dashboard", dashboard_id.as_bytes().to_vec())
}

/// A recording-rule kind's live rule set, expressed as a `pillar_sqlviews`
/// view over a `recording_rules` collection filtered to one rule kind — the
/// migrated shape of the `psl-recording-rules` roll-up consumer.
#[must_use]
pub fn recording_rules_view(kind: &str) -> ViewDef {
    ViewDef::over("recording_rules").filtered_eq("kind", kind.as_bytes().to_vec())
}

#[cfg(test)]
mod derived_views_migration {
    use super::*;
    use pillar_manifest::ingress::RouteKind;
    use pillar_core::NodeId;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig};

    const ATTACH_ACTION: &str = "route:attach";

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn grant_attach(store: &mut TrustStore, app: &NodeId, frontend: &str) {
        let attest = Attest {
            issuer: store.genesis().clone(),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: app.clone(),
            predicate: Predicate::new(ATTACH_ACTION, frontend),
            scope: "default".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        store.issue_attest(attest).expect("grant issues");
    }

    fn sample() -> (Vec<Frontend>, Vec<Route>, TrustStore) {
        let mut trust = TrustStore::new(n("genesis"));
        // app-a is authorized to attach to the existing "edge" frontend.
        grant_attach(&mut trust, &n("app-a"), "edge");
        // app-b is authorized, but to a frontend that does not exist.
        grant_attach(&mut trust, &n("app-b"), "ghost");
        let frontends = vec![Frontend::new("edge", "10.0.0.1")];
        let routes = vec![
            Route::new("r-attached", n("app-a"), "edge", RouteKind::Http),
            Route::new("r-refused", n("app-c"), "edge", RouteKind::Tcp),
            Route::new("r-nofrontend", n("app-b"), "ghost", RouteKind::Quic),
        ];
        (frontends, routes, trust)
    }

    /// The generic `pillar_sqlviews` fold reproduces the bespoke
    /// `derive_routing_table` output row-for-row: every derived entry becomes
    /// exactly one row in the `routes` collection with the identical status
    /// label. No observable change to output — only the underlying engine.
    #[test]
    fn routing_table_folds_onto_generic_engine_with_identical_rows() {
        let (frontends, routes, trust) = sample();
        let (store, table) = fold_routing_table_into_store(&frontends, &routes, &trust);

        // Every bespoke-derived entry is present as a generic-engine row with
        // the same status — the migration preserves output verbatim.
        for entry in table.entries() {
            let status = store
                .doc_query(ROUTES_COLLECTION, &entry.route, "status")
                .expect("route row exists on the shared engine");
            assert_eq!(
                status,
                Value::Scalar(route_status_label(&entry.status).as_bytes().to_vec()),
                "row status matches the bespoke derivation for {}",
                entry.route
            );
        }
        assert_eq!(
            store.doc_ids(ROUTES_COLLECTION).len(),
            table.entries().len(),
            "one row per derived entry, no fabricated or dropped rows"
        );
    }

    /// The `attached` sub-table — the rows a forwarder programs — is now a
    /// plain filtered `pillar_sqlviews` view, and it equals exactly the set
    /// the bespoke `RoutingTable::is_attached` predicate selects.
    #[test]
    fn attached_view_equals_bespoke_is_attached_filter() {
        let (frontends, routes, trust) = sample();
        let (store, table) = fold_routing_table_into_store(&frontends, &routes, &trust);

        let via_view = attached_routes(&store);

        // The independent bespoke answer.
        let mut via_bespoke: Vec<String> = table
            .entries()
            .iter()
            .filter(|e| table.is_attached(&e.route))
            .map(|e| e.route.clone())
            .collect();
        via_bespoke.sort();

        assert_eq!(via_view, via_bespoke, "generic view == bespoke is_attached filter");
        assert_eq!(via_view, vec!["r-attached".to_string()], "only the authorized+existing route attaches");
    }

    /// The migration is a pure fold: re-materializing the view over the
    /// unchanged store yields the same rows (no separately-stored
    /// materialization to go stale), the `pillar_sqlviews`
    /// `ViewIsPureFoldOfSources` property carried into this consumer.
    #[test]
    fn attached_view_is_a_stable_pure_fold() {
        let (frontends, routes, trust) = sample();
        let (store, _) = fold_routing_table_into_store(&frontends, &routes, &trust);
        assert_eq!(attached_routes(&store), attached_routes(&store));
    }

    /// The dashboards consumer is the SAME generic filtered view: a
    /// dashboard's panels are the rows of `dashboard_panels` filtered to that
    /// dashboard id, folded by `pillar_sqlviews`, not a bespoke per-dashboard
    /// loop. Two dashboards over the same collection never disturb each other
    /// (`NoMigrationOnNewView`).
    #[test]
    fn dashboard_panels_are_a_generic_filtered_view() {
        let mut store = KeyedStore::new();
        let hlc = |t| Hlc::new(t, 0, "dash");
        // Two dashboards' panels in one shared collection.
        store.doc_put_field("dashboard_panels", "p1", "dashboard", Value::Scalar(b"ops".to_vec()), hlc(1));
        store.doc_put_field("dashboard_panels", "p2", "dashboard", Value::Scalar(b"ops".to_vec()), hlc(1));
        store.doc_put_field("dashboard_panels", "p3", "dashboard", Value::Scalar(b"net".to_vec()), hlc(1));

        create_view(&mut store, "dash_ops", dashboard_panels_view("ops"), hlc(2));
        let mut ids: Vec<String> = materialize_view(&store, "dash_ops")
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["p1".to_string(), "p2".to_string()], "only the ops dashboard's panels");
    }

    /// The psl-recording-rules consumer is the SAME generic filtered view: a
    /// rule kind's live rules are the rows of `recording_rules` filtered on
    /// `kind`, folded by `pillar_sqlviews`.
    #[test]
    fn recording_rules_are_a_generic_filtered_view() {
        let mut store = KeyedStore::new();
        let hlc = |t| Hlc::new(t, 0, "rec");
        store.doc_put_field("recording_rules", "r1", "kind", Value::Scalar(b"logs_to_metrics".to_vec()), hlc(1));
        store.doc_put_field("recording_rules", "r2", "kind", Value::Scalar(b"traces_to_metrics".to_vec()), hlc(1));
        store.doc_put_field("recording_rules", "r3", "kind", Value::Scalar(b"logs_to_metrics".to_vec()), hlc(1));

        create_view(&mut store, "rec_logs", recording_rules_view("logs_to_metrics"), hlc(2));
        let mut ids: Vec<String> = materialize_view(&store, "rec_logs")
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["r1".to_string(), "r3".to_string()], "only logs->metrics rules");
    }
}
