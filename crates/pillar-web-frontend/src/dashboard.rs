//! The **Dashboard** observability product resource — a *composition* of PSL
//! panels, one of the natively-registered
//! [`pillar_manifest::builtin::BuiltinKind::Dashboard`] built-in kinds.
//!
//! A Dashboard never invents a second query model, a second manifest model, or
//! a second view-cache: it is glue over three things the swarm already built.
//!
//! 1. **Panels compose existing PSL ASTs.** Each [`Panel`] holds the SAME
//!    [`pillar_observability::PslQuery`] AST the Explore builder
//!    ([`crate::explore`]) emits — a Dashboard just names it and lays it out.
//!    No panel carries a bespoke query language.
//! 2. **A Dashboard renders to a real built-in [`Crd`].** [`Dashboard::to_crd`]
//!    produces a `Dashboard`-kind manifest whose `spec.panels` count is the
//!    panel count, and it validates against the EXACT
//!    [`BuiltinKind::Dashboard`] schema in the registry
//!    [`pillar_manifest::builtin::register_builtin_schemas`] populates — the
//!    same schema/validation path a third-party CRD walks, never a parallel one.
//! 3. **Each panel's query persists + renders as a materialized view.** A
//!    panel's query is rendered by materializing it against the live
//!    [`pillar_observability::TimeseriesStore`] through the SAME
//!    [`pillar_observability::ViewCache`] the raw-query surface uses (keyed on
//!    `(query, held-set root)`), so re-rendering an unchanged panel over an
//!    unchanged store is a cache HIT — no re-scan. The named,
//!    [`pillar_observability::PersistedMaterializedView`] form (survives a
//!    process restart) is reused verbatim; a Dashboard adds no divergent cache.
//!
//! **Cell scope + sharing.** A Dashboard is created INSIDE a cell
//! ([`CellId`]) and is only readable by a peer that (a) is in that SAME cell
//! and (b) has been granted read on it — [`Dashboard::readable_by`]. A peer in
//! a *different* cell can never read it (cell isolation), and an in-cell peer
//! reads it only once [`Dashboard::share_with`] authorizes them (shareable).
//! This mirrors the platform's per-cell object visibility (`pillar_cells`)
//! without dragging the crypto stack into the host-testable frontend: the
//! authorization DECISION is pure Rust and asserted directly.
//!
//! Like `explore`/`panels`, everything here is pure, host-testable Rust —
//! there is no Yew/DOM surface to gate, so the whole module compiles and tests
//! on the native host with a plain `cargo test`.

use std::collections::BTreeSet;

use pillar_manifest::builtin::BuiltinKind;
use pillar_manifest::{Crd, Metadata, SchemaRegistry, Value};
use pillar_observability::{
    PersistedMaterializedView, PslQuery, Query, SignalId, SignalKind, TimeseriesStore, ViewCache,
    ViewPersistError,
};

/// The cell a Dashboard lives in — the isolation boundary. A peer outside this
/// cell can never read the dashboard, exactly as a per-cell sealed object is
/// invisible outside its cell.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(pub String);

impl From<&str> for CellId {
    fn from(s: &str) -> Self {
        CellId(s.to_owned())
    }
}

/// A peer identity (a member principal) that may be granted read on a
/// Dashboard. Kept opaque so this module needs none of the crypto stack.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub String);

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        PeerId(s.to_owned())
    }
}

/// A single dashboard panel: a titled visualization backed by ONE PSL query
/// AST (the same [`PslQuery`] the Explore builder emits) plus its layout order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Panel {
    /// The panel's display title.
    pub title: String,
    /// The panel's query — a PSL AST composed by the Explore builder, stored
    /// verbatim. This is the panel's persisted definition.
    pub query: PslQuery,
}

impl Panel {
    /// A panel titled `title` backed by the PSL AST `query`.
    #[must_use]
    pub fn new(title: impl Into<String>, query: PslQuery) -> Self {
        Panel {
            title: title.into(),
            query,
        }
    }

    /// The signal kind this panel's query selects — the first `select:` kind of
    /// its PSL AST. Used to key the panel's materialized view. A well-formed
    /// PSL query always has at least one select clause (`PslQueryBuilder::build`
    /// rejects an empty one), so this is total for any panel built through the
    /// Explore surface.
    #[must_use]
    pub fn select_kind(&self) -> SignalKind {
        self.query
            .selects
            .first()
            .map_or(SignalKind::Metric, |s| s.kind)
    }

    /// The raw-query view this panel materializes: its select kind, in the
    /// SAME [`Query`] vocabulary [`ViewCache`]/[`PersistedMaterializedView`]
    /// cache on. A Dashboard does not invent a second query model.
    #[must_use]
    pub fn view_query(&self) -> Query {
        Query::of_kind(self.select_kind())
    }
}

/// A Dashboard: a cell-scoped composition of PSL panels plus a read-share ACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dashboard {
    /// The dashboard's name (its `metadata.name` when rendered to a `Crd`).
    pub name: String,
    /// The cell this dashboard lives in — its isolation boundary.
    pub cell: CellId,
    /// The panels, in layout order.
    pub panels: Vec<Panel>,
    /// The in-cell peers granted read on this dashboard (shareable).
    shared_with: BTreeSet<PeerId>,
}

impl Dashboard {
    /// A new, empty dashboard named `name`, scoped to `cell`, shared with
    /// nobody yet.
    #[must_use]
    pub fn new(name: impl Into<String>, cell: CellId) -> Self {
        Dashboard {
            name: name.into(),
            cell,
            panels: Vec::new(),
            shared_with: BTreeSet::new(),
        }
    }

    /// Append a panel (builder-style), preserving layout order.
    #[must_use]
    pub fn with_panel(mut self, panel: Panel) -> Self {
        self.panels.push(panel);
        self
    }

    /// The number of panels this dashboard composes.
    #[must_use]
    pub fn panel_count(&self) -> usize {
        self.panels.len()
    }

    /// Render this dashboard to its built-in [`Crd`] manifest: a
    /// `Dashboard`-kind resource carrying the required `title` (the dashboard
    /// name) and the `panels` count in its `spec`. This is exactly the body a
    /// controller sees, validated by the built-in [`BuiltinKind::Dashboard`]
    /// schema — never a parallel manifest shape.
    #[must_use]
    pub fn to_crd(&self) -> Crd {
        let (api_version, kind) = BuiltinKind::Dashboard.key();
        Crd::new(api_version, kind, Metadata::new(self.name.clone()))
            .with_spec("title", Value::String(self.name.clone()))
            .with_spec("panels", Value::Integer(self.panels.len() as i64))
    }

    /// Validate this dashboard's rendered manifest against the built-in schema
    /// registry. `Ok(())` iff the `Dashboard` schema (registered by
    /// [`pillar_manifest::builtin::register_builtin_schemas`]) accepts it.
    ///
    /// # Errors
    ///
    /// Returns the schema error (unknown kind, missing required field, or a
    /// type mismatch) the registry raises.
    pub fn validate(&self, registry: &SchemaRegistry) -> Result<(), pillar_manifest::SchemaError> {
        registry.validate(&self.to_crd())
    }

    /// Grant peer `peer` read on this dashboard (shareable). Only meaningful
    /// for a peer already in this dashboard's cell — cell membership is checked
    /// at read time by [`readable_by`](Self::readable_by), so sharing with a
    /// peer that later must be in-cell to actually read is safe.
    pub fn share_with(&mut self, peer: impl Into<PeerId>) {
        self.shared_with.insert(peer.into());
    }

    /// Whether `peer`, who is a member of `peer_cell`, may read this dashboard.
    ///
    /// Read requires BOTH: the peer is in the SAME cell as the dashboard (cell
    /// isolation — a peer in a different cell can never read it), AND the peer
    /// has been granted read via [`share_with`](Self::share_with) (shareable —
    /// an in-cell peer reads only once authorized).
    #[must_use]
    pub fn readable_by(&self, peer: &PeerId, peer_cell: &CellId) -> bool {
        peer_cell == &self.cell && self.shared_with.contains(peer)
    }

    /// Render every panel to its materialized view over `store`, reusing the
    /// shared [`ViewCache`] so an unchanged panel over an unchanged store is a
    /// cache HIT (no re-scan). Returns one `(panel-title, signal ids)` per
    /// panel, in layout order.
    pub fn render(&self, store: &TimeseriesStore, cache: &mut ViewCache) -> Vec<(String, Vec<SignalId>)> {
        self.panels
            .iter()
            .map(|panel| (panel.title.clone(), cache.materialize(store, panel.view_query())))
            .collect()
    }
}

/// Render a single panel through its NAMED, durably-persisted materialized
/// view (survives a process restart), keyed by the panel's title under
/// `root_dir`. Reuses [`PersistedMaterializedView`] verbatim — a Dashboard
/// adds no divergent persistence.
///
/// # Errors
///
/// Propagates any [`ViewPersistError`] the persisted view raises.
pub fn render_panel_persisted(
    panel: &Panel,
    store: &TimeseriesStore,
    root_dir: impl Into<std::path::PathBuf>,
) -> Result<Vec<SignalId>, ViewPersistError> {
    let view = PersistedMaterializedView::open(panel.title.clone(), root_dir)?;
    view.materialize(store, panel.view_query())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::builtin::register_builtin_schemas;
    use pillar_observability::PslQueryBuilder;

    /// A panel whose query selects `kind` over a `range` window — built through
    /// the real PSL builder, exactly as an Explore selection would be.
    fn panel(title: &str, kind: SignalKind) -> Panel {
        let query = PslQueryBuilder::new()
            .select(kind, vec![])
            .range_relative(300)
            .build()
            .expect("select + range is a valid PSL query");
        Panel::new(title, query)
    }

    fn dashboard_with_n_panels(n: usize, cell: &str) -> Dashboard {
        let kinds = [
            SignalKind::Metric,
            SignalKind::Log,
            SignalKind::TraceSpan,
            SignalKind::ProfileSample,
            SignalKind::MetadataSample,
        ];
        let mut d = Dashboard::new("overview", CellId::from(cell));
        for i in 0..n {
            d = d.with_panel(panel(&format!("panel-{i}"), kinds[i % kinds.len()]));
        }
        d
    }

    #[test]
    fn a_dashboard_with_n_panels_validates_against_the_builtin_schema() {
        let mut registry = SchemaRegistry::new();
        register_builtin_schemas(&mut registry);

        for n in [0usize, 1, 3, 7] {
            let d = dashboard_with_n_panels(n, "cell-a");
            assert_eq!(d.panel_count(), n);
            // Renders to the Dashboard built-in kind and validates against its
            // own schema — the SAME path any built-in/third-party CRD walks.
            let crd = d.to_crd();
            assert_eq!(crd.kind, BuiltinKind::Dashboard.kind_str());
            assert_eq!(crd.spec.get("panels"), Some(&Value::Integer(n as i64)));
            d.validate(&registry)
                .unwrap_or_else(|e| panic!("dashboard with {n} panels must validate: {e}"));
        }
    }

    #[test]
    fn each_panels_query_persists_and_renders_as_a_materialized_view_no_rescan() {
        let mut store = TimeseriesStore::new(16, 1000);
        // A held set across several kinds so panels of different kinds match.
        store.write(SignalKind::Metric, b"m".to_vec(), 1);
        store.write(SignalKind::Log, b"l".to_vec(), 1);
        store.write(SignalKind::TraceSpan, b"t".to_vec(), 1);

        let d = dashboard_with_n_panels(3, "cell-a");
        let mut cache = ViewCache::new();

        // First render: one miss per DISTINCT panel query (kinds metric/log/trace).
        let first = d.render(&store, &mut cache);
        assert_eq!(first.len(), 3);
        assert_eq!(cache.misses(), 3, "first render materializes each panel");
        assert_eq!(cache.hits(), 0);

        // Repeat render over the UNCHANGED store: every panel is a cache hit —
        // no re-scan of the held set.
        let second = d.render(&store, &mut cache);
        assert_eq!(second, first, "an unchanged panel renders identically");
        assert_eq!(cache.hits(), 3, "repeat render re-scans nothing");
        assert_eq!(cache.misses(), 3, "no new materialization on repeat");
    }

    #[test]
    fn a_panel_view_persists_across_a_restart() {
        let dir = std::env::temp_dir().join(format!(
            "pillar-dashboard-view-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = TimeseriesStore::new(16, 1000);
        store.write(SignalKind::Metric, b"m".to_vec(), 1);
        let p = panel("cpu", SignalKind::Metric);

        let first = render_panel_persisted(&p, &store, &dir).expect("first materialize");
        // A brand-new persisted-view handle (standing in for a process restart)
        // recognizes the on-disk record for the same (query, root) and returns
        // it verbatim — a restart is not a forced recompute.
        let after_restart = render_panel_persisted(&p, &store, &dir).expect("post-restart");
        assert_eq!(after_restart, first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dashboard_is_cell_scoped_a_peer_in_a_different_cell_cannot_read() {
        let mut d = dashboard_with_n_panels(2, "cell-a");
        let peer = PeerId::from("bob");
        // Even after being granted read, a peer whose cell differs cannot read.
        d.share_with(peer.clone());
        assert!(
            !d.readable_by(&peer, &CellId::from("cell-b")),
            "a peer in a different cell must never read the dashboard"
        );
    }

    #[test]
    fn a_dashboard_is_shareable_an_authorized_in_cell_peer_can_read() {
        let mut d = dashboard_with_n_panels(2, "cell-a");
        let peer = PeerId::from("alice");
        // Same cell but not yet shared: no read.
        assert!(
            !d.readable_by(&peer, &CellId::from("cell-a")),
            "an unshared in-cell peer cannot read yet"
        );
        // Share, then the same-cell peer can read.
        d.share_with(peer.clone());
        assert!(
            d.readable_by(&peer, &CellId::from("cell-a")),
            "an authorized in-cell peer can read the shared dashboard"
        );
    }
}
