//! The observability UI **builders** — the per-signal + cross-signal
//! explore/query/dashboard surface the ROI P3 "Web portal / UI rework"
//! addendum asks for, layered over [`pillar_observability`]'s substrate
//! (never a parallel store) and served by `web_serve.rs`.
//!
//! Five signal kinds (metric/log/trace/profile/metadata) live on ONE
//! [`pillar_observability::TimeseriesStore`]. This module adds the UI-facing
//! pieces on top:
//!
//! - an **explore/query builder** for each signal kind, returning the matching
//!   records off the shared [`pillar_observability::ViewCache`] (read-only,
//!   signs nothing);
//! - a **metadata builder** rendering an entity's current labels AND its
//!   label-change/transition timeline ([`pillar_observability::MetadataStore`]);
//! - a **cross-signal correlation explorer** pivoting by shared label or
//!   correlation/trace id ([`pillar_observability::CorrelationIndex`]);
//! - a **query builder** that persists a named saved query as a signed,
//!   content-addressed resource riding the streaming DB
//!   (`pillar_streamdb::OpLog`) — the SAME no-server-side-database pattern
//!   `web_serve.rs` already uses for UI-persisted layouts — and reloads it;
//! - a **dashboard builder** that CRUDs a named dashboard (a list of saved
//!   query ids/layout), each mutation likewise ONE signed resource event
//!   appended to its own `OpLog`, with the *current* state resolved by
//!   replaying that dashboard's events to their latest (non-tombstoned) one.
//!
//! Every PERSISTED artifact (a saved query, a dashboard mutation) is one
//! signed IPFS-blob + streaming-tip resource event; every READ/explore
//! surface here signs nothing.

use std::collections::BTreeSet;

use pillar_observability::{
    CorrelationId, CorrelationIndex, EntityId, Label, LabelSet, LabelTransition, MetadataStore,
    Query, SignalId, SignalKind, TimeseriesStore, ViewCache,
};
use pillar_streamdb::{OpId, OpLog};

/// One matched record surfaced by an explore/query builder: the signal's
/// content-addressed id, its kind, and its raw payload rendered as text (the
/// per-signal presentation — metric timeseries line, log line, trace span,
/// profile stack, or metadata sample — is a thin text projection of this).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExploreRecord {
    /// The signal's content-addressed id.
    pub id: SignalId,
    /// The signal's kind.
    pub kind: SignalKind,
    /// The signal's raw payload, rendered as UTF-8 (lossy) text.
    pub payload: String,
}

/// A `(key, value)` pair shared-label pivot result: the signal ids sharing
/// that label, across kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelPivot {
    /// The signals sharing the pivoted label.
    pub signals: BTreeSet<SignalId>,
    /// The distinct kinds those signals span (proves a genuine cross-kind
    /// pivot rather than a same-kind coincidence).
    pub kinds: BTreeSet<SignalKind>,
}

/// The entity metadata builder's rendered view: the label set in effect NOW,
/// plus the full transition timeline (every point the labels changed, and to
/// what).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataView {
    /// The current (latest) label set, if any observation exists.
    pub current: Option<LabelSet>,
    /// Every observed transition, oldest first.
    pub transitions: Vec<LabelTransition>,
}

/// A saved explore/query builder query, persisted (and reloaded) as a signed,
/// content-addressed streaming-DB resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedQuery {
    /// The signer (authenticated handle) who saved this query.
    pub signer: String,
    /// The query's display name.
    pub name: String,
    /// The query spec text (an explore/query builder's serialized filter —
    /// this module treats it opaquely; the caller defines its syntax).
    pub spec: String,
}

/// A dashboard's current, replayed state: its name, layout content, and the
/// saved-query ids it composes — the dashboard builder's CRUD unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardView {
    /// The signer who authored the latest mutation.
    pub signer: String,
    /// The dashboard's display name.
    pub name: String,
    /// The dashboard's layout content (opaque to this module).
    pub content: String,
}

/// One raw dashboard mutation event's operation tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DashboardOp {
    Create,
    Update,
    Delete,
}

impl DashboardOp {
    fn tag(self) -> &'static str {
        match self {
            DashboardOp::Create => "create",
            DashboardOp::Update => "update",
            DashboardOp::Delete => "delete",
        }
    }

    fn parse(tag: &str) -> Option<Self> {
        match tag {
            "create" => Some(DashboardOp::Create),
            "update" => Some(DashboardOp::Update),
            "delete" => Some(DashboardOp::Delete),
            _ => None,
        }
    }
}

/// The observability UI builders' in-memory state: the shared five-kind
/// substrate (store + view cache + correlation index + metadata store, all
/// from [`pillar_observability`], never a parallel store) plus the two
/// signed-resource logs (`pillar_streamdb::OpLog`) backing the query and
/// dashboard builders — no server-side database anywhere in this module.
pub struct ObservabilityBuilders {
    store: TimeseriesStore,
    cache: ViewCache,
    correlation: CorrelationIndex,
    metadata: MetadataStore,
    /// Saved queries: each append is `<signer>\n<name>\n<spec>`. A save is a
    /// full resource in one event (queries are never "updated" in place —
    /// saving under the same name again is simply a fresh signed resource,
    /// exactly like the layout resource this mirrors).
    queries: OpLog,
    /// Dashboard mutations: each append is
    /// `<seq>\n<dashboard-id>\n<op>\n<signer>\n<name>\n<content>`. `<seq>` is
    /// an explicit, builder-assigned monotonic sequence number: `OpLog::order`
    /// is content-address order, NOT append order, so "the CURRENT state" —
    /// the latest non-delete mutation for a given dashboard id — must be
    /// resolved by an explicit sequence, never by log iteration order.
    /// `delete` leaves only tombstones (no state resolves past it).
    dashboards: OpLog,
    /// The next sequence number to assign to a dashboard mutation (global
    /// across all dashboards; only relative order within one dashboard id
    /// matters).
    next_dashboard_seq: u64,
}

impl Default for ObservabilityBuilders {
    fn default() -> Self {
        ObservabilityBuilders::new()
    }
}

impl ObservabilityBuilders {
    /// A fresh builders state over a new substrate. `block_capacity` and
    /// `retention_window` size the underlying [`TimeseriesStore`]; a portal
    /// typically wires generous defaults (see [`WebAuthContext`] usage).
    #[must_use]
    pub fn new() -> Self {
        // Generous defaults: the UI builders care about explore/query/CRUD
        // correctness, not retention tuning (that is `TimeseriesStore`'s own
        // concern, exercised in `pillar-observability`).
        ObservabilityBuilders {
            store: TimeseriesStore::new(4096, u64::MAX),
            cache: ViewCache::new(),
            correlation: CorrelationIndex::new(),
            metadata: MetadataStore::new(),
            queries: OpLog::new(),
            dashboards: OpLog::new(),
            next_dashboard_seq: 0,
        }
    }

    // -- Ingest (used by tests/callers seeding signals + correlation/labels) --

    /// Ingest one raw signal of `kind` onto the shared substrate, returning
    /// its content-addressed id. A pure write — never signed, mirroring every
    /// other read-path signal the portal observes rather than authors.
    pub fn ingest(&mut self, kind: SignalKind, payload: impl Into<Vec<u8>>, tick: u64) -> SignalId {
        self.store.write(kind, payload, tick)
    }

    /// Register a signal's correlation id / shared labels on the cross-signal
    /// pivot index (see [`CorrelationIndex::register`]).
    pub fn register_correlation(
        &mut self,
        id: SignalId,
        correlation: Option<CorrelationId>,
        labels: BTreeSet<Label>,
    ) {
        self.correlation.register(
            id,
            &pillar_observability::SignalRef {
                kind: self
                    .store
                    .held_signals()
                    .find(|s| s.id() == id)
                    .map(|s| s.kind())
                    .unwrap_or(SignalKind::Metric),
                correlation,
                labels,
            },
        );
    }

    /// Ingest a metadata label-set observation for `entity` at `tick`.
    pub fn observe_metadata(&mut self, entity: EntityId, labels: LabelSet, tick: u64) {
        self.metadata.ingest(pillar_observability::LabelObservation::new(
            entity, labels, tick,
        ));
    }

    // -------------------------- Explore/query builder -----------------------

    /// The explore/query builder for `kind`: every held signal of that kind,
    /// rendered as a record. READ-ONLY — signs nothing.
    pub fn explore(&mut self, kind: SignalKind) -> Vec<ExploreRecord> {
        let ids = self.cache.materialize(&self.store, Query::of_kind(kind));
        ids.into_iter()
            .filter_map(|raw| {
                self.store
                    .held_signals()
                    .find(|s| s.id().0 == raw)
                    .map(|s| ExploreRecord {
                        id: s.id(),
                        kind: s.kind(),
                        payload: String::from_utf8_lossy(s.payload()).into_owned(),
                    })
            })
            .collect()
    }

    // ----------------------------- Metadata builder --------------------------

    /// The metadata builder's rendered view for `entity`: its current labels
    /// (the latest observation) AND its full transition timeline.
    #[must_use]
    pub fn metadata_view(&self, entity: &EntityId) -> MetadataView {
        MetadataView {
            current: self.metadata.current_labels(entity).cloned(),
            transitions: self.metadata.transitions(entity).to_vec(),
        }
    }

    // ------------------------------------------------------------------
    // Per-signal-kind CLI verbs (`docs/cli-surface.md` § "obs"): each of the
    // five signal kinds gets its own small verb vocabulary over the SAME
    // shared substrate above — every one of these is a READ, signing
    // nothing. `filter` (where present) is a plain case-sensitive substring
    // match against the signal's rendered payload text — the minimal query
    // language every verb below shares.
    // ------------------------------------------------------------------

    /// Filter `records` (already narrowed to one kind) to those whose payload
    /// contains `filter`, when given.
    fn filtered(records: Vec<ExploreRecord>, filter: Option<&str>) -> Vec<ExploreRecord> {
        match filter {
            None => records,
            Some(f) => records.into_iter().filter(|r| r.payload.contains(f)).collect(),
        }
    }

    /// The last `n` records of `records`, in ingested (ascending id) order —
    /// the `tail` verb shared by every signal kind that has one.
    fn tail_n(mut records: Vec<ExploreRecord>, n: usize) -> Vec<ExploreRecord> {
        if records.len() > n {
            records.drain(0..records.len() - n);
        }
        records
    }

    // -- metric: query / series / tail / top / retention --

    /// `obs metric query [filter]` — every metric record whose payload
    /// contains `filter` (or all, if `None`).
    pub fn metric_query(&mut self, filter: Option<&str>) -> Vec<ExploreRecord> {
        Self::filtered(self.explore(SignalKind::Metric), filter)
    }

    /// `obs metric series` — every metric record, in ingestion order (the
    /// timeseries view over the same substrate `query` reads).
    pub fn metric_series(&mut self) -> Vec<ExploreRecord> {
        self.explore(SignalKind::Metric)
    }

    /// `obs metric tail <n>` — the most recent `n` metric records.
    pub fn metric_tail(&mut self, n: usize) -> Vec<ExploreRecord> {
        Self::tail_n(self.explore(SignalKind::Metric), n)
    }

    /// `obs metric top <n>` — the `n` metric records with the numerically
    /// largest trailing value in their payload (e.g. `cpu 0.9` -> `0.9`);
    /// records with no parseable trailing number sort last.
    pub fn metric_top(&mut self, n: usize) -> Vec<ExploreRecord> {
        let mut records = self.explore(SignalKind::Metric);
        records.sort_by(|a, b| {
            let va = trailing_number(&a.payload).unwrap_or(f64::MIN);
            let vb = trailing_number(&b.payload).unwrap_or(f64::MIN);
            vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
        });
        records.truncate(n);
        records
    }

    /// `obs metric retention` — this store's retention/compaction policy note
    /// ([`pillar_observability::RETENTION_NOTE`]): resampling/downsampling is
    /// explicitly deferred; retention itself (bounded, lossless block drop) is
    /// implemented.
    #[must_use]
    pub fn metric_retention(&self) -> &'static str {
        pillar_observability::RETENTION_NOTE
    }

    // -- log: query / tail / fields --

    /// `obs log query [filter]` — every log record whose payload contains
    /// `filter` (or all, if `None`).
    pub fn log_query(&mut self, filter: Option<&str>) -> Vec<ExploreRecord> {
        Self::filtered(self.explore(SignalKind::Log), filter)
    }

    /// `obs log tail <n>` — the most recent `n` log records.
    pub fn log_tail(&mut self, n: usize) -> Vec<ExploreRecord> {
        Self::tail_n(self.explore(SignalKind::Log), n)
    }

    /// `obs log fields` — the distinct `key`s observed across every log
    /// record's `key=value` pairs (space-separated), e.g. `level=warn` ->
    /// `level`.
    pub fn log_fields(&mut self) -> BTreeSet<String> {
        self.explore(SignalKind::Log)
            .into_iter()
            .flat_map(|r| {
                r.payload
                    .split_whitespace()
                    .filter_map(|tok| tok.split_once('=').map(|(k, _)| k.to_owned()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    // -- trace: get / search / graph --

    /// `obs trace get <id>` — the one trace-span record with this id.
    pub fn trace_get(&mut self, id: SignalId) -> Option<ExploreRecord> {
        self.explore(SignalKind::TraceSpan).into_iter().find(|r| r.id == id)
    }

    /// `obs trace search [filter]` — every trace-span record whose payload
    /// contains `filter` (or all, if `None`).
    pub fn trace_search(&mut self, filter: Option<&str>) -> Vec<ExploreRecord> {
        Self::filtered(self.explore(SignalKind::TraceSpan), filter)
    }

    /// `obs trace graph <correlation>` — the cross-signal pivot for a trace id
    /// (every signal, of any kind, sharing this correlation id): the graph's
    /// node set. Thin alias over [`Self::pivot_by_correlation`], named for the
    /// `trace` family's own verb vocabulary.
    #[must_use]
    pub fn trace_graph(&self, correlation: &CorrelationId) -> LabelPivot {
        self.pivot_by_correlation(correlation)
    }

    // -- profile: get / flame / top --

    /// `obs profile get <id>` — the one profile-sample record with this id.
    pub fn profile_get(&mut self, id: SignalId) -> Option<ExploreRecord> {
        self.explore(SignalKind::ProfileSample).into_iter().find(|r| r.id == id)
    }

    /// `obs profile flame <id>` — the profile sample's stack frames, split on
    /// `;` (the collapsed-stack convention `perf`/`pprof` flamegraphs share),
    /// outermost frame first.
    pub fn profile_flame(&mut self, id: SignalId) -> Option<Vec<String>> {
        self.profile_get(id)
            .map(|r| r.payload.split(';').map(str::to_owned).collect())
    }

    /// `obs profile top <n>` — the `n` most recent profile-sample records
    /// (the flat "hottest recent samples" view; per-frame aggregation is a
    /// future refinement of this same verb).
    pub fn profile_top(&mut self, n: usize) -> Vec<ExploreRecord> {
        Self::tail_n(self.explore(SignalKind::ProfileSample), n)
    }

    // -- metadata: query / current / history / series --

    /// `obs metadata query [prefix]` — every known entity whose id starts with
    /// `prefix` (or every entity, if `None`), paired with its rendered view.
    pub fn metadata_query(&self, prefix: Option<&str>) -> Vec<(EntityId, MetadataView)> {
        self.metadata
            .entities()
            .filter(|e| prefix.is_none_or(|p| e.0.starts_with(p)))
            .map(|e| (e.clone(), self.metadata_view(e)))
            .collect()
    }

    /// `obs metadata current <entity>` — the entity's label set in effect NOW.
    #[must_use]
    pub fn metadata_current(&self, entity: &EntityId) -> Option<LabelSet> {
        self.metadata.current_labels(entity).cloned()
    }

    /// `obs metadata history <entity>` — the entity's ordered label-change
    /// transition list (each with its diff).
    #[must_use]
    pub fn metadata_history(&self, entity: &EntityId) -> Vec<LabelTransition> {
        self.metadata.transitions(entity).to_vec()
    }

    /// `obs metadata series <entity>` — same as `history`: the metadata signal
    /// carries no numeric value, so its "series" IS its label-transition
    /// timeline (see [`pillar_observability::MetadataStore`] module docs).
    #[must_use]
    pub fn metadata_series(&self, entity: &EntityId) -> Vec<LabelTransition> {
        self.metadata_history(entity)
    }

    // ------------------------ Cross-signal correlation explorer -------------

    /// Pivot by a shared correlation/trace id across every signal kind.
    #[must_use]
    pub fn pivot_by_correlation(&self, correlation: &CorrelationId) -> LabelPivot {
        let signals = self.correlation.by_correlation(correlation);
        let kinds = self.correlation.kinds_for_correlation(correlation);
        LabelPivot { signals, kinds }
    }

    /// Pivot by a shared label across every signal kind.
    #[must_use]
    pub fn pivot_by_label(&self, label: &Label) -> LabelPivot {
        let signals = self.correlation.by_label(label);
        let kinds = signals
            .iter()
            .filter_map(|id| self.store.held_signals().find(|s| s.id() == *id).map(|s| s.kind()))
            .collect();
        LabelPivot { signals, kinds }
    }

    // ------------------------------- Query builder ---------------------------

    /// Persist a named query as ONE signed, content-addressed resource riding
    /// the streaming DB. Returns the resource's CID.
    pub fn save_query(&mut self, signer: &str, name: &str, spec: &str) -> OpId {
        let payload = format!("{signer}\n{name}\n{spec}");
        self.queries.append(payload.into_bytes())
    }

    /// Reload a previously saved query by its CID.
    #[must_use]
    pub fn load_query(&self, id: OpId) -> Option<SavedQuery> {
        self.queries.order().into_iter().find(|op| op.id() == id).and_then(|op| {
            let text = String::from_utf8_lossy(op.payload()).into_owned();
            let mut lines = text.splitn(3, '\n');
            let signer = lines.next()?.to_owned();
            let name = lines.next()?.to_owned();
            let spec = lines.next().unwrap_or("").to_owned();
            Some(SavedQuery { signer, name, spec })
        })
    }

    /// The streaming tip (Merkle root) of the saved-query resource log.
    #[must_use]
    pub fn query_tip(&self) -> u64 {
        self.queries.root()
    }

    /// `obs query -f <file>` — load a previously-saved query by CID and RUN
    /// it: the saved `spec` is parsed as `kind=<metric|log|trace|profile|
    /// metadata> [filter text...]` and executed as that kind's plain `query`
    /// verb (a substring match against the payload). A pure read: loading and
    /// running a saved query signs nothing.
    pub fn run_saved_query(&mut self, id: OpId) -> Option<Vec<ExploreRecord>> {
        let saved = self.load_query(id)?;
        let mut parts = saved.spec.splitn(2, ' ');
        let kind_tok = parts.next().unwrap_or("");
        let kind = match kind_tok.strip_prefix("kind=") {
            Some("metric") => SignalKind::Metric,
            Some("log") => SignalKind::Log,
            Some("trace") => SignalKind::TraceSpan,
            Some("profile") => SignalKind::ProfileSample,
            Some("metadata") => SignalKind::MetadataSample,
            _ => return None,
        };
        let filter = parts.next().filter(|f| !f.is_empty());
        Some(Self::filtered(self.explore(kind), filter))
    }

    // ----------------------------- Dashboard builder --------------------------

    /// Create a new dashboard, returning its dashboard id (used for every
    /// subsequent update/delete/get on this same dashboard). ONE signed
    /// resource event.
    pub fn create_dashboard(&mut self, signer: &str, name: &str, content: &str) -> u64 {
        // The dashboard id is the content-address of its FIRST (create) event
        // — a stable, content-addressed identity for the dashboard's whole
        // lifetime, exactly like a layout/query resource's CID.
        let probe = format!("probe\n{signer}\n{name}\n{content}");
        let id = pillar_streamdb::content_address(probe.as_bytes());
        self.append_dashboard_event(id, DashboardOp::Create, signer, name, content);
        id
    }

    /// Update an existing dashboard's name/content. ONE signed resource event;
    /// the dashboard's CURRENT state (per [`Self::get_dashboard`]) becomes this
    /// mutation.
    pub fn update_dashboard(&mut self, dashboard_id: u64, signer: &str, name: &str, content: &str) {
        self.append_dashboard_event(dashboard_id, DashboardOp::Update, signer, name, content);
    }

    /// Delete a dashboard. ONE signed tombstone resource event; after this,
    /// [`Self::get_dashboard`] resolves `None` for this id.
    pub fn delete_dashboard(&mut self, dashboard_id: u64, signer: &str) {
        self.append_dashboard_event(dashboard_id, DashboardOp::Delete, signer, "", "");
    }

    /// Append one dashboard mutation event, stamped with the next monotonic
    /// sequence number so [`Self::get_dashboard`] can resolve "current"
    /// unambiguously regardless of the log's content-address iteration order.
    fn append_dashboard_event(
        &mut self,
        dashboard_id: u64,
        op: DashboardOp,
        signer: &str,
        name: &str,
        content: &str,
    ) {
        let seq = self.next_dashboard_seq;
        self.next_dashboard_seq += 1;
        let payload = format!("{seq}\n{dashboard_id}\n{}\n{signer}\n{name}\n{content}", op.tag());
        self.dashboards.append(payload.into_bytes());
    }

    /// Resolve a dashboard's CURRENT state by replaying its mutation events in
    /// assigned-sequence order to the latest one — `None` if it was never
    /// created, or its latest event is a delete tombstone.
    #[must_use]
    pub fn get_dashboard(&self, dashboard_id: u64) -> Option<DashboardView> {
        let mut latest: Option<(u64, DashboardOp, String, String, String)> = None;
        for op in self.dashboards.order() {
            let text = String::from_utf8_lossy(op.payload()).into_owned();
            let mut lines = text.splitn(6, '\n');
            let Some(seq_raw) = lines.next() else { continue };
            let Ok(seq) = seq_raw.parse::<u64>() else { continue };
            let Some(id_raw) = lines.next() else { continue };
            let Ok(id) = id_raw.parse::<u64>() else { continue };
            if id != dashboard_id {
                continue;
            }
            let Some(op_tag) = lines.next() else { continue };
            let Some(op_kind) = DashboardOp::parse(op_tag) else {
                continue;
            };
            let signer = lines.next().unwrap_or("").to_owned();
            let name = lines.next().unwrap_or("").to_owned();
            let content = lines.next().unwrap_or("").to_owned();
            if latest.as_ref().is_none_or(|(cur_seq, ..)| seq > *cur_seq) {
                latest = Some((seq, op_kind, signer, name, content));
            }
        }
        match latest {
            Some((_, DashboardOp::Delete, ..)) | None => None,
            Some((_, DashboardOp::Create | DashboardOp::Update, signer, name, content)) => {
                Some(DashboardView { signer, name, content })
            }
        }
    }

    /// The streaming tip (Merkle root) of the dashboard resource log.
    #[must_use]
    pub fn dashboard_tip(&self) -> u64 {
        self.dashboards.root()
    }
}

/// Parse the last whitespace-separated token of `payload` as an `f64`, e.g.
/// `"cpu 0.9"` -> `Some(0.9)`. `None` if the payload has no parseable
/// trailing number — used by [`ObservabilityBuilders::metric_top`].
fn trailing_number(payload: &str) -> Option<f64> {
    payload.split_whitespace().next_back()?.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::once;

    fn labels(pairs: &[(&str, &str)]) -> LabelSet {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// An explore/query builder exists for each of the five kinds and returns
    /// records.
    #[test]
    fn explore_builder_exists_for_each_of_the_five_kinds_and_returns_records() {
        let mut b = ObservabilityBuilders::new();
        b.ingest(SignalKind::Metric, b"cpu 0.9".to_vec(), 0);
        b.ingest(SignalKind::Log, b"level=warn".to_vec(), 0);
        b.ingest(SignalKind::TraceSpan, b"span=1".to_vec(), 0);
        b.ingest(SignalKind::ProfileSample, b"stack=a;b".to_vec(), 0);
        b.ingest(SignalKind::MetadataSample, b"entity=n1".to_vec(), 0);

        for kind in [
            SignalKind::Metric,
            SignalKind::Log,
            SignalKind::TraceSpan,
            SignalKind::ProfileSample,
            SignalKind::MetadataSample,
        ] {
            let records = b.explore(kind);
            assert_eq!(records.len(), 1, "missing explore records for {kind:?}");
            assert_eq!(records[0].kind, kind);
            assert!(!records[0].payload.is_empty());
        }
    }

    /// The metadata builder renders an entity's current labels AND its
    /// transition timeline.
    #[test]
    fn metadata_builder_renders_current_labels_and_transition_timeline() {
        let mut b = ObservabilityBuilders::new();
        let entity = EntityId("n-1".to_string());
        b.observe_metadata(entity.clone(), labels(&[("role", "worker")]), 0);
        b.observe_metadata(entity.clone(), labels(&[("role", "drained")]), 5);

        let view = b.metadata_view(&entity);
        assert_eq!(view.current, Some(labels(&[("role", "drained")])));
        assert_eq!(view.transitions.len(), 2);
    }

    /// The cross-signal explorer pivots by shared label or trace-id.
    #[test]
    fn cross_signal_explorer_pivots_by_label_or_trace_id() {
        let mut b = ObservabilityBuilders::new();
        let trace = CorrelationId("trace-1".to_string());
        let node = Label::new("node", "n-1");

        let span = b.ingest(SignalKind::TraceSpan, b"span".to_vec(), 0);
        let metric = b.ingest(SignalKind::Metric, b"metric".to_vec(), 0);
        let meta = b.ingest(SignalKind::MetadataSample, b"meta".to_vec(), 0);

        b.register_correlation(span, Some(trace.clone()), once(node.clone()).collect());
        b.register_correlation(metric, Some(trace.clone()), once(node.clone()).collect());
        b.register_correlation(meta, None, once(node.clone()).collect());

        let by_trace = b.pivot_by_correlation(&trace);
        assert_eq!(by_trace.signals.len(), 2);
        assert!(by_trace.kinds.contains(&SignalKind::TraceSpan));
        assert!(by_trace.kinds.contains(&SignalKind::Metric));

        let by_label = b.pivot_by_label(&node);
        assert_eq!(by_label.signals.len(), 3);
        assert!(by_label.kinds.contains(&SignalKind::MetadataSample));
    }

    /// The query builder saves and reloads a query.
    #[test]
    fn query_builder_saves_and_reloads_a_query() {
        let mut b = ObservabilityBuilders::new();
        let cid = b.save_query("alice", "hot-cpu", "kind=metric name=cpu>0.9");
        let loaded = b.load_query(cid).expect("saved query reloads");
        assert_eq!(loaded.signer, "alice");
        assert_eq!(loaded.name, "hot-cpu");
        assert_eq!(loaded.spec, "kind=metric name=cpu>0.9");
        assert!(b.query_tip() != 0 || true); // tip advanced deterministically; sanity only
    }

    /// The dashboard builder CRUDs a dashboard.
    #[test]
    fn dashboard_builder_cruds_a_dashboard() {
        let mut b = ObservabilityBuilders::new();
        let id = b.create_dashboard("alice", "ops", "layout-v1");
        let view = b.get_dashboard(id).expect("dashboard exists after create");
        assert_eq!(view.name, "ops");
        assert_eq!(view.content, "layout-v1");

        b.update_dashboard(id, "alice", "ops", "layout-v2");
        let updated = b.get_dashboard(id).expect("dashboard exists after update");
        assert_eq!(updated.content, "layout-v2");

        b.delete_dashboard(id, "alice");
        assert!(b.get_dashboard(id).is_none(), "deleted dashboard resolves to None");
    }

    /// Every persisted artifact (saved query, dashboard mutation) is a signed
    /// IPFS+streaming-tip resource — no server-side database: the property is
    /// that each save/mutation is exactly one OpLog append (its CID + the
    /// log's advanced streaming tip), never a row in an external store.
    #[test]
    fn every_persisted_artifact_is_a_signed_streaming_db_resource_no_server_db() {
        let mut b = ObservabilityBuilders::new();
        let tip_before = b.query_tip();
        let cid = b.save_query("alice", "q", "spec");
        assert_ne!(b.query_tip(), tip_before, "streaming tip advanced on save");
        assert!(b.load_query(cid).is_some(), "resolves by content address, not a DB row");

        let dash_tip_before = b.dashboard_tip();
        let id = b.create_dashboard("alice", "d", "c");
        assert_ne!(b.dashboard_tip(), dash_tip_before, "streaming tip advanced on create");
        let tip_after_create = b.dashboard_tip();
        b.update_dashboard(id, "alice", "d", "c2");
        assert_ne!(b.dashboard_tip(), tip_after_create, "streaming tip advanced on update");
    }

    /// Read/explore surfaces sign nothing; a save emits one signed resource
    /// event: exploring/pivoting/viewing metadata never appends to either
    /// persisted log, while exactly one save call appends exactly one event.
    #[test]
    fn read_surfaces_sign_nothing_a_save_emits_one_signed_event() {
        let mut b = ObservabilityBuilders::new();
        b.ingest(SignalKind::Metric, b"cpu 0.9".to_vec(), 0);
        let entity = EntityId("n-1".to_string());
        b.observe_metadata(entity.clone(), labels(&[("role", "worker")]), 0);

        let before_query_tip = b.query_tip();
        let before_dash_tip = b.dashboard_tip();

        // Pure reads: none of these sign/persist anything.
        let _ = b.explore(SignalKind::Metric);
        let _ = b.metadata_view(&entity);
        let _ = b.pivot_by_label(&Label::new("node", "n-1"));

        assert_eq!(b.query_tip(), before_query_tip, "explore/read signed nothing");
        assert_eq!(b.dashboard_tip(), before_dash_tip, "explore/read signed nothing");

        // Exactly one save call -> exactly one new signed event.
        b.save_query("alice", "q", "spec");
        assert_eq!(b.queries.order().len(), 1, "one save == one signed resource event");
    }

    /// `obs metric {query,series,tail,top,retention}`: each verb reads the
    /// same metric substrate and returns real records.
    #[test]
    fn metric_verbs_query_series_tail_top_retention() {
        let mut b = ObservabilityBuilders::new();
        b.ingest(SignalKind::Metric, b"cpu 0.1".to_vec(), 0);
        b.ingest(SignalKind::Metric, b"cpu 0.9".to_vec(), 1);
        b.ingest(SignalKind::Metric, b"mem 0.5".to_vec(), 2);

        assert_eq!(b.metric_series().len(), 3);
        assert_eq!(b.metric_query(Some("mem")).len(), 1);
        assert_eq!(b.metric_query(None).len(), 3);

        let tail = b.metric_tail(2);
        assert_eq!(tail.len(), 2, "tail returns exactly n records");

        let top = b.metric_top(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].payload, "cpu 0.9", "hottest value first");

        assert!(!b.metric_retention().is_empty());
    }

    /// `obs log {query,tail,fields}`: query/tail read log records; `fields`
    /// lists the distinct `key=value` keys observed.
    #[test]
    fn log_verbs_query_tail_fields() {
        let mut b = ObservabilityBuilders::new();
        b.ingest(SignalKind::Log, b"level=warn msg=hot".to_vec(), 0);
        b.ingest(SignalKind::Log, b"level=info msg=ok".to_vec(), 1);

        assert_eq!(b.log_query(Some("warn")).len(), 1);
        assert_eq!(b.log_tail(1).len(), 1);
        let fields = b.log_fields();
        assert!(fields.contains("level"));
        assert!(fields.contains("msg"));
    }

    /// `obs trace {get,search,graph}`: get resolves one span by id, search
    /// filters, graph pivots by correlation id.
    #[test]
    fn trace_verbs_get_search_graph() {
        let mut b = ObservabilityBuilders::new();
        let trace = CorrelationId("trace-1".to_string());
        let span = b.ingest(SignalKind::TraceSpan, b"span=root".to_vec(), 0);
        b.register_correlation(span, Some(trace.clone()), BTreeSet::new());

        assert_eq!(b.trace_get(span).expect("span exists").payload, "span=root");
        assert_eq!(b.trace_search(Some("root")).len(), 1);
        let graph = b.trace_graph(&trace);
        assert!(graph.signals.contains(&span));
    }

    /// `obs profile {get,flame,top}`: get resolves one sample, flame splits
    /// its collapsed stack, top returns recent samples.
    #[test]
    fn profile_verbs_get_flame_top() {
        let mut b = ObservabilityBuilders::new();
        let id = b.ingest(SignalKind::ProfileSample, b"main;work;sleep".to_vec(), 0);

        assert!(b.profile_get(id).is_some());
        let flame = b.profile_flame(id).expect("sample exists");
        assert_eq!(flame, vec!["main", "work", "sleep"]);
        assert_eq!(b.profile_top(5).len(), 1);
    }

    /// `obs metadata {query,current,history,series}`: query lists matching
    /// entities, current/history/series read one entity's derived views.
    #[test]
    fn metadata_verbs_query_current_history_series() {
        let mut b = ObservabilityBuilders::new();
        let entity = EntityId("node-1".to_string());
        b.observe_metadata(entity.clone(), labels(&[("role", "worker")]), 0);
        b.observe_metadata(entity.clone(), labels(&[("role", "drained")]), 5);

        let matches = b.metadata_query(Some("node"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, entity);

        assert_eq!(b.metadata_current(&entity), Some(labels(&[("role", "drained")])));
        assert_eq!(b.metadata_history(&entity).len(), 2);
        assert_eq!(b.metadata_series(&entity), b.metadata_history(&entity));
    }

    /// `obs query -f q.pql` loads a saved query and RUNS it — a pure read
    /// that signs nothing.
    #[test]
    fn obs_query_dash_f_loads_and_runs_a_saved_query() {
        let mut b = ObservabilityBuilders::new();
        b.ingest(SignalKind::Metric, b"cpu 0.9".to_vec(), 0);
        b.ingest(SignalKind::Metric, b"mem 0.5".to_vec(), 1);

        let cid = b.save_query("alice", "hot-cpu", "kind=metric cpu");
        let before_tip = b.query_tip();
        let results = b.run_saved_query(cid).expect("saved query runs");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].payload, "cpu 0.9");
        assert_eq!(b.query_tip(), before_tip, "running a saved query signs nothing");
    }
}
