//! The **live observability substrate** — one self-contained bundle wiring
//! ALL FIVE signal producers (metrics, logs, traces, profiles, metadata) onto
//! ONE shared [`TimeseriesStore`] + [`CorrelationIndex`] + [`MetadataStore`],
//! plus the PSL query path, the recording-rule + alert engines, and dashboard
//! materialization — everything reading the SAME live store.
//!
//! This is the piece a running `pillar node run` shares with its served web
//! surface: the controller loop feeds real signals in (self-metrics + profiles
//! each tick, a log per handled event, a span per traced operation, a periodic
//! metadata snapshot), and the portal's live-observability endpoints query,
//! evaluate rules/alerts, and materialize dashboards over the identical
//! substrate. No parallel/empty store: a query can only return data that a real
//! producer really ingested.
//!
//! Infrastructure-agnostic: the node's identity/labels are passed IN by the
//! embedder; nothing here embeds a hostname, domain, IP, or cluster name.

use std::collections::BTreeSet;

use crate::alerting::{Alert, AlertEngine, Notification, RecordingNotifier};
use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::{CorrelationId, CorrelationIndex};
use crate::ingest::{MetricsProducer, NodeCounters, NodeMetricSource};
use crate::logs::{LogEvent, LogLevel, LogProducer};
use crate::metadata::{EntityId, LabelSet, MetadataStore};
use crate::metadata_ingest::{MetadataProducer, NodeMetadataSource};
use crate::profiling::{NodeProfileSource, ProfilingProducer};
use crate::psl::{aggregate, execute, Aggregate, PslQuery};
use crate::recording::{Evaluation, RecordingEngine, RecordingRule};
use crate::traces::{SpanEvent, TraceProducer};

use pillar_manifest::scheduler::Scheduler;
use pillar_topology::TierHierarchy;

/// The default placement tier a node evaluates its own recording rules /
/// alerts under when the embedder gives none. A neutral, install-agnostic
/// label — never a real cluster/rack identifier.
pub const DEFAULT_EVAL_TIER: &str = "node";

/// One rendered live-signal record: content-addressed id, kind, the raw
/// payload as text, its write tick (logical timestamp), and its label set —
/// the wire projection the portal serves. Tick + labels let the portal show a
/// per-line timestamp and the signal's real labels (this is timeseries data),
/// never just an opaque payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRecord {
    /// The signal's content-addressed id.
    pub id: SignalId,
    /// The signal's kind.
    pub kind: SignalKind,
    /// The signal's raw payload, rendered as UTF-8 (lossy) text.
    pub payload: String,
    /// The logical write tick (timestamp) the signal was ingested at.
    pub tick: u64,
    /// The signal's real label set (`node`, `metric`, `cell`, …).
    pub labels: LabelSet,
    /// The real wall-clock timestamp (unix millis) the signal was written,
    /// resolved from the node's tick->wall-clock anchors; `None` if no anchor
    /// covers its tick (e.g. a store driven without a wall-clock node).
    pub unix_millis: Option<u64>,
}

/// The live observability substrate a running node shares with its portal.
///
/// Holds the ONE shared store every producer writes and every reader queries,
/// the five producers, the metadata-over-time view, the correlation index, and
/// the recording + alert engines (both riding the same shared scheduler). All
/// five kinds are ENABLED here (a node that exposes its substrate wants every
/// kind observable); a producer whose source has nothing real to report simply
/// writes nothing — never a fabricated sample.
pub struct LiveObservabilitySubstrate {
    store: TimeseriesStore,
    index: CorrelationIndex,
    metadata: MetadataStore,
    node_labels: LabelSet,

    counters: NodeCounters,
    metrics: MetricsProducer<NodeMetricSource>,
    logs: LogProducer,
    traces: TraceProducer,
    profiles: ProfilingProducer<NodeProfileSource>,
    node_metadata: MetadataProducer<NodeMetadataSource>,

    recording: RecordingEngine,
    alerts: AlertEngine,
    notifier: RecordingNotifier,

    /// Anchors mapping a logical write `tick` -> real wall-clock unix millis,
    /// captured at the node boundary each time it drives the substrate. The
    /// store stays deterministic (tick-only); this side table lets a read path
    /// resolve a real human timestamp for a record without a clock inside the
    /// pure store.
    tick_wallclock: std::collections::BTreeMap<u64, u64>,

    /// The registry of component-defined metric series (open metric typing).
    /// A component registers each series once; [`emit_metric`] consults this
    /// to stamp the series' type/unit/component labels and fail-closed on an
    /// unregistered name.
    ///
    /// [`emit_metric`]: LiveObservabilitySubstrate::emit_metric
    metric_registry: crate::instrument::MetricRegistry,
}

impl LiveObservabilitySubstrate {
    /// Build the substrate for a node identified by `node_labels` (the shared
    /// dimensions every emitted signal stamps, e.g. `node=<peer-id>`), and a
    /// `metadata_source` describing the node's live metadata snapshot.
    ///
    /// Every producer is enabled so the node's whole substrate is externally
    /// observable. `store_capacity`/`retention` size the shared store.
    #[must_use]
    pub fn new(
        node_labels: LabelSet,
        counters: NodeCounters,
        metadata_source: NodeMetadataSource,
        store_capacity: usize,
        retention: u64,
    ) -> Self {
        let mut metrics = MetricsProducer::new(NodeMetricSource::new(counters.clone()))
            .with_base_labels(node_labels.clone());
        metrics.set_enabled(true);
        let logs = LogProducer::new(node_labels.clone());
        let mut traces = TraceProducer::new(node_labels.clone());
        traces.set_enabled(true);
        let mut profiles =
            ProfilingProducer::new(NodeProfileSource::new()).with_base_labels(node_labels.clone());
        profiles.set_enabled(true);
        let mut node_metadata =
            MetadataProducer::new(metadata_source).with_base_labels(node_labels.clone());
        node_metadata.set_enabled(true);
        // Sample every tick so metadata is observable without waiting a full
        // default period in an externally-driven black-box scenario.
        node_metadata.set_period(1);

        let recording = RecordingEngine::new(Scheduler::new(TierHierarchy::default()));
        let alerts = AlertEngine::new(Scheduler::new(TierHierarchy::default()));

        LiveObservabilitySubstrate {
            store: TimeseriesStore::new(store_capacity, retention),
            index: CorrelationIndex::new(),
            metadata: MetadataStore::new(),
            node_labels,
            counters,
            metrics,
            logs,
            traces,
            profiles,
            node_metadata,
            recording,
            alerts,
            notifier: RecordingNotifier::default(),
            tick_wallclock: std::collections::BTreeMap::new(),
            metric_registry: crate::instrument::MetricRegistry::new(),
        }
    }

    /// The shared node labels every emitted signal stamps.
    #[must_use]
    pub fn node_labels(&self) -> &LabelSet {
        &self.node_labels
    }

    /// This node's live counters — the controller loop records real quantities
    /// (peer count, request count, ingest bytes, op-log length) here, and the
    /// metrics producer reads them on the next [`Self::sample_periodic`].
    #[must_use]
    pub fn counters(&self) -> &NodeCounters {
        &self.counters
    }

    /// Record the real wall-clock (`unix_millis`) that corresponds to logical
    /// `tick`, called by the running node each time it advances the substrate.
    /// Read paths resolve a record's human timestamp from the nearest anchor at
    /// or before its write tick. Keeps the pure store clock-free/deterministic.
    pub fn anchor_wallclock(&mut self, tick: u64, unix_millis: u64) {
        self.tick_wallclock.insert(tick, unix_millis);
    }

    /// The real wall-clock (unix millis) for a signal written at `tick`: the
    /// nearest anchor at or before `tick`, or `None` if no anchor is known.
    #[must_use]
    fn wallclock_for(&self, tick: u64) -> Option<u64> {
        self.tick_wallclock
            .range(..=tick)
            .next_back()
            .map(|(_, millis)| *millis)
    }

    /// Push the operator's real cell name into the metadata source once the
    /// cell has actually been created/named (post-bootstrap). Metadata samples
    /// after this carry the real `cell` label; earlier ones carried none (no
    /// synthetic placeholder). Also refreshes the member-count gauge.
    pub fn set_cell_name(&mut self, cell: impl Into<String>) {
        self.node_metadata.source_mut().set_cell(cell);
        let members = self.node_metadata.source_mut().member_count() as u64;
        self.counters.set_cell_member_count(members);
    }

    /// Install the per-series retention policy set (from applied
    /// `RetentionPolicy` manifests) onto the live store. Per the store
    /// contract this affects only FUTURE writes — every already-written
    /// signal keeps the expiry stamped from the window in force when it was
    /// written (the `ExpiryFrozenAtWrite`/`NoLossBeforeExpiry` guarantees of
    /// `specs/RetentionPolicy.tla`). Replaces any previously installed set.
    pub fn set_retention_policies(&mut self, policies: crate::retention::RetentionPolicySet) {
        self.store.set_policies(policies);
    }

    /// The per-series retention policy set currently installed on the live
    /// store (empty until an operator applies a `RetentionPolicy` manifest).
    #[must_use]
    pub fn retention_policies(&self) -> &crate::retention::RetentionPolicySet {
        self.store.policies()
    }

    // ----------------------------- Ingest paths -----------------------------

    /// Drive the PERIODIC producers (metrics + profiles + metadata) once at
    /// logical `tick`, writing every real sample into the shared store.
    /// Returns the total number of signals written this round.
    pub fn sample_periodic(&mut self, tick: u64) -> usize {
        let mut written = 0;
        written += self.metrics.sample(&mut self.store, tick);
        written += self.profiles.sample(&mut self.store, tick);
        if self
            .node_metadata
            .sample(&mut self.store, &mut self.metadata, tick)
            .is_some()
        {
            written += 1;
        }
        written
    }

    /// Record one real log occurrence at logical `tick` (a genuine event the
    /// node handled). Returns its signal id when captured (at/above the
    /// producer's min level), else `None`.
    pub fn record_log(
        &mut self,
        level: LogLevel,
        message: impl Into<String>,
        component: impl Into<String>,
        tick: u64,
    ) -> Option<SignalId> {
        let event = LogEvent::new(level, message).with_component(component);
        self.logs
            .record(&mut self.store, &mut self.index, &event, tick)
    }

    /// Record one real trace span at logical `tick`, correlated by `trace_id`.
    /// Returns its signal id when captured (tracing enabled), else `None`.
    pub fn record_span(
        &mut self,
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        operation: impl Into<String>,
        component: impl Into<String>,
        tick: u64,
    ) -> Option<SignalId> {
        let event = SpanEvent::root(trace_id, span_id, operation).with_component(component);
        self.traces
            .record(&mut self.store, &mut self.index, &event, tick)
    }

    // --------------------- Generic component emit surface --------------------
    //
    // The uniform per-component instrumentation path (see `crate::instrument`).
    // Every method preserves the SAME proven invariants the node-self producers
    // do: a kind that is disabled (or, for logs, below the min level) writes
    // nothing; correlation spines are registered so cross-kind pivot works;
    // metadata observations dedup unchanged snapshots (no double count). The
    // only additions are (a) arbitrary caller `extra` labels merged over the
    // node base labels, and (b) a `Cx` correlation carried on any kind.

    /// Register a component metric series so [`emit_metric`] can stamp its
    /// type/unit/component labels. Idempotent for the same descriptor;
    /// returns `false` if a different descriptor is already registered under
    /// the name (the first registration stands).
    ///
    /// [`emit_metric`]: LiveObservabilitySubstrate::emit_metric
    pub fn register_metric(&mut self, descriptor: crate::instrument::MetricDescriptor) -> bool {
        self.metric_registry.register(descriptor)
    }

    /// The metric registry (read-only) — the reader's source of a series'
    /// type/unit so it applies the right aggregation.
    #[must_use]
    pub fn metric_registry(&self) -> &crate::instrument::MetricRegistry {
        &self.metric_registry
    }

    /// Merge the node base labels, a `metric=<name>` label, the descriptor's
    /// `mtype`/`unit`/`component` labels, and any caller `extra` labels into
    /// one label set.
    fn metric_labels(
        &self,
        descriptor: &crate::instrument::MetricDescriptor,
        extra: &LabelSet,
    ) -> LabelSet {
        let mut labels = self.node_labels.clone();
        labels.insert(
            crate::metadata_index::METRIC_NAME_LABEL.to_string(),
            descriptor.name.clone(),
        );
        for (k, v) in descriptor.label_pairs() {
            labels.insert(k.to_string(), v);
        }
        for (k, v) in extra {
            labels.insert(k.clone(), v.clone());
        }
        labels
    }

    /// Emit one reading of a component metric series at logical `tick`.
    ///
    /// Fail-closed: an UNREGISTERED series name writes nothing and returns
    /// `None` — a metric whose type/unit is unknown would be mis-aggregated by
    /// a reader, so it is rejected rather than emitted with a fabricated type.
    /// The payload matches the node-self metric wire format exactly
    /// (`"<name> <value> @<tick>"`), so a component series renders through the
    /// identical query path as a node series.
    pub fn emit_metric(
        &mut self,
        name: &str,
        value: f64,
        extra: &LabelSet,
        tick: u64,
    ) -> Option<SignalId> {
        let descriptor = self.metric_registry.get(name)?.clone();
        let labels = self.metric_labels(&descriptor, extra);
        let payload = format!("{name} {value} @{tick}");
        self.store
            .write_labeled(SignalKind::Metric, payload.into_bytes(), labels, tick)
    }

    /// Emit one component-scoped log occurrence at logical `tick`, optionally
    /// correlated by a [`Cx`] so it pivots with a concurrent metric/span/
    /// profile of the same causal thread, and with arbitrary `extra` labels.
    /// Honors the same min-level gate as [`record_log`]: an occurrence below
    /// the configured minimum writes nothing.
    ///
    /// [`record_log`]: LiveObservabilitySubstrate::record_log
    /// [`Cx`]: crate::instrument::Cx
    pub fn emit_log(
        &mut self,
        level: LogLevel,
        message: impl Into<String>,
        component: impl Into<String>,
        cx: Option<&crate::instrument::Cx>,
        extra: &LabelSet,
        tick: u64,
    ) -> Option<SignalId> {
        let event = match cx {
            Some(cx) => LogEvent::correlated(level, message, cx.correlation.0.clone())
                .with_component(component),
            None => LogEvent::new(level, message).with_component(component),
        };
        self.logs
            .record_with(&mut self.store, &mut self.index, &event, extra, tick)
    }

    /// Emit one component-scoped trace span at logical `tick`, correlated by
    /// `cx` (its correlation id is the trace id), parented at `cx.span` when a
    /// parent span is open, with arbitrary `extra` labels. Honors the same
    /// enabled gate as [`record_span`] (tracing OFF -> writes nothing).
    ///
    /// [`record_span`]: LiveObservabilitySubstrate::record_span
    pub fn emit_span(
        &mut self,
        cx: &crate::instrument::Cx,
        span_id: impl Into<String>,
        operation: impl Into<String>,
        component: impl Into<String>,
        extra: &LabelSet,
        tick: u64,
    ) -> Option<SignalId> {
        let operation = operation.into();
        let event = match &cx.span {
            Some(parent) => {
                SpanEvent::child(cx.correlation.0.clone(), span_id, parent.clone(), operation)
            }
            None => SpanEvent::root(cx.correlation.0.clone(), span_id, operation),
        }
        .with_component(component);
        self.traces
            .record_with(&mut self.store, &mut self.index, &event, extra, tick)
    }

    /// Emit one component profile sample at logical `tick`: `weight` (the
    /// sample's cost, e.g. cpu ticks or bytes) attributed to `stack` (root ->
    /// leaf frames, one per line). Honors the same enabled gate as the node
    /// profiling producer (profiling OFF -> writes nothing).
    pub fn emit_profile(
        &mut self,
        profile_kind: crate::ProfileKind,
        weight: u64,
        stack: impl Into<String>,
        component: impl Into<String>,
        extra: &LabelSet,
        tick: u64,
    ) -> Option<SignalId> {
        if !self.profiles.is_enabled() {
            return None;
        }
        let name = profile_kind.name();
        let mut labels = self.node_labels.clone();
        labels.insert("profile".to_string(), name.to_string());
        labels.insert(
            crate::instrument::COMPONENT_LABEL.to_string(),
            component.into(),
        );
        for (k, v) in extra {
            labels.insert(k.clone(), v.clone());
        }
        let payload = format!("{name} {weight} @{tick}\n{}", stack.into());
        self.store.write_labeled(
            SignalKind::ProfileSample,
            payload.into_bytes(),
            labels,
            tick,
        )
    }

    /// Record a component entity's current label set at logical `tick` — the
    /// per-component metadata-over-time observation. Dedups an unchanged
    /// snapshot through the same [`MetadataStore`] the node metadata producer
    /// uses (NoDoubleCount), and writes a `MetadataSample` signal so the
    /// observation is queryable. Returns the signal id when a NEW observation
    /// was written (labels changed since the last one for this entity), else
    /// `None`.
    pub fn observe_metadata(
        &mut self,
        entity: EntityId,
        entity_labels: LabelSet,
        component: impl Into<String>,
        tick: u64,
    ) -> Option<SignalId> {
        // Feed the label-over-time view; it returns a transition only when the
        // snapshot genuinely changed, which is exactly when we emit a signal.
        let transition = self.metadata.ingest(crate::metadata::LabelObservation::new(
            entity.clone(),
            entity_labels.clone(),
            tick,
        ));
        transition.as_ref()?;
        let mut labels = self.node_labels.clone();
        for (k, v) in &entity_labels {
            labels.insert(k.clone(), v.clone());
        }
        labels.insert("entity".to_string(), entity.0.clone());
        labels.insert(
            crate::instrument::COMPONENT_LABEL.to_string(),
            component.into(),
        );
        let mut kv: Vec<String> = entity_labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        kv.sort();
        let payload = format!("entity={} {} @{}", entity.0, kv.join(" "), tick);
        self.store.write_labeled(
            SignalKind::MetadataSample,
            payload.into_bytes(),
            labels,
            tick,
        )
    }

    // ------------------------------- Read paths ------------------------------

    /// Every held signal of `kind`, rendered as a record — the explore view.
    pub fn explore(&self, kind: SignalKind) -> Vec<LiveRecord> {
        self.store
            .held_signals()
            .filter(|s| s.kind() == kind)
            .map(|s| LiveRecord {
                id: s.id(),
                kind: s.kind(),
                payload: String::from_utf8_lossy(s.payload()).into_owned(),
                tick: self.store.write_tick_of(&s.id()).unwrap_or(0),
                labels: s.labels().clone(),
                unix_millis: self.wallclock_for(self.store.write_tick_of(&s.id()).unwrap_or(0)),
            })
            .collect()
    }

    /// A [`MetadataIndex`] projected from the live store's currently-held
    /// signal set — the REAL typeahead source the Explore query builders'
    /// `select`/`where` autofill reads (metric names, label keys, label
    /// VALUES). It holds no signals of its own and fabricates nothing: an
    /// unknown key yields an empty value list, per the index's own
    /// anti-fabrication contract. Rebuilt on demand so it always reflects the
    /// current held set (retention-correct, never a drifting side catalog).
    #[must_use]
    pub fn metadata_index(&self) -> crate::metadata_index::MetadataIndex {
        crate::metadata_index::MetadataIndex::from_store(&self.store)
    }

    /// How many signals of `kind` the live store currently holds — the
    /// black-box "was this kind really ingested?" probe.
    #[must_use]
    pub fn count_of_kind(&self, kind: SignalKind) -> usize {
        self.store
            .held_signals()
            .filter(|s| s.kind() == kind)
            .count()
    }

    /// The highest write tick any held signal carries — the logical "now" a
    /// PSL relative range should end at so its window covers every ingested
    /// signal (a caller querying with `u64::MAX` would push the whole window
    /// PAST every real signal). `0` when the store is empty.
    #[must_use]
    pub fn latest_tick(&self) -> u64 {
        self.store
            .held_signals()
            .filter_map(|s| self.store.write_tick_of(&s.id()))
            .max()
            .unwrap_or(0)
    }

    /// Run a PSL query (`parse`d text) against the LIVE store + index as of
    /// logical `now`, returning every matched signal rendered as a record. A
    /// pure read — signs nothing, and can only surface really-ingested data.
    pub fn psl_query(&self, query: &PslQuery, now: u64) -> Vec<LiveRecord> {
        let result = execute(query, &self.store, &self.index, now);
        result
            .matched
            .iter()
            .filter_map(|id| {
                self.store
                    .held_signals()
                    .find(|s| &s.id() == id)
                    .map(|s| LiveRecord {
                        id: s.id(),
                        kind: s.kind(),
                        payload: String::from_utf8_lossy(s.payload()).into_owned(),
                        tick: self.store.write_tick_of(&s.id()).unwrap_or(0),
                        labels: s.labels().clone(),
                        unix_millis: self
                            .wallclock_for(self.store.write_tick_of(&s.id()).unwrap_or(0)),
                    })
            })
            .collect()
    }

    /// The correlate groups a PSL query with a `correlate:` clause produces
    /// over the live store — cross-signal grouping by shared correlation id.
    #[must_use]
    pub fn psl_correlate(&self, query: &PslQuery, now: u64) -> Vec<(SignalId, Vec<SignalId>)> {
        execute(query, &self.store, &self.index, now)
            .groups
            .into_iter()
            .map(|g| (g.anchor, g.members))
            .collect()
    }

    // -------------------- Recording rules + alerting ------------------------

    /// Register a recording rule on the node's real scheduler engine.
    pub fn register_rule(&mut self, rule: RecordingRule) {
        self.recording.register(rule);
    }

    /// Evaluate recording rule `id` at logical `now` against the LIVE store,
    /// writing the derived metric(s) back INTO the same live store so they are
    /// themselves queryable. `tier` is the placement tier (default
    /// [`DEFAULT_EVAL_TIER`]).
    ///
    /// # Errors
    /// Propagates the scheduler [`FireError`](pillar_manifest::scheduler::FireError)
    /// (e.g. an unknown/inadmissible rule).
    pub fn evaluate_rule(
        &mut self,
        id: &str,
        tier: &str,
        now: u64,
    ) -> Result<Evaluation, pillar_manifest::scheduler::FireError> {
        // A recording rule reads real signals from a source snapshot and
        // emits its derived metrics into the LIVE store, so the derived series
        // is itself queryable off the same substrate every reader sees. The
        // source is a snapshot of the live store taken before this scan (the
        // rule never reads its own just-written derived metrics mid-scan).
        let source = self.store.clone();
        self.recording
            .evaluate(id, tier, now, &source, &self.index, &mut self.store)
    }

    /// Read the derived metric series recording rule `id` last emitted into the
    /// live store.
    #[must_use]
    pub fn derived_series(&self, rule_id: &str) -> Vec<f64> {
        self.recording.query_derived(rule_id, &self.store)
    }

    /// Register an alert on the node's real scheduler engine.
    pub fn register_alert(&mut self, alert: Alert) {
        self.alerts.register(alert);
    }

    /// Evaluate alert `id` at logical `now` against the LIVE store, firing a
    /// notification for every group tripping the predicate. Returns the
    /// notifications produced this evaluation (also recorded on the substrate's
    /// notifier for later inspection via [`Self::fired_notifications`]).
    ///
    /// # Errors
    /// Propagates the scheduler [`FireError`](pillar_manifest::scheduler::FireError).
    pub fn evaluate_alert(
        &mut self,
        id: &str,
        tier: &str,
        now: u64,
    ) -> Result<Vec<Notification>, pillar_manifest::scheduler::FireError> {
        let eval =
            self.alerts
                .evaluate(id, tier, now, &self.store, &self.index, &mut self.notifier)?;
        Ok(eval.notifications)
    }

    /// Every alert notification this substrate has ever fired, in order.
    #[must_use]
    pub fn fired_notifications(&self) -> &[Notification] {
        &self.notifier.received
    }

    // ---------------------------- Dashboards --------------------------------

    /// Materialize a dashboard from the LIVE store: run each of the dashboard's
    /// PSL panel queries against the live substrate and return, per panel, the
    /// matched records. `panels` is a list of `(panel-name, query)` — the
    /// dashboard's composed views, each reading the same live data every other
    /// reader sees.
    #[must_use]
    pub fn materialize_dashboard(
        &self,
        panels: &[(String, PslQuery)],
        now: u64,
    ) -> Vec<(String, Vec<LiveRecord>)> {
        panels
            .iter()
            .map(|(name, query)| (name.clone(), self.psl_query(query, now)))
            .collect()
    }

    /// Convenience aggregate over the live store (the value a dashboard gauge /
    /// alert threshold reads), by the identical [`crate::psl::aggregate`] path
    /// recording rules and alerts use.
    #[must_use]
    pub fn aggregate(
        &self,
        query: &PslQuery,
        now: u64,
        agg: Aggregate,
        by: &[String],
    ) -> Vec<crate::psl::AggregateRow> {
        aggregate(query, &self.store, &self.index, now, agg, by)
    }

    /// The set of signal kinds currently observable in the live store — a
    /// black-box observer's proof that every one of the five kinds is really
    /// ingested (not merely queryable in the abstract).
    #[must_use]
    pub fn observed_kinds(&self) -> BTreeSet<SignalKind> {
        self.store.held_signals().map(|s| s.kind()).collect()
    }

    /// Pivot the live correlation index by a shared correlation id.
    #[must_use]
    pub fn pivot_by_correlation(&self, correlation: &CorrelationId) -> BTreeSet<SignalId> {
        self.index.by_correlation(correlation)
    }
}

/// A per-component instrumentation handle: the one object a pillar component
/// holds to emit across all five signal kinds without ever touching the five
/// producers directly.
///
/// It bundles (a) the shared substrate handle, (b) the emitting `component`
/// name, and (c) `base_labels` baked into every signal (e.g. a subsystem or a
/// role dimension). A component clones a probe cheaply (both fields are
/// shared/small) and threads a [`Cx`](crate::instrument::Cx) through its hot
/// path so its log/metric/span/profile of one operation correlate.
///
/// Every method locks the shared substrate briefly and forwards to the
/// substrate's generic emit surface, so a probe cannot bypass the proven
/// gating/dedup invariants — it is a convenience facade, not a second path.
#[derive(Clone)]
pub struct ComponentProbe {
    component: String,
    base_labels: LabelSet,
    substrate: std::sync::Arc<std::sync::Mutex<LiveObservabilitySubstrate>>,
}

impl ComponentProbe {
    /// A probe for `component`, sharing `substrate`, stamping `base_labels`
    /// onto every signal it emits.
    #[must_use]
    pub fn new(
        component: impl Into<String>,
        base_labels: LabelSet,
        substrate: std::sync::Arc<std::sync::Mutex<LiveObservabilitySubstrate>>,
    ) -> ComponentProbe {
        ComponentProbe {
            component: component.into(),
            base_labels,
            substrate,
        }
    }

    /// The component this probe emits as.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Register a metric series this component will emit. Idempotent; returns
    /// `false` on a conflicting redefinition (see
    /// [`MetricRegistry::register`](crate::instrument::MetricRegistry::register)).
    pub fn register_metric(&self, descriptor: crate::instrument::MetricDescriptor) -> bool {
        self.lock().register_metric(descriptor)
    }

    /// Emit one reading of a registered metric series at `tick`.
    pub fn metric(&self, name: &str, value: f64, tick: u64) -> Option<SignalId> {
        let base = self.base_labels.clone();
        self.lock().emit_metric(name, value, &base, tick)
    }

    /// Emit one component log occurrence at `tick`, optionally correlated.
    pub fn log(
        &self,
        level: LogLevel,
        message: impl Into<String>,
        cx: Option<&crate::instrument::Cx>,
        tick: u64,
    ) -> Option<SignalId> {
        let (component, base) = (self.component.clone(), self.base_labels.clone());
        self.lock()
            .emit_log(level, message, component, cx, &base, tick)
    }

    /// Emit one component trace span at `tick`, correlated by `cx`.
    pub fn span(
        &self,
        cx: &crate::instrument::Cx,
        span_id: impl Into<String>,
        operation: impl Into<String>,
        tick: u64,
    ) -> Option<SignalId> {
        let (component, base) = (self.component.clone(), self.base_labels.clone());
        self.lock()
            .emit_span(cx, span_id, operation, component, &base, tick)
    }

    /// Emit one component profile sample at `tick`.
    pub fn profile(
        &self,
        profile_kind: crate::ProfileKind,
        weight: u64,
        stack: impl Into<String>,
        tick: u64,
    ) -> Option<SignalId> {
        let (component, base) = (self.component.clone(), self.base_labels.clone());
        self.lock()
            .emit_profile(profile_kind, weight, stack, component, &base, tick)
    }

    /// Record a component entity's current labels at `tick` (metadata-over-
    /// time). Returns the signal id only when the labels changed.
    pub fn observe(
        &self,
        entity: EntityId,
        entity_labels: LabelSet,
        tick: u64,
    ) -> Option<SignalId> {
        let component = self.component.clone();
        self.lock()
            .observe_metadata(entity, entity_labels, component, tick)
    }

    /// Lock the shared substrate, recovering a poisoned lock (a panic in
    /// another holder must not wedge every component's instrumentation).
    fn lock(&self) -> std::sync::MutexGuard<'_, LiveObservabilitySubstrate> {
        self.substrate.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::instrument::{Cx, MetricDescriptor, MetricType};
    use crate::metadata_index::METRIC_NAME_LABEL;

    fn substrate() -> LiveObservabilitySubstrate {
        let mut node_labels = LabelSet::new();
        node_labels.insert("node".to_string(), "n-probe".to_string());
        let counters = NodeCounters::new();
        let metadata_source = NodeMetadataSource::new(
            "n-probe",
            Some("cell-probe".to_string()),
            std::iter::once("n-probe".to_string()),
            "0.0.0",
            None,
        );
        LiveObservabilitySubstrate::new(node_labels, counters, metadata_source, 256, 100_000)
    }

    /// A registered component metric emits a real Metric signal that carries
    /// the series name AND the descriptor's type/unit/component labels, and is
    /// queryable through the same path as a node self-metric.
    #[test]
    fn registered_component_metric_emits_with_type_unit_component_labels() {
        let mut sub = substrate();
        assert!(sub.register_metric(MetricDescriptor::new(
            "ipam_pool_used_bytes",
            MetricType::Gauge,
            "bytes",
            "ipam",
        )));
        let id = sub
            .emit_metric("ipam_pool_used_bytes", 4096.0, &LabelSet::new(), 5)
            .expect("registered metric emits");
        let rec = sub
            .explore(SignalKind::Metric)
            .into_iter()
            .find(|r| r.id == id)
            .expect("the emitted metric is held and explorable");
        assert_eq!(rec.payload, "ipam_pool_used_bytes 4096 @5");
        assert_eq!(
            rec.labels.get(METRIC_NAME_LABEL).map(String::as_str),
            Some("ipam_pool_used_bytes")
        );
        assert_eq!(rec.labels.get("mtype").map(String::as_str), Some("gauge"));
        assert_eq!(rec.labels.get("unit").map(String::as_str), Some("bytes"));
        assert_eq!(
            rec.labels.get("component").map(String::as_str),
            Some("ipam")
        );
    }

    /// Fail-closed: emitting an UNREGISTERED series writes nothing (no
    /// fabricated-type metric ever reaches the store).
    #[test]
    fn unregistered_metric_is_rejected_and_writes_nothing() {
        let mut sub = substrate();
        let before = sub.count_of_kind(SignalKind::Metric);
        assert!(sub
            .emit_metric("never_registered", 1.0, &LabelSet::new(), 1)
            .is_none());
        assert_eq!(sub.count_of_kind(SignalKind::Metric), before);
    }

    /// A correlated log + span emitted under one `Cx` pivot together through
    /// the correlation index (cross-kind correlation works for component
    /// emissions, not just node self-signals).
    #[test]
    fn correlated_component_log_and_span_pivot_together() {
        let mut sub = substrate();
        let cx = Cx::new("req-7");
        let log_id = sub
            .emit_log(
                LogLevel::Warn,
                "slow allocate",
                "ipam",
                Some(&cx),
                &LabelSet::new(),
                3,
            )
            .expect("warn log captured at default info level");
        let cx = cx.in_span("span-a");
        let span_id = sub
            .emit_span(&cx, "span-a", "allocate", "ipam", &LabelSet::new(), 3)
            .expect("tracing enabled on the live substrate");
        let pivot =
            sub.pivot_by_correlation(&crate::correlation::CorrelationId("req-7".to_owned()));
        assert!(pivot.contains(&log_id), "log is on the causal thread");
        assert!(
            pivot.contains(&span_id),
            "span is on the same causal thread"
        );
    }

    /// A parented span carries the parent-span edge and its `component` label.
    #[test]
    fn component_span_records_parent_edge() {
        let mut sub = substrate();
        let root = Cx::new("trace-1");
        sub.emit_span(&root, "s1", "reconcile", "controller", &LabelSet::new(), 1);
        let child = root.in_span("s1");
        let child_id = sub
            .emit_span(&child, "s2", "apply", "controller", &LabelSet::new(), 2)
            .expect("child span recorded");
        let rec = sub
            .explore(SignalKind::TraceSpan)
            .into_iter()
            .find(|r| r.id == child_id)
            .expect("child span held");
        assert!(
            rec.payload.contains("parent=s1"),
            "parent edge: {}",
            rec.payload
        );
        assert_eq!(
            rec.labels.get("component").map(String::as_str),
            Some("controller")
        );
    }

    /// A component metadata observation writes a MetadataSample on FIRST
    /// observation, dedups an unchanged snapshot (NoDoubleCount), and emits
    /// again only when the labels genuinely change.
    #[test]
    fn component_metadata_observation_dedups_unchanged_snapshots() {
        let mut sub = substrate();
        let entity = EntityId("ipam-pool/default".to_owned());
        let mut labels = LabelSet::new();
        labels.insert("free".to_string(), "250".to_string());
        assert!(sub
            .observe_metadata(entity.clone(), labels.clone(), "ipam", 1)
            .is_some());
        // Same snapshot again -> deduped, no new signal.
        assert!(sub
            .observe_metadata(entity.clone(), labels.clone(), "ipam", 2)
            .is_none());
        // Changed snapshot -> a new observation is emitted.
        labels.insert("free".to_string(), "249".to_string());
        assert!(sub.observe_metadata(entity, labels, "ipam", 3).is_some());
    }

    /// The `ComponentProbe` facade emits through the shared substrate: a metric
    /// registered and emitted via a probe is visible on the substrate.
    #[test]
    fn component_probe_emits_through_shared_substrate() {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(substrate()));
        let mut base = LabelSet::new();
        base.insert("subsystem".to_string(), "allocator".to_string());
        let probe = ComponentProbe::new("ipam", base, shared.clone());
        assert!(probe.register_metric(MetricDescriptor::counter("ipam_allocations_total", "ipam")));
        let id = probe
            .metric("ipam_allocations_total", 1.0, 9)
            .expect("probe emits the registered metric");
        let sub = shared.lock().unwrap();
        let rec = sub
            .explore(SignalKind::Metric)
            .into_iter()
            .find(|r| r.id == id)
            .expect("probe-emitted metric held on the shared substrate");
        // The probe's base labels ride the signal.
        assert_eq!(
            rec.labels.get("subsystem").map(String::as_str),
            Some("allocator")
        );
        assert_eq!(rec.labels.get("mtype").map(String::as_str), Some("counter"));
    }

    /// The substrate passthrough installs a per-series retention policy onto
    /// the live store: a matched write's lifetime is shortened to the policy
    /// window while an unmatched series keeps the default, and the installed
    /// set is reflected by `retention_policies()`.
    #[test]
    fn set_retention_policies_installs_per_series_windows_on_the_live_store() {
        use crate::retention::{LabelSelector, RetentionPolicy, RetentionPolicySet};
        let mut sub = substrate();
        assert!(sub.retention_policies().policies().is_empty());

        // Metric{app=web} retained 10 ticks; everything else the default.
        let mut set = RetentionPolicySet::empty();
        set.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::matching([("app", "web")]),
            window: Some(10),
            downsample: None,
        });
        sub.set_retention_policies(set);
        assert_eq!(sub.retention_policies().policies().len(), 1);

        // The effective window for the matched series is the policy's (10);
        // an unmatched series falls back to the substrate default.
        let mut web = LabelSet::new();
        web.insert("app".to_string(), "web".to_string());
        let eff_web = sub.retention_policies().effective(SignalKind::Metric, &web);
        assert_eq!(eff_web.window, Some(10));
        let mut other = LabelSet::new();
        other.insert("app".to_string(), "db".to_string());
        let eff_other = sub
            .retention_policies()
            .effective(SignalKind::Metric, &other);
        assert_eq!(eff_other.window, None, "unmatched -> store default applies");
    }
}
