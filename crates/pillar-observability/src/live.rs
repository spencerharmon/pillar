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
use crate::metadata::{LabelSet, MetadataStore};
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

/// One rendered live-signal record: content-addressed id, kind, and the raw
/// payload as text — the wire projection the portal serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRecord {
    /// The signal's content-addressed id.
    pub id: SignalId,
    /// The signal's kind.
    pub kind: SignalKind,
    /// The signal's raw payload, rendered as UTF-8 (lossy) text.
    pub payload: String,
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
        let mut metrics = MetricsProducer::new(NodeMetricSource::new(counters.clone()));
        metrics.set_enabled(true);
        let logs = LogProducer::new(node_labels.clone());
        let mut traces = TraceProducer::new(node_labels.clone());
        traces.set_enabled(true);
        let mut profiles = ProfilingProducer::new(NodeProfileSource::new());
        profiles.set_enabled(true);
        let mut node_metadata = MetadataProducer::new(metadata_source);
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
        tick: u64,
    ) -> Option<SignalId> {
        let event = LogEvent::new(level, message);
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
        tick: u64,
    ) -> Option<SignalId> {
        let event = SpanEvent::root(trace_id, span_id, operation);
        self.traces
            .record(&mut self.store, &mut self.index, &event, tick)
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
            })
            .collect()
    }

    /// How many signals of `kind` the live store currently holds — the
    /// black-box "was this kind really ingested?" probe.
    #[must_use]
    pub fn count_of_kind(&self, kind: SignalKind) -> usize {
        self.store.held_signals().filter(|s| s.kind() == kind).count()
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
