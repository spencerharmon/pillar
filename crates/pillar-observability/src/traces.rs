//! Real distributed-trace span ingestion — the running node emits genuine
//! trace spans into the shared [`crate::TimeseriesStore`] through the SAME
//! single producer contract every other kind uses, carrying the SAME
//! label/correlation shape the correlation spine ([`crate::correlation`])
//! pivots on.
//!
//! This is the Rust refinement of the `traces` producer of
//! `specs/ObsIngestionSubstrate.tla`. Unlike metrics/logs/metadata, tracing is
//! **OFF by default** — `default_on(SignalKind::TraceSpan) == false`
//! ([`crate::signal_config`], the spec's `DefaultOn = {metrics, logs,
//! metadata}`). A [`TraceProducer`] therefore writes nothing until a config
//! toggle enables it, and a fresh, un-toggled node emits no span at all.
//!
//! # No fabrication
//!
//! A span is written ONLY for a real [`SpanEvent`] the node genuinely observed
//! (a request handled, an op applied, an rpc issued). There is no synthetic
//! demo span, no placeholder, no zero-fill: recording a span requires a caller
//! to hand the producer a real occurrence. A disabled producer, or one handed
//! no events, writes nothing.
//!
//! # Shared correlation/label shape
//!
//! Every span the producer writes stamps:
//!
//! - a `trace` label (`= trace_id`) AND a matching [`CorrelationId`] so the
//!   span cross-pivots with the metric/log/profile/metadata signals of the
//!   same causal thread through [`crate::correlation::CorrelationIndex`]; and
//! - the node's shared labels (e.g. `node=<id>`) so a concurrent metric or log
//!   stamping the same `node` value gathers alongside the span by the shared
//!   label pivot.
//!
//! This is exactly the producer contract shape [`crate::ingest::MetricsProducer`]
//! writes with (`store.write_labeled` onto the one store), so a trace, a
//! metric, and a log emitted concurrently on one node correlate with no second
//! index and no second store.

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
use crate::metadata::LabelSet;

/// A single real span occurrence the node observed: an operation with a name,
/// its trace id (the causal thread it belongs to), an optional parent span id
/// (composing the parent-child span DAG), and its own span id.
///
/// Every field is a genuine value of a real operation — the producer never
/// synthesizes one. A caller records a [`SpanEvent`] only when the operation
/// actually happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanEvent {
    /// The trace id — the causal thread this span belongs to. Becomes both the
    /// span's `trace` label and its [`CorrelationId`], so the span pivots to
    /// every other signal of the same thread.
    pub trace_id: String,
    /// This span's own id (unique within the trace).
    pub span_id: String,
    /// The parent span id, or `None` for a root span — the parent-child DAG
    /// edge that composes spans into a trace.
    pub parent_span_id: Option<String>,
    /// The operation this span covers (e.g. `handle_request`, `apply_op`).
    pub operation: String,
}

impl SpanEvent {
    /// A root span (no parent) for `operation` on `trace_id`.
    #[must_use]
    pub fn root(
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        SpanEvent {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            parent_span_id: None,
            operation: operation.into(),
        }
    }

    /// A child span of `parent_span_id` on `trace_id`.
    #[must_use]
    pub fn child(
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        parent_span_id: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        SpanEvent {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            parent_span_id: Some(parent_span_id.into()),
            operation: operation.into(),
        }
    }

    /// The correlation id this span shares with every other signal of the same
    /// causal thread — the trace id.
    #[must_use]
    pub fn correlation(&self) -> CorrelationId {
        CorrelationId(self.trace_id.clone())
    }
}

/// The `traces` producer: on each real [`SpanEvent`] it writes one genuine
/// trace-span signal onto the shared substrate through the single producer
/// contract, stamping the shared `trace`/`node` labels + correlation id.
///
/// **OFF by default** (`traces` is NOT in `DefaultOn`). A config override
/// ([`TraceProducer::set_enabled`]) enabling it starts writes; while disabled
/// (its default) a `record` writes nothing and returns `None`.
pub struct TraceProducer {
    /// The node's shared labels every span stamps (e.g. `node=<id>`,
    /// `cell=<c>`) — the common dimensions that cross-pivot with metrics/logs.
    node_labels: LabelSet,
    enabled: bool,
    /// Whether the enabled state was set explicitly by config (vs. the
    /// default-off), mirroring the substrate spec's `overridden` set.
    overridden: bool,
}

impl TraceProducer {
    /// A producer at its DEFAULT state: **disabled** (tracing is off by
    /// default), not yet overridden by config. `node_labels` are the shared
    /// dimensions every emitted span stamps.
    #[must_use]
    pub fn new(node_labels: LabelSet) -> Self {
        debug_assert!(
            !crate::signal_config::default_on(SignalKind::TraceSpan),
            "tracing must default OFF"
        );
        TraceProducer {
            node_labels,
            enabled: false,
            overridden: false,
        }
    }

    /// Whether this producer is currently live (writing spans).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether the enabled state was set by an explicit config override.
    #[must_use]
    pub fn is_overridden(&self) -> bool {
        self.overridden
    }

    /// Apply a config override flipping tracing on/off — records it as an
    /// explicit override (`overridden`), exactly the substrate spec's
    /// `ConfigToggle`. Enabling starts future `record`s writing.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.overridden = true;
    }

    /// The shared node labels every emitted span stamps.
    #[must_use]
    pub fn node_labels(&self) -> &LabelSet {
        &self.node_labels
    }

    /// The label set a span carries: the node's shared labels plus a
    /// `trace=<trace_id>` label, so the span pivots by both the shared node
    /// label AND the trace correlation id.
    fn span_labels(&self, event: &SpanEvent) -> LabelSet {
        let mut labels = self.node_labels.clone();
        labels.insert("trace".to_string(), event.trace_id.clone());
        labels
    }

    /// Record one real span occurrence into `store` at logical `tick`, and
    /// register it on `index` under its trace correlation id + shared labels so
    /// it cross-pivots with the other kinds.
    ///
    /// Writes a trace-span signal (payload
    /// `"span=<id> parent=<pid|-> op=<operation> trace=<trace_id> @<tick>"`,
    /// labels = node labels + `trace=<trace_id>`) through the store's single
    /// producer path and returns its id. While disabled it writes nothing,
    /// registers nothing, and returns `None`.
    pub fn record(
        &self,
        store: &mut TimeseriesStore,
        index: &mut CorrelationIndex,
        event: &SpanEvent,
        tick: u64,
    ) -> Option<SignalId> {
        if !self.enabled {
            return None;
        }
        let labels = self.span_labels(event);
        let parent = event.parent_span_id.as_deref().unwrap_or("-");
        let payload = format!(
            "span={} parent={} op={} trace={} @{}",
            event.span_id, parent, event.operation, event.trace_id, tick
        );
        let id = store.write_labeled(
            SignalKind::TraceSpan,
            payload.into_bytes(),
            labels.clone(),
            tick,
        )?;
        // Register on the correlation spine: trace-id correlation + shared
        // labels, the SAME shape every other kind stamps.
        let spine = SignalRef {
            kind: SignalKind::TraceSpan,
            correlation: Some(event.correlation()),
            labels: labels
                .iter()
                .map(|(k, v)| Label::new(k.clone(), v.clone()))
                .collect(),
        };
        index.register(id.clone(), &spine);
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use crate::signal_config::default_on;
    use crate::ViewCache;

    fn node_labels(node: &str) -> LabelSet {
        let mut l = LabelSet::new();
        l.insert("node".to_string(), node.to_string());
        l
    }

    /// A fresh producer is OFF by default (tracing is not in `DefaultOn`), and
    /// a default-boot node writes NO span — the config-off half of the toggle.
    #[test]
    fn tracing_is_off_by_default_no_span_written_on_fresh_boot() {
        assert!(
            !default_on(SignalKind::TraceSpan),
            "tracing must default OFF"
        );
        let producer = TraceProducer::new(node_labels("n-1"));
        assert!(!producer.is_enabled(), "traces producer is OFF by default");
        assert!(!producer.is_overridden(), "no override yet on a fresh node");

        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();
        // A short run of real span occurrences while disabled: nothing lands.
        for tick in 0..5 {
            let out = producer.record(
                &mut store,
                &mut index,
                &SpanEvent::root("t", format!("s{tick}"), "op"),
                tick,
            );
            assert_eq!(out, None, "a disabled producer writes no span");
        }
        assert_eq!(store.held_len(), 0, "default-off means zero span writes");
        assert!(
            index
                .by_correlation(&CorrelationId("t".to_string()))
                .is_empty(),
            "nothing registered on the spine either"
        );
    }

    /// Enabling tracing via config produces REAL span records in the store,
    /// and each correlates to a concurrent metric AND log via a SHARED label
    /// (node) and via the trace correlation id — the cross-kind pivot the ROI
    /// requires. FAILS without a real trace producer.
    #[test]
    fn enabled_tracing_produces_real_spans_correlating_to_metric_and_log() {
        let mut producer = TraceProducer::new(node_labels("n-7"));

        // Config toggle: enable tracing.
        producer.set_enabled(true);
        assert!(producer.is_enabled());
        assert!(producer.is_overridden(), "toggle recorded as an override");

        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        // The node handles a real request: a root span + a child span, both on
        // one trace, emitted concurrently with a metric and a log stamping the
        // same node.
        let trace = "trace-req-42";
        let root = producer
            .record(
                &mut store,
                &mut index,
                &SpanEvent::root(trace, "s-root", "handle_request"),
                0,
            )
            .expect("tracing enabled: root span lands");
        let child = producer
            .record(
                &mut store,
                &mut index,
                &SpanEvent::child(trace, "s-child", "s-root", "apply_op"),
                1,
            )
            .expect("tracing enabled: child span lands");

        // Real span records are in the store and read back as TraceSpan.
        assert!(store.contains(&root));
        assert!(store.contains(&child));
        let mut cache = ViewCache::new();
        let spans = cache.materialize(&store, Query::of_kind(SignalKind::TraceSpan));
        assert_eq!(spans.len(), 2, "two real span records ingested");

        // A concurrent metric and log on the same node, sharing the node label
        // and the trace correlation id (a real request emits all three).
        let node = Label::new("node", "n-7");
        let mut metric_labels = LabelSet::new();
        metric_labels.insert("node".to_string(), "n-7".to_string());
        metric_labels.insert("metric".to_string(), "node_request_count".to_string());
        let metric_id = store
            .write_labeled(
                SignalKind::Metric,
                b"node_request_count 1 @0".to_vec(),
                metric_labels.clone(),
                0,
            )
            .unwrap();
        index.register(
            metric_id.clone(),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: Some(CorrelationId(trace.to_string())),
                labels: metric_labels
                    .iter()
                    .map(|(k, v)| Label::new(k.clone(), v.clone()))
                    .collect(),
            },
        );

        let mut log_labels = LabelSet::new();
        log_labels.insert("node".to_string(), "n-7".to_string());
        let log_id = store
            .write_labeled(
                SignalKind::Log,
                b"level=info msg=served @0".to_vec(),
                log_labels.clone(),
                0,
            )
            .unwrap();
        index.register(
            log_id.clone(),
            &SignalRef {
                kind: SignalKind::Log,
                correlation: Some(CorrelationId(trace.to_string())),
                labels: log_labels
                    .iter()
                    .map(|(k, v)| Label::new(k.clone(), v.clone()))
                    .collect(),
            },
        );

        // Shared-label pivot: the node label gathers BOTH spans, the metric,
        // and the log — the span correlates to the concurrent metric/log.
        let by_node = index.by_label(&node);
        assert!(by_node.contains(&root));
        assert!(by_node.contains(&child));
        assert!(by_node.contains(&metric_id), "span shares the node label with the metric");
        assert!(by_node.contains(&log_id), "span shares the node label with the log");

        // Correlation-id pivot: the trace id gathers the spans AND the metric
        // AND the log, and genuinely crosses those kinds.
        let cid = CorrelationId(trace.to_string());
        let by_trace = index.by_correlation(&cid);
        assert!(by_trace.contains(&root));
        assert!(by_trace.contains(&metric_id));
        assert!(by_trace.contains(&log_id));
        let kinds = index.kinds_for_correlation(&cid);
        assert!(kinds.contains(&SignalKind::TraceSpan));
        assert!(kinds.contains(&SignalKind::Metric));
        assert!(kinds.contains(&SignalKind::Log));
    }

    /// The config toggle is bidirectional: disabling a live producer stops new
    /// span writes; re-enabling resumes them — exactly the `ConfigToggle`
    /// contract, off and back on.
    #[test]
    fn config_toggle_off_stops_writes_and_reenable_resumes() {
        let mut producer = TraceProducer::new(node_labels("n-1"));
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        producer.set_enabled(true);
        let a = producer.record(
            &mut store,
            &mut index,
            &SpanEvent::root("t", "s0", "op"),
            0,
        );
        assert!(a.is_some(), "enabled producer writes a span");
        let held_after_enabled = store.held_len();
        assert_eq!(held_after_enabled, 1);

        // Disable: subsequent records write nothing.
        producer.set_enabled(false);
        assert!(!producer.is_enabled());
        for tick in 1..4 {
            let out = producer.record(
                &mut store,
                &mut index,
                &SpanEvent::root("t", format!("s{tick}"), "op"),
                tick,
            );
            assert_eq!(out, None, "disabled producer writes nothing");
        }
        assert_eq!(
            store.held_len(),
            held_after_enabled,
            "no new span writes while disabled"
        );

        // Re-enable: writes resume.
        producer.set_enabled(true);
        let b = producer.record(
            &mut store,
            &mut index,
            &SpanEvent::root("t", "s-resume", "op"),
            9,
        );
        assert!(b.is_some(), "re-enabling resumes real span writes");
        assert_eq!(store.held_len(), held_after_enabled + 1);
    }

    /// A recorded span carries the parent-child DAG edge in its payload, so a
    /// child span composes onto its root — spans genuinely form traces.
    #[test]
    fn recorded_span_carries_parent_edge_forming_the_trace_dag() {
        let mut producer = TraceProducer::new(node_labels("n-1"));
        producer.set_enabled(true);
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        producer
            .record(
                &mut store,
                &mut index,
                &SpanEvent::root("tr", "root", "handle"),
                0,
            )
            .unwrap();
        producer
            .record(
                &mut store,
                &mut index,
                &SpanEvent::child("tr", "leaf", "root", "apply"),
                1,
            )
            .unwrap();

        let leaf = store
            .held_signals()
            .find(|s| {
                s.kind() == SignalKind::TraceSpan
                    && String::from_utf8_lossy(s.payload()).contains("span=leaf")
            })
            .expect("child span present");
        let text = String::from_utf8_lossy(leaf.payload());
        assert!(text.contains("parent=root"), "child records its parent edge");

        let root = store
            .held_signals()
            .find(|s| String::from_utf8_lossy(s.payload()).contains("span=root"))
            .unwrap();
        assert!(
            String::from_utf8_lossy(root.payload()).contains("parent=-"),
            "root span has no parent"
        );
    }
}
