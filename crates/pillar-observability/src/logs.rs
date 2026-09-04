//! Real log ingestion — the running node's info-level logging (ON by
//! default) is captured as genuine log signals into the shared
//! [`crate::TimeseriesStore`] through the SAME single producer contract every
//! other kind uses, stamping the SAME label shape the metrics producer
//! ([`crate::ingest::MetricsProducer`]) stamps so a log and a metric from the
//! same request correlate.
//!
//! This is the Rust refinement of the `logs` producer of
//! `specs/ObsIngestionSubstrate.tla`. Logs default **ON** (`DefaultOn =
//! {metrics, logs, metadata}`, [`crate::signal_config`]) at [`LogLevel::Info`]
//! — a fresh, un-toggled node captures real info-and-above entries with no
//! config change required.
//!
//! # No fabrication
//!
//! A log signal is written ONLY for a real [`LogEvent`] the node genuinely
//! emitted (a request served, an op applied, a warning/error actually raised).
//! There is no synthetic demo line, no placeholder: recording a log requires a
//! caller to hand the producer a real occurrence, and the occurrence is
//! written only if its level clears the currently-configured minimum level.
//!
//! # Shared label shape
//!
//! Every log the producer writes stamps the node's shared labels (e.g.
//! `node=<id>`) — the SAME dimensions [`crate::ingest::MetricsProducer`] and
//! [`crate::traces::TraceProducer`] stamp — so a log emitted concurrently with
//! a metric or span on the same node gathers alongside it by the shared label
//! pivot, and (when the caller supplies one) a request/trace correlation id so
//! it cross-pivots by causal thread too.

use crate::block::{SignalKind, TimeseriesStore};
use crate::correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
use crate::metadata::LabelSet;

/// The severity of a real log occurrence, ordered from least to most severe.
/// Mirrors the standard `TRACE < DEBUG < INFO < WARN < ERROR` info-logging
/// hierarchy; the producer captures a level's occurrence only when it is `>=`
/// the currently-configured minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Fine-grained diagnostic detail.
    Trace,
    /// Diagnostic detail useful in development.
    Debug,
    /// Normal operational information — the node's default captured level.
    Info,
    /// A recoverable, noteworthy condition.
    Warn,
    /// A failure condition.
    Error,
}

impl LogLevel {
    /// The stable string used in a log signal's payload/label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// A single real log occurrence the node emitted: a level, a message, and the
/// operation/component it came from. Every field is a genuine value of a real
/// emission — the producer never synthesizes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvent {
    /// The severity the node actually logged at.
    pub level: LogLevel,
    /// The log message itself.
    pub message: String,
    /// An optional request/trace correlation id shared with a concurrent
    /// metric/span of the same causal thread.
    pub correlation: Option<String>,
}

impl LogEvent {
    /// A real log occurrence at `level` with `message`, uncorrelated to any
    /// particular causal thread.
    #[must_use]
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        LogEvent {
            level,
            message: message.into(),
            correlation: None,
        }
    }

    /// A real log occurrence at `level` with `message`, correlated to
    /// `correlation` (e.g. a request/trace id) so it cross-pivots with a
    /// concurrent metric/span of the same thread.
    #[must_use]
    pub fn correlated(
        level: LogLevel,
        message: impl Into<String>,
        correlation: impl Into<String>,
    ) -> Self {
        LogEvent {
            level,
            message: message.into(),
            correlation: Some(correlation.into()),
        }
    }
}

/// The `logs` producer: on each real [`LogEvent`] whose level clears the
/// currently-configured minimum, writes one genuine log signal onto the
/// shared substrate through the single producer contract, stamping the node's
/// shared labels (+ an optional correlation id).
///
/// **ON by default** (`logs` is in `DefaultOn`) at [`LogLevel::Info`] — a
/// fresh, un-toggled node captures info-and-above entries immediately. A
/// config override ([`LogProducer::set_min_level`]) to a different level
/// changes what is subsequently captured: raising it drops lower-severity
/// occurrences, lowering it admits them.
pub struct LogProducer {
    /// The node's shared labels every log stamps (e.g. `node=<id>`) — the same
    /// dimensions [`crate::ingest::MetricsProducer`] stamps.
    node_labels: LabelSet,
    min_level: LogLevel,
    /// Whether the level was set explicitly by config (vs. the declared
    /// default), mirroring the substrate spec's `overridden` set.
    overridden: bool,
}

impl LogProducer {
    /// A producer at its DEFAULT state: capturing at [`LogLevel::Info`] (logs
    /// is in `DefaultOn`), not yet overridden by config. `node_labels` are the
    /// shared dimensions every emitted log stamps.
    #[must_use]
    pub fn new(node_labels: LabelSet) -> Self {
        debug_assert!(
            crate::signal_config::default_on(SignalKind::Log),
            "logs must default ON"
        );
        LogProducer {
            node_labels,
            min_level: LogLevel::Info,
            overridden: false,
        }
    }

    /// The currently-configured minimum captured level.
    #[must_use]
    pub fn min_level(&self) -> LogLevel {
        self.min_level
    }

    /// Whether the minimum level was set by an explicit config override.
    #[must_use]
    pub fn is_overridden(&self) -> bool {
        self.overridden
    }

    /// Apply a config override changing the minimum captured level — records
    /// it as an explicit override, exactly the substrate spec's
    /// `ConfigToggle`. Takes effect for every subsequent [`record`](Self::record).
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
        self.overridden = true;
    }

    /// The shared node labels every emitted log stamps.
    #[must_use]
    pub fn node_labels(&self) -> &LabelSet {
        &self.node_labels
    }

    fn log_labels(&self) -> LabelSet {
        self.node_labels.clone()
    }

    /// Record one real log occurrence into `store` at logical `tick`, and
    /// register it on `index` under the node's shared labels (+ its
    /// correlation id, if any) so it cross-pivots with the other kinds.
    ///
    /// Writes a log signal (payload `"level=<level> msg=<message> @<tick>"`,
    /// labels = the node's shared labels) through the store's single producer
    /// path and returns its id — but ONLY when `event.level >= min_level`.
    /// An occurrence below the currently-configured minimum writes nothing,
    /// registers nothing, and returns `None`; this is the config-driven
    /// filter, never a fabricated/omitted-then-backfilled entry.
    pub fn record(
        &self,
        store: &mut TimeseriesStore,
        index: &mut CorrelationIndex,
        event: &LogEvent,
        tick: u64,
    ) -> Option<crate::block::SignalId> {
        if event.level < self.min_level {
            return None;
        }
        let labels = self.log_labels();
        let payload = format!(
            "level={} msg={} @{}",
            event.level.as_str(),
            event.message,
            tick
        );
        let id = store.write_labeled(SignalKind::Log, payload.into_bytes(), labels.clone(), tick)?;
        let spine = SignalRef {
            kind: SignalKind::Log,
            correlation: event.correlation.clone().map(CorrelationId),
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
    use crate::correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
    use crate::query::Query;
    use crate::signal_config::default_on;
    use crate::ViewCache;

    fn node_labels(node: &str) -> LabelSet {
        let mut l = LabelSet::new();
        l.insert("node".to_string(), node.to_string());
        l
    }

    /// Logs default ON at Info, and a booted (un-toggled) node emits real
    /// info-level log entries into the store — the config-off half never
    /// applies here since logs is in `DefaultOn`. FAILS without a real log
    /// producer that actually captures entries by default.
    #[test]
    fn booted_node_captures_real_log_entries_at_default_info_level() {
        assert!(default_on(SignalKind::Log), "logs must default ON");
        let producer = LogProducer::new(node_labels("n-1"));
        assert_eq!(producer.min_level(), LogLevel::Info, "default level is info");
        assert!(!producer.is_overridden(), "no override yet on a fresh node");

        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        let id = producer
            .record(
                &mut store,
                &mut index,
                &LogEvent::new(LogLevel::Info, "node booted"),
                0,
            )
            .expect("a fresh node captures a real info-level log by default");
        assert!(store.contains(&id));

        let mut cache = ViewCache::new();
        let logs = cache.materialize(&store, Query::of_kind(SignalKind::Log));
        assert_eq!(logs.len(), 1, "one real log entry ingested");
    }

    /// A log entry emitted concurrently with a metric on the same node shares
    /// the node label with it — the log/metric correlation the ROI requires.
    /// FAILS without the log producer stamping the metrics producer's shared
    /// label shape.
    #[test]
    fn concurrent_log_and_metric_share_labels_and_correlate() {
        let producer = LogProducer::new(node_labels("n-7"));
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        let trace = "trace-req-9";
        let log_id = producer
            .record(
                &mut store,
                &mut index,
                &LogEvent::correlated(LogLevel::Info, "served request", trace),
                0,
            )
            .expect("info log captured by default");

        // A concurrent metric on the same node, sharing the node label and
        // the request correlation id.
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

        // Shared-label pivot: the node label gathers both the log and the
        // metric.
        let node = Label::new("node", "n-7");
        let by_node = index.by_label(&node);
        assert!(by_node.contains(&log_id));
        assert!(by_node.contains(&metric_id), "log shares node label with metric");

        // Correlation-id pivot: the request id gathers both.
        let cid = CorrelationId(trace.to_string());
        let by_trace = index.by_correlation(&cid);
        assert!(by_trace.contains(&log_id));
        assert!(by_trace.contains(&metric_id));
        let kinds = index.kinds_for_correlation(&cid);
        assert!(kinds.contains(&SignalKind::Log));
        assert!(kinds.contains(&SignalKind::Metric));
    }

    /// A config override to a different (higher) level changes what is
    /// captured: raising the minimum to Warn drops a subsequent Info
    /// occurrence that would otherwise have been captured, while a Warn/Error
    /// occurrence still lands. FAILS without a real level filter honoring the
    /// override.
    #[test]
    fn config_override_to_a_different_level_changes_what_is_captured() {
        let mut producer = LogProducer::new(node_labels("n-1"));
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        // At the default (info) level, an info occurrence is captured.
        let a = producer.record(
            &mut store,
            &mut index,
            &LogEvent::new(LogLevel::Info, "normal op"),
            0,
        );
        assert!(a.is_some(), "info captured at default info level");

        // Override: raise the minimum to Warn.
        producer.set_min_level(LogLevel::Warn);
        assert!(producer.is_overridden());
        assert_eq!(producer.min_level(), LogLevel::Warn);

        // A subsequent info occurrence is now dropped...
        let b = producer.record(
            &mut store,
            &mut index,
            &LogEvent::new(LogLevel::Info, "quiet op"),
            1,
        );
        assert!(b.is_none(), "info dropped once minimum raised to warn");

        // ...but a warn/error occurrence still lands.
        let c = producer
            .record(
                &mut store,
                &mut index,
                &LogEvent::new(LogLevel::Warn, "disk almost full"),
                2,
            )
            .expect("warn still captured at warn minimum");
        assert!(store.contains(&c));

        // Exactly two log entries total: the initial info + the warn; the
        // dropped info never landed.
        let mut cache = ViewCache::new();
        let logs = cache.materialize(&store, Query::of_kind(SignalKind::Log));
        assert_eq!(logs.len(), 2, "the level-filtered info never landed");

        // Lowering the minimum back down resumes capturing info entries.
        producer.set_min_level(LogLevel::Info);
        let d = producer.record(
            &mut store,
            &mut index,
            &LogEvent::new(LogLevel::Info, "resumed"),
            3,
        );
        assert!(d.is_some(), "lowering the minimum resumes info capture");
    }
}
