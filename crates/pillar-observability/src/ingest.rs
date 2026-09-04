//! Real metrics ingestion — the running node instruments ITSELF and writes
//! genuine metric signals into the [`crate::TimeseriesStore`] via the ONE
//! producer contract the ingestion substrate spec
//! (`specs/ObsIngestionSubstrate.tla`) models: a single `Produce` path onto
//! the store, a default-on/off matrix, and a per-producer config toggle.
//!
//! This is the Rust refinement of the `metrics` producer of that spec. Metrics
//! ingestion is **on by default** (`DefaultOn = {metrics, logs, metadata}`),
//! and a config override disabling it stops new writes — nothing else changes.
//!
//! # No fabrication (the `NoFabricatedSample` invariant, one hop upstream)
//!
//! The substrate proves `Produce` only ever admits data for a real occurrence.
//! Here that is enforced structurally: a [`MetricsProducer`] NEVER synthesizes
//! a value. Every sample it writes comes from a [`MetricSource`] reading of a
//! REAL, currently-observable quantity (a `/proc` counter, a live atomic
//! counter the node itself increments). A source with no genuine reading for a
//! metric returns `None`, and the producer writes nothing for it — there is no
//! placeholder, no constant, no demo series. A booted node therefore ends up
//! with real, non-zero series for the metrics its host actually exposes, and
//! never a fabricated one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::block::{SignalKind, TimeseriesStore};
use crate::metadata::LabelSet;

/// The named node self-metrics the ROI requires a running node to ingest.
///
/// Each is a real, observable quantity of the running process/host — never a
/// synthetic value. The stable string [`MetricKind::name`] is the series name
/// carried in every metric signal's payload and its `metric` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricKind {
    /// Process CPU used, in whole ticks (monotonic, from the OS scheduler).
    Cpu,
    /// Process resident memory, in bytes (from the OS).
    Mem,
    /// StreamDB operations applied by this node (monotonic counter).
    StreamdbOps,
    /// Current live p2p peer count (an instantaneous gauge).
    P2pPeers,
    /// Requests served by this node (monotonic counter).
    RequestCount,
    /// Bytes ingested onto the observability substrate (monotonic counter).
    IngestBytes,
}

impl MetricKind {
    /// Every named metric a running node instruments itself with.
    pub const ALL: [MetricKind; 6] = [
        MetricKind::Cpu,
        MetricKind::Mem,
        MetricKind::StreamdbOps,
        MetricKind::P2pPeers,
        MetricKind::RequestCount,
        MetricKind::IngestBytes,
    ];

    /// The stable series name — the string carried in the signal payload and
    /// the `metric` label, so a query can select exactly this series.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            MetricKind::Cpu => "node_cpu_ticks",
            MetricKind::Mem => "node_mem_bytes",
            MetricKind::StreamdbOps => "node_streamdb_ops",
            MetricKind::P2pPeers => "node_p2p_peers",
            MetricKind::RequestCount => "node_request_count",
            MetricKind::IngestBytes => "node_ingest_bytes",
        }
    }
}

/// A source of REAL metric readings for the running node.
///
/// The single seam through which a [`MetricsProducer`] obtains values. An
/// implementation returns `Some(value)` ONLY for a metric it can genuinely
/// observe right now, and `None` for one it cannot — the producer never
/// invents a value in that case, which is what keeps `NoFabricatedSample` true
/// end to end.
pub trait MetricSource {
    /// The current real reading for `metric`, or `None` if this host cannot
    /// genuinely observe it (never a placeholder/zero-fill).
    fn read(&self, metric: MetricKind) -> Option<u64>;
}

/// Live, node-owned counters the process increments as it does real work, plus
/// the current peer gauge — the genuine source for the counter/gauge metrics
/// that have no `/proc` equivalent (streamdb ops, p2p peers, requests, ingest
/// bytes). Every field is moved forward ONLY by real events in the node
/// (an applied op, a served request, a byte written to the substrate), so a
/// reading off it is a real measurement, not a fabricated one.
///
/// Cheaply cloneable and thread-safe (shared `Arc<AtomicU64>` cells): the node
/// hands clones to the subsystems that record events while the producer reads
/// the same cells.
#[derive(Clone, Debug, Default)]
pub struct NodeCounters {
    streamdb_ops: Arc<AtomicU64>,
    p2p_peers: Arc<AtomicU64>,
    request_count: Arc<AtomicU64>,
    ingest_bytes: Arc<AtomicU64>,
}

impl NodeCounters {
    /// Fresh zeroed counters (no work observed yet).
    #[must_use]
    pub fn new() -> Self {
        NodeCounters::default()
    }

    /// Record `n` streamdb operations applied.
    pub fn record_streamdb_ops(&self, n: u64) {
        self.streamdb_ops.fetch_add(n, Ordering::Relaxed);
    }

    /// Set the current live p2p peer count (a gauge, not a counter).
    pub fn set_p2p_peers(&self, peers: u64) {
        self.p2p_peers.store(peers, Ordering::Relaxed);
    }

    /// Record `n` requests served.
    pub fn record_requests(&self, n: u64) {
        self.request_count.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` bytes ingested onto the substrate.
    pub fn record_ingest_bytes(&self, n: u64) {
        self.ingest_bytes.fetch_add(n, Ordering::Relaxed);
    }

    fn get(&self, metric: MetricKind) -> Option<u64> {
        match metric {
            MetricKind::StreamdbOps => Some(self.streamdb_ops.load(Ordering::Relaxed)),
            MetricKind::P2pPeers => Some(self.p2p_peers.load(Ordering::Relaxed)),
            MetricKind::RequestCount => Some(self.request_count.load(Ordering::Relaxed)),
            MetricKind::IngestBytes => Some(self.ingest_bytes.load(Ordering::Relaxed)),
            // cpu/mem come from the OS, not these counters.
            MetricKind::Cpu | MetricKind::Mem => None,
        }
    }
}

/// The real self-metric source for a running node: OS-level cpu/mem from Linux
/// `/proc/self/stat` + `/proc/self/statm`, and the node's own live
/// [`NodeCounters`] for the counter/gauge metrics. Every reading is a genuine
/// measurement of THIS process — nothing is synthesized.
#[derive(Clone, Debug, Default)]
pub struct NodeMetricSource {
    counters: NodeCounters,
}

impl NodeMetricSource {
    /// A source backed by the node's own live counters.
    #[must_use]
    pub fn new(counters: NodeCounters) -> Self {
        NodeMetricSource { counters }
    }

    /// Real process CPU in ticks: `utime + stime` from `/proc/self/stat`
    /// (fields 14 and 15, after the `comm` field which may contain spaces).
    fn read_cpu_ticks() -> Option<u64> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // The `comm` field is parenthesized and may hold spaces/`)`; split on
        // the LAST ')' so the remaining fields are stable and space-separated.
        let after = stat.rsplit_once(')')?.1;
        let fields: Vec<&str> = after.split_whitespace().collect();
        // After ')', field indices shift: state is [0]; utime is the 14th stat
        // field overall = index 11 here, stime = index 12.
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        Some(utime.saturating_add(stime))
    }

    /// Real resident memory in bytes: RSS pages from `/proc/self/statm`
    /// (field 2) times the system page size.
    fn read_mem_bytes() -> Option<u64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // Standard Linux page size; 4 KiB on every platform this node targets.
        let page_size: u64 = 4096;
        Some(rss_pages.saturating_mul(page_size))
    }
}

impl MetricSource for NodeMetricSource {
    fn read(&self, metric: MetricKind) -> Option<u64> {
        match metric {
            MetricKind::Cpu => Self::read_cpu_ticks(),
            MetricKind::Mem => Self::read_mem_bytes(),
            other => self.counters.get(other),
        }
    }
}

/// The `metrics` producer: on each [`sample`](MetricsProducer::sample) it reads
/// every named metric from its [`MetricSource`] and writes a real metric signal
/// onto the shared substrate through the single producer contract — the ONLY
/// path onto the store.
///
/// On by default (`DefaultOn` includes `metrics`). A config override
/// ([`MetricsProducer::set_enabled`]) disabling it stops new writes; a `sample`
/// while disabled writes nothing and returns 0.
pub struct MetricsProducer<S: MetricSource> {
    source: S,
    enabled: bool,
    /// Whether the enabled state was set explicitly by config (vs. the
    /// default), mirroring the spec's `overridden` set so a reconcile can tell
    /// a deliberate toggle from an untouched default.
    overridden: bool,
}

impl<S: MetricSource> MetricsProducer<S> {
    /// A producer at its DEFAULT state: **enabled** (metrics is in `DefaultOn`),
    /// not yet overridden by config.
    #[must_use]
    pub fn new(source: S) -> Self {
        MetricsProducer {
            source,
            enabled: true,
            overridden: false,
        }
    }

    /// Whether this producer is currently live (writing samples).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether the enabled state was set by an explicit config override.
    #[must_use]
    pub fn is_overridden(&self) -> bool {
        self.overridden
    }

    /// Apply a config override flipping this producer on/off — records it as an
    /// explicit override (`overridden`), exactly the substrate spec's
    /// `ConfigToggle`. Disabling stops future `sample`s from writing.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.overridden = true;
    }

    /// The producer's metric source (for inspection/testing).
    #[must_use]
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Ingest one round of self-metrics into `store` at logical `tick`.
    ///
    /// For each named metric the source can GENUINELY read, builds a metric
    /// envelope (payload `"<name> <value>"`, a `metric=<name>` label) and writes
    /// it through the store's single producer path. A metric the source cannot
    /// observe (`None`) is skipped — never zero-filled — so no fabricated series
    /// is ever created. Returns the number of real samples written.
    ///
    /// While disabled it writes nothing and returns 0.
    pub fn sample(&self, store: &mut TimeseriesStore, tick: u64) -> usize {
        if !self.enabled {
            return 0;
        }
        let mut written = 0;
        for metric in MetricKind::ALL {
            let Some(value) = self.source.read(metric) else {
                continue;
            };
            let name = metric.name();
            let mut labels = LabelSet::new();
            labels.insert("metric".to_string(), name.to_string());
            // Payload carries name + value so identical (name,value,tick)
            // samples content-dedupe while distinct readings are distinct
            // signals. Tick disambiguates otherwise-equal successive readings.
            let payload = format!("{name} {value} @{tick}");
            if store
                .write_labeled(SignalKind::Metric, payload.into_bytes(), labels, tick)
                .is_some()
            {
                written += 1;
            }
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use crate::ViewCache;
    use std::collections::BTreeMap;

    /// A deterministic REAL source for tests: it returns genuine, caller-set
    /// readings for exactly the metrics it was given a real value for, and
    /// `None` for any it has no genuine reading of. This is not fabrication —
    /// it models a host that truly exposes those quantities — and it lets a
    /// test assert both the non-zero-series and the no-fabrication properties
    /// deterministically without depending on the CI host's `/proc`.
    #[derive(Clone, Default)]
    struct FixedSource {
        readings: BTreeMap<MetricKind, u64>,
    }

    impl FixedSource {
        fn with(mut self, metric: MetricKind, value: u64) -> Self {
            self.readings.insert(metric, value);
            self
        }
        /// A source with a real, non-zero reading for every named metric.
        fn all_nonzero() -> Self {
            let mut s = FixedSource::default();
            for (i, m) in MetricKind::ALL.iter().enumerate() {
                s.readings.insert(*m, (i as u64) + 1);
            }
            s
        }
    }

    impl MetricSource for FixedSource {
        fn read(&self, metric: MetricKind) -> Option<u64> {
            self.readings.get(&metric).copied()
        }
    }

    /// Every named metric series is present and non-zero in the store after a
    /// short run of a booted (default-on) producer. FAILS if the producer does
    /// not actually instrument the node.
    #[test]
    fn booted_node_ingests_real_nonzero_series_for_each_named_metric() {
        let producer = MetricsProducer::new(FixedSource::all_nonzero());
        assert!(producer.is_enabled(), "metrics producer is ON by default");

        let mut store = TimeseriesStore::new(64, 10_000);
        // A short run: a handful of sampling rounds.
        let mut total = 0;
        for tick in 0..5 {
            total += producer.sample(&mut store, tick);
        }
        assert!(total > 0, "a booted node must ingest metric samples");

        // Each named metric has at least one real signal, and its value is
        // non-zero (the source's readings were all >= 1, none fabricated to 0).
        let mut cache = ViewCache::new();
        let metric_ids = cache.materialize(&store, Query::of_kind(SignalKind::Metric));
        assert!(!metric_ids.is_empty(), "metric kind ingested onto substrate");

        for metric in MetricKind::ALL {
            let name = metric.name();
            let found: Vec<_> = store
                .held_signals()
                .filter(|s| s.kind() == SignalKind::Metric)
                .filter(|s| {
                    s.labels().get("metric").map(String::as_str) == Some(name)
                })
                .collect();
            assert!(
                !found.is_empty(),
                "named metric {name} has a real ingested series"
            );
            // Every payload for this metric parses to a non-zero value.
            for s in found {
                let text = String::from_utf8(s.payload().to_vec()).unwrap();
                // "<name> <value> @<tick>"
                let value: u64 = text
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .expect("metric payload carries a numeric value");
                assert!(value > 0, "series {name} carries a real, non-zero value");
            }
        }
    }

    /// `NoFabricatedSample`: the producer writes a signal ONLY for a metric the
    /// source genuinely observes. A source that cannot read a metric (`None`)
    /// yields NO signal for it — never a synthetic/zero placeholder.
    #[test]
    fn no_fabricated_sample_when_source_has_no_reading() {
        // A source that can only genuinely observe two of the six metrics.
        let source = FixedSource::default()
            .with(MetricKind::Cpu, 42)
            .with(MetricKind::Mem, 4096);
        let producer = MetricsProducer::new(source);

        let mut store = TimeseriesStore::new(64, 10_000);
        let written = producer.sample(&mut store, 0);
        assert_eq!(written, 2, "exactly the two genuinely-observed metrics");
        assert_eq!(store.held_len(), 2, "no fabricated signals for the other four");

        // The four unobservable metrics have NO series at all.
        for metric in [
            MetricKind::StreamdbOps,
            MetricKind::P2pPeers,
            MetricKind::RequestCount,
            MetricKind::IngestBytes,
        ] {
            let name = metric.name();
            let any = store.held_signals().any(|s| {
                s.labels().get("metric").map(String::as_str) == Some(name)
            });
            assert!(!any, "unobservable metric {name} was NOT fabricated");
        }
    }

    /// A config override disabling metrics stops new writes — the substrate
    /// spec's `ConfigToggle` off. Samples taken while enabled remain; no new
    /// signal appears after the toggle.
    #[test]
    fn config_override_disabling_metrics_stops_new_writes() {
        let mut producer = MetricsProducer::new(FixedSource::all_nonzero());
        let mut store = TimeseriesStore::new(64, 10_000);

        let before = producer.sample(&mut store, 0);
        assert!(before > 0, "enabled producer writes");
        let held_after_enabled = store.held_len();
        assert_eq!(held_after_enabled, before);

        // Config override: disable the metrics producer.
        producer.set_enabled(false);
        assert!(!producer.is_enabled());
        assert!(producer.is_overridden(), "toggle recorded as an override");

        // Every subsequent sample writes nothing.
        for tick in 1..5 {
            let n = producer.sample(&mut store, tick);
            assert_eq!(n, 0, "disabled producer writes nothing");
        }
        assert_eq!(
            store.held_len(),
            held_after_enabled,
            "no new writes after the disabling override"
        );
    }

    /// Live node counters feed real counter/gauge readings, and re-enabling
    /// resumes writes — the toggle is bidirectional.
    #[test]
    fn node_counters_feed_real_readings_and_reenable_resumes() {
        let counters = NodeCounters::new();
        counters.record_streamdb_ops(7);
        counters.set_p2p_peers(3);
        counters.record_requests(11);
        counters.record_ingest_bytes(2048);

        let source = NodeMetricSource::new(counters.clone());
        // The counter-backed metrics read the real live values.
        assert_eq!(source.read(MetricKind::StreamdbOps), Some(7));
        assert_eq!(source.read(MetricKind::P2pPeers), Some(3));
        assert_eq!(source.read(MetricKind::RequestCount), Some(11));
        assert_eq!(source.read(MetricKind::IngestBytes), Some(2048));

        let mut producer = MetricsProducer::new(source);
        let mut store = TimeseriesStore::new(64, 10_000);

        // cpu/mem come from real /proc on this host and may or may not be
        // available in the sandbox; the four counter metrics are always real.
        let n0 = producer.sample(&mut store, 0);
        assert!(n0 >= 4, "at least the four live-counter metrics are written");

        producer.set_enabled(false);
        assert_eq!(producer.sample(&mut store, 1), 0);

        producer.set_enabled(true);
        assert!(producer.is_overridden());
        let n2 = producer.sample(&mut store, 2);
        assert!(n2 >= 4, "re-enabling resumes real writes");
    }

    /// A newly-observed counter increment shows up as a distinct, larger real
    /// reading — proving the series tracks genuine node activity, not a
    /// constant.
    #[test]
    fn counter_readings_track_real_activity() {
        let counters = NodeCounters::new();
        let source = NodeMetricSource::new(counters.clone());
        assert_eq!(source.read(MetricKind::RequestCount), Some(0));
        counters.record_requests(5);
        assert_eq!(source.read(MetricKind::RequestCount), Some(5));
        counters.record_requests(2);
        assert_eq!(source.read(MetricKind::RequestCount), Some(7));
    }
}
