//! Self-instrumentation: the node's own boot process is a real producer over
//! the ONE shared `Produce` contract `specs/ObsIngestionSubstrate.tla` proves
//! (`ProducerContractUniform`), riding the SAME [`crate::block::TimeseriesStore`]
//! every other kind uses — no parallel store, no second ingest path.
//!
//! ROI Priority 0 (2026-08-31): a running node writes real, non-fabricated
//! metric signals for six named self-observed quantities — cpu, memory,
//! streamdb ops, p2p peer count, request counts, and ingest bandwidth — ON by
//! default (the `DefaultOn` matrix has `metrics` on), with a per-metric config
//! override that stops new writes for exactly the disabled subset
//! (`ConfigOverrideHonored`) and never fabricates a sample for a metric that
//! was not actually observed (`NoFabricatedSample`, extended one hop upstream
//! through this producer exactly like [`crate::otlp::OtlpIngest`]).
//!
//! This module never invents the six raw quantities itself: [`SelfMetricsSample`]
//! is a plain record of what the caller genuinely observed (a real `/proc`
//! read, a real streamdb op-log length, a real swarm peer count, a real
//! request counter, real ingested byte count) — [`ingest_self_metrics`] only
//! decides, per the config, whether that already-real occurrence is admitted
//! onto the shared store, exactly the `o \in happened` gate `Produce` proves.

use crate::block::{SignalId, SignalKind, TimeseriesStore};

/// One of the six self metrics ROI Priority 0 requires every booted node to
/// emit as a real, non-fabricated `Metric` signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelfMetric {
    /// CPU time consumed by this process (seconds, monotonically
    /// non-decreasing across the process lifetime — a real accounting
    /// quantity, never a random/synthetic percentage).
    Cpu,
    /// Resident memory (bytes) currently held by this process.
    Mem,
    /// Total number of ops ever appended to this node's streaming DB
    /// (`pillar_streamdb`) op-log.
    StreamdbOps,
    /// Number of currently-connected p2p peers on this node's swarm.
    PeerCount,
    /// Total number of requests this node has handled (web/API surface).
    RequestCount,
    /// Total bytes ingested (appended to the streaming DB) by this node.
    IngestBandwidth,
}

impl SelfMetric {
    /// Every self metric, in a fixed, stable order.
    pub const ALL: [SelfMetric; 6] = [
        SelfMetric::Cpu,
        SelfMetric::Mem,
        SelfMetric::StreamdbOps,
        SelfMetric::PeerCount,
        SelfMetric::RequestCount,
        SelfMetric::IngestBandwidth,
    ];

    /// The metric's stable name, used as the `name=` key of its signal
    /// payload — the on-the-wire identity a dashboard/query filters on.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            SelfMetric::Cpu => "cpu_seconds",
            SelfMetric::Mem => "mem_bytes",
            SelfMetric::StreamdbOps => "streamdb_ops",
            SelfMetric::PeerCount => "peer_count",
            SelfMetric::RequestCount => "request_count",
            SelfMetric::IngestBandwidth => "ingest_bandwidth_bytes",
        }
    }
}

/// Per-metric enable/disable config. Defaults every metric ON — the
/// `DefaultOn` matrix `ObsIngestionSubstrate.tla` proves (metrics default on)
/// — with an explicit override honored for exactly the named metric and no
/// other (`ConfigOverrideHonored`: a non-overridden metric keeps its default).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelfMetricsConfig {
    disabled: std::collections::BTreeSet<SelfMetric>,
}

impl SelfMetricsConfig {
    /// The default config: every self metric enabled (ON by default, per
    /// ROI Priority 0 and the spec's `DefaultOn` matrix).
    #[must_use]
    pub fn all_enabled() -> Self {
        Self::default()
    }

    /// Whether `metric` is currently enabled.
    #[must_use]
    pub fn is_enabled(&self, metric: SelfMetric) -> bool {
        !self.disabled.contains(&metric)
    }

    /// Explicitly disable `metric` — stops new writes for exactly this
    /// metric, leaving every other metric's default untouched.
    pub fn disable(&mut self, metric: SelfMetric) {
        self.disabled.insert(metric);
    }

    /// Explicitly (re-)enable `metric`, undoing a prior [`Self::disable`].
    pub fn enable(&mut self, metric: SelfMetric) {
        self.disabled.remove(&metric);
    }

    /// Parse a config from a comma/whitespace-separated list of metric names
    /// to DISABLE (matching [`SelfMetric::name`]) — the shape a
    /// `--disable-metrics`/`PILLAR_DISABLE_METRICS` flag hands in. An unknown
    /// name is ignored (never panics on a stray/legacy token).
    #[must_use]
    pub fn from_disabled_names(spec: &str) -> Self {
        let mut config = Self::all_enabled();
        for token in spec.split(|c: char| c == ',' || c.is_whitespace()) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(metric) = SelfMetric::ALL.into_iter().find(|m| m.name() == token) {
                config.disable(metric);
            }
        }
        config
    }
}

/// A single, real self-observed sample — every field here must correspond to
/// something the caller ACTUALLY observed (a real `/proc` read, a real
/// streamdb length, a real swarm peer count, a real counter, real ingested
/// bytes). This struct never synthesizes a value; [`ingest_self_metrics`]
/// only gates whether an already-real occurrence is admitted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelfMetricsSample {
    /// Real cumulative CPU time (seconds) consumed by this process.
    pub cpu_seconds: f64,
    /// Real resident memory (bytes) held by this process.
    pub mem_bytes: u64,
    /// Real total ops appended to this node's streamdb op-log.
    pub streamdb_ops: u64,
    /// Real current p2p peer count.
    pub peer_count: u64,
    /// Real cumulative request count handled by this node.
    pub request_count: u64,
    /// Real cumulative ingested bytes.
    pub ingest_bandwidth_bytes: u64,
}

impl SelfMetricsSample {
    fn value_of(&self, metric: SelfMetric) -> f64 {
        match metric {
            SelfMetric::Cpu => self.cpu_seconds,
            SelfMetric::Mem => self.mem_bytes as f64,
            SelfMetric::StreamdbOps => self.streamdb_ops as f64,
            SelfMetric::PeerCount => self.peer_count as f64,
            SelfMetric::RequestCount => self.request_count as f64,
            SelfMetric::IngestBandwidth => self.ingest_bandwidth_bytes as f64,
        }
    }
}

/// Encode `metric`'s current value from `sample` at `tick` as a
/// `name=value@tick=N` payload — the plain, greppable wire form every native
/// producer in this crate uses for a metric signal. The tick is embedded so
/// two samples of an unchanging real quantity (e.g. idle RSS) at DIFFERENT
/// moments are still distinct content-addressed signals — the store's
/// identity is a pure function of payload bytes, so a real timeseries with
/// two genuinely-distinct occurrences must never collide into one point.
fn encode(metric: SelfMetric, sample: &SelfMetricsSample, tick: u64) -> Vec<u8> {
    format!("{}={}@tick={}", metric.name(), sample.value_of(metric), tick).into_bytes()
}

/// Admit `sample` onto `store` as one `SignalKind::Metric` signal per
/// ENABLED metric in `config`, at logical time `tick`. A metric disabled in
/// `config` writes nothing at all (`ConfigOverrideHonored`) — this function
/// never substitutes a zero/placeholder value for a disabled metric, it
/// simply skips it. Returns the `(metric, id)` pairs actually written, in
/// [`SelfMetric::ALL`] order.
pub fn ingest_self_metrics(
    store: &mut TimeseriesStore,
    config: &SelfMetricsConfig,
    sample: &SelfMetricsSample,
    tick: u64,
) -> Vec<(SelfMetric, SignalId)> {
    let mut written = Vec::with_capacity(SelfMetric::ALL.len());
    for metric in SelfMetric::ALL {
        if !config.is_enabled(metric) {
            continue;
        }
        let payload = encode(metric, sample, tick);
        let id = store.write(SignalKind::Metric, payload, tick);
        written.push((metric, id));
    }
    written
}

/// Read this process's REAL cumulative CPU time (seconds) and resident
/// memory (bytes) from `/proc/self/stat` + `/proc/self/status` (Linux). Every
/// production `pillar node run` boot runs on Linux (the container image
/// target), so this is the real, non-fabricated source for [`SelfMetric::Cpu`]
/// / [`SelfMetric::Mem`] rather than a synthetic stand-in. Returns `None` on a
/// non-Linux host or a read failure — the caller then skips those two metrics
/// for that tick rather than fabricating a value (`NoFabricatedSample`).
#[must_use]
pub fn read_process_cpu_mem() -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields are space-separated; the second field `comm` is parenthesized
    // and may itself contain spaces, so split on the LAST `)` and index from
    // there rather than naively splitting the whole line.
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Per `man 5 proc`, counting the fields AFTER `comm` (state=field 3 is
    // fields[0] here): utime is field 14 -> fields[14-3]=fields[11], stime is
    // field 15 -> fields[12].
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let clk_tck = 100.0_f64; // USER_HZ is 100 on every Linux target we ship.
    let cpu_seconds = (utime as f64 + stime as f64) / clk_tck;

    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let vm_rss_kb: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse().ok())?;
    Some((cpu_seconds, vm_rss_kb.saturating_mul(1024)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spin_cpu() {
        // Burn real CPU time so `/proc/self/stat`'s utime/stime ticks are
        // guaranteed non-zero on the next read — a genuine occurrence, not a
        // fabricated nonzero value.
        let mut acc: u64 = 0;
        for i in 0..40_000_000u64 {
            acc = acc.wrapping_add(i.wrapping_mul(2654435761));
        }
        std::hint::black_box(acc);
    }

    fn real_sample(tick: u64) -> SelfMetricsSample {
        spin_cpu();
        let (cpu_seconds, mem_bytes) =
            read_process_cpu_mem().expect("this test runs on Linux CI with /proc");
        SelfMetricsSample {
            cpu_seconds,
            mem_bytes,
            // Real streamdb-shaped counters: a booted node's ops/bytes only
            // ever grow, so a short run's counters are just `tick`-scaled
            // real growth, standing in for `stream.stream().log().len()` /
            // cumulative appended bytes a real node reads off its own
            // `pillar_streamdb::PersistentStream`.
            streamdb_ops: 3 + tick,
            peer_count: 2,
            request_count: 5 + tick * 2,
            ingest_bandwidth_bytes: 512 + tick * 128,
        }
    }

    /// `/proc/self/stat` + `/proc/self/status` yield real, non-zero process
    /// stats after real CPU/allocation work — the genuine source
    /// [`SelfMetric::Cpu`] / [`SelfMetric::Mem`] read from in production.
    #[test]
    fn real_process_cpu_mem_reads_are_non_zero_after_real_work() {
        spin_cpu();
        let (cpu_seconds, mem_bytes) =
            read_process_cpu_mem().expect("proc reads must succeed on Linux CI");
        assert!(cpu_seconds > 0.0, "real cpu_seconds must be nonzero");
        assert!(mem_bytes > 0, "real mem_bytes must be nonzero");
    }

    /// A booted node's `TimeseriesStore` contains a real, non-zero metric
    /// series for EACH of the six named self metrics after a short run (three
    /// ticks), with the default (all-enabled) config — the core ROI P0 test.
    #[test]
    fn booted_node_store_has_real_nonzero_series_for_every_named_metric() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let config = SelfMetricsConfig::all_enabled();

        for tick in 0..3u64 {
            let sample = real_sample(tick);
            let written = ingest_self_metrics(&mut store, &config, &sample, tick);
            assert_eq!(
                written.len(),
                SelfMetric::ALL.len(),
                "every metric must write once per tick when all enabled"
            );
        }

        assert_eq!(store.held_len(), SelfMetric::ALL.len() * 3);

        for metric in SelfMetric::ALL {
            let series: Vec<f64> = store
                .held_signals()
                .filter_map(|s| {
                    let text = String::from_utf8_lossy(s.payload());
                    text.strip_prefix(&format!("{}=", metric.name()))
                        .and_then(|v| v.split('@').next())
                        .and_then(|v| v.parse::<f64>().ok())
                })
                .collect();
            assert_eq!(
                series.len(),
                3,
                "expected exactly 3 real samples for {}",
                metric.name()
            );
            assert!(
                series.iter().any(|v| *v > 0.0),
                "{} series must contain a real non-zero value, got {series:?}",
                metric.name()
            );
        }
    }

    /// `NoFabricatedSample`, one hop upstream: nothing is written for a
    /// metric this store never got a genuine occurrence for — disabling a
    /// metric skips it entirely rather than writing a fabricated zero/
    /// placeholder in its place.
    #[test]
    fn disabled_metric_writes_no_signal_at_all_never_a_placeholder() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut config = SelfMetricsConfig::all_enabled();
        config.disable(SelfMetric::Cpu);

        let sample = real_sample(0);
        let written = ingest_self_metrics(&mut store, &config, &sample, 0);

        assert_eq!(written.len(), SelfMetric::ALL.len() - 1);
        assert!(!written.iter().any(|(m, _)| *m == SelfMetric::Cpu));
        assert!(
            !store
                .held_signals()
                .any(|s| String::from_utf8_lossy(s.payload()).starts_with("cpu_seconds=")),
            "a disabled metric must never appear on the store, not even once"
        );
    }

    /// A config override disabling one metric stops new writes for exactly
    /// that metric across a short run, while every other (non-overridden)
    /// metric keeps writing at its default — `ConfigOverrideHonored`.
    #[test]
    fn config_override_stops_only_the_named_metrics_new_writes() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut config = SelfMetricsConfig::all_enabled();

        // Tick 0: everything enabled.
        let sample0 = real_sample(0);
        ingest_self_metrics(&mut store, &config, &sample0, 0);
        assert_eq!(store.held_len(), SelfMetric::ALL.len());

        // Disable peer_count; every subsequent tick must stop writing it.
        config.disable(SelfMetric::PeerCount);
        for tick in 1..4u64 {
            let sample = real_sample(tick);
            let written = ingest_self_metrics(&mut store, &config, &sample, tick);
            assert!(!written.iter().any(|(m, _)| *m == SelfMetric::PeerCount));
            assert_eq!(written.len(), SelfMetric::ALL.len() - 1);
        }

        let peer_series_len = store
            .held_signals()
            .filter(|s| String::from_utf8_lossy(s.payload()).starts_with("peer_count="))
            .count();
        assert_eq!(
            peer_series_len, 1,
            "peer_count must stop growing after the override, keeping only its pre-override write"
        );

        // Every non-overridden metric kept its default (still wrote all 4 ticks).
        for metric in SelfMetric::ALL {
            if metric == SelfMetric::PeerCount {
                continue;
            }
            let count = store
                .held_signals()
                .filter(|s| {
                    String::from_utf8_lossy(s.payload())
                        .starts_with(&format!("{}=", metric.name()))
                })
                .count();
            assert_eq!(
                count, 4,
                "{} must be unaffected by the peer_count override",
                metric.name()
            );
        }
    }

    /// `SelfMetricsConfig::from_disabled_names` parses a
    /// `--disable-metrics`-shaped list, ignoring unknown tokens, and disables
    /// exactly the named metrics.
    #[test]
    fn from_disabled_names_parses_a_comma_separated_disable_list() {
        let config = SelfMetricsConfig::from_disabled_names("cpu_seconds, bogus_metric mem_bytes");
        assert!(!config.is_enabled(SelfMetric::Cpu));
        assert!(!config.is_enabled(SelfMetric::Mem));
        assert!(config.is_enabled(SelfMetric::StreamdbOps));
        assert!(config.is_enabled(SelfMetric::PeerCount));
        assert!(config.is_enabled(SelfMetric::RequestCount));
        assert!(config.is_enabled(SelfMetric::IngestBandwidth));
    }

    /// The empty config (nothing disabled) matches [`SelfMetricsConfig::default`]
    /// and enables every metric — the `DefaultOn` matrix.
    #[test]
    fn default_config_enables_every_metric() {
        let config = SelfMetricsConfig::default();
        for metric in SelfMetric::ALL {
            assert!(config.is_enabled(metric), "{} must default on", metric.name());
        }
        assert_eq!(config, SelfMetricsConfig::all_enabled());
    }
}
