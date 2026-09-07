//! RecordingRule — a scheduled, PSL-defined signal-to-metric aggregation.
//!
//! A [`RecordingRule`] generalizes the earlier metrics-only `psl-recording-rules`
//! gate to EVERY signal kind where a periodic roll-up makes sense. It bundles
//! three things into one built-in resource:
//!
//!   1. a **schedule** — the rule fires as an ordinary `Observability` job on the
//!      shared [`pillar_manifest::scheduler::Scheduler`] engine (the
//!      `scheduler-controller-impl` engine), through the identical
//!      `fire`/`succeed`/`fail` code path a CronJob workload uses; there is NO
//!      second dispatcher for observability jobs.
//!   2. a **PSL query + numeric aggregate** — the expensive scan over the raw
//!      source signals runs via [`crate::psl::aggregate`] (the
//!      `psl-numeric-ops` aggregation), producing one derived value per `by`
//!      group.
//!   3. an **emit** — each group's value is written back as a fast, label-indexed
//!      derived `Metric` signal, so a later reader queries the pre-computed
//!      series with NO re-scan of the raw source.
//!
//! ## The five cross-kind mappings ([`RuleKind`])
//!
//! Every mapping is `<source-kind> -> metrics`. The source select-kind and the
//! aggregate differ; the emit is always a derived `Metric`:
//!
//!   - **logs -> metrics** — count / rate of matched log lines
//!     ([`RuleKind::LogsToMetrics`]).
//!   - **traces -> metrics** — span-latency quantiles / error rate
//!     ([`RuleKind::TracesToMetrics`]).
//!   - **profiles -> metrics** — hot-frame sample counts
//!     ([`RuleKind::ProfilesToMetrics`]).
//!   - **metadata -> metrics** — entity-count over labels
//!     ([`RuleKind::MetadataToMetrics`]).
//!   - **metrics -> metrics** — downsample / rollup of an existing series
//!     ([`RuleKind::MetricsToMetrics`]).
//!
//! The rule carries no per-kind branch in its evaluation: the source kind is a
//! field of the PSL `select`, and the aggregate is a field of the rule. One
//! [`RecordingRule::evaluate`] path serves all five.

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::CorrelationIndex;
use crate::metadata::LabelSet;
use crate::psl::{aggregate, Aggregate, PslQuery};
use pillar_manifest::scheduler::{
    ConcurrencyPolicy, FireError, FireOutcome, Job, JobKind, Scheduler,
};

/// The label a derived signal carries naming the rule that produced it, so a
/// reader can select exactly one rule's output series.
pub const DERIVED_RULE_LABEL: &str = "__recording_rule";
/// The label a derived signal carries naming the aggregate metric, matching the
/// rule's `emit` name.
pub const DERIVED_NAME_LABEL: &str = "name";

/// Which cross-kind roll-up a [`RecordingRule`] performs. This is descriptive
/// (it names the ROI mapping and fixes the expected source kind); the actual
/// scan is driven by the rule's PSL query and [`Aggregate`], not a per-kind
/// branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    /// logs -> metrics: count / rate of matched log lines.
    LogsToMetrics,
    /// traces -> metrics: span-latency quantile / error rate.
    TracesToMetrics,
    /// profiles -> metrics: hot-frame sample counts.
    ProfilesToMetrics,
    /// metadata -> metrics: entity-count over labels.
    MetadataToMetrics,
    /// metrics -> metrics: downsample / rollup of an existing series.
    MetricsToMetrics,
}

impl RuleKind {
    /// The source [`SignalKind`] this mapping scans. The rule's PSL query MUST
    /// select this kind (enforced by [`RecordingRule::new`]).
    #[must_use]
    pub fn source_kind(self) -> SignalKind {
        match self {
            RuleKind::LogsToMetrics => SignalKind::Log,
            RuleKind::TracesToMetrics => SignalKind::TraceSpan,
            RuleKind::ProfilesToMetrics => SignalKind::ProfileSample,
            RuleKind::MetadataToMetrics => SignalKind::MetadataSample,
            RuleKind::MetricsToMetrics => SignalKind::Metric,
        }
    }
}

/// Why constructing a [`RecordingRule`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// The PSL query does not select the source kind the [`RuleKind`] requires
    /// (e.g. a `LogsToMetrics` rule whose query selects only metrics).
    SourceKindMismatch {
        /// The kind the rule's mapping requires.
        required: SignalKind,
        /// The kind(s) the query actually selects.
        selected: Vec<SignalKind>,
    },
    /// The rule's emit (derived metric) name is empty.
    EmptyEmitName,
}

/// A scheduled signal-to-metric aggregation resource.
#[derive(Clone, Debug)]
pub struct RecordingRule {
    id: String,
    kind: RuleKind,
    query: PslQuery,
    aggregate: Aggregate,
    by: Vec<String>,
    emit_name: String,
    required_tier: String,
}

impl RecordingRule {
    /// Build a rule. Rejects a query whose selects do not include the mapping's
    /// source kind, and an empty emit name.
    pub fn new(
        id: impl Into<String>,
        kind: RuleKind,
        query: PslQuery,
        aggregate: Aggregate,
        by: Vec<String>,
        emit_name: impl Into<String>,
        required_tier: impl Into<String>,
    ) -> Result<RecordingRule, RuleError> {
        let emit_name = emit_name.into();
        if emit_name.is_empty() {
            return Err(RuleError::EmptyEmitName);
        }
        let selected: Vec<SignalKind> = query.selects.iter().map(|s| s.kind).collect();
        if !selected.contains(&kind.source_kind()) {
            return Err(RuleError::SourceKindMismatch {
                required: kind.source_kind(),
                selected,
            });
        }
        Ok(RecordingRule {
            id: id.into(),
            kind,
            query,
            aggregate,
            by,
            emit_name,
            required_tier: required_tier.into(),
        })
    }

    /// The rule's stable id (also its scheduler job id).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The cross-kind mapping this rule performs.
    #[must_use]
    pub fn kind(&self) -> RuleKind {
        self.kind
    }

    /// The derived metric name this rule emits.
    #[must_use]
    pub fn emit_name(&self) -> &str {
        &self.emit_name
    }

    /// The scheduler [`Job`] for this rule — an `Observability`-kind job that
    /// rides the shared scheduling engine. `Forbid` concurrency: a rule never
    /// evaluates concurrently with itself (a second scan while one is in flight
    /// is skipped), so its derived series is never double-written for one tick.
    #[must_use]
    fn job(&self) -> Job {
        Job::new(
            JobKind::Observability,
            ConcurrencyPolicy::Forbid,
            self.required_tier.clone(),
            3,
            5,
        )
    }
}

/// The IDs of the derived signals [`RecordingEngine::evaluate`] emitted for one
/// firing, plus how many source signals the scan matched. Empty `emitted` with
/// a skipped fire means the schedule was not due (concurrency-forbidden).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// The derived `Metric` signal ids written this evaluation, one per group.
    pub emitted: Vec<SignalId>,
    /// Whether the schedule actually fired (vs. skipped by concurrency policy).
    pub fired: bool,
}

/// Drives a set of [`RecordingRule`]s on the shared scheduler engine.
///
/// The engine owns exactly one [`Scheduler`] — the same one that dispatches
/// workload CronJobs — and registers each rule as a job on it. [`evaluate`]
/// fires the rule's schedule, runs its aggregate over the SOURCE store, emits
/// the derived metrics into the TARGET store, then terminates the run. The
/// derived series lives in the target store as ordinary label-indexed `Metric`
/// signals, so [`query_derived`] reads it with no re-scan of the source.
///
/// [`evaluate`]: RecordingEngine::evaluate
/// [`query_derived`]: RecordingEngine::query_derived
pub struct RecordingEngine {
    scheduler: Scheduler,
    rules: std::collections::BTreeMap<String, RecordingRule>,
}

impl RecordingEngine {
    /// A fresh engine over the given scheduler.
    #[must_use]
    pub fn new(scheduler: Scheduler) -> RecordingEngine {
        RecordingEngine {
            scheduler,
            rules: std::collections::BTreeMap::new(),
        }
    }

    /// Register a rule, installing its job on the shared scheduler.
    pub fn register(&mut self, rule: RecordingRule) {
        self.scheduler.register(rule.id.clone(), rule.job());
        self.rules.insert(rule.id.clone(), rule);
    }

    /// Read-only view of the underlying scheduler (to inspect run history).
    #[must_use]
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Fire rule `id`'s schedule at logical time `now` and, if it fired, run its
    /// aggregate over `source`/`index` and emit the derived metrics into
    /// `target`. Placement `tier` must be admissible for the rule's job.
    ///
    /// The whole scan/emit runs INSIDE one scheduler run: `fire` opens the run,
    /// the aggregate + emit is the run's body, and `succeed` closes it. So a
    /// rule that is concurrency-skipped (a prior run still in flight) neither
    /// scans nor emits — its `Evaluation` reports `fired = false`.
    pub fn evaluate(
        &mut self,
        id: &str,
        tier: &str,
        now: u64,
        source: &TimeseriesStore,
        index: &CorrelationIndex,
        target: &mut TimeseriesStore,
    ) -> Result<Evaluation, FireError> {
        let rule = self
            .rules
            .get(id)
            .ok_or_else(|| FireError::UnknownJob(id.to_owned()))?
            .clone();

        match self.scheduler.fire(id, tier)? {
            FireOutcome::Skipped => {
                return Ok(Evaluation {
                    emitted: Vec::new(),
                    fired: false,
                })
            }
            FireOutcome::Fired => {}
        }

        // Run body: the expensive scan runs exactly once here, on the schedule.
        let rows = aggregate(
            &rule.query,
            source,
            index,
            now,
            rule.aggregate,
            &rule.by,
        );

        let mut emitted = Vec::new();
        for row in rows {
            // TopK yields several values; every other aggregate yields one.
            // Emit one derived point per produced value, tagging its rank when
            // more than one exists so distinct values do not content-address
            // to the same id.
            for (rank, value) in row.values.iter().enumerate() {
                let mut labels: LabelSet = LabelSet::new();
                labels.insert(DERIVED_RULE_LABEL.to_string(), rule.id.clone());
                labels.insert(DERIVED_NAME_LABEL.to_string(), rule.emit_name.clone());
                for (k, v) in &row.group {
                    labels.insert(k.clone(), v.clone());
                }
                if row.values.len() > 1 {
                    labels.insert("__rank".to_string(), rank.to_string());
                }
                // The payload's trailing token is the numeric value, so a later
                // aggregate over the DERIVED series reads it back via the same
                // `signal_value` path.
                let payload = format!("{} {}", rule.emit_name, value);
                if let Some(sid) =
                    target.write_labeled(SignalKind::Metric, payload.into_bytes(), labels, now)
                {
                    emitted.push(sid);
                }
            }
        }

        // Close the run successfully — the derived series is now materialized.
        let _ = self.scheduler.succeed(id);

        Ok(Evaluation {
            emitted,
            fired: true,
        })
    }

    /// Query the derived series a rule emitted, WITHOUT re-scanning the raw
    /// source. This reads only the label-indexed derived `Metric` signals in
    /// `target` tagged with the rule's id — the pre-computed values, never the
    /// original logs/traces/profiles/metadata/metrics the rule aggregated.
    ///
    /// Returns each derived point's numeric value in ascending group order.
    #[must_use]
    pub fn query_derived(&self, rule_id: &str, target: &TimeseriesStore) -> Vec<f64> {
        let mut out: Vec<(Vec<(String, String)>, f64)> = Vec::new();
        for signal in target.held_signals() {
            if signal.kind() != SignalKind::Metric {
                continue;
            }
            match signal.labels().get(DERIVED_RULE_LABEL) {
                Some(r) if r == rule_id => {}
                _ => continue,
            }
            let Some(v) = std::str::from_utf8(signal.payload())
                .ok()
                .and_then(|t| t.split_whitespace().last().map(|s| s.to_owned()))
                .and_then(|s| s.parse::<f64>().ok())
            else {
                continue;
            };
            // Sort key: the group labels (excluding the internal marker labels),
            // then rank, so output is deterministic regardless of write order.
            let mut key: Vec<(String, String)> = signal
                .labels()
                .iter()
                .filter(|(k, _)| {
                    k.as_str() != DERIVED_RULE_LABEL && k.as_str() != DERIVED_NAME_LABEL
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            key.sort();
            out.push((key, v));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.into_iter().map(|(_, v)| v).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psl::{Predicate, PslQueryBuilder};

    /// The eight-tier default hierarchy the scheduler ranks placement against.
    fn engine() -> RecordingEngine {
        RecordingEngine::new(Scheduler::new(pillar_topology::TierHierarchy::default()))
    }

    /// Build a source store + a matching index. Signals are written at tick
    /// `now-1` so they fall inside a `now-<range>` window.
    fn source_store() -> (TimeseriesStore, CorrelationIndex) {
        (TimeseriesStore::new(64, 1_000_000), CorrelationIndex::new())
    }

    fn labels(pairs: &[(&str, &str)]) -> LabelSet {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A rule whose PSL query selects the wrong kind is refused at construction.
    #[test]
    fn a_rule_whose_query_selects_the_wrong_source_kind_is_refused() {
        let q = PslQueryBuilder::new()
            .select(SignalKind::Metric, vec![])
            .range_relative(3600)
            .build()
            .unwrap();
        let err = RecordingRule::new(
            "bad",
            RuleKind::LogsToMetrics,
            q,
            Aggregate::Count,
            vec![],
            "derived",
            "node",
        )
        .unwrap_err();
        assert_eq!(
            err,
            RuleError::SourceKindMismatch {
                required: SignalKind::Log,
                selected: vec![SignalKind::Metric],
            }
        );
    }

    /// logs -> metrics: a scheduled rule counts matched log lines and emits a
    /// derived metric; the derived signal is queryable with no re-scan.
    #[test]
    fn logs_to_metrics_counts_lines_on_schedule_and_is_queryable() {
        let (mut source, index) = source_store();
        source
            .write_labeled(SignalKind::Log, b"level=error a".to_vec(), labels(&[("level", "error")]), 999)
            .unwrap();
        source
            .write_labeled(SignalKind::Log, b"level=error b".to_vec(), labels(&[("level", "error")]), 999)
            .unwrap();
        source
            .write_labeled(SignalKind::Log, b"level=info c".to_vec(), labels(&[("level", "info")]), 999)
            .unwrap();

        let q = PslQueryBuilder::new()
            .select(SignalKind::Log, vec![Predicate::eq("level", "error")])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "err_count",
            RuleKind::LogsToMetrics,
            q,
            Aggregate::Count,
            vec![],
            "log_error_count",
            "node",
        )
        .unwrap();

        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        let eval = eng
            .evaluate("err_count", "node", 1000, &source, &index, &mut target)
            .unwrap();
        assert!(eval.fired);
        assert_eq!(eval.emitted.len(), 1);

        // Two error lines were counted; the derived value is 2, read back with
        // no re-scan of the source logs.
        assert_eq!(eng.query_derived("err_count", &target), vec![2.0]);
    }

    /// traces -> metrics: span-latency quantile over matched spans.
    #[test]
    fn traces_to_metrics_computes_a_latency_quantile() {
        let (mut source, index) = source_store();
        for latency in [10u32, 20, 30, 40] {
            source
                .write_labeled(
                    SignalKind::TraceSpan,
                    format!("span svc=api {latency}").into_bytes(),
                    labels(&[("svc", "api")]),
                    999,
                )
                .unwrap();
        }

        let q = PslQueryBuilder::new()
            .select(SignalKind::TraceSpan, vec![Predicate::eq("svc", "api")])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "p95",
            RuleKind::TracesToMetrics,
            q,
            Aggregate::Quantile(0.75),
            vec![],
            "span_latency_q",
            "node",
        )
        .unwrap();

        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("p95", "node", 1000, &source, &index, &mut target)
            .unwrap();
        // Nearest-rank q=0.75 over [10,20,30,40]: rank=ceil(0.75*4)=3 -> 30.
        assert_eq!(eng.query_derived("p95", &target), vec![30.0]);
    }

    /// profiles -> metrics: hot-frame sample counts, grouped by frame label.
    #[test]
    fn profiles_to_metrics_counts_hot_frames_by_group() {
        let (mut source, index) = source_store();
        for (i, frame) in ["parse", "parse", "parse", "encode"].iter().enumerate() {
            source
                .write_labeled(
                    SignalKind::ProfileSample,
                    format!("sample {i} frame={frame} 1").into_bytes(),
                    labels(&[("frame", frame)]),
                    999,
                )
                .unwrap();
        }

        let q = PslQueryBuilder::new()
            .select(SignalKind::ProfileSample, vec![])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "hot_frames",
            RuleKind::ProfilesToMetrics,
            q,
            Aggregate::Count,
            vec!["frame".to_string()],
            "profile_frame_count",
            "node",
        )
        .unwrap();

        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("hot_frames", "node", 1000, &source, &index, &mut target)
            .unwrap();
        // Groups sort by label: encode=1, parse=3.
        assert_eq!(
            eng.query_derived("hot_frames", &target),
            vec![1.0, 3.0]
        );
    }

    /// metadata -> metrics: entity-count over a label dimension.
    #[test]
    fn metadata_to_metrics_counts_entities_over_labels() {
        let (mut source, index) = source_store();
        for (tenant, n) in [("t1", 2), ("t2", 1)] {
            for i in 0..n {
                source
                    .write_labeled(
                        SignalKind::MetadataSample,
                        format!("entity {tenant}-{i} 1").into_bytes(),
                        labels(&[("tenant", tenant)]),
                        999,
                    )
                    .unwrap();
            }
        }

        let q = PslQueryBuilder::new()
            .select(SignalKind::MetadataSample, vec![])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "entity_count",
            RuleKind::MetadataToMetrics,
            q,
            Aggregate::Count,
            vec!["tenant".to_string()],
            "metadata_entity_count",
            "node",
        )
        .unwrap();

        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("entity_count", "node", 1000, &source, &index, &mut target)
            .unwrap();
        // t1=2, t2=1, in ascending group order.
        assert_eq!(
            eng.query_derived("entity_count", &target),
            vec![2.0, 1.0]
        );
    }

    /// metrics -> metrics: sum-rollup of an existing series into a coarser one.
    #[test]
    fn metrics_to_metrics_rolls_up_an_existing_series() {
        let (mut source, index) = source_store();
        for v in [5u32, 7, 3] {
            source
                .write_labeled(
                    SignalKind::Metric,
                    format!("bytes {v}").into_bytes(),
                    labels(&[("name", "bytes")]),
                    999,
                )
                .unwrap();
        }

        let q = PslQueryBuilder::new()
            .select(SignalKind::Metric, vec![Predicate::eq("name", "bytes")])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "bytes_total",
            RuleKind::MetricsToMetrics,
            q,
            Aggregate::Sum,
            vec![],
            "bytes_rollup",
            "node",
        )
        .unwrap();

        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("bytes_total", "node", 1000, &source, &index, &mut target)
            .unwrap();
        // 5+7+3 = 15.
        assert_eq!(eng.query_derived("bytes_total", &target), vec![15.0]);
    }

    /// The derived series lives in the TARGET store as ordinary metrics, so
    /// querying it never touches the source: emptying the source after
    /// evaluation leaves the derived answer intact.
    #[test]
    fn derived_query_does_not_rescan_the_source() {
        let (mut source, index) = source_store();
        source
            .write_labeled(SignalKind::Log, b"x 1".to_vec(), LabelSet::new(), 999)
            .unwrap();
        let q = PslQueryBuilder::new()
            .select(SignalKind::Log, vec![])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "c",
            RuleKind::LogsToMetrics,
            q,
            Aggregate::Count,
            vec![],
            "c",
            "node",
        )
        .unwrap();
        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("c", "node", 1000, &source, &index, &mut target)
            .unwrap();

        // Drop the source entirely; the derived series is self-contained.
        let empty = TimeseriesStore::new(64, 1_000_000);
        drop(source);
        let _ = empty;
        assert_eq!(eng.query_derived("c", &target), vec![1.0]);
    }

    /// The rule rides the SHARED scheduler: its evaluation is one run on the
    /// same engine a workload uses, recorded in run history.
    #[test]
    fn evaluation_is_one_run_on_the_shared_scheduler() {
        let (source, index) = source_store();
        let q = PslQueryBuilder::new()
            .select(SignalKind::Log, vec![])
            .range_relative(3600)
            .build()
            .unwrap();
        let rule = RecordingRule::new(
            "r",
            RuleKind::LogsToMetrics,
            q,
            Aggregate::Count,
            vec![],
            "r",
            "node",
        )
        .unwrap();
        let mut eng = engine();
        eng.register(rule);
        let mut target = TimeseriesStore::new(64, 1_000_000);
        eng.evaluate("r", "node", 1000, &source, &index, &mut target)
            .unwrap();
        // One terminal run recorded on the shared scheduler for this rule.
        assert_eq!(eng.scheduler().terminal_count("r"), 1);
        assert_eq!(eng.scheduler().runs()[0].kind, JobKind::Observability);
    }
}
