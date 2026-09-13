//! End-to-end PSL query tests over the REAL [`LiveObservabilitySubstrate`]
//! producer→store→query path (the same surface the portal serves), not the
//! `psl` unit internals. Every signal here is written through the genuine
//! producer wire format (`level=<l> msg=<m> @<tick>` / `<name> <value> @<tick>`)
//! so these tests exercise the exact production payloads — the divergence that
//! previously let the psl unit tests pass while the live query surface returned
//! mis-ordered, unfiltered, or value-less results.
//!
//! Regression coverage for six query bugs:
//!  1. logs returned in content-hash order instead of chronological order;
//!  3. metric `sum`/`topk`/`quantile` reading `@<tick>` as the value (→ 0/NaN);
//!  4. `message = <exact>` never matching because the stored `msg` field still
//!     carried the trailing ` @<tick>` marker;
//!  5. a quoted predicate value containing a comma being fractured;
//!  6. a clause keyword (`range:`/`correlate:`/`where:`) inside a quoted value
//!     misrouting the parse.
//!
//! Bug 2 (the producer stamping a per-sample counter instead of real seconds)
//! lives in `pillar-cli`'s run loop; here we drive ticks as real seconds and
//! prove the range filter genuinely limits the window on the public path.

use pillar_observability::psl::Aggregate;
use pillar_observability::{
    parse_psl, LabelSet, LiveObservabilitySubstrate, LogLevel, NodeCounters, NodeMetadataSource,
    SignalKind,
};

fn substrate() -> LiveObservabilitySubstrate {
    let mut node_labels = LabelSet::new();
    node_labels.insert("node".to_string(), "n-itest".to_string());
    let counters = NodeCounters::new();
    let metadata_source = NodeMetadataSource::new(
        "n-itest",
        Some("cell-itest".to_string()),
        std::iter::once("n-itest".to_string()),
        "0.0.0",
        None,
    );
    LiveObservabilitySubstrate::new(node_labels, counters, metadata_source, 256, 1_000_000)
}

/// Bug 1: logs written out of chronological order come back oldest-first from
/// the live `psl_query` path, NOT in content-hash order.
#[test]
fn logs_query_returns_chronological_order() {
    let mut sub = substrate();
    // Write in a deliberately scrambled tick order.
    sub.record_log(LogLevel::Info, "event-c", "itest", 300);
    sub.record_log(LogLevel::Info, "event-a", "itest", 100);
    sub.record_log(LogLevel::Info, "event-e", "itest", 500);
    sub.record_log(LogLevel::Info, "event-b", "itest", 200);
    sub.record_log(LogLevel::Info, "event-d", "itest", 400);

    let query = parse_psl("select: logs range: now-1000s").expect("parses");
    let recs = sub.psl_query(&query, sub.latest_tick());

    let ticks: Vec<u64> = recs.iter().map(|r| r.tick).collect();
    assert_eq!(
        ticks,
        vec![100, 200, 300, 400, 500],
        "records must be oldest-first, got {ticks:?}"
    );
}

/// Bug 2 (range genuinely limits on the public path): with a seconds tick axis,
/// `range: now-100s` excludes an old signal and includes recent ones.
#[test]
fn range_clause_limits_the_query_window() {
    let mut sub = substrate();
    sub.record_log(LogLevel::Info, "ancient", "itest", 1);
    sub.record_log(LogLevel::Info, "recent-1", "itest", 950);
    sub.record_log(LogLevel::Info, "recent-2", "itest", 1000);

    let now = sub.latest_tick();
    assert_eq!(now, 1000);

    let query = parse_psl("select: logs range: now-100s").expect("parses");
    let msgs: Vec<String> = sub
        .psl_query(&query, now)
        .into_iter()
        .map(|r| r.payload)
        .collect();

    assert_eq!(msgs.len(), 2, "only the in-window logs, got {msgs:?}");
    assert!(msgs.iter().all(|m| !m.contains("ancient")), "old excluded");
    assert!(msgs.iter().any(|m| m.contains("recent-1")));
    assert!(msgs.iter().any(|m| m.contains("recent-2")));
}

/// Bug 4: `message = <exact>` (Eq) matches a real log despite the producer's
/// trailing ` @<tick>` marker on the payload.
#[test]
fn message_equality_matches_real_payload_with_tick_marker() {
    let mut sub = substrate();
    sub.record_log(LogLevel::Info, "served", "itest", 10);
    sub.record_log(LogLevel::Info, "dropped", "itest", 11);

    // Sanity: the stored payload really does carry the ` @<tick>` marker.
    let served_payload = sub
        .explore(SignalKind::Log)
        .into_iter()
        .find(|r| r.payload.contains("msg=served"))
        .expect("served log held")
        .payload;
    assert!(
        served_payload.ends_with("@10"),
        "producer payload carries the tick marker: {served_payload}"
    );

    let query = parse_psl("select: logs(message = served) range: now-1000s").expect("parses");
    let recs = sub.psl_query(&query, sub.latest_tick());
    assert_eq!(recs.len(), 1, "exactly the exact-message log matches");
    assert!(recs[0].payload.contains("msg=served"));
}

/// Bug 3: metric value aggregation (`sum`/`topk`) reads the real numeric value
/// out of the `<name> <value> @<tick>` payload, not the `@<tick>` marker.
#[test]
fn metric_aggregation_reads_real_values_not_the_tick_marker() {
    use pillar_observability::{MetricDescriptor, MetricType};

    let mut sub = substrate();
    assert!(sub.register_metric(MetricDescriptor::new(
        "latency_ms",
        MetricType::Gauge,
        "ms",
        "itest",
    )));
    let extra = LabelSet::new();
    sub.emit_metric("latency_ms", 10.0, &extra, 100);
    sub.emit_metric("latency_ms", 30.0, &extra, 200);
    sub.emit_metric("latency_ms", 20.0, &extra, 300);

    let now = sub.latest_tick();
    let query = parse_psl("select: metrics(metric = latency_ms) range: now-1000s").expect("parses");

    let sum = sub.aggregate(&query, now, Aggregate::Sum, &[]);
    assert!(
        (sum[0].values[0] - 60.0).abs() < 1e-9,
        "sum of real values, got {:?}",
        sum[0].values
    );
    let topk = sub.aggregate(&query, now, Aggregate::TopK(2), &[]);
    assert_eq!(topk[0].values, vec![30.0, 20.0], "top-2 real values descending");
}

/// Bugs 5 & 6: a query whose quoted match value contains BOTH a comma and the
/// clause keywords parses as one predicate and runs correctly over the live
/// path — the quoted content never fractures the parse.
#[test]
fn quoted_value_with_comma_and_keywords_parses_and_queries() {
    let mut sub = substrate();
    // A log whose message literally contains a comma and a `range:` token.
    sub.record_log(LogLevel::Error, "scan range: prod, region eu", "itest", 50);
    sub.record_log(LogLevel::Error, "unrelated failure", "itest", 51);

    let query = parse_psl(
        r#"select: logs(level = error, message =~ "range: prod, region eu") range: now-1000s"#,
    )
    .expect("the quoted comma + keyword value must not misroute the parse");

    let recs = sub.psl_query(&query, sub.latest_tick());
    assert_eq!(recs.len(), 1, "only the matching log, got {recs:?}");
    assert!(recs[0].payload.contains("range: prod, region eu"));
}
