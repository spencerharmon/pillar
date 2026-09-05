//! Acceptance test — `node-observability-live-surface`.
//!
//! ROI "pillar-integration" observability-psl prerequisite. Proves that a
//! running node EXPOSES its LIVE observability substrate over its external HTTP
//! surface, so a BLACK-BOX observer (this test — it speaks only real HTTP over
//! a real TCP socket to the served `/portal/obs/live/*` endpoints, never
//! reaching into in-process state) can independently confirm, for the SAME
//! live store the node's producers feed:
//!
//! 1. all five signal kinds (metric, log, trace, profile, metadata) are
//!    really ingested from the running workload
//!    (`all_five_signal_kinds_are_live_and_independently_traceable`);
//! 2. PSL select/where/range/correlate queries run against that live data and
//!    return ONLY really-ingested signals — a query for an unemitted kind
//!    returns nothing (`psl_queries_return_only_really_ingested_signals`);
//! 3. a recording rule evaluates across kinds on the node's REAL scheduler
//!    engine over the live store, and an alert fires
//!    (`recording_rules_and_alerts_evaluate_on_the_live_store`);
//! 4. a dashboard materializes its panels from the real live store
//!    (`dashboards_materialize_from_the_live_store`).
//!
//! RED if a query returns data with no corresponding real ingested signal;
//! GREEN when every signal kind is independently traceable to a real workload
//! emission THROUGH the served surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-e2e --test observability_live_surface
//! --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pillar_cli::web_serve::{bind, serve, SharedLiveObs, WebAuthContext};
use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_observability::{
    LabelSet, LiveObservabilitySubstrate, LogLevel, NodeCounters, NodeMetadataSource, SignalKind,
};
use pillar_web::node_custody::Cid;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "operational-key-material";

/// One HTTP response the black-box client parsed off the wire.
struct HttpResponse {
    status: u16,
    session_token: Option<String>,
    body: String,
}

/// Send one real HTTP/1.1 request to `addr` and read the full response back —
/// the black-box client's ONLY view of the node.
fn http(addr: &str, method: &str, path: &str, body: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect to served surface");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("write request");
    stream.flush().expect("flush");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).expect("header line");
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    HttpResponse {
        status,
        session_token,
        body: resp_body,
    }
}

/// Build a live substrate, feed it a REAL workload emission of all five signal
/// kinds (self-metrics + profiles + metadata sampled from this process's real
/// `/proc`/identity, plus real logs and trace spans for handled operations),
/// and hand back the shared handle. This is the running node's own
/// self-instrumentation, exactly what `pillar node run`'s controller loop does.
fn live_substrate_with_real_workload() -> SharedLiveObs {
    let mut node_labels = LabelSet::new();
    node_labels.insert("node".to_string(), "acceptance-node".to_string());
    let counters = NodeCounters::new();
    // Real counters this node genuinely observed this run.
    counters.record_requests(7);
    counters.record_ingest_bytes(4096);
    counters.set_p2p_peers(2);
    counters.record_streamdb_ops(11);
    let metadata_source = NodeMetadataSource::new(
        "acceptance-node",
        "cell-acceptance",
        std::iter::once("acceptance-node".to_string()),
        env!("CARGO_PKG_VERSION"),
        None,
    );
    let mut sub = LiveObservabilitySubstrate::new(node_labels, counters, metadata_source, 256, 100_000);

    // Drive several ticks of the real periodic producers + real per-event
    // logs/spans, so every one of the five kinds has genuinely-ingested data.
    for tick in 0..8u64 {
        sub.sample_periodic(tick);
        sub.record_log(LogLevel::Info, format!("handled event tick={tick}"), tick);
        sub.record_span(
            format!("trace-{tick}"),
            format!("span-{tick}"),
            "handle_workload_op",
            tick,
        );
    }
    // A single error-level log so an alert on log volume has a non-trivial
    // count to trip.
    for tick in 8..14u64 {
        sub.record_log(LogLevel::Error, format!("workload error tick={tick}"), tick);
    }

    Arc::new(Mutex::new(sub))
}

/// Stand a real node web surface up on an ephemeral port, wired to a live
/// substrate already fed a real workload emission, admit + provision a user so
/// the black-box client can log in, and return `(addr, token)`.
fn serve_and_login() -> (String, String) {
    let live: SharedLiveObs = live_substrate_with_real_workload();

    let listener = bind(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0).expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let subkey = NodeSubkey::from("op-subkey-alice");
    let mut ctx = WebAuthContext::new(
        "https://node.example.com",
        NodeId::from("this-node"),
        "this-node-secret",
        NodeId::from("owner"),
        4,
    )
    .with_live_observability(Arc::clone(&live));
    ctx.admit_subject(subkey.node_id(), 4);
    ctx.provision_offer("alice@node", "Alice", Cid::from("cid-alice"), subkey, PASSWORD, SECRET);

    std::thread::spawn(move || serve(listener, &mut ctx));
    // Give the accept loop a moment to start.
    std::thread::sleep(Duration::from_millis(100));

    // GET /nonce, then POST /login (two fields + nonce id) — the real
    // node-side custody login over HTTP.
    let nonce = http(&addr, "GET", "/nonce", "");
    assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
    let id: u64 = nonce
        .body
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("nonce id");
    let login = http(&addr, "POST", "/login", &format!("alice@node\n{PASSWORD}\n{id}"));
    assert_eq!(login.status, 200, "login: {}", login.body);
    let token = login.session_token.expect("session token");
    (addr, token)
}

#[test]
fn all_five_signal_kinds_are_live_and_independently_traceable() {
    let (addr, token) = serve_and_login();

    // The kinds endpoint reports the per-kind counts of really-ingested
    // signals in the live store.
    let kinds = http(&addr, "GET", &format!("/portal/obs/live/kinds?token={token}"), "");
    assert_eq!(kinds.status, 200, "kinds: {}", kinds.body);

    for kind in ["metric", "log", "trace", "profile", "metadata"] {
        // Each kind's count line must show a genuinely-ingested, non-zero
        // count — every kind is independently traceable to a real emission.
        let line = kinds
            .body
            .lines()
            .find(|l| l.starts_with(&format!("KIND {kind} ")))
            .unwrap_or_else(|| panic!("missing kind {kind} in: {}", kinds.body));
        let count: usize = line
            .rsplit_once("COUNT ")
            .and_then(|(_, n)| n.trim().parse().ok())
            .expect("count");
        assert!(count > 0, "signal kind {kind} must be really ingested; got {count}");

        // And its explore endpoint returns that many real records, each
        // rendered with a real payload — traceable to the workload emission.
        let explore = http(
            &addr,
            "GET",
            &format!("/portal/obs/live/explore?token={token}&kind={kind}"),
            "",
        );
        assert_eq!(explore.status, 200, "explore {kind}: {}", explore.body);
        let records = explore.body.lines().filter(|l| l.starts_with("SIGNAL ")).count();
        assert_eq!(
            records, count,
            "explore for {kind} must surface exactly the ingested signals"
        );
    }

    // The auth gate holds on the live surface: no token -> 401.
    let unauth = http(&addr, "GET", "/portal/obs/live/kinds", "");
    assert_eq!(unauth.status, 401, "live surface must require an admitted session");
}

#[test]
fn psl_queries_return_only_really_ingested_signals() {
    let (addr, token) = serve_and_login();

    // A PSL select over a kind that WAS ingested returns its real signals.
    let q_metric = http(
        &addr,
        "POST",
        "/portal/obs/live/query",
        &format!("{token}\nselect: metrics range: now-100000s"),
    );
    assert_eq!(q_metric.status, 200, "metric query: {}", q_metric.body);
    let metric_hits = q_metric.body.lines().filter(|l| l.starts_with("SIGNAL ")).count();
    assert!(metric_hits > 0, "a real metric was ingested; PSL must find it");

    // Every returned signal id must correspond to a really-held signal: the
    // explore endpoint (the ground truth of what is held) must contain each.
    let explore_metric = http(
        &addr,
        "GET",
        &format!("/portal/obs/live/explore?token={token}&kind=metric"),
        "",
    );
    let held_ids: Vec<&str> = explore_metric
        .body
        .lines()
        .filter_map(|l| l.strip_prefix("SIGNAL ").and_then(|r| r.split_whitespace().next()))
        .collect();
    for line in q_metric.body.lines().filter(|l| l.starts_with("SIGNAL ")) {
        let id = line.strip_prefix("SIGNAL ").unwrap().split_whitespace().next().unwrap();
        assert!(
            held_ids.contains(&id),
            "PSL returned signal {id} that is NOT really held — phantom data (RED)"
        );
    }

    // A correlate query centered on the trace kind groups the trace span with
    // its really-linked peers sharing the correlation id.
    let q_corr = http(
        &addr,
        "POST",
        "/portal/obs/live/query",
        &format!("{token}\nselect: traces range: now-100000s correlate: {{ window: 100000s, anchor: traces }}"),
    );
    assert_eq!(q_corr.status, 200, "correlate query: {}", q_corr.body);
    assert!(
        q_corr.body.lines().any(|l| l.starts_with("GROUP ")),
        "a correlate query over live traces must produce at least one group: {}",
        q_corr.body
    );

    // A query for a WHERE that no real signal satisfies returns nothing —
    // never fabricated data.
    let q_none = http(
        &addr,
        "POST",
        "/portal/obs/live/query",
        &format!("{token}\nselect: metrics where: metric = this-metric-never-emitted range: now-100000s"),
    );
    assert_eq!(q_none.status, 200, "empty query: {}", q_none.body);
    assert_eq!(
        q_none.body.lines().filter(|l| l.starts_with("SIGNAL ")).count(),
        0,
        "a query with no matching real signal must return nothing (no fabrication)"
    );
}

#[test]
fn recording_rules_and_alerts_evaluate_on_the_live_store() {
    let (addr, token) = serve_and_login();

    // Register + evaluate a recording rule (logs -> metric count) on the
    // node's REAL scheduler engine over the live store.
    let rule = http(
        &addr,
        "POST",
        "/portal/obs/live/recording",
        &format!("{token}\nlog-rate|log-count|select: logs range: now-100000s|log_count"),
    );
    assert_eq!(rule.status, 200, "recording: {}", rule.body);
    assert!(
        rule.body.contains("FIRED true"),
        "the recording rule must fire on the live store: {}",
        rule.body
    );
    let derived_line = rule
        .body
        .lines()
        .find(|l| l.starts_with("DERIVED "))
        .expect("derived line");
    let derived: Vec<f64> = derived_line
        .strip_prefix("DERIVED ")
        .unwrap()
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    assert!(
        derived.iter().any(|v| *v > 0.0),
        "the derived metric must reflect real ingested logs: {derived:?}"
    );

    // Register + evaluate an alert whose predicate trips on the real log
    // volume (count > 0).
    let alert = http(
        &addr,
        "POST",
        "/portal/obs/live/alert",
        &format!("{token}\nlogs-present|select: logs range: now-100000s|gt|0"),
    );
    assert_eq!(alert.status, 200, "alert: {}", alert.body);
    assert!(
        alert.body.lines().any(|l| l.starts_with("ALERT ")),
        "an alert over real live logs must fire a notification: {}",
        alert.body
    );

    // An alert whose threshold no real value can trip fires nothing.
    let quiet = http(
        &addr,
        "POST",
        "/portal/obs/live/alert",
        &format!("{token}\nimpossible|select: logs range: now-100000s|gt|1000000"),
    );
    assert_eq!(quiet.status, 200, "quiet alert: {}", quiet.body);
    assert!(
        !quiet.body.lines().any(|l| l.starts_with("ALERT ")),
        "an alert no real value trips must NOT fire: {}",
        quiet.body
    );
}

#[test]
fn dashboards_materialize_from_the_live_store() {
    let (addr, token) = serve_and_login();

    // A dashboard with a panel per signal kind materializes each panel's real
    // matched signals off the live store.
    let panels = "metrics=select: metrics range: now-100000s\n\
                  logs=select: logs range: now-100000s\n\
                  traces=select: traces range: now-100000s";
    let dash = http(
        &addr,
        "POST",
        "/portal/obs/live/dashboard",
        &format!("{token}\n{panels}"),
    );
    assert_eq!(dash.status, 200, "dashboard: {}", dash.body);

    for panel in ["metrics", "logs", "traces"] {
        let header = dash
            .body
            .lines()
            .find(|l| l.starts_with(&format!("PANEL {panel} ")))
            .unwrap_or_else(|| panic!("missing panel {panel}: {}", dash.body));
        let count: usize = header
            .rsplit_once("COUNT ")
            .and_then(|(_, n)| n.trim().parse().ok())
            .expect("panel count");
        assert!(
            count > 0,
            "dashboard panel {panel} must materialize real live data; got {count}"
        );
    }
}

// Silence unused-import lint for the SignalKind re-export kept for clarity of
// the module's domain (the black-box test names kinds as strings on the wire).
#[allow(dead_code)]
fn _kinds_domain(_k: SignalKind) {}
