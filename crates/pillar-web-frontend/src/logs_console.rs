//! Production logging / observability console — the Tier 1-3 exploration
//! surface over the live PSL query endpoint (`/portal/obs/live/query`).
//!
//! The legacy `ObservabilityTile` (portal.rs) offered a raw PSL textarea and a
//! flat result list. This module adds the real logging-workflow features an
//! operator expects, all driven by ONE structured query model:
//!
//! - **Tier 1** — human timestamps per signal (the store is timeseries data);
//!   click-to-filter label chips; a severity (`level`) filter with color; a
//!   full-text `message =~` search box; per-line payload-field expansion.
//! - **Tier 2** — a match-volume histogram bucketed over the result window; a
//!   time-range picker (now-15m / 1h / 24h / …); auto-refresh "live tail"; a
//!   label-key/value explorer sidebar (from `/label-keys` + `/label-values`).
//! - **Tier 3** — a guided query builder whose fields mirror PSL structure
//!   (select / where / range / correlate + anchor); CSV/JSON export of the
//!   current result set; a shareable query (serialized into the URL hash);
//!   correlate → jump-to-trace.
//!
//! Everything that can be is a PURE function tested on the host (query build,
//! response parse, histogram bucketing, export rendering); only the Yew
//! component and the wall-clock formatting are wasm-gated.

use std::collections::BTreeMap;

/// One parsed live-signal row from a PSL query response line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalRow {
    /// Content-addressed signal id.
    pub id: String,
    /// Kind tag (`metric`/`log`/`trace`/`profile`/`metadata`).
    pub kind: String,
    /// Logical write tick.
    pub tick: u64,
    /// Real wall-clock unix millis, when the server anchored the tick.
    pub unix_millis: Option<u64>,
    /// The signal's real labels (key -> value), sorted by key.
    pub labels: Vec<(String, String)>,
    /// Raw payload text.
    pub payload: String,
}

impl SignalRow {
    /// The value of a label by key, if present.
    #[must_use]
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The severity level of a log row (its `level` label), if any.
    #[must_use]
    pub fn level(&self) -> Option<&str> {
        self.label("level")
    }
}

/// Parse the `k=v;k=v` LABELS field into sorted key/value pairs.
#[must_use]
pub fn parse_label_field(field: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = field
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    out.sort();
    out
}

/// Parse a PSL query response body into structured signal rows.
///
/// Each `SIGNAL` line is `<id> KIND <kind> [TICK <n>] [TS <millis>]
/// [LABELS <k=v;…>] PAYLOAD <payload>`. The optional fields appear in that
/// fixed order; a line missing them (an older/other response shape) still
/// parses (tick 0, no timestamp, no labels). `GROUP` lines are ignored here
/// (see [`parse_correlate_groups`]).
#[must_use]
pub fn parse_signal_rows(body: &str) -> Vec<SignalRow> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("SIGNAL ") else {
            continue;
        };
        let Some((id, after)) = rest.split_once(" KIND ") else {
            continue;
        };
        let (head, payload) = match after.split_once(" PAYLOAD ") {
            Some((h, p)) => (h, p.to_owned()),
            None => (after, String::new()),
        };
        let mut row = SignalRow {
            id: id.trim().to_owned(),
            payload,
            ..SignalRow::default()
        };
        if let Some((kind, tail)) = head.split_once(" TICK ") {
            row.kind = kind.trim().to_owned();
            // tail = "<tick> [TS <millis>] [LABELS <k=v;…>]"
            let (tick_str, tail) = split_marker(tail, " TS ");
            row.tick = tick_str.trim().parse().unwrap_or(0);
            if let Some(tail) = tail {
                let (ts_str, labels) = split_marker(tail, " LABELS ");
                row.unix_millis = ts_str.trim().parse::<u64>().ok();
                if let Some(labels) = labels {
                    row.labels = parse_label_field(labels);
                }
            } else {
                // No TS: the remainder may still carry LABELS directly.
                let (tick_only, labels) = split_marker(tick_str, " LABELS ");
                row.tick = tick_only.trim().parse().unwrap_or(row.tick);
                if let Some(labels) = labels {
                    row.labels = parse_label_field(labels);
                }
            }
        } else {
            // Fallback shape: `<id> KIND <kind> PAYLOAD <payload>`.
            row.kind = head.trim().to_owned();
        }
        rows.push(row);
    }
    rows
}

/// Split `s` at the first `marker`, returning the head and the optional tail
/// after the marker.
fn split_marker<'a>(s: &'a str, marker: &str) -> (&'a str, Option<&'a str>) {
    match s.split_once(marker) {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    }
}

/// Parse the `GROUP <anchor> MEMBERS <id,id,…>` correlate lines of a response.
#[must_use]
pub fn parse_correlate_groups(body: &str) -> Vec<(String, Vec<String>)> {
    let mut groups = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("GROUP ") else {
            continue;
        };
        let Some((anchor, members)) = rest.split_once(" MEMBERS ") else {
            continue;
        };
        let ids: Vec<String> = members
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        groups.push((anchor.trim().to_owned(), ids));
    }
    groups
}

/// Parse a `key=value key=value` payload into its structured fields (the
/// per-line "expand" view). Whitespace-separated; only `k=v` tokens are kept.
#[must_use]
pub fn payload_fields(payload: &str) -> Vec<(String, String)> {
    payload
        .split_whitespace()
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// A structured logging query — the guided builder's state, mirroring PSL
/// structure so it round-trips to a real PSL string via [`build_psl`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogQuery {
    /// Selected kind, plural PSL token (`logs`/`metrics`/`traces`/…).
    pub kind: String,
    /// `where:` equality predicates (label = value), e.g. from a chip click.
    pub wheres: Vec<(String, String)>,
    /// Severity filter (a `level = <lvl>` where-predicate); empty = any.
    pub level: String,
    /// Full-text search over the log message (`message =~ "<text>"`); only
    /// meaningful for the `logs` kind.
    pub search: String,
    /// Relative window in seconds (`range: now-<n>s`).
    pub range_seconds: u64,
    /// Optional correlate: `(window_seconds, anchor_kind)`.
    pub correlate: Option<(u64, String)>,
}

impl Default for LogQuery {
    fn default() -> Self {
        LogQuery {
            kind: "logs".to_owned(),
            wheres: Vec::new(),
            level: String::new(),
            search: String::new(),
            range_seconds: 3600,
            correlate: None,
        }
    }
}

impl LogQuery {
    /// Add a `key = value` where-predicate (a chip click), de-duplicated.
    pub fn add_where(&mut self, key: &str, value: &str) {
        let pair = (key.to_owned(), value.to_owned());
        if !self.wheres.contains(&pair) {
            self.wheres.push(pair);
        }
    }

    /// Remove a where-predicate (chip dismiss).
    pub fn remove_where(&mut self, key: &str, value: &str) {
        self.wheres.retain(|(k, v)| !(k == key && v == value));
    }
}

/// Escape a user search string for a safe `message =~ "<...>"` literal (drop
/// the quote char that would terminate the literal).
fn escape_regex_literal(s: &str) -> String {
    s.trim().replace('"', "")
}

/// Render a [`LogQuery`] to a real PSL string the backend parses.
#[must_use]
pub fn build_psl(q: &LogQuery) -> String {
    let mut s = format!("select: {}", q.kind);
    let mut preds: Vec<String> = q.wheres.iter().map(|(k, v)| format!("{k} = {v}")).collect();
    if !q.level.trim().is_empty() {
        preds.push(format!("level = {}", q.level.trim()));
    }
    if q.kind == "logs" && !q.search.trim().is_empty() {
        preds.push(format!(
            "message =~ \"{}\"",
            escape_regex_literal(&q.search)
        ));
    }
    if !preds.is_empty() {
        s.push_str(&format!(" where: {}", preds.join(", ")));
    }
    s.push_str(&format!(" range: now-{}s", q.range_seconds));
    if let Some((window, anchor)) = &q.correlate {
        s.push_str(&format!(
            " correlate: {{ window: {window}s, anchor: {anchor} }}"
        ));
    }
    s
}

/// The time-range presets the picker offers: `(label, seconds)`.
#[must_use]
pub fn range_presets() -> Vec<(&'static str, u64)> {
    vec![
        ("15m", 900),
        ("1h", 3_600),
        ("6h", 21_600),
        ("24h", 86_400),
        ("7d", 604_800),
    ]
}

/// The severity levels offered by the level filter (ascending).
#[must_use]
pub fn level_options() -> [&'static str; 4] {
    ["debug", "info", "warn", "error"]
}

/// A CSS class for a severity level, so a row is colored by severity.
#[must_use]
pub fn level_class(level: &str) -> &'static str {
    match level.to_ascii_lowercase().as_str() {
        "error" => "lvl-error",
        "warn" | "warning" => "lvl-warn",
        "debug" | "trace" => "lvl-debug",
        _ => "lvl-info",
    }
}

/// Bucket rows into `buckets` equal time bins over their timestamp span,
/// returning per-bucket counts (left → right) — the volume histogram series.
/// Uses `unix_millis` when present, else the logical `tick`; an empty or
/// single-point set yields a single full bucket.
#[must_use]
pub fn histogram_buckets(rows: &[SignalRow], buckets: usize) -> Vec<f64> {
    let buckets = buckets.max(1);
    if rows.is_empty() {
        return vec![0.0; buckets];
    }
    let stamps: Vec<u64> = rows
        .iter()
        .map(|r| r.unix_millis.unwrap_or(r.tick))
        .collect();
    let min = *stamps.iter().min().unwrap();
    let max = *stamps.iter().max().unwrap();
    if min == max {
        // All at one instant: everything in the last bucket.
        let mut out = vec![0.0; buckets];
        *out.last_mut().unwrap() = stamps.len() as f64;
        return out;
    }
    let span = (max - min) as f64;
    let mut out = vec![0.0; buckets];
    for s in stamps {
        let frac = (s - min) as f64 / span;
        let mut idx = (frac * buckets as f64) as usize;
        if idx >= buckets {
            idx = buckets - 1;
        }
        out[idx] += 1.0;
    }
    out
}

/// Render the rows as CSV (`time_ms,kind,labels,payload`), each label pair
/// joined `k=v` with `;`, and CSV-quoted.
#[must_use]
pub fn rows_to_csv(rows: &[SignalRow]) -> String {
    let mut out = String::from("time_ms,tick,kind,labels,payload\n");
    for r in rows {
        let labels = r
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        let ts = r.unix_millis.map(|m| m.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_quote(&ts),
            r.tick,
            csv_quote(&r.kind),
            csv_quote(&labels),
            csv_quote(&r.payload),
        ));
    }
    out
}

fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Render the rows as a JSON array of objects. Hand-rolled (no serde in this
/// crate's wasm closure) but fully escaped.
#[must_use]
pub fn rows_to_json(rows: &[SignalRow]) -> String {
    let mut out = String::from("[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let labels = r
            .labels
            .iter()
            .map(|(k, v)| format!("{}:{}", json_str(k), json_str(v)))
            .collect::<Vec<_>>()
            .join(",");
        let ts = match r.unix_millis {
            Some(m) => m.to_string(),
            None => "null".to_owned(),
        };
        out.push_str(&format!(
            "{{\"id\":{},\"kind\":{},\"tick\":{},\"unix_millis\":{},\"labels\":{{{}}},\"payload\":{}}}",
            json_str(&r.id),
            json_str(&r.kind),
            r.tick,
            ts,
            labels,
            json_str(&r.payload),
        ));
    }
    out.push(']');
    out
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Serialize a query to a compact `#logs?…` URL hash for sharing.
#[must_use]
pub fn query_to_hash(q: &LogQuery) -> String {
    let mut parts = vec![
        format!("kind={}", q.kind),
        format!("range={}", q.range_seconds),
    ];
    if !q.level.trim().is_empty() {
        parts.push(format!("level={}", q.level.trim()));
    }
    if q.kind == "logs" && !q.search.trim().is_empty() {
        parts.push(format!("q={}", url_encode(q.search.trim())));
    }
    for (k, v) in &q.wheres {
        parts.push(format!("w={}", url_encode(&format!("{k}={v}"))));
    }
    if let Some((w, anchor)) = &q.correlate {
        parts.push(format!("cw={w}"));
        parts.push(format!("ca={anchor}"));
    }
    format!("#logs?{}", parts.join("&"))
}

/// Parse a `#logs?…` hash back into a query (best-effort; unknown keys
/// ignored). Returns `None` if the hash is not a logs-console hash.
#[must_use]
pub fn query_from_hash(hash: &str) -> Option<LogQuery> {
    let body = hash
        .trim_start_matches('#')
        .strip_prefix("logs?")
        .or_else(|| hash.strip_prefix("logs?"))?;
    let mut q = LogQuery::default();
    let mut wheres = Vec::new();
    for pair in body.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "kind" => q.kind = v.to_owned(),
            "range" => q.range_seconds = v.parse().unwrap_or(3600),
            "level" => q.level = v.to_owned(),
            "q" => q.search = url_decode(v),
            "w" => {
                if let Some((wk, wv)) = url_decode(v).split_once('=') {
                    wheres.push((wk.trim().to_owned(), wv.trim().to_owned()));
                }
            }
            "cw" => {
                let w = v.parse().unwrap_or(1);
                let anchor = q
                    .correlate
                    .clone()
                    .map(|(_, a)| a)
                    .unwrap_or_else(|| q.kind.clone());
                q.correlate = Some((w, anchor));
            }
            "ca" => {
                let w = q.correlate.clone().map(|(w, _)| w).unwrap_or(1);
                q.correlate = Some((w, v.to_owned()));
            }
            _ => {}
        }
    }
    q.wheres = wheres;
    Some(q)
}

/// Minimal percent-encoding for the hash values we emit (space + `&`/`#`/`%`
/// + `=`), enough to round-trip a query safely.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Count rows per severity level for the summary strip (`level -> count`).
#[must_use]
pub fn level_counts(rows: &[SignalRow]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for r in rows {
        if let Some(l) = r.level() {
            *counts.entry(l.to_owned()).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> String {
        "SIGNAL a1 KIND log TICK 7 TS 1700000000000 LABELS node=peer1;level=warn;component=federation PAYLOAD level=warn msg=disk almost full\n\
         SIGNAL b2 KIND log TICK 8 TS 1700000015000 LABELS node=peer1;level=info;component=core PAYLOAD level=info msg=served request\n\
         GROUP a1 MEMBERS a1,b2\n"
            .to_owned()
    }

    #[test]
    fn parses_signal_rows_with_tick_ts_labels() {
        let rows = parse_signal_rows(&sample_body());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "a1");
        assert_eq!(rows[0].kind, "log");
        assert_eq!(rows[0].tick, 7);
        assert_eq!(rows[0].unix_millis, Some(1_700_000_000_000));
        assert_eq!(rows[0].label("component"), Some("federation"));
        assert_eq!(rows[0].level(), Some("warn"));
        assert_eq!(rows[0].payload, "level=warn msg=disk almost full");
    }

    #[test]
    fn parses_correlate_groups() {
        let groups = parse_correlate_groups(&sample_body());
        assert_eq!(
            groups,
            vec![("a1".to_owned(), vec!["a1".to_owned(), "b2".to_owned()])]
        );
    }

    #[test]
    fn tolerates_old_format_without_tick_ts_labels() {
        let rows = parse_signal_rows("SIGNAL x KIND metric PAYLOAD node_cpu_ticks 5 @1");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "metric");
        assert_eq!(rows[0].tick, 0);
        assert_eq!(rows[0].unix_millis, None);
        assert!(rows[0].labels.is_empty());
        assert_eq!(rows[0].payload, "node_cpu_ticks 5 @1");
    }

    #[test]
    fn parses_labels_and_payload_fields() {
        assert_eq!(
            parse_label_field("node=peer1;level=warn"),
            vec![
                ("level".to_owned(), "warn".to_owned()),
                ("node".to_owned(), "peer1".to_owned())
            ]
        );
        assert_eq!(
            payload_fields("level=warn msg=hello k=v"),
            vec![
                ("level".to_owned(), "warn".to_owned()),
                ("msg".to_owned(), "hello".to_owned()),
                ("k".to_owned(), "v".to_owned())
            ]
        );
    }

    #[test]
    fn builds_psl_from_the_structured_query() {
        let mut q = LogQuery::default();
        q.add_where("node", "peer1");
        q.level = "warn".to_owned();
        q.search = "time\"out".to_owned();
        q.range_seconds = 900;
        assert_eq!(
            build_psl(&q),
            "select: logs where: node = peer1, level = warn, message =~ \"timeout\" range: now-900s"
        );
    }

    #[test]
    fn builds_psl_with_correlate_and_no_search_off_logs() {
        let q = LogQuery {
            kind: "metrics".to_owned(),
            search: "ignored off logs".to_owned(),
            range_seconds: 3600,
            correlate: Some((1, "metrics".to_owned())),
            ..LogQuery::default()
        };
        assert_eq!(
            build_psl(&q),
            "select: metrics range: now-3600s correlate: { window: 1s, anchor: metrics }"
        );
    }

    #[test]
    fn where_add_is_deduped_and_removable() {
        let mut q = LogQuery::default();
        q.add_where("node", "p");
        q.add_where("node", "p");
        assert_eq!(q.wheres.len(), 1);
        q.remove_where("node", "p");
        assert!(q.wheres.is_empty());
    }

    #[test]
    fn histogram_buckets_spread_over_time() {
        let rows = parse_signal_rows(&sample_body());
        let h = histogram_buckets(&rows, 4);
        assert_eq!(h.len(), 4);
        assert_eq!(h.iter().sum::<f64>(), 2.0);
        // Two stamps 15s apart -> one in the first bucket, one in the last.
        assert_eq!(h[0], 1.0);
        assert_eq!(h[3], 1.0);
    }

    #[test]
    fn histogram_of_empty_is_zeros() {
        assert_eq!(histogram_buckets(&[], 3), vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn exports_csv_and_json() {
        let rows = parse_signal_rows(&sample_body());
        let csv = rows_to_csv(&rows);
        assert!(csv.starts_with("time_ms,tick,kind,labels,payload\n"));
        assert!(csv.contains("1700000000000,7,log,component=federation;level=warn;node=peer1,"));
        // payload has a comma-free value here; still present.
        assert!(csv.contains("level=warn msg=disk almost full"));
        let json = rows_to_json(&rows);
        assert!(json.starts_with('['));
        assert!(json.contains("\"kind\":\"log\""));
        assert!(json.contains("\"unix_millis\":1700000000000"));
        assert!(json.contains("\"node\":\"peer1\""));
    }

    #[test]
    fn level_class_maps_severity() {
        assert_eq!(level_class("error"), "lvl-error");
        assert_eq!(level_class("WARN"), "lvl-warn");
        assert_eq!(level_class("info"), "lvl-info");
        assert_eq!(level_class("whatever"), "lvl-info");
    }

    #[test]
    fn level_counts_tallies_by_severity() {
        let rows = parse_signal_rows(&sample_body());
        let counts = level_counts(&rows);
        assert_eq!(counts.get("warn"), Some(&1));
        assert_eq!(counts.get("info"), Some(&1));
    }

    #[test]
    fn query_round_trips_through_the_url_hash() {
        let mut q = LogQuery::default();
        q.kind = "logs".to_owned();
        q.add_where("component", "federation");
        q.level = "warn".to_owned();
        q.search = "disk full".to_owned();
        q.range_seconds = 21_600;
        q.correlate = Some((2, "traces".to_owned()));
        let hash = query_to_hash(&q);
        let back = query_from_hash(&hash).expect("parses");
        assert_eq!(back, q);
    }

    #[test]
    fn query_from_non_logs_hash_is_none() {
        assert!(query_from_hash("#overview").is_none());
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::LogsConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::*;
    use crate::auth::use_auth;
    use crate::portal::{get_url, http, input_value};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::HtmlSelectElement;
    use yew::prelude::*;

    /// Read the selected value of a `<select>` an `onchange` fired on.
    fn select_value(e: &Event) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            .map(|s| s.value())
            .unwrap_or_default()
    }

    /// Format a real wall-clock unix-millis stamp as a local time string; a
    /// row with no anchored timestamp renders an em dash.
    fn human_time(millis: Option<u64>) -> String {
        match millis {
            Some(m) => {
                let d = js_sys::Date::new(&JsValue::from_f64(m as f64));
                d.to_locale_string("en-US", &JsValue::UNDEFINED)
                    .as_string()
                    .unwrap_or_default()
            }
            None => "—".to_owned(),
        }
    }

    /// Trigger a browser download of `content` as `filename` via a data URL.
    fn download(filename: &str, mime: &str, content: &str) {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(document) = window.document() else {
            return;
        };
        let encoded = super::url_encode(content);
        let href = format!("data:{mime};charset=utf-8,{encoded}");
        if let Ok(a) = document.create_element("a") {
            let _ = a.set_attribute("href", &href);
            let _ = a.set_attribute("download", filename);
            if let Some(a) = a.dyn_ref::<web_sys::HtmlElement>() {
                a.click();
            }
        }
    }

    #[function_component(LogsConsole)]
    pub fn logs_console() -> Html {
        let auth = use_auth();
        let query = use_state(LogQuery::default);
        let rows = use_state(Vec::<SignalRow>::new);
        let groups = use_state(Vec::<(String, Vec<String>)>::new);
        let msg = use_state(|| None::<(String, bool)>);
        let expanded = use_state(|| None::<String>);
        let label_keys = use_state(Vec::<String>::new);
        let label_values = use_state(Vec::<String>::new);
        let active_key = use_state(String::new);
        let live = use_state(|| false);
        let tick = use_state(|| 0u64);

        // Schema: available label keys (explorer sidebar + typeahead source).
        {
            let (auth, label_keys) = (auth.clone(), label_keys.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let label_keys = label_keys.clone();
                    let url = get_url("/portal/obs/live/label-keys", &token, &[]);
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                label_keys.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                    });
                }
                || ()
            });
        }

        // Run the current query (also the live-tail heartbeat dependency).
        let run = {
            let (auth, query, rows, groups, msg) = (
                auth.clone(),
                query.clone(),
                rows.clone(),
                groups.clone(),
                msg.clone(),
            );
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let psl = build_psl(&query);
                let (rows, groups, msg) = (rows.clone(), groups.clone(), msg.clone());
                let url = get_url("/portal/obs/live/query", &token, &[]);
                spawn_local(async move {
                    match http("POST", &url, Some(&psl)).await {
                        Ok(r) if r.ok() => {
                            let parsed = parse_signal_rows(&r.body);
                            let g = parse_correlate_groups(&r.body);
                            if parsed.is_empty() && g.is_empty() {
                                msg.set(Some((
                                    "no matching signals in this window".to_owned(),
                                    false,
                                )));
                            } else {
                                msg.set(None);
                            }
                            rows.set(parsed);
                            groups.set(g);
                        }
                        Ok(r) => {
                            rows.set(Vec::new());
                            groups.set(Vec::new());
                            msg.set(Some((r.body.trim().to_owned(), false)));
                        }
                        Err(_) => {
                            msg.set(Some(("request failed".to_owned(), false)));
                        }
                    }
                });
            })
        };

        // Live tail: while enabled, bump `tick` on an interval; the effect
        // below re-runs the query each bump. Cleaned up on toggle/unmount.
        {
            let (live, tick) = (live.clone(), tick.clone());
            use_effect_with(*live, move |enabled| {
                let mut handle: Option<(i32, Closure<dyn FnMut()>)> = None;
                if *enabled {
                    if let Some(window) = web_sys::window() {
                        let tick = tick.clone();
                        let cb = Closure::<dyn FnMut()>::new(move || {
                            tick.set(*tick + 1);
                        });
                        if let Ok(id) = window
                            .set_interval_with_callback_and_timeout_and_arguments_0(
                                cb.as_ref().unchecked_ref(),
                                5000,
                            )
                        {
                            handle = Some((id, cb));
                        }
                    }
                }
                move || {
                    if let Some((id, _cb)) = handle {
                        if let Some(window) = web_sys::window() {
                            window.clear_interval_with_handle(id);
                        }
                    }
                }
            });
        }

        // Re-run on each live-tail tick.
        {
            let run = run.clone();
            use_effect_with(*tick, move |t| {
                if *t > 0 {
                    run.emit(());
                }
                || ()
            });
        }

        let run_click = {
            let run = run.clone();
            Callback::from(move |_: MouseEvent| run.emit(()))
        };

        let on_kind = {
            let query = query.clone();
            Callback::from(move |e: Event| {
                let mut q = (*query).clone();
                q.kind = select_value(&e);
                query.set(q);
            })
        };
        let on_level = {
            let query = query.clone();
            Callback::from(move |e: Event| {
                let mut q = (*query).clone();
                q.level = select_value(&e);
                query.set(q);
            })
        };
        let on_search = {
            let query = query.clone();
            Callback::from(move |e: InputEvent| {
                let mut q = (*query).clone();
                q.search = input_value(&e);
                query.set(q);
            })
        };
        let set_range = {
            let (query, run) = (query.clone(), run.clone());
            move |seconds: u64| {
                let (query, run) = (query.clone(), run.clone());
                Callback::from(move |_: MouseEvent| {
                    let mut q = (*query).clone();
                    q.range_seconds = seconds;
                    query.set(q);
                    run.emit(());
                })
            }
        };
        let add_chip = {
            let query = query.clone();
            move |key: String, value: String| {
                let query = query.clone();
                Callback::from(move |_: MouseEvent| {
                    let mut q = (*query).clone();
                    q.add_where(&key, &value);
                    query.set(q);
                })
            }
        };
        let remove_chip = {
            let query = query.clone();
            move |key: String, value: String| {
                let query = query.clone();
                Callback::from(move |_: MouseEvent| {
                    let mut q = (*query).clone();
                    q.remove_where(&key, &value);
                    query.set(q);
                })
            }
        };
        let toggle_expand = {
            let expanded = expanded.clone();
            move |id: String| {
                let expanded = expanded.clone();
                Callback::from(move |_: MouseEvent| {
                    if expanded.as_ref() == Some(&id) {
                        expanded.set(None);
                    } else {
                        expanded.set(Some(id.clone()));
                    }
                })
            }
        };
        let toggle_live = {
            let live = live.clone();
            Callback::from(move |_: MouseEvent| live.set(!*live))
        };
        let explore_key = {
            let (auth, active_key, label_values) =
                (auth.clone(), active_key.clone(), label_values.clone());
            move |key: String| {
                let (auth, active_key, label_values) =
                    (auth.clone(), active_key.clone(), label_values.clone());
                Callback::from(move |_: MouseEvent| {
                    active_key.set(key.clone());
                    let Some(token) = auth.token.clone() else {
                        return;
                    };
                    let url = get_url("/portal/obs/live/label-values", &token, &[("key", &key)]);
                    let label_values = label_values.clone();
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                label_values.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                    });
                })
            }
        };
        let export_csv = {
            let rows = rows.clone();
            Callback::from(move |_: MouseEvent| {
                download("pillar-signals.csv", "text/csv", &rows_to_csv(&rows));
            })
        };
        let export_json = {
            let rows = rows.clone();
            Callback::from(move |_: MouseEvent| {
                download(
                    "pillar-signals.json",
                    "application/json",
                    &rows_to_json(&rows),
                );
            })
        };
        let copy_share = {
            let query = query.clone();
            Callback::from(move |_: MouseEvent| {
                let hash = query_to_hash(&query);
                if let Some(window) = web_sys::window() {
                    let _ = window.location().set_hash(&hash);
                }
            })
        };

        let hist = histogram_buckets(&rows, 24);
        let lcounts = level_counts(&rows);
        let psl_preview = build_psl(&query);

        html! {
            <div class="tile" id="logs-console">
                <h3>{ "Logs & signals" }</h3>
                <p class="hint">{ "Explore the live timeseries store: filter by label, \
                    severity and free text; click a label chip to add it to the query; \
                    every row shows its real timestamp." }</p>

                // ---- Guided query builder (PSL-structured fields) ----
                <div class="row logs-builder">
                    <label>{ "select" }</label>
                    <select id="logs-kind" onchange={on_kind}>
                        { for ["logs","metrics","traces","profiles","metadata"].iter().map(|k| html!{
                            <option value={*k} selected={query.kind==*k}>{ *k }</option>
                        }) }
                    </select>
                    <label>{ "level" }</label>
                    <select id="logs-level" onchange={on_level}>
                        <option value="" selected={query.level.is_empty()}>{ "any" }</option>
                        { for level_options().iter().map(|l| html!{
                            <option value={*l} selected={query.level==*l}>{ *l }</option>
                        }) }
                    </select>
                    if query.kind == "logs" {
                        <input id="logs-search" type="text" placeholder="search message (regex)"
                            value={query.search.clone()} oninput={on_search} />
                    }
                    <button type="button" id="logs-run" onclick={run_click}>{ "Run" }</button>
                    <button type="button" id="logs-live"
                        class={if *live {"active"} else {""}} onclick={toggle_live}>
                        { if *live { "Live: on" } else { "Live: off" } }
                    </button>
                </div>

                // ---- Time-range picker ----
                <div class="row logs-ranges">
                    <label>{ "range" }</label>
                    { for range_presets().into_iter().map(|(lbl, secs)| {
                        let active = query.range_seconds == secs;
                        html!{ <button type="button"
                            class={if active {"active"} else {""}}
                            onclick={set_range(secs)}>{ lbl }</button> }
                    }) }
                </div>

                // ---- Active where-chips ----
                if !query.wheres.is_empty() {
                    <div class="row logs-chips">
                        <label>{ "where" }</label>
                        { for query.wheres.iter().map(|(k,v)| {
                            let (k2, v2) = (k.clone(), v.clone());
                            html!{ <span class="chip">
                                { format!("{k} = {v}") }
                                <button type="button" class="chip-x"
                                    onclick={remove_chip(k2, v2)}>{ "×" }</button>
                            </span> }
                        }) }
                    </div>
                }

                <p class="hint mono">{ format!("PSL: {psl_preview}") }</p>
                { message_line("logs-msg", &msg) }

                // ---- Volume histogram + level summary ----
                if !rows.is_empty() {
                    <div class="logs-hist">
                        <crate::primitives::Chart values={hist.clone()}
                            kind={crate::primitives::ChartKind::Bar} width={480.0} height={56.0} />
                        <div class="row logs-levelsum">
                            { for lcounts.iter().map(|(lvl,n)| html!{
                                <span class={classes!("chip", level_class(lvl))}>
                                    { format!("{lvl}: {n}") }
                                </span>
                            }) }
                            <span class="chip">{ format!("total: {}", rows.len()) }</span>
                        </div>
                    </div>
                }

                <div class="row logs-actions">
                    <button type="button" id="logs-export-csv" onclick={export_csv}>{ "Export CSV" }</button>
                    <button type="button" id="logs-export-json" onclick={export_json}>{ "Export JSON" }</button>
                    <button type="button" id="logs-share" onclick={copy_share}>{ "Shareable link" }</button>
                </div>

                <div class="logs-layout">
                    // ---- Result rows ----
                    <div class="logs-results" id="logs-results">
                        { for rows.iter().map(|r| {
                            let lvl = r.level().unwrap_or("");
                            let is_open = expanded.as_ref() == Some(&r.id);
                            html!{
                                <div class={classes!("logs-row", level_class(lvl))}>
                                    <div class="logs-row-head" onclick={toggle_expand(r.id.clone())}>
                                        <span class="logs-ts">{ human_time(r.unix_millis) }</span>
                                        <span class="logs-kind">{ r.kind.clone() }</span>
                                        <span class="logs-payload">{ r.payload.clone() }</span>
                                    </div>
                                    <div class="logs-chips-inline">
                                        { for r.labels.iter().map(|(k,v)| {
                                            let (k2,v2)=(k.clone(),v.clone());
                                            html!{ <button type="button" class="chip chip-click"
                                                title="filter by this label"
                                                onclick={add_chip(k2,v2)}>
                                                { format!("{k}={v}") }
                                            </button> }
                                        }) }
                                    </div>
                                    if is_open {
                                        <div class="logs-fields">
                                            { for payload_fields(&r.payload).into_iter().map(|(k,v)| html!{
                                                <div class="logs-field">
                                                    <span class="logs-field-k">{ k }</span>
                                                    <span class="logs-field-v">{ v }</span>
                                                </div>
                                            }) }
                                            <div class="logs-field">
                                                <span class="logs-field-k">{ "id" }</span>
                                                <span class="logs-field-v mono">{ r.id.clone() }</span>
                                            </div>
                                            <div class="logs-field">
                                                <span class="logs-field-k">{ "tick" }</span>
                                                <span class="logs-field-v">{ r.tick.to_string() }</span>
                                            </div>
                                        </div>
                                    }
                                </div>
                            }
                        }) }
                    </div>

                    // ---- Label explorer sidebar ----
                    <div class="logs-explorer">
                        <label>{ "label keys" }</label>
                        <div class="logs-keylist">
                            { for label_keys.iter().map(|k| {
                                let active = *active_key == *k;
                                html!{ <button type="button"
                                    class={if active {"chip active"} else {"chip"}}
                                    onclick={explore_key(k.clone())}>{ k.clone() }</button> }
                            }) }
                        </div>
                        if !active_key.is_empty() {
                            <label>{ format!("values of {}", *active_key) }</label>
                            <div class="logs-vallist">
                                { for label_values.iter().map(|v| {
                                    let (k2,v2)=((*active_key).clone(), v.clone());
                                    html!{ <button type="button" class="chip chip-click"
                                        onclick={add_chip(k2,v2)}>{ v.clone() }</button> }
                                }) }
                            </div>
                        }
                    </div>
                </div>

                // ---- Correlate groups (jump-to-trace) ----
                if !groups.is_empty() {
                    <div class="logs-groups">
                        <label>{ "correlate groups" }</label>
                        { for groups.iter().map(|(anchor, members)| html!{
                            <p class="logs-group">
                                <strong>{ format!("anchor {anchor}: ") }</strong>
                                { members.join(", ") }
                            </p>
                        }) }
                    </div>
                }
            </div>
        }
    }

    /// A small status line (reused shape from the portal): green on success,
    /// red on error.
    fn message_line(id: &str, msg: &UseStateHandle<Option<(String, bool)>>) -> Html {
        match &**msg {
            Some((text, ok)) => html! {
                <p id={id.to_owned()} class={if *ok {"msg-ok"} else {"msg-err"}}>{ text.clone() }</p>
            },
            None => html! {},
        }
    }
}
