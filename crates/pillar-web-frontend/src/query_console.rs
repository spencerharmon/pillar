//! The single canonical observability query console.
//!
//! This module supersedes the earlier split surfaces (the raw-PSL textarea and
//! legacy explore/query tiles in `portal.rs`, the five guided builders in
//! `explore.rs`, the correlate-only `drilldown` tab, and the interim
//! `logs_console`). It presents ONE console with two always-synchronised
//! views of the SAME query:
//!
//! - a **structured builder** whose controls map one-to-one onto the real PSL
//!   grammar — arbitrary `select:` clauses (multi-kind correlation), label
//!   predicates inside a select's parentheses, global `where:` predicates, an
//!   arbitrary relative `range:`, and an optional `correlate:` spec; and
//! - the **raw PSL** text.
//!
//! Both views render from a single source of truth: the raw PSL string. The
//! builder is a projection of `pillar_observability::psl::parse(text)`; every
//! structured edit mutates the parsed [`PslQuery`] and writes
//! `query.to_text()` back — so the two directions round-trip exactly through
//! the real grammar (no parallel string model). Log severity is not special:
//! it is just a `level = <lvl>` predicate like any other label filter.
//!
//! Results render per kind by default: metrics as time-series graphs (toggle
//! to a table), profiles as a flame graph, logs/traces/metadata as rows with
//! click-to-filter label chips and timestamps. A `correlate:` query renders
//! each correlation group with every member kind's default view side by side.
//!
//! Everything that can be is a pure function tested on the host (response
//! parsing, metric-series extraction, flame-graph layout, CSV/JSON export,
//! duration and URL-hash round-trips); only the Yew component and wall-clock
//! formatting are wasm-gated.

use std::collections::BTreeMap;

use pillar_observability::SignalKind;

/// The five signal kinds paired with their plural PSL token, in menu order.
pub const KINDS: [(SignalKind, &str); 5] = [
    (SignalKind::Metric, "metrics"),
    (SignalKind::Log, "logs"),
    (SignalKind::TraceSpan, "traces"),
    (SignalKind::ProfileSample, "profiles"),
    (SignalKind::MetadataSample, "metadata"),
];

/// The plural PSL token for a kind (`metrics`/`logs`/`traces`/`profiles`/
/// `metadata`).
#[must_use]
pub fn kind_token(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Metric => "metrics",
        SignalKind::Log => "logs",
        SignalKind::TraceSpan => "traces",
        SignalKind::ProfileSample => "profiles",
        SignalKind::MetadataSample => "metadata",
    }
}

/// Parse a plural PSL kind token back to a [`SignalKind`].
#[must_use]
pub fn kind_from_token(token: &str) -> Option<SignalKind> {
    KINDS.iter().find(|(_, t)| *t == token).map(|(k, _)| *k)
}

/// The singular kind tag used in a response `SIGNAL … KIND <tag>` line.
#[must_use]
pub fn kind_tag_to_token(tag: &str) -> &'static str {
    match tag {
        "metric" => "metrics",
        "log" => "logs",
        "trace" => "traces",
        "profile" => "profiles",
        "metadata" => "metadata",
        _ => "logs",
    }
}

/// One parsed live-signal row from a PSL query response line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalRow {
    /// Content-addressed signal id (lowercase hex — matches correlate members).
    pub id: String,
    /// Singular kind tag (`metric`/`log`/`trace`/`profile`/`metadata`).
    pub kind: String,
    /// Logical write tick.
    pub tick: u64,
    /// Real wall-clock unix millis, when the server anchored the tick.
    pub unix_millis: Option<u64>,
    /// The signal's real labels (key -> value), sorted by key.
    pub labels: Vec<(String, String)>,
    /// Raw payload text (un-escaped — newlines restored).
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

    /// The severity level of a row (its `level` label), if any.
    #[must_use]
    pub fn level(&self) -> Option<&str> {
        self.label("level")
    }
}

/// Reverse the server's payload escaping (`\\` -> `\`, `\n` -> newline,
/// `\r` -> carriage return). Profile payloads carry a multi-line backtrace
/// escaped onto one response line; this restores it.
#[must_use]
pub fn unescape_payload(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
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

/// Split `s` at the first `marker`, returning head and optional tail.
fn split_marker<'a>(s: &'a str, marker: &str) -> (&'a str, Option<&'a str>) {
    match s.split_once(marker) {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    }
}

/// Parse a PSL query response body into structured signal rows.
///
/// Each `SIGNAL` line is `<id> KIND <kind> [TICK <n>] [TS <millis>]
/// [LABELS <k=v;…>] PAYLOAD <payload>`, the payload escaped so it is always a
/// single line. Optional fields appear in that fixed order; a line missing
/// them (an older/other response shape) still parses. `GROUP` lines are
/// handled by [`parse_correlate_groups`].
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
            Some((h, p)) => (h, unescape_payload(p)),
            None => (after, String::new()),
        };
        let mut row = SignalRow {
            id: id.trim().to_owned(),
            payload,
            ..SignalRow::default()
        };
        if let Some((kind, tail)) = head.split_once(" TICK ") {
            row.kind = kind.trim().to_owned();
            let (tick_str, tail) = split_marker(tail, " TS ");
            row.tick = tick_str.trim().parse().unwrap_or(0);
            if let Some(tail) = tail {
                let (ts_str, labels) = split_marker(tail, " LABELS ");
                row.unix_millis = ts_str.trim().parse::<u64>().ok();
                if let Some(labels) = labels {
                    row.labels = parse_label_field(labels);
                }
            } else {
                let (tick_only, labels) = split_marker(tick_str, " LABELS ");
                row.tick = tick_only.trim().parse().unwrap_or(row.tick);
                if let Some(labels) = labels {
                    row.labels = parse_label_field(labels);
                }
            }
        } else {
            row.kind = head.trim().to_owned();
        }
        rows.push(row);
    }
    rows
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

/// Parse a `key=value key=value` payload into structured fields (whitespace
/// separated; only `k=v` tokens are kept).
#[must_use]
pub fn payload_fields(payload: &str) -> Vec<(String, String)> {
    payload
        .split_whitespace()
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Metric series
// ---------------------------------------------------------------------------

/// A single metric reading extracted from a metric signal's payload.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricPoint {
    /// Logical write tick (the x-axis ordering).
    pub tick: u64,
    /// Real wall-clock millis, when anchored.
    pub unix_millis: Option<u64>,
    /// The numeric reading.
    pub value: f64,
}

/// A named metric time series (one line on the graph).
#[derive(Clone, Debug, PartialEq)]
pub struct MetricSeries {
    /// Series name (the `metric` label, else the payload's leading token).
    pub name: String,
    /// Points sorted ascending by tick.
    pub points: Vec<MetricPoint>,
}

/// Parse a metric payload `"<name> <value> @<tick>"` into `(name, value)`.
#[must_use]
pub fn parse_metric_value(payload: &str) -> Option<(String, f64)> {
    let mut toks = payload.split_whitespace();
    let name = toks.next()?.to_owned();
    let value: f64 = toks.next()?.parse().ok()?;
    Some((name, value))
}

/// Group metric rows into named series, points sorted by tick. A row's series
/// is its `metric` label when present, else the payload's leading token.
#[must_use]
pub fn metric_series(rows: &[SignalRow]) -> Vec<MetricSeries> {
    let mut by_name: BTreeMap<String, Vec<MetricPoint>> = BTreeMap::new();
    for r in rows {
        if r.kind != "metric" {
            continue;
        }
        let Some((payload_name, value)) = parse_metric_value(&r.payload) else {
            continue;
        };
        let name = r.label("metric").map(str::to_owned).unwrap_or(payload_name);
        by_name.entry(name).or_default().push(MetricPoint {
            tick: r.tick,
            unix_millis: r.unix_millis,
            value,
        });
    }
    by_name
        .into_iter()
        .map(|(name, mut points)| {
            points.sort_by_key(|p| p.tick);
            MetricSeries { name, points }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Flame graph (profiles)
// ---------------------------------------------------------------------------

/// A node in the aggregated flame tree.
#[derive(Clone, Debug, PartialEq)]
pub struct FlameNode {
    /// Frame symbol (or `"all"` for the synthetic root).
    pub name: String,
    /// Total weight of all samples passing through this frame.
    pub value: u64,
    /// Child frames, insertion order.
    pub children: Vec<FlameNode>,
}

impl FlameNode {
    fn child_mut(&mut self, name: &str) -> &mut FlameNode {
        if let Some(idx) = self.children.iter().position(|c| c.name == name) {
            &mut self.children[idx]
        } else {
            self.children.push(FlameNode {
                name: name.to_owned(),
                value: 0,
                children: Vec::new(),
            });
            self.children.last_mut().unwrap()
        }
    }
}

/// Parse a profile payload `"<name> <weight> @<tick>\n<backtrace>"` into its
/// weight and root-to-leaf frame path. The backtrace is a standard Rust
/// `Backtrace` dump (`   N: symbol` lines, leaf first); we keep the symbols in
/// root-to-leaf order and drop the `at <file:line>` continuation lines.
#[must_use]
pub fn parse_profile_sample(payload: &str) -> Option<(u64, Vec<String>)> {
    let (header, stack) = match payload.split_once('\n') {
        Some((h, s)) => (h, s),
        None => (payload, ""),
    };
    let mut htoks = header.split_whitespace();
    let _name = htoks.next()?;
    let weight: u64 = htoks.next()?.parse().ok()?;
    let mut frames: Vec<String> = Vec::new();
    for line in stack.lines() {
        let line = line.trim();
        // A frame line looks like `12: some::symbol::here`.
        let Some((num, sym)) = line.split_once(':') else {
            continue;
        };
        if num.trim().parse::<u64>().is_err() {
            continue;
        }
        let sym = sym.trim();
        if sym.is_empty() {
            continue;
        }
        frames.push(sym.to_owned());
    }
    // Backtrace is leaf-first; a flame graph reads root (bottom) to leaf (top).
    frames.reverse();
    Some((weight, frames))
}

/// Aggregate profile samples into a flame tree rooted at `all`.
#[must_use]
pub fn build_flame(samples: &[(u64, Vec<String>)]) -> FlameNode {
    let mut root = FlameNode {
        name: "all".to_owned(),
        value: 0,
        children: Vec::new(),
    };
    for (weight, frames) in samples {
        root.value += weight;
        let mut node = &mut root;
        for frame in frames {
            node = node.child_mut(frame);
            node.value += weight;
        }
    }
    root
}

/// A laid-out flame-graph rectangle (fractions of the total width, 0.0..=1.0).
#[derive(Clone, Debug, PartialEq)]
pub struct FlameRect {
    /// Frame symbol.
    pub name: String,
    /// Sample weight at this frame.
    pub value: u64,
    /// Stack depth (0 = root at the bottom row).
    pub depth: usize,
    /// Left edge as a fraction of total width.
    pub x: f64,
    /// Width as a fraction of total width.
    pub width: f64,
}

/// Flatten a flame tree into positioned rectangles (icicle layout). Widths are
/// proportional to sample weight relative to the root total; siblings are
/// packed left-to-right under their parent.
#[must_use]
pub fn flatten_flame(root: &FlameNode) -> Vec<FlameRect> {
    let mut rects = Vec::new();
    if root.value == 0 {
        return rects;
    }
    let total = root.value as f64;
    fn walk(node: &FlameNode, depth: usize, x: f64, total: f64, rects: &mut Vec<FlameRect>) {
        let width = node.value as f64 / total;
        rects.push(FlameRect {
            name: node.name.clone(),
            value: node.value,
            depth,
            x,
            width,
        });
        let mut cursor = x;
        for child in &node.children {
            walk(child, depth + 1, cursor, total, rects);
            cursor += child.value as f64 / total;
        }
    }
    walk(root, 0, 0.0, total, &mut rects);
    rects
}

/// The maximum stack depth in a set of rectangles (for sizing the SVG).
#[must_use]
pub fn flame_max_depth(rects: &[FlameRect]) -> usize {
    rects.iter().map(|r| r.depth).max().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Rendering helpers shared by the component
// ---------------------------------------------------------------------------

/// A CSS class for a severity level, so a row is colored by severity.
#[must_use]
pub fn level_class(level: &str) -> &'static str {
    match level.to_ascii_lowercase().as_str() {
        "error" | "fatal" => "lvl-error",
        "warn" | "warning" => "lvl-warn",
        "debug" | "trace" => "lvl-debug",
        _ => "lvl-info",
    }
}

/// Bucket rows into `buckets` equal time bins over their timestamp span,
/// returning per-bucket counts (left → right) — the log-volume histogram.
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

/// Count rows per severity level (`level -> count`).
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

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Render rows as CSV (`time_ms,tick,kind,labels,payload`).
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

/// Render rows as a JSON array of objects.
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

// ---------------------------------------------------------------------------
// Duration + URL hash (share link) — round-trip the raw PSL text
// ---------------------------------------------------------------------------

/// Parse a relative duration (`90m`, `1h`, `3600s`, `2d`, or a bare number of
/// seconds) into seconds. Matches the units the PSL grammar accepts.
#[must_use]
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&s[..i], &s[i..]),
        None => (s, ""),
    };
    let n: u64 = num.parse().ok()?;
    let mult = match unit.trim() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return None,
    };
    Some(n * mult)
}

/// Render seconds as the largest whole unit (matching PSL `to_text`).
#[must_use]
pub fn format_duration(seconds: u64) -> String {
    if seconds != 0 && seconds % 86_400 == 0 {
        format!("{}d", seconds / 86_400)
    } else if seconds != 0 && seconds % 3_600 == 0 {
        format!("{}h", seconds / 3_600)
    } else if seconds != 0 && seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

/// Minimal percent-encoding for hash/data-URL values.
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

/// Serialize the raw PSL text into a shareable `#query?q=<encoded>` hash.
#[must_use]
pub fn psl_to_hash(text: &str) -> String {
    format!("#query?q={}", url_encode(text.trim()))
}

/// Recover raw PSL text from a `#query?q=…` hash, if present.
#[must_use]
pub fn psl_from_hash(hash: &str) -> Option<String> {
    let body = hash.trim_start_matches('#');
    let q = body.strip_prefix("query?q=")?;
    Some(url_decode(q))
}

/// The default query a fresh console opens with.
#[must_use]
pub fn default_query_text() -> String {
    "select: logs range: now-1h".to_owned()
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
    fn unescapes_multiline_profile_payload() {
        // The server escapes newlines so a profile stack is one response line.
        let body = "SIGNAL p KIND profile TICK 3 TS  LABELS node=n1 PAYLOAD cpu 42 @3\\n   0: pillar::sample\\n   1: pillar::main";
        let rows = parse_signal_rows(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].payload,
            "cpu 42 @3\n   0: pillar::sample\n   1: pillar::main"
        );
    }

    #[test]
    fn kind_token_round_trips() {
        for (k, t) in KINDS {
            assert_eq!(kind_token(k), t);
            assert_eq!(kind_from_token(t), Some(k));
        }
        assert_eq!(kind_from_token("bogus"), None);
        assert_eq!(kind_tag_to_token("profile"), "profiles");
    }

    #[test]
    fn extracts_metric_series_sorted_by_tick() {
        let body = "SIGNAL m1 KIND metric TICK 2 TS  LABELS metric=node_cpu_ticks PAYLOAD node_cpu_ticks 9 @2\n\
                    SIGNAL m2 KIND metric TICK 1 TS  LABELS metric=node_cpu_ticks PAYLOAD node_cpu_ticks 4 @1\n\
                    SIGNAL m3 KIND metric TICK 1 TS  LABELS metric=node_mem PAYLOAD node_mem 100 @1";
        let rows = parse_signal_rows(body);
        let series = metric_series(&rows);
        assert_eq!(series.len(), 2);
        let cpu = series.iter().find(|s| s.name == "node_cpu_ticks").unwrap();
        assert_eq!(cpu.points.len(), 2);
        // Sorted ascending by tick: (t1,v4) then (t2,v9).
        assert_eq!(cpu.points[0].tick, 1);
        assert_eq!(cpu.points[0].value, 4.0);
        assert_eq!(cpu.points[1].value, 9.0);
    }

    #[test]
    fn metric_series_falls_back_to_payload_name() {
        let body = "SIGNAL m KIND metric TICK 1 TS  LABELS node=n1 PAYLOAD ingest_bytes 512 @1";
        let series = metric_series(&parse_signal_rows(body));
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].name, "ingest_bytes");
        assert_eq!(series[0].points[0].value, 512.0);
    }

    #[test]
    fn parses_profile_sample_root_to_leaf() {
        let payload =
            "cpu 10 @5\n   0: leaf::fn\n             at src/x.rs:1\n   1: mid::fn\n   2: root::fn";
        let (w, frames) = parse_profile_sample(payload).unwrap();
        assert_eq!(w, 10);
        // Backtrace is leaf-first; we return root-to-leaf.
        assert_eq!(frames, vec!["root::fn", "mid::fn", "leaf::fn"]);
    }

    #[test]
    fn builds_and_flattens_flame_tree() {
        let samples = vec![
            (3, vec!["a".to_owned(), "b".to_owned()]),
            (1, vec!["a".to_owned(), "c".to_owned()]),
        ];
        let root = build_flame(&samples);
        assert_eq!(root.value, 4);
        let a = root.children.iter().find(|c| c.name == "a").unwrap();
        assert_eq!(a.value, 4);
        assert_eq!(a.children.len(), 2);
        let rects = flatten_flame(&root);
        // root(all) + a + b + c = 4 rects.
        assert_eq!(rects.len(), 4);
        let root_rect = &rects[0];
        assert_eq!(root_rect.name, "all");
        assert_eq!(root_rect.width, 1.0);
        // b has weight 3/4, c has weight 1/4; b is laid out before c.
        let b = rects.iter().find(|r| r.name == "b").unwrap();
        let c = rects.iter().find(|r| r.name == "c").unwrap();
        assert!((b.width - 0.75).abs() < 1e-9);
        assert!((c.width - 0.25).abs() < 1e-9);
        assert_eq!(b.depth, 2);
        assert!(c.x >= b.x + b.width - 1e-9);
        assert_eq!(flame_max_depth(&rects), 2);
    }

    #[test]
    fn duration_parses_and_formats_round_trip() {
        assert_eq!(parse_duration("90m"), Some(5400));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("2d"), Some(172_800));
        assert_eq!(parse_duration("45"), Some(45));
        assert_eq!(parse_duration("45s"), Some(45));
        assert_eq!(parse_duration("bogus"), None);
        assert_eq!(parse_duration("10x"), None);
        assert_eq!(format_duration(5400), "90m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(172_800), "2d");
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn psl_hash_round_trips() {
        let text = "select: logs where: level = warn range: now-1h";
        let hash = psl_to_hash(text);
        assert!(hash.starts_with("#query?q="));
        assert_eq!(psl_from_hash(&hash).as_deref(), Some(text));
        assert!(psl_from_hash("#overview").is_none());
    }

    #[test]
    fn exports_csv_and_json() {
        let rows = parse_signal_rows(&sample_body());
        let csv = rows_to_csv(&rows);
        assert!(csv.starts_with("time_ms,tick,kind,labels,payload\n"));
        assert!(csv.contains("1700000000000,7,log,component=federation;level=warn;node=peer1,"));
        let json = rows_to_json(&rows);
        assert!(json.contains("\"kind\":\"log\""));
        assert!(json.contains("\"unix_millis\":1700000000000"));
    }

    #[test]
    fn level_class_maps_severity() {
        assert_eq!(level_class("error"), "lvl-error");
        assert_eq!(level_class("WARN"), "lvl-warn");
        assert_eq!(level_class("info"), "lvl-info");
        assert_eq!(level_class("whatever"), "lvl-info");
    }

    #[test]
    fn histogram_and_level_counts() {
        let rows = parse_signal_rows(&sample_body());
        let h = histogram_buckets(&rows, 4);
        assert_eq!(h.len(), 4);
        assert_eq!(h.iter().sum::<f64>(), 2.0);
        let counts = level_counts(&rows);
        assert_eq!(counts.get("warn"), Some(&1));
        assert_eq!(counts.get("info"), Some(&1));
    }

    #[test]
    fn builder_mutations_round_trip_through_real_grammar() {
        use pillar_observability::{parse_psl, Predicate};
        // Start from the default, add a where predicate, re-serialise, re-parse.
        let mut q = parse_psl(&default_query_text()).unwrap();
        q.where_predicates.push(Predicate::eq("level", "warn"));
        let text = q.to_text();
        assert_eq!(text, "select: logs where: level = warn range: now-1h");
        let back = parse_psl(&text).unwrap();
        assert_eq!(back, q);
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::QueryConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::*;
    use crate::auth::use_auth;
    use crate::portal::{http, input_value};
    use pillar_observability::{parse_psl, CorrelateSpec, Predicate, RelativeRange, SelectClause};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::{HtmlSelectElement, HtmlTextAreaElement};
    use yew::prelude::*;

    /// Which result rendering to prefer where a choice exists (metrics/profiles).
    #[derive(Clone, Copy, PartialEq)]
    enum View {
        Graph,
        Table,
    }

    fn select_value(e: &Event) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            .map(|s| s.value())
            .unwrap_or_default()
    }

    fn textarea_value(e: &InputEvent) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlTextAreaElement>().ok())
            .map(|t| t.value())
            .unwrap_or_default()
    }

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

    fn download(filename: &str, mime: &str, content: &str) {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(document) = window.document() else {
            return;
        };
        let href = format!("data:{mime};charset=utf-8,{}", super::url_encode(content));
        if let Ok(a) = document.create_element("a") {
            let _ = a.set_attribute("href", &href);
            let _ = a.set_attribute("download", filename);
            if let Some(a) = a.dyn_ref::<web_sys::HtmlElement>() {
                a.click();
            }
        }
    }

    /// A stable-ish color for a flame frame, derived from its name.
    fn flame_color(name: &str) -> String {
        let mut h: u32 = 2166136261;
        for b in name.bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(16777619);
        }
        let hue = h % 360;
        format!("hsl({hue}, 55%, 45%)")
    }

    /// The single canonical observability query console: an AST-backed builder
    /// and the raw PSL text as two synchronized views of one query, with
    /// per-kind result rendering (metric graphs, profile flame graphs, log/
    /// trace/metadata rows) and correlation groups.
    #[function_component(QueryConsole)]
    pub fn query_console() -> Html {
        let auth = use_auth();
        let text = use_state(default_query_text);
        let rows = use_state(Vec::<SignalRow>::new);
        let groups = use_state(Vec::<(String, Vec<String>)>::new);
        let msg = use_state(|| None::<(String, bool)>);
        let expanded = use_state(|| None::<String>);
        let label_keys = use_state(Vec::<String>::new);
        let metric_names = use_state(Vec::<String>::new);
        let values = use_state(Vec::<String>::new);
        let live = use_state(|| false);
        let heartbeat = use_state(|| 0u64);
        let view = use_state(|| View::Graph);

        // On mount: seed from a shared #query hash, and load typeahead schema.
        {
            let text = text.clone();
            use_effect_with((), move |_| {
                if let Some(window) = web_sys::window() {
                    if let Ok(hash) = window.location().hash() {
                        if let Some(shared) = psl_from_hash(&hash) {
                            if !shared.trim().is_empty() {
                                text.set(shared);
                            }
                        }
                    }
                }
                || ()
            });
        }
        {
            let (auth, label_keys, metric_names) =
                (auth.clone(), label_keys.clone(), metric_names.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let (label_keys, metric_names) = (label_keys.clone(), metric_names.clone());
                    let base = format!("?token={}", super::url_encode(&token));
                    spawn_local(async move {
                        if let Ok(r) =
                            http("GET", &format!("/portal/obs/live/label-keys{base}"), None).await
                        {
                            if r.ok() {
                                label_keys.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                        if let Ok(r) =
                            http("GET", &format!("/portal/obs/live/metric-names{base}"), None).await
                        {
                            if r.ok() {
                                metric_names.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                    });
                }
                || ()
            });
        }

        // Run the current query. Body is `<token>\n<psl>` (the endpoint reads
        // the token from the first body line, NOT the URL).
        let run = {
            let (auth, text, rows, groups, msg) = (
                auth.clone(),
                text.clone(),
                rows.clone(),
                groups.clone(),
                msg.clone(),
            );
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let psl = (*text).trim().to_owned();
                if psl.is_empty() {
                    return;
                }
                let body = format!("{token}\n{psl}");
                let (rows, groups, msg) = (rows.clone(), groups.clone(), msg.clone());
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/query", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            let parsed = parse_signal_rows(&r.body);
                            let g = parse_correlate_groups(&r.body);
                            if parsed.is_empty() && g.is_empty() {
                                msg.set(Some((
                                    "no matching signals in this window".to_owned(),
                                    true,
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
                        Err(_) => msg.set(Some(("request failed".to_owned(), false))),
                    }
                });
            })
        };

        // Live tail.
        {
            let (live, heartbeat) = (live.clone(), heartbeat.clone());
            use_effect_with(*live, move |enabled| {
                let mut handle: Option<(i32, Closure<dyn FnMut()>)> = None;
                if *enabled {
                    if let Some(window) = web_sys::window() {
                        let heartbeat = heartbeat.clone();
                        let cb = Closure::<dyn FnMut()>::new(move || {
                            heartbeat.set(*heartbeat + 1);
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
        {
            let run = run.clone();
            use_effect_with(*heartbeat, move |h| {
                if *h > 0 {
                    run.emit(());
                }
                || ()
            });
        }

        // Parse the current text into the real AST for the builder projection.
        let parsed = parse_psl(&text);

        // A helper producing a callback that mutates the parsed query and
        // writes `to_text()` back. Each control clones this and applies its
        // own edit closure.
        let apply = {
            let text = text.clone();
            move |edit: Box<dyn Fn(&mut pillar_observability::PslQuery)>| {
                if let Ok(mut q) = parse_psl(&text) {
                    edit(&mut q);
                    text.set(q.to_text());
                }
            }
        };

        let run_click = {
            let run = run.clone();
            Callback::from(move |_: MouseEvent| run.emit(()))
        };
        let on_raw = {
            let text = text.clone();
            Callback::from(move |e: InputEvent| text.set(textarea_value(&e)))
        };
        let toggle_live = {
            let live = live.clone();
            Callback::from(move |_: MouseEvent| live.set(!*live))
        };
        let toggle_view = {
            let view = view.clone();
            Callback::from(move |_: MouseEvent| {
                view.set(match *view {
                    View::Graph => View::Table,
                    View::Table => View::Graph,
                })
            })
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
        let share = {
            let text = text.clone();
            Callback::from(move |_: MouseEvent| {
                if let Some(window) = web_sys::window() {
                    let _ = window.location().set_hash(&psl_to_hash(&text));
                }
            })
        };
        // Fetch label values for a key (typeahead for a value input on focus).
        let load_values = {
            let (auth, values, metric_names) = (auth.clone(), values.clone(), metric_names.clone());
            move |key: String, kind_is_metric: bool| {
                let (auth, values, metric_names) =
                    (auth.clone(), values.clone(), metric_names.clone());
                Callback::from(move |_: FocusEvent| {
                    // Metric-name fields are best served by the metric catalog.
                    if kind_is_metric && (key == "metric" || key == "name") {
                        values.set((*metric_names).clone());
                        return;
                    }
                    let Some(token) = auth.token.clone() else {
                        return;
                    };
                    if key.trim().is_empty() {
                        return;
                    }
                    let url = format!(
                        "/portal/obs/live/label-values?token={}&key={}",
                        super::url_encode(&token),
                        super::url_encode(&key)
                    );
                    let values = values.clone();
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                values.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                    });
                })
            }
        };

        // Click a label chip -> add a `where: key = value` predicate.
        let push_where = {
            let text = text.clone();
            move |key: String, value: String| {
                let text = text.clone();
                Callback::from(move |_: MouseEvent| {
                    if let Ok(mut q) = parse_psl(&text) {
                        let pred = Predicate::eq(key.clone(), value.clone());
                        if !q.where_predicates.contains(&pred) {
                            q.where_predicates.push(pred);
                            text.set(q.to_text());
                        }
                    }
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

        let builder = match &parsed {
            Ok(q) => render_builder(q, &apply, &label_keys, &metric_names, &values, &load_values),
            Err(e) => html! {
                <p class="msg-err">{ format!("PSL parse error: {} — edit the raw query below.", e.0) }</p>
            },
        };

        html! {
            <div class="tile" id="query-console">
                <h3>{ "Query" }</h3>
                <p class="hint">{ "One console over the live timeseries store. The builder and \
                    the raw PSL below are two views of the same query — edit either. Metrics \
                    graph by default, profiles render a flame graph, correlations show every \
                    member kind together." }</p>

                { builder }

                // ---- Raw PSL (canonical source of truth) ----
                <label class="query-rawlabel">{ "raw PSL" }</label>
                <textarea id="query-raw" class="mono query-raw" rows="2"
                    value={(*text).clone()} oninput={on_raw} />

                <div class="row query-actions">
                    <button type="button" id="query-run" onclick={run_click}>{ "Run" }</button>
                    <button type="button" id="query-live"
                        class={if *live {"active"} else {""}} onclick={toggle_live}>
                        { if *live { "Live: on" } else { "Live: off" } }
                    </button>
                    <button type="button" id="query-view" onclick={toggle_view}>
                        { match *view { View::Graph => "View: graph", View::Table => "View: table" } }
                    </button>
                    <button type="button" id="query-csv" onclick={export_csv}>{ "Export CSV" }</button>
                    <button type="button" id="query-json" onclick={export_json}>{ "Export JSON" }</button>
                    <button type="button" id="query-share" onclick={share}>{ "Shareable link" }</button>
                </div>

                { message_line("query-msg", &msg) }

                // ---- Results ----
                if groups.is_empty() {
                    { render_kind_sections(&rows, *view, &push_where, &toggle_expand, &expanded) }
                } else {
                    <div class="query-correlations">
                        <label>{ format!("{} correlation group(s)", groups.len()) }</label>
                        { for groups.iter().map(|(anchor, members)| {
                            let member_rows: Vec<SignalRow> = rows
                                .iter()
                                .filter(|r| members.contains(&r.id) || &r.id == anchor)
                                .cloned()
                                .collect();
                            html! {
                                <div class="query-group">
                                    <p class="query-group-head mono">
                                        { format!("anchor {}", short_id(anchor)) }
                                    </p>
                                    { render_kind_sections(&member_rows, *view, &push_where, &toggle_expand, &expanded) }
                                </div>
                            }
                        }) }
                    </div>
                }
            </div>
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn render_builder(
        q: &pillar_observability::PslQuery,
        apply: &(impl Fn(Box<dyn Fn(&mut pillar_observability::PslQuery)>) + Clone + 'static),
        label_keys: &[String],
        metric_names: &[String],
        values: &[String],
        load_values: &(impl Fn(String, bool) -> Callback<FocusEvent> + Clone + 'static),
    ) -> Html {
        let selects = q.selects.clone();
        let selects_len = selects.len();
        let add_select = {
            let apply = apply.clone();
            Callback::from(move |_: MouseEvent| {
                apply(Box::new(|q| {
                    q.selects
                        .push(SelectClause::new(SignalKind::Log, Vec::new()));
                }));
            })
        };
        let add_where = {
            let apply = apply.clone();
            Callback::from(move |_: MouseEvent| {
                apply(Box::new(|q| {
                    q.where_predicates.push(Predicate::eq("", ""));
                }));
            })
        };
        let correlate_on = q.correlate.is_some();
        let toggle_correlate = {
            let apply = apply.clone();
            let first_kind = selects.first().map(|s| s.kind).unwrap_or(SignalKind::Log);
            Callback::from(move |_: MouseEvent| {
                apply(Box::new(move |q| {
                    if q.correlate.is_some() {
                        q.correlate = None;
                    } else {
                        q.correlate = Some(CorrelateSpec {
                            window_seconds: 60,
                            anchor: first_kind,
                        });
                    }
                }));
            })
        };

        html! {
            <div class="query-builder">
                // ---- select clauses (multi-kind / correlation) ----
                <div class="query-section">
                    <div class="query-section-head">
                        <label>{ "select" }</label>
                        <button type="button" class="query-add" onclick={add_select}>{ "+ select" }</button>
                    </div>
                    { for selects.iter().enumerate().map(|(si, clause)| {
                        render_select_clause(si, clause, selects_len, apply, label_keys, metric_names, values, load_values)
                    }) }
                </div>

                // ---- global where predicates ----
                <div class="query-section">
                    <div class="query-section-head">
                        <label>{ "where" }</label>
                        <button type="button" class="query-add" onclick={add_where}>{ "+ filter" }</button>
                    </div>
                    { for q.where_predicates.iter().enumerate().map(|(pi, pred)| {
                        render_where_predicate(pi, pred, apply, label_keys, metric_names, values, load_values)
                    }) }
                    if q.where_predicates.is_empty() {
                        <p class="hint">{ "no global filters" }</p>
                    }
                </div>

                // ---- range ----
                { render_range(q.range, apply) }

                // ---- correlate ----
                <div class="query-section">
                    <div class="query-section-head">
                        <label>{ "correlate" }</label>
                        <button type="button"
                            class={if correlate_on {"query-add active"} else {"query-add"}}
                            onclick={toggle_correlate}>
                            { if correlate_on { "on" } else { "off" } }
                        </button>
                    </div>
                    if let Some(spec) = &q.correlate {
                        { render_correlate(spec, apply) }
                    }
                </div>
            </div>
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn render_select_clause(
        si: usize,
        clause: &SelectClause,
        selects_len: usize,
        apply: &(impl Fn(Box<dyn Fn(&mut pillar_observability::PslQuery)>) + Clone + 'static),
        label_keys: &[String],
        metric_names: &[String],
        values: &[String],
        load_values: &(impl Fn(String, bool) -> Callback<FocusEvent> + Clone + 'static),
    ) -> Html {
        let kind_is_metric = clause.kind == SignalKind::Metric;
        let on_kind = {
            let apply = apply.clone();
            Callback::from(move |e: Event| {
                let token = select_value(&e);
                if let Some(kind) = kind_from_token(&token) {
                    apply(Box::new(move |q| {
                        if let Some(c) = q.selects.get_mut(si) {
                            c.kind = kind;
                        }
                    }));
                }
            })
        };
        let add_pred = {
            let apply = apply.clone();
            Callback::from(move |_: MouseEvent| {
                apply(Box::new(move |q| {
                    if let Some(c) = q.selects.get_mut(si) {
                        c.predicates.push(Predicate::eq("", ""));
                    }
                }));
            })
        };
        let remove_select = {
            let apply = apply.clone();
            Callback::from(move |_: MouseEvent| {
                apply(Box::new(move |q| {
                    if q.selects.len() > 1 {
                        q.selects.remove(si);
                    }
                }));
            })
        };

        html! {
            <div class="query-select">
                <select class="query-kind" onchange={on_kind}>
                    { for KINDS.iter().map(|(k, t)| html!{
                        <option value={*t} selected={clause.kind==*k}>{ *t }</option>
                    }) }
                </select>
                <span class="query-paren">{ "(" }</span>
                <div class="query-preds">
                    { for clause.predicates.iter().enumerate().map(|(pi, pred)| {
                        render_predicate(
                            pred,
                            kind_is_metric,
                            label_keys,
                            metric_names,
                            values,
                            load_values,
                            {
                                let apply = apply.clone();
                                Callback::from(move |np: Predicate| {
                                    apply(Box::new(move |q| {
                                        if let Some(c) = q.selects.get_mut(si) {
                                            if let Some(p) = c.predicates.get_mut(pi) { *p = np.clone(); }
                                        }
                                    }));
                                })
                            },
                            {
                                let apply = apply.clone();
                                Callback::from(move |_: MouseEvent| {
                                    apply(Box::new(move |q| {
                                        if let Some(c) = q.selects.get_mut(si) {
                                            if pi < c.predicates.len() { c.predicates.remove(pi); }
                                        }
                                    }));
                                })
                            },
                        )
                    }) }
                </div>
                <span class="query-paren">{ ")" }</span>
                <button type="button" class="query-add" onclick={add_pred}>{ "+ filter" }</button>
                if selects_len > 1 {
                    <button type="button" class="chip-x" onclick={remove_select} title="remove select">{ "×" }</button>
                }
            </div>
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn render_where_predicate(
        pi: usize,
        pred: &Predicate,
        apply: &(impl Fn(Box<dyn Fn(&mut pillar_observability::PslQuery)>) + Clone + 'static),
        label_keys: &[String],
        metric_names: &[String],
        values: &[String],
        load_values: &(impl Fn(String, bool) -> Callback<FocusEvent> + Clone + 'static),
    ) -> Html {
        render_predicate(
            pred,
            false,
            label_keys,
            metric_names,
            values,
            load_values,
            {
                let apply = apply.clone();
                Callback::from(move |np: Predicate| {
                    apply(Box::new(move |q| {
                        if let Some(p) = q.where_predicates.get_mut(pi) {
                            *p = np.clone();
                        }
                    }));
                })
            },
            {
                let apply = apply.clone();
                Callback::from(move |_: MouseEvent| {
                    apply(Box::new(move |q| {
                        if pi < q.where_predicates.len() {
                            q.where_predicates.remove(pi);
                        }
                    }));
                })
            },
        )
    }

    /// One predicate row: key combobox, op select (`=`/`=~`), value combobox,
    /// remove. `on_change` receives the rebuilt predicate; `on_remove` drops it.
    #[allow(clippy::too_many_arguments)]
    fn render_predicate(
        pred: &Predicate,
        kind_is_metric: bool,
        label_keys: &[String],
        metric_names: &[String],
        values: &[String],
        load_values: &(impl Fn(String, bool) -> Callback<FocusEvent> + Clone + 'static),
        on_change: Callback<Predicate>,
        on_remove: Callback<MouseEvent>,
    ) -> Html {
        use pillar_observability::psl::PredOp;
        let key = pred.key.clone();
        let value = pred.value.clone();
        let is_match = pred.op == PredOp::Match;

        let on_key = {
            let (on_change, value, is_match) = (on_change.clone(), value.clone(), is_match);
            Callback::from(move |e: InputEvent| {
                let k = input_value(&e);
                on_change.emit(make_pred(&k, &value, is_match));
            })
        };
        let on_op = {
            let (on_change, key, value) = (on_change.clone(), key.clone(), value.clone());
            Callback::from(move |e: Event| {
                let m = select_value(&e) == "=~";
                on_change.emit(make_pred(&key, &value, m));
            })
        };
        let on_value = {
            let (on_change, key, is_match) = (on_change.clone(), key.clone(), is_match);
            Callback::from(move |e: InputEvent| {
                let v = input_value(&e);
                on_change.emit(make_pred(&key, &v, is_match));
            })
        };
        let onfocus = load_values(key.clone(), kind_is_metric);

        // Value typeahead: metric names for a metric name field, else label
        // values loaded on focus. Keys use the label-keys catalog.
        let value_options: Vec<String> = if kind_is_metric && (key == "metric" || key == "name") {
            metric_names.to_vec()
        } else {
            values.to_vec()
        };

        html! {
            <div class="query-pred">
                <input class="query-key" list="query-keylist" placeholder="label"
                    value={key.clone()} oninput={on_key} />
                <select class="query-op" onchange={on_op}>
                    <option value="=" selected={!is_match}>{ "=" }</option>
                    <option value="=~" selected={is_match}>{ "=~" }</option>
                </select>
                <input class="query-val" list="query-vallist" placeholder="value"
                    value={value} oninput={on_value} onfocus={onfocus} />
                <button type="button" class="chip-x" onclick={on_remove} title="remove filter">{ "×" }</button>

                <datalist id="query-keylist">
                    { for label_keys.iter().map(|k| html!{ <option value={k.clone()} /> }) }
                </datalist>
                <datalist id="query-vallist">
                    { for value_options.iter().map(|v| html!{ <option value={v.clone()} /> }) }
                </datalist>
            </div>
        }
    }

    fn make_pred(key: &str, value: &str, is_match: bool) -> Predicate {
        if is_match {
            Predicate::matches(key, value)
        } else {
            Predicate::eq(key, value)
        }
    }

    fn render_range(
        range: RelativeRange,
        apply: &(impl Fn(Box<dyn Fn(&mut pillar_observability::PslQuery)>) + Clone + 'static),
    ) -> Html {
        let current = format_duration(range.seconds);
        let on_range = {
            let apply = apply.clone();
            Callback::from(move |e: InputEvent| {
                let raw = input_value(&e);
                if let Some(secs) = parse_duration(&raw) {
                    apply(Box::new(move |q| q.range = RelativeRange::seconds(secs)));
                }
            })
        };
        let preset_buttons = [
            ("15m", 900u64),
            ("1h", 3600),
            ("6h", 21600),
            ("24h", 86400),
            ("7d", 604800),
        ];
        html! {
            <div class="query-section query-range">
                <label>{ "range" }</label>
                <span class="query-nowdash mono">{ "now-" }</span>
                <input class="query-rangeinput mono" value={current} oninput={on_range}
                    placeholder="1h / 90m / 3600s / 2d" />
                { for preset_buttons.into_iter().map(|(lbl, secs)| {
                    let apply = apply.clone();
                    let cb = Callback::from(move |_: MouseEvent| {
                        apply(Box::new(move |q| q.range = RelativeRange::seconds(secs)));
                    });
                    html!{ <button type="button" class="query-preset" onclick={cb}>{ lbl }</button> }
                }) }
            </div>
        }
    }

    fn render_correlate(
        spec: &CorrelateSpec,
        apply: &(impl Fn(Box<dyn Fn(&mut pillar_observability::PslQuery)>) + Clone + 'static),
    ) -> Html {
        let window = format_duration(spec.window_seconds);
        let anchor = spec.anchor;
        let on_window = {
            let apply = apply.clone();
            Callback::from(move |e: InputEvent| {
                let raw = input_value(&e);
                if let Some(secs) = parse_duration(&raw) {
                    apply(Box::new(move |q| {
                        if let Some(c) = q.correlate.as_mut() {
                            c.window_seconds = secs;
                        }
                    }));
                }
            })
        };
        let on_anchor = {
            let apply = apply.clone();
            Callback::from(move |e: Event| {
                if let Some(kind) = kind_from_token(&select_value(&e)) {
                    apply(Box::new(move |q| {
                        if let Some(c) = q.correlate.as_mut() {
                            c.anchor = kind;
                        }
                    }));
                }
            })
        };
        html! {
            <div class="query-correlate">
                <label>{ "window" }</label>
                <input class="query-rangeinput mono" value={window} oninput={on_window}
                    placeholder="60s / 5m" />
                <label>{ "anchor" }</label>
                <select class="query-kind" onchange={on_anchor}>
                    { for KINDS.iter().map(|(k, t)| html!{
                        <option value={*t} selected={anchor==*k}>{ *t }</option>
                    }) }
                </select>
            </div>
        }
    }

    /// Render each kind present in `rows` with its default visualization.
    fn render_kind_sections(
        rows: &[SignalRow],
        view: View,
        push_where: &(impl Fn(String, String) -> Callback<MouseEvent> + Clone + 'static),
        toggle_expand: &(impl Fn(String) -> Callback<MouseEvent> + Clone + 'static),
        expanded: &UseStateHandle<Option<String>>,
    ) -> Html {
        if rows.is_empty() {
            return html! {};
        }
        let metrics: Vec<SignalRow> = rows
            .iter()
            .filter(|r| r.kind == "metric")
            .cloned()
            .collect();
        let profiles: Vec<SignalRow> = rows
            .iter()
            .filter(|r| r.kind == "profile")
            .cloned()
            .collect();
        let others: Vec<SignalRow> = rows
            .iter()
            .filter(|r| r.kind != "metric" && r.kind != "profile")
            .cloned()
            .collect();

        html! {
            <>
                if !metrics.is_empty() {
                    { render_metrics(&metrics, view) }
                }
                if !profiles.is_empty() {
                    { render_profiles(&profiles, view) }
                }
                if !others.is_empty() {
                    { render_rows(&others, push_where, toggle_expand, expanded) }
                }
            </>
        }
    }

    fn render_metrics(rows: &[SignalRow], view: View) -> Html {
        let series = metric_series(rows);
        if view == View::Table {
            return html! {
                <div class="query-metrics">
                    <label>{ "metrics" }</label>
                    <table class="query-table">
                        <thead><tr><th>{ "series" }</th><th>{ "tick" }</th><th>{ "value" }</th></tr></thead>
                        <tbody>
                        { for series.iter().flat_map(|s| {
                            s.points.iter().map(move |p| html!{
                                <tr><td>{ s.name.clone() }</td><td>{ p.tick }</td>
                                    <td class="mono">{ p.value }</td></tr>
                            })
                        }) }
                        </tbody>
                    </table>
                </div>
            };
        }
        html! {
            <div class="query-metrics">
                <label>{ "metrics" }</label>
                { for series.iter().map(|s| {
                    let vals: Vec<f64> = s.points.iter().map(|p| p.value).collect();
                    let last = s.points.last().map(|p| p.value).unwrap_or(0.0);
                    html! {
                        <div class="query-metric">
                            <div class="query-metric-head">
                                <span class="mono">{ s.name.clone() }</span>
                                <span class="query-metric-last">{ format!("last {last}") }</span>
                            </div>
                            <crate::components::chart::Chart values={vals}
                                kind={crate::components::chart::ChartKind::Line} />
                        </div>
                    }
                }) }
            </div>
        }
    }

    fn render_profiles(rows: &[SignalRow], view: View) -> Html {
        let samples: Vec<(u64, Vec<String>)> = rows
            .iter()
            .filter_map(|r| parse_profile_sample(&r.payload))
            .collect();
        let root = build_flame(&samples);
        let rects = flatten_flame(&root);
        if view == View::Table || rects.is_empty() {
            return html! {
                <div class="query-profiles">
                    <label>{ "profiles" }</label>
                    <table class="query-table">
                        <thead><tr><th>{ "frame" }</th><th>{ "depth" }</th><th>{ "weight" }</th></tr></thead>
                        <tbody>
                        { for rects.iter().map(|r| html!{
                            <tr><td class="mono">{ r.name.clone() }</td><td>{ r.depth }</td><td>{ r.value }</td></tr>
                        }) }
                        </tbody>
                    </table>
                </div>
            };
        }
        let max_depth = flame_max_depth(&rects);
        let row_h = 18.0_f64;
        let width = 720.0_f64;
        let height = (max_depth as f64 + 1.0) * row_h;
        let total = root.value.max(1);
        html! {
            <div class="query-profiles">
                <label>{ format!("profile flame graph ({} samples)", samples.len()) }</label>
                <svg class="flamegraph" width={width.to_string()} height={height.to_string()}
                    viewBox={format!("0 0 {width} {height}")}>
                    { for rects.iter().map(|r| {
                        let x = r.x * width;
                        let w = (r.width * width).max(0.5);
                        // Depth 0 (root) at the bottom row.
                        let y = height - (r.depth as f64 + 1.0) * row_h;
                        let pct = 100.0 * r.value as f64 / total as f64;
                        let show_text = w > 42.0;
                        html! {
                            <g class="flame-cell">
                                <rect x={x.to_string()} y={y.to_string()}
                                    width={w.to_string()} height={(row_h - 1.0).to_string()}
                                    fill={flame_color(&r.name)} rx="1">
                                    <title>{ format!("{} — {} ({:.1}%)", r.name, r.value, pct) }</title>
                                </rect>
                                if show_text {
                                    <text x={(x + 3.0).to_string()} y={(y + row_h - 6.0).to_string()}
                                        class="flame-label">{ truncate(&r.name, (w / 6.5) as usize) }</text>
                                }
                            </g>
                        }
                    }) }
                </svg>
            </div>
        }
    }

    fn render_rows(
        rows: &[SignalRow],
        push_where: &(impl Fn(String, String) -> Callback<MouseEvent> + Clone + 'static),
        toggle_expand: &(impl Fn(String) -> Callback<MouseEvent> + Clone + 'static),
        expanded: &UseStateHandle<Option<String>>,
    ) -> Html {
        // Log-volume histogram + severity summary when logs are present.
        let logs: Vec<SignalRow> = rows.iter().filter(|r| r.kind == "log").cloned().collect();
        let hist = histogram_buckets(&logs, 24);
        let lcounts = level_counts(&logs);

        html! {
            <div class="query-rows-wrap">
                if !logs.is_empty() {
                    <div class="logs-hist">
                        <crate::primitives::Chart values={hist}
                            kind={crate::primitives::ChartKind::Bar} width={480.0} height={48.0} />
                        <div class="row logs-levelsum">
                            { for lcounts.iter().map(|(lvl,n)| html!{
                                <span class={classes!("chip", level_class(lvl))}>{ format!("{lvl}: {n}") }</span>
                            }) }
                        </div>
                    </div>
                }
                <div class="logs-results">
                    { for rows.iter().map(|r| {
                        let lvl = r.level().unwrap_or("");
                        let is_open = expanded.as_ref() == Some(&r.id);
                        html! {
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
                                            onclick={push_where(k2,v2)}>{ format!("{k}={v}") }</button> }
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
                                            <span class="logs-field-v mono">{ short_id(&r.id) }</span>
                                        </div>
                                    </div>
                                }
                            </div>
                        }
                    }) }
                </div>
            </div>
        }
    }

    fn short_id(id: &str) -> String {
        if id.len() > 12 {
            format!("{}…", &id[..12])
        } else {
            id.to_owned()
        }
    }

    fn truncate(s: &str, max: usize) -> String {
        if max == 0 {
            return String::new();
        }
        if s.chars().count() > max {
            s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
        } else {
            s.to_owned()
        }
    }

    fn message_line(id: &str, msg: &UseStateHandle<Option<(String, bool)>>) -> Html {
        match &**msg {
            Some((text, ok)) => html! {
                <p id={id.to_owned()} class={if *ok {"msg-ok"} else {"msg-err"}}>{ text.clone() }</p>
            },
            None => html! {},
        }
    }
}
