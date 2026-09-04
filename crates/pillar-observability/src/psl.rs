//! **PSL** — the Pillar (compact) query surface, plus a structured-AST
//! builder and the query engine that executes both surfaces over the real
//! [`crate::CorrelationIndex`] / [`crate::TimeseriesStore`].
//!
//! PSL has TWO surfaces over ONE [`PslQuery`] AST, never two parallel query
//! models:
//!
//! - a **compact text surface** ([`parse`]) — e.g.
//!   `select: metrics(name = ingest_bandwidth), logs where: cell =
//!   testpillarcell range: now-1d correlate: { window: 1s, anchor: metrics }`;
//! - a **structured surface** ([`PslQueryBuilder`]) — the same AST built
//!   field-by-field, the shape the Yew query builders compose against without
//!   ever round-tripping through text.
//!
//! `PslQuery` derives `PartialEq`, and [`PslQuery::to_text`] gives a single
//! canonical serialization either surface can produce — so
//! `parse(text)?.to_text() == builder.build()?.to_text()` (and the two ASTs
//! themselves are `==`) proves **surface equivalence**: text and structured
//! construction of the same query are indistinguishable to the engine below.
//!
//! [`execute`] runs a `PslQuery`'s `select`/`where`/`range` as a signal-set
//! filter over a real [`crate::TimeseriesStore`], then (if `correlate` is
//! present) groups the matched anchor-kind signals with their causal-thread
//! peers via the real [`crate::CorrelationIndex`], bounded to the declared
//! time window — never a second, parallel correlation model.

use std::collections::BTreeSet;
use std::fmt;

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::CorrelationIndex;

/// A parse or build error naming exactly what was wrong and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PslError(pub String);

impl fmt::Display for PslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "psl: {}", self.0)
    }
}

impl std::error::Error for PslError {}

/// An equality predicate on a signal's label: `key = value`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Predicate {
    /// The label key to match.
    pub key: String,
    /// The value the label must equal.
    pub value: String,
}

impl Predicate {
    /// A `key = value` equality predicate.
    #[must_use]
    pub fn eq(key: impl Into<String>, value: impl Into<String>) -> Self {
        Predicate {
            key: key.into(),
            value: value.into(),
        }
    }

    fn to_text(&self) -> String {
        format!("{} = {}", self.key, self.value)
    }
}

/// One `select:` item: a signal kind plus its own (kind-scoped) predicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectClause {
    /// The signal kind this clause selects.
    pub kind: SignalKind,
    /// The predicates scoped to this kind (an `AND` of equalities).
    pub predicates: Vec<Predicate>,
}

impl SelectClause {
    /// A select clause for `kind` scoped to `predicates`.
    #[must_use]
    pub fn new(kind: SignalKind, predicates: Vec<Predicate>) -> Self {
        SelectClause { kind, predicates }
    }

    fn to_text(&self) -> String {
        if self.predicates.is_empty() {
            kind_name(self.kind).to_string()
        } else {
            let preds = self
                .predicates
                .iter()
                .map(Predicate::to_text)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}({})", kind_name(self.kind), preds)
        }
    }
}

/// `range: now-<N><unit>` — a relative window ending "now", expressed in
/// seconds (this crate's ticks are already second-granular logical time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelativeRange {
    /// The window length in seconds, ending at "now".
    pub seconds: u64,
}

impl RelativeRange {
    /// A relative range of `seconds` ending "now".
    #[must_use]
    pub fn seconds(seconds: u64) -> Self {
        RelativeRange { seconds }
    }

    fn to_text(self) -> String {
        format!("now-{}", duration_to_text(self.seconds))
    }
}

/// `correlate: { window: <duration>, anchor: <kind> }` — group the matched
/// `anchor`-kind signals with their causal-thread peers within `window`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelateSpec {
    /// The correlation time window, in seconds.
    pub window_seconds: u64,
    /// The signal kind whose matches become correlation-group anchors.
    pub anchor: SignalKind,
}

impl CorrelateSpec {
    fn to_text(self) -> String {
        format!(
            "{{ window: {}, anchor: {} }}",
            duration_to_text(self.window_seconds),
            kind_name(self.anchor)
        )
    }
}

/// The ONE PSL AST both surfaces (text, structured) produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PslQuery {
    /// The `select:` clauses (one per selected signal kind).
    pub selects: Vec<SelectClause>,
    /// The `where:` predicates, applied across every selected kind.
    pub where_predicates: Vec<Predicate>,
    /// The `range:` clause.
    pub range: RelativeRange,
    /// The optional `correlate:` clause.
    pub correlate: Option<CorrelateSpec>,
}

impl PslQuery {
    /// The canonical text serialization of this query — the SAME string
    /// [`parse`] would accept, so `parse(q.to_text())? == q`. Used to prove
    /// [`SelectClause`]/structured-vs-text surface equivalence.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("select: ");
        out.push_str(
            &self
                .selects
                .iter()
                .map(SelectClause::to_text)
                .collect::<Vec<_>>()
                .join(", "),
        );
        if !self.where_predicates.is_empty() {
            out.push_str(" where: ");
            out.push_str(
                &self
                    .where_predicates
                    .iter()
                    .map(Predicate::to_text)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        out.push_str(" range: ");
        out.push_str(&self.range.to_text());
        if let Some(c) = self.correlate {
            out.push_str(" correlate: ");
            out.push_str(&c.to_text());
        }
        out
    }
}

/// The structured surface: builds a [`PslQuery`] field-by-field — the shape
/// the Yew query builders compose against, producing the SAME AST [`parse`]
/// would from the equivalent text.
#[derive(Clone, Debug, Default)]
pub struct PslQueryBuilder {
    selects: Vec<SelectClause>,
    where_predicates: Vec<Predicate>,
    range: Option<RelativeRange>,
    correlate: Option<CorrelateSpec>,
}

impl PslQueryBuilder {
    /// A fresh, empty builder.
    #[must_use]
    pub fn new() -> Self {
        PslQueryBuilder::default()
    }

    /// Add a `select:` clause for `kind` scoped to `predicates`.
    #[must_use]
    pub fn select(mut self, kind: SignalKind, predicates: Vec<Predicate>) -> Self {
        self.selects.push(SelectClause::new(kind, predicates));
        self
    }

    /// Add a `where:` equality predicate applied across every selected kind.
    #[must_use]
    pub fn where_eq(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.where_predicates.push(Predicate::eq(key, value));
        self
    }

    /// Set the `range:` clause to `seconds` ending "now".
    #[must_use]
    pub fn range_relative(mut self, seconds: u64) -> Self {
        self.range = Some(RelativeRange::seconds(seconds));
        self
    }

    /// Set the `correlate:` clause.
    #[must_use]
    pub fn correlate(mut self, window_seconds: u64, anchor: SignalKind) -> Self {
        self.correlate = Some(CorrelateSpec {
            window_seconds,
            anchor,
        });
        self
    }

    /// Finish the build. Fails if no `select` was given or `range` was never
    /// set — the two fields every PSL query requires.
    pub fn build(self) -> Result<PslQuery, PslError> {
        if self.selects.is_empty() {
            return Err(PslError("select clause is required".to_string()));
        }
        let range = self
            .range
            .ok_or_else(|| PslError("range clause is required".to_string()))?;
        Ok(PslQuery {
            selects: self.selects,
            where_predicates: self.where_predicates,
            range,
            correlate: self.correlate,
        })
    }
}

fn kind_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Metric => "metrics",
        SignalKind::Log => "logs",
        SignalKind::TraceSpan => "traces",
        SignalKind::ProfileSample => "profiles",
        SignalKind::MetadataSample => "metadata",
    }
}

fn kind_from_name(name: &str) -> Result<SignalKind, PslError> {
    Ok(match name {
        "metrics" => SignalKind::Metric,
        "logs" => SignalKind::Log,
        "traces" => SignalKind::TraceSpan,
        "profiles" => SignalKind::ProfileSample,
        "metadata" => SignalKind::MetadataSample,
        other => return Err(PslError(format!("unknown signal kind '{other}'"))),
    })
}

/// Render a duration in seconds back to the largest whole unit (`d`/`h`/`m`/
/// `s`) — the inverse of the unit parsing in [`parse_duration_seconds`], so a
/// round-tripped duration reads back exactly as it was written for the
/// canonical durations PSL queries actually use.
fn duration_to_text(seconds: u64) -> String {
    const DAY: u64 = 86_400;
    const HOUR: u64 = 3_600;
    const MIN: u64 = 60;
    if seconds != 0 && seconds % DAY == 0 {
        format!("{}d", seconds / DAY)
    } else if seconds != 0 && seconds % HOUR == 0 {
        format!("{}h", seconds / HOUR)
    } else if seconds != 0 && seconds % MIN == 0 {
        format!("{}m", seconds / MIN)
    } else {
        format!("{seconds}s")
    }
}

/// Parse a `<number><unit>` duration (`1d`, `30m`, `1s`, …) to seconds.
fn parse_duration_seconds(s: &str) -> Result<u64, PslError> {
    let s = s.trim();
    let unit_start = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| PslError(format!("duration '{s}' has no unit")))?;
    let (num, unit) = s.split_at(unit_start);
    let num: u64 = num
        .parse()
        .map_err(|_| PslError(format!("duration '{s}' has an invalid number")))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        other => return Err(PslError(format!("duration '{s}' has unknown unit '{other}'"))),
    };
    Ok(num * mult)
}

/// Split `s` at the first occurrence of any of `keywords`, returning
/// `(before, Some(matched_keyword_and_rest))` or `(s, None)` if none occur.
fn split_at_first_keyword<'a>(s: &'a str, keywords: &[&'a str]) -> (&'a str, Option<(&'a str, &'a str)>) {
    let mut best: Option<(usize, &str)> = None;
    for kw in keywords {
        if let Some(idx) = s.find(kw) {
            if best.map(|(bi, _)| idx < bi).unwrap_or(true) {
                best = Some((idx, kw));
            }
        }
    }
    match best {
        Some((idx, kw)) => (&s[..idx], Some((kw, &s[idx + kw.len()..]))),
        None => (s, None),
    }
}

/// Parse a `select:` body: a comma-separated list of `kind[(predicates)]`.
fn parse_selects(body: &str) -> Result<Vec<SelectClause>, PslError> {
    let body = body.trim();
    if body.is_empty() {
        return Err(PslError("select clause must name at least one kind".to_string()));
    }
    let mut selects = Vec::new();
    // Split on top-level commas (not inside parens).
    for item in split_top_level(body, ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (name, predicates) = if let Some(open) = item.find('(') {
            let name = item[..open].trim();
            let close = item
                .rfind(')')
                .ok_or_else(|| PslError(format!("select item '{item}' missing closing ')'")))?;
            let inner = &item[open + 1..close];
            (name, parse_predicates(inner)?)
        } else {
            (item, Vec::new())
        };
        selects.push(SelectClause::new(kind_from_name(name)?, predicates));
    }
    if selects.is_empty() {
        return Err(PslError("select clause must name at least one kind".to_string()));
    }
    Ok(selects)
}

/// Parse a comma-separated `key = value` predicate list.
fn parse_predicates(body: &str) -> Result<Vec<Predicate>, PslError> {
    let body = body.trim();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item in split_top_level(body, ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.splitn(2, '=');
        let key = parts
            .next()
            .ok_or_else(|| PslError(format!("predicate '{item}' missing '='")))?
            .trim();
        let value = parts
            .next()
            .ok_or_else(|| PslError(format!("predicate '{item}' missing value")))?
            .trim();
        if key.is_empty() || value.is_empty() {
            return Err(PslError(format!("predicate '{item}' is malformed")));
        }
        out.push(Predicate::eq(key, value));
    }
    Ok(out)
}

/// Parse a `range:` body: `now-<duration>`.
fn parse_range(body: &str) -> Result<RelativeRange, PslError> {
    let body = body.trim();
    let rest = body
        .strip_prefix("now-")
        .ok_or_else(|| PslError(format!("range '{body}' must be of the form now-<duration>")))?;
    Ok(RelativeRange::seconds(parse_duration_seconds(rest)?))
}

/// Parse a `correlate:` body: `{ window: <duration>, anchor: <kind> }`.
fn parse_correlate(body: &str) -> Result<CorrelateSpec, PslError> {
    let body = body.trim();
    let inner = body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| PslError(format!("correlate '{body}' must be wrapped in {{ }}")))?;
    let mut window = None;
    let mut anchor = None;
    for item in split_top_level(inner, ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.splitn(2, ':');
        let key = parts
            .next()
            .ok_or_else(|| PslError(format!("correlate field '{item}' missing ':'")))?
            .trim();
        let value = parts
            .next()
            .ok_or_else(|| PslError(format!("correlate field '{item}' missing value")))?
            .trim();
        match key {
            "window" => window = Some(parse_duration_seconds(value)?),
            "anchor" => anchor = Some(kind_from_name(value)?),
            other => return Err(PslError(format!("unknown correlate field '{other}'"))),
        }
    }
    Ok(CorrelateSpec {
        window_seconds: window
            .ok_or_else(|| PslError("correlate missing 'window'".to_string()))?,
        anchor: anchor.ok_or_else(|| PslError("correlate missing 'anchor'".to_string()))?,
    })
}

/// Split `s` on every top-level occurrence of `sep` — one NOT nested inside
/// `(`/`)` or `{`/`}` — so a predicate list inside `select: metrics(a = b)`
/// isn't fractured by the comma-separated select list around it.
fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '{' => depth += 1,
            ')' | '}' => depth -= 1,
            c if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Parse the compact PSL text surface into a [`PslQuery`].
///
/// Grammar (fixed clause order, `where`/`correlate` optional):
/// `select: <kind[(pred,...)], ...> [where: <pred, ...>] range: now-<dur>
/// [correlate: { window: <dur>, anchor: <kind> }]`
pub fn parse(input: &str) -> Result<PslQuery, PslError> {
    let input = input.trim();
    let rest = input
        .strip_prefix("select:")
        .ok_or_else(|| PslError("query must start with 'select:'".to_string()))?;

    let (select_body, after_select) =
        split_at_first_keyword(rest, &["where:", "range:", "correlate:"]);
    let selects = parse_selects(select_body)?;

    let (kw, rest) = after_select
        .ok_or_else(|| PslError("query is missing a 'range:' clause".to_string()))?;

    let (where_predicates, kw, rest) = if kw == "where:" {
        let (where_body, after_where) = split_at_first_keyword(rest, &["range:", "correlate:"]);
        let preds = parse_predicates(where_body)?;
        let (kw, rest) = after_where
            .ok_or_else(|| PslError("query is missing a 'range:' clause".to_string()))?;
        (preds, kw, rest)
    } else {
        (Vec::new(), kw, rest)
    };

    if kw != "range:" {
        return Err(PslError(format!("expected 'range:', found '{kw}'")));
    }
    let (range_body, after_range) = split_at_first_keyword(rest, &["correlate:"]);
    let range = parse_range(range_body)?;

    let correlate = match after_range {
        Some((_kw, rest)) => Some(parse_correlate(rest)?),
        None => None,
    };

    Ok(PslQuery {
        selects,
        where_predicates,
        range,
        correlate,
    })
}

/// A group of signals correlated with an `anchor` signal (the correlate
/// clause's anchor kind), gathered via the real [`CorrelationIndex`] and
/// bounded to the declared time window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrelationGroup {
    /// The anchor-kind signal this group is centered on.
    pub anchor: SignalId,
    /// Every matched signal (including the anchor) within the correlate
    /// window and sharing the anchor's correlation id.
    pub members: Vec<SignalId>,
}

/// Execute `query` over `store` (filtering: kind, `select`-scoped and
/// `where`-scoped label equality, and `range` relative to `now`), then — if
/// `query.correlate` is set — group the matched anchor-kind signals with
/// their real-`CorrelationIndex`-linked peers within the declared window.
///
/// Returns the matched signal ids in content-address order when there is no
/// `correlate` clause (`groups` empty, `matched` populated); when `correlate`
/// is set, `groups` carries one [`CorrelationGroup`] per matched anchor
/// signal (content-address ordered) and `matched` is still the full matched
/// set (every selected/filtered signal, regardless of kind).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PslResult {
    /// Every signal matching `select`/`where`/`range`, regardless of kind.
    pub matched: Vec<SignalId>,
    /// One [`CorrelationGroup`] per matched anchor-kind signal, populated
    /// only when the query carried a `correlate:` clause.
    pub groups: Vec<CorrelationGroup>,
}

fn signal_matches_predicates(
    labels: &std::collections::BTreeMap<String, String>,
    predicates: &[Predicate],
) -> bool {
    predicates
        .iter()
        .all(|p| labels.get(&p.key).is_some_and(|v| v == &p.value))
}

/// Execute `query` against `store`/`index` as of logical time `now`.
#[must_use]
pub fn execute(
    query: &PslQuery,
    store: &TimeseriesStore,
    index: &CorrelationIndex,
    now: u64,
) -> PslResult {
    let range_start = now.saturating_sub(query.range.seconds);

    // kind -> per-kind predicates, so a signal must match its OWN select
    // clause's predicates (never another kind's).
    let mut matched: BTreeSet<SignalId> = BTreeSet::new();
    let mut per_kind_predicates: Vec<(SignalKind, &[Predicate])> = Vec::new();
    for sel in &query.selects {
        per_kind_predicates.push((sel.kind, &sel.predicates));
    }

    for signal in store.held_signals() {
        let Some((_, kind_predicates)) = per_kind_predicates
            .iter()
            .find(|(k, _)| *k == signal.kind())
        else {
            continue; // signal's kind was not selected
        };
        let Some(tick) = store.write_tick_of(&signal.id()) else {
            continue;
        };
        if tick < range_start || tick > now {
            continue;
        }
        if !signal_matches_predicates(signal.labels(), kind_predicates) {
            continue;
        }
        if !signal_matches_predicates(signal.labels(), &query.where_predicates) {
            continue;
        }
        matched.insert(signal.id());
    }

    let matched_vec: Vec<SignalId> = matched.iter().cloned().collect();

    let groups = match query.correlate {
        None => Vec::new(),
        Some(spec) => {
            let mut groups = Vec::new();
            for anchor_id in matched.iter().filter(|id| {
                store
                    .held_signals()
                    .find(|s| s.id() == **id)
                    .is_some_and(|s| s.kind() == spec.anchor)
            }) {
                let Some(anchor_tick) = store.write_tick_of(anchor_id) else {
                    continue;
                };
                let mut members = Vec::new();
                match index.correlation_of(anchor_id) {
                    Some(cid) => {
                        for peer in index.by_correlation(&cid) {
                            if !matched.contains(&peer) {
                                continue;
                            }
                            let Some(peer_tick) = store.write_tick_of(&peer) else {
                                continue;
                            };
                            let delta = anchor_tick.abs_diff(peer_tick);
                            if delta <= spec.window_seconds {
                                members.push(peer);
                            }
                        }
                    }
                    None => members.push(anchor_id.clone()),
                }
                members.sort();
                members.dedup();
                groups.push(CorrelationGroup {
                    anchor: anchor_id.clone(),
                    members,
                });
            }
            groups.sort_by(|a, b| a.anchor.cmp(&b.anchor));
            groups
        }
    };

    PslResult {
        matched: matched_vec,
        groups,
    }
}

/// A numeric aggregation over a matched signal set: the observability
/// numeric primitives (`count`, `rate`, `sum`, `quantile`, `topk`) that
/// compose over the same [`execute`] match set the select/where/correlate
/// primitives produce — never a second, parallel query path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Aggregate {
    /// The number of matched signals.
    Count,
    /// Matched-signal count divided by the query's range in seconds
    /// (events per second over the window).
    Rate,
    /// The sum of every matched signal's numeric value.
    Sum,
    /// The value at quantile `q` (0.0..=1.0) of the matched signals' numeric
    /// values, by the nearest-rank method on the sorted values.
    Quantile(f64),
    /// The `k` largest matched signals by numeric value (descending).
    TopK(usize),
}

/// One aggregation output row: the group it belongs to (empty when the query
/// carried no `by [labels]` grouping) and the produced value(s).
#[derive(Clone, Debug, PartialEq)]
pub struct AggregateRow {
    /// The `(label-key, label-value)` pairs identifying this group, in label
    /// order. Empty for an ungrouped aggregation (one row over the whole set).
    pub group: Vec<(String, String)>,
    /// The aggregate value(s). `Count`/`Rate`/`Sum`/`Quantile` produce one
    /// value; `TopK` produces up to `k` values (descending).
    pub values: Vec<f64>,
}

/// Extract a signal's numeric value: the LAST whitespace-separated token of
/// its payload parsed as an `f64` (e.g. `ingest_bandwidth 42` -> `42.0`).
/// A payload with no parseable trailing number contributes nothing.
fn signal_value(signal: &crate::block::Signal) -> Option<f64> {
    let text = std::str::from_utf8(signal.payload()).ok()?;
    text.split_whitespace().last()?.parse::<f64>().ok()
}

/// Apply a numeric [`Aggregate`] to the signals `execute` matched for
/// `query`, optionally partitioned by the `by` label keys.
///
/// `by` is the `by [labels]` grouping: an empty slice aggregates the whole
/// matched set into a single ungrouped row; otherwise one row is produced per
/// distinct tuple of those label values (a signal missing any `by` key is
/// dropped from the grouped aggregation, exactly as a missing dimension is
/// unselectable). Rows are returned in ascending group-key order so the
/// output is deterministic regardless of store write order.
#[must_use]
pub fn aggregate(
    query: &PslQuery,
    store: &TimeseriesStore,
    index: &CorrelationIndex,
    now: u64,
    agg: Aggregate,
    by: &[String],
) -> Vec<AggregateRow> {
    use std::collections::BTreeMap;

    let result = execute(query, store, index, now);
    // Resolve each matched id back to its Signal (for labels + value).
    let matched: Vec<&crate::block::Signal> = result
        .matched
        .iter()
        .filter_map(|id| store.held_signals().find(|s| &s.id() == id))
        .collect();

    // Partition into groups keyed by the `by` label tuple (empty key = the
    // single ungrouped bucket).
    let mut groups: BTreeMap<Vec<(String, String)>, Vec<&crate::block::Signal>> = BTreeMap::new();
    for signal in matched {
        let mut key = Vec::with_capacity(by.len());
        let mut complete = true;
        for label in by {
            match signal.labels().get(label) {
                Some(v) => key.push((label.clone(), v.clone())),
                None => {
                    complete = false;
                    break;
                }
            }
        }
        if !complete {
            continue; // signal lacks a grouping dimension
        }
        groups.entry(key).or_default().push(signal);
    }

    // For an ungrouped aggregation over an EMPTY match set we still emit one
    // zero row (count/sum/rate of nothing is 0), matching PromQL-style
    // instant-vector semantics; a grouped aggregation over nothing is empty.
    if by.is_empty() && groups.is_empty() {
        groups.insert(Vec::new(), Vec::new());
    }

    groups
        .into_iter()
        .map(|(group, signals)| {
            let values = apply_aggregate(agg, &signals, query.range.seconds);
            AggregateRow { group, values }
        })
        .collect()
}

/// Compute one group's aggregate value(s) from its matched signals.
fn apply_aggregate(agg: Aggregate, signals: &[&crate::block::Signal], range_seconds: u64) -> Vec<f64> {
    match agg {
        Aggregate::Count => vec![signals.len() as f64],
        Aggregate::Rate => {
            let denom = if range_seconds == 0 { 1.0 } else { range_seconds as f64 };
            vec![signals.len() as f64 / denom]
        }
        Aggregate::Sum => {
            let sum: f64 = signals.iter().filter_map(|s| signal_value(s)).sum();
            vec![sum]
        }
        Aggregate::Quantile(q) => {
            let mut vals: Vec<f64> = signals.iter().filter_map(|s| signal_value(s)).collect();
            if vals.is_empty() {
                return vec![f64::NAN];
            }
            vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let q = q.clamp(0.0, 1.0);
            // Nearest-rank: rank = ceil(q * n), 1-based, clamped to [1, n].
            let rank = (q * vals.len() as f64).ceil().max(1.0) as usize;
            let idx = rank.min(vals.len()) - 1;
            vec![vals[idx]]
        }
        Aggregate::TopK(k) => {
            let mut vals: Vec<f64> = signals.iter().filter_map(|s| signal_value(s)).collect();
            vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            vals.truncate(k);
            vals
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::SignalKind;
    use crate::correlation::{CorrelationId, SignalRef};
    use std::collections::BTreeSet as Set;

    const ROI_EXAMPLE: &str = "select: metrics(name = ingest_bandwidth), logs \
        where: cell = testpillarcell range: now-1d correlate: { window: 1s, anchor: metrics }";

    fn expected_ast() -> PslQuery {
        PslQuery {
            selects: vec![
                SelectClause::new(
                    SignalKind::Metric,
                    vec![Predicate::eq("name", "ingest_bandwidth")],
                ),
                SelectClause::new(SignalKind::Log, vec![]),
            ],
            where_predicates: vec![Predicate::eq("cell", "testpillarcell")],
            range: RelativeRange::seconds(86_400),
            correlate: Some(CorrelateSpec {
                window_seconds: 1,
                anchor: SignalKind::Metric,
            }),
        }
    }

    fn structured_equivalent() -> PslQuery {
        PslQueryBuilder::new()
            .select(
                SignalKind::Metric,
                vec![Predicate::eq("name", "ingest_bandwidth")],
            )
            .select(SignalKind::Log, vec![])
            .where_eq("cell", "testpillarcell")
            .range_relative(86_400)
            .correlate(1, SignalKind::Metric)
            .build()
            .expect("structured build of a valid query must succeed")
    }

    /// The ROI canonical example parses to exactly the expected AST.
    #[test]
    fn roi_example_query_parses_to_the_expected_ast() {
        let parsed = parse(ROI_EXAMPLE).expect("canonical ROI example must parse");
        assert_eq!(parsed, expected_ast());
    }

    /// `SurfaceEquivalence`: the text surface and the structured builder
    /// surface of the SAME query produce a byte-identical canonical
    /// serialization (and an equal AST) — neither is a second, divergent
    /// query model.
    #[test]
    fn structured_and_text_surfaces_are_byte_identical() {
        let from_text = parse(ROI_EXAMPLE).expect("must parse");
        let from_builder = structured_equivalent();
        assert_eq!(from_text, from_builder);
        assert_eq!(from_text.to_text(), from_builder.to_text());
    }

    /// A round-tripped query (`to_text` then re-`parse`) reproduces the same
    /// AST — the canonical serialization really is the parser's own grammar.
    #[test]
    fn to_text_round_trips_through_parse() {
        let original = expected_ast();
        let reparsed = parse(&original.to_text()).expect("canonical text must re-parse");
        assert_eq!(original, reparsed);
    }

    /// Build a fixture: a real `TimeseriesStore` + `CorrelationIndex` holding
    /// the matching metric, a correlated log within the 1s window, an
    /// out-of-window log sharing the same correlation id, and unrelated noise
    /// (wrong cell, wrong metric name, outside the range) that must NOT
    /// appear in the result.
    fn fixture() -> (TimeseriesStore, CorrelationIndex, SignalId, SignalId) {
        let mut store = TimeseriesStore::new(64, 1_000_000);
        let mut index = CorrelationIndex::new();

        let cell_label = |labels: &mut std::collections::BTreeMap<String, String>| {
            labels.insert("cell".to_string(), "testpillarcell".to_string());
        };

        // The anchor metric, at tick 199_000, matching name + cell.
        let mut metric_labels = std::collections::BTreeMap::new();
        metric_labels.insert("name".to_string(), "ingest_bandwidth".to_string());
        cell_label(&mut metric_labels);
        let metric_id = store
            .write_labeled(
                SignalKind::Metric,
                b"ingest_bandwidth 42".to_vec(),
                metric_labels,
                199_000,
            )
            .expect("metric write is never downsampled (no policy installed)");
        let trace = CorrelationId("trace-anchor".to_string());
        index.register(
            metric_id.clone(),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: Some(trace.clone()),
                labels: Set::new(),
            },
        );

        // A log correlated to the same trace, within the 1s window (tick
        // 199_001) and matching the where-clause cell.
        let mut log_labels = std::collections::BTreeMap::new();
        cell_label(&mut log_labels);
        let log_in_window = store
            .write_labeled(
                SignalKind::Log,
                b"level=info msg=served".to_vec(),
                log_labels.clone(),
                199_001,
            )
            .expect("log write is never downsampled (no policy installed)");
        index.register(
            log_in_window.clone(),
            &SignalRef {
                kind: SignalKind::Log,
                correlation: Some(trace.clone()),
                labels: Set::new(),
            },
        );

        // A log on the SAME trace but well outside the 1s correlate window —
        // must be matched (range/where/select all pass) but excluded from
        // the anchor's correlation GROUP.
        let log_out_of_window = store
            .write_labeled(
                SignalKind::Log,
                b"level=info msg=late".to_vec(),
                log_labels.clone(),
                199_100,
            )
            .expect("log write is never downsampled");
        index.register(
            log_out_of_window,
            &SignalRef {
                kind: SignalKind::Log,
                correlation: Some(trace),
                labels: Set::new(),
            },
        );

        // Noise: wrong cell — must never be matched at all.
        let mut wrong_cell = std::collections::BTreeMap::new();
        wrong_cell.insert("cell".to_string(), "other-cell".to_string());
        let noise_log = store
            .write_labeled(SignalKind::Log, b"level=info msg=noise".to_vec(), wrong_cell, 199_001)
            .expect("log write is never downsampled");
        index.register(
            noise_log,
            &SignalRef {
                kind: SignalKind::Log,
                correlation: None,
                labels: Set::new(),
            },
        );

        // Noise: wrong metric name — must never be matched.
        let mut wrong_name = std::collections::BTreeMap::new();
        wrong_name.insert("name".to_string(), "unrelated_metric".to_string());
        cell_label(&mut wrong_name);
        store
            .write_labeled(SignalKind::Metric, b"unrelated 1".to_vec(), wrong_name, 199_001)
            .expect("metric write is never downsampled");

        // Noise: outside the range window (now=200_000, range=1d=86_400s ->
        // range_start=113_600; tick 1 is long before it).
        let mut old_labels = std::collections::BTreeMap::new();
        cell_label(&mut old_labels);
        store
            .write_labeled(SignalKind::Log, b"level=info msg=ancient".to_vec(), old_labels, 1)
            .expect("log write is never downsampled");

        (store, index, metric_id, log_in_window)
    }

    /// The canonical ROI example query executes against a real store fixture
    /// and returns exactly the expected correlation group: the anchor metric
    /// grouped with the in-window log, excluding the out-of-window log on the
    /// same trace and every piece of noise (wrong cell/name/range).
    #[test]
    fn roi_example_executes_against_a_real_store_and_returns_correlation_groups() {
        let (store, index, metric_id, log_in_window) = fixture();
        let query = expected_ast();
        let now = 200_000;

        let result = execute(&query, &store, &index, now);

        // matched: the anchor metric + the two same-cell logs (in-window and
        // out-of-window), but NEITHER noise signal.
        assert_eq!(result.matched.len(), 3, "expected exactly 3 matched signals, got {:?}", result.matched);
        assert!(result.matched.contains(&metric_id));
        assert!(result.matched.contains(&log_in_window));

        assert_eq!(result.groups.len(), 1, "exactly one anchor (metric) group");
        let group = &result.groups[0];
        assert_eq!(group.anchor, metric_id);
        assert_eq!(
            group.members,
            {
                let mut m = vec![metric_id.clone(), log_in_window.clone()];
                m.sort();
                m
            },
            "the correlation group must contain the anchor and the in-window log only"
        );
    }

    /// The structured-builder surface, executed against the SAME fixture,
    /// returns a byte-identical (field-for-field equal) result to the
    /// text-surface query — `SurfaceEquivalence` extended to execution, not
    /// merely AST equality.
    #[test]
    fn structured_and_text_surfaces_execute_to_identical_results() {
        let (store, index, _metric_id, _log_in_window) = fixture();
        let now = 200_000;

        let text_result = execute(&parse(ROI_EXAMPLE).unwrap(), &store, &index, now);
        let structured_result = execute(&structured_equivalent(), &store, &index, now);

        assert_eq!(text_result, structured_result);
    }

    /// A malformed query (missing the required `range:` clause) is REFUSED,
    /// not silently defaulted.
    #[test]
    fn missing_range_clause_is_refused() {
        let err = parse("select: metrics where: cell = x");
        assert!(err.is_err());
    }

    /// The structured builder refuses a query with no `select`.
    #[test]
    fn builder_refuses_empty_select() {
        let err = PslQueryBuilder::new().range_relative(60).build();
        assert!(err.is_err());
    }

    // ---- Numeric aggregation fixture & tests -----------------------------

    /// A real store of five in-range metric points on the same cell, with
    /// known numeric values (10, 20, 30, 40, 50) split across two `service`
    /// groups — so count/rate/sum/quantile/topk and `by [service]` grouping
    /// each have a single, hand-checkable correct answer. One out-of-range
    /// point (value 9999) proves the aggregation composes over `execute`'s
    /// range filter and is never counted.
    fn numeric_fixture() -> (TimeseriesStore, CorrelationIndex, PslQuery, u64) {
        let mut store = TimeseriesStore::new(64, 10_000_000);
        let index = CorrelationIndex::new();
        let now = 1_000_000;

        let write = |store: &mut TimeseriesStore, value: i64, service: &str, tick: u64| {
            let mut labels = std::collections::BTreeMap::new();
            labels.insert("cell".to_string(), "c".to_string());
            labels.insert("service".to_string(), service.to_string());
            store
                .write_labeled(
                    SignalKind::Metric,
                    format!("latency {value}").into_bytes(),
                    labels,
                    tick,
                )
                .expect("metric write is never downsampled (no policy)");
        };

        // In-range points (now-range .. now). range = 100s below.
        write(&mut store, 10, "a", now - 90);
        write(&mut store, 20, "a", now - 80);
        write(&mut store, 30, "b", now - 70);
        write(&mut store, 40, "b", now - 60);
        write(&mut store, 50, "b", now - 50);
        // Out-of-range: far in the past, must never be aggregated.
        write(&mut store, 9999, "a", 1);

        let query = PslQueryBuilder::new()
            .select(SignalKind::Metric, vec![Predicate::eq("cell", "c")])
            .range_relative(100)
            .build()
            .expect("valid query");

        (store, index, query, now)
    }

    /// `count` returns the number of in-range matched signals (5), never the
    /// out-of-range noise point.
    #[test]
    fn count_returns_the_matched_signal_count() {
        let (store, index, query, now) = numeric_fixture();
        let rows = aggregate(&query, &store, &index, now, Aggregate::Count, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values, vec![5.0]);
    }

    /// `rate` is the matched count over the range in seconds (5 / 100s).
    #[test]
    fn rate_is_count_over_the_range_seconds() {
        let (store, index, query, now) = numeric_fixture();
        let rows = aggregate(&query, &store, &index, now, Aggregate::Rate, &[]);
        assert_eq!(rows.len(), 1);
        assert!((rows[0].values[0] - 0.05).abs() < 1e-12, "5/100 = 0.05, got {:?}", rows[0].values);
    }

    /// `sum` totals every matched signal's numeric payload value
    /// (10+20+30+40+50 = 150), excluding the out-of-range 9999.
    #[test]
    fn sum_totals_the_matched_numeric_values() {
        let (store, index, query, now) = numeric_fixture();
        let rows = aggregate(&query, &store, &index, now, Aggregate::Sum, &[]);
        assert_eq!(rows.len(), 1);
        assert!((rows[0].values[0] - 150.0).abs() < 1e-9, "got {:?}", rows[0].values);
    }

    /// `quantile` uses nearest-rank on the sorted values [10,20,30,40,50]:
    /// the median (q=0.5) is 30, and q=1.0 is the max (50), q=0.0 the min (10).
    #[test]
    fn quantile_returns_the_nearest_rank_value() {
        let (store, index, query, now) = numeric_fixture();
        let median = aggregate(&query, &store, &index, now, Aggregate::Quantile(0.5), &[]);
        assert_eq!(median[0].values, vec![30.0]);
        let p100 = aggregate(&query, &store, &index, now, Aggregate::Quantile(1.0), &[]);
        assert_eq!(p100[0].values, vec![50.0]);
        let p0 = aggregate(&query, &store, &index, now, Aggregate::Quantile(0.0), &[]);
        assert_eq!(p0[0].values, vec![10.0]);
    }

    /// `topk` returns the k largest matched values in descending order
    /// (top 3 of [10,20,30,40,50] = [50,40,30]).
    #[test]
    fn topk_returns_the_k_largest_values_descending() {
        let (store, index, query, now) = numeric_fixture();
        let rows = aggregate(&query, &store, &index, now, Aggregate::TopK(3), &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values, vec![50.0, 40.0, 30.0]);
    }

    /// `by [service]` groups the matched set: service `a` sums 10+20=30 (2
    /// points), service `b` sums 30+40+50=120 (3 points); rows come back in
    /// ascending group-key order regardless of write order.
    #[test]
    fn by_labels_groups_the_aggregation() {
        let (store, index, query, now) = numeric_fixture();
        let by = vec!["service".to_string()];

        let sums = aggregate(&query, &store, &index, now, Aggregate::Sum, &by);
        assert_eq!(sums.len(), 2, "one row per service group");
        assert_eq!(sums[0].group, vec![("service".to_string(), "a".to_string())]);
        assert!((sums[0].values[0] - 30.0).abs() < 1e-9);
        assert_eq!(sums[1].group, vec![("service".to_string(), "b".to_string())]);
        assert!((sums[1].values[0] - 120.0).abs() < 1e-9);

        let counts = aggregate(&query, &store, &index, now, Aggregate::Count, &by);
        assert_eq!(counts[0].values, vec![2.0]); // service a
        assert_eq!(counts[1].values, vec![3.0]); // service b
    }
}
