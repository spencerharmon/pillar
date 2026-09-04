//! The **Explore** guided PSL query builder — the shared implementation the
//! other four signal-kind Explore views replicate, established here for
//! `metrics` (the first vertical).
//!
//! The builder never invents a second, parallel query model: every query it
//! composes is the SAME [`pillar_observability::PslQuery`] AST the compact
//! text surface (`pillar_observability::parse_psl`) parses, built
//! field-by-field via [`pillar_observability::PslQueryBuilder`] — so a
//! structured selection the user makes in the UI and the equivalent text a
//! power user could type produce byte-for-byte-`==` ASTs (see
//! [`build_metric_query`]'s test). Its select/where autofill is never a
//! fabricated/hardcoded list: [`label_key_options`] and
//! [`label_value_options`] read straight through to a real
//! [`pillar_observability::MetadataIndex`] built from the live held signal
//! set, so an unknown key returns empty, never a placeholder (mirroring the
//! index's own anti-fabrication contract). The correlate panel
//! ([`correlate_candidates`]) pivots to the OTHER signal kinds sharing
//! labels within a window — never metrics itself.
//!
//! This module (the builder state, the query composition, and the autofill
//! lookups) is pure, host-testable Rust; only the DOM/`fetch` wiring in
//! [`ExploreBuilder`] lives behind the `yew` feature, mirroring `panels`' and
//! `auth`'s "host-testable logic, thin Yew wrapper" split.

use pillar_observability::{MetadataIndex, PslError, PslQuery, PslQueryBuilder, Predicate, SignalKind};

#[cfg(feature = "yew")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(feature = "yew")]
use web_sys::{Headers, RequestInit, RequestMode, Response};
#[cfg(feature = "yew")]
use yew::prelude::*;

#[cfg(feature = "yew")]
use crate::auth::{use_auth, AuthAction};

/// The signal kind this pass's builder targets — the first of the five
/// Explore verticals ("metrics") the shared implementation establishes.
pub const METRIC_KIND: SignalKind = SignalKind::Metric;

/// The signal kind the `profiles` Explore vertical targets — the second of
/// the five verticals, replicating the shared `metrics` builder above for
/// [`SignalKind::ProfileSample`].
pub const PROFILE_KIND: SignalKind = SignalKind::ProfileSample;

/// Build the structured [`PslQuery`] for a `metrics` Explore selection:
/// `select: metrics(<select_predicates>) where: <where_predicates> range:
/// now-<range_seconds>s [correlate: { window: <w>, anchor: <a> }]` — the SAME
/// AST [`pillar_observability::parse_psl`] would produce from the equivalent
/// compact text, by construction (both surfaces build the one
/// [`PslQueryBuilder`]/[`PslQuery`] model).
///
/// Fails only as [`PslQueryBuilder::build`] does (no `select`, which cannot
/// happen here since `metrics` is always selected, or no `range`, which
/// cannot happen either since `range_seconds` is always supplied) — the
/// `Result` is kept so a future kind/field can fail honestly rather than
/// panicking.
pub fn build_metric_query(
    select_predicates: &[(String, String)],
    where_predicates: &[(String, String)],
    range_seconds: u64,
    correlate: Option<(u64, SignalKind)>,
) -> Result<PslQuery, PslError> {
    let select = select_predicates
        .iter()
        .map(|(k, v)| Predicate::eq(k.clone(), v.clone()))
        .collect();
    let mut builder = PslQueryBuilder::new()
        .select(METRIC_KIND, select)
        .range_relative(range_seconds);
    for (k, v) in where_predicates {
        builder = builder.where_eq(k.clone(), v.clone());
    }
    if let Some((window_seconds, anchor)) = correlate {
        builder = builder.correlate(window_seconds, anchor);
    }
    builder.build()
}

/// The select/where label-KEY autofill: every label key actually present in
/// the live held signal set, sorted. Delegates straight to the real
/// [`MetadataIndex`] — never a hardcoded list, so a key the operator never
/// ingested never appears.
#[must_use]
pub fn label_key_options(index: &MetadataIndex) -> Vec<String> {
    index.label_keys()
}

/// The select/where label-VALUE autofill for `key`: exactly the values
/// actually present for that key in the live held signal set, sorted. An
/// unknown key returns empty (delegated to [`MetadataIndex::label_values`]'s
/// own anti-fabrication contract) — the builder never offers a value that
/// would match nothing.
#[must_use]
pub fn label_value_options(index: &MetadataIndex, key: &str) -> Vec<String> {
    index.label_values(key)
}

/// The correlate panel's pivot-target candidates: every signal kind OTHER
/// than the one this builder selects (`metrics`) that a correlation window
/// can group against. Order is fixed so the panel renders deterministically.
#[must_use]
pub fn correlate_candidates() -> Vec<SignalKind> {
    vec![
        SignalKind::Log,
        SignalKind::TraceSpan,
        SignalKind::ProfileSample,
        SignalKind::MetadataSample,
    ]
}

/// Build the structured [`PslQuery`] for a `profiles` Explore selection — the
/// exact analogue of [`build_metric_query`] for [`PROFILE_KIND`]: `select:
/// profiles(<select_predicates>) where: <where_predicates> range:
/// now-<range_seconds>s [correlate: { window: <w>, anchor: <a> }]`, the SAME
/// AST [`pillar_observability::parse_psl`] produces from the equivalent
/// compact text, by construction (both surfaces build the one
/// [`PslQueryBuilder`]/[`PslQuery`] model). The profiles vertical never forks
/// a second query model; it only differs from `metrics` in the selected
/// [`SignalKind`].
///
/// Fails only as [`PslQueryBuilder::build`] does (kept as a `Result` so a
/// future field can fail honestly rather than panicking).
pub fn build_profile_query(
    select_predicates: &[(String, String)],
    where_predicates: &[(String, String)],
    range_seconds: u64,
    correlate: Option<(u64, SignalKind)>,
) -> Result<PslQuery, PslError> {
    let select = select_predicates
        .iter()
        .map(|(k, v)| Predicate::eq(k.clone(), v.clone()))
        .collect();
    let mut builder = PslQueryBuilder::new()
        .select(PROFILE_KIND, select)
        .range_relative(range_seconds);
    for (k, v) in where_predicates {
        builder = builder.where_eq(k.clone(), v.clone());
    }
    if let Some((window_seconds, anchor)) = correlate {
        builder = builder.correlate(window_seconds, anchor);
    }
    builder.build()
}

/// The `profiles` correlate panel's pivot-target candidates: every signal
/// kind OTHER than the one this builder selects (`profiles`). Order is fixed
/// so the panel renders deterministically.
#[must_use]
pub fn profile_correlate_candidates() -> Vec<SignalKind> {
    vec![
        SignalKind::Metric,
        SignalKind::Log,
        SignalKind::TraceSpan,
        SignalKind::MetadataSample,
    ]
}

/// The signal kind the `metadata` vertical's builder targets — the second
/// of the five Explore verticals to replicate the shared
/// [`build_metric_query`]/[`correlate_candidates`] pattern.
pub const METADATA_KIND: SignalKind = SignalKind::MetadataSample;

/// Build the structured [`PslQuery`] for a `metadata` Explore selection:
/// `select: metadata(<select_predicates>) where: <where_predicates> range:
/// now-<range_seconds>s [correlate: { window: <w>, anchor: <a> }]` — the SAME
/// AST [`pillar_observability::parse_psl`] would produce from the equivalent
/// compact text, by construction, mirroring [`build_metric_query`] for the
/// `metadata` signal kind.
///
/// Fails only as [`PslQueryBuilder::build`] does (no `select`, which cannot
/// happen here since `metadata` is always selected, or no `range`, which
/// cannot happen either since `range_seconds` is always supplied) — the
/// `Result` is kept so a future kind/field can fail honestly rather than
/// panicking.
pub fn build_metadata_query(
    select_predicates: &[(String, String)],
    where_predicates: &[(String, String)],
    range_seconds: u64,
    correlate: Option<(u64, SignalKind)>,
) -> Result<PslQuery, PslError> {
    let select = select_predicates
        .iter()
        .map(|(k, v)| Predicate::eq(k.clone(), v.clone()))
        .collect();
    let mut builder = PslQueryBuilder::new()
        .select(METADATA_KIND, select)
        .range_relative(range_seconds);
    for (k, v) in where_predicates {
        builder = builder.where_eq(k.clone(), v.clone());
    }
    if let Some((window_seconds, anchor)) = correlate {
        builder = builder.correlate(window_seconds, anchor);
    }
    builder.build()
}

/// The correlate panel's pivot-target candidates for the `metadata`
/// vertical: every signal kind OTHER than `metadata` itself that a
/// correlation window can group against. Order is fixed so the panel
/// renders deterministically.
#[must_use]
pub fn correlate_candidates_metadata() -> Vec<SignalKind> {
    vec![
        SignalKind::Metric,
        SignalKind::Log,
        SignalKind::TraceSpan,
        SignalKind::ProfileSample,
    ]
}

/// The signal kind the `traces` vertical's builder targets — the third of
/// the five Explore verticals to replicate the shared
/// [`build_metric_query`]/[`correlate_candidates`] pattern.
pub const TRACE_KIND: SignalKind = SignalKind::TraceSpan;

/// Build the structured [`PslQuery`] for a `traces` Explore selection:
/// `select: traces(<select_predicates>) where: <where_predicates> range:
/// now-<range_seconds>s [correlate: { window: <w>, anchor: <a> }]` — the SAME
/// AST [`pillar_observability::parse_psl`] would produce from the equivalent
/// compact text, by construction, mirroring [`build_metric_query`]/
/// [`build_metadata_query`] for the `traces` signal kind.
///
/// Fails only as [`PslQueryBuilder::build`] does (no `select`, which cannot
/// happen here since `traces` is always selected, or no `range`, which
/// cannot happen either since `range_seconds` is always supplied) — the
/// `Result` is kept so a future kind/field can fail honestly rather than
/// panicking.
pub fn build_trace_query(
    select_predicates: &[(String, String)],
    where_predicates: &[(String, String)],
    range_seconds: u64,
    correlate: Option<(u64, SignalKind)>,
) -> Result<PslQuery, PslError> {
    let select = select_predicates
        .iter()
        .map(|(k, v)| Predicate::eq(k.clone(), v.clone()))
        .collect();
    let mut builder = PslQueryBuilder::new()
        .select(TRACE_KIND, select)
        .range_relative(range_seconds);
    for (k, v) in where_predicates {
        builder = builder.where_eq(k.clone(), v.clone());
    }
    if let Some((window_seconds, anchor)) = correlate {
        builder = builder.correlate(window_seconds, anchor);
    }
    builder.build()
}

/// The correlate panel's pivot-target candidates for the `traces` vertical:
/// every signal kind OTHER than `traces` itself that a correlation window
/// can group against. Order is fixed so the panel renders deterministically.
#[must_use]
pub fn correlate_candidates_traces() -> Vec<SignalKind> {
    vec![
        SignalKind::Metric,
        SignalKind::Log,
        SignalKind::ProfileSample,
        SignalKind::MetadataSample,
    ]
}

/// The signal kind the `logs` vertical's builder targets — the fifth (and
/// last) of the five Explore verticals to replicate the shared
/// [`build_metric_query`]/[`correlate_candidates`] pattern. Unique among the
/// five: logs also carry the LOG-payload `select:` filter fields (`level`,
/// `message`, `field.x`) that the `psl-log-filters` dep added to the shared
/// [`pillar_observability`] PSL model — see [`LogFilter`].
pub const LOG_KIND: SignalKind = SignalKind::Log;

/// One `select:` payload filter row for the `logs` builder: a LOG-payload
/// field (`level`, `message`, or a nested `field.x`) paired with the
/// operator the shared PSL model requires for it — an exact [`PredOp::Eq`]
/// for `level`/`field.x`, or a substring [`PredOp::Match`] for `message`
/// (the only payload field whose values are free text, so the builder never
/// asks for whole-string equality on a human-authored message).
///
/// [`PredOp::Eq`]: pillar_observability::PredOp::Eq
/// [`PredOp::Match`]: pillar_observability::PredOp::Match
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFilter {
    /// The LOG-payload field key (`level`, `message`, or `field.x`).
    pub key: String,
    /// The value the field must equal (`level`/`field.x`) or contain
    /// (`message`).
    pub value: String,
    /// Whether this filter compares by substring containment (`message`)
    /// rather than exact equality.
    pub is_match: bool,
}

impl LogFilter {
    /// An exact-equality LOG-payload filter (`level = value` / `field.x =
    /// value`).
    #[must_use]
    pub fn eq(key: impl Into<String>, value: impl Into<String>) -> Self {
        LogFilter {
            key: key.into(),
            value: value.into(),
            is_match: false,
        }
    }

    /// A substring-match LOG-payload filter (`message =~ value`).
    #[must_use]
    pub fn matches(key: impl Into<String>, value: impl Into<String>) -> Self {
        LogFilter {
            key: key.into(),
            value: value.into(),
            is_match: true,
        }
    }

    /// The real [`Predicate`] this filter composes into the shared PSL
    /// model — `Predicate::eq` for an exact filter, `Predicate::matches`
    /// for a substring one. Never a second, parallel filter model: every
    /// `LogFilter` maps to the SAME `Predicate` the compact text surface
    /// (`level = error`, `message =~ "timeout"`) parses to.
    #[must_use]
    pub fn to_predicate(&self) -> Predicate {
        if self.is_match {
            Predicate::matches(self.key.clone(), self.value.clone())
        } else {
            Predicate::eq(self.key.clone(), self.value.clone())
        }
    }

    /// Constructs the [`LogFilter`] with the operator the shared PSL model
    /// requires for `key`: `message` auto-selects the substring `=~` match
    /// (free text), every other key (`level`, `field.x`, …) auto-selects
    /// exact `=` equality.
    #[must_use]
    pub fn for_key(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        if key == "message" {
            LogFilter::matches(key, value)
        } else {
            LogFilter::eq(key, value)
        }
    }
}

/// Build the structured [`PslQuery`] for a `logs` Explore selection: `select:
/// logs(<select_filters>) where: <where_predicates> range: now-<range_seconds>s
/// [correlate: { window: <w>, anchor: <a> }]` — the SAME AST
/// [`pillar_observability::parse_psl`] would produce from the equivalent
/// compact text, by construction (both surfaces build the one
/// [`PslQueryBuilder`]/[`PslQuery`] model). Unique among the five Explore
/// verticals: `select_filters` composes the LOG-payload fields (`level`,
/// `message`, `field.x`) via [`LogFilter::to_predicate`] rather than the
/// plain label equality the other four kinds' `select:` uses.
///
/// Fails only as [`PslQueryBuilder::build`] does (no `select`, which cannot
/// happen here since `logs` is always selected, or no `range`, which cannot
/// happen either since `range_seconds` is always supplied) — the `Result`
/// is kept so a future field can fail honestly rather than panicking.
pub fn build_log_query(
    select_filters: &[LogFilter],
    where_predicates: &[(String, String)],
    range_seconds: u64,
    correlate: Option<(u64, SignalKind)>,
) -> Result<PslQuery, PslError> {
    let select = select_filters.iter().map(LogFilter::to_predicate).collect();
    let mut builder = PslQueryBuilder::new()
        .select(LOG_KIND, select)
        .range_relative(range_seconds);
    for (k, v) in where_predicates {
        builder = builder.where_eq(k.clone(), v.clone());
    }
    if let Some((window_seconds, anchor)) = correlate {
        builder = builder.correlate(window_seconds, anchor);
    }
    builder.build()
}

/// The correlate panel's pivot-target candidates for the `logs` vertical:
/// every signal kind OTHER than `logs` itself that a correlation window can
/// group against. Order is fixed so the panel renders deterministically.
#[must_use]
pub fn correlate_candidates_logs() -> Vec<SignalKind> {
    vec![
        SignalKind::Metric,
        SignalKind::TraceSpan,
        SignalKind::ProfileSample,
        SignalKind::MetadataSample,
    ]
}

#[cfg(feature = "yew")]
/// One `key = value` row the user has added to the `select:`/`where:`
/// predicate list.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PredicateRow {
    /// The label key.
    pub key: String,
    /// The label value.
    pub value: String,
}

#[cfg(feature = "yew")]
/// Props for [`ExploreBuilder`].
#[derive(Properties, PartialEq)]
pub struct ExploreBuilderProps {
    /// The endpoint this builder fetches its label-key typeahead from (a
    /// `GET` returning one label key per line).
    pub label_keys_path: &'static str,
    /// The endpoint this builder fetches a label's real values from — the
    /// key is appended as `?key=<key>` (a `GET` returning one value per
    /// line).
    pub label_values_path: &'static str,
    /// The endpoint this builder submits its composed query text to (a
    /// `GET` with the composed text as `?query=<text>`), returning the
    /// matched series rendered one per line.
    pub query_path: &'static str,
}

#[cfg(feature = "yew")]
/// The guided PSL query builder for the `metrics` signal kind: `select:`/
/// `where:` predicate rows whose keys and values autofill (as the user
/// types) from the real [`pillar_observability::MetadataIndex`] served at
/// [`ExploreBuilderProps::label_keys_path`]/`label_values_path`, a `range:`
/// field, and a correlate panel that pivots the composed query to the other
/// signal kinds sharing labels within a window. Submits the composed
/// [`build_metric_query`] text (via [`PslQuery::to_text`]) to
/// [`ExploreBuilderProps::query_path`] and renders the real matched series —
/// never a fabricated result set.
#[function_component(ExploreBuilder)]
pub fn explore_builder(props: &ExploreBuilderProps) -> Html {
    let auth = use_auth();
    let label_keys: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_key_input = use_state(String::new);
    let where_value_input = use_state(String::new);
    let label_values: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_rows: UseStateHandle<Vec<PredicateRow>> = use_state(Vec::new);
    let range_seconds = use_state(|| 3600u64);
    let correlate_anchor: UseStateHandle<Option<SignalKind>> = use_state(|| None);
    let results: UseStateHandle<Vec<String>> = use_state(Vec::new);

    // Load the real label-key typeahead on mount.
    {
        let label_keys = label_keys.clone();
        let path = props.label_keys_path;
        let token = auth.token.clone();
        use_effect_with((path, token.clone()), move |_| {
            let label_keys = label_keys.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(FetchOutcome::Ok(text)) = fetch_text(path, token.as_deref()).await {
                    label_keys.set(crate::panels::parse_lines(&text, ""));
                }
            });
            || ()
        });
    }

    // Re-fetch the real label-value typeahead every time the user changes
    // which key they are filling in — never a fabricated superset.
    {
        let label_values = label_values.clone();
        let path = props.label_values_path;
        let token = auth.token.clone();
        let key = (*where_key_input).clone();
        use_effect_with((path, key.clone(), token.clone()), move |_| {
            let label_values = label_values.clone();
            if key.is_empty() {
                label_values.set(Vec::new());
            } else {
                wasm_bindgen_futures::spawn_local(async move {
                    let full = format!("{path}?key={key}");
                    if let Ok(FetchOutcome::Ok(text)) = fetch_text(&full, token.as_deref()).await {
                        label_values.set(crate::panels::parse_lines(&text, ""));
                    }
                });
            }
            || ()
        });
    }

    let on_key_input = {
        let where_key_input = where_key_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_key_input.set(value);
        })
    };

    let on_value_input = {
        let where_value_input = where_value_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_value_input.set(value);
        })
    };

    let on_add_predicate = {
        let where_rows = where_rows.clone();
        let where_key_input = where_key_input.clone();
        let where_value_input = where_value_input.clone();
        Callback::from(move |_| {
            let key = (*where_key_input).clone();
            let value = (*where_value_input).clone();
            if key.is_empty() || value.is_empty() {
                return;
            }
            let mut rows = (*where_rows).clone();
            rows.push(PredicateRow { key, value });
            where_rows.set(rows);
        })
    };

    let on_run = {
        let where_rows = where_rows.clone();
        let range_seconds = range_seconds.clone();
        let correlate_anchor = correlate_anchor.clone();
        let query_path = props.query_path;
        let auth = auth.clone();
        let results = results.clone();
        Callback::from(move |_| {
            let predicates: Vec<(String, String)> = (*where_rows)
                .iter()
                .map(|r| (r.key.clone(), r.value.clone()))
                .collect();
            let correlate = (*correlate_anchor).map(|anchor| (60u64, anchor));
            let Ok(query) = build_metric_query(&[], &predicates, *range_seconds, correlate) else {
                return;
            };
            let text = query.to_text();
            let path = query_path;
            let token = auth.token.clone();
            let results = results.clone();
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let full = format!("{path}?query={}", urlencode(&text));
                match fetch_text(&full, token.as_deref()).await {
                    Ok(FetchOutcome::Ok(text)) => results.set(crate::panels::parse_lines(&text, "")),
                    Ok(FetchOutcome::Unauthorized) => auth.dispatch(AuthAction::Unauthorized),
                    Err(_) => {}
                }
            });
        })
    };

    html! {
        <section data-panel="explore-metrics">
            <h2>{ "Explore — metrics" }</h2>
            <div data-role="predicate-builder">
                <input
                    data-role="where-key"
                    list="explore-label-keys"
                    value={(*where_key_input).clone()}
                    oninput={on_key_input}
                />
                <datalist id="explore-label-keys">
                    { for label_keys.iter().map(|k| html! { <option value={k.clone()} /> }) }
                </datalist>
                <input
                    data-role="where-value"
                    list="explore-label-values"
                    value={(*where_value_input).clone()}
                    oninput={on_value_input}
                />
                <datalist id="explore-label-values">
                    { for label_values.iter().map(|v| html! { <option value={v.clone()} /> }) }
                </datalist>
                <button data-role="add-predicate" onclick={on_add_predicate}>{ "Add" }</button>
            </div>
            <ul data-role="predicate-rows">
                { for where_rows.iter().map(|r| html! { <li>{ format!("{} = {}", r.key, r.value) }</li> }) }
            </ul>
            <section data-panel="correlate">
                <h3>{ "Correlate" }</h3>
                { for correlate_candidates().into_iter().map(|kind| {
                    let correlate_anchor = correlate_anchor.clone();
                    let label = format!("{kind:?}");
                    let onclick = Callback::from(move |_| correlate_anchor.set(Some(kind)));
                    html! { <button data-role="correlate-kind" onclick={onclick}>{ label }</button> }
                }) }
            </section>
            <button data-role="run-query" onclick={on_run}>{ "Run" }</button>
            <ul data-role="results">
                { for results.iter().map(|r| html! { <li>{ r.clone() }</li> }) }
            </ul>
        </section>
    }
}

#[cfg(feature = "yew")]
/// The guided PSL query builder for the `profiles` signal kind — the exact
/// analogue of [`ExploreBuilder`] for [`PROFILE_KIND`], sharing the same
/// autofill/correlate/submit wiring and differing only in the selected signal
/// kind ([`build_profile_query`] / [`profile_correlate_candidates`]) and its
/// `data-panel` marker. Submits the composed [`PslQuery::to_text`] to
/// [`ExploreBuilderProps::query_path`] and renders the real matched series.
#[function_component(ExploreProfilesBuilder)]
pub fn explore_profiles_builder(props: &ExploreBuilderProps) -> Html {
    let auth = use_auth();
    let label_keys: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_key_input = use_state(String::new);
    let where_value_input = use_state(String::new);
    let label_values: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_rows: UseStateHandle<Vec<PredicateRow>> = use_state(Vec::new);
    let range_seconds = use_state(|| 3600u64);
    let correlate_anchor: UseStateHandle<Option<SignalKind>> = use_state(|| None);
    let results: UseStateHandle<Vec<String>> = use_state(Vec::new);

    // Load the real label-key typeahead on mount.
    {
        let label_keys = label_keys.clone();
        let path = props.label_keys_path;
        let token = auth.token.clone();
        use_effect_with((path, token.clone()), move |_| {
            let label_keys = label_keys.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(FetchOutcome::Ok(text)) = fetch_text(path, token.as_deref()).await {
                    label_keys.set(crate::panels::parse_lines(&text, ""));
                }
            });
            || ()
        });
    }

    // Re-fetch the real label-value typeahead every time the user changes
    // which key they are filling in — never a fabricated superset.
    {
        let label_values = label_values.clone();
        let path = props.label_values_path;
        let token = auth.token.clone();
        let key = (*where_key_input).clone();
        use_effect_with((path, key.clone(), token.clone()), move |_| {
            let label_values = label_values.clone();
            if key.is_empty() {
                label_values.set(Vec::new());
            } else {
                wasm_bindgen_futures::spawn_local(async move {
                    let full = format!("{path}?key={key}");
                    if let Ok(FetchOutcome::Ok(text)) = fetch_text(&full, token.as_deref()).await {
                        label_values.set(crate::panels::parse_lines(&text, ""));
                    }
                });
            }
            || ()
        });
    }

    let on_key_input = {
        let where_key_input = where_key_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_key_input.set(value);
        })
    };

    let on_value_input = {
        let where_value_input = where_value_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_value_input.set(value);
        })
    };

    let on_add_predicate = {
        let where_rows = where_rows.clone();
        let where_key_input = where_key_input.clone();
        let where_value_input = where_value_input.clone();
        Callback::from(move |_| {
            let key = (*where_key_input).clone();
            let value = (*where_value_input).clone();
            if key.is_empty() || value.is_empty() {
                return;
            }
            let mut rows = (*where_rows).clone();
            rows.push(PredicateRow { key, value });
            where_rows.set(rows);
        })
    };

    let on_run = {
        let where_rows = where_rows.clone();
        let range_seconds = range_seconds.clone();
        let correlate_anchor = correlate_anchor.clone();
        let query_path = props.query_path;
        let auth = auth.clone();
        let results = results.clone();
        Callback::from(move |_| {
            let predicates: Vec<(String, String)> = (*where_rows)
                .iter()
                .map(|r| (r.key.clone(), r.value.clone()))
                .collect();
            let correlate = (*correlate_anchor).map(|anchor| (60u64, anchor));
            let Ok(query) = build_profile_query(&[], &predicates, *range_seconds, correlate) else {
                return;
            };
            let text = query.to_text();
            let path = query_path;
            let token = auth.token.clone();
            let results = results.clone();
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let full = format!("{path}?query={}", urlencode(&text));
                match fetch_text(&full, token.as_deref()).await {
                    Ok(FetchOutcome::Ok(text)) => results.set(crate::panels::parse_lines(&text, "")),
                    Ok(FetchOutcome::Unauthorized) => auth.dispatch(AuthAction::Unauthorized),
                    Err(_) => {}
                }
            });
        })
    };

    html! {
        <section data-panel="explore-profiles">
            <h2>{ "Explore — profiles" }</h2>
            <div data-role="predicate-builder">
                <input
                    data-role="where-key"
                    list="explore-profiles-label-keys"
                    value={(*where_key_input).clone()}
                    oninput={on_key_input}
                />
                <datalist id="explore-profiles-label-keys">
                    { for label_keys.iter().map(|k| html! { <option value={k.clone()} /> }) }
                </datalist>
                <input
                    data-role="where-value"
                    list="explore-profiles-label-values"
                    value={(*where_value_input).clone()}
                    oninput={on_value_input}
                />
                <datalist id="explore-profiles-label-values">
                    { for label_values.iter().map(|v| html! { <option value={v.clone()} /> }) }
                </datalist>
                <button data-role="add-predicate" onclick={on_add_predicate}>{ "Add" }</button>
            </div>
            <ul data-role="predicate-rows">
                { for where_rows.iter().map(|r| html! { <li>{ format!("{} = {}", r.key, r.value) }</li> }) }
            </ul>
            <section data-panel="correlate">
                <h3>{ "Correlate" }</h3>
                { for profile_correlate_candidates().into_iter().map(|kind| {
                    let correlate_anchor = correlate_anchor.clone();
                    let label = format!("{kind:?}");
                    let onclick = Callback::from(move |_| correlate_anchor.set(Some(kind)));
                    html! { <button data-role="correlate-kind" onclick={onclick}>{ label }</button> }
                }) }
            </section>
            <button data-role="run-query" onclick={on_run}>{ "Run" }</button>
            <ul data-role="results">
                { for results.iter().map(|r| html! { <li>{ r.clone() }</li> }) }
            </ul>
        </section>
    }
}

#[cfg(feature = "yew")]
/// The guided PSL query builder for the `logs` signal kind — the exact
/// analogue of [`ExploreBuilder`]/[`ExploreProfilesBuilder`] for
/// [`LOG_KIND`], sharing the same label `where:` autofill/correlate/submit
/// wiring, PLUS a `select:` LOG-payload filter builder unique to this
/// vertical: a `level`/`message`/`field.x` key input that auto-selects the
/// substring `=~` operator for `message` and exact `=` for every other key
/// ([`LogFilter::for_key`]), so the composed query always matches
/// [`build_log_query`]'s (and the shared PSL model's) real operator
/// semantics.
#[function_component(ExploreLogsBuilder)]
pub fn explore_logs_builder(props: &ExploreBuilderProps) -> Html {
    let auth = use_auth();
    let label_keys: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_key_input = use_state(String::new);
    let where_value_input = use_state(String::new);
    let label_values: UseStateHandle<Vec<String>> = use_state(Vec::new);
    let where_rows: UseStateHandle<Vec<PredicateRow>> = use_state(Vec::new);
    let select_key_input = use_state(String::new);
    let select_value_input = use_state(String::new);
    let select_rows: UseStateHandle<Vec<LogFilter>> = use_state(Vec::new);
    let range_seconds = use_state(|| 3600u64);
    let correlate_anchor: UseStateHandle<Option<SignalKind>> = use_state(|| None);
    let results: UseStateHandle<Vec<String>> = use_state(Vec::new);

    // Load the real label-key typeahead on mount.
    {
        let label_keys = label_keys.clone();
        let path = props.label_keys_path;
        let token = auth.token.clone();
        use_effect_with((path, token.clone()), move |_| {
            let label_keys = label_keys.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(FetchOutcome::Ok(text)) = fetch_text(path, token.as_deref()).await {
                    label_keys.set(crate::panels::parse_lines(&text, ""));
                }
            });
            || ()
        });
    }

    // Re-fetch the real label-value typeahead every time the user changes
    // which key they are filling in — never a fabricated superset.
    {
        let label_values = label_values.clone();
        let path = props.label_values_path;
        let token = auth.token.clone();
        let key = (*where_key_input).clone();
        use_effect_with((path, key.clone(), token.clone()), move |_| {
            let label_values = label_values.clone();
            if key.is_empty() {
                label_values.set(Vec::new());
            } else {
                wasm_bindgen_futures::spawn_local(async move {
                    let full = format!("{path}?key={key}");
                    if let Ok(FetchOutcome::Ok(text)) = fetch_text(&full, token.as_deref()).await {
                        label_values.set(crate::panels::parse_lines(&text, ""));
                    }
                });
            }
            || ()
        });
    }

    let on_key_input = {
        let where_key_input = where_key_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_key_input.set(value);
        })
    };

    let on_value_input = {
        let where_value_input = where_value_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            where_value_input.set(value);
        })
    };

    let on_add_predicate = {
        let where_rows = where_rows.clone();
        let where_key_input = where_key_input.clone();
        let where_value_input = where_value_input.clone();
        Callback::from(move |_| {
            let key = (*where_key_input).clone();
            let value = (*where_value_input).clone();
            if key.is_empty() || value.is_empty() {
                return;
            }
            let mut rows = (*where_rows).clone();
            rows.push(PredicateRow { key, value });
            where_rows.set(rows);
        })
    };

    let on_select_key_input = {
        let select_key_input = select_key_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            select_key_input.set(value);
        })
    };

    let on_select_value_input = {
        let select_value_input = select_value_input.clone();
        Callback::from(move |e: InputEvent| {
            let value = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            select_value_input.set(value);
        })
    };

    let on_add_filter = {
        let select_rows = select_rows.clone();
        let select_key_input = select_key_input.clone();
        let select_value_input = select_value_input.clone();
        Callback::from(move |_| {
            let key = (*select_key_input).clone();
            let value = (*select_value_input).clone();
            if key.is_empty() || value.is_empty() {
                return;
            }
            let mut rows = (*select_rows).clone();
            rows.push(LogFilter::for_key(key, value));
            select_rows.set(rows);
        })
    };

    let on_run = {
        let where_rows = where_rows.clone();
        let select_rows = select_rows.clone();
        let range_seconds = range_seconds.clone();
        let correlate_anchor = correlate_anchor.clone();
        let query_path = props.query_path;
        let auth = auth.clone();
        let results = results.clone();
        Callback::from(move |_| {
            let predicates: Vec<(String, String)> = (*where_rows)
                .iter()
                .map(|r| (r.key.clone(), r.value.clone()))
                .collect();
            let filters: Vec<LogFilter> = (*select_rows).clone();
            let correlate = (*correlate_anchor).map(|anchor| (60u64, anchor));
            let Ok(query) = build_log_query(&filters, &predicates, *range_seconds, correlate) else {
                return;
            };
            let text = query.to_text();
            let path = query_path;
            let token = auth.token.clone();
            let results = results.clone();
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let full = format!("{path}?query={}", urlencode(&text));
                match fetch_text(&full, token.as_deref()).await {
                    Ok(FetchOutcome::Ok(text)) => results.set(crate::panels::parse_lines(&text, "")),
                    Ok(FetchOutcome::Unauthorized) => auth.dispatch(AuthAction::Unauthorized),
                    Err(_) => {}
                }
            });
        })
    };

    html! {
        <section data-panel="explore-logs">
            <h2>{ "Explore — logs" }</h2>
            <div data-role="log-filter-builder">
                <input
                    data-role="select-key"
                    value={(*select_key_input).clone()}
                    oninput={on_select_key_input}
                />
                <input
                    data-role="select-value"
                    value={(*select_value_input).clone()}
                    oninput={on_select_value_input}
                />
                <button data-role="add-filter" onclick={on_add_filter}>{ "Add filter" }</button>
            </div>
            <ul data-role="filter-rows">
                { for select_rows.iter().map(|r| {
                    let op = if r.is_match { "=~" } else { "=" };
                    html! { <li>{ format!("{} {} {}", r.key, op, r.value) }</li> }
                }) }
            </ul>
            <div data-role="predicate-builder">
                <input
                    data-role="where-key"
                    list="explore-logs-label-keys"
                    value={(*where_key_input).clone()}
                    oninput={on_key_input}
                />
                <datalist id="explore-logs-label-keys">
                    { for label_keys.iter().map(|k| html! { <option value={k.clone()} /> }) }
                </datalist>
                <input
                    data-role="where-value"
                    list="explore-logs-label-values"
                    value={(*where_value_input).clone()}
                    oninput={on_value_input}
                />
                <datalist id="explore-logs-label-values">
                    { for label_values.iter().map(|v| html! { <option value={v.clone()} /> }) }
                </datalist>
                <button data-role="add-predicate" onclick={on_add_predicate}>{ "Add" }</button>
            </div>
            <ul data-role="predicate-rows">
                { for where_rows.iter().map(|r| html! { <li>{ format!("{} = {}", r.key, r.value) }</li> }) }
            </ul>
            <section data-panel="correlate">
                <h3>{ "Correlate" }</h3>
                { for correlate_candidates_logs().into_iter().map(|kind| {
                    let correlate_anchor = correlate_anchor.clone();
                    let label = format!("{kind:?}");
                    let onclick = Callback::from(move |_| correlate_anchor.set(Some(kind)));
                    html! { <button data-role="correlate-kind" onclick={onclick}>{ label }</button> }
                }) }
            </section>
            <button data-role="run-query" onclick={on_run}>{ "Run" }</button>
            <ul data-role="results">
                { for results.iter().map(|r| html! { <li>{ r.clone() }</li> }) }
            </ul>
        </section>
    }
}

#[cfg(feature = "yew")]
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

#[cfg(feature = "yew")]
enum FetchOutcome {
    Ok(String),
    Unauthorized,
}

#[cfg(feature = "yew")]
/// A bearer-token-authenticated `GET`, mirroring `panels::fetch_text`'s
/// contract (a plain read here — the builder never mutates state via a
/// typeahead/run round trip).
async fn fetch_text(path: &str, token: Option<&str>) -> Result<FetchOutcome, JsValue> {
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::SameOrigin);
    let headers = Headers::new()?;
    if let Some(t) = token {
        headers.set("X-Pillar-Session", t)?;
    }
    opts.set_headers(&headers);

    let window = web_sys::window().expect("window exists in a browser context");
    let resp_value =
        wasm_bindgen_futures::JsFuture::from(window.fetch_with_str_and_init(path, &opts)).await?;
    let resp: Response = resp_value.dyn_into()?;
    if resp.status() == 401 {
        return Ok(FetchOutcome::Unauthorized);
    }
    let text_value = wasm_bindgen_futures::JsFuture::from(resp.text()?).await?;
    Ok(FetchOutcome::Ok(text_value.as_string().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_observability::{
        parse_psl, CorrelationIndex, LabelSet, SpanEvent, TimeseriesStore, TraceProducer,
    };

    /// The structured builder produces the SAME AST `parse_psl` parses from
    /// the equivalent compact text — proving surface equivalence for the
    /// `metrics` vertical. FAILS without `build_metric_query` composing the
    /// real `PslQueryBuilder`/`PslQuery` model.
    #[test]
    fn structured_builder_matches_the_parsed_equivalent_text_query() {
        let text =
            "select: metrics(cell = eu-1) where: node = n-1 range: now-1h correlate: { window: 30s, anchor: metrics }";
        let parsed = parse_psl(text).expect("fixture text query parses");

        let built = build_metric_query(
            &[("cell".to_string(), "eu-1".to_string())],
            &[("node".to_string(), "n-1".to_string())],
            3600,
            Some((30, SignalKind::Metric)),
        )
        .expect("structured build succeeds");

        assert_eq!(built, parsed, "structured AST must equal the parsed text AST");
        assert_eq!(built.to_text(), parsed.to_text());
        assert_eq!(built.to_text(), text);
    }

    /// A builder with no `where:`/correlate still matches its minimal text
    /// equivalent (covers the "just select + range" shape the UI starts
    /// from before the user adds any predicate).
    #[test]
    fn minimal_selection_matches_its_text_equivalent() {
        let text = "select: metrics range: now-5m";
        let parsed = parse_psl(text).expect("fixture text query parses");
        let built = build_metric_query(&[], &[], 300, None).expect("build succeeds");
        assert_eq!(built, parsed);
    }

    /// The autofill dropdown is populated from a REAL `MetadataIndex` built
    /// from genuinely ingested signals — never a fabricated list — and an
    /// unknown key returns empty. FAILS without `label_key_options`/
    /// `label_value_options` delegating to the real index.
    #[test]
    fn autofill_options_come_from_a_real_metadata_index_fixture_never_fabricated() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::Metric,
            b"a".to_vec(),
            [
                ("cell".to_string(), "eu-1".to_string()),
                ("metric".to_string(), "ingest_bandwidth".to_string()),
            ]
            .into_iter()
            .collect(),
            0,
        );
        store.write_labeled(
            SignalKind::Metric,
            b"b".to_vec(),
            [("cell".to_string(), "us-2".to_string())].into_iter().collect(),
            0,
        );

        let index = MetadataIndex::from_store(&store);

        let keys = label_key_options(&index);
        assert!(keys.contains(&"cell".to_string()));
        assert!(keys.contains(&"metric".to_string()));

        let values = label_value_options(&index, "cell");
        assert_eq!(values, vec!["eu-1".to_string(), "us-2".to_string()]);
        // Never a value that was never actually ingested.
        assert!(!values.contains(&"ap-9".to_string()));

        // An unknown key returns empty — never a placeholder list.
        assert!(label_value_options(&index, "nonexistent-key").is_empty());
    }

    /// The correlate panel pivots to every OTHER signal kind sharing labels
    /// — never back to `metrics` itself.
    #[test]
    fn correlate_candidates_pivot_to_other_kinds_never_metrics_itself() {
        let candidates = correlate_candidates();
        assert!(!candidates.contains(&SignalKind::Metric));
        assert!(candidates.contains(&SignalKind::Log));
        assert!(candidates.contains(&SignalKind::TraceSpan));
        assert!(candidates.contains(&SignalKind::ProfileSample));
        assert!(candidates.contains(&SignalKind::MetadataSample));
        assert_eq!(candidates.len(), 4);
    }

    /// The `metadata` builder produces the SAME AST `parse_psl` parses from
    /// the equivalent compact text — proving surface equivalence for the
    /// `metadata` vertical, mirroring the `metrics` structured-builder test.
    /// FAILS without `build_metadata_query` composing the real
    /// `PslQueryBuilder`/`PslQuery` model.
    #[test]
    fn metadata_structured_builder_matches_the_parsed_equivalent_text_query() {
        let text = "select: metadata(source = node-1) where: env = prod range: now-1h correlate: { window: 30s, anchor: metadata }";
        let parsed = parse_psl(text).expect("fixture text query parses");

        let built = build_metadata_query(
            &[("source".to_string(), "node-1".to_string())],
            &[("env".to_string(), "prod".to_string())],
            3600,
            Some((30, SignalKind::MetadataSample)),
        )
        .expect("structured build succeeds");

        assert_eq!(built, parsed, "structured AST must equal the parsed text AST");
        assert_eq!(built.to_text(), parsed.to_text());
        assert_eq!(built.to_text(), text);
    }

    /// A `metadata` builder with no `where:`/correlate still matches its
    /// minimal text equivalent (covers the "just select + range" shape the
    /// UI starts from before the user adds any predicate).
    #[test]
    fn metadata_minimal_selection_matches_its_text_equivalent() {
        let text = "select: metadata range: now-5m";
        let parsed = parse_psl(text).expect("fixture text query parses");
        let built = build_metadata_query(&[], &[], 300, None).expect("build succeeds");
        assert_eq!(built, parsed);
    }

    /// The `metadata` vertical's autofill dropdown is populated from a REAL
    /// `MetadataIndex` built from genuinely ingested `MetadataSample`
    /// signals — never a fabricated list — and an unknown key returns
    /// empty, mirroring the `metrics` autofill-fixture test against a real
    /// metadata fixture.
    #[test]
    fn metadata_autofill_options_come_from_a_real_metadata_index_fixture_never_fabricated() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::MetadataSample,
            b"a".to_vec(),
            [
                ("source".to_string(), "node-1".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]
            .into_iter()
            .collect(),
            0,
        );
        store.write_labeled(
            SignalKind::MetadataSample,
            b"b".to_vec(),
            [("source".to_string(), "node-2".to_string())].into_iter().collect(),
            0,
        );

        let index = MetadataIndex::from_store(&store);

        let keys = label_key_options(&index);
        assert!(keys.contains(&"source".to_string()));
        assert!(keys.contains(&"env".to_string()));

        let values = label_value_options(&index, "source");
        assert_eq!(values, vec!["node-1".to_string(), "node-2".to_string()]);
        // Never a value that was never actually ingested.
        assert!(!values.contains(&"node-9".to_string()));

        // An unknown key returns empty — never a placeholder list.
        assert!(label_value_options(&index, "nonexistent-key").is_empty());
    }

    /// The `metadata` correlate panel pivots to every OTHER signal kind
    /// sharing labels — never back to `metadata` itself.
    #[test]
    fn metadata_correlate_candidates_pivot_to_other_kinds_never_metadata_itself() {
        let candidates = correlate_candidates_metadata();
        assert!(!candidates.contains(&SignalKind::MetadataSample));
        assert!(candidates.contains(&SignalKind::Metric));
        assert!(candidates.contains(&SignalKind::Log));
        assert!(candidates.contains(&SignalKind::TraceSpan));
        assert!(candidates.contains(&SignalKind::ProfileSample));
        assert_eq!(candidates.len(), 4);
    }

    /// The `traces` builder produces the SAME AST `parse_psl` parses from
    /// the equivalent compact text — proving surface equivalence for the
    /// `traces` vertical, mirroring the `metrics`/`metadata`
    /// structured-builder tests. FAILS without `build_trace_query` composing
    /// the real `PslQueryBuilder`/`PslQuery` model.
    #[test]
    fn trace_structured_builder_matches_the_parsed_equivalent_text_query() {
        let text = "select: traces(trace = t-1) where: node = n-1 range: now-1h correlate: { window: 30s, anchor: traces }";
        let parsed = parse_psl(text).expect("fixture text query parses");

        let built = build_trace_query(
            &[("trace".to_string(), "t-1".to_string())],
            &[("node".to_string(), "n-1".to_string())],
            3600,
            Some((30, SignalKind::TraceSpan)),
        )
        .expect("structured build succeeds");

        assert_eq!(built, parsed, "structured AST must equal the parsed text AST");
        assert_eq!(built.to_text(), parsed.to_text());
        assert_eq!(built.to_text(), text);
    }

    /// A `traces` builder with no `where:`/correlate still matches its
    /// minimal text equivalent (covers the "just select + range" shape the
    /// UI starts from before the user adds any predicate).
    #[test]
    fn trace_minimal_selection_matches_its_text_equivalent() {
        let text = "select: traces range: now-5m";
        let parsed = parse_psl(text).expect("fixture text query parses");
        let built = build_trace_query(&[], &[], 300, None).expect("build succeeds");
        assert_eq!(built, parsed);
    }

    /// The `traces` vertical's autofill dropdown is populated from a REAL
    /// `MetadataIndex` built against a genuine trace fixture — real
    /// `SpanEvent`s recorded through the actual `TraceProducer` onto the
    /// shared store (never a hardcoded/fabricated list) — and an unknown key
    /// returns empty, mirroring the `metrics`/`metadata` autofill-fixture
    /// tests.
    #[test]
    fn trace_autofill_options_come_from_a_real_metadata_index_fixture_never_fabricated() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index_spine = CorrelationIndex::new();

        let mut node_labels_a: LabelSet = LabelSet::new();
        node_labels_a.insert("node".to_string(), "n-1".to_string());
        let mut producer_a = TraceProducer::new(node_labels_a);
        producer_a.set_enabled(true);
        producer_a.record(
            &mut store,
            &mut index_spine,
            &SpanEvent::root("t-1", "s-1", "handle_request"),
            0,
        );

        let mut node_labels_b: LabelSet = LabelSet::new();
        node_labels_b.insert("node".to_string(), "n-2".to_string());
        let mut producer_b = TraceProducer::new(node_labels_b);
        producer_b.set_enabled(true);
        producer_b.record(
            &mut store,
            &mut index_spine,
            &SpanEvent::child("t-2", "s-2", "s-1", "apply_op"),
            1,
        );

        let index = MetadataIndex::from_store(&store);

        let keys = label_key_options(&index);
        assert!(keys.contains(&"node".to_string()));
        assert!(keys.contains(&"trace".to_string()));

        let values = label_value_options(&index, "node");
        assert_eq!(values, vec!["n-1".to_string(), "n-2".to_string()]);
        // Never a value that was never actually recorded.
        assert!(!values.contains(&"n-9".to_string()));

        let trace_values = label_value_options(&index, "trace");
        assert_eq!(trace_values, vec!["t-1".to_string(), "t-2".to_string()]);

        // An unknown key returns empty — never a placeholder list.
        assert!(label_value_options(&index, "nonexistent-key").is_empty());
    }

    /// The `traces` correlate panel pivots to every OTHER signal kind
    /// sharing labels — never back to `traces` itself.
    #[test]
    fn trace_correlate_candidates_pivot_to_other_kinds_never_traces_itself() {
        let candidates = correlate_candidates_traces();
        assert!(!candidates.contains(&SignalKind::TraceSpan));
        assert!(candidates.contains(&SignalKind::Metric));
        assert!(candidates.contains(&SignalKind::Log));
        assert!(candidates.contains(&SignalKind::ProfileSample));
        assert!(candidates.contains(&SignalKind::MetadataSample));
        assert_eq!(candidates.len(), 4);
    }

    /// The `profiles` structured builder produces the SAME AST `parse_psl`
    /// parses from the equivalent compact text — the profiles analogue of
    /// `structured_builder_matches_the_parsed_equivalent_text_query`. FAILS
    /// without `build_profile_query` composing the real `PslQueryBuilder`/
    /// `PslQuery` model against `SignalKind::ProfileSample`.
    #[test]
    fn structured_profile_builder_matches_the_parsed_equivalent_text_query() {
        let text =
            "select: profiles(cell = eu-1) where: node = n-1 range: now-1h correlate: { window: 30s, anchor: profiles }";
        let parsed = parse_psl(text).expect("fixture text query parses");

        let built = build_profile_query(
            &[("cell".to_string(), "eu-1".to_string())],
            &[("node".to_string(), "n-1".to_string())],
            3600,
            Some((30, SignalKind::ProfileSample)),
        )
        .expect("structured build succeeds");

        assert_eq!(built, parsed, "structured AST must equal the parsed text AST");
        assert_eq!(built.to_text(), parsed.to_text());
        assert_eq!(built.to_text(), text);
    }

    /// A `profiles` builder with no `where:`/correlate still matches its
    /// minimal text equivalent.
    #[test]
    fn minimal_profile_selection_matches_its_text_equivalent() {
        let text = "select: profiles range: now-5m";
        let parsed = parse_psl(text).expect("fixture text query parses");
        let built = build_profile_query(&[], &[], 300, None).expect("build succeeds");
        assert_eq!(built, parsed);
    }

    /// The `profiles` autofill is populated from a REAL `MetadataIndex` built
    /// from genuinely ingested PROFILE signals — never a fabricated list —
    /// and an unknown key returns empty. FAILS without the shared
    /// `label_key_options`/`label_value_options` delegating to the real index
    /// over a real profile fixture.
    #[test]
    fn profile_autofill_options_come_from_a_real_metadata_index_fixture_never_fabricated() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::ProfileSample,
            b"stack=a;b;c".to_vec(),
            [
                ("cell".to_string(), "eu-1".to_string()),
                ("service".to_string(), "ingest".to_string()),
            ]
            .into_iter()
            .collect(),
            0,
        );
        store.write_labeled(
            SignalKind::ProfileSample,
            b"stack=d;e".to_vec(),
            [("cell".to_string(), "us-2".to_string())].into_iter().collect(),
            0,
        );

        let index = MetadataIndex::from_store(&store);

        let keys = label_key_options(&index);
        assert!(keys.contains(&"cell".to_string()));
        assert!(keys.contains(&"service".to_string()));

        let values = label_value_options(&index, "cell");
        assert_eq!(values, vec!["eu-1".to_string(), "us-2".to_string()]);
        assert!(!values.contains(&"ap-9".to_string()));

        assert!(label_value_options(&index, "nonexistent-key").is_empty());
    }

    /// The `profiles` correlate panel pivots to every OTHER signal kind —
    /// never back to `profiles` itself.
    #[test]
    fn profile_correlate_candidates_pivot_to_other_kinds_never_profiles_itself() {
        let candidates = profile_correlate_candidates();
        assert!(!candidates.contains(&SignalKind::ProfileSample));
        assert!(candidates.contains(&SignalKind::Metric));
        assert!(candidates.contains(&SignalKind::Log));
        assert!(candidates.contains(&SignalKind::TraceSpan));
        assert!(candidates.contains(&SignalKind::MetadataSample));
        assert_eq!(candidates.len(), 4);
    }

    /// The `logs` structured builder produces the SAME AST `parse_psl`
    /// parses from the equivalent compact text — proving surface
    /// equivalence for the `logs` vertical, mirroring the other four
    /// verticals' structured-builder tests. Unique to `logs`: the
    /// `select:` clause composes [`LogFilter`]s (`level = error`, `message
    /// =~ "connection timeout"`, `field.x = alpha`) rather than the plain
    /// label equality the other kinds' `select:` uses. FAILS without
    /// `build_log_query` composing the real `PslQueryBuilder`/`PslQuery`
    /// model with the correct `Eq`/`Match` operator per field.
    #[test]
    fn log_structured_builder_matches_the_parsed_equivalent_text_query() {
        let text = r#"select: logs(level = error, message =~ "connection timeout", field.x = alpha) where: cell = eu-1 range: now-1h correlate: { window: 30s, anchor: logs }"#;
        let parsed = parse_psl(text).expect("fixture text query parses");

        let built = build_log_query(
            &[
                LogFilter::eq("level", "error"),
                LogFilter::matches("message", "connection timeout"),
                LogFilter::eq("field.x", "alpha"),
            ],
            &[("cell".to_string(), "eu-1".to_string())],
            3600,
            Some((30, SignalKind::Log)),
        )
        .expect("structured build succeeds");

        assert_eq!(built, parsed, "structured AST must equal the parsed text AST");
        assert_eq!(built.to_text(), parsed.to_text());
        assert_eq!(built.to_text(), text);
    }

    /// A `logs` builder with no `select:` filters/`where:`/correlate still
    /// matches its minimal text equivalent (covers the "just select + range"
    /// shape the UI starts from before the user adds any filter).
    #[test]
    fn log_minimal_selection_matches_its_text_equivalent() {
        let text = "select: logs range: now-5m";
        let parsed = parse_psl(text).expect("fixture text query parses");
        let built = build_log_query(&[], &[], 300, None).expect("build succeeds");
        assert_eq!(built, parsed);
    }

    /// The log-filter-specific query-correctness assertion: a `message`
    /// filter composes the substring `=~` operator while a `level`/`field.x`
    /// filter composes the exact `=` operator — proven distinct by
    /// round-tripping each through the parser, so a substring grep can never
    /// collapse to an exact equality (or vice versa). FAILS without
    /// `LogFilter`/`LogFilter::for_key` picking the operator the shared PSL
    /// model requires per field.
    #[test]
    fn log_message_filter_is_a_substring_match_while_level_is_exact() {
        let message_filter = LogFilter::for_key("message", "timeout");
        assert!(message_filter.is_match, "message auto-selects the substring operator");
        assert_eq!(message_filter.to_predicate(), Predicate::matches("message", "timeout"));

        let level_filter = LogFilter::for_key("level", "error");
        assert!(!level_filter.is_match, "level auto-selects exact equality");
        assert_eq!(level_filter.to_predicate(), Predicate::eq("level", "error"));

        let field_filter = LogFilter::for_key("field.x", "alpha");
        assert!(!field_filter.is_match, "field.x auto-selects exact equality");
        assert_eq!(field_filter.to_predicate(), Predicate::eq("field.x", "alpha"));

        // Round-trip through the parser: a query built with the substring
        // filter must parse back to the SAME AST as the equivalent `=~` text
        // — never collapsing to `=`.
        let built = build_log_query(&[message_filter], &[], 300, None).expect("build succeeds");
        let parsed = parse_psl(r#"select: logs(message =~ timeout) range: now-5m"#)
            .expect("fixture text query parses");
        assert_eq!(built, parsed);

        let built_eq = build_log_query(&[level_filter], &[], 300, None).expect("build succeeds");
        let parsed_eq =
            parse_psl("select: logs(level = error) range: now-5m").expect("fixture text query parses");
        assert_eq!(built_eq, parsed_eq);
    }

    /// The `logs` vertical's autofill dropdown (for the `where:` label
    /// filters, shared with the other four verticals) is populated from a
    /// REAL `MetadataIndex` built from genuinely ingested LOG signals —
    /// never a fabricated list — and an unknown key returns empty, mirroring
    /// the `metrics`/`metadata`/`traces`/`profiles` autofill-fixture tests.
    #[test]
    fn log_autofill_options_come_from_a_real_metadata_index_fixture_never_fabricated() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::Log,
            b"level=error msg=connection timeout".to_vec(),
            [
                ("cell".to_string(), "eu-1".to_string()),
                ("service".to_string(), "ingest".to_string()),
            ]
            .into_iter()
            .collect(),
            0,
        );
        store.write_labeled(
            SignalKind::Log,
            b"level=info msg=served".to_vec(),
            [("cell".to_string(), "us-2".to_string())].into_iter().collect(),
            0,
        );

        let index = MetadataIndex::from_store(&store);

        let keys = label_key_options(&index);
        assert!(keys.contains(&"cell".to_string()));
        assert!(keys.contains(&"service".to_string()));

        let values = label_value_options(&index, "cell");
        assert_eq!(values, vec!["eu-1".to_string(), "us-2".to_string()]);
        // Never a value that was never actually ingested.
        assert!(!values.contains(&"ap-9".to_string()));

        // An unknown key returns empty — never a placeholder list.
        assert!(label_value_options(&index, "nonexistent-key").is_empty());
    }

    /// The `logs` correlate panel pivots to every OTHER signal kind sharing
    /// labels — never back to `logs` itself.
    #[test]
    fn log_correlate_candidates_pivot_to_other_kinds_never_logs_itself() {
        let candidates = correlate_candidates_logs();
        assert!(!candidates.contains(&SignalKind::Log));
        assert!(candidates.contains(&SignalKind::Metric));
        assert!(candidates.contains(&SignalKind::TraceSpan));
        assert!(candidates.contains(&SignalKind::ProfileSample));
        assert!(candidates.contains(&SignalKind::MetadataSample));
        assert_eq!(candidates.len(), 4);
    }
}
