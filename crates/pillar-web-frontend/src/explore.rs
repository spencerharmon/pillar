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
    use pillar_observability::{parse_psl, TimeseriesStore};

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
}
