//! The **observability console** — the Observability section's real, multi-tab
//! surface over the node's *live* observability substrate
//! (`/portal/obs/live/*`). Before this, the portal surfaced only the five
//! Explore query builders and left the rest of the live machinery — per-kind
//! signal counts, dashboard materialization, recording rules, and alerts —
//! served by the backend but rendered nowhere. This wires each of those live
//! endpoints into a tab, so the observability machinery is actually visible.
//!
//! The wire framing (request bodies) and the response parsers are **pure,
//! host-testable** Rust: every backend contract is pinned by a `cargo test`
//! against the exact line formats `pillar-cli`'s `dispatch_obs_live_*` emit.
//! The [`ObservabilityConsole`] component (behind the `yew` feature) is the thin
//! fetch/render wiring; it reuses the portal's shared `http`/`get_url` helpers
//! and mounts the existing `ObservabilityTile` (the Explore builders) verbatim
//! for the Explore tab.

/// A parsed per-kind signal count from `GET /portal/obs/live/kinds`
/// (`KIND <tag> COUNT <n>` lines).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindCount {
    /// The signal-kind tag (`metric`/`log`/`trace`/`profile`/`metadata`, as the
    /// backend's `signal_kind_tag` emits).
    pub kind: String,
    /// The number of signals of that kind currently in the live store.
    pub count: u64,
}

/// Parse the `GET /portal/obs/live/kinds` body: one `KIND <tag> COUNT <n>` line
/// per signal kind. Malformed lines are skipped (never fabricated).
#[must_use]
pub fn parse_kind_counts(body: &str) -> Vec<KindCount> {
    body.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            match (it.next(), it.next(), it.next(), it.next()) {
                (Some("KIND"), Some(kind), Some("COUNT"), Some(n)) => {
                    n.parse::<u64>().ok().map(|count| KindCount {
                        kind: kind.to_owned(),
                        count,
                    })
                }
                _ => None,
            }
        })
        .collect()
}

/// One materialized dashboard panel from `POST /portal/obs/live/dashboard`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashPanel {
    /// The panel name (the `<name>` of the `<name>=<psl>` spec line).
    pub name: String,
    /// The number of signals the panel's query matched.
    pub count: usize,
    /// The matched signals, in returned order.
    pub signals: Vec<DashSignal>,
}

/// One signal row inside a materialized [`DashPanel`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashSignal {
    /// The signal id.
    pub id: String,
    /// The signal-kind tag.
    pub kind: String,
    /// The signal payload (verbatim from the store).
    pub payload: String,
}

/// Parse the `POST /portal/obs/live/dashboard` body: a `PANEL <name> COUNT <n>`
/// line opens a panel, each following `SIGNAL <id> KIND <tag> PAYLOAD <payload>`
/// line adds a signal to the current panel (payload may contain spaces — it is
/// the remainder of the line).
#[must_use]
pub fn parse_dashboard(body: &str) -> Vec<DashPanel> {
    let mut panels: Vec<DashPanel> = Vec::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("PANEL ") {
            // `<name> COUNT <n>`
            if let Some((name, tail)) = rest.rsplit_once(" COUNT ") {
                let count = tail.trim().parse::<usize>().unwrap_or(0);
                panels.push(DashPanel {
                    name: name.trim().to_owned(),
                    count,
                    signals: Vec::new(),
                });
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("SIGNAL ") {
            // `<id> KIND <tag> PAYLOAD <payload...>`
            if let Some((id, after_id)) = rest.split_once(" KIND ") {
                if let Some((kind, payload)) = after_id.split_once(" PAYLOAD ") {
                    if let Some(panel) = panels.last_mut() {
                        panel.signals.push(DashSignal {
                            id: id.trim().to_owned(),
                            kind: kind.trim().to_owned(),
                            payload: payload.to_owned(),
                        });
                    }
                }
            }
        }
    }
    panels
}

/// Build the `POST /portal/obs/live/dashboard` request body: the session token
/// on the first line, then the caller's `<name>=<psl>` panel-spec lines
/// verbatim.
#[must_use]
pub fn dashboard_request_body(token: &str, spec: &str) -> String {
    format!("{token}\n{}", spec.trim())
}

/// Build the `POST /portal/obs/live/recording` request body: token first line,
/// then the `<id>|<kind>|<psl>|<emit>` rule spec.
#[must_use]
pub fn recording_request_body(token: &str, id: &str, kind: &str, psl: &str, emit: &str) -> String {
    format!(
        "{token}\n{}|{}|{}|{}",
        id.trim(),
        kind.trim(),
        psl.trim(),
        emit.trim()
    )
}

/// Build the `POST /portal/obs/live/alert` request body: token first line, then
/// the `<id>|<psl>|<op>|<threshold>` alert spec.
#[must_use]
pub fn alert_request_body(token: &str, id: &str, psl: &str, op: &str, threshold: &str) -> String {
    format!(
        "{token}\n{}|{}|{}|{}",
        id.trim(),
        psl.trim(),
        op.trim(),
        threshold.trim()
    )
}

#[cfg(feature = "yew")]
pub use yew_impl::ObservabilityConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        alert_request_body, dashboard_request_body, parse_dashboard, parse_kind_counts,
        recording_request_body, DashPanel, KindCount,
    };
    use crate::auth::use_auth;
    use crate::components::data_table::{Column, DataTable};
    use crate::drilldown::DrilldownPanel;
    use crate::drilldown_live::{build_drilldowns, parse_correlate_response};
    use crate::portal::{get_url, http, input_value, ObservabilityTile};
    use crate::primitives::{Chart, ChartKind, StatCard, Tabs};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// The observability console tabs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Tab {
        Overview,
        Explore,
        Drilldown,
        Dashboards,
        Rules,
        Alerts,
    }

    impl Tab {
        const ALL: [Tab; 6] = [
            Tab::Overview,
            Tab::Explore,
            Tab::Drilldown,
            Tab::Dashboards,
            Tab::Rules,
            Tab::Alerts,
        ];
        fn label(self) -> &'static str {
            match self {
                Tab::Overview => "Overview",
                Tab::Explore => "Explore",
                Tab::Drilldown => "Drilldown",
                Tab::Dashboards => "Dashboards",
                Tab::Rules => "Recording rules",
                Tab::Alerts => "Alerts",
            }
        }
    }

    /// The Observability section content: a tab bar over the live substrate.
    /// Overview shows per-kind live signal counts; Explore mounts the existing
    /// query builders; Dashboards materializes panels; Rules and Alerts register
    /// + evaluate against the live store — every tab a real `/portal/obs/live/*`
    /// round trip.
    #[function_component(ObservabilityConsole)]
    pub fn observability_console() -> Html {
        let auth = use_auth();
        let tab = use_state(|| Tab::Overview);
        let counts = use_state(Vec::<KindCount>::new);

        // Load the live per-kind counts on mount / token change.
        {
            let (auth, counts) = (auth.clone(), counts.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let counts = counts.clone();
                    let url = get_url("/portal/obs/live/kinds", &token, &[]);
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                counts.set(parse_kind_counts(&r.body));
                            }
                        }
                    });
                }
                || ()
            });
        }

        let tabs_ui = {
            let tab = tab.clone();
            let labels: Vec<String> = Tab::ALL.iter().map(|t| t.label().to_owned()).collect();
            let selected = Tab::ALL.iter().position(|t| *t == *tab).unwrap_or(0);
            let onselect = Callback::from(move |i: usize| {
                if let Some(t) = Tab::ALL.get(i) {
                    tab.set(*t);
                }
            });
            html! { <Tabs tabs={labels} {selected} {onselect} /> }
        };

        let body = match *tab {
            Tab::Overview => render_overview(&counts),
            Tab::Explore => html! { <ObservabilityTile /> },
            Tab::Drilldown => html! { <DrilldownTab /> },
            Tab::Dashboards => html! { <DashboardsTab /> },
            Tab::Rules => html! { <RulesTab /> },
            Tab::Alerts => html! { <AlertsTab /> },
        };

        html! {
            <div class="tile" id="observability-console">
                <h3>{ "Observability" }</h3>
                <p>{ "Live metrics, logs, traces, profiles, and metadata over this \
                      node's observability substrate." }</p>
                <div class="obs-tabpanel-head">{ tabs_ui }</div>
                <div class="obs-tabpanel">{ body }</div>
            </div>
        }
    }

    /// The Overview tab: a live-count stat card per signal kind plus a bar chart
    /// of the distribution, built on the shared design-system primitives.
    fn render_overview(counts: &[KindCount]) -> Html {
        if counts.is_empty() {
            return html! { <p class="ds-empty">{ "No live signals yet, or no live \
            substrate attached to this node." }</p> };
        }
        let bars: Vec<f64> = counts.iter().map(|c| c.count as f64).collect();
        html! {
            <>
                <div class="obs-statgrid">
                    { for counts.iter().map(|c| html! {
                        <StatCard label={c.kind.clone()} value={c.count.to_string()} />
                    }) }
                </div>
                <div class="obs-panel">
                    <h4>{ "Signal distribution" }</h4>
                    <Chart values={bars} kind={ChartKind::Bar} width={480.0} height={120.0} />
                </div>
            </>
        }
    }

    /// The Drilldown tab: runs a correlate PSL query against the live store and
    /// reconstructs a real [`Drilldown`](crate::drilldown::Drilldown) per anchor
    /// from the server's `SIGNAL`/`GROUP` response, mounting the shared
    /// `DrilldownPanel` with the node's actual correlated signals. No
    /// client-side store, no fabrication.
    #[function_component(DrilldownTab)]
    fn drilldown_tab() -> Html {
        let auth = use_auth();
        let query = use_state(|| "correlate: metric".to_owned());
        let drills = use_state(Vec::new);
        let msg = use_state(|| None::<String>);

        let on_query = {
            let query = query.clone();
            Callback::from(move |e: InputEvent| query.set(input_value(&e)))
        };
        let run = {
            let (auth, query, drills, msg) =
                (auth.clone(), query.clone(), drills.clone(), msg.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = format!("{token}\n{}", *query);
                let (drills, msg) = (drills.clone(), msg.clone());
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/query", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            let built = build_drilldowns(&parse_correlate_response(&r.body));
                            if built.is_empty() {
                                msg.set(Some(
                                    "No correlated drilldowns for that query.".to_owned(),
                                ));
                            } else {
                                msg.set(None);
                            }
                            drills.set(built);
                        }
                        Ok(r) => msg.set(Some(r.body.trim().to_owned())),
                        Err(_) => msg.set(Some("request failed".to_owned())),
                    }
                });
            })
        };

        html! {
            <div class="res-change">
                <div class="res-toolbar">
                    <input class="ds-table__filter" type="text"
                           placeholder="correlate PSL query"
                           value={(*query).clone()} oninput={on_query} />
                    <button class="ds-tab" onclick={run}>{ "Drill down" }</button>
                </div>
                <p class="ds-empty">{ "Runs psl_correlate over the live store and pivots \
                    each metric anchor into its correlated logs, traces, profiles, and \
                    metadata." }</p>
                if let Some(m) = &*msg {
                    <p class="obs-msg">{ m }</p>
                }
                { for drills.iter().map(|d| html! { <DrilldownPanel drilldown={d.clone()} /> }) }
            </div>
        }
    }

    /// The Dashboards tab: a `<name>=<psl>` panel-spec editor that materializes
    /// panels off the live store and renders each panel's matched signals.
    #[function_component(DashboardsTab)]
    fn dashboards_tab() -> Html {
        let auth = use_auth();
        let spec = use_state(String::new);
        let panels = use_state(Vec::<DashPanel>::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let on_spec = {
            let spec = spec.clone();
            Callback::from(move |e: InputEvent| spec.set(input_value(&e)))
        };
        let materialize = {
            let (auth, spec, panels, msg, busy) = (
                auth.clone(),
                spec.clone(),
                panels.clone(),
                msg.clone(),
                busy.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = dashboard_request_body(&token, &spec);
                let (panels, msg, busy) = (panels.clone(), msg.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/dashboard", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            panels.set(parse_dashboard(&r.body));
                            msg.set(None);
                        }
                        Ok(r) => msg.set(Some((r.body.trim().to_owned(), false))),
                        Err(_) => msg.set(Some(("request failed".to_owned(), false))),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="obs-subpanel">
                <label>{ "Panels — one \u{201c}name=<PSL query>\u{201d} per line" }</label>
                <textarea
                    class="obs-spec"
                    rows="4"
                    placeholder="errors=select:log where:level=error\nrequests=select:metric where:name=http_requests"
                    oninput={on_spec}
                    value={(*spec).clone()}
                />
                <button type="button" class="obs-run" disabled={*busy} onclick={materialize}>
                    { if *busy { "Materializing\u{2026}" } else { "Materialize" } }
                </button>
                { render_msg(&msg) }
                { for panels.iter().map(render_panel) }
            </div>
        }
    }

    /// Render one materialized dashboard panel as a titled signal table,
    /// rendered through the shared [`DataTable`] component library primitive
    /// (the sortable/filterable console table) — the first real consumer of the
    /// Phase 1 library, mapping each [`DashSignal`] onto the signal/kind/payload
    /// columns.
    fn render_panel(panel: &DashPanel) -> Html {
        let columns = vec![
            Column::text("signal"),
            Column::text("kind"),
            Column::unsortable("payload"),
        ];
        let rows: Vec<Vec<String>> = panel
            .signals
            .iter()
            .map(|s| vec![s.id.clone(), s.kind.clone(), s.payload.clone()])
            .collect();
        html! {
            <section class="obs-panel" data-panel={panel.name.clone()}>
                <h4>{ format!("{} ({})", panel.name, panel.count) }</h4>
                if panel.signals.is_empty() {
                    <p class="ds-empty">{ "No signals matched." }</p>
                } else {
                    <DataTable
                        columns={columns}
                        rows={rows}
                        page_size={25}
                        class={classes!("obs-table")}
                    />
                }
            </section>
        }
    }

    /// The Recording-rules tab: register + evaluate a rule over the live store,
    /// showing whether it fired and its derived series.
    #[function_component(RulesTab)]
    fn rules_tab() -> Html {
        let auth = use_auth();
        let id = use_state(String::new);
        let kind = use_state(|| "log-count".to_owned());
        let psl = use_state(String::new);
        let emit = use_state(String::new);
        let result = use_state(Vec::<String>::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let field = |st: UseStateHandle<String>| {
            Callback::from(move |e: InputEvent| st.set(input_value(&e)))
        };
        let run = {
            let (auth, id, kind, psl, emit, result, msg, busy) = (
                auth.clone(),
                id.clone(),
                kind.clone(),
                psl.clone(),
                emit.clone(),
                result.clone(),
                msg.clone(),
                busy.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = recording_request_body(&token, &id, &kind, &psl, &emit);
                let (result, msg, busy) = (result.clone(), msg.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/recording", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            result.set(r.body.lines().map(str::to_owned).collect());
                            msg.set(None);
                        }
                        Ok(r) => msg.set(Some((r.body.trim().to_owned(), false))),
                        Err(_) => msg.set(Some(("request failed".to_owned(), false))),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="obs-subpanel">
                <label>{ "Recording rule" }</label>
                <input placeholder="rule id" value={(*id).clone()} oninput={field(id.clone())} />
                <select value={(*kind).clone()} onchange={{
                    let kind = kind.clone();
                    Callback::from(move |e: Event| {
                        use wasm_bindgen::JsCast;
                        if let Some(t) = e.target().and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok()) {
                            kind.set(t.value());
                        }
                    })
                }}>
                    <option value="log-count">{ "log-count" }</option>
                    <option value="trace-count">{ "trace-count" }</option>
                    <option value="metric-count">{ "metric-count" }</option>
                </select>
                <input placeholder="PSL query" value={(*psl).clone()} oninput={field(psl.clone())} />
                <input placeholder="emit metric name" value={(*emit).clone()} oninput={field(emit.clone())} />
                <button type="button" class="obs-run" disabled={*busy} onclick={run}>
                    { if *busy { "Evaluating\u{2026}" } else { "Register & evaluate" } }
                </button>
                { render_msg(&msg) }
                { render_lines(&result) }
            </div>
        }
    }

    /// The Alerts tab: register + evaluate an alert over the live store, showing
    /// any fired notifications.
    #[function_component(AlertsTab)]
    fn alerts_tab() -> Html {
        let auth = use_auth();
        let id = use_state(String::new);
        let psl = use_state(String::new);
        let op = use_state(|| "gt".to_owned());
        let threshold = use_state(String::new);
        let result = use_state(Vec::<String>::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let field = |st: UseStateHandle<String>| {
            Callback::from(move |e: InputEvent| st.set(input_value(&e)))
        };
        let run = {
            let (auth, id, psl, op, threshold, result, msg, busy) = (
                auth.clone(),
                id.clone(),
                psl.clone(),
                op.clone(),
                threshold.clone(),
                result.clone(),
                msg.clone(),
                busy.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = alert_request_body(&token, &id, &psl, &op, &threshold);
                let (result, msg, busy) = (result.clone(), msg.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/alert", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            let lines: Vec<String> = r.body.lines().map(str::to_owned).collect();
                            if lines.iter().all(|l| l.trim().is_empty()) {
                                result.set(vec![
                                    "No alert fired (predicate not tripped).".to_owned()
                                ]);
                            } else {
                                result.set(lines);
                            }
                            msg.set(None);
                        }
                        Ok(r) => msg.set(Some((r.body.trim().to_owned(), false))),
                        Err(_) => msg.set(Some(("request failed".to_owned(), false))),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="obs-subpanel">
                <label>{ "Alert" }</label>
                <input placeholder="alert id" value={(*id).clone()} oninput={field(id.clone())} />
                <input placeholder="PSL query" value={(*psl).clone()} oninput={field(psl.clone())} />
                <select value={(*op).clone()} onchange={{
                    let op = op.clone();
                    Callback::from(move |e: Event| {
                        use wasm_bindgen::JsCast;
                        if let Some(t) = e.target().and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok()) {
                            op.set(t.value());
                        }
                    })
                }}>
                    <option value="gt">{ "greater than" }</option>
                    <option value="lt">{ "less than" }</option>
                </select>
                <input placeholder="threshold" value={(*threshold).clone()} oninput={field(threshold.clone())} />
                <button type="button" class="obs-run" disabled={*busy} onclick={run}>
                    { if *busy { "Evaluating\u{2026}" } else { "Register & evaluate" } }
                </button>
                { render_msg(&msg) }
                { render_lines(&result) }
            </div>
        }
    }

    /// A simple result-line list.
    fn render_lines(lines: &[String]) -> Html {
        if lines.is_empty() {
            return Html::default();
        }
        html! {
            <ul class="obs-results">
                { for lines.iter().map(|l| html! { <li>{ l.clone() }</li> }) }
            </ul>
        }
    }

    /// An inline status message (error styled distinctly).
    fn render_msg(msg: &Option<(String, bool)>) -> Html {
        match msg {
            Some((text, ok)) => {
                let class = if *ok { "obs-msg" } else { "obs-msg is-error" };
                html! { <p class={class}>{ text.clone() }</p> }
            }
            None => Html::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mount-audit (anti-facade DoD): the observability console must actually
    /// CONSUME the Phase 1 component library — this file references
    /// `crate::components::data_table::{Column, DataTable}` and renders the
    /// materialized-panel table through `DataTable`. We assert that on the
    /// module's own source so the library can never silently regress back to a
    /// hand-rolled `<table>` (an orphaned library with zero call sites is the
    /// exact facade failure this ROI bans).
    #[test]
    fn obs_console_consumes_the_datatable_component() {
        let src = include_str!("obs_console.rs");
        assert!(
            src.contains("crate::components::data_table"),
            "obs_console.rs no longer imports the components::data_table library"
        );
        assert!(
            src.contains("<DataTable"),
            "obs_console.rs no longer renders the shared DataTable primitive"
        );
    }

    #[test]
    fn kind_counts_parse_the_backend_line_format() {
        let body = "KIND metric COUNT 12\nKIND log COUNT 3\nKIND trace COUNT 0\n";
        let got = parse_kind_counts(body);
        assert_eq!(
            got,
            vec![
                KindCount {
                    kind: "metric".into(),
                    count: 12
                },
                KindCount {
                    kind: "log".into(),
                    count: 3
                },
                KindCount {
                    kind: "trace".into(),
                    count: 0
                },
            ]
        );
    }

    #[test]
    fn kind_counts_skip_malformed_lines_and_never_fabricate() {
        let body = "KIND metric COUNT 5\ngarbage\nKIND log COUNT notanumber\n\n";
        let got = parse_kind_counts(body);
        assert_eq!(
            got,
            vec![KindCount {
                kind: "metric".into(),
                count: 5
            }]
        );
    }

    #[test]
    fn dashboard_parses_panels_and_their_signals() {
        let body = "PANEL errors COUNT 2\n\
                    SIGNAL s1 KIND log PAYLOAD level=error msg=boom\n\
                    SIGNAL s2 KIND log PAYLOAD level=error msg=again\n\
                    PANEL empty COUNT 0\n";
        let got = parse_dashboard(body);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "errors");
        assert_eq!(got[0].count, 2);
        assert_eq!(got[0].signals.len(), 2);
        // Payload keeps its internal spaces (remainder of the line).
        assert_eq!(got[0].signals[0].id, "s1");
        assert_eq!(got[0].signals[0].kind, "log");
        assert_eq!(got[0].signals[0].payload, "level=error msg=boom");
        assert_eq!(got[1].name, "empty");
        assert_eq!(got[1].count, 0);
        assert!(got[1].signals.is_empty());
    }

    #[test]
    fn request_bodies_put_the_token_first_and_match_backend_specs() {
        assert_eq!(
            dashboard_request_body("tok", " a=select:metric \n"),
            "tok\na=select:metric"
        );
        assert_eq!(
            recording_request_body("tok", " r1 ", " log-count ", " select:log ", " errs "),
            "tok\nr1|log-count|select:log|errs"
        );
        assert_eq!(
            alert_request_body("tok", " a1 ", " select:log ", " gt ", " 5 "),
            "tok\na1|select:log|gt|5"
        );
    }
}
