//! The **Resource Sets** console — pillar's ArgoCD-Applications view.
//!
//! Lists every ResourceSet (the synthesized Default set included) with its
//! rolled-up health / sync status, and — on selecting one — renders its
//! interconnected resource GRAPH (the set at the root, an edge to each member
//! labeled with the member's health) alongside a member table and the pending
//! reconcile plan (adopt / prune).
//!
//! The wire parsers ([`parse_set_list`], [`parse_set_detail`]) are plain,
//! host-testable logic over the `GET /portal/resource/sets` and `GET
//! /portal/resource/set` line protocols; the Yew view (behind the `yew`
//! feature) is thin fetch-and-render wiring, reusing
//! [`crate::primitives::Graph`].

/// One row of the ResourceSet list: its name and rolled-up status.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceSetRow {
    pub name: String,
    pub health: String,
    pub sync: String,
    pub members: usize,
    pub adopt: usize,
    pub prune: usize,
    /// Net-new shipped defaults available to adopt (additive advisory, NOT
    /// drift). Only meaningful for the Default set.
    pub defaults_available: usize,
}

/// Parse the `GET /portal/resource/sets` body: one
/// `SET <name> HEALTH <h> SYNC <s> MEMBERS <n> ADOPT <n> PRUNE <n> DEFAULTS <n>`
/// line per set. A line missing a field falls back to sensible defaults.
#[must_use]
pub fn parse_set_list(body: &str) -> Vec<ResourceSetRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() != Some(&"SET") || toks.len() < 2 {
            continue;
        }
        let mut row = ResourceSetRow {
            name: toks[1].to_string(),
            ..Default::default()
        };
        let mut i = 2;
        while i + 1 < toks.len() {
            let (key, val) = (toks[i], toks[i + 1]);
            match key {
                "HEALTH" => row.health = val.to_string(),
                "SYNC" => row.sync = val.to_string(),
                "MEMBERS" => row.members = val.parse().unwrap_or(0),
                "ADOPT" => row.adopt = val.parse().unwrap_or(0),
                "PRUNE" => row.prune = val.parse().unwrap_or(0),
                "DEFAULTS" => row.defaults_available = val.parse().unwrap_or(0),
                _ => {}
            }
            i += 2;
        }
        out.push(row);
    }
    out
}

/// One member row of a ResourceSet detail: the `Kind/name` reference, its
/// observed health, and its provenance (`defaults@<v>` or `operator`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberRow {
    pub reference: String,
    pub health: String,
    pub origin: String,
}

/// A ResourceSet's full detail, parsed from `GET /portal/resource/set`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceSetDetail {
    pub name: String,
    pub description: String,
    pub health: String,
    pub sync: String,
    pub members: Vec<MemberRow>,
    pub adopt: Vec<String>,
    pub prune: Vec<String>,
    /// Graph node labels, in emission order (node 0 is the set root).
    pub nodes: Vec<String>,
    /// Graph edges as `(from_index, to_index, label)`.
    pub edges: Vec<(usize, usize, String)>,
    /// Shipped-defaults advisory (Default set only) — a SEPARATE axis from sync.
    pub bundle_version: String,
    /// Net-new shipped defaults available to adopt.
    pub defaults_available: Vec<String>,
    /// Present defaults the operator has diverged from ship.
    pub defaults_edited: Vec<String>,
    /// Operator-deleted defaults (never resurrected).
    pub defaults_tombstoned: Vec<String>,
}

/// Is a set's reconcile plan non-empty (something to adopt or prune)? A pure
/// predicate shared by the list row (counts) and the detail view (csv lists)
/// so the "reconciling..." indicator is derived, never hand-toggled.
#[must_use]
pub fn is_reconciling(adopt: usize, prune: usize) -> bool {
    adopt > 0 || prune > 0
}

/// Framework-agnostic driver for the "Refresh" button + optional interval
/// poll ("watch"). The actual HTTP fetch is injected as a closure so this is
/// host-testable without wasm/yew: a manual `refresh()` always re-fetches;
/// `on_tick()` (driven by a `setInterval` callback in the Yew wiring) only
/// re-fetches while polling is enabled, so toggling watch on/off is provably
/// what gates the interval-driven re-fetch.
#[derive(Debug, Default)]
pub struct RefreshDriver {
    poll_enabled: bool,
    fetch_count: usize,
}

impl RefreshDriver {
    /// A fresh driver with polling off and no fetches recorded yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the interval poll ("watch") is currently enabled.
    #[must_use]
    pub fn poll_enabled(&self) -> bool {
        self.poll_enabled
    }

    /// Enable/disable the interval poll.
    pub fn set_poll_enabled(&mut self, enabled: bool) {
        self.poll_enabled = enabled;
    }

    /// How many times `fetch` has actually been invoked so far.
    #[must_use]
    pub fn fetch_count(&self) -> usize {
        self.fetch_count
    }

    /// Manual refresh: always drives a re-fetch.
    pub fn refresh(&mut self, mut fetch: impl FnMut()) {
        self.fetch_count += 1;
        fetch();
    }

    /// One interval tick: re-fetches only while polling is enabled.
    pub fn on_tick(&mut self, mut fetch: impl FnMut()) {
        if self.poll_enabled {
            self.fetch_count += 1;
            fetch();
        }
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Parse the `GET /portal/resource/set` body: a `SET`/`DESC` header, `MEMBER
/// <ref> HEALTH <h>` lines, `PLAN ADOPT`/`PLAN PRUNE` csv lines, the rolled-up
/// `HEALTH`/`SYNC`, and the `NODE <i> <label>` / `EDGE <from> <to> <label>`
/// graph. Unknown lines are ignored.
#[must_use]
pub fn parse_set_detail(body: &str) -> ResourceSetDetail {
    let mut d = ResourceSetDetail::default();
    for line in body.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("SET ") {
            d.name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("DESC ") {
            d.description = rest.to_string();
        } else if line == "DESC" {
            d.description.clear();
        } else if let Some(rest) = line.strip_prefix("MEMBER ") {
            // `<ref> HEALTH <h> [ORIGIN <origin>]`
            if let Some((reference, tail)) = rest.split_once(" HEALTH ") {
                let (health, origin) = match tail.split_once(" ORIGIN ") {
                    Some((h, o)) => (h.trim().to_string(), o.trim().to_string()),
                    None => (tail.trim().to_string(), String::new()),
                };
                d.members.push(MemberRow {
                    reference: reference.trim().to_string(),
                    health,
                    origin,
                });
            }
        } else if let Some(rest) = line.strip_prefix("PLAN ADOPT ") {
            d.adopt = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("PLAN PRUNE ") {
            d.prune = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("DEFAULT-BUNDLE ") {
            d.bundle_version = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("DEFAULT-AVAILABLE ") {
            d.defaults_available = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("DEFAULT-EDITED ") {
            d.defaults_edited = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("DEFAULT-TOMBSTONED ") {
            d.defaults_tombstoned = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("HEALTH ") {
            d.health = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("SYNC ") {
            d.sync = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("NODE ") {
            // `<i> <label>` — index is positional (nodes emitted in order).
            if let Some((_idx, label)) = rest.split_once(' ') {
                d.nodes.push(label.trim().to_string());
            }
        } else if let Some(rest) = line.strip_prefix("EDGE ") {
            // `<from> <to> <label>`
            let toks: Vec<&str> = rest.splitn(3, ' ').collect();
            if let [from, to, label] = toks.as_slice() {
                if let (Ok(from), Ok(to)) = (from.parse::<usize>(), to.parse::<usize>()) {
                    d.edges.push((from, to, label.trim().to_string()));
                }
            }
        }
    }
    d
}

#[cfg(feature = "yew")]
pub use yew_impl::ResourceSetsConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{is_reconciling, parse_set_detail, parse_set_list, ResourceSetDetail, ResourceSetRow};
    use crate::auth::use_auth;
    use crate::portal::{get_url, http};
    use crate::primitives::{Badge, Graph, GraphEdge, Tone};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// How often the optional interval poll re-fetches, in milliseconds.
    const WATCH_INTERVAL_MS: i32 = 5000;

    fn sync_tone(sync: &str) -> Tone {
        if sync.eq_ignore_ascii_case("Synced") {
            Tone::Success
        } else {
            Tone::Warn
        }
    }

    /// Render a last-observed wall-clock instant (JS millis since epoch) as a
    /// locale timestamp string, or an em-dash before the first fetch lands.
    fn human_time(millis: Option<f64>) -> String {
        match millis {
            Some(m) => {
                let d = js_sys::Date::new(&JsValue::from_f64(m));
                d.to_locale_string("en-US", &JsValue::UNDEFINED)
                    .as_string()
                    .unwrap_or_default()
            }
            None => "—".to_owned(),
        }
    }

    /// The Resource Sets console: a list of ResourceSets with health/sync
    /// pills; selecting one loads its detail + resource graph.
    #[function_component(ResourceSetsConsole)]
    pub fn resource_sets_console() -> Html {
        let auth = use_auth();
        let sets = use_state(Vec::<ResourceSetRow>::new);
        let selected = use_state(|| None::<String>);
        let detail = use_state(|| None::<ResourceSetDetail>);
        // Optional interval poll ("watch"): off by default so the console
        // never re-fetches unless the operator explicitly opts in.
        let watch = use_state(|| false);
        // Bumped once per manual refresh or interval tick to re-trigger the
        // fetch effects below (yew's `use_effect_with` re-runs only when its
        // dependency changes).
        let refresh_tick = use_state(|| 0u32);
        // Last-observed wall-clock instant (JS millis) of the most recent
        // successful sets-list fetch.
        let last_observed = use_state(|| None::<f64>);

        // Load the set list on mount / token change / manual refresh /
        // interval tick.
        {
            let (auth, sets, last_observed) = (auth.clone(), sets.clone(), last_observed.clone());
            use_effect_with(
                (auth.token.clone(), *refresh_tick),
                move |(token, _tick)| {
                    if let Some(token) = token.clone() {
                        let (sets, last_observed) = (sets.clone(), last_observed.clone());
                        let url = get_url("/portal/resource/sets", &token, &[]);
                        spawn_local(async move {
                            if let Ok(r) = http("GET", &url, None).await {
                                if r.ok() {
                                    sets.set(parse_set_list(&r.body));
                                    last_observed.set(Some(js_sys::Date::now()));
                                }
                            }
                        });
                    }
                    || ()
                },
            );
        }

        // Load the selected set's detail on selection / token change /
        // manual refresh / interval tick.
        {
            let (auth, selected, detail) = (auth.clone(), selected.clone(), detail.clone());
            use_effect_with(
                ((*selected).clone(), auth.token.clone(), *refresh_tick),
                move |(sel, token, _tick)| {
                    if let (Some(name), Some(token)) = (sel.clone(), token.clone()) {
                        let detail = detail.clone();
                        let url = get_url("/portal/resource/set", &token, &[("name", &name)]);
                        spawn_local(async move {
                            if let Ok(r) = http("GET", &url, None).await {
                                if r.ok() {
                                    detail.set(Some(parse_set_detail(&r.body)));
                                }
                            }
                        });
                    }
                    || ()
                },
            );
        }

        let refresh_click = {
            let refresh_tick = refresh_tick.clone();
            Callback::from(move |_: MouseEvent| refresh_tick.set(*refresh_tick + 1))
        };
        let toggle_watch = {
            let watch = watch.clone();
            Callback::from(move |_: MouseEvent| watch.set(!*watch))
        };

        // The optional interval poll: while `watch` is on, tick `refresh_tick`
        // every `WATCH_INTERVAL_MS`, which re-runs the fetch effects above —
        // a real re-fetch call site, not a static render.
        {
            let (watch, refresh_tick) = (watch.clone(), refresh_tick.clone());
            use_effect_with(*watch, move |enabled| {
                let mut handle: Option<(i32, Closure<dyn FnMut()>)> = None;
                if *enabled {
                    if let Some(window) = web_sys::window() {
                        let refresh_tick = refresh_tick.clone();
                        let cb = Closure::<dyn FnMut()>::new(move || {
                            refresh_tick.set(*refresh_tick + 1);
                        });
                        if let Ok(id) = window
                            .set_interval_with_callback_and_timeout_and_arguments_0(
                                cb.as_ref().unchecked_ref(),
                                WATCH_INTERVAL_MS,
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

        let rows: Html = sets
            .iter()
            .map(|s: &ResourceSetRow| {
                let name = s.name.clone();
                let is_active = selected.as_deref() == Some(name.as_str());
                let select = {
                    let (selected, name) = (selected.clone(), name.clone());
                    Callback::from(move |_: MouseEvent| selected.set(Some(name.clone())))
                };
                let mut class = Classes::from("ds-row");
                if is_active {
                    class.push("is-active");
                }
                let defaults_cell = if s.defaults_available > 0 {
                    html! { <Badge label={format!("{} available", s.defaults_available)} tone={Tone::Info} /> }
                } else {
                    html! { <span class="ds-muted">{ "—" }</span> }
                };
                let reconciling_cell = if is_reconciling(s.adopt, s.prune) {
                    html! { <Badge label={"reconciling…"} tone={Tone::Warn} /> }
                } else {
                    html! { <span class="ds-muted">{ "—" }</span> }
                };
                html! {
                    <tr class={class} onclick={select} style="cursor:pointer">
                        <td class="mono">{ name }</td>
                        <td><Badge label={s.health.clone()} /></td>
                        <td><Badge label={s.sync.clone()} tone={sync_tone(&s.sync)} /></td>
                        <td>{ s.members }</td>
                        <td>{ s.adopt }</td>
                        <td>{ s.prune }</td>
                        <td>{ defaults_cell }</td>
                        <td>{ reconciling_cell }</td>
                    </tr>
                }
            })
            .collect();

        let detail_view: Html = match &*detail {
            None => {
                html! { <p class="ds-empty">{ "Select a resource set to view its graph." }</p> }
            }
            Some(d) => {
                let graph_edges: Vec<GraphEdge> = d
                    .edges
                    .iter()
                    .map(|(from, to, label)| GraphEdge {
                        from: *from,
                        to: *to,
                        label: label.clone(),
                    })
                    .collect();
                let member_rows: Html = d
                    .members
                    .iter()
                    .map(|m| {
                        let origin = if m.origin.is_empty() {
                            html! {}
                        } else {
                            html! { <span class="ds-muted">{ m.origin.clone() }</span> }
                        };
                        html! {
                            <tr>
                                <td class="mono">{ m.reference.clone() }</td>
                                <td><Badge label={m.health.clone()} /></td>
                                <td>{ origin }</td>
                            </tr>
                        }
                    })
                    .collect();
                let plan = if d.adopt.is_empty() && d.prune.is_empty() {
                    html! { <p class="ds-muted">{ "Nothing to reconcile — the set is synced." }</p> }
                } else {
                    html! {
                        <ul class="ds-list">
                            { for d.adopt.iter().map(|r| html!{ <li>{ format!("adopt {r}") }</li> }) }
                            { for d.prune.iter().map(|r| html!{ <li>{ format!("prune {r}") }</li> }) }
                        </ul>
                    }
                };
                let reconciling_badge = if is_reconciling(d.adopt.len(), d.prune.len()) {
                    html! { <Badge label={"reconciling…"} tone={Tone::Warn} /> }
                } else {
                    html! {}
                };
                // Shipped-defaults advisory: a SEPARATE axis from sync. Net-new
                // defaults are an additive offer (adopt via `pillar render
                // defaults/<name>` then apply); operator edits/deletions are
                // first-class and never flagged as drift.
                let defaults_advisory = {
                    let has_any = !d.defaults_available.is_empty()
                        || !d.defaults_edited.is_empty()
                        || !d.defaults_tombstoned.is_empty();
                    if !has_any {
                        html! {}
                    } else {
                        html! {
                            <>
                                <h4>
                                    { "Shipped defaults" }
                                    if !d.bundle_version.is_empty() {
                                        <span class="ds-muted">{ format!(" (bundle v{})", d.bundle_version) }</span>
                                    }
                                </h4>
                                if !d.defaults_available.is_empty() {
                                    <p class="ds-muted">
                                        { "Available to adopt (″pillar render defaults/<name>″ then apply):" }
                                    </p>
                                    <ul class="ds-list">
                                        { for d.defaults_available.iter().map(|n| html!{
                                            <li><span class="mono">{ n.clone() }</span>{ " " }<Badge label={"available"} tone={Tone::Info} /></li>
                                        }) }
                                    </ul>
                                }
                                if !d.defaults_edited.is_empty() {
                                    <p class="ds-muted">{ "Edited (diverged from ship — kept, not reverted):" }</p>
                                    <ul class="ds-list">
                                        { for d.defaults_edited.iter().map(|n| html!{ <li class="mono">{ n.clone() }</li> }) }
                                    </ul>
                                }
                                if !d.defaults_tombstoned.is_empty() {
                                    <p class="ds-muted">{ "Deleted (tombstoned — will not be resurrected):" }</p>
                                    <ul class="ds-list">
                                        { for d.defaults_tombstoned.iter().map(|n| html!{ <li class="mono">{ n.clone() }</li> }) }
                                    </ul>
                                }
                            </>
                        }
                    }
                };
                html! {
                    <section class="ds-panel">
                        <header class="ds-panel__head">
                            <h3>{ format!("ResourceSet / {}", d.name) }</h3>
                            <div class="ds-badges">
                                <Badge label={d.health.clone()} />
                                <Badge label={d.sync.clone()} tone={sync_tone(&d.sync)} />
                                { reconciling_badge }
                            </div>
                            <button type="button" id="resource-set-detail-refresh" onclick={refresh_click.clone()}>
                                { "Refresh" }
                            </button>
                        </header>
                        if !d.description.is_empty() {
                            <p class="ds-muted">{ d.description.clone() }</p>
                        }
                        <Graph nodes={d.nodes.clone()} edges={graph_edges} />
                        <h4>{ "Members" }</h4>
                        <table class="ds-table">
                            <thead><tr><th>{ "Resource" }</th><th>{ "Health" }</th><th>{ "Origin" }</th></tr></thead>
                            <tbody>{ member_rows }</tbody>
                        </table>
                        <h4>{ "Reconcile plan" }</h4>
                        { plan }
                        { defaults_advisory }
                    </section>
                }
            }
        };

        html! {
            <div class="console-tile" id="resource-sets">
                <h2>{ "Resource Sets" }</h2>
                <p class="ds-muted">
                    { "Declarative resource groups (ArgoCD-Application analog). The Default set owns the default retention policies." }
                </p>
                <div class="ds-toolbar">
                    <button type="button" id="resource-sets-refresh" onclick={refresh_click.clone()}>
                        { "Refresh" }
                    </button>
                    <button type="button" id="resource-sets-watch"
                        class={if *watch {"active"} else {""}} onclick={toggle_watch}>
                        { if *watch { "Watch: on" } else { "Watch: off" } }
                    </button>
                    <span class="ds-muted" id="resource-sets-last-observed">
                        { format!("Last observed: {}", human_time(*last_observed)) }
                    </span>
                </div>
                <table class="ds-table">
                    <thead>
                        <tr>
                            <th>{ "Name" }</th><th>{ "Health" }</th><th>{ "Sync" }</th>
                            <th>{ "Members" }</th><th>{ "Adopt" }</th><th>{ "Prune" }</th>
                            <th>{ "Defaults" }</th><th>{ "Reconciling" }</th>
                        </tr>
                    </thead>
                    <tbody>{ rows }</tbody>
                </table>
                { detail_view }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_set_list_lines() {
        let body = "SET default HEALTH Healthy SYNC Synced MEMBERS 2 ADOPT 0 PRUNE 0 DEFAULTS 3\n\
                    SET web HEALTH Degraded SYNC OutOfSync MEMBERS 3 ADOPT 1 PRUNE 2 DEFAULTS 0\n\
                    garbage line";
        let rows = parse_set_list(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            ResourceSetRow {
                name: "default".into(),
                health: "Healthy".into(),
                sync: "Synced".into(),
                members: 2,
                adopt: 0,
                prune: 0,
                defaults_available: 3,
            }
        );
        assert_eq!(rows[1].name, "web");
        assert_eq!(rows[1].adopt, 1);
        assert_eq!(rows[1].prune, 2);
        assert_eq!(rows[1].sync, "OutOfSync");
        assert_eq!(rows[1].defaults_available, 0);
    }

    #[test]
    fn parses_the_detail_header_members_plan_and_graph() {
        let body = "SET default\n\
                    DESC default retention policies\n\
                    MEMBER RetentionPolicy/web-metrics HEALTH Healthy ORIGIN operator\n\
                    MEMBER Job/nightly HEALTH Missing\n\
                    PLAN ADOPT Job/nightly\n\
                    PLAN PRUNE \n\
                    HEALTH Degraded\n\
                    SYNC OutOfSync\n\
                    NODE 0 ResourceSet/default\n\
                    NODE 1 RetentionPolicy/web-metrics\n\
                    NODE 2 Job/nightly\n\
                    EDGE 0 1 Healthy\n\
                    EDGE 0 2 Missing";
        let d = parse_set_detail(body);
        assert_eq!(d.name, "default");
        assert_eq!(d.description, "default retention policies");
        assert_eq!(d.members.len(), 2);
        assert_eq!(d.members[0].reference, "RetentionPolicy/web-metrics");
        assert_eq!(d.members[0].health, "Healthy");
        assert_eq!(d.members[0].origin, "operator");
        assert_eq!(d.members[1].health, "Missing");
        assert_eq!(d.members[1].origin, "");
        assert_eq!(d.adopt, vec!["Job/nightly".to_string()]);
        assert!(d.prune.is_empty());
        assert_eq!(d.health, "Degraded");
        assert_eq!(d.sync, "OutOfSync");
        assert_eq!(
            d.nodes,
            vec![
                "ResourceSet/default".to_string(),
                "RetentionPolicy/web-metrics".to_string(),
                "Job/nightly".to_string(),
            ]
        );
        assert_eq!(
            d.edges,
            vec![(0, 1, "Healthy".to_string()), (0, 2, "Missing".to_string()),]
        );
    }

    #[test]
    fn empty_default_set_detail_has_only_the_root_node() {
        let body = "SET default\nDESC \nHEALTH Empty\nSYNC Synced\nNODE 0 ResourceSet/default";
        let d = parse_set_detail(body);
        assert_eq!(d.description, "");
        assert_eq!(d.health, "Empty");
        assert_eq!(d.nodes, vec!["ResourceSet/default".to_string()]);
        assert!(d.edges.is_empty());
        assert!(d.members.is_empty());
    }

    #[test]
    fn parses_the_shipped_defaults_advisory_and_member_origin() {
        let body = "SET default\n\
                    MEMBER RetentionPolicy/metrics-default HEALTH Healthy ORIGIN defaults@1\n\
                    HEALTH Healthy\n\
                    SYNC Synced\n\
                    DEFAULT-BUNDLE 1\n\
                    DEFAULT-AVAILABLE logs-default,traces-default\n\
                    DEFAULT-EDITED \n\
                    DEFAULT-TOMBSTONED old-default\n\
                    NODE 0 ResourceSet/default";
        let d = parse_set_detail(body);
        assert_eq!(d.members[0].origin, "defaults@1");
        assert_eq!(d.bundle_version, "1");
        assert_eq!(
            d.defaults_available,
            vec!["logs-default".to_string(), "traces-default".to_string()]
        );
        assert!(d.defaults_edited.is_empty());
        assert_eq!(d.defaults_tombstoned, vec!["old-default".to_string()]);
        // The advisory is a SEPARATE axis: the set is still Synced/Healthy.
        assert_eq!(d.sync, "Synced");
        assert_eq!(d.health, "Healthy");
    }

    #[test]
    fn reconciling_indicator_is_derived_from_a_non_empty_plan() {
        assert!(!is_reconciling(0, 0), "synced set is not reconciling");
        assert!(is_reconciling(1, 0), "pending adopt is reconciling");
        assert!(is_reconciling(0, 1), "pending prune is reconciling");
        assert!(is_reconciling(2, 3), "both adopt and prune is reconciling");
    }

    #[test]
    fn manual_refresh_always_drives_a_real_re_fetch_call() {
        let mut driver = RefreshDriver::new();
        let mut calls = 0;
        driver.refresh(|| calls += 1);
        driver.refresh(|| calls += 1);
        assert_eq!(calls, 2);
        assert_eq!(driver.fetch_count(), 2);
    }

    #[test]
    fn interval_tick_only_re_fetches_while_watch_is_enabled() {
        let mut driver = RefreshDriver::new();
        let mut calls = 0;

        // Watch off by default: an interval tick is a no-op, not a static
        // render — proving the tick itself is what's gated, not the fetch
        // wiring.
        driver.on_tick(|| calls += 1);
        assert_eq!(calls, 0);
        assert!(!driver.poll_enabled());

        driver.set_poll_enabled(true);
        driver.on_tick(|| calls += 1);
        driver.on_tick(|| calls += 1);
        assert_eq!(calls, 2, "each tick while enabled drives its own fetch");

        driver.set_poll_enabled(false);
        driver.on_tick(|| calls += 1);
        assert_eq!(calls, 2, "disabling watch stops the interval from fetching");
    }
}
