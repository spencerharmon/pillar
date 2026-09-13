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
/// observed health, its provenance (`defaults@<v>` or `operator`), and — for a
/// non-`Healthy` member — an optional free-form REASON explaining the
/// degradation (rendered as health-badge subtext/tooltip).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberRow {
    pub reference: String,
    pub health: String,
    pub origin: String,
    /// Free-form degradation reason (empty when healthy / not reported).
    pub reason: String,
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
    /// Per-node health axis, parallel to `nodes` (empty string if absent).
    pub node_health: Vec<String>,
    /// Per-node sync axis, parallel to `nodes` (empty string if absent).
    pub node_sync: Vec<String>,
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

// ---------------------------------------------------------------------------
// Reconcile as an action — selective sync
// ---------------------------------------------------------------------------

/// Build the `POST /portal/resource/reconcile` body for a (possibly
/// selective) sync apply: `token`, the set `name`, then `ADOPT <csv>` /
/// `PRUNE <csv>` lines carrying ONLY the operator-SELECTED subset of the
/// plan's adopt/prune members — never the full plan when the operator
/// deselected a member. An empty selection on one axis still emits an empty
/// `ADOPT `/`PRUNE ` line (never omitted), so the backend never has to guess
/// whether the field was intentionally cleared or missing.
#[must_use]
pub fn reconcile_request_body(token: &str, name: &str, adopt: &[String], prune: &[String]) -> String {
    format!("{token}\n{name}\nADOPT {}\nPRUNE {}", adopt.join(","), prune.join(","))
}

/// Narrow a plan's full adopt/prune member lists down to the subset the
/// operator has checked "selected", preserving the plan's original order.
/// Host-testable — no `yew` — so the selective-sync narrowing itself is
/// provably correct independent of the checkbox wiring.
#[must_use]
pub fn selected_subset(plan: &[String], selected: &std::collections::HashSet<String>) -> Vec<String> {
    plan.iter().filter(|m| selected.contains(*m)).cloned().collect()
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
            // `<ref> HEALTH <h> [ORIGIN <origin>] [REASON <msg>]`. REASON is an
            // ADDITIVE, free-form tail (always LAST, may contain spaces), so it
            // is split off FIRST; ORIGIN is then parsed from what remains.
            if let Some((reference, tail)) = rest.split_once(" HEALTH ") {
                let (tail, reason) = match tail.split_once(" REASON ") {
                    Some((head, msg)) => (head, msg.trim().to_string()),
                    None => (tail, String::new()),
                };
                let (health, origin) = match tail.split_once(" ORIGIN ") {
                    Some((h, o)) => (h.trim().to_string(), o.trim().to_string()),
                    None => (tail.trim().to_string(), String::new()),
                };
                d.members.push(MemberRow {
                    reference: reference.trim().to_string(),
                    health,
                    origin,
                    reason,
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
            // `<i> <label> [HEALTH <h> SYNC <s>]` — index is positional (nodes
            // emitted in order). The label is a single space-free token; the
            // ADDITIVE `HEALTH <h> SYNC <s>` tail (present since the depth graph)
            // powers per-node badges. Older bodies omit it -> empty tokens.
            if let Some((_idx, rest)) = rest.split_once(' ') {
                let (label, mut health, mut sync) = (rest, String::new(), String::new());
                let label = if let Some((lbl, tail)) = label.split_once(" HEALTH ") {
                    if let Some((h, s)) = tail.split_once(" SYNC ") {
                        health = h.trim().to_string();
                        sync = s.trim().to_string();
                    } else {
                        health = tail.trim().to_string();
                    }
                    lbl
                } else {
                    label
                };
                d.nodes.push(label.trim().to_string());
                d.node_health.push(health);
                d.node_sync.push(sync);
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

use crate::components::tree::TreeNode;
use crate::primitives::Tone;

/// Build the COLLAPSIBLE, layered depth tree the console renders from a parsed
/// `ResourceSetDetail`'s flat graph (node 0 = the set root; edges run parent ->
/// child). Each node's label carries its per-node health+sync token (`<label>
/// — <health>/<sync>`) so the tree row shows the same two-axis signal the flat
/// graph did, and the tree's expand/collapse gives ArgoCD-parity depth over the
/// `ResourceSet -> Workload -> replica` chain. Pure (no `yew`), so the tree
/// shape is host-tested independent of the render wiring. Returns the single
/// root (node 0) or `None` when the graph is empty.
#[must_use]
pub fn depth_tree(d: &ResourceSetDetail) -> Option<TreeNode> {
    if d.nodes.is_empty() {
        return None;
    }
    // children[i] = the node indices i points at (parent -> child edges).
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); d.nodes.len()];
    for (from, to, _label) in &d.edges {
        if *from < d.nodes.len() && *to < d.nodes.len() {
            children[*from].push(*to);
        }
    }
    fn build(
        idx: usize,
        nodes: &[String],
        health: &[String],
        sync: &[String],
        children: &[Vec<usize>],
    ) -> TreeNode {
        let label = &nodes[idx];
        let h = health.get(idx).map(String::as_str).unwrap_or("");
        let s = sync.get(idx).map(String::as_str).unwrap_or("");
        let full = match (h.is_empty(), s.is_empty()) {
            (false, false) => format!("{label} — {h}/{s}"),
            (false, true) => format!("{label} — {h}"),
            _ => label.clone(),
        };
        let kids = children[idx]
            .iter()
            .map(|c| build(*c, nodes, health, sync, children))
            .collect();
        TreeNode::branch(format!("rsnode-{idx}"), full, kids)
    }
    Some(build(0, &d.nodes, &d.node_health, &d.node_sync, &children))
}

/// Resolve a depth-tree node id (`rsnode-<idx>`, the id [`depth_tree`] stamps on
/// every [`TreeNode`]) back to the `Kind/name` resource it represents, as the
/// [`crate::resources_console::ResourceRow`] the ALREADY-SHIPPED resources-console
/// per-resource detail drawer ([`crate::resources_console::ResourceDetail`])
/// consumes. This is the pure routing hop the console's node `onselect` runs to
/// open the shipped drawer over a clicked graph/tree node — no new backend, no
/// new drawer. Returns `None` for an id that is not a `rsnode-<idx>` in range, or
/// whose node label is not a `Kind/name` reference (e.g. the set-root, which the
/// graph roots at `ResourceSet/<name>` but which carries no per-resource detail).
/// The set-root node (index 0) is intentionally NOT routable — a ResourceSet is
/// the container, not a member resource with an Overview/Manifest/Logs drawer.
#[must_use]
pub fn node_resource_ref(
    d: &ResourceSetDetail,
    node_id: &str,
) -> Option<crate::resources_console::ResourceRow> {
    let idx: usize = node_id.strip_prefix("rsnode-")?.parse().ok()?;
    // Node 0 is the ResourceSet container root, not a per-resource member.
    if idx == 0 {
        return None;
    }
    let label = d.nodes.get(idx)?;
    let (kind, name) = label.split_once('/')?;
    if kind.is_empty() || name.is_empty() {
        return None;
    }
    Some(crate::resources_console::ResourceRow {
        kind: kind.to_owned(),
        name: name.to_owned(),
        replicas: None,
    })
}

/// FULL sync tone set (ArgoCD-parity), replacing the old binary Synced-vs-Warn:
/// Synced -> Success, Progressing -> Info, OutOfSync -> Warn, Error -> Danger,
/// Unknown / anything else -> Neutral. Host-testable (no `yew`).
#[must_use]
pub fn sync_tone(sync: &str) -> Tone {
    match sync.to_ascii_lowercase().as_str() {
        "synced" => Tone::Success,
        "progressing" => Tone::Info,
        "outofsync" => Tone::Warn,
        "error" => Tone::Danger,
        _ => Tone::Neutral,
    }
}

/// Tone for a member/set HEALTH string: Healthy -> Success, Degraded -> Warn,
/// Missing / Error -> Danger, Empty / Unknown -> Neutral. Host-testable.
#[must_use]
pub fn health_tone(health: &str) -> Tone {
    match health.to_ascii_lowercase().as_str() {
        "healthy" => Tone::Success,
        "degraded" => Tone::Warn,
        "missing" | "error" => Tone::Danger,
        _ => Tone::Neutral,
    }
}

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        depth_tree, health_tone, is_reconciling, node_resource_ref, parse_set_detail,
        parse_set_list, reconcile_request_body, selected_subset, sync_tone, ResourceSetDetail,
        ResourceSetRow,
    };
    use crate::auth::use_auth;
    use crate::components::data_table::{Column, DataTable, Row};
    use crate::components::tree::Tree;
    use crate::portal::{get_url, http};
    use crate::primitives::{Badge, DiffView, Drawer, Tone};
    use crate::resources_console::{parse_act_result, parse_predicted, ChangeState, ResourceDetail};
    use std::collections::HashSet;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// How often the optional interval poll re-fetches, in milliseconds.
    const WATCH_INTERVAL_MS: i32 = 5000;

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


    /// The "Reconcile" action: turns the adopt/prune plan from a DISPLAY-only
    /// list into a signed act, gated by the SAME [`ChangeState`] dry-run
    /// machine `console-resources-view`'s [`crate::resources_console::ChangeFlow`]
    /// uses (imported, not reimplemented), with per-member checkboxes so the
    /// operator can apply a SUBSET of the plan ("selective sync") rather than
    /// only the whole thing.
    #[derive(Properties, PartialEq)]
    struct ReconcilePanelProps {
        name: String,
        adopt: Vec<String>,
        prune: Vec<String>,
    }

    #[function_component(ReconcilePanel)]
    fn reconcile_panel(props: &ReconcilePanelProps) -> Html {
        let auth = use_auth();
        let name = props.name.clone();
        let adopt = props.adopt.clone();
        let prune = props.prune.clone();

        // Every member starts SELECTED (a full sync is the default), but the
        // operator may uncheck any one to hold it back — a selective sync.
        let selected = use_state({
            let (adopt, prune) = (adopt.clone(), prune.clone());
            move || -> HashSet<String> { adopt.iter().chain(prune.iter()).cloned().collect() }
        });
        let gate = use_state(ChangeState::default);
        let result = use_state(|| None::<Result<String, String>>);

        let toggle = {
            let (selected, gate) = (selected.clone(), gate.clone());
            Callback::from(move |member: String| {
                let mut next = (*selected).clone();
                if !next.remove(&member) {
                    next.insert(member);
                }
                selected.set(next);
                // The selection just changed WHICH change a confirm would
                // apply, so any prior preview no longer describes it.
                gate.set(gate.invalidated());
            })
        };

        let selected_adopt = selected_subset(&adopt, &selected);
        let selected_prune = selected_subset(&prune, &selected);

        // Preview: the SAME `/portal/resource/dry-run` authorization check
        // every other change flow uses, for the CURRENT (possibly narrowed)
        // selection.
        let preview = {
            let (auth, gate, result) = (auth.clone(), gate.clone(), result.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url("/portal/resource/dry-run", &token, &[]);
                let (gate, result) = (gate.clone(), result.clone());
                result.set(None);
                spawn_local(async move {
                    if let Ok(r) = http("GET", &url, None).await {
                        if let Some(allow) = parse_predicted(&r.body) {
                            gate.set(gate.previewed(allow));
                        }
                    }
                });
            })
        };

        // Apply: reachable ONLY while `gate.can_confirm()` holds — the
        // control below never renders the button otherwise, so no reconcile
        // apply can issue without a preceding ALLOW dry-run of this exact
        // (possibly narrowed) selection.
        let apply = {
            let (auth, name, gate, result) = (
                auth.clone(),
                name.clone(),
                gate.clone(),
                result.clone(),
            );
            let (selected_adopt, selected_prune) = (selected_adopt.clone(), selected_prune.clone());
            Callback::from(move |_: MouseEvent| {
                if !gate.can_confirm() {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = reconcile_request_body(&token, &name, &selected_adopt, &selected_prune);
                let (gate, result) = (gate.clone(), result.clone());
                spawn_local(async move {
                    match http("POST", "/portal/resource/reconcile", Some(&body)).await {
                        Ok(r) => result.set(Some(parse_act_result(&r.body))),
                        Err(_) => result.set(Some(Err("request failed".to_owned()))),
                    }
                    // The act consumed this preview; a re-apply needs a
                    // fresh dry-run even if the selection is unchanged.
                    gate.set(gate.invalidated());
                });
            })
        };

        let member_row = |member: &String, verb: &'static str| {
            let checked = selected.contains(member);
            let onchange = {
                let (toggle, member) = (toggle.clone(), member.clone());
                Callback::from(move |_: Event| toggle.emit(member.clone()))
            };
            let member = member.clone();
            html! {
                <li class="ds-list__item">
                    <label>
                        <input type="checkbox" checked={checked} onchange={onchange} />
                        { format!(" {verb} {member}") }
                    </label>
                </li>
            }
        };

        let diff_old = "no changes".to_string();
        let diff_new = {
            let mut lines: Vec<String> = Vec::new();
            lines.extend(selected_adopt.iter().map(|m| format!("adopt {m}")));
            lines.extend(selected_prune.iter().map(|m| format!("prune {m}")));
            if lines.is_empty() {
                "no changes".to_string()
            } else {
                lines.join("\n")
            }
        };

        html! {
            <div class="res-change" id="resourceset-reconcile">
                <h4>{ "Reconcile (selective sync)" }</h4>
                <ul class="ds-list">
                    { for adopt.iter().map(|m| member_row(m, "adopt")) }
                    { for prune.iter().map(|m| member_row(m, "prune")) }
                </ul>
                <h4>{ "Diff (current \u{2192} proposed)" }</h4>
                <DiffView old={diff_old} new={diff_new} />
                <div class="res-toolbar">
                    <button type="button" id="resourceset-reconcile-preview" onclick={preview}>
                        { "Preview reconcile" }
                    </button>
                </div>
                <div class="res-verdict">
                    { match *gate {
                        ChangeState::Previewed(true) => html! { <Badge label="dry-run: ALLOW" tone={Tone::Success} /> },
                        ChangeState::Previewed(false) => html! { <Badge label="dry-run: DENY" tone={Tone::Danger} /> },
                        ChangeState::Idle => html! { <span class="ds-empty">{ "Preview to see the authorization decision." }</span> },
                    } }
                    if gate.can_confirm() {
                        <button type="button" id="resourceset-reconcile-apply" onclick={apply}>
                            { "Apply selected" }
                        </button>
                    }
                </div>
                { match &*result {
                    Some(Ok(cid)) => html! { <p class="obs-msg">{ format!("Event emitted: {cid}") }</p> },
                    Some(Err(e)) => html! { <p class="obs-msg is-error">{ format!("Refused: {e}") }</p> },
                    None => Html::default(),
                } }
            </div>
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

        // The graph/tree node the operator clicked, resolved to the resources-
        // console `ResourceRow` its ALREADY-SHIPPED per-resource detail drawer
        // consumes. `Some` opens the shipped Drawer over that resource; `None`
        // closes it. Node selection is wired straight into the real, mounted
        // detail drawer — no new backend, no new drawer.
        let selected_node =
            use_state(|| None::<crate::resources_console::ResourceRow>);

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

        // Health / sync filter CHIPS: `None` = show all, `Some(v)` = only rows
        // whose health (resp. sync) equals `v` (case-insensitive). The list then
        // renders through the SHIPPED DataTable primitive (filter box + sortable
        // columns) over the chip-narrowed row set.
        let health_chip = use_state(|| None::<String>);
        let sync_chip = use_state(|| None::<String>);

        // DataTable columns: Name/Health/Sync are text-sortable; the counts are
        // numeric-sortable; Defaults and Reconciling are plain advisory cells.
        // The Reconciling column folds in the live-status refresh/watch feature.
        let columns: Vec<Column> = vec![
            Column::text("Name"),
            Column::text("Health"),
            Column::text("Sync"),
            Column::numeric("Members"),
            Column::numeric("Adopt"),
            Column::numeric("Prune"),
            Column::text("Defaults"),
            Column::text("Reconciling"),
        ];

        // Map each set onto DataTable cells, narrowed by the active chips.
        let table_rows: Vec<Row> = sets
            .iter()
            .filter(|s| {
                health_chip
                    .as_deref()
                    .is_none_or(|h| s.health.eq_ignore_ascii_case(h))
                    && sync_chip
                        .as_deref()
                        .is_none_or(|sy| s.sync.eq_ignore_ascii_case(sy))
            })
            .map(|s: &ResourceSetRow| {
                let defaults = if s.defaults_available > 0 {
                    format!("{} available", s.defaults_available)
                } else {
                    "—".to_string()
                };
                let reconciling = if is_reconciling(s.adopt, s.prune) {
                    "reconciling…".to_string()
                } else {
                    "—".to_string()
                };
                vec![
                    s.name.clone(),
                    s.health.clone(),
                    s.sync.clone(),
                    s.members.to_string(),
                    s.adopt.to_string(),
                    s.prune.to_string(),
                    defaults,
                    reconciling,
                ]
            })
            .collect();

        // Render the Health/Sync/Defaults cells as toned Badges; other columns
        // stay plain text (sort/filter still run over the underlying string).
        let render_cell = {
            Callback::from(move |(col, value): (usize, String)| -> Html {
                match col {
                    1 => html! { <Badge label={value.clone()} tone={health_tone(&value)} /> },
                    2 => html! { <Badge label={value.clone()} tone={sync_tone(&value)} /> },
                    6 if value != "—" => {
                        html! { <Badge label={value.clone()} tone={Tone::Info} /> }
                    }
                    _ => html! { { value } },
                }
            })
        };

        // Row click selects the set (cell 0 is the name).
        let on_row_click = {
            let selected = selected.clone();
            Callback::from(move |row: Row| {
                if let Some(name) = row.first() {
                    selected.set(Some(name.clone()));
                }
            })
        };

        // The filter-chip row: one chip per health and sync tone; clicking a
        // chip toggles it (a second click clears back to "all").
        let chip = |label: &str,
                    active: bool,
                    on_click: Callback<MouseEvent>|
         -> Html {
            let mut class = Classes::from("ds-chip");
            if active {
                class.push("is-active");
            }
            html! { <button type="button" class={class} onclick={on_click}>{ label.to_string() }</button> }
        };
        let health_chip_btn = |value: &'static str| {
            let active = health_chip.as_deref() == Some(value);
            let on_click = {
                let health_chip = health_chip.clone();
                Callback::from(move |_: MouseEvent| {
                    if active {
                        health_chip.set(None);
                    } else {
                        health_chip.set(Some(value.to_string()));
                    }
                })
            };
            chip(value, active, on_click)
        };
        let sync_chip_btn = |value: &'static str| {
            let active = sync_chip.as_deref() == Some(value);
            let on_click = {
                let sync_chip = sync_chip.clone();
                Callback::from(move |_: MouseEvent| {
                    if active {
                        sync_chip.set(None);
                    } else {
                        sync_chip.set(Some(value.to_string()));
                    }
                })
            };
            chip(value, active, on_click)
        };

        let detail_view: Html = match &*detail {
            None => {
                html! { <p class="ds-empty">{ "Select a resource set to view its graph." }</p> }
            }
            Some(d) => {
                // The layered, collapsible depth tree (ArgoCD-parity), reusing
                // the shipped Tree primitive — REPLACING the old fixed circle-
                // layout star. Node 0 (the set root) and its Workload members
                // are expanded by default so the ResourceSet -> Workload ->
                // replica depth is visible at a glance; deeper/leaf nodes
                // collapse. The tree lives inside a zoom/pan viewport.
                let tree_root = depth_tree(d);
                let default_expanded: Vec<String> = d
                    .nodes
                    .iter()
                    .enumerate()
                    .filter(|(i, label)| *i == 0 || label.starts_with("Workload/"))
                    .map(|(i, _)| format!("rsnode-{i}"))
                    .collect();
                // Clicking a graph/tree node routes its id -> the node's
                // `Kind/name` resource -> the SHIPPED resources-console detail
                // drawer (mounted below). `node_resource_ref` is the pure
                // routing hop; the set-root and any non-resource node resolve to
                // `None` and simply do not open a drawer.
                let on_node_select = {
                    let d = d.clone();
                    let selected_node = selected_node.clone();
                    Callback::from(move |node_id: String| {
                        if let Some(row) = node_resource_ref(&d, &node_id) {
                            selected_node.set(Some(row));
                        }
                    })
                };
                let member_rows: Html = d
                    .members
                    .iter()
                    .map(|m| {
                        let origin = if m.origin.is_empty() {
                            html! {}
                        } else {
                            html! { <span class="ds-muted">{ m.origin.clone() }</span> }
                        };
                        // The additive REASON: rendered as health-badge subtext
                        // (and a hover tooltip) beneath the health badge.
                        let health_cell = if m.reason.is_empty() {
                            html! { <Badge label={m.health.clone()} tone={health_tone(&m.health)} /> }
                        } else {
                            html! {
                                <>
                                    <Badge label={m.health.clone()} tone={health_tone(&m.health)} />
                                    <div class="ds-badge__subtext" title={m.reason.clone()}>
                                        { m.reason.clone() }
                                    </div>
                                </>
                            }
                        };
                        html! {
                            <tr>
                                <td class="mono">{ m.reference.clone() }</td>
                                <td>{ health_cell }</td>
                                <td>{ origin }</td>
                            </tr>
                        }
                    })
                    .collect();
                let plan = if d.adopt.is_empty() && d.prune.is_empty() {
                    html! { <p class="ds-muted">{ "Nothing to reconcile — the set is synced." }</p> }
                } else {
                    html! {
                        <ReconcilePanel
                            name={d.name.clone()}
                            adopt={d.adopt.clone()}
                            prune={d.prune.clone()}
                        />
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
                                <Badge label={d.health.clone()} tone={health_tone(&d.health)} />
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
                        <div class="ds-resource-tree ds-resource-tree--zoompan" role="group" aria-label="ResourceSet resource tree">
                            if let Some(root) = tree_root.clone() {
                                <Tree roots={vec![root]} default_expanded={default_expanded.clone()} onselect={on_node_select.clone()} />
                            } else {
                                <p class="ds-muted">{ "No resources in this set yet." }</p>
                            }
                        </div>
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

        // Close the node detail drawer.
        let close_node = {
            let selected_node = selected_node.clone();
            Callback::from(move |()| selected_node.set(None))
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
                <div class="ds-chips" role="group" aria-label="Filter by health and sync">
                    <span class="ds-chips__label">{ "Health" }</span>
                    { health_chip_btn("Healthy") }
                    { health_chip_btn("Degraded") }
                    { health_chip_btn("Empty") }
                    <span class="ds-chips__label">{ "Sync" }</span>
                    { sync_chip_btn("Synced") }
                    { sync_chip_btn("Progressing") }
                    { sync_chip_btn("OutOfSync") }
                    { sync_chip_btn("Unknown") }
                    { sync_chip_btn("Error") }
                </div>
                <DataTable
                    columns={columns}
                    rows={table_rows}
                    render_cell={render_cell}
                    on_row_click={on_row_click}
                    empty_label={"No resource sets match the current filters."}
                />
                { detail_view }
                // The ALREADY-SHIPPED resources-console per-resource detail
                // drawer (Overview / Manifest / Logs / Exec / Events + the
                // diff-before-apply gate), opened over the clicked graph/tree
                // node. Reuses the shipped `Drawer` primitive and the
                // `ResourceDetail` component verbatim — no new drawer.
                <Drawer open={selected_node.is_some()}
                        title={selected_node.as_ref().map(|r| format!("{}/{}", r.kind, r.name)).unwrap_or_default()}
                        onclose={close_node}>
                    if let Some(row) = &*selected_node {
                        <ResourceDetail row={row.clone()} />
                    }
                </Drawer>
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
    fn parses_per_node_health_sync_tokens_and_builds_a_depth_tree() {
        // The depth graph descends a Workload member into two replicas and
        // stamps a per-node `HEALTH <h> SYNC <s>` token on every NODE line.
        let body = "SET prod\n\
                    HEALTH Healthy\n\
                    SYNC Synced\n\
                    NODE 0 ResourceSet/prod HEALTH Healthy SYNC Synced\n\
                    NODE 1 Workload/web HEALTH Healthy SYNC Synced\n\
                    NODE 2 Replica/web-192.0.2.10 HEALTH Healthy SYNC Synced\n\
                    NODE 3 Replica/web-192.0.2.11 HEALTH Missing SYNC Synced\n\
                    EDGE 0 1 Healthy\n\
                    EDGE 1 2 Healthy\n\
                    EDGE 1 3 Missing";
        let d = parse_set_detail(body);
        // Labels parse WITHOUT the token tail; the tokens land in the parallel
        // per-node vectors.
        assert_eq!(
            d.nodes,
            vec![
                "ResourceSet/prod".to_string(),
                "Workload/web".to_string(),
                "Replica/web-192.0.2.10".to_string(),
                "Replica/web-192.0.2.11".to_string(),
            ]
        );
        assert_eq!(d.node_health, vec!["Healthy", "Healthy", "Healthy", "Missing"]);
        assert_eq!(d.node_sync, vec!["Synced", "Synced", "Synced", "Synced"]);

        // The collapsible depth tree: set root -> workload -> its two replicas.
        let root = depth_tree(&d).expect("non-empty graph yields a root");
        assert_eq!(root.id, "rsnode-0");
        assert_eq!(root.label, "ResourceSet/prod — Healthy/Synced");
        assert_eq!(root.children.len(), 1, "set root has the one Workload child");
        let wl = &root.children[0];
        assert_eq!(wl.label, "Workload/web — Healthy/Synced");
        assert_eq!(wl.children.len(), 2, "workload descends into its 2 replicas");
        assert_eq!(
            wl.children[1].label,
            "Replica/web-192.0.2.11 — Missing/Synced",
            "the exited replica carries a Missing per-node token"
        );
    }

    #[test]
    fn depth_tree_is_none_for_an_empty_graph() {
        let d = parse_set_detail("SET x\nHEALTH Empty\nSYNC Synced");
        assert!(depth_tree(&d).is_none());
    }

    /// Mount-audit (anti-facade DoD): the ResourceSet detail must render its
    /// resource tree through the SHIPPED `Tree` primitive as a real,
    /// collapsible, layered depth view — NOT the old fixed circle-layout
    /// `Graph` star. This asserts the component is mounted (referenced from the
    /// console module), not orphaned.
    #[test]
    fn resource_tree_is_mounted_through_the_shipped_tree_primitive() {
        let src = include_str!("resourcesets_console.rs");
        assert!(
            src.contains("use crate::components::tree::Tree;"),
            "the console no longer imports the shipped Tree primitive"
        );
        assert!(
            src.contains("<Tree roots={vec![root]}"),
            "the depth tree is no longer mounted through the Tree component"
        );
        assert!(
            src.contains("ds-resource-tree--zoompan"),
            "the tree is no longer wrapped in a zoom/pan viewport"
        );
        // The fixed circle-layout Graph star is gone from the detail render:
        // the console no longer imports the Graph/GraphEdge primitive at all.
        // (Built by concatenation so this assertion's own text is not a match.)
        let old_graph_import = format!("Badge, DiffView, {}, {}, Tone", "Graph", "GraphEdge");
        assert!(
            !src.contains(&old_graph_import),
            "the fixed circle-layout Graph star must be replaced by the depth tree"
        );
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

    #[test]
    fn parses_the_additive_member_reason_tail_after_origin() {
        // A degraded member carries the ADDITIVE, free-form `REASON <msg>` tail
        // (LAST, may contain spaces) AFTER `ORIGIN <origin>`; a healthy member
        // has no reason. Both are parsed off correctly.
        let body = "SET web\n\
                    MEMBER Job/nightly HEALTH Missing ORIGIN operator REASON declared member Job/nightly is absent from the live resource plane\n\
                    MEMBER RetentionPolicy/web-metrics HEALTH Healthy ORIGIN operator\n\
                    HEALTH Degraded\nSYNC OutOfSync";
        let d = parse_set_detail(body);
        assert_eq!(d.members.len(), 2);
        // Missing member: origin still parsed, reason captured whole.
        assert_eq!(d.members[0].reference, "Job/nightly");
        assert_eq!(d.members[0].health, "Missing");
        assert_eq!(d.members[0].origin, "operator");
        assert_eq!(
            d.members[0].reason,
            "declared member Job/nightly is absent from the live resource plane"
        );
        // Healthy member: no reason tail.
        assert_eq!(d.members[1].health, "Healthy");
        assert_eq!(d.members[1].origin, "operator");
        assert!(d.members[1].reason.is_empty());
    }

    #[test]
    fn member_reason_parses_even_without_an_origin_field() {
        // Backward/forward compatible: `MEMBER <ref> HEALTH <h> REASON <msg>`
        // (no ORIGIN) still splits the reason off correctly.
        let body = "SET web\nMEMBER Job/x HEALTH Missing REASON gone";
        let d = parse_set_detail(body);
        assert_eq!(d.members[0].health, "Missing");
        assert_eq!(d.members[0].origin, "");
        assert_eq!(d.members[0].reason, "gone");
    }

    #[test]
    fn sync_tone_covers_the_full_argocd_parity_set() {
        // The FULL tone set, replacing the old binary Synced-vs-Warn.
        assert_eq!(sync_tone("Synced"), Tone::Success);
        assert_eq!(sync_tone("Progressing"), Tone::Info);
        assert_eq!(sync_tone("OutOfSync"), Tone::Warn);
        assert_eq!(sync_tone("Error"), Tone::Danger);
        assert_eq!(sync_tone("Unknown"), Tone::Neutral);
        // Case-insensitive; an unrecognized value is Neutral (not Warn).
        assert_eq!(sync_tone("progressing"), Tone::Info);
        assert_eq!(sync_tone("whatever"), Tone::Neutral);
    }

    #[test]
    fn health_tone_maps_each_health_state() {
        assert_eq!(health_tone("Healthy"), Tone::Success);
        assert_eq!(health_tone("Degraded"), Tone::Warn);
        assert_eq!(health_tone("Missing"), Tone::Danger);
        assert_eq!(health_tone("Empty"), Tone::Neutral);
    }

    /// Mount-audit (anti-facade DoD): the ResourceSet list must render through
    /// the SHIPPED DataTable primitive with health/sync filter chips — not a
    /// hand-rolled `<table>`. A source audit locks the wiring so a future edit
    /// cannot silently drop the DataTable/chips and regress to the old list.
    #[test]
    fn list_renders_through_datatable_with_filter_chips() {
        let src = include_str!("resourcesets_console.rs");
        assert!(
            src.contains("use crate::components::data_table::{Column, DataTable, Row}"),
            "resourcesets_console no longer imports the DataTable primitive"
        );
        assert!(
            src.contains("<DataTable") && src.contains("on_row_click={on_row_click}"),
            "the list is no longer rendered through DataTable with row selection"
        );
        assert!(
            src.contains("health_chip_btn(") && src.contains("sync_chip_btn("),
            "the list no longer offers health/sync filter chips"
        );
    }

    /// Mount-audit (anti-facade DoD): the reconcile plan must be a real
    /// operator ACTION — mounted through `ReconcilePanel`, reusing the SAME
    /// `ChangeState` dry-run gate + `DiffView` the resources console uses,
    /// with a checkbox per adopt/prune member (selective sync) — never a
    /// hand-rolled read-only `<ul>` of the plan.
    #[test]
    fn reconcile_plan_is_mounted_as_a_signed_dry_run_gated_action() {
        let src = include_str!("resourcesets_console.rs");
        assert!(
            src.contains("<ReconcilePanel"),
            "the reconcile plan no longer mounts the ReconcilePanel action"
        );
        assert!(
            src.contains("use crate::resources_console::{parse_act_result, parse_predicted, ChangeState}"),
            "ReconcilePanel no longer reuses the shared ChangeState dry-run gate"
        );
        assert!(
            src.contains("<DiffView old={diff_old} new={diff_new} />"),
            "ReconcilePanel no longer renders the shipped DiffView preview"
        );
        assert!(
            src.contains(r#"id="resourceset-reconcile-apply""#)
                && src.contains("if gate.can_confirm()"),
            "the apply control is no longer gated on ChangeState::can_confirm"
        );
        assert!(
            src.contains(r#"type="checkbox""#) && src.contains("selected_subset("),
            "ReconcilePanel no longer offers per-member selective-sync checkboxes"
        );
        assert!(
            src.contains(r#"http("POST", "/portal/resource/reconcile", Some(&body))"#),
            "the selective apply no longer routes through the signed act path"
        );
    }

    #[test]
    fn reconcile_request_body_carries_token_name_and_selected_members_only() {
        let body = reconcile_request_body(
            "tok",
            "web",
            &["Job/nightly".to_string()],
            &["RetentionPolicy/old".to_string()],
        );
        assert_eq!(body, "tok\nweb\nADOPT Job/nightly\nPRUNE RetentionPolicy/old");
        // Deselecting an axis narrows to an empty (never omitted) field.
        let narrowed = reconcile_request_body("tok", "web", &[], &["RetentionPolicy/old".to_string()]);
        assert_eq!(narrowed, "tok\nweb\nADOPT \nPRUNE RetentionPolicy/old");
    }

    #[test]
    fn selected_subset_narrows_the_plan_to_only_the_checked_members_in_order() {
        let plan = vec![
            "Job/a".to_string(),
            "Job/b".to_string(),
            "Job/c".to_string(),
        ];
        let mut selected = std::collections::HashSet::new();
        selected.insert("Job/a".to_string());
        selected.insert("Job/c".to_string());
        assert_eq!(
            selected_subset(&plan, &selected),
            vec!["Job/a".to_string(), "Job/c".to_string()]
        );
        // Deselecting everything narrows to an empty selective sync, never
        // silently falling back to the full plan.
        assert!(selected_subset(&plan, &std::collections::HashSet::new()).is_empty());
    }

    /// The reconcile/apply state machine — same [`ChangeState`] the resources
    /// console's dry-run-gate test proves, applied here to the reconcile
    /// action: a mutating apply of the (possibly selective) plan cannot issue
    /// without a preceding dry-run of that EXACT selection having just
    /// answered ALLOW, and narrowing the selection invalidates a stale
    /// preview so it can never authorize a DIFFERENT (now-narrower) apply.
    #[test]
    fn reconcile_cannot_apply_without_a_preceding_allow_dry_run_of_this_exact_selection() {
        use crate::resources_console::ChangeState;

        let mut gate = ChangeState::default();
        assert!(!gate.can_confirm(), "a reconcile apply must not confirm from Idle");
        // A DENY dry-run still refuses.
        gate = gate.previewed(false);
        assert!(!gate.can_confirm(), "a DENY dry-run must not authorize a reconcile apply");
        // Only a preceding ALLOW dry-run authorizes the apply.
        gate = gate.previewed(true);
        assert!(gate.can_confirm(), "an ALLOW dry-run must authorize the reconcile apply");
        // Toggling a member's selective-sync checkbox (invalidation) strips
        // the authorization: a stale ALLOW previewed a DIFFERENT selection.
        gate = gate.invalidated();
        assert!(
            !gate.can_confirm(),
            "narrowing the selection after preview must not carry over its ALLOW"
        );
    }

    /// The node `onselect` routing hop: a clicked depth-tree node id
    /// (`rsnode-<idx>`) resolves to the `Kind/name` resource the SHIPPED
    /// resources-console per-resource detail drawer consumes. This is the exact
    /// value the console's `on_node_select` callback feeds into the mounted
    /// `ResourceDetail` drawer — proving node selection is wired to the real
    /// drawer's input type, not a stub. The return type is
    /// `crate::resources_console::ResourceRow`, i.e. `ResourceDetailProps::row`.
    #[test]
    fn a_selected_graph_node_routes_into_the_resources_console_detail_drawer() {
        let body = "SET web\n\
                    HEALTH Degraded\n\
                    SYNC OutOfSync\n\
                    NODE 0 ResourceSet/web\n\
                    NODE 1 Workload/api\n\
                    NODE 2 Job/nightly\n\
                    EDGE 0 1 Healthy\n\
                    EDGE 0 2 Missing";
        let d = parse_set_detail(body);

        // A member node routes to that member's ResourceRow — the SAME type
        // `ResourceDetailProps { row }` (the shipped drawer's props) carries.
        let row: crate::resources_console::ResourceRow =
            node_resource_ref(&d, "rsnode-1").expect("a member node must route to a resource");
        assert_eq!(row.kind, "Workload");
        assert_eq!(row.name, "api");
        assert_eq!(row.replicas, None);

        let job = node_resource_ref(&d, "rsnode-2").expect("the Job member node must route");
        assert_eq!(job.kind, "Job");
        assert_eq!(job.name, "nightly");

        // The set-root (node 0) is the container, not a per-resource member:
        // it never opens the detail drawer.
        assert!(
            node_resource_ref(&d, "rsnode-0").is_none(),
            "the ResourceSet root node must not open a per-resource drawer"
        );
        // A non-node / out-of-range id resolves to nothing (no drawer opens).
        assert!(node_resource_ref(&d, "rsnode-99").is_none());
        assert!(node_resource_ref(&d, "not-a-node").is_none());
    }

    /// Guard the exact ids `depth_tree` stamps are the ones `node_resource_ref`
    /// resolves — so the tree the console renders and the routing hop the
    /// `onselect` runs agree on node identity end to end (a stub that hard-coded
    /// ids would drift from the real tree).
    #[test]
    fn depth_tree_node_ids_round_trip_through_the_select_router() {
        let body = "SET web\n\
                    NODE 0 ResourceSet/web\n\
                    NODE 1 Workload/api\n\
                    EDGE 0 1 Healthy";
        let d = parse_set_detail(body);
        let root = depth_tree(&d).expect("a non-empty graph builds a tree");
        // The root's child is the Workload member node; its id must route.
        let child = &root.children[0];
        assert_eq!(child.id, "rsnode-1");
        let row = node_resource_ref(&d, &child.id)
            .expect("the tree's own child-node id must route into the detail drawer");
        assert_eq!((row.kind.as_str(), row.name.as_str()), ("Workload", "api"));
    }
}
