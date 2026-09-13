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

use crate::primitives::Tone;

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
    use super::{health_tone, parse_set_detail, parse_set_list, sync_tone, ResourceSetDetail, ResourceSetRow};
    use crate::auth::use_auth;
    use crate::components::data_table::{Column, DataTable, Row};
    use crate::portal::{get_url, http};
    use crate::primitives::{Badge, Graph, GraphEdge, Tone};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// The Resource Sets console: a list of ResourceSets with health/sync
    /// pills; selecting one loads its detail + resource graph.
    #[function_component(ResourceSetsConsole)]
    pub fn resource_sets_console() -> Html {
        let auth = use_auth();
        let sets = use_state(Vec::<ResourceSetRow>::new);
        let selected = use_state(|| None::<String>);
        let detail = use_state(|| None::<ResourceSetDetail>);

        // Load the set list on mount / token change.
        {
            let (auth, sets) = (auth.clone(), sets.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let sets = sets.clone();
                    let url = get_url("/portal/resource/sets", &token, &[]);
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                sets.set(parse_set_list(&r.body));
                            }
                        }
                    });
                }
                || ()
            });
        }

        // Load the selected set's detail on selection / token change.
        {
            let (auth, selected, detail) = (auth.clone(), selected.clone(), detail.clone());
            use_effect_with(
                ((*selected).clone(), auth.token.clone()),
                move |(sel, token)| {
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

        // Health / sync filter CHIPS: `None` = show all, `Some(v)` = only rows
        // whose health (resp. sync) equals `v` (case-insensitive). The list then
        // renders through the SHIPPED DataTable primitive (filter box + sortable
        // columns) over the chip-narrowed row set.
        let health_chip = use_state(|| None::<String>);
        let sync_chip = use_state(|| None::<String>);

        // DataTable columns: Name/Health/Sync are text-sortable; the counts are
        // numeric-sortable; Defaults is a plain advisory cell.
        let columns: Vec<Column> = vec![
            Column::text("Name"),
            Column::text("Health"),
            Column::text("Sync"),
            Column::numeric("Members"),
            Column::numeric("Adopt"),
            Column::numeric("Prune"),
            Column::text("Defaults"),
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
                vec![
                    s.name.clone(),
                    s.health.clone(),
                    s.sync.clone(),
                    s.members.to_string(),
                    s.adopt.to_string(),
                    s.prune.to_string(),
                    defaults,
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
                        <ul class="ds-list">
                            { for d.adopt.iter().map(|r| html!{ <li>{ format!("adopt {r}") }</li> }) }
                            { for d.prune.iter().map(|r| html!{ <li>{ format!("prune {r}") }</li> }) }
                        </ul>
                    }
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
                            </div>
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
}
