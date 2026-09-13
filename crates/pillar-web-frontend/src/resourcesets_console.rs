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

/// One node of the ResourceSet's resource graph/tree: its label plus its own
/// per-node health+sync token (node 0 is the set root; a `Workload` member's
/// live replica children — descended from the `/portal/resource/replicas`
/// oracle by the backend dispatcher — carry `sync = "Live"`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphNodeInfo {
    pub label: String,
    pub health: String,
    pub sync: String,
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
    /// Graph nodes, in emission order (node 0 is the set root) — depth-tree
    /// aware: a `Workload` member's live replicas are appended after the
    /// top-level member nodes and reached via `edges`.
    pub nodes: Vec<GraphNodeInfo>,
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
            // `<i> <label> [HEALTH <h> SYNC <s>]` — index is positional (nodes
            // emitted in order); the HEALTH/SYNC suffix is optional so an
            // older wire body (label only) still parses.
            if let Some((_idx, rest)) = rest.split_once(' ') {
                match rest.split_once(" HEALTH ") {
                    Some((label, tail)) => {
                        let (health, sync) = match tail.split_once(" SYNC ") {
                            Some((h, s)) => (h.trim().to_string(), s.trim().to_string()),
                            None => (tail.trim().to_string(), String::new()),
                        };
                        d.nodes.push(GraphNodeInfo {
                            label: label.trim().to_string(),
                            health,
                            sync,
                        });
                    }
                    None => d.nodes.push(GraphNodeInfo {
                        label: rest.trim().to_string(),
                        health: String::new(),
                        sync: String::new(),
                    }),
                }
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

/// Lower a [`ResourceSetDetail`]'s flat `(nodes, edges)` wire shape into the
/// nested [`crate::components::tree::TreeNode`] hierarchy the console renders
/// — a pure, host-testable derivation (no protocol) mirroring the depth the
/// backend descended (`ResourceSet -> Workload -> replica`). Node 0 is the
/// root; every other node is reached by following its FIRST incoming edge (a
/// resource graph here is always tree-shaped: the backend emits exactly one
/// edge into each non-root node).
#[must_use]
pub fn nodes_to_tree(nodes: &[GraphNodeInfo], edges: &[(usize, usize, String)]) -> Vec<crate::components::tree::TreeNode> {
    use crate::components::tree::TreeNode;

    fn label_for(n: &GraphNodeInfo) -> String {
        if n.health.is_empty() {
            n.label.clone()
        } else if n.sync.is_empty() {
            format!("{} [{}]", n.label, n.health)
        } else {
            format!("{} [{}/{}]", n.label, n.health, n.sync)
        }
    }

    fn build(i: usize, nodes: &[GraphNodeInfo], edges: &[(usize, usize, String)]) -> TreeNode {
        let children: Vec<TreeNode> = edges
            .iter()
            .filter(|(from, _, _)| *from == i)
            .filter_map(|(_, to, _)| nodes.get(*to).map(|_| build(*to, nodes, edges)))
            .collect();
        let label = nodes
            .get(i)
            .map(|n| label_for(n))
            .unwrap_or_default();
        TreeNode {
            id: i.to_string(),
            label,
            children,
        }
    }

    if nodes.is_empty() {
        return Vec::new();
    }
    vec![build(0, nodes, edges)]
}

#[cfg(feature = "yew")]
pub use yew_impl::ResourceSetsConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{nodes_to_tree, parse_set_detail, parse_set_list, ResourceSetDetail, ResourceSetRow};
    use crate::auth::use_auth;
    use crate::components::tree::Tree;
    use crate::portal::{get_url, http};
    use crate::primitives::{Badge, Tone};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    fn sync_tone(sync: &str) -> Tone {
        if sync.eq_ignore_ascii_case("Synced") {
            Tone::Success
        } else {
            Tone::Warn
        }
    }

    const ZOOM_STEP: f64 = 0.15;
    const ZOOM_MIN: f64 = 0.4;
    const ZOOM_MAX: f64 = 2.5;

    /// Zoom/pan chrome around a scrollable tree — zoom in/out/reset buttons
    /// scale the wrapped content, panning is left to native scroll (the
    /// wrapper is `overflow: auto`), which keeps this dependency-free (no
    /// pointer-drag JS glue) while still giving the operator a way to see a
    /// deep tree at a glance (zoom out) or drill into one branch (zoom in).
    #[derive(Properties, PartialEq)]
    pub struct ZoomPanProps {
        #[prop_or_default]
        pub children: Html,
    }

    #[function_component(ZoomPan)]
    pub fn zoom_pan(props: &ZoomPanProps) -> Html {
        let zoom = use_state(|| 1.0_f64);
        let zoom_in = {
            let zoom = zoom.clone();
            Callback::from(move |_: MouseEvent| zoom.set((*zoom + ZOOM_STEP).min(ZOOM_MAX)))
        };
        let zoom_out = {
            let zoom = zoom.clone();
            Callback::from(move |_: MouseEvent| zoom.set((*zoom - ZOOM_STEP).max(ZOOM_MIN)))
        };
        let zoom_reset = {
            let zoom = zoom.clone();
            Callback::from(move |_: MouseEvent| zoom.set(1.0))
        };
        let style = format!("transform: scale({}); transform-origin: top left;", *zoom);
        html! {
            <div class="ds-zoompan">
                <div class="ds-zoompan__controls">
                    <button type="button" onclick={zoom_out}>{ "\u{2212}" }</button>
                    <span class="ds-muted">{ format!("{:.0}%", *zoom * 100.0) }</span>
                    <button type="button" onclick={zoom_in}>{ "+" }</button>
                    <button type="button" onclick={zoom_reset}>{ "Reset" }</button>
                </div>
                <div class="ds-zoompan__viewport">
                    <div class="ds-zoompan__content" style={style}>
                        { props.children.clone() }
                    </div>
                </div>
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
                html! {
                    <tr class={class} onclick={select} style="cursor:pointer">
                        <td class="mono">{ name }</td>
                        <td><Badge label={s.health.clone()} /></td>
                        <td><Badge label={s.sync.clone()} tone={sync_tone(&s.sync)} /></td>
                        <td>{ s.members }</td>
                        <td>{ s.adopt }</td>
                        <td>{ s.prune }</td>
                        <td>{ defaults_cell }</td>
                    </tr>
                }
            })
            .collect();

        let detail_view: Html = match &*detail {
            None => {
                html! { <p class="ds-empty">{ "Select a resource set to view its graph." }</p> }
            }
            Some(d) => {
                let tree_roots = nodes_to_tree(&d.nodes, &d.edges);
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
                            </div>
                        </header>
                        if !d.description.is_empty() {
                            <p class="ds-muted">{ d.description.clone() }</p>
                        }
                        <h4>{ "Resource tree" }</h4>
                        <ZoomPan>
                            <Tree roots={tree_roots} default_expanded={vec!["0".to_string()]} />
                        </ZoomPan>
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
                <table class="ds-table">
                    <thead>
                        <tr>
                            <th>{ "Name" }</th><th>{ "Health" }</th><th>{ "Sync" }</th>
                            <th>{ "Members" }</th><th>{ "Adopt" }</th><th>{ "Prune" }</th>
                            <th>{ "Defaults" }</th>
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
                    NODE 0 ResourceSet/default HEALTH Degraded SYNC OutOfSync\n\
                    NODE 1 RetentionPolicy/web-metrics HEALTH Healthy SYNC Healthy\n\
                    NODE 2 Job/nightly HEALTH Missing SYNC Missing\n\
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
                GraphNodeInfo {
                    label: "ResourceSet/default".to_string(),
                    health: "Degraded".to_string(),
                    sync: "OutOfSync".to_string(),
                },
                GraphNodeInfo {
                    label: "RetentionPolicy/web-metrics".to_string(),
                    health: "Healthy".to_string(),
                    sync: "Healthy".to_string(),
                },
                GraphNodeInfo {
                    label: "Job/nightly".to_string(),
                    health: "Missing".to_string(),
                    sync: "Missing".to_string(),
                },
            ]
        );
        assert_eq!(
            d.edges,
            vec![(0, 1, "Healthy".to_string()), (0, 2, "Missing".to_string()),]
        );
    }

    #[test]
    fn nodes_to_tree_descends_a_workload_into_its_replicas() {
        let body = "SET default\n\
                    NODE 0 ResourceSet/default HEALTH Healthy SYNC Synced\n\
                    NODE 1 Workload/web HEALTH Healthy SYNC Healthy\n\
                    NODE 2 Replica/node-a:9001 HEALTH Healthy SYNC Live\n\
                    NODE 3 Replica/node-b:9002 HEALTH Healthy SYNC Live\n\
                    EDGE 0 1 Healthy\n\
                    EDGE 1 2 Healthy\n\
                    EDGE 1 3 Healthy";
        let d = parse_set_detail(body);
        let tree = nodes_to_tree(&d.nodes, &d.edges);
        assert_eq!(tree.len(), 1);
        let root = &tree[0];
        assert!(root.label.contains("ResourceSet/default"));
        assert_eq!(root.children.len(), 1);
        let workload = &root.children[0];
        assert!(workload.label.contains("Workload/web"));
        assert_eq!(workload.children.len(), 2);
        assert!(workload.children[0].label.contains("Replica/node-a:9001"));
        assert!(workload.children[1].label.contains("Replica/node-b:9002"));
        assert!(workload.children[0].children.is_empty());
    }

    #[test]
    fn empty_default_set_detail_has_only_the_root_node() {
        let body = "SET default\nDESC \nHEALTH Empty\nSYNC Synced\nNODE 0 ResourceSet/default HEALTH Empty SYNC Synced";
        let d = parse_set_detail(body);
        assert_eq!(d.description, "");
        assert_eq!(d.health, "Empty");
        assert_eq!(
            d.nodes,
            vec![GraphNodeInfo {
                label: "ResourceSet/default".to_string(),
                health: "Empty".to_string(),
                sync: "Synced".to_string(),
            }]
        );
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
}
