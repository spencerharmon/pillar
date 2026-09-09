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
}

/// Parse the `GET /portal/resource/sets` body: one
/// `SET <name> HEALTH <h> SYNC <s> MEMBERS <n> ADOPT <n> PRUNE <n>` line per
/// set. A line missing a field falls back to sensible defaults for that field.
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
                _ => {}
            }
            i += 2;
        }
        out.push(row);
    }
    out
}

/// One member row of a ResourceSet detail: the `Kind/name` reference and its
/// observed health.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberRow {
    pub reference: String,
    pub health: String,
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
            // `<ref> HEALTH <h>`
            if let Some((reference, health)) = rest.split_once(" HEALTH ") {
                d.members.push(MemberRow {
                    reference: reference.trim().to_string(),
                    health: health.trim().to_string(),
                });
            }
        } else if let Some(rest) = line.strip_prefix("PLAN ADOPT ") {
            d.adopt = split_csv(rest);
        } else if let Some(rest) = line.strip_prefix("PLAN PRUNE ") {
            d.prune = split_csv(rest);
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
    use super::{parse_set_detail, parse_set_list, ResourceSetDetail, ResourceSetRow};
    use crate::auth::use_auth;
    use crate::portal::{get_url, http};
    use crate::primitives::{Badge, Graph, GraphEdge, Tone};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    fn sync_tone(sync: &str) -> Tone {
        if sync.eq_ignore_ascii_case("Synced") {
            Tone::Success
        } else {
            Tone::Warn
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
                html! {
                    <tr class={class} onclick={select} style="cursor:pointer">
                        <td class="mono">{ name }</td>
                        <td><Badge label={s.health.clone()} /></td>
                        <td><Badge label={s.sync.clone()} tone={sync_tone(&s.sync)} /></td>
                        <td>{ s.members }</td>
                        <td>{ s.adopt }</td>
                        <td>{ s.prune }</td>
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
                        html! {
                            <tr>
                                <td class="mono">{ m.reference.clone() }</td>
                                <td><Badge label={m.health.clone()} /></td>
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
                        <Graph nodes={d.nodes.clone()} edges={graph_edges} />
                        <h4>{ "Members" }</h4>
                        <table class="ds-table">
                            <thead><tr><th>{ "Resource" }</th><th>{ "Health" }</th></tr></thead>
                            <tbody>{ member_rows }</tbody>
                        </table>
                        <h4>{ "Reconcile plan" }</h4>
                        { plan }
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
        let body = "SET default HEALTH Healthy SYNC Synced MEMBERS 2 ADOPT 0 PRUNE 0\n\
                    SET web HEALTH Degraded SYNC OutOfSync MEMBERS 3 ADOPT 1 PRUNE 2\n\
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
            }
        );
        assert_eq!(rows[1].name, "web");
        assert_eq!(rows[1].adopt, 1);
        assert_eq!(rows[1].prune, 2);
        assert_eq!(rows[1].sync, "OutOfSync");
    }

    #[test]
    fn parses_the_detail_header_members_plan_and_graph() {
        let body = "SET default\n\
                    DESC default retention policies\n\
                    MEMBER RetentionPolicy/web-metrics HEALTH Healthy\n\
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
        assert_eq!(d.members[1].health, "Missing");
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
}
