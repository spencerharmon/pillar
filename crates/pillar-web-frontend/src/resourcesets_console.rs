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

/// One prior revision of a resource, parsed from a `REVISION <i> EVENT <cid>
/// SIGNER <s> HASH <h> IMAGE <img>` line of `GET /portal/resource/history`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevisionRow {
    /// The positional index (0 = oldest revision).
    pub index: usize,
    /// The authorizing event CID (a rollback re-applies this exact revision).
    pub event_cid: String,
    /// The subject that signed (authorized) the revision.
    pub signer: String,
    /// The content-addressed manifest hash for the revision.
    pub hash: String,
    /// The revision's spec `image` (`-` when the manifest declares none).
    pub image: String,
}

/// The parsed change timeline of one resource: its `Kind/name` reference and
/// its revisions (oldest first), from `GET /portal/resource/history`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevisionHistory {
    /// The `Kind/name` reference the timeline belongs to.
    pub reference: String,
    /// The prior revisions of the resource, oldest first.
    pub revisions: Vec<RevisionRow>,
}

/// Parse the `GET /portal/resource/history` body: a `HISTORY <kind>/<name>
/// COUNT <n>` header + one `REVISION <i> EVENT <cid> SIGNER <s> HASH <h> IMAGE
/// <img>` line per prior apply. Unknown lines are ignored.
#[must_use]
pub fn parse_history(body: &str) -> RevisionHistory {
    let mut h = RevisionHistory::default();
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("HISTORY ") {
            h.reference = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
        } else if let Some(rest) = line.strip_prefix("REVISION ") {
            let toks: Vec<&str> = rest.split_whitespace().collect();
            // `<i> EVENT <cid> SIGNER <s> HASH <h> IMAGE <img>`
            if toks.len() >= 9
                && toks[1] == "EVENT"
                && toks[3] == "SIGNER"
                && toks[5] == "HASH"
                && toks[7] == "IMAGE"
            {
                h.revisions.push(RevisionRow {
                    index: toks[0].parse().unwrap_or(0),
                    event_cid: toks[2].to_string(),
                    signer: toks[4].to_string(),
                    hash: toks[6].to_string(),
                    image: toks[8].to_string(),
                });
            }
        }
    }
    h
}

#[cfg(feature = "yew")]
pub use yew_impl::ResourceSetsConsole;
#[cfg(feature = "yew")]
mod yew_impl {
    use super::{parse_set_detail, parse_set_list, ResourceSetDetail, ResourceSetRow};
    use super::{parse_history, RevisionHistory};
    use crate::auth::use_auth;
    use crate::portal::{body_lines, get_url, http};
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

    /// The **Revision history + rollback** panel: load a workload's change
    /// timeline from `GET /portal/resource/history` (each row's authorizing
    /// event CID + signer), and roll a resource back to a prior revision via
    /// `POST /portal/resource/rollback` — a re-apply of that event's manifest
    /// gated by the SAME dry-run + diff preview (`GET /portal/resource/dry-run`)
    /// as any other apply. On rollback the history reloads so the new head is
    /// visible.
    #[function_component(RevisionHistoryPanel)]
    pub fn revision_history_panel() -> Html {
        let auth = use_auth();
        let name = use_state(String::new);
        let history = use_state(|| None::<RevisionHistory>);
        let preview = use_state(String::new);

        let on_name = {
            let name = name.clone();
            Callback::from(move |e: InputEvent| name.set(crate::portal::input_value(&e)))
        };

        let load = {
            let (auth, name, history) = (auth.clone(), name.clone(), history.clone());
            Callback::from(move |_: MouseEvent| {
                if let (Some(token), n) = (auth.token.clone(), (*name).clone()) {
                    if n.is_empty() {
                        return;
                    }
                    let history = history.clone();
                    let url = get_url(
                        "/portal/resource/history",
                        &token,
                        &[("kind", "Workload"), ("name", &n)],
                    );
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &url, None).await {
                            if r.ok() {
                                history.set(Some(parse_history(&r.body)));
                            } else {
                                history.set(Some(RevisionHistory::default()));
                            }
                        }
                    });
                }
            })
        };

        let rollback = {
            let (auth, name, history, preview) =
                (auth.clone(), name.clone(), history.clone(), preview.clone());
            Callback::from(move |event_cid: String| {
                if let (Some(token), n) = (auth.token.clone(), (*name).clone()) {
                    if n.is_empty() {
                        return;
                    }
                    let (history, preview) = (history.clone(), preview.clone());
                    spawn_local(async move {
                        // Gate the rollback on the SAME dry-run + diff preview
                        // any apply uses: predict the decider decision first.
                        let dry = get_url("/portal/resource/dry-run", &token, &[]);
                        let predicted = match http("GET", &dry, None).await {
                            Ok(r) if r.ok() => r.body,
                            _ => String::new(),
                        };
                        preview.set(predicted.clone());
                        if !predicted.contains("ALLOW") {
                            return;
                        }
                        let body = body_lines(&[&token, &n, &event_cid]);
                        if let Ok(r) = http("POST", "/portal/resource/rollback", Some(&body)).await {
                            if r.ok() {
                                // Reload the timeline so the rolled-back head shows.
                                let url = get_url(
                                    "/portal/resource/history",
                                    &token,
                                    &[("kind", "Workload"), ("name", &n)],
                                );
                                if let Ok(h) = http("GET", &url, None).await {
                                    if h.ok() {
                                        history.set(Some(parse_history(&h.body)));
                                    }
                                }
                            }
                        }
                    });
                }
            })
        };

        let rows: Html = match &*history {
            None => html! { <p class="ds-muted">{ "Enter a workload name and load its revision history." }</p> },
            Some(h) if h.revisions.is_empty() => {
                html! { <p class="ds-empty">{ "No prior revisions for that resource." }</p> }
            }
            Some(h) => {
                let rows: Html = h
                    .revisions
                    .iter()
                    .rev()
                    .map(|rev| {
                        let cid = rev.event_cid.clone();
                        let do_rollback = {
                            let (rollback, cid) = (rollback.clone(), cid.clone());
                            Callback::from(move |_: MouseEvent| rollback.emit(cid.clone()))
                        };
                        html! {
                            <tr>
                                <td>{ rev.index }</td>
                                <td class="mono">{ rev.event_cid.clone() }</td>
                                <td class="mono">{ rev.signer.clone() }</td>
                                <td class="mono">{ rev.image.clone() }</td>
                                <td>
                                    <button class="ds-btn" onclick={do_rollback}>{ "Roll back" }</button>
                                </td>
                            </tr>
                        }
                    })
                    .collect();
                html! {
                    <table class="ds-table">
                        <thead>
                            <tr>
                                <th>{ "Rev" }</th><th>{ "Event CID" }</th>
                                <th>{ "Signer" }</th><th>{ "Image" }</th><th>{ "" }</th>
                            </tr>
                        </thead>
                        <tbody>{ rows }</tbody>
                    </table>
                }
            }
        };

        let preview_view = if preview.is_empty() {
            html! {}
        } else {
            html! { <p class="ds-muted">{ format!("Dry-run: {}", *preview) }</p> }
        };

        html! {
            <section class="ds-panel" id="revision-history">
                <header class="ds-panel__head">
                    <h3>{ "Revision history + rollback" }</h3>
                </header>
                <p class="ds-muted">
                    { "Each signed change records its authorizing event CID + signer. Rollback re-applies a prior revision's manifest, gated by the same dry-run + diff preview as any apply." }
                </p>
                <div class="ds-field">
                    <input
                        class="ds-input"
                        placeholder="workload name"
                        value={(*name).clone()}
                        oninput={on_name}
                    />
                    <button class="ds-btn" onclick={load}>{ "Load history" }</button>
                </div>
                { preview_view }
                { rows }
            </section>
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
                <RevisionHistoryPanel />
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_history_timeline_lines() {
        let body = "HISTORY Workload/web COUNT 2\n\
                    REVISION 0 EVENT cid-aaa SIGNER op-subkey-alice HASH h0 IMAGE app:v1\n\
                    REVISION 1 EVENT cid-bbb SIGNER op-subkey-alice HASH h1 IMAGE app:v2\n\
                    garbage line";
        let h = parse_history(body);
        assert_eq!(h.reference, "Workload/web");
        assert_eq!(h.revisions.len(), 2);
        assert_eq!(
            h.revisions[0],
            RevisionRow {
                index: 0,
                event_cid: "cid-aaa".into(),
                signer: "op-subkey-alice".into(),
                hash: "h0".into(),
                image: "app:v1".into(),
            }
        );
        assert_eq!(h.revisions[1].event_cid, "cid-bbb");
        assert_eq!(h.revisions[1].image, "app:v2");
    }

    #[test]
    fn history_with_no_revisions_parses_empty() {
        let h = parse_history("HISTORY Workload/absent COUNT 0\n");
        assert_eq!(h.reference, "Workload/absent");
        assert!(h.revisions.is_empty());
    }

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
}
