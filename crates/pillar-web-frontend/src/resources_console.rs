//! The Resources console (Phase 3) — an AWS/ArgoCD-style workload console over
//! the node's already-served `/portal/resource/*` control plane. Every view is
//! a real round trip to an existing endpoint; the only new logic is
//! presentation plus a **dry-run + diff before apply** confirmation flow that
//! pairs the backend's authorization preview (`PREDICTED ALLOW/DENY`) with a
//! host-computed diff of the resource's current field vs the proposed change,
//! so an operator sees exactly what a signed act will do before it is emitted.
//!
//! As with the rest of the console, the wire parsers are pure functions pinned
//! to the exact line formats the backend dispatchers emit, unit-tested on the
//! host; the `yew` component is a thin wrapper over them.

/// One row of `GET /portal/resource/get`: `<kind>/<name>[ replicas=<n>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRow {
    /// The resource kind (e.g. `Workload`).
    pub kind: String,
    /// The resource name.
    pub name: String,
    /// The declared replica count, when the row carries one.
    pub replicas: Option<i64>,
}

/// Parse the `resource_get` body: one `<kind>/<name>[ replicas=<n>]` per line,
/// ignoring the trailing `EVENTS <n>` bookkeeping line. Malformed lines are
/// skipped rather than fabricated.
#[must_use]
pub fn parse_resource_rows(body: &str) -> Vec<ResourceRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("EVENTS ") {
            continue;
        }
        let (head, replicas) = match line.split_once(" replicas=") {
            Some((h, n)) => (h, n.trim().parse::<i64>().ok()),
            None => (line, None),
        };
        let Some((kind, name)) = head.split_once('/') else {
            continue;
        };
        if kind.is_empty() || name.is_empty() {
            continue;
        }
        out.push(ResourceRow {
            kind: kind.to_owned(),
            name: name.to_owned(),
            replicas,
        });
    }
    out
}

/// One live replica from `GET /portal/resource/replicas`:
/// `REPLICA <workload> <node> pid=<pid> port=<port> digest=<hex>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaRow {
    /// The owning workload name.
    pub workload: String,
    /// The node the replica runs on.
    pub node: String,
    /// The OS process id.
    pub pid: String,
    /// The bound port.
    pub port: String,
    /// The content-addressed image digest.
    pub digest: String,
}

/// Parse the replica oracle body, skipping the trailing `REPLICAS <n>` count
/// line and anything that does not match the `REPLICA …` shape.
#[must_use]
pub fn parse_replicas(body: &str) -> Vec<ReplicaRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("REPLICA ") else {
            continue;
        };
        // `<workload> <node> pid=<> port=<> digest=<>`
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let field =
            |p: &str, key: &str| -> Option<String> { p.strip_prefix(key).map(str::to_owned) };
        let (Some(pid), Some(port), Some(digest)) = (
            field(parts[2], "pid="),
            field(parts[3], "port="),
            field(parts[4], "digest="),
        ) else {
            continue;
        };
        out.push(ReplicaRow {
            workload: parts[0].to_owned(),
            node: parts[1].to_owned(),
            pid,
            port,
            digest,
        });
    }
    out
}

/// Interpret `GET /portal/resource/dry-run`: `PREDICTED ALLOW` → `Some(true)`,
/// `PREDICTED DENY` → `Some(false)`, anything else → `None`.
#[must_use]
pub fn parse_predicted(body: &str) -> Option<bool> {
    match body.trim() {
        "PREDICTED ALLOW" => Some(true),
        "PREDICTED DENY" => Some(false),
        _ => None,
    }
}

/// Interpret a `POST /portal/resource/{apply,edit,scale,rollout}` response:
/// `EVENT <cid>` (first line) → `Ok(cid)`; a `DENIED …` body → `Err(reason)`.
#[must_use]
pub fn parse_act_result(body: &str) -> Result<String, String> {
    let first = body.lines().next().unwrap_or("").trim();
    if let Some(cid) = first.strip_prefix("EVENT ") {
        Ok(cid.to_owned())
    } else if let Some(reason) = first.strip_prefix("DENIED ") {
        Err(reason.to_owned())
    } else {
        Err(first.to_owned())
    }
}

/// The signed acts a resource change can request. Mirrors the backend
/// `ResourceAct` and the `POST /portal/resource/<verb>` routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceAction {
    /// Declarative upsert of a workload at an image.
    Apply,
    /// Change a workload's image.
    Edit,
    /// Change a workload's replica count.
    Scale,
    /// Trigger a rollout/restart.
    Rollout,
}

impl ResourceAction {
    /// All actions, in menu order.
    #[must_use]
    pub fn all() -> [ResourceAction; 4] {
        [
            ResourceAction::Apply,
            ResourceAction::Edit,
            ResourceAction::Scale,
            ResourceAction::Rollout,
        ]
    }

    /// The `/portal/resource/<path>` this action POSTs to.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            ResourceAction::Apply => "/portal/resource/apply",
            ResourceAction::Edit => "/portal/resource/edit",
            ResourceAction::Scale => "/portal/resource/scale",
            ResourceAction::Rollout => "/portal/resource/rollout",
        }
    }

    /// The human label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ResourceAction::Apply => "Apply",
            ResourceAction::Edit => "Edit image",
            ResourceAction::Scale => "Scale",
            ResourceAction::Rollout => "Roll out",
        }
    }

    /// The caption for this action's argument field, or `None` when the action
    /// takes no argument (rollout).
    #[must_use]
    pub fn arg_hint(self) -> Option<&'static str> {
        match self {
            ResourceAction::Apply => Some("image (default app:v1)"),
            ResourceAction::Edit => Some("new image"),
            ResourceAction::Scale => Some("replica count"),
            ResourceAction::Rollout => None,
        }
    }
}

/// The `<token>\n<name>\n<arg>` body every resource act POSTs (`arg` is empty
/// for a rollout).
#[must_use]
pub fn act_request_body(token: &str, name: &str, arg: &str) -> String {
    format!("{token}\n{name}\n{arg}")
}

/// Build the two sides of the "diff before apply" preview for `row` under
/// `action`/`arg`: the resource's CURRENT relevant field vs. the PROPOSED one,
/// derived entirely from live state (the selected inventory row) and the
/// operator's typed argument — never fabricated. Returns `(current, proposed)`
/// multi-line strings for [`crate::primitives::diff_lines`].
#[must_use]
pub fn change_preview(row: &ResourceRow, action: ResourceAction, arg: &str) -> (String, String) {
    let head = format!("{}/{}", row.kind, row.name);
    let cur_replicas = row
        .replicas
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unset".to_owned());
    match action {
        ResourceAction::Scale => {
            let want = if arg.trim().is_empty() {
                "1".to_owned()
            } else {
                arg.trim().to_owned()
            };
            (
                format!("{head}\nreplicas: {cur_replicas}"),
                format!("{head}\nreplicas: {want}"),
            )
        }
        ResourceAction::Apply => {
            let img = if arg.trim().is_empty() {
                "app:v1"
            } else {
                arg.trim()
            };
            (
                format!("{head}\n(absent or existing)"),
                format!("{head}\nimage: {img}\nreplicas: 1"),
            )
        }
        ResourceAction::Edit => {
            let img = if arg.trim().is_empty() {
                "app:v2"
            } else {
                arg.trim()
            };
            (
                format!("{head}\nimage: (current)"),
                format!("{head}\nimage: {img}"),
            )
        }
        ResourceAction::Rollout => (
            format!("{head}\n(running)"),
            format!("{head}\nrollout: restart (no manifest field change)"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Yew component
// ---------------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use yew_impl::ResourcesConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        act_request_body, change_preview, parse_act_result, parse_predicted, parse_replicas,
        parse_resource_rows, ReplicaRow, ResourceAction, ResourceRow,
    };
    use crate::auth::use_auth;
    use crate::portal::{get_url, http, input_value};
    use crate::primitives::{Badge, DataTable, DiffView, Drawer, Tabs, Tone};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// The Resources section: an inventory grid + live-replica oracle, a
    /// per-resource detail drawer (describe / logs / exec), and a dry-run +
    /// diff-before-apply change flow.
    #[function_component(ResourcesConsole)]
    pub fn resources_console() -> Html {
        let auth = use_auth();
        let kind = use_state(|| "Workload".to_owned());
        let rows = use_state(Vec::<ResourceRow>::new);
        let replicas = use_state(Vec::<ReplicaRow>::new);
        let selected = use_state(|| None::<ResourceRow>);
        let load_msg = use_state(|| None::<(String, bool)>);

        // ---- inventory load ----
        let load = {
            let (auth, kind, rows, load_msg) =
                (auth.clone(), kind.clone(), rows.clone(), load_msg.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url("/portal/resource/get", &token, &[("kind", &kind)]);
                let (rows, load_msg) = (rows.clone(), load_msg.clone());
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) if r.ok() => {
                            rows.set(parse_resource_rows(&r.body));
                            load_msg.set(None);
                        }
                        Ok(r) => load_msg.set(Some((r.body.trim().to_owned(), false))),
                        Err(_) => load_msg.set(Some(("request failed".to_owned(), false))),
                    }
                });
            })
        };

        // ---- live replica oracle (unauthenticated endpoint) ----
        let load_replicas = {
            let replicas = replicas.clone();
            Callback::from(move |_: MouseEvent| {
                let replicas = replicas.clone();
                spawn_local(async move {
                    if let Ok(r) = http("GET", "/portal/resource/replicas", None).await {
                        if r.ok() {
                            replicas.set(parse_replicas(&r.body));
                        }
                    }
                });
            })
        };

        let on_kind = {
            let kind = kind.clone();
            Callback::from(move |e: InputEvent| kind.set(input_value(&e)))
        };

        // Inventory table: kind/name/replicas, each row opens the detail drawer.
        let columns = vec!["name".to_owned(), "replicas".to_owned()];
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    r.replicas.map(|n| n.to_string()).unwrap_or_default(),
                ]
            })
            .collect();
        // Row-open buttons (a plain DataTable is read-only, so render a parallel
        // open control per row).
        let open_list = {
            let selected = selected.clone();
            rows.iter()
                .map(|r| {
                    let selected = selected.clone();
                    let row = r.clone();
                    let onclick =
                        Callback::from(move |_: MouseEvent| selected.set(Some(row.clone())));
                    html! {
                        <button class="ds-tab" {onclick}>{ format!("Inspect {}", r.name) }</button>
                    }
                })
                .collect::<Html>()
        };

        let replica_cols = vec![
            "workload".to_owned(),
            "node".to_owned(),
            "pid".to_owned(),
            "port".to_owned(),
            "digest".to_owned(),
        ];
        let replica_rows: Vec<Vec<String>> = replicas
            .iter()
            .map(|r| {
                vec![
                    r.workload.clone(),
                    r.node.clone(),
                    r.pid.clone(),
                    r.port.clone(),
                    r.digest.clone(),
                ]
            })
            .collect();

        let close = {
            let selected = selected.clone();
            Callback::from(move |()| selected.set(None))
        };

        html! {
            <div class="tile" id="resources-console">
                <h3>{ "Resources" }</h3>
                <p>{ "Workloads and their live replicas over this node's resource \
                      control plane. Every change is previewed (dry-run + diff) before \
                      a signed act is emitted." }</p>

                <div class="res-toolbar">
                    <input class="ds-table__filter" type="text" placeholder="kind"
                           value={(*kind).clone()} oninput={on_kind} />
                    <button class="ds-tab" onclick={load}>{ "List" }</button>
                    <button class="ds-tab" onclick={load_replicas}>{ "Refresh live replicas" }</button>
                </div>
                if let Some((m, _)) = &*load_msg {
                    <p class="obs-msg is-error">{ m }</p>
                }

                <div class="obs-panel">
                    <h4>{ "Inventory" }</h4>
                    <DataTable columns={columns} rows={table_rows} />
                    <div class="res-openrow">{ open_list }</div>
                </div>

                <div class="obs-panel">
                    <h4>{ "Live replicas" }</h4>
                    if replica_rows.is_empty() {
                        <p class="ds-empty">{ "No live replicas reported (no reconciler wired, \
                          or nothing running). Click \"Refresh live replicas\"." }</p>
                    } else {
                        <DataTable columns={replica_cols} rows={replica_rows} />
                    }
                </div>

                <Drawer open={selected.is_some()}
                        title={selected.as_ref().map(|r| format!("{}/{}", r.kind, r.name)).unwrap_or_default()}
                        onclose={close}>
                    if let Some(row) = &*selected {
                        <ResourceDetail row={row.clone()} />
                    }
                </Drawer>
            </div>
        }
    }

    /// The per-resource detail drawer: Describe / Logs / Exec tabs plus the
    /// dry-run + diff-before-apply change flow.
    #[derive(Properties, PartialEq)]
    pub struct ResourceDetailProps {
        /// The selected inventory row.
        pub row: ResourceRow,
    }

    #[function_component(ResourceDetail)]
    fn resource_detail(props: &ResourceDetailProps) -> Html {
        let auth = use_auth();
        let row = props.row.clone();
        let tab = use_state(|| 0usize);
        let output = use_state(String::new);
        let cmd = use_state(|| "sh".to_owned());

        // A read tab (describe/logs/exec) fetches its endpoint into `output`.
        let fetch = {
            let (auth, row, output, cmd) = (auth.clone(), row.clone(), output.clone(), cmd.clone());
            Callback::from(move |which: &'static str| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = match which {
                    "describe" => get_url(
                        "/portal/resource/describe",
                        &token,
                        &[("kind", &row.kind), ("name", &row.name)],
                    ),
                    "logs" => get_url("/portal/resource/logs", &token, &[("name", &row.name)]),
                    _ => get_url(
                        "/portal/resource/exec",
                        &token,
                        &[("name", &row.name), ("cmd", &cmd)],
                    ),
                };
                let output = output.clone();
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) => output.set(r.body),
                        Err(_) => output.set("request failed".to_owned()),
                    }
                });
            })
        };

        let tabs = vec![
            "Describe".to_owned(),
            "Logs".to_owned(),
            "Exec".to_owned(),
            "Change".to_owned(),
        ];
        let onselect = {
            let (tab, output, fetch) = (tab.clone(), output.clone(), fetch.clone());
            Callback::from(move |i: usize| {
                output.set(String::new());
                tab.set(i);
                match i {
                    0 => fetch.emit("describe"),
                    1 => fetch.emit("logs"),
                    _ => {}
                }
            })
        };

        let on_cmd = {
            let cmd = cmd.clone();
            Callback::from(move |e: InputEvent| cmd.set(input_value(&e)))
        };

        let body = match *tab {
            0 | 1 => html! { <CodeOut text={(*output).clone()} /> },
            2 => {
                let run = {
                    let fetch = fetch.clone();
                    Callback::from(move |_: MouseEvent| fetch.emit("exec"))
                };
                html! {
                    <>
                        <div class="res-toolbar">
                            <input class="ds-table__filter" type="text" placeholder="command"
                                   value={(*cmd).clone()} oninput={on_cmd} />
                            <button class="ds-tab" onclick={run}>{ "Exec" }</button>
                        </div>
                        <CodeOut text={(*output).clone()} />
                    </>
                }
            }
            _ => html! { <ChangeFlow row={row.clone()} /> },
        };

        html! {
            <>
                <Tabs tabs={tabs} selected={*tab} onselect={onselect} />
                { body }
            </>
        }
    }

    #[derive(Properties, PartialEq)]
    struct CodeOutProps {
        text: String,
    }

    #[function_component(CodeOut)]
    fn code_out(props: &CodeOutProps) -> Html {
        if props.text.is_empty() {
            return html! { <p class="ds-empty">{ "No output yet." }</p> };
        }
        html! { <crate::primitives::CodeBlock text={props.text.clone()} /> }
    }

    /// The dry-run + diff-before-apply change flow for one resource.
    #[derive(Properties, PartialEq)]
    struct ChangeFlowProps {
        row: ResourceRow,
    }

    #[function_component(ChangeFlow)]
    fn change_flow(props: &ChangeFlowProps) -> Html {
        let auth = use_auth();
        let row = props.row.clone();
        let action = use_state(|| ResourceAction::Scale);
        let arg = use_state(String::new);
        let predicted = use_state(|| None::<bool>);
        let result = use_state(|| None::<Result<String, String>>);

        let on_arg = {
            let arg = arg.clone();
            Callback::from(move |e: InputEvent| arg.set(input_value(&e)))
        };
        let on_action = {
            let action = action.clone();
            Callback::from(move |e: Event| {
                use wasm_bindgen::JsCast;
                if let Some(t) = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                {
                    let a = match t.value().as_str() {
                        "Apply" => ResourceAction::Apply,
                        "Edit image" => ResourceAction::Edit,
                        "Roll out" => ResourceAction::Rollout,
                        _ => ResourceAction::Scale,
                    };
                    action.set(a);
                }
            })
        };

        // Preview: fetch the authorization dry-run (PREDICTED ALLOW/DENY).
        let preview = {
            let (auth, predicted, result) = (auth.clone(), predicted.clone(), result.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url("/portal/resource/dry-run", &token, &[]);
                let (predicted, result) = (predicted.clone(), result.clone());
                result.set(None);
                spawn_local(async move {
                    if let Ok(r) = http("GET", &url, None).await {
                        predicted.set(parse_predicted(&r.body));
                    }
                });
            })
        };

        // Confirm: POST the signed act, interpret EVENT/DENIED.
        let confirm = {
            let (auth, row, action, arg, result) = (
                auth.clone(),
                row.clone(),
                action.clone(),
                arg.clone(),
                result.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = act_request_body(&token, &row.name, &arg);
                let (path, result) = ((*action).path(), result.clone());
                spawn_local(async move {
                    match http("POST", path, Some(&body)).await {
                        Ok(r) => result.set(Some(parse_act_result(&r.body))),
                        Err(_) => result.set(Some(Err("request failed".to_owned()))),
                    }
                });
            })
        };

        let (cur, prop) = change_preview(&row, *action, &arg);
        let show_arg = (*action).arg_hint();

        html! {
            <div class="res-change">
                <div class="res-toolbar">
                    <select onchange={on_action}>
                        { for ResourceAction::all().into_iter().map(|a| html! {
                            <option selected={a == *action}>{ a.label() }</option>
                        }) }
                    </select>
                    if let Some(hint) = show_arg {
                        <input class="ds-table__filter" type="text" placeholder={hint}
                               value={(*arg).clone()} oninput={on_arg} />
                    }
                    <button class="ds-tab" onclick={preview}>{ "Preview change" }</button>
                </div>

                <h4>{ "Diff (current \u{2192} proposed)" }</h4>
                <DiffView old={cur} new={prop} />

                <div class="res-verdict">
                    { match *predicted {
                        Some(true) => html! { <Badge label="dry-run: ALLOW" tone={Tone::Success} /> },
                        Some(false) => html! { <Badge label="dry-run: DENY" tone={Tone::Danger} /> },
                        None => html! { <span class="ds-empty">{ "Preview to see the authorization decision." }</span> },
                    } }
                    if matches!(*predicted, Some(true)) {
                        <button class="ds-tab" onclick={confirm}>{ "Confirm & apply" }</button>
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_rows_parse_kind_name_and_replicas() {
        let body = "Workload/web replicas=3\nWorkload/db\nEVENTS 7\n";
        let rows = parse_resource_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            ResourceRow {
                kind: "Workload".into(),
                name: "web".into(),
                replicas: Some(3),
            }
        );
        assert_eq!(rows[1].replicas, None);
        // the EVENTS bookkeeping line is never a resource row.
        assert!(rows.iter().all(|r| r.kind != "EVENTS"));
    }

    #[test]
    fn resource_rows_skip_malformed_and_never_fabricate() {
        let rows = parse_resource_rows("garbage\n/noname\nKind/\n\n");
        assert!(rows.is_empty());
    }

    #[test]
    fn replicas_parse_the_oracle_line_and_skip_the_count() {
        let body = "REPLICA web n1 pid=42 port=8080 digest=abc123\nREPLICAS 1\n";
        let reps = parse_replicas(body);
        assert_eq!(reps.len(), 1);
        assert_eq!(
            reps[0],
            ReplicaRow {
                workload: "web".into(),
                node: "n1".into(),
                pid: "42".into(),
                port: "8080".into(),
                digest: "abc123".into(),
            }
        );
    }

    #[test]
    fn replicas_skip_short_or_malformed_lines() {
        assert!(parse_replicas("REPLICA web n1 pid=42\nREPLICAS 0\n").is_empty());
        assert!(parse_replicas("noise\n").is_empty());
    }

    #[test]
    fn predicted_maps_allow_deny_only() {
        assert_eq!(parse_predicted("PREDICTED ALLOW"), Some(true));
        assert_eq!(parse_predicted("PREDICTED DENY\n"), Some(false));
        assert_eq!(parse_predicted("PREDICTED MAYBE"), None);
        assert_eq!(parse_predicted("garbage"), None);
    }

    #[test]
    fn act_result_reads_event_cid_or_denied_reason() {
        assert_eq!(
            parse_act_result("EVENT bafy123\nEVENTS 4"),
            Ok("bafy123".into())
        );
        assert_eq!(
            parse_act_result("DENIED unauthorized"),
            Err("unauthorized".into())
        );
        // an unexpected body is surfaced as an error, never silently ok.
        assert!(parse_act_result("weird").is_err());
    }

    #[test]
    fn act_body_is_token_name_arg_in_order() {
        assert_eq!(act_request_body("tk", "web", "app:v2"), "tk\nweb\napp:v2");
    }

    #[test]
    fn change_preview_reflects_current_and_proposed_field() {
        let row = ResourceRow {
            kind: "Workload".into(),
            name: "web".into(),
            replicas: Some(2),
        };
        let (cur, prop) = change_preview(&row, ResourceAction::Scale, "5");
        assert!(cur.contains("replicas: 2"));
        assert!(prop.contains("replicas: 5"));
        // an empty scale arg defaults to 1 (the backend's default), not a fake.
        let (_, prop1) = change_preview(&row, ResourceAction::Scale, "");
        assert!(prop1.contains("replicas: 1"));
        // edit shows the proposed image.
        let (_, prope) = change_preview(&row, ResourceAction::Edit, "app:v9");
        assert!(prope.contains("image: app:v9"));
    }
}
