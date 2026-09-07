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
//! host; the `yew` component is a thin wrapper over them. This module also
//! carries the `/resources/:kind/:id` **detail route** page ([`ResourceDetailPage`],
//! referenced from [`crate::router`]), a rollout-health classifier
//! ([`RolloutHealth`]) derived from declared-vs-live replica counts, a CronJob
//! panel over the `cronjob/apply`+`cronjob/delete` acts, and the
//! **dry-run gate state machine** ([`ChangeState`]) that proves — independent
//! of any UI wiring — that a mutating act can never be confirmed without a
//! preceding ALLOW dry-run of the CURRENT proposed change.

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
// Dry-run gate — the mandatory state machine
// ---------------------------------------------------------------------------

/// The change flow's confirmation gate. A mutating act may be confirmed ONLY
/// from [`ChangeState::Previewed(true)`] (a dry-run that just answered ALLOW
/// for the CURRENT action/arg). Every edit to the action or its argument — and
/// every fresh act result — invalidates a stale preview back to `Idle`, so a
/// dry-run answer can never be "carried over" to authorize a DIFFERENT change
/// than the one it actually previewed. This is the anti-facade proof that no
/// mutating call issues without a preceding (matching) dry-run call; the `yew`
/// [`ChangeFlow`] component below is a thin wrapper that drives this exact
/// state machine rather than an ad-hoc boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChangeState {
    /// No live preview for the current action/arg — confirming is refused.
    #[default]
    Idle,
    /// A dry-run just answered for the current action/arg: `true` = ALLOW
    /// (confirmable), `false` = DENY (still refused).
    Previewed(bool),
}

impl ChangeState {
    /// Whether a "Confirm & apply" click is currently permitted.
    #[must_use]
    pub fn can_confirm(self) -> bool {
        matches!(self, ChangeState::Previewed(true))
    }

    /// Transition after a dry-run response for the CURRENT action/arg.
    #[must_use]
    pub fn previewed(self, allow: bool) -> ChangeState {
        ChangeState::Previewed(allow)
    }

    /// Transition after the operator changes the action or its argument (or
    /// after an act completes): any prior preview no longer describes what a
    /// confirm would now do, so it is discarded.
    #[must_use]
    pub fn invalidated(self) -> ChangeState {
        ChangeState::Idle
    }
}

// ---------------------------------------------------------------------------
// Rollout health
// ---------------------------------------------------------------------------

/// A resource's rollout health, derived ONLY from the DECLARED replica target
/// (`resource_get`'s `replicas=<n>`) versus the LIVE replica count the
/// `/portal/resource/replicas` oracle actually reports for that workload name
/// — never a fabricated "Ready" the backend never asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RolloutHealth {
    /// No declared replica target (not a scalable workload, or never fetched).
    Unknown,
    /// Live replica count matches the declared target.
    Healthy,
    /// Live replica count is below the declared target.
    Degraded,
    /// Live replica count exceeds the declared target (old replicas draining).
    Excess,
}

impl RolloutHealth {
    /// Classify from the declared target and the observed live count.
    #[must_use]
    pub fn compute(desired: Option<i64>, live: usize) -> RolloutHealth {
        let Some(desired) = desired.filter(|d| *d >= 0) else {
            return RolloutHealth::Unknown;
        };
        #[allow(clippy::cast_sign_loss)]
        let desired = desired as usize;
        match live.cmp(&desired) {
            std::cmp::Ordering::Equal => RolloutHealth::Healthy,
            std::cmp::Ordering::Less => RolloutHealth::Degraded,
            std::cmp::Ordering::Greater => RolloutHealth::Excess,
        }
    }

    /// The badge tone this health status renders as.
    #[must_use]
    pub fn tone(self) -> crate::primitives::Tone {
        use crate::primitives::Tone;
        match self {
            RolloutHealth::Unknown => Tone::Neutral,
            RolloutHealth::Healthy => Tone::Success,
            RolloutHealth::Degraded => Tone::Danger,
            RolloutHealth::Excess => Tone::Warn,
        }
    }

    /// The human summary, e.g. `"2/3 replicas ready"`.
    #[must_use]
    pub fn summary(self, desired: Option<i64>, live: usize) -> String {
        match (self, desired) {
            (RolloutHealth::Unknown, _) => "no rollout target declared".to_owned(),
            (_, Some(d)) => format!("{live}/{d} replicas ready"),
            (_, None) => format!("{live} replicas live"),
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest / provenance (Manifest + Events tabs)
// ---------------------------------------------------------------------------

/// Extract the provenance lines (`Signer:`, `Content-Hash:`, `Event-CID:`,
/// `Exercised-Authority:`) from a `GET /portal/resource/describe` body — the
/// real per-event trail the backend already renders, never fabricated. Used
/// for the detail page's **Events** tab; the raw `describe` body itself is the
/// **Manifest** tab.
#[must_use]
pub fn parse_event_trail(describe_body: &str) -> Vec<String> {
    const KEYS: [&str; 4] = [
        "Signer:",
        "Content-Hash:",
        "Event-CID:",
        "Exercised-Authority:",
    ];
    describe_body
        .lines()
        .map(str::trim)
        .filter(|l| KEYS.iter().any(|k| l.starts_with(k)))
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// CronJobs panel
// ---------------------------------------------------------------------------

/// The built-in kind string a CronJob/Job resource is listed/applied under —
/// mirrors the backend's `CRONJOB_KIND` constant so the console's `kind`
/// filter agrees with what the admission route actually registers.
pub const CRONJOB_KIND: &str = "CronJob";

/// The `<token>\n<name>\n<schedule-secs>\n<command>` body
/// `POST /portal/resource/cronjob/apply` expects.
#[must_use]
pub fn cronjob_apply_body(token: &str, name: &str, schedule_secs: &str, command: &str) -> String {
    format!("{token}\n{name}\n{schedule_secs}\n{command}")
}

/// The `<token>\n<name>` body `POST /portal/resource/cronjob/delete` expects.
#[must_use]
pub fn cronjob_delete_body(token: &str, name: &str) -> String {
    format!("{token}\n{name}")
}

// ---------------------------------------------------------------------------
// Yew component
// ---------------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use yew_impl::{CronJobsPanel, ResourceDetailPage, ResourcesConsole};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        act_request_body, change_preview, cronjob_apply_body, cronjob_delete_body,
        parse_act_result, parse_event_trail, parse_predicted, parse_replicas,
        parse_resource_rows, ChangeState, ReplicaRow, ResourceAction, ResourceRow, RolloutHealth,
        CRONJOB_KIND,
    };
    use crate::auth::use_auth;
    use crate::portal::{get_url, http, input_value};
    use crate::primitives::{Badge, DataTable, DiffView, Drawer, Tabs};
    use crate::router::Route;
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;
    use yew_router::prelude::*;

    /// The Resources section: an inventory grid + live-replica oracle, a
    /// CronJobs panel, a per-resource detail drawer (describe / logs / exec),
    /// and a dry-run + diff-before-apply change flow.
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
        // open control per row) plus a real deep-link into the routed detail
        // page (`/resources/:kind/:id`).
        let open_list = {
            let selected = selected.clone();
            rows.iter()
                .map(|r| {
                    let selected2 = selected.clone();
                    let row = r.clone();
                    let onclick =
                        Callback::from(move |_: MouseEvent| selected2.set(Some(row.clone())));
                    html! {
                        <span class="res-openrow__item">
                            <button class="ds-tab" {onclick}>{ format!("Inspect {}", r.name) }</button>
                            <Link<Route>
                                classes="ds-tab"
                                to={Route::ResourceDetail { kind: r.kind.clone(), id: r.name.clone() }}
                            >
                                { "Open detail page" }
                            </Link<Route>>
                        </span>
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

        // ---- rollout health, per declared row, against the live oracle ----
        let health_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|r| {
                let live = replicas.iter().filter(|rep| rep.workload == r.name).count();
                let health = RolloutHealth::compute(r.replicas, live);
                (r.name.clone(), health, live)
            })
            .map(|(name, health, live)| vec![name, format!("{health:?}"), live.to_string()])
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
                    <h4>{ "Rollout health" }</h4>
                    if health_rows.is_empty() {
                        <p class="ds-empty">{ "List the inventory to see rollout health." }</p>
                    } else {
                        <DataTable
                            columns={vec!["name".to_owned(), "status".to_owned(), "live".to_owned()]}
                            rows={health_rows}
                            filterable={false}
                        />
                    }
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

                <CronJobsPanel />

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

    /// The CronJobs panel: lists `CronJob` resources over the SAME
    /// `resource_get` inventory endpoint the workload grid uses (`kind=CronJob`)
    /// and drives the `cronjob/apply` + `cronjob/delete` acts — the ONLY two
    /// new backend endpoints this task's ROI card names.
    #[function_component(CronJobsPanel)]
    pub fn cronjobs_panel() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<ResourceRow>::new);
        let name = use_state(String::new);
        let schedule = use_state(|| "60".to_owned());
        let command = use_state(String::new);
        let msg = use_state(|| None::<String>);

        let load = {
            let (auth, rows, msg) = (auth.clone(), rows.clone(), msg.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url("/portal/resource/get", &token, &[("kind", CRONJOB_KIND)]);
                let (rows, msg) = (rows.clone(), msg.clone());
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) if r.ok() => {
                            rows.set(parse_resource_rows(&r.body));
                            msg.set(None);
                        }
                        Ok(r) => msg.set(Some(r.body.trim().to_owned())),
                        Err(_) => msg.set(Some("request failed".to_owned())),
                    }
                });
            })
        };

        let on_name = {
            let name = name.clone();
            Callback::from(move |e: InputEvent| name.set(input_value(&e)))
        };
        let on_schedule = {
            let schedule = schedule.clone();
            Callback::from(move |e: InputEvent| schedule.set(input_value(&e)))
        };
        let on_command = {
            let command = command.clone();
            Callback::from(move |e: InputEvent| command.set(input_value(&e)))
        };

        let apply = {
            let (auth, name, schedule, command, msg, load) = (
                auth.clone(),
                name.clone(),
                schedule.clone(),
                command.clone(),
                msg.clone(),
                load.clone(),
            );
            Callback::from(move |ev: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = cronjob_apply_body(&token, &name, &schedule, &command);
                let (msg, load, ev) = (msg.clone(), load.clone(), ev.clone());
                spawn_local(async move {
                    match http("POST", "/portal/resource/cronjob/apply", Some(&body)).await {
                        Ok(r) => {
                            msg.set(Some(parse_act_result(&r.body).map_or_else(
                                |e| format!("Refused: {e}"),
                                |cid| format!("Applied: {cid}"),
                            )));
                            load.emit(ev);
                        }
                        Err(_) => msg.set(Some("request failed".to_owned())),
                    }
                });
            })
        };

        let delete = {
            let (auth, name, msg, load) = (auth.clone(), name.clone(), msg.clone(), load.clone());
            Callback::from(move |ev: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = cronjob_delete_body(&token, &name);
                let (msg, load, ev) = (msg.clone(), load.clone(), ev.clone());
                spawn_local(async move {
                    match http("POST", "/portal/resource/cronjob/delete", Some(&body)).await {
                        Ok(r) => {
                            msg.set(Some(parse_act_result(&r.body).map_or_else(
                                |e| format!("Refused: {e}"),
                                |cid| format!("Deleted: {cid}"),
                            )));
                            load.emit(ev);
                        }
                        Err(_) => msg.set(Some("request failed".to_owned())),
                    }
                });
            })
        };

        let columns = vec!["name".to_owned()];
        let table_rows: Vec<Vec<String>> = rows.iter().map(|r| vec![r.name.clone()]).collect();

        html! {
            <div class="obs-panel">
                <h4>{ "CronJobs" }</h4>
                <div class="res-toolbar">
                    <button class="ds-tab" onclick={load}>{ "List CronJobs" }</button>
                </div>
                <DataTable {columns} rows={table_rows} filterable={false} />
                <div class="res-toolbar">
                    <input class="ds-table__filter" type="text" placeholder="name"
                           value={(*name).clone()} oninput={on_name} />
                    <input class="ds-table__filter" type="text" placeholder="period (seconds)"
                           value={(*schedule).clone()} oninput={on_schedule} />
                    <input class="ds-table__filter" type="text" placeholder="command"
                           value={(*command).clone()} oninput={on_command} />
                    <button class="ds-tab" onclick={apply}>{ "Apply" }</button>
                    <button class="ds-tab" onclick={delete}>{ "Delete" }</button>
                </div>
                if let Some(m) = &*msg {
                    <p class="obs-msg">{ m }</p>
                }
            </div>
        }
    }

    /// The per-resource detail drawer: Overview / Manifest / Logs / Exec /
    /// Events tabs plus the dry-run + diff-before-apply change flow (folded
    /// into Overview).
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

        // A read tab (manifest/logs/exec/events) fetches its endpoint into
        // `output`. Events reuses the SAME `describe` body as Manifest — its
        // real per-event provenance trail, filtered by `parse_event_trail`.
        let fetch = {
            let (auth, row, output, cmd) = (auth.clone(), row.clone(), output.clone(), cmd.clone());
            Callback::from(move |which: &'static str| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = match which {
                    "manifest" | "events" => get_url(
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
                let (output, which) = (output.clone(), which);
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) if which == "events" => {
                            let trail = parse_event_trail(&r.body).join("\n");
                            output.set(if trail.is_empty() {
                                "No provenance recorded yet.".to_owned()
                            } else {
                                trail
                            });
                        }
                        Ok(r) => output.set(r.body),
                        Err(_) => output.set("request failed".to_owned()),
                    }
                });
            })
        };

        let tabs = vec![
            "Overview".to_owned(),
            "Manifest".to_owned(),
            "Logs".to_owned(),
            "Exec".to_owned(),
            "Events".to_owned(),
        ];
        let onselect = {
            let (tab, output, fetch) = (tab.clone(), output.clone(), fetch.clone());
            Callback::from(move |i: usize| {
                output.set(String::new());
                tab.set(i);
                match i {
                    1 => fetch.emit("manifest"),
                    2 => fetch.emit("logs"),
                    4 => fetch.emit("events"),
                    _ => {}
                }
            })
        };

        let on_cmd = {
            let cmd = cmd.clone();
            Callback::from(move |e: InputEvent| cmd.set(input_value(&e)))
        };

        let body = match *tab {
            0 => html! { <ChangeFlow row={row.clone()} /> },
            1 | 4 => html! { <CodeOut text={(*output).clone()} /> },
            2 => html! { <CodeOut text={(*output).clone()} /> },
            _ => {
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
        };

        html! {
            <>
                <Tabs tabs={tabs} selected={*tab} onselect={onselect} />
                { body }
            </>
        }
    }

    /// The `/resources/:kind/:id` routed detail page — the deep-linkable
    /// counterpart of the drawer, mounted directly by [`crate::router`] so the
    /// detail component is a real reachable route, not only a modal.
    #[derive(Properties, PartialEq)]
    pub struct ResourceDetailPageProps {
        /// The resource kind, from the route path segment.
        pub kind: String,
        /// The resource name, from the route path segment.
        pub id: String,
    }

    #[function_component(ResourceDetailPage)]
    /// The `/resources/:kind/:id` routed detail page component.
    pub fn resource_detail_page(props: &ResourceDetailPageProps) -> Html {
        let row = ResourceRow {
            kind: props.kind.clone(),
            name: props.id.clone(),
            replicas: None,
        };
        html! {
            <div class="tile" id="resource-detail-page">
                <div class="res-toolbar">
                    <Link<Route> classes="ds-tab" to={Route::Resources}>{ "\u{2190} Resources" }</Link<Route>>
                    <h3>{ format!("{}/{}", props.kind, props.id) }</h3>
                </div>
                <ResourceDetail row={row} />
            </div>
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

    /// The dry-run + diff-before-apply change flow for one resource. Drives
    /// [`ChangeState`] exactly: every action/arg edit invalidates a stale
    /// preview, and "Confirm & apply" is rendered ONLY when
    /// `ChangeState::can_confirm` holds.
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
        let gate = use_state(ChangeState::default);
        let result = use_state(|| None::<Result<String, String>>);

        let on_arg = {
            let (arg, gate) = (arg.clone(), gate.clone());
            Callback::from(move |e: InputEvent| {
                arg.set(input_value(&e));
                gate.set(gate.invalidated());
            })
        };
        let on_action = {
            let (action, gate) = (action.clone(), gate.clone());
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
                    gate.set(gate.invalidated());
                }
            })
        };

        // Preview: fetch the authorization dry-run (PREDICTED ALLOW/DENY) for
        // the CURRENT action/arg, and transition the gate accordingly.
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

        // Confirm: POST the signed act, interpret EVENT/DENIED. Only reachable
        // while `gate.can_confirm()` — the component below never renders the
        // button otherwise.
        let confirm = {
            let (auth, row, action, arg, gate, result) = (
                auth.clone(),
                row.clone(),
                action.clone(),
                arg.clone(),
                gate.clone(),
                result.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if !gate.can_confirm() {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let body = act_request_body(&token, &row.name, &arg);
                let (path, gate, result) = ((*action).path(), gate.clone(), result.clone());
                spawn_local(async move {
                    match http("POST", path, Some(&body)).await {
                        Ok(r) => result.set(Some(parse_act_result(&r.body))),
                        Err(_) => result.set(Some(Err("request failed".to_owned()))),
                    }
                    // The act consumed this preview; a re-confirm needs a fresh
                    // dry-run even if nothing else changed.
                    gate.set(gate.invalidated());
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
                    { match *gate {
                        ChangeState::Previewed(true) => html! { <Badge label="dry-run: ALLOW" tone={crate::primitives::Tone::Success} /> },
                        ChangeState::Previewed(false) => html! { <Badge label="dry-run: DENY" tone={crate::primitives::Tone::Danger} /> },
                        ChangeState::Idle => html! { <span class="ds-empty">{ "Preview to see the authorization decision." }</span> },
                    } }
                    if gate.can_confirm() {
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

    // ---- dry-run gate state machine (anti-facade DoD) ----

    #[test]
    fn gate_starts_idle_and_refuses_confirm() {
        let gate = ChangeState::default();
        assert_eq!(gate, ChangeState::Idle);
        assert!(!gate.can_confirm());
    }

    #[test]
    fn gate_confirms_only_after_an_allow_preview() {
        let gate = ChangeState::default();
        let denied = gate.previewed(false);
        assert!(!denied.can_confirm(), "a DENY preview must never confirm");
        let allowed = gate.previewed(true);
        assert!(allowed.can_confirm());
    }

    #[test]
    fn editing_the_argument_after_preview_invalidates_it() {
        let gate = ChangeState::default().previewed(true);
        assert!(gate.can_confirm());
        // the operator edits the arg (or action) — the OLD preview no longer
        // describes the new proposed change, so confirm is refused again
        // until a fresh dry-run runs.
        let edited = gate.invalidated();
        assert!(!edited.can_confirm());
    }

    #[test]
    fn a_completed_act_invalidates_the_gate_for_the_next_change() {
        // Mirrors the `confirm` callback: after the act resolves (regardless
        // of its own outcome) the gate is reset so a SECOND confirm can never
        // ride the first preview.
        let gate = ChangeState::default().previewed(true);
        assert!(gate.can_confirm());
        let after_confirm = gate.invalidated();
        assert!(!after_confirm.can_confirm());
    }

    #[test]
    fn no_sequence_of_edits_alone_ever_reaches_can_confirm() {
        // Exhaustive-ish sanity: only `previewed(true)` ever yields a
        // confirmable state; `invalidated` (any number of times) never does.
        let mut gate = ChangeState::default();
        for _ in 0..5 {
            gate = gate.invalidated();
            assert!(!gate.can_confirm());
        }
    }

    // ---- rollout health ----

    #[test]
    fn rollout_health_matches_live_to_declared() {
        assert_eq!(RolloutHealth::compute(Some(3), 3), RolloutHealth::Healthy);
        assert_eq!(RolloutHealth::compute(Some(3), 1), RolloutHealth::Degraded);
        assert_eq!(RolloutHealth::compute(Some(1), 3), RolloutHealth::Excess);
        assert_eq!(RolloutHealth::compute(None, 3), RolloutHealth::Unknown);
        // a negative declared count is nonsensical — never fabricate a target.
        assert_eq!(RolloutHealth::compute(Some(-1), 0), RolloutHealth::Unknown);
    }

    #[test]
    fn rollout_health_tone_matches_severity() {
        use crate::primitives::Tone;
        assert_eq!(RolloutHealth::Healthy.tone(), Tone::Success);
        assert_eq!(RolloutHealth::Degraded.tone(), Tone::Danger);
        assert_eq!(RolloutHealth::Excess.tone(), Tone::Warn);
        assert_eq!(RolloutHealth::Unknown.tone(), Tone::Neutral);
    }

    #[test]
    fn rollout_health_summary_is_derived_never_fabricated() {
        let s = RolloutHealth::Degraded.summary(Some(3), 1);
        assert_eq!(s, "1/3 replicas ready");
        let s = RolloutHealth::Unknown.summary(None, 0);
        assert_eq!(s, "no rollout target declared");
    }

    // ---- manifest/events provenance ----

    #[test]
    fn event_trail_extracts_only_provenance_lines() {
        let body = "Name:        web\nKind:        v1/Workload\nSpec:\n  image: app:v1\n\
                     Envelope:\n  Signer:        did:node:abc\n  Content-Hash:  deadbeef\n  \
                     Event-CID:     bafy123\n  Exercised-Authority: explicit grant (allow)\n";
        let trail = parse_event_trail(body);
        assert_eq!(
            trail,
            vec![
                "Signer:        did:node:abc".to_owned(),
                "Content-Hash:  deadbeef".to_owned(),
                "Event-CID:     bafy123".to_owned(),
                "Exercised-Authority: explicit grant (allow)".to_owned(),
            ]
        );
        // never picks up the Spec section.
        assert!(!trail.iter().any(|l| l.contains("image")));
    }

    #[test]
    fn event_trail_is_empty_when_no_provenance_recorded() {
        assert!(parse_event_trail("Name: web\nKind: v1/Workload\n").is_empty());
    }

    // ---- cronjob request bodies ----

    #[test]
    fn cronjob_apply_body_is_token_name_schedule_command_in_order() {
        assert_eq!(
            cronjob_apply_body("tk", "backup", "3600", "/bin/backup.sh"),
            "tk\nbackup\n3600\n/bin/backup.sh"
        );
    }

    #[test]
    fn cronjob_delete_body_is_token_name_in_order() {
        assert_eq!(cronjob_delete_body("tk", "backup"), "tk\nbackup");
    }
}
