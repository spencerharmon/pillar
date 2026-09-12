//! The **IAM console sections** (ROI Priority 0 IAM epic): Profile, Users,
//! Roles & Groups, and OAuth Clients — the Yew surfaces over the
//! `user-record-and-profile`, `roles-groups-rbac-bridge`, and
//! `oauth-client-registry` crates' state machines.
//!
//! As with every other console section, the wire parsers/builders are pure,
//! host-testable functions pinned to the endpoint shapes those crates'
//! `authorize_*`/`apply_op` gates imply (`/portal/profile`, `/portal/users`,
//! `/portal/roles`, `/portal/groups`, `/portal/oauth/clients` — the endpoint
//! task these console sections are built against); the `yew` component is a
//! thin wrapper over them (same "host-testable logic, thin Yew wrapper" split
//! as `crate::auth`/`crate::router`/`crate::resources_console`).
//!
//! Every **sensitive** mutation here (disable a user, force a password
//! change, revoke an OAuth consent) follows the SAME **predicted-effect-via-
//! decider** pattern `crate::resources_console` establishes for resource
//! mutations: a `GET .../dry-run` round trip returns `PREDICTED ALLOW` or
//! `PREDICTED DENY` (parsed by the shared [`crate::resources_console::
//! parse_predicted`]), and the action button is only enabled when the
//! decider's prediction is `ALLOW` — so the operator never fires a mutating
//! act the shared `pillar_rbac::RbacDecider` (the SAME decider
//! `roles-groups-rbac-bridge`'s `authorize_effective_capability` folds into)
//! will refuse; predicted == enforced by construction, never a UI-only guess.

use crate::resources_console::parse_predicted;

// ===========================================================================
// Pure wire helpers (host-tested; no web-sys / DOM).
// ===========================================================================

/// `GET /portal/profile`: `PROFILE handle=<h> display_name=<n> email=<e>
/// status=<Invited|Active|Disabled> force_password_change=<bool>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileView {
    /// The handle this profile belongs to.
    pub handle: String,
    /// The self-service-editable display name.
    pub display_name: String,
    /// The self-service-editable email.
    pub email: String,
    /// The lifecycle status (`Invited`/`Active`/`Disabled`).
    pub status: String,
    /// Whether a password change is currently forced before anything else.
    pub force_password_change: bool,
}

/// Parse one `PROFILE ...` line into a [`ProfileView`]. An unparseable/empty
/// body yields the default (empty) view — never a fabricated identity.
#[must_use]
pub fn parse_profile(body: &str) -> ProfileView {
    let mut view = ProfileView::default();
    let Some(rest) = body.lines().next().and_then(|l| l.strip_prefix("PROFILE ")) else {
        return view;
    };
    for field in rest.split_whitespace() {
        if let Some(v) = field.strip_prefix("handle=") {
            view.handle = v.to_owned();
        } else if let Some(v) = field.strip_prefix("display_name=") {
            view.display_name = v.to_owned();
        } else if let Some(v) = field.strip_prefix("email=") {
            view.email = v.to_owned();
        } else if let Some(v) = field.strip_prefix("status=") {
            view.status = v.to_owned();
        } else if let Some(v) = field.strip_prefix("force_password_change=") {
            view.force_password_change = v == "true";
        }
    }
    view
}

/// `PUT /portal/profile` body: `<token>\n<display_name>\n<email>` — the
/// self-service edit (mirrors the crate's `update_profile`, which touches
/// only these two fields).
#[must_use]
pub fn profile_update_wire(token: &str, display_name: &str, email: &str) -> String {
    crate::portal::body_lines(&[token, display_name, email])
}

/// One row of `GET /portal/users`: `<handle> status=<s>
/// force_password_change=<bool> roles=<r1,r2,...>` (an empty `roles=` means
/// no direct roles, matching a freshly-invited record).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserRow {
    /// The user's handle.
    pub handle: String,
    /// The lifecycle status (`Invited`/`Active`/`Disabled`).
    pub status: String,
    /// Whether the user must change their password before anything else.
    pub force_password_change: bool,
    /// The user's direct role names (group-attached roles are not listed
    /// here — see `RolesGroups`).
    pub roles: Vec<String>,
}

/// Parse `GET /portal/users`'s body into [`UserRow`]s. A line that does not
/// start with a bare handle token is skipped rather than fabricated.
#[must_use]
pub fn parse_user_rows(body: &str) -> Vec<UserRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(handle) = parts.next() else {
            continue;
        };
        let mut row = UserRow {
            handle: handle.to_owned(),
            ..Default::default()
        };
        for field in parts {
            if let Some(v) = field.strip_prefix("status=") {
                row.status = v.to_owned();
            } else if let Some(v) = field.strip_prefix("force_password_change=") {
                row.force_password_change = v == "true";
            } else if let Some(v) = field.strip_prefix("roles=") {
                row.roles = v
                    .split(',')
                    .filter(|r| !r.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
        out.push(row);
    }
    out
}

/// `POST /portal/users/invite` body: `<token>\n<handle>\n<email>`.
#[must_use]
pub fn invite_user_wire(token: &str, handle: &str, email: &str) -> String {
    crate::portal::body_lines(&[token, handle, email])
}

/// `POST /portal/users/{disable,enable,reset-password,
/// require-password-change}` body: `<token>\n<handle>` — every one of these
/// single-target admin acts shares the same two-field framing.
#[must_use]
pub fn user_target_wire(token: &str, handle: &str) -> String {
    crate::portal::body_lines(&[token, handle])
}

/// One row of `GET /portal/roles`: `<name> capabilities=<c1,c2,...>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleRow {
    /// The role's name.
    pub name: String,
    /// The `pillar_rbac::Capability` strings this role grants.
    pub capabilities: Vec<String>,
}

/// Parse `GET /portal/roles`'s body into [`RoleRow`]s.
#[must_use]
pub fn parse_role_rows(body: &str) -> Vec<RoleRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, rest)) = line.split_once(' ') else {
            out.push(RoleRow {
                name: line.to_owned(),
                capabilities: Vec::new(),
            });
            continue;
        };
        let capabilities = rest
            .strip_prefix("capabilities=")
            .map(|c| {
                c.split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.push(RoleRow {
            name: name.to_owned(),
            capabilities,
        });
    }
    out
}

/// One row of `GET /portal/groups`: `<name> roles=<r1,r2,...>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupRow {
    /// The `ManagedGroup`'s name.
    pub name: String,
    /// The role names attached to this group.
    pub roles: Vec<String>,
}

/// Parse `GET /portal/groups`'s body into [`GroupRow`]s.
#[must_use]
pub fn parse_group_rows(body: &str) -> Vec<GroupRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, rest)) = line.split_once(' ') else {
            out.push(GroupRow {
                name: line.to_owned(),
                roles: Vec::new(),
            });
            continue;
        };
        let roles = rest
            .strip_prefix("roles=")
            .map(|c| {
                c.split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.push(GroupRow {
            name: name.to_owned(),
            roles,
        });
    }
    out
}

/// `POST /portal/roles/create` body: `<token>\n<name>\n<capabilities-csv>`.
#[must_use]
pub fn create_role_wire(token: &str, name: &str, capabilities_csv: &str) -> String {
    crate::portal::body_lines(&[token, name, capabilities_csv])
}

/// `POST /portal/groups/create` body: `<token>\n<name>`.
#[must_use]
pub fn create_group_wire(token: &str, name: &str) -> String {
    crate::portal::body_lines(&[token, name])
}

/// `POST /portal/groups/attach-role` body: `<token>\n<group>\n<role>`.
#[must_use]
pub fn attach_role_wire(token: &str, group: &str, role: &str) -> String {
    crate::portal::body_lines(&[token, group, role])
}

/// One row of `GET /portal/oauth/clients`: `<client_id> type=<Confidential|
/// Public> scopes=<s1,s2,...> redirect_uris=<u1,u2,...>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthClientRow {
    /// The client id.
    pub client_id: String,
    /// `"Confidential"` or `"Public"`.
    pub client_type: String,
    /// The allowed scopes.
    pub scopes: Vec<String>,
    /// The registered redirect-URI allow-list.
    pub redirect_uris: Vec<String>,
}

/// Parse `GET /portal/oauth/clients`'s body into [`OAuthClientRow`]s.
#[must_use]
pub fn parse_oauth_client_rows(body: &str) -> Vec<OAuthClientRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(client_id) = parts.next() else {
            continue;
        };
        let mut row = OAuthClientRow {
            client_id: client_id.to_owned(),
            ..Default::default()
        };
        for field in parts {
            if let Some(v) = field.strip_prefix("type=") {
                row.client_type = v.to_owned();
            } else if let Some(v) = field.strip_prefix("scopes=") {
                row.scopes = v
                    .split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect();
            } else if let Some(v) = field.strip_prefix("redirect_uris=") {
                row.redirect_uris = v
                    .split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
        out.push(row);
    }
    out
}

/// `POST /portal/oauth/clients/register` body: `<token>\n<client_type>\n
/// <redirect_uri>\n<scopes-csv>` (mirrors `client_registry::register_client`'s
/// gated builder — one redirect URI per call, matching the invite-style
/// single-value admin forms elsewhere in this console; repeat the call to add
/// more to the same client's allow-list).
#[must_use]
pub fn register_client_wire(
    token: &str,
    client_type: &str,
    redirect_uri: &str,
    scopes_csv: &str,
) -> String {
    crate::portal::body_lines(&[token, client_type, redirect_uri, scopes_csv])
}

/// `POST /portal/oauth/clients/revoke-consent` body: `<token>\n<client_id>\n
/// <handle>` — revokes the `(handle, client_id)` consent, immediately
/// invalidating every token introspected under it (the crate's documented
/// effect).
#[must_use]
pub fn revoke_consent_wire(token: &str, client_id: &str, handle: &str) -> String {
    crate::portal::body_lines(&[token, client_id, handle])
}

/// The predicted-effect-via-decider gate every sensitive act in this console
/// checks before it lets the operator fire the real act: interprets a
/// `GET .../dry-run` body the SAME way `crate::resources_console::
/// parse_predicted` does, defaulting CLOSED (an unparseable/absent prediction
/// never enables a sensitive control).
#[must_use]
pub fn sensitive_action_allowed(dry_run_body: &str) -> bool {
    parse_predicted(dry_run_body).unwrap_or(false)
}

// ===========================================================================
// Yew components + fetch glue (behind the `yew` feature).
// ===========================================================================

#[cfg(feature = "yew")]
pub use yew_impl::ChangePasswordPage;
#[cfg(feature = "yew")]
pub use yew_impl::{AccountHub, OAuthClientsTile, ProfileTile, RolesGroupsTile, UsersTile};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::*;
    use crate::auth::{use_auth, AuthAction, AuthContext};
    use crate::components::{
        use_toaster, Badge, Column, DataTable, Dialog, Drawer, Row, SecretReveal, Side, StatusPill,
        TabItem, Tabs, Tone,
    };
    use crate::portal::{
        body_lines, get_url, http, input_value, nonempty_lines, CredentialsTile, IdentityTile,
        PendingButton, SessionsTile,
    };
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// A best-effort authenticated `GET` returning parsed non-empty lines;
    /// dispatches `Unauthorized` on 401 — mirrors `crate::portal`'s private
    /// `get_lines`, kept local here since that helper is not re-exported.
    async fn get_lines(auth: AuthContext, url: String) -> Option<Vec<String>> {
        match http("GET", &url, None).await {
            Ok(r) if r.ok() => Some(nonempty_lines(&r.body)),
            Ok(r) => {
                if r.status == 401 {
                    auth.dispatch(AuthAction::Unauthorized);
                }
                None
            }
            Err(_) => None,
        }
    }

    /// A status/error message line (empty when `None`).
    fn message_line(id: &'static str, msg: &Option<(String, bool)>) -> Html {
        match msg {
            Some((text, ok)) => {
                html! { <p class={classes!("msg", if *ok { "ok" } else { "err" })} id={id}>{ text.clone() }</p> }
            }
            None => html! { <p class="msg" id={id}></p> },
        }
    }

    // -----------------------------------------------------------------
    // Shared render helpers.
    // -----------------------------------------------------------------

    /// Render a comma-joined list as tone-neutral chips; an empty list renders
    /// a muted em-dash so a cell is never blank.
    fn chips(csv: &str) -> Html {
        let items: Vec<&str> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if items.is_empty() {
            return html! { <span class="cell-empty">{ "\u{2014}" }</span> };
        }
        html! {
            <span class="chip-row">
                { for items.into_iter().map(|c| html! { <Badge label={c.to_owned()} tone={Tone::Neutral} /> }) }
            </span>
        }
    }

    /// The predicted-effect caption shown in a confirm dialog: the shared
    /// `dry-run` decider's ALLOW/DENY, surfaced as an inline guardrail so the
    /// operator sees the server's verdict BEFORE firing (predicted == enforced).
    fn predicted_caption(p: Option<bool>) -> Html {
        match p {
            Some(true) => html! { <p class="predict is-allow">{ "The server will allow this action." }</p> },
            Some(false) => html! {
                <p class="predict is-deny">
                    { "Blocked \u{2014} the server would refuse this (for example, the last remaining \
                       administrator cannot be disabled or have 2FA removed)." }
                </p>
            },
            None => html! { <p class="predict">{ "Checking with the server\u{2026}" }</p> },
        }
    }

    /// A dimmed modal backdrop wrapping a [`Dialog`] card.
    fn modal(children: Html) -> Html {
        html! { <div class="modal-backdrop"><Dialog>{ children }</Dialog></div> }
    }

    /// Read the current value of the `<select>` an event fired on.
    fn select_value(e: &Event) -> String {
        use wasm_bindgen::JsCast;
        e.target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
            .map(|s| s.value())
            .unwrap_or_default()
    }

    // ===================================================================
    // Account hub (self-service): one tabbed page over the four folded
    // self-service surfaces + a self password change.
    // ===================================================================

    /// The signed-in user's account hub — a single tabbed destination that
    /// replaces the four separate sidebar entries (profile / security keys /
    /// sessions / identity) with one "Account" page, plus a self-service
    /// password change. Each tab mounts the existing capability tile verbatim,
    /// so no self-service surface is lost — only re-homed under one roof.
    #[function_component(AccountHub)]
    pub fn account_hub() -> Html {
        let tabs = vec![
            TabItem { label: "Profile".into(), panel: html! { <ProfileTile /> } },
            TabItem { label: "Password".into(), panel: html! { <PasswordTab /> } },
            TabItem { label: "Security keys".into(), panel: html! { <CredentialsTile /> } },
            TabItem { label: "Sessions".into(), panel: html! { <SessionsTile /> } },
            TabItem { label: "Identity".into(), panel: html! { <IdentityTile /> } },
        ];
        html! {
            <section class="account-hub" id="account-hub">
                <h2 class="section-title">{ "Account" }</h2>
                <p class="section-sub">{ "Manage your own profile, password, security keys, sessions, and identity." }</p>
                <Tabs tabs={tabs} />
            </section>
        }
    }

    /// Self-service voluntary password change (distinct from the forced
    /// interstitial): new password + confirmation, gated on a match, posting
    /// the same reseal endpoint as the forced flow.
    #[function_component(PasswordTab)]
    pub fn password_tab() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let pw = use_state(String::new);
        let confirm = use_state(String::new);
        let busy = use_state(|| false);

        let on_pw = {
            let pw = pw.clone();
            Callback::from(move |e: InputEvent| pw.set(input_value(&e)))
        };
        let on_confirm = {
            let confirm = confirm.clone();
            Callback::from(move |e: InputEvent| confirm.set(input_value(&e)))
        };

        let mismatch = !confirm.is_empty() && *pw != *confirm;
        let can_submit = !pw.trim().is_empty() && *pw == *confirm && !*busy;

        let submit = {
            let (auth, toaster, pw, confirm, busy) = (
                auth.clone(),
                toaster.clone(),
                pw.clone(),
                confirm.clone(),
                busy.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if pw.trim().is_empty() || *pw != *confirm || *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = body_lines(&[&token, pw.trim()]);
                let (toaster, pw, confirm, busy) =
                    (toaster.clone(), pw.clone(), confirm.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/users/reset-password", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            toaster.success("Password changed.");
                            pw.set(String::new());
                            confirm.set(String::new());
                        }
                        Ok(r) => toaster.error(&format!("Could not change password: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not change password: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="tile" id="password-tab">
                <h3>{ "Change password" }</h3>
                <label for="self-pw-input">{ "New password" }</label>
                <input id="self-pw-input" type="password" value={(*pw).clone()} oninput={on_pw} />
                <label for="self-pw-confirm">{ "Confirm new password" }</label>
                <input id="self-pw-confirm" type="password" value={(*confirm).clone()} oninput={on_confirm} />
                if mismatch {
                    <p class="msg err">{ "The two passwords do not match." }</p>
                }
                <div class="tile-actions">
                    <button type="button" id="self-pw-btn" disabled={!can_submit} onclick={submit}>
                        { if *busy { "Working\u{2026}" } else { "Change password" } }
                    </button>
                </div>
            </div>
        }
    }

    // ===================================================================
    // Profile (self-service): display name / email.
    // ===================================================================

    /// Self-service Profile: display name / email, with the account status
    /// shown as a pill.
    #[function_component(ProfileTile)]
    pub fn profile_tile() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let view = use_state(ProfileView::default);
        let display_name = use_state(String::new);
        let email = use_state(String::new);
        let busy = use_state(|| false);

        {
            let (auth, view, display_name, email) =
                (auth.clone(), view.clone(), display_name.clone(), email.clone());
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let (view, display_name, email) = (view.clone(), display_name.clone(), email.clone());
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &get_url("/portal/profile", &token, &[]), None).await {
                            if r.ok() {
                                let parsed = parse_profile(&r.body);
                                display_name.set(parsed.display_name.clone());
                                email.set(parsed.email.clone());
                                view.set(parsed);
                            }
                        }
                    });
                }
                || ()
            });
        }

        let on_name = {
            let display_name = display_name.clone();
            Callback::from(move |e: InputEvent| display_name.set(input_value(&e)))
        };
        let on_email = {
            let email = email.clone();
            Callback::from(move |e: InputEvent| email.set(input_value(&e)))
        };
        let save = {
            let (auth, toaster, busy, display_name, email) = (
                auth.clone(),
                toaster.clone(),
                busy.clone(),
                display_name.clone(),
                email.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = profile_update_wire(&token, &display_name, &email);
                let (toaster, busy) = (toaster.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("PUT", "/portal/profile", Some(&body)).await {
                        Ok(r) if r.ok() => toaster.success("Profile saved."),
                        Ok(r) => toaster.error(&format!("Could not save profile: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not save profile: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };

        let status = if view.status.is_empty() { "Unknown".to_owned() } else { view.status.clone() };
        html! {
            <div class="tile" id="profile-tile">
                <div class="tile-head">
                    <h3>{ "Profile" }</h3>
                    <StatusPill status={status} />
                </div>
                if !view.handle.is_empty() {
                    <p class="tile-meta" id="profile-handle">{ format!("Signed in as {}", view.handle) }</p>
                }
                <label for="profile-name-input">{ "Display name" }</label>
                <input id="profile-name-input" type="text" value={(*display_name).clone()} oninput={on_name} />
                <label for="profile-email-input">{ "Email" }</label>
                <input id="profile-email-input" type="email" value={(*email).clone()} oninput={on_email} />
                <div class="tile-actions">
                    <PendingButton id="profile-save-btn" label="Save profile" busy={*busy} onclick={save} />
                </div>
            </div>
        }
    }

    // ===================================================================
    // Users (admin): directory table -> detail drawer with row actions,
    // invite dialog with one-time temp-password reveal.
    // ===================================================================

    /// A queued sensitive user action, staged into a confirm dialog with a
    /// dry-run prediction before it fires.
    #[derive(Clone, PartialEq)]
    struct UserAction {
        handle: String,
        path: &'static str,
        dry: &'static str,
        title: &'static str,
        confirm_label: &'static str,
        desc: String,
        reveals_secret: bool,
    }

    /// Admin user directory. A best-in-class list→detail flow: a filterable
    /// [`DataTable`] with a status pill and role chips per row; clicking a row
    /// (or its Manage action) opens a detail [`Drawer`] whose lifecycle
    /// actions (disable / enable / reset password / require change) each stage
    /// a confirm dialog gated on the shared decider's dry-run prediction. An
    /// invite opens a dialog and, on success, reveals the one-time temporary
    /// password via [`SecretReveal`].
    #[function_component(UsersTile)]
    pub fn users_tile() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let users = use_state(Vec::<UserRow>::new);
        let selected = use_state(|| None::<UserRow>);
        let invite_open = use_state(|| false);
        let handle = use_state(String::new);
        let email = use_state(String::new);
        let pending = use_state(|| None::<UserAction>);
        let predicted = use_state(|| None::<bool>);
        let secret = use_state(|| None::<(String, String)>);
        let busy = use_state(|| false);

        let refresh = {
            let (auth, users) = (auth.clone(), users.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else { return };
                let (auth, users) = (auth.clone(), users.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(auth, get_url("/portal/users", &token, &[])).await {
                        users.set(parse_user_rows(&lines.join("\n")));
                    }
                });
            })
        };
        {
            let refresh = refresh.clone();
            use_effect_with(auth.token.clone(), move |_| {
                refresh.emit(());
                || ()
            });
        }

        // Build the table rows (handle / status / roles / password state).
        let rows: Vec<Row> = users
            .iter()
            .map(|u| {
                vec![
                    u.handle.clone(),
                    u.status.clone(),
                    u.roles.join(","),
                    if u.force_password_change { "Must change".to_owned() } else { "OK".to_owned() },
                ]
            })
            .collect();

        let render_cell = Callback::from(|(col, val): (usize, String)| -> Html {
            match col {
                1 => html! { <StatusPill status={val} /> },
                2 => chips(&val),
                3 => {
                    let tone = if val == "Must change" { Tone::Warning } else { Tone::Success };
                    html! { <Badge label={val} tone={tone} /> }
                }
                _ => html! { { val } },
            }
        });

        let select_by_handle = {
            let (users, selected) = (users.clone(), selected.clone());
            move |h: &str| {
                if let Some(u) = users.iter().find(|u| u.handle == h) {
                    selected.set(Some(u.clone()));
                }
            }
        };
        let on_row_click = {
            let select_by_handle = select_by_handle.clone();
            Callback::from(move |row: Row| {
                if let Some(h) = row.first() {
                    select_by_handle(h);
                }
            })
        };
        let row_actions = {
            let select_by_handle = select_by_handle.clone();
            Callback::from(move |row: Row| -> Html {
                let h = row.first().cloned().unwrap_or_default();
                let select = select_by_handle.clone();
                let onclick = Callback::from(move |_: MouseEvent| select(&h));
                html! { <button type="button" class="row-action" onclick={onclick}>{ "Manage" }</button> }
            })
        };

        // Stage a sensitive action: open the confirm dialog and fetch its
        // dry-run prediction.
        let stage = {
            let (auth, pending, predicted) = (auth.clone(), pending.clone(), predicted.clone());
            move |act: UserAction| {
                predicted.set(None);
                pending.set(Some(act.clone()));
                let (auth, predicted) = (auth.clone(), predicted.clone());
                spawn_local(async move {
                    let token = auth.token.clone().unwrap_or_default();
                    let url = get_url(act.dry, &token, &[("handle", &act.handle)]);
                    if let Ok(r) = http("GET", &url, None).await {
                        predicted.set(Some(sensitive_action_allowed(&r.body)));
                    } else {
                        predicted.set(Some(false));
                    }
                });
            }
        };

        // Fire a non-sensitive enable directly (still enforced server-side).
        let enable = {
            let (auth, toaster, busy, refresh) = (auth.clone(), toaster.clone(), busy.clone(), refresh.clone());
            move |h: String| {
                let token = auth.token.clone().unwrap_or_default();
                let body = user_target_wire(&token, &h);
                let (toaster, busy, refresh) = (toaster.clone(), busy.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/users/enable", Some(&body)).await {
                        Ok(r) if r.ok() => toaster.success("User enabled."),
                        Ok(r) => toaster.error(&format!("Could not enable: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not enable: the request failed."),
                    }
                    refresh.emit(());
                    busy.set(false);
                });
            }
        };

        let confirm = {
            let (auth, toaster, pending, predicted, secret, busy, refresh, selected) = (
                auth.clone(),
                toaster.clone(),
                pending.clone(),
                predicted.clone(),
                secret.clone(),
                busy.clone(),
                refresh.clone(),
                selected.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                let Some(act) = (*pending).clone() else { return };
                if *busy || !matches!(*predicted, Some(true)) {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = user_target_wire(&token, &act.handle);
                let (toaster, pending, secret, busy, refresh, selected) = (
                    toaster.clone(),
                    pending.clone(),
                    secret.clone(),
                    busy.clone(),
                    refresh.clone(),
                    selected.clone(),
                );
                busy.set(true);
                spawn_local(async move {
                    match http("POST", act.path, Some(&body)).await {
                        Ok(r) if r.ok() => {
                            if act.reveals_secret {
                                secret.set(Some(("Temporary password".to_owned(), r.body.trim().to_owned())));
                            } else {
                                toaster.success("Done.");
                            }
                            selected.set(None);
                            refresh.emit(());
                        }
                        Ok(r) => toaster.error(&format!("Refused: {}", r.body.trim())),
                        Err(_) => toaster.error("The request failed."),
                    }
                    pending.set(None);
                    busy.set(false);
                });
            })
        };
        let cancel = {
            let pending = pending.clone();
            Callback::from(move |_: MouseEvent| pending.set(None))
        };

        // Invite handlers.
        let on_handle = {
            let handle = handle.clone();
            Callback::from(move |e: InputEvent| handle.set(input_value(&e)))
        };
        let on_email = {
            let email = email.clone();
            Callback::from(move |e: InputEvent| email.set(input_value(&e)))
        };
        let open_invite = {
            let (invite_open, handle, email, secret) = (invite_open.clone(), handle.clone(), email.clone(), secret.clone());
            Callback::from(move |_: MouseEvent| {
                handle.set(String::new());
                email.set(String::new());
                secret.set(None);
                invite_open.set(true);
            })
        };
        let do_invite = {
            let (auth, toaster, busy, refresh, handle, email, secret) = (
                auth.clone(),
                toaster.clone(),
                busy.clone(),
                refresh.clone(),
                handle.clone(),
                email.clone(),
                secret.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || handle.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = invite_user_wire(&token, handle.trim(), email.trim());
                let (toaster, busy, refresh, secret) = (toaster.clone(), busy.clone(), refresh.clone(), secret.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/users/invite", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            secret.set(Some(("Temporary password".to_owned(), r.body.trim().to_owned())));
                            refresh.emit(());
                        }
                        Ok(r) => toaster.error(&format!("Could not invite: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not invite: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };
        let close_invite = {
            let (invite_open, secret) = (invite_open.clone(), secret.clone());
            Callback::from(move |_: MouseEvent| {
                invite_open.set(false);
                secret.set(None);
            })
        };
        let dismiss_secret = {
            let secret = secret.clone();
            Callback::from(move |_: MouseEvent| secret.set(None))
        };

        html! {
            <section class="tile" id="users-tile">
                <div class="tile-head">
                    <h3>{ "Users" }</h3>
                    <button type="button" id="user-invite-open" class="btn-primary" onclick={open_invite}>
                        { "Invite user" }
                    </button>
                </div>
                <DataTable
                    columns={vec![
                        Column::text("Handle"),
                        Column::text("Status"),
                        Column::unsortable("Roles"),
                        Column::text("Password"),
                    ]}
                    rows={rows}
                    page_size={12}
                    render_cell={render_cell}
                    row_actions={row_actions}
                    on_row_click={on_row_click}
                    empty_label={"No users yet — invite one to get started."}
                />

                // Detail drawer for the selected user.
                <Drawer open={selected.is_some()} side={Side::Right}
                    on_close={{ let selected = selected.clone(); Callback::from(move |_: MouseEvent| selected.set(None)) }}>
                    if let Some(u) = (*selected).clone() {
                        { user_detail(&u, stage.clone(), enable.clone()) }
                    }
                </Drawer>

                // Confirm dialog for a staged sensitive action.
                if let Some(act) = (*pending).clone() {
                    { modal(html! {
                        <>
                            <h3>{ act.title }</h3>
                            <p>{ act.desc.clone() }</p>
                            { predicted_caption(*predicted) }
                            <div class="dialog-actions">
                                <button type="button" class="btn-ghost" onclick={cancel.clone()}>{ "Cancel" }</button>
                                <button type="button" class="btn-danger" id="user-action-confirm"
                                    disabled={!matches!(*predicted, Some(true)) || *busy}
                                    onclick={confirm.clone()}>
                                    { if *busy { "Working\u{2026}" } else { act.confirm_label } }
                                </button>
                            </div>
                        </>
                    }) }
                }

                // Invite dialog (+ one-time secret reveal on success).
                if *invite_open {
                    { modal(html! {
                        <>
                            <h3>{ "Invite user" }</h3>
                            if let Some((label, value)) = (*secret).clone() {
                                <p>{ "The account was created. Share this one-time password with the user." }</p>
                                <SecretReveal label={label} secret={value} />
                                <div class="dialog-actions">
                                    <button type="button" class="btn-primary" onclick={close_invite.clone()}>{ "Done" }</button>
                                </div>
                            } else {
                                <label for="user-invite-handle">{ "Handle" }</label>
                                <input id="user-invite-handle" type="text" placeholder="handle"
                                    value={(*handle).clone()} oninput={on_handle} />
                                <label for="user-invite-email">{ "Email" }</label>
                                <input id="user-invite-email" type="email" placeholder="email"
                                    value={(*email).clone()} oninput={on_email} />
                                <div class="dialog-actions">
                                    <button type="button" class="btn-ghost" onclick={close_invite.clone()}>{ "Cancel" }</button>
                                    <PendingButton id="user-invite-btn" label="Send invite" busy={*busy} onclick={do_invite} />
                                </div>
                            }
                        </>
                    }) }
                }

                // A reset-password reveal (outside the invite flow).
                if !*invite_open {
                    if let Some((label, value)) = (*secret).clone() {
                        { modal(html! {
                            <>
                                <h3>{ "Temporary password" }</h3>
                                <p>{ "Share this one-time password with the user; they must change it at next sign-in." }</p>
                                <SecretReveal label={label} secret={value} />
                                <div class="dialog-actions">
                                    <button type="button" class="btn-primary" onclick={dismiss_secret}>{ "Done" }</button>
                                </div>
                            </>
                        }) }
                    }
                }
            </section>
        }
    }

    /// The user detail drawer body: identity summary + the lifecycle action
    /// buttons, each staging a confirm dialog (or firing enable directly).
    fn user_detail(
        u: &UserRow,
        stage: impl Fn(UserAction) + Clone + 'static,
        enable: impl Fn(String) + Clone + 'static,
    ) -> Html {
        let disabled = u.status.eq_ignore_ascii_case("disabled");
        let h = u.handle.clone();

        let on_disable = {
            let (stage, h) = (stage.clone(), h.clone());
            Callback::from(move |_: MouseEvent| stage(UserAction {
                handle: h.clone(),
                path: "/portal/users/disable",
                dry: "/portal/users/disable/dry-run",
                title: "Disable user",
                confirm_label: "Disable",
                desc: format!("Disable {} — they will be signed out and cannot sign in until re-enabled.", h),
                reveals_secret: false,
            }))
        };
        let on_reset = {
            let (stage, h) = (stage.clone(), h.clone());
            Callback::from(move |_: MouseEvent| stage(UserAction {
                handle: h.clone(),
                path: "/portal/users/reset-password",
                dry: "/portal/users/reset-password/dry-run",
                title: "Reset password",
                confirm_label: "Reset password",
                desc: format!("Issue a new one-time password for {} (their registered security keys are preserved).", h),
                reveals_secret: true,
            }))
        };
        let on_require = {
            let (stage, h) = (stage.clone(), h.clone());
            Callback::from(move |_: MouseEvent| stage(UserAction {
                handle: h.clone(),
                path: "/portal/users/require-password-change",
                dry: "/portal/users/require-password-change/dry-run",
                title: "Require password change",
                confirm_label: "Require change",
                desc: format!("Force {} to set a new password at their next sign-in.", h),
                reveals_secret: false,
            }))
        };
        let on_enable = {
            let (enable, h) = (enable.clone(), h.clone());
            Callback::from(move |_: MouseEvent| enable(h.clone()))
        };

        html! {
            <div class="drawer-body" id="user-detail">
                <div class="tile-head">
                    <h3>{ u.handle.clone() }</h3>
                    <StatusPill status={u.status.clone()} />
                </div>
                <dl class="detail-list">
                    <dt>{ "Roles" }</dt>
                    <dd>{ chips(&u.roles.join(",")) }</dd>
                    <dt>{ "Password" }</dt>
                    <dd>{ if u.force_password_change { "Change required at next sign-in" } else { "OK" } }</dd>
                </dl>
                <div class="drawer-actions">
                    if disabled {
                        <button type="button" class="btn-primary" id="user-enable-btn" onclick={on_enable}>{ "Enable" }</button>
                    } else {
                        <button type="button" class="btn-danger" id="user-disable-btn" onclick={on_disable}>{ "Disable" }</button>
                    }
                    <button type="button" id="user-reset-btn" onclick={on_reset}>{ "Reset password" }</button>
                    <button type="button" id="user-require-btn" onclick={on_require}>{ "Require password change" }</button>
                </div>
                <p class="drawer-note">
                    { "Managing this user's security keys and role assignments is available once the \
                       admin credential and role-assignment endpoints land." }
                </p>
            </div>
        }
    }

    // ===================================================================
    // Roles & Groups (admin): two focused object tabs.
    // ===================================================================

    /// The documented IAM administrative capabilities, offered as a checkbox
    /// picker when defining a role (a free-text field remains for any other
    /// capability the deployment defines).
    const KNOWN_CAPS: &[&str] = &[
        "iam:users:write",
        "iam:roles:write",
        "iam:groups:write",
        "iam:credentials:manage",
    ];

    /// Admin roles + managed groups, split into two focused tabs (each an
    /// object table with an inline creator) instead of one stacked form dump.
    #[function_component(RolesGroupsTile)]
    pub fn roles_groups_tile() -> Html {
        let tabs = vec![
            TabItem { label: "Roles".into(), panel: html! { <RolesPanel /> } },
            TabItem { label: "Groups".into(), panel: html! { <GroupsPanel /> } },
        ];
        html! {
            <section class="tile" id="roles-groups-tile">
                <h3>{ "Roles & Groups" }</h3>
                <Tabs tabs={tabs} />
            </section>
        }
    }

    #[function_component(RolesPanel)]
    fn roles_panel() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let roles = use_state(Vec::<RoleRow>::new);
        let name = use_state(String::new);
        let checked = use_state(Vec::<String>::new);
        let extra = use_state(String::new);
        let busy = use_state(|| false);

        let refresh = {
            let (auth, roles) = (auth.clone(), roles.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else { return };
                let (auth, roles) = (auth.clone(), roles.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(auth, get_url("/portal/roles", &token, &[])).await {
                        roles.set(parse_role_rows(&lines.join("\n")));
                    }
                });
            })
        };
        {
            let refresh = refresh.clone();
            use_effect_with(auth.token.clone(), move |_| { refresh.emit(()); || () });
        }

        let rows: Vec<Row> = roles
            .iter()
            .map(|r| vec![r.name.clone(), r.capabilities.join(","), r.capabilities.len().to_string()])
            .collect();
        let render_cell = Callback::from(|(col, val): (usize, String)| -> Html {
            if col == 1 { chips(&val) } else { html! { { val } } }
        });

        let on_name = { let name = name.clone(); Callback::from(move |e: InputEvent| name.set(input_value(&e))) };
        let on_extra = { let extra = extra.clone(); Callback::from(move |e: InputEvent| extra.set(input_value(&e))) };
        let toggle_cap = {
            let checked = checked.clone();
            move |cap: &'static str| {
                let checked = checked.clone();
                Callback::from(move |_: MouseEvent| {
                    let mut next = (*checked).clone();
                    if let Some(i) = next.iter().position(|c| c == cap) { next.remove(i); } else { next.push(cap.to_owned()); }
                    checked.set(next);
                })
            }
        };
        let create = {
            let (auth, toaster, busy, refresh, name, checked, extra) = (
                auth.clone(), toaster.clone(), busy.clone(), refresh.clone(), name.clone(), checked.clone(), extra.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || name.trim().is_empty() { return; }
                let mut caps: Vec<String> = (*checked).clone();
                caps.extend(extra.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned));
                let token = auth.token.clone().unwrap_or_default();
                let body = create_role_wire(&token, name.trim(), &caps.join(","));
                let (toaster, busy, refresh, name, checked, extra) =
                    (toaster.clone(), busy.clone(), refresh.clone(), name.clone(), checked.clone(), extra.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/roles/create", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            toaster.success("Role created.");
                            name.set(String::new()); checked.set(Vec::new()); extra.set(String::new());
                            refresh.emit(());
                        }
                        Ok(r) => toaster.error(&format!("Could not create role: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not create role: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="object-panel" id="roles-panel">
                <DataTable
                    columns={vec![Column::text("Role"), Column::unsortable("Capabilities"), Column::numeric("Count")]}
                    rows={rows}
                    render_cell={render_cell}
                    empty_label={"No roles defined yet."}
                />
                <div class="creator">
                    <h4>{ "Create role" }</h4>
                    <label for="role-name-input">{ "Name" }</label>
                    <input id="role-name-input" type="text" placeholder="name" value={(*name).clone()} oninput={on_name} />
                    <div class="check-grid">
                        { for KNOWN_CAPS.iter().map(|cap| {
                            let on = checked.iter().any(|c| c == *cap);
                            let onclick = toggle_cap(cap);
                            html! {
                                <button type="button" class={classes!("check-pill", on.then_some("is-on"))} onclick={onclick}>
                                    { if on { "\u{2713} " } else { "" } }{ *cap }
                                </button>
                            }
                        }) }
                    </div>
                    <label for="role-caps-extra">{ "Additional capabilities (comma-separated)" }</label>
                    <input id="role-caps-extra" type="text" placeholder="resource:apply, obs:read"
                        value={(*extra).clone()} oninput={on_extra} />
                    <div class="tile-actions">
                        <PendingButton id="role-create-btn" label="Create role" busy={*busy} onclick={create} />
                    </div>
                </div>
            </div>
        }
    }

    #[function_component(GroupsPanel)]
    fn groups_panel() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let groups = use_state(Vec::<GroupRow>::new);
        let roles = use_state(Vec::<RoleRow>::new);
        let name = use_state(String::new);
        let attach_group = use_state(String::new);
        let attach_role = use_state(String::new);
        let busy = use_state(|| false);

        let refresh = {
            let (auth, groups, roles) = (auth.clone(), groups.clone(), roles.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else { return };
                let (a1, groups, t1) = (auth.clone(), groups.clone(), token.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(a1, get_url("/portal/groups", &t1, &[])).await {
                        groups.set(parse_group_rows(&lines.join("\n")));
                    }
                });
                let (a2, roles, t2) = (auth.clone(), roles.clone(), token.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(a2, get_url("/portal/roles", &t2, &[])).await {
                        roles.set(parse_role_rows(&lines.join("\n")));
                    }
                });
            })
        };
        {
            let refresh = refresh.clone();
            use_effect_with(auth.token.clone(), move |_| { refresh.emit(()); || () });
        }

        let rows: Vec<Row> = groups
            .iter()
            .map(|g| vec![g.name.clone(), g.roles.join(","), g.roles.len().to_string()])
            .collect();
        let render_cell = Callback::from(|(col, val): (usize, String)| -> Html {
            if col == 1 { chips(&val) } else { html! { { val } } }
        });

        let on_name = { let name = name.clone(); Callback::from(move |e: InputEvent| name.set(input_value(&e))) };
        let on_attach_group = { let g = attach_group.clone(); Callback::from(move |e: Event| g.set(select_value(&e))) };
        let on_attach_role = { let r = attach_role.clone(); Callback::from(move |e: Event| r.set(select_value(&e))) };

        let create = {
            let (auth, toaster, busy, refresh, name) = (auth.clone(), toaster.clone(), busy.clone(), refresh.clone(), name.clone());
            Callback::from(move |_: MouseEvent| {
                if *busy || name.trim().is_empty() { return; }
                let token = auth.token.clone().unwrap_or_default();
                let body = create_group_wire(&token, name.trim());
                let (toaster, busy, refresh, name) = (toaster.clone(), busy.clone(), refresh.clone(), name.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/groups/create", Some(&body)).await {
                        Ok(r) if r.ok() => { toaster.success("Group created."); name.set(String::new()); refresh.emit(()); }
                        Ok(r) => toaster.error(&format!("Could not create group: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not create group: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };
        let attach = {
            let (auth, toaster, busy, refresh, attach_group, attach_role) = (
                auth.clone(), toaster.clone(), busy.clone(), refresh.clone(), attach_group.clone(), attach_role.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || attach_group.is_empty() || attach_role.is_empty() { return; }
                let token = auth.token.clone().unwrap_or_default();
                let body = attach_role_wire(&token, &attach_group, &attach_role);
                let (toaster, busy, refresh) = (toaster.clone(), busy.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/groups/attach-role", Some(&body)).await {
                        Ok(r) if r.ok() => { toaster.success("Role attached to group."); refresh.emit(()); }
                        Ok(r) => toaster.error(&format!("Could not attach role: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not attach role: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="object-panel" id="groups-panel">
                <DataTable
                    columns={vec![Column::text("Group"), Column::unsortable("Attached roles"), Column::numeric("Count")]}
                    rows={rows}
                    render_cell={render_cell}
                    empty_label={"No groups defined yet."}
                />
                <div class="creator">
                    <h4>{ "Create group" }</h4>
                    <label for="group-name-input">{ "Name" }</label>
                    <input id="group-name-input" type="text" placeholder="name" value={(*name).clone()} oninput={on_name} />
                    <div class="tile-actions">
                        <PendingButton id="group-create-btn" label="Create group" busy={*busy} onclick={create} />
                    </div>
                    <h4>{ "Attach a role to a group" }</h4>
                    <label for="attach-group-select">{ "Group" }</label>
                    <select id="attach-group-select" onchange={on_attach_group}>
                        <option value="" selected={attach_group.is_empty()}>{ "Select a group\u{2026}" }</option>
                        { for groups.iter().map(|g| html! {
                            <option value={g.name.clone()} selected={*attach_group == g.name}>{ g.name.clone() }</option>
                        }) }
                    </select>
                    <label for="attach-role-select">{ "Role" }</label>
                    <select id="attach-role-select" onchange={on_attach_role}>
                        <option value="" selected={attach_role.is_empty()}>{ "Select a role\u{2026}" }</option>
                        { for roles.iter().map(|r| html! {
                            <option value={r.name.clone()} selected={*attach_role == r.name}>{ r.name.clone() }</option>
                        }) }
                    </select>
                    <div class="tile-actions">
                        <PendingButton id="attach-role-btn" label="Attach role" busy={*busy} onclick={attach} />
                    </div>
                </div>
            </div>
        }
    }

    // ===================================================================
    // OAuth clients (admin): client registry + consents, two tabs.
    // ===================================================================

    /// Admin OAuth client registry, split into a Clients tab (registry table +
    /// register dialog with one-time client-secret reveal) and a Consents tab
    /// (revoke a `(client, user)` consent behind a dry-run-gated confirm).
    #[function_component(OAuthClientsTile)]
    pub fn oauth_clients_tile() -> Html {
        let tabs = vec![
            TabItem { label: "Clients".into(), panel: html! { <OAuthClientsPanel /> } },
            TabItem { label: "Consents".into(), panel: html! { <OAuthConsentsPanel /> } },
        ];
        html! {
            <section class="tile" id="oauth-clients-tile">
                <h3>{ "OAuth Clients" }</h3>
                <Tabs tabs={tabs} />
            </section>
        }
    }

    #[function_component(OAuthClientsPanel)]
    fn oauth_clients_panel() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let rows_state = use_state(Vec::<OAuthClientRow>::new);
        let dialog_open = use_state(|| false);
        let client_type = use_state(|| "Confidential".to_owned());
        let redirect_uri = use_state(String::new);
        let scopes = use_state(String::new);
        let secret = use_state(|| None::<String>);
        let busy = use_state(|| false);

        let refresh = {
            let (auth, rows_state) = (auth.clone(), rows_state.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else { return };
                let (auth, rows_state) = (auth.clone(), rows_state.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(auth, get_url("/portal/oauth/clients", &token, &[])).await {
                        rows_state.set(parse_oauth_client_rows(&lines.join("\n")));
                    }
                });
            })
        };
        {
            let refresh = refresh.clone();
            use_effect_with(auth.token.clone(), move |_| { refresh.emit(()); || () });
        }

        let rows: Vec<Row> = rows_state
            .iter()
            .map(|c| vec![c.client_id.clone(), c.client_type.clone(), c.scopes.join(","), c.redirect_uris.join(", ")])
            .collect();
        let render_cell = Callback::from(|(col, val): (usize, String)| -> Html {
            if col == 2 { chips(&val) } else { html! { { val } } }
        });

        let on_type = { let t = client_type.clone(); Callback::from(move |e: Event| t.set(select_value(&e))) };
        let on_redirect = { let r = redirect_uri.clone(); Callback::from(move |e: InputEvent| r.set(input_value(&e))) };
        let on_scopes = { let s = scopes.clone(); Callback::from(move |e: InputEvent| s.set(input_value(&e))) };
        let open = {
            let (dialog_open, redirect_uri, scopes, secret) = (dialog_open.clone(), redirect_uri.clone(), scopes.clone(), secret.clone());
            Callback::from(move |_: MouseEvent| {
                redirect_uri.set(String::new()); scopes.set(String::new()); secret.set(None); dialog_open.set(true);
            })
        };
        let close = {
            let (dialog_open, secret) = (dialog_open.clone(), secret.clone());
            Callback::from(move |_: MouseEvent| { dialog_open.set(false); secret.set(None); })
        };
        let register = {
            let (auth, toaster, busy, refresh, client_type, redirect_uri, scopes, secret) = (
                auth.clone(), toaster.clone(), busy.clone(), refresh.clone(),
                client_type.clone(), redirect_uri.clone(), scopes.clone(), secret.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || redirect_uri.trim().is_empty() { return; }
                let token = auth.token.clone().unwrap_or_default();
                let body = register_client_wire(&token, client_type.trim(), redirect_uri.trim(), scopes.trim());
                let (toaster, busy, refresh, secret) = (toaster.clone(), busy.clone(), refresh.clone(), secret.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/oauth/clients/register", Some(&body)).await {
                        Ok(r) if r.ok() => { secret.set(Some(r.body.trim().to_owned())); refresh.emit(()); }
                        Ok(r) => toaster.error(&format!("Could not register client: {}", r.body.trim())),
                        Err(_) => toaster.error("Could not register client: the request failed."),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="object-panel" id="oauth-clients-panel">
                <div class="tile-head">
                    <span class="tile-meta">{ "Registered OAuth 2.1 / OIDC clients" }</span>
                    <button type="button" id="oauth-register-open" class="btn-primary" onclick={open}>{ "Register client" }</button>
                </div>
                <DataTable
                    columns={vec![Column::text("Client ID"), Column::text("Type"), Column::unsortable("Scopes"), Column::unsortable("Redirect URIs")]}
                    rows={rows}
                    render_cell={render_cell}
                    empty_label={"No clients registered yet."}
                />
                if *dialog_open {
                    { modal(html! {
                        <>
                            <h3>{ "Register OAuth client" }</h3>
                            if let Some(value) = (*secret).clone() {
                                <p>{ "Client registered. Copy the client secret now." }</p>
                                <SecretReveal label={"Client secret"} secret={value} />
                                <div class="dialog-actions">
                                    <button type="button" class="btn-primary" onclick={close.clone()}>{ "Done" }</button>
                                </div>
                            } else {
                                <label for="oauth-type-select">{ "Client type" }</label>
                                <select id="oauth-type-select" onchange={on_type}>
                                    <option value="Confidential" selected={*client_type == "Confidential"}>{ "Confidential" }</option>
                                    <option value="Public" selected={*client_type == "Public"}>{ "Public" }</option>
                                </select>
                                <label for="oauth-redirect-input">{ "Redirect URI" }</label>
                                <input id="oauth-redirect-input" type="url" placeholder="https://app.example.com/callback"
                                    value={(*redirect_uri).clone()} oninput={on_redirect} />
                                <label for="oauth-scopes-input">{ "Scopes (comma-separated)" }</label>
                                <input id="oauth-scopes-input" type="text" placeholder="openid, profile, email"
                                    value={(*scopes).clone()} oninput={on_scopes} />
                                <div class="dialog-actions">
                                    <button type="button" class="btn-ghost" onclick={close.clone()}>{ "Cancel" }</button>
                                    <PendingButton id="oauth-register-btn" label="Register" busy={*busy} onclick={register} />
                                </div>
                            }
                        </>
                    }) }
                }
            </div>
        }
    }

    #[function_component(OAuthConsentsPanel)]
    fn oauth_consents_panel() -> Html {
        let auth = use_auth();
        let toaster = use_toaster();
        let clients = use_state(Vec::<OAuthClientRow>::new);
        let client = use_state(String::new);
        let handle = use_state(String::new);
        let staged = use_state(|| false);
        let predicted = use_state(|| None::<bool>);
        let busy = use_state(|| false);

        {
            let (auth, clients) = (auth.clone(), clients.clone());
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let (auth, clients) = (auth.clone(), clients.clone());
                    spawn_local(async move {
                        if let Some(lines) = get_lines(auth, get_url("/portal/oauth/clients", &token, &[])).await {
                            clients.set(parse_oauth_client_rows(&lines.join("\n")));
                        }
                    });
                }
                || ()
            });
        }

        let on_client = { let c = client.clone(); Callback::from(move |e: Event| c.set(select_value(&e))) };
        let on_handle = { let h = handle.clone(); Callback::from(move |e: InputEvent| h.set(input_value(&e))) };

        let stage = {
            let (auth, client, handle, staged, predicted) = (auth.clone(), client.clone(), handle.clone(), staged.clone(), predicted.clone());
            Callback::from(move |_: MouseEvent| {
                if client.is_empty() || handle.trim().is_empty() { return; }
                predicted.set(None);
                staged.set(true);
                let (auth, client, handle, predicted) = (auth.clone(), client.clone(), handle.clone(), predicted.clone());
                spawn_local(async move {
                    let token = auth.token.clone().unwrap_or_default();
                    let url = get_url("/portal/oauth/clients/revoke-consent/dry-run", &token,
                        &[("client_id", &client), ("handle", handle.trim())]);
                    if let Ok(r) = http("GET", &url, None).await {
                        predicted.set(Some(sensitive_action_allowed(&r.body)));
                    } else { predicted.set(Some(false)); }
                });
            })
        };
        let cancel = { let staged = staged.clone(); Callback::from(move |_: MouseEvent| staged.set(false)) };
        let confirm = {
            let (auth, toaster, client, handle, staged, predicted, busy) = (
                auth.clone(), toaster.clone(), client.clone(), handle.clone(), staged.clone(), predicted.clone(), busy.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || !matches!(*predicted, Some(true)) { return; }
                let token = auth.token.clone().unwrap_or_default();
                let body = revoke_consent_wire(&token, client.trim(), handle.trim());
                let (toaster, staged, busy) = (toaster.clone(), staged.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/oauth/clients/revoke-consent", Some(&body)).await {
                        Ok(r) if r.ok() => toaster.success("Consent revoked."),
                        Ok(r) => toaster.error(&format!("Refused: {}", r.body.trim())),
                        Err(_) => toaster.error("The request failed."),
                    }
                    staged.set(false);
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="object-panel" id="oauth-consents-panel">
                <h4>{ "Revoke a user's consent for a client" }</h4>
                <label for="consent-client-select">{ "Client" }</label>
                <select id="consent-client-select" onchange={on_client}>
                    <option value="" selected={client.is_empty()}>{ "Select a client\u{2026}" }</option>
                    { for clients.iter().map(|c| html! {
                        <option value={c.client_id.clone()} selected={*client == c.client_id}>{ c.client_id.clone() }</option>
                    }) }
                </select>
                <label for="consent-handle-input">{ "User handle" }</label>
                <input id="consent-handle-input" type="text" placeholder="handle" value={(*handle).clone()} oninput={on_handle} />
                <div class="tile-actions">
                    <button type="button" id="consent-revoke-open" class="btn-danger"
                        disabled={client.is_empty() || handle.trim().is_empty()} onclick={stage}>
                        { "Revoke consent" }
                    </button>
                </div>
                if *staged {
                    { modal(html! {
                        <>
                            <h3>{ "Revoke consent" }</h3>
                            <p>{ format!("Revoke {}'s consent for client {}.", handle.trim(), *client) }</p>
                            { predicted_caption(*predicted) }
                            <div class="dialog-actions">
                                <button type="button" class="btn-ghost" onclick={cancel}>{ "Cancel" }</button>
                                <button type="button" class="btn-danger" id="consent-revoke-confirm"
                                    disabled={!matches!(*predicted, Some(true)) || *busy} onclick={confirm}>
                                    { if *busy { "Working\u{2026}" } else { "Revoke" } }
                                </button>
                            </div>
                        </>
                    }) }
                }
            </div>
        }
    }

    /// The forced-change interstitial: mounted by [`crate::router::guarded`]
    /// whenever `crate::router::guard` resolves to
    /// `crate::router::Route::ChangePassword` (an authenticated session with
    /// `force_password_change` set) — intercepting EVERY other route until the
    /// password is changed, mirroring the `UserLifecycle.tla`
    /// `InvitedForcesChange` invariant the underlying crate refines.
    #[function_component(ChangePasswordPage)]
    pub fn change_password_page() -> Html {
        let auth = use_auth();
        let new_password = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let on_new = {
            let new_password = new_password.clone();
            Callback::from(move |e: InputEvent| new_password.set(input_value(&e)))
        };
        let submit = {
            let (auth, busy, msg, new_password) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                new_password.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || new_password.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = body_lines(&[&token, new_password.trim()]);
                let (busy, msg) = (busy.clone(), msg.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/users/reset-password", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="pillar-bootstrap" id="change-password-page">
                <h2>{ "A password change is required" }</h2>
                <p>{ "Your account requires a new password before you can continue." }</p>
                <label for="change-password-input">{ "New password" }</label>
                <input id="change-password-input" type="password"
                    value={(*new_password).clone()} oninput={on_new} />
                <PendingButton id="change-password-btn" label="Change password" busy={*busy} onclick={submit} />
                { message_line("change-password-msg", &msg) }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_profile_reads_every_field() {
        let body = "PROFILE handle=alice display_name=Alice email=alice@example.com \
                     status=Active force_password_change=false";
        let view = parse_profile(body);
        assert_eq!(view.handle, "alice");
        assert_eq!(view.display_name, "Alice");
        assert_eq!(view.email, "alice@example.com");
        assert_eq!(view.status, "Active");
        assert!(!view.force_password_change);
    }

    #[test]
    fn parse_profile_on_a_garbage_body_yields_the_default_empty_view() {
        assert_eq!(parse_profile(""), ProfileView::default());
        assert_eq!(parse_profile("not a profile line"), ProfileView::default());
    }

    #[test]
    fn profile_update_wire_carries_token_then_name_then_email() {
        assert_eq!(
            profile_update_wire("tok", "Alice", "alice@example.com"),
            "tok\nAlice\nalice@example.com"
        );
    }

    #[test]
    fn parse_user_rows_reads_status_force_change_and_roles() {
        let body = "alice status=Active force_password_change=false roles=admin,viewer\n\
                     bob status=Invited force_password_change=true roles=\n";
        let rows = parse_user_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].handle, "alice");
        assert_eq!(rows[0].status, "Active");
        assert!(!rows[0].force_password_change);
        assert_eq!(
            rows[0].roles,
            vec!["admin".to_string(), "viewer".to_string()]
        );
        assert_eq!(rows[1].handle, "bob");
        assert!(rows[1].force_password_change);
        assert!(rows[1].roles.is_empty());
    }

    #[test]
    fn parse_user_rows_on_empty_body_is_empty() {
        assert!(parse_user_rows("").is_empty());
        assert!(parse_user_rows("\n\n").is_empty());
    }

    #[test]
    fn invite_and_target_wires_carry_the_token_first() {
        assert_eq!(
            invite_user_wire("tok", "alice", "a@x.com"),
            "tok\nalice\na@x.com"
        );
        assert_eq!(user_target_wire("tok", "alice"), "tok\nalice");
    }

    #[test]
    fn parse_role_rows_reads_capabilities() {
        let body = "admin capabilities=iam:users:write,iam:roles:write\nviewer capabilities=\n";
        let rows = parse_role_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "admin");
        assert_eq!(
            rows[0].capabilities,
            vec!["iam:users:write".to_string(), "iam:roles:write".to_string()]
        );
        assert_eq!(rows[1].name, "viewer");
        assert!(rows[1].capabilities.is_empty());
    }

    #[test]
    fn parse_group_rows_reads_attached_roles() {
        let body = "ops roles=admin,oncall\nempty-group roles=\n";
        let rows = parse_group_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "ops");
        assert_eq!(
            rows[0].roles,
            vec!["admin".to_string(), "oncall".to_string()]
        );
        assert!(rows[1].roles.is_empty());
    }

    #[test]
    fn role_group_wires_carry_the_token_first() {
        assert_eq!(
            create_role_wire("tok", "admin", "iam:users:write,iam:roles:write"),
            "tok\nadmin\niam:users:write,iam:roles:write"
        );
        assert_eq!(create_group_wire("tok", "ops"), "tok\nops");
        assert_eq!(attach_role_wire("tok", "ops", "admin"), "tok\nops\nadmin");
    }

    #[test]
    fn parse_oauth_client_rows_reads_every_field() {
        let body = "abc123 type=Confidential scopes=read,write \
                     redirect_uris=https://example.com/cb\n";
        let rows = parse_oauth_client_rows(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].client_id, "abc123");
        assert_eq!(rows[0].client_type, "Confidential");
        assert_eq!(
            rows[0].scopes,
            vec!["read".to_string(), "write".to_string()]
        );
        assert_eq!(
            rows[0].redirect_uris,
            vec!["https://example.com/cb".to_string()]
        );
    }

    #[test]
    fn oauth_client_wires_carry_the_token_first() {
        assert_eq!(
            register_client_wire(
                "tok",
                "Confidential",
                "https://example.com/cb",
                "read,write"
            ),
            "tok\nConfidential\nhttps://example.com/cb\nread,write"
        );
        assert_eq!(
            revoke_consent_wire("tok", "abc123", "alice"),
            "tok\nabc123\nalice"
        );
    }

    /// The predicted-effect gate: mirrors `crate::resources_console::
    /// parse_predicted`'s ALLOW/DENY mapping and defaults CLOSED on anything
    /// else — a sensitive act is never enabled on an unparseable prediction.
    #[test]
    fn sensitive_action_allowed_maps_allow_deny_and_defaults_closed() {
        assert!(sensitive_action_allowed("PREDICTED ALLOW"));
        assert!(!sensitive_action_allowed("PREDICTED DENY"));
        assert!(!sensitive_action_allowed("garbage"));
        assert!(!sensitive_action_allowed(""));
    }
}
