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
pub use yew_impl::{OAuthClientsTile, ProfileTile, RolesGroupsTile, UsersTile};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::*;
    use crate::auth::{use_auth, AuthAction, AuthContext};
    use crate::portal::{body_lines, get_url, http, input_value, nonempty_lines, PendingButton};
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

    /// Self-service Profile: `display_name`/`email` edit.
    #[function_component(ProfileTile)]
    pub fn profile_tile() -> Html {
        let auth = use_auth();
        let view = use_state(ProfileView::default);
        let display_name = use_state(String::new);
        let email = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        {
            let auth = auth.clone();
            let view = view.clone();
            let display_name = display_name.clone();
            let email = email.clone();
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let (view, display_name, email) =
                        (view.clone(), display_name.clone(), email.clone());
                    spawn_local(async move {
                        if let Ok(r) =
                            http("GET", &get_url("/portal/profile", &token, &[]), None).await
                        {
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
            let (auth, busy, msg, display_name, email) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                display_name.clone(),
                email.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = profile_update_wire(&token, &display_name, &email);
                let (busy, msg) = (busy.clone(), msg.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("PUT", "/portal/profile", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="tile" id="profile-tile">
                <h3>{ "Profile" }</h3>
                <p id="profile-status">{ format!("Status: {}", if view.status.is_empty() { "-" } else { &view.status }) }</p>
                <label for="profile-name-input">{ "Display name" }</label>
                <input id="profile-name-input" type="text" value={(*display_name).clone()} oninput={on_name} />
                <label for="profile-email-input">{ "Email" }</label>
                <input id="profile-email-input" type="text" value={(*email).clone()} oninput={on_email} />
                <PendingButton id="profile-save-btn" label="Save profile" busy={*busy} onclick={save} />
                { message_line("profile-msg", &msg) }
            </div>
        }
    }

    /// Admin Users: invite/list/disable/enable/reset-password/require-
    /// password-change, each sensitive act gated behind a predicted-effect
    /// dry-run (see [`super::sensitive_action_allowed`]).
    #[function_component(UsersTile)]
    pub fn users_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<UserRow>::new);
        let handle = use_state(String::new);
        let email = use_state(String::new);
        let target = use_state(String::new);
        let predicted = use_state(|| None::<bool>);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let auth = auth.clone();
            let rows = rows.clone();
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth, rows) = (auth.clone(), rows.clone());
                spawn_local(async move {
                    if let Some(lines) =
                        get_lines(auth, get_url("/portal/users", &token, &[])).await
                    {
                        rows.set(parse_user_rows(&lines.join("\n")));
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

        let on_handle = {
            let handle = handle.clone();
            Callback::from(move |e: InputEvent| handle.set(input_value(&e)))
        };
        let on_email = {
            let email = email.clone();
            Callback::from(move |e: InputEvent| email.set(input_value(&e)))
        };
        let on_target = {
            let target = target.clone();
            let predicted = predicted.clone();
            Callback::from(move |e: InputEvent| {
                target.set(input_value(&e));
                predicted.set(None);
            })
        };

        let invite = {
            let (auth, busy, msg, refresh, handle, email) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                handle.clone(),
                email.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || handle.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = invite_user_wire(&token, handle.trim(), email.trim());
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/users/invite", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };

        // Check the predicted effect of the currently-typed target handle for
        // the given sensitive act path, WITHOUT firing it.
        let check_predicted = {
            let (auth, target, predicted) = (auth.clone(), target.clone(), predicted.clone());
            move |path: &'static str| {
                let (auth, target, predicted) = (auth.clone(), target.clone(), predicted.clone());
                Callback::from(move |_: MouseEvent| {
                    let token = auth.token.clone().unwrap_or_default();
                    let t = (*target).clone();
                    let predicted = predicted.clone();
                    spawn_local(async move {
                        let url = get_url(path, &token, &[("handle", &t)]);
                        if let Ok(r) = http("GET", &url, None).await {
                            predicted.set(Some(sensitive_action_allowed(&r.body)));
                        }
                    });
                })
            }
        };

        let fire_sensitive = {
            let (auth, busy, msg, refresh, target, predicted) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                target.clone(),
                predicted.clone(),
            );
            move |path: &'static str| {
                let (auth, busy, msg, refresh, target, predicted) = (
                    auth.clone(),
                    busy.clone(),
                    msg.clone(),
                    refresh.clone(),
                    target.clone(),
                    predicted.clone(),
                );
                Callback::from(move |_: MouseEvent| {
                    if *busy || !matches!(*predicted, Some(true)) || target.trim().is_empty() {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let body = user_target_wire(&token, target.trim());
                    let (busy, msg, refresh, predicted) = (
                        busy.clone(),
                        msg.clone(),
                        refresh.clone(),
                        predicted.clone(),
                    );
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) = http("POST", path, Some(&body)).await {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                            if r.ok() {
                                refresh.emit(());
                            }
                        }
                        predicted.set(None);
                        busy.set(false);
                    });
                })
            }
        };

        html! {
            <div class="tile" id="users-tile">
                <h3>{ "Users" }</h3>
                <div id="user-list">
                    { for rows.iter().map(|u| html! {
                        <p class="user-row">
                            { format!(
                                "{} status={} force_password_change={} roles={}",
                                u.handle, u.status, u.force_password_change, u.roles.join(",")
                            ) }
                        </p>
                    }) }
                </div>
                <label for="user-invite-handle">{ "Invite" }</label>
                <input id="user-invite-handle" type="text" placeholder="handle"
                    value={(*handle).clone()} oninput={on_handle} />
                <input id="user-invite-email" type="text" placeholder="email"
                    value={(*email).clone()} oninput={on_email} />
                <PendingButton id="user-invite-btn" label="Invite" busy={*busy} onclick={invite} />

                <label for="user-target-handle">{ "Target handle (disable/enable/reset/require-change)" }</label>
                <input id="user-target-handle" type="text" value={(*target).clone()} oninput={on_target} />
                <button type="button" id="user-check-disable"
                    onclick={check_predicted("/portal/users/disable/dry-run")}>
                    { "Check disable" }
                </button>
                <PendingButton id="user-disable-btn" label="Disable" busy={*busy}
                    onclick={fire_sensitive("/portal/users/disable")} />
                <PendingButton id="user-enable-btn" label="Enable" busy={*busy}
                    onclick={fire_sensitive("/portal/users/enable")} />
                <PendingButton id="user-reset-btn" label="Reset password" busy={*busy}
                    onclick={fire_sensitive("/portal/users/reset-password")} />
                <PendingButton id="user-require-change-btn" label="Require password change" busy={*busy}
                    onclick={fire_sensitive("/portal/users/require-password-change")} />
                <p id="user-predicted">
                    { match *predicted {
                        Some(true) => "predicted: ALLOW".to_owned(),
                        Some(false) => "predicted: DENY".to_owned(),
                        None => "predicted: (not checked)".to_owned(),
                    } }
                </p>
                { message_line("user-msg", &msg) }
            </div>
        }
    }

    /// Admin Roles & Groups: create a role, create a group, attach a role to
    /// a group.
    #[function_component(RolesGroupsTile)]
    pub fn roles_groups_tile() -> Html {
        let auth = use_auth();
        let role_rows = use_state(Vec::<RoleRow>::new);
        let group_rows = use_state(Vec::<GroupRow>::new);
        let role_name = use_state(String::new);
        let role_caps = use_state(String::new);
        let group_name = use_state(String::new);
        let attach_group = use_state(String::new);
        let attach_role = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let auth = auth.clone();
            let role_rows = role_rows.clone();
            let group_rows = group_rows.clone();
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth1, role_rows) = (auth.clone(), role_rows.clone());
                let token1 = token.clone();
                spawn_local(async move {
                    if let Some(lines) =
                        get_lines(auth1, get_url("/portal/roles", &token1, &[])).await
                    {
                        role_rows.set(parse_role_rows(&lines.join("\n")));
                    }
                });
                let (auth2, group_rows, token2) = (auth.clone(), group_rows.clone(), token.clone());
                spawn_local(async move {
                    if let Some(lines) =
                        get_lines(auth2, get_url("/portal/groups", &token2, &[])).await
                    {
                        group_rows.set(parse_group_rows(&lines.join("\n")));
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

        let on_role_name = {
            let role_name = role_name.clone();
            Callback::from(move |e: InputEvent| role_name.set(input_value(&e)))
        };
        let on_role_caps = {
            let role_caps = role_caps.clone();
            Callback::from(move |e: InputEvent| role_caps.set(input_value(&e)))
        };
        let create_role = {
            let (auth, busy, msg, refresh, role_name, role_caps) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                role_name.clone(),
                role_caps.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || role_name.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = create_role_wire(&token, role_name.trim(), role_caps.trim());
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/roles/create", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let on_group_name = {
            let group_name = group_name.clone();
            Callback::from(move |e: InputEvent| group_name.set(input_value(&e)))
        };
        let create_group = {
            let (auth, busy, msg, refresh, group_name) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                group_name.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || group_name.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = create_group_wire(&token, group_name.trim());
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/groups/create", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let on_attach_group = {
            let attach_group = attach_group.clone();
            Callback::from(move |e: InputEvent| attach_group.set(input_value(&e)))
        };
        let on_attach_role = {
            let attach_role = attach_role.clone();
            Callback::from(move |e: InputEvent| attach_role.set(input_value(&e)))
        };
        let attach = {
            let (auth, busy, msg, refresh, attach_group, attach_role) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                attach_group.clone(),
                attach_role.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || attach_group.trim().is_empty() || attach_role.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = attach_role_wire(&token, attach_group.trim(), attach_role.trim());
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/groups/attach-role", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="tile" id="roles-groups-tile">
                <h3>{ "Roles & Groups" }</h3>
                <div id="role-list">
                    { for role_rows.iter().map(|r| html! {
                        <p class="role-row">{ format!("{} capabilities={}", r.name, r.capabilities.join(",")) }</p>
                    }) }
                </div>
                <div id="group-list">
                    { for group_rows.iter().map(|g| html! {
                        <p class="group-row">{ format!("{} roles={}", g.name, g.roles.join(",")) }</p>
                    }) }
                </div>
                <label for="role-name-input">{ "Create role" }</label>
                <input id="role-name-input" type="text" placeholder="name"
                    value={(*role_name).clone()} oninput={on_role_name} />
                <input id="role-caps-input" type="text" placeholder="capabilities (csv)"
                    value={(*role_caps).clone()} oninput={on_role_caps} />
                <PendingButton id="role-create-btn" label="Create role" busy={*busy} onclick={create_role} />

                <label for="group-name-input">{ "Create group" }</label>
                <input id="group-name-input" type="text" placeholder="name"
                    value={(*group_name).clone()} oninput={on_group_name} />
                <PendingButton id="group-create-btn" label="Create group" busy={*busy} onclick={create_group} />

                <label for="attach-group-input">{ "Attach role to group" }</label>
                <input id="attach-group-input" type="text" placeholder="group"
                    value={(*attach_group).clone()} oninput={on_attach_group} />
                <input id="attach-role-input" type="text" placeholder="role"
                    value={(*attach_role).clone()} oninput={on_attach_role} />
                <PendingButton id="attach-role-btn" label="Attach" busy={*busy} onclick={attach} />
                { message_line("roles-groups-msg", &msg) }
            </div>
        }
    }

    /// Admin OAuth Clients: list, register, and revoke a `(handle, client)`
    /// consent — revoking a consent is a sensitive act gated behind a
    /// predicted-effect dry-run.
    #[function_component(OAuthClientsTile)]
    pub fn oauth_clients_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<OAuthClientRow>::new);
        let client_type = use_state(|| "Confidential".to_owned());
        let redirect_uri = use_state(String::new);
        let scopes = use_state(String::new);
        let revoke_client = use_state(String::new);
        let revoke_handle = use_state(String::new);
        let predicted = use_state(|| None::<bool>);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let auth = auth.clone();
            let rows = rows.clone();
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth, rows) = (auth.clone(), rows.clone());
                spawn_local(async move {
                    if let Some(lines) =
                        get_lines(auth, get_url("/portal/oauth/clients", &token, &[])).await
                    {
                        rows.set(parse_oauth_client_rows(&lines.join("\n")));
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

        let on_client_type = {
            let client_type = client_type.clone();
            Callback::from(move |e: InputEvent| client_type.set(input_value(&e)))
        };
        let on_redirect_uri = {
            let redirect_uri = redirect_uri.clone();
            Callback::from(move |e: InputEvent| redirect_uri.set(input_value(&e)))
        };
        let on_scopes = {
            let scopes = scopes.clone();
            Callback::from(move |e: InputEvent| scopes.set(input_value(&e)))
        };
        let register = {
            let (auth, busy, msg, refresh, client_type, redirect_uri, scopes) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                client_type.clone(),
                redirect_uri.clone(),
                scopes.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || redirect_uri.trim().is_empty() {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = register_client_wire(
                    &token,
                    client_type.trim(),
                    redirect_uri.trim(),
                    scopes.trim(),
                );
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/oauth/clients/register", Some(&body)).await
                    {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let on_revoke_client = {
            let revoke_client = revoke_client.clone();
            let predicted = predicted.clone();
            Callback::from(move |e: InputEvent| {
                revoke_client.set(input_value(&e));
                predicted.set(None);
            })
        };
        let on_revoke_handle = {
            let revoke_handle = revoke_handle.clone();
            let predicted = predicted.clone();
            Callback::from(move |e: InputEvent| {
                revoke_handle.set(input_value(&e));
                predicted.set(None);
            })
        };
        let check_revoke_predicted = {
            let (auth, revoke_client, revoke_handle, predicted) = (
                auth.clone(),
                revoke_client.clone(),
                revoke_handle.clone(),
                predicted.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                let token = auth.token.clone().unwrap_or_default();
                let (client, handle) = ((*revoke_client).clone(), (*revoke_handle).clone());
                let predicted = predicted.clone();
                spawn_local(async move {
                    let url = get_url(
                        "/portal/oauth/clients/revoke-consent/dry-run",
                        &token,
                        &[("client_id", &client), ("handle", &handle)],
                    );
                    if let Ok(r) = http("GET", &url, None).await {
                        predicted.set(Some(sensitive_action_allowed(&r.body)));
                    }
                });
            })
        };
        let revoke = {
            let (auth, busy, msg, refresh, revoke_client, revoke_handle, predicted) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                revoke_client.clone(),
                revoke_handle.clone(),
                predicted.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy || !matches!(*predicted, Some(true)) {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = revoke_consent_wire(&token, revoke_client.trim(), revoke_handle.trim());
                let (busy, msg, refresh, predicted) = (
                    busy.clone(),
                    msg.clone(),
                    refresh.clone(),
                    predicted.clone(),
                );
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) =
                        http("POST", "/portal/oauth/clients/revoke-consent", Some(&body)).await
                    {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    predicted.set(None);
                    busy.set(false);
                });
            })
        };

        html! {
            <div class="tile" id="oauth-clients-tile">
                <h3>{ "OAuth Clients" }</h3>
                <div id="oauth-client-list">
                    { for rows.iter().map(|c| html! {
                        <p class="oauth-client-row">
                            { format!(
                                "{} type={} scopes={} redirect_uris={}",
                                c.client_id, c.client_type, c.scopes.join(","), c.redirect_uris.join(",")
                            ) }
                        </p>
                    }) }
                </div>
                <label for="oauth-client-type-input">{ "Register client" }</label>
                <input id="oauth-client-type-input" type="text" placeholder="Confidential|Public"
                    value={(*client_type).clone()} oninput={on_client_type} />
                <input id="oauth-client-redirect-input" type="text" placeholder="redirect_uri"
                    value={(*redirect_uri).clone()} oninput={on_redirect_uri} />
                <input id="oauth-client-scopes-input" type="text" placeholder="scopes (csv)"
                    value={(*scopes).clone()} oninput={on_scopes} />
                <PendingButton id="oauth-client-register-btn" label="Register" busy={*busy} onclick={register} />

                <label for="oauth-revoke-client-input">{ "Revoke consent" }</label>
                <input id="oauth-revoke-client-input" type="text" placeholder="client_id"
                    value={(*revoke_client).clone()} oninput={on_revoke_client} />
                <input id="oauth-revoke-handle-input" type="text" placeholder="handle"
                    value={(*revoke_handle).clone()} oninput={on_revoke_handle} />
                <button type="button" id="oauth-revoke-check-btn" onclick={check_revoke_predicted}>
                    { "Check revoke" }
                </button>
                <PendingButton id="oauth-revoke-btn" label="Revoke consent" busy={*busy} onclick={revoke} />
                <p id="oauth-revoke-predicted">
                    { match *predicted {
                        Some(true) => "predicted: ALLOW".to_owned(),
                        Some(false) => "predicted: DENY".to_owned(),
                        None => "predicted: (not checked)".to_owned(),
                    } }
                </p>
                { message_line("oauth-clients-msg", &msg) }
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
