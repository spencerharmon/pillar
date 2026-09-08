//! The portal's ROOT entry surface served at `/`: a status-driven shell that
//! renders the atomic create-cell + first-user **bootstrap** form on a fresh
//! node, the TWO-FIELD node-side custody **login** on a bootstrapped one, and
//! the authenticated [`crate::portal::Portal`] once signed in.
//!
//! All request framing / response parsing / error mapping is delegated to the
//! host-tested pure helpers in [`crate::portal`] (`login_wire`,
//! `interpret_login`, `bootstrap_wire`, `interpret_bootstrap`,
//! `interpret_name_check`, `friendly_error`), so this module is only the Yew
//! wiring. The wire contract (per `pillar_web_api`): `GET /nonce` then
//! `POST /login` (`<identifier>\n<password>\n<nonceId>`, no CID field — the
//! node holds the key and unlocks it server-side); `GET /bootstrap/status`
//! then `POST /bootstrap/create` (`<cell>\n<handle>\n<factor>`); and a live
//! `GET /bootstrap/name-check?name=…` uniqueness hint as the operator types.

#[cfg(feature = "yew")]
pub use yew_impl::PortalEntry;

#[cfg(feature = "yew")]
mod yew_impl {
    use crate::auth::{use_auth, AuthAction};
    use crate::portal::{
        bootstrap_wire, friendly_error, http, input_value, interpret_bootstrap, interpret_login,
        interpret_name_check, login_wire, NameHint,
    };
    use crate::router::Route;
    use pillar_web_api::{BootstrapStatus, NonceResponse};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;
    use yew_router::prelude::*;

    /// The TWO-FIELD node-side custody login. `GET /nonce` -> `POST /login`;
    /// on success dispatches [`AuthAction::LoginSuccess`] with the handle +
    /// bearer token; on failure shows the plain-language `friendly_error`.
    #[function_component(LoginForm)]
    pub fn login_form() -> Html {
        let auth = use_auth();
        let identifier = use_state(String::new);
        let password = use_state(String::new);
        let message = use_state(|| None::<String>);
        let busy = use_state(|| false);

        let on_id = {
            let identifier = identifier.clone();
            Callback::from(move |e: InputEvent| identifier.set(input_value(&e)))
        };
        let on_pw = {
            let password = password.clone();
            Callback::from(move |e: InputEvent| password.set(input_value(&e)))
        };

        let on_submit = {
            let (auth, identifier, password, message, busy) = (
                auth.clone(),
                identifier.clone(),
                password.clone(),
                message.clone(),
                busy.clone(),
            );
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                if *busy {
                    return;
                }
                let (auth, id, pw) = (auth.clone(), (*identifier).clone(), (*password).clone());
                let (message, busy) = (message.clone(), busy.clone());
                if id.is_empty() || pw.is_empty() {
                    message.set(Some("Enter your identifier and unlock factor.".to_owned()));
                    return;
                }
                busy.set(true);
                message.set(Some("Requesting challenge\u{2026}".to_owned()));
                spawn_local(async move {
                    // 1. Fetch the origin/expiry-bound challenge nonce.
                    let nonce = match http("GET", "/nonce", None).await {
                        Ok(r) if r.ok() => NonceResponse::from_body(&r.body),
                        _ => None,
                    };
                    let Some(nonce) = nonce else {
                        message.set(Some(friendly_error("could not reach the node")));
                        busy.set(false);
                        return;
                    };
                    // 2. POST exactly the two fields (+ the nonce id).
                    message.set(Some("Signing in on the node\u{2026}".to_owned()));
                    match http("POST", "/login", Some(&login_wire(&id, &pw, nonce.id))).await {
                        Ok(r) => match interpret_login(r.ok(), &r.body, &id) {
                            Ok(handle) => {
                                message.set(None);
                                auth.dispatch(AuthAction::LoginSuccess {
                                    user: handle,
                                    token: r.session_token.unwrap_or_default(),
                                });
                            }
                            Err(reason) => message.set(Some(friendly_error(&reason))),
                        },
                        Err(_) => message.set(Some(friendly_error("could not reach the node"))),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <form id="login-form" class="pillar-login" onsubmit={on_submit}>
                <h2>{ "Sign in to manage your node" }</h2>
                <label for="identifier">{ "User identifier" }</label>
                <input id="identifier" type="text" value={(*identifier).clone()}
                    placeholder="you@pillar / username / genesis CID" oninput={on_id} />
                <label for="password">{ "Unlock factor" }</label>
                <input id="password" type="password" value={(*password).clone()}
                    placeholder="Password or passkey token" oninput={on_pw} />
                <button id="submit" type="submit" disabled={*busy}>{ "Sign in" }</button>
                { message_line("msg", &message) }
                <p class="hint">
                    { "Your credential is sent over TLS to this trusted node, which holds your \
                       key only because the cell sealed an offer to it. The node resolves your \
                       offer, unlocks your operational key, and signs a one-time challenge on \
                       your behalf. There is deliberately no CID field \u{2014} the node \
                       resolves that itself." }
                </p>
            </form>
        }
    }

    /// Props for [`BootstrapForm`].
    #[derive(Properties, PartialEq)]
    pub struct BootstrapFormProps {
        /// Called with the created first-user handle once the node is
        /// bootstrapped, so the entry flips to the login screen (prefilled).
        pub on_bootstrapped: Callback<String>,
    }

    /// The first-run bootstrap: create the cell AND first user in ONE atomic
    /// `POST /bootstrap/create`, with a live cell-name uniqueness hint and the
    /// what-happens-next explainer.
    #[function_component(BootstrapForm)]
    pub fn bootstrap_form(props: &BootstrapFormProps) -> Html {
        let cell = use_state(String::new);
        let handle = use_state(String::new);
        let factor = use_state(String::new);
        let name_hint = use_state(|| NameHint::Idle);
        let message = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        // Live, best-effort cell-name uniqueness check as the operator types.
        let on_cell = {
            let (cell, name_hint) = (cell.clone(), name_hint.clone());
            Callback::from(move |e: InputEvent| {
                let name = input_value(&e);
                cell.set(name.clone());
                let (cell_now, name_hint) = (cell.clone(), name_hint.clone());
                let trimmed = name.trim().to_owned();
                if trimmed.is_empty() {
                    name_hint.set(NameHint::Idle);
                    return;
                }
                spawn_local(async move {
                    let url = format!(
                        "/bootstrap/name-check?name={}",
                        crate::portal::query_encode(&trimmed)
                    );
                    if let Ok(r) = http("GET", &url, None).await {
                        // Only apply if the field still holds this name.
                        if cell_now.trim() == trimmed {
                            name_hint.set(interpret_name_check(r.ok(), &r.body));
                        }
                    }
                });
            })
        };
        let on_handle = {
            let handle = handle.clone();
            Callback::from(move |e: InputEvent| handle.set(input_value(&e)))
        };
        let on_factor = {
            let factor = factor.clone();
            Callback::from(move |e: InputEvent| factor.set(input_value(&e)))
        };

        let on_submit = {
            let (cell, handle, factor, message, busy) = (
                cell.clone(),
                handle.clone(),
                factor.clone(),
                message.clone(),
                busy.clone(),
            );
            let on_bootstrapped = props.on_bootstrapped.clone();
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                if *busy {
                    return;
                }
                let (cell_v, handle_v, factor_v) =
                    ((*cell).clone(), (*handle).clone(), (*factor).clone());
                let (message, busy, on_bootstrapped) =
                    (message.clone(), busy.clone(), on_bootstrapped.clone());
                if cell_v.trim().is_empty() || handle_v.trim().is_empty() || factor_v.is_empty() {
                    message.set(Some((
                        "Enter a cell name, a handle, and an unlock factor.".to_owned(),
                        false,
                    )));
                    return;
                }
                busy.set(true);
                message.set(Some((
                    "Creating the cell and first user\u{2026}".to_owned(),
                    true,
                )));
                spawn_local(async move {
                    let body = bootstrap_wire(cell_v.trim(), handle_v.trim(), &factor_v);
                    match http("POST", "/bootstrap/create", Some(&body)).await {
                        Ok(r) => match interpret_bootstrap(r.ok(), &r.body) {
                            Ok(()) => {
                                message.set(Some((
                                    "Cell and first user created. This node is now bootstrapped \u{2014} sign in below.".to_owned(),
                                    true,
                                )));
                                on_bootstrapped.emit(handle_v.trim().to_owned());
                            }
                            Err(reason) => message.set(Some((
                                format!("Could not bootstrap the node: {reason}"),
                                false,
                            ))),
                        },
                        Err(_) => {
                            message.set(Some(("The node could not be reached.".to_owned(), false)))
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let (hint_text, hint_cls) = match &*name_hint {
            NameHint::Idle => (String::new(), "field-hint"),
            NameHint::Free => ("Available.".to_owned(), "field-hint ok"),
            NameHint::InUse(m) => (m.clone(), "field-hint err"),
        };

        html! {
            <form id="bootstrap-form" class="pillar-bootstrap" onsubmit={on_submit}>
                <div class="step" id="bootstrap-step">{ "Set up this node \u{2014} create your cell and first user" }</div>
                <label for="cell-id">{ "Cell name" }</label>
                <input id="cell-id" type="text" value={(*cell).clone()} placeholder="e.g. spencer-cell" oninput={on_cell} />
                <div id="cell-name-hint" class={hint_cls}>{ hint_text }</div>
                <label for="custody">{ "Cell key custody" }</label>
                <select id="custody">
                    <option value="tpm">{ "TPM (hardware-bound)" }</option>
                    <option value="passkey">{ "Passkey / WebAuthn" }</option>
                    <option value="password">{ "Password" }</option>
                    <option value="keyring">{ "OS keyring" }</option>
                </select>
                <label for="first-handle">{ "First user handle" }</label>
                <input id="first-handle" type="text" value={(*handle).clone()} placeholder="e.g. spencer" oninput={on_handle} />
                <label for="first-factor">{ "Unlock factor" }</label>
                <input id="first-factor" type="password" value={(*factor).clone()} placeholder="Password or passkey token" oninput={on_factor} />
                <button id="bootstrap-submit" type="submit" disabled={*busy}>{ "Create cell & first user" }</button>
                <div class="explainer" id="bootstrap-explainer">
                    <strong>{ "What happens next:" }</strong>
                    { " signing this creates the cell's genesis key, has it sign your first user's key \
                        and grant that user the add-users right, then revokes its own \u{2014} one atomic \
                        signed act. Nothing is sent to any third party; the keys are generated and sealed \
                        on this node." }
                </div>
                { match &*message {
                    Some((t, ok)) => html! { <div class={classes!("msg", if *ok {"ok"} else {"err"})} id="bootstrap-msg">{ t.clone() }</div> },
                    None => html! { <div class="msg" id="bootstrap-msg"></div> },
                } }
            </form>
        }
    }

    fn message_line(id: &'static str, message: &Option<String>) -> Html {
        match message {
            Some(t) => html! { <div class="msg" id={id} role="status">{ t.clone() }</div> },
            None => html! { <div class="msg" id={id} role="status"></div> },
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Phase {
        Loading,
        Fresh,
        Bootstrapped,
    }

    /// The `/` entry surface: the authenticated portal when signed in, else the
    /// bootstrap form (fresh node) or the two-field login (bootstrapped node),
    /// decided by `GET /bootstrap/status` on mount.
    #[function_component(PortalEntry)]
    pub fn portal_entry() -> Html {
        let auth = use_auth();
        let phase = use_state(|| Phase::Loading);

        {
            let phase = phase.clone();
            use_effect_with((), move |_| {
                let phase = phase.clone();
                spawn_local(async move {
                    let next = match http("GET", "/bootstrap/status", None).await {
                        Ok(r) if r.ok() => match BootstrapStatus::from_body(&r.body) {
                            Some(BootstrapStatus::Fresh) => Phase::Fresh,
                            // Default to login for a bootstrapped node OR an
                            // unreadable status (never a blank page).
                            _ => Phase::Bootstrapped,
                        },
                        _ => Phase::Bootstrapped,
                    };
                    phase.set(next);
                });
                || ()
            });
        }

        // An authenticated session never belongs on the public entry screen.
        // `guard()` already rewrites an authed Home/Login to the console home,
        // but redirect here too so any path that mounts PortalEntry with a live
        // session lands ON the console instead of the legacy single-page portal.
        if auth.is_authenticated() {
            return html! { <Redirect<Route> to={Route::Overview} /> };
        }

        let on_bootstrapped = {
            let phase = phase.clone();
            Callback::from(move |_handle: String| phase.set(Phase::Bootstrapped))
        };

        match *phase {
            Phase::Loading => html! { <p class="pillar-loading">{ "Loading\u{2026}" }</p> },
            Phase::Fresh => html! { <BootstrapForm on_bootstrapped={on_bootstrapped} /> },
            Phase::Bootstrapped => html! { <LoginForm /> },
        }
    }
}
