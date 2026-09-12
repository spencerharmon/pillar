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
    use crate::webauthn;
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
                    message.set(Some("Signing in on the node…".to_owned()));
                    match http("POST", "/login", Some(&login_wire(&id, &pw, nonce.id))).await {
                        Ok(r) => {
                            // A user with an enrolled WebAuthn credential gets a
                            // `NEEDS-2FA <handle>` challenge instead of a live
                            // session: the password admitted, but a second
                            // factor is REQUIRED. Drive the assertion ceremony
                            // with the returned pending token; only its success
                            // promotes a real session.
                            let body = r.body.trim().to_owned();
                            if r.ok() && body.starts_with("NEEDS-2FA") {
                                let handle = body
                                    .strip_prefix("NEEDS-2FA")
                                    .map(str::trim)
                                    .filter(|h| !h.is_empty())
                                    .unwrap_or(&id)
                                    .to_owned();
                                let ptoken = r.session_token.clone().unwrap_or_default();
                                message.set(Some(
                                    "Touch your security key / passkey to finish signing in…"
                                        .to_owned(),
                                ));
                                match webauthn::run_authenticate(&ptoken).await {
                                    Ok(fin) => match fin.session_token {
                                        Some(real) if !real.is_empty() => {
                                            message.set(None);
                                            auth.dispatch(AuthAction::LoginSuccess {
                                                user: handle,
                                                token: real,
                                                force_password_change: false,
                                            });
                                        }
                                        _ => message.set(Some(friendly_error(
                                            "second factor did not complete",
                                        ))),
                                    },
                                    Err(e) => message.set(Some(e.message())),
                                }
                            } else {
                                match interpret_login(r.ok(), &r.body, &id) {
                                    Ok(handle) => {
                                        message.set(None);
                                        auth.dispatch(AuthAction::LoginSuccess {
                                            user: handle,
                                            token: r.session_token.unwrap_or_default(),
                                            force_password_change: false,
                                        });
                                    }
                                    Err(reason) => message.set(Some(friendly_error(&reason))),
                                }
                            }
                        }
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
        /// Called when the first user chose a HARDWARE second factor: carries
        /// `(session_token, handle, factor)` from the post-bootstrap auto-login
        /// so the entry transitions to the WebAuthn enrollment panel.
        pub on_enroll: Callback<(String, String, String)>,
    }

    /// The first-run bootstrap: create the cell AND first user in ONE atomic
    /// `POST /bootstrap/create`, with a live cell-name uniqueness hint and the
    /// what-happens-next explainer.
    #[function_component(BootstrapForm)]
    pub fn bootstrap_form(props: &BootstrapFormProps) -> Html {
        let cell = use_state(String::new);
        let handle = use_state(String::new);
        let factor = use_state(String::new);
        let second_factor = use_state(|| "password".to_owned());
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
        let on_second_factor = {
            let second_factor = second_factor.clone();
            Callback::from(move |e: Event| {
                if let Some(sel) = e.target_dyn_into::<web_sys::HtmlSelectElement>() {
                    second_factor.set(sel.value());
                }
            })
        };

        let on_submit = {
            let (cell, handle, factor, second_factor, message, busy) = (
                cell.clone(),
                handle.clone(),
                factor.clone(),
                second_factor.clone(),
                message.clone(),
                busy.clone(),
            );
            let on_bootstrapped = props.on_bootstrapped.clone();
            let on_enroll = props.on_enroll.clone();
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                if *busy {
                    return;
                }
                let (cell_v, handle_v, factor_v, second_factor_v) = (
                    (*cell).clone(),
                    (*handle).clone(),
                    (*factor).clone(),
                    (*second_factor).clone(),
                );
                let (message, busy, on_bootstrapped, on_enroll) = (
                    message.clone(),
                    busy.clone(),
                    on_bootstrapped.clone(),
                    on_enroll.clone(),
                );
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
                    let body =
                        bootstrap_wire(cell_v.trim(), handle_v.trim(), &factor_v, &second_factor_v);
                    match http("POST", "/bootstrap/create", Some(&body)).await {
                        Ok(r) => match interpret_bootstrap(r.ok(), &r.body) {
                            Ok(()) => {
                                if second_factor_v != "password" {
                                    // A hardware second factor was chosen: sign
                                    // in now (no credential enrolled yet, so the
                                    // password alone yields a full session) to
                                    // get a token, then hand off to the WebAuthn
                                    // enrollment panel which prompts the device.
                                    message.set(Some((
                                        "Cell created. Signing in to enroll your security key…"
                                            .to_owned(),
                                        true,
                                    )));
                                    let nonce = match http("GET", "/nonce", None).await {
                                        Ok(r) if r.ok() => NonceResponse::from_body(&r.body),
                                        _ => None,
                                    };
                                    match nonce {
                                        Some(n) => match http(
                                            "POST",
                                            "/login",
                                            Some(&login_wire(handle_v.trim(), &factor_v, n.id)),
                                        )
                                        .await
                                        {
                                            Ok(r) if r.ok() => {
                                                let token = r.session_token.unwrap_or_default();
                                                on_enroll.emit((
                                                    token,
                                                    handle_v.trim().to_owned(),
                                                    second_factor_v.clone(),
                                                ));
                                            }
                                            _ => message.set(Some((
                                                "Created the cell, but could not sign in to \
                                                 enroll your key. Reload and sign in with your \
                                                 password to try again."
                                                    .to_owned(),
                                                false,
                                            ))),
                                        },
                                        None => message.set(Some((
                                            "Created the cell, but could not reach the node to \
                                             enroll your key."
                                                .to_owned(),
                                            false,
                                        ))),
                                    }
                                } else {
                                    message.set(Some((
                                        "Cell and first user created. This node is now bootstrapped \u{2014} sign in below.".to_owned(),
                                        true,
                                    )));
                                    on_bootstrapped.emit(handle_v.trim().to_owned());
                                }
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
                <input id="cell-id" type="text" value={(*cell).clone()} placeholder="your cell name" oninput={on_cell} />
                <div id="cell-name-hint" class={hint_cls}>{ hint_text }</div>
                <label for="first-handle">{ "First user handle" }</label>
                <input id="first-handle" type="text" value={(*handle).clone()} placeholder="choose a handle" oninput={on_handle} />
                <label for="first-factor">{ "Unlock factor" }</label>
                <input id="first-factor" type="password" value={(*factor).clone()} placeholder="Password or passkey token" oninput={on_factor} />
                <label for="first-2fa">{ "First user second factor (2FA)" }</label>
                <select id="first-2fa" onchange={on_second_factor}>
                    <option value="password" selected={*second_factor == "password"}>{ "None (password only)" }</option>
                    <option value="passkey" selected={*second_factor == "passkey"}>{ "Passkey / WebAuthn (FIDO2)" }</option>
                </select>
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

    /// Props for [`EnrollPanel`].
    #[derive(Properties, PartialEq)]
    pub struct EnrollPanelProps {
        /// The live session token from the post-bootstrap auto-login.
        pub token: String,
        /// The first user's handle (the credential's user handle).
        pub handle: String,
        /// The chosen factor (`passkey`), for the prompt copy.
        pub factor: String,
    }

    /// The WebAuthn/FIDO2 **enrollment** step shown right after a first-user
    /// bootstrap that selected a hardware second factor. It drives the REAL
    /// browser registration ceremony (`navigator.credentials.create()` →
    /// `POST /webauthn/register/finish`) so the operator is actually prompted to
    /// touch/unlock the device. On success the already-live session lands on the
    /// console; from then on the authenticator is REQUIRED at every login.
    #[function_component(EnrollPanel)]
    pub fn enroll_panel(props: &EnrollPanelProps) -> Html {
        let auth = use_auth();
        let busy = use_state(|| true);
        let error = use_state(|| None::<String>);
        let attempt = use_state(|| 0u32);

        {
            let (auth, busy, error) = (auth.clone(), busy.clone(), error.clone());
            let (token, handle) = (props.token.clone(), props.handle.clone());
            use_effect_with(*attempt, move |_| {
                let (auth, busy, error) = (auth.clone(), busy.clone(), error.clone());
                let (token, handle) = (token.clone(), handle.clone());
                busy.set(true);
                error.set(None);
                spawn_local(async move {
                    match webauthn::run_register(&token, &handle, "").await {
                        Ok(_cred) => {
                            // Enrolled + journaled server-side. The session is
                            // already live; land on the console. Every future
                            // login now REQUIRES this device.
                            auth.dispatch(AuthAction::LoginSuccess {
                                user: handle,
                                token,
                                force_password_change: false,
                            });
                        }
                        Err(e) => {
                            error.set(Some(e.message()));
                            busy.set(false);
                        }
                    }
                });
                || ()
            });
        }

        let factor_label = match props.factor.as_str() {
            "passkey" => "passkey / security key (WebAuthn)",
            other => other,
        };
        let on_retry = {
            let attempt = attempt.clone();
            Callback::from(move |_: MouseEvent| attempt.set(*attempt + 1))
        };

        html! {
            <div class="pillar-enroll">
                <h2>{ "Enroll your second factor" }</h2>
                <p>{ format!("Registering your {factor_label}. Follow your browser's prompt and touch or unlock the device.") }</p>
                if *busy {
                    <p class="pillar-enroll__status">{ "Waiting for your authenticator\u{2026}" }</p>
                }
                if let Some(err) = &*error {
                    <>
                        <p class="pillar-enroll__error" role="alert">{ err.clone() }</p>
                        <button type="button" onclick={on_retry}>{ "Try again" }</button>
                    </>
                }
            </div>
        }
    }

    #[derive(Clone, PartialEq)]
    enum Phase {
        Loading,
        Fresh,
        Bootstrapped,
        /// A first user was just created WITH a hardware second factor selected:
        /// enroll the authenticator now (browser WebAuthn ceremony) before
        /// landing on the console. Carries the freshly-minted session token (from
        /// the post-bootstrap auto-login), the handle, and the chosen factor.
        Enroll {
            token: String,
            handle: String,
            factor: String,
        },
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
        let on_enroll = {
            let phase = phase.clone();
            Callback::from(move |(token, handle, factor): (String, String, String)| {
                phase.set(Phase::Enroll {
                    token,
                    handle,
                    factor,
                })
            })
        };

        match (*phase).clone() {
            Phase::Loading => html! { <p class="pillar-loading">{ "Loading\u{2026}" }</p> },
            Phase::Fresh => {
                html! { <BootstrapForm on_bootstrapped={on_bootstrapped} on_enroll={on_enroll} /> }
            }
            Phase::Bootstrapped => html! { <LoginForm /> },
            Phase::Enroll {
                token,
                handle,
                factor,
            } => html! { <EnrollPanel token={token} handle={handle} factor={factor} /> },
        }
    }
}
