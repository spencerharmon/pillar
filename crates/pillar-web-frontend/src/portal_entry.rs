//! The portal's ROOT entry surface served at `/` — the piece that was missing
//! from the Yew migration and that made a `/`-cutover impossible without
//! regressing the operator's bootstrap/login gate.
//!
//! It reproduces, in Yew, the three states the old static `web_login.html`
//! served at `/`:
//!   * **Fresh node** (`GET /bootstrap/status` -> `FRESH`): the guided
//!     create-cell + create-first-user bootstrap form (ONE atomic
//!     `POST /bootstrap/create`, so a reload can never strand a cell with no
//!     user).
//!   * **Bootstrapped, not signed in**: the TWO-FIELD node-side custody login
//!     (identifier + unlock factor). The node resolves the offer, unlocks the
//!     operational key SERVER-SIDE, and signs the challenge — there is NO CID
//!     field. The flow is `GET /nonce` -> `POST /login` (per
//!     `pillar_web_api::{NonceResponse, LoginRequest, LoginResponse}`), and the
//!     `X-Pillar-Session` bearer token from the response admits the session.
//!   * **Signed in**: the authenticated dashboard (every migrated panel).
//!
//! The wire framing is built and parsed exclusively through the shared
//! `pillar-web-api` DTOs so the client and the `pillar-cli` server cannot
//! drift. The pure request/response helpers below are host-testable (no
//! `web-sys`/DOM), so `cargo test -p pillar-web-frontend` pins the framing and
//! the success/failure parsing; the components + `fetch` glue are behind the
//! `yew` feature (compiled into the real WASM bundle).

use pillar_web_api::{BootstrapCreateRequest, LoginRequest};

/// Build the exact `POST /login` body for the two human fields bound to a
/// prior `GET /nonce`'s id. Delegates to the shared DTO so the framing can
/// never diverge from the server's parser.
#[must_use]
pub fn login_wire(identifier: &str, password: &str, nonce_id: u64) -> String {
    LoginRequest {
        identifier: identifier.to_owned(),
        password: password.to_owned(),
        nonce_id,
    }
    .to_wire()
}

/// Interpret a `/login` response. On a 2xx `"OK <handle>"` body, returns the
/// admitted handle (falling back to the submitted identifier when the server
/// echoes no handle). Otherwise returns the human-facing failure reason with
/// the `DENIED` prefix stripped.
///
/// # Errors
/// Returns `Err(reason)` when the login was not admitted.
pub fn parse_login_result(ok: bool, body: &str, submitted_identifier: &str) -> Result<String, String> {
    let body = body.trim();
    if ok && body.starts_with("OK") {
        let handle = body.trim_start_matches("OK").trim();
        if handle.is_empty() {
            Ok(submitted_identifier.to_owned())
        } else {
            Ok(handle.to_owned())
        }
    } else {
        Err(strip_denied(body))
    }
}

/// Build the exact `POST /bootstrap/create` body for the atomic
/// create-cell + create-first-user step.
#[must_use]
pub fn bootstrap_wire(cell_id: &str, handle: &str, password: &str) -> String {
    BootstrapCreateRequest {
        cell_id: cell_id.to_owned(),
        handle: handle.to_owned(),
        password: password.to_owned(),
    }
    .to_wire()
}

/// Interpret a `/bootstrap/create` response: success iff a 2xx `BOOTSTRAPPED`
/// body, else the stripped failure reason.
///
/// # Errors
/// Returns `Err(reason)` when the node refused the bootstrap.
pub fn parse_bootstrap_result(ok: bool, body: &str) -> Result<(), String> {
    let body = body.trim();
    if ok && body.contains("BOOTSTRAPPED") {
        Ok(())
    } else {
        Err(strip_denied(body))
    }
}

/// Strip a leading `DENIED`/`MISSING` marker so the UI shows the bare reason.
fn strip_denied(body: &str) -> String {
    let trimmed = body
        .trim_start_matches("DENIED")
        .trim_start_matches("MISSING")
        .trim();
    if trimmed.is_empty() {
        "the node refused the request".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::PortalEntry;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{bootstrap_wire, login_wire, parse_bootstrap_result, parse_login_result};
    use crate::auth::{use_auth, AuthAction};
    use crate::panels::{Panel, ALL_PANELS};
    use pillar_web_api::{BootstrapStatus, NonceResponse};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::{spawn_local, JsFuture};
    use web_sys::{Headers, HtmlInputElement, RequestInit, RequestMode, Response};
    use yew::prelude::*;

    /// One `fetch` round trip. Returns `(status, body_text, session_token)`
    /// where `session_token` is the `X-Pillar-Session` response header when
    /// present (the login handler sets it on success). `body`, when `Some`,
    /// sends a `POST` with that text body; `None` is a plain `GET`.
    async fn request(
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String, Option<String>), JsValue> {
        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_mode(RequestMode::SameOrigin);
        if let Some(b) = body {
            opts.set_body(&JsValue::from_str(b));
        }
        let headers = Headers::new()?;
        opts.set_headers(&headers);

        let window = web_sys::window().expect("a browser window context");
        let resp_value = JsFuture::from(window.fetch_with_str_and_init(path, &opts)).await?;
        let resp: Response = resp_value.dyn_into()?;
        let status = resp.status();
        let token = resp.headers().get("X-Pillar-Session").ok().flatten();
        let text_value = JsFuture::from(resp.text()?).await?;
        let text = text_value.as_string().unwrap_or_default();
        Ok((status, text, token))
    }

    /// Read the current value of the `<input>` an event fired on.
    fn input_value(e: &InputEvent) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
            .map(|i| i.value())
            .unwrap_or_default()
    }

    /// The TWO-FIELD node-side custody login (identifier + unlock factor).
    /// `GET /nonce` -> `POST /login`; on success dispatches
    /// [`AuthAction::LoginSuccess`] with the handle + bearer token.
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
            let auth = auth.clone();
            let identifier = identifier.clone();
            let password = password.clone();
            let message = message.clone();
            let busy = busy.clone();
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                let auth = auth.clone();
                let id = (*identifier).clone();
                let pw = (*password).clone();
                let message = message.clone();
                let busy = busy.clone();
                if id.is_empty() || pw.is_empty() {
                    message.set(Some("Enter your identifier and unlock factor.".to_owned()));
                    return;
                }
                busy.set(true);
                message.set(Some("Signing in on the node\u{2026}".to_owned()));
                spawn_local(async move {
                    // 1. Fetch the origin/expiry-bound challenge.
                    let nonce = match request("GET", "/nonce", None).await {
                        Ok((s, body, _)) if (200..300).contains(&s) => {
                            NonceResponse::from_body(&body)
                        }
                        _ => None,
                    };
                    let Some(nonce) = nonce else {
                        message.set(Some("Could not reach the node for a challenge.".to_owned()));
                        busy.set(false);
                        return;
                    };
                    // 2. POST exactly the two fields (+ the nonce id).
                    let wire = login_wire(&id, &pw, nonce.id);
                    match request("POST", "/login", Some(&wire)).await {
                        Ok((status, body, token)) => {
                            match parse_login_result((200..300).contains(&status), &body, &id) {
                                Ok(handle) => {
                                    message.set(None);
                                    auth.dispatch(AuthAction::LoginSuccess {
                                        user: handle,
                                        token: token.unwrap_or_default(),
                                    });
                                }
                                Err(reason) => message.set(Some(reason)),
                            }
                        }
                        Err(_) => message.set(Some("The node could not be reached.".to_owned())),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <form class="pillar-login" onsubmit={on_submit}>
                <h2>{ "Sign in to manage your node" }</h2>
                <label for="identifier">{ "User identifier" }</label>
                <input id="identifier" r#type="text" value={(*identifier).clone()}
                    placeholder="you@pillar / username / genesis CID"
                    oninput={on_id} />
                <label for="password">{ "Unlock factor" }</label>
                <input id="password" r#type="password" value={(*password).clone()}
                    placeholder="Password or passkey token" oninput={on_pw} />
                <button type="submit" disabled={*busy}>{ "Sign in" }</button>
                if let Some(msg) = &*message {
                    <div class="msg" role="status">{ msg.clone() }</div>
                }
                <p class="hint">
                    { "Your credential is sent over TLS to this trusted node, which \
                       holds your key only because the cell sealed an offer to it. \
                       The node resolves your offer, unlocks your operational key, \
                       and signs a one-time challenge on your behalf." }
                </p>
            </form>
        }
    }

    /// Props for [`BootstrapForm`].
    #[derive(Properties, PartialEq)]
    pub struct BootstrapFormProps {
        /// Invoked with the created first-user handle once the node reports it
        /// bootstrapped, so the entry can flip to the login screen.
        pub on_bootstrapped: Callback<String>,
    }

    /// The first-run, operator-driven bootstrap: create the cell AND the first
    /// user in ONE atomic `POST /bootstrap/create`.
    #[function_component(BootstrapForm)]
    pub fn bootstrap_form(props: &BootstrapFormProps) -> Html {
        let cell = use_state(String::new);
        let handle = use_state(String::new);
        let factor = use_state(String::new);
        let message = use_state(|| None::<String>);
        let busy = use_state(|| false);

        let on_cell = {
            let cell = cell.clone();
            Callback::from(move |e: InputEvent| cell.set(input_value(&e)))
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
            let cell = cell.clone();
            let handle = handle.clone();
            let factor = factor.clone();
            let message = message.clone();
            let busy = busy.clone();
            let on_bootstrapped = props.on_bootstrapped.clone();
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                let cell_v = (*cell).clone();
                let handle_v = (*handle).clone();
                let factor_v = (*factor).clone();
                let message = message.clone();
                let busy = busy.clone();
                let on_bootstrapped = on_bootstrapped.clone();
                if cell_v.is_empty() || handle_v.is_empty() || factor_v.is_empty() {
                    message.set(Some("Enter a cell name, a handle, and an unlock factor.".to_owned()));
                    return;
                }
                busy.set(true);
                message.set(Some("Creating the cell and first user\u{2026}".to_owned()));
                spawn_local(async move {
                    let wire = bootstrap_wire(&cell_v, &handle_v, &factor_v);
                    match request("POST", "/bootstrap/create", Some(&wire)).await {
                        Ok((status, body, _)) => {
                            match parse_bootstrap_result((200..300).contains(&status), &body) {
                                Ok(()) => {
                                    message.set(None);
                                    on_bootstrapped.emit(handle_v.clone());
                                }
                                Err(reason) => message.set(Some(format!(
                                    "Could not bootstrap the node: {reason}"
                                ))),
                            }
                        }
                        Err(_) => message.set(Some("The node could not be reached.".to_owned())),
                    }
                    busy.set(false);
                });
            })
        };

        html! {
            <form class="pillar-bootstrap" onsubmit={on_submit}>
                <h2>{ "Set up this node \u{2014} create your cell and first user" }</h2>
                <label for="cell-id">{ "Cell name" }</label>
                <input id="cell-id" r#type="text" value={(*cell).clone()}
                    placeholder="e.g. spencer-cell" oninput={on_cell} />
                <label for="first-handle">{ "First user handle" }</label>
                <input id="first-handle" r#type="text" value={(*handle).clone()}
                    placeholder="e.g. spencer" oninput={on_handle} />
                <label for="first-factor">{ "Unlock factor" }</label>
                <input id="first-factor" r#type="password" value={(*factor).clone()}
                    placeholder="Password or passkey token" oninput={on_factor} />
                <button type="submit" disabled={*busy}>{ "Create cell & first user" }</button>
                if let Some(msg) = &*message {
                    <div class="msg" role="status">{ msg.clone() }</div>
                }
                <p class="hint">
                    { "This node has not been bootstrapped yet. Creating the cell \
                       and the first user happens in ONE atomic step so you can \
                       never be left with a cell but no way to add the first user." }
                </p>
            </form>
        }
    }

    /// The node's bootstrap state as the entry knows it.
    #[derive(Clone, Copy, PartialEq)]
    enum Phase {
        /// `GET /bootstrap/status` not yet answered.
        Loading,
        /// Fresh node — show the bootstrap form.
        Fresh,
        /// Bootstrapped — show the login form.
        Bootstrapped,
    }

    /// The `/` entry surface: renders the dashboard when signed in, else the
    /// bootstrap form on a fresh node or the two-field login on a bootstrapped
    /// one. Fetches `GET /bootstrap/status` on mount to decide.
    #[function_component(PortalEntry)]
    pub fn portal_entry() -> Html {
        let auth = use_auth();
        let phase = use_state(|| Phase::Loading);

        {
            let phase = phase.clone();
            use_effect_with((), move |_| {
                let phase = phase.clone();
                spawn_local(async move {
                    let next = match request("GET", "/bootstrap/status", None).await {
                        Ok((s, body, _)) if (200..300).contains(&s) => {
                            match BootstrapStatus::from_body(&body) {
                                Some(BootstrapStatus::Fresh) => Phase::Fresh,
                                // Default to the login screen for a
                                // bootstrapped node OR an unreadable status
                                // (never strand the operator on a blank page).
                                _ => Phase::Bootstrapped,
                            }
                        }
                        _ => Phase::Bootstrapped,
                    };
                    phase.set(next);
                });
                || ()
            });
        }

        // Signed in: the authenticated portal (every migrated panel).
        if auth.is_authenticated() {
            return html! {
                <div class="pillar-portal">
                    <h1>{ format!("Welcome{}", auth.user.as_deref().map(|u| format!(", {u}")).unwrap_or_default()) }</h1>
                    { for ALL_PANELS.iter().map(|spec| html! { <Panel spec={*spec} /> }) }
                </div>
            };
        }

        // After a successful bootstrap, flip to the login screen.
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

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_web_api::{BootstrapStatus, NonceResponse};

    #[test]
    fn login_wire_matches_the_server_parser() {
        let wire = login_wire("spencer@pillar", "hunter2", 7);
        let parsed = pillar_web_api::LoginRequest::from_body(&wire);
        assert_eq!(parsed.identifier, "spencer@pillar");
        assert_eq!(parsed.password, "hunter2");
        assert_eq!(parsed.nonce_id, 7);
    }

    #[test]
    fn login_success_yields_the_greeted_handle() {
        assert_eq!(
            parse_login_result(true, "OK spencer\n", "spencer@pillar"),
            Ok("spencer".to_owned())
        );
    }

    #[test]
    fn login_success_without_echoed_handle_falls_back_to_identifier() {
        assert_eq!(
            parse_login_result(true, "OK", "spencer@pillar"),
            Ok("spencer@pillar".to_owned())
        );
    }

    #[test]
    fn login_denied_surfaces_the_bare_reason() {
        assert_eq!(
            parse_login_result(false, "DENIED bad-unlock-factor", "x"),
            Err("bad-unlock-factor".to_owned())
        );
        // A non-2xx status with an OK-looking body is still a failure.
        assert!(parse_login_result(false, "OK spencer", "x").is_err());
    }

    #[test]
    fn bootstrap_wire_matches_the_server_parser() {
        let wire = bootstrap_wire("spencer-cell", "spencer", "pw");
        let parsed = pillar_web_api::BootstrapCreateRequest::from_body(&wire);
        assert_eq!(parsed.cell_id, "spencer-cell");
        assert_eq!(parsed.handle, "spencer");
        assert_eq!(parsed.password, "pw");
    }

    #[test]
    fn bootstrap_success_and_failure() {
        assert_eq!(parse_bootstrap_result(true, "BOOTSTRAPPED spencer"), Ok(()));
        assert_eq!(
            parse_bootstrap_result(false, "DENIED CellNameInUse"),
            Err("CellNameInUse".to_owned())
        );
    }

    #[test]
    fn shared_status_and_nonce_dtos_parse_the_server_framing() {
        assert_eq!(BootstrapStatus::from_body("FRESH"), Some(BootstrapStatus::Fresh));
        assert_eq!(
            BootstrapStatus::from_body("BOOTSTRAPPED"),
            Some(BootstrapStatus::Bootstrapped)
        );
        let n = NonceResponse::from_body("NONCE 42 99").expect("parses");
        assert_eq!(n.id, 42);
    }
}
