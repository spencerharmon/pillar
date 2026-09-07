//! The portal's **browser WebAuthn ceremony** — the "register a security key"
//! and "sign in with a security key" flows that replace the old fake
//! "passkey" control (a `type=password` field with a label).
//!
//! Registration runs `navigator.credentials.create()` against a
//! `POST /webauthn/register/begin` challenge and posts the attestation to
//! `POST /webauthn/register/finish`; authentication runs
//! `navigator.credentials.get()` against a `POST /webauthn/authenticate/begin`
//! challenge and posts the assertion to `POST /webauthn/authenticate/finish`.
//! password/passphrase custody remains a supported fallback login path.
//!
//! The RP's wire protocol (see `pillar-cli`'s `web_serve` dispatchers
//! `dispatch_webauthn_register_begin`/`_finish`/`dispatch_webauthn_authenticate_*`)
//! is a **plain line-based text protocol**, not JSON — every request/response
//! body builder/parser in this module matches that contract exactly, byte for
//! byte, so a real browser round trip actually works against the real server.
//!
//! ## Why the ceremony sequencing is host-testable
//!
//! The real ceremony touches two browser-only surfaces: the network (the
//! begin/finish HTTP calls) and `navigator.credentials` (a
//! [`web_sys::CredentialsContainer`]). Both are abstracted behind the
//! [`RpTransport`] and [`CredentialCeremony`] traits, so the ORCHESTRATION —
//! the exact begin→create/get→finish request sequence, the wire payload
//! shapes, and the error-path messaging — is pure Rust, asserted with a
//! native `cargo test` against a mocked transport + authenticator (see the
//! tests below). The real, DOM-touching [`BrowserTransport`] /
//! [`BrowserCeremony`] impls (behind the `yew` feature) drive the actual
//! `fetch` + `navigator.credentials.create()/get()` calls, reusing these same
//! wire build/parse functions so the wire contract is defined exactly once.

use std::fmt;

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// A user-facing ceremony failure. Every variant carries its own
/// plain-language message via [`CeremonyError::message`] — no raw JS
/// exception text ever leaks to the user. `NoAuthenticator`, `UserCancelled`,
/// and `Unsupported` are the three browser-side conditions the ROI calls out
/// explicitly; each message points the user at the password/passphrase
/// fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyError {
    /// This browser has no WebAuthn / `navigator.credentials` support.
    Unsupported,
    /// No authenticator was available to satisfy the ceremony (no security
    /// key present / no platform authenticator).
    NoAuthenticator,
    /// The user dismissed or cancelled the browser's ceremony prompt.
    UserCancelled,
    /// A begin/finish HTTP call failed, or the RP refused the request (its
    /// `DENIED <reason>` fail-closed response).
    Network(String),
    /// The server's challenge, or the authenticator's response, could not be
    /// parsed into the expected wire shape.
    Protocol(String),
}

impl CeremonyError {
    /// The clear, in-UI message for this failure.
    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeremonyError::Unsupported => write!(
                f,
                "This browser does not support security keys. Sign in with your password instead."
            ),
            CeremonyError::NoAuthenticator => write!(
                f,
                "No security key was found. Plug in a security key or use a device with built-in \
                 biometrics, or sign in with your password instead."
            ),
            CeremonyError::UserCancelled => write!(
                f,
                "The security key prompt was cancelled. Try again, or sign in with your password \
                 instead."
            ),
            CeremonyError::Network(detail) => {
                write!(f, "Could not complete the security key request: {detail}")
            }
            CeremonyError::Protocol(detail) => {
                write!(f, "Unexpected response from the server: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------
// Ceremony data
// ---------------------------------------------------------------------

/// A pending registration ceremony: the begin challenge plus the rp id/user
/// handle `navigator.credentials.create()` needs, exactly as
/// `dispatch_webauthn_register_begin` returns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterChallenge {
    /// Base64url-encoded random challenge.
    pub challenge_b64: String,
    /// The WebAuthn relying-party id (the portal's origin host).
    pub rp_id: String,
    /// The user handle being enrolled.
    pub user_handle: String,
}

/// The attestation a registration ceremony's `create()` step produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The new credential's id (base64url).
    pub credential_id_b64: String,
    /// The base64url-encoded CBOR attestation object.
    pub attestation_object_b64: String,
}

/// A pending authentication ceremony: the begin challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// Base64url-encoded random challenge.
    pub challenge_b64: String,
}

/// The assertion an authentication ceremony's `get()` step produces,
/// including the PRF extension output the RP derives the operational-key
/// unlock secret from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The asserting credential's id (base64url).
    pub credential_id_b64: String,
    /// The base64url-encoded authenticator data.
    pub authenticator_data_b64: String,
    /// The base64url-encoded `clientDataJSON`.
    pub client_data_json_b64: String,
    /// The base64url-encoded signature.
    pub signature_b64: String,
    /// The base64url-encoded PRF extension output.
    pub prf_output_b64: String,
}

// ---------------------------------------------------------------------
// Wire build/parse — the RP's plain-text protocol, owned exactly once.
// ---------------------------------------------------------------------

/// `POST /webauthn/register/begin` request body: `<token>\n<user_handle>`.
pub fn register_begin_body(token: &str, user_handle: &str) -> String {
    format!("{token}\n{user_handle}")
}

/// Parses a `/webauthn/register/begin` response: `CHALLENGE <b64> <rp_id>
/// <user_handle>`.
pub fn parse_register_begin(body: &str) -> Result<RegisterChallenge, CeremonyError> {
    let mut parts = body.trim().splitn(4, ' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("CHALLENGE"), Some(challenge), Some(rp_id), Some(user_handle))
            if !challenge.is_empty() && !rp_id.is_empty() && !user_handle.is_empty() =>
        {
            Ok(RegisterChallenge {
                challenge_b64: challenge.to_owned(),
                rp_id: rp_id.to_owned(),
                user_handle: user_handle.to_owned(),
            })
        }
        _ => Err(CeremonyError::Protocol(format!(
            "malformed register/begin response: {body:?}"
        ))),
    }
}

/// `POST /webauthn/register/finish` request body:
/// `<token>\n<user_handle>\n<challenge_b64>\n<attestation_object_b64>`.
pub fn register_finish_body(
    token: &str,
    user_handle: &str,
    challenge_b64: &str,
    attestation: &Attestation,
) -> String {
    format!(
        "{token}\n{user_handle}\n{challenge_b64}\n{}",
        attestation.attestation_object_b64
    )
}

/// Parses a `/webauthn/register/finish` response: `REGISTERED <cred_b64>`.
pub fn parse_register_finish(body: &str) -> Result<String, CeremonyError> {
    let mut parts = body.trim().splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some("REGISTERED"), Some(cred)) if !cred.is_empty() => Ok(cred.to_owned()),
        _ => Err(CeremonyError::Protocol(format!(
            "malformed register/finish response: {body:?}"
        ))),
    }
}

/// `POST /webauthn/authenticate/begin` request body: `<token>`.
pub fn authenticate_begin_body(token: &str) -> String {
    token.to_owned()
}

/// Parses a `/webauthn/authenticate/begin` response: `CHALLENGE <b64>`.
pub fn parse_authenticate_begin(body: &str) -> Result<AuthChallenge, CeremonyError> {
    let mut parts = body.trim().splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some("CHALLENGE"), Some(challenge)) if !challenge.is_empty() => Ok(AuthChallenge {
            challenge_b64: challenge.to_owned(),
        }),
        _ => Err(CeremonyError::Protocol(format!(
            "malformed authenticate/begin response: {body:?}"
        ))),
    }
}

/// `POST /webauthn/authenticate/finish` request body:
/// `<token>\n<challenge_b64>\n<cred_b64>\n<authenticator_data_b64>\n
/// <client_data_json_b64>\n<signature_b64>\n<prf_output_b64>`.
pub fn authenticate_finish_body(
    token: &str,
    challenge_b64: &str,
    assertion: &Assertion,
) -> String {
    format!(
        "{token}\n{challenge_b64}\n{}\n{}\n{}\n{}\n{}",
        assertion.credential_id_b64,
        assertion.authenticator_data_b64,
        assertion.client_data_json_b64,
        assertion.signature_b64,
        assertion.prf_output_b64,
    )
}

/// Parses a `/webauthn/authenticate/finish` response: `UNLOCKED <b64>`.
pub fn parse_authenticate_finish(body: &str) -> Result<String, CeremonyError> {
    let mut parts = body.trim().splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some("UNLOCKED"), Some(unlock)) if !unlock.is_empty() => Ok(unlock.to_owned()),
        _ => Err(CeremonyError::Protocol(format!(
            "malformed authenticate/finish response: {body:?}"
        ))),
    }
}

/// Maps a non-2xx RP HTTP response to a [`CeremonyError`]. The RP's
/// `DENIED <reason>` fail-closed bodies (see `pillar-cli`'s
/// `webauthn_rp_error`) surface verbatim.
pub fn map_error_response(status: u16, body: &str) -> CeremonyError {
    let reason = body.trim().strip_prefix("DENIED ").unwrap_or(body.trim());
    CeremonyError::Network(format!("{status} {reason}"))
}

// ---------------------------------------------------------------------
// The two browser-only surfaces — abstracted for host-testability.
// ---------------------------------------------------------------------

/// One RP endpoint a ceremony posts to, in the order the two flows exercise
/// them. Doubles as the request-sequence a [`RpTransport`] mock records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST /webauthn/register/begin`.
    RegisterBegin,
    /// `POST /webauthn/register/finish`.
    RegisterFinish,
    /// `POST /webauthn/authenticate/begin`.
    AuthenticateBegin,
    /// `POST /webauthn/authenticate/finish`.
    AuthenticateFinish,
}

impl Endpoint {
    /// The request path this endpoint posts to.
    pub fn path(self) -> &'static str {
        match self {
            Endpoint::RegisterBegin => "/webauthn/register/begin",
            Endpoint::RegisterFinish => "/webauthn/register/finish",
            Endpoint::AuthenticateBegin => "/webauthn/authenticate/begin",
            Endpoint::AuthenticateFinish => "/webauthn/authenticate/finish",
        }
    }
}

/// The begin/finish HTTP transport, abstracted so the ceremony's request
/// sequence is host-testable. The real impl ([`BrowserTransport`], behind
/// `yew`) posts with `gloo-net`/`fetch`; a test impl records the endpoints hit
/// and returns canned bodies.
pub trait RpTransport {
    /// POST the wire `body` to `endpoint`, returning the raw response body.
    fn post(&self, endpoint: Endpoint, body: &str) -> Result<String, CeremonyError>;
}

/// The browser `navigator.credentials` surface, abstracted so the ceremony is
/// host-testable against a mock. The real impl ([`BrowserCeremony`], behind
/// `yew`) calls `web_sys::CredentialsContainer`; a test impl returns canned
/// results or the error conditions the flows must handle.
pub trait CredentialCeremony {
    /// `navigator.credentials.create()` against the begin challenge.
    fn create(&self, challenge: &RegisterChallenge) -> Result<Attestation, CeremonyError>;
    /// `navigator.credentials.get()` against the begin challenge.
    fn get(&self, challenge: &AuthChallenge) -> Result<Assertion, CeremonyError>;
}

/// Drives the full "register a security key" ceremony: `begin` → `create()` →
/// `finish`. Returns the new credential id (base64url) on success. On a
/// `create()` failure (no authenticator / cancelled / unsupported), `finish`
/// is never posted.
pub fn register(
    transport: &impl RpTransport,
    ceremony: &impl CredentialCeremony,
    token: &str,
    user_handle: &str,
) -> Result<String, CeremonyError> {
    let begin_resp = transport.post(Endpoint::RegisterBegin, &register_begin_body(token, user_handle))?;
    let challenge = parse_register_begin(&begin_resp)?;
    let attestation = ceremony.create(&challenge)?;
    let finish_resp = transport.post(
        Endpoint::RegisterFinish,
        &register_finish_body(token, user_handle, &challenge.challenge_b64, &attestation),
    )?;
    parse_register_finish(&finish_resp)
}

/// Drives the full "sign in with a security key" ceremony: `begin` → `get()`
/// → `finish`. Returns the unlock secret (base64url) on success. On a `get()`
/// failure, `finish` is never posted.
pub fn authenticate(
    transport: &impl RpTransport,
    ceremony: &impl CredentialCeremony,
    token: &str,
) -> Result<String, CeremonyError> {
    let begin_resp = transport.post(Endpoint::AuthenticateBegin, &authenticate_begin_body(token))?;
    let challenge = parse_authenticate_begin(&begin_resp)?;
    let assertion = ceremony.get(&challenge)?;
    let finish_resp = transport.post(
        Endpoint::AuthenticateFinish,
        &authenticate_finish_body(token, &challenge.challenge_b64, &assertion),
    )?;
    parse_authenticate_finish(&finish_resp)
}

// ---------------------------------------------------------------------
// The real, DOM-touching implementations (behind `yew`).
// ---------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use browser::{run_authenticate, run_register, BrowserCeremony, BrowserTransport};

#[cfg(feature = "yew")]
mod browser {
    use super::*;
    use gloo_net::http::Request;
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, AuthenticatorResponse,
        CredentialCreationOptions, CredentialRequestOptions, CredentialsContainer,
        PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
        PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    };

    /// Base64url (no padding) decode, per the WebAuthn wire convention every
    /// RP payload here uses.
    fn b64_decode(s: &str) -> Result<Vec<u8>, CeremonyError> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| CeremonyError::Protocol(format!("bad base64url: {e}")))
    }

    /// Base64url (no padding) encode.
    fn b64_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn array_buffer_to_b64(buf: &js_sys::ArrayBuffer) -> String {
        b64_encode(&Uint8Array::new(buf).to_vec())
    }

    fn js_err(e: JsValue) -> CeremonyError {
        // `DOMException.name` distinguishes user-cancel/no-authenticator from
        // any other browser-side failure; anything unrecognized is folded
        // into `Unsupported` since the caller has no better fallback.
        if let Some(name) = Reflect::get(&e, &JsValue::from_str("name"))
            .ok()
            .and_then(|v| v.as_string())
        {
            match name.as_str() {
                "NotAllowedError" => return CeremonyError::UserCancelled,
                "InvalidStateError" | "NotSupportedError" => return CeremonyError::NoAuthenticator,
                _ => {}
            }
        }
        CeremonyError::Unsupported
    }

    fn navigator_credentials() -> Result<CredentialsContainer, CeremonyError> {
        web_sys::window()
            .and_then(|w| w.navigator().credentials().into())
            .ok_or(CeremonyError::Unsupported)
    }

    /// The real `POST /webauthn/*` transport, driven with `gloo-net`'s
    /// `fetch`-backed `Request`.
    pub struct BrowserTransport {
        /// The origin the ceremony endpoints are relative to (empty for
        /// same-origin relative requests).
        pub base_url: String,
    }

    impl BrowserTransport {
        /// A transport posting to same-origin relative `/webauthn/*` paths.
        pub fn new() -> Self {
            BrowserTransport { base_url: String::new() }
        }

        async fn post_async(&self, endpoint: Endpoint, body: String) -> Result<String, CeremonyError> {
            let url = format!("{}{}", self.base_url, endpoint.path());
            let resp = Request::post(&url)
                .header("Content-Type", "text/plain")
                .body(body)
                .map_err(|e| CeremonyError::Network(e.to_string()))?
                .send()
                .await
                .map_err(|e| CeremonyError::Network(e.to_string()))?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| CeremonyError::Network(e.to_string()))?;
            if !(200..300).contains(&status) {
                return Err(map_error_response(status, &text));
            }
            Ok(text)
        }
    }

    impl Default for BrowserTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    /// The real `navigator.credentials` ceremony, driven with `web_sys`.
    pub struct BrowserCeremony;

    impl BrowserCeremony {
        async fn create_async(
            &self,
            challenge: &RegisterChallenge,
        ) -> Result<Attestation, CeremonyError> {
            let creds = navigator_credentials()?;
            let challenge_bytes = b64_decode(&challenge.challenge_b64)?;
            let mut challenge_bytes = challenge_bytes;
            let rp = PublicKeyCredentialRpEntity::new(&challenge.rp_id);
            let user_id = Uint8Array::from(challenge.user_handle.as_bytes());
            let user = PublicKeyCredentialUserEntity::new_with_u8_array(
                &challenge.user_handle,
                &challenge.user_handle,
                &user_id,
            );
            let params = Array::new();
            // ES256 (-7): the only algorithm `pillar_crypto::webauthn` verifies.
            params.push(&PublicKeyCredentialParameters::new(
                -7,
                PublicKeyCredentialType::PublicKey,
            ));
            let pkc_options = PublicKeyCredentialCreationOptions::new_with_u8_slice(
                &mut challenge_bytes,
                &params,
                &rp,
                &user,
            );
            let options = CredentialCreationOptions::new();
            options.set_public_key(&pkc_options);
            let promise = creds
                .create_with_options(&options)
                .map_err(js_err)?;
            let cred = JsFuture::from(promise).await.map_err(js_err)?;
            let cred: PublicKeyCredential = cred.dyn_into().map_err(|_| CeremonyError::Unsupported)?;
            let credential_id_b64 = Object::from(cred.clone().unchecked_into::<Object>());
            // `Credential.id` is already the base64url credential id per spec.
            let credential_id_b64 = Reflect::get(&credential_id_b64, &JsValue::from_str("id"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            let response: AuthenticatorResponse = cred.response();
            let attestation_response: &AuthenticatorAttestationResponse = response.unchecked_ref();
            let attestation_object_b64 =
                array_buffer_to_b64(&attestation_response.attestation_object());
            Ok(Attestation {
                credential_id_b64,
                attestation_object_b64,
            })
        }

        async fn get_async(&self, challenge: &AuthChallenge) -> Result<Assertion, CeremonyError> {
            let creds = navigator_credentials()?;
            let mut challenge_bytes = b64_decode(&challenge.challenge_b64)?;
            let pkc_options =
                PublicKeyCredentialRequestOptions::new_with_u8_slice(&mut challenge_bytes);
            let options = CredentialRequestOptions::new();
            options.set_public_key(&pkc_options);
            let promise = creds.get_with_options(&options).map_err(js_err)?;
            let cred = JsFuture::from(promise).await.map_err(js_err)?;
            let cred: PublicKeyCredential = cred.dyn_into().map_err(|_| CeremonyError::Unsupported)?;
            let credential_id_b64 = Reflect::get(&cred, &JsValue::from_str("id"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            let response: AuthenticatorResponse = cred.response();
            let assertion_response: &AuthenticatorAssertionResponse = response.unchecked_ref();
            let authenticator_data_b64 =
                array_buffer_to_b64(&assertion_response.authenticator_data());
            let client_data_json_b64 = array_buffer_to_b64(&response.client_data_json());
            let signature_b64 = array_buffer_to_b64(&assertion_response.signature());
            // The PRF extension's evaluated output, if the authenticator
            // supports the `prf` extension (best-effort: an authenticator
            // without PRF support simply yields an empty output and the RP
            // fails closed on an empty/short unlock derivation).
            let ext: JsValue = cred.get_client_extension_results().into();
            let prf_output_b64 = Some(ext)
                .and_then(|ext| Reflect::get(&ext, &JsValue::from_str("prf")).ok())
                .and_then(|prf| Reflect::get(&prf, &JsValue::from_str("results")).ok())
                .and_then(|results| Reflect::get(&results, &JsValue::from_str("first")).ok())
                .and_then(|first| first.dyn_into::<js_sys::ArrayBuffer>().ok())
                .map(|buf| array_buffer_to_b64(&buf))
                .unwrap_or_default();
            Ok(Assertion {
                credential_id_b64,
                authenticator_data_b64,
                client_data_json_b64,
                signature_b64,
                prf_output_b64,
            })
        }
    }

    impl Default for BrowserCeremony {
        fn default() -> Self {
            BrowserCeremony
        }
    }

    /// Runs the real "register a security key" ceremony end to end in the
    /// browser: `POST /webauthn/register/begin` → `navigator.credentials
    /// .create()` → `POST /webauthn/register/finish`. Returns the new
    /// credential id (base64url) on success.
    pub async fn run_register(token: &str, user_handle: &str) -> Result<String, CeremonyError> {
        let transport = BrowserTransport::new();
        let ceremony = BrowserCeremony;
        let begin_resp = transport
            .post_async(Endpoint::RegisterBegin, register_begin_body(token, user_handle))
            .await?;
        let challenge = parse_register_begin(&begin_resp)?;
        let attestation = ceremony.create_async(&challenge).await?;
        let finish_resp = transport
            .post_async(
                Endpoint::RegisterFinish,
                register_finish_body(token, user_handle, &challenge.challenge_b64, &attestation),
            )
            .await?;
        parse_register_finish(&finish_resp)
    }

    /// Runs the real "sign in with a security key" ceremony end to end in the
    /// browser: `POST /webauthn/authenticate/begin` → `navigator.credentials
    /// .get()` → `POST /webauthn/authenticate/finish`. Returns the unlock
    /// secret (base64url) on success.
    pub async fn run_authenticate(token: &str) -> Result<String, CeremonyError> {
        let transport = BrowserTransport::new();
        let ceremony = BrowserCeremony;
        let begin_resp = transport
            .post_async(Endpoint::AuthenticateBegin, authenticate_begin_body(token))
            .await?;
        let challenge = parse_authenticate_begin(&begin_resp)?;
        let assertion = ceremony.get_async(&challenge).await?;
        let finish_resp = transport
            .post_async(
                Endpoint::AuthenticateFinish,
                authenticate_finish_body(token, &challenge.challenge_b64, &assertion),
            )
            .await?;
        parse_authenticate_finish(&finish_resp)
    }
}

// ---------------------------------------------------------------------
// Tests — the ceremony ORCHESTRATION, host-tested against mocks.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every endpoint hit, in order, and returns pre-programmed
    /// responses (or a network failure) per endpoint.
    struct MockTransport {
        steps: RefCell<Vec<Endpoint>>,
        responses: Vec<(Endpoint, Result<&'static str, CeremonyError>)>,
    }

    impl MockTransport {
        fn new(responses: Vec<(Endpoint, Result<&'static str, CeremonyError>)>) -> Self {
            MockTransport { steps: RefCell::new(Vec::new()), responses }
        }
    }

    impl RpTransport for MockTransport {
        fn post(&self, endpoint: Endpoint, _body: &str) -> Result<String, CeremonyError> {
            self.steps.borrow_mut().push(endpoint);
            self.responses
                .iter()
                .find(|(e, _)| *e == endpoint)
                .map(|(_, r)| r.clone().map(str::to_owned))
                .unwrap_or_else(|| {
                    Err(CeremonyError::Protocol(format!("unexpected endpoint {endpoint:?}")))
                })
        }
    }

    /// A mocked `navigator.credentials`: returns a pre-programmed result and
    /// records whether it was called.
    struct MockCeremony {
        create_result: Result<Attestation, CeremonyError>,
        get_result: Result<Assertion, CeremonyError>,
        create_calls: RefCell<u32>,
        get_calls: RefCell<u32>,
    }

    impl MockCeremony {
        fn ok() -> Self {
            MockCeremony {
                create_result: Ok(Attestation {
                    credential_id_b64: "cred-1".into(),
                    attestation_object_b64: "att-obj".into(),
                }),
                get_result: Ok(Assertion {
                    credential_id_b64: "cred-1".into(),
                    authenticator_data_b64: "auth-data".into(),
                    client_data_json_b64: "cdj-auth".into(),
                    signature_b64: "sig".into(),
                    prf_output_b64: "prf-out".into(),
                }),
                create_calls: RefCell::new(0),
                get_calls: RefCell::new(0),
            }
        }

        fn failing(err: CeremonyError) -> Self {
            let mut m = MockCeremony::ok();
            m.create_result = Err(err.clone());
            m.get_result = Err(err);
            m
        }
    }

    impl CredentialCeremony for MockCeremony {
        fn create(&self, _challenge: &RegisterChallenge) -> Result<Attestation, CeremonyError> {
            *self.create_calls.borrow_mut() += 1;
            self.create_result.clone()
        }

        fn get(&self, _challenge: &AuthChallenge) -> Result<Assertion, CeremonyError> {
            *self.get_calls.borrow_mut() += 1;
            self.get_result.clone()
        }
    }

    #[test]
    fn registration_drives_begin_create_finish_in_order() {
        let transport = MockTransport::new(vec![
            (Endpoint::RegisterBegin, Ok("CHALLENGE Y2hhbGxlbmdl pillar.example alice")),
            (Endpoint::RegisterFinish, Ok("REGISTERED Y3JlZC0x")),
        ]);
        let ceremony = MockCeremony::ok();

        let result = register(&transport, &ceremony, "tok-1", "alice");

        assert_eq!(result, Ok("Y3JlZC0x".to_owned()));
        assert_eq!(
            *transport.steps.borrow(),
            vec![Endpoint::RegisterBegin, Endpoint::RegisterFinish],
            "registration must post begin THEN finish, in that order"
        );
        assert_eq!(*ceremony.create_calls.borrow(), 1);
        assert_eq!(*ceremony.get_calls.borrow(), 0, "registration never calls get()");
    }

    #[test]
    fn authentication_drives_begin_get_finish_in_order() {
        let transport = MockTransport::new(vec![
            (Endpoint::AuthenticateBegin, Ok("CHALLENGE Y2hhbGxlbmdl")),
            (Endpoint::AuthenticateFinish, Ok("UNLOCKED dW5sb2Nr")),
        ]);
        let ceremony = MockCeremony::ok();

        let result = authenticate(&transport, &ceremony, "tok-1");

        assert_eq!(result, Ok("dW5sb2Nr".to_owned()));
        assert_eq!(
            *transport.steps.borrow(),
            vec![Endpoint::AuthenticateBegin, Endpoint::AuthenticateFinish],
            "authentication must post begin THEN finish, in that order"
        );
        assert_eq!(*ceremony.get_calls.borrow(), 1);
        assert_eq!(*ceremony.create_calls.borrow(), 0, "authentication never calls create()");
    }

    #[test]
    fn user_cancel_surfaces_message_and_skips_finish() {
        let transport = MockTransport::new(vec![(
            Endpoint::RegisterBegin,
            Ok("CHALLENGE Y2hhbGxlbmdl pillar.example alice"),
        )]);
        let ceremony = MockCeremony::failing(CeremonyError::UserCancelled);

        let err = register(&transport, &ceremony, "tok-1", "alice").unwrap_err();

        assert_eq!(err, CeremonyError::UserCancelled);
        assert!(err.message().contains("cancelled"));
        assert!(err.message().contains("password"), "must point at the fallback");
        assert_eq!(
            *transport.steps.borrow(),
            vec![Endpoint::RegisterBegin],
            "a cancelled ceremony must NEVER post finish"
        );
    }

    #[test]
    fn no_authenticator_surfaces_message_and_skips_finish() {
        let transport = MockTransport::new(vec![(
            Endpoint::AuthenticateBegin,
            Ok("CHALLENGE Y2hhbGxlbmdl"),
        )]);
        let ceremony = MockCeremony::failing(CeremonyError::NoAuthenticator);

        let err = authenticate(&transport, &ceremony, "tok-1").unwrap_err();

        assert_eq!(err, CeremonyError::NoAuthenticator);
        assert!(err.message().contains("No security key"));
        assert_eq!(*transport.steps.borrow(), vec![Endpoint::AuthenticateBegin]);
    }

    #[test]
    fn unsupported_browser_surfaces_fallback_message() {
        let transport = MockTransport::new(vec![(
            Endpoint::RegisterBegin,
            Ok("CHALLENGE Y2hhbGxlbmdl pillar.example alice"),
        )]);
        let ceremony = MockCeremony::failing(CeremonyError::Unsupported);

        let err = register(&transport, &ceremony, "tok-1", "alice").unwrap_err();

        assert_eq!(err, CeremonyError::Unsupported);
        assert!(err.message().to_lowercase().contains("does not support"));
        assert!(err.message().contains("password"));
    }

    #[test]
    fn a_denied_finish_response_surfaces_the_rp_reason() {
        let transport = MockTransport::new(vec![
            (Endpoint::AuthenticateBegin, Ok("CHALLENGE Y2hhbGxlbmdl")),
            (
                Endpoint::AuthenticateFinish,
                Err(map_error_response(403, "DENIED challenge-binding")),
            ),
        ]);
        let ceremony = MockCeremony::ok();

        let err = authenticate(&transport, &ceremony, "tok-1").unwrap_err();

        match err {
            CeremonyError::Network(msg) => {
                assert!(msg.contains("403"));
                assert!(msg.contains("challenge-binding"));
            }
            other => panic!("expected a Network error, got {other:?}"),
        }
    }

    #[test]
    fn every_error_has_a_clear_distinct_message() {
        let errors = [
            CeremonyError::Unsupported,
            CeremonyError::NoAuthenticator,
            CeremonyError::UserCancelled,
            CeremonyError::Network("boom".into()),
            CeremonyError::Protocol("bad shape".into()),
        ];
        let messages: Vec<String> = errors.iter().map(CeremonyError::message).collect();
        for m in &messages {
            assert!(!m.is_empty());
        }
        let mut unique = messages.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), messages.len(), "every error must have a distinct message");
    }

    #[test]
    fn malformed_challenge_is_a_protocol_error_not_a_panic() {
        assert!(matches!(
            parse_register_begin("garbage"),
            Err(CeremonyError::Protocol(_))
        ));
        assert!(matches!(
            parse_register_begin("CHALLENGE only-one-field"),
            Err(CeremonyError::Protocol(_))
        ));
        assert!(matches!(
            parse_authenticate_finish("NOPE"),
            Err(CeremonyError::Protocol(_))
        ));
    }

    #[test]
    fn wire_bodies_match_the_rp_dispatcher_contract() {
        // register/begin: "<token>\n<user_handle>"
        assert_eq!(register_begin_body("tok", "alice"), "tok\nalice");
        // register/finish: "<token>\n<user_handle>\n<challenge>\n<attestation>"
        let attestation = Attestation {
            credential_id_b64: "cred".into(),
            attestation_object_b64: "att".into(),
        };
        assert_eq!(
            register_finish_body("tok", "alice", "chal", &attestation),
            "tok\nalice\nchal\natt"
        );
        // authenticate/begin: "<token>"
        assert_eq!(authenticate_begin_body("tok"), "tok");
        // authenticate/finish: "<token>\n<challenge>\n<cred>\n<ad>\n<cdj>\n<sig>\n<prf>"
        let assertion = Assertion {
            credential_id_b64: "cred".into(),
            authenticator_data_b64: "ad".into(),
            client_data_json_b64: "cdj".into(),
            signature_b64: "sig".into(),
            prf_output_b64: "prf".into(),
        };
        assert_eq!(
            authenticate_finish_body("tok", "chal", &assertion),
            "tok\nchal\ncred\nad\ncdj\nsig\nprf"
        );
    }
}
