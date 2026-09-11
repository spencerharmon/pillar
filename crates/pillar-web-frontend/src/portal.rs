//! The authenticated **portal** — the full Yew port of every capability the
//! shipped `web_login.html` served once a session is admitted. Each tile is a
//! real, functional Yew component wired to the SAME `/portal/*` / `/bootstrap/*`
//! endpoints, with the SAME request framing and the SAME session-auth scheme
//! the node's `web_serve.rs` handlers accept:
//!
//!   * **GET** list/read endpoints authenticate with a `?token=<session>` query
//!     parameter (plus any endpoint-specific params).
//!   * **POST** act endpoints authenticate with the session token as the FIRST
//!     LINE of the body, followed by the act's fields (one per line).
//!
//! (The `X-Pillar-Session` header is only the LOGIN response's token carrier —
//! the node does not read it as request auth, so the panels must not either.)
//!
//! Every piece of request framing and response parsing is a pure, host-tested
//! function (the `wire` items below); only the DOM/`fetch` glue lives behind the
//! `yew` feature. This is a faithful behavioral port, not a decorative one: a
//! button sends the operator's real field values, not an empty body.

use pillar_web_api::LoginRequest;

// ===========================================================================
// Pure wire helpers (host-tested; no web-sys / DOM).
// ===========================================================================

/// Percent-encode a value for use in a query string (RFC 3986 unreserved set
/// stays literal; everything else becomes `%XX`). Mirrors the browser's
/// `encodeURIComponent` closely enough for the tokens/kinds/selectors the
/// portal sends.
#[must_use]
pub fn query_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build a `GET` URL: `path?token=<enc>` with each extra `(key, value)`
/// appended as `&key=<enc>` (an empty value is omitted, matching the old page's
/// conditional `if (selector) url += …`).
#[must_use]
pub fn get_url(path: &str, token: &str, extra: &[(&str, &str)]) -> String {
    let mut url = format!("{path}?token={}", query_encode(token));
    for (k, v) in extra {
        if !v.is_empty() {
            url.push('&');
            url.push_str(k);
            url.push('=');
            url.push_str(&query_encode(v));
        }
    }
    url
}

/// Join body fields with `\n` (the portal's universal POST framing).
#[must_use]
pub fn body_lines(fields: &[&str]) -> String {
    fields.join("\n")
}

/// Format a `/portal/obs/live/query` (PSL) response body into human-readable
/// display rows. The live substrate emits one
/// `SIGNAL <id> KIND <kind> PAYLOAD <payload>` line per matched signal and one
/// `GROUP <anchor> MEMBERS <id,id,...>` line per correlate group (see
/// `web_serve::WebAuthContext::live_obs_psl`); this renders each as a compact
/// one-line row. A line matching neither shape is passed through verbatim so
/// nothing is silently dropped. An empty / whitespace-only body yields an empty
/// vec — the caller shows a "no matching signals" notice, never a blank panel
/// masquerading as a result.
#[must_use]
pub fn format_psl_response(body: &str) -> Vec<String> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("SIGNAL ") {
            // `<id> KIND <kind> [TICK <n>] [LABELS <k=v;…>] PAYLOAD <payload>`
            // — render a timeseries log line: `[t=<tick>] <kind> <labels>:
            // <payload>`. TICK/LABELS are optional so an older/other response
            // shape still renders (falls back to `<kind> <id>: <payload>`).
            if let Some((id, after)) = rest.split_once(" KIND ") {
                let (head, payload) = match after.split_once(" PAYLOAD ") {
                    Some((h, p)) => (h, p.trim()),
                    None => (after, ""),
                };
                let mut kind = head.trim();
                let mut tick: Option<&str> = None;
                let mut labels: Option<&str> = None;
                if let Some((k, r2)) = head.split_once(" TICK ") {
                    kind = k.trim();
                    if let Some((t, l)) = r2.split_once(" LABELS ") {
                        tick = Some(t.trim());
                        labels = Some(l.trim());
                    } else {
                        tick = Some(r2.trim());
                    }
                }
                let ts = tick.map(|t| format!("[t={t}] ")).unwrap_or_default();
                let label_part = match labels {
                    Some(l) if !l.is_empty() => format!(" {}", l.replace(';', " ")),
                    _ => String::new(),
                };
                if tick.is_some() {
                    rows.push(format!("{ts}{kind}{label_part}: {payload}"));
                } else {
                    // Fallback for a response without the TICK/LABELS fields.
                    rows.push(format!("{kind} {}: {payload}", id.trim()));
                }
                continue;
            }
            rows.push(line.to_owned());
        } else if let Some(rest) = line.strip_prefix("GROUP ") {
            // `<anchor> MEMBERS <id,id,...>`
            if let Some((anchor, members)) = rest.split_once(" MEMBERS ") {
                let members = members
                    .split(',')
                    .filter(|m| !m.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                rows.push(format!("group {anchor}: {members}"));
                continue;
            }
            rows.push(line.to_owned());
        } else {
            rows.push(line.to_owned());
        }
    }
    rows
}

/// Compose the notice shown when a PSL query returns NO matching signals, from
/// the live store's per-kind counts (`KIND <k> COUNT <n>` lines, the
/// `/portal/obs/live/kinds` body) and its real label keys (one per line, the
/// `/portal/obs/live/label-keys` body).
///
/// It answers the operator's real question — "is there no data, or did my query
/// just not match?" — honestly: a genuinely EMPTY store says so; a NON-empty
/// store reports what it holds and names the label keys that actually exist, so
/// an operator who filtered on a label that isn't present (e.g. `where: cell =
/// …` when signals are labeled `node`) sees why nothing matched and what to use
/// instead. Never fabricates a count or a key.
#[must_use]
pub fn empty_result_hint(kinds_body: &str, label_keys_body: &str) -> String {
    let counts: Vec<(String, u64)> = kinds_body
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next(), it.next(), it.next()) {
                (Some("KIND"), Some(k), Some("COUNT"), Some(n)) => {
                    n.parse::<u64>().ok().map(|c| (k.to_owned(), c))
                }
                _ => None,
            }
        })
        .collect();
    let total: u64 = counts.iter().map(|(_, c)| c).sum();
    if total == 0 {
        return "Query ran; the live store is empty — no signals have been recorded on this \
                node yet."
            .to_owned();
    }
    let held = counts
        .iter()
        .filter(|(_, c)| *c > 0)
        .map(|(k, c)| format!("{k} {c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let keys: Vec<&str> = label_keys_body
        .lines()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .collect();
    let keys_note = if keys.is_empty() {
        "no label keys are present".to_owned()
    } else {
        format!("available label keys: {}", keys.join(", "))
    };
    format!(
        "Query ran; no signals matched. The live store holds: {held}. Your where:/select: \
         predicates may reference a label that isn't present — {keys_note}. Try the query \
         without the where: clause, or filter on one of those keys."
    )
}

/// The `POST /login` body for the two human fields bound to a `/nonce` id.
#[must_use]
pub fn login_wire(identifier: &str, password: &str, nonce_id: u64) -> String {
    LoginRequest {
        identifier: identifier.to_owned(),
        password: password.to_owned(),
        nonce_id,
    }
    .to_wire()
}

/// Interpret a `/login` response: `Ok(handle)` on a 2xx `OK <handle>` (falling
/// back to the submitted identifier), else `Err(reason)` with `DENIED` stripped.
///
/// # Errors
/// Returns `Err(reason)` when the login was not admitted.
pub fn interpret_login(ok: bool, body: &str, submitted: &str) -> Result<String, String> {
    let body = body.trim();
    if ok && body.starts_with("OK") {
        let handle = body.trim_start_matches("OK").trim();
        Ok(if handle.is_empty() {
            submitted.to_owned()
        } else {
            handle.to_owned()
        })
    } else {
        Err(strip_marker(body))
    }
}

/// The atomic `POST /bootstrap/create` body
/// (`<cell>\n<handle>\n<factor>\n<second_factor>`). `second_factor` is the
/// first user's 2FA method (`password`|`passkey`). A browser second factor is
/// always a WebAuthn passkey; TPM/PKCS#11 are node-key custody, not user
/// credentials, and are not offered here.
#[must_use]
pub fn bootstrap_wire(cell: &str, handle: &str, factor: &str, second_factor: &str) -> String {
    body_lines(&[cell, handle, factor, second_factor])
}

/// A bootstrap succeeded iff a 2xx body contains `BOOTSTRAPPED`.
///
/// # Errors
/// Returns `Err(reason)` when the node refused the bootstrap.
pub fn interpret_bootstrap(ok: bool, body: &str) -> Result<(), String> {
    if ok && body.contains("BOOTSTRAPPED") {
        Ok(())
    } else {
        Err(strip_marker(body.trim()))
    }
}

/// The live cell-name uniqueness hint state (`GET /bootstrap/name-check`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NameHint {
    /// No hint (empty field or an unreachable/best-effort check).
    Idle,
    /// The name is free.
    Free,
    /// The name is already in use, with the node's message.
    InUse(String),
}

/// Interpret a `/bootstrap/name-check` response into an inline hint. A failed
/// or unrecognized check is best-effort and yields [`NameHint::Idle`] (never
/// blocks bootstrap), mirroring the old page.
#[must_use]
pub fn interpret_name_check(ok: bool, body: &str) -> NameHint {
    let body = body.trim();
    if ok && body.starts_with("IN-USE") {
        let msg = body.trim_start_matches("IN-USE").trim();
        NameHint::InUse(if msg.is_empty() {
            "cell name already in use \u{2014} choose another".to_owned()
        } else {
            msg.to_owned()
        })
    } else if ok && body.starts_with("FREE") {
        NameHint::Free
    } else {
        NameHint::Idle
    }
}

/// The `POST /bootstrap/request/{approve,reject}` body (`<id>\n<token>`).
#[must_use]
pub fn inbox_decide_wire(id: &str, token: &str) -> String {
    body_lines(&[id, token])
}

/// A parsed request-inbox row: `<id> <kind> <subject>`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InboxRow {
    /// The request id.
    pub id: String,
    /// The request kind (`node` / `user`).
    pub kind: String,
    /// The subject (the joining identity).
    pub subject: String,
}

/// Parse one inbox line into `(id, kind, subject)`; `None` if it has fewer than
/// three whitespace-separated fields.
#[must_use]
pub fn parse_inbox_line(line: &str) -> Option<InboxRow> {
    let mut it = line.split_whitespace();
    let id = it.next()?.to_owned();
    let kind = it.next()?.to_owned();
    let subject = it.next()?.to_owned();
    Some(InboxRow { id, kind, subject })
}

/// Extract the CID an approval echoes (a `bafy…` token), for the copy
/// affordance the inbox surfaces on a successful approve.
#[must_use]
pub fn extract_cid(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|w| w.starts_with("bafy") && w.len() > 4)
        .map(str::to_owned)
}

/// The node-identity/status view (`GET /portal/status`), one `KEY value` per
/// line.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct StatusView {
    /// The node's libp2p PeerId.
    pub peer_id: String,
    /// The node's listen addresses.
    pub listen: String,
    /// Uptime in seconds.
    pub uptime_secs: String,
    /// The connected-peer count.
    pub peer_count: String,
    /// The connected peers.
    pub peers: Vec<String>,
    /// The current lease holder's fingerprint.
    pub lease_holder: String,
}

/// Parse the `/portal/status` body into a [`StatusView`], applying the same
/// `—`/`none`/`0` placeholders the old page used for missing fields.
#[must_use]
pub fn parse_status(text: &str) -> StatusView {
    let mut f = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some(sp) = line.find(' ') {
            f.insert(line[..sp].to_owned(), line[sp + 1..].to_owned());
        }
    }
    let peers: Vec<String> = f
        .get("PEERS")
        .map(|s| {
            s.split(',')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let peer_count = f
        .get("PEER-COUNT")
        .cloned()
        .unwrap_or_else(|| peers.len().to_string());
    StatusView {
        peer_id: f
            .get("PEER-ID")
            .cloned()
            .unwrap_or_else(|| "\u{2014}".to_owned()),
        listen: f
            .get("LISTEN")
            .cloned()
            .unwrap_or_else(|| "none".to_owned()),
        uptime_secs: f
            .get("UPTIME-SECS")
            .cloned()
            .unwrap_or_else(|| "0".to_owned()),
        peer_count,
        peers,
        lease_holder: f
            .get("LEASE-HOLDER")
            .cloned()
            .unwrap_or_else(|| "none".to_owned()),
    }
}

/// The identity/domains view (`GET /portal/identity`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct IdentityView {
    /// The global identity CID (stable across rotation/recovery).
    pub cid: String,
    /// The current key generation.
    pub generation: String,
    /// The per-domain keys.
    pub domains: Vec<String>,
}

/// Parse the `/portal/identity` body (`CID …`, `GEN …`, `DOMAIN …` lines).
#[must_use]
pub fn parse_identity(text: &str) -> IdentityView {
    let mut view = IdentityView {
        cid: "\u{2014}".to_owned(),
        generation: "0".to_owned(),
        domains: Vec::new(),
    };
    for line in text.lines().filter(|l| !l.is_empty()) {
        if let Some(rest) = line.strip_prefix("CID ") {
            view.cid = rest.to_owned();
        } else if let Some(rest) = line.strip_prefix("GEN ") {
            view.generation = rest.to_owned();
        } else if let Some(rest) = line.strip_prefix("DOMAIN ") {
            view.domains.push(rest.to_owned());
        }
    }
    view
}

/// A parsed credential row from `/webauthn/credentials/list`
/// (`CRED <id> <label> <rp_id> <created> <last|-> <signs>`; `label`/`rp_id`
/// arrive as `-` when empty).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CredentialRow {
    /// The base64url credential id.
    pub id: String,
    /// The user-chosen label (empty when none).
    pub label: String,
    /// The rpId / domain the credential is bound to (empty when unknown).
    pub rp_id: String,
    /// Registration time (unix seconds, as text).
    pub created_at: String,
    /// Last-used time (unix seconds, or `-` when never used).
    pub last_used: String,
    /// The authenticator sign-count.
    pub sign_count: String,
}

/// Parse one `/webauthn/credentials/list` line; `None` if it does not match.
#[must_use]
pub fn parse_credential_line(line: &str) -> Option<CredentialRow> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 7 || f[0] != "CRED" {
        return None;
    }
    let undash = |s: &str| if s == "-" { String::new() } else { s.to_owned() };
    Some(CredentialRow {
        id: f[1].to_owned(),
        label: undash(f[2]),
        rp_id: undash(f[3]),
        created_at: f[4].to_owned(),
        last_used: f[5].to_owned(),
        sign_count: f[6].to_owned(),
    })
}

/// A parsed active-session row (`SESSION <id> NODE <n> ISSUED <t> EXPIRY <t>
/// CURRENT <yes|no>`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionRow {
    /// The session id.
    pub id: String,
    /// The node/domain the session lives on.
    pub node: String,
    /// The issued-at logical timestamp.
    pub issued_at: String,
    /// The expiry logical timestamp.
    pub expiry: String,
    /// Whether this is the caller's current browser session.
    pub current: bool,
}

/// Parse one `/portal/sessions` line; `None` if it does not match the shape.
#[must_use]
pub fn parse_session_line(line: &str) -> Option<SessionRow> {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() != 10
        || t[0] != "SESSION"
        || t[2] != "NODE"
        || t[4] != "ISSUED"
        || t[6] != "EXPIRY"
        || t[8] != "CURRENT"
    {
        return None;
    }
    Some(SessionRow {
        id: t[1].to_owned(),
        node: t[3].to_owned(),
        issued_at: t[5].to_owned(),
        expiry: t[7].to_owned(),
        current: t[9] == "yes",
    })
}

/// Split a response into non-empty lines (the shared list renderer's input).
#[must_use]
pub fn nonempty_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// Map a raw `DENIED <reason>` into the plain-language guidance the old page's
/// `friendlyError` produced.
#[must_use]
pub fn friendly_error(reason: &str) -> String {
    let r = reason.to_lowercase();
    if r.contains("no-offer-for-user") {
        "This node has no key offer for you (it may lack the key-distribution \
         label). Contact your operator."
            .to_owned()
    } else if r.contains("no-custody") {
        "This node is not sealed to hold your key. Contact your operator to seal \
         an offer to it."
            .to_owned()
    } else if r.contains("unlock-failed") || r.contains("missing-field") {
        "Wrong identifier or unlock factor \u{2014} please try again.".to_owned()
    } else if r.contains("not-authorized") {
        "Your key is not admitted (or was revoked). Contact your node operator.".to_owned()
    } else if r.contains("bad-nonce") {
        "The challenge was invalid or expired \u{2014} please try again.".to_owned()
    } else if reason.is_empty() {
        "Login failed \u{2014} please try again.".to_owned()
    } else {
        format!("Login failed: {reason}")
    }
}

/// Strip a leading `DENIED`/`MISSING` marker so the UI shows the bare reason.
fn strip_marker(body: &str) -> String {
    let trimmed = body
        .trim()
        .trim_start_matches("DENIED")
        .trim_start_matches("MISSING")
        .trim();
    if trimmed.is_empty() {
        "the node refused the request".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The physical libp2p swarm this node runs on (`GET /portal/swarm`): the
/// running swarm's kind + fingerprint plus its configured seed multiaddrs.
/// Pillar keeps NO swarm state — a node is repointed only by rebooting with a
/// new `--swarm-key`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SwarmView {
    /// The swarm kind tag (`public` / `private`).
    pub kind: String,
    /// The running swarm's key fingerprint.
    pub fingerprint: String,
    /// The configured seed multiaddrs.
    pub seeds: Vec<String>,
}

/// Parse the `/portal/swarm` body: one `SWARM <kind> <fingerprint>` line plus
/// zero or more `SEED <multiaddr>` lines.
#[must_use]
pub fn parse_swarm(text: &str) -> SwarmView {
    let mut view = SwarmView::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("SWARM ") {
            let mut it = rest.splitn(2, ' ');
            view.kind = it.next().unwrap_or("").trim().to_owned();
            view.fingerprint = it.next().unwrap_or("").trim().to_owned();
        } else if let Some(seed) = line.strip_prefix("SEED ") {
            let seed = seed.trim();
            if !seed.is_empty() {
                view.seeds.push(seed.to_owned());
            }
        }
    }
    if view.kind.is_empty() {
        view.kind = "\u{2014}".to_owned();
    }
    if view.fingerprint.is_empty() {
        view.fingerprint = "\u{2014}".to_owned();
    }
    view
}

/// A freshly minted private swarm key (`POST /portal/swarm/generate` ->
/// `KEY <root-secret>` + `FINGERPRINT <fp>`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct GeneratedKey {
    /// The `--swarm-key` root secret to reboot a node onto this private swarm.
    pub key: String,
    /// The new key's fingerprint.
    pub fingerprint: String,
}

/// Parse the `/portal/swarm/generate` success body, or an error reason.
pub fn interpret_generate(ok: bool, body: &str) -> Result<GeneratedKey, String> {
    if !ok {
        return Err(strip_marker(body));
    }
    let mut g = GeneratedKey::default();
    for line in body.lines() {
        if let Some(k) = line.strip_prefix("KEY ") {
            g.key = k.trim().to_owned();
        } else if let Some(fp) = line.strip_prefix("FINGERPRINT ") {
            g.fingerprint = fp.trim().to_owned();
        }
    }
    if g.key.is_empty() {
        return Err(strip_marker(body));
    }
    Ok(g)
}

// ===========================================================================
// Yew components + fetch glue (behind the `yew` feature).
// ===========================================================================

#[cfg(feature = "yew")]
pub use yew_impl::{CopyValue, PendingButton, Portal};

#[cfg(feature = "yew")]
pub(crate) use yew_impl::{http, input_value};

// The per-capability tiles, exposed to the console shell ([`crate::console`])
// so it can mount each one into its own navigable section. They are defined
// once here and reused verbatim by the shell.
#[cfg(feature = "yew")]
pub(crate) use yew_impl::{
    CredentialsTile, IdentityTile, InboxTile, MembersTile, NodeStatusTile, SessionsTile, SwarmTile,
};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::*;
    use crate::auth::{use_auth, AuthAction, AuthContext};
    use crate::explore::{
        ExploreBuilder, ExploreLogsBuilder, ExploreMetadataBuilder, ExploreProfilesBuilder,
        ExploreTracesBuilder,
    };
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::{spawn_local, JsFuture};
    use web_sys::{
        Headers, HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, RequestInit,
        RequestMode, Response,
    };
    use yew::prelude::*;

    /// One HTTP round trip's result: status, body text, and the login
    /// response's `X-Pillar-Session` token when present.
    pub(crate) struct HttpResult {
        pub status: u16,
        pub body: String,
        pub session_token: Option<String>,
    }

    impl HttpResult {
        pub fn ok(&self) -> bool {
            (200..300).contains(&self.status)
        }
    }

    /// Perform one `fetch`. `body` `Some` -> `POST` that text; `None` -> `GET`.
    pub(crate) async fn http(
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<HttpResult, JsValue> {
        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_mode(RequestMode::SameOrigin);
        if let Some(b) = body {
            opts.set_body(&JsValue::from_str(b));
        }
        let headers: JsValue = Headers::new()?.into();
        opts.set_headers(&headers);
        let window = web_sys::window().expect("a browser window context");
        let resp_value = JsFuture::from(window.fetch_with_str_and_init(url, &opts)).await?;
        let resp: Response = resp_value.dyn_into()?;
        let status = resp.status();
        let session_token = resp.headers().get("X-Pillar-Session").ok().flatten();
        let text = JsFuture::from(resp.text()?)
            .await?
            .as_string()
            .unwrap_or_default();
        Ok(HttpResult {
            status,
            body: text,
            session_token,
        })
    }

    /// Read the current value of the `<input>` an event fired on.
    pub(crate) fn input_value(e: &InputEvent) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
            .map(|i| i.value())
            .unwrap_or_default()
    }

    /// Read the current value of the `<textarea>` an event fired on — the
    /// multi-line analogue of [`input_value`] for the raw-PSL query box (a
    /// `<textarea>` is `HtmlTextAreaElement`, not `HtmlInputElement`, so the
    /// input-element cast would silently yield an empty string).
    pub(crate) fn textarea_value(e: &InputEvent) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlTextAreaElement>().ok())
            .map(|t| t.value())
            .unwrap_or_default()
    }

    /// Read the current value of the `<select>` an event fired on.
    fn select_value(e: &Event) -> String {
        e.target()
            .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            .map(|s| s.value())
            .unwrap_or_default()
    }

    /// Dispatch [`AuthAction::Unauthorized`] on a `401` (clears the session,
    /// the router guard returns to login). Returns `true` when it was a 401.
    fn handle_401(auth: &AuthContext, status: u16) -> bool {
        if status == 401 {
            auth.dispatch(AuthAction::Unauthorized);
            true
        } else {
            false
        }
    }

    // ---- Reusable affordances -------------------------------------------

    /// Props for [`PendingButton`].
    #[derive(Properties, PartialEq)]
    pub struct PendingButtonProps {
        /// The idle label.
        pub label: AttrValue,
        /// The click handler (the parent guards double-submit via `busy`).
        pub onclick: Callback<MouseEvent>,
        /// Whether the button's signed act is in flight.
        #[prop_or_default]
        pub busy: bool,
        /// An optional stable id (so a test/needle can name the control).
        #[prop_or_default]
        pub id: AttrValue,
    }

    /// A mutating control whose signed act shows a pending + disabled state
    /// (no double-submit) while in flight, re-enabling on the result. Ports the
    /// old page's `withPending` wrapper: `aria-busy` + a `Working…` label.
    #[function_component(PendingButton)]
    pub fn pending_button(props: &PendingButtonProps) -> Html {
        html! {
            <button type="button" id={props.id.clone()}
                aria-busy={props.busy.to_string()} disabled={props.busy}
                onclick={props.onclick.clone()}>
                { if props.busy { "Working\u{2026}" } else { props.label.as_str() } }
            </button>
        }
    }

    /// Props for [`CopyValue`].
    #[derive(Properties, PartialEq)]
    pub struct CopyValueProps {
        /// The field kind (`"PeerId"`, `"CID"`, `"fingerprint"`, …), surfaced
        /// as `data-copy-field` and in the button's aria-label.
        pub field: AttrValue,
        /// The value to display and copy.
        pub value: AttrValue,
    }

    /// A value with a copy-to-clipboard affordance next to it (ports
    /// `attachCopyButton`/`copyText`/`wireCopyables`): a `data-copy-field`
    /// span plus a `Copy` button that writes the value to the clipboard.
    #[function_component(CopyValue)]
    pub fn copy_value(props: &CopyValueProps) -> Html {
        let copied = use_state(|| false);
        let onclick = {
            let value = props.value.to_string();
            let copied = copied.clone();
            Callback::from(move |_| {
                let value = value.clone();
                let copied = copied.clone();
                if value.is_empty() || value == "\u{2014}" {
                    return;
                }
                spawn_local(async move {
                    if copy_to_clipboard(&value).await {
                        copied.set(true);
                    }
                });
            })
        };
        html! {
            <span class="copyable">
                <span data-copy-field={props.field.clone()}>{ props.value.clone() }</span>
                <button type="button" class={classes!("copy-btn", copied.then_some("copied"))}
                    aria-label={format!("Copy {}", props.field)} {onclick}>
                    { if *copied { "Copied" } else { "Copy" } }
                </button>
            </span>
        }
    }

    /// Write `text` to the system clipboard via the async Clipboard API.
    async fn copy_to_clipboard(text: &str) -> bool {
        let Some(window) = web_sys::window() else {
            return false;
        };
        let clipboard = window.navigator().clipboard();
        JsFuture::from(clipboard.write_text(text)).await.is_ok()
    }

    /// A best-effort authenticated `GET` returning parsed non-empty lines;
    /// dispatches `Unauthorized` on 401.
    async fn get_lines(auth: AuthContext, url: String) -> Option<Vec<String>> {
        match http("GET", &url, None).await {
            Ok(r) if r.ok() => Some(nonempty_lines(&r.body)),
            Ok(r) => {
                handle_401(&auth, r.status);
                None
            }
            Err(_) => None,
        }
    }

    // ---- Tiles ----------------------------------------------------------

    /// Node identity / peers / lease-holder, from real node state, with copy
    /// affordances on the PeerId and lease-holder fingerprint.
    #[function_component(NodeStatusTile)]
    pub(crate) fn node_status_tile() -> Html {
        let auth = use_auth();
        let status = use_state(StatusView::default);
        {
            let auth = auth.clone();
            let status = status.clone();
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let status = status.clone();
                    let auth = auth.clone();
                    spawn_local(async move {
                        if let Ok(r) =
                            http("GET", &get_url("/portal/status", &token, &[]), None).await
                        {
                            if r.ok() {
                                status.set(parse_status(&r.body));
                            } else {
                                handle_401(&auth, r.status);
                            }
                        }
                    });
                }
                || ()
            });
        }
        let s = &*status;
        html! {
            <div class="tile" id="node-identity-tile">
                <h3>{ "Node identity" }</h3>
                <p>{ "PeerId: " }<CopyValue field="PeerId" value={s.peer_id.clone()} /></p>
                <p>{ format!("Listen addrs: {}", s.listen) }</p>
                <p>{ format!("Uptime: {}s", s.uptime_secs) }</p>
                <p>{ format!("Peers: {} \u{2014} {}", s.peer_count,
                    if s.peers.is_empty() { "none".to_owned() } else { s.peers.join(", ") }) }</p>
                <p>{ "Lease holder: " }<CopyValue field="fingerprint" value={s.lease_holder.clone()} /></p>
            </div>
        }
    }

    /// The physical libp2p swarm this node runs on: a read-only view (kind +
    /// fingerprint + seeds) plus one stateless act — mint a fresh private
    /// swarm key to reboot a node onto with `--swarm-key`. Ports the Swarm
    /// panel; wires `/portal/swarm` + `/portal/swarm/generate`.
    #[function_component(SwarmTile)]
    pub(crate) fn swarm_tile() -> Html {
        let auth = use_auth();
        let view = use_state(SwarmView::default);
        let busy = use_state(|| false);
        let minted = use_state(|| None::<Result<GeneratedKey, String>>);
        {
            let auth = auth.clone();
            let view = view.clone();
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let (view, auth) = (view.clone(), auth.clone());
                    spawn_local(async move {
                        if let Ok(r) =
                            http("GET", &get_url("/portal/swarm", &token, &[]), None).await
                        {
                            if r.ok() {
                                view.set(parse_swarm(&r.body));
                            } else {
                                handle_401(&auth, r.status);
                            }
                        }
                    });
                }
                || ()
            });
        }
        let generate = {
            let auth = auth.clone();
            let busy = busy.clone();
            let minted = minted.clone();
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let (auth, busy, minted) = (auth.clone(), busy.clone(), minted.clone());
                busy.set(true);
                spawn_local(async move {
                    match http("POST", "/portal/swarm/generate", Some(&token)).await {
                        Ok(r) => {
                            handle_401(&auth, r.status);
                            minted.set(Some(interpret_generate(r.ok(), &r.body)));
                        }
                        Err(_) => minted.set(Some(Err("the node refused the request".to_owned()))),
                    }
                    busy.set(false);
                });
            })
        };
        let v = &*view;
        html! {
            <div class="tile" id="swarm-tile">
                <h3>{ "Swarm" }</h3>
                <p>{ format!("Running swarm: {}", v.kind) }</p>
                <p>{ "Fingerprint: " }<CopyValue field="fingerprint" value={v.fingerprint.clone()} /></p>
                <p>{ format!("Seeds: {}",
                    if v.seeds.is_empty() { "none".to_owned() } else { v.seeds.join(", ") }) }</p>
                <div class="explainer">
                    <strong>{ "What happens next:" }</strong>
                    { " generating mints a fresh private swarm key. Pillar keeps no \
                       swarm state — reboot a node with `--swarm-key` to repoint it \
                       onto the new private swarm." }
                </div>
                <PendingButton id="swarm-generate-btn"
                    label="Generate private swarm key" busy={*busy}
                    onclick={generate} />
                {
                    match &*minted {
                        Some(Ok(g)) => html! {
                            <div class="result" id="swarm-generated">
                                <p>{ "New swarm key: " }<CopyValue field="swarm-key" value={g.key.clone()} /></p>
                                <p>{ "Fingerprint: " }<CopyValue field="fingerprint" value={g.fingerprint.clone()} /></p>
                            </div>
                        },
                        Some(Err(e)) => html! { <p class="error">{ format!("Failed: {e}") }</p> },
                        None => Html::default(),
                    }
                }
            </div>
        }
    }

    /// Request-approval inbox: pending join requests, each with a
    /// what-happens-next explainer and Approve/Reject (a CID on approve gets a
    /// copy affordance).
    #[function_component(InboxTile)]
    pub(crate) fn inbox_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<InboxRow>::new);
        let busy = use_state(|| false);
        let result = use_state(|| None::<(String, String, bool)>); // (id, text/cid, ok)

        let refresh = {
            let rows = rows.clone();
            Callback::from(move |_: ()| {
                let rows = rows.clone();
                spawn_local(async move {
                    if let Ok(r) = http("GET", "/bootstrap/request/list", None).await {
                        if r.ok() {
                            rows.set(
                                nonempty_lines(&r.body)
                                    .iter()
                                    .filter_map(|l| parse_inbox_line(l))
                                    .collect(),
                            );
                        }
                    }
                });
            })
        };
        {
            let refresh = refresh.clone();
            use_effect_with((), move |_| {
                refresh.emit(());
                || ()
            });
        }

        let decide = {
            let auth = auth.clone();
            let busy = busy.clone();
            let result = result.clone();
            let refresh = refresh.clone();
            move |id: String, approve: bool| {
                let auth = auth.clone();
                let busy = busy.clone();
                let result = result.clone();
                let refresh = refresh.clone();
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let id = id.clone();
                    let (busy, result, refresh) = (busy.clone(), result.clone(), refresh.clone());
                    busy.set(true);
                    spawn_local(async move {
                        let path = if approve {
                            "/bootstrap/request/approve"
                        } else {
                            "/bootstrap/request/reject"
                        };
                        match http("POST", path, Some(&inbox_decide_wire(&id, &token))).await {
                            Ok(r) => {
                                let text = r.body.trim().to_owned();
                                let cid = if r.ok() { extract_cid(&text) } else { None };
                                result.set(Some(match cid {
                                    Some(c) => (id.clone(), c, true),
                                    None => (
                                        id.clone(),
                                        if r.ok() {
                                            text
                                        } else {
                                            format!("Failed: {}", strip_marker(&text))
                                        },
                                        r.ok(),
                                    ),
                                }));
                                if r.ok() {
                                    refresh.emit(());
                                }
                            }
                            Err(_) => {
                                result.set(Some((id.clone(), "request failed".to_owned(), false)))
                            }
                        }
                        busy.set(false);
                    });
                })
            }
        };

        html! {
            <div class="tile" id="inbox-tile">
                <h3>{ "Request inbox" }</h3>
                <p>{ "Pending node/user join requests for this cell." }</p>
                <div id="inbox-list">
                    { for rows.iter().map(|row| {
                        let approve = decide(row.id.clone(), true);
                        let reject = decide(row.id.clone(), false);
                        html! {
                            <div class="tile" data-request-id={row.id.clone()}>
                                <p><strong>{ format!("#{}", row.id) }</strong>{ format!(" {} \u{2014} {}", row.kind, row.subject) }</p>
                                <div class="explainer">
                                    <strong>{ "What happens next:" }</strong>
                                    { format!(" approving signs an attestation admitting {} into this cell \
                                        \u{2014} your key vouches for their {} key. Rejecting signs nothing \
                                        and drops the request.", row.subject, row.kind) }
                                </div>
                                <div class="row">
                                    <PendingButton label="Approve" busy={*busy} onclick={approve} />
                                    <PendingButton label="Reject" busy={*busy} onclick={reject} />
                                </div>
                                {
                                    match &*result {
                                        Some((rid, body, ok)) if *rid == row.id && *ok && body.starts_with("bafy") =>
                                            html! { <p class="msg ok">{ "Admitted: " }<CopyValue field="CID" value={body.clone()} /></p> },
                                        Some((rid, body, ok)) if *rid == row.id =>
                                            html! { <p class={classes!("msg", if *ok {"ok"} else {"err"})}>{ body.clone() }</p> },
                                        _ => Html::default(),
                                    }
                                }
                            </div>
                        }
                    }) }
                    { if rows.is_empty() { html! { <p>{ "No pending requests." }</p> } } else { Html::default() } }
                </div>
            </div>
        }
    }

    /// Identity & domains: CID (copyable) + generation + per-domain keys, with
    /// enroll / rotate-primary / recover acts.
    #[function_component(IdentityTile)]
    pub(crate) fn identity_tile() -> Html {
        let auth = use_auth();
        let view = use_state(IdentityView::default);
        let domains = use_state(Vec::<String>::new);
        let domain_input = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let auth = auth.clone();
            let view = view.clone();
            let domains = domains.clone();
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth, view, domains) = (auth.clone(), view.clone(), domains.clone());
                spawn_local(async move {
                    if let Ok(r) =
                        http("GET", &get_url("/portal/identity", &token, &[]), None).await
                    {
                        if r.ok() {
                            view.set(parse_identity(&r.body));
                        } else {
                            handle_401(&auth, r.status);
                        }
                    }
                    if let Some(lines) =
                        get_lines(auth.clone(), get_url("/portal/domains", &token, &[])).await
                    {
                        domains.set(lines);
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

        let act = {
            let auth = auth.clone();
            let busy = busy.clone();
            let msg = msg.clone();
            let refresh = refresh.clone();
            let domain_input = domain_input.clone();
            move |path: &'static str, with_domain: bool, rotate_key: bool| {
                let (auth, busy, msg, refresh, domain_input) = (
                    auth.clone(),
                    busy.clone(),
                    msg.clone(),
                    refresh.clone(),
                    domain_input.clone(),
                );
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let body = if with_domain {
                        body_lines(&[&token, (*domain_input).trim()])
                    } else if rotate_key {
                        body_lines(&[&token, "primary-rotation"])
                    } else {
                        token.clone()
                    };
                    let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) = http("POST", path, Some(&body)).await {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                            if r.ok() {
                                refresh.emit(());
                            }
                        }
                        busy.set(false);
                    });
                })
            }
        };

        let on_domain = {
            let domain_input = domain_input.clone();
            Callback::from(move |e: InputEvent| domain_input.set(input_value(&e)))
        };
        let v = &*view;
        html! {
            <div class="tile" id="identity-tile">
                <h3>{ "Identity & domains" }</h3>
                <p>{ "Global identity: " }<CopyValue field="CID" value={v.cid.clone()} />{ format!(" (generation {})", v.generation) }</p>
                <div id="identity-domain-keys">
                    { for v.domains.iter().map(|d| html! { <p class="identity-domain-key">{ d.clone() }</p> }) }
                </div>
                <div id="domain-list">
                    { for domains.iter().map(|d| html! { <p class="domain-row">{ d.clone() }</p> }) }
                </div>
                <label for="identity-domain-input">{ "Enroll in a domain" }</label>
                <input id="identity-domain-input" type="text" placeholder="domain"
                    value={(*domain_input).clone()} oninput={on_domain} />
                <PendingButton id="identity-enroll-btn" label="Enroll" busy={*busy}
                    onclick={act("/portal/identity/enroll", true, false)} />
                <PendingButton id="identity-rotate-btn" label="Rotate primary key" busy={*busy}
                    onclick={act("/portal/identity/rotate", false, true)} />
                <PendingButton id="identity-recover-btn" label="Recover identity" busy={*busy}
                    onclick={act("/portal/identity/recover", false, false)} />
                { message_line("identity-msg", &msg) }
            </div>
        }
    }

    /// Members: list + add/invite with handle + role.
    #[function_component(MembersTile)]
    pub(crate) fn members_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<String>::new);
        let handle = use_state(String::new);
        let role = use_state(|| "member".to_owned());
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
                        get_lines(auth, get_url("/portal/members", &token, &[])).await
                    {
                        rows.set(lines);
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

        let add = {
            let (auth, busy, msg, refresh, handle, role) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                handle.clone(),
                role.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let role_val = if (*role).trim().is_empty() {
                    "member"
                } else {
                    (*role).trim()
                };
                let body = body_lines(&[&token, (*handle).trim(), role_val]);
                let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/members/add", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            refresh.emit(());
                        }
                    }
                    busy.set(false);
                });
            })
        };
        let on_handle = {
            let handle = handle.clone();
            Callback::from(move |e: InputEvent| handle.set(input_value(&e)))
        };
        let on_role = {
            let role = role.clone();
            Callback::from(move |e: InputEvent| role.set(input_value(&e)))
        };
        html! {
            <div class="tile" id="members-tile">
                <h3>{ "Members" }</h3>
                <p>{ "Add, invite, and manage member roles for this cell." }</p>
                <div id="member-list">
                    { for rows.iter().map(|m| html! { <p class="member-row">{ m.clone() }</p> }) }
                </div>
                <label for="member-handle-input">{ "Add / invite member" }</label>
                <input id="member-handle-input" type="text" placeholder="handle"
                    value={(*handle).clone()} oninput={on_handle} />
                <input id="member-role-input" type="text" placeholder="role"
                    value={(*role).clone()} oninput={on_role} />
                <PendingButton id="member-add-btn" label="Add / invite" busy={*busy} onclick={add} />
                { message_line("member-add-msg", &msg) }
            </div>
        }
    }

    /// Active server-side sessions with expiry + a "(this session)" marker and
    /// per-session revoke + sign-out-everywhere.
    #[function_component(SessionsTile)]
    pub(crate) fn sessions_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<SessionRow>::new);
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
                        get_lines(auth, get_url("/portal/sessions", &token, &[])).await
                    {
                        rows.set(lines.iter().filter_map(|l| parse_session_line(l)).collect());
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

        let revoke = {
            let (auth, busy, msg, refresh) =
                (auth.clone(), busy.clone(), msg.clone(), refresh.clone());
            move |id: String| {
                let (auth, busy, msg, refresh) =
                    (auth.clone(), busy.clone(), msg.clone(), refresh.clone());
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let body = body_lines(&[&token, &id]);
                    let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) = http("POST", "/portal/sessions/revoke", Some(&body)).await {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                            if r.ok() {
                                refresh.emit(());
                            }
                        }
                        busy.set(false);
                    });
                })
            }
        };
        let revoke_all = {
            let (auth, busy, msg) = (auth.clone(), busy.clone(), msg.clone());
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let (auth, busy, msg) = (auth.clone(), busy.clone(), msg.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/sessions/revoke-all", Some(&token)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        if r.ok() {
                            // this session was revoked too -> return to login.
                            auth.dispatch(AuthAction::Logout);
                        }
                    }
                    busy.set(false);
                });
            })
        };
        html! {
            <div class="tile" id="sessions-tile">
                <h3>{ "Sessions" }</h3>
                <p>{ "Your active server-side sessions on this node, with a live expiry countdown." }</p>
                <div id="session-list">
                    { for rows.iter().map(|s| {
                        let rev = revoke(s.id.clone());
                        html! {
                            <div class="tile session-row" data-session-id={s.id.clone()}>
                                <p><strong>{ s.id.clone() }</strong>
                                    { if s.current { html! { <span class="current-marker">{ " (this session)" }</span> } } else { Html::default() } }</p>
                                <p>{ format!("Node/domain: {}", s.node) }</p>
                                <p>{ format!("Issued at: {}", s.issued_at) }</p>
                                <p>{ format!("Expires: {}", s.expiry) }</p>
                                { if s.current { Html::default() } else { html! { <PendingButton label="Revoke" busy={*busy} onclick={rev} /> } } }
                            </div>
                        }
                    }) }
                </div>
                <PendingButton id="signout-everywhere-btn" label="Sign out everywhere" busy={*busy} onclick={revoke_all} />
                { message_line("session-msg", &msg) }
            </div>
        }
    }

    /// The user's WebAuthn credentials (security keys / passkeys): list each
    /// with its label, bound domain, created / last-used / sign-count; enroll
    /// another; and revoke individually. Register more than one so a lost key
    /// is a revoke, not a lockout.
    #[function_component(CredentialsTile)]
    pub(crate) fn credentials_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<CredentialRow>::new);
        let label = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let (auth, rows) = (auth.clone(), rows.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let rows = rows.clone();
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/webauthn/credentials/list", Some(&token)).await {
                        if r.ok() {
                            rows.set(
                                r.body.lines().filter_map(parse_credential_line).collect(),
                            );
                        }
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

        let on_label = {
            let label = label.clone();
            Callback::from(move |e: InputEvent| label.set(input_value(&e)))
        };

        let enroll = {
            let (auth, busy, msg, refresh, label) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                refresh.clone(),
                label.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let user = auth.user.clone().unwrap_or_default();
                let label_v = (*label).clone();
                let (busy, msg, refresh, label) =
                    (busy.clone(), msg.clone(), refresh.clone(), label.clone());
                busy.set(true);
                msg.set(Some(("Touch your security key to enroll it…".to_owned(), true)));
                spawn_local(async move {
                    match crate::webauthn::run_register(&token, &user, &label_v).await {
                        Ok(_) => {
                            msg.set(Some(("Security key enrolled.".to_owned(), true)));
                            label.set(String::new());
                            refresh.emit(());
                        }
                        Err(e) => msg.set(Some((e.message(), false))),
                    }
                    busy.set(false);
                });
            })
        };

        let revoke = {
            let (auth, busy, msg, refresh) =
                (auth.clone(), busy.clone(), msg.clone(), refresh.clone());
            move |id: String| {
                let (auth, busy, msg, refresh) =
                    (auth.clone(), busy.clone(), msg.clone(), refresh.clone());
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let body = body_lines(&[&token, &id]);
                    let (busy, msg, refresh) = (busy.clone(), msg.clone(), refresh.clone());
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) =
                            http("POST", "/webauthn/credentials/revoke", Some(&body)).await
                        {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                            if r.ok() {
                                refresh.emit(());
                            }
                        }
                        busy.set(false);
                    });
                })
            }
        };

        html! {
            <div class="tile" id="credentials-tile">
                <h3>{ "Security keys" }</h3>
                <p>{ "Your WebAuthn passkeys / security keys. Register more than one so a lost key is a revoke, not a lockout." }</p>
                <div id="credential-list">
                    { for rows.iter().map(|c| {
                        let rev = revoke(c.id.clone());
                        let last = if c.last_used == "-" { "never".to_owned() } else { c.last_used.clone() };
                        let bound = if c.rp_id.is_empty() { "(unknown)".to_owned() } else { c.rp_id.clone() };
                        let name = if c.label.is_empty() { "(unlabeled)".to_owned() } else { c.label.clone() };
                        html! {
                            <div class="tile credential-row" data-credential-id={c.id.clone()}>
                                <p><strong>{ name }</strong></p>
                                <p>{ format!("Bound domain: {bound}") }</p>
                                <p>{ format!("Created: {}  ·  Last used: {last}  ·  Signs: {}", c.created_at, c.sign_count) }</p>
                                <p class="credential-id">{ c.id.clone() }</p>
                                <PendingButton label="Revoke" busy={*busy} onclick={rev} />
                            </div>
                        }
                    }) }
                </div>
                <label for="credential-label">{ "Label for a new key" }</label>
                <input id="credential-label" type="text" value={(*label).clone()} placeholder="e.g. yubikey-blue" oninput={on_label} />
                <PendingButton id="enroll-credential-btn" label="Add a security key" busy={*busy} onclick={enroll} />
                { message_line("credential-msg", &msg) }
            </div>
        }
    }

    /// Trust graph + attestation builder + key/offer custody actions.
    #[function_component(TrustTile)]
    pub(crate) fn trust_tile() -> Html {
        let auth = use_auth();
        let edges = use_state(Vec::<String>::new);
        let attest = use_state(AttestFields::default);
        let attest_result = use_state(Vec::<String>::new);
        let custody = use_state(CustodyFields::default);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let refresh = {
            let auth = auth.clone();
            let edges = edges.clone();
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth, edges) = (auth.clone(), edges.clone());
                spawn_local(async move {
                    if let Some(lines) =
                        get_lines(auth, get_url("/portal/trust-graph", &token, &[])).await
                    {
                        edges.set(lines);
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

        let build_attestation = {
            let (auth, busy, msg, attest, attest_result) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                attest.clone(),
                attest_result.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let a = (*attest).clone();
                let capacity = if a.capacity.trim().is_empty() {
                    "self".to_owned()
                } else {
                    a.capacity.trim().to_owned()
                };
                let body = body_lines(&[
                    &token,
                    a.issuer.trim(),
                    &capacity,
                    a.authority.trim(),
                    a.subject.trim(),
                    a.action.trim(),
                    a.resource.trim(),
                    a.quota.trim(),
                    a.scope.trim(),
                ]);
                let (busy, msg, attest_result) = (busy.clone(), msg.clone(), attest_result.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/attestations/build", Some(&body)).await {
                        if r.ok() {
                            attest_result.set(nonempty_lines(&r.body));
                            msg.set(Some(("Attestation built.".to_owned(), true)));
                        } else {
                            msg.set(Some((strip_marker(&r.body), false)));
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let custody_act = {
            let (auth, busy, msg, custody) =
                (auth.clone(), busy.clone(), msg.clone(), custody.clone());
            move |path: &'static str, kind: CustodyKind| {
                let (auth, busy, msg, custody) =
                    (auth.clone(), busy.clone(), msg.clone(), custody.clone());
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let c = (*custody).clone();
                    let body = match kind {
                        CustodyKind::Rotate => body_lines(&[&token, c.handle.trim(), c.cid.trim()]),
                        CustodyKind::Seal | CustodyKind::Revoke => {
                            body_lines(&[&token, c.handle.trim()])
                        }
                        CustodyKind::Migrate => {
                            body_lines(&[&token, c.handle.trim(), c.holder.trim(), c.cid.trim()])
                        }
                    };
                    let (busy, msg) = (busy.clone(), msg.clone());
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) = http("POST", path, Some(&body)).await {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                        }
                        busy.set(false);
                    });
                })
            }
        };

        let af = attest.clone();
        let cf = custody.clone();
        let attest_field = move |get: fn(&AttestFields) -> String,
                                 set: fn(&mut AttestFields, String)| {
            let af = af.clone();
            Callback::from(move |e: InputEvent| {
                let mut cur = (*af).clone();
                let _ = get(&cur);
                set(&mut cur, input_value(&e));
                af.set(cur);
            })
        };
        let custody_field = move |set: fn(&mut CustodyFields, String)| {
            let cf = cf.clone();
            Callback::from(move |e: InputEvent| {
                let mut cur = (*cf).clone();
                set(&mut cur, input_value(&e));
                cf.set(cur);
            })
        };

        html! {
            <div class="tile" id="trust-tile">
                <h3>{ "Trust & key builders" }</h3>
                <p>{ "The trust-graph, the attestation builder, and key/offer custody actions." }</p>
                <PendingButton id="trust-graph-refresh-btn" label="Refresh trust graph" busy={*busy}
                    onclick={Callback::from(move |_| refresh.emit(()))} />
                <div id="trust-graph-list">
                    { for edges.iter().map(|e| html! { <p class="trust-edge">{ e.clone() }</p> }) }
                </div>
                <label>{ "Build an attestation" }</label>
                <input id="attest-issuer" type="text" placeholder="issuer" value={attest.issuer.clone()}
                    oninput={attest_field(|a| a.issuer.clone(), |a, v| a.issuer = v)} />
                <input id="attest-capacity" type="text" placeholder="capacity (self or role@scope)" value={attest.capacity.clone()}
                    oninput={attest_field(|a| a.capacity.clone(), |a, v| a.capacity = v)} />
                <input id="attest-authority" type="text" placeholder="authority cid (optional)" value={attest.authority.clone()}
                    oninput={attest_field(|a| a.authority.clone(), |a, v| a.authority = v)} />
                <input id="attest-subject" type="text" placeholder="subject" value={attest.subject.clone()}
                    oninput={attest_field(|a| a.subject.clone(), |a, v| a.subject = v)} />
                <input id="attest-action" type="text" placeholder="action" value={attest.action.clone()}
                    oninput={attest_field(|a| a.action.clone(), |a, v| a.action = v)} />
                <input id="attest-resource" type="text" placeholder="resource" value={attest.resource.clone()}
                    oninput={attest_field(|a| a.resource.clone(), |a, v| a.resource = v)} />
                <input id="attest-quota" type="text" placeholder="quota (optional)" value={attest.quota.clone()}
                    oninput={attest_field(|a| a.quota.clone(), |a, v| a.quota = v)} />
                <input id="attest-scope" type="text" placeholder="scope" value={attest.scope.clone()}
                    oninput={attest_field(|a| a.scope.clone(), |a, v| a.scope = v)} />
                <PendingButton id="attest-build-btn" label="Build attestation" busy={*busy} onclick={build_attestation} />
                <div id="attestation-result">
                    { for attest_result.iter().map(|l| html! { <p class="attest-line">{ l.clone() }</p> }) }
                </div>
                <label>{ "Key / offer custody" }</label>
                <input id="custody-handle" type="text" placeholder="handle" value={custody.handle.clone()}
                    oninput={custody_field(|c, v| c.handle = v)} />
                <input id="custody-cid" type="text" placeholder="new cid (rotate/migrate)" value={custody.cid.clone()}
                    oninput={custody_field(|c, v| c.cid = v)} />
                <input id="custody-holder" type="text" placeholder="new holder (migrate)" value={custody.holder.clone()}
                    oninput={custody_field(|c, v| c.holder = v)} />
                <div class="row">
                    <PendingButton id="custody-rotate-btn" label="Rotate" busy={*busy} onclick={custody_act("/portal/custody/rotate", CustodyKind::Rotate)} />
                    <PendingButton id="custody-seal-btn" label="Seal / escrow" busy={*busy} onclick={custody_act("/portal/custody/seal", CustodyKind::Seal)} />
                    <PendingButton id="custody-migrate-btn" label="Migrate" busy={*busy} onclick={custody_act("/portal/custody/migrate", CustodyKind::Migrate)} />
                    <PendingButton id="custody-revoke-btn" label="Revoke" busy={*busy} onclick={custody_act("/portal/custody/revoke", CustodyKind::Revoke)} />
                </div>
                { message_line("custody-msg", &msg) }
            </div>
        }
    }

    #[derive(Clone, Copy)]
    enum CustodyKind {
        Rotate,
        Seal,
        Migrate,
        Revoke,
    }

    #[derive(Clone, Default, PartialEq)]
    struct AttestFields {
        issuer: String,
        capacity: String,
        authority: String,
        subject: String,
        action: String,
        resource: String,
        quota: String,
        scope: String,
    }

    #[derive(Clone, Default, PartialEq)]
    struct CustodyFields {
        handle: String,
        cid: String,
        holder: String,
    }

    /// Resource / workload: get (kind + selector), dry-run, and the signed
    /// apply/edit/scale/rollout acts (name + arg).
    #[function_component(ResourceTile)]
    pub(crate) fn resource_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<String>::new);
        let kind = use_state(|| "Workload".to_owned());
        let selector = use_state(String::new);
        let name = use_state(String::new);
        let arg = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let get = {
            let (auth, rows, kind, selector, msg) = (
                auth.clone(),
                rows.clone(),
                kind.clone(),
                selector.clone(),
                msg.clone(),
            );
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url(
                    "/portal/resource/get",
                    &token,
                    &[("kind", (*kind).trim()), ("selector", (*selector).trim())],
                );
                let (auth, rows, msg) = (auth.clone(), rows.clone(), msg.clone());
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) if r.ok() => rows.set(nonempty_lines(&r.body)),
                        Ok(r) => {
                            if !handle_401(&auth, r.status) {
                                msg.set(Some((strip_marker(&r.body), false)));
                            }
                        }
                        Err(_) => {}
                    }
                });
            })
        };
        {
            let get = get.clone();
            use_effect_with(auth.token.clone(), move |_| {
                get.emit(());
                || ()
            });
        }
        let dry_run = {
            let (auth, msg, busy) = (auth.clone(), msg.clone(), busy.clone());
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (msg, busy) = (msg.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http(
                        "GET",
                        &get_url("/portal/resource/dry-run", &token, &[]),
                        None,
                    )
                    .await
                    {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                    }
                    busy.set(false);
                });
            })
        };
        let act = {
            let (auth, busy, msg, name, arg, get) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                name.clone(),
                arg.clone(),
                get.clone(),
            );
            move |path: &'static str| {
                let (auth, busy, msg, name, arg, get) = (
                    auth.clone(),
                    busy.clone(),
                    msg.clone(),
                    name.clone(),
                    arg.clone(),
                    get.clone(),
                );
                Callback::from(move |_: MouseEvent| {
                    if *busy {
                        return;
                    }
                    let token = auth.token.clone().unwrap_or_default();
                    let body = body_lines(&[&token, (*name).trim(), (*arg).trim()]);
                    let (busy, msg, get) = (busy.clone(), msg.clone(), get.clone());
                    busy.set(true);
                    spawn_local(async move {
                        if let Ok(r) = http("POST", path, Some(&body)).await {
                            msg.set(Some((r.body.trim().to_owned(), r.ok())));
                            if r.ok() {
                                get.emit(());
                            }
                        }
                        busy.set(false);
                    });
                })
            }
        };
        let on_kind = {
            let kind = kind.clone();
            Callback::from(move |e: InputEvent| kind.set(input_value(&e)))
        };
        let on_selector = {
            let selector = selector.clone();
            Callback::from(move |e: InputEvent| selector.set(input_value(&e)))
        };
        let on_name = {
            let name = name.clone();
            Callback::from(move |e: InputEvent| name.set(input_value(&e)))
        };
        let on_arg = {
            let arg = arg.clone();
            Callback::from(move |e: InputEvent| arg.set(input_value(&e)))
        };
        let get_click = {
            let get = get.clone();
            Callback::from(move |_: MouseEvent| get.emit(()))
        };
        html! {
            <div class="tile" id="resource-tile">
                <h3>{ "Resources & workloads" }</h3>
                <p>{ "List, apply, edit, scale, and roll out workloads; preview a dry-run." }</p>
                <label>{ "List resources" }</label>
                <input id="resource-kind" type="text" placeholder="kind" value={(*kind).clone()} oninput={on_kind} />
                <input id="resource-selector" type="text" placeholder="selector (optional)" value={(*selector).clone()} oninput={on_selector} />
                <button type="button" id="resource-get-btn" onclick={get_click}>{ "Get" }</button>
                <PendingButton id="resource-dryrun-btn" label="Dry-run" busy={*busy} onclick={dry_run} />
                <div id="resource-list">
                    { for rows.iter().map(|r| html! { <p class="resource-row">{ r.clone() }</p> }) }
                </div>
                <label>{ "Apply / edit / scale / roll out a workload" }</label>
                <input id="resource-name" type="text" placeholder="name" value={(*name).clone()} oninput={on_name} />
                <input id="resource-arg" type="text" placeholder="image (apply/edit) or replicas (scale)" value={(*arg).clone()} oninput={on_arg} />
                <div class="row">
                    <PendingButton id="resource-apply-btn" label="Apply" busy={*busy} onclick={act("/portal/resource/apply")} />
                    <PendingButton id="resource-edit-btn" label="Edit" busy={*busy} onclick={act("/portal/resource/edit")} />
                    <PendingButton id="resource-scale-btn" label="Scale" busy={*busy} onclick={act("/portal/resource/scale")} />
                    <PendingButton id="resource-rollout-btn" label="Roll out" busy={*busy} onclick={act("/portal/resource/rollout")} />
                </div>
                { message_line("resource-act-msg", &msg) }
            </div>
        }
    }

    /// Observability: explore/query the five signal kinds + save a dashboard.
    #[function_component(ObservabilityTile)]
    pub(crate) fn observability_tile() -> Html {
        let auth = use_auth();
        let rows = use_state(Vec::<String>::new);
        let kind = use_state(|| "metric".to_owned());
        let filter = use_state(String::new);
        let dash_name = use_state(String::new);
        let dash_spec = use_state(String::new);
        let msg = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);
        // Raw PSL query surface: the full observability query language the live
        // store already parses (`/portal/obs/live/query`), which the plain
        // `filter` substring box below cannot express.
        let psl = use_state(String::new);
        let psl_rows = use_state(Vec::<String>::new);
        let psl_msg = use_state(|| None::<(String, bool)>);
        // Schema hints: the live store's real metric names + label keys, so the
        // operator isn't guessing what to select/filter on in a raw PSL query.
        let schema_metrics = use_state(Vec::<String>::new);
        let schema_keys = use_state(Vec::<String>::new);
        {
            let (auth, schema_metrics, schema_keys) =
                (auth.clone(), schema_metrics.clone(), schema_keys.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let (schema_metrics, schema_keys) =
                        (schema_metrics.clone(), schema_keys.clone());
                    let mnames = get_url("/portal/obs/live/metric-names", &token, &[]);
                    let lkeys = get_url("/portal/obs/live/label-keys", &token, &[]);
                    spawn_local(async move {
                        if let Ok(r) = http("GET", &mnames, None).await {
                            if r.ok() {
                                schema_metrics.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                        if let Ok(r) = http("GET", &lkeys, None).await {
                            if r.ok() {
                                schema_keys.set(crate::panels::parse_lines(&r.body, ""));
                            }
                        }
                    });
                }
                || ()
            });
        }

        let explore = {
            let (auth, rows, kind) = (auth.clone(), rows.clone(), kind.clone());
            Callback::from(move |_: ()| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url("/portal/obs/explore", &token, &[("kind", (*kind).trim())]);
                let (auth, rows) = (auth.clone(), rows.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(auth, url).await {
                        rows.set(lines);
                    }
                });
            })
        };
        {
            let explore = explore.clone();
            use_effect_with(auth.token.clone(), move |_| {
                explore.emit(());
                || ()
            });
        }
        let query = {
            let (auth, rows, kind, filter) =
                (auth.clone(), rows.clone(), kind.clone(), filter.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url(
                    "/portal/obs/query",
                    &token,
                    &[("kind", (*kind).trim()), ("filter", (*filter).trim())],
                );
                let (auth, rows) = (auth.clone(), rows.clone());
                spawn_local(async move {
                    if let Some(lines) = get_lines(auth, url).await {
                        rows.set(lines);
                    }
                });
            })
        };
        let save_dashboard = {
            let (auth, busy, msg, dash_name, dash_spec) = (
                auth.clone(),
                busy.clone(),
                msg.clone(),
                dash_name.clone(),
                dash_spec.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = format!(
                    "{}\n{}: {}",
                    token,
                    (*dash_name).trim(),
                    (*dash_spec).trim()
                );
                let (busy, msg) = (busy.clone(), msg.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/obs/dashboard", Some(&body)).await {
                        msg.set(Some((r.body.trim().to_owned(), r.ok())));
                    }
                    busy.set(false);
                });
            })
        };
        let on_kind = {
            let kind = kind.clone();
            Callback::from(move |e: Event| kind.set(select_value(&e)))
        };
        let on_filter = {
            let filter = filter.clone();
            Callback::from(move |e: InputEvent| filter.set(input_value(&e)))
        };
        let on_psl = {
            let psl = psl.clone();
            Callback::from(move |e: InputEvent| psl.set(textarea_value(&e)))
        };
        let run_psl = {
            let (auth, psl, psl_rows, psl_msg) =
                (auth.clone(), psl.clone(), psl_rows.clone(), psl_msg.clone());
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let query = (*psl).trim().to_owned();
                if query.is_empty() {
                    psl_msg.set(Some((
                        "Enter a PSL query, e.g. select: metrics(name = ingest_bandwidth) \
                         range: now-1d"
                            .to_owned(),
                        false,
                    )));
                    return;
                }
                let body = format!("{token}\n{query}");
                let (psl_rows, psl_msg) = (psl_rows.clone(), psl_msg.clone());
                spawn_local(async move {
                    match http("POST", "/portal/obs/live/query", Some(&body)).await {
                        Ok(r) if r.ok() => {
                            let rows = format_psl_response(&r.body);
                            if rows.is_empty() {
                                psl_rows.set(Vec::new());
                                // Distinguish an EMPTY store from a filter that
                                // simply matched nothing, and name the real label
                                // keys, by consulting the live store directly.
                                let kinds = http(
                                    "GET",
                                    &get_url("/portal/obs/live/kinds", &token, &[]),
                                    None,
                                )
                                .await
                                .ok()
                                .filter(HttpResult::ok)
                                .map(|r| r.body)
                                .unwrap_or_default();
                                let keys = http(
                                    "GET",
                                    &get_url("/portal/obs/live/label-keys", &token, &[]),
                                    None,
                                )
                                .await
                                .ok()
                                .filter(HttpResult::ok)
                                .map(|r| r.body)
                                .unwrap_or_default();
                                psl_msg.set(Some((empty_result_hint(&kinds, &keys), true)));
                            } else {
                                psl_msg.set(None);
                                psl_rows.set(rows);
                            }
                        }
                        // Surface the backend's real error (e.g. `PSL-PARSE …`,
                        // `NO-LIVE-SUBSTRATE`) instead of a silent empty result.
                        Ok(r) => {
                            psl_rows.set(Vec::new());
                            psl_msg.set(Some((r.body.trim().to_owned(), false)));
                        }
                        Err(_) => {
                            psl_rows.set(Vec::new());
                            psl_msg.set(Some(("request failed".to_owned(), false)));
                        }
                    }
                });
            })
        };
        let on_name = {
            let dash_name = dash_name.clone();
            Callback::from(move |e: InputEvent| dash_name.set(input_value(&e)))
        };
        let on_spec = {
            let dash_spec = dash_spec.clone();
            Callback::from(move |e: InputEvent| dash_spec.set(input_value(&e)))
        };
        let explore_click = {
            let explore = explore.clone();
            Callback::from(move |_: MouseEvent| explore.emit(()))
        };
        html! {
            <div class="tile" id="observability-tile">
                <h3>{ "Observability" }</h3>
                <p>{ "Explore and query metrics/logs/traces/profiles/metadata; save a dashboard." }</p>
                <label>{ "Run a PSL query" }</label>
                <p class="hint">{ "The full observability query language, run over the live store: \
                    select: <kind>(<label = value>, …) [where: <label = value>, …] \
                    range: now-<dur> [correlate: { window: <dur>, anchor: <kind> }]. \
                    Returns matched signals plus any correlate groups; a malformed query \
                    reports the parse error. (The 'filter' box below is a plain substring \
                    match, not PSL.)" }</p>
                <div id="obs-schema" class="obs-schema">
                    <p class="hint">{ "Available in the live store right now — click nothing, \
                        just use these in your query:" }</p>
                    <p class="hint">
                        <strong>{ "label keys: " }</strong>
                        if schema_keys.is_empty() {
                            { "(none yet)" }
                        } else {
                            { schema_keys.join(", ") }
                        }
                    </p>
                    <p class="hint">
                        <strong>{ "metric names: " }</strong>
                        if schema_metrics.is_empty() {
                            { "(none yet)" }
                        } else {
                            { schema_metrics.join(", ") }
                        }
                    </p>
                    <p class="hint">{ "Every signal is stamped node=<this node's peer id>; \
                        filter any kind with where: node = <id>. Metrics also carry \
                        metric=<name>; logs/traces carry node; metadata carries cell/peer." }</p>
                </div>
                <textarea id="obs-psl" rows="3"
                    placeholder="select: logs where: node = <peer-id> range: now-1d"
                    value={(*psl).clone()} oninput={on_psl}></textarea>
                <button type="button" id="obs-psl-btn" onclick={run_psl}>{ "Run PSL query" }</button>
                { message_line("obs-psl-msg", &psl_msg) }
                <div id="obs-psl-list">
                    { for psl_rows.iter().map(|r| html! { <p class="obs-row">{ r.clone() }</p> }) }
                </div>
                <label>{ "Explore / query signals" }</label>
                <select id="obs-kind" onchange={on_kind}>
                    <option value="metric">{ "metric" }</option>
                    <option value="log">{ "log" }</option>
                    <option value="trace">{ "trace" }</option>
                    <option value="profile">{ "profile" }</option>
                    <option value="metadata">{ "metadata" }</option>
                </select>
                <input id="obs-filter" type="text" placeholder="substring filter (optional) — not PSL" value={(*filter).clone()} oninput={on_filter} />
                <div class="row">
                    <button type="button" id="obs-explore-btn" onclick={explore_click}>{ "Explore" }</button>
                    <button type="button" id="obs-query-btn" onclick={query}>{ "Query" }</button>
                </div>
                <div id="obs-list">
                    { for rows.iter().map(|r| html! { <p class="obs-row">{ r.clone() }</p> }) }
                </div>
                <div id="obs-guided-builder" class="obs-builder">
                    <label>{ "Guided PSL query builder" }</label>
                    <p class="hint">{ "select/where fields autofill from the live metadata index; \
                        the Correlate panel pivots to the other signal kinds within a window. \
                        Same builder, one per signal kind (switch it with the selector above)." }</p>
                    {
                        // The kind selector above chooses which guided builder
                        // to mount — the ROI's "same builder, five entry points."
                        // All fetch the REAL live-store typeahead + query
                        // endpoints (see web_serve.rs `/portal/obs/live/*`).
                        match (*kind).as_str() {
                            "log" => html! { <ExploreLogsBuilder
                                label_keys_path="/portal/obs/live/label-keys"
                                label_values_path="/portal/obs/live/label-values"
                                query_path="/portal/obs/live/query" /> },
                            "trace" => html! { <ExploreTracesBuilder
                                label_keys_path="/portal/obs/live/label-keys"
                                label_values_path="/portal/obs/live/label-values"
                                query_path="/portal/obs/live/query" /> },
                            "profile" => html! { <ExploreProfilesBuilder
                                label_keys_path="/portal/obs/live/label-keys"
                                label_values_path="/portal/obs/live/label-values"
                                query_path="/portal/obs/live/query" /> },
                            "metadata" => html! { <ExploreMetadataBuilder
                                label_keys_path="/portal/obs/live/label-keys"
                                label_values_path="/portal/obs/live/label-values"
                                query_path="/portal/obs/live/query" /> },
                            _ => html! { <ExploreBuilder
                                label_keys_path="/portal/obs/live/label-keys"
                                label_values_path="/portal/obs/live/label-values"
                                query_path="/portal/obs/live/query" /> },
                        }
                    }
                </div>
                <label>{ "Save a dashboard" }</label>
                <input id="obs-dashboard-name" type="text" placeholder="name" value={(*dash_name).clone()} oninput={on_name} />
                <input id="obs-dashboard-spec" type="text" placeholder="spec" value={(*dash_spec).clone()} oninput={on_spec} />
                <PendingButton id="obs-dashboard-btn" label="Save dashboard" busy={*busy} onclick={save_dashboard} />
                { message_line("obs-dashboard-msg", &msg) }
            </div>
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

    /// The whole authenticated portal: greeting + every capability tile + a
    /// sign-out that clears the session.
    #[function_component(Portal)]
    pub fn portal() -> Html {
        let auth = use_auth();
        let handle = auth.user.clone().unwrap_or_default();
        let signout = {
            let auth = auth.clone();
            Callback::from(move |_: MouseEvent| auth.dispatch(AuthAction::Logout))
        };
        html! {
            <section id="portal" class="portal">
                <h2 id="greeting">{ format!("Welcome, {handle}") }</h2>
                <div class="who" id="portal-who">{ format!("Signed in as {handle}") }</div>
                <div class="tile"><h3>{ "Node status" }</h3><p id="node-status">{ "Session admitted. Your node is reachable." }</p></div>
                <NodeStatusTile />
                <SwarmTile />
                <InboxTile />
                <IdentityTile />
                <MembersTile />
                <SessionsTile />
                <TrustTile />
                <ResourceTile />
                <ObservabilityTile />
                <button type="button" id="signout" class="signout" onclick={signout}>{ "Sign out" }</button>
            </section>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encode_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(query_encode("a b/c=d&e"), "a%20b%2Fc%3Dd%26e");
        assert_eq!(query_encode("tok-1_2.3~x"), "tok-1_2.3~x");
    }

    #[test]
    fn empty_result_hint_reports_an_empty_store() {
        let kinds = "KIND metric COUNT 0\nKIND log COUNT 0\nKIND trace COUNT 0\n\
                     KIND profile COUNT 0\nKIND metadata COUNT 0\n";
        let hint = empty_result_hint(kinds, "");
        assert!(hint.contains("live store is empty"), "got: {hint}");
    }

    #[test]
    fn empty_result_hint_reports_held_counts_and_real_label_keys() {
        // The exact situation the operator hit: the store HAS signals (labeled
        // `node`), but their `where: cell = …` matched nothing. The hint must
        // say what's held and name the real key (`node`), never claim empty.
        let kinds = "KIND metric COUNT 128\nKIND log COUNT 64\nKIND trace COUNT 8\n\
                     KIND profile COUNT 0\nKIND metadata COUNT 4\n";
        let hint = empty_result_hint(kinds, "node\n");
        assert!(!hint.contains("empty"), "must not claim empty: {hint}");
        assert!(hint.contains("metric 128"), "got: {hint}");
        assert!(hint.contains("log 64"), "got: {hint}");
        assert!(
            !hint.contains("profile"),
            "zero-count kinds omitted: {hint}"
        );
        assert!(hint.contains("available label keys: node"), "got: {hint}");
    }

    #[test]
    fn format_psl_response_renders_signals_and_correlate_groups() {
        let body = "SIGNAL abc123 KIND metric TICK 7 LABELS node=peer1;metric=node_cpu_ticks \
                     PAYLOAD node_cpu_ticks 42 @7\n\
                    SIGNAL def456 KIND log TICK 8 LABELS node=peer1 \
                     PAYLOAD level=info msg=served request\n\
                    GROUP abc123 MEMBERS abc123,def456\n";
        assert_eq!(
            format_psl_response(body),
            vec![
                "[t=7] metric node=peer1 metric=node_cpu_ticks: node_cpu_ticks 42 @7".to_owned(),
                "[t=8] log node=peer1: level=info msg=served request".to_owned(),
                "group abc123: abc123, def456".to_owned(),
            ]
        );
    }

    #[test]
    fn format_psl_response_falls_back_without_tick_labels_fields() {
        // A SIGNAL line without the TICK/LABELS fields still renders.
        assert_eq!(
            format_psl_response("SIGNAL abc KIND log PAYLOAD hello world"),
            vec!["log abc: hello world".to_owned()]
        );
    }

    #[test]
    fn format_psl_response_is_empty_for_a_no_match_body() {
        // An empty / whitespace-only body must yield no rows (the caller shows
        // a "no matching signals" notice) — never a fabricated placeholder row.
        assert!(format_psl_response("").is_empty());
        assert!(format_psl_response("   \n  \n").is_empty());
    }

    #[test]
    fn format_psl_response_passes_unrecognized_lines_through_verbatim() {
        // A line matching neither shape is preserved, so nothing is silently
        // dropped (e.g. a future line kind, or a malformed member list).
        assert_eq!(
            format_psl_response("SIGNAL only-an-id-no-kind\nGROUP anchor-with-no-members"),
            vec![
                "SIGNAL only-an-id-no-kind".to_owned(),
                "GROUP anchor-with-no-members".to_owned(),
            ]
        );
    }

    #[test]
    fn get_url_appends_token_and_nonempty_params_only() {
        assert_eq!(
            get_url(
                "/portal/resource/get",
                "t k",
                &[("kind", "Workload"), ("selector", "")]
            ),
            "/portal/resource/get?token=t%20k&kind=Workload"
        );
    }

    #[test]
    fn login_wire_and_interpret_round_trip() {
        let wire = login_wire("spencer", "pw", 5);
        let parsed = pillar_web_api::LoginRequest::from_body(&wire);
        assert_eq!(
            (
                parsed.identifier.as_str(),
                parsed.password.as_str(),
                parsed.nonce_id
            ),
            ("spencer", "pw", 5)
        );
        assert_eq!(
            interpret_login(true, "OK spencer", "x"),
            Ok("spencer".to_owned())
        );
        assert_eq!(
            interpret_login(true, "OK", "spencer"),
            Ok("spencer".to_owned())
        );
        assert_eq!(
            interpret_login(false, "DENIED unlock-failed", "x"),
            Err("unlock-failed".to_owned())
        );
    }

    #[test]
    fn bootstrap_wire_and_interpret() {
        assert_eq!(bootstrap_wire("cell", "h", "f", "passkey"), "cell\nh\nf\npasskey");
        assert!(interpret_bootstrap(true, "BOOTSTRAPPED cell").is_ok());
        assert_eq!(
            interpret_bootstrap(false, "DENIED CellNameInUse"),
            Err("CellNameInUse".to_owned())
        );
    }

    #[test]
    fn name_check_interpretation() {
        assert_eq!(interpret_name_check(true, "FREE"), NameHint::Free);
        assert_eq!(
            interpret_name_check(true, "IN-USE served by peer-7"),
            NameHint::InUse("served by peer-7".to_owned())
        );
        // Best-effort: an error/unreachable check never blocks.
        assert_eq!(interpret_name_check(false, "boom"), NameHint::Idle);
        assert_eq!(interpret_name_check(true, ""), NameHint::Idle);
    }

    #[test]
    fn inbox_line_and_cid_extraction() {
        assert_eq!(
            parse_inbox_line("7 node alice extra"),
            Some(InboxRow {
                id: "7".into(),
                kind: "node".into(),
                subject: "alice".into()
            })
        );
        assert_eq!(parse_inbox_line("bad"), None);
        assert_eq!(
            extract_cid("APPROVED bafyabc123 done"),
            Some("bafyabc123".to_owned())
        );
        assert_eq!(extract_cid("APPROVED nothing"), None);
    }

    #[test]
    fn swarm_parse_and_generate_round_trip() {
        let v =
            parse_swarm("SWARM public 0011223344556677\nSEED /ip4/192.0.2.5/tcp/4001/p2p/abc\n");
        assert_eq!(v.kind, "public");
        assert_eq!(v.fingerprint, "0011223344556677");
        assert_eq!(v.seeds, vec!["/ip4/192.0.2.5/tcp/4001/p2p/abc".to_owned()]);
        // Missing fields fall back to the em-dash placeholder; no seeds is empty.
        let empty = parse_swarm("");
        assert_eq!(
            (empty.kind.as_str(), empty.fingerprint.as_str()),
            ("\u{2014}", "\u{2014}")
        );
        assert!(empty.seeds.is_empty());
        // Generate parses KEY + FINGERPRINT; a body without a KEY is an error.
        assert_eq!(
            interpret_generate(true, "KEY deadbeef\nFINGERPRINT aabbccdd\n"),
            Ok(GeneratedKey {
                key: "deadbeef".to_owned(),
                fingerprint: "aabbccdd".to_owned()
            })
        );
        assert_eq!(
            interpret_generate(false, "DENIED not-authenticated"),
            Err("not-authenticated".to_owned())
        );
        assert!(interpret_generate(true, "FINGERPRINT aabbccdd").is_err());
    }

    #[test]
    fn status_parsing_fills_placeholders_and_splits_peers() {
        let s = parse_status(
            "PEER-ID 12D3Koo\nLISTEN /ip4/…\nUPTIME-SECS 42\nPEERS a,b,c\nLEASE-HOLDER fp:abc",
        );
        assert_eq!(s.peer_id, "12D3Koo");
        assert_eq!(s.uptime_secs, "42");
        assert_eq!(s.peers, vec!["a", "b", "c"]);
        assert_eq!(s.peer_count, "3");
        assert_eq!(s.lease_holder, "fp:abc");
        let empty = parse_status("");
        assert_eq!(empty.peer_id, "\u{2014}");
        assert_eq!(empty.listen, "none");
    }

    #[test]
    fn identity_parsing() {
        let v = parse_identity("CID bafyid\nGEN 3\nDOMAIN d1 key=k1\nDOMAIN d2 key=k2");
        assert_eq!(v.cid, "bafyid");
        assert_eq!(v.generation, "3");
        assert_eq!(v.domains, vec!["d1 key=k1", "d2 key=k2"]);
    }

    #[test]
    fn session_line_parsing() {
        let s = parse_session_line("SESSION s1 NODE n1 ISSUED 10 EXPIRY 99 CURRENT yes").unwrap();
        assert_eq!(
            (
                s.id.as_str(),
                s.node.as_str(),
                s.issued_at.as_str(),
                s.expiry.as_str(),
                s.current
            ),
            ("s1", "n1", "10", "99", true)
        );
        assert!(
            !parse_session_line("SESSION s1 NODE n1 ISSUED 10 EXPIRY 99 CURRENT no")
                .unwrap()
                .current
        );
        assert!(parse_session_line("garbage").is_none());
    }

    #[test]
    fn credential_line_parsing() {
        let c = parse_credential_line("CRED aWQ yubikey-blue deleteme.example.com 100 250 7")
            .unwrap();
        assert_eq!(c.id, "aWQ");
        assert_eq!(c.label, "yubikey-blue");
        assert_eq!(c.rp_id, "deleteme.example.com");
        assert_eq!(c.created_at, "100");
        assert_eq!(c.last_used, "250");
        assert_eq!(c.sign_count, "7");
        // `-` sentinels for an unlabeled, never-used credential decode to empty.
        let c2 = parse_credential_line("CRED aWQ - - 100 - 0").unwrap();
        assert_eq!(c2.label, "");
        assert_eq!(c2.rp_id, "");
        assert_eq!(c2.last_used, "-");
        assert!(parse_credential_line("SESSION x").is_none());
        assert!(parse_credential_line("CRED too few").is_none());
    }

    #[test]
    fn attestation_and_topology_bodies_match_field_order() {
        // 9-field attestation body, capacity defaulting handled by the caller.
        let b = body_lines(&["tok", "iss", "self", "", "subj", "act", "res", "", "scope"]);
        assert_eq!(b, "tok\niss\nself\n\nsubj\nact\nres\n\nscope");
        // 8-field topology attest body.
        let t = body_lines(&["tok", "iss", "self", "", "node", "rack", "r1", "scope"]);
        assert_eq!(t.split('\n').count(), 8);
    }

    #[test]
    fn friendly_error_maps_known_reasons() {
        assert!(friendly_error("no-offer-for-user").contains("no key offer"));
        assert!(friendly_error("bad-nonce").contains("expired"));
        assert!(friendly_error("").contains("please try again"));
        assert_eq!(friendly_error("weird"), "Login failed: weird");
    }

    #[test]
    fn inbox_decide_wire_is_id_then_token() {
        assert_eq!(inbox_decide_wire("7", "tok"), "7\ntok");
    }
}
