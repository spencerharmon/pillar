//! Serves the web PORTAL from the deployed `pillar node run` process on a
//! configurable, **non-loopback** bind (`--web-bind`/`PILLAR_WEB_BIND`), so a
//! k8s Service can reach it (flux's `pillar-web-ingress-tls` gates on this).
//!
//! `pillar --web` (see `pillar-cli/src/main.rs`) stays localhost-only for the
//! no-identity-yet bootstrap flow; THIS surface is the one that leaves the
//! host, and it never inherits that surface's loopback exemption.
//!
//! ## Node-side custody login (the REVISED model)
//!
//! This portal implements **node-side key custody on a trusted node** (see
//! [`pillar_web::node_custody`], refining `specs/NodeCustodyLogin.tla`). It
//! SUPERSEDES the old client-side model that asked for THREE fields (handle +
//! CID + password). The user now supplies exactly **TWO** inputs — a user
//! identifier and an unlock factor (password/passkey); **no CID field** (a
//! third field would be a bug for a trusted node). The NODE resolves the
//! user's node-sealed key offer from the cell DB (CID → sealed blob), strips
//! the node-seal with its node key, unlocks the operational key SERVER-SIDE
//! (argon2id last line), signs the origin+expiry nonce, runs the shared
//! WoT/RBAC decider, and admits the user into an authenticated portal view
//! greeting them by handle with node management. Nonce/sign/verify stay hidden
//! plumbing.
//!
//! SECURITY MODEL — the password crosses TLS to the trusted node, which holds
//! the key ONLY because the cell sealed an offer to it (per-node, revocable —
//! that per-node seal IS the access control), NOT a blanket leak. Client-side
//! signing / caBLE ([`pillar_web::key_login`]) remains only the
//! untrusted/foreign-node path; passkey/WebAuthn stays an optional stronger
//! unlock factor.
//!
//! ## First-run bootstrap (operator-driven)
//!
//! On a FRESH, unbootstrapped node the `/` page guides the OPERATOR to (a)
//! create the cell, then (b) create the first user in the same guided step,
//! which links cell↔initial-user and CONSUMES the one-shot
//! `cell_key_can_create_user` capability (auto-flips false after the first
//! create — see [`pillar_web::node_custody::CellBootstrap`]). A bootstrapped
//! node shows the two-field login screen directly. The swarm DELIVERS this
//! flow; it never runs it — the operator drives it.
//!
//! ## Transport: HTTP/1.1
//!
//! The surface speaks HTTP/1.1 so a browser, `curl`, or a k8s Ingress can
//! reach it. Endpoints:
//!
//! - `GET /` — the graphical portal UI (HTML, 200): the two-field login (or,
//!   on a fresh node, the create-cell → create-first-user bootstrap flow).
//! - `GET /nonce` — a fresh origin/expiry-bound challenge nonce; body
//!   `NONCE <id> <expiry>`.
//! - `POST /login` — body `<identifier>\n<password>`: node-side custody
//!   login; 200 `OK` (+ `X-Pillar-Session`) with the greeted handle, or 401
//!   `DENIED <reason>`.
//! - `GET /bootstrap/status` — `FRESH` (unbootstrapped) or `BOOTSTRAPPED`.
//! - `POST /bootstrap/create-cell` — body `<cell-id>`: operator step (a).
//! - `POST /bootstrap/create-user` — body `<handle>\n<password>`: operator
//!   step (b), consuming the one-shot capability AND, atomically, applying
//!   the key-distribution label to this node + escrowing the new user's
//!   node-sealed operational-key offer to it, so this node can resolve it at
//!   the very next login.
//! - `POST /ping` — a stand-in signing action gated through
//!   [`pillar_web::authorize_nonloopback_signing_action`]; a non-loopback
//!   peer must present an admitted session (`X-Pillar-Session`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};

use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_web::key_login::{LoginSession, Origin};
use pillar_web::node_custody::{
    BootstrapError, CellBootstrap, Cid, NodeCustodyError, NodeCustodySession, NodeCustodyVerifier,
    NodeKey,
};
use pillar_web::{authorize_nonloopback_signing_action, bind_web};
use pillar_wot_authority::{FencedActor, WotAuthority};

/// The server-side state the node-side-custody portal needs: the node-custody
/// verifier (holding this node's node key + its cell-DB view of node-sealed
/// offers), the shared WoT authority/actor login admission resolves through
/// (never a parallel one), the one-shot bootstrap capability state, and the
/// admitted portal sessions keyed by the bearer token handed to the client.
pub struct WebAuthContext {
    verifier: NodeCustodyVerifier,
    authority: WotAuthority,
    actor: FencedActor,
    bootstrap: CellBootstrap,
    /// Admitted node-custody portal sessions, keyed by the `X-Pillar-Session`
    /// bearer. HTTP is connection-per-request, so an admitted session must
    /// outlive the connection it was minted on.
    sessions: HashMap<String, NodeCustodySession>,
    /// The `pillar_web` login-session view (for the shared non-loopback gate).
    login_sessions: HashMap<String, LoginSession>,
    next_session: u64,
}

impl WebAuthContext {
    /// A fresh context for a node identified by `node`, holding node key
    /// `node_secret`, serving `origin`, with `owner` as the WoT authority root
    /// at `max_depth`. The node starts UNBOOTSTRAPPED (its `/` serves the
    /// create-cell → create-first-user flow) with no offers provisioned yet.
    #[must_use]
    pub fn new(
        origin: impl Into<String>,
        node: NodeId,
        node_secret: impl Into<String>,
        owner: NodeId,
        max_depth: u8,
    ) -> Self {
        let origin = origin.into();
        let authority = WotAuthority::new(owner, max_depth);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        let node_key = NodeKey::new(node, node_secret);
        WebAuthContext {
            verifier: NodeCustodyVerifier::new(node_key, Origin::from(origin.as_str())),
            authority,
            actor,
            bootstrap: CellBootstrap::new(),
            sessions: HashMap::new(),
            login_sessions: HashMap::new(),
            next_session: 0,
        }
    }

    /// Chain `subject` to the authority root at `level`, admitting it as
    /// WoT-authoritative — required before a login for its operational subkey
    /// can admit.
    pub fn admit_subject(&mut self, subject: NodeId, level: u8) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject, level);
        self.actor.refresh(&self.authority);
    }

    /// Provision a node-sealed key offer this node custodies (the cell sealed
    /// it to THIS node): the user `identifier` (greeted by `handle`) resolves
    /// to `cid`, whose blob unlocks the operational `subkey` under `password`
    /// (`secret` = the operational-key material). In a real node the label +
    /// offer arrive via `pillar_key_distribution`.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: pillar_identity::NodeSubkey,
        password: &str,
        secret: &str,
    ) {
        self.verifier
            .provision_offer(identifier, handle, cid, subkey, password, secret);
    }

    /// Mutable access to the one-shot bootstrap capability state — the `/`
    /// bootstrap flow drives this.
    pub fn bootstrap_mut(&mut self) -> &mut CellBootstrap {
        &mut self.bootstrap
    }

    /// Step (b) of the bootstrap flow, DONE ATOMICALLY: create the first user
    /// AND seal their operational key's offer to THIS node — applying the
    /// key-distribution label + escrowing the node-sealed L1 offer (per the
    /// always-node-sealed offer mechanism) — so the very node that created
    /// the user can immediately resolve, strip, and unlock it at first login.
    /// Without this, a fresh bootstrap node correctly reports the untrusted-
    /// node `no-offer-for-user` mode even for the user it just created — the
    /// observed bug. Shared by both the CLI and the web-UI create-first-user
    /// steps (crates/pillar-cli/src/web_serve.rs) so neither drifts.
    ///
    /// `password` is the user's chosen unlock factor (never retained in the
    /// clear beyond this call); the scoped, revocable OPERATIONAL key is what
    /// gets escrowed — the cold root is never touched, and node authority is
    /// unchanged (this node only ever holds what the cell explicitly seals to
    /// it, per-node/opt-in/revocable).
    ///
    /// # Errors
    ///
    /// Propagates [`BootstrapError`] from the underlying [`CellBootstrap`]
    /// step (no cell yet / capability already spent) — the offer is escrowed
    /// only once that step succeeds.
    pub fn bootstrap_create_first_user(
        &mut self,
        handle: impl Into<String>,
        password: &str,
    ) -> Result<(), BootstrapError> {
        let handle = handle.into();
        self.bootstrap.create_first_user(handle.clone())?;

        // (1) Apply the key-distribution label: chain the new user's
        // operational subkey into the WoT authority at the root's own
        // budget, so it is authoritative once admitted.
        let subkey = NodeSubkey::from(format!("op-subkey-{handle}").as_str());
        let level = self.authority.max_depth();
        self.admit_subject(subkey.node_id(), level);

        // (2) Escrow the scoped operational key as a node-sealed L1 offer to
        // THIS bootstrap node's own node key — the per-node seal IS the
        // access control; no other node custodies this offer.
        let cid = Cid::from(format!("cid-{handle}").as_str());
        let secret = format!("operational-key-material-{handle}");
        self.provision_offer(handle.clone(), handle, cid, subkey, password, &secret);

        Ok(())
    }

    /// The bootstrap capability state.
    #[must_use]
    pub fn bootstrap(&self) -> &CellBootstrap {
        &self.bootstrap
    }

    fn store_session(&mut self, session: NodeCustodySession) -> String {
        let token = format!("s{}", self.next_session);
        self.next_session += 1;
        // Mirror a `pillar_web` login-session view keyed by the same token so
        // the shared non-loopback signing gate can resolve it.
        self.login_sessions.insert(
            token.clone(),
            LoginSession {
                subject: session.subject.clone(),
                nonce_id: session.nonce_id,
                watermark: session.watermark,
            },
        );
        self.sessions.insert(token.clone(), session);
        token
    }

    fn login_session_for(&self, token: &str) -> Option<&LoginSession> {
        self.login_sessions.get(token)
    }
}

/// Bind the portal listener on `addr:port` — `addr` MAY be non-loopback (see
/// module docs); the caller must still gate every signing action through
/// [`authorize_nonloopback_signing_action`].
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the address/port cannot be bound.
pub fn bind(addr: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    bind_web(addr, port)
}

/// Serve HTTP/1.1 on `listener` until it errors or the process is torn down.
/// Blocking — run on a dedicated thread.
pub fn serve(listener: TcpListener, ctx: &mut WebAuthContext) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        handle_connection(stream, ctx);
    }
}

/// The graphical portal UI served at `GET /` — a real login page (two fields:
/// user identifier + unlock factor, NO CID), whose embedded script drives the
/// `GET /nonce` → `POST /login` handshake as hidden plumbing and, on success,
/// transitions into an authenticated portal view greeting the user by handle
/// with node management. On a FRESH node the same page guides the operator
/// through the create-cell → create-first-user bootstrap flow. The origin is
/// derived from the browser (`location`) at runtime, so no infrastructure
/// identifier is embedded in this public source.
const LANDING_PAGE: &str = include_str!("web_login.html");

/// A parsed HTTP request: method, path, and body.
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

/// Read and parse one HTTP/1.1 request from `reader`. Returns `None` on a
/// closed connection or an unparseable request line.
fn read_http_request(reader: &mut impl BufRead) -> Option<HttpRequest> {
    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_ok() {
            body = String::from_utf8_lossy(&buf).into_owned();
        }
    }

    Some(HttpRequest { method, path, body })
}

/// An HTTP response to write back.
struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    session_token: Option<String>,
    body: String,
}

impl HttpResponse {
    fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
        );
        if let Some(token) = &self.session_token {
            head.push_str(&format!("X-Pillar-Session: {token}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())?;
        stream.flush()
    }
}

fn handle_connection(mut stream: TcpStream, ctx: &mut WebAuthContext) {
    let Ok(peer) = stream.peer_addr() else { return };
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let Some(request) = read_http_request(&mut reader) else {
        return;
    };
    let response = dispatch_http(ctx, &peer, &request);
    let _ = response.write_to(&mut stream);
}

/// Map an HTTP request onto the portal action, preserving the auth gate.
fn dispatch_http(
    ctx: &mut WebAuthContext,
    peer: &SocketAddr,
    request: &HttpRequest,
) -> HttpResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    match (request.method.as_str(), path) {
        ("GET", "/") => HttpResponse {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            session_token: None,
            body: LANDING_PAGE.to_owned(),
        },
        ("GET", "/bootstrap/status") => {
            let status = if ctx.bootstrap().is_bootstrapped() {
                "BOOTSTRAPPED"
            } else {
                "FRESH"
            };
            text_response(200, "OK", status.to_owned())
        }
        ("POST", "/bootstrap/create-cell") => {
            let cell = request.body.trim();
            if cell.is_empty() {
                return text_response(400, "Bad Request", "MISSING cell id".to_owned());
            }
            match ctx.bootstrap_mut().create_cell(NodeId::from(cell)) {
                Ok(()) => text_response(200, "OK", "CELL-CREATED".to_owned()),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("POST", "/bootstrap/create-user") => {
            // Body: "<handle>\n<password>" — the operator's chosen unlock
            // factor for the new user, escrowed atomically (see
            // `bootstrap_create_first_user`) so login works immediately.
            let mut lines = request.body.lines();
            let handle = lines.next().unwrap_or("").trim();
            let password = lines.next().unwrap_or("").trim();
            if handle.is_empty() || password.is_empty() {
                return text_response(400, "Bad Request", "MISSING handle-or-password".to_owned());
            }
            match ctx.bootstrap_create_first_user(handle, password) {
                Ok(()) => text_response(200, "OK", format!("USER-CREATED {handle}")),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("GET", "/nonce") => {
            let nonce = ctx.verifier.issue_nonce(u64::MAX);
            text_response(200, "OK", format!("NONCE {} {}", nonce.id(), nonce.expiry()))
        }
        ("POST", "/login") => dispatch_login(ctx, request),
        ("POST", "/ping") => {
            // Resolve the admitted session from the bearer token, then run the
            // UNCHANGED shared gate: a non-loopback peer with no admitted
            // session is still always refused.
            let token = request.body.trim();
            let session = ctx.login_session_for(token).cloned();
            match authorize_nonloopback_signing_action(peer, session.as_ref()) {
                Ok(()) => text_response(200, "OK", "PONG".to_owned()),
                Err(e) => text_response(403, "Forbidden", format!("REFUSED {e:?}")),
            }
        }
        _ => text_response(404, "Not Found", "not found".to_owned()),
    }
}

/// Drive one node-side custody login: parse the TWO fields (identifier +
/// password), issue nothing here (the client already fetched a nonce), and let
/// the node resolve+strip+unlock+sign+admit SERVER-SIDE.
fn dispatch_login(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    // Body: "<identifier>\n<password>\n<nonce_id>". The client fetched the
    // nonce via GET /nonce and echoes its id so the server can bind the login
    // to that exact challenge; the password + identifier are the two human
    // fields. The CID is NEVER in the body — the node resolves it.
    let mut lines = request.body.lines();
    let identifier = lines.next().unwrap_or("").trim();
    let password = lines.next().unwrap_or("").trim();
    let nonce_id: u64 = lines.next().unwrap_or("").trim().parse().unwrap_or(u64::MAX);

    if identifier.is_empty() || password.is_empty() {
        return text_response(401, "Unauthorized", "DENIED missing-field".to_owned());
    }

    let authority = ctx.authority.clone();
    let actor = ctx.actor.clone();
    match ctx
        .verifier
        .admit(identifier, password, nonce_id, 0, &authority, &actor)
    {
        Ok(session) => {
            let handle = session.handle.clone();
            let token = ctx.store_session(session);
            HttpResponse {
                status: 200,
                reason: "OK",
                content_type: "text/plain; charset=utf-8",
                session_token: Some(token),
                body: format!("OK {handle}\n"),
            }
        }
        Err(e) => {
            let reason = login_reason(&e);
            text_response(401, "Unauthorized", format!("DENIED {reason}"))
        }
    }
}

/// Map a [`NodeCustodyError`] onto a stable in-UI reason token — including the
/// NEW node-custody mode "this node lacks the key-distribution label / has no
/// offer for this user".
fn login_reason(e: &NodeCustodyError) -> &'static str {
    match e {
        NodeCustodyError::NoOfferForUser => "no-offer-for-user",
        NodeCustodyError::NoCustody => "no-custody-on-this-node",
        NodeCustodyError::UnlockFailed => "unlock-failed",
        NodeCustodyError::NotAuthorized(_) => "not-authorized",
        NodeCustodyError::BadNonce => "bad-nonce",
    }
}

fn text_response(status: u16, reason: &'static str, mut body: String) -> HttpResponse {
    if !body.ends_with('\n') {
        body.push('\n');
    }
    HttpResponse {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        session_token: None,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_identity::NodeSubkey;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "operational-key-material";
    const ORIGIN: &str = "https://pillar.example.com";

    fn remote_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4242)
    }

    // A node that already custodies an offer for alice, WoT-chained + admitted.
    fn provisioned_ctx() -> (WebAuthContext, NodeSubkey) {
        let subkey = NodeSubkey::from("op-subkey-alice");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        ctx.admit_subject(subkey.node_id(), 4);
        ctx.provision_offer(
            "alice@pillar",
            "Alice",
            Cid::from("cid-alice"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        (ctx, subkey)
    }

    fn get(ctx: &mut WebAuthContext, path: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "GET".into(),
                path: path.into(),
                body: String::new(),
            },
        )
    }

    fn post(ctx: &mut WebAuthContext, path: &str, body: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                body: body.into(),
            },
        )
    }

    #[test]
    fn node_run_web_surface_binds_a_non_loopback_address() {
        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            !addr.ip().is_loopback(),
            "node-run web surface must bind a non-loopback address"
        );
    }

    // The full HTTP node-side custody login: GET /nonce, then POST /login with
    // exactly TWO fields (identifier + password, NO CID) — the node resolves
    // the offer, strips the seal, unlocks the key, signs, and admits. Then a
    // signing action POST /ping with and without the session token.
    #[test]
    fn two_field_node_custody_login_then_ping_dispatch_preserves_the_auth_gate() {
        let (mut ctx, _subkey) = provisioned_ctx();

        // Unauthenticated signing action against a non-loopback peer: 403.
        let refused = post(&mut ctx, "/ping", "");
        assert_eq!(refused.status, 403, "unauthenticated non-loopback ping must be refused");

        // GET /nonce.
        let nonce_resp = get(&mut ctx, "/nonce");
        assert_eq!(nonce_resp.status, 200);
        let mut parts = nonce_resp.body.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id");

        // POST /login — TWO fields + the nonce id (hidden plumbing). NO CID.
        let login_body = format!("alice@pillar\n{PASSWORD}\n{id}");
        let login_resp = post(&mut ctx, "/login", &login_body);
        assert_eq!(login_resp.status, 200, "login body: {}", login_resp.body);
        assert!(
            login_resp.body.starts_with("OK Alice"),
            "the node greets the user by handle: {}",
            login_resp.body
        );
        let token = login_resp.session_token.expect("a session token");

        // POST /ping WITH the token → 200 PONG.
        let ping_resp = post(&mut ctx, "/ping", &token);
        assert_eq!(ping_resp.status, 200, "authenticated ping: {}", ping_resp.body);
        assert!(ping_resp.body.starts_with("PONG"));
    }

    #[test]
    fn login_form_asks_two_fields_only_no_cid_field() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("text/html"));
        let body = &resp.body;

        // A real graphical login FORM with EXACTLY the two human inputs.
        assert!(body.contains("<form"), "must render a login form");
        assert!(
            body.contains("id=\"identifier\"") && body.contains("id=\"password\""),
            "must present the identifier + unlock-factor inputs"
        );
        // NO CID field — a third field would be a bug for node-side custody.
        assert!(
            !body.contains("id=\"cid\"") && !body.contains("id=\"keymat\""),
            "the node-side custody login must NOT ask for a CID / key material"
        );
        // The script drives the handshake as hidden plumbing.
        assert!(body.contains("<script"), "must embed a client-side script");
        assert!(
            body.contains("/nonce") && body.contains("/login"),
            "the script must drive the /nonce and /login endpoints itself"
        );
        // It transitions into an authenticated portal view.
        assert!(
            body.contains("id=\"portal\""),
            "must transition into an authenticated portal view"
        );
    }

    #[test]
    fn root_page_is_the_interactive_portal_not_the_protocol_description() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let lower = resp.body.to_lowercase();
        assert!(
            !(lower.contains("get <code>/nonce</code> for a challenge")
                || lower.contains("post the signature to")),
            "the page must NOT be the bare protocol-description text"
        );
    }

    #[test]
    fn get_root_over_http_yields_a_2xx_response_with_a_body() {
        use std::io::Read as _;

        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(!addr.ip().is_loopback(), "must bind a non-loopback address");

        let handle = std::thread::spawn(move || {
            let (mut ctx, _subkey) = provisioned_ctx();
            let stream = listener
                .incoming()
                .next()
                .expect("one connection")
                .expect("accept");
            super::handle_connection(stream, &mut ctx);
        });

        let connect = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let mut client = TcpStream::connect(connect).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: pillar.example.com\r\n\r\n")
            .expect("write request");
        let mut raw = String::new();
        client.read_to_string(&mut raw).expect("read response");
        handle.join().expect("server thread");

        let status_line = raw.lines().next().expect("a status line");
        assert!(
            status_line.starts_with("HTTP/1.1 2"),
            "expected an HTTP/1.1 2xx status line, got: {status_line}"
        );
        let (_, body) = raw.split_once("\r\n\r\n").expect("a header/body separator");
        assert!(!body.is_empty(), "expected a non-empty response body");
    }

    #[test]
    fn a_wrong_password_surfaces_a_clear_unlock_failed_message() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let resp = post(&mut ctx, "/login", &format!("alice@pillar\nwrong\n{id}"));
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("unlock-failed"), "got: {}", resp.body);
    }

    #[test]
    fn a_node_without_an_offer_surfaces_the_new_no_offer_mode() {
        // A node that holds NO offer for this user (or lacks the label) must
        // surface the NEW node-custody mode, distinct from a wrong password.
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let resp = post(&mut ctx, "/login", &format!("nobody@pillar\n{PASSWORD}\n{id}"));
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("no-offer-for-user"), "got: {}", resp.body);
    }

    // The first-run BOOTSTRAP flow: a fresh node serves the create-cell ->
    // create-first-user flow; the first create consumes the one-shot
    // capability (a second cell-key create-user is refused) and links
    // cell<->initial-user; a bootstrapped node reports BOOTSTRAPPED.
    #[test]
    fn fresh_node_serves_create_cell_then_create_first_user_consuming_the_capability() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        // Fresh: status FRESH.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        // Cannot create a user before the cell.
        let early = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(early.status, 409);
        assert!(early.body.contains("NoCellYet"), "got: {}", early.body);

        // (a) create the cell.
        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        assert!(cell.body.contains("CELL-CREATED"));

        // (b) create the first user — consumes the one-shot capability.
        let user = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(user.status, 200);
        assert!(user.body.contains("USER-CREATED spencer"));

        // Now BOOTSTRAPPED, cell<->user linked.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "BOOTSTRAPPED");
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));

        // A SECOND cell-key create-user is refused (capability spent).
        let second = post(&mut ctx, "/bootstrap/create-user", &format!("second-user\n{PASSWORD}"));
        assert_eq!(second.status, 409);
        assert!(second.body.contains("CapabilitySpent"), "got: {}", second.body);
    }

    // Regression: the observed bug — after create-cell -> create-first-user
    // on a fresh bootstrap node, login used to fail "no offer for you" for
    // the very user just created. The bootstrap create-first-user step MUST
    // atomically apply the key-distribution label + escrow the new user's
    // node-sealed offer to this node, so the FIRST login succeeds
    // immediately, with no separate operator provisioning step.
    #[test]
    fn first_login_immediately_after_bootstrap_succeeds_with_no_extra_provisioning() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        let user = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(user.status, 200, "got: {}", user.body);

        // Log in as the just-created user with NO further offer provisioning.
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let login = post(&mut ctx, "/login", &format!("spencer\n{PASSWORD}\n{id}"));
        assert_eq!(
            login.status, 200,
            "first login right after bootstrap must succeed, got: {}",
            login.body
        );
        assert!(login.body.contains("spencer"), "got: {}", login.body);

        // A wrong password on the same identifier is still a plain
        // unlock-failed, never the no-offer mode — proving the offer really
        // is present and the failure mode is unlock-specific.
        let nonce_resp2 = get(&mut ctx, "/nonce");
        let id2: u64 = nonce_resp2.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let bad = post(&mut ctx, "/login", &format!("spencer\nwrong\n{id2}"));
        assert_eq!(bad.status, 401);
        assert!(bad.body.contains("unlock-failed"), "got: {}", bad.body);
    }


    #[test]
    fn a_bootstrapped_node_reports_bootstrapped_directly() {
        let (mut ctx, _subkey) = provisioned_ctx();
        ctx.bootstrap_mut().create_cell(NodeId::from("cell-genesis")).unwrap();
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "BOOTSTRAPPED");
    }
}
