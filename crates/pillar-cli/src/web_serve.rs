//! Serves the web UI from the deployed `pillar node run` process on a
//! configurable, **non-loopback** bind (`--web-bind`/`PILLAR_WEB_BIND`), so a
//! k8s Service can reach it (flux's `pillar-web-ingress-tls` gates on this).
//!
//! `pillar --web` (see `pillar-cli/src/main.rs`) stays localhost-only for the
//! no-identity-yet bootstrap flow; THIS surface is the one that leaves the
//! host, and it never inherits that surface's loopback exemption
//! ([`pillar_web::authorize_nonloopback_signing_action`]): reaching a
//! signing action from off-host REQUIRES an already-admitted WoT-key login
//! session ([`pillar_web::key_login`]) — the ROI's default gate for the
//! exposed surface. Passkey/WebAuthn remains available only as an optional
//! signer feeding the very same decider, never a parallel gate.
//!
//! ## Transport: HTTP/1.1
//!
//! The surface speaks **HTTP/1.1** so a browser, `curl`, or a k8s Ingress
//! (traefik proxying plain HTTP to the pillar-web Service) can reach it — the
//! flux `pillar-web-ingress-tls` check gates on `curl -sf https://…/`. Each
//! request line + headers is parsed, dispatched to one of the endpoints
//! below, and answered with a real HTTP/1.1 status line, `Content-Type`,
//! `Content-Length`, and body. Because a single browser/`curl` session opens
//! several short-lived connections, the WoT-key login SESSION is keyed by the
//! nonce/subkey handshake (an `X-Pillar-Session` bearer the client echoes on
//! the signing request), not by connection lifetime.
//!
//! Endpoints (the SAME auth-gate decisions as before — only the transport
//! changed; `handle_line` still holds the pure protocol logic and its tests):
//!
//! - `GET /` — the UNAUTHENTICATED, self-guided WoT-key login UI (HTML, 200):
//!   a real graphical login page (see [`LANDING_PAGE`] / `web_login.html`), not
//!   a protocol description. The human enters their handle + unlock password;
//!   the embedded script performs the whole `GET /nonce` → local unlock+sign →
//!   `POST /login` handshake as hidden plumbing and, on success, transitions
//!   into an authenticated portal view greeting the user by handle. The browser
//!   unlocks a WoT-trusted auth subkey LOCALLY and signs the server nonce;
//!   serving this page exposes NO authenticated action.
//! - `GET /nonce` — issue a fresh challenge nonce bound to this origin; body
//!   `NONCE <id> <expiry>`.
//! - `POST /login` — body `<id> <expiry> <subkey> <sig>`: admit a WoT-key
//!   login; 200 `OK` (with an `X-Pillar-Session` token) or 401 `DENIED
//!   <reason>`.
//! - `POST /ping` — a stand-in signing action gated through
//!   [`pillar_web::authorize_nonloopback_signing_action`]; a non-loopback
//!   peer must present an admitted session (`X-Pillar-Session`). 200 `PONG`
//!   or 403 `REFUSED <reason>`.
//!
//! `handle_line` maps each HTTP endpoint onto the ORIGINAL line-protocol verb
//! (`NONCE`/`LOGIN`/`PING`/`QUIT`), so the auth-gate decision logic — in
//! particular that a non-loopback peer with no admitted session is ALWAYS
//! refused — is unchanged and still exercised directly by the unit tests.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};

use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_web::key_login::{
    KeyLoginVerifier, LoginSession, Nonce, NonceIssuer, RegisteredAuthKey, Signature,
};
use pillar_web::{authorize_nonloopback_signing_action, bind_web};
use pillar_wot_authority::{FencedActor, WotAuthority};

/// The server-side state a web-serving process needs to run the WoT-key
/// login handshake: the nonce issuer, the verifier holding registered auth
/// keys, and the shared authority/actor login admission resolves through —
/// the SAME [`pillar_wot_authority`] authority the rest of the platform
/// trusts, never a parallel one.
pub struct WebAuthContext {
    issuer: NonceIssuer,
    verifier: KeyLoginVerifier,
    issued: HashMap<u64, Nonce>,
    authority: WotAuthority,
    actor: FencedActor,
    /// Admitted WoT-key login sessions, keyed by the bearer token handed to
    /// the client (`X-Pillar-Session`) on a successful `POST /login`. HTTP is
    /// connection-per-request, so an admitted session must outlive the
    /// connection it was minted on; the client echoes its token on the later
    /// signing request.
    sessions: HashMap<String, LoginSession>,
    /// Monotonic counter minting distinct session-token strings.
    next_session: u64,
}

impl WebAuthContext {
    /// A fresh context: no auth keys registered, `owner` as the WoT
    /// authority root at `max_depth`.
    #[must_use]
    pub fn new(origin: impl Into<String>, owner: NodeId, max_depth: u8) -> Self {
        let authority = WotAuthority::new(owner, max_depth);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        WebAuthContext {
            issuer: NonceIssuer::new(origin.into().as_str()),
            verifier: KeyLoginVerifier::new(),
            issued: HashMap::new(),
            authority,
            actor,
            sessions: HashMap::new(),
            next_session: 0,
        }
    }

    /// Register the public half of an auth key so a login signed by it can
    /// be admitted.
    pub fn register_auth_key(&mut self, key: RegisteredAuthKey) {
        self.verifier.register_auth_key(key);
    }

    /// Chain `subject` to the authority root at `level`, admitting it as
    /// WoT-authoritative — required before a login for its subkey can admit.
    pub fn admit_subject(&mut self, subject: NodeId, level: u8) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject, level);
        self.actor.refresh(&self.authority);
    }

    /// Issue a fresh challenge nonce, tracking it as issued so a later
    /// login can be checked against it.
    pub fn issue_nonce(&mut self, expiry: u64) -> Nonce {
        let nonce = self.issuer.issue(expiry);
        self.issued.insert(nonce.id(), nonce.clone());
        self.verifier.track_issued(nonce.clone());
        nonce
    }

    /// This server's own origin.
    #[must_use]
    pub fn origin(&self) -> &pillar_web::key_login::Origin {
        self.issuer.origin()
    }

    /// Admit a login given the wire-transmitted `(id, expiry, subkey, sig)`.
    ///
    /// # Errors
    ///
    /// The matching [`pillar_web::key_login::LoginError`] for the first
    /// failing precondition — an unknown/expired/replayed/wrong-origin
    /// nonce, an unregistered auth key, a bad signature, or a subkey that
    /// fails the fail-closed WoT authority guard.
    pub fn admit_login(
        &mut self,
        id: u64,
        expiry: u64,
        subkey: &NodeSubkey,
        sig: &Signature,
        clock: u64,
    ) -> Result<LoginSession, pillar_web::key_login::LoginError> {
        let Some(nonce) = self.issued.get(&id).cloned() else {
            return Err(pillar_web::key_login::LoginError::UnknownNonce);
        };
        if nonce.expiry() != expiry {
            return Err(pillar_web::key_login::LoginError::UnknownNonce);
        }
        let origin = self.issuer.origin().clone();
        self.verifier.admit(
            &nonce,
            sig,
            subkey,
            &origin,
            clock,
            &self.authority,
            &self.actor,
        )
    }

    /// Store an admitted `session` under a freshly minted bearer token,
    /// returning that token for the client to echo (`X-Pillar-Session`) on a
    /// later signing request. HTTP connections are per-request, so the
    /// session must be looked up by token, not connection.
    fn store_session(&mut self, session: LoginSession) -> String {
        let token = format!("s{}", self.next_session);
        self.next_session += 1;
        self.sessions.insert(token.clone(), session);
        token
    }

    /// The admitted session for a bearer `token`, if any.
    fn session_for(&self, token: &str) -> Option<&LoginSession> {
        self.sessions.get(token)
    }
}

/// Bind the web UI listener on `addr:port` — `addr` MAY be non-loopback (see
/// module docs); the caller must still gate every signing action through
/// [`WebAuthContext`] / [`authorize_nonloopback_signing_action`].
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

/// The unauthenticated, self-guided WoT-key login UI (HTML + CSS + JS) served
/// at `GET /`. It is a real graphical login page — NOT a protocol description:
/// the human supplies exactly two inputs (their handle and the password that
/// LOCALLY unlocks their auth subkey), and the page's embedded script performs
/// the whole handshake as hidden plumbing — `GET /nonce`, local unlock + sign,
/// `POST /login` — then transitions into an authenticated portal view greeting
/// the user by handle and exposing node management.
///
/// SECURITY INVARIANTS (identical to `web-key-auth-impl`; this is presentation
/// over that mechanism, not a new auth model): the password and the plaintext
/// key NEVER leave the browser — unlock is a purely local computation; only the
/// nonce SIGNATURE (never the password or plaintext key) is POSTed. The origin
/// the signature is bound to is derived from the browser (`location`) at
/// runtime, so no infrastructure identifier is embedded in this public source.
///
/// The embedded script mirrors, in JS, the crate's deterministic no-real-crypto
/// KDF/signature stand-ins (`pillar_web::key_login`'s `argon2id`/`sign_nonce`,
/// both built on Rust's `DefaultHasher` = SipHash-1-3 seeded with keys (0,0)
/// and `str`'s hash framing of "bytes then 0xFF"), so the client-side unlock +
/// sign it performs is genuine end-to-end against this server — in a real
/// deployment these stand-ins are the real memory-hard argon2id + signature,
/// unchanged in shape.
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

    // Read headers until the blank line, capturing Content-Length.
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

/// An HTTP response to write back: status code, reason, content-type, an
/// optional `X-Pillar-Session` token, and body.
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

/// Map an HTTP request onto the ORIGINAL line-protocol decision in
/// [`handle_line`], preserving every auth-gate rule (only the transport
/// changed). The signing action's session is resolved from the
/// `X-Pillar-Session` bearer the client echoes.
fn dispatch_http(
    ctx: &mut WebAuthContext,
    peer: &SocketAddr,
    request: &HttpRequest,
) -> HttpResponse {
    // Strip any query string; match on the path prefix.
    let path = request.path.split('?').next().unwrap_or(&request.path);
    match (request.method.as_str(), path) {
        ("GET", "/") => HttpResponse {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            session_token: None,
            body: LANDING_PAGE.to_owned(),
        },
        ("GET", "/nonce") => {
            let mut session: Option<LoginSession> = None;
            let reply = handle_line(ctx, &mut session, peer, "NONCE");
            text_response(200, "OK", reply.text)
        }
        ("POST", "/login") => {
            let mut session: Option<LoginSession> = None;
            let line = format!("LOGIN {}", request.body.trim());
            let reply = handle_line(ctx, &mut session, peer, &line);
            if reply.text == "OK" {
                if let Some(s) = session {
                    let token = ctx.store_session(s);
                    return HttpResponse {
                        status: 200,
                        reason: "OK",
                        content_type: "text/plain; charset=utf-8",
                        session_token: Some(token),
                        body: "OK\n".to_owned(),
                    };
                }
            }
            text_response(401, "Unauthorized", reply.text)
        }
        ("POST", "/ping") => {
            // Resolve the admitted session from the bearer token, then run the
            // UNCHANGED gate: a non-loopback peer with no admitted session is
            // still always refused.
            let token = request.body.trim();
            let mut session: Option<LoginSession> = ctx.session_for(token).cloned();
            let reply = handle_line(ctx, &mut session, peer, "PING");
            if reply.text == "PONG" {
                text_response(200, "OK", reply.text)
            } else {
                text_response(403, "Forbidden", reply.text)
            }
        }
        _ => text_response(404, "Not Found", "not found".to_owned()),
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

/// One protocol reply: the text to write back. HTTP dispatch maps this onto
/// a status code + body (see [`dispatch_http`]).
struct Reply {
    text: String,
}

fn reply(text: impl Into<String>) -> Reply {
    Reply { text: text.into() }
}

/// The pure per-line protocol handler, independent of any real socket, so
/// the auth-gate decision (in particular: a non-loopback `peer` with no
/// admitted session is ALWAYS refused, real network plumbing notwithstanding)
/// is exercised directly by unit tests rather than relying on a real TCP
/// connection's observed peer address (which is loopback whenever the test
/// client and server share a host, regardless of the bind address).
fn handle_line(
    ctx: &mut WebAuthContext,
    session: &mut Option<LoginSession>,
    peer: &SocketAddr,
    line: &str,
) -> Reply {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("NONCE") => {
            let nonce = ctx.issue_nonce(u64::MAX);
            reply(format!("NONCE {} {}", nonce.id(), nonce.expiry()))
        }
        Some("LOGIN") => {
            let (Some(id), Some(expiry), Some(subkey), Some(sig)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return reply("usage: LOGIN <id> <expiry> <subkey> <sig>");
            };
            let (Ok(id), Ok(expiry), Ok(sig)) =
                (id.parse::<u64>(), expiry.parse::<u64>(), sig.parse::<u64>())
            else {
                return reply("DENIED bad-arguments");
            };
            let subkey = NodeSubkey::from(subkey);
            let signature = Signature::from_wire(sig);
            match ctx.admit_login(id, expiry, &subkey, &signature, 0) {
                Ok(s) => {
                    *session = Some(s);
                    reply("OK")
                }
                Err(e) => reply(format!("DENIED {e:?}")),
            }
        }
        Some("PING") => match authorize_nonloopback_signing_action(peer, session.as_ref()) {
            Ok(()) => reply("PONG"),
            Err(e) => reply(format!("REFUSED {e:?}")),
        },
        _ => reply("unknown command; use NONCE, LOGIN, or PING"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "plaintext-auth-subkey-secret";

    fn remote_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4242)
    }

    fn fresh_ctx_with_subkey() -> (WebAuthContext, NodeSubkey) {
        let subkey = NodeSubkey::from("auth-subkey-node-run");
        let mut ctx = WebAuthContext::new("https://pillar.example.com", NodeId::from("owner"), 4);
        ctx.admit_subject(subkey.node_id(), 4);

        let encrypted =
            pillar_web::key_login::EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        ctx.register_auth_key(pillar_web::key_login::RegisteredAuthKey::register(
            &encrypted, PASSWORD, SECRET,
        ));
        (ctx, subkey)
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

    // Exercises the auth-gate decision directly against a synthetic
    // non-loopback peer address — a real TCP loopback connection between a
    // test client and server on the same host always reports 127.0.0.1 as
    // the peer regardless of the bind address, so it cannot exercise the
    // "reachable off-host" branch of the gate at all; this is the only way
    // to actually prove the non-loopback refusal.
    #[test]
    fn unauthenticated_signing_action_against_a_nonloopback_peer_is_refused() {
        let (mut ctx, _subkey) = fresh_ctx_with_subkey();
        let mut session: Option<LoginSession> = None;
        let reply = handle_line(&mut ctx, &mut session, &remote_peer(), "PING");
        assert!(
            reply.text.starts_with("REFUSED"),
            "expected an unauthenticated non-loopback PING to be refused, got: {}",
            reply.text
        );
    }

    #[test]
    fn wot_key_login_then_signing_action_from_a_nonloopback_peer_is_admitted() {
        let (mut ctx, subkey) = fresh_ctx_with_subkey();
        let mut session: Option<LoginSession> = None;
        let peer = remote_peer();

        let nonce_reply = handle_line(&mut ctx, &mut session, &peer, "NONCE");
        let mut parts = nonce_reply.text.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id parses");
        let expiry: u64 = parts
            .next()
            .expect("expiry")
            .parse()
            .expect("expiry parses");

        // Client side: unlock the auth subkey and sign the nonce locally —
        // the password/plaintext key never cross the wire.
        let encrypted =
            pillar_web::key_login::EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let unlocked = pillar_web::key_login::unlock_auth_subkey(&encrypted, PASSWORD, SECRET)
            .expect("unlock");
        let signing_nonce = test_nonce(id, "https://pillar.example.com", expiry);
        let sig = unlocked.sign_nonce(&signing_nonce);

        let login_line = format!("LOGIN {id} {expiry} {} {}", subkey.0, sig.to_wire());
        let login_reply = handle_line(&mut ctx, &mut session, &peer, &login_line);
        assert_eq!(login_reply.text, "OK", "login reply: {}", login_reply.text);
        assert!(
            session.is_some(),
            "an admitted login must populate the connection session"
        );

        let ping_reply = handle_line(&mut ctx, &mut session, &peer, "PING");
        assert_eq!(
            ping_reply.text, "PONG",
            "expected an authenticated non-loopback PING to be admitted, got: {}",
            ping_reply.text
        );
    }

    // Bind the web surface on an ephemeral NON-loopback port, serve one HTTP
    // request in a background thread, and assert `GET /` yields a real
    // HTTP/1.1 2xx response with a body — the exact contract traefik/curl (and
    // the flux `pillar-web-ingress-tls` check) depend on.
    #[test]
    fn get_root_over_http_yields_a_2xx_response_with_a_body() {
        use std::io::Read as _;

        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(!addr.ip().is_loopback(), "must bind a non-loopback address");

        let handle = std::thread::spawn(move || {
            let (mut ctx, _subkey) = fresh_ctx_with_subkey();
            // Serve exactly one connection then return.
            let stream = listener
                .incoming()
                .next()
                .expect("one connection")
                .expect("accept");
            super::handle_connection(stream, &mut ctx);
        });

        // Connect to the bound port over the loopback route (the OS routes a
        // 0.0.0.0 bind via 127.0.0.1) and speak raw HTTP/1.1.
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

    // The `/` page must be a real, self-guided GRAPHICAL login UI — the two
    // human inputs (handle + unlock password) plus the client-side script that
    // fetches `/nonce`, unlocks + signs LOCALLY, and POSTs `/login` — and must
    // transition into an authenticated portal view. It must NOT be the old
    // bare protocol-description text that merely told the human to run the
    // `GET /nonce` / sign / `POST /login` steps by hand. This is the exact
    // presentation contract `portal-login-ui` gates the operator login-test on.
    #[test]
    fn root_page_is_the_interactive_login_ui_not_the_protocol_description() {
        let (mut ctx, _subkey) = fresh_ctx_with_subkey();
        let resp = dispatch_http(
            &mut ctx,
            &remote_peer(),
            &HttpRequest {
                method: "GET".into(),
                path: "/".into(),
                body: String::new(),
            },
        );
        assert_eq!(resp.status, 200);
        assert!(
            resp.content_type.contains("text/html"),
            "the login page must be served as HTML"
        );
        let body = &resp.body;

        // A real graphical login FORM with the two human inputs.
        assert!(body.contains("<form"), "must render a login form");
        assert!(
            body.contains("id=\"handle\"") && body.contains("id=\"password\""),
            "must present the handle + unlock-password inputs"
        );

        // The client-side script that performs the handshake as hidden plumbing.
        assert!(body.contains("<script"), "must embed a client-side script");
        assert!(
            body.contains("/nonce") && body.contains("/login"),
            "the script must drive the /nonce and /login endpoints itself"
        );
        assert!(
            body.to_lowercase().contains("sign"),
            "the script must sign the challenge client-side"
        );

        // On success it transitions into an authenticated portal view.
        assert!(
            body.contains("id=\"portal\""),
            "must transition into an authenticated portal view"
        );

        // It must NOT be the old protocol-description landing page that
        // instructed the human to run the steps by hand.
        let lower = body.to_lowercase();
        assert!(
            !(lower.contains("get <code>/nonce</code> for a challenge")
                || lower.contains("post the signature to")),
            "the page must NOT be the bare protocol-description text"
        );
    }

    // Exercise the full HTTP handshake against a synthetic non-loopback peer:
    // GET /nonce, sign, POST /login (receiving a session token), then a signing
    // action POST /ping with and without that token — proving the auth gate is
    // unchanged, only carried over HTTP now.
    #[test]
    fn http_login_then_ping_dispatch_preserves_the_auth_gate() {
        let (mut ctx, subkey) = fresh_ctx_with_subkey();
        let peer = remote_peer();

        // Unauthenticated signing action against a non-loopback peer: 403.
        let refused = dispatch_http(
            &mut ctx,
            &peer,
            &HttpRequest {
                method: "POST".into(),
                path: "/ping".into(),
                body: String::new(),
            },
        );
        assert_eq!(
            refused.status, 403,
            "unauthenticated non-loopback ping must be refused"
        );

        // GET /nonce.
        let nonce_resp = dispatch_http(
            &mut ctx,
            &peer,
            &HttpRequest {
                method: "GET".into(),
                path: "/nonce".into(),
                body: String::new(),
            },
        );
        assert_eq!(nonce_resp.status, 200);
        let mut parts = nonce_resp.body.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id");
        let expiry: u64 = parts.next().expect("expiry").parse().expect("expiry");

        // Client-side sign.
        let encrypted =
            pillar_web::key_login::EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let unlocked = pillar_web::key_login::unlock_auth_subkey(&encrypted, PASSWORD, SECRET)
            .expect("unlock");
        let signing_nonce = test_nonce(id, "https://pillar.example.com", expiry);
        let sig = unlocked.sign_nonce(&signing_nonce);

        // POST /login → 200 + session token.
        let login_body = format!("{id} {expiry} {} {}", subkey.0, sig.to_wire());
        let login_resp = dispatch_http(
            &mut ctx,
            &peer,
            &HttpRequest {
                method: "POST".into(),
                path: "/login".into(),
                body: login_body,
            },
        );
        assert_eq!(login_resp.status, 200, "login body: {}", login_resp.body);
        let token = login_resp.session_token.expect("a session token");

        // POST /ping WITH the token → 200 PONG.
        let ping_resp = dispatch_http(
            &mut ctx,
            &peer,
            &HttpRequest {
                method: "POST".into(),
                path: "/ping".into(),
                body: token,
            },
        );
        assert_eq!(
            ping_resp.status, 200,
            "authenticated ping body: {}",
            ping_resp.body
        );
        assert!(ping_resp.body.starts_with("PONG"));
    }

    // Test-only: reconstruct a `Nonce` with a chosen id for signing, mirroring
    // exactly what `NonceIssuer::issue` produces server-side (verified by
    // `pillar_web::key_login`'s own tests) — used here only because
    // `Nonce`'s fields are crate-private by design.
    fn test_nonce(id: u64, origin: &str, expiry: u64) -> pillar_web::key_login::Nonce {
        // Drive a fresh issuer to the target serial by discarding earlier ids.
        let mut issuer = pillar_web::key_login::NonceIssuer::new(origin);
        let mut nonce = issuer.issue(expiry);
        while nonce.id() != id {
            nonce = issuer.issue(expiry);
        }
        nonce
    }
}
