//! Acceptance test — `portal-swarm-surface`.
//!
//! ROI reconcile 2026-09-06 (superseding correction, STATELESS): swarm
//! membership must be inspectable — and a fresh private key mintable — from the
//! web portal, EXACTLY at the parity of the `pillar swarm` CLI, without the
//! portal ever repointing a running node's swarm (that is fixed at boot by
//! `--swarm-key`/`--seed-node`). This suite is a BLACK-BOX observer: it speaks
//! only real HTTP/1.1 over a real TCP socket to a node web surface bound on an
//! ephemeral loopback port and served by the production `web_serve::serve`
//! accept loop — never reaching into in-process state. It proves, for the SAME
//! running node the portal fronts:
//!
//! 1. `GET /portal/swarm` reports the RUNNING node's swarm kind + non-secret
//!    fingerprint + configured seed multiaddrs, and NEVER serializes a root
//!    secret — for a PRIVATE running swarm the join credential appears nowhere
//!    in the response (`get_reports_running_swarm_and_never_leaks_the_root`).
//! 2. `POST /portal/swarm/generate` mints a fresh OS-CSPRNG private `SwarmKey`,
//!    returns its raw secret ONCE in the body for out-of-band distribution,
//!    a fresh DISTINCT key each call, and has NO persisted side effect — a
//!    second `GET /portal/swarm` still reports the ORIGINAL running swarm
//!    (`generate_mints_a_fresh_distinct_key_with_no_persisted_side_effect`).
//! 3. Unauthenticated requests are refused: `GET /portal/swarm` with no session
//!    is 401, and `POST /portal/swarm/generate` from a non-loopback peer with a
//!    bad session is refused (`unauthenticated_requests_are_refused`).
//!
//! RED if the running root ever appears in a GET response, if `generate` mutates
//! the running swarm or repeats a key, or if the surface answers an unauthed
//! caller. GREEN when the portal and CLI drive the SAME stateless `SwarmKey`
//! facility over the real served surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md stub);
//! run via `cargo test -p pillar-cli --test portal_swarm_surface --features
//! acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::time::Duration;

use pillar_cli::web_serve::{bind, serve, WebAuthContext};
use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_swarm::{SwarmKey, SwarmKind};
use pillar_web::node_custody::Cid;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "operational-key-material";

/// One HTTP response the black-box client parsed off the wire.
struct HttpResponse {
    status: u16,
    session_token: Option<String>,
    body: String,
}

/// Send one real HTTP/1.1 request to `addr` and read the full response back —
/// the black-box client's ONLY view of the node.
fn http(addr: &str, method: &str, path: &str, body: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect to served surface");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).expect("header line");
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    HttpResponse {
        status,
        session_token,
        body: resp_body,
    }
}

/// Stand a real node web surface up on an ephemeral loopback port, told (as a
/// running node is at boot) it is on the given swarm, admit + provision a user
/// so the black-box client can log in, and return `(addr, running_key, token)`.
/// `running_key` is the key the node is actually running on — the join
/// credential the GET view must NEVER leak.
fn serve_with_swarm(running: SwarmKey) -> (String, SwarmKey, String) {
    let listener = bind(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0).expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let subkey = NodeSubkey::from("op-subkey-alice");
    let mut ctx = WebAuthContext::new(
        "https://node.example.com",
        NodeId::from("this-node"),
        "this-node-secret",
        NodeId::from("owner"),
        4,
    )
    .with_swarm_info(
        running.kind(),
        running.fingerprint(),
        vec!["/ip4/192.0.2.7/tcp/4001/p2p/12D3KooWSeedExample".to_owned()],
    );
    ctx.admit_subject(subkey.node_id(), 4);
    ctx.provision_offer(
        "alice@node",
        "Alice",
        Cid::from("cid-alice"),
        subkey,
        PASSWORD,
        SECRET,
    );

    std::thread::spawn(move || serve(listener, &mut ctx));
    // Give the accept loop a moment to start.
    std::thread::sleep(Duration::from_millis(100));

    let token = login(&addr);
    (addr, running, token)
}

/// The real node-side custody login over HTTP: `GET /nonce`, then `POST /login`
/// (two fields + nonce id). Returns the admitted session token.
fn login(addr: &str) -> String {
    let nonce = http(addr, "GET", "/nonce", "");
    assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
    let id: u64 = nonce
        .body
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("nonce id");
    let resp = http(addr, "POST", "/login", &format!("alice@node\n{PASSWORD}\n{id}"));
    assert_eq!(resp.status, 200, "login: {}", resp.body);
    resp.session_token.expect("session token")
}

#[test]
fn get_reports_running_swarm_and_never_leaks_the_root() {
    // Boot the node onto a PRIVATE swarm so there is a real join credential the
    // GET view must never expose.
    let private = SwarmKey::generate();
    assert_eq!(private.kind(), SwarmKind::Private);
    let (addr, running, token) = serve_with_swarm(private);

    let shown = http(&addr, "GET", &format!("/portal/swarm?token={token}"), "");
    assert_eq!(shown.status, 200, "swarm view: {}", shown.body);

    // Reports the running node's kind + non-secret fingerprint + seeds.
    assert!(
        shown
            .body
            .contains(&format!("SWARM private {}", running.fingerprint())),
        "GET must report the running swarm kind + fingerprint, got: {}",
        shown.body
    );
    assert!(
        shown.body.contains("SEED /ip4/192.0.2.7/tcp/4001"),
        "GET must report the configured seed multiaddrs, got: {}",
        shown.body
    );

    // NEVER serializes a root: the running join credential appears NOWHERE in
    // the response body.
    assert!(
        !shown.body.contains(running.root_secret()),
        "GET leaked the running swarm root secret: {}",
        shown.body
    );
    // Belt-and-suspenders: the raw generated-key prefix never appears either.
    assert!(
        !shown.body.contains("pillar-swarm/v1:"),
        "GET must not serialize any raw swarm key material: {}",
        shown.body
    );
}

#[test]
fn generate_mints_a_fresh_distinct_key_with_no_persisted_side_effect() {
    // Boot on the PUBLIC swarm; `generate` must not repoint it.
    let public = SwarmKey::public();
    let (addr, running, token) = serve_with_swarm(public);
    let original_fingerprint = running.fingerprint();

    // First generate returns a fresh PRIVATE key once, in the body.
    let g1 = http(&addr, "POST", "/portal/swarm/generate", &token);
    assert_eq!(g1.status, 200, "generate: {}", g1.body);
    let key1 = extract_key(&g1.body);
    assert_eq!(
        key1.kind(),
        SwarmKind::Private,
        "generate must mint a PRIVATE key, got: {}",
        g1.body
    );
    assert!(
        g1.body.contains(&format!("FINGERPRINT {}", key1.fingerprint())),
        "generate must return the key fingerprint, got: {}",
        g1.body
    );

    // A second generate mints a DISTINCT fresh key (OS-CSPRNG, no reuse).
    let g2 = http(&addr, "POST", "/portal/swarm/generate", &token);
    assert_eq!(g2.status, 200, "generate 2: {}", g2.body);
    let key2 = extract_key(&g2.body);
    assert_ne!(
        key1.root_secret(),
        key2.root_secret(),
        "each generate must mint a distinct key"
    );

    // NO persisted side effect: the running node's swarm is UNCHANGED — a
    // subsequent GET still reports the ORIGINAL running (public) swarm, not a
    // minted key.
    let shown = http(&addr, "GET", &format!("/portal/swarm?token={token}"), "");
    assert_eq!(shown.status, 200, "swarm view: {}", shown.body);
    assert!(
        shown
            .body
            .contains(&format!("SWARM public {original_fingerprint}")),
        "generate must not repoint the running node — GET must still report the \
         original running swarm, got: {}",
        shown.body
    );
    assert!(
        !shown.body.contains(key1.fingerprint().as_str())
            && !shown.body.contains(key2.fingerprint().as_str()),
        "a minted key must not become the running swarm, got: {}",
        shown.body
    );
}

#[test]
fn unauthenticated_requests_are_refused() {
    let (addr, _running, _token) = serve_with_swarm(SwarmKey::public());

    // GET with no session is refused.
    let no_session = http(&addr, "GET", "/portal/swarm", "");
    assert_eq!(
        no_session.status, 401,
        "unauthenticated GET must be 401, got {}: {}",
        no_session.status, no_session.body
    );

    // GET with a bad session token is refused.
    let bad_session = http(&addr, "GET", "/portal/swarm?token=not-a-real-session", "");
    assert_eq!(
        bad_session.status, 401,
        "bad-session GET must be 401, got {}: {}",
        bad_session.status, bad_session.body
    );

    // POST generate from a non-loopback peer with a bad session is refused by
    // the shared non-loopback signing guard. (The TCP connection here is
    // loopback, but a bad session still cannot mint — no key is returned.)
    let bad_generate = http(&addr, "POST", "/portal/swarm/generate", "not-a-real-session");
    assert!(
        bad_generate.status == 401 || bad_generate.status == 403,
        "unauthenticated generate must be refused (401/403), got {}: {}",
        bad_generate.status,
        bad_generate.body
    );
    assert!(
        !bad_generate.body.contains("KEY pillar-swarm/v1:"),
        "a refused generate must not mint or leak any key: {}",
        bad_generate.body
    );
}

/// Parse the `KEY <root>` line out of a `generate` response body into a
/// `SwarmKey`, asserting the body actually carried a raw key to distribute.
fn extract_key(body: &str) -> SwarmKey {
    let line = body
        .lines()
        .find(|l| l.starts_with("KEY "))
        .unwrap_or_else(|| panic!("generate must return a KEY line, got: {body}"));
    SwarmKey::parse(&line["KEY ".len()..]).expect("minted key parses")
}
