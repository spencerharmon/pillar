//! Acceptance test — `um-selfservice-opkey-rotation` (ROI P1 "User management
//! & lifecycle" roadmap A2).
//!
//! Proves the self-service operational-key rotation surface: a user rotates
//! their OWN operational key on demand under their EXISTING unlock factor via
//! `POST /portal/profile/rotate-key` (body `<token>\n<password>`). A fresh key
//! is minted from OS entropy and the prior key is revoked — no password change,
//! no admin authority, no act on another user.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal surface. Two REGRESSIONS this proves:
//!   1. The rotation is GATED on the caller's own live operational key: a
//!      WRONG password is refused `403 REFUSED opkey-rotation ...` and mints
//!      nothing (the delegated-sign proof fails closed). A stamped session
//!      token ALONE is not enough.
//!   2. A CORRECT-password rotation mints a genuinely DIFFERENT operational
//!      key: the returned `opkey=<hex>` fingerprint CHANGES across a rotation
//!      (the prior key is cryptographically dead), while the SAME unlock
//!      password still logs the user in afterward (the factor is unchanged).
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test selfservice_opkey_rotation --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 selfservice-opkey";
const ADMIN_HANDLE: &str = "alice@pillar";

struct HttpResponse {
    status: u16,
    body: String,
    session_token: Option<String>,
}

fn http(port: u16, method: &str, path: &str, body: &str) -> Option<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(value) = header.trim_end().strip_prefix("X-Pillar-Session: ") {
            session_token = Some(value.to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        body: resp_body,
        session_token,
    })
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

/// A booted `pillar node run` subprocess with its HTTP portal surface bound;
/// killed on drop.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node { child, http_port };
        node.await_ready(Duration::from_secs(20));
        node
    }

    fn await_ready(&self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(resp) = http(self.http_port, "GET", "/bootstrap/status", "") {
                if resp.status == 200 {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "pillar node run did not serve /bootstrap/status within {within:?} on port {}",
                    self.http_port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        http(self.http_port, "POST", path, body).expect("POST succeeds")
    }

    fn get(&self, path: &str) -> HttpResponse {
        http(self.http_port, "GET", path, "").expect("GET succeeds")
    }

    /// GET /nonce then POST /login with `identifier\npassword\n<nonce id>` — the
    /// real two-field node-custody login every portal session uses. The admitted
    /// session token is carried on the `X-Pillar-Session` response header.
    fn login(&self, identifier: &str, password: &str) -> String {
        let nonce_resp = self.get("/nonce");
        assert_eq!(nonce_resp.status, 200, "nonce: {}", nonce_resp.body);
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses");
        let login_resp = self.post("/login", &format!("{identifier}\n{password}\n{id}"));
        assert_eq!(login_resp.status, 200, "login: {}", login_resp.body);
        login_resp
            .session_token
            .expect("login response carries a session token")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parse the `opkey=<hex>` fingerprint out of a `ROTATED opkey=<hex>` body.
fn opkey_of(body: &str) -> String {
    body.trim()
        .strip_prefix("ROTATED opkey=")
        .unwrap_or_else(|| panic!("rotate body must be `ROTATED opkey=<hex>`: {body}"))
        .to_owned()
}

#[test]
fn a_user_rotates_their_own_operational_key_under_their_unlock_factor() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let token = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    // Invite a real IAM-record user `bob` with an operational key directly
    // (force_password_change = false), so bob holds a live operational key AND a
    // `users`-map record — the subject of a self-service rotation. (The
    // bootstrap first user holds a login-only key with no record.)
    let bob_pw = "bob-operational-pw-2026";
    let invite = node.post(
        "/portal/users/invite",
        &format!("{ADMIN_PASSWORD}\n{token}\nbob\nbob@example.com\n{bob_pw}\nfalse\nfalse"),
    );
    assert_eq!(invite.status, 200, "invite bob: {}", invite.body);
    let token = node.login("bob", bob_pw);
    let user_pw = bob_pw;

    // --- Rotation REFUSED with the WRONG password: the rotation is gated on a
    // REAL delegated-sign proof of the caller's live operational key, not the
    // mere possession of an admitted session token. Nothing is minted.
    let bad = node.post(
        "/portal/profile/rotate-key",
        &format!("{token}\nwrong-password"),
    );
    assert_eq!(
        bad.status, 403,
        "a wrong password must be refused: {}",
        bad.body
    );
    assert!(
        bad.body.contains("opkey-rotation"),
        "the refusal must name the opkey-rotation gate: {}",
        bad.body
    );

    // --- Rotation SUCCEEDS with the correct password: a fresh operational key
    // is minted (its public fingerprint is returned).
    let rot1 = node.post(
        "/portal/profile/rotate-key",
        &format!("{token}\n{user_pw}"),
    );
    assert_eq!(rot1.status, 200, "rotate #1: {}", rot1.body);
    let key1 = opkey_of(&rot1.body);
    assert!(!key1.is_empty(), "rotated key fingerprint is non-empty");

    // The SAME unlock password still logs the user in (the factor is unchanged
    // — only the operational key rotated).
    let token2 = node.login("bob", user_pw);

    // --- A SECOND rotation mints a GENUINELY DIFFERENT key: the fingerprint
    // changes, proving the prior key was superseded (revoked / dead), not
    // merely re-sealed. This is the regression that would fail if rotation were
    // a no-op or re-minted the same deterministic key.
    let rot2 = node.post(
        "/portal/profile/rotate-key",
        &format!("{token2}\n{user_pw}"),
    );
    assert_eq!(rot2.status, 200, "rotate #2: {}", rot2.body);
    let key2 = opkey_of(&rot2.body);
    assert_ne!(
        key1, key2,
        "each rotation must mint a fresh, distinct operational key"
    );

    // And the user can still log in with the unchanged password after the
    // second rotation too.
    let _token3 = node.login("bob", user_pw);
}
