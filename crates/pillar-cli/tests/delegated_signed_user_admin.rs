//! Acceptance test — `um-delegated-signed-user-admin` (ROI P1 "User
//! management & lifecycle" roadmap A1).
//!
//! Proves every admin user-mutation (invite / disable / enable /
//! require-password-change / admin password reset) on the portal's
//! `/portal/users/*` REST surface now routes through a delegated-signed
//! `ControlOp::User(...)` op — the node signs the op on the admin's OWN
//! behalf via `pillar_web::node_custody::NodeCustodyVerifier::sign_op_for`,
//! gated on the admin's OWN password + a fresh step-up — and applies it
//! through the SAME `iam:users:write`-gated `WebAuthContext::control_op` ->
//! `user_op` path the CLI's keyed client and the resource-op UDP tier
//! already use, instead of a bespoke, unauthenticated-beyond-the-session-
//! token privileged mutation.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal surface. The REGRESSION this proves: before
//! this task, an admin's already-admitted session token ALONE was
//! sufficient to invite/disable/enable/reset another user (no re-proof of
//! the admin's own password); after it, the SAME session token WITHOUT the
//! admin's correct password is refused (`403 REFUSED delegated-sign
//! ...`) — the request is only accepted once the real delegated signature
//! is produced and cryptographically verified.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test delegated_signed_user_admin --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 delegated-user-admin";
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

/// A booted `pillar node run` subprocess with its HTTP portal surface
/// bound; killed on drop.
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

    /// GET /nonce then POST /login with `identifier\npassword\n<nonce id>` —
    /// the real two-field node-custody login every portal session uses.
    /// The admitted session token is carried on the `X-Pillar-Session`
    /// response header (never the body).
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

#[test]
fn admin_user_mutations_require_a_real_delegated_signature_not_just_a_session_token() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let admin = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    // --- Invite REFUSED with the WRONG admin password: the delegated
    // signature is a REAL crypto check, not merely a stamped session
    // token — a regression that would pass before this task (any
    // authenticated admin session mutated another user unconditionally).
    let bad_invite = node.post(
        "/portal/users/invite",
        &format!("wrong-admin-password\n{admin}\nbob\nbob@example.com"),
    );
    assert_eq!(
        bad_invite.status, 403,
        "a wrong admin password must be refused: {}",
        bad_invite.body
    );
    assert!(
        bad_invite.body.contains("delegated-sign"),
        "the refusal must name the delegated-signature gate: {}",
        bad_invite.body
    );

    // --- Invite SUCCEEDS with the correct admin password: the delegated
    // signature verifies and the SAME `iam:users:write`-gated `user_op`
    // mutation the CLI's keyed client rides applies.
    let invite = node.post(
        "/portal/users/invite",
        &format!("{ADMIN_PASSWORD}\n{admin}\nbob\nbob@example.com\nbob-initial-pw\nfalse\nfalse"),
    );
    assert_eq!(invite.status, 200, "invite: {}", invite.body);
    let temp = invite.body.trim().to_owned();
    assert_eq!(temp, "bob-initial-pw");

    // bob is listed, active (force-change off).
    let list = node.get(&format!("/portal/users?token={admin}"));
    assert_eq!(list.status, 200);
    assert!(
        list.body.contains("bob status=Invited force_password_change=false"),
        "bob invited: {}",
        list.body
    );
    // bob can log in with the password the admin set.
    let _bob = node.login("bob", "bob-initial-pw");

    // --- Disable REFUSED with the wrong admin password.
    let bad_disable = node.post(
        "/portal/users/disable",
        &format!("wrong-admin-password\n{admin}\nbob"),
    );
    assert_eq!(
        bad_disable.status, 403,
        "disable with a wrong admin password must be refused: {}",
        bad_disable.body
    );

    // --- Disable SUCCEEDS with the correct admin password, and the
    // SAME `user_op`/`iam:users:write` mutation that revokes bob's live
    // sessions applies (the identical effect the pre-existing REST path
    // produced, now reached ONLY via a verified delegated signature).
    let disable = node.post(
        "/portal/users/disable",
        &format!("{ADMIN_PASSWORD}\n{admin}\nbob"),
    );
    assert_eq!(disable.status, 200, "disable: {}", disable.body);
    let list2 = node.get(&format!("/portal/users?token={admin}"));
    assert!(
        list2.body.contains("bob status=Disabled"),
        "bob disabled: {}",
        list2.body
    );

    // --- Admin password reset REFUSED with the wrong admin password, and
    // SUCCEEDS with the correct one, reissuing a fresh temp password.
    let bad_reset = node.post(
        "/portal/users/reset-password",
        &format!("{admin}\nbob\nwrong-admin-password"),
    );
    assert_eq!(
        bad_reset.status, 403,
        "admin reset with a wrong admin password must be refused: {}",
        bad_reset.body
    );
    let reset = node.post(
        "/portal/users/reset-password",
        &format!("{admin}\nbob\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(reset.status, 200, "admin reset: {}", reset.body);
    let new_temp = reset.body.trim().to_owned();
    assert!(!new_temp.is_empty() && new_temp != temp);
}
