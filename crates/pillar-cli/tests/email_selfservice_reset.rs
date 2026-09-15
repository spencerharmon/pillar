//! Acceptance test — `um-email-selfservice-reset` (ROI P1 "User management &
//! lifecycle" roadmap B1).
//!
//! Proves the self-service, email-triggered password reset: `POST
//! /portal/users/forgot-password` with a VERIFIED email re-onboards the
//! matching account through the SAME login-only re-enrollment offer path an
//! admin reset drives (no operational key survives, `force_password_change`
//! is set), delivers the fresh one-time password ONLY by email (via the
//! infra-supplied SMTP capture backend — never in the HTTP response), and
//! NEVER leaks whether an email matched (identical `200 OK` body either way).
//! Also proves an UNVERIFIED email — even one that belongs to a real account
//! — never triggers the flow: no re-enrollment, no mail sent.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal surface, with `PILLAR_SMTP_CAPTURE_DIR`
//! pointed at a test-owned directory so the node's outbound mail lands as a
//! real `.eml` file this test reads back — the same capture-backend delivery
//! path a non-production install points at instead of a real relay.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test email_selfservice_reset --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 email-selfservice-reset";
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

/// A booted `pillar node run` subprocess with its HTTP portal surface bound
/// and its outbound mail routed to a test-owned capture directory; killed on
/// drop.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path, mail_capture_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("PILLAR_SMTP_CAPTURE_DIR", mail_capture_dir)
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

    /// A `/login` attempt that is expected to be refused (wrong/expired
    /// password) rather than admitted.
    fn login_is_refused(&self, identifier: &str, password: &str) -> bool {
        let nonce_resp = self.get("/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses");
        let login_resp = self.post("/login", &format!("{identifier}\n{password}\n{id}"));
        login_resp.status != 200
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read every `.eml` file written under `dir`, newest first, returning their
/// full contents.
fn captured_emails(dir: &std::path::Path) -> Vec<String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_else(|_| Vec::new());
    entries.sort_by_key(|e| e.file_name());
    entries
        .into_iter()
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .collect()
}

/// Extract the one-time password from a captured reset email's body (the
/// line `    <temp>` this test's own mailer message format emits).
fn extract_temp_password(email_body: &str) -> String {
    email_body
        .lines()
        .find(|l| l.trim_start().len() == 32 && l.trim().chars().all(|c| c.is_ascii_hexdigit()))
        .expect("captured email must carry the one-time password line")
        .trim()
        .to_owned()
}

#[test]
fn verified_email_forgot_password_reissues_a_login_only_offer_delivered_by_mail_only() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let mail_dir = tempfile::tempdir().expect("mail capture dir");
    let node = Node::boot(data_dir.path(), mail_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let admin = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    // Invite june with a permanent password (no forced onboarding change) and
    // an explicit `verified_email = true` (the 8th invite-body line) — the
    // ONLY way an email becomes eligible for the self-service lookup.
    let invite = node.post(
        "/portal/users/invite",
        &format!(
            "{ADMIN_PASSWORD}\n{admin}\njune\njune@example.com\njune-initial-pw\nfalse\nfalse\ntrue"
        ),
    );
    assert_eq!(invite.status, 200, "invite: {}", invite.body);
    // june can log in with her operational key under the initial password.
    let _june = node.login("june", "june-initial-pw");

    // --- Forgot-password with an email that does NOT match any verified
    // account: generic response, no mail sent.
    let miss = node.post(
        "/portal/users/forgot-password",
        "nobody-verified@example.com",
    );
    assert_eq!(miss.status, 200, "forgot-password miss: {}", miss.body);
    assert!(
        captured_emails(mail_dir.path()).is_empty(),
        "an unmatched email must never trigger mail delivery"
    );

    // --- Forgot-password with june's VERIFIED email: identical generic
    // response body (never leaks the match), but a reset email IS sent and
    // june's prior operational password stops admitting (the re-enrollment
    // offer supersedes it exactly like an admin reset).
    let hit = node.post("/portal/users/forgot-password", "june@example.com");
    assert_eq!(hit.status, 200, "forgot-password hit: {}", hit.body);
    assert_eq!(
        hit.body, miss.body,
        "a matched vs unmatched forgot-password request must respond identically"
    );

    let emails = captured_emails(mail_dir.path());
    assert_eq!(emails.len(), 1, "exactly one reset email must be sent");
    assert!(
        emails[0].contains("To: june@example.com"),
        "captured email: {}",
        emails[0]
    );
    let temp = extract_temp_password(&emails[0]);

    // june's OLD operational password is dead — the re-enrollment offer
    // revoked it, exactly like an admin reset.
    assert!(
        node.login_is_refused("june", "june-initial-pw"),
        "the prior operational password must be revoked by the reset"
    );

    // The freshly emailed one-time password admits — login-only, forced
    // change, no opKey yet (the SAME onboarding containment every invite/
    // admin-reset re-enrollment uses).
    let nonce = node.get("/nonce");
    let id: u64 = nonce
        .body
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let login = node.post("/login", &format!("june\n{temp}\n{id}"));
    assert_eq!(login.status, 200, "reset-offer login: {}", login.body);
    assert!(
        login.body.contains("force_password_change=true"),
        "the re-enrollment offer must force a password change: {}",
        login.body
    );
    let june_token = login
        .session_token
        .expect("the reset offer admits a session token");

    // June completes her self password change through the existing
    // self-service reset-password branch — the SAME containment escape every
    // onboarding/re-enrollment path uses.
    let change = node.post(
        "/portal/users/reset-password",
        &format!("{june_token}\njunes-fresh-password!"),
    );
    assert_eq!(change.status, 200, "self change: {}", change.body);
    let _june2 = node.login("june", "junes-fresh-password!");
}

#[test]
fn an_unverified_email_never_triggers_a_reset_even_for_a_real_account() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let mail_dir = tempfile::tempdir().expect("mail capture dir");
    let node = Node::boot(data_dir.path(), mail_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    let admin = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    // kai is invited WITHOUT the verified_email option (defaults to
    // unverified) — a real account with a real matching email address.
    let invite = node.post(
        "/portal/users/invite",
        &format!("{ADMIN_PASSWORD}\n{admin}\nkai\nkai@example.com\nkai-initial-pw\nfalse\nfalse"),
    );
    assert_eq!(invite.status, 200, "invite: {}", invite.body);

    let resp = node.post("/portal/users/forgot-password", "kai@example.com");
    assert_eq!(resp.status, 200, "forgot-password: {}", resp.body);
    assert!(
        captured_emails(mail_dir.path()).is_empty(),
        "an unverified email must never trigger mail delivery"
    );
    // kai's original password still admits — nothing was reset.
    let _kai = node.login("kai", "kai-initial-pw");
}
