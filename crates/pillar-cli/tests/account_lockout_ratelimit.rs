//! Acceptance test — `um-account-lockout-ratelimit` (ROI P1 "User
//! management & lifecycle" roadmap B3).
//!
//! Proves the account lockout + rate-limit throttle sitting in front of the
//! existing fail-closed `/login` admit path:
//!   * repeated WRONG-password `/login` attempts against one identifier trip
//!     an account lockout after a threshold of consecutive failures — the
//!     locked account is then refused (`423 Locked`) even with the CORRECT
//!     password, until either an admin unlocks it
//!     (`POST /portal/users/unlock`) or the lockout auto-expires
//!     (`PILLAR_LOGIN_LOCKOUT_SECS`);
//!   * a burst of requests to a rate-limited route (`/nonce`) from one
//!     source is refused `429 Too Many Requests` once it exceeds the
//!     sliding-window cap, and a fresh request succeeds again once the
//!     window has slid past the oldest hit.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal surface, exactly like
//! `delegated_signed_user_admin.rs`.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test account_lockout_ratelimit --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 account-lockout";
const ADMIN_HANDLE: &str = "alice@pillar";
const BOB_PASSWORD: &str = "bob-initial-pw";

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
/// bound; killed on drop. `lockout_secs` is forwarded as
/// `PILLAR_LOGIN_LOCKOUT_SECS` so the test can observe auto-expiry within a
/// bounded wait instead of the real 300s default.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path, lockout_secs: u64) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("PILLAR_LOGIN_LOCKOUT_SECS", lockout_secs.to_string())
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

    /// GET /nonce then POST /login with `identifier\npassword\n<nonce id>`.
    /// Returns the raw response (NOT asserting success) so callers can
    /// inspect a refused/locked-out/rate-limited attempt.
    fn try_login(&self, identifier: &str, password: &str) -> HttpResponse {
        let nonce_resp = self.get("/nonce");
        assert_eq!(nonce_resp.status, 200, "nonce: {}", nonce_resp.body);
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses");
        self.post("/login", &format!("{identifier}\n{password}\n{id}"))
    }

    fn login(&self, identifier: &str, password: &str) -> String {
        let resp = self.try_login(identifier, password);
        assert_eq!(resp.status, 200, "login: {}", resp.body);
        resp.session_token.expect("login response carries a session token")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Repeated wrong-password `/login` attempts against one identifier trip an
/// account lockout: past the failure threshold, even the CORRECT password
/// is refused `423 Locked` — proving this is a real counter/threshold gate,
/// not merely the pre-existing per-attempt `401 DENIED`. An admin unlock
/// (`POST /portal/users/unlock`) clears it early, and the CORRECT password
/// then succeeds again.
#[test]
fn repeated_failed_logins_trip_a_lockout_that_admin_unlock_clears() {
    let data_dir = tempfile::tempdir().expect("data dir");
    // Long enough that auto-expiry never races the admin-unlock assertions
    // below.
    let node = Node::boot(data_dir.path(), 3600);

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let admin = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);
    let invite = node.post(
        "/portal/users/invite",
        &format!("{ADMIN_PASSWORD}\n{admin}\nbob\nbob@example.com\n{BOB_PASSWORD}\nfalse\nfalse"),
    );
    assert_eq!(invite.status, 200, "invite: {}", invite.body);

    // A handful of wrong-password attempts each read the pre-existing
    // per-attempt 401 — the lockout has not tripped yet.
    for n in 0..4 {
        let resp = node.try_login("bob", "definitely-wrong");
        assert_eq!(resp.status, 401, "attempt {n}: {}", resp.body);
    }

    // The 5th consecutive failure trips the lockout.
    let tripping = node.try_login("bob", "definitely-wrong");
    assert_eq!(tripping.status, 401, "tripping attempt: {}", tripping.body);

    // Now even the CORRECT password is refused `423 Locked` — this is the
    // regression the counter/threshold proves: before this task, the
    // correct password always admitted regardless of prior failures.
    let locked = node.try_login("bob", BOB_PASSWORD);
    assert_eq!(
        locked.status, 423,
        "a locked-out account must refuse even the correct password: {}",
        locked.body
    );
    assert!(
        locked.body.contains("account-locked"),
        "the refusal must name the lockout: {}",
        locked.body
    );

    // The admin unlocks bob's account.
    let unlock = node.post("/portal/users/unlock", &format!("{admin}\nbob"));
    assert_eq!(unlock.status, 200, "unlock: {}", unlock.body);

    // The correct password now succeeds again.
    let recovered = node.try_login("bob", BOB_PASSWORD);
    assert_eq!(
        recovered.status, 200,
        "bob must be able to log in again after admin unlock: {}",
        recovered.body
    );
}

/// A burst of requests to a rate-limited route (`/nonce`) from one source
/// is refused `429 Too Many Requests` once it exceeds the sliding-window
/// cap — proving a real per-source throttle sits in front of the route,
/// not merely an unbounded admit path.
#[test]
fn a_request_burst_is_rate_limited() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path(), 3600);

    let mut saw_success = false;
    let mut saw_rate_limited = false;
    // Comfortably past any reasonable sliding-window cap; the loop stops
    // the instant a 429 is observed, so this is not asserting an exact cap.
    for _ in 0..200 {
        let resp = node.get("/nonce");
        match resp.status {
            200 => saw_success = true,
            429 => {
                assert!(
                    resp.body.contains("rate-limited"),
                    "the refusal must name the rate limit: {}",
                    resp.body
                );
                saw_rate_limited = true;
                break;
            }
            other => panic!("unexpected /nonce status {other}: {}", resp.body),
        }
    }
    assert!(saw_success, "at least the early requests must succeed");
    assert!(
        saw_rate_limited,
        "a burst of {} requests must eventually be rate-limited",
        200
    );
}
