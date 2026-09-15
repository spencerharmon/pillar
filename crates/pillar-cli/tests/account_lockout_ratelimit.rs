//! Acceptance test — `um-account-lockout-ratelimit` (ROI Priority 1 "User
//! management & lifecycle" roadmap B3).
//!
//! Proves the failed-attempt LOCKOUT and RATE-LIMIT throttle layered on top
//! of the existing fail-closed `/login` admit path — a counter/threshold in
//! front of the UNCHANGED admit decision, no new authority path / TLA+ gate:
//!
//!  1. **Lockout**: N consecutive DENIED logins for an identifier lock the
//!     account; a subsequent login is refused UP FRONT (`403 DENIED
//!     account-locked …`) even with the CORRECT password — the throttle sits
//!     before the admit path. An **admin unlock**
//!     (`POST /portal/users/unlock`, delegated-signed like invite/reset)
//!     clears the lock immediately so the real user gets back in, and the
//!     lock also **auto-expires** after its cooldown. A successful login
//!     CLEARS the counter (so honest retries never accumulate toward a lock).
//!  2. **Rate limit**: nonce issuance is token-bucket capped per client, so an
//!     attacker cannot spin the challenge machinery arbitrarily fast
//!     (`429 DENIED rate-limited nonce` past the burst).
//!
//! Black-box: execs the real compiled `pillar` binary and drives its real
//! HTTP portal surface. The lockout thresholds/cooldown and the rate limiter
//! are made deterministic via the `PILLAR_LOCKOUT_MAX_FAILURES` /
//! `PILLAR_LOCKOUT_SECS` / `PILLAR_RATELIMIT_DISABLE` env knobs the server
//! reads at boot, so the test never waits a real 15-minute cooldown.
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

/// A booted `pillar node run` subprocess with its HTTP portal surface; killed
/// on drop. `env` carries the deterministic lockout/rate-limit knobs.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot_with(data_dir: &std::path::Path, env: &[(&str, &str)]) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let mut cmd = Command::new(bin);
        cmd.arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn pillar node run");
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

    fn nonce_id(&self) -> u64 {
        let nonce_resp = self.get("/nonce");
        assert_eq!(nonce_resp.status, 200, "nonce: {}", nonce_resp.body);
        nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses")
    }

    /// A raw login attempt (returns the response, no assertions), driving the
    /// real GET /nonce -> POST /login handshake.
    fn try_login(&self, identifier: &str, password: &str) -> HttpResponse {
        let id = self.nonce_id();
        self.post("/login", &format!("{identifier}\n{password}\n{id}"))
    }

    /// A login that must succeed; returns the admitted session token.
    fn login(&self, identifier: &str, password: &str) -> String {
        let resp = self.try_login(identifier, password);
        assert_eq!(resp.status, 200, "login: {}", resp.body);
        resp.session_token
            .expect("login response carries a session token")
    }

    fn bootstrap_admin(&self) {
        let create_cell = self.post("/bootstrap/create-cell", "cell-genesis");
        assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
        let create_user = self.post(
            "/bootstrap/create-user",
            &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
        );
        assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Failed-attempt lockout over the fail-closed admit path: threshold locks,
/// the lock refuses even the correct password up front, and an admin unlock
/// restores access immediately. Uses a LONG cooldown so the assertions are
/// timing-insensitive (auto-expiry has its own dedicated test).
#[test]
fn failed_attempts_lock_the_account_and_admin_unlock_restores_it() {
    let data_dir = tempfile::tempdir().expect("data dir");
    // 3 failures locks; a long (1h) cooldown so nothing auto-expires under the
    // test's own wall-clock; rate limiter off so the LOCKOUT gate (not the
    // burst limiter) is what refuses.
    let node = Node::boot_with(
        data_dir.path(),
        &[
            ("PILLAR_LOCKOUT_MAX_FAILURES", "3"),
            ("PILLAR_LOCKOUT_SECS", "3600"),
            ("PILLAR_RATELIMIT_DISABLE", "1"),
        ],
    );
    node.bootstrap_admin();

    // The admin is a distinct principal we keep ALWAYS usable (never locked),
    // so it can drive the delegated-signed unlock. All lockout testing targets
    // a second user 'bob'.
    let admin_token = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);
    let invite = node.post(
        "/portal/users/invite",
        &format!(
            "{ADMIN_PASSWORD}\n{admin_token}\nbob\nbob@example.com\nbob-initial-pw\nfalse\nfalse"
        ),
    );
    assert_eq!(invite.status, 200, "invite bob: {}", invite.body);

    // Sanity: bob logs in before any failures.
    let _ = node.login("bob", "bob-initial-pw");

    // --- Two wrong-password attempts: DENIED (401) but NOT yet locked.
    for i in 0..2 {
        let bad = node.try_login("bob", "wrong-password");
        assert_eq!(
            bad.status, 401,
            "attempt {i} denied not locked: {}",
            bad.body
        );
        assert!(
            bad.body.contains("DENIED") && !bad.body.contains("account-locked"),
            "attempt {i} is a plain admit denial: {}",
            bad.body
        );
    }
    // A correct login STILL works here — below the threshold, and it CLEARS
    // the accumulated counter (honest retries never trip a lock).
    let _ = node.login("bob", "bob-initial-pw");

    // --- Now trip the lock: 3 consecutive wrong attempts.
    for _ in 0..3 {
        let bad = node.try_login("bob", "wrong-password");
        assert_eq!(bad.status, 401, "denied: {}", bad.body);
    }
    // The account is LOCKED: even the CORRECT password is refused UP FRONT
    // (403, before the admit path) — the counter/threshold throttle in action.
    let locked = node.try_login("bob", "bob-initial-pw");
    assert_eq!(
        locked.status, 403,
        "correct password must be refused while locked: {}",
        locked.body
    );
    assert!(
        locked.body.contains("account-locked"),
        "the refusal names the lockout, not an admit failure: {}",
        locked.body
    );

    // --- A wrong admin password is refused by the delegated-signature gate.
    let bad_unlock = node.post(
        "/portal/users/unlock",
        &format!("wrong-admin-password\n{admin_token}\nbob"),
    );
    assert_eq!(
        bad_unlock.status, 403,
        "unlock with a wrong admin password must be refused: {}",
        bad_unlock.body
    );
    // bob is still locked after the refused unlock.
    assert_eq!(
        node.try_login("bob", "bob-initial-pw").status,
        403,
        "still locked after a refused unlock"
    );

    // --- ADMIN UNLOCK with the correct admin password clears the lock
    // IMMEDIATELY (the cooldown has not elapsed — this is a real clear).
    let unlock = node.post(
        "/portal/users/unlock",
        &format!("{ADMIN_PASSWORD}\n{admin_token}\nbob"),
    );
    assert_eq!(unlock.status, 200, "admin unlock bob: {}", unlock.body);
    assert!(
        unlock.body.contains("cleared=true"),
        "unlock reports it cleared bob's lock: {}",
        unlock.body
    );
    // bob is admitted again right away — no cooldown wait needed.
    let bob_back = node.try_login("bob", "bob-initial-pw");
    assert_eq!(
        bob_back.status, 200,
        "bob logs in immediately after admin unlock: {}",
        bob_back.body
    );
}

/// The lockout AUTO-EXPIRES after its cooldown: a locked account is admittable
/// again with the correct password once the cooldown elapses, with no admin
/// action. Uses a short (test-only) cooldown.
#[test]
fn lockout_auto_expires_after_the_cooldown() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot_with(
        data_dir.path(),
        &[
            ("PILLAR_LOCKOUT_MAX_FAILURES", "3"),
            ("PILLAR_LOCKOUT_SECS", "3"),
            ("PILLAR_RATELIMIT_DISABLE", "1"),
        ],
    );
    node.bootstrap_admin();

    // Lock the admin account out.
    for _ in 0..3 {
        let _ = node.try_login(ADMIN_HANDLE, "wrong-password");
    }
    let locked = node.try_login(ADMIN_HANDLE, ADMIN_PASSWORD);
    assert_eq!(
        locked.status, 403,
        "locked before cooldown: {}",
        locked.body
    );
    assert!(locked.body.contains("account-locked"));

    // Wait out the (short, test-only) cooldown; the lock auto-expires.
    std::thread::sleep(Duration::from_secs(5)); // > PILLAR_LOCKOUT_SECS=3
    let after_expiry = node.try_login(ADMIN_HANDLE, ADMIN_PASSWORD);
    assert_eq!(
        after_expiry.status, 200,
        "lock auto-expires after cooldown: {}",
        after_expiry.body
    );
}

/// Nonce issuance is token-bucket rate-limited per client: a burst passes,
/// then further requests in the same window are `429`-refused — an attacker
/// cannot spin the challenge machinery arbitrarily fast.
#[test]
fn nonce_issuance_is_rate_limited_past_the_burst() {
    let data_dir = tempfile::tempdir().expect("data dir");
    // Rate limiter ON (default policies). Nonce burst is 30 + 5/sec refill, so
    // a tight loop of well over the burst must eventually hit a 429.
    let node = Node::boot_with(data_dir.path(), &[]);
    node.bootstrap_admin();

    let mut saw_ok = false;
    let mut saw_limited = false;
    // Fire many nonce requests back-to-back from this one client.
    for _ in 0..80 {
        let resp = node.get("/nonce");
        match resp.status {
            200 => saw_ok = true,
            429 => {
                saw_limited = true;
                assert!(
                    resp.body.contains("rate-limited"),
                    "429 names the rate limit: {}",
                    resp.body
                );
                break;
            }
            other => panic!("unexpected nonce status {other}: {}", resp.body),
        }
    }
    assert!(saw_ok, "the initial burst of nonces is served");
    assert!(
        saw_limited,
        "sustained nonce issuance past the burst is rate-limited (429)"
    );
}
