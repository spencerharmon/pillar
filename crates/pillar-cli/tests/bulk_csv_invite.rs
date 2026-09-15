//! Acceptance test — `um-bulk-csv-invite` (ROI P1 "User management &
//! lifecycle" roadmap B5).
//!
//! Proves `POST /portal/users/bulk-invite` batches the proven
//! delegated-signed invite path (`um-delegated-signed-user-admin`) from a
//! CSV body — one `handle,email[,password[,force_change[,require_passkey]]]`
//! row per line — and is PARTIAL-BATCH TOLERANT: a malformed row (missing
//! handle) or a duplicate-user row never aborts the rest of the batch, and
//! the response reports one `<handle> OK <password>` / `<handle> ERROR
//! <reason>` line per row so the caller can reconcile exactly which invites
//! landed. This is batching convenience over the existing single-user
//! `/portal/users/invite` delegated-signed tier — no new authority, no new
//! RBAC gate: a wrong admin password still refuses EVERY row (the
//! delegated signature is checked once per row, same crypto gate as the
//! single-invite path, reported as a per-row `ERROR` result).
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test bulk_csv_invite --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 bulk-csv-invite";
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

/// Parse a `<handle> OK <password>` / `<handle> ERROR <reason>` response
/// line into (handle, ok, rest).
fn parse_row(line: &str) -> (&str, bool, &str) {
    let mut parts = line.splitn(3, ' ');
    let handle = parts.next().unwrap_or("");
    let verdict = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    (handle, verdict == "OK", rest)
}

#[test]
fn bulk_invite_batches_the_delegated_signed_path_and_tolerates_partial_failure() {
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

    // --- Every row REFUSED with the wrong admin password: the delegated
    // signature is checked per-row exactly like the single-invite path (a
    // wrong password never unlocks any row's signing offer), so nobody in
    // the batch gets invited — but each refusal is reported as an ERROR
    // result line (200 overall), consistent with partial-batch tolerance
    // rather than a hard early abort.
    let bad_batch = node.post(
        "/portal/users/bulk-invite",
        &format!("wrong-admin-password\n{admin}\nbob,bob@example.com,bob-pw,false,false"),
    );
    assert_eq!(bad_batch.status, 200, "bulk-invite: {}", bad_batch.body);
    let (bad_handle, bad_ok, bad_rest) = parse_row(bad_batch.body.trim());
    assert_eq!(bad_handle, "bob");
    assert!(
        !bad_ok,
        "a wrong admin password must refuse the row: {}",
        bad_batch.body
    );
    assert!(
        bad_rest.contains("delegated-sign"),
        "the refusal must name the delegated-signature gate: {}",
        bad_batch.body
    );
    let list_after_bad = node.get(&format!("/portal/users?token={admin}"));
    assert!(
        !list_after_bad.body.contains("bob "),
        "bob must not have been created by the refused batch: {}",
        list_after_bad.body
    );

    // --- A batch of 4 CSV rows: two good invites, one malformed (missing
    // handle), one duplicate (bob, already invited in this same batch by an
    // earlier row) — proving PARTIAL-BATCH TOLERANCE: every row is still
    // attempted and reported, none of the failures abort the batch.
    let csv_body = format!(
        "{ADMIN_PASSWORD}\n{admin}\n\
         bob,bob@example.com,bob-initial-pw,false,false\n\
         # a comment line and a blank line are skipped\n\
         \n\
         ,missing-handle@example.com\n\
         carol,carol@example.com,carol-initial-pw,false,false\n\
         bob,bob-dupe@example.com,another-pw,false,false\n"
    );
    let batch = node.post("/portal/users/bulk-invite", &csv_body);
    assert_eq!(batch.status, 200, "bulk-invite: {}", batch.body);
    let result_lines: Vec<&str> = batch.body.lines().collect();
    assert_eq!(
        result_lines.len(),
        4,
        "one result line per non-comment/non-blank CSV row: {:?}",
        result_lines
    );

    let (h0, ok0, rest0) = parse_row(result_lines[0]);
    assert_eq!(h0, "bob");
    assert!(ok0, "bob's first invite must succeed: {}", result_lines[0]);
    assert_eq!(rest0, "bob-initial-pw");

    let (h1, ok1, _rest1) = parse_row(result_lines[1]);
    assert_eq!(h1, "");
    assert!(
        !ok1,
        "the missing-handle row must be reported as an error, not silently dropped: {}",
        result_lines[1]
    );

    let (h2, ok2, rest2) = parse_row(result_lines[2]);
    assert_eq!(h2, "carol");
    assert!(ok2, "carol's invite must succeed: {}", result_lines[2]);
    assert_eq!(rest2, "carol-initial-pw");

    let (h3, ok3, _rest3) = parse_row(result_lines[3]);
    assert_eq!(h3, "bob");
    assert!(
        !ok3,
        "the duplicate bob row must be reported as an error, not silently dropped: {}",
        result_lines[3]
    );

    // --- Both successful invitees are really live: they are listed and can
    // log in with the passwords the batch set.
    let list = node.get(&format!("/portal/users?token={admin}"));
    assert_eq!(list.status, 200);
    assert!(
        list.body
            .contains("bob status=Invited force_password_change=false"),
        "bob invited exactly once (the dupe row must not have re-created/mutated it): {}",
        list.body
    );
    assert!(
        list.body
            .contains("carol status=Invited force_password_change=false"),
        "carol invited: {}",
        list.body
    );
    let _bob = node.login("bob", "bob-initial-pw");
    let _carol = node.login("carol", "carol-initial-pw");
}
