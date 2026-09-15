//! Acceptance test — `um-bulk-csv-invite` (ROI P1 "User management &
//! lifecycle" roadmap B5).
//!
//! Proves `POST /portal/users/bulk-invite` batches the PROVEN
//! delegated-signed invite path (`um-delegated-signed-user-admin`'s
//! `dispatch_delegated_user_op` -> `ControlOp::User(Invite)` ->
//! `iam:users:write`-gated `user_op`) across a CSV of rows, using the SAME
//! admin re-authentication for the whole batch, and is PARTIAL-BATCH
//! TOLERANT: a malformed row or a per-row failure (e.g. a duplicate handle)
//! does not abort the remaining rows.
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
fn bulk_invite_batches_the_delegated_signed_invite_path_and_tolerates_partial_failure() {
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

    // --- REGRESSION: with the WRONG admin password, the whole batch is
    // refused via the SAME delegated-signature gate the single invite
    // endpoint enforces — no row is silently admitted on a stale session
    // token alone.
    let bad_batch = node.post(
        "/portal/users/bulk-invite",
        &format!("wrong-admin-password\n{admin}\ncarol,carol@example.com"),
    );
    assert_eq!(bad_batch.status, 200, "bad batch: {}", bad_batch.body);
    assert!(
        bad_batch.body.contains("carol FAILED") && bad_batch.body.contains("delegated-sign"),
        "wrong admin password must refuse every row via the delegated-sign gate: {}",
        bad_batch.body
    );

    // --- Batch of THREE rows: bob (explicit temp password), dana (node-
    // generated password), and a MALFORMED row (missing email) sandwiched
    // between them — proving partial-batch tolerance: the malformed row
    // fails on its own but neither neighbor is aborted.
    let csv = format!(
        "{ADMIN_PASSWORD}\n{admin}\n\
         bob,bob@example.com,bob-initial-pw,false,false\n\
         onlyhandle\n\
         dana,dana@example.com"
    );
    let batch = node.post("/portal/users/bulk-invite", &csv);
    assert_eq!(batch.status, 200, "batch: {}", batch.body);

    let lines: Vec<&str> = batch.body.lines().collect();
    assert_eq!(lines.len(), 3, "one report line per input row: {:?}", lines);
    assert_eq!(lines[0], "bob OK bob-initial-pw");
    assert!(
        lines[1].starts_with("onlyhandle FAILED"),
        "malformed row reported without aborting the batch: {}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("dana OK "),
        "dana still invited despite the malformed row before it: {}",
        lines[2]
    );
    let dana_temp = lines[2].strip_prefix("dana OK ").unwrap().to_owned();
    assert!(!dana_temp.is_empty());

    // bob is listed active (force-change explicitly disabled), dana is
    // listed with the default force-change ON.
    let list = node.get(&format!("/portal/users?token={admin}"));
    assert_eq!(list.status, 200);
    assert!(
        list.body
            .contains("bob status=Invited force_password_change=false"),
        "bob invited: {}",
        list.body
    );
    assert!(
        list.body
            .contains("dana status=Invited force_password_change=true"),
        "dana invited: {}",
        list.body
    );
    // onlyhandle was never created.
    assert!(
        !list.body.lines().any(|l| l.starts_with("onlyhandle ")),
        "malformed row never created a user: {}",
        list.body
    );

    // both real invitees can log in with the passwords the batch set.
    let _bob = node.login("bob", "bob-initial-pw");
    let _dana = node.login("dana", &dana_temp);

    // --- Re-inviting bob in a second batch fails that ONE row
    // (`already-exists`) while an accompanying new row still succeeds.
    let second_batch = node.post(
        "/portal/users/bulk-invite",
        &format!(
            "{ADMIN_PASSWORD}\n{admin}\n\
             bob,bob@example.com\n\
             erin,erin@example.com"
        ),
    );
    assert_eq!(
        second_batch.status, 200,
        "second batch: {}",
        second_batch.body
    );
    let second_lines: Vec<&str> = second_batch.body.lines().collect();
    assert_eq!(second_lines.len(), 2);
    assert!(
        second_lines[0].starts_with("bob FAILED already-exists"),
        "duplicate handle reported as a per-row failure: {}",
        second_lines[0]
    );
    assert!(
        second_lines[1].starts_with("erin OK "),
        "erin still invited despite bob's failure in the same batch: {}",
        second_lines[1]
    );
}
