//! Acceptance test — `streamdb-persistence-impl` (node-level).
//!
//! ROI reconcile 2026-09-09 (operator-directed): a CRATE-scoped rehydrate test
//! (`cargo test -p pillar-streamdb --test rehydrate_from_ipfs`) went green
//! while a production bug shipped — the `pillar node run` web portal
//! (`WebAuthContext`) held cell/first-user/members/custody/identity state
//! ONLY in memory with no handle to the durable stream, so a bootstrapped
//! node persisted NOTHING (0 streamdb files) and re-served the bootstrap flow
//! on every restart. The crate test could not catch this because it never
//! drives the node's web plane.
//!
//! This suite is BLACK-BOX and REAL: it execs the actual compiled `pillar`
//! binary (`CARGO_BIN_EXE_pillar`) as a subprocess with a web surface bound
//! and a real on-disk `--data-dir`, drives it purely over real HTTP/1.1 on a
//! real TCP socket — never an in-process `WebAuthContext` call — and proves:
//!
//! 1. Bootstrapping a cell + first user over the real HTTP portal writes real,
//!    non-empty, content-addressed files under `<data-dir>/streamdb/` — and
//!    the plaintext password never appears in any of them.
//! 2. Killing that process and booting a FRESH one against the SAME data dir
//!    (a pod restart on the same PVC) reports `/bootstrap/status` as
//!    `BOOTSTRAPPED` — serving login, not create-cell — purely from what was
//!    rehydrated off disk.
//! 3. The first user logs in on the restarted node with the CORRECT password
//!    and is DENIED with a wrong one.
//! 4. A post-bootstrap management act (adding a member) performed on the
//!    FIRST process survives the restart and is visible on the SECOND.
//!
//! RED before the portal was wired to the durable stream (0 streamdb files,
//! restart re-serves bootstrap); GREEN once the op-journal write-through +
//! replay-on-boot lands.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-cli --test node_persistence_rehydrate
//! --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "correct horse battery staple 2026";
const HANDLE: &str = "spencer";

/// One HTTP response the black-box client parsed off the wire.
struct HttpResponse {
    status: u16,
    session_token: Option<String>,
    body: String,
}

/// Send one real HTTP/1.1 request to `127.0.0.1:<port>` and read the full
/// response back — the black-box client's ONLY view of the node.
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
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        session_token,
        body: resp_body,
    })
}

/// Claim a free localhost TCP port for the node's web surface.
fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

/// A booted `pillar node run` subprocess; killed on drop.
struct Node {
    child: Child,
    port: u16,
}

impl Node {
    /// Boot the real compiled `pillar` binary against `data_dir`, on a fresh
    /// free web port, and block until its `/bootstrap/status` route answers
    /// (or panic past the deadline).
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node { child, port };
        node.await_ready(Duration::from_secs(20));
        node
    }

    fn await_ready(&self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(resp) = http(self.port, "GET", "/bootstrap/status", "") {
                if resp.status == 200 {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "pillar node run did not serve /bootstrap/status within {within:?} on port {}",
                    self.port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn get(&self, path: &str) -> HttpResponse {
        http(self.port, "GET", path, "").expect("GET succeeds")
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        http(self.port, "POST", path, body).expect("POST succeeds")
    }

    /// Real node-side login: `GET /nonce`, then `POST /login`. Returns the
    /// admitted session token.
    fn login(&self, handle: &str, password: &str) -> HttpResponse {
        let nonce = self.get("/nonce");
        assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
        let id: u64 = nonce
            .body
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("nonce id");
        self.post("/login", &format!("{handle}\n{password}\n{id}"))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Recursively collect every regular file's bytes under `dir` — used to prove
/// the streaming DB actually wrote durable content and never a plaintext
/// password.
fn read_all_files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(read_all_files(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, bytes));
        }
    }
    out
}

#[test]
fn bootstrapped_node_persists_and_a_fresh_context_on_the_same_disk_rehydrates_to_login() {
    let data_dir = tempfile::tempdir().expect("data dir");

    // --- Process A: bootstrap over the REAL HTTP portal. ---
    let node_a = Node::boot(data_dir.path());

    assert_eq!(
        node_a.get("/bootstrap/status").body.trim(),
        "FRESH",
        "a brand-new node must present FRESH before bootstrap"
    );

    let create_cell = node_a.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);

    let create_user = node_a.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    assert_eq!(
        node_a.get("/bootstrap/status").body.trim(),
        "BOOTSTRAPPED",
        "after cell + first user the node must report BOOTSTRAPPED"
    );

    // First login on the SAME process, immediately after bootstrap, with the
    // correct password.
    let login_a = node_a.login(HANDLE, PASSWORD);
    assert_eq!(login_a.status, 200, "first login: {}", login_a.body);
    assert!(
        login_a.body.contains(HANDLE),
        "login response should greet the handle, got: {}",
        login_a.body
    );
    let token_a = login_a.session_token.expect("session token");

    // A post-bootstrap MANAGEMENT ACT: add a member. This must ALSO survive
    // the restart below.
    let add_member = node_a.post(
        "/portal/members/add",
        &format!("{token_a}\ncharlie\noperator"),
    );
    assert_eq!(add_member.status, 200, "add member: {}", add_member.body);

    // Give the durable append a moment to land on disk (it is synchronous in
    // the handler, but be generous against scheduling jitter before we kill
    // the process).
    std::thread::sleep(Duration::from_millis(200));

    // --- Prove the durable effect landed on REAL disk before we tear the
    // process down: non-empty, content-addressed files under
    // `<data-dir>/streamdb/`, and the plaintext password appears in NONE of
    // them (the first user's credential is persisted only as its
    // already-sealed offer ciphertext). ---
    let streamdb_dir = data_dir.path().join("streamdb");
    let files = read_all_files(&streamdb_dir);
    assert!(
        !files.is_empty(),
        "expected non-empty durable streamdb files under {}, found none",
        streamdb_dir.display()
    );
    for (path, bytes) in &files {
        assert!(
            !bytes
                .windows(PASSWORD.len())
                .any(|w| w == PASSWORD.as_bytes()),
            "plaintext password must never be written to disk, found in {}",
            path.display()
        );
    }

    drop(node_a);

    // --- Process B: a FRESH context (empty in-memory state) on the SAME
    // durable stream — a pod restart on the same PVC. ---
    let node_b = Node::boot(data_dir.path());

    assert_eq!(
        node_b.get("/bootstrap/status").body.trim(),
        "BOOTSTRAPPED",
        "a restarted node with a rehydrated stream must report BOOTSTRAPPED \
         (serving login), never re-serve bootstrap"
    );

    // The first user logs in with the CORRECT password on the RESTARTED node.
    let login_b = node_b.login(HANDLE, PASSWORD);
    assert_eq!(
        login_b.status, 200,
        "restarted-node login must succeed, got: {}",
        login_b.body
    );
    assert!(login_b.body.contains(HANDLE), "got: {}", login_b.body);
    let token_b = login_b.session_token.expect("session token");

    // Denied with a wrong password.
    let bad_login = node_b.login(HANDLE, "definitely-the-wrong-password");
    assert_eq!(
        bad_login.status, 401,
        "wrong password must be denied, got: {}",
        bad_login.body
    );

    // The post-bootstrap management act (add-member) survived the restart.
    let members = node_b.get(&format!("/portal/members?token={token_b}"));
    assert_eq!(members.status, 200, "members: {}", members.body);
    assert!(
        members.body.contains("MEMBER charlie ROLE operator"),
        "the pre-restart add-member act must survive rehydrate, got: {}",
        members.body
    );
}
