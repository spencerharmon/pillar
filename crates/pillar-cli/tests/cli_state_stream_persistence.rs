//! Acceptance test — `cli-state-stream-persistence-invariant` (NODE-level).
//!
//! ## The invariant under test (2026-09-09 ROI HEAD)
//!
//! Everything is persisted; every state-changing act — portal OR CLI — is a
//! signed state-stream event. NO state lives only in RAM on either front-end;
//! both are front-ends over the SAME shared mutator (the node's journaled
//! `WebAuthContext`), so persistence is STRUCTURAL. A CLI subcommand that
//! mutated in-memory without emitting the journaled event would be a BUG of the
//! same class as placeholder crypto.
//!
//! `node_persistence_rehydrate` already proves the PORTAL (browser) surface
//! survives a restart. THIS suite proves the invariant across the OTHER
//! front-end: it drives the REAL compiled `pillar` CLI mutator
//! (`pillar portal members add`) — the actual argv shell, as a subprocess,
//! over real HTTP/1.1 — against a running node, then KILLS that node and boots
//! a FRESH one (empty in-memory state) against the SAME on-disk data dir, and
//! asserts the CLI-authored mutation rehydrated. A crate-level round-trip is
//! insufficient (it never drives the real CLI against a real node); this is the
//! node-level, per-surface acceptance the card requires.
//!
//! What it proves, end to end:
//! 1. A CLI mutation (`pillar portal members add`) against a running node is
//!    captured in the durable streaming DB (`<data-dir>/streamdb/` grows real,
//!    non-empty, content-addressed files; the plaintext password is in NONE).
//! 2. After the node is killed and a FRESH-context node boots on the SAME data
//!    dir, the CLI-authored member is visible via `pillar portal members list`
//!    — rehydrated purely from disk, never carried in RAM.
//! 3. Login material stays sealed: the plaintext password never lands on disk.
//! 4. A SECOND CLI mutation on the restarted node (a role change) is itself
//!    journaled and survives a further restart — the write-through holds for
//!    every act, not just the first.
//!
//! RED if a CLI mutator ever bypassed the journaled shared mutator (the
//! mutation would vanish on restart); GREEN because `pillar portal` drives the
//! node's already-journaled portal route, so the CLI and the browser emit the
//! IDENTICAL signed op onto the IDENTICAL stream.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md stub);
//! run via `cargo test -p pillar-cli --test cli_state_stream_persistence
//! --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "correct horse battery staple — cli 2026";
const HANDLE: &str = "spencer";
const CELL: &str = "cell-cli-genesis";

/// A minimal HTTP response used only for the node-readiness probe (the CLI
/// itself does all the real driving as a subprocess).
struct HttpResponse {
    status: u16,
    body: String,
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
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).ok()?;
        if n == 0 || header == "\r\n" {
            break;
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();
    Some(HttpResponse {
        status,
        body: resp_body,
    })
}

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

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn status(&self) -> String {
        http(self.port, "GET", "/bootstrap/status", "")
            .expect("status")
            .body
            .trim()
            .to_string()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One captured run of the REAL `pillar` CLI as a subprocess.
struct CliRun {
    status_ok: bool,
    stdout: String,
    stderr: String,
}

/// Exec the real compiled `pillar` CLI (`CARGO_BIN_EXE_pillar`) with `args`
/// against node `node_url`, optionally carrying `PILLAR_TOKEN`. This is the
/// black-box driver — never an in-process library call.
fn pillar_cli(node_url: &str, token: Option<&str>, args: &[&str]) -> CliRun {
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
    let mut cmd = Command::new(bin);
    cmd.arg("portal")
        .arg("--node")
        .arg(node_url)
        .args(args)
        .env("RUST_LOG", "error");
    if let Some(t) = token {
        cmd.env("PILLAR_TOKEN", t);
    }
    let out = cmd.output().expect("exec pillar portal");
    CliRun {
        status_ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Recursively collect every regular file's bytes under `dir`.
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

/// Bootstrap a node over the real HTTP portal (cell + first user), then return
/// a logged-in session token minted BY THE CLI (`pillar portal login`), proving
/// the CLI can authenticate against the running node before it mutates.
fn bootstrap_and_cli_login(node: &Node) -> String {
    // Bootstrap the cell + first user directly over HTTP (bootstrap is the
    // browser-portal surface `node_persistence_rehydrate` already covers; this
    // test's subject is the CLI MUTATOR, so we reach a bootstrapped node the
    // cheap way and then drive the CLI for the act under test).
    let create_cell = http(node.port, "POST", "/bootstrap/create-cell", CELL).expect("create-cell");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = http(
        node.port,
        "POST",
        "/bootstrap/create-user",
        &format!("{HANDLE}\n{PASSWORD}"),
    )
    .expect("create-user");
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    assert_eq!(node.status(), "BOOTSTRAPPED");

    // Log in THROUGH THE REAL CLI and capture the minted token from stdout.
    let login = pillar_cli(&node.url(), None, &["login", HANDLE, PASSWORD]);
    assert!(
        login.status_ok,
        "cli login failed: stdout={:?} stderr={:?}",
        login.stdout, login.stderr
    );
    let token = login.stdout.trim().to_string();
    assert!(!token.is_empty(), "cli login printed no token: {login:?}", login = login.stderr);
    token
}

#[test]
fn a_cli_mutation_against_a_running_node_is_journaled_and_survives_a_fresh_context_restart() {
    let data_dir = tempfile::tempdir().expect("data dir");

    // --- Process A: bootstrap, then MUTATE via the real CLI. ---
    let node_a = Node::boot(data_dir.path());
    assert_eq!(node_a.status(), "FRESH");
    let token = bootstrap_and_cli_login(&node_a);

    // THE CLI MUTATION under test: add a member via `pillar portal members add`.
    // This drives the node's journaled `/portal/members/add` route, so the act
    // is written through to the durable stream — never held only in CLI RAM.
    let add = pillar_cli(
        &node_a.url(),
        Some(&token),
        &["members", "add", "charlie", "operator"],
    );
    assert!(
        add.status_ok,
        "cli members add failed: stdout={:?} stderr={:?}",
        add.stdout, add.stderr
    );

    // The CLI itself can read the member back on the SAME node (materialized
    // view folded on the node, read over the CLI).
    let list_a = pillar_cli(&node_a.url(), Some(&token), &["members", "list"]);
    assert!(list_a.status_ok, "cli members list: {}", list_a.stderr);
    assert!(
        list_a.stdout.contains("MEMBER charlie ROLE operator"),
        "same-process CLI list must show the just-added member, got: {}",
        list_a.stdout
    );

    // Give the synchronous durable append a beat before we tear the node down.
    std::thread::sleep(Duration::from_millis(200));

    // The CLI mutation landed in the durable streaming DB, and the plaintext
    // password appears in NONE of the persisted files.
    let streamdb_dir = data_dir.path().join("streamdb");
    let files = read_all_files(&streamdb_dir);
    assert!(
        !files.is_empty(),
        "expected non-empty durable streamdb files under {} after a CLI mutation, found none",
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

    // --- Process B: a FRESH context on the SAME durable stream. ---
    let node_b = Node::boot(data_dir.path());
    assert_eq!(
        node_b.status(),
        "BOOTSTRAPPED",
        "a restarted node must rehydrate to a bootstrapped state from disk"
    );

    // Re-authenticate via the CLI against the restarted node and confirm the
    // CLI-authored member REHYDRATED (it was journaled, not RAM-only).
    let token_b = pillar_cli(&node_b.url(), None, &["login", HANDLE, PASSWORD])
        .stdout
        .trim()
        .to_string();
    assert!(!token_b.is_empty(), "cli re-login on restarted node minted no token");

    let list_b = pillar_cli(&node_b.url(), Some(&token_b), &["members", "list"]);
    assert!(list_b.status_ok, "cli members list on restart: {}", list_b.stderr);
    assert!(
        list_b.stdout.contains("MEMBER charlie ROLE operator"),
        "the CLI-authored add-member act MUST survive a fresh-context restart \
         (rehydrated from the durable stream), got: {}",
        list_b.stdout
    );

    // --- A SECOND CLI mutation on the RESTARTED node, then a further restart:
    // the write-through holds for every act, not just the first. ---
    let role = pillar_cli(
        &node_b.url(),
        Some(&token_b),
        &["members", "role", "charlie", "viewer"],
    );
    assert!(
        role.status_ok,
        "cli members role failed: stdout={:?} stderr={:?}",
        role.stdout, role.stderr
    );
    std::thread::sleep(Duration::from_millis(200));
    drop(node_b);

    let node_c = Node::boot(data_dir.path());
    assert_eq!(node_c.status(), "BOOTSTRAPPED");
    let token_c = pillar_cli(&node_c.url(), None, &["login", HANDLE, PASSWORD])
        .stdout
        .trim()
        .to_string();
    let list_c = pillar_cli(&node_c.url(), Some(&token_c), &["members", "list"]);
    assert!(list_c.status_ok, "cli members list after 2nd restart: {}", list_c.stderr);
    assert!(
        list_c.stdout.contains("MEMBER charlie ROLE viewer"),
        "the SECOND CLI mutation (role change) must ALSO survive a restart, got: {}",
        list_c.stdout
    );
}
