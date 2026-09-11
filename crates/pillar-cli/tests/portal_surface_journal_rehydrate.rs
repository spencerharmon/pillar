//! Acceptance test — `portal-nonlogin-surface-journal` (node-level).
//!
//! ROI reconcile 2026-09-09 (operator-directed): the 2026-09-07 persistence
//! fix (`streamdb-persistence-impl`) journals only the login/management-
//! critical portal state (cell + first user, members, custody, identity,
//! saved layouts). This task brings the OTHER portal-authored surfaces onto
//! the SAME durable-journal-and-replay mechanism so a restarted node
//! rehydrates the FULL operator-authored state:
//!
//! 1. resource-plane apply (`/portal/resource/apply` — workloads)
//! 2. trust attestations (`/portal/attestations/build`)
//! 3. topology label declarations (`/portal/topology/label/declare`)
//! 4. observability dashboards (`/portal/obs/dashboard`)
//!
//! This suite is BLACK-BOX and REAL: it execs the actual compiled `pillar`
//! binary (`CARGO_BIN_EXE_pillar`) as a subprocess with a web surface bound
//! and a real on-disk `--data-dir`, drives it purely over real HTTP/1.1 on a
//! real TCP socket, and proves EACH surface's authored state survives a
//! process restart against the SAME data dir (a pod restart on the same
//! PVC) — never an in-process `WebAuthContext` call.
//!
//! RED before this task (each surface lives only in the in-context
//! `WebAuthContext`, lost on restart); GREEN once every surface above is
//! journaled as a durable `PortalOp` and replayed on boot.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-cli --test
//! portal_surface_journal_rehydrate --features acceptance`.

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

/// Bootstrap a fresh cell + first user over the REAL HTTP portal, returning
/// the admitted session token.
fn bootstrap_and_login(node: &Node) -> String {
    assert_eq!(
        node.get("/bootstrap/status").body.trim(),
        "FRESH",
        "a brand-new node must present FRESH before bootstrap"
    );
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    let login = node.login(HANDLE, PASSWORD);
    assert_eq!(login.status, 200, "login: {}", login.body);
    login.session_token.expect("session token")
}

#[test]
fn resource_plane_apply_survives_restart() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node_a = Node::boot(data_dir.path());
    let token = bootstrap_and_login(&node_a);

    let applied = node_a.post("/portal/resource/apply", &format!("{token}\nweb\napp:v1"));
    assert_eq!(applied.status, 200, "apply: {}", applied.body);

    std::thread::sleep(Duration::from_millis(200));
    drop(node_a);

    let node_b = Node::boot(data_dir.path());
    let token_b = bootstrap_and_login_skip_if_bootstrapped(&node_b);
    let listed = node_b.get(&format!(
        "/portal/resource/describe?token={token_b}&kind=Workload&name=web"
    ));
    assert_eq!(listed.status, 200, "describe: {}", listed.body);
    assert!(
        listed.body.contains("web") && listed.body.contains("app:v1"),
        "the pre-restart resource apply must survive rehydrate, got: {}",
        listed.body
    );
}

#[test]
fn trust_attestation_survives_restart() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node_a = Node::boot(data_dir.path());
    let _token = bootstrap_and_login(&node_a);

    let built = node_a.post(
        "/portal/attestations/build",
        &format!("{_token}\nowner\nself\n\nzoe\nstream:append\ncell-b/streams/*\n\ncell-b"),
    );
    assert_eq!(built.status, 200, "attest build: {}", built.body);

    std::thread::sleep(Duration::from_millis(200));
    drop(node_a);

    let node_b = Node::boot(data_dir.path());
    let token_b = bootstrap_and_login_skip_if_bootstrapped(&node_b);
    let graph = node_b.get(&format!("/portal/trust-graph?token={token_b}"));
    assert_eq!(graph.status, 200, "trust-graph: {}", graph.body);
    assert!(
        graph.body.contains("owner") && graph.body.contains("zoe"),
        "the pre-restart attestation must survive rehydrate, got: {}",
        graph.body
    );
}

#[test]
fn topology_label_declare_survives_restart() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node_a = Node::boot(data_dir.path());
    let token = bootstrap_and_login(&node_a);

    let declared = node_a.post(
        "/portal/topology/label/declare",
        &format!("{token}\nnode-7\nrack\nr7"),
    );
    assert_eq!(declared.status, 200, "declare: {}", declared.body);

    std::thread::sleep(Duration::from_millis(200));
    drop(node_a);

    // A restarted node whose declared label did NOT survive would have an
    // EMPTY declared map, so attesting a DIFFERENT value for the SAME
    // node/tier would show no mismatch at all (nothing to compare against).
    // Attesting a deliberately mismatched value here and observing the
    // MISMATCH line is exactly `topology_mismatches`'s own declared-vs-
    // attested comparison, so it only fires if the pre-restart declare is
    // still present in `self.declared` post-rehydrate.
    let node_b = Node::boot(data_dir.path());
    let token_b = bootstrap_and_login_skip_if_bootstrapped(&node_b);
    let attested = node_b.post(
        "/portal/topology/label/attest",
        &format!("{token_b}\nowner\nself\n\nnode-7\nrack\nr99\ncell-genesis"),
    );
    assert_eq!(attested.status, 200, "attest: {}", attested.body);

    let mismatches = node_b.get(&format!("/portal/topology/mismatches?token={token_b}"));
    assert_eq!(mismatches.status, 200, "mismatches: {}", mismatches.body);
    assert!(
        mismatches
            .body
            .contains("MISMATCH node-7 tier=rack declared=r7 attested=r99"),
        "the pre-restart topology declare must survive rehydrate (else there is nothing \
         to mismatch against the post-restart attest), got: {}",
        mismatches.body
    );
}

#[test]
fn observability_dashboard_survives_restart() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node_a = Node::boot(data_dir.path());
    let token = bootstrap_and_login(&node_a);

    let saved = node_a.post("/portal/obs/dashboard", &format!("{token}\nops: layout-v1"));
    assert_eq!(saved.status, 200, "save dashboard: {}", saved.body);
    let dashboard_id = saved
        .body
        .split_whitespace()
        .nth(1)
        .expect("OBS-DASHBOARD-CID <id>")
        .to_owned();

    std::thread::sleep(Duration::from_millis(200));
    drop(node_a);

    let node_b = Node::boot(data_dir.path());
    let token_b = bootstrap_and_login_skip_if_bootstrapped(&node_b);
    let fetched = node_b.get(&format!(
        "/portal/obs/dashboard/get?token={token_b}&id={dashboard_id}"
    ));
    assert_eq!(fetched.status, 200, "dashboard get: {}", fetched.body);
    assert!(
        fetched.body.contains("OBS-DASHBOARD-NAME ops")
            && fetched.body.contains("OBS-DASHBOARD-CONTENT layout-v1"),
        "the pre-restart saved dashboard must survive rehydrate, got: {}",
        fetched.body
    );
}

/// A restarted node is already BOOTSTRAPPED (rehydrated) — just log the
/// first user back in, never re-run create-cell/create-user.
fn bootstrap_and_login_skip_if_bootstrapped(node: &Node) -> String {
    assert_eq!(
        node.get("/bootstrap/status").body.trim(),
        "BOOTSTRAPPED",
        "a restarted node with a rehydrated stream must report BOOTSTRAPPED"
    );
    let login = node.login(HANDLE, PASSWORD);
    assert_eq!(login.status, 200, "restarted-node login: {}", login.body);
    login.session_token.expect("session token")
}
