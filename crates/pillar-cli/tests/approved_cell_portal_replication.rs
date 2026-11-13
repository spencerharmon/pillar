//! Acceptance — `approved-cell-live-portal-replication`.
//!
//! Real multi-process flow over the real `pillar` binary, a test-owned
//! PRIVATE swarm key and test-owned user credentials:
//!
//! 1. bootstrap ONLY node1 (`pillar bootstrap cell`);
//! 2. node2 joins the swarm and submits a signed node request
//!    (`pillar bootstrap node`) — while pending it receives no cell journal,
//!    cannot log in, and `bootstrap node complete` is `DENIED pending`;
//! 3. approve through the existing flow (`pillar bootstrap request approve`),
//!    complete, and authenticate to node2's OWN portal (`GET /nonce`,
//!    `POST /login`) with node2's distinct identity;
//! 4. mutate data on node1 AFTER enrollment (`POST /portal/obs/dashboard`)
//!    and observe the exact data on the still-running node2
//!    (`GET /portal/obs/dashboard/get`) — live op-sync + incremental portal
//!    materialization, no restart;
//! 5. an unapproved peer on the SAME swarm (an in-test libp2p node built with
//!    the shipped `pillar_net::build_event_swarm_with_root`) gets no portal
//!    journal over op-sync and cannot inject portal ops by gossip or op-sync;
//! 6. stop node1, restart node2 in isolation, log in and read the same data.
//!
//! Run: `cargo test -p pillar-cli --test approved_cell_portal_replication --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PASSWORD: &str = "approved cell replication test unlock factor";
const HANDLE: &str = "alice";
const PORTAL_OP_TAG: &[u8] = b"PORTALOPv1\n";

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pillar"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "error")
        .current_dir(home)
        .stdin(Stdio::null());
    command
}

fn run(command: &mut Command) -> (bool, String) {
    let output = command.output().expect("execute pillar");
    (
        output.status.success(),
        format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn success(command: &mut Command) -> String {
    let (ok, text) = run(command);
    assert!(ok, "pillar failed: {text}");
    text
}

struct Response {
    status: u16,
    session: Option<String>,
    body: String,
}

fn http(port: u16, method: &str, path: &str, body: &str) -> std::io::Result<Response> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = headers
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let session = headers
        .lines()
        .find_map(|l| l.strip_prefix("X-Pillar-Session: "))
        .map(|v| v.trim().to_owned());
    Ok(Response {
        status,
        session,
        body: body.to_owned(),
    })
}

fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    dir: tempfile::TempDir,
    child: Option<Child>,
    http_port: u16,
    p2p_port: u16,
    resource_port: u16,
    swarm_key: PathBuf,
    dial: Option<String>,
    log: PathBuf,
}

impl Node {
    fn new(swarm_key: &Path, dial: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("node.log");
        Self {
            child: None,
            http_port: free_tcp(),
            p2p_port: free_tcp(),
            resource_port: UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port(),
            swarm_key: swarm_key.to_owned(),
            dial,
            log,
            dir,
        }
    }

    fn p2p_addr(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}", self.p2p_port)
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.http_port)
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let resource = format!("127.0.0.1:{}", self.resource_port);
        let mut command = cli(self.dir.path());
        command
            .args(["node", "run"])
            .env("RUST_LOG", "warn,pillar_cli=info")
            .env("PILLAR_DATA_DIR", self.dir.path())
            .env("PILLAR_LISTEN", self.p2p_addr())
            .env("PILLAR_SWARM_KEY", &self.swarm_key)
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", self.http_port.to_string())
            .env("PILLAR_HEALTH_BIND", "127.0.0.1")
            .env("PILLAR_HEALTH_PORT", "0")
            .env("PILLAR_DISABLE_METRICS", "1")
            .env("PILLAR_RESOURCE_OP_UDP_BIND", &resource)
            .env("PILLAR_PUBLIC_RESOURCE_OP_ADDR", &resource)
            .stdout(Stdio::null())
            .stderr(log);
        if let Some(dial) = &self.dial {
            command.env("PILLAR_DIAL", dial);
        }
        self.child = Some(command.spawn().expect("spawn pillar node run"));
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "node exited before readiness: {}",
                self.log_text()
            );
            if http(self.http_port, "GET", "/bootstrap/status", "").is_ok_and(|r| r.status == 200) {
                return;
            }
            assert!(Instant::now() < deadline, "node readiness timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn status(&self) -> String {
        http(self.http_port, "GET", "/bootstrap/status", "")
            .unwrap()
            .body
            .trim()
            .to_owned()
    }

    /// Real node-side custody login on THIS node's portal.
    fn portal_login(&self) -> Result<String, String> {
        let nonce = http(self.http_port, "GET", "/nonce", "").map_err(|e| e.to_string())?;
        let Some(id) = nonce
            .body
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
        else {
            return Err(format!("nonce {}: {}", nonce.status, nonce.body));
        };
        let login = http(
            self.http_port,
            "POST",
            "/login",
            &format!("{HANDLE}\n{PASSWORD}\n{id}"),
        )
        .map_err(|e| e.to_string())?;
        match (login.status, login.session) {
            (200, Some(token)) => Ok(token),
            (status, _) => Err(format!("login {status}: {}", login.body)),
        }
    }

    fn dashboard(&self, token: &str, id: &str) -> Response {
        http(
            self.http_port,
            "GET",
            &format!("/portal/obs/dashboard/get?token={token}&id={id}"),
            "",
        )
        .unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What the unapproved same-swarm peer observed / attempted.
#[derive(Default)]
struct Rogue {
    stop: AtomicBool,
    responses: AtomicUsize,
    leaked_portal_ops: AtomicUsize,
    forged_answers: AtomicUsize,
    forged_gossip: AtomicUsize,
}

fn forged_portal_op() -> Vec<u8> {
    let mut op = PORTAL_OP_TAG.to_vec();
    op.extend_from_slice(&(1u64 << 40).to_be_bytes());
    op.extend_from_slice(
        br#"{"SaveObservabilityDashboard":{"signer":"mallory","name":"forged","spec":"injected"}}"#,
    );
    op
}

fn forged_dashboard_id() -> String {
    pillar_streamdb::OpId(pillar_streamdb::content_address(
        b"probe\nmallory\nforged\ninjected",
    ))
    .to_hex()
}

/// An UNAPPROVED peer holding the swarm key: requests node1's journal over
/// op-sync, answers node1's requests with a forged portal op, and gossips it.
fn spawn_rogue(
    root_secret: String,
    dial: String,
    rogue: Arc<Rogue>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use futures::StreamExt;
        use libp2p::request_response::{Event, Message};
        use libp2p::swarm::SwarmEvent;
        use pillar_net::EventBehaviourEvent;

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let mut swarm = pillar_net::build_event_swarm_with_root(
                libp2p::identity::Keypair::generate_ed25519(),
                pillar_net::PrivateSwarmKey::from_root_secret(&root_secret),
                false,
                false,
            )
            .unwrap();
            let topic = pillar_net::event_log_topic();
            swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
            swarm.dial(dial.parse::<libp2p::Multiaddr>().unwrap()).unwrap();
            let mut tick = tokio::time::interval(Duration::from_millis(1000));
            while !rogue.stop.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = tick.tick() => {
                        let peers: Vec<_> = swarm.connected_peers().copied().collect();
                        for peer in peers {
                            swarm.behaviour_mut().op_sync.send_request(
                                &peer,
                                pillar_net::OpSyncRequest { have: Vec::new() },
                            );
                        }
                        if swarm.behaviour_mut().gossipsub.publish(topic.clone(), forged_portal_op()).is_ok() {
                            rogue.forged_gossip.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(EventBehaviourEvent::OpSync(Event::Message { message, .. })) = event {
                            match message {
                                Message::Request { channel, .. } => {
                                    let forged = pillar_net::OpSyncResponse { ops: vec![forged_portal_op()] };
                                    if swarm.behaviour_mut().op_sync.send_response(channel, forged).is_ok() {
                                        rogue.forged_answers.fetch_add(1, Ordering::SeqCst);
                                    }
                                }
                                Message::Response { response, .. } => {
                                    rogue.responses.fetch_add(1, Ordering::SeqCst);
                                    let leaked = response.ops.iter().filter(|op| op.starts_with(PORTAL_OP_TAG)).count();
                                    rogue.leaked_portal_ops.fetch_add(leaked, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
            }
        });
    })
}

fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn assert_dashboard(node: &Node, token: &str, id: &str) {
    let got = node.dashboard(token, id);
    assert_eq!(got.status, 200, "dashboard get: {}", got.body);
    assert!(
        got.body.contains("OBS-DASHBOARD-NAME replicated")
            && got
                .body
                .contains("OBS-DASHBOARD-CONTENT written-on-node1-after-enrollment"),
        "exact replicated dashboard expected, got: {}",
        got.body
    );
}

fn assert_no_forgery(node: &Node, token: &str) {
    let got = node.dashboard(token, &forged_dashboard_id());
    assert!(
        !got.body.contains("OBS-DASHBOARD-CONTENT injected"),
        "unapproved peer injected a portal mutation: {}",
        got.body
    );
}

#[test]
fn approved_node_joins_live_replication_and_survives_isolated_restart() {
    let keys = tempfile::tempdir().unwrap();
    let swarm_key_path = keys.path().join("swarm.key");
    let root_secret = pillar_swarm::SwarmKey::generate().root_secret().to_owned();
    std::fs::write(&swarm_key_path, format!("{root_secret}\n")).unwrap();

    // 1. Only node1 is bootstrapped.
    let mut node1 = Node::new(&swarm_key_path, None);
    node1.start();
    success(cli(node1.dir.path()).args([
        "bootstrap",
        "cell",
        "replication-cell",
        "--user",
        HANDLE,
        "--password",
        PASSWORD,
        "--domain",
        &node1.authority(),
    ]));
    let cli_token = success(cli(node1.dir.path()).args([
        "login",
        "--domain",
        &node1.authority(),
        "--user",
        HANDLE,
        "--password",
        PASSWORD,
    ]))
    .lines()
    .find_map(|l| l.strip_prefix("export PILLAR_TOKEN="))
    .expect("login token")
    .to_owned();

    // The unapproved same-swarm peer.
    let rogue = Arc::new(Rogue::default());
    let rogue_thread = spawn_rogue(root_secret.clone(), node1.p2p_addr(), Arc::clone(&rogue));

    // 2. node2 shares the swarm while pending: no journal, no login.
    let mut node2 = Node::new(&swarm_key_path, Some(node1.p2p_addr()));
    node2.start();
    let submitted = success(
        cli(node2.dir.path())
            .args([
                "bootstrap",
                "node",
                "--domain",
                &node1.authority(),
                "--data-dir",
            ])
            .arg(node2.dir.path()),
    );
    let id = submitted
        .lines()
        .find_map(|l| l.strip_prefix("REQUEST "))
        .expect("REQUEST <id>")
        .trim()
        .to_owned();
    wait_until(
        "pending node2 to attempt op-sync",
        Duration::from_secs(30),
        || {
            node1
                .log_text()
                .contains("withheld cell journal from non-member peer")
                && rogue.responses.load(Ordering::SeqCst) >= 2
        },
    );
    std::thread::sleep(Duration::from_secs(7));
    assert_eq!(
        node2.status(),
        "FRESH",
        "pending node2 materialized cell data"
    );
    assert!(
        node2.portal_login().is_err(),
        "pending node2 admitted a login"
    );
    node2.stop();
    // Pending retrieval is refused (real subject proof, wrong state) ...
    let (ok, text) = run(cli(node2.dir.path())
        .args([
            "bootstrap",
            "node",
            "complete",
            &id,
            "--domain",
            &node1.authority(),
            "--data-dir",
        ])
        .arg(node2.dir.path()));
    assert!(!ok && text.contains("DENIED pending"), "{text}");
    // ... as is a forged retrieval proof and an unauthenticated approval.
    let forged = http(
        node1.http_port,
        "POST",
        "/bootstrap/request/retrieve",
        &format!(r#"{{"id":{id},"public_key":[1,2,3],"signature":[4,5,6]}}"#),
    )
    .unwrap();
    assert_eq!(forged.status, 401, "{}", forged.body);
    let (ok, text) = run(cli(node2.dir.path()).env("PILLAR_TOKEN", "invalid").args([
        "bootstrap",
        "request",
        "approve",
        &id,
        "--domain",
        &node1.authority(),
    ]));
    assert!(!ok && text.contains("401"), "{text}");
    assert!(!node2.dir.path().join("enrollment.sealed").exists());

    // 3. Approve via the existing request flow; complete; node2's own login.
    let approved = success(cli(node1.dir.path()).env("PILLAR_TOKEN", &cli_token).args([
        "bootstrap",
        "request",
        "approve",
        &id,
        "--domain",
        &node1.authority(),
    ]));
    assert!(approved.contains(&format!("APPROVED {id}")), "{approved}");
    success(
        cli(node2.dir.path())
            .args([
                "bootstrap",
                "node",
                "complete",
                &id,
                "--domain",
                &node1.authority(),
                "--data-dir",
            ])
            .arg(node2.dir.path()),
    );
    assert_ne!(
        std::fs::read(node1.dir.path().join("identity.key")).unwrap(),
        std::fs::read(node2.dir.path().join("identity.key")).unwrap(),
        "nodes must keep distinct identities"
    );
    node2.start();
    assert_eq!(node2.status(), "BOOTSTRAPPED");
    let token2 = node2.portal_login().expect("approved node2 portal login");

    // 4. Mutate on node1 AFTER enrollment; observe on the running node2.
    let token1 = node1.portal_login().expect("node1 portal login");
    let saved = http(
        node1.http_port,
        "POST",
        "/portal/obs/dashboard",
        &format!("{token1}\nreplicated: written-on-node1-after-enrollment"),
    )
    .unwrap();
    assert_eq!(saved.status, 200, "save: {}", saved.body);
    let dashboard_id = saved.body.split_whitespace().nth(1).unwrap().to_owned();
    assert_ne!(node2.dashboard(&token2, &dashboard_id).status, 0);
    wait_until("live replication to node2", Duration::from_secs(45), || {
        node2.dashboard(&token2, &dashboard_id).status == 200
    });
    assert_dashboard(&node2, &token2, &dashboard_id);

    // 5. The unapproved peer got no journal and injected nothing.
    wait_until("rogue forgery attempts", Duration::from_secs(30), || {
        rogue.forged_answers.load(Ordering::SeqCst) >= 1
            && rogue.forged_gossip.load(Ordering::SeqCst) >= 1
            && node1
                .log_text()
                .contains("refused portal ops from non-member peer")
            && node1
                .log_text()
                .contains("refused portal op over transport gossip")
    });
    std::thread::sleep(Duration::from_secs(7));
    assert!(rogue.responses.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        rogue.leaked_portal_ops.load(Ordering::SeqCst),
        0,
        "unapproved peer obtained confidential journal ops"
    );
    assert_no_forgery(&node1, &token1);
    assert_no_forgery(&node2, &token2);
    rogue.stop.store(true, Ordering::SeqCst);
    rogue_thread.join().unwrap();

    // 6. Isolate node2 and restart it; node1 is unavailable.
    node1.stop();
    node2.stop();
    node2.start();
    assert_eq!(node2.status(), "BOOTSTRAPPED");
    let token2 = node2
        .portal_login()
        .expect("isolated restarted node2 login");
    assert_dashboard(&node2, &token2, &dashboard_id);
    assert_no_forgery(&node2, &token2);
}
