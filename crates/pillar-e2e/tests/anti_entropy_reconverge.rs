#![cfg(feature = "acceptance")]
//! Acceptance: a partitioned/late `pillar node run` peer RECONVERGES to the
//! full durable op set via anti-entropy catch-up sync.
//!
//! This is the black-box proof for `anti-entropy-sync-wire-node-run`: the
//! existing anti-entropy protocol is wired into the runtime peer's controller
//! loop so a node that missed an op while it was NOT connected (gossipsub only
//! ever delivers to peers subscribed AT PUBLISH TIME and never re-delivers)
//! catches up after it joins — its durable `streamdb/ops/` ends holding the
//! missed op's content-addressed CID, the IDENTICAL CID the publisher stored.
//!
//! Topology of the test:
//!   1. Start node A alone and have it publish one op (`PILLAR_TEST_PUBLISH`)
//!      while it has NO peers. A stores the op durably; no other node hears it
//!      over gossip (there is nobody subscribed).
//!   2. Assert A's `streamdb/ops/<CID>` exists — the op is real and durable.
//!   3. Start node B pointed at A (`--dial`). B connects only AFTER the publish,
//!      so gossipsub will NEVER deliver the op to it — its ONLY path to the op
//!      is anti-entropy catch-up sync.
//!   4. Poll B's data-dir: with the wiring, B's `streamdb/ops/<CID>` appears
//!      (identical CID) and B has reconverged. WITHOUT the wiring (the state
//!      before this task) B never gets the op and the test FAILS on timeout.
//!
//! Real processes, real libp2p, real on-disk stores — no in-memory stand-in.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Grab a currently-free localhost TCP port by binding to :0 and releasing it.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn unique_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pillar-anti-entropy-reconverge-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The content-addressed filename (lowercase hex) a raw op payload is stored
/// under in `streamdb/ops/` — exactly what `pillar node run` persists a gossiped
/// or synced op as.
fn op_cid_hex(payload: &[u8]) -> String {
    pillar_streamdb::OpId(pillar_streamdb::content_address(payload)).to_hex()
}

/// Locate the `pillar` binary built by cargo. `CARGO_BIN_EXE_pillar` is only
/// exported when the bin lives in the SAME package as the test; here `pillar`
/// comes from the `pillar-cli` dev-dependency, so we resolve it from the target
/// directory that also holds this test executable (`.../target/<profile>/deps/`
/// → `.../target/<profile>/pillar`).
fn pillar_bin() -> PathBuf {
    // The test exe is at target/<profile>/deps/<name>-<hash>. Walk up to the
    // profile dir and look for `pillar` there.
    let exe = std::env::current_exe().expect("current test exe");
    let mut dir = exe.parent().expect("deps dir").to_path_buf();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let candidate = dir.join("pillar");
    if !candidate.is_file() {
        // Not present yet: `cargo test` does not auto-build a dev-dependency's
        // binary, so build it once into the same profile dir. Deterministic and
        // idempotent (a no-op once built).
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-p", "pillar-cli", "--bin", "pillar"])
            .status()
            .expect("build pillar bin");
        assert!(status.success(), "cargo build -p pillar-cli failed");
    }
    assert!(
        candidate.is_file(),
        "pillar binary not found at {} after build",
        candidate.display()
    );
    candidate
}

/// A spawned `pillar node run` child, capturing its stdout so we can read its
/// real listen multiaddr and peer id, and killing it on drop.
struct Node {
    child: Child,
    data_dir: PathBuf,
    /// A receiver of stdout lines, drained by a reader thread.
    lines: mpsc::Receiver<String>,
}

impl Node {
    fn spawn(tag: &str, listen_port: u16, dial: Option<&str>, publish: Option<&str>) -> Node {
        let data_dir = unique_dir(tag);
        let listen = format!("/ip4/127.0.0.1/tcp/{listen_port}");
        let mut cmd = Command::new(pillar_bin());
        cmd.args(["node", "run", "--data-dir"])
            .arg(&data_dir)
            .args(["--listen", &listen]);
        if let Some(dial) = dial {
            cmd.args(["--dial", dial]);
        }
        // Disable the web/health surfaces' noise is fine; keep defaults.
        cmd.env("RUST_LOG", "info");
        if let Some(v) = publish {
            cmd.env("PILLAR_TEST_PUBLISH", v);
        } else {
            cmd.env_remove("PILLAR_TEST_PUBLISH");
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn pillar node run");

        // tracing/tracing-subscriber writes its logs to STDERR by default, so
        // the log lines we key on ("identity loaded", "listening", "connection
        // established") arrive there; capture stderr into the channel and just
        // drain stdout so the child never blocks on a full pipe.
        let stderr = child.stderr.take().expect("child stderr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for _ in reader.lines().map_while(Result::ok) {}
            });
        }
        Node {
            child,
            data_dir,
            lines: rx,
        }
    }

    /// Block until the node logs a line matching `needle`, returning it, or
    /// panic after `timeout`.
    fn wait_for_line(&self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                panic!("timed out waiting for log line containing {needle:?}");
            }
            match self.lines.recv_timeout(remaining) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(_) => panic!("stdout closed before log line containing {needle:?}"),
            }
        }
    }

    fn ops_dir(&self) -> PathBuf {
        self.data_dir.join("streamdb").join("ops")
    }

    fn holds_op(&self, cid_hex: &str) -> bool {
        self.ops_dir().join(cid_hex).is_file()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Extract the `/ip4/…/tcp/…/p2p/<peer-id>` dial multiaddr from a node's log
/// stream: it logs its peer id ("identity loaded") and a listen address
/// ("pillar peer listening"). We compose them into a dial target for the peer.
fn dial_addr(node: &Node, listen_port: u16) -> String {
    // The identity line carries `peer_id=<id>`.
    let id_line = node.wait_for_line("pillar peer identity loaded", Duration::from_secs(30));
    let peer_id = id_line
        .split("peer_id=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("peer_id in identity log line")
        .to_string();
    // Wait until it is actually listening before anyone dials it.
    node.wait_for_line("pillar peer listening", Duration::from_secs(30));
    format!("/ip4/127.0.0.1/tcp/{listen_port}/p2p/{peer_id}")
}

fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    cond()
}

fn dir_holds(ops_dir: &Path, cid_hex: &str) -> bool {
    ops_dir.join(cid_hex).is_file()
}

#[test]
fn partitioned_late_node_reconverges_via_anti_entropy() {
    let payload = "anti-entropy-reconverge-op";
    let cid = op_cid_hex(payload.as_bytes());

    // --- 1. Node A alone: publishes one op with no peers listening. ---
    let a_port = free_tcp_port();
    let node_a = Node::spawn("a", a_port, None, Some(payload));
    let a_dial = dial_addr(&node_a, a_port);

    // A publishes after its 8s settle delay and folds its own publish into its
    // durable store. Wait for the op to be durably present at A.
    let a_has = wait_until(|| node_a.holds_op(&cid), Duration::from_secs(40));
    assert!(
        a_has,
        "publisher A must durably hold the published op {cid} under {}",
        node_a.ops_dir().display()
    );

    // --- 2. Node B joins AFTER the publish: gossip will never deliver the op
    //        to it, so its only path is anti-entropy catch-up sync. ---
    let b_port = free_tcp_port();
    let node_b = Node::spawn("b", b_port, Some(&a_dial), None);
    // Confirm B actually connected to A.
    node_b.wait_for_line("pillar peer connection established", Duration::from_secs(30));

    // Sanity: B does not have the op immediately on connect (it missed the
    // gossip; only anti-entropy can fill it).
    assert!(
        !node_b.holds_op(&cid),
        "B should not have the missed op merely from connecting (gossip does not re-deliver)"
    );

    // --- 3. With the wiring, B's periodic anti-entropy round pulls the op from
    //        A and persists it under the IDENTICAL CID. Without the wiring this
    //        never happens and the assert times out (the regression). ---
    let b_ops = node_b.ops_dir();
    let reconverged = wait_until(|| dir_holds(&b_ops, &cid), Duration::from_secs(40));
    assert!(
        reconverged,
        "partitioned/late node B must reconverge via anti-entropy: expected op {cid} under {}",
        b_ops.display()
    );

    // Reconvergence to ONE consistent state: A and B now hold the identical CID.
    assert!(node_a.holds_op(&cid) && node_b.holds_op(&cid));
}
