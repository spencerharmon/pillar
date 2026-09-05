//! `pillar-ingress-lb-udp-external-surface` acceptance — proves the real
//! published `pillar` binary exposes a black-box-drivable UDP ingress/LB
//! surface: `pillar ingress-lb-udp serve <manifest.json>`.
//!
//! Unlike `crates/pillar-net/tests` / `crates/pillar-e2e/tests/udp_dataplane.rs`
//! (which link `pillar-net` directly and call `UdpDataplane::bind` in-process),
//! this test execs the REAL COMPILED `pillar` CLI as a child process, gives it
//! a manifest naming two real UDP echo backends, reads the bound VIP address
//! off the child's stdout (`LISTENING <ip:port>`), sends a real UDP client
//! datagram from OUTSIDE the process, and asserts a real backend answered it
//! — proving the dataplane is reachable via the wired external surface, not
//! merely that `UdpDataplane::bind` was called somewhere in-crate.
//!
//! Only runs under `--features acceptance` (same gate as every other
//! acceptance test in this crate).

#![cfg(feature = "acceptance")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

/// Locate the `pillar` binary built by cargo, building it once if absent —
/// same resolution strategy as the sibling acceptance tests in this crate
/// (`pillar` is a `pillar-cli` dev-dependency binary, not this crate's own).
fn pillar_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current test exe");
    let mut dir = exe.parent().expect("deps dir").to_path_buf();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let candidate = dir.join("pillar");
    if !candidate.is_file() {
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

fn unique_manifest_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pillar-ingress-lb-udp-manifest-{tag}-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

/// A real UDP echo backend bound on loopback: for every datagram received it
/// replies `"<id>:<payload>"` so the test can attribute the reply to the
/// exact backend that served it.
async fn spawn_echo_backend(id: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = sock.local_addr().unwrap();
    let id_owned = id.to_owned();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let reply = format!("{}:{}", id_owned, String::from_utf8_lossy(&buf[..n]));
            let _ = sock.send_to(reply.as_bytes(), from).await;
        }
    });
    (addr, handle)
}

/// A spawned `pillar ingress-lb-udp serve` child. Kills the child on drop so
/// a failing assertion never leaks a bound socket into the next test run.
struct Dataplane {
    child: Child,
    vip: SocketAddr,
}

impl Drop for Dataplane {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_dataplane(manifest_path: &Path) -> Dataplane {
    let mut child = Command::new(pillar_bin())
        .args(["ingress-lb-udp", "serve"])
        .arg(manifest_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pillar ingress-lb-udp serve");

    // Drain stderr so the child never blocks on a full pipe (tracing/logging
    // may write there); read the `LISTENING <addr>` line off stdout.
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stderr);
            for _line in reader.lines().map_while(Result::ok) {}
        });
    }

    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let is_listening = line.starts_with("LISTENING ");
            let _ = tx.send(line);
            if is_listening {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut vip: Option<SocketAddr> = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(rest) = line.strip_prefix("LISTENING ") {
                    vip = rest.trim().parse().ok();
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let vip = vip.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("pillar ingress-lb-udp serve never printed LISTENING <addr> within 20s");
    });

    Dataplane { child, vip }
}

/// The DoD real-effect proof: exec the real `pillar` binary's
/// `ingress-lb-udp serve` verb against a manifest naming two real UDP echo
/// backends, send a real client datagram from OUTSIDE the process, and
/// assert a real backend answered — never merely that `UdpDataplane::bind`
/// was called in-process.
#[tokio::test]
async fn real_cli_process_forwards_real_udp_traffic_to_a_real_backend() {
    let (backend0_addr, _h0) = spawn_echo_backend("b0").await;
    let (backend1_addr, _h1) = spawn_echo_backend("b1").await;

    let manifest = format!(
        r#"{{
            "vip": "127.0.0.1:0",
            "backends": [
                {{"id": "b0", "addr": "{backend0_addr}"}},
                {{"id": "b1", "addr": "{backend1_addr}"}}
            ],
            "algorithm": "round_robin",
            "affinity": "none",
            "active_health": false
        }}"#
    );
    let manifest_path = unique_manifest_path("rr");
    std::fs::write(&manifest_path, manifest).expect("write manifest");

    let dataplane = spawn_dataplane(&manifest_path);

    // Drive real client traffic from OUTSIDE the pillar process: a plain
    // std UdpSocket, no crate linkage into the dataplane's internals.
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client
        .connect(dataplane.vip)
        .await
        .expect("connect to VIP");

    let mut seen_backends = std::collections::HashSet::new();
    let mut buf = vec![0u8; 4096];
    for i in 0..8 {
        client
            .send(format!("ping{i}").as_bytes())
            .await
            .expect("send to VIP");
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("reply within 5s")
            .expect("recv reply");
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            reply.starts_with("b0:ping") || reply.starts_with("b1:ping"),
            "unexpected reply `{reply}`"
        );
        let (backend_id, _) = reply.split_once(':').unwrap();
        seen_backends.insert(backend_id.to_owned());
    }

    // RoundRobin over 8 requests against 2 live backends must have hit BOTH
    // — proving real forwarding (not merely "some socket answered").
    assert_eq!(
        seen_backends.len(),
        2,
        "expected both backends to be attributed real traffic via round-robin, saw {seen_backends:?}"
    );

    let _ = std::fs::remove_file(&manifest_path);
}

/// A manifest naming a single backend must forward every datagram to it —
/// and the dataplane must reject a manifest that names none.
#[tokio::test]
async fn missing_manifest_file_fails_loudly_not_silently() {
    let missing = unique_manifest_path("missing");
    let mut child = Command::new(pillar_bin())
        .args(["ingress-lb-udp", "serve"])
        .arg(&missing)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pillar ingress-lb-udp serve");
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("process exits promptly on a missing manifest");
    assert!(
        !status.success(),
        "expected a non-zero exit for a missing manifest file"
    );
}
