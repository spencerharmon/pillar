//! Acceptance test — `pillar-node-workload-runtime-wiring`.
//!
//! Proves the real workload-runtime vertical is wired into the SHIPPED,
//! running `pillar node run` process and is drivable BLACK-BOX — over the real
//! external surface of the compiled `pillar` binary, with NO pillar crate
//! linkage driving the node.
//!
//! Every lower layer of this vertical (`workload-oci-runtime-real`,
//! `workload-deployment-kind`, `image_libp2p_fetch`) was, before this task,
//! reachable ONLY as an in-process Rust test that built its own
//! identity/capability/lease/view stack and called the library APIs directly.
//! This test instead:
//!
//! 1. Stands up a REAL libp2p blob provider (`pillar_net::build_blob_swarm` +
//!    `BlobStore`) serving the `udp_echo` binary's bytes by content address —
//!    the same "OCI image" the sibling acceptance tests spawn.
//! 2. Boots the REAL compiled `pillar` binary (`CARGO_BIN_EXE_pillar`) as a
//!    subprocess with a web surface bound and the integration-rig
//!    `PILLAR_TEST_WORKLOAD=<name>|<blob-image-ref>|<replicas>` hook set (the
//!    SAME `PILLAR_TEST_*` pattern `PILLAR_TEST_PUBLISH` established) — so the
//!    node itself runs its own reconcile loop: fetch-by-CID over live libp2p,
//!    digest-verified controller admission, topology-spread placement, and a
//!    real supervised-process spawn.
//! 3. Observes the effect purely over the node's external HTTP surface — the
//!    unauthenticated `/portal/resource/replicas` oracle — to learn each
//!    replica's REAL pid, REAL bound port, and content-addressed image digest,
//!    then round-trips a datagram over that real socket to prove it is a live
//!    listening process, not a modeled value.
//! 4. Kills the replica's real OS process and asserts the node's
//!    RestartPolicy::Always sweep brings it back on a FRESH pid — observed via
//!    the same oracle going down then back up.
//!
//! RED before this task's reconcile wiring existed (the binary had no
//! `PILLAR_TEST_WORKLOAD` hook, no reconciler, and no `/portal/resource/replicas`
//! oracle, so the node ran nothing and the oracle 404'd); GREEN after.
//!
//! `#[cfg(feature = "acceptance")]`-gated, run via
//! `cargo test -p pillar-e2e --test node_workload_runtime_wiring --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::Read;
use std::net::{TcpStream, UdpSocket as StdUdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_net::{build_blob_swarm, BlobBehaviourEvent, BlobDigest, BlobStore};

/// The `blob:<provider-multiaddr>|<digest-hex>` image reference the node's
/// reconcile loop fetches by CID. Kept as a local literal builder so this
/// black-box test needs no pillar-cli linkage to construct the reference the
/// node parses (`pillar_cli::workload_reconcile::ImageRef`).
fn blob_image_ref(provider: &Multiaddr, digest: &BlobDigest) -> String {
    let mut hex = String::new();
    for b in digest.as_bytes() {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("blob:{provider}|{hex}")
}

/// Claim a free localhost TCP port for the node's web surface.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

/// Bind an ephemeral UDP port only to discover a free number for a NON-purpose
/// (unused here) — kept minimal.
#[allow(dead_code)]
fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .expect("free udp port")
}

/// Listen on TCP/0 and return the first concrete listen multiaddr the swarm
/// binds — the dialable provider address.
async fn listen_and_get_addr<B>(swarm: &mut libp2p::Swarm<B>) -> Multiaddr
where
    B: libp2p::swarm::NetworkBehaviour,
{
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen on loopback tcp");
    timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("provider bound a listen addr")
}

/// A running libp2p blob provider serving `bytes` by content address; returns
/// its dialable `/p2p/`-terminated multiaddr and the digest the bytes were
/// published under. A background task answers every inbound blob request.
async fn spawn_provider(bytes: Vec<u8>) -> (Multiaddr, BlobDigest) {
    let mut provider = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
    let provider_peer_id = *provider.local_peer_id();
    let mut store = BlobStore::new();
    let digest = store.insert(bytes);
    let addr = listen_and_get_addr(&mut provider).await;
    let dialable = addr.with(libp2p::multiaddr::Protocol::P2p(provider_peer_id));

    tokio::spawn(async move {
        loop {
            let event = provider.select_next_some().await;
            if let SwarmEvent::Behaviour(BlobBehaviourEvent::Blob(
                request_response::Event::Message {
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) = event
            {
                let response = store.answer(&request);
                let _ = provider
                    .behaviour_mut()
                    .blob
                    .send_response(channel, response);
            }
        }
    });

    (dialable, digest)
}

/// A booted `pillar node run` subprocess; killed on drop.
struct Node {
    child: Child,
    web_port: u16,
    _data_dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Locate the compiled `pillar` binary. Cargo only exports
/// `CARGO_BIN_EXE_<name>` for binaries of the SAME package, so we derive the
/// path from a bin that IS ours (`udp_echo`): both compile into the same
/// target profile directory, so the `pillar` binary sits next to it. Building
/// it is ensured by the test harness (the workspace builds all bins), but we
/// assert its presence with a clear message if absent.
fn pillar_binary() -> std::path::PathBuf {
    let udp_echo = std::path::PathBuf::from(env!("CARGO_BIN_EXE_udp_echo"));
    let dir = udp_echo
        .parent()
        .expect("udp_echo lives in a target dir")
        .to_path_buf();
    let candidate = dir.join(if cfg!(windows) {
        "pillar.exe"
    } else {
        "pillar"
    });
    assert!(
        candidate.exists(),
        "the compiled `pillar` binary must exist at {} — run `cargo build -p pillar-cli` first (the acceptance check builds the workspace)",
        candidate.display()
    );
    candidate
}

/// Boot the real compiled `pillar` binary with a web surface and the
/// `PILLAR_TEST_WORKLOAD` reconcile hook.
fn boot_pillar_node(image_ref: &str, workload: &str, replicas: usize) -> Node {
    let bin = pillar_binary();
    let data_dir = tempfile::tempdir().expect("data dir");
    let web_port = free_tcp_port();
    let child = Command::new(bin)
        .arg("node")
        .arg("run")
        .env("PILLAR_DATA_DIR", data_dir.path())
        .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
        .env("PILLAR_WEB_BIND", "127.0.0.1")
        .env("PILLAR_WEB_PORT", web_port.to_string())
        .env(
            "PILLAR_TEST_WORKLOAD",
            format!("{workload}::{replicas}::{image_ref}"),
        )
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn pillar node run");
    Node {
        child,
        web_port,
        _data_dir: data_dir,
    }
}

/// Raw HTTP GET against the node's web surface, returning `(status, body)`.
fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    use std::io::Write;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())?;
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    Some((status, body))
}

/// One parsed `REPLICA <workload> <node> pid=<p> port=<p> digest=<hex>` line.
#[derive(Debug, Clone)]
struct Replica {
    pid: u32,
    port: u16,
    digest: String,
}

/// Poll the `/portal/resource/replicas` oracle until at least `want` replicas
/// with a live (>0) pid are reported, or the deadline passes.
fn await_replicas(port: u16, want: usize, within: Duration) -> Vec<Replica> {
    let deadline = Instant::now() + within;
    loop {
        if let Some((200, body)) = http_get(port, "/portal/resource/replicas") {
            let replicas = parse_replicas(&body);
            let live: Vec<Replica> = replicas.into_iter().filter(|r| r.pid > 0).collect();
            if live.len() >= want {
                return live;
            }
        }
        if Instant::now() >= deadline {
            let last = http_get(port, "/portal/resource/replicas");
            panic!("workload replicas did not come up within {within:?}; last oracle = {last:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn parse_replicas(body: &str) -> Vec<Replica> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("REPLICA ")?;
            let mut pid = None;
            let mut port = None;
            let mut digest = None;
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix("pid=") {
                    pid = v.parse().ok();
                } else if let Some(v) = tok.strip_prefix("port=") {
                    port = v.parse().ok();
                } else if let Some(v) = tok.strip_prefix("digest=") {
                    digest = Some(v.to_owned());
                }
            }
            Some(Replica {
                pid: pid?,
                port: port?,
                digest: digest?,
            })
        })
        .collect()
}

/// Round-trip a datagram over a replica's real listening UDP socket, retrying
/// to absorb the freshly-spawned child's bind latency.
async fn probe_echo(port: u16, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(("127.0.0.1", port)).await?;
        client.send(msg).await?;
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_millis(300), client.recv(&mut buf)).await {
            Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
            _ if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no echo reply within deadline",
                ))
            }
        }
    }
}

/// The whole black-box vertical: the real `pillar` binary, driven only over its
/// external surface, fetches a CID image over real libp2p and runs it as a real
/// supervised process reachable over a real socket, and restarts it on death.
#[tokio::test]
async fn real_node_reconciles_a_workload_into_real_supervised_replicas() {
    // 1. Publish the udp_echo "image" over a real libp2p blob provider.
    let image_bytes = std::fs::read(env!("CARGO_BIN_EXE_udp_echo")).expect("read udp_echo image");
    let expected_digest = BlobDigest::of(&image_bytes);
    let (provider_addr, digest) = spawn_provider(image_bytes).await;
    assert_eq!(
        digest, expected_digest,
        "provider published the exact bytes"
    );
    let image_ref = blob_image_ref(&provider_addr, &digest);

    // 2. Boot the REAL pillar binary with the reconcile hook. Run the blocking
    //    subprocess/oracle/probe interaction off the async reactor thread. The
    //    booted node is kept alive for the whole interaction and torn down at
    //    the end of the blocking task (its `Drop` kills the subprocess).
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let node = boot_pillar_node(&image_ref, "web", 1);
        let web_port = node.web_port;

        // 3. Observe the real replica come up purely over the external oracle.
        let replicas = await_replicas(web_port, 1, Duration::from_secs(40));
        let replica = replicas[0].clone();
        assert!(replica.pid > 0, "replica has a real os pid");

        // The oracle reports the content-addressed image digest the node
        // admitted the replica under.
        let mut want_hex = String::new();
        for b in digest.as_bytes() {
            want_hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            replica.digest, want_hex,
            "oracle reports the real image CID"
        );

        // Prove the replica is a REAL live listening socket over the wire.
        let reply = handle
            .block_on(probe_echo(replica.port, b"hello-black-box"))
            .expect("echo over the replica's real socket");
        assert_eq!(reply, b"hello-black-box");

        // 4. Kill the replica's REAL process; the node's RestartPolicy::Always
        //    sweep must bring it back on a FRESH pid, observed via the oracle.
        let killed_pid = replica.pid;
        let status = Command::new("kill")
            .arg("-9")
            .arg(killed_pid.to_string())
            .status()
            .expect("kill the replica process");
        assert!(status.success(), "SIGKILL delivered to the replica");

        // Poll until the oracle reports a replica on a DIFFERENT pid.
        let deadline = Instant::now() + Duration::from_secs(20);
        let restarted = loop {
            let live = await_replicas(web_port, 1, Duration::from_secs(20));
            if let Some(r) = live.iter().find(|r| r.pid != killed_pid && r.pid > 0) {
                break r.clone();
            }
            if Instant::now() >= deadline {
                panic!("replica was not restarted on a fresh pid within deadline");
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        assert_ne!(
            restarted.pid, killed_pid,
            "restarted replica runs as a fresh real process"
        );

        // The restarted replica answers again over a real socket, and the
        // oracle still reports the same content-addressed image digest.
        let reply_again = handle
            .block_on(probe_echo(restarted.port, b"hello-again"))
            .expect("echo over the restarted replica's real socket");
        assert_eq!(reply_again, b"hello-again");
        assert_eq!(
            restarted.digest, want_hex,
            "restarted replica keeps the same content-addressed image"
        );

        // node dropped here → subprocess killed.
    })
    .await
    .expect("node interaction task");
}
