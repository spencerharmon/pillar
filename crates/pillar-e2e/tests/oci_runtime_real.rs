//! Acceptance test — `workload-oci-runtime-real`.
//!
//! Proves the EXECUTE half of the workload vertical (the fetch half is
//! covered by `image_libp2p_fetch.rs`): a digest-verified image, run through
//! `pillar_controller::RunningWorkload::spawn_process`, becomes a REAL
//! supervised OS process — a real pid (via `tokio::process`) bound to a real
//! listening UDP socket — not a modeled `Running` state value. The image
//! under test is a trivial standalone UDP echo binary
//! (`crates/pillar-e2e/src/bin/udp_echo.rs`), built by cargo like any other
//! binary target and read off disk as this test's "OCI image bytes".
//!
//! `#[cfg(feature = "acceptance")]`-gated: only exercised via
//! `cargo test -p pillar-e2e --test oci_runtime_real --features acceptance`
//! (the `acceptance-e2e` CHECKS.md stub), never a plain `cargo test`.

#![cfg(feature = "acceptance")]

use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_controller::{Controller, RunningWorkload, WorkloadSpec, RUN_WORKLOAD_CAPABILITY};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry};
use pillar_net::BlobDigest;
use pillar_streamdb::Stream;

/// Claim a free localhost UDP port by binding then immediately dropping the
/// socket — the child process we spawn next binds it for real.
fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    socket.local_addr().expect("local addr").port()
}

/// Build an admitted-and-verified `RunningWorkload` for the `udp_echo`
/// binary's real bytes, through the full identity/capability/lease/view gate
/// stack and the digest-verification gate — exactly the same authorization
/// path `image_libp2p_fetch.rs` proves, so this test starts from a REAL
/// reconciled workload, not a shortcut around admission.
fn admitted_running_workload(image_bytes: Vec<u8>) -> RunningWorkload {
    let digest = BlobDigest::of(&image_bytes);

    let mut identity = Registry::new();
    let primary = PrimaryKeypair::from_secret_seed(&pillar_crypto::Seed::from_bytes(
        b"pillar-e2e-oci-runtime-operator-primary".to_vec(),
    ));
    let controller_key = NodeSubkey::from("e2e-oci-runtime-controller");
    identity.register(primary.primary());
    assert!(identity.issue_subkey(primary.certify(&controller_key)));
    identity.handshake(&controller_key).unwrap();

    let mut caps = CapabilityRegistry::new();
    caps.grant(
        controller_key.clone(),
        Capability::from(RUN_WORKLOAD_CAPABILITY),
    );
    let controller = Controller::new(controller_key);

    let epoch = Epoch(1);
    let mut lease = LeaseRegister::new(3);
    lease
        .grant(NodeId::from("voter-1"), controller.node(), epoch)
        .unwrap();
    lease
        .grant(NodeId::from("voter-2"), controller.node(), epoch)
        .unwrap();
    assert!(lease.try_acquire(&controller.node(), epoch));

    let spec = WorkloadSpec::new(
        "e2e-oci-runtime-workload",
        controller.node(),
        digest,
        SideEffect::Exclusive,
    );
    let mut stream = Stream::new();
    stream
        .try_append(spec.encode(), spec.effect())
        .expect("strict stream admits the exclusive declaration");
    let view = stream.view();

    let admitted = controller
        .authorize_fetch(&identity, &caps, &lease, epoch, &view, &spec)
        .expect("every safety layer admits the workload");

    admitted
        .run(image_bytes)
        .expect("image bytes verify against the authorized digest")
}

/// Send `msg` to `port` and await the echoed reply, proving a REAL listening
/// UDP socket is live and answering — not merely that a pid exists. Retries
/// briefly to absorb the real process's scheduling/bind latency (the child
/// has genuinely just been spawned by the kernel; this is not a modeled
/// instant transition).
async fn probe_echo(port: u16, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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

/// Confirm nothing answers on `port` within a short window — the socket is
/// truly closed, not merely slow to reply. A connected UDP socket surfaces
/// "nobody is listening" either as a timeout (no ICMP came back) or as an
/// immediate `ConnectionRefused`/`ConnectionReset` (the kernel delivered the
/// port-unreachable ICMP) — both count as "no listener".
async fn assert_no_listener(port: u16) {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client
        .connect(("127.0.0.1", port))
        .await
        .expect("connect");
    client.send(b"ping").await.expect("send");
    let mut buf = [0u8; 1024];
    match timeout(Duration::from_millis(500), client.recv(&mut buf)).await {
        Err(_) => {} // timed out waiting for a reply: no listener.
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
            ) => {} // kernel confirmed nobody is bound to the port.
        Ok(Ok(n)) => panic!(
            "expected no reply after stop, but the port answered with {n} bytes"
        ),
        Ok(Err(e)) => panic!("unexpected error probing stopped port: {e}"),
    }
}

/// A digest-verified workload, executed through the OCI runtime layer,
/// yields a REAL pid bound to a REAL listening UDP socket; stopping it exits
/// the pid and closes the socket, and restarting brings both back live.
#[tokio::test]
async fn spawns_stops_and_restarts_a_real_supervised_process() {
    let image_bytes = std::fs::read(env!("CARGO_BIN_EXE_udp_echo")).expect("read udp_echo image");
    let running = admitted_running_workload(image_bytes);

    let port = free_udp_port();
    let mut process = running
        .spawn_process(&[port.to_string()])
        .expect("spawn real supervised process");

    // Real pid.
    let pid = process.pid().expect("process has a real os pid");
    assert!(pid > 0);
    assert!(process.is_alive().expect("liveness check"));

    // Real listening socket: the echo actually round-trips over the wire.
    let reply = probe_echo(port, b"hello-real-process")
        .await
        .expect("echo over real socket");
    assert_eq!(reply, b"hello-real-process");

    // Stop: the real process actually exits and the socket actually closes.
    process.stop().await.expect("stop supervised process");
    assert!(!process.is_alive().expect("liveness check after stop"));
    assert_no_listener(port).await;

    // Restart: a fresh real process re-binds the same entrypoint/port and
    // answers again — health reflects liveness across the cycle.
    process.restart().await.expect("restart supervised process");
    assert!(process.is_alive().expect("liveness check after restart"));
    let new_pid = process.pid().expect("restarted process has a real pid");
    assert_ne!(
        new_pid,
        0,
        "restarted process must have been assigned a real pid"
    );

    let reply_after_restart = probe_echo(port, b"hello-again")
        .await
        .expect("echo over restarted real socket");
    assert_eq!(reply_after_restart, b"hello-again");

    process.stop().await.expect("final stop");
    assert!(!process.is_alive().expect("liveness check after final stop"));
}
