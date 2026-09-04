//! Acceptance test — `workload-deployment-kind`.
//!
//! Proves the **Deployment** built-in kind (long-running, replicated — NOT
//! the Job/CronJob one-shots): declare a Deployment with 3 replicas, the
//! REAL topology-spread engine (`pillar_topology::Topology::spread`) places
//! them across 3 DISTINCT nodes/racks (never a re-derived heuristic), each
//! placement is admitted through the full identity/capability/lease/view
//! gate stack exactly like `oci_runtime_real.rs`, and each admitted replica
//! is EXECUTED as a real supervised OS process
//! (`pillar_controller::deployment::Deployment`) — a real pid bound to a
//! real listening UDP socket, not an in-memory `Run` struct. Killing a
//! replica's real process and reconciling restarts brings it back as a
//! fresh real process on the same port.
//!
//! `#[cfg(feature = "acceptance")]`-gated: only exercised via
//! `cargo test -p pillar-e2e --test deployment_kind --features acceptance`
//! (the `acceptance-e2e` CHECKS.md stub), never a plain `cargo test`.

#![cfg(feature = "acceptance")]

use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_controller::deployment::{Deployment, DeploymentReplica, DeploymentSpec, RestartPolicy};
use pillar_controller::{Controller, RUN_WORKLOAD_CAPABILITY, WorkloadSpec};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry};
use pillar_net::BlobDigest;
use pillar_streamdb::Stream;
use pillar_topology::{Label, TierHierarchy, Topology};

/// Claim a free localhost UDP port by binding then immediately dropping the
/// socket — the child process we spawn next binds it for real.
fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    socket.local_addr().expect("local addr").port()
}

/// Build an identity/capability/lease/view stack admitting `node` as a
/// controller for its own workloads, then authorize + run a `WorkloadSpec`
/// declaring `image_bytes` on `node` — exactly the same admission path
/// `oci_runtime_real.rs` proves, so each replica starts from a REAL
/// reconciled workload, not a shortcut around admission.
fn admit_and_spawn(
    node_seed: &str,
    workload_name: &str,
    image_bytes: Vec<u8>,
    port: u16,
) -> pillar_controller::SupervisedWorkload {
    let digest = BlobDigest::of(&image_bytes);

    let mut identity = Registry::new();
    let primary = PrimaryKeypair::from_secret_seed(&pillar_crypto::Seed::from_bytes(
        format!("pillar-e2e-deployment-kind-{node_seed}-primary").into_bytes(),
    ));
    let controller_key = NodeSubkey::from(node_seed);
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
        workload_name,
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
        .expect("every safety layer admits the replica's workload");

    let running = admitted
        .run(image_bytes)
        .expect("image bytes verify against the authorized digest");

    running
        .spawn_process(&[port.to_string()])
        .expect("spawn real supervised process for this replica")
}

/// Send `msg` to `port` and await the echoed reply, proving a REAL listening
/// UDP socket is live and answering. Retries briefly to absorb the real
/// process's scheduling/bind latency.
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

/// A Deployment with 3 replicas is PLACED (via the real topology-spread
/// engine) across 3 distinct nodes/racks and EXECUTED as 3 real supervised
/// processes; killing one replica's real pid and reconciling restarts brings
/// it back as a fresh real process answering on the same port.
#[tokio::test]
async fn deployment_places_and_runs_replicas_and_restarts_a_killed_one() {
    let image_bytes = std::fs::read(env!("CARGO_BIN_EXE_udp_echo")).expect("read udp_echo image");

    // --- scheduler: PLACE 3 replicas across 3 DISTINCT racks, via the real
    // topology engine's spread decision — never a re-derived heuristic.
    let mut topology = Topology::new(TierHierarchy::default());
    topology.declare(NodeId::from("node-a"), &[Label::new("rack", "r1")]);
    topology.declare(NodeId::from("node-b"), &[Label::new("rack", "r2")]);
    topology.declare(NodeId::from("node-c"), &[Label::new("rack", "r3")]);

    let spec = DeploymentSpec::new("echo-deployment", 3, "rack", RestartPolicy::Always);
    let candidates = [
        NodeId::from("node-a"),
        NodeId::from("node-b"),
        NodeId::from("node-c"),
    ];
    let placed = spec
        .place(&topology, &candidates)
        .expect("3 distinct racks satisfy the 3-replica spread");
    assert_eq!(placed.len(), 3, "all 3 replicas were placed");
    let racks: std::collections::BTreeSet<_> = placed
        .iter()
        .map(|n| topology.placement(n).at("rack").unwrap().to_owned())
        .collect();
    assert_eq!(
        racks.len(),
        3,
        "topology spread placed the 3 replicas on 3 DISTINCT racks"
    );

    // --- runtime: EXECUTE each placed replica as a real supervised process
    // bound to its own real listening UDP socket — real pids, real sockets.
    let mut ports = Vec::new();
    let mut replicas = Vec::new();
    for node in &placed {
        let port = free_udp_port();
        ports.push(port);
        let process = admit_and_spawn(&node.0, spec.name(), image_bytes.clone(), port);
        replicas.push(DeploymentReplica::new(node.clone(), process));
    }

    let mut deployment = Deployment::new(spec, replicas);
    assert_eq!(deployment.replicas().len(), 3);

    // Every replica has a real pid and answers on its real socket.
    let mut pids = Vec::new();
    for (i, replica) in deployment.replicas_mut().iter_mut().enumerate() {
        let pid = replica
            .process_mut()
            .pid()
            .expect("replica has a real os pid");
        assert!(pid > 0);
        assert!(replica
            .process_mut()
            .is_alive()
            .expect("liveness check succeeds"));
        pids.push(pid);
        let reply = probe_echo(ports[i], b"hello-replica")
            .await
            .expect("echo over real replica socket");
        assert_eq!(reply, b"hello-replica");
    }
    // Distinct real pids across replicas.
    let distinct_pids: std::collections::BTreeSet<_> = pids.iter().copied().collect();
    assert_eq!(distinct_pids.len(), 3, "each replica is a distinct real process");

    // --- restart policy: kill one replica's REAL process out from under the
    // supervisor (simulating an external crash) and confirm reconciliation
    // actually restarts it — a fresh real pid rebinding the same port.
    let killed_index = 1;
    let killed_pid = pids[killed_index];
    // A real external SIGKILL (via the `kill` binary — the workspace forbids
    // unsafe code, so no direct libc FFI here) simulating an out-of-band
    // process crash the supervisor did not itself initiate.
    let status = std::process::Command::new("kill")
        .arg("-9")
        .arg(killed_pid.to_string())
        .status()
        .expect("run kill(1)");
    assert!(status.success(), "kill(1) failed to signal the replica pid");
    // Give the kernel a moment to actually reap/deliver the death.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let alive = deployment.replicas_mut()[killed_index]
            .process_mut()
            .is_alive()
            .expect("liveness check succeeds");
        if !alive {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "killed replica never observed dead"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let restarted = deployment
        .reconcile_restarts()
        .await
        .expect("restart-policy reconciliation succeeds");
    assert_eq!(
        restarted,
        vec![placed[killed_index].clone()],
        "reconciliation restarted exactly the killed replica"
    );

    let new_pid = deployment.replicas_mut()[killed_index]
        .process_mut()
        .pid()
        .expect("restarted replica has a real pid");
    assert_ne!(new_pid, 0);
    assert_ne!(
        new_pid, killed_pid,
        "restart produced a FRESH real process, not the dead one"
    );
    assert!(deployment.replicas_mut()[killed_index]
        .process_mut()
        .is_alive()
        .expect("liveness check after restart"));

    let reply = probe_echo(ports[killed_index], b"hello-after-restart")
        .await
        .expect("echo over restarted replica's real socket");
    assert_eq!(reply, b"hello-after-restart");

    // The other two replicas were never touched by the restart.
    for (i, replica) in deployment.replicas_mut().iter_mut().enumerate() {
        if i == killed_index {
            continue;
        }
        assert!(replica
            .process_mut()
            .is_alive()
            .expect("untouched replica still alive"));
    }

    // Clean up every replica's real process.
    for replica in deployment.replicas_mut() {
        let _ = replica.process_mut().stop().await;
    }
}
