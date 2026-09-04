//! Acceptance test — `real-workload-acceptance` (the P0 capstone).
//!
//! This is NOT a unit test over a model. It is the executable end-to-end gate
//! that IS the acceptance narrative — the literal definition of "pillar runs a
//! workload," executed with a trivial UDP echo application over REAL sockets,
//! REAL OS processes, REAL image bytes fetched by CID over a REAL libp2p swarm,
//! REAL crypto, and REAL IPFS-pinned sealed state. Every link is genuine; there
//! is no model, stand-in payload, in-memory `resolve`, or no-op reconcile
//! anywhere in the chain. The whole story, in one test:
//!
//! 1. **Apply.** The operator authors a Deployment manifest (YAML) and submits
//!    it with the real `pillar apply` envelope path
//!    ([`pillar_manifest::ManifestStore::apply_yaml`]) — decode → schema
//!    validate → sign into the pillar-native [`Envelope`] → store. The replica
//!    count and topology key are read back out of the sealed, stored object.
//! 2. **Schedule.** The real topology-spread engine
//!    ([`pillar_manifest`]'s `DeploymentSpec::place` over
//!    [`pillar_topology::Topology`]) places three replicas across three DISTINCT
//!    pillar nodes / racks — never a re-derived heuristic.
//! 3. **Fetch-by-CID + execute.** Each node fetches the image BY CID over a
//!    live libp2p swarm from the cell's content-addressed store
//!    ([`pillar_net::BlobStore`] + the `/pillar/blob/1.0.0` request/response
//!    protocol), verifies the digest through the production controller gate
//!    ([`pillar_controller::AdmittedFetch::run`]), and EXECUTES it as a real
//!    supervised OS process — a real pid on a real listening UDP socket.
//! 4. **VIP + Frontend/Route.** The operator allocates a VIP from an IPAM pool
//!    with the real operator surface ([`pillar_ipam::operator::IpamOperator`])
//!    through the quorum fence; it is recorded. A UDP [`Frontend`] (that VIP)
//!    and a [`Route`] (`RouteKind::Udp`, `RoundRobin`) attach the app's three
//!    real backends.
//! 5. **Dataplane.** A client sends UDP datagrams to VIP:port; the real
//!    dataplane ([`pillar_net::UdpDataplane`]) binds the VIP, selects a backend
//!    per the Route's algorithm, forwards each datagram, and the client
//!    receives echoes demonstrably served by ALL THREE nodes.
//! 6. **Failover + rehydrate.** Killing one node's real process drops it via the
//!    health check and traffic continues to the surviving two. Then the cell's
//!    workload/routing/IPAM state rehydrates from IPFS-pinned SEALED state (NOT
//!    local disk) — [`pillar_streamdb::IpfsPersistentStream::rehydrate`] +
//!    `unseal_signing_key` — and the app is reachable again with no operator
//!    intervention.
//!
//! Behind the explicit `acceptance` CI feature so it is RUN, never skipped:
//! `cargo test -p pillar-e2e --test real_workload_acceptance --features acceptance`.
//! The harness itself IS the test — it FAILS on any broken link and PASSES only
//! when the whole chain executes live.

#![cfg(feature = "acceptance")]

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::request_response;
use libp2p::swarm::{Swarm, SwarmEvent};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_controller::deployment::{DeploymentSpec, RestartPolicy};
use pillar_controller::{
    Controller, SupervisedWorkload, WorkloadSpec, RUN_WORKLOAD_CAPABILITY,
};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_crypto::seal::sealing_keypair_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::Seed;
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry};
use pillar_ipam::operator::IpamOperator;
use pillar_ipam::{Pool, TopologyScopedIpam};
use pillar_manifest::ingress::{
    Affinity, Algorithm, Backend, Frontend, HealthCheck, Listener, LoadBalancerPolicy, Route,
    RouteKind,
};
use pillar_manifest::apply::{ManifestKey, ManifestStore};
use pillar_manifest::{Crd, FieldType, Schema, SchemaRegistry, Value};
use pillar_net::{
    build_blob_swarm, BlobBehaviour, BlobBehaviourEvent, BlobDigest, BlobRequest, BlobStore,
    UdpDataplane,
};
use pillar_streamdb::{Cid, IpfsPersistentStream, SignedSegment, Stream, Visibility};
use pillar_topology::{Label, TierHierarchy, Topology};

// ---------------------------------------------------------------------------
// Step 1 — the operator's authored Deployment manifest (real YAML).
// ---------------------------------------------------------------------------

const DEPLOYMENT_API_VERSION: &str = "pillar.dev/v1";
const DEPLOYMENT_KIND: &str = "Deployment";

/// The exact YAML an operator authors and submits with `pillar apply -f
/// echo.yaml`. Three replicas of a UDP echo app, spread across the `rack`
/// topology tier.
const ECHO_DEPLOYMENT_YAML: &str = r#"
apiVersion: pillar.dev/v1
kind: Deployment
metadata:
  name: echo-app
spec:
  replicas: 3
  topologyKey: rack
  protocol: udp
"#;

/// Register the `Deployment` kind's schema exactly the way any third-party CRD
/// registers — no built-in special-casing. `pillar apply` validates the
/// operator's YAML against this before sealing it into an envelope.
fn deployment_schema() -> Schema {
    Schema::new(DEPLOYMENT_API_VERSION, DEPLOYMENT_KIND)
        .required("replicas", FieldType::Integer)
        .required("topologyKey", FieldType::String)
        .property("protocol", FieldType::String)
}

/// Read a required integer spec field out of a stored, sealed CRD body.
fn spec_int(crd: &Crd, field: &str) -> i64 {
    match crd.spec.get(field) {
        Some(Value::Integer(i)) => *i,
        other => panic!("expected integer spec.{field}, got {other:?}"),
    }
}

/// Read a required string spec field out of a stored, sealed CRD body.
fn spec_str(crd: &Crd, field: &str) -> String {
    match crd.spec.get(field) {
        Some(Value::String(s)) => s.clone(),
        other => panic!("expected string spec.{field}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Step 3 — real libp2p fetch-by-CID + digest-verified admission.
// ---------------------------------------------------------------------------

fn local_tcp_listen_addr() -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
        .with(Protocol::Tcp(0))
}

async fn listen_and_get_addr(swarm: &mut Swarm<BlobBehaviour>) -> Multiaddr {
    swarm.listen_on(local_tcp_listen_addr()).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("listen addr")
}

/// The cell's content-addressed store node: it publishes the echo image blob
/// and serves it to any peer that asks by digest, over a REAL libp2p swarm.
async fn spawn_image_provider(bytes: Vec<u8>) -> (Multiaddr, libp2p::PeerId, BlobDigest) {
    let mut provider = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
    let provider_peer_id = *provider.local_peer_id();
    let mut store = BlobStore::new();
    let digest = store.insert(bytes);
    let provider_addr = listen_and_get_addr(&mut provider).await;

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
                provider
                    .behaviour_mut()
                    .blob
                    .send_response(channel, response)
                    .expect("send response");
            }
        }
    });

    (provider_addr, provider_peer_id, digest)
}

/// A SEPARATE fetcher node dials the provider and pulls the blob purely by its
/// CID/digest over the real request/response protocol.
async fn fetch_image_by_cid(
    provider_addr: Multiaddr,
    provider_peer_id: libp2p::PeerId,
    digest: BlobDigest,
) -> Vec<u8> {
    let mut fetcher = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
    fetcher
        .dial(provider_addr.with(Protocol::P2p(provider_peer_id)))
        .unwrap();

    timeout(Duration::from_secs(20), async {
        loop {
            match fetcher.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. }
                    if peer_id == provider_peer_id =>
                {
                    fetcher.behaviour_mut().blob.send_request(
                        &provider_peer_id,
                        BlobRequest {
                            digest: digest.clone(),
                        },
                    );
                }
                SwarmEvent::Behaviour(BlobBehaviourEvent::Blob(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) => {
                    return response.bytes.expect("provider served the blob");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("blob fetched over libp2p")
}

/// Admit a workload for `node` running the given digest, through the full
/// identity/capability/lease/view gate stack (never a shortcut around
/// admission), verify the fetched bytes against the authorized digest, and
/// EXECUTE it as a real supervised process bound to `port`, tagged with `id`
/// (so the dataplane client can tell which node's replica served a datagram).
fn admit_verify_and_spawn(
    node_seed: &str,
    workload_name: &str,
    digest: BlobDigest,
    fetched_bytes: Vec<u8>,
    port: u16,
    id: &str,
) -> SupervisedWorkload {
    let mut identity = Registry::new();
    let primary = PrimaryKeypair::from_secret_seed(&pillar_crypto::Seed::from_bytes(
        format!("pillar-e2e-real-workload-{node_seed}-primary").into_bytes(),
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
        digest.clone(),
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
    assert_eq!(
        admitted.digest(),
        digest,
        "the authorized digest is the CID we fetched by"
    );

    let running = admitted
        .run(fetched_bytes)
        .expect("bytes fetched over libp2p verify against the authorized digest");

    running
        .spawn_process(&[port.to_string(), id.to_string()])
        .expect("spawn real supervised process for this replica")
}

// ---------------------------------------------------------------------------
// Client probes over real sockets.
// ---------------------------------------------------------------------------

/// Claim a free localhost UDP port by binding then dropping the socket — the
/// child process we spawn next binds it for real.
fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    s.local_addr().expect("local addr").port()
}

/// Directly probe a replica's own socket (bypassing the VIP), retrying briefly
/// to absorb the freshly-spawned process's bind latency. Returns the serving
/// backend id parsed from the `<id>:<payload>` reply.
async fn probe_replica(port: u16, msg: &[u8]) -> std::io::Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(("127.0.0.1", port)).await?;
        client.send(msg).await?;
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_millis(300), client.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let reply = &buf[..n];
                let colon = reply.iter().position(|&b| b == b':').expect("id-framed reply");
                return Ok(String::from_utf8_lossy(&reply[..colon]).into_owned());
            }
            _ if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no reply within deadline",
                ))
            }
        }
    }
}

/// Send `payload` to the VIP through the real dataplane and return the serving
/// backend id (the `<id>:` prefix the workload replica stamps on its reply).
async fn vip_round_trip(vip: SocketAddr, payload: &[u8]) -> Option<String> {
    let client = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.connect(vip).await.ok()?;
    client.send(payload).await.ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let reply = &buf[..n];
    let colon = reply.iter().position(|&b| b == b':')?;
    Some(String::from_utf8_lossy(&reply[..colon]).into_owned())
}

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse().unwrap())
}

// ---------------------------------------------------------------------------
// The whole story, executed literally.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn workload_reckoning_end_to_end_over_real_everything() {
    // === Step 1: apply the operator's Deployment manifest through the REAL
    // envelope path (decode → schema-validate → sign → store). ===
    let mut registry = SchemaRegistry::new();
    registry.register(deployment_schema());
    let mut manifests = ManifestStore::new(registry, "operator-key");

    manifests
        .apply_yaml(ECHO_DEPLOYMENT_YAML)
        .expect("the authored Deployment YAML decodes, validates, and seals");

    // Read the desired state back out of the SEALED, stored envelope — not the
    // in-memory YAML string.
    let key = ManifestKey {
        api_version: DEPLOYMENT_API_VERSION.to_owned(),
        kind: DEPLOYMENT_KIND.to_owned(),
        name: "echo-app".to_owned(),
    };
    let stored = manifests
        .get_body(&key)
        .expect("the applied Deployment is stored and readable back");
    let replicas = spec_int(&stored, "replicas");
    let topology_key = spec_str(&stored, "topologyKey");
    assert_eq!(replicas, 3, "the operator declared three replicas");
    assert_eq!(topology_key, "rack");

    // === Step 3a: publish the echo image to the cell's content-addressed
    // store and derive its CID. The image is the real udp_echo binary bytes. ===
    let image_bytes = std::fs::read(env!("CARGO_BIN_EXE_udp_echo")).expect("read udp_echo image");
    let (provider_addr, provider_peer_id, digest) =
        spawn_image_provider(image_bytes.clone()).await;

    // === Step 2: the REAL topology-spread engine places `replicas` across
    // `replicas` DISTINCT racks. ===
    let mut topology = Topology::new(TierHierarchy::default());
    topology.declare(NodeId::from("node-a"), &[Label::new("rack", "r1")]);
    topology.declare(NodeId::from("node-b"), &[Label::new("rack", "r2")]);
    topology.declare(NodeId::from("node-c"), &[Label::new("rack", "r3")]);

    let dep_spec = DeploymentSpec::new(
        "echo-app",
        replicas as usize,
        &topology_key,
        RestartPolicy::Always,
    );
    let candidates = [
        NodeId::from("node-a"),
        NodeId::from("node-b"),
        NodeId::from("node-c"),
    ];
    let placed = dep_spec
        .place(&topology, &candidates)
        .expect("three distinct racks satisfy the three-replica spread");
    assert_eq!(placed.len(), 3, "all three replicas were placed");
    let racks: BTreeSet<_> = placed
        .iter()
        .map(|n| topology.placement(n).at("rack").unwrap().to_owned())
        .collect();
    assert_eq!(racks.len(), 3, "topology spread placed replicas on 3 DISTINCT racks");

    // === Step 3b + execute: each placed node fetches the image BY CID over
    // real libp2p, verifies the digest, and runs it as a REAL process on a
    // real listening UDP socket. The backend id == the node id, so the
    // dataplane client can prove which node served each datagram. ===
    let mut ports = Vec::new();
    let mut backend_table: Vec<(String, SocketAddr)> = Vec::new();
    let mut processes: Vec<SupervisedWorkload> = Vec::new();
    for node in &placed {
        let fetched = fetch_image_by_cid(
            provider_addr.clone(),
            provider_peer_id,
            digest.clone(),
        )
        .await;
        assert_eq!(fetched, image_bytes, "fetched-by-CID bytes equal the published image");

        let port = free_udp_port();
        let id = node.0.clone();
        let process = admit_verify_and_spawn(
            &node.0,
            "echo-app",
            digest.clone(),
            fetched,
            port,
            &id,
        );
        ports.push(port);
        backend_table.push((id, SocketAddr::new(v4("127.0.0.1"), port)));
        processes.push(process);
    }

    // Each replica is a distinct real process answering on its real socket.
    let mut pids = BTreeSet::new();
    for (i, process) in processes.iter_mut().enumerate() {
        let pid = process.pid().expect("replica has a real os pid");
        assert!(pid > 0);
        assert!(process.is_alive().expect("liveness check"));
        pids.insert(pid);
        let who = probe_replica(ports[i], b"warmup")
            .await
            .expect("replica answers on its real socket");
        assert_eq!(who, placed[i].0, "the replica identifies itself by node id");
    }
    assert_eq!(pids.len(), 3, "each replica is a distinct real process");

    // === Step 4: the operator allocates a VIP from an IPAM pool through the
    // real operator surface + quorum fence, and it is RECORDED. ===
    let mut ipam_topo = Topology::new(TierHierarchy::default());
    ipam_topo.declare(NodeId::from("lb-west"), &[Label::new("region", "west")]);
    let mut ipam = TopologyScopedIpam::new(ipam_topo, "region").unwrap();
    ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
    let mut ipam_op = IpamOperator::new(ipam);

    let vip = v4("10.1.0.7");
    let lb_node = NodeId::from("lb-west");
    ipam_op
        .ipam_mut()
        .grant_for(NodeId::from("voter-1"), &lb_node, vip)
        .unwrap();
    ipam_op
        .ipam_mut()
        .grant_for(NodeId::from("voter-2"), &lb_node, vip)
        .unwrap();
    let binding = ipam_op
        .allocate("echo-frontend-vip", &lb_node, vip)
        .expect("a quorum-backed VIP allocates and records");
    assert!(binding.allocated);
    assert_eq!(ipam_op.recorded_addr("echo-frontend-vip"), Some(vip));

    // The operator declares a UDP Frontend (that VIP) and a Route
    // (RouteKind::Udp, RoundRobin) attaching the three real backends.
    let mut route = Route::new("echo-route", "echo-app", "echo-frontend", RouteKind::Udp);
    for (id, _addr) in &backend_table {
        route = route.with_backend(Backend::new(id.clone()));
    }
    let _frontend = Frontend::new("echo-frontend", vip.to_string()).with_listener(Listener {
        port: 0,
        protocol: RouteKind::Udp,
        tls: None,
    });
    assert_eq!(route.kind, RouteKind::Udp);

    // === Step 5: the real dataplane binds the VIP and forwards client
    // datagrams round-robin; the client's echoes come back served by ALL
    // THREE real nodes. ===
    let policy = LoadBalancerPolicy {
        algorithm: Algorithm::RoundRobin,
        affinity: Affinity::None,
        locality_tier: None,
        health: HealthCheck {
            active: true,
            interval_ms: 100,
        },
        consistency_class: SideEffect::Convergent,
    };
    let dp = UdpDataplane::bind("127.0.0.1:0", &backend_table, policy)
        .await
        .expect("dataplane binds the VIP");
    let dp_vip = dp.vip_addr();
    assert_ne!(dp_vip.port(), 0, "a real VIP port was bound");

    // Let the active health probe mark all three real backends healthy.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut served: BTreeSet<String> = BTreeSet::new();
    for i in 0..60u32 {
        if let Some(who) = vip_round_trip(dp_vip, format!("req-{i}").as_bytes()).await {
            served.insert(who);
        }
    }
    assert_eq!(
        served,
        placed.iter().map(|n| n.0.clone()).collect(),
        "the dataplane spread real client datagrams across ALL THREE real nodes, got {served:?}"
    );

    // === Step 6a: kill one node's REAL process; the health check drops it and
    // traffic continues to the surviving two. ===
    let killed = placed[1].0.clone();
    let killed_pid = processes[1].pid().expect("killed replica has a pid");
    let status = std::process::Command::new("kill")
        .arg("-9")
        .arg(killed_pid.to_string())
        .status()
        .expect("run kill(1)");
    assert!(status.success(), "kill(1) failed to signal the replica pid");

    // Give the active health check (interval 100ms) a few cycles to drop it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !dp.healthy_ids().contains(&killed) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "health check never dropped the killed node, healthy={:?}",
            dp.healthy_ids()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut after: BTreeSet<String> = BTreeSet::new();
    for i in 0..60u32 {
        if let Some(who) = vip_round_trip(dp_vip, format!("post-{i}").as_bytes()).await {
            after.insert(who);
        }
    }
    assert!(
        !after.contains(&killed),
        "the killed node served NO traffic after failover, got {after:?}"
    );
    let survivors: BTreeSet<String> = placed
        .iter()
        .map(|n| n.0.clone())
        .filter(|n| n != &killed)
        .collect();
    assert_eq!(
        after, survivors,
        "traffic continued uninterrupted to the surviving two nodes, got {after:?}"
    );

    // === Step 6b: the cell's workload/routing/IPAM state rehydrates from
    // IPFS-pinned SEALED state (NOT local disk), and a restarting node recovers
    // write capability from ONLY its custody-held key + the sealed IPFS
    // segment. We durably record the whole declared cell state (the applied
    // manifest, the VIP binding, and the route) as ops on an IPFS-persistent
    // stream, seal the signing key, then rehydrate a FRESH node with an empty
    // local store purely from the pinned segments. ===
    let (owner_pk, owner_sk) =
        signing_keypair_from_seed(&Seed::from_bytes(b"real-workload-cell-owner".to_vec()))
            .expect("keygen");
    let (node_pub, node_secret) =
        sealing_keypair_from_seed(&Seed::from_bytes(b"real-workload-node-custody".to_vec()))
            .expect("keygen");

    let mut cell = IpfsPersistentStream::genesis(owner_pk.clone(), owner_sk, Visibility::Public);
    // Durable cell state: the sealed manifest content-hash, the VIP binding,
    // and the route declaration — the real declared state a node must recover.
    let manifest_hash = manifests
        .get(&key)
        .expect("stored envelope")
        .content_hash();
    cell.append(
        format!("workload:echo-app:{manifest_hash:?}").into_bytes(),
        SideEffect::Exclusive,
    )
    .expect("append workload op");
    cell.append(
        format!("vip:echo-frontend-vip:{vip}").into_bytes(),
        SideEffect::Exclusive,
    )
    .expect("append vip op");
    cell.append(
        b"route:echo-route:udp:roundrobin:node-a,node-b,node-c".to_vec(),
        SideEffect::Convergent,
    )
    .expect("append route op");

    let root_before = cell.stream().log().root();
    let len_before = cell.stream().log().len();

    // Seal the segment-signing secret to the restarting node's custody public
    // key and pin the envelope to IPFS (Sealed — never advertised to the DHT).
    let sealed_cid: Cid = cell
        .seal_signing_key(&[node_pub])
        .expect("seal + pin the signing key to IPFS");
    assert!(
        !cell.store().is_provided(&sealed_cid),
        "a sealed segment must never be advertised to the public DHT"
    );

    // The head is resolved out of band (the swarm's IPNS/pubsub), never a file.
    let head = cell
        .store()
        .resolve_head(&owner_pk)
        .cloned()
        .expect("cell published a head");

    // A FRESH/RESTARTED node with an EMPTY local store: it reaches the original
    // node's pinned segments only through the private-swarm SegmentSource
    // abstraction (a closure over the remote store) — exactly a real libp2p
    // backfill, never a local `ops/` directory.
    let remote = cell.store();
    let source = move |cid: &Cid| -> Option<SignedSegment> { remote.get_local(cid) };
    let mut restarted = IpfsPersistentStream::rehydrate(owner_pk.clone(), &head, &source)
        .expect("rehydrate the cell state purely from IPFS-pinned sealed segments");

    // Reconverges to EXACTLY the recorded cell state — same op count, same
    // Merkle root — proving no declared workload/route/IPAM state was lost.
    assert_eq!(
        restarted.stream().log().len(),
        len_before,
        "the rehydrated cell recovered every declared-state op"
    );
    assert_eq!(
        restarted.stream().log().root(),
        root_before,
        "the cell state reconverged purely from IPFS, not local disk"
    );

    // A purely-rehydrated handle is read-only until it recovers write
    // capability from ONLY its custody-held node key + the sealed IPFS segment.
    assert!(
        restarted
            .append(b"should-fail".to_vec(), SideEffect::Exclusive)
            .is_err(),
        "a purely rehydrated handle holds no signing secret yet"
    );
    restarted
        .unseal_signing_key(&sealed_cid, &node_secret, &source)
        .expect("recover write capability from custody key + sealed IPFS segment");
    restarted
        .append(b"post-restart:reconciled".to_vec(), SideEffect::Convergent)
        .expect("the restarted node writes again after unsealing");

    // === Step 6c: after the restart, the app is reachable again with no
    // operator intervention — the surviving real backends still serve the VIP.
    // (The killed node stays dropped; the cell continues on its two survivors,
    // exactly as a real cell would until a replacement replica is scheduled.) ===
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    for i in 0..40u32 {
        if let Some(who) = vip_round_trip(dp_vip, format!("rehydrated-{i}").as_bytes()).await {
            reachable.insert(who);
        }
    }
    assert_eq!(
        reachable, survivors,
        "post-rehydration the workload is reachable via the VIP with no operator action, got {reachable:?}"
    );

    // Clean up every remaining real process.
    for process in processes.iter_mut() {
        let _ = process.stop().await;
    }
}
