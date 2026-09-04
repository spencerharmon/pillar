//! `ingress-lb-udp-dataplane` acceptance — a REAL UDP dataplane, not a model.
//!
//! Acceptance-narrative step 5, executed literally over real sockets: a client
//! sends UDP datagrams to a `Frontend` VIP:port; the dataplane BINDS the VIP
//! ([`tokio::net::UdpSocket`]), SELECTS a backend per the `Route`'s
//! [`Algorithm`](pillar_manifest::ingress::Algorithm) + affinity, FORWARDS each
//! datagram to a real backend, and relays the echo back to the client. Every
//! hop is a genuine socket send/recv — there is no modelled `forward`.
//!
//! Two DoD properties, each its own `#[test]`, plus failover:
//!
//! 1. **Distribution per the Route algorithm.** A RoundRobin policy spreads a
//!    stream of datagrams across all live backends; the client's collected
//!    echoes are served by EVERY backend. A ConsistentHash + sticky policy
//!    pins a client's stream to ONE backend.
//! 2. **Health-check failover.** With active health checks on, one backend is
//!    KILLED (stops answering probes); the dataplane drops it and the client's
//!    traffic continues, uninterrupted, to the survivors — never the dead one.
//!
//! Only runs under `--features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pillar_core::SideEffect;
use pillar_manifest::ingress::{
    Affinity, Algorithm, Backend, Frontend, HealthCheck, Listener, LoadBalancerPolicy, Route,
    RouteKind,
};
use pillar_net::{UdpDataplane, HEALTH_PROBE};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// A real UDP echo backend: it binds a loopback socket and, for every datagram,
/// echoes back `"<backend-id>:<payload>"` so the client can tell WHICH backend
/// served each reply. It answers the health probe too (so an *alive* backend
/// stays healthy). Returns the backend id, its bound address, and the task
/// handle (drop/abort to "kill" it).
async fn spawn_echo_backend(id: &str) -> (String, SocketAddr, JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = sock.local_addr().unwrap();
    let id_owned = id.to_owned();
    let sock = Arc::new(sock);
    let id_for_task = id_owned.clone();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let payload = &buf[..n];
            // Health probes get echoed verbatim so the dataplane's active
            // probe sees the backend as alive.
            let reply: Vec<u8> = if payload == HEALTH_PROBE {
                payload.to_vec()
            } else {
                let mut r = id_for_task.clone().into_bytes();
                r.push(b':');
                r.extend_from_slice(payload);
                r
            };
            let _ = sock.send_to(&reply, from).await;
        }
    });
    (id_owned, addr, handle)
}

/// Send `payload` to `vip` from a fresh client socket and collect the reply's
/// serving-backend id (the prefix before the first `:`).
async fn round_trip(vip: SocketAddr, payload: &[u8]) -> Option<String> {
    let client = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.connect(vip).await.ok()?;
    client.send(payload).await.ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let reply = &buf[..n];
    let colon = reply.iter().position(|&b| b == b':')?;
    Some(String::from_utf8_lossy(&reply[..colon]).into_owned())
}

/// Build a `Frontend`/`Route` manifest and the matching live-backend address
/// table over three real echo backends. Returns the manifest objects plus the
/// `(id, addr)` table the dataplane binds.
async fn three_backend_fixture(
    kind: RouteKind,
) -> (
    Frontend,
    Route,
    Vec<(String, SocketAddr)>,
    Vec<JoinHandle<()>>,
) {
    let mut table = Vec::new();
    let mut handles = Vec::new();
    let mut route = Route::new("udp-route", "app", "udp-frontend", kind);
    for id in ["b1", "b2", "b3"] {
        let (bid, addr, h) = spawn_echo_backend(id).await;
        route = route.with_backend(Backend::new(bid.clone()));
        table.push((bid, addr));
        handles.push(h);
    }
    let frontend = Frontend::new("udp-frontend", "127.0.0.1").with_listener(Listener {
        port: 0,
        protocol: kind,
        tls: None,
    });
    (frontend, route, table, handles)
}

/// (1) A RoundRobin UDP dataplane binds a real VIP and SPREADS a stream of
/// client datagrams across ALL live backends — echoes come back served by
/// every backend, proving real per-datagram selection + forwarding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roundrobin_dataplane_distributes_datagrams_across_all_live_backends() {
    let (_frontend, _route, backends, _handles) = three_backend_fixture(RouteKind::Udp).await;

    let policy = LoadBalancerPolicy::round_robin();
    let dp = UdpDataplane::bind("127.0.0.1:0", &backends, policy)
        .await
        .expect("dataplane binds the VIP");
    let vip = dp.vip_addr();
    assert_ne!(vip.port(), 0, "a real VIP port was bound");

    // Let the initial active health probe mark all backends healthy.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut served: HashSet<String> = HashSet::new();
    for i in 0..30u32 {
        if let Some(who) = round_trip(vip, format!("req-{i}").as_bytes()).await {
            served.insert(who);
        }
    }
    assert_eq!(
        served,
        ["b1", "b2", "b3"].iter().map(|s| s.to_string()).collect(),
        "round-robin spread real datagrams across every live backend, got {served:?}"
    );
}

/// (1b) A ConsistentHash + sticky policy pins a given client's stream to ONE
/// backend (the exclusive/affinity guarantee), over real sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consistent_hash_sticky_pins_a_client_to_one_backend() {
    let (_frontend, _route, backends, _handles) = three_backend_fixture(RouteKind::Udp).await;

    let policy = LoadBalancerPolicy {
        algorithm: Algorithm::ConsistentHash,
        affinity: Affinity::Sticky,
        locality_tier: None,
        health: HealthCheck {
            active: true,
            interval_ms: 200,
        },
        consistency_class: SideEffect::Exclusive,
    };
    let dp = UdpDataplane::bind("127.0.0.1:0", &backends, policy)
        .await
        .expect("dataplane binds the VIP");
    let vip = dp.vip_addr();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A single client socket keeps the SAME source port across the whole
    // stream, so consistent-hash+sticky must pin every datagram to one backend.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(vip).await.unwrap();
    let mut served: HashSet<String> = HashSet::new();
    for i in 0..20u32 {
        client.send(format!("k-{i}").as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("reply within deadline")
            .unwrap();
        let reply = &buf[..n];
        let colon = reply.iter().position(|&b| b == b':').unwrap();
        served.insert(String::from_utf8_lossy(&reply[..colon]).into_owned());
    }
    assert_eq!(
        served.len(),
        1,
        "consistent-hash + sticky pinned the client's whole stream to ONE backend, got {served:?}"
    );
}

/// (2) Failover: with active health checks on, KILL a backend (abort its task
/// so it stops answering probes). The dataplane's health check drops it and
/// the client's traffic CONTINUES to the survivors — the dead backend never
/// serves another datagram.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killed_backend_is_dropped_by_health_check_and_traffic_continues() {
    let (_frontend, _route, backends, mut handles) = three_backend_fixture(RouteKind::Udp).await;

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
    let dp = UdpDataplane::bind("127.0.0.1:0", &backends, policy)
        .await
        .expect("dataplane binds the VIP");
    let vip = dp.vip_addr();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Sanity: before the kill all three backends serve.
    let mut before: HashSet<String> = HashSet::new();
    for i in 0..30u32 {
        if let Some(who) = round_trip(vip, format!("pre-{i}").as_bytes()).await {
            before.insert(who);
        }
    }
    assert!(
        before.contains("b2"),
        "b2 served before it was killed, got {before:?}"
    );

    // KILL backend b2 (index 1): abort its echo task so it stops answering.
    handles.remove(1).abort();

    // Give the active health check (interval 100ms) a few cycles to observe
    // the dead backend and drop it.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !dp.healthy_ids().contains(&"b2".to_string()),
        "health check dropped the killed backend, healthy={:?}",
        dp.healthy_ids()
    );

    // Traffic continues to the SURVIVORS only; b2 never serves again.
    let mut after: HashSet<String> = HashSet::new();
    for i in 0..40u32 {
        if let Some(who) = round_trip(vip, format!("post-{i}").as_bytes()).await {
            after.insert(who);
        }
    }
    assert!(
        !after.contains("b2"),
        "the killed backend served NO traffic after failover, got {after:?}"
    );
    assert!(
        after.contains("b1") && after.contains("b3"),
        "traffic continued uninterrupted to the surviving backends, got {after:?}"
    );
}
