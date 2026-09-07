//! Full end-to-end transport-matrix coverage on the REAL (enabled-root / pnet)
//! path that every deployed node actually boots through.
//!
//! Why this file exists: the transport posture is exercised in three places
//! that, before this suite, left gaps a real node's crash could hide in:
//!
//!   * `pillar_udp_live_transport.rs` / `pillar_udp_preferred_transport.rs`
//!     drive pillar-UDP end-to-end, but only on the DISABLED-root
//!     `build_event_swarm` path (`root.0 == None`) — the path NO real node
//!     takes. Every deployed node resolves an ENABLED pnet root (the public
//!     published key or a private `--swarm-key`) and boots the
//!     `build_event_swarm_with_root(Some(key), …)` branch instead.
//!   * `network_root_pnet.rs` drives that ENABLED path, but every node in it
//!     listens on TCP only — QUIC and pillar-UDP are never bound or dialed.
//!   * QUIC had NO two-node dial/handshake/datagram test anywhere in the Rust
//!     suite at all; its only prior evidence was a live cluster bootstrap.
//!
//! This suite closes all three gaps at once: for EACH transport it stands up
//! two real swarms on the enabled pnet path, has the listener bind ONLY that
//! transport, has the dialer dial ONLY that transport's concrete address,
//! asserts the established connection's remote address is genuinely that
//! transport (not a silent fallback), and then routes a real application
//! datagram (a gossipsub event-log message) end-to-end across it. It also
//! pins the class-scoping the fix mandates: the PUBLIC pnet swarm offers QUIC
//! (its published key is a namespace tag, not a secret), while a PRIVATE pnet
//! swarm REJECTS a QUIC listen address, because QUIC cannot be pnet-wrapped and
//! must never open an un-gated side channel around a private swarm's secret
//! root.
//!
//! These stand up loopback sockets only (fast, deterministic direct dials), so
//! they run in the ordinary `cargo test` unit run — the three protocols are
//! genuinely exercised on every test invocation, not behind an opt-in gate.

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{gossipsub, identity::Keypair, Multiaddr};
use pillar_net::{
    build_event_swarm_with_root, event_log_topic, is_pillar_udp_addr, EventBehaviourEvent,
    PrivateSwarmKey,
};
use pillar_swarm::PUBLIC_PILLAR_ROOT;
use tokio::time::timeout;

/// A loopback, ephemeral-port listen multiaddr for each transport.
fn tcp_listen_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}
fn quic_listen_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
}
fn pillar_udp_listen_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/unix/p-pillar".parse().unwrap()
}

/// Transport recognisers over a concrete (bound or negotiated) multiaddr. They
/// are mutually exclusive for the three addresses above: a `…/tcp/N` addr has a
/// `Tcp`; a `…/udp/N/quic-v1` addr has a `QuicV1`; a `…/udp/N/unix/p-pillar`
/// addr has neither and is recognised by `is_pillar_udp_addr`.
fn is_tcp_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}
fn is_quic_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

/// The pnet root a real node resolves with NO `--swarm-key`: the published
/// public swarm key. Both peers derive it identically, so the pnet-wrapped
/// TCP / pillar-UDP legs handshake, and QUIC is additionally offered.
fn public_root() -> PrivateSwarmKey {
    PrivateSwarmKey::from_root_secret(PUBLIC_PILLAR_ROOT)
}
/// The pnet root two peers resolve from the SAME operator-distributed
/// `--swarm-key` file: a private swarm. QUIC is withheld here.
fn private_root() -> PrivateSwarmKey {
    PrivateSwarmKey::from_root_secret("transport-matrix-private-root")
}

async fn drive_until<B: NetworkBehaviour, T>(
    swarm: &mut Swarm<B>,
    deadline: Duration,
    mut pred: impl FnMut(&SwarmEvent<B::ToSwarm>) -> Option<T>,
) -> T {
    timeout(deadline, async {
        loop {
            let event = swarm.select_next_some().await;
            if let Some(v) = pred(&event) {
                return v;
            }
        }
    })
    .await
    .expect("deadline elapsed waiting for expected swarm event")
}

/// End-to-end assertion for one transport on the enabled pnet path: build two
/// swarms with the given roots, have the listener bind ONLY `listen_addr`, have
/// the dialer dial ONLY that address, prove the negotiated connection is
/// genuinely `is_expected`, then route a real gossipsub datagram across it.
async fn assert_transport_e2e(
    label: &str,
    root_a: PrivateSwarmKey,
    root_b: PrivateSwarmKey,
    quic_enabled: bool,
    listen_addr: Multiaddr,
    is_expected: fn(&Multiaddr) -> bool,
) {
    let mut a =
        build_event_swarm_with_root(Keypair::generate_ed25519(), root_a, false, quic_enabled)
            .unwrap_or_else(|e| panic!("{label}: dialer swarm builds: {e}"));
    let mut b =
        build_event_swarm_with_root(Keypair::generate_ed25519(), root_b, false, quic_enabled)
            .unwrap_or_else(|e| panic!("{label}: listener swarm builds: {e}"));
    let b_peer_id = *b.local_peer_id();

    let topic = event_log_topic();
    a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    b.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // The listener binds ONLY the target transport. `listen_on` returns
    // `Err(MultiaddrNotSupported)` synchronously if that transport is not
    // registered — the exact failure a real node hit when QUIC was missing.
    b.listen_on(listen_addr.clone())
        .unwrap_or_else(|e| panic!("{label}: listener must register + bind a {label} addr: {e}"));
    let b_addr = drive_until(&mut b, Duration::from_secs(10), |event| match event {
        SwarmEvent::NewListenAddr { address, .. } if is_expected(address) => Some(address.clone()),
        _ => None,
    })
    .await;
    assert!(
        is_expected(&b_addr),
        "{label}: listener advertised a {label} address ({b_addr})"
    );

    // The dialer dials EXACTLY that transport's address — nothing else is
    // offered, so a connection can only form over `label`.
    let dial = b_addr.clone().with(Protocol::P2p(b_peer_id));
    a.dial(dial)
        .unwrap_or_else(|e| panic!("{label}: dialing over {label} is accepted: {e}"));

    // Phase 1: the connection establishes, and its negotiated remote address is
    // genuinely this transport (proving no silent fallback). Drive b
    // concurrently so the handshake completes.
    let connected_over = {
        let a_conn = drive_until(&mut a, Duration::from_secs(30), |event| match event {
            SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                Some(is_expected(endpoint.get_remote_address()))
            }
            _ => None,
        });
        let b_drive = async {
            loop {
                let _ = b.select_next_some().await;
            }
        };
        futures::future::select(Box::pin(a_conn), Box::pin(b_drive))
            .await
            .factor_first()
            .0
    };
    assert!(
        connected_over,
        "{label}: the established connection's remote address is a {label} multiaddr \
         => the path is genuinely {label}, not a fallback transport"
    );

    // Phase 2: the two-peer gossipsub mesh forms on both sides.
    let deadline = Duration::from_secs(30);
    let drive_a_sub = async {
        loop {
            if let SwarmEvent::Behaviour(EventBehaviourEvent::Gossipsub(
                gossipsub::Event::Subscribed { .. },
            )) = a.select_next_some().await
            {
                break;
            }
        }
    };
    let drive_b_sub = async {
        loop {
            if let SwarmEvent::Behaviour(EventBehaviourEvent::Gossipsub(
                gossipsub::Event::Subscribed { .. },
            )) = b.select_next_some().await
            {
                break;
            }
        }
    };
    timeout(deadline, futures::future::join(drive_a_sub, drive_b_sub))
        .await
        .unwrap_or_else(|_| panic!("{label}: both peers subscribed to the event-log topic"));

    // Phase 3: a real datagram published by a is received by b OVER this
    // transport. Retry publish until the single-peer mesh is ready, driving
    // both swarms.
    let payload = format!("hello-over-{label}").into_bytes();
    let received = timeout(deadline, async {
        loop {
            let _ = a
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), payload.clone());
            tokio::select! {
                ev = a.select_next_some() => { let _ = ev; }
                ev = b.select_next_some() => {
                    if let SwarmEvent::Behaviour(EventBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) = ev
                    {
                        break message.data;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("{label}: a datagram published over {label} was received end-to-end")
    });

    assert_eq!(
        received, payload,
        "{label}: the exact datagram routed end-to-end over the {label} transport"
    );
}

/// TCP, end-to-end, on the PUBLIC pnet path (pnet-wrapped TCP leg).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_e2e_on_public_pnet_swarm() {
    assert_transport_e2e(
        "tcp",
        public_root(),
        public_root(),
        true,
        tcp_listen_addr(),
        is_tcp_addr,
    )
    .await;
}

/// QUIC, end-to-end, on the PUBLIC pnet path — the transport that had no
/// two-node dial/handshake/datagram test anywhere, and the one whose LISTEN
/// address a real node used to reject (`Multiaddr is not supported`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_e2e_on_public_pnet_swarm() {
    assert_transport_e2e(
        "quic",
        public_root(),
        public_root(),
        true,
        quic_listen_addr(),
        is_quic_addr,
    )
    .await;
}

/// pillar-UDP (the PREFERRED transport), end-to-end, on the PUBLIC pnet path —
/// the enabled-root branch its prior e2e coverage never touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pillar_udp_e2e_on_public_pnet_swarm() {
    assert_transport_e2e(
        "pillar-udp",
        public_root(),
        public_root(),
        true,
        pillar_udp_listen_addr(),
        is_pillar_udp_addr,
    )
    .await;
}

/// pillar-UDP, end-to-end, on a PRIVATE pnet swarm (`quic_enabled = false`):
/// the preferred transport must work identically when the root is a secret
/// operator key, not just the public one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pillar_udp_e2e_on_private_pnet_swarm() {
    assert_transport_e2e(
        "pillar-udp",
        private_root(),
        private_root(),
        false,
        pillar_udp_listen_addr(),
        is_pillar_udp_addr,
    )
    .await;
}

/// TCP, end-to-end, on a PRIVATE pnet swarm (the pnet-wrapped TCP fallback leg).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_e2e_on_private_pnet_swarm() {
    assert_transport_e2e(
        "tcp",
        private_root(),
        private_root(),
        false,
        tcp_listen_addr(),
        is_tcp_addr,
    )
    .await;
}

/// Class-scoping, at the integration (real-socket) level: a PUBLIC pnet swarm
/// binds a QUIC listen address (QUIC is offered because the published key is a
/// namespace tag, not a secret), while a PRIVATE pnet swarm REJECTS it —
/// `listen_on` returns `Err` because QUIC is not registered on a private root
/// (it cannot be pnet-wrapped, so admitting it would bypass the secret-root
/// membership gate). Complements the datagram tests above with the negative
/// half of the posture on the real path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_is_public_only_on_the_pnet_path() {
    // PUBLIC: QUIC listen accepted.
    let mut public =
        build_event_swarm_with_root(Keypair::generate_ed25519(), public_root(), false, true)
            .expect("public pnet swarm builds");
    public.listen_on(quic_listen_addr()).expect(
        "a PUBLIC pnet swarm must accept a QUIC listen addr (published key is a namespace tag)",
    );

    // PRIVATE: QUIC listen rejected (transport not registered), but the pnet
    // legs it DOES offer are accepted.
    let mut private =
        build_event_swarm_with_root(Keypair::generate_ed25519(), private_root(), false, false)
            .expect("private pnet swarm builds");
    assert!(
        private.listen_on(quic_listen_addr()).is_err(),
        "a PRIVATE pnet swarm must REJECT a QUIC listen addr: QUIC cannot be pnet-wrapped, so \
         admitting it would open an un-gated side channel around the secret root"
    );
    private
        .listen_on(pillar_udp_listen_addr())
        .expect("a private pnet swarm still binds its preferred pillar-UDP transport");
    private
        .listen_on(tcp_listen_addr())
        .expect("a private pnet swarm still binds its TCP fallback transport");
}
