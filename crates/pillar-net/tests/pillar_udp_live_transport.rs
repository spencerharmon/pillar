//! Live pillar-UDP transport integration test.
//!
//! `pillar-udp-transport-impl` landed the pillar-UDP protocol MECHANICS as an
//! isolated module but never registered pillar-UDP in the running node's swarm
//! (`build_event_swarm` bound TCP+QUIC only). This test proves the wiring this
//! task adds: a node built by `build_event_swarm`
//!
//!   1. actually REGISTERS the pillar-UDP transport and LISTENS on a
//!      `…/udp/<port>/p-pillar` multiaddr (not merely TCP/QUIC), and
//!   2. routes a real datagram end-to-end OVER that pillar-UDP transport
//!      between two nodes — an application message published on one node and
//!      received on the other, with the connection established solely via the
//!      pillar-UDP dial address.
//!
//! The module's own unit tests are explicitly NOT sufficient evidence for this
//! task; this stands up live swarms and drives a real datagram across the wire.

use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, identity::Keypair, Multiaddr, Swarm};
use pillar_net::{
    build_event_swarm, event_log_topic, is_pillar_udp_addr, pillar_udp_socket_addr,
    EventBehaviourEvent,
};
use tokio::time::timeout;

/// A loopback pillar-UDP listen multiaddr on an ephemeral port.
fn pillar_udp_listen_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/unix/p-pillar"
        .parse()
        .expect("static pillar-udp multiaddr parses")
}

async fn drive_until<B, T>(
    swarm: &mut Swarm<B>,
    deadline: Duration,
    mut pred: impl FnMut(&SwarmEvent<B::ToSwarm>) -> Option<T>,
) -> T
where
    B: libp2p::swarm::NetworkBehaviour,
{
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

/// The pillar-UDP multiaddr helpers recognise our own addresses and reject
/// non-pillar-UDP ones (TCP, QUIC).
#[test]
fn pillar_udp_addr_recognition() {
    let ours: Multiaddr = "/ip4/127.0.0.1/udp/4001/unix/p-pillar".parse().unwrap();
    assert!(is_pillar_udp_addr(&ours));
    assert_eq!(
        pillar_udp_socket_addr(&ours).unwrap(),
        "127.0.0.1:4001".parse().unwrap()
    );

    let quic: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
    assert!(!is_pillar_udp_addr(&quic));
    let tcp: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    assert!(!is_pillar_udp_addr(&tcp));
}

/// A node built by `build_event_swarm` REGISTERS the pillar-UDP transport:
/// asked to listen on a `…/udp/<port>/p-pillar` address it actually binds and
/// reports a live pillar-UDP listen address (proving the transport is wired in,
/// not just TCP+QUIC).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn build_event_swarm_registers_and_listens_on_pillar_udp() {
    let mut node = build_event_swarm(Keypair::generate_ed25519()).unwrap();
    node.listen_on(pillar_udp_listen_addr())
        .expect("swarm accepts a pillar-UDP listen address => transport registered");

    let bound = drive_until(&mut node, Duration::from_secs(10), |event| match event {
        SwarmEvent::NewListenAddr { address, .. } if is_pillar_udp_addr(address) => {
            Some(address.clone())
        }
        _ => None,
    })
    .await;

    // The bound address is a real pillar-UDP endpoint on a concrete port.
    let sock = pillar_udp_socket_addr(&bound).expect("bound addr is pillar-UDP");
    assert_ne!(sock.port(), 0, "an ephemeral port was actually bound");
}

/// End-to-end: two `build_event_swarm` nodes connect SOLELY over the
/// pillar-UDP transport (the listener advertises only its pillar-UDP address,
/// the dialer dials only that), complete the Noise+yamux upgrade over the
/// reliable-ordered UDP substrate, and a datagram (a gossipsub event-log
/// message) published by the dialer is received by the listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datagram_routes_end_to_end_over_pillar_udp() {
    let mut a = build_event_swarm(Keypair::generate_ed25519()).unwrap();
    let mut b = build_event_swarm(Keypair::generate_ed25519()).unwrap();
    let b_peer_id = *b.local_peer_id();

    let topic = event_log_topic();
    a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    b.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // b listens ONLY on pillar-UDP; capture that address.
    b.listen_on(pillar_udp_listen_addr()).unwrap();
    let b_addr = drive_until(&mut b, Duration::from_secs(10), |event| match event {
        SwarmEvent::NewListenAddr { address, .. } if is_pillar_udp_addr(address) => {
            Some(address.clone())
        }
        _ => None,
    })
    .await;
    assert!(
        is_pillar_udp_addr(&b_addr),
        "listener advertised a pillar-UDP address"
    );

    // a dials b over the pillar-UDP address exclusively.
    let dial = b_addr.clone().with(Protocol::P2p(b_peer_id));
    a.dial(dial).expect("dialing over pillar-UDP is accepted");

    // Confirm the connection actually established over the pillar-UDP transport
    // (the negotiated endpoint address is a pillar-UDP multiaddr).
    let connected_over_pillar_udp = {
        let deadline = Duration::from_secs(30);
    let a_conn = drive_until(&mut a, deadline, |event| match event {
            SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                Some(is_pillar_udp_addr(endpoint.get_remote_address()))
            }
            _ => None,
        });
        // Drive b concurrently so the handshake can complete.
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
        connected_over_pillar_udp,
        "the established connection's remote address is a pillar-UDP multiaddr \
         => the datagram path is genuinely pillar-UDP, not a fallback transport"
    );

    // Now route a real datagram: wait for gossipsub mesh formation on both
    // sides, then publish from a and assert b receives it.
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
        .expect("both peers subscribed to the event-log topic over pillar-UDP");

    // Retry publish until the single-peer mesh is ready, driving both swarms.
    let payload = b"hello-over-pillar-udp".to_vec();
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
    .expect("a datagram published over pillar-UDP was received end-to-end");

    assert_eq!(
        received, payload,
        "the exact datagram routed end-to-end over the pillar-UDP transport"
    );
}
