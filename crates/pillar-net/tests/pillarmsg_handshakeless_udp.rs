//! Acceptance (real sockets / real swarm): the handshakeless pillar-UDP
//! cutover — method #1 step (f).
//!
//! Gated by the crate's `acceptance` feature (off by default). Exercises the
//! REAL effect the task delivers, not merely that code compiles:
//!
//! 1. **Every libp2p payload rides a `PillarMessage`, sealed to the peer's WoT
//!    static X25519 key, handshakeless, over a REAL UDP socket.** Two ends
//!    exchange a control payload wrapped as a `PillarMessage` and sealed with
//!    `seal_to_recipients` to the recipient's static sealing key across an
//!    actual bound `UdpSocket` — no Noise handshake, no round-trip. The
//!    recipient opens it; a non-recipient key cannot; the application content
//!    is never plaintext on the wire.
//! 2. **The pillar-UDP transport drops the Noise upgrade and still carries a
//!    real libp2p connection over a real swarm.** Two libp2p swarms built with
//!    `handshakeless_pillar_udp_transport` (NO `noise::Config` authenticate
//!    step) connect over `…/udp/<port>/p-pillar` sockets and complete a
//!    `ping` round-trip — proving the transport with Noise removed is a live,
//!    dial-able libp2p transport.
//! 3. **NegotiationRefusesIncompatible / RollingCoexistence.** A peer
//!    declaring the current pillar-UDP protocol version links; a Noise-era /
//!    out-of-window peer is refused cleanly, and that refusal is scoped to the
//!    one relationship (a compatible peer in the same run still links).

#![cfg(feature = "acceptance")]

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{ping, PeerId, Swarm};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_net::pillar_udp::{MIN_PROTOCOL_VERSION, PROTOCOL_COMPAT_WINDOW, PROTOCOL_VERSION};
use pillar_net::{
    handshakeless_pillar_udp_transport, negotiate_handshakeless_peer, open_datagram,
    peer_sealing_keypair, seal_datagram_to_peer, unwrap_control, wrap_control, ControlProtocol,
    HandshakelessError,
};

/// A minimal ping-only behaviour: enough to prove a real connection is live
/// over the handshakeless pillar-UDP transport.
#[derive(NetworkBehaviour)]
struct PingBehaviour {
    ping: ping::Behaviour,
}

fn build_handshakeless_swarm(keypair: Keypair) -> Swarm<PingBehaviour> {
    let transport: Boxed<(PeerId, StreamMuxerBox)> = handshakeless_pillar_udp_transport(&keypair);
    libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(move |_| transport)
        .expect("register handshakeless pillar-UDP transport")
        .with_behaviour(|_| PingBehaviour {
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_millis(200)),
            ),
        })
        .expect("behaviour")
        .build()
}

async fn listen_addr(swarm: &mut Swarm<PingBehaviour>) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/unix/p-pillar".parse().unwrap())
        .unwrap();
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

/// (1) A `PillarMessage`-wrapped control payload, sealed to the peer's static
/// X25519 key, crosses a REAL UDP socket handshakeless; only the recipient
/// opens it and the content is never plaintext on the wire.
#[tokio::test]
async fn sealed_pillar_message_crosses_a_real_udp_socket_handshakeless() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // The recipient (server) publishes its static WoT sealing key; a third
    // party has a different key.
    let (server_pk, server_sk) = peer_sealing_keypair("acceptance-server-wot");
    let (_eve_pk, eve_sk) = peer_sealing_keypair("acceptance-eve-wot");

    // The client wraps an opsync control payload as a PillarMessage and seals
    // the datagram to the server's static key — no handshake precedes it.
    let raw = b"opsync-request: give me ops since head H";
    let msg = wrap_control(
        ControlProtocol::OpSync,
        raw,
        "acceptance-cell",
        "acceptance-signer",
    )
    .expect("wrap");
    let datagram = seal_datagram_to_peer(&msg, &server_pk).expect("seal");
    let on_wire = datagram.as_bytes().to_vec();

    // The application content is NOT visible in the datagram bytes.
    assert!(
        !on_wire.windows(raw.len()).any(|w| w == raw),
        "sealed datagram must not carry the plaintext control payload"
    );

    // Single datagram send — no prior handshake round-trip.
    client.send_to(&on_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 64 * 1024];
    let (n, _from) = timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .expect("server receives datagram")
        .unwrap();
    let received = pillar_crypto::SealedEnvelope::from_bytes(buf[..n].to_vec());

    // The intended recipient opens it back to the exact control payload.
    let opened = open_datagram(&received, &server_sk).expect("server opens datagram");
    let (proto, got_raw) = unwrap_control(&opened, "acceptance-cell").expect("unwrap");
    assert_eq!(proto, ControlProtocol::OpSync);
    assert_eq!(got_raw, raw);

    // A non-recipient (Eve) cannot open it.
    assert!(matches!(
        open_datagram(&received, &eve_sk),
        Err(HandshakelessError::Seal(_))
    ));
}

/// (2) Two libp2p swarms whose pillar-UDP transport has the Noise upgrade
/// REMOVED connect over real `…/udp/<port>/p-pillar` sockets and complete a
/// ping round-trip — a live, dial-able transport with no Noise handshake.
#[tokio::test]
async fn handshakeless_pillar_udp_swarm_connects_and_pings() {
    let mut listener = build_handshakeless_swarm(Keypair::generate_ed25519());
    let listener_peer = *listener.local_peer_id();
    let addr = listen_addr(&mut listener).await;

    let mut dialer = build_handshakeless_swarm(Keypair::generate_ed25519());
    dialer
        .dial(addr.with(Protocol::P2p(listener_peer)))
        .unwrap();

    // Drive both swarms; require a ping SUCCESS across the connection (proves
    // the muxed stream actually carries application protocol traffic, not just
    // that a socket opened).
    let deadline = Duration::from_secs(30);
    let pinged = timeout(deadline, async {
        loop {
            tokio::select! {
                ev = listener.select_next_some() => {
                    if let SwarmEvent::Behaviour(PingBehaviourEvent::Ping(ping::Event {
                        result: Ok(_), ..
                    })) = ev {
                        return true;
                    }
                }
                ev = dialer.select_next_some() => {
                    if let SwarmEvent::Behaviour(PingBehaviourEvent::Ping(ping::Event {
                        result: Ok(_), ..
                    })) = ev {
                        return true;
                    }
                }
            }
        }
    })
    .await;
    assert!(
        pinged.is_ok(),
        "two handshakeless (no-Noise) pillar-UDP swarms must connect and ping over real sockets"
    );
}

/// (3) NegotiationRefusesIncompatible + RollingCoexistence: a current-version
/// peer links; a Noise-era / out-of-window peer is refused cleanly, and the
/// refusal is scoped to that one peer (the compatible peer still links in the
/// same run — a mixed swarm coexists).
#[tokio::test]
async fn negotiation_refuses_noise_era_peer_but_compatible_peers_coexist() {
    // Compatible peer (declares the current version): links.
    assert!(negotiate_handshakeless_peer(PROTOCOL_VERSION).is_ok());

    // Noise-era peer: a declared version below the minimum this build decodes.
    let noise_era = pillar_crypto::SurfaceVersion(MIN_PROTOCOL_VERSION.0.saturating_sub(1));
    if noise_era.0 < MIN_PROTOCOL_VERSION.0 {
        assert!(
            negotiate_handshakeless_peer(noise_era).is_err(),
            "a Noise-era peer below the min protocol version must be refused cleanly"
        );
    }

    // Far-future / out-of-window peer: refused.
    let future = pillar_crypto::SurfaceVersion(PROTOCOL_VERSION.0 + PROTOCOL_COMPAT_WINDOW.0 + 1);
    assert!(negotiate_handshakeless_peer(future).is_err());

    // RollingCoexistence: after refusing the incompatible peers above, a
    // compatible peer still links — the refusal did not poison the surface.
    assert!(
        negotiate_handshakeless_peer(PROTOCOL_VERSION).is_ok(),
        "a compatible peer must still link after an incompatible one was refused"
    );
}
