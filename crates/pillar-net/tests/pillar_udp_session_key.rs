//! Acceptance (real sockets): the portable cell-minted **pillar-UDP session
//! key** scheme (`docs/papers/pillar-udp-encryption.md`; formally gated by
//! `specs/PillarUdpEncryption.tla`).
//!
//! Gated by the crate's `acceptance` feature (off by default). Exercises the
//! REAL effect the task delivers — not merely that code compiles — over actual
//! bound `UdpSocket`s and a real libp2p swarm:
//!
//! 1. **Portability + authorize-before-serve over real sockets.** A client
//!    mints a signed `SessionInit`, derives `K_s` locally (0-RTT), and SPRAYS
//!    the init (redundant, multipath) across a real UDP socket to TWO distinct
//!    ingress nodes. Each independently authorizes it and, from the converged
//!    cell-signed record alone, derives the BYTE-IDENTICAL `K_s` and serves a
//!    session frame the client sealed — proving the key is portable across cell
//!    nodes with no key on the wire and no per-pair binding. An unauthorized
//!    session id yields NO key (authorize-before-serve). Replay of a frame is
//!    dropped by CID dedup. Sender identity is the ed25519 signature inside the
//!    `PillarMessage`, verified on open — never `K_s`.
//! 2. **Revocation + GC-erase (security-critical).** A cell-signed revocation
//!    converges to a node; it stops honoring `K_s`, and GC then ERASES the
//!    record so `K_s` is no longer recomputable even with the cell static key —
//!    the revoked-but-uncollected decryption oracle is closed.
//! 3. **Anonymous-as-policy.** An anonymous (unattested) principal runs the
//!    IDENTICAL scheme over the same sockets and gets a served key; only the
//!    default-deny RBAC outcome differs — it holds no privileged grant, while an
//!    attested principal does. Same crypto path, different policy.
//! 4. **NegotiationRefusesIncompatible / RollingCoexistence over a real swarm.**
//!    The session-key transport carries a live, dial-able libp2p connection
//!    (ping round-trip); a legacy (version-1) peer is refused cleanly while a
//!    compatible peer in the same run still links.

#![cfg(feature = "acceptance")]

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{ping, PeerId, Swarm};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use pillar_crypto::{Seed, SigningPublicKey, SigningSecretKey};
use pillar_net::pillar_udp::{
    DedupProcessor, MIN_PROTOCOL_VERSION, PROTOCOL_COMPAT_WINDOW, PROTOCOL_VERSION,
};
use pillar_net::{
    cell_node_session_key, client_session_key, frame_sender, handshakeless_pillar_udp_transport,
    negotiate_session_key_peer, open_frame, peer_sealing_keypair, seal_frame, unwrap_frame_body,
    wrap_frame_body, CellKeys, Grant, SessionError, SessionInit, SessionRecord, SessionStore,
};

// ---- helpers -------------------------------------------------------------

fn client_signing(seed: &str) -> (SigningPublicKey, SigningSecretKey) {
    let s = Seed::from_bytes(format!("acceptance-client-sign::{seed}").into_bytes());
    pillar_crypto::sign::signing_keypair_from_seed(&s).unwrap()
}

/// Mint a signed session init for a client, deriving a fresh ephemeral X25519
/// keypair from a seed (a live client draws it randomly). Returns the init plus
/// the client's ephemeral secret (so the client can derive `K_s` locally).
fn mint_init(seed: &str) -> (SessionInit, pillar_crypto::SealingSecretKey, Vec<u8>) {
    let (spk, ssk) = client_signing(seed);
    let (epk, esk) = peer_sealing_keypair(&format!("acceptance-eph::{seed}"));
    let nonce = format!("acceptance-nonce::{seed}").into_bytes();
    let init = SessionInit::mint(&spk, &ssk, &epk, nonce.clone()).unwrap();
    (init, esk, nonce)
}

/// Serialize a `SessionInit` for the wire (init is sprayed to ingress nodes).
fn init_to_wire(init: &SessionInit) -> Vec<u8> {
    let mut b = Vec::new();
    let push = |b: &mut Vec<u8>, s: &[u8]| {
        b.extend_from_slice(&(s.len() as u32).to_be_bytes());
        b.extend_from_slice(s);
    };
    push(&mut b, init.principal_pk.as_bytes());
    push(&mut b, init.eph_pk.as_bytes());
    push(&mut b, &init.client_nonce);
    push(&mut b, init.principal_sig.as_bytes());
    b
}

fn init_from_wire(bytes: &[u8]) -> SessionInit {
    let mut pos = 0usize;
    let take = |bytes: &[u8], pos: &mut usize| -> Vec<u8> {
        let len = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap()) as usize;
        *pos += 4;
        let s = bytes[*pos..*pos + len].to_vec();
        *pos += len;
        s
    };
    let principal_pk = SigningPublicKey::from_bytes(take(bytes, &mut pos));
    let eph_pk = pillar_crypto::SealingPublicKey::from_bytes(take(bytes, &mut pos));
    let client_nonce = take(bytes, &mut pos);
    let principal_sig = pillar_crypto::Signature::from_bytes(take(bytes, &mut pos));
    SessionInit {
        principal_pk,
        eph_pk,
        client_nonce,
        principal_sig,
    }
}

const CELL_SEED: &str = "acceptance-cell-A";

/// (1) Portability + authorize-before-serve + replay defense + sender identity,
/// with the init SPRAYED over REAL UDP sockets to two distinct ingress nodes.
#[tokio::test]
async fn session_key_is_portable_across_ingress_nodes_over_real_sockets() {
    let cell = CellKeys::from_seed(CELL_SEED).unwrap();

    // Two real ingress-node sockets; the client sprays the init to both
    // (redundant, multipath).
    let ingress1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ingress2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr1 = ingress1.local_addr().unwrap();
    let addr2 = ingress2.local_addr().unwrap();
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Client mints a signed init and derives K_s LOCALLY (0-RTT), before any
    // round-trip, against the published cell static public key.
    let (init, eph_sk, nonce) = mint_init("alice");
    let k_client = client_session_key(&eph_sk, &cell.static_pk, &nonce).unwrap();

    // No key material is on the wire — only the derivation inputs.
    let init_bytes = init_to_wire(&init);
    assert!(
        !init_bytes
            .windows(k_client.as_bytes().len())
            .any(|w| w == k_client.as_bytes()),
        "the session key must NEVER appear on the wire"
    );

    // Spray the init to BOTH ingress nodes over the real socket.
    client_sock.send_to(&init_bytes, addr1).await.unwrap();
    client_sock.send_to(&init_bytes, addr2).await.unwrap();

    // Each ingress node receives, verifies, authorizes, and derives K_s from
    // the record inputs ALONE (portability). Two independent stores stand in
    // for two independent cell nodes.
    async fn recv_and_authorize(
        sock: &UdpSocket,
        store: &mut SessionStore,
        cell: &CellKeys,
    ) -> SessionRecord {
        let mut buf = vec![0u8; 64 * 1024];
        let (n, _from) = timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("ingress receives init")
            .unwrap();
        let got = init_from_wire(&buf[..n]);
        // attested principal for this session
        store.authorize(&got, true, cell).unwrap()
    }

    let mut store1 = SessionStore::new();
    let mut store2 = SessionStore::new();
    let rec1: SessionRecord = recv_and_authorize(&ingress1, &mut store1, &cell).await;
    let rec2: SessionRecord = recv_and_authorize(&ingress2, &mut store2, &cell).await;

    // Deterministic: two racing ingress nodes append the byte-identical
    // cell-signed record.
    assert_eq!(
        rec1, rec2,
        "racing ingress nodes derive the identical record"
    );
    assert_eq!(rec1.session_id, init.session_id());

    // Authorize-before-serve: each node serves K_s ONLY from its converged
    // record, and both equal the client's K_s (PORTABLE across nodes).
    let k1 = store1.serve_key(&init.session_id(), &cell).unwrap();
    let k2 = store2.serve_key(&init.session_id(), &cell).unwrap();
    assert_eq!(k1.as_bytes(), k_client.as_bytes());
    assert_eq!(k2.as_bytes(), k_client.as_bytes());

    // A DIFFERENT (third) cell node that only converged the cell-signed record
    // (never saw the init) still serves the identical key — pure portability.
    let mut store3 = SessionStore::new();
    store3.converge(&rec1, &cell.signing_pk).unwrap();
    let k3 = store3.serve_key(&init.session_id(), &cell).unwrap();
    assert_eq!(k3.as_bytes(), k_client.as_bytes());

    // Direct cross-check of the ECDH portability identity.
    let k_node_direct = cell_node_session_key(&cell.static_sk, &init.eph_pk, &nonce).unwrap();
    assert_eq!(k_node_direct.as_bytes(), k_client.as_bytes());

    // Authorize-before-serve refuses a fabricated / never-authorized session.
    let (bogus, _e, _n) = mint_init("never-authorized");
    assert_eq!(
        store1.serve_key(&bogus.session_id(), &cell),
        Err(SessionError::NotAuthorized)
    );

    // The client seals a transport frame under K_s; ANY cell node with the
    // served key opens it and verifies the ed25519 sender identity.
    let (spk, ssk) = client_signing("alice");
    let frame_msg = wrap_frame_body(b"opsync-request-since-H", CELL_SEED, &spk, &ssk).unwrap();
    let (cid, sealed) = seal_frame(&frame_msg, &k_client).unwrap();

    let opened_at_2 = open_frame(&sealed, &k2).unwrap();
    assert_eq!(
        frame_sender(&opened_at_2),
        &spk,
        "sender identity is the ed25519 signer INSIDE the envelope, not K_s"
    );
    assert_eq!(
        unwrap_frame_body(&opened_at_2, CELL_SEED).unwrap(),
        b"opsync-request-since-H"
    );

    // Replay defense via CID dedup: a replayed frame has the same Cid and is
    // dropped (processed once).
    let mut dedup = DedupProcessor::new();
    assert!(dedup.process(&cid), "first copy admitted");
    let (cid_replay, _sealed_replay) = seal_frame(&frame_msg, &k_client).unwrap();
    assert_eq!(
        cid, cid_replay,
        "the frame is content-addressed convergently"
    );
    assert!(
        !dedup.process(&cid_replay),
        "a replayed frame is deduped, never re-applied"
    );
}

/// (2) Revocation stops service and GC erases the key material (the oracle
/// window is closed).
#[tokio::test]
async fn revocation_stops_service_and_gc_erases_key_material() {
    let cell = CellKeys::from_seed(CELL_SEED).unwrap();
    let (init, _eph_sk, _nonce) = mint_init("carol");
    let sid = init.session_id();

    let mut store = SessionStore::new();
    store.authorize(&init, true, &cell).unwrap();
    assert!(store.serve_key(&sid, &cell).is_ok());
    assert!(store.key_material_present(&sid));

    // A cell-signed revocation converges → the node stops honoring K_s, but the
    // derivation inputs are still present (the oracle window before GC).
    let rev = SessionStore::sign_revocation(&sid, &cell).unwrap();
    store.revoke(&sid, &rev, &cell.signing_pk).unwrap();
    assert_eq!(store.serve_key(&sid, &cell), Err(SessionError::Revoked));
    assert!(store.key_material_present(&sid));

    // A forged revocation (wrong cell key) is refused.
    let other_cell = CellKeys::from_seed("acceptance-cell-B").unwrap();
    let forged = SessionStore::sign_revocation(&sid, &other_cell).unwrap();
    let mut store2 = SessionStore::new();
    store2.authorize(&init, true, &cell).unwrap();
    assert_eq!(
        store2.revoke(&sid, &forged, &cell.signing_pk),
        Err(SessionError::BadCellSignature)
    );

    // GC erases the record: K_s is no longer recomputable even with the cell
    // static key — the security-critical collection.
    assert!(store.gc_erase(&sid));
    assert!(!store.key_material_present(&sid));
    assert_eq!(
        store.serve_key(&sid, &cell),
        Err(SessionError::NotAuthorized),
        "after GC-erase the session is indistinguishable from never-existed"
    );
}

/// (3) Anonymous is policy, not a separate scheme: same crypto path, restricted
/// (default-deny) grants for an unattested principal, privileged for an
/// attested one.
#[tokio::test]
async fn anonymous_is_policy_not_a_separate_scheme() {
    let cell = CellKeys::from_seed(CELL_SEED).unwrap();

    // An anonymous client generates an anonymous signing key and runs the exact
    // scheme; it is unattested → restricted grants.
    let (anon_init, anon_eph, anon_nonce) = mint_init("anonymous-client");
    let (attested_init, _e2, _n2) = mint_init("attested-user");

    let mut store = SessionStore::new();
    store.authorize(&anon_init, false, &cell).unwrap(); // is_attested = false
    store.authorize(&attested_init, true, &cell).unwrap(); // is_attested = true

    let anon_grants = store.grants(&anon_init.session_id()).unwrap();
    assert!(
        anon_grants.allows(Grant::Communicate),
        "an anonymous session may still communicate"
    );
    assert!(
        !anon_grants.is_privileged(),
        "an unattested principal must NEVER hold a privileged grant (default-deny)"
    );

    let user_grants = store.grants(&attested_init.session_id()).unwrap();
    assert!(
        user_grants.is_privileged(),
        "an attested principal holds the privileged grant"
    );

    // The anonymous session still derives + serves K_s identically — only the
    // policy differs, not the crypto path.
    let k_anon_node = store.serve_key(&anon_init.session_id(), &cell).unwrap();
    let k_anon_client = client_session_key(&anon_eph, &cell.static_pk, &anon_nonce).unwrap();
    assert_eq!(
        k_anon_node.as_bytes(),
        k_anon_client.as_bytes(),
        "the anonymous session runs the identical portable-key scheme"
    );
}

// ---- (4) real swarm + negotiation ---------------------------------------

#[derive(NetworkBehaviour)]
struct PingBehaviour {
    ping: ping::Behaviour,
}

fn build_swarm(keypair: Keypair) -> Swarm<PingBehaviour> {
    let transport: Boxed<(PeerId, StreamMuxerBox)> = handshakeless_pillar_udp_transport(&keypair);
    libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(move |_| transport)
        .expect("register pillar-UDP transport")
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

/// (4) The session-key pillar-UDP transport carries a live libp2p connection
/// (ping round-trip) over a real swarm, and negotiation refuses a legacy peer
/// cleanly while a compatible peer still links.
#[tokio::test]
async fn session_key_transport_pings_over_real_swarm_and_negotiation_refuses_legacy() {
    // NegotiationRefusesIncompatible / RollingCoexistence.
    assert!(
        negotiate_session_key_peer(PROTOCOL_VERSION).is_ok(),
        "a peer at the current session-key protocol version links"
    );
    let legacy = pillar_crypto::SurfaceVersion(MIN_PROTOCOL_VERSION.0.saturating_sub(1));
    assert!(
        negotiate_session_key_peer(legacy).is_err(),
        "a legacy (pre-cutover) peer is refused cleanly"
    );
    let out_of_window =
        pillar_crypto::SurfaceVersion(PROTOCOL_VERSION.0 + PROTOCOL_COMPAT_WINDOW.0 + 1);
    assert!(negotiate_session_key_peer(out_of_window).is_err());

    // A real, dial-able connection over the transport: ping round-trip.
    let mut listener = build_swarm(Keypair::generate_ed25519());
    let mut dialer = build_swarm(Keypair::generate_ed25519());
    let addr = listen_addr(&mut listener).await;
    dialer.dial(addr).unwrap();

    let pinged = timeout(Duration::from_secs(30), async {
        let mut listener_ok = false;
        let mut dialer_ok = false;
        loop {
            tokio::select! {
                ev = listener.select_next_some() => {
                    if let SwarmEvent::Behaviour(PingBehaviourEvent::Ping(ping::Event { result: Ok(_), .. })) = ev {
                        listener_ok = true;
                    }
                }
                ev = dialer.select_next_some() => {
                    if let SwarmEvent::Behaviour(PingBehaviourEvent::Ping(ping::Event { result: Ok(_), .. })) = ev {
                        dialer_ok = true;
                    }
                }
            }
            if listener_ok && dialer_ok {
                return true;
            }
        }
    })
    .await;
    assert!(
        pinged.unwrap_or(false),
        "the session-key pillar-UDP transport must carry a live ping round-trip"
    );

    // Negotiation still admits a compatible peer after the legacy refusal
    // (RollingCoexistence: one refusal does not partition the swarm).
    assert!(negotiate_session_key_peer(PROTOCOL_VERSION).is_ok());
}
