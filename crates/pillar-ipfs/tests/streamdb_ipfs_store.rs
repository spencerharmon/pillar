//! Integration test proving the streamdb-ipfs-store-spec contract end to end
//! against pillar's own embedded IPFS node: a signed segment round-trips by
//! real CIDv1, a missing-but-reachable segment backfills over a second node
//! through pillar's own private libp2p swarm (never an external daemon, never
//! the public IPFS DHT), and an IPNS-format head resolves to its latest valid
//! sequence, rejecting a stale/lower-sequence or forged candidate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{request_response, Swarm};
use tokio::time::timeout;

use pillar_crypto::{sign, Seed};
use pillar_ipfs::{
    answer_block_request, build_ipfs_swarm, content_id, resolve_latest, BlockRequest,
    IpfsSwarmBehaviour, IpfsSwarmBehaviourEvent, IpnsHead, PrivateSwarmKey, Visibility,
};

/// The private-swarm root every node in this test shares — matching
/// `PrivateSwarmKey::disabled()` peers would never even complete the
/// transport handshake, which is exactly the "off the public DHT, on
/// pillar's own private swarm" guarantee this test exercises.
fn test_swarm_root() -> PrivateSwarmKey {
    PrivateSwarmKey::from_root_secret("streamdb-ipfs-store-impl test root")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// A signed segment (put) round-trips byte-identical, and its bytes are
/// verified against the real CIDv1(raw, sha2-256) multihash on the way back
/// out — the same identity a reference IPFS node would compute.
#[test]
fn signed_segment_round_trips_by_cid_multihash_verified() {
    let node = pillar_ipfs::IpfsNode::in_memory();

    let (owner_pk, owner_sk) =
        sign::signing_keypair_from_seed(&Seed::from_bytes(b"segment-owner-seed".to_vec()))
            .expect("keygen");
    let payload = b"a real signed streaming-db segment's wire bytes".to_vec();
    let signature = sign::sign(&owner_sk, &payload).expect("sign segment");

    // The "signed segment" wire form: payload || signature bytes, addressed
    // by ITS OWN content id (a block is opaque bytes to the store; the
    // signature is a property the consumer checks against `owner_pk`, not the
    // store).
    let mut wire = payload.clone();
    wire.extend_from_slice(signature.as_bytes());

    let cid = node.put_block(&wire).expect("put segment");
    assert_eq!(cid, content_id(&wire), "CID must be the real multihash of the bytes");

    let fetched = node
        .get_block(&cid)
        .expect("get segment")
        .expect("segment present");
    assert_eq!(fetched, wire, "round-tripped bytes must be byte-identical");

    // The consumer-side signature check the wire form exists to support:
    let fetched_payload = &fetched[..payload.len()];
    let fetched_sig_bytes = &fetched[payload.len()..];
    let fetched_sig = pillar_crypto::Signature::from_bytes(fetched_sig_bytes.to_vec());
    assert_eq!(fetched_payload, &payload[..]);
    assert_eq!(
        sign::verify(&owner_pk, fetched_payload, &fetched_sig),
        Ok(()),
        "the round-tripped segment's signature must still verify"
    );
}

async fn listen_and_get_addr(swarm: &mut Swarm<IpfsSwarmBehaviour>) -> Multiaddr {
    swarm
        .listen_on(
            Multiaddr::empty()
                .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
                .with(Protocol::Tcp(0)),
        )
        .expect("listen");
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

/// A block held by node A but missing on node B is fetched by B, purely by
/// CID, over pillar's own private libp2p swarm — never an external daemon —
/// and B independently re-verifies the received bytes hash to the CID it
/// asked for before ever accepting them.
#[tokio::test]
async fn backfills_missing_segment_from_a_second_node_over_the_private_swarm() {
    let root = test_swarm_root();

    // Node A holds the segment durably.
    let node_a = pillar_ipfs::IpfsNode::in_memory();
    let block = b"a segment only node A has pinned".to_vec();
    let cid = node_a.put_block(&block).expect("put on A");
    node_a.pin(&cid).expect("pin on A");

    let mut swarm_a =
        build_ipfs_swarm(Keypair::generate_ed25519(), root.clone()).expect("build swarm A");
    let peer_a = *swarm_a.local_peer_id();
    let addr_a = listen_and_get_addr(&mut swarm_a).await;

    // Drive A in the background: answer any bitswap want from its local
    // blockstore.
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(IpfsSwarmBehaviourEvent::Bitswap(
                request_response::Event::Message {
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) = swarm_a.select_next_some().await
            {
                let response = answer_block_request(&node_a, &request);
                swarm_a
                    .behaviour_mut()
                    .bitswap
                    .send_response(channel, response)
                    .expect("send response");
            }
        }
    });

    // Node B does NOT have the block locally.
    let node_b = pillar_ipfs::IpfsNode::in_memory();
    assert!(!node_b.has_block(&cid).expect("has_block on B"));

    let mut swarm_b = build_ipfs_swarm(Keypair::generate_ed25519(), root).expect("build swarm B");
    swarm_b
        .dial(addr_a.with(Protocol::P2p(peer_a)))
        .expect("dial A");

    let backfilled = timeout(Duration::from_secs(15), async {
        loop {
            match swarm_b.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_a => {
                    swarm_b
                        .behaviour_mut()
                        .bitswap
                        .send_request(&peer_a, BlockRequest { cid: cid.clone() });
                }
                SwarmEvent::Behaviour(IpfsSwarmBehaviourEvent::Bitswap(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) => {
                    let bytes = response.bytes.expect("A had the block");
                    // B re-verifies the received bytes against the CID it
                    // asked for BEFORE ever storing them.
                    node_b
                        .put_block_checked(&cid, &bytes)
                        .expect("bytes must verify against the requested CID");
                    return bytes;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("backfilled the missing segment over the private swarm");

    assert_eq!(backfilled, block);
    assert!(
        node_b.has_block(&cid).expect("has_block on B after backfill"),
        "node B must hold the block locally after backfill"
    );
    assert_eq!(
        node_b.get_block(&cid).expect("get on B").as_deref(),
        Some(&block[..])
    );
}

/// The IPNS-format mutable head resolves to the latest valid sequence: a
/// stale (lower-sequence) candidate and a forged (signature-mismatched)
/// candidate never win, matching `HeadSequenceMonotonic` /
/// `HeadSignedByOwner` in `specs/StreamdbIpfsStore.tla`.
#[test]
fn ipns_head_resolves_to_latest_sequence_rejecting_stale_or_forged() {
    let (owner_pk, owner_sk) =
        sign::signing_keypair_from_seed(&Seed::from_bytes(b"ipns-head-owner-seed".to_vec()))
            .expect("keygen");
    let (mallory_pk, mallory_sk) =
        sign::signing_keypair_from_seed(&Seed::from_bytes(b"ipns-head-mallory-seed".to_vec()))
            .expect("keygen");

    let now = now_unix();
    let far_future = now + 10_000;

    let stale = IpnsHead::sign(
        &owner_sk,
        owner_pk.clone(),
        1,
        content_id(b"root-v1"),
        far_future,
        Visibility::Public,
    );
    let latest = IpnsHead::sign(
        &owner_sk,
        owner_pk.clone(),
        2,
        content_id(b"root-v2"),
        far_future,
        Visibility::Public,
    );
    // A forged candidate: signed by mallory's key, but claiming a higher
    // sequence AND the genuine owner's public key.
    let mut forged = IpnsHead::sign(
        &mallory_sk,
        mallory_pk,
        99,
        content_id(b"root-forged"),
        far_future,
        Visibility::Public,
    );
    forged.owner = owner_pk.clone();

    let winner = resolve_latest(&[stale.clone(), latest.clone(), forged], now)
        .expect("a genuine candidate must win");

    assert_eq!(winner, latest, "the highest genuinely-signed sequence must win");
    assert_ne!(winner.sequence, stale.sequence, "the stale sequence must not win");
    assert_ne!(
        winner.cid,
        content_id(b"root-forged"),
        "the forged head must never win"
    );
    assert_eq!(winner.owner, owner_pk);
}
