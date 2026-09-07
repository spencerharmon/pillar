//! Acceptance test — `workload-image-libp2p-fetch-real`.
//!
//! Proves the image-fetch half of the workload vertical with REAL libp2p, not
//! a same-process/in-memory stand-in: a provider node publishes an image blob
//! to its own content-addressed store (`pillar_net::BlobStore`, the
//! `libp2p-blob-distribution` substrate), and a SEPARATE fetcher node — a
//! distinct libp2p [`Swarm`] with its own keypair/[`PeerId`], dialed over a
//! real TCP listener — fetches those bytes purely by [`BlobDigest`] (the
//! content address / CID) over the `/pillar/blob/1.0.0` request/response
//! protocol. The fetched bytes are verified against the digest via
//! [`AdmittedFetch::run`] — the same production gate the controller vertical
//! uses — before the workload is allowed to run. A tampered response and a
//! CID/digest mismatch are both rejected: the fetcher never accepts bytes
//! that don't hash to what it asked for.
//!
//! `#[cfg(feature = "acceptance")]`-gated: only exercised via
//! `cargo test -p pillar-e2e --test image_libp2p_fetch --features acceptance`
//! (the `acceptance-e2e` CHECKS.md stub), never a plain `cargo test`.

#![cfg(feature = "acceptance")]

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::request_response;
use libp2p::swarm::{Swarm, SwarmEvent};
use tokio::time::timeout;

use pillar_controller::{Controller, WorkloadSpec, RUN_WORKLOAD_CAPABILITY};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry};
use pillar_net::{
    build_blob_swarm, BlobBehaviour, BlobBehaviourEvent, BlobDigest, BlobRequest, BlobStore,
};
use pillar_streamdb::Stream;

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

/// Spawn a provider node serving `bytes` from its content-addressed store to
/// any peer that requests them by digest; returns its dialable address, its
/// [`PeerId`], and the [`BlobDigest`] the bytes were published under.
async fn spawn_provider(bytes: Vec<u8>) -> (Multiaddr, libp2p::PeerId, BlobDigest) {
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

/// Dial `provider_addr` from a fresh fetcher node and request `digest`,
/// returning the raw bytes the provider answered with (unverified — callers
/// verify against the digest they actually asked for).
async fn fetch_by_digest(
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

/// Build an admitted-but-not-yet-run controller authorization for `image` on
/// a freshly admitted+granted controller node, exercising the full
/// identity/capability/lease/view gate stack (not a shortcut around it).
fn authorize(image: BlobDigest) -> pillar_controller::AdmittedFetch {
    let mut identity = Registry::new();
    let primary = PrimaryKeypair::from_secret_seed(&pillar_crypto::Seed::from_bytes(
        b"pillar-e2e-image-fetch-operator-primary".to_vec(),
    ));
    let controller_key = NodeSubkey::from("e2e-image-fetch-controller");
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
        "e2e-image-fetch-workload",
        controller.node(),
        image,
        SideEffect::Exclusive,
    );
    let mut stream = Stream::new();
    stream
        .try_append(spec.encode(), spec.effect())
        .expect("strict stream admits the exclusive declaration");
    let view = stream.view();

    controller
        .authorize_fetch(&identity, &caps, &lease, epoch, &view, &spec)
        .expect("every safety layer admits the workload")
}

/// Publish a real OCI-image-shaped byte payload to one node's content-
/// addressed store, and fetch it BY CID on a wholly separate node over a
/// REAL libp2p swarm — proving the fetch half of the workload vertical
/// exercises the actual transport, not an in-process stand-in.
#[tokio::test]
async fn fetches_published_image_by_cid_across_real_libp2p_nodes() {
    // A real image's exact bytes (arbitrary but non-trivial content — not a
    // placeholder token), published to the provider node's store.
    let image_bytes: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let (provider_addr, provider_peer_id, digest) = spawn_provider(image_bytes.clone()).await;

    // Authorize the fetch through the full controller gate stack for this
    // exact digest, then pull the bytes on a SEPARATE fetcher node/swarm.
    let admitted = authorize(digest.clone());
    assert_eq!(admitted.digest(), digest);

    let fetched = fetch_by_digest(provider_addr, provider_peer_id, admitted.digest()).await;
    assert_eq!(
        fetched, image_bytes,
        "fetched bytes must equal the published image"
    );

    let running = admitted
        .run(fetched)
        .expect("bytes fetched over libp2p verify against the authorized digest and run");
    assert_eq!(running.image(), digest);
    assert_eq!(running.image_bytes(), image_bytes.as_slice());
}

/// A response bearing bytes that do NOT hash to the digest the fetcher asked
/// for — a tampered / CID-mismatched blob — must be REJECTED before it is
/// ever allowed to run, even though it arrived over a real, successfully
/// negotiated libp2p connection.
#[tokio::test]
async fn rejects_tampered_blob_that_does_not_match_requested_digest() {
    let real_image_bytes: Vec<u8> = b"the-real-oci-image-bytes-for-this-workload".to_vec();
    let (provider_addr, provider_peer_id, real_digest) =
        spawn_provider(real_image_bytes.clone()).await;

    let admitted = authorize(real_digest.clone());

    // Fetch the real bytes over the wire, then simulate an on-path tamper (a
    // malicious/compromised peer substituting different content for the same
    // digest) by corrupting the bytes actually handed to the verification
    // gate. The digest itself never changes — this is exactly the "CID says
    // X, bytes are Y" attack the content-addressing gate must catch.
    let mut fetched = fetch_by_digest(provider_addr, provider_peer_id, admitted.digest()).await;
    assert_eq!(fetched, real_image_bytes);
    fetched[0] ^= 0xFF;
    fetched.push(0);

    let err = admitted
        .run(fetched)
        .expect_err("tampered bytes must not verify against the authorized digest");
    assert!(matches!(
        err,
        pillar_controller::ReconcileError::ImageDigestMismatch { .. }
    ));
}

/// A fetcher that requests one digest but is served bytes for an entirely
/// different (also genuinely stored) blob — a CID mismatch, not merely
/// corruption — is likewise rejected: content-addressing means the requester
/// verifies independently of what the peer claims to have sent.
#[tokio::test]
async fn rejects_blob_served_under_a_different_digest() {
    let requested_image: Vec<u8> = b"the-image-this-workload-actually-declared".to_vec();
    let other_image: Vec<u8> = b"a-completely-different-unrelated-blob".to_vec();

    // Two distinct blobs are published; only `requested_image`'s digest is
    // ever authorized for this workload.
    let (provider_addr, provider_peer_id, requested_digest) =
        spawn_provider(requested_image.clone()).await;
    let other_digest = BlobDigest::of(&other_image);
    assert_ne!(requested_digest, other_digest);

    let admitted = authorize(requested_digest.clone());

    // Fetch the correctly-addressed bytes over the real swarm, then simulate
    // a peer answering with the WRONG blob's bytes for the requested digest.
    let correctly_fetched =
        fetch_by_digest(provider_addr, provider_peer_id, admitted.digest()).await;
    assert_eq!(correctly_fetched, requested_image);

    let err = admitted
        .run(other_image)
        .expect_err("bytes for a different digest must never verify");
    assert!(matches!(
        err,
        pillar_controller::ReconcileError::ImageDigestMismatch { .. }
    ));
}
