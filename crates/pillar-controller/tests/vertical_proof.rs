//! Vertical-proof integration test: substrate -> coordination -> view ->
//! controller -> workload, end to end, with the workload image pulled over the
//! REAL libp2p blob request/response substrate.
//!
//! A workload is declared on the streaming DB to run an OCI image on a peer.
//! A controller running on that peer reconciles the declaration: it is
//! admitted and capability-granted, the stream's view admits the exclusive
//! effect, and it holds the quorum-fenced lease for its epoch. Only then does
//! it dial a provider peer over libp2p, pull the image bytes purely by digest,
//! verify them, and run the workload. This is the P2 vertical proof in one
//! executable slice; the full cluster wiring lives privately in gitea.

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
use pillar_identity::{NodeSubkey, Registry, Signature, UserPrimary};
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

/// The whole vertical, executed: a declared exclusive workload is reconciled
/// by an authorized controller that holds the lease, and its image is pulled
/// over libp2p and verified before it runs.
#[tokio::test]
async fn vertical_proof_runs_declared_workload_over_libp2p() {
    let image_bytes = b"content-addressed-oci-image-for-vertical-proof".to_vec();
    let digest = BlobDigest::of(&image_bytes);

    // --- substrate: a provider peer holds the image blob, serving it by
    // digest over the libp2p blob request/response protocol.
    let mut provider = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
    let provider_peer_id = *provider.local_peer_id();
    let mut store = BlobStore::new();
    assert_eq!(store.insert(image_bytes.clone()), digest);
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

    // --- identity/controller layer: the controller node is admitted under a
    // registered primary and explicitly granted the run-workload capability.
    let mut identity = Registry::new();
    let primary = UserPrimary::from("operator-primary");
    let controller_key = NodeSubkey::from("vertical-proof-controller");
    identity.register(primary.clone());
    identity.issue_subkey(Signature::new(controller_key.clone(), primary));
    identity.handshake(&controller_key).unwrap();

    let mut caps = CapabilityRegistry::new();
    caps.grant(
        controller_key.clone(),
        Capability::from(RUN_WORKLOAD_CAPABILITY),
    );
    let controller = Controller::new(controller_key);

    // --- coordination layer: a 3-node cluster grants the controller the lease
    // for epoch 1 by majority.
    let epoch = Epoch(1);
    let mut lease = LeaseRegister::new(3);
    lease
        .grant(NodeId::from("voter-1"), controller.node(), epoch)
        .unwrap();
    lease
        .grant(NodeId::from("voter-2"), controller.node(), epoch)
        .unwrap();
    assert!(lease.try_acquire(&controller.node(), epoch));

    // --- view layer: the workload is declared as an op on a strict (CP)
    // stream, and read back through a view.
    let spec = WorkloadSpec::new(
        "singleton-web",
        controller.node(),
        digest,
        SideEffect::Exclusive,
    );
    let mut stream = Stream::new();
    stream
        .try_append(spec.encode(), spec.effect())
        .expect("strict stream admits the exclusive declaration");
    // Re-read the declaration from the stream's materialized view, proving the
    // controller acts on the streaming-DB record, not the in-memory spec.
    let view = stream.view();
    let stored = view
        .order()
        .into_iter()
        .next()
        .expect("declaration op present");
    let declared = WorkloadSpec::decode(stored.payload()).expect("declaration decodes");
    assert_eq!(declared, spec);

    // --- controller: run every non-network gate, yielding authorization to
    // pull the image.
    let admitted = controller
        .authorize_fetch(&identity, &caps, &lease, epoch, &view, &declared)
        .expect("every safety layer admits the workload");
    assert_eq!(admitted.digest(), digest);

    // --- substrate pull: the controller dials the provider and fetches the
    // authorized image digest over libp2p.
    let mut fetcher = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
    fetcher
        .dial(provider_addr.with(Protocol::P2p(provider_peer_id)))
        .unwrap();

    let fetched_bytes = timeout(Duration::from_secs(20), async {
        loop {
            match fetcher.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. }
                    if peer_id == provider_peer_id =>
                {
                    fetcher.behaviour_mut().blob.send_request(
                        &provider_peer_id,
                        BlobRequest {
                            digest: admitted.digest(),
                        },
                    );
                }
                SwarmEvent::Behaviour(BlobBehaviourEvent::Blob(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) => {
                    return response.bytes.expect("provider served the image");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("image pulled over libp2p");

    // --- workload: the controller verifies the pulled bytes against the
    // authorized digest and runs the workload, stamped with its epoch.
    let running = admitted
        .run(fetched_bytes)
        .expect("pulled image verifies and runs");
    assert_eq!(running.name(), "singleton-web");
    assert_eq!(running.node(), &controller.node());
    assert_eq!(running.image(), digest);
    assert_eq!(running.image_bytes(), image_bytes.as_slice());
    assert_eq!(running.epoch(), epoch);
}
