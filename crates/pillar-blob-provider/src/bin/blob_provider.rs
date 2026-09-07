//! `blob_provider` — a standalone REAL libp2p blob-provider process for the
//! `pillar-integration` black-box scenario harness
//! (`scripts/pillar-integration/scenarios/workload-runtime.sh`).
//!
//! Serves ONE file's bytes as a real content-addressed blob over
//! `pillar_net`'s `/pillar/blob/1.0.0` request/response protocol, so a REAL
//! `pillar node run` process — running inside a container, linking NO test
//! code — can fetch it by CID over live libp2p through its
//! `PILLAR_TEST_WORKLOAD` boot hook. This binary is the harness's OWN
//! external process (its own crate, `pillar-blob-provider`, never linked into
//! `pillar_cli` or any scenario script), so the scenario stays black-box
//! about the node under test while still exercising the real wire protocol
//! end to end — the same provider-swarm-as-a-separate-process shape
//! `crates/pillar-e2e/tests/node_workload_runtime_wiring.rs` proves in-process
//! for its acceptance test, just run here as a genuinely separate OS process
//! so a bash harness can drive it without linking any pillar crate itself.
//!
//! Usage: `blob_provider <listen-tcp-port> <file-to-serve>`
//!
//! On success, prints exactly two lines once the real listener is bound and
//! the content is loaded, then serves forever until killed:
//!
//! ```text
//! PEER <peer-id>
//! DIGEST <64-hex-char content address>
//! ```

use futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use pillar_net::{build_blob_swarm, BlobBehaviourEvent, BlobStore};

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("usage: blob_provider <listen-tcp-port> <file-to-serve>")
        .parse()
        .expect("listen-tcp-port must be a valid u16");
    let path = args
        .next()
        .expect("usage: blob_provider <listen-tcp-port> <file-to-serve>");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));

    let mut swarm = build_blob_swarm(libp2p::identity::Keypair::generate_ed25519())
        .expect("build the real blob swarm");
    let peer_id = *swarm.local_peer_id();

    let listen_addr: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}")
        .parse()
        .expect("valid listen multiaddr");
    swarm
        .listen_on(listen_addr)
        .expect("bind the real listener");

    let mut store = BlobStore::new();
    let digest = store.insert(bytes);

    // Block until the real socket is actually bound before announcing
    // readiness to the harness watching our stdout.
    loop {
        if let SwarmEvent::NewListenAddr { .. } = swarm.select_next_some().await {
            break;
        }
    }

    println!("PEER {peer_id}");
    println!("DIGEST {}", encode_hex(digest.as_bytes()));
    use std::io::Write as _;
    std::io::stdout().flush().ok();

    // Serve every real content-address request over the wire, forever.
    loop {
        if let SwarmEvent::Behaviour(BlobBehaviourEvent::Blob(request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) = swarm.select_next_some().await
        {
            let response = store.answer(&request);
            let _ = swarm.behaviour_mut().blob.send_response(channel, response);
        }
    }
}
