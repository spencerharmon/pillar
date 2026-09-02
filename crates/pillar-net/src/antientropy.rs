//! Anti-entropy log sync over the libp2p transport — the wire protocol that
//! carries [`pillar_eventlog`]'s range-based reconciliation between peers.
//!
//! Gossipsub ([`crate::EVENT_LOG_TOPIC`]) is best-effort: a partitioned or
//! freshly-joined node misses arbitrary event-log messages, leaving GAPS in its
//! Merkle-DAG. Anti-entropy is the background repair channel (ROI P1, "Event
//! order & integrity"): a peer advertises, per author, the height of the
//! contiguous prefix it holds ([`pillar_eventlog::LogDigest`]); the peer it asks
//! replies with EXACTLY the events beyond that height — the gap — in causal
//! order, and the requester ingests them to converge on the identical reachable
//! event set.
//!
//! This is a libp2p request/response protocol, modelled exactly like
//! [`crate::blob`]: a requester sends its digest, the answerer serves the
//! missing tail from its local [`pillar_eventlog::EventLog`], and — because
//! events are **content-addressed** — the requester's [`EventLog::ingest`]
//! independently re-verifies every event (signature, content id, `NoGaps`,
//! cross-author parents) before admitting it, so a peer can never be tricked
//! into accepting a forged or gap-inducing event. Only genuinely-missing events
//! cross the wire (range-based, deduplicated) — never the whole log.
//!
//! The end-to-end property (`AntiEntropy.tla`'s `Completeness`) is proven live
//! by `peer_with_gaps_converges_over_libp2p`: two swarms connect, the gapped
//! peer requests, and after the single round it holds the answerer's full set.

use libp2p::{
    identity::Keypair, noise, request_response, swarm::NetworkBehaviour, tcp, yamux, PeerId,
    StreamProtocol, Swarm,
};
use pillar_eventlog::{Event, EventLog, LogDigest};
use serde::{Deserialize, Serialize};

/// libp2p protocol name for the anti-entropy log-sync request/response exchange.
pub const ANTI_ENTROPY_PROTOCOL_NAME: &str = "/pillar/anti-entropy/1.0.0";

/// A sync request: the requester's compact per-author [`LogDigest`], describing
/// the contiguous prefix it already holds so the answerer can compute exactly
/// the gap to send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    /// The requester's per-author heights — everything it already holds.
    pub digest: LogDigest,
}

/// The answer to a [`SyncRequest`]: exactly the events the requester is missing,
/// in a causal (topological) order safe to ingest sequentially.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The missing events, causally ordered (`prev`/`parents` first).
    pub events: Vec<Event>,
}

/// Compute the answer to `request` from `log`: exactly the events `log` holds
/// that the requester (per its digest) is missing, causally ordered. Pure — the
/// answering half of a sync round, factored out so it is unit-testable without a
/// live swarm.
#[must_use]
pub fn answer_sync(log: &EventLog, request: &SyncRequest) -> SyncResponse {
    SyncResponse {
        events: log.events_missing_from(&request.digest),
    }
}

/// Ingest a received [`SyncResponse`] into `log`, applying the transferred
/// events in the causal order they arrived and returning the number newly
/// admitted. Each event is re-verified by [`EventLog::ingest`]; an already-held
/// event dedups to a no-op.
pub fn apply_sync(log: &mut EventLog, response: SyncResponse) -> usize {
    let before = log.len();
    for event in response.events {
        let _ = log.ingest(event);
    }
    log.len() - before
}

/// The behaviour run by a node participating in anti-entropy sync: a single
/// request/response protocol carrying [`SyncRequest`]/[`SyncResponse`] pairs,
/// CBOR-encoded on the wire.
#[derive(NetworkBehaviour)]
pub struct AntiEntropyBehaviour {
    /// The anti-entropy log-sync request/response protocol.
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}

fn anti_entropy_request_response() -> request_response::cbor::Behaviour<SyncRequest, SyncResponse> {
    request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(ANTI_ENTROPY_PROTOCOL_NAME),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

/// Builds a [`Swarm`] running [`AntiEntropyBehaviour`] over TCP and QUIC, using
/// the supplied identity.
pub fn build_anti_entropy_swarm(
    keypair: Keypair,
) -> Result<Swarm<AntiEntropyBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|_key| AntiEntropyBehaviour {
            sync: anti_entropy_request_response(),
        })?
        .build();
    Ok(swarm)
}

/// Convenience: the [`PeerId`] a [`Keypair`] resolves to.
#[must_use]
pub fn anti_entropy_peer_id_of(keypair: &Keypair) -> PeerId {
    keypair.public().to_peer_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::core::multiaddr::{Multiaddr, Protocol};
    use libp2p::swarm::SwarmEvent;
    use pillar_eventlog::Author;
    use std::collections::BTreeSet;
    use std::time::Duration;
    use tokio::time::timeout;

    fn author(name: &str) -> Author {
        Author(name.to_string())
    }

    /// Build a full replica with an interleaved cross-author DAG.
    fn full_log() -> EventLog {
        let alice = author("alice");
        let bob = author("bob");
        let mut log = EventLog::new();
        log.append(&alice, b"a0".to_vec());
        log.append(&bob, b"b0".to_vec());
        log.append(&alice, b"a1".to_vec());
        log.append(&bob, b"b1".to_vec());
        log.append(&alice, b"a2".to_vec());
        log
    }

    fn ids(log: &EventLog) -> BTreeSet<pillar_eventlog::EventId> {
        let mut out = BTreeSet::new();
        for a in ["alice", "bob"] {
            let author = author(a);
            let mut seq = 0;
            while let Some(ev) = log.event_at(&author, seq) {
                out.insert(ev.id());
                seq += 1;
            }
        }
        out
    }

    /// The pure answer/apply halves reconcile a gapped peer in one round.
    #[test]
    fn answer_then_apply_fills_the_gap() {
        let full = full_log();
        let mut gapped = EventLog::new();
        // gapped holds only alice's genesis.
        let alice = author("alice");
        gapped
            .ingest(full.event_at(&alice, 0).unwrap().clone())
            .unwrap();
        assert_ne!(ids(&gapped), ids(&full));

        let response = answer_sync(
            &full,
            &SyncRequest {
                digest: gapped.digest(),
            },
        );
        let admitted = apply_sync(&mut gapped, response);
        assert_eq!(admitted, full.len() - 1);
        assert_eq!(ids(&gapped), ids(&full), "converged after one round");
    }

    fn local_tcp_listen_addr() -> Multiaddr {
        Multiaddr::empty()
            .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
            .with(Protocol::Tcp(0))
    }

    async fn listen_and_get_addr(swarm: &mut Swarm<AntiEntropyBehaviour>) -> Multiaddr {
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

    /// End-to-end: an answerer peer holds the full event DAG; a gapped fetcher
    /// dials it, advertises its (near-empty) digest, receives exactly the
    /// missing events over libp2p, ingests them, and converges to the identical
    /// reachable event set — the live `Completeness` property.
    #[tokio::test]
    async fn peer_with_gaps_converges_over_libp2p() {
        // Answerer holds the full log.
        let mut answerer = build_anti_entropy_swarm(Keypair::generate_ed25519()).unwrap();
        let answerer_peer_id = *answerer.local_peer_id();
        let full = full_log();
        let full_ids = ids(&full);

        let answerer_addr = listen_and_get_addr(&mut answerer).await;

        // Drive the answerer in the background: it serves the missing tail from
        // its full log for any inbound sync request.
        tokio::spawn(async move {
            loop {
                let event = answerer.select_next_some().await;
                if let SwarmEvent::Behaviour(AntiEntropyBehaviourEvent::Sync(
                    request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) = event
                {
                    let response = answer_sync(&full, &request);
                    answerer
                        .behaviour_mut()
                        .sync
                        .send_response(channel, response)
                        .expect("send response");
                }
            }
        });

        // Gapped fetcher holds only alice's genesis.
        let mut fetcher_log = EventLog::new();
        {
            let source = full_log();
            let alice = author("alice");
            fetcher_log
                .ingest(source.event_at(&alice, 0).unwrap().clone())
                .unwrap();
        }
        assert_ne!(ids(&fetcher_log), full_ids);

        let mut fetcher = build_anti_entropy_swarm(Keypair::generate_ed25519()).unwrap();
        fetcher
            .dial(answerer_addr.with(Protocol::P2p(answerer_peer_id)))
            .unwrap();

        timeout(Duration::from_secs(20), async {
            loop {
                match fetcher.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. }
                        if peer_id == answerer_peer_id =>
                    {
                        fetcher.behaviour_mut().sync.send_request(
                            &answerer_peer_id,
                            SyncRequest {
                                digest: fetcher_log.digest(),
                            },
                        );
                    }
                    SwarmEvent::Behaviour(AntiEntropyBehaviourEvent::Sync(
                        request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        },
                    )) => {
                        let admitted = apply_sync(&mut fetcher_log, response);
                        assert!(admitted > 0, "the round transferred the missing events");
                        assert_eq!(
                            ids(&fetcher_log),
                            full_ids,
                            "fetcher converged to the identical reachable event set over libp2p"
                        );
                        return;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("gapped peer converged via anti-entropy over libp2p");
    }
}
