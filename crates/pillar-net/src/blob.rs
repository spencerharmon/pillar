//! Content-addressed blob / OCI-layer distribution over the libp2p transport.
//!
//! A blob is an opaque byte payload (an OCI image layer, an artifact, …)
//! identified by its [`BlobDigest`] — the content address derived by
//! [`pillar_streamdb::content_address`], the *same* canonical
//! bytes-to-identity function the streamdb op-log uses. Reusing that function
//! is the whole point: a blob's identity is a pure function of its bytes, so
//! any two nodes agree on a blob's digest without coordination, exactly as
//! they do for op ids.
//!
//! Distribution is a libp2p request/response protocol: a peer asks another
//! peer for the bytes of a digest, and the answering peer serves them from its
//! local [`BlobStore`]. The requester independently recomputes the digest of
//! the bytes it received and REJECTS them unless they match what it asked for
//! — a peer can never be tricked into accepting the wrong content for a
//! digest, because the digest is verifiable from the bytes alone.

use std::collections::HashMap;

use libp2p::{
    identity::Keypair, noise, request_response, swarm::NetworkBehaviour, tcp, yamux, PeerId,
    StreamProtocol, Swarm,
};
use pillar_streamdb::content_address;
use serde::{Deserialize, Serialize};

/// libp2p protocol name for the blob-fetch request/response exchange.
pub const BLOB_PROTOCOL_NAME: &str = "/pillar/blob/1.0.0";

/// The content address of a blob: a pure function of its bytes, computed with
/// the streamdb content-addressing function (a real SHA2-256 multihash) so
/// blob identities are canonical AND collision-resistant across every Pillar
/// layer — an adversary cannot forge a distinct blob sharing a digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobDigest(pub pillar_streamdb::OpId);

impl BlobDigest {
    /// The raw multihash bytes of this digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Derive the digest of `bytes` via the shared content-addressing function.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        BlobDigest(pillar_streamdb::OpId(content_address(bytes)))
    }

    /// Whether `bytes` actually hash to this digest.
    #[must_use]
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        BlobDigest::of(bytes) == *self
    }
}

impl PartialOrd for BlobDigest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BlobDigest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}
impl Serialize for BlobDigest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().to_vec().serialize(s)
    }
}
impl<'de> Deserialize<'de> for BlobDigest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        Ok(BlobDigest(pillar_streamdb::OpId(
            pillar_crypto::ContentId::from_bytes(bytes),
        )))
    }
}

/// A request for the bytes of a blob, addressed purely by its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRequest {
    /// The content address of the wanted blob.
    pub digest: BlobDigest,
}

/// The answer to a [`BlobRequest`]: the blob's bytes if the answering peer
/// holds it, or `None` if it does not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobResponse {
    /// The blob's bytes, present iff the peer had the requested digest.
    pub bytes: Option<Vec<u8>>,
}

/// An in-memory content-addressed store of blobs, keyed by digest.
///
/// Insertion derives the key from the bytes, so a store can never map a digest
/// to bytes that do not hash to it.
#[derive(Debug, Default, Clone)]
pub struct BlobStore {
    blobs: HashMap<BlobDigest, Vec<u8>>,
}

impl BlobStore {
    /// A new, empty store.
    #[must_use]
    pub fn new() -> Self {
        BlobStore::default()
    }

    /// Insert `bytes`, returning the digest it is now addressable by.
    pub fn insert(&mut self, bytes: impl Into<Vec<u8>>) -> BlobDigest {
        let bytes = bytes.into();
        let digest = BlobDigest::of(&bytes);
        self.blobs.insert(digest.clone(), bytes);
        digest
    }

    /// Fetch a blob's bytes by digest, if present.
    #[must_use]
    pub fn get(&self, digest: &BlobDigest) -> Option<&[u8]> {
        self.blobs.get(digest).map(Vec::as_slice)
    }

    /// Whether the store holds the given digest.
    #[must_use]
    pub fn contains(&self, digest: &BlobDigest) -> bool {
        self.blobs.contains_key(digest)
    }

    /// Number of distinct blobs held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Answer a request from this store (serves the bytes iff held).
    #[must_use]
    pub fn answer(&self, request: &BlobRequest) -> BlobResponse {
        BlobResponse {
            bytes: self.get(&request.digest).map(<[u8]>::to_vec),
        }
    }
}

/// The behaviour run by a node participating in blob distribution: a single
/// request/response protocol carrying [`BlobRequest`]/[`BlobResponse`] pairs,
/// CBOR-encoded on the wire.
#[derive(NetworkBehaviour)]
pub struct BlobBehaviour {
    /// The blob-fetch request/response protocol.
    pub blob: request_response::cbor::Behaviour<BlobRequest, BlobResponse>,
}

fn blob_request_response() -> request_response::cbor::Behaviour<BlobRequest, BlobResponse> {
    request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(BLOB_PROTOCOL_NAME),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

/// Builds a [`Swarm`] running [`BlobBehaviour`] over TCP and QUIC, using the
/// supplied identity.
pub fn build_blob_swarm(
    keypair: Keypair,
) -> Result<Swarm<BlobBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|_key| BlobBehaviour {
            blob: blob_request_response(),
        })?
        .build();
    Ok(swarm)
}

/// Convenience: the [`PeerId`] a [`Keypair`] resolves to.
#[must_use]
pub fn blob_peer_id_of(keypair: &Keypair) -> PeerId {
    keypair.public().to_peer_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::core::multiaddr::{Multiaddr, Protocol};
    use libp2p::swarm::SwarmEvent;
    use std::time::Duration;
    use tokio::time::timeout;

    fn local_tcp_listen_addr() -> Multiaddr {
        Multiaddr::empty()
            .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
            .with(Protocol::Tcp(0))
    }

    #[test]
    fn digest_is_content_addressed_and_verifies() {
        let bytes = b"an-oci-layer-blob".to_vec();
        let digest = BlobDigest::of(&bytes);
        // Same bytes -> same digest (pure function), and it uses the shared
        // streamdb content-addressing.
        assert_eq!(digest, BlobDigest::of(&bytes));
        assert_eq!(digest.0, pillar_streamdb::OpId(content_address(&bytes)));
        assert!(digest.verifies(&bytes));
        // Different bytes must not verify against the digest.
        assert!(!digest.verifies(b"tampered-bytes"));
    }

    #[test]
    fn store_keys_by_content_address() {
        let mut store = BlobStore::new();
        let digest = store.insert(b"layer".to_vec());
        assert!(store.contains(&digest));
        assert_eq!(store.get(&digest), Some(&b"layer"[..]));
        assert!(digest.verifies(store.get(&digest).unwrap()));
        // A digest we never inserted is absent, and answering yields None.
        let absent = BlobDigest::of(b"not-here");
        assert!(!store.contains(&absent));
        assert_eq!(store.answer(&BlobRequest { digest: absent }).bytes, None);
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

    /// End-to-end: a provider peer holds a blob; a fetcher peer dials it,
    /// requests the blob purely by digest, receives the bytes, and verifies
    /// those bytes hash back to the digest it asked for.
    #[tokio::test]
    async fn peer_fetches_blob_by_digest_and_verifies() {
        // Provider holds the blob.
        let mut provider = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
        let provider_peer_id = *provider.local_peer_id();
        let blob_bytes = b"content-addressed-oci-layer-payload".to_vec();
        let digest = BlobDigest::of(&blob_bytes);

        let mut store = BlobStore::new();
        assert_eq!(store.insert(blob_bytes.clone()), digest);

        let provider_addr = listen_and_get_addr(&mut provider).await;

        // Drive the provider in the background: it answers any inbound blob
        // request from its store.
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

        // Fetcher dials the provider and requests the blob by digest only.
        let mut fetcher = build_blob_swarm(Keypair::generate_ed25519()).unwrap();
        fetcher
            .dial(provider_addr.with(Protocol::P2p(provider_peer_id)))
            .unwrap();

        // Once connected, issue the request.
        timeout(Duration::from_secs(15), async {
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
                        let bytes = response.bytes.expect("provider had the blob");
                        // The received bytes MUST verify against the digest we
                        // asked for — this is the content-addressing guarantee.
                        assert!(
                            digest.verifies(&bytes),
                            "fetched bytes must hash to the requested digest"
                        );
                        assert_eq!(bytes, blob_bytes);
                        return;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("fetched and verified blob by digest");
    }
}
