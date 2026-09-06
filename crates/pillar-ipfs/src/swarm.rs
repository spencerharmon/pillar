//! The network layer: bitswap-style block exchange plus Kademlia provider
//! routing, run over pillar's OWN private libp2p swarm — never the public
//! IPFS DHT, never an external daemon.
//!
//! A block is requested purely by its real CIDv1 identity (see [`crate::cid`])
//! over a request/response protocol modelled on IPFS's bitswap (want a CID,
//! get back the bytes or "don't have it"); the requester independently
//! re-verifies the received bytes hash to the CID it asked for before ever
//! storing them, exactly as [`crate::IpfsNode::put_block_checked`] already
//! enforces. Kademlia provider records are the "who has this public anchor"
//! routing layer bitswap consults when a want is not satisfied by a directly
//! connected peer; both behaviours run over the SAME transport, wrapped in a
//! [`PrivateSwarmKey`] pre-shared-key handshake so a peer outside pillar's own
//! swarm root can never even complete the connection, let alone see a want or
//! answer one — the swarm this node speaks on is never the well-known public
//! IPFS/libp2p DHT.

use libp2p::{
    core::{muxing::StreamMuxerBox, upgrade::Version},
    identity::Keypair,
    kad, noise,
    pnet::{PnetConfig, PreSharedKey},
    request_response, tcp, yamux, PeerId, StreamProtocol, Swarm, Transport,
};
use pillar_crypto::ContentId;
use serde::{Deserialize, Serialize};

/// A libp2p private-swarm (pnet) pre-shared key, OFF by default.
///
/// A pnet key XORs a per-connection stream cipher over every transport byte,
/// so only peers holding the SAME key can complete a handshake at all — this
/// is what makes the IPFS network layer genuinely "pillar's own private
/// swarm, off the public DHT" rather than a policy enforced only above the
/// transport: a peer with a different (or no) root can never get far enough
/// to send a bitswap want or a Kademlia query. (Reimplemented locally rather
/// than taken as a `pillar-net` dependency — see the crate's `Cargo.toml`
/// comment for why that edge would be a dependency cycle; the derivation is
/// identical to `pillar_net::PrivateSwarmKey::from_root_secret` so a node
/// operator configures ONE root secret for both the event-log swarm and this
/// IPFS swarm and gets the same membership semantics on each.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateSwarmKey(pub Option<[u8; 32]>);

impl PrivateSwarmKey {
    /// The default: no private-swarm key (open transport). Only suitable for
    /// isolated unit tests; every real deployment configures a root.
    #[must_use]
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Derives a private-swarm pre-shared key from an operator-configured
    /// network root secret, via the same SHAKE256 derivation
    /// `pillar_net::PrivateSwarmKey` uses (a distinct domain-separation
    /// label, so the two crates' keys never collide even given the same root
    /// secret text).
    #[must_use]
    pub fn from_root_secret(root_secret: &str) -> Self {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut hasher = sha3::Shake256::default();
        hasher.update(b"pillar-ipfs-network-root-psk-v1");
        hasher.update(root_secret.as_bytes());
        let mut key = [0u8; 32];
        hasher.finalize_xof().read(&mut key);
        Self(Some(key))
    }
}

/// libp2p protocol name for the block-want/have exchange (pillar's bitswap
/// analogue).
pub const BITSWAP_PROTOCOL_NAME: &str = "/pillar/ipfs/bitswap/1.0.0";

/// Protocol name for the Kademlia instance routing provider records for
/// public-anchor CIDs — distinct from `pillar-net`'s general event-DHT
/// protocol name so an IPFS-layer swarm never cross-talks with the event-log
/// swarm even if the two happened to share a transport/root.
pub const IPFS_KAD_PROTOCOL_NAME: &str = "/pillar/ipfs/kad/1.0.0";

/// A want for a block, addressed purely by its real CID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    /// The content id of the wanted block.
    #[serde(with = "content_id_wire")]
    pub cid: ContentId,
}

/// The answer to a [`BlockRequest`]: the block's bytes if the answering peer
/// holds them locally, `None` otherwise ("don't have it" — bitswap's `HAVE`/
/// `DONT_HAVE` collapsed into one response since this is a direct want, not a
/// broadcast).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse {
    /// The requested block's bytes, present iff the peer had it.
    pub bytes: Option<Vec<u8>>,
}

/// [`ContentId`] is a foreign thin `Vec<u8>` newtype with no `serde` impl of
/// its own (the orphan rule forbids adding one here); this module is the
/// `#[serde(with = "...")]` shim that (de)serializes it as its raw bytes.
mod content_id_wire {
    use pillar_crypto::ContentId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(id: &ContentId, s: S) -> Result<S::Ok, S::Error> {
        id.as_bytes().to_vec().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ContentId, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        Ok(ContentId::from_bytes(bytes))
    }
}

/// The behaviour a networked IPFS node runs: the bitswap-style want/answer
/// protocol plus Kademlia for provider-record routing of public anchors.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct IpfsSwarmBehaviour {
    /// Direct block want/answer exchange.
    pub bitswap: request_response::cbor::Behaviour<BlockRequest, BlockResponse>,
    /// Provider-record routing for public anchor CIDs, on pillar's own
    /// private DHT instance (never the public IPFS DHT).
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

fn bitswap_behaviour() -> request_response::cbor::Behaviour<BlockRequest, BlockResponse> {
    request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(BITSWAP_PROTOCOL_NAME),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

fn kad_config() -> kad::Config {
    kad::Config::new(
        StreamProtocol::try_from_owned(IPFS_KAD_PROTOCOL_NAME.to_string())
            .expect("static protocol name is valid"),
    )
}

fn new_kademlia(peer_id: PeerId) -> kad::Behaviour<kad::store::MemoryStore> {
    let mut kademlia =
        kad::Behaviour::with_config(peer_id, kad::store::MemoryStore::new(peer_id), kad_config());
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
}

/// Builds a [`Swarm`] running [`IpfsSwarmBehaviour`], bound to `root`'s
/// configured [`PrivateSwarmKey`].
///
/// `root.is_enabled() == false` runs the OPEN transport (TCP+QUIC, no pnet
/// layer) — useful only for isolated unit tests; every real deployment
/// configures a root so the swarm's TRANSPORT itself refuses any peer outside
/// pillar's own network (the same guarantee `pillar_net::build_event_swarm_with_root`
/// documents), which is what makes this genuinely "pillar's own private
/// swarm, off the public DHT" rather than a policy pillar merely intends to
/// enforce at a higher layer.
///
/// # Errors
/// Propagates any libp2p transport/behaviour construction error.
pub fn build_ipfs_swarm(
    keypair: Keypair,
    root: PrivateSwarmKey,
) -> Result<Swarm<IpfsSwarmBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = match root.0 {
        None => libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();
                IpfsSwarmBehaviour {
                    bitswap: bitswap_behaviour(),
                    kademlia: new_kademlia(peer_id),
                }
            })?
            .build(),
        Some(key) => {
            let psk = PreSharedKey::new(key);
            libp2p::SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_other_transport(|kp| pnet_tcp_transport(kp, psk))?
                .with_behaviour(|key| {
                    let peer_id = key.public().to_peer_id();
                    IpfsSwarmBehaviour {
                        bitswap: bitswap_behaviour(),
                        kademlia: new_kademlia(peer_id),
                    }
                })?
                .build()
        }
    };
    Ok(swarm)
}

/// Answers a [`BlockRequest`] from `node`'s local blockstore — the bitswap
/// responder side every networked node runs for every inbound want.
#[must_use]
pub fn answer_block_request(node: &crate::IpfsNode, request: &BlockRequest) -> BlockResponse {
    BlockResponse {
        bytes: node.get_block(&request.cid).ok().flatten(),
    }
}

/// Builds a TCP transport wrapped in the pnet pre-shared-key handshake (below
/// noise/yamux), identical in shape to `pillar_net`'s private-swarm TCP leg:
/// a peer without the matching key never completes the pnet handshake at all,
/// so it can never reach far enough to send a bitswap want or a Kademlia
/// query.
fn pnet_tcp_transport(
    keypair: &Keypair,
    psk: PreSharedKey,
) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    let pnet_config = PnetConfig::new(psk);
    tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| pnet_config.handshake(socket))
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(keypair).expect("static noise config is valid"))
        .multiplex(yamux::Config::default())
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed()
}
