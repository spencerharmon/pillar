//! Pillar's own **embeddable IPFS node** — the real IPFS/libp2p content-object
//! primitive the streaming DB rides, implemented in-process with **no external
//! daemon** (no `kubo`, no sidecar, no HTTP RPC).
//!
//! ROI non-negotiables #5 (the IPFS/libp2p plugin OWNS content-addressing) and
//! #7 (durable persistence MUST ride IPFS) require pillar to build ON real IPFS
//! as a primitive rather than re-implement content-addressing under a pillar
//! name. This crate is that primitive, owned by pillar and embedded in the node
//! binary: content is addressed by a real **CIDv1** (`raw` codec, SHA2-256
//! multihash — the exact bytes-to-identity a reference IPFS node computes, see
//! [`cid`]), stored in a durable content-addressed [`Blockstore`], and made
//! durable / discoverable via [`IpfsNode`]'s pin and provide sets.
//!
//! # Interop, proven
//! Because a pillar [`pillar_crypto::ContentId`] is exactly the multihash inside
//! a CIDv1(`raw`), a block this node stores IS a real IPFS block: a reference
//! IPFS implementation given the same bytes computes the identical CID and can
//! address the block by the CID this node computed. `tests/kubo_interop.rs`
//! proves this against the `ipfs`/kubo CLI used purely as an external oracle —
//! kubo appears in a TEST only, never as a runtime dependency of this crate or
//! of pillar.
//!
//! # Layering (this crate grows the network in place)
//! Today this node is the **storage + addressing** layer: blockstore, pin set,
//! provide set — everything a solo node needs to persist its op-log durably and
//! rehydrate purely from its own IPFS-pinned blocks across a restart. The
//! **network** layer (a libp2p swarm: bitswap block exchange + Kademlia
//! provider routing, on pillar's OWN private swarm off the public DHT) is the
//! next layer, added to THIS node behind the same [`IpfsNode`] surface — the
//! [`IpfsNode::provide`] / [`IpfsNode::provided`] sets are already the anchor
//! bookkeeping that layer publishes. A consumer coding against [`IpfsNode`]
//! does not change when it gains the network.

mod blockstore;
mod cid;
mod error;
mod head;
mod node;
#[cfg(feature = "network")]
mod swarm;

pub use blockstore::{
    Blockstore, FsBlockstore, FsMarkerSet, MarkerSet, MemBlockstore, MemMarkerSet,
};
pub use cid::{content_id, from_cidv1_raw, to_cidv1_raw};
pub use error::IpfsError;
pub use head::{resolve_latest, HeadError, IpnsHead, Visibility};
pub use node::IpfsNode;
#[cfg(feature = "network")]
pub use swarm::{
    answer_block_request, build_ipfs_swarm, BlockRequest, BlockResponse, IpfsSwarmBehaviour,
    IpfsSwarmBehaviourEvent, PrivateSwarmKey, BITSWAP_PROTOCOL_NAME, IPFS_KAD_PROTOCOL_NAME,
};
