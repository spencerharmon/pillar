//! The durability seam that lets [`crate::ContentStore`] ride pillar's own
//! embeddable IPFS node ([`pillar_ipfs`]) instead of a hand-rolled in-process
//! map — with NO external daemon.
//!
//! The 2026-08-31 audit (ROI non-negotiable #7 / #5) requires the streaming
//! DB's durable persistence to ride an IPFS / libp2p content-object store —
//! pillar's OWN embeddable IPFS node — with the IPFS layer OWNING
//! content-addressing, never a bespoke local reimplementation and never an
//! external IPFS daemon. This module makes that literal: an [`IpfsBackend`] is
//! the abstract block/pin/provide/head substrate a [`crate::ContentStore`]
//! delegates to, with one production impl:
//!
//! - [`NativeIpfsBackend`] — a thin adapter over a [`pillar_ipfs::IpfsNode`]:
//!   segment blocks are real IPFS `raw` blocks addressed by real CIDv1s (proven
//!   against the reference implementation in `pillar-ipfs`'s kubo oracle test),
//!   `pin` keeps them durable on the PVC, and `provide` records the public
//!   anchors the node advertises. A solo node rehydrates purely from its own
//!   pinned blocks; cross-node block backfill (bitswap over pillar's private
//!   swarm) is the network layer being grown into [`pillar_ipfs::IpfsNode`].
//!
//! A pure in-memory store keeps NO backend (`ContentStore::new`): the map IS
//! the store, for fast unit tests and ephemeral peers.
//!
//! ## Where the mutable head lives
//! A block store is immutable/content-addressed; a stream's HEAD is a mutable,
//! owner-signed pointer (the IPNS-format [`HeadRecord`]). Pillar owns head
//! signing itself and persists the head RECORD locally (a tiny, inherently
//! node-local mutable pointer — exactly what IPNS is). The immutable content the
//! head points AT lives in the IPFS node; head propagation across nodes rides
//! pillar's own gossip. This matches the spec's `publishHead` (owner-signed,
//! monotone) precisely.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use pillar_ipfs::IpfsNode;

use crate::store::{hex_encode, io_store_err, Cid, HeadRecord, StoreError};

/// The abstract IPFS content-object substrate a [`crate::ContentStore`]
/// delegates its durability to. Every method is synchronous (the store surface
/// is sync); the backend is an in-process [`pillar_ipfs::IpfsNode`], so there is
/// no runtime and no daemon.
///
/// All content is addressed by [`Cid`] — the pillar SHA2-256 multihash, which
/// is exactly the multihash inside a real IPFS CIDv1 (`raw` codec), so a pillar
/// `Cid` and an IPFS CID are two encodings of the SAME identity.
pub trait IpfsBackend: std::fmt::Debug + Send + Sync {
    /// Store an immutable block. `cid` MUST equal the content address of
    /// `wire`; the node re-derives the CID from the bytes and returns
    /// [`StoreError::CidMismatch`] on disagreement, so a block can never be
    /// filed under an id its bytes do not hash to. Idempotent.
    fn block_put(&self, cid: &Cid, wire: &[u8]) -> Result<(), StoreError>;

    /// Fetch a block's bytes from the local blockstore, or `Ok(None)` if not
    /// held. The returned bytes are re-verified against `cid` by the node.
    fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError>;

    /// Whether the block is held in the LOCAL blockstore.
    fn block_has(&self, cid: &Cid) -> Result<bool, StoreError>;

    /// Pin a block durable (never garbage-collected).
    fn pin(&self, cid: &Cid) -> Result<(), StoreError>;

    /// The set of pinned (durable) CIDs — the node's durable content on boot.
    fn pinned(&self) -> Result<Vec<Cid>, StoreError>;

    /// Advertise a PUBLIC-anchor block so a lagging peer can discover a provider
    /// (`Provide` in the spec). Best-effort.
    fn provide(&self, cid: &Cid) -> Result<(), StoreError>;

    /// The set of CIDs this node has advertised as public anchors.
    fn provided(&self) -> Result<Vec<Cid>, StoreError>;

    /// Persist an owner-signed mutable head record (the IPNS-format pointer).
    /// Overwrite is correct: a head only ever advances (the store enforces
    /// monotonicity before calling this).
    fn put_head(&self, record: &HeadRecord) -> Result<(), StoreError>;

    /// Every persisted head record (one per owner), for reload on boot.
    fn heads(&self) -> Result<Vec<HeadRecord>, StoreError>;

    /// Whether this backend survives a process restart.
    fn is_durable(&self) -> bool;
}

fn ipfs_err(e: pillar_ipfs::IpfsError) -> StoreError {
    match e {
        pillar_ipfs::IpfsError::Io(kind) => StoreError::Io(kind),
        pillar_ipfs::IpfsError::CidMismatch => StoreError::CidMismatch,
    }
}

// ---------------------------------------------------------------------------
// NativeIpfsBackend — pillar's embedded IPFS node as the durability substrate.
// ---------------------------------------------------------------------------

/// The durability substrate: a [`pillar_ipfs::IpfsNode`] for content
/// (blocks/pins/provides) plus an owner-signed [`HeadStore`] for the mutable
/// IPNS-format head. Durable when opened on the PVC ([`Self::open`]);
/// in-memory for tests ([`Self::in_memory`]).
#[derive(Debug)]
pub struct NativeIpfsBackend {
    node: IpfsNode,
    heads: HeadStore,
}

impl NativeIpfsBackend {
    /// Open a durable node rooted at `root` on the PVC (content under
    /// `root`, heads under `root/heads`).
    ///
    /// # Errors
    /// [`StoreError::Io`] if the store layout cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        let node = IpfsNode::open(&root).map_err(ipfs_err)?;
        let heads = HeadStore::open(root.join("heads"))?;
        Ok(NativeIpfsBackend { node, heads })
    }

    /// A non-durable backend holding everything in memory (tests).
    #[must_use]
    pub fn in_memory() -> Self {
        NativeIpfsBackend {
            node: IpfsNode::in_memory(),
            heads: HeadStore::in_memory(),
        }
    }
}

impl IpfsBackend for NativeIpfsBackend {
    fn block_put(&self, cid: &Cid, wire: &[u8]) -> Result<(), StoreError> {
        self.node.put_block_checked(&cid.0, wire).map_err(ipfs_err)
    }

    fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.node.get_block(&cid.0).map_err(ipfs_err)
    }

    fn block_has(&self, cid: &Cid) -> Result<bool, StoreError> {
        self.node.has_block(&cid.0).map_err(ipfs_err)
    }

    fn pin(&self, cid: &Cid) -> Result<(), StoreError> {
        self.node.pin(&cid.0).map_err(ipfs_err)
    }

    fn pinned(&self) -> Result<Vec<Cid>, StoreError> {
        Ok(self
            .node
            .pinned()
            .map_err(ipfs_err)?
            .into_iter()
            .map(Cid)
            .collect())
    }

    fn provide(&self, cid: &Cid) -> Result<(), StoreError> {
        self.node.provide(&cid.0).map_err(ipfs_err)
    }

    fn provided(&self) -> Result<Vec<Cid>, StoreError> {
        Ok(self
            .node
            .provided()
            .map_err(ipfs_err)?
            .into_iter()
            .map(Cid)
            .collect())
    }

    fn put_head(&self, record: &HeadRecord) -> Result<(), StoreError> {
        self.heads.put(record)
    }

    fn heads(&self) -> Result<Vec<HeadRecord>, StoreError> {
        self.heads.list()
    }

    fn is_durable(&self) -> bool {
        self.heads.is_durable()
    }
}

// ---------------------------------------------------------------------------
// HeadStore — the owner-signed, IPNS-format mutable head pointer.
// ---------------------------------------------------------------------------

/// Persistence for the mutable, owner-signed head record (one per owner). A
/// head only advances; a write overwrites the owner's previous record.
#[derive(Debug)]
enum HeadStore {
    /// One length-prefixed record file per owner under a PVC directory.
    Fs(PathBuf),
    /// In-memory, keyed by owner bytes (tests / ephemeral peers).
    Mem(Mutex<HashMap<Vec<u8>, HeadRecord>>),
}

impl HeadStore {
    fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(io_store_err)?;
        Ok(HeadStore::Fs(dir))
    }

    fn in_memory() -> Self {
        HeadStore::Mem(Mutex::new(HashMap::new()))
    }

    fn is_durable(&self) -> bool {
        matches!(self, HeadStore::Fs(_))
    }

    fn put(&self, record: &HeadRecord) -> Result<(), StoreError> {
        match self {
            HeadStore::Fs(dir) => {
                let path = dir.join(hex_encode(record.owner().as_bytes()));
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, record.to_wire()).map_err(io_store_err)?;
                std::fs::rename(&tmp, &path).map_err(io_store_err)?;
                Ok(())
            }
            HeadStore::Mem(map) => {
                map.lock()
                    .expect("HeadStore mutex poisoned")
                    .insert(record.owner().as_bytes().to_vec(), record.clone());
                Ok(())
            }
        }
    }

    fn list(&self) -> Result<Vec<HeadRecord>, StoreError> {
        match self {
            HeadStore::Fs(dir) => {
                let mut out = Vec::new();
                for entry in std::fs::read_dir(dir).map_err(io_store_err)? {
                    let path = entry.map_err(io_store_err)?.path();
                    if !path.is_file() || path.extension().is_some_and(|e| e == "tmp") {
                        continue;
                    }
                    let w = std::fs::read(&path).map_err(io_store_err)?;
                    if let Some(head) = HeadRecord::from_wire(&w) {
                        out.push(head);
                    }
                }
                Ok(out)
            }
            HeadStore::Mem(map) => Ok(map
                .lock()
                .expect("HeadStore mutex poisoned")
                .values()
                .cloned()
                .collect()),
        }
    }
}

// ---------------------------------------------------------------------------
// CIDv1 (raw) string <-> pillar Cid — thin adapters over pillar-ipfs, kept for
// the streamdb-facing API surface and callers that need the on-the-wire string.
// ---------------------------------------------------------------------------

/// The CIDv1(`raw`) multibase-`base32` string (`bafkrei…`) for a pillar [`Cid`].
#[must_use]
pub fn cid_to_cidv1_raw(cid: &Cid) -> String {
    pillar_ipfs::to_cidv1_raw(&cid.0)
}

/// Parse a CIDv1(`raw`) multibase-`base32` string back to a pillar [`Cid`].
#[must_use]
pub fn cidv1_raw_to_cid(s: &str) -> Option<Cid> {
    pillar_ipfs::from_cidv1_raw(s).map(Cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Cid;

    #[test]
    fn cidv1_raw_round_trips_a_pillar_cid() {
        let cid = Cid::of(b"a pillar segment's wire bytes");
        let s = cid_to_cidv1_raw(&cid);
        assert!(
            s.starts_with("bafkrei"),
            "raw+sha2-256 CIDv1 is `bafkrei...`, got {s}"
        );
        assert_eq!(
            cidv1_raw_to_cid(&s),
            Some(cid),
            "CIDv1 string must round-trip"
        );
    }

    #[test]
    fn native_backend_persists_blocks_pins_and_heads() {
        let dir = std::env::temp_dir().join(format!("pillar-native-be-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let be = NativeIpfsBackend::open(&dir).expect("open");
        let wire = b"block-bytes".to_vec();
        let cid = Cid::of(&wire);
        be.block_put(&cid, &wire).expect("put");
        be.pin(&cid).expect("pin");
        assert!(be.block_has(&cid).unwrap());
        assert_eq!(be.block_get(&cid).unwrap().as_deref(), Some(&wire[..]));
        assert_eq!(be.pinned().unwrap(), vec![cid.clone()]);
        // A block filed under the wrong CID is refused.
        assert_eq!(
            be.block_put(&Cid::of(b"other"), &wire),
            Err(StoreError::CidMismatch)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
