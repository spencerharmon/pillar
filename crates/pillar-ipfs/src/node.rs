//! The embeddable IPFS node: a content-addressed blockstore plus the pin and
//! provide sets that make blocks durable and (in the coming network layer)
//! discoverable.

use std::path::Path;

use pillar_crypto::ContentId;

use crate::blockstore::{
    Blockstore, FsBlockstore, FsMarkerSet, MarkerSet, MemBlockstore, MemMarkerSet,
};
use crate::cid::content_id;
use crate::error::IpfsError;

/// Pillar's own IPFS node, embedded in-process (no external daemon).
///
/// It owns three sets over real IPFS [`ContentId`]s: the immutable
/// content-addressed **blockstore**, the **pin** set (blocks kept durable,
/// never garbage-collected — the node's durable content on boot), and the
/// **provide** set (public anchors this node advertises; the bookkeeping the
/// network layer's Kademlia `Provide` publishes).
///
/// A durable node ([`IpfsNode::open`]) persists all three to the PVC and
/// rehydrates from them on restart; an ephemeral node ([`IpfsNode::in_memory`])
/// keeps them in memory for peers and tests.
#[derive(Debug)]
pub struct IpfsNode {
    blocks: Box<dyn Blockstore>,
    pins: Box<dyn MarkerSet>,
    provides: Box<dyn MarkerSet>,
}

impl IpfsNode {
    /// Open a **durable** node rooted at `root` on the PVC, creating the layout
    /// (`blocks/`, `pins/`, `provides/`) if absent. A restarting node reopens
    /// the same root and finds its pinned blocks intact.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the store directories cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, IpfsError> {
        let root = root.as_ref();
        Ok(IpfsNode {
            blocks: Box::new(FsBlockstore::open(root.join("blocks"))?),
            pins: Box::new(FsMarkerSet::open(root.join("pins"))?),
            provides: Box::new(FsMarkerSet::open(root.join("provides"))?),
        })
    }

    /// A non-durable node holding everything in memory (ephemeral peers, tests).
    #[must_use]
    pub fn in_memory() -> Self {
        IpfsNode {
            blocks: Box::new(MemBlockstore::new()),
            pins: Box::new(MemMarkerSet::new()),
            provides: Box::new(MemMarkerSet::new()),
        }
    }

    /// Compose a node from arbitrary backings (advanced / testing).
    #[must_use]
    pub fn from_parts(
        blocks: Box<dyn Blockstore>,
        pins: Box<dyn MarkerSet>,
        provides: Box<dyn MarkerSet>,
    ) -> Self {
        IpfsNode {
            blocks,
            pins,
            provides,
        }
    }

    /// Store an immutable block, returning its content id. The id is derived
    /// from the bytes (never supplied by the caller), so a block can only ever
    /// be filed under the CID its bytes actually produce. Idempotent.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the block cannot be written.
    pub fn put_block(&self, block: &[u8]) -> Result<ContentId, IpfsError> {
        let id = content_id(block);
        self.blocks.put(&id, block)?;
        Ok(id)
    }

    /// Store a block whose expected id the caller already computed, verifying
    /// the bytes hash to `expected` before storing. Rejects a mismatch with
    /// [`IpfsError::CidMismatch`] — the integrity gate for a block received from
    /// a peer (backfill) or read back from disk.
    ///
    /// # Errors
    /// [`IpfsError::CidMismatch`] if `block` does not hash to `expected`;
    /// [`IpfsError::Io`] if the block cannot be written.
    pub fn put_block_checked(&self, expected: &ContentId, block: &[u8]) -> Result<(), IpfsError> {
        if content_id(block) != *expected {
            return Err(IpfsError::CidMismatch);
        }
        self.blocks.put(expected, block)
    }

    /// Fetch a block's bytes from the local store, or `Ok(None)` if not held.
    /// The bytes are re-verified against `id` before return, so a corrupt
    /// on-disk block is reported as [`IpfsError::CidMismatch`] rather than
    /// silently served.
    ///
    /// # Errors
    /// [`IpfsError::CidMismatch`] if a stored block no longer hashes to `id`;
    /// [`IpfsError::Io`] if the store cannot be read.
    pub fn get_block(&self, id: &ContentId) -> Result<Option<Vec<u8>>, IpfsError> {
        match self.blocks.get(id)? {
            None => Ok(None),
            Some(bytes) => {
                if content_id(&bytes) != *id {
                    return Err(IpfsError::CidMismatch);
                }
                Ok(Some(bytes))
            }
        }
    }

    /// Whether the block is held in the local store.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the store cannot be read.
    pub fn has_block(&self, id: &ContentId) -> Result<bool, IpfsError> {
        self.blocks.has(id)
    }

    /// Pin a block durable (never garbage-collected).
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the pin cannot be persisted.
    pub fn pin(&self, id: &ContentId) -> Result<(), IpfsError> {
        self.pins.insert(id)
    }

    /// The set of pinned CIDs — the node's durable content on boot.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the pin set cannot be enumerated.
    pub fn pinned(&self) -> Result<Vec<ContentId>, IpfsError> {
        self.pins.list()
    }

    /// Mark a public-anchor block as provided (advertised). The network layer
    /// republishes this set to Kademlia; today it is durable bookkeeping.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the marker cannot be persisted.
    pub fn provide(&self, id: &ContentId) -> Result<(), IpfsError> {
        self.provides.insert(id)
    }

    /// The set of CIDs this node advertises (public anchors).
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the provide set cannot be enumerated.
    pub fn provided(&self) -> Result<Vec<ContentId>, IpfsError> {
        self.provides.list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(node: &IpfsNode) {
        let block = b"a pillar signed segment's wire bytes".to_vec();
        let id = node.put_block(&block).expect("put");
        assert!(node.has_block(&id).unwrap());
        assert_eq!(node.get_block(&id).unwrap().as_deref(), Some(&block[..]));

        node.pin(&id).expect("pin");
        assert_eq!(node.pinned().unwrap(), vec![id.clone()]);

        node.provide(&id).expect("provide");
        assert_eq!(node.provided().unwrap(), vec![id.clone()]);

        // A block that does not hash to the claimed id is refused.
        assert_eq!(
            node.put_block_checked(&content_id(b"other"), &block),
            Err(IpfsError::CidMismatch)
        );
    }

    #[test]
    fn in_memory_node_round_trips_blocks_pins_and_provides() {
        roundtrip(&IpfsNode::in_memory());
    }

    #[test]
    fn durable_node_survives_reopen_from_disk() {
        let dir = std::env::temp_dir().join(format!("pillar-ipfs-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let block = b"durable segment".to_vec();
        let id = {
            let node = IpfsNode::open(&dir).expect("open");
            let id = node.put_block(&block).expect("put");
            node.pin(&id).expect("pin");
            id
        };

        // A fresh handle on the same root rehydrates the pinned block.
        let reopened = IpfsNode::open(&dir).expect("reopen");
        assert_eq!(reopened.pinned().unwrap(), vec![id.clone()]);
        assert_eq!(
            reopened.get_block(&id).unwrap().as_deref(),
            Some(&block[..])
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
