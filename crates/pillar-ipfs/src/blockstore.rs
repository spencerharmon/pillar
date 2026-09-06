//! The content-addressed block store and the durable marker sets (pins,
//! provides) that back an [`crate::IpfsNode`].
//!
//! Two backings, one behaviour: [`FsBlockstore`] / [`FsMarkerSet`] persist to a
//! directory on the node's PVC (blocks named by their real CIDv1 string, so the
//! on-disk store is legible as real IPFS blocks); [`MemBlockstore`] /
//! [`MemMarkerSet`] keep state in memory for ephemeral peers and unit tests.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use pillar_crypto::ContentId;

use crate::cid::{from_cidv1_raw, to_cidv1_raw};
use crate::error::{io_err, IpfsError};

/// A content-addressed immutable block store: bytes in, addressed by their
/// [`ContentId`]. Implementations MUST be safe for concurrent use.
pub trait Blockstore: Send + Sync + std::fmt::Debug {
    /// Store `block` under `id`. Idempotent; the caller (the node) has already
    /// verified `id` is the content address of `block`.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the block cannot be written.
    fn put(&self, id: &ContentId, block: &[u8]) -> Result<(), IpfsError>;

    /// Fetch a block's bytes from the local store, or `Ok(None)` if absent.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the store cannot be read.
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, IpfsError>;

    /// Whether the block is held locally (no network).
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the store cannot be read.
    fn has(&self, id: &ContentId) -> Result<bool, IpfsError>;
}

/// A durable set of [`ContentId`]s — the node's pin set or provide set.
pub trait MarkerSet: Send + Sync + std::fmt::Debug {
    /// Add `id` to the set. Idempotent.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the marker cannot be persisted.
    fn insert(&self, id: &ContentId) -> Result<(), IpfsError>;

    /// The full set, for rebuild on boot.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the set cannot be enumerated.
    fn list(&self) -> Result<Vec<ContentId>, IpfsError>;
}

// ---------------------------------------------------------------------------
// On-disk backing.
// ---------------------------------------------------------------------------

/// A durable block store rooted at a directory on the node's PVC. Each block is
/// one file named by its real CIDv1(`raw`) string, so the directory is a set of
/// real IPFS blocks a reference node could import unchanged.
#[derive(Debug, Clone)]
pub struct FsBlockstore {
    dir: PathBuf,
}

impl FsBlockstore {
    /// Open (creating it if absent) a block store at `dir`.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, IpfsError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        Ok(FsBlockstore { dir })
    }

    fn path(&self, id: &ContentId) -> PathBuf {
        self.dir.join(format!("{}.block", to_cidv1_raw(id)))
    }
}

impl Blockstore for FsBlockstore {
    fn put(&self, id: &ContentId, block: &[u8]) -> Result<(), IpfsError> {
        let path = self.path(id);
        if !path.exists() {
            let tmp = path.with_extension("block.tmp");
            std::fs::write(&tmp, block).map_err(io_err)?;
            std::fs::rename(&tmp, &path).map_err(io_err)?;
        }
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, IpfsError> {
        match std::fs::read(self.path(id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    fn has(&self, id: &ContentId) -> Result<bool, IpfsError> {
        Ok(self.path(id).exists())
    }
}

/// A durable marker set backed by empty files named by CIDv1 string in a
/// directory on the PVC.
#[derive(Debug, Clone)]
pub struct FsMarkerSet {
    dir: PathBuf,
}

impl FsMarkerSet {
    /// Open (creating it if absent) a marker set at `dir`.
    ///
    /// # Errors
    /// [`IpfsError::Io`] if the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, IpfsError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        Ok(FsMarkerSet { dir })
    }
}

impl MarkerSet for FsMarkerSet {
    fn insert(&self, id: &ContentId) -> Result<(), IpfsError> {
        let path = self.dir.join(to_cidv1_raw(id));
        if !path.exists() {
            std::fs::write(&path, []).map_err(io_err)?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<ContentId>, IpfsError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(io_err)? {
            let name = entry.map_err(io_err)?.file_name();
            if let Some(id) = name.to_str().and_then(from_cidv1_raw) {
                out.push(id);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// In-memory backing.
// ---------------------------------------------------------------------------

/// An in-memory block store for ephemeral peers and unit tests.
#[derive(Debug, Default)]
pub struct MemBlockstore {
    blocks: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemBlockstore {
    /// A new, empty in-memory block store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Blockstore for MemBlockstore {
    fn put(&self, id: &ContentId, block: &[u8]) -> Result<(), IpfsError> {
        self.blocks
            .lock()
            .expect("MemBlockstore mutex poisoned")
            .insert(id.as_bytes().to_vec(), block.to_vec());
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, IpfsError> {
        Ok(self
            .blocks
            .lock()
            .expect("MemBlockstore mutex poisoned")
            .get(id.as_bytes())
            .cloned())
    }

    fn has(&self, id: &ContentId) -> Result<bool, IpfsError> {
        Ok(self
            .blocks
            .lock()
            .expect("MemBlockstore mutex poisoned")
            .contains_key(id.as_bytes()))
    }
}

/// An in-memory marker set for ephemeral peers and unit tests.
#[derive(Debug, Default)]
pub struct MemMarkerSet {
    set: Mutex<HashSet<Vec<u8>>>,
}

impl MemMarkerSet {
    /// A new, empty in-memory marker set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl MarkerSet for MemMarkerSet {
    fn insert(&self, id: &ContentId) -> Result<(), IpfsError> {
        self.set
            .lock()
            .expect("MemMarkerSet mutex poisoned")
            .insert(id.as_bytes().to_vec());
        Ok(())
    }

    fn list(&self) -> Result<Vec<ContentId>, IpfsError> {
        Ok(self
            .set
            .lock()
            .expect("MemMarkerSet mutex poisoned")
            .iter()
            .map(|b| ContentId::from_bytes(b.clone()))
            .collect())
    }
}
