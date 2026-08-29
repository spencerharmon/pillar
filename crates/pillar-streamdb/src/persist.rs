//! Durable, content-addressed backend for a [`Stream`].
//!
//! The in-memory [`OpLog`]/[`Stream`] is the proven Rust refinement of
//! `specs/StreamingDB.tla`. This module lands that SAME model onto a durable
//! backend under a `--data-dir` — **no protocol change**: the on-disk store is
//! purely an op cache whose identity is, exactly as in the CRDT, each op's
//! content address. Nothing about the wire model, the merge/gossip semantics,
//! the materialized order, or the Merkle root changes; a [`PersistentStream`]
//! is an [`OpLog`] whose ops also live on disk.
//!
//! # On-disk layout (content-addressed)
//!
//! Given a stream root `D` (`<data-dir>/streamdb/<stream-name>` in practice):
//!
//! ```text
//! D/ops/<content-address-hex>      one file per op, named by its content
//!                                  address; the file's bytes ARE the op payload
//! ```
//!
//! Because a file is named by [`content_address`] of its own bytes, the store
//! is content-addressed end to end: writing the same op twice targets the same
//! path with identical bytes (idempotent, matching the CRDT's idempotent
//! `Write`/merge), and two nodes that persist the same op set produce byte-for-
//! byte the same `ops/` directory. Loading is order-independent: the
//! materialized order and root are recomputed from the loaded *set*, never from
//! filesystem iteration order — so a reopened store converges to exactly the
//! view a continuously-gossiped peer holds (`NoLostWrite` / `DeterministicMerkleRoot`).
//!
//! # Durability discipline
//!
//! Each op is written to a per-op temp file and atomically `rename`d into place,
//! so a crash mid-write never leaves a partially-written op under its content
//! address (the reader would otherwise load bytes that hash to a different
//! address). A load VERIFIES every file: bytes whose content address does not
//! match the filename are rejected as corruption rather than silently admitted.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pillar_core::SideEffect;

use crate::{content_address, Op, OpId, PolicyViolation, Stream};
use pillar_core::ViewPolicy;

/// A [`Stream`] backed by a content-addressed on-disk op store.
///
/// Wraps an in-memory [`Stream`] (the proven CRDT) plus the directory the ops
/// are persisted under. Every accepted append is durably written before the
/// method returns; opening an existing directory reloads the full op set, so
/// the materialized view survives a restart unchanged.
#[derive(Debug)]
pub struct PersistentStream {
    stream: Stream,
    root_dir: PathBuf,
}

/// Where op files live under a stream root.
fn ops_dir(root: &Path) -> PathBuf {
    root.join("ops")
}

/// The content-addressed filename of an op: its address as fixed-width hex.
fn op_filename(id: OpId) -> String {
    format!("{:016x}", id.0)
}

impl PersistentStream {
    /// Open (creating if absent) a content-addressed op store rooted at
    /// `root_dir`, with no declared policy (safe-by-default `Strict`/CP).
    ///
    /// Any ops already present under `root_dir/ops/` are loaded, so the
    /// returned stream holds exactly the persisted op set and converges to the
    /// same materialized order/root it had before the process exited.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the directory cannot be created/read, or if
    /// a persisted op file's bytes do not match its content-addressed name
    /// (on-disk corruption).
    pub fn open(root_dir: impl Into<PathBuf>) -> Result<Self, PersistError> {
        Self::open_with(root_dir, None)
    }

    /// Open a content-addressed op store with an explicit declared policy.
    ///
    /// The policy is a local admission concern (never replicated, never
    /// persisted) — it governs only what THIS process admits, exactly as for an
    /// in-memory [`Stream`].
    ///
    /// # Errors
    ///
    /// As [`PersistentStream::open`].
    pub fn open_with_policy(
        root_dir: impl Into<PathBuf>,
        policy: ViewPolicy,
    ) -> Result<Self, PersistError> {
        Self::open_with(root_dir, Some(policy))
    }

    fn open_with(
        root_dir: impl Into<PathBuf>,
        policy: Option<ViewPolicy>,
    ) -> Result<Self, PersistError> {
        let root_dir = root_dir.into();
        let ops = ops_dir(&root_dir);
        fs::create_dir_all(&ops).map_err(|source| PersistError::Io {
            path: ops.clone(),
            source,
        })?;

        let mut stream = match policy {
            Some(p) => Stream::with_policy(p),
            None => Stream::new(),
        };

        // Load every persisted op, verifying its content address. Loading order
        // is irrelevant: the materialized order/root are recomputed from the
        // set, so append order here does not matter.
        for entry in fs::read_dir(&ops).map_err(|source| PersistError::Io {
            path: ops.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| PersistError::Io {
                path: ops.clone(),
                source,
            })?;
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|source| PersistError::Io {
                    path: path.clone(),
                    source,
                })?
                .is_file()
            {
                continue;
            }
            let bytes = fs::read(&path).map_err(|source| PersistError::Io {
                path: path.clone(),
                source,
            })?;
            let addr = content_address(&bytes);
            let expected = entry.file_name().to_string_lossy().into_owned();
            if op_filename(OpId(addr)) != expected {
                return Err(PersistError::Corrupt {
                    path,
                    expected,
                    actual: op_filename(OpId(addr)),
                });
            }
            // Re-appending is idempotent on the CRDT set; policy is not checked
            // on load since persisted ops were already admitted when written.
            stream.log_mut().append(bytes);
        }

        Ok(PersistentStream { stream, root_dir })
    }

    /// The stream root directory this store persists under.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// This store's effective view policy (declared or defaulted `Strict`).
    #[must_use]
    pub fn policy(&self) -> ViewPolicy {
        self.stream.policy()
    }

    /// Append `payload` as a fresh op, durably persisting it under its content
    /// address before returning, and refusing the write if this store's policy
    /// does not admit `effect`.
    ///
    /// Durability: the op is written to disk (atomically) before the in-memory
    /// set records it, so a returned [`OpId`] is a persisted op — a subsequent
    /// crash + [`PersistentStream::open`] reloads it. Idempotent: re-appending
    /// the same payload targets the same content-addressed file with identical
    /// bytes and leaves the set unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Policy`] if `effect` is not admitted (nothing is
    /// written), or [`PersistError::Io`] if the op cannot be persisted (in which
    /// case the in-memory set is left unchanged so disk and memory never
    /// diverge).
    pub fn append(
        &mut self,
        payload: impl Into<Vec<u8>>,
        effect: SideEffect,
    ) -> Result<OpId, PersistError> {
        let payload = payload.into();
        let policy = self.stream.policy();
        if !policy.admits(effect) {
            return Err(PersistError::Policy(PolicyViolation::new(policy, effect)));
        }
        let op = Op::new(payload.clone());
        // Persist FIRST: only record in memory once it is durably on disk.
        self.persist_op(op.id(), &payload)?;
        Ok(self.stream.log_mut().append(payload))
    }

    /// Merge another stream's ops into this store, persisting every newly
    /// admitted op durably. The CvRDT gossip join extended to the durable
    /// backend: after a merge the on-disk `ops/` set equals the merged
    /// in-memory set.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Io`] if any newly merged op cannot be persisted.
    pub fn merge_persistent(&mut self, other: &Stream) -> Result<(), PersistError> {
        for op in other.log().order() {
            if !self.stream.log().contains(op.id()) {
                self.persist_op(op.id(), op.payload())?;
            }
        }
        self.stream.merge(other);
        Ok(())
    }

    /// Borrow the underlying in-memory [`Stream`] for read access (view, order,
    /// root, log). Reads never touch disk — the in-memory set is authoritative
    /// and always equals the persisted set.
    #[must_use]
    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    /// Atomically write one op's payload under its content-addressed name.
    /// A write to a temp file + `rename` guarantees a reader never observes a
    /// partial file under a content address it does not hash to.
    fn persist_op(&self, id: OpId, payload: &[u8]) -> Result<(), PersistError> {
        let ops = ops_dir(&self.root_dir);
        let final_path = ops.join(op_filename(id));
        // Idempotent: an identical op already persisted needs no rewrite.
        if final_path.exists() {
            return Ok(());
        }
        let tmp_path = ops.join(format!("{}.tmp", op_filename(id)));
        fs::write(&tmp_path, payload).map_err(|source| PersistError::Io {
            path: tmp_path.clone(),
            source,
        })?;
        fs::rename(&tmp_path, &final_path).map_err(|source| PersistError::Io {
            path: final_path.clone(),
            source,
        })?;
        Ok(())
    }
}

/// A failure persisting or loading a [`PersistentStream`].
#[derive(Debug)]
pub enum PersistError {
    /// An I/O error touching a specific path.
    Io {
        /// The filesystem path the failing operation targeted.
        path: PathBuf,
        /// The underlying I/O failure.
        source: io::Error,
    },
    /// A persisted op file's bytes do not hash to its content-addressed name.
    Corrupt {
        /// The offending op file.
        path: PathBuf,
        /// The content-addressed filename the op was stored under.
        expected: String,
        /// The content address the file's actual bytes hash to.
        actual: String,
    },
    /// The requested append was refused by the store's view policy.
    Policy(PolicyViolation),
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistError::Io { path, source } => {
                write!(f, "streamdb persistence I/O error at {}: {source}", path.display())
            }
            PersistError::Corrupt {
                path,
                expected,
                actual,
            } => write!(
                f,
                "corrupt streamdb op at {}: content address {actual} does not match name {expected}",
                path.display()
            ),
            PersistError::Policy(v) => write!(f, "{v}"),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PersistError::Io { source, .. } => Some(source),
            PersistError::Corrupt { .. } => None,
            PersistError::Policy(v) => Some(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpLog;

    fn tmp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "pillar-streamdb-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        p
    }

    /// Durability: ops appended to a store, then dropped, are reloaded by a
    /// fresh `open` of the same directory — the reopened store holds exactly
    /// the same op set, materialized order, and Merkle root. This is the core
    /// persistence guarantee the task adds (`NoLostWrite` across a restart).
    #[test]
    fn appended_ops_survive_reopen_with_identical_view() {
        let root = tmp_root("reopen");
        let (ids, order_before, root_before);
        {
            let mut db = PersistentStream::open(&root).unwrap();
            let a = db.append(b"alpha".to_vec(), SideEffect::Exclusive).unwrap();
            let b = db.append(b"bravo".to_vec(), SideEffect::Convergent).unwrap();
            let c = db.append(b"charlie".to_vec(), SideEffect::Exclusive).unwrap();
            ids = vec![a, b, c];
            order_before = db
                .stream()
                .log()
                .order()
                .iter()
                .map(|op| op.id())
                .collect::<Vec<_>>();
            root_before = db.stream().log().root();
        } // db dropped — nothing but the on-disk store remains

        let reopened = PersistentStream::open(&root).unwrap();
        for id in &ids {
            assert!(reopened.stream().log().contains(*id));
        }
        assert_eq!(reopened.stream().log().len(), 3);
        assert_eq!(
            reopened
                .stream()
                .log()
                .order()
                .iter()
                .map(|op| op.id())
                .collect::<Vec<_>>(),
            order_before
        );
        assert_eq!(reopened.stream().log().root(), root_before);

        fs::remove_dir_all(&root).ok();
    }

    /// The store is content-addressed: each op is a file named by its content
    /// address, and that file's bytes ARE the payload (so it hashes to its own
    /// name). Two independent stores that persist the same op produce the same
    /// filename.
    #[test]
    fn on_disk_layout_is_content_addressed() {
        let root = tmp_root("layout");
        let mut db = PersistentStream::open(&root).unwrap();
        let id = db.append(b"payload".to_vec(), SideEffect::Exclusive).unwrap();

        let path = ops_dir(&root).join(op_filename(id));
        assert!(path.is_file(), "op stored under its content-addressed name");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, b"payload");
        assert_eq!(content_address(&bytes), id.0);

        fs::remove_dir_all(&root).ok();
    }

    /// Re-appending the same payload is idempotent on disk: it targets the same
    /// content-addressed file with identical bytes and does not grow the set,
    /// matching the CRDT's idempotent write/merge.
    #[test]
    fn reappend_is_idempotent_on_disk() {
        let root = tmp_root("idem");
        let mut db = PersistentStream::open(&root).unwrap();
        let id1 = db.append(b"dup".to_vec(), SideEffect::Exclusive).unwrap();
        let id2 = db.append(b"dup".to_vec(), SideEffect::Exclusive).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(db.stream().log().len(), 1);
        let file_count = fs::read_dir(ops_dir(&root))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().is_file())
            .count();
        assert_eq!(file_count, 1);

        fs::remove_dir_all(&root).ok();
    }

    /// A relaxed store refuses an exclusive effect and persists nothing — disk
    /// and memory stay empty, exactly as the in-memory `try_append` guarantees.
    #[test]
    fn relaxed_store_refuses_exclusive_and_persists_nothing() {
        let root = tmp_root("policy");
        let mut db =
            PersistentStream::open_with_policy(&root, ViewPolicy::Relaxed).unwrap();
        let err = db
            .append(b"fire".to_vec(), SideEffect::Exclusive)
            .unwrap_err();
        assert!(matches!(err, PersistError::Policy(_)));
        assert!(db.stream().log().is_empty());
        let file_count = fs::read_dir(ops_dir(&root)).unwrap().count();
        assert_eq!(file_count, 0);

        fs::remove_dir_all(&root).ok();
    }

    /// Loading verifies every op's content address: a file whose bytes do not
    /// hash to its name is rejected as corruption rather than silently loaded
    /// (a partial/tampered write can never masquerade as a valid op).
    #[test]
    fn corrupt_op_file_is_rejected_on_load() {
        let root = tmp_root("corrupt");
        {
            let mut db = PersistentStream::open(&root).unwrap();
            db.append(b"good".to_vec(), SideEffect::Exclusive).unwrap();
        }
        // Plant a file named for one address but holding different bytes.
        let bogus = ops_dir(&root).join(op_filename(OpId(0xdead_beef)));
        fs::write(&bogus, b"not-matching-bytes").unwrap();

        let err = PersistentStream::open(&root).unwrap_err();
        assert!(matches!(err, PersistError::Corrupt { .. }));

        fs::remove_dir_all(&root).ok();
    }

    /// A persistent store and a purely in-memory `OpLog` fed the same op set
    /// converge to the same materialized order and Merkle root — persistence is
    /// a durable cache of the proven CRDT, changing no protocol-visible value.
    #[test]
    fn persistent_store_matches_in_memory_oplog_view() {
        let root = tmp_root("match");
        let payloads: [&[u8]; 3] = [b"one", b"two", b"three"];

        let mut db = PersistentStream::open(&root).unwrap();
        for p in payloads {
            db.append(p.to_vec(), SideEffect::Exclusive).unwrap();
        }

        let mut mem = OpLog::new();
        // Feed the in-memory log in a DIFFERENT order to prove convergence is
        // over the set, not the append path.
        for p in payloads.iter().rev() {
            mem.append(p.to_vec());
        }

        assert_eq!(db.stream().log().root(), mem.root());
        assert_eq!(
            db.stream()
                .log()
                .order()
                .iter()
                .map(|op| op.id())
                .collect::<Vec<_>>(),
            mem.order().iter().map(|op| op.id()).collect::<Vec<_>>()
        );

        fs::remove_dir_all(&root).ok();
    }

    /// `merge_persistent` durably persists every newly merged op: after merging
    /// a peer's stream, reopening the store reloads the full merged set (the
    /// CvRDT gossip join lands on disk, not just in memory).
    #[test]
    fn merge_persists_new_ops_across_reopen() {
        let root = tmp_root("merge");
        {
            let mut db = PersistentStream::open(&root).unwrap();
            db.append(b"local".to_vec(), SideEffect::Exclusive).unwrap();

            let mut peer = Stream::new();
            peer.try_append(b"remote-1".to_vec(), SideEffect::Exclusive)
                .unwrap();
            peer.try_append(b"remote-2".to_vec(), SideEffect::Convergent)
                .unwrap();

            db.merge_persistent(&peer).unwrap();
            assert_eq!(db.stream().log().len(), 3);
        }

        let reopened = PersistentStream::open(&root).unwrap();
        assert_eq!(reopened.stream().log().len(), 3);

        fs::remove_dir_all(&root).ok();
    }
}
