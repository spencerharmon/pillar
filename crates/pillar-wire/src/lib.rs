//! `pillar-wire` — the shared-substrate crate for every byte Pillar persists
//! or transmits (design of record: `docs/papers/pillar-message-format.md`).
//!
//! Owns:
//!
//! - [`envelope::PillarMessage`] — the version-stamped envelope enum + its
//!   canonical (deterministic) CBOR codec + [`store::Cid`] derivation.
//! - [`seal`] — the convergent content-seal interface the envelope's sealed
//!   body rides (the trait; the deterministic-nonce crypto primitive itself
//!   lands in `pillar-crypto` via the `cell-seal-convergent-impl` task and
//!   this crate's [`seal::CellSeal`] switches to it then).
//! - [`store`] — `SignedSegment`/`Cid`/`HeadRecord`/`Visibility`/
//!   `ContentStore` — **moved down** from `pillar-streamdb` verbatim (no
//!   behavior change; `pillar-streamdb` now re-exports these from here so
//!   every existing call site keeps working unchanged).
//! - [`ipfs_backend`] — the `IpfsBackend` trait + `NativeIpfsBackend` — also
//!   moved down from `pillar-streamdb`.
//!
//! Dependency direction (no cycles): `pillar-streamdb`, `pillar-observability`,
//! `pillar-net` -> `pillar-wire` -> `pillar-crypto`, `pillar-core`,
//! `pillar-ipfs`. This crate must NEVER depend on `pillar-net`,
//! `pillar-streamdb`, or `pillar-observability`.

/// Deterministic, collision-resistant content address of an arbitrary byte
/// payload — the same pure bytes->identity function every content-addressed
/// Pillar surface (op-log, blob layer, [`store::Cid`], [`envelope::PillarMessage`])
/// uses, so two nodes holding the same bytes necessarily agree on the address.
///
/// Delegates to [`pillar_crypto::content::content_address`] (a real SHA2-256
/// multihash); infallible for an in-memory byte slice, so any error surfaces
/// as a panic rather than threading a `Result` through every identity
/// computation (a failure here would mean the crypto primitive itself is
/// broken).
#[must_use]
pub fn content_address(bytes: &[u8]) -> pillar_crypto::ContentId {
    pillar_crypto::content::content_address(bytes)
        .expect("SHA2-256 content addressing is infallible for an in-memory payload")
}

pub mod store;
pub use store::{Cid, ContentStore, HeadRecord, SegmentSource, SignedSegment, StoreError, Visibility};

pub mod ipfs_backend;
pub use ipfs_backend::IpfsBackend;
#[cfg(feature = "ipfs")]
pub use ipfs_backend::{cid_to_cidv1_raw, cidv1_raw_to_cid, NativeIpfsBackend};

pub mod seal;
pub mod envelope;
pub use envelope::{Body, PillarMessage, PILLAR_MESSAGE_MAX_SUPPORTED, PILLAR_MESSAGE_MIN_SUPPORTED};
