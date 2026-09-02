//! Content addressing (cryptographic multihash).
//!
//! The streaming DB and blob layer address content by hash. That hash must be
//! collision-resistant — a non-cryptographic hash (FNV, SipHash) is not a
//! content address, it is a checksum. The output is opaque multihash bytes so
//! the digest algorithm (sha256, blake3, …) can change without a format break.

use crate::error::{CryptoError, Result};
use crate::types::ContentId;

/// Compute the content address of `bytes`.
///
/// Contract: deterministic; distinct inputs yield distinct addresses (collision
/// resistance); a single-bit change flips the address; at least 32 bytes wide.
pub fn content_address(bytes: &[u8]) -> Result<ContentId> {
    let _ = bytes;
    Err(CryptoError::NotImplemented("content::content_address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_address_is_deterministic_distinct_and_wide() {
        let a = content_address(b"pillar streaming-db op A").expect("address");
        let a_again = content_address(b"pillar streaming-db op A").expect("address");
        let b = content_address(b"pillar streaming-db op B").expect("address");

        assert_eq!(a, a_again, "content addressing must be deterministic");
        assert_ne!(a, b, "distinct inputs must yield distinct addresses");
        assert!(
            a.len() >= 32,
            "a content address must be at least 256 bits wide, got {} bytes",
            a.len()
        );
    }

    #[test]
    fn content_address_has_avalanche() {
        // A one-byte change must produce a completely different address.
        let base = content_address(b"pillar-op-0000").expect("address");
        let flipped = content_address(b"pillar-op-0001").expect("address");
        assert_ne!(base, flipped, "a small input change must change the address");
    }

    #[test]
    fn empty_input_still_addresses() {
        let empty = content_address(b"").expect("address");
        assert!(empty.len() >= 32, "even the empty input hashes to full width");
    }
}
