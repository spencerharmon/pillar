//! Authenticated symmetric encryption (AEAD).
//!
//! Encrypts the user's private key under the [`crate::kdf`] output, and is the
//! bulk-data cipher for cell-scoped confidentiality. Associated data (`aad`) is
//! authenticated but not encrypted (domain separation / context binding).
//!
//! # Self-describing ciphertext
//!
//! Every [`Ciphertext`] this module produces is SELF-DESCRIBING: its very
//! first byte is the producing [`AeadAlgorithm`]'s stable tag, so
//! [`open_symmetric`] reads the algorithm off the ciphertext itself and never
//! assumes the binary's *current* default. This is what lets a sealed
//! artifact (sealed key, sealed cell key, sealed offer — every one of them is
//! built on this primitive, directly or via [`crate::seal`]) keep decrypting
//! correctly after the default flips: an artifact sealed under
//! [`AeadAlgorithm::ChaCha20Poly1305V1`] retains that tag forever and always
//! routes back to the ChaCha20-Poly1305 code path, even once
//! [`AeadAlgorithm::current_default`] has moved on to
//! [`AeadAlgorithm::XChaCha20Poly1305V1`]. An unrecognized tag byte fails
//! closed via [`CryptoError::UnsupportedAlgorithm`] rather than being treated
//! as the current default.

use crate::error::{CryptoError, Result};
use crate::types::{AeadAlgorithm, Ciphertext, SymmetricKey};

/// ChaCha20-Poly1305 nonce width, in bytes.
const CHACHA20_NONCE_LEN: usize = 12;
/// XChaCha20-Poly1305 (extended nonce) width, in bytes.
const XCHACHA20_NONCE_LEN: usize = 24;

/// Bind an arbitrary-length [`SymmetricKey`] to the fixed 32-byte key the
/// cipher requires, via an algorithm-domain-separated SHA-256. This lets the
/// opaque key newtype hold any width without a length precondition at the call
/// site, while also ensuring the two algorithms never derive the same working
/// key from the same [`SymmetricKey`] (an independent key per algorithm, not
/// merely a different nonce width).
fn cipher_key32(domain: &[u8], key: &SymmetricKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(key.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Encrypt `plaintext` under `key` and [`AeadAlgorithm::current_default`],
/// authenticating `aad`. The producing algorithm's tag is stamped as the
/// ciphertext's first byte (see the module docs).
///
/// Contract: `open_symmetric` with the same key and aad recovers the
/// plaintext, regardless of which algorithm was current when this was called.
pub fn seal_symmetric(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    seal_symmetric_with(AeadAlgorithm::current_default(), key, plaintext, aad)
}

/// Encrypt `plaintext` under `key` and an EXPLICIT algorithm, authenticating
/// `aad`. Exists so an artifact can be (re)sealed under a specific
/// previously-shipped algorithm rather than always the current default —
/// e.g. to exercise "an old artifact still decrypts after the default
/// flips", or for a caller that must match an existing artifact's algorithm.
/// Ordinary callers should use [`seal_symmetric`].
pub fn seal_symmetric_with(
    algorithm: AeadAlgorithm,
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Ciphertext> {
    use rand_core::{OsRng, RngCore};

    match algorithm {
        AeadAlgorithm::ChaCha20Poly1305V1 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::ChaCha20Poly1305;

            let key32 = cipher_key32(b"pillar-crypto/aead/chacha20poly1305/key-v1", key);
            let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key32));

            let mut nonce_bytes = [0u8; CHACHA20_NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

            let ct = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)?;

            // Envelope layout: tag(1) || nonce || ciphertext-with-tag.
            let mut out = Vec::with_capacity(1 + CHACHA20_NONCE_LEN + ct.len());
            out.push(algorithm.tag());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            Ok(Ciphertext::from_bytes(out))
        }
        AeadAlgorithm::XChaCha20Poly1305V1 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::XChaCha20Poly1305;

            let key32 = cipher_key32(b"pillar-crypto/aead/xchacha20poly1305/key-v1", key);
            let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key32));

            let mut nonce_bytes = [0u8; XCHACHA20_NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

            let ct = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)?;

            // Envelope layout: tag(1) || nonce || ciphertext-with-tag.
            let mut out = Vec::with_capacity(1 + XCHACHA20_NONCE_LEN + ct.len());
            out.push(algorithm.tag());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            Ok(Ciphertext::from_bytes(out))
        }
    }
}

/// Decrypt and authenticate `ciphertext` under `key` and `aad`.
///
/// Reads the producing algorithm off the ciphertext's own inline tag (see the
/// module docs) — never off [`AeadAlgorithm::current_default`] — so an
/// artifact sealed under an old algorithm keeps decrypting after the default
/// flips.
///
/// Contract: fails with [`CryptoError::DecryptionFailed`] on the wrong key,
/// wrong aad, or any tampering (indistinguishably), and with
/// [`CryptoError::UnsupportedAlgorithm`] on a tag naming no known algorithm
/// (fail closed — never silently treated as the current default).
pub fn open_symmetric(key: &SymmetricKey, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    let bytes = ciphertext.as_bytes();
    let (&tag, rest) = bytes.split_first().ok_or(CryptoError::DecryptionFailed)?;
    let algorithm = AeadAlgorithm::from_tag(tag)?;

    match algorithm {
        AeadAlgorithm::ChaCha20Poly1305V1 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::ChaCha20Poly1305;

            if rest.len() < CHACHA20_NONCE_LEN {
                return Err(CryptoError::DecryptionFailed);
            }
            let (nonce_bytes, ct) = rest.split_at(CHACHA20_NONCE_LEN);
            let key32 = cipher_key32(b"pillar-crypto/aead/chacha20poly1305/key-v1", key);
            let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key32));
            let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

            cipher
                .decrypt(nonce, Payload { msg: ct, aad })
                .map_err(|_| CryptoError::DecryptionFailed)
        }
        AeadAlgorithm::XChaCha20Poly1305V1 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::XChaCha20Poly1305;

            if rest.len() < XCHACHA20_NONCE_LEN {
                return Err(CryptoError::DecryptionFailed);
            }
            let (nonce_bytes, ct) = rest.split_at(XCHACHA20_NONCE_LEN);
            let key32 = cipher_key32(b"pillar-crypto/aead/xchacha20poly1305/key-v1", key);
            let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key32));
            let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

            cipher
                .decrypt(nonce, Payload { msg: ct, aad })
                .map_err(|_| CryptoError::DecryptionFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes(b"0123456789abcdef0123456789abcdef".to_vec())
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let plaintext = b"user ed25519 private key (plaintext, in memory only)";
        let aad = b"pillar-inner-privkey-v1";
        let ct = seal_symmetric(&key(), plaintext, aad).expect("seal must succeed");
        assert_eq!(
            open_symmetric(&key(), &ct, aad).as_deref(),
            Ok(plaintext.as_ref()),
            "round-trip must recover the exact plaintext"
        );
    }

    #[test]
    fn rejects_wrong_key_wrong_aad_and_tampering() {
        let plaintext = b"secret";
        let aad = b"ctx-A";
        let ct = seal_symmetric(&key(), plaintext, aad).expect("seal must succeed");

        let wrong_key = SymmetricKey::from_bytes(b"ffffffffffffffffffffffffffffffff".to_vec());
        assert_eq!(
            open_symmetric(&wrong_key, &ct, aad),
            Err(CryptoError::DecryptionFailed),
            "wrong key must fail"
        );
        assert_eq!(
            open_symmetric(&key(), &ct, b"ctx-B"),
            Err(CryptoError::DecryptionFailed),
            "wrong associated data must fail"
        );

        let mut tampered = ct.into_bytes();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }
        let tampered = Ciphertext::from_bytes(tampered);
        assert_eq!(
            open_symmetric(&key(), &tampered, aad),
            Err(CryptoError::DecryptionFailed),
            "tampered ciphertext must fail"
        );
    }

    // ---- Self-describing sealed artifact: algorithm tag ----

    #[test]
    fn old_artifact_still_unseals_after_the_default_algorithm_flips() {
        // Seal under the ORIGINAL algorithm explicitly (as if this artifact
        // predates the default flip below), then confirm the CURRENT default
        // is something else, then confirm the old artifact still opens
        // correctly — reading its algorithm off its own inline tag, never off
        // the binary's current default.
        let plaintext = b"pre-flip sealed artifact contents";
        let aad = b"pillar-crypto/aead/tests/old-artifact-v1";
        let old = seal_symmetric_with(AeadAlgorithm::ChaCha20Poly1305V1, &key(), plaintext, aad)
            .expect("seal under old algorithm must succeed");

        assert_eq!(
            AeadAlgorithm::current_default(),
            AeadAlgorithm::XChaCha20Poly1305V1,
            "the default must genuinely differ from the algorithm this artifact was sealed under"
        );
        assert_eq!(old.as_bytes()[0], AeadAlgorithm::ChaCha20Poly1305V1.tag());

        assert_eq!(
            open_symmetric(&key(), &old, aad).as_deref(),
            Ok(plaintext.as_ref()),
            "an artifact sealed under the old algorithm must still unseal after the default flips"
        );
    }

    #[test]
    fn newly_sealed_artifact_records_the_current_default_and_round_trips() {
        let plaintext = b"post-flip sealed artifact contents";
        let aad = b"pillar-crypto/aead/tests/new-artifact-v1";
        let fresh = seal_symmetric(&key(), plaintext, aad).expect("seal must succeed");

        assert_eq!(
            fresh.as_bytes()[0],
            AeadAlgorithm::current_default().tag(),
            "a freshly-sealed artifact must record the current default's own tag inline"
        );
        assert_eq!(
            open_symmetric(&key(), &fresh, aad).as_deref(),
            Ok(plaintext.as_ref()),
            "a freshly-sealed artifact must round-trip"
        );
    }

    #[test]
    fn both_algorithms_are_simultaneously_supported() {
        let plaintext = b"both algorithms live side by side";
        let aad = b"pillar-crypto/aead/tests/both-v1";

        let a = seal_symmetric_with(AeadAlgorithm::ChaCha20Poly1305V1, &key(), plaintext, aad)
            .expect("seal under A");
        let b = seal_symmetric_with(AeadAlgorithm::XChaCha20Poly1305V1, &key(), plaintext, aad)
            .expect("seal under B");

        assert_eq!(open_symmetric(&key(), &a, aad).as_deref(), Ok(plaintext.as_ref()));
        assert_eq!(open_symmetric(&key(), &b, aad).as_deref(), Ok(plaintext.as_ref()));
    }

    #[test]
    fn unrecognized_algorithm_tag_fails_closed() {
        let plaintext = b"artifact";
        let aad = b"pillar-crypto/aead/tests/unknown-tag-v1";
        let ct = seal_symmetric(&key(), plaintext, aad).expect("seal must succeed");

        let mut bytes = ct.into_bytes();
        bytes[0] = 0xEE; // no algorithm has ever shipped under this tag
        let unknown = Ciphertext::from_bytes(bytes);

        assert_eq!(
            open_symmetric(&key(), &unknown, aad),
            Err(CryptoError::UnsupportedAlgorithm(0xEE)),
            "an unrecognized algorithm tag must be rejected outright, never treated as the \
             current default"
        );
    }

    #[test]
    fn tampering_with_the_inline_algorithm_tag_is_detected() {
        // The tag selects which cipher/nonce-width decodes the rest of the
        // envelope, so flipping it to another SHIPPED algorithm's tag (rather
        // than an unknown byte) must still fail closed via AEAD
        // authentication (garbage nonce/ciphertext split under the wrong
        // cipher), never silently "succeed" under the wrong algorithm.
        let plaintext = b"tag-tamper artifact";
        let aad = b"pillar-crypto/aead/tests/tag-tamper-v1";
        let ct = seal_symmetric_with(AeadAlgorithm::ChaCha20Poly1305V1, &key(), plaintext, aad)
            .expect("seal must succeed");

        let mut bytes = ct.into_bytes();
        assert_eq!(bytes[0], AeadAlgorithm::ChaCha20Poly1305V1.tag());
        bytes[0] = AeadAlgorithm::XChaCha20Poly1305V1.tag();
        let retagged = Ciphertext::from_bytes(bytes);

        assert_eq!(
            open_symmetric(&key(), &retagged, aad),
            Err(CryptoError::DecryptionFailed),
            "reinterpreting the same bytes under a different algorithm's tag must fail closed"
        );
    }
}
