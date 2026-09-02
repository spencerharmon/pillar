//! Authenticated symmetric encryption (AEAD).
//!
//! Encrypts the user's private key under the [`crate::kdf`] output, and is the
//! bulk-data cipher for cell-scoped confidentiality. Associated data (`aad`) is
//! authenticated but not encrypted (domain separation / context binding).

use crate::error::{CryptoError, Result};
use crate::types::{Ciphertext, SymmetricKey};

/// ChaCha20-Poly1305 nonce width, in bytes. The nonce is prepended to the
/// ciphertext so `open_symmetric` can recover it.
const NONCE_LEN: usize = 12;

/// Bind an arbitrary-length [`SymmetricKey`] to the fixed 32-byte key
/// ChaCha20-Poly1305 requires, via a domain-separated SHA-256. This lets the
/// opaque key newtype hold any width without a length precondition at the call
/// site while still feeding a real 256-bit key into the cipher.
fn cipher_key(key: &SymmetricKey) -> chacha20poly1305::Key {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-crypto/aead/chacha20poly1305/key-v1");
    h.update(key.as_bytes());
    chacha20poly1305::Key::clone_from_slice(h.finalize().as_slice())
}

/// Encrypt `plaintext` under `key`, authenticating `aad`.
///
/// Contract: `open_symmetric` with the same key and aad recovers the plaintext.
pub fn seal_symmetric(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    use rand_core::{OsRng, RngCore};

    let cipher = ChaCha20Poly1305::new(&cipher_key(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Envelope layout: nonce || ciphertext-with-tag.
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(Ciphertext::from_bytes(out))
}

/// Decrypt and authenticate `ciphertext` under `key` and `aad`.
///
/// Contract: fails with [`CryptoError::DecryptionFailed`] on the wrong key,
/// wrong aad, or any tampering — indistinguishably.
pub fn open_symmetric(key: &SymmetricKey, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    let bytes = ciphertext.as_bytes();
    if bytes.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(&cipher_key(key));
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
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
}
