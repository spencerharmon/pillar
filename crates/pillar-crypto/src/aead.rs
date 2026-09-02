//! Authenticated symmetric encryption (AEAD).
//!
//! Encrypts the user's private key under the [`crate::kdf`] output, and is the
//! bulk-data cipher for cell-scoped confidentiality. Associated data (`aad`) is
//! authenticated but not encrypted (domain separation / context binding).

use crate::error::{CryptoError, Result};
use crate::types::{Ciphertext, SymmetricKey};

/// Encrypt `plaintext` under `key`, authenticating `aad`.
///
/// Contract: `open_symmetric` with the same key and aad recovers the plaintext.
pub fn seal_symmetric(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    let _ = (key, plaintext, aad);
    Err(CryptoError::NotImplemented("aead::seal_symmetric"))
}

/// Decrypt and authenticate `ciphertext` under `key` and `aad`.
///
/// Contract: fails with [`CryptoError::DecryptionFailed`] on the wrong key,
/// wrong aad, or any tampering — indistinguishably.
pub fn open_symmetric(key: &SymmetricKey, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    let _ = (key, ciphertext, aad);
    Err(CryptoError::NotImplemented("aead::open_symmetric"))
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
