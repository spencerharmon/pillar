//! Password → key derivation (memory-hard KDF).
//!
//! Turns a low-entropy [`Password`] into a [`SymmetricKey`]. In the pillar
//! model this key encrypts the user's private key (via [`crate::aead`]) to form
//! the argon2id-encrypted private key, and also unwraps a node's sealing secret
//! under the `password` custody backend.

use crate::error::{CryptoError, Result};
use crate::types::{KdfParams, Salt, SymmetricKey};

/// Derive a symmetric key from a password and salt under the given parameters.
///
/// Contract: deterministic in `(password, salt, params)`, sensitive to each
/// input, memory-hard, and at least `params.output_len` bytes wide.
pub fn derive_key(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<SymmetricKey> {
    let _ = (password, salt, params);
    Err(CryptoError::NotImplemented("kdf::derive_key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_and_input_sensitive() {
        let params = KdfParams::default();
        let salt = Salt::from_bytes(b"pillar-fixed-per-user-salt-0001".to_vec());
        let password = b"correct horse battery staple";

        let k1 = derive_key(password, &salt, &params).expect("derive must succeed");
        let k2 = derive_key(password, &salt, &params).expect("derive must succeed");
        assert_eq!(k1, k2, "same (password, salt, params) must yield the same key");
        assert!(
            k1.len() >= params.output_len,
            "key must be at least output_len bytes"
        );

        let wrong_pw = derive_key(b"Correct Horse Battery Staple", &salt, &params)
            .expect("derive must succeed");
        assert_ne!(k1, wrong_pw, "a different password must yield a different key");

        let salt2 = Salt::from_bytes(b"pillar-fixed-per-user-salt-0002".to_vec());
        let other_salt = derive_key(password, &salt2, &params).expect("derive must succeed");
        assert_ne!(k1, other_salt, "a different salt must yield a different key");
    }
}
