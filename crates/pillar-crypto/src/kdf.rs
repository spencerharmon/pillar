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
    use argon2::{Algorithm, Argon2, Params, Version};

    if params.output_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    // Argon2 requires a salt of at least 8 bytes. The advisory `Salt` newtype is
    // arbitrary-length caller input, so bind it into a fixed-width, KDF-safe salt
    // via a domain-separated SHA-256 rather than rejecting short salts.
    let bound_salt = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"pillar-crypto/kdf/argon2id/salt-v1");
        h.update(salt.as_bytes());
        h.finalize()
    };

    let a2params = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| CryptoError::InvalidLength)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2params);

    let mut out = vec![0u8; params.output_len];
    argon
        .hash_password_into(password, bound_salt.as_slice(), &mut out)
        .map_err(|_| CryptoError::InvalidLength)?;
    Ok(SymmetricKey::from_bytes(out))
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
        assert_eq!(
            k1, k2,
            "same (password, salt, params) must yield the same key"
        );
        assert!(
            k1.len() >= params.output_len,
            "key must be at least output_len bytes"
        );

        let wrong_pw = derive_key(b"Correct Horse Battery Staple", &salt, &params)
            .expect("derive must succeed");
        assert_ne!(
            k1, wrong_pw,
            "a different password must yield a different key"
        );

        let salt2 = Salt::from_bytes(b"pillar-fixed-per-user-salt-0002".to_vec());
        let other_salt = derive_key(password, &salt2, &params).expect("derive must succeed");
        assert_ne!(
            k1, other_salt,
            "a different salt must yield a different key"
        );
    }
}
