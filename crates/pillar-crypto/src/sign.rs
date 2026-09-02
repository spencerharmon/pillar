//! Asymmetric signatures.
//!
//! The user's private key signs a login nonce; verification uses only the
//! WoT-registered public key. Also used for streaming-DB event authorship and
//! trust attestations. The key property is asymmetry: holding the public key
//! must not let anyone forge a signature.

use crate::error::{CryptoError, Result};
use crate::types::{Seed, Signature, SigningPublicKey, SigningSecretKey};

/// Derive a signing keypair deterministically from `seed`.
///
/// Contract: deterministic in `seed`; distinct seeds yield distinct keypairs.
/// (Reproducible generation; real key generation may draw the seed from an OS
/// CSPRNG.)
pub fn signing_keypair_from_seed(seed: &Seed) -> Result<(SigningPublicKey, SigningSecretKey)> {
    let _ = seed;
    Err(CryptoError::NotImplemented("sign::signing_keypair_from_seed"))
}

/// Sign `message` with `secret`.
pub fn sign(secret: &SigningSecretKey, message: &[u8]) -> Result<Signature> {
    let _ = (secret, message);
    Err(CryptoError::NotImplemented("sign::sign"))
}

/// Verify `signature` over `message` against `public`.
///
/// Contract: `Ok(())` only for a signature produced by the matching secret over
/// exactly this message; [`CryptoError::VerificationFailed`] otherwise.
pub fn verify(public: &SigningPublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let _ = (public, message, signature);
    Err(CryptoError::NotImplemented("sign::verify"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(label: &str) -> Seed {
        Seed::from_bytes(format!("pillar-signing-seed::{label}").into_bytes())
    }

    #[test]
    fn signature_verifies_and_is_deterministic_in_seed() {
        let (pk_a1, _) = signing_keypair_from_seed(&seed("alice")).expect("keygen");
        let (pk_a2, _) = signing_keypair_from_seed(&seed("alice")).expect("keygen");
        assert_eq!(pk_a1, pk_a2, "same seed must yield the same public key");

        let (pk, sk) = signing_keypair_from_seed(&seed("alice")).expect("keygen");
        let nonce = b"login-nonce origin=cellA expiry=42 user=alice";
        let sig = sign(&sk, nonce).expect("sign");
        assert_eq!(
            verify(&pk, nonce, &sig),
            Ok(()),
            "a valid signature must verify against the matching public key"
        );
    }

    #[test]
    fn verification_rejects_tampering_and_wrong_key() {
        let (pk, sk) = signing_keypair_from_seed(&seed("alice")).expect("keygen");
        let nonce = b"login-nonce origin=cellA expiry=42 user=alice";
        let sig = sign(&sk, nonce).expect("sign");

        assert_eq!(
            verify(&pk, b"login-nonce origin=cellA expiry=43 user=alice", &sig),
            Err(CryptoError::VerificationFailed),
            "a tampered message must not verify"
        );

        // Asymmetry: a different keypair's public key must not verify a
        // signature it did not produce — the public key alone cannot forge.
        let (pk_mallory, _) = signing_keypair_from_seed(&seed("mallory")).expect("keygen");
        assert_eq!(
            verify(&pk_mallory, nonce, &sig),
            Err(CryptoError::VerificationFailed),
            "another party's public key must not verify alice's signature"
        );
    }
}
