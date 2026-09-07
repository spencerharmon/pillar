//! Asymmetric signatures.
//!
//! The user's private key signs a login nonce; verification uses only the
//! WoT-registered public key. Also used for streaming-DB event authorship and
//! trust attestations. The key property is asymmetry: holding the public key
//! must not let anyone forge a signature.

use crate::error::{CryptoError, Result};
use crate::types::{Seed, Signature, SigningPublicKey, SigningSecretKey};

/// Derive a 32-byte ed25519 secret scalar seed from arbitrary seed material via
/// a domain-separated SHA-256 (independent of the sealing derivation).
pub(crate) fn ed25519_secret_bytes(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-crypto/sign/ed25519/seed-v1");
    h.update(seed);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Derive a signing keypair deterministically from `seed`.
///
/// Contract: deterministic in `seed`; distinct seeds yield distinct keypairs.
/// (Reproducible generation; real key generation may draw the seed from an OS
/// CSPRNG.)
pub fn signing_keypair_from_seed(seed: &Seed) -> Result<(SigningPublicKey, SigningSecretKey)> {
    use ed25519_dalek::SigningKey;

    let sk_bytes = ed25519_secret_bytes(seed.as_bytes());
    let signing = SigningKey::from_bytes(&sk_bytes);
    let verifying = signing.verifying_key();
    Ok((
        SigningPublicKey::from_bytes(verifying.to_bytes().to_vec()),
        SigningSecretKey::from_bytes(sk_bytes.to_vec()),
    ))
}

/// Sign `message` with `secret`.
pub fn sign(secret: &SigningSecretKey, message: &[u8]) -> Result<Signature> {
    use ed25519_dalek::{Signer, SigningKey};

    let sk_bytes: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let signing = SigningKey::from_bytes(&sk_bytes);
    let sig = signing.sign(message);
    Ok(Signature::from_bytes(sig.to_bytes().to_vec()))
}

/// Verify `signature` over `message` against `public`.
///
/// Contract: `Ok(())` only for a signature produced by the matching secret over
/// exactly this message; [`CryptoError::VerificationFailed`] otherwise.
pub fn verify(public: &SigningPublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    let pk_bytes: [u8; 32] = public
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::VerificationFailed)?;
    let verifying =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::VerificationFailed)?;
    let sig_bytes: [u8; 64] = signature
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::VerificationFailed)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
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
