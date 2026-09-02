//! Public-key recipient sealing.
//!
//! The heart of the key-distribution model: an artifact (typically the
//! argon2id-encrypted private key) is sealed to a set of recipient public keys
//! — **nodes and cells alike** — and only a holder of one of those recipients'
//! secret keys can unseal it. A party that knows only the recipients' public
//! keys and the envelope learns nothing.

use crate::error::{CryptoError, Result};
use crate::types::{SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed};

/// Derive a sealing (recipient) keypair deterministically from `seed`.
///
/// Contract: deterministic in `seed`; distinct seeds yield distinct keypairs.
pub fn sealing_keypair_from_seed(seed: &Seed) -> Result<(SealingPublicKey, SealingSecretKey)> {
    let _ = seed;
    Err(CryptoError::NotImplemented("seal::sealing_keypair_from_seed"))
}

/// Seal `plaintext` to every recipient in `recipients`.
///
/// Contract: each recipient (node or cell) can [`unseal`] the envelope to the
/// exact plaintext; nobody else can.
pub fn seal_to_recipients(
    plaintext: &[u8],
    recipients: &[SealingPublicKey],
) -> Result<SealedEnvelope> {
    let _ = (plaintext, recipients);
    Err(CryptoError::NotImplemented("seal::seal_to_recipients"))
}

/// Unseal `envelope` with a recipient's `secret`.
///
/// Contract: recovers the plaintext when `secret` matches one of the envelope's
/// recipients; [`CryptoError::NotARecipient`] otherwise.
pub fn unseal(envelope: &SealedEnvelope, secret: &SealingSecretKey) -> Result<Vec<u8>> {
    let _ = (envelope, secret);
    Err(CryptoError::NotImplemented("seal::unseal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(label: &str) -> Seed {
        Seed::from_bytes(format!("pillar-sealing-seed::{label}").into_bytes())
    }

    #[test]
    fn every_recipient_node_or_cell_can_unseal_and_outsiders_cannot() {
        let (node_pk, node_sk) = sealing_keypair_from_seed(&seed("node-1")).expect("keygen");
        let (cell_pk, cell_sk) = sealing_keypair_from_seed(&seed("cell-A")).expect("keygen");
        let (_out_pk, out_sk) = sealing_keypair_from_seed(&seed("outsider")).expect("keygen");

        // The artifact is the argon2id-encrypted user private key (opaque here).
        let artifact = b"argon2id-encrypted user private key blob";

        // Sealed to BOTH a node recipient and a cell recipient.
        let env = seal_to_recipients(artifact, &[node_pk, cell_pk]).expect("seal");

        assert_eq!(
            unseal(&env, &node_sk).as_deref(),
            Ok(artifact.as_ref()),
            "the node recipient must recover the artifact"
        );
        assert_eq!(
            unseal(&env, &cell_sk).as_deref(),
            Ok(artifact.as_ref()),
            "the cell recipient must recover the artifact"
        );
        assert_eq!(
            unseal(&env, &out_sk),
            Err(CryptoError::NotARecipient),
            "a non-recipient must not be able to unseal"
        );
    }

    #[test]
    fn single_recipient_seal_is_confidential_to_that_recipient() {
        let (pk, sk) = sealing_keypair_from_seed(&seed("node-only")).expect("keygen");
        let (_other_pk, other_sk) = sealing_keypair_from_seed(&seed("other-node")).expect("keygen");
        let env = seal_to_recipients(b"cell group key", &[pk]).expect("seal");
        assert_eq!(unseal(&env, &sk).as_deref(), Ok(b"cell group key".as_ref()));
        assert_eq!(unseal(&env, &other_sk), Err(CryptoError::NotARecipient));
    }
}
