//! Node-key operations: a node unlocks the cell keys and user keys sealed to it.
//!
//! A node is a [`crate::principal`] whose sealing secret is held in
//! [`crate::custody`] (unencrypted / password / tpm / passkey). Its job in the
//! key-distribution model is to **unseal**: recover a cell group key or a user
//! private key that was sealed to the node's sealing public key.

use crate::error::{CryptoError, Result};
use crate::types::{SealedEnvelope, SealingSecretKey};

/// Unlock (unseal) an artifact that was sealed to this node — a sealed cell key
/// or a sealed user key. Delegates to the shared [`crate::seal`] primitive with
/// the node's custody-held sealing secret.
///
/// Contract: recovers the plaintext when this node is a recipient;
/// [`CryptoError::NotARecipient`] otherwise.
pub fn node_unlock(node_sealing_secret: &SealingSecretKey, sealed: &SealedEnvelope) -> Result<Vec<u8>> {
    let _ = (node_sealing_secret, sealed);
    Err(CryptoError::NotImplemented("node::node_unlock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::principal_from_seed;
    use crate::seal::seal_to_recipients;
    use crate::types::Seed;

    #[test]
    fn node_unlocks_an_artifact_sealed_to_it_and_rejects_others() {
        let (node_pub, node_sec) =
            principal_from_seed(&Seed::from_bytes(b"node-1".to_vec())).expect("node");
        let (_other_pub, other_sec) =
            principal_from_seed(&Seed::from_bytes(b"node-2".to_vec())).expect("other node");

        let artifact = b"sealed cell group key (opaque)";
        let sealed = seal_to_recipients(artifact, &[node_pub.sealing]).expect("seal");

        assert_eq!(
            node_unlock(&node_sec.sealing, &sealed).as_deref(),
            Ok(artifact.as_ref()),
            "the addressed node must unlock the artifact"
        );
        assert_eq!(
            node_unlock(&other_sec.sealing, &sealed),
            Err(CryptoError::NotARecipient),
            "a node that is not a recipient must not unlock it"
        );
    }
}
