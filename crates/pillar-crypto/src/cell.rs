//! Cell-key operations: the cell group key encrypts the database and broadcasts.
//!
//! A cell has two kinds of key material:
//!
//! * an asymmetric **cell principal** ([`crate::principal`]) — the recipient
//!   identity that artifacts (and cell-to-cell messages) are sealed *to*; and
//! * a symmetric **cell group key** ([`CellGroupKey`]) — encrypts the cell's
//!   slice of the streaming database and its broadcast messages, and is
//!   distributed to members by sealing it to their sealing public keys.
//!
//! Cell-to-cell messaging needs no bespoke primitive: because a cell is a
//! principal, cell A seals to cell B's [`PrincipalPublic::sealing`] with the
//! shared [`crate::seal`] operation.

use crate::error::Result;
use crate::types::{Ciphertext, SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed, SymmetricKey};

/// The symmetric group key of a cell. Encrypts the cell's database records and
/// broadcast messages; distributed to members as a sealed artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellGroupKey(SymmetricKey);

impl CellGroupKey {
    /// Wrap raw symmetric key bytes as a cell group key.
    pub fn from_key(key: SymmetricKey) -> Self {
        Self(key)
    }
    /// Borrow the underlying symmetric key.
    pub fn key(&self) -> &SymmetricKey {
        &self.0
    }
}

/// Derive a fresh cell group key from seed material (real generation may use a
/// CSPRNG; a rotation derives a new one).
pub fn group_key_from_seed(seed: &Seed) -> Result<CellGroupKey> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-crypto/cell/group-key/seed-v1");
    h.update(seed.as_bytes());
    Ok(CellGroupKey(SymmetricKey::from_bytes(h.finalize().to_vec())))
}

/// Encrypt a streaming-database record or a broadcast message under the cell
/// group key. `aad` domain-separates record vs broadcast vs other contexts.
///
/// Contract: [`cell_decrypt`] with the same group key and aad recovers it; a
/// different group key cannot.
pub fn cell_encrypt(group: &CellGroupKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    crate::aead::seal_symmetric(&group.0, plaintext, aad)
}

/// Decrypt a record/broadcast produced by [`cell_encrypt`].
pub fn cell_decrypt(group: &CellGroupKey, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    crate::aead::open_symmetric(&group.0, ciphertext, aad)
}

/// Seal the cell group key to a set of member recipients (node and/or user
/// sealing public keys) for distribution.
///
/// Contract: any recipient can [`recover_group_key`]; nobody else can.
pub fn distribute_group_key(
    group: &CellGroupKey,
    recipients: &[SealingPublicKey],
) -> Result<SealedEnvelope> {
    crate::seal::seal_to_recipients(group.0.as_bytes(), recipients)
}

/// Recover the cell group key from a sealed distribution using a recipient's
/// sealing secret — a node's custody-held secret, or a user's.
pub fn recover_group_key(
    sealed: &SealedEnvelope,
    recipient_secret: &SealingSecretKey,
) -> Result<CellGroupKey> {
    let key = crate::seal::unseal(sealed, recipient_secret)?;
    Ok(CellGroupKey(SymmetricKey::from_bytes(key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::principal_from_seed;

    fn seed(label: &str) -> Seed {
        Seed::from_bytes(format!("pillar-cell-seed::{label}").into_bytes())
    }

    #[test]
    fn group_key_encrypts_db_records_and_broadcasts() {
        let group = group_key_from_seed(&seed("cell-A")).expect("group key");

        let record = b"db op: append authority(admin, cell-A)";
        let ct = cell_encrypt(&group, record, b"db-record").expect("encrypt");
        assert_eq!(
            cell_decrypt(&group, &ct, b"db-record").as_deref(),
            Ok(record.as_ref()),
            "a member with the group key reads the record"
        );

        let broadcast = b"cell broadcast: rotate group key at epoch 5";
        let bct = cell_encrypt(&group, broadcast, b"broadcast").expect("encrypt");
        assert_eq!(
            cell_decrypt(&group, &bct, b"broadcast").as_deref(),
            Ok(broadcast.as_ref())
        );

        let other = group_key_from_seed(&seed("cell-B")).expect("group key");
        assert!(
            cell_decrypt(&other, &ct, b"db-record").is_err(),
            "a different cell's group key must not decrypt cell-A's record"
        );
    }

    #[test]
    fn group_key_distributes_to_members_and_only_members() {
        let group = group_key_from_seed(&seed("cell-A")).expect("group key");
        let (member_pub, member_sec) = principal_from_seed(&seed("member")).expect("member");
        let (_out_pub, out_sec) = principal_from_seed(&seed("outsider")).expect("outsider");

        let sealed = distribute_group_key(&group, &[member_pub.sealing]).expect("distribute");
        assert_eq!(
            recover_group_key(&sealed, &member_sec.sealing),
            Ok(group),
            "a member recovers the exact group key"
        );
        assert!(
            recover_group_key(&sealed, &out_sec.sealing).is_err(),
            "a non-member cannot recover the group key"
        );
    }
}
