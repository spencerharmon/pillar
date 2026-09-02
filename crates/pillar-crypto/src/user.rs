//! User-key operations: signing, cell-scoped messages, direct messages, and the
//! cross-cell subkey certificates that let one user's subkeys validate each
//! other.
//!
//! A user has a **master** signing identity and one **per-cell subkey** (a
//! [`crate::principal`]) per cell they belong to. The master *certifies* each
//! subkey ([`certify_subkey`]), binding it to a [`CellId`]; two subkeys in
//! different cells validate one another because both certificates verify
//! against the same master ([`verify_subkey`]). This is the shared basis for:
//!
//! * signing + encrypting a message **to the user's cell** (under the cell
//!   group key) — [`signed_cell_message`] / [`open_signed_cell_message`];
//! * a **direct message to another user** — sealed to that user's sealing key
//!   and signed by the sender's subkey — [`seal_message_to_user`] /
//!   [`open_message_from_user`]. This works user-to-user WITHIN a cell and
//!   ACROSS cells identically, since sealing is independent of cell membership.

use crate::cell::CellGroupKey;
use crate::error::Result;
#[cfg(test)]
use crate::error::CryptoError;
use crate::principal::PrincipalPublic;
use crate::types::{
    Ciphertext, CellId, SealedEnvelope, SealingSecretKey, Signature, SigningPublicKey,
    SigningSecretKey,
};

/// A message encrypted under a cell group key and signed by the sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCellMessage {
    /// Group-key ciphertext of the plaintext.
    pub ciphertext: Ciphertext,
    /// Sender's detached signature over the plaintext.
    pub signature: Signature,
}

/// A direct message sealed to a recipient and signed by the sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDirectMessage {
    /// Recipient-sealed ciphertext.
    pub envelope: SealedEnvelope,
    /// Sender's detached signature over the plaintext.
    pub signature: Signature,
}

/// Build the canonical message a subkey certificate signs: a domain-separated
/// binding of the subkey's public material to the cell it is valid in.
fn subkey_cert_message(subkey: &PrincipalPublic, cell: &CellId) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"pillar-crypto/user/subkey-cert-v1");
    m.extend_from_slice(&(subkey.signing.as_bytes().len() as u32).to_be_bytes());
    m.extend_from_slice(subkey.signing.as_bytes());
    m.extend_from_slice(&(subkey.sealing.as_bytes().len() as u32).to_be_bytes());
    m.extend_from_slice(subkey.sealing.as_bytes());
    m.extend_from_slice(&(cell.as_bytes().len() as u32).to_be_bytes());
    m.extend_from_slice(cell.as_bytes());
    m
}

/// Certify a per-cell subkey under the user's master signing key: the master
/// signs the subkey's public material bound to `cell`.
///
/// Contract: the returned certificate verifies via [`verify_subkey`] against
/// the master public key, for this subkey and cell only.
pub fn certify_subkey(
    master_signing_secret: &SigningSecretKey,
    subkey: &PrincipalPublic,
    cell: &CellId,
) -> Result<Signature> {
    let msg = subkey_cert_message(subkey, cell);
    crate::sign::sign(master_signing_secret, &msg)
}

/// Verify a subkey certificate against the user's master public key.
///
/// Contract: `Ok(())` only for a certificate the master produced over exactly
/// this subkey and cell; [`CryptoError::VerificationFailed`] otherwise. Two
/// subkeys whose certificates both verify against the same master are the same
/// user across cells.
pub fn verify_subkey(
    master_signing_public: &SigningPublicKey,
    subkey: &PrincipalPublic,
    cell: &CellId,
    cert: &Signature,
) -> Result<()> {
    let msg = subkey_cert_message(subkey, cell);
    crate::sign::verify(master_signing_public, &msg, cert)
}

/// Sign `plaintext` with the sender's (subkey) signing secret and encrypt it
/// under the cell group key, for delivery to the sender's cell.
pub fn signed_cell_message(
    sender_signing_secret: &SigningSecretKey,
    group: &CellGroupKey,
    plaintext: &[u8],
) -> Result<SignedCellMessage> {
    let signature = crate::sign::sign(sender_signing_secret, plaintext)?;
    let ciphertext =
        crate::cell::cell_encrypt(group, plaintext, b"pillar-crypto/user/cell-message-v1")?;
    Ok(SignedCellMessage {
        ciphertext,
        signature,
    })
}

/// Decrypt a cell message under the group key and verify the sender's signature
/// against their public key.
pub fn open_signed_cell_message(
    group: &CellGroupKey,
    sender_signing_public: &SigningPublicKey,
    message: &SignedCellMessage,
) -> Result<Vec<u8>> {
    let plaintext = crate::cell::cell_decrypt(
        group,
        &message.ciphertext,
        b"pillar-crypto/user/cell-message-v1",
    )?;
    crate::sign::verify(sender_signing_public, &plaintext, &message.signature)?;
    Ok(plaintext)
}

/// Seal a direct message to `recipient` (any principal — another user, in the
/// same cell or another) and sign it with the sender's signing secret.
pub fn seal_message_to_user(
    sender_signing_secret: &SigningSecretKey,
    recipient: &PrincipalPublic,
    plaintext: &[u8],
) -> Result<SignedDirectMessage> {
    let signature = crate::sign::sign(sender_signing_secret, plaintext)?;
    let envelope =
        crate::seal::seal_to_recipients(plaintext, std::slice::from_ref(&recipient.sealing))?;
    Ok(SignedDirectMessage {
        envelope,
        signature,
    })
}

/// Unseal a direct message with the recipient's sealing secret and verify the
/// sender's signature against their public key.
///
/// Contract: recovers the plaintext for the addressed recipient with a valid
/// sender signature; fails otherwise (wrong recipient or bad signature).
pub fn open_message_from_user(
    recipient_sealing_secret: &SealingSecretKey,
    sender_signing_public: &SigningPublicKey,
    message: &SignedDirectMessage,
) -> Result<Vec<u8>> {
    let plaintext = crate::seal::unseal(&message.envelope, recipient_sealing_secret)?;
    crate::sign::verify(sender_signing_public, &plaintext, &message.signature)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::group_key_from_seed;
    use crate::principal::principal_from_seed;
    use crate::types::Seed;

    fn seed(label: &str) -> Seed {
        Seed::from_bytes(format!("pillar-user-seed::{label}").into_bytes())
    }

    #[test]
    fn user_signs_and_encrypts_a_message_to_their_cell() {
        let (sub_pub, sub_sec) = principal_from_seed(&seed("alice@cellA")).expect("subkey");
        let group = group_key_from_seed(&seed("cellA")).expect("group");
        let msg = b"hello cell A, this is alice";

        let signed = signed_cell_message(&sub_sec.signing, &group, msg).expect("send");
        assert_eq!(
            open_signed_cell_message(&group, &sub_pub.signing, &signed).as_deref(),
            Ok(msg.as_ref()),
            "a cell member verifies the sender and reads the message"
        );
    }

    #[test]
    fn direct_message_only_opens_for_the_addressed_user() {
        let (_a_pub, a_sec) = principal_from_seed(&seed("alice")).expect("alice");
        let (a_pub, _) = principal_from_seed(&seed("alice")).expect("alice pub");
        let (b_pub, b_sec) = principal_from_seed(&seed("bob")).expect("bob");
        let (_c_pub, c_sec) = principal_from_seed(&seed("carol")).expect("carol");

        let msg = b"dm: meet at epoch 7";
        let dm = seal_message_to_user(&a_sec.signing, &b_pub, msg).expect("seal dm");

        assert_eq!(
            open_message_from_user(&b_sec.sealing, &a_pub.signing, &dm).as_deref(),
            Ok(msg.as_ref()),
            "the addressed user opens it and verifies the sender"
        );
        assert!(
            open_message_from_user(&c_sec.sealing, &a_pub.signing, &dm).is_err(),
            "a non-recipient cannot open it"
        );
    }

    #[test]
    fn user_subkeys_in_multiple_cells_validate_via_the_same_master() {
        let (master_pub, master_sec) = principal_from_seed(&seed("alice-master")).expect("master");
        let (sub_a_pub, _) = principal_from_seed(&seed("alice@cellA")).expect("subA");
        let (sub_b_pub, _) = principal_from_seed(&seed("alice@cellB")).expect("subB");
        let cell_a = CellId::from_bytes(b"cell-A".to_vec());
        let cell_b = CellId::from_bytes(b"cell-B".to_vec());

        let cert_a = certify_subkey(&master_sec.signing, &sub_a_pub, &cell_a).expect("cert A");
        let cert_b = certify_subkey(&master_sec.signing, &sub_b_pub, &cell_b).expect("cert B");

        assert_eq!(verify_subkey(&master_pub.signing, &sub_a_pub, &cell_a, &cert_a), Ok(()));
        assert_eq!(verify_subkey(&master_pub.signing, &sub_b_pub, &cell_b, &cert_b), Ok(()));

        // A cert from a different master must not validate alice's subkey.
        let (mallory_pub, _) = principal_from_seed(&seed("mallory-master")).expect("mallory");
        assert_eq!(
            verify_subkey(&mallory_pub.signing, &sub_a_pub, &cell_a, &cert_a),
            Err(CryptoError::VerificationFailed),
            "a foreign master must not validate the subkey"
        );
    }
}
