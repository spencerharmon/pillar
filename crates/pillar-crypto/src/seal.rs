//! Public-key recipient sealing.
//!
//! The heart of the key-distribution model: an artifact (typically the
//! argon2id-encrypted private key) is sealed to a set of recipient public keys
//! — **nodes and cells alike** — and only a holder of one of those recipients'
//! secret keys can unseal it. A party that knows only the recipients' public
//! keys and the envelope learns nothing.

use crate::error::{CryptoError, Result};
use crate::types::{SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed};

/// Derive the 32-byte X25519 static secret scalar from arbitrary seed material
/// via a domain-separated SHA-256 (independent of the signing derivation).
pub(crate) fn x25519_secret_bytes(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-crypto/seal/x25519/seed-v1");
    h.update(seed);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Derive a sealing (recipient) keypair deterministically from `seed`.
///
/// Contract: deterministic in `seed`; distinct seeds yield distinct keypairs.
pub fn sealing_keypair_from_seed(seed: &Seed) -> Result<(SealingPublicKey, SealingSecretKey)> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk_bytes = x25519_secret_bytes(seed.as_bytes());
    let secret = StaticSecret::from(sk_bytes);
    let public = PublicKey::from(&secret);
    // Store the clamped scalar bytes so the secret round-trips exactly.
    Ok((
        SealingPublicKey::from_bytes(public.to_bytes().to_vec()),
        SealingSecretKey::from_bytes(secret.to_bytes().to_vec()),
    ))
}

/// Derive the recipient's X25519 public key from its stored secret bytes, so the
/// envelope can be probed for a matching recipient wrap on unseal.
fn public_from_secret(secret: &SealingSecretKey) -> Result<[u8; 32]> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk_bytes: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let sk = StaticSecret::from(sk_bytes);
    Ok(PublicKey::from(&sk).to_bytes())
}

fn wrap_key_for(
    ephemeral_secret: &x25519_dalek::StaticSecret,
    recipient_pub: &[u8; 32],
    content_key: &[u8; 32],
) -> Result<Vec<u8>> {
    use crate::types::SymmetricKey;
    use x25519_dalek::PublicKey;

    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(*recipient_pub));
    let kek = SymmetricKey::from_bytes(shared.to_bytes().to_vec());
    let wrapped = crate::aead::seal_symmetric(&kek, content_key, b"pillar-crypto/seal/wrap-v1")
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(wrapped.into_bytes())
}

fn u32_bytes(n: usize) -> Result<[u8; 4]> {
    u32::try_from(n)
        .map(|v| v.to_be_bytes())
        .map_err(|_| CryptoError::InvalidLength)
}

/// Seal `plaintext` to every recipient in `recipients`.
///
/// Contract: each recipient (node or cell) can [`unseal`] the envelope to the
/// exact plaintext; nobody else can.
pub fn seal_to_recipients(
    plaintext: &[u8],
    recipients: &[SealingPublicKey],
) -> Result<SealedEnvelope> {
    use crate::types::SymmetricKey;
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Fresh content key (encrypts the payload once) and ephemeral X25519 key
    // (wraps the content key to each recipient).
    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let ephemeral = StaticSecret::from(eph_bytes);
    let ephemeral_pub = PublicKey::from(&ephemeral).to_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&ephemeral_pub);
    out.extend_from_slice(&u32_bytes(recipients.len())?);

    for r in recipients {
        let rp: [u8; 32] = r
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let wrapped = wrap_key_for(&ephemeral, &rp, &content_key)?;
        out.extend_from_slice(&rp);
        out.extend_from_slice(&u32_bytes(wrapped.len())?);
        out.extend_from_slice(&wrapped);
    }

    let payload = crate::aead::seal_symmetric(
        &SymmetricKey::from_bytes(content_key.to_vec()),
        plaintext,
        b"pillar-crypto/seal/payload-v1",
    )?;
    let payload = payload.into_bytes();
    out.extend_from_slice(&u32_bytes(payload.len())?);
    out.extend_from_slice(&payload);

    Ok(SealedEnvelope::from_bytes(out))
}

/// Unseal `envelope` with a recipient's `secret`.
///
/// Contract: recovers the plaintext when `secret` matches one of the envelope's
/// recipients; [`CryptoError::NotARecipient`] otherwise.
pub fn unseal(envelope: &SealedEnvelope, secret: &SealingSecretKey) -> Result<Vec<u8>> {
    use crate::types::{Ciphertext, SymmetricKey};
    use x25519_dalek::{PublicKey, StaticSecret};

    let buf = envelope.as_bytes();
    let mut pos = 0usize;

    let take = |buf: &[u8], pos: &mut usize, n: usize| -> Result<Vec<u8>> {
        if *pos + n > buf.len() {
            return Err(CryptoError::InvalidLength);
        }
        let s = buf[*pos..*pos + n].to_vec();
        *pos += n;
        Ok(s)
    };
    let take_u32 = |buf: &[u8], pos: &mut usize| -> Result<usize> {
        let b = take(buf, pos, 4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };

    let ephemeral_pub: [u8; 32] = take(buf, &mut pos, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;

    let sk_bytes: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let my_secret = StaticSecret::from(sk_bytes);
    let my_pub = public_from_secret(secret)?;
    let shared = my_secret.diffie_hellman(&PublicKey::from(ephemeral_pub));
    let kek = SymmetricKey::from_bytes(shared.to_bytes().to_vec());

    let n = take_u32(buf, &mut pos)?;
    let mut content_key: Option<[u8; 32]> = None;
    for _ in 0..n {
        let rp: [u8; 32] = take(buf, &mut pos, 32)?
            .try_into()
            .map_err(|_| CryptoError::InvalidLength)?;
        let wl = take_u32(buf, &mut pos)?;
        let wrapped = take(buf, &mut pos, wl)?;
        if rp == my_pub {
            let ck = crate::aead::open_symmetric(
                &kek,
                &Ciphertext::from_bytes(wrapped),
                b"pillar-crypto/seal/wrap-v1",
            )
            .map_err(|_| CryptoError::NotARecipient)?;
            let ck: [u8; 32] = ck.try_into().map_err(|_| CryptoError::InvalidKey)?;
            content_key = Some(ck);
        }
    }

    let content_key = content_key.ok_or(CryptoError::NotARecipient)?;

    let pl = take_u32(buf, &mut pos)?;
    let payload = take(buf, &mut pos, pl)?;
    crate::aead::open_symmetric(
        &SymmetricKey::from_bytes(content_key.to_vec()),
        &Ciphertext::from_bytes(payload),
        b"pillar-crypto/seal/payload-v1",
    )
    .map_err(|_| CryptoError::DecryptionFailed)
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
