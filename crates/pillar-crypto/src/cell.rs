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
use crate::types::{
    Ciphertext, SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed, SymmetricKey,
};

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
    Ok(CellGroupKey(SymmetricKey::from_bytes(
        h.finalize().to_vec(),
    )))
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

/// **Convergent** cell seal: AEAD-encrypt `plaintext` under the cell group key
/// using a DETERMINISTIC nonce, so the same plaintext sealed under the same
/// group key on independent nodes yields byte-identical ciphertext — and
/// therefore an identical [`crate::content::content_address`]/`Cid` — while
/// two DISTINCT plaintexts never reuse a nonce (see the module-level design
/// paper §5, `docs/papers/pillar-message-format.md`).
///
/// The nonce is derived as:
/// `HKDF(key = group key, info = "pillar-wire/convergent-nonce/v1" || domain,
///       ikm = content_address(plaintext))[..nonce_len]`
///
/// `domain` separates record classes (e.g. streamdb op vs observability
/// signal) so the convergent-equality leak (two sealed records are provably
/// byte-identical) never crosses class boundaries. `aad` is the same
/// authenticated-but-not-encrypted context [`cell_encrypt`] takes (the
/// envelope header, binding this seal to it).
///
/// Contract: [`cell_open_convergent`] with the same group key and aad
/// recovers the plaintext; a different group key cannot; sealing the SAME
/// `(plaintext, domain)` under the SAME group key twice yields byte-identical
/// [`Ciphertext`] (convergence); sealing DISTINCT plaintexts never reuses a
/// nonce (nonce-safety), because the nonce is bound to
/// `content_address(plaintext)`.
pub fn cell_seal_convergent(
    group: &CellGroupKey,
    plaintext: &[u8],
    domain: &[u8],
    aad: &[u8],
) -> Result<Ciphertext> {
    use crate::types::AeadAlgorithm;

    let algorithm = AeadAlgorithm::current_default();
    let nonce = convergent_nonce(group, plaintext, domain, algorithm)?;
    crate::aead::seal_symmetric_with_nonce(algorithm, &group.0, &nonce, plaintext, aad)
}

/// Decrypt a record/broadcast produced by [`cell_seal_convergent`].
///
/// Reads the producing algorithm off the ciphertext's own inline tag (via
/// [`crate::aead::open_symmetric`]), exactly like [`cell_decrypt`] — a
/// convergent and a non-convergent seal share the same on-the-wire envelope
/// shape and are interchangeable to open (only the sealing side differs).
pub fn cell_open_convergent(
    group: &CellGroupKey,
    ciphertext: &Ciphertext,
    aad: &[u8],
) -> Result<Vec<u8>> {
    crate::aead::open_symmetric(&group.0, ciphertext, aad)
}

/// Derive the deterministic convergent nonce for `plaintext` under `group`
/// and `domain`, sized for `algorithm`. Internal to [`cell_seal_convergent`];
/// exposed at crate-visibility only for the contract tests below that must
/// assert non-reuse/determinism directly against the derivation.
fn convergent_nonce(
    group: &CellGroupKey,
    plaintext: &[u8],
    domain: &[u8],
    algorithm: crate::types::AeadAlgorithm,
) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = crate::content::content_address(plaintext)?;

    let mut info = Vec::with_capacity(32 + domain.len());
    info.extend_from_slice(b"pillar-wire/convergent-nonce/v1");
    info.extend_from_slice(domain);

    let hk = Hkdf::<Sha256>::new(Some(group.0.as_bytes()), ikm.as_bytes());
    let nonce_len = crate::aead::nonce_len(algorithm);
    let mut nonce = vec![0u8; nonce_len];
    hk.expand(&info, &mut nonce)
        .map_err(|_| crate::error::CryptoError::InvalidLength)?;
    Ok(nonce)
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

    // ---- cell_seal_convergent / cell_open_convergent ----

    #[test]
    fn convergent_seal_round_trips() {
        let group = group_key_from_seed(&seed("cell-convergent")).expect("group key");
        let plaintext = b"a pillar-message body sealed convergently";
        let aad = b"envelope-header-v1";
        let domain = b"streamdb-op";

        let ct = cell_seal_convergent(&group, plaintext, domain, aad).expect("seal");
        assert_eq!(
            cell_open_convergent(&group, &ct, aad).as_deref(),
            Ok(plaintext.as_ref()),
            "convergent open must recover the exact plaintext"
        );
    }

    #[test]
    fn convergent_seal_is_deterministic_same_body_same_key_same_ciphertext() {
        // ConvergentDeterministic: identical (plaintext, domain, aad) sealed
        // twice under the same group key must yield BYTE-IDENTICAL
        // ciphertext, so the derived Cid is stable across independently-
        // sealing nodes (dedup / IPFS convergence).
        let group = group_key_from_seed(&seed("cell-convergent")).expect("group key");
        let plaintext = b"identical body sealed on two different nodes";
        let aad = b"envelope-header-v1";
        let domain = b"streamdb-op";

        let ct1 = cell_seal_convergent(&group, plaintext, domain, aad).expect("seal 1");
        let ct2 = cell_seal_convergent(&group, plaintext, domain, aad).expect("seal 2");
        assert_eq!(
            ct1, ct2,
            "sealing the same plaintext under the same group key and domain must be \
             byte-identical (convergence)"
        );
    }

    #[test]
    fn convergent_seal_never_reuses_a_nonce_across_distinct_plaintext() {
        // NoNonceReuseAcrossDistinctPlaintext: distinct plaintexts must
        // produce distinct ciphertext (in particular, distinct nonces),
        // never the AEAD-breaking nonce-reuse-under-one-key case.
        let group = group_key_from_seed(&seed("cell-convergent")).expect("group key");
        let aad = b"envelope-header-v1";
        let domain = b"streamdb-op";

        let ct_a = cell_seal_convergent(&group, b"plaintext A", domain, aad).expect("seal A");
        let ct_b = cell_seal_convergent(&group, b"plaintext B", domain, aad).expect("seal B");
        assert_ne!(
            ct_a, ct_b,
            "distinct plaintexts must never share ciphertext (nonce reuse)"
        );

        // The nonce is the fixed-width prefix right after the 1-byte algorithm
        // tag; assert THAT specifically differs (not merely the tail, which
        // trivially differs because the plaintexts differ).
        let nonce_len = crate::aead::nonce_len(crate::types::AeadAlgorithm::current_default());
        let nonce_a = &ct_a.as_bytes()[1..1 + nonce_len];
        let nonce_b = &ct_b.as_bytes()[1..1 + nonce_len];
        assert_ne!(
            nonce_a, nonce_b,
            "distinct plaintexts must derive distinct nonces, never reuse one"
        );
    }

    #[test]
    fn convergent_seal_domain_separates_otherwise_identical_bodies() {
        // The `domain` input separates record classes so the
        // convergent-equality leak never crosses class boundaries: the same
        // plaintext sealed under two different domains must NOT converge to
        // the same ciphertext/nonce.
        let group = group_key_from_seed(&seed("cell-convergent")).expect("group key");
        let plaintext = b"same body, different record classes";
        let aad = b"envelope-header-v1";

        let ct_op = cell_seal_convergent(&group, plaintext, b"streamdb-op", aad).expect("seal op");
        let ct_signal =
            cell_seal_convergent(&group, plaintext, b"observability-signal", aad).expect("seal signal");
        assert_ne!(
            ct_op, ct_signal,
            "the same plaintext under different domains must not converge across classes"
        );
    }

    #[test]
    fn convergent_seal_is_confidential_only_to_the_group_key() {
        // ConvergentConfidential: a different cell's group key cannot open a
        // convergently-sealed record.
        let group = group_key_from_seed(&seed("cell-convergent-A")).expect("group key");
        let other = group_key_from_seed(&seed("cell-convergent-B")).expect("group key");
        let plaintext = b"confidential to cell A only";
        let aad = b"envelope-header-v1";

        let ct = cell_seal_convergent(&group, plaintext, b"streamdb-op", aad).expect("seal");
        assert!(
            cell_open_convergent(&other, &ct, aad).is_err(),
            "a different cell's group key must not open a convergently-sealed record"
        );
    }

    #[test]
    fn convergent_seal_authenticates_aad() {
        let group = group_key_from_seed(&seed("cell-convergent")).expect("group key");
        let plaintext = b"header-bound body";

        let ct = cell_seal_convergent(&group, plaintext, b"streamdb-op", b"header-v1")
            .expect("seal");
        assert!(
            cell_open_convergent(&group, &ct, b"different-header").is_err(),
            "wrong aad must fail to open even with the right group key"
        );
    }
}
