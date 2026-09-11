//! The three per-body seal treatments (`docs/papers/pillar-message-format.md`
//! §5, `specs/PillarBodySeals.tla`), decided by **how many parties must
//! unseal** a body:
//!
//! - [`ContentSeal`]/[`CellSeal`] — **convergent**: the streamdb op-log, obs
//!   signals, and a direct message's cell *wrapper* all reach every member of
//!   a cell, so the seal MUST be a deterministic function of (cell key,
//!   plaintext, domain) — the same plaintext sealed twice yields
//!   byte-identical ciphertext, so the derived [`crate::store::Cid`] is
//!   stable across independently-sealing nodes (dedup depends on this).
//!   Backed by [`pillar_crypto::cell::cell_seal_convergent`]/
//!   `cell_open_convergent` (`cell-seal-convergent-impl`).
//! - [`RecipientSeal`] — **random**: a direct message's application content
//!   reaches exactly ONE recipient, so it draws fresh randomness per seal
//!   (an X25519 sealed-box via [`pillar_crypto::seal::seal_to_recipients`]/
//!   `unseal`) and is deliberately **not** convergent — two seals of
//!   identical plaintext at different times must be distinct records, never
//!   deduped (`RcptRandomDistinctByEntropy`).
//! - [`plain_cid`] — **unencrypted**: some control bodies ride inside the
//!   already-sealed transport frame with no additional confidentiality claim,
//!   but still get a stable content-addressed `Cid` for reference/dedup
//!   (`DedupByCid`/`PlainReadableWithoutKey`). This is a deliberate per-body
//!   opt-in — a caller must explicitly choose it, never a silent fallback
//!   when a seal call is skipped.

use pillar_crypto::cell::{cell_open_convergent, cell_seal_convergent, CellGroupKey};
use pillar_crypto::seal::{seal_to_recipients, unseal};
use pillar_crypto::{Ciphertext, Result as CryptoResult, SealingPublicKey, SealingSecretKey};

use crate::store::Cid;

/// The interface a **convergent** `PillarMessage` body seal implements: seal
/// a plaintext body to a cell (so any cell member can open it) and open a
/// ciphertext back to plaintext. `domain` separates record classes (e.g.
/// streamdb op vs observability signal vs control-body wrapper) so the
/// convergent-equality leak never crosses class boundaries; `aad` is
/// authenticated-but-not-encrypted associated data — the envelope binds its
/// header (version/visibility/cell) here so a sealed body can never be
/// replayed under a different header.
///
/// A conforming implementation guarantees: sealing the same
/// `(plaintext, domain)` under the same `group` key twice yields
/// byte-identical [`Ciphertext`] (so the derived [`crate::store::Cid`] is
/// stable across nodes).
pub trait ContentSeal {
    /// Seal `plaintext` to `group` (the cell group key) under `domain`,
    /// binding `aad`.
    ///
    /// # Errors
    /// Propagates any AEAD failure from the underlying primitive.
    fn seal(
        &self,
        group: &CellGroupKey,
        plaintext: &[u8],
        domain: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Ciphertext>;

    /// Open `ciphertext` sealed to `group`, verifying `aad`.
    ///
    /// # Errors
    /// Fails if `ciphertext`/`aad` do not match what was sealed, or the key
    /// is wrong.
    fn open(
        &self,
        group: &CellGroupKey,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

/// The `pillar-wire` convergent seal: cell-group-key AEAD with a
/// deterministic, content-address-derived nonce
/// ([`pillar_crypto::cell::cell_seal_convergent`]/`cell_open_convergent`) —
/// see the module docs. Every convergent body kind (streamdb ops, obs
/// signals, a direct message's cell wrapper, and a cell-sealed control body)
/// goes through this, keyed to its own `domain` so equality never leaks
/// across record classes.
#[derive(Clone, Copy, Debug, Default)]
pub struct CellSeal;

impl ContentSeal for CellSeal {
    fn seal(
        &self,
        group: &CellGroupKey,
        plaintext: &[u8],
        domain: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Ciphertext> {
        cell_seal_convergent(group, plaintext, domain, aad)
    }

    fn open(
        &self,
        group: &CellGroupKey,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        cell_open_convergent(group, ciphertext, aad)
    }
}

/// The domain a [`CellSeal`] uses for a libp2p control-body wrapper (see
/// `pillar-net`'s `wrap_control`) — separate from streamdb's/observability's
/// own domains so equality never leaks across record classes.
pub const CONTROL_BODY_SEAL_DOMAIN: &[u8] = b"pillar-wire/control-body/v1";

/// The **random**, single-recipient seal for a direct message's application
/// content (§5(b)): an X25519 sealed-box to exactly one recipient principal,
/// drawing FRESH randomness on every call
/// ([`pillar_crypto::seal::seal_to_recipients`]). Deliberately not
/// convergent — sealing identical plaintext twice yields distinct ciphertext
/// (and therefore a distinct [`crate::store::Cid`]), so two same-text direct
/// messages sent at different times are DISTINCT records, never deduped
/// (`RcptRandomDistinctByEntropy`). Exactly-once delivery coordination is an
/// application-layer concern (e.g. streamdb), never smuggled into the wire
/// format as dedup.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecipientSeal;

impl RecipientSeal {
    /// Seal `plaintext` to the single `recipient`'s static X25519 key. The
    /// result carries its own fresh ephemeral key + content key (see
    /// [`pillar_crypto::seal::seal_to_recipients`]), so two calls with the
    /// same `plaintext`/`recipient` produce byte-distinct output.
    ///
    /// # Errors
    /// Propagates any sealing failure from the underlying primitive.
    pub fn seal(&self, recipient: &SealingPublicKey, plaintext: &[u8]) -> CryptoResult<Ciphertext> {
        let sealed = seal_to_recipients(plaintext, std::slice::from_ref(recipient))?;
        Ok(Ciphertext::from_bytes(sealed.into_bytes()))
    }

    /// Open a [`RecipientSeal::seal`]ed body with the recipient's `secret`.
    ///
    /// # Errors
    /// [`pillar_crypto::CryptoError::NotARecipient`] if `secret` does not
    /// match the seal's recipient; otherwise propagates a malformed-envelope
    /// or decryption fault.
    pub fn open(&self, secret: &SealingSecretKey, ciphertext: &Ciphertext) -> CryptoResult<Vec<u8>> {
        let envelope = pillar_crypto::SealedEnvelope::from_bytes(ciphertext.as_bytes().to_vec());
        unseal(&envelope, secret)
    }
}

/// The **plain** treatment (§5(c)): derive a stable content-addressed
/// [`Cid`] directly from `plaintext`, with no seal/open call at all. Some
/// control bodies ride unencrypted inside the already-sealed transport frame
/// — this is what lets them still be referenced/deduped by identity without
/// any additional confidentiality claim (`DedupByCid`/
/// `PlainReadableWithoutKey`). A caller must explicitly opt into this
/// treatment per body kind; it is never a silent fallback for a body whose
/// seal call was skipped.
#[must_use]
pub fn plain_cid(plaintext: &[u8]) -> Cid {
    Cid::of(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::seal::sealing_keypair_from_seed;
    use pillar_crypto::Seed;

    const DOMAIN: &[u8] = b"pillar-wire/tests/cell-seal/v1";

    #[test]
    fn cell_seal_round_trips_and_authenticates_aad() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("key");
        let seal = CellSeal;
        let ct = seal
            .seal(&group, b"a sealed pillar-message body", DOMAIN, b"header-aad-v1")
            .expect("seal");
        let pt = seal.open(&group, &ct, b"header-aad-v1").expect("open");
        assert_eq!(pt, b"a sealed pillar-message body");

        // Wrong AAD is rejected (the header can't be swapped under the seal).
        assert!(seal.open(&group, &ct, b"different-aad").is_err());
    }

    /// The convergent seal is a pure function of (group, plaintext, domain):
    /// sealing the same body twice yields byte-identical ciphertext, so the
    /// derived Cid dedups (`ConvergentCellDedup`).
    #[test]
    fn cell_seal_is_convergent_across_independent_calls() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("key");
        let seal = CellSeal;
        let ct1 = seal
            .seal(&group, b"identical body", DOMAIN, b"aad")
            .expect("seal 1");
        let ct2 = seal
            .seal(&group, b"identical body", DOMAIN, b"aad")
            .expect("seal 2");
        assert_eq!(ct1.as_bytes(), ct2.as_bytes(), "convergent seal must be deterministic");
        assert_eq!(Cid::of(ct1.as_bytes()), Cid::of(ct2.as_bytes()));
    }

    /// Two recipient-sealed calls with the SAME plaintext/recipient at
    /// different times produce distinct ciphertexts and distinct Cids — the
    /// opposite of the convergent treatment (`RcptRandomDistinctByEntropy`).
    #[test]
    fn recipient_seal_same_plaintext_produces_distinct_ciphertexts_over_time() {
        let (recipient_pub, _recipient_secret) =
            sealing_keypair_from_seed(&Seed::from_bytes(b"recipient-a".to_vec())).expect("keygen");
        let seal = RecipientSeal;
        let ct1 = seal.seal(&recipient_pub, b"hey").expect("seal 1");
        let ct2 = seal.seal(&recipient_pub, b"hey").expect("seal 2");
        assert_ne!(
            ct1.as_bytes(),
            ct2.as_bytes(),
            "recipient seal must draw fresh randomness per call, never converge"
        );
        assert_ne!(
            Cid::of(ct1.as_bytes()),
            Cid::of(ct2.as_bytes()),
            "distinct ciphertexts must yield distinct Cids (no dedup across time)"
        );
    }

    /// A recipient-sealed body opens for the intended recipient and is
    /// opaque to a different valid key holder (`RcptOpaqueToNonHolder`).
    #[test]
    fn recipient_seal_round_trips_and_is_opaque_to_a_non_recipient() {
        let (recipient_pub, recipient_secret) =
            sealing_keypair_from_seed(&Seed::from_bytes(b"recipient-a".to_vec())).expect("keygen");
        let (_other_pub, other_secret) =
            sealing_keypair_from_seed(&Seed::from_bytes(b"someone-else".to_vec())).expect("keygen");

        let seal = RecipientSeal;
        let ct = seal
            .seal(&recipient_pub, b"a direct message body")
            .expect("seal");

        let opened = seal.open(&recipient_secret, &ct).expect("open");
        assert_eq!(opened, b"a direct message body");

        assert!(
            seal.open(&other_secret, &ct).is_err(),
            "a non-recipient's valid key must not open the seal"
        );
    }

    /// A plain body's Cid derives directly from its own plaintext, is
    /// stable/deterministic, and requires no key/seal call at all
    /// (`DedupByCid`).
    #[test]
    fn plain_body_gets_a_stable_content_addressed_cid_without_a_seal() {
        let a = plain_cid(b"a plain control body");
        let b = plain_cid(b"a plain control body");
        assert_eq!(a, b, "identical plaintext must yield the identical Cid");

        let different = plain_cid(b"a different plain control body");
        assert_ne!(a, different);
    }
}
