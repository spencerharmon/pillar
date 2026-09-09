//! The convergent content-seal interface.
//!
//! Per `docs/papers/pillar-message-format.md` §5, [`envelope::PillarMessage`]
//! (see [`crate::envelope`]) seals its body to the CELL (a symmetric group
//! key any cell member holds), and — because the [`crate::store::Cid`] is a
//! hash of the sealed bytes — that seal MUST be **convergent**: the same
//! plaintext body sealed under the same cell key must yield byte-identical
//! ciphertext on every node, or dedup/IPFS-convergence breaks.
//!
//! [`ContentSeal`] is that interface, kept independent of the concrete AEAD
//! scheme so `pillar-wire` never depends on which primitive backs it.
//!
//! **Interim implementation note.** The genuinely new deterministic-nonce
//! primitive (`cell_seal_convergent`/`cell_open_convergent`, HKDF over the
//! cell key + content address + domain — see the design paper §5) is its own
//! task, `cell-seal-convergent-impl`, gated on its own TLA+ obligations
//! (`ConvergentDeterministic`, `ConvergentConfidential`,
//! `NoNonceReuseAcrossDistinctPlaintext`). Until that primitive lands in
//! `pillar-crypto`, [`CellSeal`] is backed by the EXISTING random-nonce
//! [`pillar_crypto::cell::cell_encrypt`]/`cell_decrypt` — correct and secure,
//! but **not yet convergent** (sealing the same plaintext twice yields
//! different ciphertext bytes, so `Cid` dedup across independently-sealing
//! nodes does not yet hold for this seal). This is intentionally scoped:
//! `pillar-wire-crate-impl`'s task card is the envelope + codec + `Cid`
//! derivation + moved-down store; the convergent property itself is
//! `cell-seal-convergent-impl`'s deliverable, which will swap the body of
//! [`CellSeal::seal`]/[`CellSeal::open`] to the deterministic primitive
//! without changing this trait's shape. No CRDT/Merkle behavior depends on
//! convergence yet (v1 `SignedSegment` stays the read-compat path, per the
//! task card), so this interim gap is safe to ship behind the trait.

use pillar_crypto::cell::{cell_decrypt, cell_encrypt, CellGroupKey};
use pillar_crypto::{Ciphertext, Result as CryptoResult};

/// The interface a `PillarMessage` body seal implements: seal a plaintext
/// body to a cell (so any cell member can open it) and open a ciphertext
/// back to plaintext. `aad` is authenticated-but-not-encrypted associated
/// data — the envelope binds its header (version/visibility/cell) here so a
/// sealed body can never be replayed under a different header.
///
/// A **convergent** implementation additionally guarantees: sealing the same
/// `plaintext` under the same `group` key twice yields byte-identical
/// [`Ciphertext`] (so the derived [`crate::store::Cid`] is stable across
/// nodes) — see the module docs for why `CellSeal` does not yet guarantee
/// this.
pub trait ContentSeal {
    /// Seal `plaintext` to `group` (the cell group key), binding `aad`.
    ///
    /// # Errors
    /// Propagates any AEAD failure from the underlying primitive.
    fn seal(&self, group: &CellGroupKey, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Ciphertext>;

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

/// The current `pillar-wire` seal: cell-group-key AEAD via
/// `pillar_crypto::cell`. See the module docs — this is the interim,
/// **not-yet-convergent** implementation; `cell-seal-convergent-impl` swaps
/// its body for the deterministic-nonce primitive without changing the
/// [`ContentSeal`] trait shape or any caller of it.
#[derive(Clone, Copy, Debug, Default)]
pub struct CellSeal;

impl ContentSeal for CellSeal {
    fn seal(&self, group: &CellGroupKey, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Ciphertext> {
        cell_encrypt(group, plaintext, aad)
    }

    fn open(
        &self,
        group: &CellGroupKey,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        cell_decrypt(group, ciphertext, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::Seed;

    #[test]
    fn cell_seal_round_trips_and_authenticates_aad() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("key");
        let seal = CellSeal;
        let ct = seal
            .seal(&group, b"a sealed pillar-message body", b"header-aad-v1")
            .expect("seal");
        let pt = seal
            .open(&group, &ct, b"header-aad-v1")
            .expect("open");
        assert_eq!(pt, b"a sealed pillar-message body");

        // Wrong AAD is rejected (the header can't be swapped under the seal).
        assert!(seal.open(&group, &ct, b"different-aad").is_err());
    }
}
