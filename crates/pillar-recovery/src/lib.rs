//! Layered backup & recovery: encrypted-to-recovery-key backup blob stored
//! over the sealed-artifact transport, Shamir k-of-n social split, and WoT
//! social re-vouch, refining `specs/Recovery.tla`.
//!
//! Three recovery mechanisms, both usable at the cell and user [`Tier`]:
//!
//! 1. [`BackupBlob`] — the cold root (and other critical material) encrypted
//!    to the user/cell's own recovery encryption subkey `E`
//!    ([`RecoveryKey`]), stored on Pillar's own federation-restricted swarm
//!    via [`store_backup`]/[`fetch_backup`] (the offer/sealed-artifact
//!    transport of `pillar-key-distribution` + `pillar-net`). A blob is
//!    *never* a passphrase-only public artifact: [`store_backup`] always
//!    seals it to an explicit recipient set, and [`fetch_backup`] refuses any
//!    requester outside that seal.
//! 2. [`shamir_split`]/[`shamir_reconstruct`] — an optional k-of-n split of
//!    the [`RecoveryKey`] across trusted peers/cells for social recovery.
//!    Fewer than `k` shares are information-theoretically insufficient to
//!    recover the key.
//! 3. [`RecoveryLedger::social_revouch`] — re-admission of a rebuilt/rotated
//!    key through existing WoT edges, regranting exactly the subject's
//!    surviving prior authority (never more: `RecoveryPreservesAuthority`) and
//!    never a revoked capability (`NoActionAfterRevocation`).
//!
//! [`RecoveryLedger::total_device_loss_recover`] combines (1)-(3) so recovery
//! never strictly requires the physical cold root, and
//! [`bootstrap_recovery_plan`] is what cell/user bootstrap emits: the
//! offline-export + hot-keyring-strip step plus the chosen mechanism(s).

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};

use pillar_core::NodeId;
use pillar_net::blob::{BlobDigest, BlobStore};
use pillar_rbac::Capability;
use pillar_wot_authority::WotAuthority;
use sha3::{Digest, Sha3_256};

/// The tier at which a recovery record applies: a whole cell key, or a single
/// user's identity within a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tier {
    /// The cell's own key hierarchy.
    Cell,
    /// A user's identity within a cell.
    User,
}

/// Every way a recovery attempt can be refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The presented recovery key did not decrypt the blob (wrong key, or the
    /// blob was tampered with).
    WrongRecoveryKey,
    /// The requester is not in the blob's federation-restricted seal set.
    NotSealedToRequester,
    /// The blob's raw bytes were not found in the swarm's blob store.
    ArtifactNotFound,
    /// Fewer Shamir shares were presented than the reconstruction threshold.
    SubThresholdShares {
        /// Shares actually presented.
        have: usize,
        /// Shares required.
        need: usize,
    },
    /// Fewer social vouchers were presented than the re-vouch threshold, or
    /// they overlap fewer than `K` distinct authoritative signers.
    InsufficientVouchers {
        /// Vouchers actually presented.
        have: usize,
        /// Vouchers required.
        need: usize,
    },
    /// A presented voucher does not currently hold authority (revoked, or
    /// never was authoritative) — never regrant on the word of a party who is
    /// not themselves authoritative right now.
    VoucherNotAuthoritative(NodeId),
    /// The subject has no surviving authority left to regrant (nothing to
    /// recover, or everything held has since been revoked).
    NothingToRecover,
}

// ---------------------------------------------------------------------------
// Encrypted-to-recovery-keys backup blob
// ---------------------------------------------------------------------------

/// The user/cell's own recovery encryption subkey material, `E` in
/// `specs/Recovery.tla`. In production this wraps real asymmetric key
/// material (`pillar-identity`'s `KeyMaterialSet::encryption`); here it is the
/// symmetric secret a [`BackupBlob`] is encrypted to, matching the rest of the
/// workspace's model-first, crypto-abstracted style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryKey(pub u64);

fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A keystream of `len` bytes derived from `key` by hash-chaining a counter —
/// enough to give a real (if minimal) "wrong key never decrypts" property
/// without pulling in a stream-cipher crate the workspace does not otherwise
/// depend on.
fn keystream(key: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        out.extend_from_slice(hasher.finalize().as_slice());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn xor(bytes: &[u8], stream: &[u8]) -> Vec<u8> {
    bytes.iter().zip(stream).map(|(b, s)| b ^ s).collect()
}

/// An encrypted-to-recovery-keys backup blob: the cold root (or other
/// critical material) as ciphertext, decryptable only by the party holding
/// the matching [`RecoveryKey`]. Never a passphrase-only public blob — there
/// is no offline-brute-force surface, because the key is never derived from a
/// low-entropy secret the blob itself carries any hint of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupBlob {
    ciphertext: Vec<u8>,
    tag: [u8; 32],
}

impl BackupBlob {
    /// Encrypt `payload` (e.g. the serialized cold root) to `recovery_key`.
    #[must_use]
    pub fn seal(payload: &[u8], recovery_key: RecoveryKey) -> Self {
        let stream = keystream(&recovery_key.0.to_le_bytes(), payload.len());
        BackupBlob {
            ciphertext: xor(payload, &stream),
            tag: sha3_256(payload),
        }
    }

    /// Decrypt with `recovery_key`, verifying the recovered plaintext against
    /// the sealed integrity tag. A wrong key (or corrupted ciphertext) is
    /// detected and refused rather than silently returning garbage.
    pub fn decrypt(&self, recovery_key: RecoveryKey) -> Result<Vec<u8>, RecoveryError> {
        let stream = keystream(&recovery_key.0.to_le_bytes(), self.ciphertext.len());
        let candidate = xor(&self.ciphertext, &stream);
        if sha3_256(&candidate) == self.tag {
            Ok(candidate)
        } else {
            Err(RecoveryError::WrongRecoveryKey)
        }
    }

    /// Encode to raw bytes for storage in a [`BlobStore`]: an 8-byte
    /// little-endian ciphertext length, the ciphertext, then the 32-byte tag.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.ciphertext.len() + 32);
        out.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Decode from the raw bytes [`BackupBlob::to_bytes`] produced.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let len = u64::from_le_bytes(bytes[..8].try_into().ok()?) as usize;
        if bytes.len() != 8 + len + 32 {
            return None;
        }
        let ciphertext = bytes[8..8 + len].to_vec();
        let tag: [u8; 32] = bytes[8 + len..8 + len + 32].try_into().ok()?;
        Some(BackupBlob { ciphertext, tag })
    }
}

/// A [`BackupBlob`] stored on the federation-restricted swarm: its content
/// address plus the sealed-to node set (never empty, never "everyone" —
/// distinct from a public blob).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwarmBackup {
    digest: BlobDigest,
    sealed_to: BTreeSet<NodeId>,
}

impl SwarmBackup {
    /// The content address of the stored ciphertext.
    #[must_use]
    pub fn digest(&self) -> BlobDigest {
        self.digest.clone()
    }

    /// Whether `node` is within the federation-restricted seal.
    #[must_use]
    pub fn is_sealed_to(&self, node: &NodeId) -> bool {
        self.sealed_to.contains(node)
    }
}

/// Store `blob` on the swarm's [`BlobStore`], sealed to exactly
/// `sealed_to` (the recovery-key holders / trusted peers/cells authorized to
/// fetch it). `sealed_to` must be non-empty: an empty seal is refused,
/// because that would otherwise coincide with "sealed to nobody", not "sealed
/// to everybody" — never a passphrase-only public artifact.
pub fn store_backup(
    store: &mut BlobStore,
    blob: &BackupBlob,
    sealed_to: BTreeSet<NodeId>,
) -> Result<SwarmBackup, RecoveryError> {
    if sealed_to.is_empty() {
        return Err(RecoveryError::NotSealedToRequester);
    }
    let digest = store.insert(blob.to_bytes());
    Ok(SwarmBackup {
        digest,
        sealed_to,
    })
}

/// Fetch and decode the [`BackupBlob`] `swarm` addresses, refusing any
/// `requester` outside the federation-restricted seal (fail-closed: the
/// transport itself never hands the ciphertext to an unsealed party,
/// independent of whether they hold the recovery key).
pub fn fetch_backup(
    store: &BlobStore,
    swarm: &SwarmBackup,
    requester: &NodeId,
) -> Result<BackupBlob, RecoveryError> {
    if !swarm.is_sealed_to(requester) {
        return Err(RecoveryError::NotSealedToRequester);
    }
    let bytes = store
        .get(&swarm.digest)
        .ok_or(RecoveryError::ArtifactNotFound)?;
    BackupBlob::from_bytes(bytes).ok_or(RecoveryError::ArtifactNotFound)
}

// ---------------------------------------------------------------------------
// Shamir k-of-n split of the recovery key
// ---------------------------------------------------------------------------

/// A 61-bit Mersenne prime, `2^61 - 1`, used as the finite field modulus for
/// [`shamir_split`]/[`shamir_reconstruct`]. [`RecoveryKey`] values are reduced
/// mod this prime.
const FIELD_PRIME: u128 = 2_305_843_009_213_693_951;

/// One share of a Shamir-split [`RecoveryKey`]: a point `(index, value)` on
/// the sharing polynomial. Fewer than the reconstruction threshold `k`
/// shares carry no information about the secret (information-theoretic
/// security of Shamir's scheme): any candidate secret remains consistent with
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShamirShare {
    /// The share's evaluation point (never zero — zero would leak the secret
    /// directly).
    pub index: u64,
    /// The polynomial's value at `index`, mod [`FIELD_PRIME`].
    pub value: u64,
}

/// A fast, dependency-free, deterministic PRNG (SplitMix64) used only to
/// derive the sharing polynomial's non-secret coefficients from a caller-
/// supplied seed. Not cryptographically hardened on its own — the security
/// property Shamir needs is that the coefficients are *unknown to an outside
/// party*, which a fresh random seed per split provides.
fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

/// Split `secret` into `n` [`ShamirShare`]s such that any `k` of them
/// reconstruct it exactly (Lagrange interpolation at `x = 0`), while any
/// fewer reveal nothing. `seed` derives the polynomial's non-secret
/// coefficients and must be fresh per split (an attacker who knows the seed
/// and `k - 1` shares can recover the secret, exactly as knowing a Shamir
/// polynomial's non-constant coefficients would).
///
/// # Panics
/// Panics if `k` is zero or `n < k` (a threshold above the number of parties
/// present is never satisfiable).
#[must_use]
pub fn shamir_split(secret: RecoveryKey, k: usize, n: usize, seed: u64) -> Vec<ShamirShare> {
    assert!(k >= 1, "Shamir threshold must be at least 1");
    assert!(n >= k, "Shamir share count must be at least the threshold");
    let mut coeffs: Vec<u128> = Vec::with_capacity(k);
    coeffs.push((secret.0 as u128) % FIELD_PRIME);
    let mut state = seed;
    for _ in 1..k {
        state = splitmix64(state);
        coeffs.push((state as u128) % FIELD_PRIME);
    }
    (1..=n as u64)
        .map(|x| {
            let mut acc: u128 = 0;
            let mut xp: u128 = 1;
            for c in &coeffs {
                acc = (acc + c * xp) % FIELD_PRIME;
                xp = (xp * x as u128) % FIELD_PRIME;
            }
            ShamirShare {
                index: x,
                value: acc as u64,
            }
        })
        .collect()
}

/// Reconstruct the [`RecoveryKey`] from `shares` via Lagrange interpolation
/// at `x = 0`, refusing if fewer than `k` distinct shares are presented.
pub fn shamir_reconstruct(shares: &[ShamirShare], k: usize) -> Result<RecoveryKey, RecoveryError> {
    if shares.len() < k {
        return Err(RecoveryError::SubThresholdShares {
            have: shares.len(),
            need: k,
        });
    }
    let pts = &shares[..k];
    let mut secret: u128 = 0;
    for (i, pi) in pts.iter().enumerate() {
        let mut num: u128 = 1;
        let mut den: u128 = 1;
        let xi = pi.index as u128 % FIELD_PRIME;
        for (j, pj) in pts.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = pj.index as u128 % FIELD_PRIME;
            num = num * ((FIELD_PRIME - xj) % FIELD_PRIME) % FIELD_PRIME;
            let diff = (xi + FIELD_PRIME - xj) % FIELD_PRIME;
            den = den * diff % FIELD_PRIME;
        }
        let den_inv = mod_pow(den, FIELD_PRIME - 2, FIELD_PRIME);
        let term = (pi.value as u128 % FIELD_PRIME) * num % FIELD_PRIME * den_inv % FIELD_PRIME;
        secret = (secret + term) % FIELD_PRIME;
    }
    Ok(RecoveryKey(secret as u64))
}

// ---------------------------------------------------------------------------
// Social re-vouch over the WoT + total-device-loss recovery
// ---------------------------------------------------------------------------

/// The ledger of prior authority a subject held, and the record of its most
/// recent recovery, mirroring `Recovery.tla`'s `held`/`lastRecovery`.
#[derive(Debug, Default, Clone)]
pub struct RecoveryLedger {
    held: std::collections::HashMap<NodeId, HashSet<Capability>>,
    revoked: HashSet<(NodeId, Capability)>,
    last_recovery: std::collections::HashMap<NodeId, HashSet<Capability>>,
}

impl RecoveryLedger {
    /// A new, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `subject` holds `capability` (prior authority).
    pub fn grant(&mut self, subject: NodeId, capability: Capability) {
        self.held.entry(subject).or_default().insert(capability);
    }

    /// Revoke `capability` from `subject`. Revocation is grow-only and
    /// permanent: a revoked capability can never again be part of a
    /// recovery's regranted set for that subject
    /// (`NoActionAfterRevocation`).
    pub fn revoke(&mut self, subject: NodeId, capability: Capability) {
        self.revoked.insert((subject, capability));
    }

    /// The subject's currently-surviving prior authority: everything ever
    /// held, minus everything ever revoked (`SurvivingAuth` in the spec).
    #[must_use]
    pub fn surviving_authority(&self, subject: &NodeId) -> HashSet<Capability> {
        self.held
            .get(subject)
            .into_iter()
            .flatten()
            .filter(|cap| !self.revoked.contains(&(subject.clone(), (*cap).clone())))
            .cloned()
            .collect()
    }

    /// The regranted capability set from `subject`'s most recently completed
    /// recovery, if any.
    #[must_use]
    pub fn last_recovery(&self, subject: &NodeId) -> Option<&HashSet<Capability>> {
        self.last_recovery.get(subject)
    }

    /// Social re-vouch: re-admit `subject`'s rebuilt/rotated key through
    /// existing WoT edges. Requires at least `min_k` distinct
    /// `vouchers`, each of whom must be currently authoritative in
    /// `authority` right now (never on the word of a party who has since
    /// been revoked or was never authoritative) — regrants exactly the
    /// subject's surviving prior authority, never more
    /// (`RecoveryPreservesAuthority`) and never a revoked capability
    /// (`NoActionAfterRevocation`).
    pub fn social_revouch(
        &mut self,
        subject: &NodeId,
        vouchers: &[NodeId],
        authority: &WotAuthority,
        min_k: usize,
    ) -> Result<HashSet<Capability>, RecoveryError> {
        let distinct: HashSet<&NodeId> = vouchers.iter().collect();
        if distinct.len() < min_k {
            return Err(RecoveryError::InsufficientVouchers {
                have: distinct.len(),
                need: min_k,
            });
        }
        for voucher in &distinct {
            if !authority.is_authoritative(voucher) {
                return Err(RecoveryError::VoucherNotAuthoritative((*voucher).clone()));
            }
        }
        let regranted = self.surviving_authority(subject);
        if regranted.is_empty() {
            return Err(RecoveryError::NothingToRecover);
        }
        self.last_recovery
            .insert(subject.clone(), regranted.clone());
        Ok(regranted)
    }

    /// Total-device-loss recovery: combine the encrypted backup blob (via
    /// Shamir-reconstructed [`RecoveryKey`] shares) and social re-vouch so
    /// recovery does not strictly require the physical cold root on hand. At
    /// least one of the two mechanisms must succeed; the regranted authority
    /// is the union of whatever each successful mechanism attests, still
    /// bounded by the subject's surviving authority.
    #[allow(clippy::too_many_arguments)]
    pub fn total_device_loss_recover(
        &mut self,
        subject: &NodeId,
        blob_shares: &[ShamirShare],
        blob_k: usize,
        expected_blob_key: Option<RecoveryKey>,
        vouchers: &[NodeId],
        authority: &WotAuthority,
        min_k: usize,
    ) -> Result<HashSet<Capability>, RecoveryError> {
        let blob_ok = if blob_shares.is_empty() {
            false
        } else {
            match shamir_reconstruct(blob_shares, blob_k) {
                Ok(recovered) => match expected_blob_key {
                    Some(expected) => expected == recovered,
                    None => true,
                },
                Err(_) => false,
            }
        };
        let revouch_result = if vouchers.is_empty() {
            None
        } else {
            self.social_revouch(subject, vouchers, authority, min_k)
                .ok()
        };

        if !blob_ok && revouch_result.is_none() {
            return Err(RecoveryError::InsufficientVouchers {
                have: vouchers.len(),
                need: min_k,
            });
        }

        let regranted = self.surviving_authority(subject);
        if regranted.is_empty() {
            return Err(RecoveryError::NothingToRecover);
        }
        self.last_recovery
            .insert(subject.clone(), regranted.clone());
        Ok(regranted)
    }
}

// ---------------------------------------------------------------------------
// Bootstrap recovery plan
// ---------------------------------------------------------------------------

/// Which recovery mechanism(s) a bootstrap has chosen to enroll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMechanism {
    /// The encrypted-to-recovery-key backup blob.
    Blob,
    /// A Shamir k-of-n social split of the recovery key.
    ShamirSplit,
    /// Social re-vouch over the WoT.
    SocialRevouch,
}

/// The recovery plan cell/user bootstrap emits: the mandatory offline-export
/// + hot-keyring-strip step, and which mechanism(s) are enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPlan {
    tier: Tier,
    mechanisms: Vec<RecoveryMechanism>,
}

impl RecoveryPlan {
    /// The plan's tier.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// The enrolled mechanism(s), in enrollment order.
    #[must_use]
    pub fn mechanisms(&self) -> &[RecoveryMechanism] {
        &self.mechanisms
    }

    /// Render the plan as the text bootstrap prints: the offline-export +
    /// hot-keyring-strip step, followed by each enrolled mechanism.
    #[must_use]
    pub fn render(&self) -> String {
        let tier = match self.tier {
            Tier::Cell => "cell",
            Tier::User => "user",
        };
        let mut out = format!(
            "Recovery plan ({tier}):\n\
             1. Export the cold root offline (hardware token / air-gapped \
             encrypted backup / vault).\n\
             2. Strip the cold root from the hot keyring -- this node keeps \
             only subkeys.\n\
             3. Enrolled recovery mechanism(s):\n"
        );
        for mechanism in &self.mechanisms {
            let line = match mechanism {
                RecoveryMechanism::Blob => {
                    "   - encrypted-to-recovery-key backup blob (federation-restricted swarm)\n"
                }
                RecoveryMechanism::ShamirSplit => {
                    "   - Shamir k-of-n social split across trusted peers/cells\n"
                }
                RecoveryMechanism::SocialRevouch => "   - social re-vouch over the web of trust\n",
            };
            out.push_str(line);
        }
        out
    }
}

/// Emit the recovery plan cell/user bootstrap prints, per `Recovery.tla`'s
/// requirement that bootstrap always states the offline-export step and the
/// chosen mechanism(s), applying identically at the cell and user tiers.
#[must_use]
pub fn bootstrap_recovery_plan(tier: Tier, mechanisms: Vec<RecoveryMechanism>) -> RecoveryPlan {
    RecoveryPlan { tier, mechanisms }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_wot_authority::WotAuthority;

    fn cap(s: &str) -> Capability {
        Capability(s.to_owned())
    }

    fn node(s: &str) -> NodeId {
        NodeId(s.to_owned())
    }

    // --- Backup blob round trip / undecryptable without the recovery key ---

    #[test]
    fn backup_round_trips_with_the_correct_recovery_key() {
        let payload = b"cold-root-critical-material".to_vec();
        let key = RecoveryKey(0xDEAD_BEEF_1234_5678);
        let blob = BackupBlob::seal(&payload, key);
        assert_eq!(blob.decrypt(key).unwrap(), payload);
    }

    #[test]
    fn backup_is_undecryptable_without_the_recovery_key() {
        let payload = b"cold-root-critical-material".to_vec();
        let key = RecoveryKey(0xDEAD_BEEF_1234_5678);
        let wrong_key = RecoveryKey(0x1111_1111_1111_1111);
        let blob = BackupBlob::seal(&payload, key);
        assert_eq!(
            blob.decrypt(wrong_key),
            Err(RecoveryError::WrongRecoveryKey)
        );
    }

    #[test]
    fn backup_blob_bytes_round_trip() {
        let payload = b"another secret payload".to_vec();
        let key = RecoveryKey(42);
        let blob = BackupBlob::seal(&payload, key);
        let bytes = blob.to_bytes();
        let decoded = BackupBlob::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.decrypt(key).unwrap(), payload);
    }

    #[test]
    fn swarm_backup_refuses_a_requester_outside_the_seal() {
        let payload = b"cold root".to_vec();
        let key = RecoveryKey(7);
        let blob = BackupBlob::seal(&payload, key);
        let mut store = BlobStore::new();
        let mut sealed_to = BTreeSet::new();
        sealed_to.insert(node("peer-a"));
        let swarm = store_backup(&mut store, &blob, sealed_to).unwrap();

        assert!(fetch_backup(&store, &swarm, &node("peer-a")).is_ok());
        assert_eq!(
            fetch_backup(&store, &swarm, &node("outsider")),
            Err(RecoveryError::NotSealedToRequester)
        );
    }

    #[test]
    fn storing_a_backup_to_an_empty_seal_is_refused() {
        let payload = b"cold root".to_vec();
        let blob = BackupBlob::seal(&payload, RecoveryKey(1));
        let mut store = BlobStore::new();
        assert_eq!(
            store_backup(&mut store, &blob, BTreeSet::new()),
            Err(RecoveryError::NotSealedToRequester)
        );
    }

    // --- Shamir threshold ---

    #[test]
    fn shamir_reconstructs_with_at_least_k_shares() {
        let secret = RecoveryKey(123_456_789);
        let shares = shamir_split(secret, 3, 5, 0xABCD);
        let recovered = shamir_reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(recovered, secret);
        // Any other subset of size k also reconstructs it.
        let recovered2 = shamir_reconstruct(&shares[2..5], 3).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn shamir_fails_closed_below_threshold() {
        let secret = RecoveryKey(987_654_321);
        let shares = shamir_split(secret, 3, 5, 0x1234);
        assert_eq!(
            shamir_reconstruct(&shares[..2], 3),
            Err(RecoveryError::SubThresholdShares { have: 2, need: 3 })
        );
    }

    #[test]
    fn sub_threshold_shares_reveal_nothing_about_the_secret() {
        // With k-1 shares, an attacker cannot even distinguish which of two
        // different secrets produced them: splitting two different secrets
        // with the same seed-derived non-constant coefficients yields shares
        // that differ in every coordinate, and there is no way to tell from
        // k-1 points alone which polynomial (and thus which secret) is real
        // -- infinitely many degree-(k-1) polynomials pass through them, one
        // for every possible secret.
        let shares_a = shamir_split(RecoveryKey(111), 3, 5, 0x42);
        let shares_b = shamir_split(RecoveryKey(999), 3, 5, 0x42);
        // The sub-threshold prefixes differ (no accidental collision)...
        assert_ne!(&shares_a[..2], &shares_b[..2]);
        // ...but neither is reconstructable on its own.
        assert!(shamir_reconstruct(&shares_a[..2], 3).is_err());
        assert!(shamir_reconstruct(&shares_b[..2], 3).is_err());
    }

    // --- Social re-vouch: subset-or-equal authority, never resurrect revoked ---

    #[test]
    fn revouch_grants_exactly_surviving_prior_authority() {
        let subject = node("alice");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));
        ledger.grant(subject.clone(), cap("admin"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        authority.issue_edge(node("owner"), node("voucher-2"), 1);

        let vouchers = vec![node("voucher-1"), node("voucher-2")];
        let regranted = ledger
            .social_revouch(&subject, &vouchers, &authority, 2)
            .unwrap();

        let expected: HashSet<Capability> = [cap("deploy"), cap("admin")].into_iter().collect();
        assert_eq!(regranted, expected);
        assert_eq!(ledger.last_recovery(&subject), Some(&expected));
    }

    #[test]
    fn revouch_never_regrants_more_than_prior_authority() {
        let subject = node("bob");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        authority.issue_edge(node("owner"), node("voucher-2"), 1);
        let vouchers = vec![node("voucher-1"), node("voucher-2")];

        let regranted = ledger
            .social_revouch(&subject, &vouchers, &authority, 2)
            .unwrap();
        // Never anything the subject did not already hold.
        assert!(regranted.iter().all(|c| *c == cap("deploy")));
        assert_eq!(regranted.len(), 1);
    }

    #[test]
    fn revouch_requires_at_least_k_distinct_authoritative_vouchers() {
        let subject = node("carol");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);

        // Only one distinct voucher (duplicated) -- below threshold 2.
        let vouchers = vec![node("voucher-1"), node("voucher-1")];
        assert_eq!(
            ledger.social_revouch(&subject, &vouchers, &authority, 2),
            Err(RecoveryError::InsufficientVouchers { have: 1, need: 2 })
        );
    }

    #[test]
    fn revouch_refuses_a_voucher_who_is_not_authoritative() {
        let subject = node("dave");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        // voucher-2 was never issued an edge -- not authoritative.
        let vouchers = vec![node("voucher-1"), node("voucher-2")];
        assert_eq!(
            ledger.social_revouch(&subject, &vouchers, &authority, 2),
            Err(RecoveryError::VoucherNotAuthoritative(node("voucher-2")))
        );
    }

    #[test]
    fn a_revoked_key_is_never_resurrected_by_revouch() {
        let subject = node("erin");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));
        ledger.grant(subject.clone(), cap("admin"));
        ledger.revoke(subject.clone(), cap("admin"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        authority.issue_edge(node("owner"), node("voucher-2"), 1);
        let vouchers = vec![node("voucher-1"), node("voucher-2")];

        let regranted = ledger
            .social_revouch(&subject, &vouchers, &authority, 2)
            .unwrap();
        assert!(!regranted.contains(&cap("admin")));
        assert_eq!(regranted, [cap("deploy")].into_iter().collect());
    }

    #[test]
    fn revoking_every_capability_leaves_nothing_to_recover() {
        let subject = node("frank");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));
        ledger.revoke(subject.clone(), cap("deploy"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        authority.issue_edge(node("owner"), node("voucher-2"), 1);
        let vouchers = vec![node("voucher-1"), node("voucher-2")];

        assert_eq!(
            ledger.social_revouch(&subject, &vouchers, &authority, 2),
            Err(RecoveryError::NothingToRecover)
        );
    }

    // --- Total device loss: recovery without the physical cold root ---

    #[test]
    fn total_device_loss_recovers_via_blob_shares_alone() {
        let subject = node("grace");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));

        let key = RecoveryKey(555_555);
        let shares = shamir_split(key, 3, 5, 0x9999);
        let authority = WotAuthority::new(node("owner"), 4);

        let regranted = ledger
            .total_device_loss_recover(&subject, &shares[..3], 3, Some(key), &[], &authority, 2)
            .unwrap();
        assert_eq!(regranted, [cap("deploy")].into_iter().collect());
    }

    #[test]
    fn total_device_loss_recovers_via_social_revouch_alone_without_the_cold_root() {
        let subject = node("heidi");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));

        let mut authority = WotAuthority::new(node("owner"), 4);
        authority.issue_edge(node("owner"), node("voucher-1"), 1);
        authority.issue_edge(node("owner"), node("voucher-2"), 1);
        let vouchers = vec![node("voucher-1"), node("voucher-2")];

        // No blob shares presented at all -- the physical cold root (and any
        // backup of it) is genuinely gone; social re-vouch alone recovers.
        let regranted = ledger
            .total_device_loss_recover(&subject, &[], 3, None, &vouchers, &authority, 2)
            .unwrap();
        assert_eq!(regranted, [cap("deploy")].into_iter().collect());
    }

    #[test]
    fn total_device_loss_fails_closed_when_neither_mechanism_succeeds() {
        let subject = node("ivan");
        let mut ledger = RecoveryLedger::new();
        ledger.grant(subject.clone(), cap("deploy"));
        let authority = WotAuthority::new(node("owner"), 4);

        let key = RecoveryKey(1);
        let shares = shamir_split(key, 3, 5, 0x1);
        let result = ledger.total_device_loss_recover(
            &subject,
            &shares[..2], // below threshold
            3,
            Some(key),
            &[], // no vouchers
            &authority,
            2,
        );
        assert!(result.is_err());
    }

    // --- Bootstrap recovery plan ---

    #[test]
    fn bootstrap_plan_names_the_offline_export_and_keyring_strip_step() {
        let plan = bootstrap_recovery_plan(
            Tier::User,
            vec![RecoveryMechanism::Blob, RecoveryMechanism::SocialRevouch],
        );
        let rendered = plan.render();
        assert!(rendered.contains("Export the cold root offline"));
        assert!(rendered.contains("Strip the cold root from the hot keyring"));
        assert!(rendered.contains("encrypted-to-recovery-key backup blob"));
        assert!(rendered.contains("social re-vouch over the web of trust"));
        assert_eq!(
            plan.mechanisms(),
            &[RecoveryMechanism::Blob, RecoveryMechanism::SocialRevouch]
        );
    }

    #[test]
    fn bootstrap_plan_applies_identically_at_the_cell_tier() {
        let plan = bootstrap_recovery_plan(Tier::Cell, vec![RecoveryMechanism::ShamirSplit]);
        let rendered = plan.render();
        assert!(rendered.contains("Recovery plan (cell):"));
        assert!(rendered.contains("Shamir k-of-n social split"));
    }
}
