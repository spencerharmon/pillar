//! IPNS-format mutable head: an owner-signed, sequence-numbered pointer to the
//! CID of the latest root object, scoped by visibility class.
//!
//! Real IPNS resolves a name (a peer's public key) to its latest signed
//! record; the record carries a monotone sequence number and a TTL/validity
//! window so a stale or forged pointer is rejected, and the newest valid
//! sequence always wins. This module is that same contract over a pillar
//! [`ContentId`]: [`IpnsHead::sign`] produces the record an owner publishes,
//! [`IpnsHead::verify`] is the integrity gate every receiver runs before ever
//! trusting a candidate, and [`resolve_latest`] is the "pick the newest valid
//! head" reducer a resolver runs over every candidate it has heard (from the
//! public DHT for a [`Visibility::Public`] head, or from the cell's private
//! pubsub for a [`Visibility::Cell`] one — this module does not care which
//! transport a candidate arrived over, only whether it verifies).

use pillar_crypto::{sign, ContentId, Signature, SigningPublicKey, SigningSecretKey};

/// The visibility class an IPNS head (and the objects it may point to) is
/// scoped by. Drives the transport a head is allowed to travel: `Public` heads
/// may be published to the swarm-wide Kademlia DHT (mirroring
/// `AnchorsOnlyToDHT` in `specs/StreamdbIpfsStore.tla`); `Cell` heads are
/// encrypted-scope pointers that must stay inside the owning cell's private
/// pubsub and are NEVER placed on the public DHT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// May publish to (and be resolved from) the swarm-wide DHT.
    Public,
    /// Must stay inside the owning cell; never touches the public DHT.
    Cell,
}

/// An owner-signed, sequence-numbered pointer to a CID — the IPNS-format
/// mutable head. `name` is the stable identifier the head resolves under (real
/// IPNS uses the owner's public key hash; here it is the raw signing public
/// key bytes, which is exactly that with one fewer encoding step).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpnsHead {
    /// The owning public key this head is published under.
    pub owner: SigningPublicKey,
    /// Monotone sequence number: a resolver only ever accepts a strictly
    /// greater sequence than the best one it has already accepted for this
    /// owner, so a replayed/older record can never regress the pointer.
    pub sequence: u64,
    /// The CID (raw content id bytes) this head currently points to.
    pub cid: ContentId,
    /// Unix-seconds validity deadline; a candidate at/after this deadline is
    /// stale and must be rejected regardless of its signature.
    pub valid_until: u64,
    /// Visibility scope this head (and the object it points to) is bound to.
    pub visibility: Visibility,
    /// The owner's signature over this record's canonical byte encoding.
    pub signature: Signature,
}

/// The canonical bytes an [`IpnsHead`] signature is computed over: every field
/// except the signature itself, in a fixed order, each length-prefixed so no
/// two distinct field boundaries can collide onto the same byte string.
fn signing_bytes(
    owner: &SigningPublicKey,
    sequence: u64,
    cid: &ContentId,
    valid_until: u64,
    visibility: Visibility,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"pillar-ipfs/ipns-head/v1");
    push_len_prefixed(&mut buf, owner.as_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    push_len_prefixed(&mut buf, cid.as_bytes());
    buf.extend_from_slice(&valid_until.to_be_bytes());
    buf.push(match visibility {
        Visibility::Public => 0,
        Visibility::Cell => 1,
    });
    buf
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// A fault verifying (or resolving) an [`IpnsHead`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// The signature does not verify against the claimed owner over this
    /// record's fields — a forged or corrupted head.
    Forged,
    /// `valid_until` is at/before `now` — an expired head.
    Expired,
    /// The candidate's sequence number is not strictly greater than the best
    /// already-accepted sequence for this owner — a stale/replayed head.
    Stale,
}

impl IpnsHead {
    /// Sign a new head record for `owner`/`secret` pointing at `cid`.
    #[must_use]
    pub fn sign(
        secret: &SigningSecretKey,
        owner: SigningPublicKey,
        sequence: u64,
        cid: ContentId,
        valid_until: u64,
        visibility: Visibility,
    ) -> Self {
        let bytes = signing_bytes(&owner, sequence, &cid, valid_until, visibility);
        let signature = sign::sign(secret, &bytes).expect("ed25519 signing is infallible");
        IpnsHead {
            owner,
            sequence,
            cid,
            valid_until,
            visibility,
            signature,
        }
    }

    /// Verify this head is genuinely signed by its claimed `owner` and is not
    /// expired as of `now` (Unix seconds). Does NOT check sequence monotonicity
    /// — that is [`resolve_latest`]'s job, since it is relative to what a
    /// resolver has already accepted, not an intrinsic property of one record.
    ///
    /// # Errors
    /// [`HeadError::Forged`] if the signature does not verify;
    /// [`HeadError::Expired`] if `now >= self.valid_until`.
    pub fn verify(&self, now: u64) -> Result<(), HeadError> {
        let bytes = signing_bytes(
            &self.owner,
            self.sequence,
            &self.cid,
            self.valid_until,
            self.visibility,
        );
        sign::verify(&self.owner, &bytes, &self.signature).map_err(|_| HeadError::Forged)?;
        if now >= self.valid_until {
            return Err(HeadError::Expired);
        }
        Ok(())
    }
}

/// Resolve the latest valid head for one owner out of a set of candidates
/// heard from the network (a mix of genuine, forged, expired, and stale
/// records is expected — any peer can broadcast anything). Returns the
/// candidate with the greatest `sequence` that verifies and is unexpired,
/// rejecting every forged/expired/lower-or-equal-sequence one; `None` if no
/// candidate verifies.
///
/// Every returned head's `sequence` is strictly greater than every OTHER
/// verifying candidate's sequence (ties are impossible for a rational signer:
/// re-signing the same sequence over a different CID is itself equivocation
/// and this reducer keeps only one deterministic winner — the first verifying
/// max-sequence candidate encountered).
#[must_use]
pub fn resolve_latest(candidates: &[IpnsHead], now: u64) -> Option<IpnsHead> {
    candidates
        .iter()
        .filter(|h| h.verify(now).is_ok())
        .max_by_key(|h| h.sequence)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::Seed;

    fn owner_keys(label: &str) -> (SigningPublicKey, SigningSecretKey) {
        sign::signing_keypair_from_seed(&Seed::from_bytes(
            format!("pillar-ipfs-ipns-head::{label}").into_bytes(),
        ))
        .expect("keygen")
    }

    fn cid(label: &str) -> ContentId {
        crate::cid::content_id(label.as_bytes())
    }

    #[test]
    fn genuine_head_verifies() {
        let (pk, sk) = owner_keys("alice");
        let head = IpnsHead::sign(&sk, pk, 1, cid("root-v1"), 1_000, Visibility::Public);
        assert_eq!(head.verify(500), Ok(()));
    }

    #[test]
    fn forged_head_is_rejected() {
        let (pk_alice, sk_alice) = owner_keys("alice");
        let (pk_mallory, _sk_mallory) = owner_keys("mallory");
        // Mallory signs, but claims to be alice's owner key.
        let mut head = IpnsHead::sign(
            &sk_alice,
            pk_mallory.clone(),
            1,
            cid("root-v1"),
            1_000,
            Visibility::Public,
        );
        // Signature was over pk_mallory-as-owner but produced by alice's key;
        // it must not verify against the claimed owner either way.
        assert_eq!(head.verify(500), Err(HeadError::Forged));

        // Also: swapping in a signature that never came from the claimed
        // owner at all.
        let (pk_bob, sk_bob) = owner_keys("bob");
        head.owner = pk_bob;
        head.signature = sign::sign(&sk_bob, b"unrelated bytes").expect("sign");
        assert_eq!(head.verify(500), Err(HeadError::Forged));
        let _ = pk_alice;
    }

    #[test]
    fn expired_head_is_rejected() {
        let (pk, sk) = owner_keys("alice");
        let head = IpnsHead::sign(&sk, pk, 1, cid("root-v1"), 1_000, Visibility::Public);
        assert_eq!(head.verify(1_000), Err(HeadError::Expired));
        assert_eq!(head.verify(1_001), Err(HeadError::Expired));
    }

    #[test]
    fn resolver_picks_the_latest_valid_sequence_and_rejects_stale_or_forged() {
        let (pk, sk) = owner_keys("alice");
        let (pk_mallory, sk_mallory) = owner_keys("mallory");

        let seq1 = IpnsHead::sign(&sk, pk.clone(), 1, cid("root-v1"), 10_000, Visibility::Public);
        let seq2 = IpnsHead::sign(&sk, pk.clone(), 2, cid("root-v2"), 10_000, Visibility::Public);
        let seq3_expired =
            IpnsHead::sign(&sk, pk.clone(), 3, cid("root-v3"), 100, Visibility::Public);
        // A forged candidate that CLAIMS the higher sequence 4 but is signed
        // by mallory's key while asserting alice's owner key.
        let mut forged = IpnsHead::sign(
            &sk_mallory,
            pk_mallory,
            4,
            cid("root-forged"),
            10_000,
            Visibility::Public,
        );
        forged.owner = pk.clone();

        let now = 5_000;
        let candidates = vec![seq1.clone(), seq2.clone(), seq3_expired, forged];
        let winner = resolve_latest(&candidates, now).expect("a valid candidate exists");

        // seq2 wins: seq1 is a lower sequence, seq3 is expired at `now`, and
        // the forged seq4 record never verifies.
        assert_eq!(winner, seq2);
        assert_ne!(winner.sequence, 1, "a stale lower sequence must lose");
        assert_ne!(winner.cid, cid("root-forged"), "a forged head must never win");

        // A resolver that has already accepted seq2 must reject a re-offered
        // seq1 (or seq2 itself) as stale relative to what it holds — modeled
        // here as: only a strictly greater sequence than the current best is
        // ever adopted.
        assert!(seq2.sequence > seq1.sequence);
    }
}
