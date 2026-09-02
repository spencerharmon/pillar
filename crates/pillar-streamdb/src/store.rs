//! IPFS/libp2p durable content-object store surface — the Rust refinement of
//! `specs/StreamdbIpfsStore.tla`.
//!
//! The 2026-08-31 audit ROI correction is non-negotiable: the streaming DB's
//! DURABLE persistence rides an IPFS / libp2p content-object store — pillar's
//! OWN private libp2p swarm, OFF the public IPFS DHT — owned by the IPFS/libp2p
//! plugin (non-negotiable #5: the plugin OWNS content-addressing; the streaming
//! DB never re-implements it on local disk). This module is the plugin-side
//! store surface the persistence layer targets, built ON TOP of the existing
//! canonical content-addressing ([`crate::content_address`], a real SHA2-256
//! multihash from `pillar-crypto`) and signing (`pillar_crypto::sign`) — NOT a
//! new IPFS re-implementation under a pillar name.
//!
//! Surface (each a refinement of an action/invariant in `StreamdbIpfsStore.tla`):
//!
//! - [`ContentStore::put`] — store a signed segment; its id is [`Cid`], a pure
//!   function of its bytes (a REAL multihash, never FNV/`DefaultHasher`). The
//!   segment carries an owner signature over its content, verified on `put`, so
//!   a forged/tampered segment is rejected before it is ever stored. Refines
//!   `Put` / `ContentAddressCorrect`.
//! - [`ContentStore::get`] — resolve a `Cid` from the local pin/held set, else
//!   BACKFILL it from a reachable peer over pillar's OWN private swarm and
//!   VERIFY the received bytes against the `Cid` before accepting them (a peer
//!   can never substitute wrong content for a `Cid`). Refines `Backfill`.
//! - [`ContentStore::pin`] / [`ContentStore::provide`] — pin marks a held
//!   segment durable (never GC'd); provide advertises a segment to the swarm's
//!   Kademlia DHT — but ONLY a public anchor/ROOT segment. A cell/encrypted
//!   segment is never advertised to the DHT. Refines `Pin` / `Provide` /
//!   `AnchorsOnlyToDHT`.
//! - [`MutableHead`] — an IPNS-format mutable head: owner-signed, sequence-
//!   numbered (monotone), TTL'd, scoped by [`Visibility`]. A newer head is
//!   accepted only when signed by the head's owner AND its sequence strictly
//!   advances; a stale/lower-sequence or forged head is rejected. A `public`
//!   head may be published to the swarm DHT; a `cell`/`sealed` head stays inside
//!   the cell over pubsub, never the public DHT. Refines `PublishHead` /
//!   `HeadSequenceMonotonic` / `HeadSignedByOwner`.
//!
//! Kademlia here is pillar's OWN private-swarm DHT, never the public IPFS DHT —
//! this type models the plugin's abstract store the persistence layer rides, and
//! the network wiring is provided by `pillar_net::blob` (the request/response
//! substrate that already verifies content against its digest on receipt).

use std::collections::{BTreeMap, HashMap, HashSet};

use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{ContentId, Signature, SigningPublicKey, SigningSecretKey};

use crate::content_address;

/// A content identifier: the durable store's address for a content object,
/// a pure, collision-resistant function of the object's bytes.
///
/// It IS the canonical pillar content address ([`crate::content_address`], a
/// real SHA2-256 multihash) — the SAME bytes-to-identity function the op-log
/// ([`crate::OpId`]) and the blob layer (`pillar_net::blob::BlobDigest`) use, so
/// a segment's `Cid` is identical across every layer and every node without
/// coordination. Never a checksum: an adversary cannot forge a distinct segment
/// sharing a `Cid`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cid(pub ContentId);

// `ContentId` is deliberately not `Ord` (the crypto layer treats it as opaque),
// so — like `OpId` — impose a total order by lexicographic comparison of the
// multihash bytes: a pure function of content, identical on every node.
impl PartialOrd for Cid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Cid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl Cid {
    /// The `Cid` of `bytes`, via the canonical content-addressing function.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Cid(content_address(bytes))
    }

    /// The raw multihash bytes of this `Cid`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `bytes` actually hash to this `Cid` (content-address
    /// verification — the check a receiver runs on a backfilled segment).
    #[must_use]
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        Cid::of(bytes) == *self
    }
}

/// The visibility class of a content object / mutable head.
///
/// It governs DHT discipline (`AnchorsOnlyToDHT`): only a [`Visibility::Public`]
/// anchor/root may be provided to (advertised on) the swarm's Kademlia DHT. A
/// [`Visibility::Cell`] (cell-encrypted) or [`Visibility::Sealed`] (recipient-
/// sealed) object's head travels the private swarm's pubsub, NEVER the DHT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// A public anchor object — may be advertised on the swarm DHT.
    Public,
    /// A cell-encrypted object — head stays inside the cell over pubsub.
    Cell,
    /// A recipient-sealed object — head stays private over pubsub.
    Sealed,
}

impl Visibility {
    /// Whether an object of this class may be advertised on the public swarm
    /// DHT. Only [`Visibility::Public`] may; everything else stays private.
    #[must_use]
    pub fn may_reach_dht(self) -> bool {
        matches!(self, Visibility::Public)
    }
}

/// A content object (segment) plus its authorship signature.
///
/// The segment's identity is [`SignedSegment::cid`], a pure function of its
/// `bytes`. The `signature` is the owner's ed25519 signature over exactly those
/// bytes (domain-separated), so a store can verify — from the segment alone —
/// that the author holding `signer`'s secret produced this exact content. A
/// tampered segment (bytes changed after signing) or a forged one (signed by a
/// key that is not `signer`) fails [`SignedSegment::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSegment {
    bytes: Vec<u8>,
    signer: SigningPublicKey,
    signature: Signature,
    visibility: Visibility,
}

/// Domain-separation tag so a segment authorship signature can never be
/// confused with any other pillar signature over the same bytes.
const SEGMENT_SIG_DOMAIN: &[u8] = b"pillar-streamdb/ipfs-store/segment-v1";

fn segment_signing_material(bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SEGMENT_SIG_DOMAIN.len() + bytes.len());
    m.extend_from_slice(SEGMENT_SIG_DOMAIN);
    m.extend_from_slice(bytes);
    m
}

impl SignedSegment {
    /// Author a signed segment: sign `bytes` (domain-separated) with `secret`
    /// and record `signer` (the matching public key) as its author.
    ///
    /// # Errors
    ///
    /// Propagates any signing failure from `pillar_crypto::sign`.
    pub fn author(
        bytes: impl Into<Vec<u8>>,
        signer: SigningPublicKey,
        secret: &SigningSecretKey,
        visibility: Visibility,
    ) -> pillar_crypto::Result<Self> {
        let bytes = bytes.into();
        let signature = sign(secret, &segment_signing_material(&bytes))?;
        Ok(SignedSegment {
            bytes,
            signer,
            signature,
            visibility,
        })
    }

    /// The segment's content bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The author's public key.
    #[must_use]
    pub fn signer(&self) -> &SigningPublicKey {
        &self.signer
    }

    /// The segment's visibility class.
    #[must_use]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// The content id of this segment — a pure function of its bytes.
    #[must_use]
    pub fn cid(&self) -> Cid {
        Cid::of(&self.bytes)
    }

    /// Verify the authorship signature over this segment's bytes.
    ///
    /// `Ok(())` only when the signature was produced by `signer`'s secret over
    /// exactly these bytes; any tamper or forgery yields
    /// [`StoreError::BadSignature`].
    pub fn verify(&self) -> Result<(), StoreError> {
        verify(
            &self.signer,
            &segment_signing_material(&self.bytes),
            &self.signature,
        )
        .map_err(|_| StoreError::BadSignature)
    }
}

/// An IPNS-format mutable head record: an owner-signed, sequence-numbered,
/// TTL'd pointer to the current root [`Cid`] for a head name.
///
/// A head only ever advances (`HeadSequenceMonotonic`): a receiver accepts an
/// incoming record only when it is signed by the head's owner AND its `seq`
/// strictly exceeds the currently-held one. The `visibility` scopes where the
/// head may travel: a [`Visibility::Public`] head may be published to the swarm
/// DHT; a `Cell`/`Sealed` head stays inside the cell over pubsub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRecord {
    owner: SigningPublicKey,
    seq: u64,
    target: Cid,
    ttl_secs: u64,
    visibility: Visibility,
    signature: Signature,
}

const HEAD_SIG_DOMAIN: &[u8] = b"pillar-streamdb/ipfs-store/ipns-head-v1";

fn head_signing_material(owner: &SigningPublicKey, seq: u64, target: &Cid, ttl_secs: u64) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(HEAD_SIG_DOMAIN);
    m.extend_from_slice(owner.as_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(target.as_bytes());
    m.extend_from_slice(&ttl_secs.to_be_bytes());
    m
}

impl HeadRecord {
    /// Author a signed head record advancing `owner`'s head to `seq`, pointing
    /// at `target`, valid for `ttl_secs`.
    ///
    /// # Errors
    ///
    /// Propagates any signing failure from `pillar_crypto::sign`.
    pub fn author(
        owner: SigningPublicKey,
        seq: u64,
        target: Cid,
        ttl_secs: u64,
        visibility: Visibility,
        secret: &SigningSecretKey,
    ) -> pillar_crypto::Result<Self> {
        let signature = sign(
            secret,
            &head_signing_material(&owner, seq, &target, ttl_secs),
        )?;
        Ok(HeadRecord {
            owner,
            seq,
            target,
            ttl_secs,
            visibility,
            signature,
        })
    }

    /// The head-name owner's public key.
    #[must_use]
    pub fn owner(&self) -> &SigningPublicKey {
        &self.owner
    }

    /// This record's sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The root [`Cid`] this head points at.
    #[must_use]
    pub fn target(&self) -> &Cid {
        &self.target
    }

    /// The head's TTL, in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// The head's visibility class.
    #[must_use]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Verify this record's owner signature over its full signed material.
    ///
    /// `Ok(())` only when signed by `owner`'s secret over exactly this
    /// `(owner, seq, target, ttl)` tuple; a forged head yields
    /// [`StoreError::BadSignature`].
    pub fn verify(&self) -> Result<(), StoreError> {
        verify(
            &self.owner,
            &head_signing_material(&self.owner, self.seq, &self.target, self.ttl_secs),
            &self.signature,
        )
        .map_err(|_| StoreError::BadSignature)
    }
}

/// A durable content-object store: the plugin-owned IPFS/libp2p surface the
/// streaming-DB persistence rides.
///
/// Holds a local content-addressed segment set, a pin set (durable, never GC'd),
/// the DHT-advertised set (public anchors only), and the current mutable head
/// per owner key. Networked backfill is expressed against a [`SegmentSource`]
/// abstraction so this type stays independent of the concrete libp2p wiring
/// (`pillar_net::blob`) while still modelling the private-swarm fetch + verify.
#[derive(Debug, Default)]
pub struct ContentStore {
    held: HashMap<Cid, SignedSegment>,
    pinned: HashSet<Cid>,
    dht: HashSet<Cid>,
    heads: BTreeMap<Vec<u8>, HeadRecord>,
}

/// A reachable source of segments over the private swarm — the abstraction the
/// backfill fetch targets (a peer, or a set of peers, that may hold a segment).
///
/// Implemented in tests by an in-memory peer; in production by the
/// `pillar_net::blob` request/response substrate. A source may return the WRONG
/// bytes (a malicious or buggy peer); [`ContentStore::get`] re-verifies every
/// returned segment against the requested `Cid`, so the source is untrusted.
pub trait SegmentSource {
    /// Fetch the bytes+authorship of the segment addressed by `cid`, if this
    /// source can reach it. The returned segment is UNTRUSTED — the caller
    /// verifies it against `cid` and its signature before accepting it.
    fn fetch(&self, cid: &Cid) -> Option<SignedSegment>;
}

impl<F> SegmentSource for F
where
    F: Fn(&Cid) -> Option<SignedSegment>,
{
    fn fetch(&self, cid: &Cid) -> Option<SignedSegment> {
        (self)(cid)
    }
}

impl ContentStore {
    /// A new, empty store.
    #[must_use]
    pub fn new() -> Self {
        ContentStore::default()
    }

    /// Store a signed segment, returning its [`Cid`].
    ///
    /// Verifies the segment's authorship signature FIRST — a forged or tampered
    /// segment is rejected and never stored (`put(signed segment)->CID`). The
    /// returned id is a pure function of the segment's bytes, so the caller
    /// never chooses it. Idempotent: re-putting the same segment is a no-op that
    /// returns the same `Cid`.
    ///
    /// # Errors
    ///
    /// [`StoreError::BadSignature`] if the segment's signature does not verify.
    pub fn put(&mut self, segment: SignedSegment) -> Result<Cid, StoreError> {
        segment.verify()?;
        let cid = segment.cid();
        self.held.entry(cid.clone()).or_insert(segment);
        Ok(cid)
    }

    /// Resolve `cid` to its segment: from the local held/pin set if present,
    /// otherwise BACKFILL it from `source` over the private swarm.
    ///
    /// A backfilled segment is UNTRUSTED until proven: its bytes are verified to
    /// hash to the requested `cid` (content-address verification) AND its
    /// authorship signature is verified, before it is accepted and cached
    /// locally. A peer that returns wrong or forged content is rejected with
    /// [`StoreError::CidMismatch`] / [`StoreError::BadSignature`] and nothing is
    /// stored. Refines `Backfill`.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if neither local nor `source` can supply `cid`;
    /// [`StoreError::CidMismatch`] if a peer returns bytes that do not hash to
    /// `cid`; [`StoreError::BadSignature`] if the returned segment's authorship
    /// signature does not verify.
    pub fn get(
        &mut self,
        cid: &Cid,
        source: &impl SegmentSource,
    ) -> Result<SignedSegment, StoreError> {
        if let Some(seg) = self.held.get(cid) {
            return Ok(seg.clone());
        }
        let fetched = source.fetch(cid).ok_or(StoreError::NotFound)?;
        // Untrusted until verified against the CID we asked for AND its author.
        if !cid.verifies(fetched.bytes()) {
            return Err(StoreError::CidMismatch);
        }
        fetched.verify()?;
        self.held.insert(cid.clone(), fetched.clone());
        Ok(fetched)
    }

    /// Whether the store holds `cid` locally.
    #[must_use]
    pub fn contains(&self, cid: &Cid) -> bool {
        self.held.contains_key(cid)
    }

    /// Read-only local lookup of a held segment, with no backfill and no
    /// mutation — the shape a [`SegmentSource`] peer exposes to answer a
    /// remote fetch (as opposed to [`Self::get`], which is the requesting
    /// side's local-or-backfill resolve).
    #[must_use]
    pub fn get_local(&self, cid: &Cid) -> Option<SignedSegment> {
        self.held.get(cid).cloned()
    }

    /// Mark a held segment durable (pinned — never garbage-collected).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the store does not hold `cid`.
    pub fn pin(&mut self, cid: &Cid) -> Result<(), StoreError> {
        if !self.held.contains_key(cid) {
            return Err(StoreError::NotFound);
        }
        self.pinned.insert(cid.clone());
        Ok(())
    }

    /// Whether `cid` is pinned.
    #[must_use]
    pub fn is_pinned(&self, cid: &Cid) -> bool {
        self.pinned.contains(cid)
    }

    /// Advertise a held segment to the swarm's Kademlia DHT.
    ///
    /// ONLY a public anchor/ROOT segment ([`Visibility::Public`]) may be
    /// provided (`AnchorsOnlyToDHT`): providing a cell/sealed segment is refused
    /// with [`StoreError::NotPublic`] and the DHT set is left unchanged — a
    /// cell-encrypted segment's head travels the private swarm's pubsub only,
    /// never the public DHT.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the store does not hold `cid`;
    /// [`StoreError::NotPublic`] if the held segment is not public-class.
    pub fn provide(&mut self, cid: &Cid) -> Result<(), StoreError> {
        let seg = self.held.get(cid).ok_or(StoreError::NotFound)?;
        if !seg.visibility().may_reach_dht() {
            return Err(StoreError::NotPublic);
        }
        self.dht.insert(cid.clone());
        Ok(())
    }

    /// Whether `cid` is advertised on the swarm DHT.
    #[must_use]
    pub fn is_provided(&self, cid: &Cid) -> bool {
        self.dht.contains(cid)
    }

    /// The current DHT-advertised set (invariant: every member is public-class).
    #[must_use]
    pub fn dht_set(&self) -> &HashSet<Cid> {
        &self.dht
    }

    /// Publish (accept) a mutable head record, resolving it against the current
    /// head for the same owner.
    ///
    /// Accepts the record ONLY when: its owner signature verifies
    /// (`HeadSignedByOwner`) AND its sequence strictly advances the currently-
    /// held head for that owner (`HeadSequenceMonotonic`). A stale/equal-or-
    /// lower sequence is rejected with [`StoreError::StaleHead`]; a forged head
    /// with [`StoreError::BadSignature`]. This is the IPNS resolve rule: an IPNS
    /// pointer only ever advances and only under the owner's key.
    ///
    /// A `public` head is eligible for swarm-DHT publication; a `cell`/`sealed`
    /// head stays inside the cell over pubsub — the record's [`Visibility`]
    /// records that scoping (enforced by the transport, surfaced via
    /// [`HeadRecord::visibility`]); the store never advertises a head `Cid` to
    /// the DHT (heads move over pubsub / IPNS, objects via [`Self::provide`]).
    ///
    /// # Errors
    ///
    /// [`StoreError::BadSignature`] for a forged head;
    /// [`StoreError::StaleHead`] for a non-advancing sequence.
    pub fn publish_head(&mut self, record: HeadRecord) -> Result<(), StoreError> {
        record.verify()?;
        let key = record.owner().as_bytes().to_vec();
        if let Some(current) = self.heads.get(&key) {
            if record.seq() <= current.seq() {
                return Err(StoreError::StaleHead);
            }
        }
        self.heads.insert(key, record);
        Ok(())
    }

    /// Resolve an owner's current head to its latest accepted record, if any.
    #[must_use]
    pub fn resolve_head(&self, owner: &SigningPublicKey) -> Option<&HeadRecord> {
        self.heads.get(owner.as_bytes())
    }
}

/// A fault in a durable-store operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The requested `Cid` is held neither locally nor by any reachable source.
    NotFound,
    /// A backfilled segment's bytes do not hash to the requested `Cid` — a peer
    /// tried to substitute wrong content for a content address.
    CidMismatch,
    /// A segment/head signature did not verify (tampered or forged).
    BadSignature,
    /// A non-public segment was offered for DHT advertisement (`provide`).
    NotPublic,
    /// A head record did not strictly advance the owner's sequence number.
    StaleHead,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StoreError::NotFound => "content id not found locally or over the private swarm",
            StoreError::CidMismatch => "backfilled bytes do not hash to the requested content id",
            StoreError::BadSignature => "segment or head signature did not verify",
            StoreError::NotPublic => "only a public anchor may be provided to the swarm DHT",
            StoreError::StaleHead => "head sequence did not strictly advance",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::sign::signing_keypair_from_seed;
    use pillar_crypto::Seed;

    fn keypair(label: &str) -> (SigningPublicKey, SigningSecretKey) {
        let seed = Seed::from_bytes(format!("pillar-store-test::{label}").into_bytes());
        signing_keypair_from_seed(&seed).expect("keygen")
    }

    fn segment(
        payload: &[u8],
        signer_label: &str,
        vis: Visibility,
    ) -> (SignedSegment, SigningPublicKey) {
        let (pk, sk) = keypair(signer_label);
        let seg = SignedSegment::author(payload.to_vec(), pk.clone(), &sk, vis).expect("author");
        (seg, pk)
    }

    /// DoD part 1: a signed segment round-trips by CID — byte-identical and
    /// multihash-verified. The `Cid` is a real 34-byte SHA2-256 multihash
    /// (never a checksum), and `get` returns the exact stored bytes.
    #[test]
    fn signed_segment_round_trips_by_cid_multihash_verified() {
        let mut store = ContentStore::new();
        let (seg, _pk) = segment(b"durable segment payload", "author-a", Visibility::Public);
        let cid = store.put(seg.clone()).expect("put");

        // The CID is a real sha2-256 multihash: 0x12 0x20 + 32-byte digest.
        assert_eq!(cid.as_bytes().len(), 34, "sha2-256 multihash, not a checksum");
        assert_eq!(cid.as_bytes()[0], 0x12, "multicodec sha2-256");
        assert_eq!(cid.as_bytes()[1], 0x20, "digest length 32");
        assert!(cid.verifies(seg.bytes()), "CID must verify against bytes");

        // Local round-trip: no peer needed, bytes are byte-identical.
        let never = |_: &Cid| None;
        let got = store.get(&cid, &never).expect("get local");
        assert_eq!(got.bytes(), b"durable segment payload");
        assert_eq!(got.cid(), cid);
    }

    /// A tampered or forged segment is refused on `put` — the store never holds
    /// content whose authorship signature does not verify.
    #[test]
    fn put_rejects_tampered_and_forged_segments() {
        let mut store = ContentStore::new();
        let (mut seg, _) = segment(b"authentic", "author-a", Visibility::Public);
        // Tamper the bytes after signing.
        seg.bytes[0] ^= 0x01;
        assert_eq!(store.put(seg).unwrap_err(), StoreError::BadSignature);

        // Forge: claim a different signer than the one who actually signed.
        let (_forger_pk, forger_sk) = keypair("forger");
        let (victim_pk, _victim_sk) = keypair("victim");
        let forged = SignedSegment::author(
            b"forged".to_vec(),
            victim_pk, // claim victim as author...
            &forger_sk, // ...but sign with the forger's key
            Visibility::Public,
        )
        .expect("author");
        assert_eq!(store.put(forged).unwrap_err(), StoreError::BadSignature);
    }

    /// DoD part 2: a missing-but-reachable segment is backfilled on a second
    /// node over the private swarm and verified against the CID on load. A peer
    /// returning WRONG bytes for the CID is rejected (CidMismatch); a peer
    /// returning a forged segment is rejected (BadSignature).
    #[test]
    fn backfills_missing_segment_over_private_swarm_and_verifies_cid() {
        // Node A authors and holds the segment.
        let mut node_a = ContentStore::new();
        let (seg, _pk) = segment(b"segment only A has", "author-a", Visibility::Cell);
        let cid = node_a.put(seg.clone()).expect("put A");

        // Node B is missing it. It backfills from a source that reaches A.
        let mut node_b = ContentStore::new();
        assert!(!node_b.contains(&cid), "B starts without the segment");
        let a_seg = seg.clone();
        let honest_peer = move |want: &Cid| {
            if *want == a_seg.cid() {
                Some(a_seg.clone())
            } else {
                None
            }
        };
        let got = node_b.get(&cid, &honest_peer).expect("backfill");
        assert_eq!(got.bytes(), b"segment only A has", "byte-identical backfill");
        assert!(node_b.contains(&cid), "backfilled segment is cached locally");

        // A malicious peer that returns wrong bytes for the CID is rejected.
        let (wrong_seg, _) = segment(b"WRONG bytes", "author-a", Visibility::Cell);
        let mut node_c = ContentStore::new();
        let liar = move |_want: &Cid| Some(wrong_seg.clone());
        assert_eq!(node_c.get(&cid, &liar).unwrap_err(), StoreError::CidMismatch);
        assert!(!node_c.contains(&cid), "rejected content is never cached");

        // An unreachable CID yields NotFound.
        let mut node_d = ContentStore::new();
        let none = |_: &Cid| None;
        assert_eq!(node_d.get(&cid, &none).unwrap_err(), StoreError::NotFound);
    }

    /// Pin marks a held segment durable; pinning an unheld CID fails.
    #[test]
    fn pin_requires_a_held_segment() {
        let mut store = ContentStore::new();
        let (seg, _) = segment(b"pin me", "author-a", Visibility::Public);
        let cid = store.put(seg).expect("put");
        assert!(!store.is_pinned(&cid));
        store.pin(&cid).expect("pin");
        assert!(store.is_pinned(&cid));

        let absent = Cid::of(b"never stored");
        assert_eq!(store.pin(&absent).unwrap_err(), StoreError::NotFound);
    }

    /// `AnchorsOnlyToDHT`: only a public anchor may be provided to the swarm
    /// DHT; a cell/sealed segment is refused and never reaches the DHT set.
    #[test]
    fn only_public_anchors_reach_the_dht() {
        let mut store = ContentStore::new();
        let (pub_seg, _) = segment(b"public anchor root", "author-a", Visibility::Public);
        let (cell_seg, _) = segment(b"cell-encrypted seg", "author-b", Visibility::Cell);
        let (sealed_seg, _) = segment(b"sealed seg", "author-c", Visibility::Sealed);
        let pub_cid = store.put(pub_seg).expect("put pub");
        let cell_cid = store.put(cell_seg).expect("put cell");
        let sealed_cid = store.put(sealed_seg).expect("put sealed");

        store.provide(&pub_cid).expect("provide public");
        assert!(store.is_provided(&pub_cid));

        assert_eq!(store.provide(&cell_cid).unwrap_err(), StoreError::NotPublic);
        assert_eq!(store.provide(&sealed_cid).unwrap_err(), StoreError::NotPublic);
        assert!(!store.is_provided(&cell_cid));
        assert!(!store.is_provided(&sealed_cid));

        // Invariant: everything on the DHT is public-class.
        assert_eq!(store.dht_set().len(), 1);
        assert!(store.dht_set().contains(&pub_cid));
    }

    /// DoD part 3: an IPNS-format head resolves to its latest sequence, and a
    /// stale/lower-sequence OR forged head is rejected.
    #[test]
    fn ipns_head_resolves_latest_and_rejects_stale_or_forged() {
        let mut store = ContentStore::new();
        let (owner_pk, owner_sk) = keypair("head-owner");
        let target1 = Cid::of(b"root v1");
        let target2 = Cid::of(b"root v2");

        // seq 1 accepted.
        let h1 = HeadRecord::author(
            owner_pk.clone(),
            1,
            target1.clone(),
            3600,
            Visibility::Public,
            &owner_sk,
        )
        .expect("author h1");
        store.publish_head(h1).expect("publish h1");
        assert_eq!(store.resolve_head(&owner_pk).unwrap().seq(), 1);

        // seq 2 advances -> accepted, resolves to latest.
        let h2 = HeadRecord::author(
            owner_pk.clone(),
            2,
            target2.clone(),
            3600,
            Visibility::Public,
            &owner_sk,
        )
        .expect("author h2");
        store.publish_head(h2).expect("publish h2");
        let resolved = store.resolve_head(&owner_pk).unwrap();
        assert_eq!(resolved.seq(), 2);
        assert_eq!(resolved.target(), &target2);

        // A stale (lower/equal seq) head is rejected; latest stays seq 2.
        let stale = HeadRecord::author(
            owner_pk.clone(),
            1,
            target1.clone(),
            3600,
            Visibility::Public,
            &owner_sk,
        )
        .expect("author stale");
        assert_eq!(store.publish_head(stale).unwrap_err(), StoreError::StaleHead);
        assert_eq!(store.resolve_head(&owner_pk).unwrap().seq(), 2);

        // A forged head (higher seq, but signed by the WRONG key claiming owner)
        // is rejected — HeadSignedByOwner.
        let (_forger_pk, forger_sk) = keypair("head-forger");
        let forged = HeadRecord::author(
            owner_pk.clone(),
            9,
            target1,
            3600,
            Visibility::Public,
            &forger_sk, // signed by forger, not the owner
        )
        .expect("author forged");
        assert_eq!(
            store.publish_head(forged).unwrap_err(),
            StoreError::BadSignature
        );
        assert_eq!(store.resolve_head(&owner_pk).unwrap().seq(), 2);
    }

    /// A cell/sealed head carries its private visibility so the transport keeps
    /// it off the public DHT (scoped by visibility class).
    #[test]
    fn cell_head_is_scoped_private() {
        let mut store = ContentStore::new();
        let (owner_pk, owner_sk) = keypair("cell-head-owner");
        let head = HeadRecord::author(
            owner_pk.clone(),
            1,
            Cid::of(b"cell root"),
            600,
            Visibility::Cell,
            &owner_sk,
        )
        .expect("author");
        store.publish_head(head).expect("publish");
        let resolved = store.resolve_head(&owner_pk).unwrap();
        assert_eq!(resolved.visibility(), Visibility::Cell);
        assert!(
            !resolved.visibility().may_reach_dht(),
            "a cell head must never be eligible for the public DHT"
        );
        assert_eq!(resolved.ttl_secs(), 600);
    }
}
