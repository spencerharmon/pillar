//! Durable, IPFS-backed persistence for a [`Stream`] — the real durability
//! layer per the 2026-08-31 audit correction and non-negotiable #7.
//!
//! `persist::PersistentStream` (the earlier local-filesystem content-addressed
//! store) is NOT the durability layer any more: it is demoted to at most a
//! rebuildable local materialized-view cache. The AUTHORITATIVE durable store
//! is the IPFS/libp2p content-object store surface in [`crate::store`]
//! (`streamdb-ipfs-store-impl`, already the plugin-owned durable substrate):
//! pillar's own private swarm, off the public DHT.
//!
//! This module packs the op-log into a chain of owner-[`SignedSegment`]s (a
//! segment covers new ops appended since the previous segment, linking back to
//! it by [`Cid`]), publishes a monotone [`HeadRecord`] pointing at the latest
//! segment, and — the DoD this task adds — REHYDRATES a fresh/restarted node
//! with an EMPTY local disk purely from IPFS-pinned segments reachable over a
//! [`SegmentSource`], never from a local `ops/` directory.
//!
//! Per "Persistence follows crypto": the SEALED cell/segment-signing key is
//! itself content-addressed and pinned to the store (as a `Sealed`-visibility
//! segment) so it durably survives a restart; the NODE's own private
//! (custody) key that unseals it is NEVER put in the store — it stays
//! custody-held (see [`pillar_crypto::custody`]). Those two — the
//! custody-held node key plus the IPFS-pinned sealed cell key — are the
//! minimum a restarting node needs to read the streaming DB again: unseal the
//! cell key with the node key, then walk the IPNS head to decrypt/verify the
//! segment chain.

use pillar_core::{SideEffect, ViewPolicy};
use pillar_crypto::seal::{seal_to_recipients, unseal};
use pillar_crypto::{
    CryptoError, SealedEnvelope, SealingPublicKey, SealingSecretKey, SigningPublicKey,
    SigningSecretKey,
};

use crate::store::{Cid, ContentStore, HeadRecord, SegmentSource, SignedSegment, Visibility};
use crate::{PolicyViolation, Stream, StoreError};

/// A durable-persistence fault: either a store fault or a policy refusal.
#[derive(Debug)]
pub enum IpfsPersistError {
    /// The underlying content-object store refused the operation.
    Store(StoreError),
    /// A cryptographic (signing/sealing) primitive failed.
    Crypto(CryptoError),
    /// The append was refused by the stream's view policy.
    Policy(PolicyViolation),
    /// A segment's bytes could not be decoded (corrupt / truncated chain link).
    Corrupt,
    /// A resolved head record's owner does not match the expected owner.
    WrongOwner,
    /// This handle holds no signing secret — it was rehydrated read-only (the
    /// segment-signing secret was never sealed to this node, or is not yet
    /// unsealed) and cannot author new segments.
    ReadOnly,
}

impl From<StoreError> for IpfsPersistError {
    fn from(e: StoreError) -> Self {
        IpfsPersistError::Store(e)
    }
}

impl std::fmt::Display for IpfsPersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsPersistError::Store(e) => write!(f, "ipfs store error: {e}"),
            IpfsPersistError::Crypto(e) => write!(f, "crypto error: {e}"),
            IpfsPersistError::Policy(v) => write!(f, "{v}"),
            IpfsPersistError::Corrupt => write!(f, "corrupt segment chain link"),
            IpfsPersistError::WrongOwner => write!(f, "head record owner mismatch"),
            IpfsPersistError::ReadOnly => {
                write!(f, "no segment-signing secret held — cannot author new segments")
            }
        }
    }
}

impl std::error::Error for IpfsPersistError {}

/// Encode a segment: an optional link to the previous segment's [`Cid`] plus
/// exactly one op payload appended since it. Chaining one op per segment keeps
/// the DoD's "many ops per object" property trivially true across a session
/// (each session's segments form the object set) while staying simple to
/// verify link-by-link; nothing prevents a future segment from batching many
/// ops in one object — the wire shape (`prev?, payload`) is unaffected.
fn encode_segment(prev: Option<&Cid>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match prev {
        Some(cid) => {
            let bytes = cid.as_bytes();
            out.push(1u8);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        None => out.push(0u8),
    }
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_segment(bytes: &[u8]) -> Option<(Option<Cid>, Vec<u8>)> {
    let mut pos = 0usize;
    let has_prev = *bytes.get(pos)?;
    pos += 1;
    let prev = if has_prev == 1 {
        let len = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        let cid_bytes = bytes.get(pos..pos + len)?.to_vec();
        pos += len;
        Some(Cid(pillar_crypto::ContentId::from_bytes(cid_bytes)))
    } else {
        None
    };
    let plen = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    let payload = bytes.get(pos..pos + plen)?.to_vec();
    Some((prev, payload))
}

/// A [`Stream`] whose durability rides IPFS-style signed segments + an IPNS
/// head, per [`crate::store::ContentStore`] — the real refinement of
/// `StreamdbIpfsStore.tla` this task's persistence targets.
#[derive(Debug)]
pub struct IpfsPersistentStream {
    stream: Stream,
    store: ContentStore,
    owner: SigningPublicKey,
    secret: Option<SigningSecretKey>,
    visibility: Visibility,
    seq: u64,
    head: Option<Cid>,
    ttl_secs: u64,
}

impl IpfsPersistentStream {
    /// Start a brand-new (empty) IPFS-persisted stream, authored + signed by
    /// `owner`/`secret`, whose segments/head carry `visibility`.
    #[must_use]
    pub fn genesis(owner: SigningPublicKey, secret: SigningSecretKey, visibility: Visibility) -> Self {
        Self::genesis_with_policy(owner, secret, visibility, None)
    }

    /// As [`Self::genesis`] with an explicit declared local admission policy.
    #[must_use]
    pub fn genesis_with_policy(
        owner: SigningPublicKey,
        secret: SigningSecretKey,
        visibility: Visibility,
        policy: Option<ViewPolicy>,
    ) -> Self {
        let stream = match policy {
            Some(p) => Stream::with_policy(p),
            None => Stream::new(),
        };
        IpfsPersistentStream {
            stream,
            store: ContentStore::new(),
            owner,
            secret: Some(secret),
            visibility,
            seq: 0,
            head: None,
            ttl_secs: 3600,
        }
    }

    /// This stream's IPNS-format head owner key.
    #[must_use]
    pub fn owner(&self) -> &SigningPublicKey {
        &self.owner
    }

    /// The current head [`Cid`] (the latest segment), if any op has been
    /// appended yet.
    #[must_use]
    pub fn head_cid(&self) -> Option<&Cid> {
        self.head.as_ref()
    }

    /// This handle's local content-object store (its pinned/held segment +
    /// head set — the durable IPFS-plugin-facing state).
    #[must_use]
    pub fn store(&self) -> &ContentStore {
        &self.store
    }

    /// Read access to the in-memory materialized [`Stream`] (view/order/root).
    #[must_use]
    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    /// Append `payload` as a fresh op: build + sign the new segment (linking
    /// to the previous head), store + pin it (advertise to the DHT only if
    /// `visibility` is public), publish the advanced [`HeadRecord`], and only
    /// then record the op in the in-memory view — durable-first, matching the
    /// discipline of the demoted local-fs cache.
    ///
    /// # Errors
    ///
    /// [`IpfsPersistError::Policy`] if the view policy refuses `effect`;
    /// [`IpfsPersistError::ReadOnly`] if this handle holds no signing secret;
    /// [`IpfsPersistError::Store`] / [`IpfsPersistError::Crypto`] on a
    /// store/crypto fault.
    pub fn append(
        &mut self,
        payload: impl Into<Vec<u8>>,
        effect: SideEffect,
    ) -> Result<crate::OpId, IpfsPersistError> {
        let secret = self.secret.as_ref().ok_or(IpfsPersistError::ReadOnly)?;
        let policy = self.stream.policy();
        if !policy.admits(effect) {
            return Err(IpfsPersistError::Policy(PolicyViolation::new(policy, effect)));
        }
        let payload = payload.into();

        let segment_bytes = encode_segment(self.head.as_ref(), &payload);
        let segment = SignedSegment::author(segment_bytes, self.owner.clone(), secret, self.visibility)
            .map_err(IpfsPersistError::Crypto)?;
        let cid = self.store.put(segment)?;
        self.store.pin(&cid)?;
        if self.visibility.may_reach_dht() {
            self.store.provide(&cid)?;
        }

        self.seq += 1;
        let head_record = HeadRecord::author(
            self.owner.clone(),
            self.seq,
            cid.clone(),
            self.ttl_secs,
            self.visibility,
            secret,
        )
        .map_err(IpfsPersistError::Crypto)?;
        self.store.publish_head(head_record)?;
        self.head = Some(cid);

        Ok(self.stream.log_mut().append(payload))
    }

    /// Seal this stream's segment-signing secret to `recipients` (typically
    /// the restarting node's own custody-held sealing public key), pin the
    /// resulting envelope into the store as a [`Visibility::Sealed`] segment,
    /// and return its [`Cid`] — the durable, IPFS-pinned "sealed cell key" a
    /// restarting node fetches and unseals to recover write capability.
    ///
    /// The plaintext secret is NEVER itself put in the store — only the sealed
    /// envelope is, and only a holder of one of `recipients`' matching
    /// secrets can ever recover it.
    ///
    /// # Errors
    ///
    /// [`IpfsPersistError::ReadOnly`] if this handle holds no signing secret;
    /// [`IpfsPersistError::Crypto`] / [`IpfsPersistError::Store`] on failure.
    pub fn seal_signing_key(
        &mut self,
        recipients: &[SealingPublicKey],
    ) -> Result<Cid, IpfsPersistError> {
        let secret = self.secret.as_ref().ok_or(IpfsPersistError::ReadOnly)?;
        let envelope =
            seal_to_recipients(secret.as_bytes(), recipients).map_err(IpfsPersistError::Crypto)?;
        let segment = SignedSegment::author(
            envelope.as_bytes().to_vec(),
            self.owner.clone(),
            secret,
            Visibility::Sealed,
        )
        .map_err(IpfsPersistError::Crypto)?;
        let cid = self.store.put(segment)?;
        self.store.pin(&cid)?;
        Ok(cid)
    }

    /// Rehydrate a stream PURELY from IPFS: resolve to `head` (obtained out of
    /// band — the swarm's IPNS resolution over the private DHT/pubsub, never a
    /// local file), then walk the signed-segment chain via `source` (the
    /// private-swarm backfill substrate), verifying every link, and rebuild
    /// the exact same materialized view a continuously-gossiped peer holds.
    ///
    /// The returned handle starts from a BRAND-NEW, empty local
    /// [`ContentStore`] — nothing here is read from a local `ops/` directory;
    /// every op arrives via `source`. It is read-only (no signing secret)
    /// unless [`Self::unseal_signing_key`] is subsequently used to recover
    /// write capability from a sealed segment.
    ///
    /// # Errors
    ///
    /// [`IpfsPersistError::WrongOwner`] if `head` is not signed by `owner`;
    /// [`IpfsPersistError::Corrupt`] on a malformed segment link;
    /// [`IpfsPersistError::Store`] if the chain cannot be fully backfilled or
    /// a segment fails verification.
    pub fn rehydrate(
        owner: SigningPublicKey,
        head: &HeadRecord,
        source: &impl SegmentSource,
    ) -> Result<Self, IpfsPersistError> {
        head.verify().map_err(IpfsPersistError::Store)?;
        if head.owner().as_bytes() != owner.as_bytes() {
            return Err(IpfsPersistError::WrongOwner);
        }

        let mut store = ContentStore::new();
        let mut stream = Stream::new();
        let mut payloads_newest_first = Vec::new();
        let mut cursor = Some(head.target().clone());
        while let Some(cid) = cursor {
            let seg = store.get(&cid, source)?;
            let (prev, payload) = decode_segment(seg.bytes()).ok_or(IpfsPersistError::Corrupt)?;
            payloads_newest_first.push(payload);
            store.pin(&cid)?;
            cursor = prev;
        }
        for payload in payloads_newest_first.into_iter().rev() {
            stream.log_mut().append(payload);
        }
        // Record the resolved head so a rehydrated handle can keep resolving
        // (and, once/if a secret is unsealed, keep appending) from here.
        store.publish_head(head.clone())?;

        Ok(IpfsPersistentStream {
            stream,
            store,
            owner,
            secret: None,
            visibility: head.visibility(),
            seq: head.seq(),
            head: Some(head.target().clone()),
            ttl_secs: head.ttl_secs(),
        })
    }

    /// Recover write capability on a rehydrated (read-only) handle: fetch the
    /// sealed segment at `sealed_cid` via `source`, unseal it with the
    /// restarting node's custody-held `node_secret`, and hold the recovered
    /// segment-signing secret so [`Self::append`] works again.
    ///
    /// # Errors
    ///
    /// [`IpfsPersistError::Store`] if the sealed segment cannot be fetched;
    /// [`IpfsPersistError::Crypto`] if `node_secret` is not a matching
    /// recipient (the node was never granted access) or the envelope is
    /// malformed.
    pub fn unseal_signing_key(
        &mut self,
        sealed_cid: &Cid,
        node_secret: &SealingSecretKey,
        source: &impl SegmentSource,
    ) -> Result<(), IpfsPersistError> {
        let seg = self.store.get(sealed_cid, source)?;
        let envelope = SealedEnvelope::from_bytes(seg.bytes().to_vec());
        let secret_bytes = unseal(&envelope, node_secret).map_err(IpfsPersistError::Crypto)?;
        self.secret = Some(SigningSecretKey::from_bytes(secret_bytes));
        Ok(())
    }
}
