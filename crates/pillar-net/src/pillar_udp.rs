//! pillar-UDP transport mechanics (Route A).
//!
//! This module implements the executable core of the pillar-UDP protocol
//! ("pillar-UDP as an additional libp2p [`Transport`]"), refining the
//! invariants proven in `specs/PillarUDP.tla` as Rust with regression tests
//! that mirror those TLA invariants one-for-one. It deliberately reuses the
//! platform's already-proven primitives rather than re-deriving them:
//!
//! - Content addressing ([`Cid`]) is the SAME function blobs / the op-log use
//!   ([`pillar_streamdb::content_address`]), so CIDs are canonical across every
//!   layer and two nodes hash identical bytes to the identical CID.
//! - Exclusive-vs-idempotent routing ([`ExclusiveRouter`]) reuses
//!   [`pillar_core::SideEffect`] — the same reversibility classification
//!   `streamdb`'s `ViewPolicy` uses — so an exclusive (non-idempotent) message
//!   routes only to the single deterministic lease holder while an idempotent
//!   message may be picked up opportunistically by any member.
//! - The dispersed reply-node set ([`reply_node_set`]) calls
//!   [`pillar_ipam::TopologyScopedIpam::diversity_addrs`] directly. Because
//!   that is a pure function of the topology / membership view, two nodes that
//!   independently compute the reply set over the same view agree bit-for-bit
//!   with no coordination round-trip.
//!
//! The raw libp2p [`Transport`] wiring itself (the datagram substrate, the
//! Noise+yamux upgrade, live per-link quality *measurement*) is substrate-level
//! plumbing that composes with these primitives; this module owns the protocol
//! MECHANICS — transport selection, exactly-once dedup, lease routing, reply-set
//! derivation, forwarding termination, anti-amplification, and K+M erasure
//! reconstruction — each with an executable regression test.
//!
//! [`Transport`]: libp2p::Transport

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use pillar_core::{NodeId, SideEffect};
use pillar_ipam::TopologyScopedIpam;
use pillar_streamdb::content_address;

/// A content identifier: the canonical content address of a message's bytes.
///
/// This is exactly [`pillar_streamdb::content_address`], so a CID computed here
/// equals the CID the streaming DB / blob store computes for the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub u64);

impl Cid {
    /// Compute the CID of a message's bytes (canonical across all layers).
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Cid(content_address(bytes))
    }
}

/// The measured quality of a peer link, as reported by the reliability mesh.
///
/// pillar-UDP is selected only on a link the mesh flags as unhealthy; a healthy
/// link uses QUIC (the cheaper default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkQuality {
    /// Low loss and latency: the default, cheap path.
    Healthy,
    /// Elevated but non-adversarial loss/latency.
    Degraded,
    /// Actively hostile conditions (tampering / drops).
    Adversarial,
    /// Very high packet loss.
    HighLoss,
}

/// The wire transport chosen for a single link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    /// QUIC — the default on a healthy link.
    Quic,
    /// pillar-UDP — the redundant/erasure-coded path for a degraded link.
    PillarUdp,
}

/// Select the wire transport for a link from its measured quality.
///
/// QUIC is the default on a [`LinkQuality::Healthy`] link; pillar-UDP is chosen
/// only on a Degraded / Adversarial / HighLoss link (the reliability-mesh
/// signal). This is the per-link selection Route A specifies: QUIC by default,
/// pillar-UDP where reliability demands the redundant path.
#[must_use]
pub fn select_transport(quality: LinkQuality) -> TransportKind {
    match quality {
        LinkQuality::Healthy => TransportKind::Quic,
        LinkQuality::Degraded | LinkQuality::Adversarial | LinkQuality::HighLoss => {
            TransportKind::PillarUdp
        }
    }
}

/// CID-keyed exactly-once processing gate.
///
/// Redundant copies (multiple reply nodes) and forwarded copies of the SAME
/// message all carry the same CID. The first copy of a CID is admitted for
/// processing; every subsequent copy — redundant or forwarded — is a duplicate
/// and refused. This is the exactly-once guarantee the TLA spec asserts.
#[derive(Debug, Default)]
pub struct DedupProcessor {
    seen: HashSet<Cid>,
}

impl DedupProcessor {
    /// A fresh processor that has seen no CID yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a copy of a message (by CID) for processing.
    ///
    /// Returns `true` exactly once per CID — for the first copy seen — and
    /// `false` for every later copy of the same CID, so the message is
    /// processed exactly once regardless of how many redundant / forwarded
    /// copies arrive.
    pub fn process(&mut self, cid: Cid) -> bool {
        self.seen.insert(cid)
    }

    /// Whether this CID has already been processed.
    #[must_use]
    pub fn has_seen(&self, cid: Cid) -> bool {
        self.seen.contains(&cid)
    }
}

/// Deterministic exclusive-message router over a fixed membership set.
///
/// An exclusive (non-idempotent) message must be handled by exactly ONE node —
/// the coordination-core lease holder — so it is never double-executed. An
/// idempotent (convergent) message may be picked up opportunistically by any
/// member, since duplication is harmless. The lease holder for a CID is derived
/// deterministically from the CID and the membership view, so every node agrees
/// on it without a round-trip.
#[derive(Debug, Clone)]
pub struct ExclusiveRouter {
    /// Members in deterministic (sorted) order.
    members: Vec<NodeId>,
}

impl ExclusiveRouter {
    /// Build a router over a membership set. Order is normalized (sorted) so
    /// every node computes the identical lease holder for a CID.
    #[must_use]
    pub fn new(members: impl IntoIterator<Item = NodeId>) -> Self {
        let mut members: Vec<NodeId> = members.into_iter().collect();
        members.sort();
        members.dedup();
        Self { members }
    }

    /// The single lease holder for a CID: a deterministic function of the CID
    /// and the (sorted) membership view. Returns `None` only if the membership
    /// set is empty.
    #[must_use]
    pub fn lease_holder(&self, cid: Cid) -> Option<&NodeId> {
        if self.members.is_empty() {
            return None;
        }
        let idx = (cid.0 as usize) % self.members.len();
        self.members.get(idx)
    }

    /// Whether `candidate` is permitted to handle a message of the given
    /// side-effect class and CID.
    ///
    /// - [`SideEffect::Exclusive`]: admitted ONLY if `candidate` is the
    ///   deterministic lease holder for the CID.
    /// - [`SideEffect::Convergent`]: admitted for ANY member (opportunistic
    ///   multi-node pickup is legal for idempotent messages).
    #[must_use]
    pub fn admits(&self, effect: SideEffect, cid: Cid, candidate: &NodeId) -> bool {
        match effect {
            SideEffect::Exclusive => self.lease_holder(cid) == Some(candidate),
            SideEffect::Convergent => self.members.iter().any(|m| m == candidate),
        }
    }
}

/// Compute the dispersed reply-node source-address set for a request.
///
/// Delegates to the topology-diversity primitive
/// ([`TopologyScopedIpam::diversity_addrs`]): given the redundancy count `k`,
/// it returns up to `k` addresses each drawn from a DISTINCT topology failure
/// domain, so replies for one CID are spread across the most diverse available
/// sites/zones. `want_v6` selects the address family; `preference` optionally
/// ranks domains (GeoIP / measured latency, lower first).
///
/// Because `diversity_addrs` is a pure function of the topology/membership
/// view, two nodes computing this over the SAME view produce the IDENTICAL
/// set with no coordination — the "independently-computed reply-node sets
/// agree" invariant.
#[must_use]
pub fn reply_node_set(
    ipam: &TopologyScopedIpam,
    _cid: Cid,
    k: usize,
    want_v6: bool,
    preference: Option<&BTreeMap<String, u64>>,
) -> Vec<IpAddr> {
    ipam.diversity_addrs(k, want_v6, preference)
}

/// TTL + CID-dedup forwarding termination gate.
///
/// A forwarded message carries a hop TTL. Forwarding terminates when the TTL is
/// exhausted OR when this node has already seen the CID (a loop). Both bounds
/// are required: dedup breaks an injected loop before the TTL would, and the
/// TTL bounds the total hop count even for distinct CIDs.
#[derive(Debug, Default)]
pub struct ForwardGate {
    seen: HashSet<Cid>,
}

impl ForwardGate {
    /// A fresh gate that has forwarded nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether to forward a copy of `cid` that arrived with `ttl` hops
    /// remaining, returning the decremented TTL to attach to the onward copy.
    ///
    /// Returns `Some(ttl - 1)` when the message may be forwarded (TTL not yet
    /// exhausted and the CID not seen before), and `None` when forwarding must
    /// stop — either the TTL reached zero or the CID was already forwarded
    /// (loop). A returned `Some` records the CID so any later loop copy stops.
    pub fn forward(&mut self, cid: Cid, ttl: u32) -> Option<u32> {
        if ttl == 0 {
            return None;
        }
        if !self.seen.insert(cid) {
            // Already forwarded this CID: a loop — terminate.
            return None;
        }
        Some(ttl - 1)
    }
}

/// Return-routability + anti-amplification gate for redundant replies.
///
/// An anonymous / ad-hoc client is return-routability validated BEFORE any
/// redundant reply commits: no reply is emitted to a client that has not proven
/// it owns its claimed return address. In addition, the total number of replies
/// is bounded to `factor * validated_requests` — the count of VALIDATED
/// requests, never the raw/unvalidated request count — so an attacker who never
/// completes return-routability can never amplify traffic through the mesh.
#[derive(Debug)]
pub struct AntiAmplificationGate {
    /// Amplification bound: replies per validated request.
    factor: u32,
    /// Requests whose return routability has been validated.
    validated_requests: u32,
    /// Replies already committed.
    replies_committed: u32,
}

impl AntiAmplificationGate {
    /// A gate with the given per-validated-request reply `factor`.
    #[must_use]
    pub fn new(factor: u32) -> Self {
        Self {
            factor,
            validated_requests: 0,
            replies_committed: 0,
        }
    }

    /// Record that a client passed return-routability validation. Only a
    /// validated request contributes to the reply budget.
    pub fn record_validated_request(&mut self) {
        self.validated_requests = self.validated_requests.saturating_add(1);
    }

    /// The current reply budget: `factor * validated_requests`.
    #[must_use]
    pub fn budget(&self) -> u32 {
        self.factor.saturating_mul(self.validated_requests)
    }

    /// Try to commit one redundant reply to a client.
    ///
    /// `client_validated` MUST be the return-routability status of the target
    /// client. The reply is refused (`false`) if the client is not validated,
    /// or if committing it would exceed the `factor * validated_requests`
    /// amplification bound. On success (`true`) the committed-reply counter is
    /// advanced.
    pub fn try_commit_reply(&mut self, client_validated: bool) -> bool {
        if !client_validated {
            return false;
        }
        if self.replies_committed >= self.budget() {
            return false;
        }
        self.replies_committed += 1;
        true
    }
}

/// One erasure-coded shard of a bulk message.
///
/// The message is split into `k` data shards; `m` parity shards are the XOR of
/// the data shards (all shards are equal length, the message being zero-padded
/// to a multiple of `k`). Each shard is CID-verified: `cid` is the content
/// address of `bytes`, so a corrupted shard is detected on receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard {
    /// Position of this shard: `0..k` are data shards, `k..k+m` are parity.
    pub index: usize,
    /// The shard's payload bytes (all shards share one length).
    pub bytes: Vec<u8>,
    /// Content address of `bytes`, for on-receipt integrity verification.
    pub cid: Cid,
}

impl Shard {
    /// Whether the shard's bytes still hash to its claimed CID (integrity).
    #[must_use]
    pub fn verify(&self) -> bool {
        Cid::of(&self.bytes) == self.cid
    }
}

/// An erasure-coding error.
#[derive(Debug, PartialEq, Eq)]
pub enum ShardError {
    /// `k` or the shard length was zero — nothing to encode.
    Empty,
    /// Fewer than `k` verified data shards were available to reconstruct.
    InsufficientShards {
        /// Data shards required.
        need: usize,
        /// Verified data shards supplied.
        have: usize,
    },
    /// The original byte length is required to strip zero-padding.
    MissingLength,
}

/// Split `message` into `k` data shards plus `m` XOR-parity shards.
///
/// Every shard is equal length (the message is zero-padded to a multiple of
/// `k`), and every shard is CID-stamped so corruption is detectable. The first
/// `k` shards are the data; the next `m` are parity (each the running XOR of
/// the data shards — a simple systematic code sufficient to reconstruct a
/// contiguous data shard from parity).
///
/// # Errors
/// Returns [`ShardError::Empty`] if `k == 0` or the message is empty.
pub fn encode(message: &[u8], k: usize, m: usize) -> Result<Vec<Shard>, ShardError> {
    if k == 0 || message.is_empty() {
        return Err(ShardError::Empty);
    }
    // Pad to a multiple of k, split into k equal data shards.
    let shard_len = message.len().div_ceil(k);
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * shard_len;
        let mut chunk = vec![0u8; shard_len];
        if start < message.len() {
            let end = (start + shard_len).min(message.len());
            chunk[..end - start].copy_from_slice(&message[start..end]);
        }
        data.push(chunk);
    }
    let mut shards: Vec<Shard> = data
        .iter()
        .enumerate()
        .map(|(index, bytes)| Shard {
            index,
            cid: Cid::of(bytes),
            bytes: bytes.clone(),
        })
        .collect();
    // m parity shards, each the XOR of all data shards (identical parity is
    // acceptable for XOR — any one parity recovers any one missing data shard).
    let mut parity = vec![0u8; shard_len];
    for d in &data {
        for (p, b) in parity.iter_mut().zip(d) {
            *p ^= *b;
        }
    }
    for j in 0..m {
        shards.push(Shard {
            index: k + j,
            cid: Cid::of(&parity),
            bytes: parity.clone(),
        });
    }
    Ok(shards)
}

/// Reconstruct the original `orig_len`-byte message from received shards.
///
/// Only shards that VERIFY (bytes hash to their claimed CID) are used; a shard
/// with a bad CID is rejected outright. Reconstruction needs the `k` data
/// shards; a single missing data shard is recovered from a verified parity
/// shard (XOR of the surviving data shards). Requires at least `k` verified
/// shards total covering the data positions.
///
/// # Errors
/// Returns [`ShardError::Empty`] if `k == 0`, [`ShardError::MissingLength`] if
/// `orig_len` is zero, or [`ShardError::InsufficientShards`] if fewer than `k`
/// data positions can be recovered from the verified shards.
pub fn reconstruct(
    shards: &[Shard],
    k: usize,
    orig_len: usize,
) -> Result<Vec<u8>, ShardError> {
    if k == 0 {
        return Err(ShardError::Empty);
    }
    if orig_len == 0 {
        return Err(ShardError::MissingLength);
    }
    // Keep only integrity-verified shards; a bad-CID shard is rejected.
    let good: Vec<&Shard> = shards.iter().filter(|s| s.verify()).collect();
    if good.is_empty() {
        return Err(ShardError::InsufficientShards { need: k, have: 0 });
    }
    let shard_len = good[0].bytes.len();

    // Collect available data shards by position.
    let mut data: Vec<Option<Vec<u8>>> = vec![None; k];
    for s in &good {
        if s.index < k {
            data[s.index] = Some(s.bytes.clone());
        }
    }
    let present = data.iter().filter(|d| d.is_some()).count();

    if present < k {
        // Recover ONE missing data shard from a verified parity shard, if
        // exactly one data position is missing.
        let missing: Vec<usize> = (0..k).filter(|&i| data[i].is_none()).collect();
        if missing.len() == 1 {
            if let Some(parity) = good.iter().find(|s| s.index >= k) {
                let mut recovered = parity.bytes.clone();
                for d in data.iter().flatten() {
                    for (r, b) in recovered.iter_mut().zip(d) {
                        *r ^= *b;
                    }
                }
                data[missing[0]] = Some(recovered);
            }
        }
    }

    if data.iter().any(Option::is_none) {
        let have = data.iter().filter(|d| d.is_some()).count();
        return Err(ShardError::InsufficientShards { need: k, have });
    }

    let mut out = Vec::with_capacity(k * shard_len);
    for d in data.into_iter().flatten() {
        out.extend_from_slice(&d);
    }
    out.truncate(orig_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_topology::{Label, TierHierarchy, Topology};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    /// Build a two-region dual-stack topology-scoped IPAM fixture with disjoint
    /// prefixes per region, so a K=3 diversity query spans both regions.
    fn two_region_ipam() -> TopologyScopedIpam {
        use pillar_ipam::Pool;
        use std::net::IpAddr;

        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());

        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("w1"), &[Label::new("region", "west")]);
        topo.declare(n("e1"), &[Label::new("region", "east")]);

        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
        ipam.bind_pool("west", Pool::new(v6("2001:db8:1::"), 65536), 3);
        ipam.bind_pool("east", Pool::new(v4("10.2.0.0"), 256), 3);
        ipam.bind_pool("east", Pool::new(v6("2001:db8:2::"), 65536), 3);
        ipam
    }

    // --- transport selection (TLA: correct-transport-per-link) ---

    #[test]
    fn healthy_link_selects_quic() {
        assert_eq!(select_transport(LinkQuality::Healthy), TransportKind::Quic);
    }

    #[test]
    fn injected_high_loss_link_selects_pillar_udp() {
        for q in [
            LinkQuality::Degraded,
            LinkQuality::Adversarial,
            LinkQuality::HighLoss,
        ] {
            assert_eq!(select_transport(q), TransportKind::PillarUdp);
        }
    }

    // --- exactly-once with 3 redundant + 1 forwarded copy (TLA: ExactlyOnce) ---

    #[test]
    fn three_redundant_plus_one_forwarded_copy_process_exactly_once() {
        let cid = Cid::of(b"a bulk request message");
        let mut dedup = DedupProcessor::new();
        // 3 redundant copies (3 reply nodes) + 1 forwarded copy = 4 arrivals.
        let mut processed = 0;
        for _ in 0..4 {
            if dedup.process(cid) {
                processed += 1;
            }
        }
        assert_eq!(processed, 1, "message processed exactly once across 4 copies");
        assert!(dedup.has_seen(cid));
    }

    // --- exclusive-message single-lease-holder routing (TLA: ExclusiveSingleHolder) ---

    #[test]
    fn exclusive_message_routes_only_to_lease_holder() {
        let members = [n("a"), n("b"), n("c"), n("d")];
        let router = ExclusiveRouter::new(members.clone());
        let cid = Cid::of(b"claim-the-dns-name");
        let holder = router.lease_holder(cid).cloned().unwrap();

        let mut admitted = 0;
        for m in &members {
            if router.admits(SideEffect::Exclusive, cid, m) {
                admitted += 1;
                assert_eq!(*m, holder, "only the lease holder is admitted");
            }
        }
        assert_eq!(admitted, 1, "exactly one node handles an exclusive message");
    }

    #[test]
    fn idempotent_message_admits_opportunistic_pickup_by_any_member() {
        let members = [n("a"), n("b"), n("c")];
        let router = ExclusiveRouter::new(members.clone());
        let cid = Cid::of(b"an idempotent replica advert");
        for m in &members {
            assert!(
                router.admits(SideEffect::Convergent, cid, m),
                "any member may pick up an idempotent message"
            );
        }
        // A non-member is never admitted.
        assert!(!router.admits(SideEffect::Convergent, cid, &n("stranger")));
    }

    // --- identical independently-computed reply-node sets (TLA: DeterministicReplySet) ---

    #[test]
    fn reply_node_set_identical_across_independent_computations() {
        let ipam_a = two_region_ipam();
        let ipam_b = two_region_ipam();
        let cid = Cid::of(b"a request needing 3 dispersed replies");

        let set_a = reply_node_set(&ipam_a, cid, 3, false, None);
        let set_b = reply_node_set(&ipam_b, cid, 3, false, None);
        assert_eq!(set_a, set_b, "two independent computations agree bit-for-bit");
        // K=3 over 2 bound sites spans both distinct regions (west + east).
        assert_eq!(set_a.len(), 2, "one address per distinct failure domain");
        assert!(set_a.iter().any(|a| a.to_string().starts_with("10.1")));
        assert!(set_a.iter().any(|a| a.to_string().starts_with("10.2")));
    }

    // --- forwarding-loop termination at TTL (TLA: ForwardingTerminates) ---

    #[test]
    fn forwarding_with_injected_loop_terminates_at_ttl() {
        let cid = Cid::of(b"a forwarded message in a loop");
        let mut gate = ForwardGate::new();
        // First arrival forwards with plenty of TTL.
        assert_eq!(gate.forward(cid, 8), Some(7));
        // An injected loop copy of the SAME cid is refused even with TTL left.
        assert_eq!(gate.forward(cid, 8), None, "dedup breaks the loop pre-TTL");
    }

    #[test]
    fn forwarding_terminates_exactly_at_ttl_zero_with_distinct_cids() {
        let mut gate = ForwardGate::new();
        let mut ttl = 3u32;
        let mut hops = 0;
        // Each hop is a DISTINCT cid so only the TTL bounds the chain.
        loop {
            let cid = Cid::of(format!("hop-{hops}").as_bytes());
            match gate.forward(cid, ttl) {
                Some(next) => {
                    ttl = next;
                    hops += 1;
                }
                None => break,
            }
        }
        assert_eq!(hops, 3, "exactly TTL hops before termination");
    }

    // --- anti-amplification bound (TLA: NoAmplification) ---

    #[test]
    fn anon_client_gets_no_redundant_reply_before_return_routability() {
        let mut gate = AntiAmplificationGate::new(3);
        // Client not yet validated: no reply commits, budget is zero.
        assert_eq!(gate.budget(), 0);
        assert!(!gate.try_commit_reply(false), "unvalidated client gets no reply");
        // Even claiming validated=true, with zero validated requests the budget
        // is zero so nothing commits.
        assert!(!gate.try_commit_reply(true));
    }

    #[test]
    fn total_replies_never_exceed_factor_times_validated_requests() {
        let mut gate = AntiAmplificationGate::new(3);
        gate.record_validated_request();
        gate.record_validated_request();
        // budget = 3 * 2 = 6 replies.
        assert_eq!(gate.budget(), 6);
        let mut committed = 0;
        for _ in 0..100 {
            if gate.try_commit_reply(true) {
                committed += 1;
            }
        }
        assert_eq!(committed, 6, "replies bounded to factor * validated requests");
    }

    // --- K+M shard reconstruction with bad-CID rejection (TLA: ReconstructOrReject) ---

    #[test]
    fn reconstructs_from_first_k_of_k_plus_m_shards_rejecting_bad_cid() {
        let message = b"the quick brown fox jumps over the lazy dog, in bulk".to_vec();
        let (k, m) = (4usize, 2usize);
        let mut shards = encode(&message, k, m).unwrap();

        // Corrupt one data shard's bytes WITHOUT updating its CID: it must be
        // rejected on verify, and reconstruction falls back to a parity shard.
        shards[1].bytes[0] ^= 0xFF;
        assert!(!shards[1].verify(), "corrupted shard fails CID verification");

        let recovered = reconstruct(&shards, k, message.len()).unwrap();
        assert_eq!(recovered, message, "reconstructed from surviving+parity shards");
    }

    #[test]
    fn reconstruction_fails_with_fewer_than_k_verified_shards() {
        let message = b"bulk payload requiring k data shards".to_vec();
        let (k, m) = (4usize, 1usize);
        let mut shards = encode(&message, k, m).unwrap();
        // Drop two data shards AND the single parity: only k-2 verified data
        // shards remain, and one parity cannot recover two holes.
        shards.retain(|s| s.index != 0 && s.index != 1 && s.index < k);
        let err = reconstruct(&shards, k, message.len()).unwrap_err();
        assert!(matches!(err, ShardError::InsufficientShards { need, .. } if need == k));
    }
}
