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

/// The pillar-UDP protocol wire version this build EMITS on every shard it
/// encodes (ROI P1 "Versioning, compatibility & safe rollout"). This surface's
/// version space is independent of every other stamped surface (the message
/// format's [`crate::MESSAGE_VERSION`], the event envelope, the manifest
/// schema, …): they advance separately.
///
/// **Bumped to 2 for the portable cell-minted session-key cutover**
/// (`docs/papers/pillar-udp-encryption.md`): dropping the legacy
/// Noise / seal-to-recipients pillar-UDP transport crypto in favor of the
/// portable session key ([`crate::pillarmsg_session`]) is a BREAKING wire
/// change, so the protocol version advances and
/// [`crate::pillarmsg_session::negotiate_session_key_peer`] refuses a legacy
/// (version-1) peer cleanly while a mixed rolling swarm coexists.
pub const PROTOCOL_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(2);

/// The OLDEST pillar-UDP protocol wire version this build can still decode.
/// A decoded stamp outside `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` is a
/// [`ShardError::UnsupportedProtocolVersion`] — distinct from a malformed
/// (truncated / garbage) buffer, so the future compatibility layer can treat a
/// newer peer as negotiable rather than as corruption.
///
/// Raised to 2 alongside [`PROTOCOL_VERSION`]: the session-key cutover removed
/// the legacy version-1 transport-crypto path, so a version-1 (Noise-era) peer
/// is outside this build's decodable window and is refused as a clean
/// negotiation refusal rather than mis-framed.
pub const MIN_PROTOCOL_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(2);

/// The pillar-UDP N-1+ backward-compat window (ROI P1 "Compatibility
/// contract: check, negotiate, N-1+"): the max tolerated absolute difference
/// between two peers' DECLARED [`PROTOCOL_VERSION`]s for a session to be
/// admitted. Distinct from `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` (which
/// bounds a single shard's stamp against what THIS build can decode at all):
/// the window additionally requires the PEER's declared running version stay
/// close enough to negotiate, mirroring `specs/VersioningCompat.tla`'s
/// `Negotiate` guard (`Diff(peerVer[p][s], peerVer[q][s]) <= N`).
pub const PROTOCOL_COMPAT_WINDOW: pillar_crypto::CompatWindow = pillar_crypto::CompatWindow(0);

/// The stable surface name pillar-UDP negotiates under (a
/// [`pillar_crypto::DeclaredVersions`] key).
pub const PROTOCOL_SURFACE: &str = "pillar-udp";

/// A pillar-UDP peer's declared handshake: the [`PROTOCOL_VERSION`] it is
/// currently running, exchanged BEFORE a session's shards are processed (the
/// ROI's "parties exchange declared per-surface version sets before
/// interoperating" clause, applied to the pillar-UDP transport).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerHandshake {
    /// The peer's declared running [`PROTOCOL_VERSION`].
    pub protocol_version: pillar_crypto::SurfaceVersion,
}

impl PeerHandshake {
    /// This build's own handshake: declares the current [`PROTOCOL_VERSION`].
    #[must_use]
    pub fn local() -> Self {
        PeerHandshake {
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

/// Negotiate a pillar-UDP session with a peer that declared `remote` via
/// [`PeerHandshake`], BEFORE any of its shards are decoded.
///
/// Compatible (declared versions within [`PROTOCOL_COMPAT_WINDOW`] of each
/// other) admits the session; an incompatible pair is cleanly refused via
/// [`pillar_crypto::NegotiationRefused`] — never a silent mis-negotiation and
/// never confused with [`ShardError::MalformedVersionStamp`] /
/// [`ShardError::UnsupportedProtocolVersion`] (those gate a single shard's
/// on-wire stamp; this gates the SESSION before any shard is even read).
///
/// # Errors
/// Returns [`pillar_crypto::NegotiationRefused`] when `local` and `remote`
/// disagree by more than [`PROTOCOL_COMPAT_WINDOW`].
pub fn negotiate_session(
    local: PeerHandshake,
    remote: PeerHandshake,
) -> Result<(), pillar_crypto::NegotiationRefused> {
    pillar_crypto::negotiate_surface(
        PROTOCOL_SURFACE,
        local.protocol_version,
        remote.protocol_version,
        PROTOCOL_COMPAT_WINDOW,
    )
}

/// A content identifier: the canonical content address of a message's bytes.
///
/// This is exactly [`pillar_streamdb::content_address`], so a CID computed here
/// equals the CID the streaming DB / blob store computes for the same bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cid(pub pillar_streamdb::OpId);

impl Cid {
    /// The raw multihash bytes of this CID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Compute the CID of a message's bytes (canonical across all layers).
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Cid(pillar_streamdb::OpId(content_address(bytes)))
    }
}

impl PartialOrd for Cid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Cid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
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
    pub fn process(&mut self, cid: &Cid) -> bool {
        self.seen.insert(cid.clone())
    }

    /// Whether this CID has already been processed.
    #[must_use]
    pub fn has_seen(&self, cid: &Cid) -> bool {
        self.seen.contains(cid)
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
    pub fn lease_holder(&self, cid: &Cid) -> Option<&NodeId> {
        if self.members.is_empty() {
            return None;
        }
        // Derive a stable index from the leading bytes of the (cryptographic)
        // content address — a pure function of the CID, identical on every node.
        let mut acc: u64 = 0;
        for &b in cid.as_bytes().iter().take(8) {
            acc = (acc << 8) | u64::from(b);
        }
        let idx = (acc as usize) % self.members.len();
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
    pub fn admits(&self, effect: SideEffect, cid: &Cid, candidate: &NodeId) -> bool {
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
    _cid: &Cid,
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
    pub fn forward(&mut self, cid: &Cid, ttl: u32) -> Option<u32> {
        if ttl == 0 {
            return None;
        }
        if !self.seen.insert(cid.clone()) {
            // Already forwarded this CID: a loop — terminate.
            return None;
        }
        Some(ttl - 1)
    }

    /// Decide the delivery outcome for a copy of `cid` arriving with `ttl`
    /// hops remaining — the distinction [`Self::forward`] deliberately
    /// collapses (it answers only "keep forwarding or not"), needed by the
    /// `pillar-message-hop-metric` terminal-processing metric: a message
    /// whose TTL is legitimately exhausted ON ARRIVAL at its addressed
    /// destination is a real, single terminal delivery (worth a metric
    /// sample), never conflated with a duplicate/looped arrival (which is
    /// not a distinct delivery at all and must never double-emit).
    pub fn arrive(&mut self, cid: &Cid, ttl: u32) -> Delivery {
        if !self.seen.insert(cid.clone()) {
            return Delivery::Loop;
        }
        if ttl == 0 {
            Delivery::Terminal
        } else {
            Delivery::Forward(ttl - 1)
        }
    }
}

/// The outcome of [`ForwardGate::arrive`] for one message copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Forward the message onward, decrementing the TTL to the carried
    /// value.
    Forward(u32),
    /// This node is the addressed destination (TTL exhausted on a
    /// first-seen arrival): the terminal-processing point the
    /// `pillar_message_hops` metric is emitted from.
    Terminal,
    /// A duplicate arrival of an already-seen CID: drop silently. Not a
    /// real distinct delivery — never forward, never emit a terminal
    /// metric for it.
    Loop,
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

/// A measured per-path link signal, as reported by the reliability mesh.
///
/// This is the raw quantitative input the dynamic-redundancy controller
/// consumes — the same measured signal `select_transport` classifies into a
/// coarse [`LinkQuality`], but kept numeric here so redundancy can scale
/// *continuously* with conditions rather than snap between discrete modes. A
/// clean cheap path reports a near-zero `loss` and low `latency`; a hostile one
/// reports a high `loss` and/or `latency`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PathSignal {
    /// Measured packet-loss fraction on this path, in `[0.0, 1.0]`.
    pub loss: f64,
    /// Measured one-way latency on this path, in milliseconds.
    pub latency_ms: f64,
}

impl PathSignal {
    /// A pristine path: zero measured loss, zero latency. The controller
    /// collapses redundancy toward a single copy for such a path.
    pub const PRISTINE: PathSignal = PathSignal {
        loss: 0.0,
        latency_ms: 0.0,
    };

    /// A measured path signal, clamping `loss` into `[0.0, 1.0]` and a negative
    /// `latency_ms` up to `0.0` so a bogus report can never drive a negative or
    /// out-of-range redundancy pressure.
    #[must_use]
    pub fn new(loss: f64, latency_ms: f64) -> Self {
        PathSignal {
            loss: loss.clamp(0.0, 1.0),
            latency_ms: latency_ms.max(0.0),
        }
    }

    /// The normalized `[0.0, 1.0]` redundancy PRESSURE this signal warrants:
    /// `0.0` on a pristine path (one copy is enough), rising toward `1.0` as
    /// measured loss and latency climb. Loss dominates (it directly defeats a
    /// single copy); latency contributes a smaller term (a high-RTT path
    /// benefits from spraying rather than serializing retransmit rounds).
    ///
    /// `latency_ref_ms` is the latency at which the latency term saturates
    /// (a per-connection tuning constant); a `<= 0` reference disables the
    /// latency term entirely.
    #[must_use]
    pub fn pressure(&self, latency_ref_ms: f64) -> f64 {
        let loss_term = self.loss; // already in [0,1]
        let lat_term = if latency_ref_ms > 0.0 {
            (self.latency_ms / latency_ref_ms).clamp(0.0, 1.0)
        } else {
            0.0
        };
        // Loss is the primary driver (weight 1.0); latency is a secondary
        // nudge (weight 0.5). The combined pressure is clamped to [0,1] so it
        // can never push redundancy past the allowance ceiling.
        (loss_term + 0.5 * lat_term).clamp(0.0, 1.0)
    }
}

/// A per-connection redundancy controller: redundancy is the DEFAULT delivery
/// posture on EVERY link, dynamically bounded to what measured conditions
/// warrant, never a fallback engaged only on a known-bad link.
///
/// Unlike a single-connection congestion window (TCP/QUIC) that reads loss as
/// congestion and THROTTLES one path, this controller treats the whole cell as
/// the congestion-handling resource: the measured loss/latency signal
/// REALLOCATES redundancy (more copies, spread across dispersed paths) rather
/// than shrinking a window. A clean cheap path collapses toward a SINGLE copy
/// (`floor`, default 1) so a healthy link pays little; a hostile path scales
/// UP toward — but NEVER past — the config `ceiling`, so a bad link is still
/// covered while the per-connection [`BoundedTotalDatagrams`] allowance
/// (`specs/PillarUDP.tla`) is preserved by construction.
///
/// The `ceiling` IS the declared per-connection redundancy allowance; the
/// controller guarantees `floor <= copies(signal) <= ceiling` for every
/// possible signal, so no dynamic scaling can ever exceed the allowance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RedundancyController {
    /// The minimum copy count on a pristine path (the default single-copy
    /// posture). Always `>= 1` — a message is always sent at least once.
    floor: u32,
    /// The config-bounded per-connection redundancy allowance: the maximum
    /// copies any spray round may use, NEVER exceeded (BoundedTotalDatagrams).
    ceiling: u32,
    /// Latency (ms) at which the latency pressure term saturates.
    latency_ref_ms: f64,
}

impl RedundancyController {
    /// A controller with the given single-copy `floor` (raised to at least 1)
    /// and config redundancy-allowance `ceiling` (raised to at least the
    /// floor). `latency_ref_ms` sets where the latency pressure term saturates
    /// (`<= 0` disables the latency term, making redundancy loss-driven only).
    #[must_use]
    pub fn new(floor: u32, ceiling: u32, latency_ref_ms: f64) -> Self {
        let floor = floor.max(1);
        let ceiling = ceiling.max(floor);
        RedundancyController {
            floor,
            ceiling,
            latency_ref_ms,
        }
    }

    /// The config-bounded per-connection redundancy allowance (the ceiling).
    #[must_use]
    pub fn allowance(&self) -> u32 {
        self.ceiling
    }

    /// The single-copy floor (the default posture on a pristine path).
    #[must_use]
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// The redundancy copy count this measured path signal warrants.
    ///
    /// Interpolates linearly from `floor` (at zero pressure — a pristine path)
    /// to `ceiling` (at full pressure — a maximally hostile path) using the
    /// normalized pressure from [`PathSignal::pressure`]. The result is ALWAYS
    /// in `[floor, ceiling]`:
    /// - a clean cheap path yields `floor` (a single copy by default), so a
    ///   healthy link pays almost nothing;
    /// - rising loss/latency scales copies up toward the allowance;
    /// - the count can NEVER exceed `ceiling`, preserving the per-connection
    ///   BoundedTotalDatagrams allowance regardless of how bad the signal is.
    #[must_use]
    pub fn copies(&self, signal: PathSignal) -> u32 {
        let p = signal.pressure(self.latency_ref_ms);
        let span = f64::from(self.ceiling - self.floor);
        // Round to nearest so a mid-pressure path gets a representative count;
        // clamp defensively even though pressure ∈ [0,1] guarantees the range.
        let extra = (p * span).round() as u32;
        (self.floor + extra).clamp(self.floor, self.ceiling)
    }
}

/// One erasure-coded shard of a bulk message.
///
/// The message is split into `k` data shards; `m` parity shards are the XOR of
/// the data shards (all shards are equal length, the message being zero-padded
/// to a multiple of `k`). Each shard is CID-verified: `cid` is the content
/// address of the shard's PAYLOAD, so a corrupted shard is detected on receipt.
///
/// # Wire versioning
/// The on-wire byte form of a shard ([`Shard::bytes`]) carries a leading 2-byte
/// big-endian [`PROTOCOL_VERSION`] stamp: [`encode`] prepends it and the decode
/// path ([`reconstruct`]) reads+validates it against
/// `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`. The stamp is deliberately kept
/// OUT of the content-address computation — `cid` is the address of the payload
/// bytes ONLY, not the stamped wire bytes — so bumping the protocol version
/// never changes a payload's CID and CIDs stay canonical across every layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard {
    /// Position of this shard: `0..k` are data shards, `k..k+m` are parity.
    pub index: usize,
    /// The shard's on-wire bytes: a leading 2-byte big-endian
    /// [`PROTOCOL_VERSION`] stamp followed by the payload (all shards' payloads
    /// share one length). The CID addresses the payload, NOT this stamped form.
    pub bytes: Vec<u8>,
    /// Content address of the shard's PAYLOAD (the bytes after the version
    /// stamp), for on-receipt integrity verification.
    pub cid: Cid,
}

impl Shard {
    /// The shard's payload bytes: [`Shard::bytes`] with the leading 2-byte
    /// version stamp stripped. Returns `None` if the wire bytes are too short
    /// to even carry the stamp (a malformed shard).
    #[must_use]
    fn payload(&self) -> Option<&[u8]> {
        self.bytes.get(2..)
    }

    /// Whether the shard's PAYLOAD still hashes to its claimed CID (integrity).
    ///
    /// The version stamp is excluded from this check, exactly as it is excluded
    /// from the CID computation in [`encode`].
    #[must_use]
    pub fn verify(&self) -> bool {
        self.payload().is_some_and(|p| Cid::of(p) == self.cid)
    }
}

/// An erasure-coding / pillar-UDP wire error.
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
    /// A shard's on-wire bytes were too short to carry the leading 2-byte
    /// [`PROTOCOL_VERSION`] stamp: a truncated / malformed buffer (a parse
    /// error), NOT an unknown version.
    MalformedVersionStamp,
    /// A shard's leading stamp parsed cleanly but carries a pillar-UDP protocol
    /// version outside `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` — most
    /// importantly a version NEWER than this build understands. Reported
    /// distinctly from [`ShardError::MalformedVersionStamp`] so the future
    /// compatibility layer can negotiate a newer peer rather than treat it as
    /// corruption.
    UnsupportedProtocolVersion(pillar_crypto::VersionError),
}

/// Split `message` into `k` data shards plus `m` XOR-parity shards.
///
/// Every shard's PAYLOAD is equal length (the message is zero-padded to a
/// multiple of `k`), and every shard is CID-stamped over its payload so
/// corruption is detectable. The first `k` shards are the data; the next `m`
/// are parity (each the running XOR of the data shards — a simple systematic
/// code sufficient to reconstruct a contiguous data shard from parity).
///
/// Each shard's on-wire [`Shard::bytes`] is a leading 2-byte big-endian
/// [`PROTOCOL_VERSION`] stamp followed by the payload; the CID addresses the
/// PAYLOAD only, so the stamp never perturbs a payload's content address.
///
/// # Errors
/// Returns [`ShardError::Empty`] if `k == 0` or the message is empty.
pub fn encode(message: &[u8], k: usize, m: usize) -> Result<Vec<Shard>, ShardError> {
    if k == 0 || message.is_empty() {
        return Err(ShardError::Empty);
    }
    // The leading pillar-UDP protocol version stamp prepended to every shard's
    // on-wire bytes. It is intentionally NOT fed into `Cid::of` below.
    let stamp = PROTOCOL_VERSION.to_be_bytes();
    // Prepend the version stamp to a payload to form a shard's on-wire bytes,
    // leaving the CID (computed over the payload) untouched by the stamp.
    let on_wire = |payload: &[u8]| -> Vec<u8> {
        let mut b = Vec::with_capacity(2 + payload.len());
        b.extend_from_slice(&stamp);
        b.extend_from_slice(payload);
        b
    };
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
        .map(|(index, payload)| Shard {
            index,
            cid: Cid::of(payload),
            bytes: on_wire(payload),
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
            bytes: on_wire(&parity),
        });
    }
    Ok(shards)
}

/// Reconstruct the original `orig_len`-byte message from received shards.
///
/// Each shard's on-wire bytes are first version-checked at the HEAD of the
/// decode path: a buffer too short for the leading 2-byte stamp is a
/// [`ShardError::MalformedVersionStamp`] (a parse error), while a legible stamp
/// outside `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` is a distinct
/// [`ShardError::UnsupportedProtocolVersion`] (via
/// [`pillar_crypto::SurfaceVersion::check_supported`]). Only then are payloads
/// (stamp stripped) used.
///
/// Only shards that VERIFY (payload hashes to their claimed CID) are used; a
/// shard with a bad CID is rejected outright. Reconstruction needs the `k` data
/// shards; a single missing data shard is recovered from a verified parity
/// shard (XOR of the surviving data shards). Requires at least `k` verified
/// shards total covering the data positions.
///
/// # Errors
/// Returns [`ShardError::MalformedVersionStamp`] / [`ShardError::UnsupportedProtocolVersion`]
/// on a bad version stamp, [`ShardError::Empty`] if `k == 0`,
/// [`ShardError::MissingLength`] if `orig_len` is zero, or
/// [`ShardError::InsufficientShards`] if fewer than `k` data positions can be
/// recovered from the verified shards.
pub fn reconstruct(shards: &[Shard], k: usize, orig_len: usize) -> Result<Vec<u8>, ShardError> {
    if k == 0 {
        return Err(ShardError::Empty);
    }
    if orig_len == 0 {
        return Err(ShardError::MissingLength);
    }
    // Head-of-decode-path version gate: validate every shard's leading stamp
    // BEFORE any payload is interpreted. A buffer too short for the stamp is a
    // parse error; a legible-but-out-of-window version is a DISTINCT reject.
    for s in shards {
        let stamp = pillar_crypto::SurfaceVersion::from_be_bytes(&s.bytes)
            .map_err(|_| ShardError::MalformedVersionStamp)?;
        stamp
            .check_supported(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION)
            .map_err(ShardError::UnsupportedProtocolVersion)?;
    }
    // Keep only integrity-verified shards; a bad-CID shard is rejected.
    let good: Vec<&Shard> = shards.iter().filter(|s| s.verify()).collect();
    if good.is_empty() {
        return Err(ShardError::InsufficientShards { need: k, have: 0 });
    }
    // Work over PAYLOADS (stamp stripped); every good shard has a payload since
    // it passed both the version gate and `verify`.
    let shard_len = good[0]
        .payload()
        .expect("verified shard has a payload")
        .len();

    // Collect available data shards by position.
    let mut data: Vec<Option<Vec<u8>>> = vec![None; k];
    for s in &good {
        if s.index < k {
            data[s.index] = Some(s.payload().expect("verified shard has a payload").to_vec());
        }
    }
    let present = data.iter().filter(|d| d.is_some()).count();

    if present < k {
        // Recover ONE missing data shard from a verified parity shard, if
        // exactly one data position is missing.
        let missing: Vec<usize> = (0..k).filter(|&i| data[i].is_none()).collect();
        if missing.len() == 1 {
            if let Some(parity) = good.iter().find(|s| s.index >= k) {
                let mut recovered = parity
                    .payload()
                    .expect("verified shard has a payload")
                    .to_vec();
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

// ===========================================================================
// Cross-topology-domain multiplexing for aggregate throughput.
//
// One logical transfer (a blob, a stream range, a PSL reply set) is split into
// BLOCK-ALIGNED, CID-verified chunks that are served INTERLEAVED from multiple
// sender nodes drawn from DISPERSED topology failure domains. The client
// reassembles by (offset, CID). The block->sender assignment (the "block map")
// is derived DETERMINISTICALLY from the transfer CID plus the topology/
// membership view — the SAME budgeted, trackerless mechanism the dispersed
// reply-set spray ([`reply_node_set`]) uses — so every sender and the client
// independently agree on who serves which block with NO coordination round-trip.
//
// Erasure coding (any K of N) rides on top per block via [`encode`]/
// [`reconstruct`], so a slow or lossy single path is covered by shards served
// from the other paths.
//
// The HONEST throughput bound this delivers (and the acceptance test pins):
// aggregate throughput ~= the SUM of the per-path (per-sender-upstream)
// bandwidths ONLY when the bottleneck is per-source upstream (or a lossy middle
// path). When the CLIENT last-mile downlink is the bottleneck, multiplexing
// buys NOTHING — the aggregate is capped at the client downlink. The
// [`AggregateThroughput`] model computes exactly this bound so the win is never
// overstated.
// ===========================================================================

/// One block-aligned, CID-verified chunk of a multiplexed transfer, plus the
/// sender node deterministically assigned to serve it.
///
/// `offset` is the block's byte offset in the ORIGINAL transfer (block-aligned:
/// a multiple of the plan's `block_size`), `len` its byte length (the final
/// block may be short), `cid` the content address of the block's bytes (the
/// client verifies each received block against it and reassembles by
/// `offset`+`cid`), and `sender` the node assigned to serve it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockAssignment {
    /// Block index (`0..n_blocks`), i.e. `offset / block_size`.
    pub index: usize,
    /// Byte offset of this block in the original transfer (block-aligned).
    pub offset: usize,
    /// Byte length of this block (the last block may be shorter than
    /// `block_size`).
    pub len: usize,
    /// Content address of this block's bytes — the client verifies each
    /// received block against it before accepting it into the reassembly.
    pub cid: Cid,
    /// The sender node deterministically assigned to serve this block.
    pub sender: NodeId,
}

/// A trackerless, sender-coordinated MULTIPLEX PLAN: the deterministic
/// block->sender map for one logical transfer.
///
/// Built from the transfer's bytes, a `block_size`, and the sender view
/// (`senders`). The block->sender assignment is a pure function of the transfer
/// CID and the (normalized, sorted) sender set — so a sender computing "which
/// blocks are mine" and the client computing "who serves block b" independently
/// agree with no coordination. Blocks are assigned INTERLEAVED (round-robin
/// seeded by the transfer CID) so consecutive blocks come from DIFFERENT senders
/// and the load is spread across every path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiplexPlan {
    /// Content address of the WHOLE transfer — the seed of the block map and
    /// the top-level integrity anchor.
    pub transfer_cid: Cid,
    /// Total byte length of the transfer.
    pub total_len: usize,
    /// Block granularity in bytes.
    pub block_size: usize,
    /// The normalized (sorted, deduped) sender view the map was derived over.
    pub senders: Vec<NodeId>,
    /// One assignment per block, in ascending block order.
    pub blocks: Vec<BlockAssignment>,
}

impl MultiplexPlan {
    /// Derive the deterministic multiplex plan for `transfer` at the given
    /// `block_size` across the `senders` view.
    ///
    /// The block->sender map is seeded from the transfer CID (so it is stable
    /// and trackerless) and assigns blocks round-robin over the sorted sender
    /// set, so consecutive blocks are served by distinct senders (interleaved
    /// spray). Returns `None` if `block_size == 0` or `senders` is empty.
    #[must_use]
    pub fn derive(
        transfer: &[u8],
        block_size: usize,
        senders: impl IntoIterator<Item = NodeId>,
    ) -> Option<Self> {
        if block_size == 0 {
            return None;
        }
        let mut senders: Vec<NodeId> = senders.into_iter().collect();
        senders.sort();
        senders.dedup();
        if senders.is_empty() {
            return None;
        }
        let transfer_cid = Cid::of(transfer);
        // Seed the round-robin rotation from the transfer CID so two nodes over
        // the same view agree bit-for-bit and different transfers spread
        // differently — a pure function of the CID, never a tracker.
        let mut seed: u64 = 0;
        for &b in transfer_cid.as_bytes().iter().take(8) {
            seed = (seed << 8) | u64::from(b);
        }
        let start = (seed as usize) % senders.len();

        let total_len = transfer.len();
        let n_blocks = total_len
            .div_ceil(block_size)
            .max(if total_len == 0 { 0 } else { 1 });
        let mut blocks = Vec::with_capacity(n_blocks);
        for index in 0..n_blocks {
            let offset = index * block_size;
            let end = (offset + block_size).min(total_len);
            let bytes = &transfer[offset..end];
            // Interleave: consecutive blocks rotate to the NEXT sender.
            let sender = senders[(start + index) % senders.len()].clone();
            blocks.push(BlockAssignment {
                index,
                offset,
                len: end - offset,
                cid: Cid::of(bytes),
                sender,
            });
        }
        Some(Self {
            transfer_cid,
            total_len,
            block_size,
            senders,
            blocks,
        })
    }

    /// The blocks THIS sender is responsible for serving (its slice of the
    /// interleaved map) — computed with no coordination.
    #[must_use]
    pub fn blocks_for(&self, sender: &NodeId) -> Vec<&BlockAssignment> {
        self.blocks.iter().filter(|b| &b.sender == sender).collect()
    }

    /// How many distinct sender PATHS this plan actually spreads across (the
    /// count of senders that own at least one block). Never exceeds the sender
    /// view and, for a transfer with at least as many blocks as senders, equals
    /// the full sender view — the multi-path fan-out is REAL, not nominal.
    #[must_use]
    pub fn active_paths(&self) -> usize {
        let mut seen: HashSet<&NodeId> = HashSet::new();
        for b in &self.blocks {
            seen.insert(&b.sender);
        }
        seen.len()
    }
}

/// A CID-verifying client-side REASSEMBLER for a multiplexed transfer.
///
/// The client accepts each received block ONLY if its bytes hash to the CID the
/// [`MultiplexPlan`] assigned to that offset — a corrupted, mis-delivered, or
/// stale block is rejected — then reassembles the whole transfer by placing each
/// verified block at its `offset`. Blocks may arrive in ANY order and from ANY
/// path (interleaved), so `accept` is order-independent.
#[derive(Debug)]
pub struct MultiplexReassembler {
    total_len: usize,
    block_size: usize,
    /// Per-block expected (offset, len, cid), indexed by block index.
    expect: Vec<BlockAssignment>,
    /// Received+verified block payloads, indexed by block index.
    received: Vec<Option<Vec<u8>>>,
}

/// Why a received multiplex block was rejected, or the reassembly is not done.
#[derive(Debug, PartialEq, Eq)]
pub enum MultiplexError {
    /// The block index is outside the plan.
    UnknownBlock(usize),
    /// The block's bytes did not hash to the CID the plan assigned to its
    /// offset (corruption / mis-delivery).
    CidMismatch(usize),
    /// The block's length did not match the plan's expected length.
    LengthMismatch {
        /// The offending block index.
        index: usize,
        /// The plan's expected byte length.
        expected: usize,
        /// The supplied byte length.
        got: usize,
    },
    /// Reassembly was requested but some blocks are still missing.
    Incomplete {
        /// Count of blocks still not received.
        missing: usize,
    },
}

impl MultiplexReassembler {
    /// A reassembler primed with the plan's expected block layout.
    #[must_use]
    pub fn new(plan: &MultiplexPlan) -> Self {
        Self {
            total_len: plan.total_len,
            block_size: plan.block_size,
            expect: plan.blocks.clone(),
            received: vec![None; plan.blocks.len()],
        }
    }

    /// Accept a received block (by index) with its bytes.
    ///
    /// The bytes are CID-verified against the plan's assignment for that block;
    /// a mismatch is rejected and the block is NOT stored. Idempotent: a second
    /// valid copy of an already-held block is accepted as a no-op (multi-path
    /// redundancy delivers duplicates). Returns `Ok(())` on accept.
    ///
    /// # Errors
    /// [`MultiplexError::UnknownBlock`], [`MultiplexError::LengthMismatch`], or
    /// [`MultiplexError::CidMismatch`].
    pub fn accept(&mut self, index: usize, bytes: &[u8]) -> Result<(), MultiplexError> {
        let exp = self
            .expect
            .get(index)
            .ok_or(MultiplexError::UnknownBlock(index))?;
        if bytes.len() != exp.len {
            return Err(MultiplexError::LengthMismatch {
                index,
                expected: exp.len,
                got: bytes.len(),
            });
        }
        if Cid::of(bytes) != exp.cid {
            return Err(MultiplexError::CidMismatch(index));
        }
        self.received[index] = Some(bytes.to_vec());
        Ok(())
    }

    /// Count of blocks not yet received.
    #[must_use]
    pub fn missing(&self) -> usize {
        self.received.iter().filter(|b| b.is_none()).count()
    }

    /// Whether every block has been received and verified.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing() == 0
    }

    /// Reassemble the whole transfer by placing each verified block at its
    /// offset. Every block was CID-checked on `accept`, so the reassembled bytes
    /// are integrity-guaranteed.
    ///
    /// # Errors
    /// [`MultiplexError::Incomplete`] if any block is still missing.
    pub fn reassemble(&self) -> Result<Vec<u8>, MultiplexError> {
        let missing = self.missing();
        if missing != 0 {
            return Err(MultiplexError::Incomplete { missing });
        }
        let mut out = vec![0u8; self.total_len];
        for (index, slot) in self.received.iter().enumerate() {
            let bytes = slot.as_ref().expect("complete: every slot filled");
            let offset = index * self.block_size;
            out[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        Ok(out)
    }
}

/// The measured/announced upstream bandwidth of one sender path plus the
/// client's last-mile downlink, in identical (abstract) rate units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PathBandwidth {
    /// This sender's upstream serving rate.
    pub sender_upstream: f64,
}

/// The HONEST aggregate-throughput model for a multiplexed transfer.
///
/// Multiplexing serves blocks in parallel from `paths` senders, so the
/// achievable aggregate rate is the SUM of the per-sender upstreams — but the
/// client can never receive faster than its own last-mile DOWNLINK, so the
/// realized throughput is `min(sum(sender_upstream), client_downlink)`.
///
/// This encodes the ROI's honest bound precisely:
/// - per-source-upstream-bottlenecked (each sender slower than the client
///   downlink, and their sum still under it): aggregate == the sum, STRICTLY
///   MORE than any single path — a real win;
/// - client-downlink-bottlenecked: aggregate == the client downlink, and
///   multiplexing buys NOTHING beyond it.
#[derive(Clone, Debug)]
pub struct AggregateThroughput {
    paths: Vec<PathBandwidth>,
    client_downlink: f64,
}

impl AggregateThroughput {
    /// Model an aggregate transfer over `paths` sender upstreams to a client
    /// whose last-mile downlink is `client_downlink`.
    #[must_use]
    pub fn new(paths: impl IntoIterator<Item = PathBandwidth>, client_downlink: f64) -> Self {
        Self {
            paths: paths.into_iter().collect(),
            client_downlink,
        }
    }

    /// The sum of every sender path's upstream — the parallel-serving ceiling
    /// BEFORE the client downlink is applied.
    #[must_use]
    pub fn sum_upstream(&self) -> f64 {
        self.paths.iter().map(|p| p.sender_upstream).sum()
    }

    /// The bandwidth of the single BEST path — the throughput a non-multiplexed
    /// (single-sender) transfer would achieve, itself still downlink-capped.
    #[must_use]
    pub fn best_single_path(&self) -> f64 {
        let best = self
            .paths
            .iter()
            .map(|p| p.sender_upstream)
            .fold(0.0_f64, f64::max);
        best.min(self.client_downlink)
    }

    /// The realized aggregate throughput: `min(sum(upstreams), downlink)`.
    #[must_use]
    pub fn realized(&self) -> f64 {
        self.sum_upstream().min(self.client_downlink)
    }

    /// Whether the bottleneck is the CLIENT DOWNLINK (the sum of upstreams meets
    /// or exceeds it) — the case where multiplexing buys nothing more.
    #[must_use]
    pub fn client_downlink_is_bottleneck(&self) -> bool {
        self.sum_upstream() >= self.client_downlink
    }

    /// Whether multiplexing yields a REAL aggregate win over the best single
    /// path — true exactly when the per-source upstream bottleneck lets the
    /// summed rate exceed any one path (and stay within the downlink budget).
    #[must_use]
    pub fn beats_single_path(&self) -> bool {
        self.realized() > self.best_single_path()
    }
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
            if dedup.process(&cid) {
                processed += 1;
            }
        }
        assert_eq!(
            processed, 1,
            "message processed exactly once across 4 copies"
        );
        assert!(dedup.has_seen(&cid));
    }

    // --- exclusive-message single-lease-holder routing (TLA: ExclusiveSingleHolder) ---

    #[test]
    fn exclusive_message_routes_only_to_lease_holder() {
        let members = [n("a"), n("b"), n("c"), n("d")];
        let router = ExclusiveRouter::new(members.clone());
        let cid = Cid::of(b"claim-the-dns-name");
        let holder = router.lease_holder(&cid).cloned().unwrap();

        let mut admitted = 0;
        for m in &members {
            if router.admits(SideEffect::Exclusive, &cid, m) {
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
                router.admits(SideEffect::Convergent, &cid, m),
                "any member may pick up an idempotent message"
            );
        }
        // A non-member is never admitted.
        assert!(!router.admits(SideEffect::Convergent, &cid, &n("stranger")));
    }

    // --- identical independently-computed reply-node sets (TLA: DeterministicReplySet) ---

    #[test]
    fn reply_node_set_identical_across_independent_computations() {
        let ipam_a = two_region_ipam();
        let ipam_b = two_region_ipam();
        let cid = Cid::of(b"a request needing 3 dispersed replies");

        let set_a = reply_node_set(&ipam_a, &cid, 3, false, None);
        let set_b = reply_node_set(&ipam_b, &cid, 3, false, None);
        assert_eq!(
            set_a, set_b,
            "two independent computations agree bit-for-bit"
        );
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
        assert_eq!(gate.forward(&cid, 8), Some(7));
        // An injected loop copy of the SAME cid is refused even with TTL left.
        assert_eq!(gate.forward(&cid, 8), None, "dedup breaks the loop pre-TTL");
    }

    #[test]
    fn forwarding_terminates_exactly_at_ttl_zero_with_distinct_cids() {
        let mut gate = ForwardGate::new();
        let mut ttl = 3u32;
        let mut hops = 0;
        // Each hop is a DISTINCT cid so only the TTL bounds the chain.
        loop {
            let cid = Cid::of(format!("hop-{hops}").as_bytes());
            match gate.forward(&cid, ttl) {
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
        assert!(
            !gate.try_commit_reply(false),
            "unvalidated client gets no reply"
        );
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
        assert_eq!(
            committed, 6,
            "replies bounded to factor * validated requests"
        );
    }

    // --- K+M shard reconstruction with bad-CID rejection (TLA: ReconstructOrReject) ---

    #[test]
    fn reconstructs_from_first_k_of_k_plus_m_shards_rejecting_bad_cid() {
        let message = b"the quick brown fox jumps over the lazy dog, in bulk".to_vec();
        let (k, m) = (4usize, 2usize);
        let mut shards = encode(&message, k, m).unwrap();

        // Corrupt one data shard's PAYLOAD bytes WITHOUT updating its CID: it
        // must be rejected on verify, and reconstruction falls back to a parity
        // shard. Byte index 2 is the first PAYLOAD byte (0..2 is the version
        // stamp, which is excluded from the CID).
        shards[1].bytes[2] ^= 0xFF;
        assert!(
            !shards[1].verify(),
            "corrupted shard fails CID verification"
        );

        let recovered = reconstruct(&shards, k, message.len()).unwrap();
        assert_eq!(
            recovered, message,
            "reconstructed from surviving+parity shards"
        );
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

    // --- pillar-UDP protocol wire version stamp (ROI P1 versioning) ---

    #[test]
    fn shard_round_trips_carrying_current_protocol_version() {
        let message = b"a versioned bulk payload over pillar-UDP".to_vec();
        let (k, m) = (4usize, 2usize);
        let shards = encode(&message, k, m).unwrap();

        // Every shard's on-wire bytes lead with the current PROTOCOL_VERSION
        // stamp, and the CID addresses the payload (NOT the stamped bytes).
        for s in &shards {
            assert_eq!(&s.bytes[..2], &PROTOCOL_VERSION.to_be_bytes());
            assert!(
                s.verify(),
                "payload hashes to its CID with the stamp excluded"
            );
        }

        let recovered = reconstruct(&shards, k, message.len()).unwrap();
        assert_eq!(
            recovered, message,
            "round-trips through the version-stamped wire form"
        );
    }

    #[test]
    fn shard_with_future_protocol_version_is_rejected_distinctly() {
        let message = b"a payload stamped from a newer peer".to_vec();
        let (k, m) = (4usize, 2usize);
        let mut shards = encode(&message, k, m).unwrap();

        // Bump the leading stamp on one shard to a FUTURE version. The CID is
        // untouched (it addresses the payload), so this is a legible-but-unknown
        // version, NOT corruption.
        let future = pillar_crypto::SurfaceVersion(PROTOCOL_VERSION.0 + 1);
        shards[0].bytes[..2].copy_from_slice(&future.to_be_bytes());

        let err = reconstruct(&shards, k, message.len()).unwrap_err();
        assert_eq!(
            err,
            ShardError::UnsupportedProtocolVersion(pillar_crypto::VersionError::Unsupported {
                found: future,
                min: MIN_PROTOCOL_VERSION,
                max: PROTOCOL_VERSION,
            }),
            "a future version is the distinct unsupported-version reject"
        );
        // And it is emphatically NOT the malformed/parse variant.
        assert_ne!(err, ShardError::MalformedVersionStamp);
    }

    // --- pillar-UDP SESSION negotiation (two-sided handshake, ROI P1
    // "Compatibility contract: check, negotiate, N-1+") ---

    #[test]
    fn session_negotiation_links_when_peer_matches_current_version() {
        let local = PeerHandshake::local();
        let remote = PeerHandshake::local();
        assert!(negotiate_session(local, remote).is_ok());
    }

    #[test]
    fn session_negotiation_links_within_the_compat_window() {
        let local = PeerHandshake::local();
        let remote = PeerHandshake {
            protocol_version: pillar_crypto::SurfaceVersion(
                PROTOCOL_VERSION.0.saturating_sub(PROTOCOL_COMPAT_WINDOW.0),
            ),
        };
        assert!(negotiate_session(local, remote).is_ok());
    }

    #[test]
    fn session_negotiation_refuses_a_peer_outside_the_compat_window() {
        let local = PeerHandshake::local();
        let remote = PeerHandshake {
            protocol_version: pillar_crypto::SurfaceVersion(
                PROTOCOL_VERSION.0 + PROTOCOL_COMPAT_WINDOW.0 + 1,
            ),
        };
        let err = negotiate_session(local, remote).unwrap_err();
        assert_eq!(err.surface, PROTOCOL_SURFACE);
        assert_eq!(err.local, PROTOCOL_VERSION);
        assert_eq!(err.remote, remote.protocol_version);
        assert_eq!(err.window, PROTOCOL_COMPAT_WINDOW);
    }

    #[test]
    fn shard_truncated_below_version_stamp_is_a_parse_error() {
        let message = b"a payload whose wire buffer is truncated".to_vec();
        let (k, m) = (4usize, 2usize);
        let mut shards = encode(&message, k, m).unwrap();

        // Truncate one shard's on-wire bytes below the 2-byte stamp: a parse
        // error (MalformedVersionStamp), NEVER an unsupported version.
        shards[0].bytes.truncate(1);

        let err = reconstruct(&shards, k, message.len()).unwrap_err();
        assert_eq!(err, ShardError::MalformedVersionStamp);
        assert!(
            !matches!(err, ShardError::UnsupportedProtocolVersion(_)),
            "truncation is a parse error, not an unknown version"
        );
    }
}
