//! Corrected transport POSTURE for pillar node<->node and pillar-native
//! client traffic (ROI reconcile 2026-09-07, operator "transport-posture
//! correction").
//!
//! The earlier [`crate::pillar_udp::select_transport`] posture treated QUIC as
//! the healthy-link default and pillar-UDP as a fallback used only on a link the
//! reliability mesh flagged bad. That posture wrongly conflated "poor
//! single-connection performance" with "congestion": it assumed a healthy link
//! is best served by a single QUIC connection and only reached for pillar-UDP's
//! clustered multipath redundancy when a link already looked degraded.
//!
//! This module INVERTS that. pillar-UDP is now the PREFERRED transport wherever
//! a pillar-UDP-capable peer is available, because its clustered multipath
//! redundancy gives better large-scale congestion avoidance than any single
//! connection — congestion is avoided by spreading load across many reply paths,
//! not by reacting to a single flow's loss. QUIC/TCP become the FALLBACK +
//! legacy-interop paths, used only for:
//!
//! 1. class-1 HTTPS / HTTP-3 NON-pillar ingress (a browser / legacy client that
//!    does not speak pillar-UDP), and
//! 2. a link where NO pillar-UDP-capable peer is available.
//!
//! It also encodes first-class NAT support as three reply-path tiers
//! ([`ReplyPathTier`]) and a client connection model ([`ClientConnectionSet`])
//! in which a pillar-native client opens redundant connections to several
//! reachable ingest nodes, dials OUTBOUND (its own return path, no hole punch
//! for the base case), and drains to the survivors on degradation.
//!
//! This module carries the POSTURE decision logic (pure, deterministic, unit-
//! and acceptance-testable). The live NAT-traversal wiring (circuit-relay-v2 +
//! DCUtR) rides libp2p's `relay`/`dcutr` behaviours already registered in
//! [`crate::RelayClientBehaviour`]; the pillar-UDP hole-punch role that makes
//! the IPv4+DCUtR reply-diversity tier work is expressed here as the tier's
//! declared per-peer NAT-state cost and its port-exhaustion ceiling.

use std::net::{IpAddr, SocketAddr};

use crate::pillar_udp::TransportKind;

/// Why a particular transport was chosen for a link — so a caller can log/act on
/// the REASON, not just the [`TransportKind`]. The corrected posture makes
/// pillar-UDP the preferred choice; the fallbacks each carry a distinct cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportChoiceReason {
    /// pillar-UDP was selected because a pillar-UDP-capable peer is available:
    /// its clustered multipath redundancy is the PREFERRED path.
    PillarUdpPreferred,
    /// QUIC/TCP fallback: the counterpart is a non-pillar (class-1 HTTPS /
    /// HTTP-3) ingress client that does not speak pillar-UDP.
    LegacyInteropIngress,
    /// QUIC/TCP fallback: no pillar-UDP-capable peer is available on this link,
    /// so a single-connection protocol is the only option.
    NoPillarUdpPeerAvailable,
}

/// A transport selection: the wire [`TransportKind`] AND the [`reason`] the
/// corrected posture chose it, so the decision is auditable.
///
/// [`reason`]: TransportSelection::reason
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportSelection {
    /// The chosen wire transport.
    pub kind: TransportKind,
    /// Why it was chosen.
    pub reason: TransportChoiceReason,
}

impl TransportSelection {
    /// Whether this selection is the preferred clustered-multipath pillar-UDP
    /// path (vs. a QUIC/TCP fallback).
    #[must_use]
    pub fn is_preferred(&self) -> bool {
        self.reason == TransportChoiceReason::PillarUdpPreferred
    }
}

/// What kind of counterpart is on the far end of a link — the input the
/// corrected posture selects on. Unlike the old
/// [`crate::pillar_udp::LinkQuality`] posture (which selected on measured loss),
/// the preferred posture selects on PEER CAPABILITY: is there a pillar-UDP peer
/// to cluster with at all?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAvailability {
    /// A pillar node or pillar-native client that speaks pillar-UDP is
    /// reachable — the clustered multipath path is available and PREFERRED.
    PillarUdpCapablePeer,
    /// A class-1 HTTPS / HTTP-3 NON-pillar ingress client (a browser / legacy
    /// tool) that does not speak pillar-UDP.
    NonPillarIngressClient,
    /// No pillar-UDP-capable peer is reachable on this link (e.g. only a
    /// single legacy relay is dialable).
    NoPillarUdpPeer,
}

/// Select the wire transport for a link under the CORRECTED (preferred) posture.
///
/// This is the INVERSION of [`crate::pillar_udp::select_transport`]:
///
/// - [`PeerAvailability::PillarUdpCapablePeer`] ⇒
///   [`TransportKind::PillarUdp`] (the PREFERRED clustered multipath path),
/// - [`PeerAvailability::NonPillarIngressClient`] ⇒ [`TransportKind::Quic`]
///   (legacy-interop ingress), and
/// - [`PeerAvailability::NoPillarUdpPeer`] ⇒ [`TransportKind::Quic`]
///   (fallback: no pillar-UDP peer to cluster with).
///
/// Note the contrast with the old posture, which returned QUIC for a "healthy"
/// link and pillar-UDP only for a degraded one. Here pillar-UDP is the default
/// whenever a pillar-UDP peer exists, regardless of measured link health.
#[must_use]
pub fn select_preferred_transport(peer: PeerAvailability) -> TransportSelection {
    match peer {
        PeerAvailability::PillarUdpCapablePeer => TransportSelection {
            kind: TransportKind::PillarUdp,
            reason: TransportChoiceReason::PillarUdpPreferred,
        },
        PeerAvailability::NonPillarIngressClient => TransportSelection {
            kind: TransportKind::Quic,
            reason: TransportChoiceReason::LegacyInteropIngress,
        },
        PeerAvailability::NoPillarUdpPeer => TransportSelection {
            kind: TransportKind::Quic,
            reason: TransportChoiceReason::NoPillarUdpPeerAvailable,
        },
    }
}

// -------------------------------------------------------------------------
// Three reply-path tiers.
// -------------------------------------------------------------------------

/// The reply-path reachability tier of an ingest node, ordered best-first. The
/// reply-set redundancy pillar-UDP disperses across nodes only helps if each
/// chosen node can actually be reached on its reply path; the tier records how
/// that node is reachable and what it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReplyPathTier {
    /// **PREFERRED.** An IPv6 Global Unicast Address: directly routable, scales,
    /// costs ZERO per-peer NAT state (no relay, no hole punch). Needs neither
    /// circuit-relay-v2 nor DCUtR.
    Ipv6Gua,
    /// **PARTIAL.** IPv4 behind NAT, reachable via circuit-relay-v2 + a DCUtR
    /// hole punch that yields reply diversity. Bounded by client-gateway port
    /// exhaustion: each punched path consumes a distinct gateway port, so the
    /// number of distinct reply paths has a ceiling.
    Ipv4Dcutr,
    /// **FLOOR.** IPv4 behind NAT with no working DCUtR (hole punch failed /
    /// symmetric NAT): a single relayed reply path, no diversity.
    Ipv4NoDcutr,
}

impl ReplyPathTier {
    /// Whether reaching a node in this tier requires per-peer NAT state (a relay
    /// reservation and/or a DCUtR hole punch). The IPv6 GUA tier requires none.
    #[must_use]
    pub fn requires_per_peer_nat_state(&self) -> bool {
        !matches!(self, ReplyPathTier::Ipv6Gua)
    }

    /// Whether this tier delivers reply-path DIVERSITY (more than one
    /// independent reply path). IPv6 GUA scales freely; IPv4+DCUtR gives partial
    /// diversity up to the port-exhaustion ceiling; IPv4-no-DCUtR is a single
    /// path (the floor).
    #[must_use]
    pub fn provides_reply_diversity(&self) -> bool {
        !matches!(self, ReplyPathTier::Ipv4NoDcutr)
    }

    /// Whether this tier's reply-path count is bounded by client-gateway port
    /// exhaustion. Only the IPv4+DCUtR tier is: each punched path burns a
    /// distinct gateway port. IPv6 GUA is unbounded (no NAT); IPv4-no-DCUtR is
    /// already a single path.
    #[must_use]
    pub fn port_exhaustion_bounded(&self) -> bool {
        matches!(self, ReplyPathTier::Ipv4Dcutr)
    }

    /// The maximum number of distinct reply paths this tier can sustain toward
    /// one node, given a per-gateway available-port budget `gateway_ports`.
    ///
    /// - [`Ipv6Gua`](ReplyPathTier::Ipv6Gua): unbounded by NAT — returns
    ///   [`usize::MAX`] (caller bounds by its own redundancy target).
    /// - [`Ipv4Dcutr`](ReplyPathTier::Ipv4Dcutr): bounded to `gateway_ports`
    ///   (the port-exhaustion ceiling).
    /// - [`Ipv4NoDcutr`](ReplyPathTier::Ipv4NoDcutr): exactly `1` (single path).
    #[must_use]
    pub fn max_reply_paths(&self, gateway_ports: usize) -> usize {
        match self {
            ReplyPathTier::Ipv6Gua => usize::MAX,
            ReplyPathTier::Ipv4Dcutr => gateway_ports,
            ReplyPathTier::Ipv4NoDcutr => 1,
        }
    }
}

/// Classify a node's reply-path tier from its advertised reply address and
/// whether a DCUtR hole punch to it succeeded.
///
/// An IPv6 address that is a Global Unicast Address (not loopback, not
/// link-local, not unique-local) is the preferred [`ReplyPathTier::Ipv6Gua`]
/// tier — it needs no NAT state at all, so `dcutr_ok` is irrelevant. An IPv4
/// address (assumed behind NAT for a client) is [`ReplyPathTier::Ipv4Dcutr`]
/// when a hole punch succeeded, else the [`ReplyPathTier::Ipv4NoDcutr`] floor.
#[must_use]
pub fn classify_reply_tier(reply_addr: IpAddr, dcutr_ok: bool) -> ReplyPathTier {
    match reply_addr {
        IpAddr::V6(v6) if is_global_unicast_v6(v6) => ReplyPathTier::Ipv6Gua,
        // A non-global v6 (ULA/link-local) behind NAT behaves like the v4 NAT
        // tiers: diversity only via a working hole punch.
        _ if dcutr_ok => ReplyPathTier::Ipv4Dcutr,
        _ => ReplyPathTier::Ipv4NoDcutr,
    }
}

/// Whether an IPv6 address is a routable Global Unicast Address (the `2000::/3`
/// space), excluding loopback, unspecified, link-local (`fe80::/10`), and
/// unique-local (`fc00::/7`).
fn is_global_unicast_v6(v6: std::net::Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    let seg0 = v6.segments()[0];
    // Link-local fe80::/10
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique-local fc00::/7
    if (seg0 & 0xfe00) == 0xfc00 {
        return false;
    }
    // Global unicast 2000::/3
    (seg0 & 0xe000) == 0x2000
}

// -------------------------------------------------------------------------
// Client connection model.
// -------------------------------------------------------------------------

/// One ingest node a pillar-native client may connect to, with its reply-path
/// tier and current health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngestNode {
    /// The node's dialable socket address.
    pub addr: SocketAddr,
    /// Its reply-path reachability tier.
    pub tier: ReplyPathTier,
    /// Whether the client's connection to it is currently healthy.
    pub healthy: bool,
}

/// The client-side connection model: a pillar-native client receives the cell's
/// node list, opens REDUNDANT connections to several reachable ingest nodes,
/// dials OUTBOUND (its own return path — no hole punch needed for this base
/// case, since the client initiates), and DRAINS to the survivors when a
/// connection degrades.
///
/// This is the client half of the corrected posture: the client never depends
/// on a single connection; it keeps `redundancy` connections live and, on
/// degradation, sheds the failed ones and re-fills from the remaining reachable
/// nodes, preferring better reply tiers first.
#[derive(Clone, Debug)]
pub struct ClientConnectionSet {
    nodes: Vec<IngestNode>,
    redundancy: usize,
}

impl ClientConnectionSet {
    /// Build a client connection set from the cell's node list, targeting
    /// `redundancy` simultaneous healthy connections. Nodes are ordered
    /// best-reply-tier-first so the initial fill prefers the preferred tiers.
    #[must_use]
    pub fn from_node_list(mut nodes: Vec<IngestNode>, redundancy: usize) -> Self {
        // Best tier first (Ipv6Gua < Ipv4Dcutr < Ipv4NoDcutr in Ord order).
        nodes.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.addr.cmp(&b.addr)));
        Self {
            nodes,
            redundancy: redundancy.max(1),
        }
    }

    /// The set of ingest nodes the client currently connects to: the first
    /// `redundancy` HEALTHY nodes in best-tier order. This is the OUTBOUND dial
    /// set (the client's own return path — the base case needs no hole punch,
    /// because the client, not the node, initiates the connection).
    #[must_use]
    pub fn active_connections(&self) -> Vec<IngestNode> {
        self.nodes
            .iter()
            .filter(|n| n.healthy)
            .take(self.redundancy)
            .copied()
            .collect()
    }

    /// The client's redundancy target.
    #[must_use]
    pub fn redundancy(&self) -> usize {
        self.redundancy
    }

    /// Whether the client currently has its full redundancy of healthy
    /// connections.
    #[must_use]
    pub fn is_fully_redundant(&self) -> bool {
        self.nodes.iter().filter(|n| n.healthy).count() >= self.redundancy
    }

    /// React to degradation: mark the connection to `addr` unhealthy. On the
    /// next [`active_connections`] the client DRAINS off the failed node and
    /// automatically re-fills from the surviving reachable nodes (best tier
    /// first), so the redundant connection set self-heals as long as enough
    /// reachable nodes remain.
    ///
    /// Returns `true` if a node with that address was found and marked down.
    ///
    /// [`active_connections`]: ClientConnectionSet::active_connections
    pub fn mark_degraded(&mut self, addr: SocketAddr) -> bool {
        let mut found = false;
        for n in &mut self.nodes {
            if n.addr == addr {
                n.healthy = false;
                found = true;
            }
        }
        found
    }

    /// The survivor set after degradation: the healthy nodes the client can
    /// still drain to. Equivalent to the pool [`active_connections`] refills
    /// from.
    ///
    /// [`active_connections`]: ClientConnectionSet::active_connections
    #[must_use]
    pub fn survivors(&self) -> Vec<IngestNode> {
        self.nodes.iter().filter(|n| n.healthy).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn preferred_posture_inverts_old_selection() {
        // pillar-UDP peer present => pillar-UDP is PREFERRED (old posture would
        // have used QUIC on a "healthy" link).
        let s = select_preferred_transport(PeerAvailability::PillarUdpCapablePeer);
        assert_eq!(s.kind, TransportKind::PillarUdp);
        assert!(s.is_preferred());

        // Non-pillar ingress => QUIC legacy interop.
        let s = select_preferred_transport(PeerAvailability::NonPillarIngressClient);
        assert_eq!(s.kind, TransportKind::Quic);
        assert_eq!(s.reason, TransportChoiceReason::LegacyInteropIngress);

        // No pillar-UDP peer => QUIC fallback.
        let s = select_preferred_transport(PeerAvailability::NoPillarUdpPeer);
        assert_eq!(s.kind, TransportKind::Quic);
        assert_eq!(s.reason, TransportChoiceReason::NoPillarUdpPeerAvailable);
    }

    #[test]
    fn ipv6_gua_tier_needs_no_nat_state_and_scales() {
        let gua = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap();
        let t = classify_reply_tier(IpAddr::V6(gua), false);
        assert_eq!(t, ReplyPathTier::Ipv6Gua);
        assert!(!t.requires_per_peer_nat_state());
        assert!(t.provides_reply_diversity());
        assert!(!t.port_exhaustion_bounded());
        assert_eq!(t.max_reply_paths(4), usize::MAX);
    }

    #[test]
    fn ipv4_dcutr_tier_is_port_exhaustion_bounded() {
        let t = classify_reply_tier("203.0.113.7".parse().unwrap(), true);
        assert_eq!(t, ReplyPathTier::Ipv4Dcutr);
        assert!(t.requires_per_peer_nat_state());
        assert!(t.provides_reply_diversity());
        assert!(t.port_exhaustion_bounded());
        assert_eq!(t.max_reply_paths(4), 4);
    }

    #[test]
    fn ipv4_no_dcutr_tier_is_the_single_path_floor() {
        let t = classify_reply_tier("203.0.113.7".parse().unwrap(), false);
        assert_eq!(t, ReplyPathTier::Ipv4NoDcutr);
        assert!(t.requires_per_peer_nat_state());
        assert!(!t.provides_reply_diversity());
        assert_eq!(t.max_reply_paths(4), 1);
    }

    #[test]
    fn client_drains_to_survivors_on_degradation() {
        let n = |ip: &str, port: u16, tier: ReplyPathTier| IngestNode {
            addr: SocketAddr::new(ip.parse().unwrap(), port),
            tier,
            healthy: true,
        };
        let mut set = ClientConnectionSet::from_node_list(
            vec![
                n("203.0.113.1", 5001, ReplyPathTier::Ipv4NoDcutr),
                n("203.0.113.2", 5002, ReplyPathTier::Ipv4Dcutr),
                n("203.0.113.3", 5003, ReplyPathTier::Ipv6Gua),
                n("203.0.113.4", 5004, ReplyPathTier::Ipv4Dcutr),
            ],
            2,
        );
        // Best-tier-first fill: Ipv6Gua then an Ipv4Dcutr.
        let active = set.active_connections();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].tier, ReplyPathTier::Ipv6Gua);

        let degraded = active[0].addr;
        assert!(set.mark_degraded(degraded));
        // Drains off the failed node, refills from survivors, keeps redundancy.
        let active2 = set.active_connections();
        assert_eq!(active2.len(), 2);
        assert!(active2.iter().all(|c| c.addr != degraded));
        assert!(set.is_fully_redundant());
    }
}
