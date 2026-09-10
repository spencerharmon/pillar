//! Hop-cost observability: at terminal processing, the destination emits
//! `pillar_message_hops` — the real ingest->destination hop count a
//! [`PillarMessage`](pillar_wire::PillarMessage) traveled, taken from its
//! carried hop/TTL counter (the same [`crate::pillar_udp::ForwardGate`] TTL
//! every forwarding node decrements) — labeled with the ingest + destination
//! topology tiers plus `cell`/`route`/`route_kind`, written onto the SAME
//! shared observability substrate ([`TimeseriesStore`]) every other signal
//! rides (no parallel store).
//!
//! Placement-facing rollups must trust only ATTESTED topology labels
//! (`Topology::attested_placement`) — a node's self-declared placement is
//! display-only and is never used to label this metric.

use std::collections::BTreeMap;

use pillar_manifest::ingress::RouteKind;
use pillar_observability::{SignalId, SignalKind, TimeseriesStore};
use pillar_topology::Topology;

use pillar_core::NodeId;

/// The stable series name this metric is written under (also carried as its
/// `metric` label, matching the convention every other named metric in
/// `pillar-observability::ingest::MetricKind` uses).
pub const METRIC_NAME: &str = "pillar_message_hops";

/// A stable, lower-kebab label value for a [`RouteKind`].
#[must_use]
pub fn route_kind_label(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::Http => "http",
        RouteKind::Http3 => "http3",
        RouteKind::Tcp => "tcp",
        RouteKind::Udp => "udp",
        RouteKind::Quic => "quic",
        RouteKind::PillarNative => "pillar-native",
    }
}

/// The REAL hop count a message traveled, derived purely from its carried
/// hop/TTL counter: the TTL it was ingested with minus the TTL it still
/// carried on arrival at the terminal destination. Each forwarding hop
/// decrements the TTL by exactly one (`ForwardGate::forward`), so this
/// difference is exactly the number of hops taken — never a fabricated or
/// estimated value.
#[must_use]
pub fn hops_from_ttl(ingest_ttl: u32, destination_ttl: u32) -> u32 {
    ingest_ttl.saturating_sub(destination_ttl)
}

/// Build the label set for one `pillar_message_hops` sample: the metric name,
/// `cell`, `route`, `route_kind`, plus every ATTESTED topology tier for the
/// ingest node (prefixed `ingest_<tier>`) and the destination node (prefixed
/// `destination_<tier>`). Self-declared topology labels are NEVER read here —
/// only [`Topology::attested_placement`] — per the placement-facing-rollups
/// ATTESTED-only requirement.
#[must_use]
pub fn hop_metric_labels(
    topology: &Topology,
    ingest: &NodeId,
    destination: &NodeId,
    cell: &str,
    route: &str,
    route_kind: RouteKind,
) -> BTreeMap<String, String> {
    let hierarchy = topology.hierarchy();
    let mut labels = BTreeMap::new();
    labels.insert("metric".to_string(), METRIC_NAME.to_string());
    labels.insert("cell".to_string(), cell.to_string());
    labels.insert("route".to_string(), route.to_string());
    labels.insert(
        "route_kind".to_string(),
        route_kind_label(route_kind).to_string(),
    );
    for label in topology.attested_placement(ingest).path(hierarchy) {
        labels.insert(format!("ingest_{}", label.tier), label.value);
    }
    for label in topology.attested_placement(destination).path(hierarchy) {
        labels.insert(format!("destination_{}", label.tier), label.value);
    }
    labels
}

/// Write one real `pillar_message_hops` sample for a message that just
/// finished terminal processing at `destination`, having entered the mesh at
/// `ingest` with `ingest_ttl` hops of budget and arrived carrying
/// `destination_ttl` remaining. The written value is [`hops_from_ttl`] — the
/// genuine hop count, never fabricated — and the sample's labels are built by
/// [`hop_metric_labels`] (ATTESTED topology tiers only). Writes onto `store`
/// through the SAME single producer path (`TimeseriesStore::write_labeled`)
/// every other signal kind uses — no parallel metrics store.
pub fn record_message_hop_metric(
    store: &mut TimeseriesStore,
    topology: &Topology,
    ingest: &NodeId,
    destination: &NodeId,
    cell: &str,
    route: &str,
    route_kind: RouteKind,
    ingest_ttl: u32,
    destination_ttl: u32,
    tick: u64,
) -> Option<SignalId> {
    let hops = hops_from_ttl(ingest_ttl, destination_ttl);
    let labels = hop_metric_labels(topology, ingest, destination, cell, route, route_kind);
    let payload = format!("{METRIC_NAME} {hops} @{tick}");
    store.write_labeled(SignalKind::Metric, payload.into_bytes(), labels, tick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::NodeId;
    use pillar_topology::TierHierarchy;

    #[test]
    fn hops_from_ttl_is_the_real_difference() {
        assert_eq!(hops_from_ttl(5, 2), 3);
        assert_eq!(hops_from_ttl(3, 3), 0);
        // Never underflows/panics on an inconsistent reading.
        assert_eq!(hops_from_ttl(1, 5), 0);
    }

    #[test]
    fn labels_carry_ingest_and_destination_attested_tiers_only() {
        let topology = Topology::new(TierHierarchy::default());
        let ingest = NodeId::from("node-ingest");
        let destination = NodeId::from("node-dest");
        let labels = hop_metric_labels(
            &topology,
            &ingest,
            &destination,
            "cell-a",
            "route-1",
            RouteKind::PillarNative,
        );
        assert_eq!(labels.get("metric").map(String::as_str), Some(METRIC_NAME));
        assert_eq!(labels.get("cell").map(String::as_str), Some("cell-a"));
        assert_eq!(labels.get("route").map(String::as_str), Some("route-1"));
        assert_eq!(
            labels.get("route_kind").map(String::as_str),
            Some("pillar-native")
        );
        // No topology assignments yet: no ingest_/destination_ tier labels.
        assert!(!labels.keys().any(|k| k.starts_with("ingest_")));
        assert!(!labels.keys().any(|k| k.starts_with("destination_")));
    }
}
