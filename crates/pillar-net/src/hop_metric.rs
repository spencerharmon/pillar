//! Terminal-delivery hop-cost observability (`pillar-message-hop-metric`,
//! ROI HEAD 2026-09-09): at terminal `PillarMessage` processing — this node
//! IS the addressed destination, decided via
//! [`crate::pillar_udp::ForwardGate::arrive`] returning
//! [`crate::pillar_udp::Delivery::Terminal`] — emit the `pillar_message_hops`
//! metric equal to the REAL ingest->destination hop count the envelope
//! carried ([`pillar_wire::PillarMessage::hops`], incremented by exactly one
//! per real forward via [`pillar_wire::PillarMessage::incremented_hop`]),
//! labeled with the ingest and destination topology tiers plus
//! `cell`/`route`/`route_kind` — over the SAME shared correlation spine
//! (`pillar_observability`'s [`pillar_observability::block::TimeseriesStore`],
//! itself riding the same IPFS-segments+tip `pillar_wire::ContentStore`
//! substrate every other signal uses; no parallel store).
//!
//! Placement-facing rollups over this metric must read ATTESTED topology
//! labels only (a self-declaring node could otherwise lie its way to a
//! better-looking placement score) — [`terminal_labels`] therefore reads
//! [`pillar_topology::Topology::attested_placement`] exclusively, never
//! `::placement` (which falls back to self-declared labels).

use pillar_core::NodeId;
use pillar_manifest::ingress::{Route, RouteKind};
use pillar_observability::block::{SignalId, TimeseriesStore};
use pillar_observability::hop_metric::record_message_hops;
use pillar_observability::metadata::LabelSet;
use pillar_topology::Topology;
use pillar_wire::PillarMessage;

/// The stable string a [`RouteKind`] contributes to the `route_kind` label.
#[must_use]
pub fn route_kind_label(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::Http => "http",
        RouteKind::Http3 => "http3",
        RouteKind::Tcp => "tcp",
        RouteKind::Udp => "udp",
        RouteKind::Quic => "quic",
        RouteKind::PillarNative => "pillar_native",
    }
}

/// Build the exact label set the `pillar_message_hops` metric carries:
/// `ingest_<tier>` / `destination_<tier>` for every tier hierarchy entry
/// EITHER node has an ATTESTED value at, plus `cell`, `route`, `route_kind`.
///
/// Reads [`Topology::attested_placement`] for both nodes — never
/// [`Topology::placement`] — so a node's self-declared tier can never leak
/// into a placement-facing rollup label.
#[must_use]
pub fn terminal_labels(
    topology: &Topology,
    ingest_node: &NodeId,
    destination_node: &NodeId,
    cell: &str,
    route: &Route,
) -> LabelSet {
    let mut labels = LabelSet::new();
    let ingest_placement = topology.attested_placement(ingest_node);
    let destination_placement = topology.attested_placement(destination_node);
    for tier in topology.hierarchy().tiers() {
        if let Some(v) = ingest_placement.at(tier) {
            labels.insert(format!("ingest_{tier}"), v.to_string());
        }
        if let Some(v) = destination_placement.at(tier) {
            labels.insert(format!("destination_{tier}"), v.to_string());
        }
    }
    labels.insert("cell".to_string(), cell.to_string());
    labels.insert("route".to_string(), route.name.clone());
    labels.insert(
        "route_kind".to_string(),
        route_kind_label(route.kind).to_string(),
    );
    labels
}

/// Emit the `pillar_message_hops` metric for `msg` at terminal processing.
///
/// `value = msg.hops` — the REAL wire-carried hop count (never re-derived,
/// guessed, or defaulted), the exact counter a relay advances by one via
/// [`pillar_wire::PillarMessage::incremented_hop`] on every real forward and
/// [`crate::pillar_udp::ForwardGate::arrive`] observes exhaust to `0` exactly
/// on legitimate arrival at the addressed destination.
///
/// Returns `None` only if the write was downsampled away by a configured
/// retention policy — never a fabricated/skipped value for any other reason.
pub fn record_terminal_hops(
    store: &mut TimeseriesStore,
    msg: &PillarMessage,
    topology: &Topology,
    ingest_node: &NodeId,
    destination_node: &NodeId,
    route: &Route,
    write_tick: u64,
) -> Option<SignalId> {
    let cell = String::from_utf8_lossy(msg.cell.as_bytes()).into_owned();
    let labels = terminal_labels(topology, ingest_node, destination_node, &cell, route);
    record_message_hops(store, msg.hops, labels, write_tick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pillar_udp::{Cid, Delivery, ForwardGate};
    use pillar_crypto::{CellId, Ciphertext, Signature, SigningPublicKey};
    use pillar_manifest::ingress::Backend;
    use pillar_topology::{Assignment, Label, TierHierarchy};
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};
    use pillar_wire::Visibility;

    /// A minimal, syntactically valid `PillarMessage` for exercising the hop
    /// counter + metric plumbing. Signature is a dummy (never verified in
    /// this test — only `hops`/`cell` matter here); a real node's message
    /// would carry a genuine signature per `pillar_wire::envelope`'s own
    /// tests.
    fn test_message(hops: u32) -> PillarMessage {
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let mut msg = PillarMessage::new(
            SigningPublicKey::from_bytes(vec![0u8; 32]),
            Signature::from_bytes(vec![0u8; 64]),
            Visibility::Cell,
            cell,
            Ciphertext::from_bytes(b"sealed-body".to_vec()),
        );
        for _ in 0..hops {
            msg = msg.incremented_hop();
        }
        msg
    }

    fn attest_tier(topology: &mut Topology, store: &mut TrustStore, node: &str, tier: &str, value: &str) {
        let label = Label::new(tier, value);
        let attest = Attest {
            issuer: store.genesis().clone(),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: NodeId::from(node),
            predicate: Predicate::new(pillar_topology::ATTEST_ACTION, label.resource()),
            scope: "default".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let cid = store.issue_attest(attest.clone()).expect("genesis self-issue succeeds");
        let assignment = Assignment::Attested {
            attest: Box::new(attest),
            cid,
        };
        topology
            .attest(&assignment, store)
            .expect("attestation verifies through the store");
    }

    /// Routing a `PillarMessage` across a known 2-relay (3-hop) topology and
    /// emitting the metric at real terminal delivery yields EXACTLY the real
    /// hop count, with correct ATTESTED ingest/destination tier labels.
    #[test]
    fn terminal_metric_equals_real_hop_count_with_attested_tier_labels() {
        let hierarchy = TierHierarchy::default();
        let mut trust = TrustStore::new(NodeId::from("genesis"));
        let mut topology = Topology::new(hierarchy);
        attest_tier(&mut topology, &mut trust, "ingest-node", "region", "us-east");
        attest_tier(&mut topology, &mut trust, "ingest-node", "zone", "us-east-1a");
        attest_tier(&mut topology, &mut trust, "dest-node", "region", "us-west");
        attest_tier(&mut topology, &mut trust, "dest-node", "zone", "us-west-1b");

        // A lying self-declared label must NEVER leak into the metric.
        topology.declare(
            NodeId::from("dest-node"),
            &[Label::new("region", "definitely-not-us-west")],
        );

        let route = Route::new(
            "checkout-route",
            NodeId::from("checkout-app"),
            "checkout-frontend",
            RouteKind::PillarNative,
        )
        .with_backend(Backend::new("dest-node"));

        // Route the message across a known multi-hop topology: ingest ->
        // relay-1 -> relay-2 -> destination = 3 real forwarding hops.
        let mut msg = test_message(0);
        let mut gate = ForwardGate::new();
        let mut ttl = 3u32;
        let mut hops_travelled = 0u32;
        loop {
            // Each hop's envelope differs (the `hops` counter changed), so
            // its content address genuinely differs too — recompute per
            // iteration rather than reusing one stale `Cid`, exactly as a
            // real relay (which re-derives the Cid of the message it is
            // about to forward) would.
            let cid = Cid::of(msg.cid().expect("cid").as_bytes());
            match gate.arrive(&cid, ttl) {
                Delivery::Forward(next_ttl) => {
                    ttl = next_ttl;
                    msg = msg.incremented_hop();
                    hops_travelled += 1;
                }
                Delivery::Terminal => break,
                Delivery::Loop => panic!("must not loop for a single traversal"),
            }
        }
        assert_eq!(hops_travelled, 3, "the known topology is exactly 3 hops");
        assert_eq!(msg.hops, 3, "the envelope's own counter agrees");

        let mut store = TimeseriesStore::new(64, 1_000);
        let signal_id = record_terminal_hops(
            &mut store,
            &msg,
            &topology,
            &NodeId::from("ingest-node"),
            &NodeId::from("dest-node"),
            &route,
            42,
        )
        .expect("not downsampled away");

        let signal = store
            .held_signals()
            .find(|s| s.id() == signal_id)
            .expect("written signal retrievable");
        let payload = String::from_utf8(signal.payload().to_vec()).expect("utf8");
        assert_eq!(
            payload, "pillar_message_hops 3 @42",
            "metric equals the REAL hop count"
        );
        assert_eq!(
            signal.labels().get("ingest_region").map(String::as_str),
            Some("us-east")
        );
        assert_eq!(
            signal
                .labels()
                .get("destination_region")
                .map(String::as_str),
            Some("us-west"),
            "ATTESTED label used, never the lying self-declared one"
        );
        assert_eq!(
            signal.labels().get("route_kind").map(String::as_str),
            Some("pillar_native")
        );
        assert_eq!(
            signal.labels().get("route").map(String::as_str),
            Some("checkout-route")
        );
    }
}

