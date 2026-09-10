//! `pillar-message-hop-metric` acceptance — routes a message across a KNOWN
//! multi-hop topology and asserts the `pillar_message_hops` metric equals the
//! REAL hop count, labeled with the correct ATTESTED ingest/destination
//! topology tiers.

use pillar_core::NodeId;
use pillar_manifest::ingress::RouteKind;
use pillar_net::hop_metric::{hops_from_ttl, record_message_hop_metric};
use pillar_net::pillar_udp::{Cid as UdpCid, ForwardGate};
use pillar_observability::{Query, SignalKind, TimeseriesStore, ViewCache};
use pillar_topology::{Assignment, Label, TierHierarchy, Topology};
use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};

fn n(s: &str) -> NodeId {
    NodeId::from(s)
}

/// Attest `node` at `<tier>=<value>` (a fresh cell-authority grant per call),
/// returning the recorded [`Assignment`] — mirroring
/// `pillar-topology`'s own `attest_label` test helper.
fn attest(
    trust: &mut TrustStore,
    topology: &mut Topology,
    authority: &NodeId,
    node: &NodeId,
    tier: &str,
    value: &str,
) {
    let cap = Capacity::Role {
        role: "cell-authority".to_string(),
        scope: "cell-hop".to_string(),
    };
    let grant = Attest {
        issuer: n("owner"),
        capacity: cap.clone(),
        authority: None,
        subject: authority.clone(),
        predicate: Predicate::new("topology:sign", "cell-hop/*"),
        scope: "cell-hop".to_string(),
        epoch: trust.epoch(),
        sig: Sig::sign_as(NodeId::from(""), b""),
    }
    .signed_by_issuer();
    let grant_cid = trust.issue_attest(grant).unwrap();
    let label = Label::new(tier, value);
    let assignment = Assignment::attested(
        authority.clone(),
        node.clone(),
        &label,
        cap,
        Some(grant_cid),
        "cell-hop",
        trust.epoch(),
    );
    if let Assignment::Attested { attest, .. } = &assignment {
        trust.issue_attest((**attest).clone()).unwrap();
    }
    assert!(topology.verify_attested(&assignment, trust));
    topology
        .attest(&assignment, trust)
        .expect("attestation verifies + is recorded");
}

/// Routing across a KNOWN 4-hop chain: ingest -> mid1 -> mid2 -> mid3 ->
/// destination is 4 real forwarding hops (each `ForwardGate::forward` call
/// decrements the carried TTL by exactly one). The emitted
/// `pillar_message_hops` metric must equal that real count, labeled with the
/// ATTESTED ingest/destination topology tiers.
#[test]
fn hop_metric_equals_real_hop_count_with_correct_tier_labels() {
    let hierarchy = TierHierarchy::from_order(["zone", "rack", "node"]).unwrap();
    let mut topology = Topology::new(hierarchy);
    let mut trust = TrustStore::new(n("owner"));
    let authority = n("cell-hop-authority");

    let ingest = n("node-ingest");
    let destination = n("node-destination");

    attest(&mut trust, &mut topology, &authority, &ingest, "zone", "z1");
    attest(&mut trust, &mut topology, &authority, &ingest, "rack", "r1");
    attest(
        &mut trust,
        &mut topology,
        &authority,
        &destination,
        "zone",
        "z9",
    );
    attest(
        &mut trust,
        &mut topology,
        &authority,
        &destination,
        "rack",
        "r9",
    );

    // Simulate the message's real journey: it enters the mesh with a TTL
    // budget of 4 and is forwarded exactly 4 times (mid1, mid2, mid3, then
    // finally delivered/processed at the destination) before terminal
    // processing — a KNOWN, deterministic multi-hop path.
    let ingest_ttl: u32 = 4;
    let mut gate = ForwardGate::new();

    let mut ttl = ingest_ttl;
    let mut real_hops = 0u32;
    for hop in 0..4 {
        // Each real forwarded copy of the message carries a DISTINCT CID
        // (content-addressed re-wrap per hop), exactly as
        // `ForwardGate`'s own doc/tests model — only the TTL bounds a chain
        // of otherwise-distinct CIDs.
        let cid = UdpCid::of(format!("hop-metric-acceptance-message-hop-{hop}").as_bytes());
        let next = gate
            .forward(&cid, ttl)
            .expect("each of the 4 known hops is forwardable");
        ttl = next;
        real_hops += 1;
    }
    // After 4 real forwards the message has arrived at the terminal
    // destination carrying `ingest_ttl - 4` TTL remaining.
    let destination_ttl = ttl;
    assert_eq!(real_hops, 4, "the known topology is exactly 4 hops");
    assert_eq!(hops_from_ttl(ingest_ttl, destination_ttl), real_hops);

    let mut store = TimeseriesStore::new(64, 10_000);
    let written = record_message_hop_metric(
        &mut store,
        &topology,
        &ingest,
        &destination,
        "cell-hop",
        "route-hop-acceptance",
        RouteKind::PillarNative,
        ingest_ttl,
        destination_ttl,
        0,
    );
    assert!(written.is_some(), "the hop metric sample was written");

    let mut cache = ViewCache::new();
    let ids = cache.materialize(&store, Query::of_kind(SignalKind::Metric));
    assert!(!ids.is_empty(), "metric kind ingested onto the substrate");

    let found: Vec<_> = store
        .held_signals()
        .filter(|s| s.kind() == SignalKind::Metric)
        .filter(|s| s.labels().get("metric").map(String::as_str) == Some("pillar_message_hops"))
        .collect();
    assert_eq!(found.len(), 1, "exactly one hop-metric sample was written");
    let signal = found[0];

    // The metric's numeric value equals the REAL hop count (4), never a
    // fabricated/estimated one.
    let text = String::from_utf8(signal.payload().to_vec()).unwrap();
    let value: u32 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("payload carries the numeric hop count");
    assert_eq!(value, 4, "pillar_message_hops equals the real hop count");
    assert_eq!(value, real_hops);

    // Correct ATTESTED tier labels for both ingest and destination.
    let labels = signal.labels();
    assert_eq!(labels.get("ingest_zone").map(String::as_str), Some("z1"));
    assert_eq!(labels.get("ingest_rack").map(String::as_str), Some("r1"));
    assert_eq!(
        labels.get("destination_zone").map(String::as_str),
        Some("z9")
    );
    assert_eq!(
        labels.get("destination_rack").map(String::as_str),
        Some("r9")
    );
    assert_eq!(labels.get("cell").map(String::as_str), Some("cell-hop"));
    assert_eq!(
        labels.get("route").map(String::as_str),
        Some("route-hop-acceptance")
    );
    assert_eq!(
        labels.get("route_kind").map(String::as_str),
        Some("pillar-native")
    );
}

/// A DIFFERENT known multi-hop path (2 hops via a shorter TTL budget) proves
/// the metric tracks the REAL per-message hop count, not a constant.
#[test]
fn hop_metric_reflects_a_shorter_known_path_distinctly() {
    let hierarchy = TierHierarchy::from_order(["zone", "rack", "node"]).unwrap();
    let mut topology = Topology::new(hierarchy);
    let mut trust = TrustStore::new(n("owner"));
    let authority = n("cell-hop-authority-2");

    let ingest = n("node-ingest-2");
    let destination = n("node-destination-2");
    attest(&mut trust, &mut topology, &authority, &ingest, "zone", "za");
    attest(
        &mut trust,
        &mut topology,
        &authority,
        &destination,
        "zone",
        "zb",
    );

    let ingest_ttl: u32 = 2;
    let mut gate = ForwardGate::new();
    let mut ttl = ingest_ttl;
    for hop in 0..2 {
        let cid = UdpCid::of(format!("hop-metric-acceptance-message-short-{hop}").as_bytes());
        ttl = gate.forward(&cid, ttl).expect("2 known hops forwardable");
    }
    let destination_ttl = ttl;
    assert_eq!(hops_from_ttl(ingest_ttl, destination_ttl), 2);

    let mut store = TimeseriesStore::new(64, 10_000);
    record_message_hop_metric(
        &mut store,
        &topology,
        &ingest,
        &destination,
        "cell-hop-2",
        "route-hop-short",
        RouteKind::Http,
        ingest_ttl,
        destination_ttl,
        1,
    );

    let found: Vec<_> = store
        .held_signals()
        .filter(|s| s.kind() == SignalKind::Metric)
        .filter(|s| s.labels().get("metric").map(String::as_str) == Some("pillar_message_hops"))
        .collect();
    assert_eq!(found.len(), 1);
    let text = String::from_utf8(found[0].payload().to_vec()).unwrap();
    let value: u32 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert_eq!(value, 2, "the shorter known path yields exactly 2 hops");
}
