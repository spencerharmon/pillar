//! `pillar-message-hop-metric` acceptance gate (ROI HEAD 2026-09-09).
//!
//! Intent: at terminal `PillarMessage` processing, the destination emits
//! `pillar_message_hops` = ingest->destination hops (from the envelope's own
//! hop counter), labeled with ATTESTED ingest+destination topology tiers +
//! `cell`/`route`/`RouteKind`, over the shared observability correlation
//! spine (the same `TimeseriesStore` every other signal kind rides — no
//! parallel metrics store).
//!
//! This test routes a real `PillarMessage` across a KNOWN multi-hop topology
//! (ingest -> 2 relays -> destination = 3 real forwarding hops, each one a
//! genuine [`ForwardGate::arrive`] decision advancing the envelope's own
//! [`PillarMessage::incremented_hop`] counter — never a fabricated/assumed
//! hop count) and asserts the emitted metric equals the REAL hop count with
//! correct tier labels, and that a lying self-declared label never leaks in.
//!
//! Gated behind `--features acceptance` (mirrors every other acceptance test
//! in this crate) so the ordinary `cargo test` unit run does not require it.
#![cfg(feature = "acceptance")]

use pillar_core::NodeId;
use pillar_crypto::{CellId, Ciphertext, Signature, SigningPublicKey};
use pillar_manifest::ingress::{Backend, Route, RouteKind};
use pillar_net::hop_metric::record_terminal_hops;
use pillar_net::pillar_udp::{Cid, Delivery, ForwardGate};
use pillar_observability::block::TimeseriesStore;
use pillar_topology::{Assignment, Label, TierHierarchy, Topology};
use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};
use pillar_wire::{PillarMessage, Visibility};

fn n(s: &str) -> NodeId {
    NodeId::from(s)
}

/// A minimal, syntactically valid `PillarMessage` addressed to `cell`. Its
/// signature is a dummy (this test exercises the hop counter + metric
/// plumbing, not signature verification — that is `pillar-wire`'s own
/// coverage).
fn seed_message(cell: &str) -> PillarMessage {
    PillarMessage::new(
        SigningPublicKey::from_bytes(vec![0u8; 32]),
        Signature::from_bytes(vec![0u8; 64]),
        Visibility::Cell,
        CellId::from_bytes(cell.as_bytes().to_vec()),
        Ciphertext::from_bytes(b"sealed-body".to_vec()),
    )
}

/// Attest (never merely declare) that `node` sits at `tier = value`,
/// self-issued by `store`'s genesis authority — the REAL, chain-verified
/// artifact `Topology::attested_placement` requires, not a placeholder.
fn attest_tier(topology: &mut Topology, store: &mut TrustStore, node: &str, tier: &str, value: &str) {
    let label = Label::new(tier, value);
    let attest = Attest {
        issuer: store.genesis().clone(),
        capacity: Capacity::SelfCap,
        authority: None,
        subject: n(node),
        predicate: Predicate::new(pillar_topology::ATTEST_ACTION, label.resource()),
        scope: "default".to_owned(),
        epoch: store.epoch(),
        sig: Sig::sign_as(n(""), b""),
    }
    .signed_by_issuer();
    let cid = store
        .issue_attest(attest.clone())
        .expect("genesis-authored attestation issues");
    let assignment = Assignment::Attested {
        attest: Box::new(attest),
        cid,
    };
    topology
        .attest(&assignment, store)
        .expect("attestation verifies through the store");
}

#[test]
fn routing_across_a_known_multi_hop_topology_yields_the_real_hop_count_and_tier_labels() {
    // --- topology: ingest in us-east, destination in us-west, both ATTESTED ---
    let mut trust = TrustStore::new(n("genesis"));
    let mut topology = Topology::new(TierHierarchy::default());
    attest_tier(&mut topology, &mut trust, "ingest-node", "region", "us-east");
    attest_tier(&mut topology, &mut trust, "ingest-node", "zone", "us-east-1a");
    attest_tier(&mut topology, &mut trust, "dest-node", "region", "us-west");
    attest_tier(&mut topology, &mut trust, "dest-node", "zone", "us-west-1b");

    // A node that lies about its own placement must never win: self-declared
    // labels are display-only and must not leak into a placement-facing
    // rollup label.
    topology.declare(n("dest-node"), &[Label::new("region", "not-actually-us-west")]);
    topology.declare(n("ingest-node"), &[Label::new("region", "not-actually-us-east")]);

    // --- routing context (RouteKind + cell, the other required labels) ---
    let route = Route::new(
        "checkout-route",
        n("checkout-app"),
        "checkout-frontend",
        RouteKind::PillarNative,
    )
    .with_backend(Backend::new("dest-node"));

    // --- route a real PillarMessage across a KNOWN 3-hop topology ---
    // ingest-node -[hop 1]-> relay-1 -[hop 2]-> relay-2 -[hop 3]-> dest-node
    let mut msg = seed_message("cell-checkout");
    let mut gate = ForwardGate::new();
    let mut ttl = 3u32;
    let mut real_hops = 0u32;
    loop {
        // A real relay recomputes the Cid of the envelope it is about to
        // forward; since `hops` changed, the Cid genuinely differs hop to
        // hop (never reused stale).
        let cid = Cid::of(msg.cid().expect("cid encodes").as_bytes());
        match gate.arrive(&cid, ttl) {
            Delivery::Forward(next_ttl) => {
                ttl = next_ttl;
                msg = msg.incremented_hop();
                real_hops += 1;
            }
            Delivery::Terminal => break,
            Delivery::Loop => panic!("a single forward traversal must never loop"),
        }
    }
    assert_eq!(real_hops, 3, "the known fixture topology is exactly 3 hops");
    assert_eq!(
        msg.hops, 3,
        "the envelope's own wire-carried hop counter agrees with the real traversal"
    );

    // --- terminal processing: emit the metric ---
    let mut store = TimeseriesStore::new(64, 1_000);
    let signal_id = record_terminal_hops(
        &mut store,
        &msg,
        &topology,
        &n("ingest-node"),
        &n("dest-node"),
        &route,
        100,
    )
    .expect("the write is not downsampled away");

    let signal = store
        .held_signals()
        .find(|s| s.id() == signal_id)
        .expect("the written metric signal is retrievable from the shared store");

    let payload = String::from_utf8(signal.payload().to_vec()).expect("utf8 payload");
    assert_eq!(
        payload, "pillar_message_hops 3 @100",
        "the metric equals the REAL hop count the message actually travelled"
    );

    let labels = signal.labels();
    assert_eq!(labels.get("ingest_region").map(String::as_str), Some("us-east"));
    assert_eq!(labels.get("ingest_zone").map(String::as_str), Some("us-east-1a"));
    assert_eq!(
        labels.get("destination_region").map(String::as_str),
        Some("us-west"),
        "ATTESTED destination tier, never the lying self-declared one"
    );
    assert_eq!(
        labels.get("destination_zone").map(String::as_str),
        Some("us-west-1b")
    );
    assert_eq!(labels.get("cell").map(String::as_str), Some("cell-checkout"));
    assert_eq!(labels.get("route").map(String::as_str), Some("checkout-route"));
    assert_eq!(
        labels.get("route_kind").map(String::as_str),
        Some("pillar_native")
    );
}
