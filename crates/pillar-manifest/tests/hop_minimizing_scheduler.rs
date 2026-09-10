//! Acceptance suite for the hop-minimizing placement optimizer
//! (`hop-minimizing-scheduler`).
//!
//! Off-by-default: gated on the `acceptance` feature so a plain `cargo test`
//! never runs it. The CHECKS.md `acceptance-e2e` stub invokes it explicitly:
//!
//! ```text
//! cargo test -p pillar-manifest --test hop_minimizing_scheduler --features acceptance
//! ```
//!
//! These tests assert the task's acceptance contract end-to-end over the real
//! optimizer value type (`pillar_manifest::hop_min`): with traffic concentrated
//! on one rack, placement REDUCES aggregate traffic-weighted hops WITHOUT
//! violating declared spread / anti-affinity / capacity, and does so throttled
//! and reversibly so oscillating traffic cannot thrash.

#![cfg(feature = "acceptance")]

use std::collections::{BTreeMap, BTreeSet};

use pillar_manifest::hop_min::{
    aggregate_placement_hops, Optimizer, Placement, Plan, TrafficView,
};
use pillar_topology::TierHierarchy;

fn assignment(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(b, d)| ((*b).to_owned(), (*d).to_owned()))
        .collect()
}

fn distinct_domains(placement: &Placement, backends: &[&str]) -> BTreeSet<String> {
    backends
        .iter()
        .filter_map(|b| placement.domain_of(b).map(str::to_owned))
        .collect()
}

/// THE acceptance property: traffic concentrated on one rack pulls backends
/// toward that rack, reducing aggregate traffic-weighted hops, while the
/// declared spread floor is never breached.
#[test]
fn concentrated_traffic_reduces_aggregate_hops_within_spread_bound() {
    let hierarchy = TierHierarchy::default();

    // Three backends spread across three distinct racks; the application must
    // stay spread across at least 2 distinct racks (anti-affinity floor).
    let min_spread = 2;
    let mut placement = Placement::new(
        "rack",
        assignment(&[("b1", "r1"), ("b2", "r2"), ("b3", "r3")]),
        min_spread,
        BTreeMap::new(),
    );

    // Traffic is CONCENTRATED on ingest rack r1: every backend exchanges the
    // bulk of its traffic with r1.
    let mut traffic = TrafficView::new();
    traffic.observe("b1", "r1", 500);
    traffic.observe("b2", "r1", 500);
    traffic.observe("b3", "r1", 500);
    // A little cross-traffic so hops are non-degenerate.
    traffic.observe("b2", "r2", 10);
    traffic.observe("b3", "r3", 10);

    let before = aggregate_placement_hops(&hierarchy, &placement, &traffic);

    // Generous throttle so the optimizer can make every bounded move it wants.
    let opt = Optimizer::new(hierarchy.clone(), Plan::new(8, 0));
    let moves = opt.optimize(&mut placement, &traffic);

    let after = aggregate_placement_hops(&hierarchy, &placement, &traffic);

    // 1. Aggregate traffic-weighted hops strictly fell.
    assert!(
        after < before,
        "optimizer must reduce aggregate hops: {before} -> {after}"
    );
    assert!(!moves.is_empty(), "at least one backend should be pulled toward r1");

    // 2. Every move actually moved a backend toward the concentrated ingest r1.
    for m in &moves {
        assert_eq!(m.to, "r1", "backends should be pulled toward ingest locality r1");
        assert!(m.improvement > 0, "every applied move improves aggregate hops");
    }

    // 3. The declared spread / anti-affinity floor is NEVER violated: the app
    //    remains across >= min_spread distinct racks (the quorum is not
    //    collapsed into one rack).
    let occupied = distinct_domains(&placement, &["b1", "b2", "b3"]);
    assert!(
        occupied.len() >= min_spread,
        "spread floor breached: only {:?} distinct racks remain (min {min_spread})",
        occupied
    );
    // At least one backend stays OFF r1 precisely because the spread floor
    // forbids collapsing all three onto it.
    assert!(
        occupied.contains("r1"),
        "the concentrated rack must be occupied"
    );
    assert!(
        occupied.len() == min_spread || occupied.len() == 3,
        "spread stays at or above the floor"
    );
}

/// The capacity bound is respected: a target rack at capacity cannot absorb
/// another backend even when doing so would minimize hops.
#[test]
fn capacity_bound_is_never_exceeded() {
    let hierarchy = TierHierarchy::default();

    let mut capacity = BTreeMap::new();
    capacity.insert("r1".to_owned(), 1usize); // r1 already full with b_anchor

    let mut placement = Placement::new(
        "rack",
        assignment(&[("anchor", "r1"), ("b1", "r2")]),
        1,
        capacity,
    );

    // b1's traffic concentrates on r1, so hop-minimization WANTS to move it to
    // r1 — but r1 is at capacity.
    let mut traffic = TrafficView::new();
    traffic.observe("b1", "r1", 1000);

    let opt = Optimizer::new(hierarchy.clone(), Plan::new(8, 0));
    let moves = opt.optimize(&mut placement, &traffic);

    assert!(
        moves.is_empty(),
        "no move is possible without exceeding r1 capacity, so none is made"
    );
    assert_eq!(
        placement.domain_of("b1"),
        Some("r2"),
        "b1 stays put because r1 is full"
    );
}

/// Throttle + hysteresis make the optimizer reversible against oscillating
/// traffic: a below-threshold gain is ignored so equal-and-opposite swings do
/// not ping-pong a backend, and at most `max_moves` relocations happen per round.
#[test]
fn throttle_and_hysteresis_prevent_thrashing() {
    let hierarchy = TierHierarchy::default();

    // A backend whose current placement is already near-optimal: moving it
    // yields only a tiny gain, below the hysteresis threshold.
    let mut placement = Placement::new(
        "rack",
        assignment(&[("b1", "r1"), ("b2", "r2")]),
        1,
        BTreeMap::new(),
    );
    let mut traffic = TrafficView::new();
    // b1 talks a LITTLE more to r2 than r1 — a hop gain exists, but it is small.
    traffic.observe("b1", "r1", 100);
    traffic.observe("b1", "r2", 101);

    // Hysteresis threshold set ABOVE the achievable gain: no move should fire.
    let gain = {
        // The gain of moving b1 r1->r2: weight_r1*hops - 0 minus symmetric.
        let hops = pillar_manifest::hop_min::hierarchy_hops(&hierarchy, "rack", "r1", "r2");
        // moving b1 to r2: r2 traffic becomes 0-hop, r1 traffic becomes `hops`.
        // before: 101*hops (r2 side) ; after: 100*hops (r1 side) => gain hops.
        hops
    };
    let opt_high = Optimizer::new(hierarchy.clone(), Plan::new(8, gain));
    let before = aggregate_placement_hops(&hierarchy, &placement, &traffic);
    let moves = opt_high.optimize(&mut placement, &traffic);
    let after = aggregate_placement_hops(&hierarchy, &placement, &traffic);
    assert!(
        moves.is_empty(),
        "a gain that does not exceed the hysteresis threshold is ignored"
    );
    assert_eq!(before, after, "placement is left untouched below threshold");

    // Throttle: many improving backends, but max_moves=1 caps the round to one.
    let mut heavy = TrafficView::new();
    heavy.observe("x1", "r1", 1000);
    heavy.observe("x2", "r1", 1000);
    heavy.observe("x3", "r1", 1000);
    // `seed` occupies r1 so it is a candidate target domain.
    let mut many = Placement::new(
        "rack",
        assignment(&[("seed", "r1"), ("x1", "r2"), ("x2", "r3"), ("x3", "r4")]),
        1,
        BTreeMap::new(),
    );
    let opt_throttled = Optimizer::new(hierarchy, Plan::new(1, 0));
    let throttled_moves = opt_throttled.optimize(&mut many, &heavy);
    assert_eq!(
        throttled_moves.len(),
        1,
        "throttle caps relocations to max_moves per round"
    );
}
