//! Acceptance test — `ipam-operator-surface`.
//!
//! Acceptance-narrative step 4: *the operator allocates a VIP from an IPAM pool
//! with a REAL command and it is recorded.* Before this surface,
//! [`pillar_ipam::TopologyScopedIpam::allocate_for`] was a quorum-fenced LIBRARY
//! call with NO operator surface — a VIP could not be allocated or recorded by
//! an operator. This test drives the real `pillar ipam` operator surface
//! ([`pillar_ipam::operator::IpamOperator`]) end to end over the proven
//! `allocate_for` invariants:
//!
//! 1. an operator allocates a VIP out of a delegated IPAM pool through the
//!    quorum fence and the binding is RECORDED and readable back (the durable
//!    state the load balancer's VIP wiring consumes);
//! 2. a double-allocation of the SAME address (to a different purpose) is
//!    REJECTED — the operator can never hand one VIP address to two purposes;
//! 3. `release` returns the address to the pool and clears the record, so the
//!    address can be re-allocated afterwards.
//!
//! This exercises the real operator surface, not a bare library call: the verbs
//! `allocate` / `get` / `release` are exactly what a `pillar ipam` CLI verb (or
//! a manifest apply) drives. Every allocation still flows through the
//! quorum-intersection fence proven in `specs/IPAM.tla`.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md stub);
//! run via
//! `cargo test -p pillar-e2e --test ipam_operator_surface --features acceptance`.

#![cfg(feature = "acceptance")]

use std::net::IpAddr;

use pillar_core::NodeId;
use pillar_ipam::operator::{Binding, IpamOperator, OperatorError};
use pillar_ipam::{Pool, TopologyScopedIpam};
use pillar_topology::{Label, TierHierarchy, Topology};

fn n(s: &str) -> NodeId {
    NodeId::from(s)
}

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse().unwrap())
}

/// Build the operator surface a real deployment presents: a topology-scoped
/// IPAM with a delegated VIP pool bound to the `west` region, fenced by a
/// 3-voter cluster, and a load-balancer node `lb-west` placed in that region.
fn operator_surface() -> IpamOperator {
    let mut topo = Topology::new(TierHierarchy::default());
    topo.declare(n("lb-west"), &[Label::new("region", "west")]);
    let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
    // A delegated VIP prefix for the west region.
    ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
    IpamOperator::new(ipam)
}

/// Record a majority of voter grants for `addr` to `node`, the real
/// quorum-fence precondition every live allocation requires.
fn back_with_quorum(op: &mut IpamOperator, node: &NodeId, addr: IpAddr) {
    op.ipam_mut().grant_for(n("voter-1"), node, addr).unwrap();
    op.ipam_mut().grant_for(n("voter-2"), node, addr).unwrap();
}

/// The operator allocates a VIP from the IPAM pool with the real `allocate`
/// verb and it is RECORDED and readable back — the acceptance narrative's
/// step 4.
#[test]
fn operator_allocates_a_vip_and_it_is_recorded_and_read_back() {
    let mut op = operator_surface();
    let vip = v4("10.1.0.9");

    // The quorum backs the allocation (the real fence), then the operator
    // allocates the VIP out of the pool and records it under a name.
    back_with_quorum(&mut op, &n("lb-west"), vip);
    let binding: Binding = op
        .allocate("frontend-lb-vip", &n("lb-west"), vip)
        .expect("a quorum-backed VIP allocates and records");
    assert!(binding.allocated, "the binding is a live quorum allocation");
    assert_eq!(binding.addr, vip);
    assert_eq!(binding.node, n("lb-west"));

    // It is RECORDED: reading it back yields the same VIP — this is the durable
    // operator-visible state the load balancer's VIP wiring consumes.
    assert_eq!(op.recorded_addr("frontend-lb-vip"), Some(vip));
    let read_back = op.get("frontend-lb-vip").expect("recorded binding");
    assert_eq!(read_back.addr, vip);
    assert_eq!(read_back.node, n("lb-west"));
    assert_eq!(op.len(), 1);
}

/// A double-allocation of the SAME address to a DIFFERENT purpose is REJECTED —
/// an operator can never hand one VIP address to two purposes.
#[test]
fn double_allocation_of_the_same_vip_is_rejected() {
    let mut op = operator_surface();
    let vip = v4("10.1.0.20");
    back_with_quorum(&mut op, &n("lb-west"), vip);

    op.allocate("service-a-vip", &n("lb-west"), vip)
        .expect("first allocation succeeds");

    // A second allocation of the SAME address under a different name is refused,
    // and nothing new is recorded.
    let err = op
        .allocate("service-b-vip", &n("lb-west"), vip)
        .expect_err("the same VIP cannot be handed to a second purpose");
    assert_eq!(
        err,
        OperatorError::AddressAlreadyRecorded {
            addr: vip,
            existing_name: "service-a-vip".to_owned(),
        }
    );
    assert_eq!(op.len(), 1, "only the first binding is recorded");
    assert_eq!(op.recorded_addr("service-a-vip"), Some(vip));
    assert!(op.get("service-b-vip").is_none());
}

/// A live allocation with no quorum backing is refused — the operator surface
/// never fabricates an allocation the fence did not grant.
#[test]
fn allocating_a_vip_without_a_quorum_is_refused() {
    let mut op = operator_surface();
    let vip = v4("10.1.0.30");
    // Only ONE grant: no majority of the 3-voter cluster.
    op.ipam_mut()
        .grant_for(n("voter-1"), &n("lb-west"), vip)
        .unwrap();

    let err = op
        .allocate("lonely-vip", &n("lb-west"), vip)
        .expect_err("no quorum, no allocation");
    assert_eq!(err, OperatorError::NotAllocated { addr: vip });
    assert!(op.get("lonely-vip").is_none());
}

/// Release returns the VIP to the pool and clears the record, so the address is
/// free to allocate again afterwards.
#[test]
fn releasing_a_vip_returns_it_to_the_pool_and_clears_the_record() {
    let mut op = operator_surface();
    let vip = v4("10.1.0.40");
    back_with_quorum(&mut op, &n("lb-west"), vip);
    op.allocate("ephemeral-vip", &n("lb-west"), vip)
        .expect("allocated");
    assert_eq!(op.recorded_addr("ephemeral-vip"), Some(vip));

    // Release it: the record is cleared and the address returns to the pool.
    let released = op.release("ephemeral-vip").expect("released");
    assert_eq!(released.addr, vip);
    assert!(op.get("ephemeral-vip").is_none());
    assert!(op.is_empty());

    // Releasing an unrecorded name is refused.
    assert_eq!(
        op.release("ephemeral-vip")
            .expect_err("already released / unrecorded"),
        OperatorError::NotRecorded {
            name: "ephemeral-vip".to_owned()
        }
    );

    // The address is now free to record under a new purpose.
    let b = op
        .allocate("reused-vip", &n("lb-west"), vip)
        .expect("the freed VIP allocates again");
    assert_eq!(b.addr, vip);
    assert_eq!(op.recorded_addr("reused-vip"), Some(vip));
}
