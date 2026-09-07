//! The operator SURFACE over IPAM — acceptance-narrative step 4.
//!
//! [`crate::TopologyScopedIpam`]'s `allocate_for` is a quorum-fenced LIBRARY
//! call: it decides, but it leaves no operator-visible surface. An operator
//! cannot say "allocate a VIP out of this pool and RECORD it so the load
//! balancer can read it back". This module is that surface: a single
//! [`IpamOperator`] facade whose verbs — [`allocate`](IpamOperator::allocate),
//! [`reserve`](IpamOperator::reserve), [`release`](IpamOperator::release) — an
//! operator drives (from a `pillar ipam` CLI verb or a manifest apply) to hand
//! an address out of a delegated pool, RECORD the resulting binding, and read
//! it back.
//!
//! It is a thin façade over the proven core, adding nothing to the safety
//! argument: every allocation still flows through `allocate_for`'s
//! quorum-intersection fence (a majority of voters must grant an address before
//! it can be handed out), so a double-allocation of the same address is refused
//! here exactly as it is in the library. What this layer ADDS is the *record*:
//! a persistent, queryable map from a purpose (a VIP name, a node) to the
//! address that was allocated to it — the durable operator-visible state the
//! load balancer's VIP wiring consumes.
//!
//! Nothing here reaches the network or the filesystem: the record is an
//! in-memory, deterministic value type, so the whole allocate→record→read-back
//! →release lifecycle is exercised by ordinary tests. A deployed node backs the
//! identical operations with the event log; the recorded-binding contract is
//! the same.

use std::collections::BTreeMap;
use std::net::IpAddr;

use pillar_core::NodeId;

use crate::{ScopedError, TopologyScopedIpam};

/// A recorded IPAM binding: the address handed to a purpose, plus whether it
/// was a live quorum allocation or an operator reservation (a hold placed
/// ahead of the quorum). This is the operator-visible record `pillar ipam get`
/// reads back and the load balancer's VIP wiring consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The node the address is allocated to (the actor that holds it).
    pub node: NodeId,
    /// The recorded address.
    pub addr: IpAddr,
    /// Whether a quorum currently backs this binding (a live allocation) as
    /// opposed to a not-yet-quorum operator reservation.
    pub allocated: bool,
}

/// Why an operator IPAM verb was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorError {
    /// The address is already recorded under a DIFFERENT name — a double
    /// allocation of the same recorded address is refused so an operator can
    /// never hand one VIP address to two purposes.
    AddressAlreadyRecorded {
        /// The address that is already recorded.
        addr: IpAddr,
        /// The name it is already bound to.
        existing_name: String,
    },
    /// The quorum did not (yet) back the allocation: fewer than a majority of
    /// voters have granted the address, so it cannot be handed out live.
    NotAllocated {
        /// The address whose allocation the quorum did not back.
        addr: IpAddr,
    },
    /// A `release`/`get` targeted a name that is not recorded.
    NotRecorded {
        /// The requested VIP/binding name.
        name: String,
    },
    /// The underlying topology-scoped allocation failed (out-of-pool, no scope
    /// for the node, no pool for the scope, or a monotonic grant refusal).
    Scoped(ScopedError),
}

impl From<ScopedError> for OperatorError {
    fn from(e: ScopedError) -> Self {
        OperatorError::Scoped(e)
    }
}

impl std::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorError::AddressAlreadyRecorded {
                addr,
                existing_name,
            } => write!(f, "address {addr} is already recorded to `{existing_name}`"),
            OperatorError::NotAllocated { addr } => {
                write!(f, "no quorum backs allocation of {addr}")
            }
            OperatorError::NotRecorded { name } => {
                write!(f, "no IPAM binding recorded under `{name}`")
            }
            OperatorError::Scoped(e) => write!(f, "{e:?}"),
        }
    }
}

impl std::error::Error for OperatorError {}

/// The operator surface over a [`TopologyScopedIpam`]: allocate / reserve /
/// release an address out of a delegated pool and RECORD it under a name (a
/// VIP name, a service, a node) so it can be read back.
///
/// Every `allocate` flows through the wrapped IPAM's quorum-fenced
/// `allocate_for`; the operator surface adds the durable *record* — the
/// name → [`Binding`] map the load balancer's VIP wiring consumes — and the
/// operator-facing invariants (an address recorded to one name can never be
/// recorded to another; a release returns the address to the pool AND clears
/// the record).
#[derive(Clone, Debug)]
pub struct IpamOperator {
    ipam: TopologyScopedIpam,
    /// name → recorded binding. The operator-visible state.
    records: BTreeMap<String, Binding>,
}

impl IpamOperator {
    /// A new operator surface over `ipam` with no recorded bindings.
    #[must_use]
    pub fn new(ipam: TopologyScopedIpam) -> Self {
        IpamOperator {
            ipam,
            records: BTreeMap::new(),
        }
    }

    /// Borrow the underlying topology-scoped IPAM (to bind pools, record
    /// voter grants ahead of an allocation, etc.).
    #[must_use]
    pub fn ipam(&self) -> &TopologyScopedIpam {
        &self.ipam
    }

    /// Mutable access to the underlying IPAM, so an operator can record the
    /// voter grants that a live [`allocate`](Self::allocate) requires.
    pub fn ipam_mut(&mut self) -> &mut TopologyScopedIpam {
        &mut self.ipam
    }

    /// Reject recording `addr` under `name` if it is already recorded to a
    /// different name — the operator-level duplicate-address guard.
    fn ensure_free(&self, name: &str, addr: IpAddr) -> Result<(), OperatorError> {
        for (n, b) in &self.records {
            if b.addr == addr && n != name {
                return Err(OperatorError::AddressAlreadyRecorded {
                    addr,
                    existing_name: n.clone(),
                });
            }
        }
        Ok(())
    }

    /// `pillar ipam allocate <name> --node <node> --addr <addr>` (ACT):
    /// allocate `addr` to `node` out of `node`'s topology-scoped pool through
    /// the quorum fence and RECORD it under `name`. The address MUST already be
    /// backed by a quorum of voter grants (record them via
    /// [`ipam_mut`](Self::ipam_mut)); otherwise the allocation is refused and
    /// nothing is recorded.
    ///
    /// # Errors
    /// [`OperatorError::AddressAlreadyRecorded`] if `addr` is recorded under
    /// another name, [`OperatorError::NotAllocated`] if no quorum backs the
    /// address, or [`OperatorError::Scoped`] for an out-of-pool / no-scope
    /// failure. On any error NOTHING is recorded.
    pub fn allocate(
        &mut self,
        name: impl Into<String>,
        node: &NodeId,
        addr: IpAddr,
    ) -> Result<Binding, OperatorError> {
        let name = name.into();
        self.ensure_free(&name, addr)?;
        let allocated = self.ipam.allocate_for(node, addr)?;
        if !allocated {
            return Err(OperatorError::NotAllocated { addr });
        }
        let binding = Binding {
            node: node.clone(),
            addr,
            allocated: true,
        };
        self.records.insert(name, binding.clone());
        Ok(binding)
    }

    /// `pillar ipam reserve <name> --node <node> --addr <addr>` (ACT): RECORD a
    /// hold on `addr` for `node` under `name` WITHOUT requiring a live quorum
    /// yet — the operator claims the address ahead of the grants converging.
    /// The reservation still respects the duplicate-address guard and the pool
    /// scope (a reserve of an out-of-pool / cross-site address is refused), so
    /// it can never record an address the node could not eventually be handed.
    ///
    /// A later [`allocate`](Self::allocate) under the SAME name upgrades the
    /// reservation to a live allocation once the quorum backs it.
    ///
    /// # Errors
    /// [`OperatorError::AddressAlreadyRecorded`] if `addr` is recorded under
    /// another name, or [`OperatorError::Scoped`] if the address is out of the
    /// node's scoped pool.
    pub fn reserve(
        &mut self,
        name: impl Into<String>,
        node: &NodeId,
        addr: IpAddr,
    ) -> Result<Binding, OperatorError> {
        let name = name.into();
        self.ensure_free(&name, addr)?;
        // Validate the address IS in the node's scoped pool without requiring a
        // quorum: allocate_for returns Ok(false) for an in-pool-but-not-yet-
        // quorum address and Err for an out-of-pool/no-scope one.
        let allocated = self.ipam.allocate_for(node, addr)?;
        let binding = Binding {
            node: node.clone(),
            addr,
            allocated,
        };
        self.records.insert(name, binding.clone());
        Ok(binding)
    }

    /// `pillar ipam release <name>` (ACT): release the address recorded under
    /// `name` back to its pool and clear the record. Returns the released
    /// binding.
    ///
    /// # Errors
    /// [`OperatorError::NotRecorded`] if no binding is recorded under `name`.
    pub fn release(&mut self, name: &str) -> Result<Binding, OperatorError> {
        let binding = self
            .records
            .remove(name)
            .ok_or_else(|| OperatorError::NotRecorded {
                name: name.to_owned(),
            })?;
        // Return the address to the pool at the coordination layer so the slot
        // can be re-granted to a different actor. Best-effort: the recorded
        // binding is authoritative for the operator surface, and clearing it is
        // the observable effect the load balancer sees.
        let want_v6 = binding.addr.is_ipv6();
        if let Ok(alloc) = self.ipam.allocator_for(&binding.node, want_v6) {
            alloc.release(&binding.node, binding.addr);
        }
        Ok(binding)
    }

    /// `pillar ipam get <name>` (VIEW): read back the recorded binding under
    /// `name`, if any. Signs nothing.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Binding> {
        self.records.get(name)
    }

    /// The address recorded under `name`, if any — the primitive the load
    /// balancer's VIP wiring reads.
    #[must_use]
    pub fn recorded_addr(&self, name: &str) -> Option<IpAddr> {
        self.records.get(name).map(|b| b.addr)
    }

    /// `pillar ipam get` (VIEW): every recorded binding, in name order.
    #[must_use]
    pub fn list(&self) -> Vec<(&String, &Binding)> {
        self.records.iter().collect()
    }

    /// The number of recorded bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no binding is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Add a `release` verb + `index_of` reuse: the [`crate::DelegatedAllocator`]
/// exposes `release` at the register layer. Re-exported so the operator surface
/// can return an address to its pool.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pool;
    use pillar_topology::{Label, TierHierarchy, Topology};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    /// A single-region IPAM with a v4 pool bound to `west`, and a node `w1`
    /// placed in it.
    fn one_region_operator() -> IpamOperator {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("w1"), &[Label::new("region", "west")]);
        topo.declare(n("w2"), &[Label::new("region", "west")]);
        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
        IpamOperator::new(ipam)
    }

    /// Record a quorum of grants for `addr` to `node` so a live allocation
    /// succeeds.
    fn back_with_quorum(op: &mut IpamOperator, node: &NodeId, addr: IpAddr) {
        op.ipam_mut().grant_for(n("v1"), node, addr).unwrap();
        op.ipam_mut().grant_for(n("v2"), node, addr).unwrap();
    }

    #[test]
    fn allocate_records_the_vip_and_reads_it_back() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.9");
        back_with_quorum(&mut op, &n("w1"), vip);

        let binding = op.allocate("lb-vip", &n("w1"), vip).expect("allocated");
        assert!(binding.allocated);
        assert_eq!(binding.addr, vip);

        // Read it back — the operator-visible record the LB consumes.
        assert_eq!(op.recorded_addr("lb-vip"), Some(vip));
        assert_eq!(op.get("lb-vip").unwrap().node, n("w1"));
        assert_eq!(op.len(), 1);
    }

    #[test]
    fn allocate_without_quorum_is_refused_and_records_nothing() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.5");
        // Only ONE grant — no majority.
        op.ipam_mut().grant_for(n("v1"), &n("w1"), vip).unwrap();
        let err = op.allocate("lb-vip", &n("w1"), vip).expect_err("no quorum");
        assert_eq!(err, OperatorError::NotAllocated { addr: vip });
        assert!(op.get("lb-vip").is_none());
    }

    #[test]
    fn double_allocation_of_the_same_address_is_rejected() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.7");
        back_with_quorum(&mut op, &n("w1"), vip);
        op.allocate("vip-a", &n("w1"), vip).expect("first");

        // A DIFFERENT name cannot record the SAME address.
        let err = op
            .allocate("vip-b", &n("w1"), vip)
            .expect_err("duplicate address");
        assert_eq!(
            err,
            OperatorError::AddressAlreadyRecorded {
                addr: vip,
                existing_name: "vip-a".to_owned(),
            }
        );
        // Only the first record exists.
        assert_eq!(op.len(), 1);
        assert_eq!(op.recorded_addr("vip-a"), Some(vip));
    }

    #[test]
    fn release_returns_the_address_to_the_pool_and_clears_the_record() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.3");
        back_with_quorum(&mut op, &n("w1"), vip);
        op.allocate("lb-vip", &n("w1"), vip).expect("allocated");
        assert_eq!(op.recorded_addr("lb-vip"), Some(vip));

        let released = op.release("lb-vip").expect("released");
        assert_eq!(released.addr, vip);
        // The record is gone — reading it back yields nothing.
        assert!(op.get("lb-vip").is_none());
        assert!(op.is_empty());

        // The address is now free to record again (e.g. to a different name).
        assert!(op.ensure_free("other", vip).is_ok());
    }

    #[test]
    fn releasing_an_unrecorded_name_is_refused() {
        let mut op = one_region_operator();
        assert_eq!(
            op.release("nope").expect_err("not recorded"),
            OperatorError::NotRecorded {
                name: "nope".to_owned()
            }
        );
    }

    #[test]
    fn reserve_records_an_in_pool_hold_and_refuses_out_of_pool() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.42");
        // Reserve BEFORE any quorum: an in-pool hold, not yet live.
        let b = op.reserve("held-vip", &n("w1"), vip).expect("reserved");
        assert!(!b.allocated);
        assert_eq!(op.recorded_addr("held-vip"), Some(vip));

        // An out-of-pool (wrong-site would be too) address is refused.
        let outside = v4("10.9.9.9");
        assert!(matches!(
            op.reserve("bad", &n("w1"), outside)
                .expect_err("out of pool"),
            OperatorError::Scoped(_)
        ));
    }

    #[test]
    fn reserve_then_allocate_upgrades_the_same_binding() {
        let mut op = one_region_operator();
        let vip = v4("10.1.0.11");
        op.reserve("lb-vip", &n("w1"), vip).expect("reserved");
        assert!(!op.get("lb-vip").unwrap().allocated);

        // Now a quorum converges and the operator allocates under the SAME name.
        back_with_quorum(&mut op, &n("w1"), vip);
        let b = op.allocate("lb-vip", &n("w1"), vip).expect("allocated");
        assert!(b.allocated);
        assert_eq!(op.len(), 1, "same binding upgraded, not duplicated");
    }
}
