//! Quorum-fenced address allocation — the Rust refinement of `specs/IPAM.tla`.
//!
//! An IP address must never be handed to two actors at once: a duplicate-IP
//! assignment is an outage, not a benign race. Rather than invent a bespoke
//! allocation protocol, IPAM (as the spec proves) is a *direct instance* of the
//! one coordination core: each address in a delegated pool plays the role of an
//! "epoch" slot, and "allocating address `a`" is exactly "acquiring epoch
//! `index_of(a)`". A candidate actor may only become the allocator of an
//! address once a quorum of voters has granted it that address; because any two
//! quorums intersect and grants are monotonic, no two actors can ever be
//! granted the same address by a majority simultaneously
//! (`NoDoubleAllocation` in the TLA+ model, re-exported verbatim from
//! `CoordinationCore`'s `AtMostOneHolderPerEpoch`).
//!
//! This crate holds only the allocation-decision logic plus the address<->slot
//! mapping. Distribution of grants over the streaming DB / gossip layer, and
//! the pool-delegation handshake that subdivides a parent pool to a child
//! authority, are separate components (spec-only / out of scope here, per
//! `specs/IPAM.tla`).
//!
//! Both IPv4 and IPv6 delegated pools are supported: a pool is a contiguous
//! run of addresses from a base, and each address's zero-based offset from that
//! base is its slot index (the fencing token / epoch).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pillar_coordination::{GrantError, LeaseRegister};
use pillar_core::{Epoch, NodeId};

/// A contiguous, delegated block of addresses this authority may hand out.
///
/// A pool is a base address plus a length (number of addresses). The pool is
/// single-family: an IPv4 base delegates IPv4 addresses, an IPv6 base delegates
/// IPv6 addresses. Address `base + k` (for `0 <= k < len`) occupies slot `k`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    base: IpAddr,
    len: u64,
}

/// Why an address could not be mapped into a pool slot or allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// The address is not a member of this pool: wrong family, below the base,
    /// or at/beyond `base + len`.
    OutOfPool {
        /// The address that was rejected.
        addr: IpAddr,
    },
    /// The underlying coordination grant was refused (a stale/monotonic
    /// violation on the voter). Mirrors [`GrantError`].
    Grant(GrantError),
}

impl From<GrantError> for AllocError {
    fn from(e: GrantError) -> Self {
        AllocError::Grant(e)
    }
}

fn v4_to_u128(a: Ipv4Addr) -> u128 {
    u32::from(a) as u128
}

fn v6_to_u128(a: Ipv6Addr) -> u128 {
    u128::from(a)
}

fn ip_to_u128(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => v4_to_u128(v),
        IpAddr::V6(v) => v6_to_u128(v),
    }
}

impl Pool {
    /// Create a delegated pool of `len` addresses starting at `base`.
    ///
    /// A `len` of zero is a legal (empty) pool that contains no address.
    #[must_use]
    pub fn new(base: IpAddr, len: u64) -> Self {
        Self { base, len }
    }

    /// The base (first) address of the pool.
    #[must_use]
    pub fn base(&self) -> IpAddr {
        self.base
    }

    /// The number of addresses in the pool.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the pool contains no addresses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The zero-based slot index of `addr` within this pool, or `None` if the
    /// address is not a member (wrong family, below the base, or beyond the
    /// pool's extent).
    ///
    /// The slot index is the address's fencing token — its coordination epoch.
    #[must_use]
    pub fn index_of(&self, addr: IpAddr) -> Option<u64> {
        // Family must match: an IPv4 address is never in an IPv6 pool.
        match (self.base, addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => return None,
        }
        let base = ip_to_u128(self.base);
        let a = ip_to_u128(addr);
        let offset = a.checked_sub(base)?;
        if offset < u128::from(self.len) {
            // offset < len <= u64::MAX, so this cast is lossless.
            Some(offset as u64)
        } else {
            None
        }
    }

    /// The address occupying slot `index`, or `None` if `index >= len`.
    #[must_use]
    pub fn addr_at(&self, index: u64) -> Option<IpAddr> {
        if index >= self.len {
            return None;
        }
        let raw = ip_to_u128(self.base) + u128::from(index);
        Some(match self.base {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(raw as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(raw)),
        })
    }

    /// Whether `addr` is a member of this pool.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.index_of(addr).is_some()
    }
}

/// A quorum-fenced allocator over one delegated [`Pool`].
///
/// This is `IPAM.tla` in code: it wraps a [`LeaseRegister`] and maps addresses
/// to/from the epoch slots the register fences. Every allocation is gated on a
/// quorum grant, so two concurrent allocators can never both be handed the same
/// address (the `NoDoubleAllocation` invariant).
#[derive(Clone, Debug)]
pub struct DelegatedAllocator {
    pool: Pool,
    register: LeaseRegister,
}

impl DelegatedAllocator {
    /// Create an allocator for `pool` fenced by a cluster of `cluster_size`
    /// voting nodes.
    #[must_use]
    pub fn new(pool: Pool, cluster_size: usize) -> Self {
        Self {
            pool,
            register: LeaseRegister::new(cluster_size),
        }
    }

    /// The pool this allocator hands out.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    fn epoch_of(&self, addr: IpAddr) -> Result<Epoch, AllocError> {
        self.pool
            .index_of(addr)
            .map(Epoch)
            .ok_or(AllocError::OutOfPool { addr })
    }

    /// Record `voter`'s grant of `addr` to `actor`.
    ///
    /// # Errors
    /// [`AllocError::OutOfPool`] if `addr` is not in the pool, or
    /// [`AllocError::Grant`] if the voter has already granted a higher-or-equal
    /// slot (grants are monotonic per the coordination core).
    pub fn grant(&mut self, voter: NodeId, actor: NodeId, addr: IpAddr) -> Result<(), AllocError> {
        let epoch = self.epoch_of(addr)?;
        self.register.grant(voter, actor, epoch)?;
        Ok(())
    }

    /// Attempt to allocate `addr` to `actor`.
    ///
    /// Returns `Ok(true)` iff a quorum of voters currently backs `actor` for
    /// `addr` (or `actor` already holds it — allocation is idempotent). The
    /// quorum-intersection invariant guarantees a different actor can never
    /// succeed for an address already allocated.
    ///
    /// # Errors
    /// [`AllocError::OutOfPool`] if `addr` is not in the pool.
    pub fn try_allocate(&mut self, actor: &NodeId, addr: IpAddr) -> Result<bool, AllocError> {
        let epoch = self.epoch_of(addr)?;
        Ok(self.register.try_acquire(actor, epoch))
    }

    /// The actor `addr` is currently allocated to, if any.
    #[must_use]
    pub fn allocator_of(&self, addr: IpAddr) -> Option<&NodeId> {
        let index = self.pool.index_of(addr)?;
        self.register.holder(Epoch(index))
    }
}

// =====================================================================
// Topology-scoped, multi-site, multi-prefix, dual-stack allocation.
// =====================================================================
//
// The [`DelegatedAllocator`] above fences ONE contiguous pool. A real
// deployment is multi-site: distinct regions/zones own distinct IPv4 *and*
// IPv6 prefixes, and a node must only ever be handed an address out of the
// pool bound to its OWN topology label — an allocation must never cross a
// site. [`TopologyScopedIpam`] layers exactly that binding on top, reusing
// [`pillar_topology`]'s config-ordered [`TierHierarchy`] for the tier order
// (never a hardcoded one) and its [`Topology`] registry to resolve which
// failure domain a node lives in.
//
// This layer assumes NO public anycast address and NO pillar ASN: a pool is
// just a delegated prefix bound to a `tier = value` label; addresses are the
// operator's own (private or delegated) space. Nothing here reaches the
// network.

use std::collections::BTreeMap;

use pillar_topology::{Label, TierHierarchy, Topology};

/// Why a topology-scoped allocation could not be satisfied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopedError {
    /// The node carries no resolved label at the pools' binding tier, so its
    /// topology-scoped pool cannot be determined — a node with no site is
    /// never given a cross-site address by default.
    NoScopeForNode {
        /// The node whose placement lacks a value at the binding tier.
        node: NodeId,
        /// The tier the pools are bound to.
        tier: String,
    },
    /// No pool is bound to the node's failure domain for the requested family.
    NoPoolForScope {
        /// The `tier = value` domain that has no bound pool.
        scope: Label,
        /// Whether an IPv6 (vs IPv4) address was requested.
        want_v6: bool,
    },
    /// The binding tier is not a member of the active hierarchy.
    UnknownTier(String),
    /// An underlying single-pool allocation error (out-of-pool / grant).
    Alloc(AllocError),
}

impl From<AllocError> for ScopedError {
    fn from(e: AllocError) -> Self {
        ScopedError::Alloc(e)
    }
}

/// A dual-stack pair of topology-scoped pools bound to ONE failure domain.
///
/// A site/region owns disjoint IPv4 and/or IPv6 prefixes; each is fenced by
/// its own [`DelegatedAllocator`]. Either family may be absent (a v6-only or
/// v4-only site), but at least one must be present.
#[derive(Clone, Debug)]
struct ScopedPools {
    v4: Option<DelegatedAllocator>,
    v6: Option<DelegatedAllocator>,
}

/// Multi-site, multi-prefix, dual-stack, topology-scoped IPAM.
///
/// Prefix pools are scoped to a topology label (`tier = value`) drawn from a
/// config-ordered [`TierHierarchy`]: distinct sites/regions own distinct
/// prefixes, and [`allocate_for`](Self::allocate_for) hands a node an address
/// ONLY out of the pool bound to the node's own resolved failure domain — an
/// allocation can never cross a site. A [`diversity_addrs`](Self::diversity_addrs)
/// query returns K addresses spread across the most diverse available topology
/// tiers, the primitive the UDP transport calls to pick dispersed reply-node
/// source addresses.
#[derive(Clone, Debug)]
pub struct TopologyScopedIpam {
    /// The tier the prefix pools are bound to (e.g. `"region"` or `"site"`).
    tier: String,
    /// Failure-domain value -> its dual-stack pools.
    pools: BTreeMap<String, ScopedPools>,
    /// The active topology registry (resolves a node -> its failure domain)
    /// and its config-ordered hierarchy.
    topology: Topology,
}

impl TopologyScopedIpam {
    /// A new topology-scoped IPAM whose prefix pools are bound at `tier`,
    /// resolving node placement through `topology`. `tier` must be a member of
    /// `topology`'s hierarchy.
    ///
    /// # Errors
    /// [`ScopedError::UnknownTier`] if `tier` is not in the hierarchy.
    pub fn new(topology: Topology, tier: impl Into<String>) -> Result<Self, ScopedError> {
        let tier = tier.into();
        if topology.hierarchy().rank(&tier).is_none() {
            return Err(ScopedError::UnknownTier(tier));
        }
        Ok(Self {
            tier,
            pools: BTreeMap::new(),
            topology,
        })
    }

    /// The tier the prefix pools are bound to.
    #[must_use]
    pub fn tier(&self) -> &str {
        &self.tier
    }

    /// The active hierarchy (config-ordered), for tier-diversity queries.
    #[must_use]
    pub fn hierarchy(&self) -> &TierHierarchy {
        self.topology.hierarchy()
    }

    /// The topology registry.
    #[must_use]
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Bind a delegated `pool` to the failure domain `value` at the binding
    /// tier, fenced by `cluster_size` voters. The family (v4/v6) is taken from
    /// the pool's base; binding a second pool of the same family to the same
    /// domain replaces the first.
    pub fn bind_pool(&mut self, value: impl Into<String>, pool: Pool, cluster_size: usize) {
        let entry = self
            .pools
            .entry(value.into())
            .or_insert(ScopedPools { v4: None, v6: None });
        let alloc = DelegatedAllocator::new(pool.clone(), cluster_size);
        match pool.base() {
            IpAddr::V4(_) => entry.v4 = Some(alloc),
            IpAddr::V6(_) => entry.v6 = Some(alloc),
        }
    }

    /// The failure-domain value a `node` lives in at the binding tier, from
    /// its resolved (attested-then-declared) placement.
    fn scope_of(&self, node: &NodeId) -> Result<String, ScopedError> {
        self.topology
            .placement(node)
            .at(&self.tier)
            .map(str::to_owned)
            .ok_or_else(|| ScopedError::NoScopeForNode {
                node: node.clone(),
                tier: self.tier.clone(),
            })
    }

    /// Mutable access to the [`DelegatedAllocator`] bound to `node`'s failure
    /// domain for the requested family, so grants can be recorded before an
    /// allocation. `want_v6` selects the family.
    ///
    /// # Errors
    /// [`ScopedError::NoScopeForNode`] if the node has no label at the tier, or
    /// [`ScopedError::NoPoolForScope`] if no pool of that family is bound to
    /// the node's domain.
    pub fn allocator_for(
        &mut self,
        node: &NodeId,
        want_v6: bool,
    ) -> Result<&mut DelegatedAllocator, ScopedError> {
        let scope = self.scope_of(node)?;
        let entry = self
            .pools
            .get_mut(&scope)
            .ok_or_else(|| ScopedError::NoPoolForScope {
                scope: Label::new(self.tier.clone(), scope.clone()),
                want_v6,
            })?;
        let slot = if want_v6 {
            &mut entry.v6
        } else {
            &mut entry.v4
        };
        slot.as_mut().ok_or(ScopedError::NoPoolForScope {
            scope: Label::new(self.tier.clone(), scope),
            want_v6,
        })
    }

    /// Record a `voter`'s grant of `addr` to `node` in the pool bound to
    /// `node`'s own failure domain. `addr`'s family selects the pool.
    ///
    /// # Errors
    /// A [`ScopedError`] if the node has no scoped pool of that family, or the
    /// address is out of that pool / the grant is refused.
    pub fn grant_for(
        &mut self,
        voter: NodeId,
        node: &NodeId,
        addr: IpAddr,
    ) -> Result<(), ScopedError> {
        let want_v6 = addr.is_ipv6();
        let alloc = self.allocator_for(node, want_v6)?;
        alloc.grant(voter, node.clone(), addr)?;
        Ok(())
    }

    /// Attempt to allocate `addr` to `node` from `node`'s OWN topology-scoped
    /// pool. The address MUST be a member of the pool bound to the node's
    /// failure domain — an address from another site's prefix is out-of-pool
    /// there and is refused, so an allocation can never cross a site.
    ///
    /// Returns `Ok(true)` iff a quorum currently backs `node` for `addr`.
    ///
    /// # Errors
    /// A [`ScopedError`] if the node has no scoped pool of that family, or the
    /// address is out of the node's pool.
    pub fn allocate_for(&mut self, node: &NodeId, addr: IpAddr) -> Result<bool, ScopedError> {
        let want_v6 = addr.is_ipv6();
        let alloc = self.allocator_for(node, want_v6)?;
        Ok(alloc.try_allocate(node, addr)?)
    }

    /// **Topology-diversity query.** Given a redundancy count `k`, return up to
    /// `k` addresses (one per distinct failure domain) spread across the most
    /// diverse available topology tiers, refined by an optional per-domain
    /// `preference` ranking (GeoIP / measured latency — lower is better) when
    /// available. This is the primitive the UDP transport calls to pick
    /// dispersed reply-node *source* addresses.
    ///
    /// Each returned address comes from a DISTINCT bound failure domain, so a
    /// K=3 query over ≥2 sites always spans ≥2 sites. `want_v6` selects the
    /// family. Domains are visited best-first by `preference` (ties by domain
    /// name for determinism); the base (slot 0) address of each domain's pool
    /// is returned.
    #[must_use]
    pub fn diversity_addrs(
        &self,
        k: usize,
        want_v6: bool,
        preference: Option<&BTreeMap<String, u64>>,
    ) -> Vec<IpAddr> {
        // Rank the bound domains: refined by preference (lower first) when
        // available, else lexical for determinism.
        let mut ranked: Vec<(&String, &ScopedPools)> = self
            .pools
            .iter()
            .filter(|(_, p)| {
                let slot = if want_v6 { &p.v6 } else { &p.v4 };
                slot.as_ref().is_some_and(|a| !a.pool().is_empty())
            })
            .collect();
        ranked.sort_by(|(av, _), (bv, _)| {
            let ap = preference
                .and_then(|m| m.get(*av))
                .copied()
                .unwrap_or(u64::MAX);
            let bp = preference
                .and_then(|m| m.get(*bv))
                .copied()
                .unwrap_or(u64::MAX);
            ap.cmp(&bp).then_with(|| av.cmp(bv))
        });

        let mut out = Vec::new();
        for (_value, pools) in ranked {
            if out.len() == k {
                break;
            }
            // Each distinct domain contributes at most one address, guaranteeing
            // the returned set spreads across distinct failure domains.
            let slot = if want_v6 { &pools.v6 } else { &pools.v4 };
            if let Some(alloc) = slot {
                if let Some(addr) = alloc.pool().addr_at(0) {
                    out.push(addr);
                }
            }
        }
        out
    }

    /// The number of distinct failure domains (bound sites) that have a pool
    /// of the requested family — the maximum diversity a query can achieve.
    #[must_use]
    pub fn available_diversity(&self, want_v6: bool) -> usize {
        self.pools
            .values()
            .filter(|p| {
                let slot = if want_v6 { &p.v6 } else { &p.v4 };
                slot.as_ref().is_some_and(|a| !a.pool().is_empty())
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn ipv4_pool_maps_addresses_to_slots_round_trip() {
        let pool = Pool::new(v4("10.0.0.0"), 256);
        assert_eq!(pool.index_of(v4("10.0.0.0")), Some(0));
        assert_eq!(pool.index_of(v4("10.0.0.5")), Some(5));
        assert_eq!(pool.index_of(v4("10.0.0.255")), Some(255));
        // One past the end and below the base are both out of pool.
        assert_eq!(pool.index_of(v4("10.0.1.0")), None);
        assert_eq!(pool.index_of(v4("9.255.255.255")), None);
        for k in [0u64, 1, 42, 255] {
            let a = pool.addr_at(k).unwrap();
            assert_eq!(pool.index_of(a), Some(k));
        }
        assert_eq!(pool.addr_at(256), None);
    }

    #[test]
    fn ipv6_pool_maps_addresses_to_slots_round_trip() {
        let pool = Pool::new(v6("2001:db8::"), 1024);
        assert_eq!(pool.index_of(v6("2001:db8::")), Some(0));
        assert_eq!(pool.index_of(v6("2001:db8::a")), Some(10));
        assert_eq!(pool.index_of(v6("2001:db8::3ff")), Some(1023));
        assert_eq!(pool.index_of(v6("2001:db8::400")), None);
        for k in [0u64, 1, 500, 1023] {
            let a = pool.addr_at(k).unwrap();
            assert_eq!(pool.index_of(a), Some(k));
        }
    }

    #[test]
    fn pool_is_single_family() {
        let v4pool = Pool::new(v4("192.168.0.0"), 256);
        assert_eq!(v4pool.index_of(v6("::c0a8:0")), None);
        let v6pool = Pool::new(v6("2001:db8::"), 256);
        assert_eq!(v6pool.index_of(v4("10.0.0.0")), None);
    }

    #[test]
    fn quorum_allocates_an_ipv4_address() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v4("10.0.0.0"), 256), 3);
        let addr = v4("10.0.0.7");
        alloc.grant(n("n1"), n("actorA"), addr).unwrap();
        alloc.grant(n("n2"), n("actorA"), addr).unwrap();
        assert!(alloc.try_allocate(&n("actorA"), addr).unwrap());
        assert_eq!(alloc.allocator_of(addr), Some(&n("actorA")));
    }

    #[test]
    fn quorum_allocates_an_ipv6_address() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v6("2001:db8::"), 65536), 3);
        let addr = v6("2001:db8::dead");
        alloc.grant(n("n1"), n("actorA"), addr).unwrap();
        alloc.grant(n("n2"), n("actorA"), addr).unwrap();
        assert!(alloc.try_allocate(&n("actorA"), addr).unwrap());
        assert_eq!(alloc.allocator_of(addr), Some(&n("actorA")));
    }

    #[test]
    fn minority_cannot_allocate() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v4("10.0.0.0"), 256), 3);
        let addr = v4("10.0.0.1");
        alloc.grant(n("n1"), n("actorA"), addr).unwrap();
        assert!(!alloc.try_allocate(&n("actorA"), addr).unwrap());
        assert_eq!(alloc.allocator_of(addr), None);
    }

    #[test]
    fn out_of_pool_address_is_refused() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v4("10.0.0.0"), 16), 3);
        let addr = v4("10.0.5.5");
        assert_eq!(
            alloc.grant(n("n1"), n("actorA"), addr),
            Err(AllocError::OutOfPool { addr })
        );
        assert_eq!(
            alloc.try_allocate(&n("actorA"), addr),
            Err(AllocError::OutOfPool { addr })
        );
    }

    #[test]
    fn allocation_is_idempotent_for_its_holder() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v4("10.0.0.0"), 256), 3);
        let addr = v4("10.0.0.9");
        alloc.grant(n("n1"), n("actorA"), addr).unwrap();
        alloc.grant(n("n2"), n("actorA"), addr).unwrap();
        assert!(alloc.try_allocate(&n("actorA"), addr).unwrap());
        // Re-allocating by the same holder still succeeds; no new quorum needed.
        assert!(alloc.try_allocate(&n("actorA"), addr).unwrap());
    }

    /// `NoDoubleAllocation` from `specs/IPAM.tla`, exercised exhaustively over
    /// every way 3 voters can grant one pool address to one of two concurrent
    /// actors. No assignment ever lets both actors be allocated the address —
    /// the direct duplicate-IP exclusion.
    #[test]
    fn no_double_allocation_under_concurrent_allocators() {
        let voters = [n("n1"), n("n2"), n("n3")];
        let actors = [n("actorA"), n("actorB")];
        let pool = Pool::new(v4("10.0.0.0"), 256);
        let addr = v4("10.0.0.42");

        // Each voter independently backs actorA, actorB, or abstains: 3^3 = 27
        // interleavings of two concurrent allocators contending for one address.
        for mask in 0..27u32 {
            let mut alloc = DelegatedAllocator::new(pool.clone(), voters.len());
            let mut m = mask;
            for v in &voters {
                match m % 3 {
                    0 => alloc.grant(v.clone(), actors[0].clone(), addr).unwrap(),
                    1 => alloc.grant(v.clone(), actors[1].clone(), addr).unwrap(),
                    _ => {}
                }
                m /= 3;
            }
            let a = alloc.try_allocate(&actors[0], addr).unwrap();
            let b = alloc.try_allocate(&actors[1], addr).unwrap();
            assert!(
                !(a && b),
                "duplicate IP: both actors were allocated {addr} (mask {mask})"
            );
        }
    }

    /// Distinct addresses in the pool are independent slots: once an address is
    /// allocated its holder is recorded permanently, so a second address can be
    /// allocated afterwards without disturbing the first. (Grants are monotonic
    /// per voter — mirroring `grantedAddr[v]` in `specs/IPAM.tla` — so a voter
    /// backs a higher slot only after the lower one has been acquired.)
    #[test]
    fn distinct_addresses_are_independent_slots() {
        let mut alloc = DelegatedAllocator::new(Pool::new(v4("10.0.0.0"), 256), 3);
        let a1 = v4("10.0.0.1");
        let a2 = v4("10.0.0.2");
        alloc.grant(n("n1"), n("actorA"), a1).unwrap();
        alloc.grant(n("n2"), n("actorA"), a1).unwrap();
        assert!(alloc.try_allocate(&n("actorA"), a1).unwrap());
        // a2 occupies a higher slot, so the same voters may now grant it.
        alloc.grant(n("n1"), n("actorB"), a2).unwrap();
        alloc.grant(n("n3"), n("actorB"), a2).unwrap();
        assert!(alloc.try_allocate(&n("actorB"), a2).unwrap());
        // The first allocation is untouched.
        assert_eq!(alloc.allocator_of(a1), Some(&n("actorA")));
        assert_eq!(alloc.allocator_of(a2), Some(&n("actorB")));
    }

    // =================================================================
    // Topology-scoped, multi-site, multi-prefix, dual-stack tests.
    // =================================================================

    use pillar_topology::{Label, TierHierarchy, Topology};

    /// Two disjoint sites at the `region` tier, each with its own v4 + v6
    /// prefix; nodes labeled into a region.
    fn two_region_ipam() -> TopologyScopedIpam {
        let mut topo = Topology::new(TierHierarchy::default());
        // west nodes
        topo.declare(n("w1"), &[Label::new("region", "west")]);
        topo.declare(n("w2"), &[Label::new("region", "west")]);
        // east nodes
        topo.declare(n("e1"), &[Label::new("region", "east")]);

        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        // Disjoint prefixes per region, dual-stack.
        ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
        ipam.bind_pool("west", Pool::new(v6("2001:db8:1::"), 65536), 3);
        ipam.bind_pool("east", Pool::new(v4("10.2.0.0"), 256), 3);
        ipam.bind_pool("east", Pool::new(v6("2001:db8:2::"), 65536), 3);
        ipam
    }

    /// A node is only ever handed an address out of its own region's pool; an
    /// address from another region is out-of-pool and refused — allocation
    /// never crosses a site.
    #[test]
    fn scoped_allocation_never_crosses_sites() {
        let mut ipam = two_region_ipam();
        // w1 is in west: a west address allocates after a quorum.
        let west_addr = v4("10.1.0.5");
        ipam.grant_for(n("va"), &n("w1"), west_addr).unwrap();
        ipam.grant_for(n("vb"), &n("w1"), west_addr).unwrap();
        assert!(ipam.allocate_for(&n("w1"), west_addr).unwrap());

        // The SAME node cannot be granted or allocated an EAST address: it is
        // out of w1's (west) pool entirely.
        let east_addr = v4("10.2.0.5");
        assert_eq!(
            ipam.grant_for(n("va"), &n("w1"), east_addr),
            Err(ScopedError::Alloc(AllocError::OutOfPool {
                addr: east_addr
            }))
        );
        assert_eq!(
            ipam.allocate_for(&n("w1"), east_addr),
            Err(ScopedError::Alloc(AllocError::OutOfPool {
                addr: east_addr
            }))
        );
    }

    /// A node with no label at the binding tier has no scoped pool: it is never
    /// handed a cross-site address by default.
    #[test]
    fn node_without_scope_is_refused() {
        let mut ipam = two_region_ipam();
        let unlabeled = n("stray");
        assert_eq!(
            ipam.allocate_for(&unlabeled, v4("10.1.0.1")),
            Err(ScopedError::NoScopeForNode {
                node: unlabeled,
                tier: "region".to_owned(),
            })
        );
    }

    /// Multi-site config with two disjoint prefixes each bound to a distinct
    /// region allocates correctly per region, for both families.
    #[test]
    fn multi_site_allocates_correctly_per_region_dual_stack() {
        let mut ipam = two_region_ipam();

        // west node -> west v4
        let wa = v4("10.1.0.9");
        ipam.grant_for(n("va"), &n("w1"), wa).unwrap();
        ipam.grant_for(n("vb"), &n("w1"), wa).unwrap();
        assert!(ipam.allocate_for(&n("w1"), wa).unwrap());

        // east node -> east v6
        let ea = v6("2001:db8:2::dead");
        ipam.grant_for(n("va"), &n("e1"), ea).unwrap();
        ipam.grant_for(n("vb"), &n("e1"), ea).unwrap();
        assert!(ipam.allocate_for(&n("e1"), ea).unwrap());

        // Cross-family within the correct region also works: west v6.
        let wv6 = v6("2001:db8:1::beef");
        ipam.grant_for(n("va"), &n("w2"), wv6).unwrap();
        ipam.grant_for(n("vb"), &n("w2"), wv6).unwrap();
        assert!(ipam.allocate_for(&n("w2"), wv6).unwrap());
    }

    /// Diversity query for K=3 across ≥2 zones returns addresses spread across
    /// ≥2 zones (here regions/sites).
    #[test]
    fn diversity_query_spreads_across_multiple_zones() {
        let ipam = two_region_ipam();
        assert_eq!(ipam.available_diversity(false), 2);

        let addrs = ipam.diversity_addrs(3, false, None);
        // Only 2 distinct sites bound, so at most 2 addresses (one per site).
        assert_eq!(addrs.len(), 2);

        // The two addresses come from DISTINCT sites' prefixes.
        assert!(addrs.contains(&v4("10.1.0.0")));
        assert!(addrs.contains(&v4("10.2.0.0")));

        // Distinct addresses => distinct sites.
        let set: std::collections::BTreeSet<_> = addrs.iter().collect();
        assert_eq!(set.len(), 2);
    }

    /// Three sites: a K=3 diversity query spreads across all three, and a
    /// GeoIP/latency preference orders the returned set best-first.
    #[test]
    fn diversity_query_k3_across_three_sites_prefers_lowest_latency() {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("x"), &[Label::new("region", "a")]);
        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        ipam.bind_pool("a", Pool::new(v4("10.10.0.0"), 16), 3);
        ipam.bind_pool("b", Pool::new(v4("10.20.0.0"), 16), 3);
        ipam.bind_pool("c", Pool::new(v4("10.30.0.0"), 16), 3);

        // Measured latency: b < a < c.
        let mut pref = BTreeMap::new();
        pref.insert("a".to_owned(), 20u64);
        pref.insert("b".to_owned(), 5u64);
        pref.insert("c".to_owned(), 50u64);

        let addrs = ipam.diversity_addrs(3, false, Some(&pref));
        assert_eq!(addrs.len(), 3);
        // best-first: b, a, c.
        assert_eq!(
            addrs,
            vec![v4("10.20.0.0"), v4("10.10.0.0"), v4("10.30.0.0")]
        );
        // Spans all three distinct sites.
        let set: std::collections::BTreeSet<_> = addrs.iter().collect();
        assert_eq!(set.len(), 3);
    }

    /// A v6-only site is honored: a v6 diversity query includes it, a v4 query
    /// does not.
    #[test]
    fn diversity_respects_requested_family() {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("x"), &[Label::new("region", "a")]);
        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        ipam.bind_pool("a", Pool::new(v4("10.1.0.0"), 16), 3);
        ipam.bind_pool("b", Pool::new(v6("2001:db8:99::"), 256), 3); // v6-only site

        assert_eq!(ipam.available_diversity(false), 1); // only site a has v4
        assert_eq!(ipam.available_diversity(true), 1); // only site b has v6

        let v4s = ipam.diversity_addrs(3, false, None);
        assert_eq!(v4s, vec![v4("10.1.0.0")]);
        let v6s = ipam.diversity_addrs(3, true, None);
        assert_eq!(v6s, vec![v6("2001:db8:99::")]);
    }

    /// No code path assumes a public anycast address or a pillar ASN: pools are
    /// plain private/delegated prefixes, and the diversity primitive returns
    /// site-scoped unicast addresses — never a shared anycast one. This test
    /// asserts distinct sites yield DISTINCT (non-shared) addresses.
    #[test]
    fn no_anycast_addresses_are_shared_across_sites() {
        let ipam = two_region_ipam();
        let addrs = ipam.diversity_addrs(2, false, None);
        assert_eq!(addrs.len(), 2);
        // Distinct unicast addresses per site — nothing anycast/shared.
        assert_ne!(addrs[0], addrs[1]);
    }

    /// Binding an unknown tier is refused up front.
    #[test]
    fn unknown_binding_tier_is_refused() {
        let topo = Topology::new(TierHierarchy::default());
        assert_eq!(
            TopologyScopedIpam::new(topo, "no-such-tier").err(),
            Some(ScopedError::UnknownTier("no-such-tier".to_owned()))
        );
    }

    /// Attested placement takes precedence: a node that declares one region but
    /// is attested into another is scoped by the ATTESTED region's pool.
    #[test]
    fn attested_region_governs_scope() {
        use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};

        let mut store = TrustStore::new(n("owner"));
        let mut topo = Topology::new(TierHierarchy::default());
        let node = n("liar");
        // Node lies: declares west.
        topo.declare(node.clone(), &[Label::new("region", "west")]);

        // Authority attests the truth: east.
        let auth = n("auth");
        let grant = Attest {
            issuer: n("owner"),
            capacity: Capacity::Role {
                role: "cell-authority".to_owned(),
                scope: "cell-b".to_owned(),
            },
            authority: None,
            subject: auth.clone(),
            predicate: Predicate::new("topology:sign", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: store.epoch(),
            sig: Sig::by(n("owner")),
        };
        let grant_cid = store.issue_attest(grant).unwrap();
        let assignment = pillar_topology::Assignment::attested(
            auth.clone(),
            node.clone(),
            &Label::new("region", "east"),
            Capacity::Role {
                role: "cell-authority".to_owned(),
                scope: "cell-b".to_owned(),
            },
            Some(grant_cid),
            "cell-b",
            store.epoch(),
        );
        if let pillar_topology::Assignment::Attested { attest, .. } = &assignment {
            store.issue_attest((**attest).clone()).unwrap();
        }
        topo.attest(&assignment, &store).unwrap();

        let mut ipam = TopologyScopedIpam::new(topo, "region").unwrap();
        ipam.bind_pool("west", Pool::new(v4("10.1.0.0"), 256), 3);
        ipam.bind_pool("east", Pool::new(v4("10.2.0.0"), 256), 3);

        // The node is scoped to EAST (attested), so a west address is refused
        // and an east address is accepted.
        let east = v4("10.2.0.7");
        ipam.grant_for(n("va"), &node, east).unwrap();
        ipam.grant_for(n("vb"), &node, east).unwrap();
        assert!(ipam.allocate_for(&node, east).unwrap());
        assert_eq!(
            ipam.allocate_for(&node, v4("10.1.0.7")),
            Err(ScopedError::Alloc(AllocError::OutOfPool {
                addr: v4("10.1.0.7")
            }))
        );
    }
}
