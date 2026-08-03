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
}
