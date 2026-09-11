//! Acceptance suite for CROSS-TOPOLOGY-DOMAIN MULTIPLEXING for aggregate
//! throughput (2026-09-09 ROI HEAD).
//!
//! One logical transfer (a blob / stream range / PSL reply) is split into
//! block-aligned, CID-verified chunks served INTERLEAVED from multiple sender
//! nodes drawn from dispersed topology domains; the client reassembles by
//! offset+CID. The block->sender map is TRACKERLESS and sender-coordinated:
//! derived deterministically from the transfer CID + the topology/membership
//! view (the same budgeted mechanism as the reply-set spray), so senders and
//! client agree with no round-trip. Erasure coding (any K of N) covers a
//! slow/lost path.
//!
//! The tests pin BOTH the ROI acceptance clauses:
//!   1. with per-source upstream capped BELOW the client downlink, the modeled
//!      aggregate throughput EXCEEDS any single sender path (a real aggregate),
//!      and multiplexing buys NOTHING when the client last-mile downlink is the
//!      bottleneck (the honest bound); and
//!   2. the client reassembles the EXACT bytes even under induced single-path
//!      loss, via K-of-N erasure recovery of the lost path's blocks.
//!
//! Each test fails without the multiplex plan / reassembler / aggregate model
//! and passes with them. Gated behind the `acceptance` feature (off by default).
#![cfg(feature = "acceptance")]

use pillar_core::NodeId;
use pillar_net::pillar_udp::{
    encode, reconstruct, AggregateThroughput, Cid, MultiplexError, MultiplexPlan,
    MultiplexReassembler, PathBandwidth,
};

fn n(s: &str) -> NodeId {
    NodeId::from(s)
}

/// A synthetic multi-domain transfer: a blob whose bytes are deterministic so
/// its CID (and thus its block map) is stable across a run.
fn transfer_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
        .collect()
}

/// Four sender nodes standing in for four dispersed topology failure domains.
fn four_domain_senders() -> Vec<NodeId> {
    vec![n("west-a"), n("east-b"), n("north-c"), n("south-d")]
}

// ---------------------------------------------------------------------------
// Deterministic, trackerless block map (transfer CID + sender view).
// ---------------------------------------------------------------------------

/// The block->sender map is a PURE function of the transfer CID + sender view:
/// a sender and the client computing it independently agree bit-for-bit, with
/// no coordination round-trip (the trackerless, sender-coordinated invariant).
#[test]
fn block_map_is_deterministic_across_independent_computations() {
    let data = transfer_bytes(40_000);
    let block = 4096;

    // Two independent computations over the SAME view (e.g. a sender and the
    // client), and a third where the sender view is presented in a DIFFERENT
    // order (normalization must make it identical).
    let plan_a = MultiplexPlan::derive(&data, block, four_domain_senders()).unwrap();
    let plan_b = MultiplexPlan::derive(&data, block, four_domain_senders()).unwrap();
    let shuffled = vec![n("south-d"), n("west-a"), n("north-c"), n("east-b")];
    let plan_c = MultiplexPlan::derive(&data, block, shuffled).unwrap();

    assert_eq!(
        plan_a, plan_b,
        "two nodes over the same view agree bit-for-bit"
    );
    assert_eq!(
        plan_a, plan_c,
        "sender-view order is normalized: same map regardless of presentation order"
    );
    assert_eq!(plan_a.transfer_cid, Cid::of(&data));
}

/// Blocks are served INTERLEAVED across DISPERSED senders: consecutive blocks
/// rotate to distinct senders and the fan-out uses EVERY path in the view (real
/// multi-path spread, not a single degenerate path).
#[test]
fn blocks_interleave_across_all_dispersed_paths() {
    let data = transfer_bytes(40_000);
    let block = 4096; // 10 blocks over 4 senders
    let senders = four_domain_senders();
    let plan = MultiplexPlan::derive(&data, block, senders.clone()).unwrap();

    assert_eq!(
        plan.active_paths(),
        senders.len(),
        "every dispersed sender path serves at least one block"
    );
    // Consecutive blocks rotate to different senders (interleaved spray).
    for w in plan.blocks.windows(2) {
        assert_ne!(
            w[0].sender, w[1].sender,
            "consecutive blocks are served by distinct senders"
        );
    }
    // Every block is block-aligned and covers the transfer contiguously.
    let mut expect_off = 0usize;
    for b in &plan.blocks {
        assert_eq!(
            b.offset, expect_off,
            "blocks are contiguous & block-aligned"
        );
        assert_eq!(b.cid, Cid::of(&data[b.offset..b.offset + b.len]));
        expect_off += b.len;
    }
    assert_eq!(expect_off, data.len(), "blocks cover the whole transfer");
}

// ---------------------------------------------------------------------------
// CID-verified reassembly by offset+CID (any arrival order, corruption rejected).
// ---------------------------------------------------------------------------

/// The client reassembles the EXACT transfer by offset+CID from blocks that
/// arrive out of order and interleaved from every path — and a CORRUPTED /
/// mis-delivered block is REJECTED, never admitted into the reassembly.
#[test]
fn client_reassembles_exact_bytes_by_offset_and_cid_rejecting_corruption() {
    let data = transfer_bytes(40_000);
    let block = 4096;
    let plan = MultiplexPlan::derive(&data, block, four_domain_senders()).unwrap();
    let mut asm = MultiplexReassembler::new(&plan);

    // A corrupted block is rejected (wrong CID) and does NOT get stored.
    let victim = &plan.blocks[3];
    let mut bad = data[victim.offset..victim.offset + victim.len].to_vec();
    bad[0] ^= 0xFF;
    assert_eq!(
        asm.accept(victim.index, &bad),
        Err(MultiplexError::CidMismatch(victim.index)),
        "a corrupted block is rejected on CID mismatch"
    );

    // Deliver every block in REVERSE (out-of-order, interleaved) order.
    for b in plan.blocks.iter().rev() {
        let bytes = &data[b.offset..b.offset + b.len];
        asm.accept(b.index, bytes).expect("valid block accepted");
    }
    assert!(asm.is_complete(), "all blocks received & verified");
    assert_eq!(
        asm.reassemble().unwrap(),
        data,
        "reassembled bytes are EXACT"
    );
}

// ---------------------------------------------------------------------------
// Acceptance clause 1: honest aggregate-throughput bound.
// ---------------------------------------------------------------------------

/// With per-source upstream capped BELOW the client downlink (and their sum
/// still under it), the modeled aggregate throughput is the SUM of the paths —
/// STRICTLY MORE than any single sender path. A REAL aggregate win.
#[test]
fn aggregate_exceeds_single_path_when_per_source_upstream_is_the_bottleneck() {
    // Four sender paths at 25 units each; client downlink is a generous 1000
    // (well above the 100-unit sum) — the bottleneck is per-source upstream.
    let paths = vec![
        PathBandwidth {
            sender_upstream: 25.0,
        },
        PathBandwidth {
            sender_upstream: 25.0,
        },
        PathBandwidth {
            sender_upstream: 25.0,
        },
        PathBandwidth {
            sender_upstream: 25.0,
        },
    ];
    let agg = AggregateThroughput::new(paths, 1000.0);

    assert!(
        !agg.client_downlink_is_bottleneck(),
        "per-source upstream (not the downlink) is the bottleneck here"
    );
    assert_eq!(
        agg.realized(),
        100.0,
        "aggregate == sum of per-path upstreams"
    );
    assert_eq!(
        agg.best_single_path(),
        25.0,
        "a single path delivers only 25"
    );
    assert!(
        agg.beats_single_path(),
        "multiplexing beats any single sender path: {} > {}",
        agg.realized(),
        agg.best_single_path()
    );
    assert!(
        agg.realized() > agg.best_single_path() * 3.0,
        "four capped paths deliver ~4x the single-path rate"
    );
}

/// The HONEST bound: when the CLIENT LAST-MILE DOWNLINK is the bottleneck,
/// multiplexing buys NOTHING beyond it — the aggregate is capped at the
/// downlink and does not beat the (also downlink-capped) single path.
#[test]
fn aggregate_buys_nothing_when_client_downlink_is_the_bottleneck() {
    // Four fast paths (1000 each, sum 4000) but a narrow 40-unit client
    // downlink: the last mile, not the senders, is the limit.
    let paths = vec![
        PathBandwidth {
            sender_upstream: 1000.0,
        },
        PathBandwidth {
            sender_upstream: 1000.0,
        },
        PathBandwidth {
            sender_upstream: 1000.0,
        },
        PathBandwidth {
            sender_upstream: 1000.0,
        },
    ];
    let agg = AggregateThroughput::new(paths, 40.0);

    assert!(
        agg.client_downlink_is_bottleneck(),
        "the client downlink is the bottleneck here"
    );
    assert_eq!(
        agg.realized(),
        40.0,
        "aggregate is capped at the client downlink"
    );
    assert_eq!(
        agg.best_single_path(),
        40.0,
        "even a single fast path is downlink-capped to 40"
    );
    assert!(
        !agg.beats_single_path(),
        "multiplexing buys NOTHING when the downlink is the bottleneck (honest bound)"
    );
}

// ---------------------------------------------------------------------------
// Acceptance clause 2: exact bytes under induced single-path loss (K-of-N EC).
// ---------------------------------------------------------------------------

/// Under INDUCED single-path loss — one sender's blocks never arrive — the
/// client still reassembles the EXACT transfer: each lost block is recovered
/// K-of-N from erasure shards served by the OTHER (surviving) paths.
#[test]
fn exact_bytes_under_induced_single_path_loss_via_erasure_recovery() {
    let data = transfer_bytes(40_000);
    let block = 4096;
    let senders = four_domain_senders();
    let plan = MultiplexPlan::derive(&data, block, senders.clone()).unwrap();

    // Induce total loss of ONE dispersed path: pick the sender owning the most
    // blocks and drop every block it was assigned.
    let dropped = senders
        .iter()
        .max_by_key(|s| plan.blocks_for(s).len())
        .cloned()
        .unwrap();
    let dropped_indices: std::collections::HashSet<usize> =
        plan.blocks_for(&dropped).iter().map(|b| b.index).collect();
    assert!(
        !dropped_indices.is_empty(),
        "the dropped path owned real blocks"
    );

    let mut asm = MultiplexReassembler::new(&plan);

    for b in &plan.blocks {
        let block_bytes = &data[b.offset..b.offset + b.len];
        if dropped_indices.contains(&b.index) {
            // This block's DIRECT path is lost. Recover it K-of-N from erasure
            // shards the surviving paths served for THIS block: K=3 data + 1
            // parity, then drop one data shard (the lost direct copy) and
            // reconstruct from the parity served by another path.
            let k = 3;
            let m = 1;
            let mut shards = encode(block_bytes, k, m).expect("block erasure-encoded");
            // Simulate the lost data shard (index 0) never arriving; the parity
            // shard (index k) arrives from a surviving dispersed path.
            shards.remove(0);
            let recovered =
                reconstruct(&shards, k, block_bytes.len()).expect("K-of-N recovers the block");
            assert_eq!(recovered, block_bytes, "erasure-recovered block is exact");
            asm.accept(b.index, &recovered)
                .expect("recovered block passes CID verification");
        } else {
            // Surviving direct path delivers the block normally.
            asm.accept(b.index, block_bytes)
                .expect("surviving block accepted");
        }
    }

    assert!(
        asm.is_complete(),
        "every block present after erasure recovery of the lost path"
    );
    assert_eq!(
        asm.reassemble().unwrap(),
        data,
        "bytes EXACT under induced single-path loss"
    );
}

/// The reassembler refuses to hand back a transfer while any block is still
/// missing — completeness is enforced, never a silently-truncated result.
#[test]
fn incomplete_reassembly_is_refused_not_silently_truncated() {
    let data = transfer_bytes(20_000);
    let block = 4096;
    let plan = MultiplexPlan::derive(&data, block, four_domain_senders()).unwrap();
    let mut asm = MultiplexReassembler::new(&plan);

    // Deliver all but the last block.
    for b in &plan.blocks[..plan.blocks.len() - 1] {
        asm.accept(b.index, &data[b.offset..b.offset + b.len])
            .unwrap();
    }
    assert!(!asm.is_complete());
    assert_eq!(asm.missing(), 1);
    assert_eq!(
        asm.reassemble(),
        Err(MultiplexError::Incomplete { missing: 1 }),
        "reassembly refused with a block still missing"
    );
}
