//! Streamdb performance harness — the measured half of the recurring
//! `streamdb-perf-benchmark` discipline (ROI P1 "Streamdb performance is a
//! standing, self-perpetuating discipline").
//!
//! It exercises the REAL streamdb hot paths against a fixed, deterministic
//! workload and emits a machine-readable JSON metrics blob on stdout that
//! `scripts/streamdb-perf-benchmark.sh` compares to the tracked baseline:
//!
//!   * `append_ns_per_op` — cost of appending an op (content-address +
//!     BTreeMap insert), the write hot path.
//!   * `view_fold_ns_per_op` — amortized per-op cost of materializing the view
//!     (`order()` + the cryptographic `root()` fold), the read/verify hot path.
//!   * `merge_ns_per_op` — amortized per-op cost of the CvRDT gossip join
//!     (`OpLog::merge` set-union).
//!   * `compact_ns_per_op` — amortized per-op cost of `compact()` (snapshot the
//!     full op set + fold its root).
//!
//! HARD INVARIANT (carried by the whole discipline): every measurement runs the
//! REAL primitives — a real SHA2-256 content address per op and a real
//! hash-chain Merkle fold for the view root. This harness must NEVER stub,
//! shortcut, or weaken any of them to make a number look better; a "speedup"
//! that drops a hash/signature/seal is a bug, not an optimization. To make that
//! non-negotiable the harness itself asserts, before timing, that the view root
//! is a real content-derived commitment (it changes when the op set changes and
//! is a full-width digest), and aborts if that guarantee does not hold.
//!
//! Run: `cargo run -p pillar-streamdb --example perf_bench --release -- [N]`
//! where `N` is the op count (default 5000). Output is a single JSON object.
//!
//! Rig/noise robustness: the swarm's sandbox runs on shared, often-throttled
//! CPUs where raw ns/op can swing by an order of magnitude run-to-run — not a
//! real regression, just contention. Two mitigations, both load-bearing for the
//! discipline to mean anything in this environment:
//!   1. Every metric is measured as the MIN of several independent trials (a
//!      contention/scheduler blip only ever makes a trial slower, never
//!      faster, so the min is the closest single number gets to "the real
//!      cost on quiet hardware").
//!   2. A `calib_ns_per_op` figure (a fixed, allocation-free integer workload
//!      with no streamdb code in it) is measured the same way in the same
//!      process and emitted alongside the streamdb metrics. The shell harness
//!      compares BASELINE-RELATIVE-TO-ITS-OWN-CALIBRATION ratios
//!      (metric/calib) rather than raw ns/op, which cancels out the rig's
//!      absolute clock speed / throttling state at measurement time.

use std::time::Instant;

use pillar_core::SideEffect;
use pillar_streamdb::{OpLog, Stream};

/// Run `f` `trials` times and return the MINIMUM elapsed-ns/op observed (the
/// least-contended sample), not the mean — a scheduler/contention blip can
/// only ever slow a trial down, never speed it up, so the min best isolates
/// steady-state cost from sandbox noise.
fn min_of_trials<F: FnMut() -> f64>(trials: usize, mut f: F) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..trials {
        let v = f();
        if v < best {
            best = v;
        }
    }
    best
}

/// A fixed, streamdb-free integer workload used purely to gauge this run's CPU
/// throughput, so the streamdb metrics can be reported relative to it instead
/// of as raw wall-clock ns (which swings with rig speed / throttling).
fn calibration_ns_per_op(reps: usize) -> f64 {
    min_of_trials(3, || {
        let t = Instant::now();
        let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..reps {
            acc = acc
                .wrapping_mul(0xA24B_AED4_963E_E407)
                .wrapping_add(i as u64);
            acc ^= acc.rotate_left(17);
        }
        std::hint::black_box(acc);
        t.elapsed().as_nanos() as f64 / reps as f64
    })
}

/// Deterministic, distinct payloads so every op has a distinct content address
/// (a realistic op set with no accidental dedup collapsing the work).
fn payload(i: usize) -> Vec<u8> {
    // 64 bytes, seeded by the index so the SHA2-256 address is well-distributed
    // and the BTreeMap ordering is non-trivial.
    let mut v = Vec::with_capacity(64);
    let seed = (i as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1234_5678_9ABC_DEF0);
    for k in 0..8u64 {
        let word = seed.wrapping_add(k.wrapping_mul(0xA24B_AED4_963E_E407));
        v.extend_from_slice(&word.to_le_bytes());
    }
    v
}

/// Assert the view root is a REAL cryptographic commitment before we time it,
/// so the discipline's hard invariant can never silently rot into a stubbed
/// fold. Aborts the harness (non-zero) if any guarantee is missing.
fn assert_real_crypto_root() {
    let mut a = OpLog::new();
    for i in 0..64 {
        a.append(payload(i));
    }
    let root_a = a.root();
    // Full-width: a real SHA2-256-based commitment is at least 32 bytes.
    assert!(
        root_a.as_bytes().len() >= 32,
        "view root is not a full-width (>=256-bit) digest: {} bytes — the fold has been weakened",
        root_a.as_bytes().len()
    );
    // Content-derived: changing the op set MUST change the root. A stub that
    // returns a constant (or a non-cryptographic mix) would fail here.
    let mut b = a.clone();
    b.append(payload(9_999));
    assert_ne!(
        root_a.as_bytes(),
        b.root().as_bytes(),
        "view root did not change when an op was added — the fold is not a real commitment"
    );
    // Deterministic in the set alone: same set, same root regardless of path.
    let mut c = OpLog::new();
    for i in (0..64).rev() {
        c.append(payload(i));
    }
    assert_eq!(
        root_a.as_bytes(),
        c.root().as_bytes(),
        "view root is not a pure function of the op set — determinism guarantee broken"
    );
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    assert!(
        n >= 16,
        "op count N must be >= 16 for a meaningful measurement"
    );

    // Guarantee gate: refuse to report numbers if the real crypto has regressed.
    assert_real_crypto_root();

    // A fixed, streamdb-free workload measured the same way (min-of-trials) in
    // this same process, so the metrics below can be reported relative to this
    // run's actual CPU throughput instead of raw wall-clock ns.
    let calib_ns_per_op = calibration_ns_per_op(2_000_000.max(n));

    // --- append hot path (via the policy-checked Stream::try_append, the real
    //     write surface a caller uses). ---
    let append_ns_per_op = min_of_trials(3, || {
        let mut stream = Stream::new();
        let t = Instant::now();
        for i in 0..n {
            // try_append runs the same content-address + insert as OpLog::append,
            // plus the view-policy admission check — the real caller path.
            stream
                .try_append(payload(i), SideEffect::Convergent)
                .expect("default view policy admits a convergent append");
        }
        let elapsed = t.elapsed().as_nanos() as f64 / n as f64;
        assert_eq!(stream.log().len(), n, "every distinct op must be retained");
        elapsed
    });

    // Build a plain OpLog with the same set for the fold/merge/compact paths.
    let mut log = OpLog::new();
    for i in 0..n {
        log.append(payload(i));
    }

    // --- view-fold hot path: materialized order + cryptographic root. ---
    // Repeat so a small N still yields a stable per-op number.
    let fold_reps = (1_000_000 / n).max(1);
    let view_fold_ns_per_op = min_of_trials(3, || {
        let t = Instant::now();
        let mut acc = 0u8;
        for _ in 0..fold_reps {
            let view = log.order();
            let root = log.root();
            // touch the results so the optimizer cannot elide the fold.
            acc ^= root.as_bytes()[0] ^ (view.len() as u8);
        }
        let elapsed = t.elapsed().as_nanos() as f64 / (fold_reps as f64 * n as f64);
        std::hint::black_box(acc);
        elapsed
    });

    // --- merge hot path: CvRDT gossip join of two half-overlapping logs. ---
    let mut left = OpLog::new();
    let mut right = OpLog::new();
    for i in 0..n {
        if i % 2 == 0 {
            left.append(payload(i));
        }
        right.append(payload(i)); // right holds the full set; ~half is new to left
    }
    let merge_reps = (200_000 / n).max(1);
    let merge_ns_per_op = min_of_trials(3, || {
        let t = Instant::now();
        for _ in 0..merge_reps {
            let mut dst = left.clone();
            dst.merge(&right);
            std::hint::black_box(dst.len());
        }
        // amortized over the ops examined per merge (the full right set).
        t.elapsed().as_nanos() as f64 / (merge_reps as f64 * n as f64)
    });

    // --- compact hot path: snapshot the full set + fold its root. ---
    let compact_reps = (200_000 / n).max(1);
    let compact_ns_per_op = min_of_trials(3, || {
        let t = Instant::now();
        for _ in 0..compact_reps {
            let snap = log.compact();
            std::hint::black_box(snap.len());
        }
        t.elapsed().as_nanos() as f64 / (compact_reps as f64 * n as f64)
    });

    // Single-line JSON object (stable key order) for the shell harness to parse.
    println!(
        "{{\"schema\":1,\"n\":{},\"calib_ns_per_op\":{:.6},\"append_ns_per_op\":{:.3},\"view_fold_ns_per_op\":{:.3},\"merge_ns_per_op\":{:.3},\"compact_ns_per_op\":{:.3}}}",
        n, calib_ns_per_op, append_ns_per_op, view_fold_ns_per_op, merge_ns_per_op, compact_ns_per_op
    );
}
