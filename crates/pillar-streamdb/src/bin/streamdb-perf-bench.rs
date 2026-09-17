//! `streamdb-perf-bench` — the fixed rig `scripts/streamdb-perf-benchmark.sh`
//! drives (ROI Priority 1 "Streamdb performance is a standing,
//! self-perpetuating discipline"; `streamdb-perf-benchmark` in `CHECKS.md`).
//!
//! Measures per-op throughput/latency for the streamdb op path
//! ([`pillar_streamdb::seal_stream_op`]) under BOTH visibility/confidentiality
//! profiles side by side:
//!
//! - **public** — [`Confidentiality::Public`]: no AEAD seal, still signed +
//!   content-addressed. The throughput/latency CEILING and fixed baseline.
//! - **cell** — [`Confidentiality::CellEncrypted`]: the same signed +
//!   content-addressed op, ADDITIONALLY AEAD-sealed to the cell group key.
//!
//! Both profiles pay the same signing + content-addressing cost; the
//! measured `cell - public` delta therefore isolates the pure AEAD
//! seal/unseal overhead as a first-class metric, independent of the shared
//! non-crypto hot path.
//!
//! Also measures the op-log's view-fold cost ([`pillar_streamdb::OpLog::root`])
//! — the Merkle-root materialization every appended op set pays.
//!
//! Emits one JSON object on stdout with nanosecond-per-op medians for each
//! measured stage, plus the `cell - public` delta, for `scripts/
//! streamdb-perf-benchmark.sh` to compare against the tracked baseline.
//!
//! No behavior asserted here beyond the CRDT/crypto contracts already proven
//! by the crate's own test suite — this binary only TIMES the real,
//! already-verified op-build/seal/sign/fold path; it invents no new
//! plaintext-vs-ciphertext shortcut and drops no guarantee.

use std::time::Instant;

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed};
use pillar_streamdb::{seal_stream_op, Confidentiality, OpLog, Visibility};

/// Number of op iterations measured per profile. Fixed so successive runs on
/// the same machine are comparable; override via `STREAMDB_PERF_ITERS` for a
/// quick local smoke run.
fn iterations() -> usize {
    std::env::var("STREAMDB_PERF_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000)
}

/// A realistic op payload: fixed size, distinct per iteration (so content
/// addressing/hashing never short-circuits on a repeated address).
fn payload(i: usize) -> Vec<u8> {
    let mut p = format!("streamdb-perf-bench/op/{i}/").into_bytes();
    p.extend(std::iter::repeat_n(0xABu8, 256));
    p
}

/// Median of a duration sample, in whole nanoseconds.
fn median_ns(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2
    }
}

/// Time `iterations()` runs of `seal_stream_op` under `confidentiality`,
/// returning the median per-op latency in nanoseconds.
fn bench_stream_op(confidentiality: Confidentiality) -> u128 {
    let group = group_key_from_seed(&Seed::from_bytes(b"streamdb-perf-bench/cell".to_vec()))
        .expect("derive cell group key");
    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(b"streamdb-perf-bench/signer".to_vec()))
            .expect("derive signing keypair");
    let cell = CellId::from_bytes(b"streamdb-perf-bench/cell-id".to_vec());

    let n = iterations();
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let payload = payload(i);
        let start = Instant::now();
        let msg = seal_stream_op(
            &payload,
            Some(&group),
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
            confidentiality,
        )
        .expect("seal_stream_op");
        std::hint::black_box(&msg);
        samples.push(start.elapsed().as_nanos());
    }
    median_ns(samples)
}

/// Time the view-fold cost: appending `n` ops to an [`OpLog`] and
/// materializing its Merkle root ([`OpLog::root`]), the deterministic fold
/// over the content-ordered op set every read pays.
fn bench_view_fold() -> u128 {
    let n = iterations();
    let mut log = OpLog::new();
    for i in 0..n {
        log.append(payload(i));
    }
    let start = Instant::now();
    let root = log.root();
    let elapsed = start.elapsed().as_nanos();
    std::hint::black_box(&root);
    // Per-op cost of a full-log fold, so it is comparable across differently
    // sized runs.
    elapsed / n.max(1) as u128
}

fn main() {
    let public_ns = bench_stream_op(Confidentiality::Public);
    let cell_ns = bench_stream_op(Confidentiality::CellEncrypted);
    let fold_ns = bench_view_fold();
    let delta_ns = cell_ns.saturating_sub(public_ns);

    println!(
        "{{\"iterations\":{},\"public_op_ns\":{},\"cell_op_ns\":{},\"encryption_delta_ns\":{},\"view_fold_ns_per_op\":{}}}",
        iterations(),
        public_ns,
        cell_ns,
        delta_ns,
        fold_ns,
    );
}
