//! streamdb performance benchmark harness (ROI P1 "Streamdb performance is a
//! standing, self-perpetuating discipline", `streamdb-perf-benchmark-recurring`).
//!
//! Measures op-path throughput/latency (seal + open) and view-fold cost
//! (`OpLog::root`) through BOTH `Confidentiality` visibility profiles side by
//! side:
//!
//!   * `Public` (unencrypted, `public-visibility-class`) — the throughput/
//!     latency CEILING and fixed BASELINE.
//!   * `CellEncrypted` — the guaranteed-confidentiality profile.
//!
//! The public<->encrypted delta is tracked as a first-class metric: it IS the
//! AEAD seal/unseal overhead, isolated from the signing + content-addressing
//! cost both profiles pay identically. Neither profile's signature/hash/seal
//! step is ever skipped to "speed up" a run — a change that dropped one would
//! be a correctness bug, not an optimization (see the task's HARD INVARIANT).
//!
//! Invoked by `scripts/streamdb-perf-benchmark.sh`, which loads/writes the
//! tracked baseline at `scripts/streamdb-perf-baseline.txt` and turns a
//! regression beyond tolerance into a non-zero exit.
//!
//! Output: one `key=value` line per metric on stdout (plain, greppable,
//! diffable — no serde/json dependency needed for a handful of scalars).

use std::env;
use std::time::Instant;

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed};
use pillar_streamdb::pillarmsg::{open_stream_op, seal_stream_op, Confidentiality};
use pillar_streamdb::{OpLog, Visibility};

/// Number of ops sealed/opened per profile for the op-path throughput
/// measurement. Kept modest so the recurring daily run stays fast and cheap
/// on shared CI hardware while still giving a stable-enough signal (a few
/// thousand AEAD/Ed25519 ops is well past JIT/cache warmup noise).
const DEFAULT_OP_COUNT: usize = 4_000;

/// Number of ops folded (`OpLog::root`) per profile for the view-fold cost
/// measurement.
const DEFAULT_FOLD_COUNT: usize = 4_000;

struct ProfileResult {
    seal_ops_per_sec: f64,
    open_ops_per_sec: f64,
    fold_ops_per_sec: f64,
}

fn bench_profile(confidentiality: Confidentiality, op_count: usize, fold_count: usize) -> ProfileResult {
    let seed_label = match confidentiality {
        Confidentiality::Public => "streamdb-perf-bench::public",
        Confidentiality::CellEncrypted => "streamdb-perf-bench::cell-encrypted",
    };
    let group = group_key_from_seed(&Seed::from_bytes(seed_label.as_bytes().to_vec()))
        .expect("cell group key");
    let cell = CellId::from_bytes(format!("cell::{seed_label}").into_bytes());
    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(format!("{seed_label}::signer").into_bytes()))
            .expect("signing keypair");

    // Pre-build distinct payloads (a real gossip workload never re-seals the
    // identical payload back to back) so the convergent-seal fast path is
    // exercised the same way for every op, in both profiles.
    let payloads: Vec<Vec<u8>> = (0..op_count.max(fold_count))
        .map(|i| format!("streamdb-perf-bench op payload #{i}").into_bytes())
        .collect();

    // --- seal throughput ---
    let seal_started = Instant::now();
    let mut envelopes = Vec::with_capacity(op_count);
    for payload in payloads.iter().take(op_count) {
        let msg = seal_stream_op(
            payload,
            Some(&group),
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
            confidentiality,
        )
        .expect("seal_stream_op");
        envelopes.push(msg);
    }
    let seal_elapsed = seal_started.elapsed();
    let seal_ops_per_sec = op_count as f64 / seal_elapsed.as_secs_f64();

    // --- open throughput (round-trips every sealed envelope back to plaintext) ---
    let open_started = Instant::now();
    for (msg, payload) in envelopes.iter().zip(payloads.iter()) {
        let opened = open_stream_op(msg, Some(&group), confidentiality).expect("open_stream_op");
        assert_eq!(&opened, payload, "opened payload must match sealed payload");
    }
    let open_elapsed = open_started.elapsed();
    let open_ops_per_sec = op_count as f64 / open_elapsed.as_secs_f64();

    // --- view-fold cost: seal+open the fold workload, then fold it into an
    // OpLog's Merkle root — the same op-path cost this profile pays PLUS the
    // materialized-view fold, so the measurement reflects the full
    // profile-dependent pipeline a real peer runs, not just the crypto in
    // isolation.
    let fold_started = Instant::now();
    let mut log = OpLog::new();
    for payload in payloads.iter().take(fold_count) {
        let msg = seal_stream_op(
            payload,
            Some(&group),
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
            confidentiality,
        )
        .expect("seal_stream_op");
        let opened = open_stream_op(&msg, Some(&group), confidentiality).expect("open_stream_op");
        log.append(opened);
    }
    let _root = log.root();
    let fold_elapsed = fold_started.elapsed();
    let fold_ops_per_sec = fold_count as f64 / fold_elapsed.as_secs_f64();

    ProfileResult {
        seal_ops_per_sec,
        open_ops_per_sec,
        fold_ops_per_sec,
    }
}

fn parse_count_arg(name: &str, default: usize) -> usize {
    let flag = format!("--{name}");
    let args: Vec<String> = env::args().collect();
    for i in 0..args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                return v.parse().unwrap_or(default);
            }
        }
    }
    default
}

fn main() {
    let op_count = parse_count_arg("ops", DEFAULT_OP_COUNT);
    let fold_count = parse_count_arg("fold-ops", DEFAULT_FOLD_COUNT);

    let public = bench_profile(Confidentiality::Public, op_count, fold_count);
    let encrypted = bench_profile(Confidentiality::CellEncrypted, op_count, fold_count);

    // The public profile is the ceiling/baseline; the encrypted-vs-public
    // delta (percentage SLOWER than public) isolates the AEAD seal/unseal
    // overhead from the signing+hashing cost both profiles pay.
    let seal_delta_pct =
        (public.seal_ops_per_sec - encrypted.seal_ops_per_sec) / public.seal_ops_per_sec * 100.0;
    let open_delta_pct =
        (public.open_ops_per_sec - encrypted.open_ops_per_sec) / public.open_ops_per_sec * 100.0;
    let fold_delta_pct =
        (public.fold_ops_per_sec - encrypted.fold_ops_per_sec) / public.fold_ops_per_sec * 100.0;

    println!("op_count={op_count}");
    println!("fold_count={fold_count}");
    println!("public_seal_ops_per_sec={:.2}", public.seal_ops_per_sec);
    println!("public_open_ops_per_sec={:.2}", public.open_ops_per_sec);
    println!("public_fold_ops_per_sec={:.2}", public.fold_ops_per_sec);
    println!(
        "encrypted_seal_ops_per_sec={:.2}",
        encrypted.seal_ops_per_sec
    );
    println!(
        "encrypted_open_ops_per_sec={:.2}",
        encrypted.open_ops_per_sec
    );
    println!(
        "encrypted_fold_ops_per_sec={:.2}",
        encrypted.fold_ops_per_sec
    );
    println!("seal_delta_pct={seal_delta_pct:.2}");
    println!("open_delta_pct={open_delta_pct:.2}");
    println!("fold_delta_pct={fold_delta_pct:.2}");
}
