//! streamdb performance benchmark harness (`streamdb-perf-benchmark`,
//! `scripts/streamdb-perf-benchmark.sh`).
//!
//! Measures op-path throughput/latency (seal+sign -> append -> open+verify)
//! AND view-fold cost (`OpLog::root`) through BOTH visibility profiles side
//! by side: [`Confidentiality::Public`] (unencrypted — still signed +
//! content-addressed) is the throughput/latency CEILING and the fixed
//! baseline; [`Confidentiality::CellEncrypted`] is the guaranteed-
//! confidentiality profile. The public<->encrypted DELTA is tracked as a
//! first-class metric: it IS the AEAD seal/unseal overhead, isolated from the
//! signing/hashing cost both profiles pay.
//!
//! Compares this run's measurements against a tracked baseline JSON file
//! (`crates/pillar-streamdb/benches/perf-baseline.json`, hand-editable/plain
//! text, no serde dependency needed for this tiny fixed schema). On first run
//! (no baseline file yet) this program WRITES the baseline and exits 0
//! (bootstrapping). On subsequent runs it exits non-zero only if a metric
//! regresses beyond `REGRESSION_TOLERANCE` against the tracked baseline,
//! printing the regressed metric(s) so a recurring task can file a concrete
//! tuning follow-up.
//!
//! No behavior/guarantee is ever weakened to "speed up" this benchmark: both
//! profiles always sign every op and verify every open; only the AEAD cell
//! seal is elided for `Public`.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed};
use pillar_streamdb::pillarmsg::{open_stream_op, seal_stream_op, Confidentiality};
use pillar_streamdb::store::Visibility;
use pillar_streamdb::OpLog;

/// Number of ops sealed/opened per profile per run. Small enough to run in a
/// few hundred ms in CI, large enough to average out noise.
const OP_COUNT: usize = 500;

/// Number of ops folded (via `OpLog::root`) per profile per run, to measure
/// view-fold cost independent of op-path seal/sign cost.
const FOLD_OP_COUNT: usize = 2000;

/// A metric is a regression only if it degrades by more than this fraction
/// versus the tracked baseline (guards against normal CI-noise jitter).
const REGRESSION_TOLERANCE: f64 = 0.35;

/// One profile's measured op-path + fold metrics, in whole nanoseconds
/// (integer, so the baseline file needs no float parsing).
#[derive(Clone, Copy, Debug)]
struct ProfileMetrics {
    /// Mean nanoseconds per op through seal+sign -> open+verify (round trip).
    op_ns: u64,
    /// Mean nanoseconds per op folded into `OpLog::root`.
    fold_ns: u64,
}

struct Report {
    public: ProfileMetrics,
    encrypted: ProfileMetrics,
}

fn measure_profile(confidentiality: Confidentiality) -> ProfileMetrics {
    let cell = CellId::from_bytes(b"streamdb-perf-benchmark::cell".to_vec());
    let (signer, secret) = signing_keypair_from_seed(&Seed::from_bytes(
        b"streamdb-perf-benchmark::signer".to_vec(),
    ))
    .expect("keygen");
    let group = group_key_from_seed(&Seed::from_bytes(
        b"streamdb-perf-benchmark::cell-group".to_vec(),
    ))
    .expect("cell key");
    let group_ref = match confidentiality {
        Confidentiality::CellEncrypted => Some(&group),
        Confidentiality::Public => None,
    };

    // Op-path: seal+sign then open+verify, round-tripped, timed together as
    // the unit an application op actually pays.
    let payload = vec![0x5au8; 256];
    let started = Instant::now();
    for i in 0..OP_COUNT {
        let mut this_payload = payload.clone();
        this_payload.extend_from_slice(&(i as u64).to_be_bytes());
        let msg = seal_stream_op(
            &this_payload,
            group_ref,
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Public,
            confidentiality,
        )
        .expect("seal");
        let opened = open_stream_op(&msg, group_ref, confidentiality).expect("open");
        assert_eq!(opened, this_payload, "round trip must recover payload");
    }
    let op_ns = (started.elapsed().as_nanos() / OP_COUNT as u128) as u64;

    // View-fold cost: append FOLD_OP_COUNT distinct ops to a fresh log, time
    // `root()` alone (append cost is excluded — this isolates the fold).
    let mut log = OpLog::new();
    for i in 0..FOLD_OP_COUNT {
        let mut this_payload = payload.clone();
        this_payload.extend_from_slice(&(i as u64).to_be_bytes());
        log.append(this_payload);
    }
    let started = Instant::now();
    let _root = log.root();
    let fold_ns = (started.elapsed().as_nanos() / FOLD_OP_COUNT as u128) as u64;

    ProfileMetrics { op_ns, fold_ns }
}

fn run() -> Report {
    Report {
        public: measure_profile(Confidentiality::Public),
        encrypted: measure_profile(Confidentiality::CellEncrypted),
    }
}

fn baseline_path() -> PathBuf {
    // Resolve relative to this source file's crate root so the harness works
    // regardless of the caller's cwd (the wrapping shell script always runs
    // it via `cargo run`, whose cwd is the crate/workspace root either way).
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| "crates/pillar-streamdb".to_string());
    PathBuf::from(manifest_dir).join("benches/perf-baseline.json")
}

/// Minimal hand-rolled parse/format for the tiny fixed schema below — no
/// serde dependency needed for four integers.
fn format_report(r: &Report) -> String {
    format!(
        "{{\n  \"public_op_ns\": {},\n  \"public_fold_ns\": {},\n  \"encrypted_op_ns\": {},\n  \"encrypted_fold_ns\": {}\n}}\n",
        r.public.op_ns, r.public.fold_ns, r.encrypted.op_ns, r.encrypted.fold_ns
    )
}

fn parse_baseline(text: &str) -> Option<Report> {
    let mut public_op_ns = None;
    let mut public_fold_ns = None;
    let mut encrypted_op_ns = None;
    let mut encrypted_fold_ns = None;
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let val = val.trim();
        let parsed: Option<u64> = val.parse().ok();
        match (key, parsed) {
            ("public_op_ns", Some(v)) => public_op_ns = Some(v),
            ("public_fold_ns", Some(v)) => public_fold_ns = Some(v),
            ("encrypted_op_ns", Some(v)) => encrypted_op_ns = Some(v),
            ("encrypted_fold_ns", Some(v)) => encrypted_fold_ns = Some(v),
            _ => {}
        }
    }
    Some(Report {
        public: ProfileMetrics {
            op_ns: public_op_ns?,
            fold_ns: public_fold_ns?,
        },
        encrypted: ProfileMetrics {
            op_ns: encrypted_op_ns?,
            fold_ns: encrypted_fold_ns?,
        },
    })
}

/// Returns `Some((label, baseline_ns, current_ns))` for every metric that
/// regressed (current worse than baseline by more than the tolerance).
fn regressions(baseline: &Report, current: &Report) -> Vec<(&'static str, u64, u64)> {
    let checks: [(&'static str, u64, u64); 4] = [
        ("public_op_ns", baseline.public.op_ns, current.public.op_ns),
        (
            "public_fold_ns",
            baseline.public.fold_ns,
            current.public.fold_ns,
        ),
        (
            "encrypted_op_ns",
            baseline.encrypted.op_ns,
            current.encrypted.op_ns,
        ),
        (
            "encrypted_fold_ns",
            baseline.encrypted.fold_ns,
            current.encrypted.fold_ns,
        ),
    ];
    checks
        .into_iter()
        .filter(|(_, base, cur)| {
            let base = (*base).max(1) as f64;
            let cur = *cur as f64;
            (cur - base) / base > REGRESSION_TOLERANCE
        })
        .collect()
}

fn delta_report(r: &Report) {
    let op_delta = r.encrypted.op_ns as i64 - r.public.op_ns as i64;
    let fold_delta = r.encrypted.fold_ns as i64 - r.public.fold_ns as i64;
    println!(
        "public<->encrypted delta: op_ns={op_delta:+} fold_ns={fold_delta:+} \
         (this delta IS the AEAD seal/unseal overhead, isolated from signing+hashing)"
    );
}

fn main() {
    let current = run();
    println!(
        "streamdb-perf-benchmark measured:\n{}",
        format_report(&current)
    );
    delta_report(&current);

    let path = baseline_path();
    match fs::read_to_string(&path) {
        Ok(text) => {
            let Some(baseline) = parse_baseline(&text) else {
                eprintln!(
                    "streamdb-perf-benchmark: baseline file {} is malformed; refusing to \
                     silently overwrite it — fix or delete it manually.",
                    path.display()
                );
                std::process::exit(1);
            };
            let regressed = regressions(&baseline, &current);
            if regressed.is_empty() {
                println!(
                    "streamdb-perf-benchmark: no regression beyond {:.0}% tolerance against {}",
                    REGRESSION_TOLERANCE * 100.0,
                    path.display()
                );
                std::process::exit(0);
            } else {
                eprintln!(
                    "streamdb-perf-benchmark: REGRESSION beyond {:.0}% tolerance against {}:",
                    REGRESSION_TOLERANCE * 100.0,
                    path.display()
                );
                for (label, base, cur) in &regressed {
                    let pct = ((*cur as f64 - *base as f64) / (*base).max(1) as f64) * 100.0;
                    eprintln!("  {label}: baseline={base}ns current={cur}ns ({pct:+.1}%)");
                }
                eprintln!(
                    "File a concrete tuning follow-up task for the regressed metric(s) \
                     (per streamdb-perf-benchmark-recurring's task card) before re-running."
                );
                std::process::exit(1);
            }
        }
        Err(_) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create benches dir");
            }
            fs::write(&path, format_report(&current)).expect("write baseline");
            println!(
                "streamdb-perf-benchmark: no baseline yet — recorded this run as the tracked \
                 baseline at {}",
                path.display()
            );
            std::process::exit(0);
        }
    }
}
