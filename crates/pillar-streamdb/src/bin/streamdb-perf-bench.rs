//! Recurring streamdb performance harness (ROI P1 "Streamdb performance is a
//! standing, self-perpetuating discipline", extended by "the performance +
//! integration harness measures BOTH visibility profiles side by side").
//!
//! Drives an identical synthetic op-append workload through BOTH streamdb
//! visibility/confidentiality profiles side by side:
//!
//! - **PUBLIC** ([`Confidentiality::Public`]) — no AEAD seal, still signed +
//!   content-addressed. This is the throughput/latency CEILING and the fixed
//!   baseline the delta is measured against.
//! - **CELL-ENCRYPTED** ([`Confidentiality::CellEncrypted`]) — the
//!   guaranteed-confidentiality profile every write actually uses in
//!   production.
//!
//! For each profile it measures: (a) the op-path cost (seal/sign + open/
//! verify a `PillarMessage::StreamOp` envelope, `crate::pillarmsg`) and (b)
//! the view-fold cost (`OpLog::append` + `OpLog::root`, the CRDT materialized
//! view). It reports the PUBLIC-vs-CELL delta for both as a first-class
//! metric — that delta IS the isolated AEAD seal/unseal overhead, separated
//! from the signing/hashing cost both profiles pay.
//!
//! Emits one JSON line to stdout with the measured metrics, then compares
//! them against the tracked baseline (`scripts/testdata/streamdb-perf-
//! baseline.json`, resolved relative to the workspace root via
//! `CARGO_MANIFEST_DIR`) with a generous regression tolerance (hardware
//! variance across CI/dev runners is real; the tolerance exists to avoid
//! flagging noise, not to hide a real regression). Exits non-zero — and
//! prints which metric regressed — when a measured metric falls below its
//! tolerated floor. This is the process `scripts/streamdb-perf-benchmark.sh`
//! (registered in `CHECKS.md`'s `streamdb-perf-benchmark` stub) wraps.
//!
//! HARD INVARIANT: this harness must never skip a seal/sign/verify step to
//! "go faster" — it measures the REAL op path both profiles actually pay in
//! production. A tuning task that shrinks the delta must do so within this
//! same safety envelope (see the doc at `docs/` for this task).

use std::path::PathBuf;
use std::time::Instant;

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed};
use pillar_streamdb::pillarmsg::{open_stream_op, seal_stream_op, Confidentiality};
use pillar_streamdb::store::Visibility;
use pillar_streamdb::OpLog;

/// Number of ops per profile. Large enough to smooth out noise, small enough
/// that the harness runs in well under a second even under CI load.
const OP_COUNT: usize = 4_000;
/// Synthetic op payload size (bytes) — representative of a small structured
/// write (not a bulk blob transfer, which is a different workload class).
const PAYLOAD_LEN: usize = 256;

/// One profile's measured metrics: op-path (seal+sign+open+verify) throughput
/// and the CRDT view-fold (`OpLog::append`+`root()`) throughput.
#[derive(Debug, Clone, Copy)]
struct ProfileMetrics {
    op_path_ns_per_op: f64,
    fold_ns_per_op: f64,
}

fn run_profile(confidentiality: Confidentiality) -> ProfileMetrics {
    let group = group_key_from_seed(&Seed::from_bytes(b"streamdb-perf-bench-cell".to_vec()))
        .expect("cell group key");
    let cell = CellId::from_bytes(b"streamdb-perf-bench-cell".to_vec());
    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(b"streamdb-perf-bench-author".to_vec()))
            .expect("signing keypair");
    let visibility = match confidentiality {
        Confidentiality::CellEncrypted => Visibility::Cell,
        Confidentiality::Public => Visibility::Public,
    };
    let group_ref = match confidentiality {
        Confidentiality::CellEncrypted => Some(&group),
        Confidentiality::Public => None,
    };

    let payloads: Vec<Vec<u8>> = (0..OP_COUNT)
        .map(|i| {
            let mut p = vec![0u8; PAYLOAD_LEN];
            p[..8].copy_from_slice(&(i as u64).to_le_bytes());
            p
        })
        .collect();

    // Op-path: seal (sign + AEAD-seal-or-not) then open (verify + open-or-not)
    // every op — the real round trip a write + a subsequent read both pay.
    let start = Instant::now();
    let mut opened_payloads: Vec<Vec<u8>> = Vec::with_capacity(OP_COUNT);
    for payload in &payloads {
        let msg = seal_stream_op(
            payload,
            group_ref,
            cell.clone(),
            signer.clone(),
            &secret,
            visibility,
            confidentiality,
        )
        .expect("seal_stream_op");
        let opened = open_stream_op(&msg, group_ref, confidentiality).expect("open_stream_op");
        opened_payloads.push(opened);
    }
    let op_path_elapsed = start.elapsed();
    assert_eq!(opened_payloads.len(), OP_COUNT, "every op must round-trip");

    // View-fold: append every op's payload to a fresh OpLog and fold the
    // materialized view (root) once — the CRDT view-fold cost, independent of
    // the wire/seal cost measured above.
    let start = Instant::now();
    let mut log = OpLog::new();
    for payload in &opened_payloads {
        log.append(payload.clone());
    }
    let _root = log.root();
    let fold_elapsed = start.elapsed();

    ProfileMetrics {
        op_path_ns_per_op: op_path_elapsed.as_nanos() as f64 / OP_COUNT as f64,
        fold_ns_per_op: fold_elapsed.as_nanos() as f64 / OP_COUNT as f64,
    }
}

/// The tracked baseline shape, loaded from `scripts/testdata/streamdb-perf-
/// baseline.json`. Kept minimal and hand-readable: floors are ns/op ceilings
/// (measured must be <= floor * tolerance) since lower ns/op is better.
#[derive(Debug)]
struct Baseline {
    public_op_path_ns_per_op: f64,
    public_fold_ns_per_op: f64,
    cell_op_path_ns_per_op: f64,
    cell_fold_ns_per_op: f64,
    /// Multiplicative regression tolerance applied to every ceiling above
    /// (e.g. 1.75 allows a measured value up to 75% slower than baseline
    /// before it is flagged a regression) — generous on purpose: this runs on
    /// heterogeneous/shared CI hardware, and the goal is to catch a REAL
    /// regression (a dropped fast path, an accidental O(n^2)), not hardware
    /// jitter.
    tolerance: f64,
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/testdata/streamdb-perf-baseline.json")
}

/// Minimal hand-rolled JSON reader (no serde_json dependency in this crate) —
/// the baseline file's schema is fixed and tiny, so a small ad hoc parser
/// keeps this harness free of a new dependency.
fn parse_baseline(text: &str) -> Baseline {
    fn field(text: &str, key: &str) -> f64 {
        let needle = format!("\"{key}\"");
        let idx = text
            .find(&needle)
            .unwrap_or_else(|| panic!("baseline missing field {key}"));
        let after = &text[idx + needle.len()..];
        let colon = after.find(':').expect("missing colon");
        let rest = after[colon + 1..].trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e' || c == 'E'))
            .unwrap_or(rest.len());
        rest[..end].parse::<f64>().unwrap_or_else(|e| {
            panic!(
                "baseline field {key} not a number ({e}): {:?}",
                &rest[..end]
            )
        })
    }
    Baseline {
        public_op_path_ns_per_op: field(text, "public_op_path_ns_per_op"),
        public_fold_ns_per_op: field(text, "public_fold_ns_per_op"),
        cell_op_path_ns_per_op: field(text, "cell_op_path_ns_per_op"),
        cell_fold_ns_per_op: field(text, "cell_fold_ns_per_op"),
        tolerance: field(text, "tolerance"),
    }
}

fn main() {
    let public = run_profile(Confidentiality::Public);
    let cell = run_profile(Confidentiality::CellEncrypted);

    let op_path_delta_ns = cell.op_path_ns_per_op - public.op_path_ns_per_op;
    let fold_delta_ns = cell.fold_ns_per_op - public.fold_ns_per_op;

    println!(
        "{{\"public_op_path_ns_per_op\":{:.1},\"public_fold_ns_per_op\":{:.1},\"cell_op_path_ns_per_op\":{:.1},\"cell_fold_ns_per_op\":{:.1},\"op_path_delta_ns\":{:.1},\"fold_delta_ns\":{:.1},\"op_count\":{}}}",
        public.op_path_ns_per_op,
        public.fold_ns_per_op,
        cell.op_path_ns_per_op,
        cell.fold_ns_per_op,
        op_path_delta_ns,
        fold_delta_ns,
        OP_COUNT
    );

    let baseline_file = baseline_path();
    let text = std::fs::read_to_string(&baseline_file)
        .unwrap_or_else(|e| panic!("failed to read baseline {}: {e}", baseline_file.display()));
    let baseline = parse_baseline(&text);

    let mut regressions = Vec::new();
    let mut check = |name: &str, measured: f64, floor: f64| {
        let ceiling = floor * baseline.tolerance;
        if measured > ceiling {
            regressions.push(format!(
                "{name}: measured {measured:.1}ns/op exceeds tolerated ceiling {ceiling:.1}ns/op (baseline {floor:.1}ns/op, tolerance {}x)",
                baseline.tolerance
            ));
        }
    };
    check(
        "public_op_path_ns_per_op",
        public.op_path_ns_per_op,
        baseline.public_op_path_ns_per_op,
    );
    check(
        "public_fold_ns_per_op",
        public.fold_ns_per_op,
        baseline.public_fold_ns_per_op,
    );
    check(
        "cell_op_path_ns_per_op",
        cell.op_path_ns_per_op,
        baseline.cell_op_path_ns_per_op,
    );
    check(
        "cell_fold_ns_per_op",
        cell.fold_ns_per_op,
        baseline.cell_fold_ns_per_op,
    );

    if !regressions.is_empty() {
        eprintln!("streamdb-perf-benchmark: REGRESSION(S) detected against tracked baseline:");
        for r in &regressions {
            eprintln!("  - {r}");
        }
        eprintln!(
            "File a concrete tuning follow-up task per AGENTS.md's streamdb-perf-benchmark-recurring card (never weaken this baseline to make the check pass)."
        );
        std::process::exit(1);
    }

    eprintln!("streamdb-perf-benchmark: within tolerance of tracked baseline.");
}
