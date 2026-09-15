//! Streamdb dual-profile performance harness (ROI P1 "Streamdb performance is
//! a standing, self-perpetuating discipline").
//!
//! This integration test runs IDENTICAL streamdb op workloads through BOTH
//! visibility profiles side by side and measures:
//!   * op-path throughput / latency for the PUBLIC profile (the unencrypted
//!     CEILING and fixed BASELINE — signed + content-addressed, no AEAD seal),
//!   * op-path throughput / latency for the CELL-ENCRYPTED profile (the
//!     guaranteed-confidentiality profile — additionally AEAD-sealed),
//!   * the view-fold (Merkle-root) cost over the resulting op set for BOTH
//!     profiles,
//!   * and the PUBLIC↔ENCRYPTED DELTA as a first-class metric — that delta IS
//!     the encryption (AEAD seal) overhead, isolated from the signing + hashing
//!     cost BOTH profiles pay.
//!
//! It is invoked by `scripts/streamdb-perf-benchmark.sh`, which parses the
//! machine-readable `STREAMDB_PERF_JSON <json>` line this test prints and
//! compares each metric against a tracked baseline
//! (`scripts/streamdb-perf-baseline.json`). The HARD INVARIANT — the encrypted
//! profile still seals, signs and content-addresses every op — is asserted
//! here so the harness can never "measure" a profile that skipped a guarantee
//! it owes.

use std::time::Instant;

use pillar_streamdb::pillarmsg::{open_stream_op, seal_stream_op};
use pillar_streamdb::store::Visibility;
use pillar_streamdb::{Confidentiality, OpLog};

use pillar_crypto::cell::{group_key_from_seed, CellGroupKey};
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::Seed;
use pillar_crypto::{CellId, SigningPublicKey, SigningSecretKey};

/// Fixed workload size. Kept modest so the harness runs in the offline
/// `cargo test` sandbox in a few seconds while still producing a stable
/// signal (the seal path dominates and its per-op cost is highly repeatable).
const OPS: usize = 2_000;
/// Payload size per op (bytes) — a representative small streamdb record.
const PAYLOAD_LEN: usize = 256;

struct Fixture {
    group: CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: SigningSecretKey,
}

fn fixture() -> Fixture {
    let group =
        group_key_from_seed(&Seed::from_bytes(b"streamdb-perf-cell".to_vec())).expect("cell key");
    let cell = CellId::from_bytes(b"cell::streamdb-perf".to_vec());
    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(b"streamdb-perf-author".to_vec()))
            .expect("keygen");
    Fixture {
        group,
        cell,
        signer,
        secret,
    }
}

/// Deterministic, non-degenerate payloads so every op has a distinct content
/// address (a constant payload would let idempotent-append dedup collapse the
/// set and understate the fold cost).
fn payloads() -> Vec<Vec<u8>> {
    (0..OPS)
        .map(|i| {
            let mut p = vec![0u8; PAYLOAD_LEN];
            let tag = (i as u64).to_le_bytes();
            p[..8].copy_from_slice(&tag);
            for (j, b) in p.iter_mut().enumerate().skip(8) {
                *b = ((i.wrapping_mul(31).wrapping_add(j)) & 0xff) as u8;
            }
            p
        })
        .collect()
}

/// Result of exercising the op path for one profile: elapsed nanos and the
/// resulting op set folded into an OpLog for the view-fold measurement.
struct ProfileRun {
    seal_nanos: u128,
    log: OpLog,
}

fn run_profile(
    fx: &Fixture,
    payloads: &[Vec<u8>],
    confidentiality: Confidentiality,
    visibility: Visibility,
) -> ProfileRun {
    let group = match confidentiality {
        Confidentiality::CellEncrypted => Some(&fx.group),
        Confidentiality::Public => None,
    };

    let start = Instant::now();
    let mut log = OpLog::new();
    for payload in payloads {
        let msg = seal_stream_op(
            payload,
            group,
            fx.cell.clone(),
            fx.signer.clone(),
            &fx.secret,
            visibility,
            confidentiality,
        )
        .expect("seal op");
        // The op's durable/gossiped bytes are the encoded, signed (and, for the
        // encrypted profile, sealed) envelope — content-address THOSE, exactly
        // as the durable store does.
        let encoded = msg.to_canonical_cbor().expect("encode envelope");
        log.append(encoded);
    }
    let seal_nanos = start.elapsed().as_nanos();

    ProfileRun { seal_nanos, log }
}

/// HARD INVARIANT guard: prove the encrypted profile genuinely sealed (a
/// non-member cannot read) AND still signs + content-addresses, while the
/// public profile is keyless-readable yet still signed. A "speedup" that
/// dropped a seal/sig would fail this before any number is reported.
fn assert_guarantees(fx: &Fixture, payload: &[u8]) {
    // Encrypted: sealed body is opaque to a wrong key, opens under the right one.
    let enc = seal_stream_op(
        payload,
        Some(&fx.group),
        fx.cell.clone(),
        fx.signer.clone(),
        &fx.secret,
        Visibility::Cell,
        Confidentiality::CellEncrypted,
    )
    .expect("seal encrypted");
    let opened = open_stream_op(&enc, Some(&fx.group), Confidentiality::CellEncrypted)
        .expect("member opens encrypted op");
    assert_eq!(opened, payload, "encrypted op must round-trip for a member");
    let wrong = group_key_from_seed(&Seed::from_bytes(b"streamdb-perf-wrong-cell".to_vec()))
        .expect("wrong cell key");
    assert!(
        open_stream_op(&enc, Some(&wrong), Confidentiality::CellEncrypted).is_err(),
        "encrypted profile MUST NOT be openable with the wrong cell key (seal owed)"
    );

    // Public: keyless-readable but still signed (open verifies the signature
    // unconditionally before any seal logic).
    let pubmsg = seal_stream_op(
        payload,
        None,
        fx.cell.clone(),
        fx.signer.clone(),
        &fx.secret,
        Visibility::Public,
        Confidentiality::Public,
    )
    .expect("seal public");
    let pub_opened = open_stream_op(&pubmsg, None, Confidentiality::Public)
        .expect("public op readable with no key");
    assert_eq!(pub_opened, payload, "public op must round-trip keyless");
    // Tamper the signed body: the signature check must now reject it, proving
    // the public profile is signed (not merely cleartext).
    let mut tampered = pubmsg.clone();
    let mut body = tampered.body_sealed.as_bytes().to_vec();
    body[0] ^= 0xff;
    tampered.body_sealed = pillar_crypto::Ciphertext::from_bytes(body);
    assert!(
        open_stream_op(&tampered, None, Confidentiality::Public).is_err(),
        "public profile MUST still verify the signature (tamper rejected)"
    );
}

fn fold_nanos(log: &OpLog) -> u128 {
    let start = Instant::now();
    // Fold the full op set to its Merkle root — the view-fold cost.
    let _root = log.root();
    start.elapsed().as_nanos()
}

#[test]
fn streamdb_dual_profile_perf_benchmark() {
    let fx = fixture();
    let payloads = payloads();

    // Guarantee gate first — never report a number for a profile that skipped
    // a seal/signature it owes.
    assert_guarantees(&fx, &payloads[0]);

    // PUBLIC — the throughput/latency CEILING and fixed BASELINE.
    let public = run_profile(&fx, &payloads, Confidentiality::Public, Visibility::Public);
    // CELL-ENCRYPTED — the guaranteed-confidentiality profile.
    let encrypted = run_profile(
        &fx,
        &payloads,
        Confidentiality::CellEncrypted,
        Visibility::Cell,
    );

    // Both profiles produce the SAME number of distinct ops (identical
    // workload); the fold operates over identical-cardinality sets.
    assert_eq!(public.log.len(), OPS, "public op set must hold every op");
    assert_eq!(
        encrypted.log.len(),
        OPS,
        "encrypted op set must hold every op"
    );

    let public_fold = fold_nanos(&public.log);
    let encrypted_fold = fold_nanos(&encrypted.log);

    let ops = OPS as f64;
    // Per-op latency in microseconds.
    let public_op_us = public.seal_nanos as f64 / 1_000.0 / ops;
    let encrypted_op_us = encrypted.seal_nanos as f64 / 1_000.0 / ops;
    // Throughput in ops/sec.
    let public_ops_per_sec = ops / (public.seal_nanos as f64 / 1_000_000_000.0);
    let encrypted_ops_per_sec = ops / (encrypted.seal_nanos as f64 / 1_000_000_000.0);
    // FIRST-CLASS METRIC: the op-path public↔encrypted delta = AEAD seal
    // overhead per op (microseconds), isolated from signing + hashing.
    let op_delta_us = encrypted_op_us - public_op_us;

    // View-fold cost per op (nanoseconds) for both profiles + their delta.
    let public_fold_ns = public_fold as f64 / ops;
    let encrypted_fold_ns = encrypted_fold as f64 / ops;
    let fold_delta_ns = encrypted_fold_ns - public_fold_ns;

    // Sanity: the encrypted profile can only be >= the public ceiling on the
    // op path (it does strictly more work). A negative delta would mean the
    // measurement is noise-dominated; surface it, do not silently pass.
    println!(
        "STREAMDB_PERF_JSON {{\
\"ops\":{OPS},\
\"payload_len\":{PAYLOAD_LEN},\
\"public_op_us\":{public_op_us:.4},\
\"encrypted_op_us\":{encrypted_op_us:.4},\
\"op_delta_us\":{op_delta_us:.4},\
\"public_ops_per_sec\":{public_ops_per_sec:.1},\
\"encrypted_ops_per_sec\":{encrypted_ops_per_sec:.1},\
\"public_fold_ns_per_op\":{public_fold_ns:.4},\
\"encrypted_fold_ns_per_op\":{encrypted_fold_ns:.4},\
\"fold_delta_ns_per_op\":{fold_delta_ns:.4}\
}}"
    );
}
