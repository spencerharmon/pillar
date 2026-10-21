//! Dual-profile envelope round trips and real TSDB materialization, in-process.
//! No disk/network claims: fold timing includes the full op path plus TSDB writes,
//! cold/filtered/cached queries and invalidation. All integrity checks stay timed.

use std::hint::black_box;
use std::time::Instant;

use pillar_crypto::cell::{group_key_from_seed, CellGroupKey};
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed, SigningPublicKey, SigningSecretKey};
use pillar_observability::{Query, SignalId, SignalKind, TimeseriesStore, ViewCache};
use pillar_streamdb::pillarmsg::{open_stream_op, seal_stream_op, Confidentiality};
use pillar_wire::{Cid, PillarMessage, Visibility};

const OP_COUNT: usize = 2000;
const FOLD_COUNT: usize = 2000;
const PAYLOAD_BYTES: usize = 1024;
const SAMPLES: usize = 7;

struct Harness {
    group: CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: SigningSecretKey,
    payloads: Vec<Vec<u8>>,
}

impl Harness {
    fn new(count: usize) -> Self {
        let seed = Seed::from_bytes(b"streamdb-perf-v1".to_vec());
        let (signer, secret) = signing_keypair_from_seed(&seed).expect("signer");
        Self {
            group: group_key_from_seed(&seed).expect("group key"),
            cell: CellId::from_bytes(b"benchmark-cell".to_vec()),
            signer,
            secret,
            payloads: (0..count)
                .map(|i| {
                    let mut payload = vec![b'x'; PAYLOAD_BYTES];
                    payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    payload
                })
                .collect(),
        }
    }

    fn encode(&self, payload: &[u8], profile: Confidentiality) -> (Cid, Vec<u8>) {
        let message = seal_stream_op(
            payload,
            Some(&self.group),
            self.cell.clone(),
            self.signer.clone(),
            &self.secret,
            // Keep routing metadata identical: only confidentiality varies.
            Visibility::Cell,
            profile,
        )
        .expect("seal and sign");
        let bytes = message.to_canonical_cbor().expect("encode envelope");
        (Cid::of(&bytes), bytes)
    }

    fn decode(&self, cid: &Cid, bytes: &[u8], profile: Confidentiality) -> Result<Vec<u8>, String> {
        if !cid.verifies(bytes) {
            return Err("CID mismatch".into());
        }
        // Strict decoding, not the legacy decoder's plaintext fallback.
        let message = PillarMessage::from_canonical_cbor(bytes).map_err(|e| e.to_string())?;
        if message.signer != self.signer {
            return Err("unexpected signer".into());
        }
        let group = (profile == Confidentiality::CellEncrypted).then_some(&self.group);
        open_stream_op(&message, group, profile).map_err(|e| e.to_string())
    }

    fn roundtrip(&self, payload: &[u8], profile: Confidentiality) -> Vec<u8> {
        let (cid, bytes) = self.encode(black_box(payload), profile);
        let opened = self.decode(&cid, &bytes, profile).expect("verify and open");
        assert_eq!(opened, payload);
        black_box(opened)
    }

    fn measure(&self, profile: Confidentiality, ops: usize, fold: usize) -> [f64; 2] {
        let start = Instant::now();
        for payload in &self.payloads[..ops] {
            self.roundtrip(payload, profile);
        }
        let op_ns = start.elapsed().as_secs_f64() * 1e9 / ops as f64;

        // Independent oracle: plaintext content IDs, not the IDs returned by write.
        let mut all: Vec<_> = self.payloads[..fold - 1]
            .iter()
            .map(|p| SignalId(Cid::of(p)))
            .collect();
        let mut metrics: Vec<_> = all.iter().step_by(2).cloned().collect();
        all.sort_unstable();
        metrics.sort_unstable();
        let start = Instant::now();
        let mut store = TimeseriesStore::new(256, u64::MAX / 2);
        for (i, payload) in self.payloads[..fold - 1].iter().enumerate() {
            let kind = if i % 2 == 0 {
                SignalKind::Metric
            } else {
                SignalKind::Log
            };
            store.write(kind, self.roundtrip(payload, profile), i as u64);
        }
        assert_eq!(store.held_len(), fold - 1);
        let mut cache = ViewCache::new();
        assert_eq!(cache.materialize(&store, Query::all()), all);
        assert_eq!(
            cache.materialize(&store, Query::of_kind(SignalKind::Metric)),
            metrics
        );
        assert_eq!(cache.materialize(&store, Query::all()), all);
        assert_eq!((cache.hits(), cache.misses()), (1, 2));

        let last = &self.payloads[fold - 1];
        store.write(
            SignalKind::Metric,
            self.roundtrip(last, profile),
            fold as u64,
        );
        let last_id = SignalId(Cid::of(last));
        all.push(last_id.clone());
        metrics.push(last_id);
        all.sort_unstable();
        metrics.sort_unstable();
        assert_eq!(store.held_len(), fold);
        assert_eq!(cache.materialize(&store, Query::all()), all);
        assert_eq!(
            cache.materialize(&store, Query::of_kind(SignalKind::Metric)),
            metrics
        );
        assert_eq!((cache.hits(), cache.misses()), (1, 4));
        let fold_ns = start.elapsed().as_secs_f64() * 1e9 / fold as f64;
        [op_ns, fold_ns]
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn main() {
    assert_eq!(
        std::env::args().len(),
        1,
        "workload is fixed; no arguments supported"
    );
    let harness = Harness::new(OP_COUNT.max(FOLD_COUNT));
    let profiles = [Confidentiality::Public, Confidentiality::CellEncrypted];
    // Warm both paths; alternate order to reduce shared-runner temporal bias.
    for profile in profiles {
        harness.measure(profile, 64, 64);
    }
    let mut timings = [Vec::new(), Vec::new()];
    for sample in 0..SAMPLES {
        for offset in 0..2 {
            let index = (sample + offset) % 2;
            timings[index].push(harness.measure(profiles[index], OP_COUNT, FOLD_COUNT));
        }
    }
    let [public, encrypted] = timings
        .map(|samples| [0, 1].map(|metric| median(samples.iter().map(|s| s[metric]).collect())));
    println!("{{\"schema_version\":1,\"op_count\":{OP_COUNT},\"fold_count\":{FOLD_COUNT},\"payload_bytes\":{PAYLOAD_BYTES},\"samples\":{SAMPLES},");
    println!(
        "\"public_op_ns\":{},\"encrypted_op_ns\":{},",
        public[0], encrypted[0]
    );
    println!(
        "\"public_fold_ns\":{},\"encrypted_fold_ns\":{},",
        public[1], encrypted[1]
    );
    println!(
        "\"op_delta_pct\":{},\"fold_delta_pct\":{}}}",
        (encrypted[0] / public[0] - 1.0) * 100.0,
        (encrypted[1] / public[1] - 1.0) * 100.0
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::Signature;

    #[test]
    fn both_profiles_materialize_real_tsdb_across_blocks_and_invalidate() {
        let harness = Harness::new(513);
        for profile in [Confidentiality::Public, Confidentiality::CellEncrypted] {
            let result = harness.measure(profile, 2, 513);
            assert!(result.iter().all(|n| n.is_finite() && *n > 0.0));
        }
    }

    #[test]
    fn measured_decoder_rejects_bad_hash_signature_and_seal() {
        let mut harness = Harness::new(1);
        for profile in [Confidentiality::Public, Confidentiality::CellEncrypted] {
            let (cid, bytes) = harness.encode(&harness.payloads[0], profile);
            assert!(harness.decode(&Cid::of(b"wrong"), &bytes, profile).is_err());
            let mut message = PillarMessage::from_canonical_cbor(&bytes).unwrap();
            message.signature = Signature::from_bytes(vec![0; 64]);
            let forged = message.to_canonical_cbor().unwrap();
            // Recompute the CID so this must fail at signature verification.
            assert!(harness.decode(&Cid::of(&forged), &forged, profile).is_err());
            assert_eq!(
                harness.decode(&cid, &bytes, profile).unwrap(),
                harness.payloads[0]
            );
        }
        let (cid, bytes) = harness.encode(&harness.payloads[0], Confidentiality::CellEncrypted);
        harness.group = group_key_from_seed(&Seed::from_bytes(b"wrong-key".to_vec())).unwrap();
        assert!(harness
            .decode(&cid, &bytes, Confidentiality::CellEncrypted)
            .is_err());
    }
}
