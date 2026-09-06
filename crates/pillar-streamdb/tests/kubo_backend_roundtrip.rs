//! Real-IPFS integration: exercise [`pillar_streamdb::KuboBackend`] against a
//! LIVE `ipfs/kubo` daemon (not a mock), proving the HTTP RPC client actually
//! round-trips signed segment blocks, pins them, and rehydrates a durable
//! stream from the daemon's own blockstore across a fresh store handle.
//!
//! Gated two ways so it never runs in a daemon-less CI by accident:
//!   - compiled only with `--features kubo`;
//!   - marked `#[ignore]`, and additionally requires `PILLAR_TEST_KUBO_API`
//!     (e.g. `http://127.0.0.1:5001`) to point at a reachable daemon.
//!
//! Run it (with a kubo listening on :5001) via:
//!   PILLAR_TEST_KUBO_API=http://127.0.0.1:5001 \
//!     cargo test -p pillar-streamdb --features kubo --test kubo_backend_roundtrip -- --ignored --nocapture
#![cfg(feature = "kubo")]

use pillar_core::SideEffect;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::Seed;
use pillar_streamdb::{
    ContentStore, IpfsBackend, IpfsPersistentStream, KuboBackend, SignedSegment, Visibility,
};

fn api() -> String {
    std::env::var("PILLAR_TEST_KUBO_API")
        .expect("set PILLAR_TEST_KUBO_API=http://127.0.0.1:5001 to run this test")
}

fn signer(
    label: &str,
) -> (
    pillar_crypto::SigningPublicKey,
    pillar_crypto::SigningSecretKey,
) {
    let seed = Seed::from_bytes(format!("pillar-kubo-it::{label}").into_bytes());
    signing_keypair_from_seed(&seed).expect("keygen")
}

#[test]
#[ignore = "requires a live kubo daemon at PILLAR_TEST_KUBO_API"]
fn kubo_backend_round_trips_a_signed_block_and_pins_it() {
    let head_dir =
        std::env::temp_dir().join(format!("pillar-kubo-it-heads-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&head_dir);
    let backend = KuboBackend::connect(api(), &head_dir).expect("connect to kubo");

    let (pk, sk) = signer("block");
    let seg = SignedSegment::author(b"a real IPFS block".to_vec(), pk, &sk, Visibility::Public)
        .expect("author");
    let cid = seg.cid();
    let wire = seg.to_wire();

    // Put the exact signed wire bytes as a real IPFS raw block; kubo must agree
    // on the CID (block_put re-derives it and errors on any mismatch).
    backend.block_put(&cid, &wire).expect("block_put");
    backend.pin(&cid).expect("pin");

    // The block is local (pinned) and fetches back byte-identical over the RPC.
    assert!(backend.block_has(&cid).expect("block_has"));
    assert_eq!(
        backend.block_get(&cid).expect("block_get").as_deref(),
        Some(&wire[..]),
        "kubo returned the exact bytes we stored"
    );
    assert!(
        backend.pinned().expect("pinned").contains(&cid),
        "the block is in kubo's recursive pin set"
    );

    // A never-stored CID is not local and fetches as None (bitswap miss), not an error.
    let ghost = SignedSegment::author(
        b"never stored".to_vec(),
        signer("ghost").0,
        &signer("ghost").1,
        Visibility::Public,
    )
    .unwrap()
    .cid();
    assert!(!backend.block_has(&ghost).expect("has ghost"));

    let _ = std::fs::remove_dir_all(&head_dir);
}

#[test]
#[ignore = "requires a live kubo daemon at PILLAR_TEST_KUBO_API"]
fn durable_stream_survives_reopen_from_the_real_kubo_blockstore() {
    let head_dir =
        std::env::temp_dir().join(format!("pillar-kubo-it-stream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&head_dir);
    let (owner, secret) = signer("stream-owner");

    // Boot 1: author ops through a kubo-backed durable store.
    {
        let backend = KuboBackend::connect(api(), &head_dir).expect("connect");
        let store = ContentStore::with_backend(Box::new(backend)).expect("store");
        let mut node = IpfsPersistentStream::open_with_store(
            store,
            owner.clone(),
            secret.clone(),
            Visibility::Cell,
        )
        .expect("open");
        node.append(b"cell-genesis".to_vec(), SideEffect::Convergent)
            .expect("append genesis");
        node.append(b"user:alice".to_vec(), SideEffect::Convergent)
            .expect("append user");
        assert_eq!(node.stream().log().len(), 2);
    }

    // Boot 2: a FRESH store handle over the SAME daemon (== process restart with
    // the kubo blockstore intact) rehydrates the whole op set from its pins.
    {
        let backend = KuboBackend::connect(api(), &head_dir).expect("reconnect");
        let store = ContentStore::with_backend(Box::new(backend)).expect("store");
        let node = IpfsPersistentStream::open_with_store(
            store,
            owner.clone(),
            secret.clone(),
            Visibility::Cell,
        )
        .expect("reopen");
        assert_eq!(
            node.stream().log().len(),
            2,
            "every op rehydrated from the real kubo blockstore — NOT re-bootstrapped"
        );
        let payloads: std::collections::BTreeSet<Vec<u8>> = node
            .stream()
            .log()
            .order()
            .into_iter()
            .map(|op| op.payload().to_vec())
            .collect();
        assert!(payloads.contains(&b"cell-genesis".to_vec()));
        assert!(payloads.contains(&b"user:alice".to_vec()));
    }

    let _ = std::fs::remove_dir_all(&head_dir);
}
