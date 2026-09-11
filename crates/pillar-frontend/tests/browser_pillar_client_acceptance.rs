//! Acceptance test — `browser-pillar-client` (ROI Priority 1, 2026-09-11).
//!
//! Host-testable acceptance for the browser pillar client's real production
//! code path: `pillar_web_frontend::browser_pillar_client` re-implements
//! `pillar_client::transport::seal_resource_op`/`open_resource_op`'s exact
//! encode -> seal -> sign pipeline using only wasm-safe crates (`pillar-ops`,
//! `pillar-wire` `default-features = false`, `pillar-crypto`) so it also
//! compiles for `wasm32-unknown-unknown` (this crate itself IS that
//! wasm32 target build — see `src/lib.rs`). This test asserts the SAME
//! `ResourceOp` survives the full round trip a real browser->node exchange
//! takes: encode, seal+sign into a `PillarMessage`, canonical-CBOR the
//! envelope (the exact bytes a `fetch` POST body/`dial_https` TCP body
//! carries), decode the envelope back, then verify+open+decode the op —
//! never a parallel/mocked model of that pipeline.
#![cfg(feature = "acceptance")]

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed};
use pillar_manifest::{Metadata, Value};
use pillar_ops::{Crd, ResourceOp};
use pillar_wire::{PillarMessage, Visibility};
use pillar_web_frontend::browser_pillar_client::{open_and_verify, seal_and_sign};

#[test]
fn browser_client_apply_op_round_trips_over_the_wire() {
    let group = group_key_from_seed(&Seed::from_bytes(b"acceptance-cell-seed".to_vec()))
        .expect("cell group key");
    let (signer, secret) = signing_keypair_from_seed(&Seed::from_bytes(b"acceptance-signing-seed".to_vec()))
        .expect("signing keypair");
    let cell = CellId::from_bytes(b"acceptance-cell".to_vec());

    let crd = Crd::new(
        "pillar.dev/v1",
        "Deployment",
        Metadata::new("browser-pillar-client-acceptance"),
    )
    .with_spec("replicas", Value::Integer(3));
    let op = ResourceOp::Apply { crd };

    // 1. Seal + sign, EXACTLY the pipeline the real browser client's
    //    `submit_resource_op`/`submit_resource_op_async` run before a fetch.
    let msg = seal_and_sign(&op, &group, cell, signer, &secret, Visibility::Cell)
        .expect("seal_and_sign must succeed for a well-formed op");

    // 2. Canonical-CBOR-encode the envelope -- the ACTUAL bytes a real
    //    `fetch` POST body (or `dial_https`'s raw-TCP body) carries over the
    //    wire to `/portal/client/message`.
    let wire_bytes = msg
        .to_canonical_cbor()
        .expect("PillarMessage must canonical-CBOR-encode");
    assert!(
        !wire_bytes.is_empty(),
        "a real op must produce non-empty wire bytes"
    );

    // 3. Decode the envelope back from the wire bytes -- what a receiving
    //    node (or, symmetrically, this test standing in for one) does.
    let decoded_msg =
        PillarMessage::from_canonical_cbor(&wire_bytes).expect("envelope must decode");
    assert_eq!(decoded_msg, msg, "wire round trip must be byte-exact");

    // 4. Verify the signature, open the seal, and decode the ResourceOp --
    //    the receiving side's full authentication + decrypt + decode.
    let opened = open_and_verify(&decoded_msg, &group)
        .expect("a correctly sealed+signed op must open and verify");
    assert_eq!(
        opened, op,
        "the ResourceOp that reaches the far side must be identical to what \
         the browser client sent"
    );
}

#[test]
fn browser_client_delete_op_round_trips_and_fails_closed_under_tamper() {
    let group = group_key_from_seed(&Seed::from_bytes(b"acceptance-cell-seed-2".to_vec()))
        .expect("cell group key");
    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(b"acceptance-signing-seed-2".to_vec()))
            .expect("signing keypair");
    let cell = CellId::from_bytes(b"acceptance-cell-2".to_vec());
    let op = ResourceOp::Delete {
        kind: "Deployment".to_owned(),
        name: "browser-pillar-client-acceptance-2".to_owned(),
    };

    let msg = seal_and_sign(&op, &group, cell.clone(), signer, &secret, Visibility::Cell)
        .expect("seal_and_sign must succeed");
    let opened = open_and_verify(&msg, &group).expect("must open under the correct group key");
    assert_eq!(opened, op);

    // A tampered/mis-keyed reply must fail closed, never silently open under
    // the wrong cell's group key (a stray browser tab / a different cell).
    let wrong_group = group_key_from_seed(&Seed::from_bytes(b"a-different-cell-entirely".to_vec()))
        .expect("other cell group key");
    assert!(
        open_and_verify(&msg, &wrong_group).is_err(),
        "opening under the wrong cell group key must fail, never silently succeed"
    );
}
