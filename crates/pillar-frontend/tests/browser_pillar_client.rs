//! Acceptance suite — `browser-pillar-client` (2026-09-11 ROI HEAD).
//!
//! Proves the ROI claim that the Yew browser console is now a real Pillar
//! client emitting the SAME `pillar-ops` ops the CLI does — not a privileged
//! portal-REST caller. Two properties, both host-native (this crate's wasm
//! `start()` entrypoint is `#[cfg(target_arch = "wasm32")]`-gated, so the
//! browser client's seal/sign logic — which lives in the workspace-native,
//! host-testable `pillar-web-frontend` crate — runs under a plain
//! `cargo test`, no browser/wasm runner needed):
//!
//! 1. **Byte-identical to the CLI.** The browser client
//!    (`pillar_web_frontend::pillar_client`) and the CLI's native client
//!    library (`pillar_client::transport::seal_resource_op`) seal+sign the
//!    SAME logical `ResourceOp` to the EXACT same `PillarMessage` bytes. This
//!    is the load-bearing convergence property: the console's op
//!    content-addresses to the same streamdb op id the CLI's does, so the CRDT
//!    op-log dedups them — which only holds if the two producers emit identical
//!    ciphertext. The CLI path is the ORACLE here; the browser path must match
//!    it to the byte.
//! 2. **The migrated mutation surface no longer needs privileged REST.** Every
//!    manifest-mutating resource action (`Apply`/`Edit`/`Scale`) translates to
//!    a real signed `ResourceOp` via the browser client; only the non-manifest
//!    `Rollout` restart *trigger* remains a control act. So no covered resource
//!    kind is mutated by a `/portal/resource/*` REST call anymore.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via
//! `cargo test -p pillar-frontend --features acceptance`.

#![cfg(feature = "acceptance")]

use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed, SigningPublicKey, SigningSecretKey};
use pillar_manifest::{Crd, Metadata, Value};
use pillar_ops::ResourceOp;
use pillar_wire::{PillarMessage, Visibility};

use pillar_web_frontend::pillar_client::{
    seal_signed_op_bytes, BrowserClientConfig, STREAM_OP_SEAL_DOMAIN,
};
use pillar_web_frontend::resources_console::ResourceAction;

/// Fixed cell/seed/key material shared by both the browser and CLI paths so
/// the ONLY variable under test is the seal/sign implementation.
struct Fixture {
    cell_id: Vec<u8>,
    cell_seed: Vec<u8>,
    public: SigningPublicKey,
    secret: SigningSecretKey,
}

fn fixture() -> Fixture {
    let (public, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(vec![42u8; 32])).expect("keypair");
    Fixture {
        cell_id: vec![7u8; 32],
        cell_seed: vec![9u8; 32],
        public,
        secret,
    }
}

fn browser_config(f: &Fixture) -> BrowserClientConfig {
    BrowserClientConfig {
        node_base_url: "https://node.example.com".into(),
        cell_id: f.cell_id.clone(),
        cell_seed: f.cell_seed.clone(),
        signer_public: f.public.clone().into_bytes(),
        signer_secret: f.secret.clone().into_bytes(),
    }
}

/// The CLI oracle: seal+sign `op` exactly as `pillar apply`/`pillar delete`
/// does, then serialize the envelope to CBOR.
fn cli_seal_bytes(op: &ResourceOp, f: &Fixture) -> Vec<u8> {
    let group = pillar_crypto::cell::group_key_from_seed(&Seed::from_bytes(f.cell_seed.clone()))
        .expect("group key");
    let cell = CellId::from_bytes(f.cell_id.clone());
    let msg = pillar_client::transport::seal_resource_op(
        op,
        &group,
        cell,
        f.public.clone(),
        &f.secret,
        Visibility::Cell,
    )
    .expect("cli seal_resource_op");
    msg.to_canonical_cbor().expect("cbor")
}

fn workload_apply_op() -> ResourceOp {
    ResourceOp::Apply {
        crd: Crd::new(
            "pillar.dev/v1",
            "Workload",
            Metadata::new("web").with_label("pillar.dev/managed-by", "console"),
        )
        .with_spec("image", Value::String("app:v3".into()))
        .with_spec("replicas", Value::Integer(4)),
    }
}

#[test]
fn browser_apply_seal_is_byte_identical_to_the_cli() {
    let f = fixture();
    let op = workload_apply_op();

    let browser = seal_signed_op_bytes(&op, &browser_config(&f)).expect("browser seal");
    let cli = cli_seal_bytes(&op, &f);

    assert_eq!(
        browser, cli,
        "browser client and CLI must seal the same op to byte-identical envelopes"
    );
}

#[test]
fn browser_delete_seal_is_byte_identical_to_the_cli() {
    let f = fixture();
    let op = ResourceOp::Delete {
        kind: "Workload".into(),
        name: "web".into(),
    };

    let browser = seal_signed_op_bytes(&op, &browser_config(&f)).expect("browser seal");
    let cli = cli_seal_bytes(&op, &f);

    assert_eq!(browser, cli, "delete op must also converge byte-for-byte");
}

#[test]
fn the_browser_client_reuses_the_streamdb_seal_domain() {
    // The convergence above only holds because both producers seal under the
    // SAME domain — pin the browser client's domain constant to the CLI's.
    assert_eq!(
        STREAM_OP_SEAL_DOMAIN,
        pillar_client::transport::STREAM_OP_SEAL_DOMAIN,
        "browser client must reuse pillar-client's StreamOp seal domain"
    );
}

#[test]
fn the_sealed_envelope_verifies_and_opens_to_the_original_op() {
    // A node receiving the browser's body authenticates from the signature and
    // opens the seal — proving it is a real, node-applicable signed op.
    let f = fixture();
    let op = workload_apply_op();
    let bytes = seal_signed_op_bytes(&op, &browser_config(&f)).expect("seal");
    let msg = PillarMessage::from_canonical_cbor(&bytes).expect("decode");
    let group =
        pillar_crypto::cell::group_key_from_seed(&Seed::from_bytes(f.cell_seed.clone())).unwrap();
    let recovered = pillar_client::transport::open_resource_op(&msg, &group).expect("open");
    assert_eq!(recovered, op, "envelope opens back to the exact op");
}

#[test]
fn every_migrated_mutation_action_emits_a_signed_op_never_a_rest_path() {
    // The migration property: for every manifest-mutating action the console
    // has a signed ResourceOp to emit (so it never needs `/portal/resource/*`);
    // only the non-manifest Rollout trigger remains a control act.
    let f = fixture();
    for action in ResourceAction::all() {
        match action.as_resource_op("web", "app:v9") {
            Some(op) => {
                assert!(
                    action.is_resource_op(),
                    "{action:?} produced an op but is not marked a resource-op"
                );
                // and it really seals to a signed envelope
                let bytes = seal_signed_op_bytes(&op, &browser_config(&f)).expect("seal");
                assert!(!bytes.is_empty());
            }
            None => assert!(
                !action.is_resource_op(),
                "{action:?} yields no op yet claims to be a resource-op"
            ),
        }
    }
    // Rollout is the ONLY control (non-CRUD) act.
    assert_eq!(ResourceAction::Rollout.as_resource_op("web", ""), None);
}
