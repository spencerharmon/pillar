//! Acceptance: a processing node ingests ONE signed `ResourceOp` from an
//! authenticated **non-node client peer** into its durable op-sync set, but ONLY
//! after authorizing the op under the FULL WoT/RBAC decider — policy is enforced
//! by the node and never trusted from the producer.
//!
//! Run: `cargo test -p pillar-net --test node_client_op_ingest_policy --features acceptance`
//!
//! This is the definition-of-done for `pillar:node-client-op-ingest-policy`. It
//! proves the security boundary end to end over REAL crypto (a real ed25519
//! signature, a real cell seal) and the REAL `RbacDecider` over a REAL
//! `WotAuthority`:
//!
//! - An **authorized** client signer (reachable in the WoT + an explicit write
//!   grant for the op's kind) → the op is applied; the node's durable op set
//!   grows to hold the identical content-addressed op.
//! - An **unauthorized** client signer (a validly-signed stranger with no
//!   reachable trust and no grant) → the op is REFUSED fail-closed; the durable
//!   set is left byte-for-byte UNCHANGED, even though the signature is perfectly
//!   valid. A valid signature is authentication, never authority.
//! - A **tampered** signature → refused as unauthenticated before policy runs.
//! - Enforcement is the node's: an unauthorized producer cannot make the node
//!   apply its op by any framing it controls.

#![cfg(feature = "acceptance")]

use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::{sign, signing_keypair_from_seed};
use pillar_crypto::{CellId, Seed, Signature};
use pillar_manifest::{Crd, Metadata, Value};
use pillar_net::{ingest_client_op, resource_write_capability, signer_subject, ClientOpReject};
use pillar_ops::ResourceOp;
use pillar_rbac::{ExplicitGrant, GrantEffect, PolicyEvent, PolicyTarget, ResourceClass};
use pillar_streamdb::{OpId, PersistentStream};
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::{Body, PillarMessage, Visibility};
use pillar_wot_authority::WotAuthority;

const CELL_SEED: &str = "node-client-op-ingest-policy-cell";
const OP_KIND: &str = "RetentionPolicy";

fn tmp_root(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pillar-client-ingest-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

/// The client op every producer in this test emits: an `Apply` of a
/// `RetentionPolicy` CRD (byte-identical across producers, so it content-
/// addresses to one op id).
fn client_op() -> ResourceOp {
    ResourceOp::Apply {
        crd: Crd::new(
            "pillar.dev/v1",
            OP_KIND,
            Metadata::new("metrics-default").with_label("pillar.dev/managed-by", "client"),
        )
        .with_spec("signalKind", Value::String("Metric".into()))
        .with_spec("window", Value::Integer(2_592_000)),
    }
}

/// Build a REAL signed, cell-sealed `PillarMessage` carrying `op` as a
/// `StreamOp` body, signed under the client identity derived from `signer_seed`.
/// Returns the envelope, its opened plaintext body (as the processing cell node
/// would open it), and the producer's `NodeId` subject.
fn signed_client_op(
    op: &ResourceOp,
    signer_seed: &str,
) -> (PillarMessage, Body, pillar_core::NodeId) {
    let body = Body::StreamOp(op.encode().expect("encode op"));

    let group =
        group_key_from_seed(&Seed::from_bytes(CELL_SEED.as_bytes().to_vec())).expect("cell key");
    let cell = CellId::from_bytes(format!("cell::{CELL_SEED}").into_bytes());
    let plaintext = body.to_canonical_cbor().expect("encode body");
    let aad = PillarMessage::header_aad(Visibility::Cell, &cell);
    let body_sealed = CellSeal
        .seal(&group, &plaintext, b"pillar-net/client-ingest/v1", &aad)
        .expect("seal");

    let (signer, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(signer_seed.as_bytes().to_vec()))
            .expect("keygen");
    let signature = sign(&secret, &PillarMessage::signing_material(&body_sealed)).expect("sign");
    let msg = PillarMessage::new(signer, signature, Visibility::Cell, cell, body_sealed);

    let subject = signer_subject(&msg);
    (msg, body, subject)
}

/// Build a WoT authority + policy/grant view under which `authorized_subject` is
/// allowed the `resource.write:<kind>` capability, and construct an authority in
/// which a stranger is NOT reachable. Explicit-grant based (fail-closed): only
/// the named subject is authorized.
fn authorized_view(
    authorized_subject: &pillar_core::NodeId,
) -> (WotAuthority, Vec<PolicyEvent>, Vec<ExplicitGrant>) {
    let owner = pillar_core::NodeId::from("cell-owner");
    let mut authority = WotAuthority::new(owner.clone(), 5);
    // The authorized client is reachable in the trust graph (a cell member the
    // owner has tsig-certified). The stranger is issued no edge, so it is not
    // reachable at all.
    authority.issue_edge(owner, authorized_subject.clone(), 3);

    // No depth-default policies: authorization is by explicit grant only, so the
    // decider is strictly fail-closed for anyone without a grant.
    let policies: Vec<PolicyEvent> = Vec::new();
    let grants = vec![ExplicitGrant {
        subject: authorized_subject.clone(),
        capability: resource_write_capability(&client_op()),
        effect: GrantEffect::Allow,
    }];
    (authority, policies, grants)
}

/// An authorized client peer's signed op is authenticated, authorized under the
/// full decider, and applied — the durable set grows to hold the identical CID.
#[test]
fn authorized_client_op_is_applied() {
    let root = tmp_root("authorized");
    let mut stream = PersistentStream::open(&root).unwrap();
    assert_eq!(stream.stream().log().len(), 0);

    let op = client_op();
    let (msg, body, subject) = signed_client_op(&op, "authorized-client");
    let (authority, policies, grants) = authorized_view(&subject);

    let admitted = ingest_client_op(
        &mut stream,
        &msg,
        &body,
        &authority,
        &policies,
        &grants,
        ResourceClass::All,
        0,
    )
    .expect("authorized op is ingested");
    assert!(admitted, "the op was newly admitted into the durable set");
    assert_eq!(stream.stream().log().len(), 1, "durable set grew by one op");

    // It landed under the op's content address — the identical CID any producer
    // of the same logical op yields.
    let id = OpId(pillar_streamdb::content_address(&op.encode().unwrap()));
    assert!(
        stream.stream().log().contains(&id),
        "the applied op is held under its content address"
    );

    // Re-ingesting the same authorized op is an idempotent dedup no-op.
    let again = ingest_client_op(
        &mut stream,
        &msg,
        &body,
        &authority,
        &policies,
        &grants,
        ResourceClass::All,
        0,
    )
    .expect("re-ingest still authorized");
    assert!(!again, "an already-held op admits nothing new");
    assert_eq!(stream.stream().log().len(), 1);

    std::fs::remove_dir_all(&root).ok();
}

/// A validly-signed but UNAUTHORIZED client peer (no reachable trust, no grant)
/// is refused fail-closed by the node's own decider — the durable set is left
/// UNCHANGED even though the signature is perfectly valid. A valid signature is
/// never authority.
#[test]
fn unauthorized_client_op_is_refused_and_leaves_the_store_unchanged() {
    let root = tmp_root("unauthorized");
    let mut stream = PersistentStream::open(&root).unwrap();

    let op = client_op();
    // The authorized view names a DIFFERENT subject; this stranger is neither
    // reachable in the WoT nor explicitly granted.
    let (auth_msg, _auth_body, authorized_subject) = signed_client_op(&op, "the-authorized-one");
    let (authority, policies, grants) = authorized_view(&authorized_subject);

    let (stranger_msg, stranger_body, stranger_subject) = signed_client_op(&op, "a-stranger");
    assert_ne!(
        stranger_subject, authorized_subject,
        "the stranger is a different identity"
    );
    // The stranger's signature is genuinely valid — this is authentication, not
    // authority.
    stranger_msg
        .verify_signature()
        .expect("the stranger's op is validly signed");

    let root_before = stream.stream().log().root();
    let err = ingest_client_op(
        &mut stream,
        &stranger_msg,
        &stranger_body,
        &authority,
        &policies,
        &grants,
        ResourceClass::All,
        0,
    )
    .expect_err("an unauthorized signer must be refused");
    assert_eq!(
        err,
        ClientOpReject::Unauthorized,
        "refused by the RBAC decider, not by a codec/signature error"
    );
    assert_eq!(
        stream.stream().log().len(),
        0,
        "the refused op never touched the durable set"
    );
    assert_eq!(
        stream.stream().log().root(),
        root_before,
        "the durable Merkle root is byte-for-byte unchanged"
    );

    // Silence unused warnings for the authorized envelope built only to derive
    // the subject.
    let _ = auth_msg;

    std::fs::remove_dir_all(&root).ok();
}

/// A tampered signature is refused as UNAUTHENTICATED, before any authorization
/// — the node never even asks the decider about a forged envelope.
#[test]
fn tampered_signature_is_refused_before_policy() {
    let root = tmp_root("tampered");
    let mut stream = PersistentStream::open(&root).unwrap();

    let op = client_op();
    let (mut msg, body, subject) = signed_client_op(&op, "authorized-client");
    // Even set up a view that WOULD authorize this subject — the point is the
    // signature check fails first.
    let (authority, policies, grants) = authorized_view(&subject);

    let mut sig = msg.signature.as_bytes().to_vec();
    sig[0] ^= 0x01;
    msg.signature = Signature::from_bytes(sig);

    let err = ingest_client_op(
        &mut stream,
        &msg,
        &body,
        &authority,
        &policies,
        &grants,
        ResourceClass::All,
        0,
    )
    .expect_err("a tampered envelope is refused");
    assert_eq!(
        err,
        ClientOpReject::BadSignature,
        "authentication fails before authorization"
    );
    assert_eq!(stream.stream().log().len(), 0);

    std::fs::remove_dir_all(&root).ok();
}

/// The capability the node asks the decider about is derived from the op's OWN
/// kind (`resource.write:<kind>`) — never from anything the producer asserts.
/// An explicit DENY of that exact capability overrides any allow, confirming the
/// write is one ordinary capability decision inside the full decider.
#[test]
fn write_capability_is_derived_from_the_op_kind_and_is_a_normal_decider_rung() {
    let root = tmp_root("deny");
    let mut stream = PersistentStream::open(&root).unwrap();

    let op = client_op();
    let (msg, body, subject) = signed_client_op(&op, "member-but-denied");

    let cap = resource_write_capability(&op);
    assert_eq!(
        cap.0,
        format!("resource.write:{OP_KIND}"),
        "capability names the op's own kind"
    );

    let owner = pillar_core::NodeId::from("cell-owner");
    let mut authority = WotAuthority::new(owner.clone(), 5);
    authority.issue_edge(owner, subject.clone(), 3);

    // A depth-default policy that WOULD allow the write for a reachable member…
    let policies = vec![PolicyEvent {
        target: PolicyTarget::ResourceClass(ResourceClass::All),
        capability: cap.clone(),
        depth_threshold: 0,
    }];
    // …but an explicit DENY of the same capability overrides it (deny wins,
    // unconditionally — exactly the lattice a validly-signed cell member cannot
    // escape by exceeding its capability).
    let grants = vec![ExplicitGrant {
        subject: subject.clone(),
        capability: cap,
        effect: GrantEffect::Deny,
    }];

    let err = ingest_client_op(
        &mut stream,
        &msg,
        &body,
        &authority,
        &policies,
        &grants,
        ResourceClass::All,
        0,
    )
    .expect_err("an explicitly-denied member is refused");
    assert_eq!(err, ClientOpReject::Unauthorized);
    assert_eq!(
        stream.stream().log().len(),
        0,
        "a denied member's op never lands, despite a valid signature and reachable trust"
    );

    std::fs::remove_dir_all(&root).ok();
}
