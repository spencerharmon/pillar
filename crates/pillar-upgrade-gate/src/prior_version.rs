//! The **prior-version build**: the earlier `pillar` binary that produces the
//! acceptance-gate fixture by running against a scratch cell.
//!
//! This module deliberately models "an earlier stage of this same test running
//! a prior-version build" (ROI P1). It never reaches for a current default: it
//! seals the cell key with the OLD AEAD algorithm, stamps the compat surfaces
//! at the versions an older release declared, and captures the REAL state it
//! produced into a [`CapturedCellState`]. The gate (the NEW binary) then boots
//! against that capture.
//!
//! The single value that crosses the version boundary is [`CapturedCellState`]
//! — genuine output, not hand-authored data.

use pillar_core::SideEffect;
use pillar_crypto::aead::seal_symmetric_with;
use pillar_crypto::seal::sealing_keypair_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{AeadAlgorithm, Seed, SymmetricKey};
use pillar_identity::login::{ColdRoot, DeviceSubkey, IdentityStore, OpKey};
use pillar_streamdb::{IpfsPersistentStream, Visibility};
use pillar_trust_artifacts::{Attest, Capacity, Predicate, TrustStore};

use crate::{CapturedCellState, CapturedTrust, CapturedUser, SegmentStore};

fn seed(label: &str) -> Seed {
    Seed::from_bytes(format!("upgrade-gate/prior-version::{label}").into_bytes())
}

/// The compat surface versions an EARLIER release declared. These are the
/// values the new binary negotiates its own (current) declared versions
/// against; the whole N-1 matrix must link within the compat window.
///
/// The prior release ran the same surfaces at their v1 baseline; the gate
/// asserts the new binary — whatever it now declares — still admits a peer
/// pinned at these prior versions within N.
const PRIOR_DECLARED_SURFACE_VERSIONS: &[(&str, u16)] = &[
    ("pillar-udp", 1),
    ("pillar-message", 1),
    ("event-envelope", 1),
    ("materialized-view", 1),
    ("manifest-schema", 1),
    ("trust-artifact", 1),
    ("sealed-envelope", 1),
    ("http-ingest", 1),
];

/// Run the prior-version binary against a fresh scratch cell and CAPTURE the
/// real state it produced.
///
/// Concretely, the earlier binary:
/// 1. enrolls a real user (cold root → op key → device) into the cell's
///    identity store, so a login is verifiable;
/// 2. seals the cell's symmetric key with the OLD AEAD algorithm
///    ([`AeadAlgorithm::ChaCha20Poly1305V1`]) — the exact skew case an upgrade
///    must survive;
/// 3. writes several real events into a durable streaming DB, sealing the
///    segment-signing key to the node's custody key and recording the
///    materialized view root;
/// 4. mints a real trust artifact anchored to the cell's genesis identity.
///
/// The returned [`CapturedCellState`] is the fixture the NEW binary is booted
/// against by the gate. Panicking here is correct: a prior build that cannot
/// even produce a coherent cell is a test-harness bug, not a gate outcome.
#[must_use]
pub fn run_against_scratch_cell() -> CapturedCellState {
    // ---- 1. Real user enrolled into the scratch cell's identity store ----
    let cold_root = "cell-genesis-cold-root";
    let op_key = "alice-op-key";
    let device = "alice-laptop";
    let mut identity = IdentityStore::new();
    identity.certify_op(ColdRoot::from(cold_root), OpKey::from(op_key));
    identity.grant_device(OpKey::from(op_key), DeviceSubkey::from(device));
    // Sanity: the prior binary observed a working login before capture.
    identity
        .login(&DeviceSubkey::from(device))
        .expect("prior binary: user logs in against the scratch cell");

    // ---- 2. Cell key sealed with the OLD AEAD algorithm ----
    let cell_key = SymmetricKey::from_bytes(vec![0x5Au8; 32]);
    let cell_key_plaintext = b"scratch-cell/data-encryption-key/material".to_vec();
    let cell_key_aad = b"upgrade-gate/scratch-cell/sealed-cell-key-v1".to_vec();
    let sealed_cell_key = seal_symmetric_with(
        AeadAlgorithm::ChaCha20Poly1305V1,
        &cell_key,
        &cell_key_plaintext,
        &cell_key_aad,
    )
    .expect("prior binary: seal cell key under the old algorithm");
    debug_assert_eq!(
        sealed_cell_key.as_bytes()[0],
        AeadAlgorithm::ChaCha20Poly1305V1.tag(),
        "the fixture must carry the OLD algorithm's inline tag"
    );

    // ---- 3. Durable streaming DB written by the prior binary ----
    let (owner_pub, owner_secret) =
        signing_keypair_from_seed(&seed("stream-owner")).expect("owner keygen");
    let (node_custody_pub, node_custody_secret) =
        sealing_keypair_from_seed(&seed("node-custody")).expect("custody keygen");

    let mut node = IpfsPersistentStream::genesis(
        owner_pub.clone(),
        owner_secret.clone(),
        Visibility::Public,
    );

    // Track every segment Cid as the head advances — the exact chain a
    // rehydrating new binary walks from the published head.
    let mut segment_cids = Vec::new();
    for payload in [
        b"scratch-cell/event/alpha".as_slice(),
        b"scratch-cell/event/bravo".as_slice(),
        b"scratch-cell/event/charlie".as_slice(),
    ] {
        node.append(payload.to_vec(), SideEffect::Exclusive)
            .expect("prior binary: append event");
        segment_cids.push(
            node.head_cid()
                .cloned()
                .expect("head advanced on append"),
        );
    }

    let view_root_before = node.stream().log().root();

    let sealed_signing_key_cid = node
        .seal_signing_key(&[node_custody_pub.clone()])
        .expect("prior binary: seal + pin segment-signing key");
    segment_cids.push(sealed_signing_key_cid.clone());

    let head = node
        .store()
        .resolve_head(&owner_pub)
        .cloned()
        .expect("prior binary published a head");

    let segments = SegmentStore::capture(
        node.store(),
        &segment_cids,
        owner_pub.clone(),
        owner_secret,
    );

    // ---- 4. Real trust artifact anchored to the cell genesis ----
    let genesis = "cell-genesis";
    let issuer = "cell-genesis";
    let subject = "alice";
    let role = "operator";
    let scope = "scratch-cell";
    let action = "stream:append";
    let resource = "scratch-cell/*";
    // Prove (in the prior stage) that the artifact verifies, so a broken
    // fixture can only come from deliberate corruption, never from a
    // never-valid capture.
    {
        let mut store = TrustStore::new(genesis.into());
        let attest = Attest {
            issuer: issuer.into(),
            capacity: Capacity::Role {
                role: role.to_owned(),
                scope: scope.to_owned(),
            },
            authority: None,
            subject: subject.into(),
            predicate: Predicate::new(action, resource),
            scope: scope.to_owned(),
            epoch: store.epoch(),
            sig: pillar_trust_artifacts::Sig::sign_as(issuer, b"placeholder"),
        }
        .signed_by_issuer();
        let cid = store
            .issue_attest(attest)
            .expect("prior binary: mint trust artifact");
        store
            .verify(&cid)
            .expect("prior binary: trust artifact verifies");
    }

    CapturedCellState {
        owner_pub,
        head,
        segments,
        view_root_before,
        sealed_signing_key_cid,
        node_custody_pub,
        node_custody_secret,
        sealed_cell_key,
        cell_key,
        cell_key_aad,
        cell_key_plaintext,
        user: CapturedUser {
            cold_root: cold_root.to_owned(),
            op_key: op_key.to_owned(),
            device: device.to_owned(),
        },
        declared_surface_versions: PRIOR_DECLARED_SURFACE_VERSIONS.to_vec(),
        trust: CapturedTrust {
            genesis: genesis.to_owned(),
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            role: role.to_owned(),
            scope: scope.to_owned(),
            action: action.to_owned(),
            resource: resource.to_owned(),
        },
    }
}
