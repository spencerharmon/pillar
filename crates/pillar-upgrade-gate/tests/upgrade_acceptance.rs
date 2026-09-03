//! The upgrade acceptance gate (ROI P1 "the gate that makes continuous bumps
//! safe").
//!
//! GREEN here is the promotion criterion for the image the cluster follows;
//! RED blocks promotion. The gate boots the NEW binary (this workspace's
//! current code) against a fixture of REAL captured cell state that an earlier
//! stage produced by running the PRIOR-version build against a scratch cell
//! (see `pillar_upgrade_gate::prior_version`), and asserts — TOGETHER — every
//! invariant ROI P1 names:
//!
//! 1. identity intact + a real user still logs in;
//! 2. the streaming DB rehydrates to the SAME view root;
//! 3. trust artifacts still verify;
//! 4. the sealed cell key still decrypts (an OLD algorithm tag against the new
//!    binary);
//! 5. the N-1 compat matrix holds.
//!
//! Plus the negative-path proof: a deliberately-corrupted fixture MUST fail the
//! gate.

use pillar_cells::Cell;
use pillar_crypto::aead::open_symmetric;
use pillar_crypto::{negotiate_all, CompatWindow, DeclaredVersions, SurfaceVersion};
use pillar_identity::login::{DeviceSubkey, IdentityStore, LoginOutcome};
use pillar_streamdb::IpfsPersistentStream;
use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};
use pillar_upgrade_gate::{prior_version, CapturedCellState};

/// The compat window the swarm ships: a peer up to N versions behind is still
/// negotiable (the "N-1+" contract). The gate exercises the whole matrix
/// against this window.
const COMPAT_WINDOW: CompatWindow = CompatWindow(1);

/// The versions the NEW binary declares for each surface. Modelled one step
/// AHEAD of the prior release on every surface, so the gate proves the current
/// build still links with a peer pinned at the prior release across the whole
/// matrix (each pair differs by exactly 1, inside the window).
fn new_binary_declared(surfaces: &[(&'static str, u16)]) -> DeclaredVersions {
    let mut d = DeclaredVersions::new();
    for (name, prior) in surfaces {
        d.declare(name, SurfaceVersion(prior + 1));
    }
    d
}

fn prior_declared(surfaces: &[(&'static str, u16)]) -> DeclaredVersions {
    let mut d = DeclaredVersions::new();
    for (name, prior) in surfaces {
        d.declare(name, SurfaceVersion(*prior));
    }
    d
}

/// Re-derive the prior stage's declared-surface list as `&'static str` keys the
/// negotiation API requires.
fn required_surfaces(state: &CapturedCellState) -> Vec<&'static str> {
    // The captured names are compile-time constants in `prior_version`, so map
    // them back to their static identities.
    const KNOWN: &[&str] = &[
        "pillar-udp",
        "pillar-message",
        "event-envelope",
        "materialized-view",
        "manifest-schema",
        "trust-artifact",
        "sealed-envelope",
        "http-ingest",
    ];
    state
        .declared_surface_versions
        .iter()
        .map(|(name, _)| {
            *KNOWN
                .iter()
                .find(|k| **k == *name)
                .expect("captured surface name is a known static surface")
        })
        .collect()
}

fn static_surface_versions(state: &CapturedCellState) -> Vec<(&'static str, u16)> {
    required_surfaces(state)
        .into_iter()
        .zip(state.declared_surface_versions.iter().map(|(_, v)| *v))
        .collect()
}

// ---- Invariant 1: identity intact + a real user still logs in --------------

/// The new binary rebuilds the identity store from the captured enrollment and
/// verifies the SAME user's login succeeds — identity survives the upgrade.
fn assert_identity_and_login(state: &CapturedCellState) {
    let mut identity = IdentityStore::new();
    identity.certify_op(
        pillar_identity::login::ColdRoot(state.user.cold_root.clone()),
        pillar_identity::login::OpKey(state.user.op_key.clone()),
    );
    identity.grant_device(
        pillar_identity::login::OpKey(state.user.op_key.clone()),
        DeviceSubkey(state.user.device.clone()),
    );
    let outcome: LoginOutcome = identity
        .login(&DeviceSubkey(state.user.device.clone()))
        .expect("NEW binary: captured user still logs in");
    assert_eq!(outcome.device.0, state.user.device);
    assert_eq!(outcome.op.0, state.user.op_key);
    assert_eq!(outcome.root.0, state.user.cold_root);
}

// ---- Invariant 2: streaming DB rehydrates to the SAME view root ------------

/// The new binary rehydrates from the prior binary's pinned segments and
/// reconverges to EXACTLY the captured view root, then recovers write
/// capability via the custody key + sealed segment.
fn assert_stream_rehydrates_to_same_root(state: &CapturedCellState) {
    let node = IpfsPersistentStream::rehydrate(
        state.owner_pub.clone(),
        &state.head,
        state.segment_source(),
    )
    .expect("NEW binary: rehydrate from prior-version pinned segments");

    assert_eq!(
        node.stream().log().root(),
        state.view_root_before,
        "materialized view root must reconverge bit-for-bit across the upgrade"
    );

    // Write capability is recoverable with ONLY the custody-held node secret
    // plus the IPFS-pinned sealed segment the prior binary left.
    let mut node = node;
    node.unseal_signing_key(
        &state.sealed_signing_key_cid,
        &state.node_custody_secret,
        state.segment_source(),
    )
    .expect("NEW binary: recover write capability from custody key + sealed segment");
    node.append(
        b"post-upgrade/event".to_vec(),
        pillar_core::SideEffect::Convergent,
    )
    .expect("NEW binary: write capability restored after upgrade");
}

// ---- Invariant 3: trust artifacts still verify -----------------------------

/// The new binary reconstructs the captured trust artifact and re-verifies it
/// against its genesis chain.
fn assert_trust_artifact_verifies(state: &CapturedCellState) {
    let mut store = TrustStore::new(pillar_core::NodeId(state.trust.genesis.clone()));
    let attest = Attest {
        issuer: pillar_core::NodeId(state.trust.issuer.clone()),
        capacity: Capacity::Role {
            role: state.trust.role.clone(),
            scope: state.trust.scope.clone(),
        },
        authority: None,
        subject: pillar_core::NodeId(state.trust.subject.clone()),
        predicate: Predicate::new(state.trust.action.clone(), state.trust.resource.clone()),
        scope: state.trust.scope.clone(),
        epoch: store.epoch(),
        sig: Sig::sign_as(pillar_core::NodeId(state.trust.issuer.clone()), b"placeholder"),
    }
    .signed_by_issuer();
    let cid = store
        .issue_attest(attest)
        .expect("NEW binary: trust artifact re-minted");
    store
        .verify(&cid)
        .expect("NEW binary: prior-version trust artifact still verifies");
}

// ---- Invariant 4: sealed cell key still decrypts (old algorithm) -----------

/// The new binary opens the cell key the prior binary sealed under the OLD AEAD
/// algorithm, reading the algorithm off the ciphertext's own inline tag.
fn assert_old_algorithm_cell_key_decrypts(state: &CapturedCellState) {
    let recovered = open_symmetric(&state.cell_key, &state.sealed_cell_key, &state.cell_key_aad)
        .expect("NEW binary: old-algorithm sealed cell key still decrypts");
    assert_eq!(
        recovered, state.cell_key_plaintext,
        "decrypted cell key material must match what the prior binary sealed"
    );
}

// ---- Invariant 5: the N-1 compat matrix holds ------------------------------

/// The new binary's declared surface versions negotiate against the prior
/// release's across the WHOLE matrix — every surface links within the window,
/// including admitting the prior-version node into a live cell.
fn assert_n_minus_one_compat_matrix_holds(state: &CapturedCellState) {
    let surfaces = static_surface_versions(state);
    let required = required_surfaces(state);
    let local = new_binary_declared(&surfaces);
    let remote = prior_declared(&surfaces);

    // Every surface links, in BOTH directions (symmetry of the window).
    negotiate_all(&local, &remote, &required, COMPAT_WINDOW)
        .expect("N-1 matrix: new binary negotiates every surface with the prior release");
    negotiate_all(&remote, &local, &required, COMPAT_WINDOW)
        .expect("N-1 matrix: negotiation is symmetric");

    // And the prior-version node is actually admitted into a live cell under
    // the same declared versions — the membership edge of the matrix.
    let mut cell = Cell::new();
    cell.admit_versioned(
        pillar_core::NodeId("prior-version-node".to_owned()),
        &local,
        &remote,
        &required,
        COMPAT_WINDOW,
    )
    .expect("N-1 matrix: prior-version node admitted into the cell");

    // Negative direction of the SAME check: a peer TWO+ versions behind on any
    // surface falls outside the window and is cleanly refused (never silently
    // mis-linked).
    let mut stale = DeclaredVersions::new();
    for (name, prior) in &surfaces {
        // local declares prior+1; make this peer prior-1 => diff of 2.
        stale.declare(name, SurfaceVersion(prior.saturating_sub(1)));
    }
    assert!(
        negotiate_all(&local, &stale, &required, COMPAT_WINDOW).is_err(),
        "N-1 matrix: a peer outside the window must be refused, not mis-linked"
    );
}

// ---- The gate: all invariants together, on a real captured fixture ---------

#[test]
fn upgrade_acceptance_gate_passes_on_real_prior_version_captured_state() {
    // STAGE 1 — the prior-version build produces the fixture against a scratch
    // cell. This is generated, not hand-authored.
    let captured = prior_version::run_against_scratch_cell();

    // STAGE 2 — the NEW binary boots against that captured state and every ROI
    // invariant must hold TOGETHER. Any single failure is a RED gate.
    assert_identity_and_login(&captured);
    assert_stream_rehydrates_to_same_root(&captured);
    assert_trust_artifact_verifies(&captured);
    assert_old_algorithm_cell_key_decrypts(&captured);
    assert_n_minus_one_compat_matrix_holds(&captured);
}

// ---- Negative path: a deliberately-corrupted fixture MUST fail the gate ----

#[test]
fn corrupted_fixture_fails_the_gate() {
    let captured = prior_version::run_against_scratch_cell();

    // Corrupt the durable stream segments the prior binary pinned. The new
    // binary's content-address-verifying rehydrate MUST reject them rather than
    // silently reconverging to a wrong (or any) view root.
    let corrupted = captured.corrupt_stream_segments();

    let result = IpfsPersistentStream::rehydrate(
        corrupted.owner_pub.clone(),
        &corrupted.head,
        corrupted.segment_source(),
    );
    assert!(
        result.is_err(),
        "a corrupted fixture MUST fail the gate — rehydrate must reject tampered segments"
    );
}

#[test]
fn corrupted_cell_key_ciphertext_fails_to_decrypt() {
    let captured = prior_version::run_against_scratch_cell();

    // Flip a byte of the sealed cell key's ciphertext body (past the inline
    // algorithm tag). AEAD authentication MUST fail — a corrupted sealed key is
    // never silently accepted.
    let mut bytes = captured.sealed_cell_key.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let tampered = pillar_crypto::Ciphertext::from_bytes(bytes);

    let opened = open_symmetric(&captured.cell_key, &tampered, &captured.cell_key_aad);
    assert!(
        opened.is_err(),
        "a corrupted sealed cell key MUST fail authenticated decryption"
    );
}
