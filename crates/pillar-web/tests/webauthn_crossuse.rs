//! Executable, end-to-end acceptance test for `webauthn-custody-spec`'s
//! `CrossSurfaceUsability` invariant, run against the REAL running code (not
//! the TLA+ model): a credential registered on one surface (browser ceremony)
//! must admit a login on the OTHER surface (CLI ceremony), and vice versa,
//! because both surfaces are thin ceremony-transport wrappers around the SAME
//! server-side relying party ([`pillar_web::webauthn::RelyingParty`]) and the
//! SAME wire format ([`pillar_crypto::webauthn::parse_attestation`] /
//! `verify_assertion`) — exactly as `pillar-cli`'s `webauthn_cli` module
//! documents ("No CLI-only credential shape exists anywhere in this path").
//!
//! Both "surfaces" here are simulated authenticator ceremonies (no real
//! hardware, no HTTP, no ctap-hid) that build the identical attestation-object
//! / assertion wire structures `navigator.credentials.{create,get}()` (browser)
//! and `ctap_client::{register,authenticate_with_prf}` (CLI) would produce,
//! then drive them through the real RP — the exact same fixture pattern
//! `pillar_web::webauthn`'s own unit tests already use for a single surface.
//! Both ceremonies share ONE `RelyingParty` instance scoped to a single cell,
//! standing in for the shared in-process cell DB record store
//! (`CrossSurfaceUsability` requires ONE shared record, not two divergent
//! per-surface stores).

use ciborium::value::Value;
use sha2::{Digest, Sha256};

use pillar_crypto::sign::{sign, signing_keypair_from_seed};
use pillar_crypto::webauthn::{base64url_encode, ed25519_public_key_to_cose};
use pillar_crypto::{Seed, SigningSecretKey};
use pillar_web::webauthn::{RelyingParty, RpError};

const TTL: u64 = 300;
const CELL: &str = "cell-crossuse";

/// A simulated hardware authenticator: an Ed25519 keypair plus its COSE
/// encoding, keyed by a label so each surface's ceremony can mint one.
fn authenticator(label: &str) -> (SigningSecretKey, Vec<u8>) {
    let (public, secret) =
        signing_keypair_from_seed(&Seed::from_bytes(label.as_bytes().to_vec())).expect("keygen");
    let cose = ed25519_public_key_to_cose(&public).expect("cose encode");
    (secret, cose)
}

/// Build the attestation object wire format BOTH surfaces produce
/// (`authenticatorMakeCredential`'s CBOR result): rpIdHash || flags ||
/// sign_count || aaguid || credIdLen || credId || COSE key, wrapped in the
/// `{fmt, attStmt, authData}` CBOR map `parse_attestation` expects.
fn attestation(cose: &[u8], credential_id: &[u8], sign_count: u32) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash (unchecked here)
    auth_data.push(0x40 | 0x01); // AT + UP flags
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose);
    let att = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&att, &mut out).expect("cbor encode");
    out
}

/// Build the assertion wire format (`authenticatorGetAssertion`'s signed
/// payload plus the clientDataJSON both surfaces transmit) that
/// `verify_assertion` expects: `authData || SHA-256(clientDataJSON)`, signed
/// by the presented authenticator's real secret key.
fn assertion(secret: &SigningSecretKey, challenge: &[u8], sign_count: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let cdj = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pillar.local"}}"#,
        base64url_encode(challenge)
    )
    .into_bytes();
    let mut ad = Vec::new();
    ad.extend_from_slice(&[0u8; 32]);
    ad.push(0x01);
    ad.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig = sign(secret, &signed).expect("sign");
    (ad, cdj, sig.as_bytes().to_vec())
}

/// Register a fresh credential against `rp`, simulating whichever surface
/// `session` names (`"browser-session"` / `"cli-session"` below) — the RP
/// code path (`register_finish`) is IDENTICAL either way.
fn register_on(rp: &mut RelyingParty, session: &str, now: u64, cose: &[u8], cred: &[u8]) {
    let ch = rp.begin(session, CELL, now, TTL);
    rp.register_finish(session, CELL, now, &ch, &attestation(cose, cred, 0), [9u8; 32], "alice")
        .expect("registration must succeed");
}

/// Log in against `rp`, simulating whichever surface `session` names — the RP
/// code path (`authenticate_finish`) is IDENTICAL either way.
fn login_on(
    rp: &mut RelyingParty,
    session: &str,
    now: u64,
    secret: &SigningSecretKey,
    cred: &[u8],
    sign_count: u32,
) -> Result<[u8; 32], RpError> {
    let ch = rp.begin(session, CELL, now, TTL);
    let (ad, cdj, sig) = assertion(secret, &ch, sign_count);
    rp.authenticate_finish(session, CELL, now, &ch, cred, &ad, &cdj, &sig, b"prf-out")
}

#[test]
fn register_in_browser_then_login_via_cli_succeeds() {
    let (secret, cose) = authenticator("cross-a");
    let mut rp = RelyingParty::new();

    // Register-in-browser (simulated ceremony).
    register_on(&mut rp, "browser-session", 1_000, &cose, b"cred-browser-then-cli");

    // Login-via-CLI against the SAME shared record.
    let unlock = login_on(&mut rp, "cli-session", 2_000, &secret, b"cred-browser-then-cli", 5)
        .expect("a credential registered in the browser must admit a CLI login");
    assert_ne!(unlock, [0u8; 32], "unlock secret is real, not a placeholder");
}

#[test]
fn register_at_cli_then_login_in_browser_succeeds() {
    let (secret, cose) = authenticator("cross-b");
    let mut rp = RelyingParty::new();

    // Register-at-CLI (simulated ceremony).
    register_on(&mut rp, "cli-session", 1_000, &cose, b"cred-cli-then-browser");

    // Login-in-browser (simulated ceremony) against the SAME shared record.
    let unlock = login_on(&mut rp, "browser-session", 2_000, &secret, b"cred-cli-then-browser", 5)
        .expect("a credential registered at the CLI must admit a browser login");
    assert_ne!(unlock, [0u8; 32], "unlock secret is real, not a placeholder");
}

#[test]
fn a_wrong_credential_is_refused_on_both_surfaces() {
    let (secret, cose) = authenticator("cross-c");
    let (wrong_secret, _wrong_cose) = authenticator("wrong-authenticator");
    let mut rp = RelyingParty::new();
    register_on(&mut rp, "browser-session", 1_000, &cose, b"cred-wrong");

    // Wrong authenticator via the CLI surface.
    assert_eq!(
        login_on(&mut rp, "cli-session", 2_000, &wrong_secret, b"cred-wrong", 5),
        Err(RpError::Crypto(pillar_crypto::CryptoError::VerificationFailed)),
        "a forged assertion from a wrong credential must be refused via the CLI surface"
    );

    // Wrong authenticator via the browser surface.
    assert_eq!(
        login_on(&mut rp, "browser-session", 3_000, &wrong_secret, b"cred-wrong", 5),
        Err(RpError::Crypto(pillar_crypto::CryptoError::VerificationFailed)),
        "a forged assertion from a wrong credential must be refused via the browser surface"
    );

    // The legitimate authenticator still admits on either surface afterwards.
    login_on(&mut rp, "cli-session", 4_000, &secret, b"cred-wrong", 5)
        .expect("the real credential must still admit after forged attempts were refused");
}

#[test]
fn a_revoked_credential_is_refused_on_both_surfaces() {
    let (secret, cose) = authenticator("cross-d");
    let mut rp = RelyingParty::new();
    register_on(&mut rp, "cli-session", 1_000, &cose, b"cred-revoked");
    rp.revoke(b"cred-revoked");

    assert_eq!(
        login_on(&mut rp, "cli-session", 2_000, &secret, b"cred-revoked", 5),
        Err(RpError::Revoked),
        "a revoked credential must be refused via the CLI surface"
    );
    assert_eq!(
        login_on(&mut rp, "browser-session", 3_000, &secret, b"cred-revoked", 5),
        Err(RpError::Revoked),
        "a revoked credential must be refused via the browser surface"
    );
}
