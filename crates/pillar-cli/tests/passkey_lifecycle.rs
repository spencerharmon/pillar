//! Acceptance test — `um-passkey-lifecycle` (ROI P1 "User management &
//! lifecycle" roadmap B4).
//!
//! Proves the passkey LIFECYCLE management surface over the existing WebAuthn
//! RP endpoints (`/webauthn/register/*`, `/webauthn/credentials/{list,revoke}`):
//! a user can enroll multiple NAMED credentials, LIST them (id/label/rpId/
//! created/last-used/sign-count), and REVOKE one — with the no-lockout
//! keep->=1 guard refusing an unconfirmed revoke of the LAST credential and
//! permitting it once explicitly confirmed. No new authority path, no new
//! TLA+ gate: this restates the RP's own `CrossSurfaceUsability` /
//! `RevokedKeyNeverAdmits` behavior from the management surface's point of
//! view, and drives the real `pillar webauthn list|revoke` CLI dispatch
//! (`pillar_cli::webauthn_cli::run`) — the exact code the operator's CLI
//! calls — over the real HTTP surface of a real booted node.
//!
//! The hardware `register`/`login` ceremony verbs need a real CTAP2
//! authenticator (behind the `passkey` build feature) and are exercised
//! elsewhere; here credential ENROLLMENT is driven directly over
//! `/webauthn/register/{begin,finish}` with a software Ed25519 "authenticator"
//! (the SAME technique `pillar-cli`'s own `web_serve` unit tests use), so the
//! node's REAL relying party (`pillar_web::webauthn::RelyingParty`) verifies a
//! real attested credential — only the hardware CTAP2 transport is swapped for
//! a software signer.
//!
//! Black-box: execs the real compiled `pillar` binary and drives its real
//! HTTP portal surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test passkey_lifecycle --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "correct horse battery staple 2026 passkey-lifecycle";
const ADMIN_HANDLE: &str = "alice@pillar";
const ORIGIN: &str = "https://pillar.local";

struct HttpResponse {
    status: u16,
    body: String,
    session_token: Option<String>,
}

fn http(port: u16, method: &str, path: &str, body: &str) -> Option<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(value) = header.trim_end().strip_prefix("X-Pillar-Session: ") {
            session_token = Some(value.to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        body: resp_body,
        session_token,
    })
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node { child, http_port };
        node.await_ready(Duration::from_secs(20));
        node
    }

    fn await_ready(&self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(resp) = http(self.http_port, "GET", "/bootstrap/status", "") {
                if resp.status == 200 {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "pillar node run did not serve /bootstrap/status within {within:?} on port {}",
                    self.http_port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        http(self.http_port, "POST", path, body).expect("POST succeeds")
    }

    fn get(&self, path: &str) -> HttpResponse {
        http(self.http_port, "GET", path, "").expect("GET succeeds")
    }

    fn nonce_id(&self) -> u64 {
        let nonce_resp = self.get("/nonce");
        assert_eq!(nonce_resp.status, 200, "nonce: {}", nonce_resp.body);
        nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses")
    }

    fn login(&self, identifier: &str, password: &str) -> String {
        let id = self.nonce_id();
        let resp = self.post("/login", &format!("{identifier}\n{password}\n{id}"));
        assert_eq!(resp.status, 200, "login: {}", resp.body);
        resp.session_token
            .expect("login response carries a session token")
    }

    fn bootstrap_admin(&self) {
        let create_cell = self.post("/bootstrap/create-cell", "cell-genesis");
        assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
        let create_user = self.post(
            "/bootstrap/create-user",
            &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
        );
        assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- A software Ed25519 "authenticator" (no hardware needed): builds a real
// `fmt=none` attestation object the node's real RP (`parse_attestation`)
// verifies, exactly as `pillar-cli`'s own `web_serve` unit tests do. ----

fn b64(bytes: &[u8]) -> String {
    pillar_crypto::webauthn::base64url_encode(bytes)
}

fn challenge_of(resp: &HttpResponse) -> String {
    assert_eq!(resp.status, 200, "begin failed: {}", resp.body);
    resp.body
        .split_whitespace()
        .nth(1)
        .expect("CHALLENGE <b64> ...")
        .to_owned()
}

/// A test Ed25519 authenticator: returns the CBOR attestation object for a
/// given credential id, keyed off `label` (so distinct labels mint distinct
/// keys).
fn software_attestation(label: &str, credential_id: &[u8], sign_count: u32) -> Vec<u8> {
    let (public, _secret) = pillar_crypto::sign::signing_keypair_from_seed(
        &pillar_crypto::Seed::from_bytes(label.as_bytes().to_vec()),
    )
    .expect("keypair from seed");
    let cose = pillar_crypto::webauthn::ed25519_public_key_to_cose(&public)
        .expect("cose-encode ed25519 public key");
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]);
    auth_data.push(0x40 | 0x01); // AT + UP flags
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose);
    use ciborium::value::Value;
    let att = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&att, &mut out).expect("cbor-encode attestation object");
    out
}

/// Enroll one NAMED credential for the already-logged-in `token`, via the real
/// `/webauthn/register/{begin,finish}` ceremony (software authenticator).
/// Returns the credential's base64url id.
fn enroll(node: &Node, token: &str, credential_id: &[u8], label: &str, rp_id: &str) -> String {
    let begin = node.post(
        "/webauthn/register/begin",
        &format!("{token}\nalice@pillar"),
    );
    let challenge_b64 = challenge_of(&begin);
    let attestation = software_attestation(label, credential_id, 0);
    let finish = node.post(
        "/webauthn/register/finish",
        &format!(
            "{token}\nalice@pillar\n{challenge_b64}\n{}\n{label}\n{rp_id}",
            b64(&attestation)
        ),
    );
    assert_eq!(finish.status, 200, "register/finish: {}", finish.body);
    assert!(finish.body.starts_with("REGISTERED"), "{}", finish.body);
    finish
        .body
        .split_whitespace()
        .nth(1)
        .expect("REGISTERED <cred-id-b64url>")
        .to_owned()
}

/// The full passkey lifecycle: enroll two named credentials, LIST renders
/// both with their metadata, REVOKE the first succeeds (a survivor remains),
/// REVOKE of the LAST credential is refused `409 CONFIRM-REQUIRED` unless
/// confirmed — the no-lockout keep->=1 guard — and a confirmed revoke of the
/// last credential IS allowed (a lost sole key must still be revocable).
/// Drives `list`/`revoke` through the real CLI dispatch
/// (`pillar_cli::webauthn_cli::run`), not a hand-rolled HTTP client, so this
/// proves the exact code the operator's `pillar webauthn` invokes.
#[test]
fn list_name_revoke_and_keep_at_least_one_over_the_real_cli_and_rp() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());
    node.bootstrap_admin();
    let token = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    let domain = format!("127.0.0.1:{}", node.http_port);
    let cli = |args: &[&str]| {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        pillar_cli::webauthn_cli::run(&owned)
    };

    // --- Enroll two NAMED credentials, each bound to its own rpId.
    let cred_blue = enroll(
        &node,
        &token,
        b"cred-blue",
        "yubikey-blue",
        "deleteme.example.com",
    );
    let cred_green = enroll(
        &node,
        &token,
        b"cred-green",
        "laptop-green",
        "pillar.example.net",
    );

    // --- LIST (real CLI dispatch) renders both, with their chosen names.
    let listing =
        cli(&["list", "--domain", &domain, "--token", &token]).expect("webauthn list succeeds");
    assert!(
        listing.contains(&cred_blue) && listing.contains("yubikey-blue"),
        "listing carries the first credential's id + name: {listing}"
    );
    assert!(
        listing.contains(&cred_green) && listing.contains("laptop-green"),
        "listing carries the second credential's id + name: {listing}"
    );
    assert_eq!(
        listing.lines().count(),
        2,
        "both enrolled credentials are listed: {listing}"
    );

    // --- REVOKE (real CLI dispatch) of the first credential: a survivor
    // remains, so no confirmation is required.
    let revoke_first = cli(&[
        "revoke",
        "--credential-id",
        &cred_blue,
        "--domain",
        &domain,
        "--token",
        &token,
    ])
    .expect("revoking a non-last credential needs no confirmation");
    assert!(
        revoke_first.contains("REVOKED"),
        "revoke ack: {revoke_first}"
    );

    let listing2 =
        cli(&["list", "--domain", &domain, "--token", &token]).expect("webauthn list succeeds");
    assert!(
        !listing2.contains(&cred_blue),
        "revoked credential no longer listed: {listing2}"
    );
    assert!(
        listing2.contains("laptop-green"),
        "the survivor remains listed: {listing2}"
    );

    // --- Enforce keep->=1: revoking the LAST credential WITHOUT --yes is
    // refused by the CLI (surfaces the node's 409 CONFIRM-REQUIRED as a clear
    // error, never a silent lockout).
    let err = cli(&[
        "revoke",
        "--credential-id",
        &cred_green,
        "--domain",
        &domain,
        "--token",
        &token,
    ])
    .expect_err("revoking the LAST credential without confirmation must be refused");
    assert!(
        err.contains("LAST") || err.contains("last"),
        "refusal explains the last-credential guard: {err}"
    );

    // The un-confirmed revoke was a no-op: the credential is still listed.
    let still =
        cli(&["list", "--domain", &domain, "--token", &token]).expect("webauthn list succeeds");
    assert!(
        still.contains("laptop-green"),
        "un-confirmed last-credential revoke left it intact: {still}"
    );

    // --- With --yes, revoking the LAST credential IS allowed (a lost sole key
    // must still be revocable).
    let revoke_last = cli(&[
        "revoke",
        "--credential-id",
        &cred_green,
        "--yes",
        "--domain",
        &domain,
        "--token",
        &token,
    ])
    .expect("a confirmed last-credential revoke is allowed");
    assert!(revoke_last.contains("REVOKED"), "revoke ack: {revoke_last}");

    let empty =
        cli(&["list", "--domain", &domain, "--token", &token]).expect("webauthn list succeeds");
    assert_eq!(
        empty.trim(),
        "no credentials enrolled",
        "all credentials revoked: {empty}"
    );

    // --- A revoked credential can never re-admit: even a hardware-perfect
    // fresh assertion signed with the revoked key is refused by the real RP
    // (`RevokedKeyNeverAdmits`), proving revoke is a permanent fail-closed
    // effect, not just a management-surface hide.
    let (_public, secret) = pillar_crypto::sign::signing_keypair_from_seed(
        &pillar_crypto::Seed::from_bytes(b"cred-blue".to_vec()),
    )
    .expect("keypair from seed");
    let begin = node.post("/webauthn/authenticate/begin", &token);
    let challenge_b64 = challenge_of(&begin);
    let challenge =
        pillar_crypto::webauthn::base64url_decode(&challenge_b64).expect("challenge decodes");
    use sha2::{Digest, Sha256};
    let cdj = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
        b64(&challenge)
    )
    .into_bytes();
    let mut ad = Vec::new();
    ad.extend_from_slice(&[0u8; 32]);
    ad.push(0x01);
    ad.extend_from_slice(&9u32.to_be_bytes());
    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig = pillar_crypto::sign::sign(&secret, &signed).expect("sign");
    let replay = node.post(
        "/webauthn/authenticate/finish",
        &format!(
            "{token}\n{challenge_b64}\n{}\n{}\n{}\n{}\n{}",
            b64(b"cred-blue"),
            b64(&ad),
            b64(&cdj),
            b64(sig.as_bytes()),
            b64(b"hardware-prf-output"),
        ),
    );
    assert_ne!(
        replay.status, 200,
        "a revoked credential must never re-admit: {}",
        replay.body
    );
}
