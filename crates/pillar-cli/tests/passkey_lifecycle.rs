//! Acceptance test — `um-passkey-lifecycle` (ROI P1 "User management &
//! lifecycle" roadmap B4).
//!
//! Proves the passkey MANAGEMENT surface (list/name/revoke) over the
//! existing WebAuthn RP + `/webauthn/register/*` ceremony end-to-end against
//! a real booted node, and — the crux of the task — the no-lockout guard:
//! revoking a user's LAST credential is refused (`409 CONFIRM-REQUIRED`)
//! unless the caller explicitly confirms, while renaming (purely cosmetic)
//! never gates on lockout at all.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess and
//! drives its real HTTP portal + WebAuthn surface, registering two
//! credentials with a hand-built (no-hardware) attestation object — exactly
//! the same wire shape `pillar_web::webauthn::RelyingParty`'s own unit tests
//! and the browser ceremony produce.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test passkey_lifecycle --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::webauthn::{base64url_decode, base64url_encode, ed25519_public_key_to_cose};
use pillar_crypto::Seed;

const HANDLE: &str = "alice@pillar";
const PASSWORD: &str = "correct horse battery staple 2026 passkey-lifecycle";

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

/// A booted `pillar node run` subprocess with its HTTP portal surface
/// bound; killed on drop.
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

    /// GET /nonce then POST /login with `identifier\npassword\n<nonce id>` —
    /// the real two-field node-custody login every portal session uses. The
    /// admitted session token is carried on the `X-Pillar-Session` response
    /// header (never the body).
    fn login(&self, identifier: &str, password: &str) -> String {
        let nonce_resp = self.get("/nonce");
        assert_eq!(nonce_resp.status, 200, "nonce: {}", nonce_resp.body);
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id")
            .parse()
            .expect("nonce id parses");
        let login_resp = self.post("/login", &format!("{identifier}\n{password}\n{id}"));
        assert_eq!(login_resp.status, 200, "login: {}", login_resp.body);
        login_resp
            .session_token
            .expect("login response carries a session token")
    }

    /// Drive a full no-hardware `/webauthn/register/{begin,finish}` ceremony:
    /// mint a challenge, hand-build a minimal `fmt: none` attestation object
    /// over a fresh Ed25519 "authenticator" keypair (exactly the wire shape
    /// `pillar_web::webauthn::RelyingParty`'s own unit tests and the browser
    /// ceremony produce — no real hardware / ctap-hid needed), and register
    /// it under `label`. Returns the credential id (b64url) minted.
    fn register_passkey(&self, token: &str, label: &str, credential_id: &[u8]) -> String {
        let begin = self.post("/webauthn/register/begin", &format!("{token}\n{HANDLE}"));
        assert_eq!(begin.status, 200, "register/begin: {}", begin.body);
        let mut fields = begin.body.split_whitespace();
        assert_eq!(fields.next(), Some("CHALLENGE"));
        let challenge_b64 = fields.next().expect("challenge").to_owned();
        let rp_id = fields.next().unwrap_or("pillar.local").to_owned();

        let seed = Seed::from_bytes(format!("passkey-lifecycle-{label}").into_bytes());
        let (public, _secret) = signing_keypair_from_seed(&seed).expect("keygen");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        let attestation_b64 = base64url_encode(&attestation_object(&cose, credential_id, 0));

        let finish = self.post(
            "/webauthn/register/finish",
            &format!("{token}\n{HANDLE}\n{challenge_b64}\n{attestation_b64}\n{label}\n{rp_id}"),
        );
        assert_eq!(finish.status, 200, "register/finish: {}", finish.body);
        base64url_encode(credential_id)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Hand-build a minimal `fmt: none` CBOR attestation object carrying
/// `authData` (rpIdHash || flags(AT|UP) || signCount || aaguid=0 ||
/// credIdLen || credId || COSE public key) — the exact shape
/// `pillar_web::webauthn::RelyingParty::register_finish`'s
/// `pillar_crypto::webauthn::parse_attestation` expects, mirroring
/// `pillar_web::webauthn`'s own `mod tests::attestation` helper.
fn attestation_object(cose: &[u8], credential_id: &[u8], sign_count: u32) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash (unchecked here)
    auth_data.push(0x40 | 0x01); // flags: AT (attested cred data) | UP (user present)
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]); // aaguid
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose);
    use ciborium::value::Value;
    let att = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&att, &mut out).expect("cbor encode");
    out
}

/// Parse one `CRED <id> <label> <rp_id> <created> <last|-> <signs>` line from
/// `/webauthn/credentials/list`'s body into `(id, label)`.
fn parse_cred_lines(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() == 7 && f[0] == "CRED" {
                Some((f[1].to_owned(), f[2].to_owned()))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn passkey_list_name_revoke_enforce_no_lockout() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let token = node.login(HANDLE, PASSWORD);

    // --- 0. No credentials yet: an empty set.
    let empty = node.post("/webauthn/credentials/list", &token);
    assert_eq!(empty.status, 200, "list: {}", empty.body);
    assert!(
        empty.body.trim().is_empty(),
        "no credentials enrolled yet: {}",
        empty.body
    );

    // --- 1. Enroll TWO passkeys.
    let cred_a = node.register_passkey(&token, "laptop", b"cred-passkey-a");
    let cred_b = node.register_passkey(&token, "yubikey", b"cred-passkey-b");

    // --- 2. LIST shows both, oldest-first, with their labels.
    let list = node.post("/webauthn/credentials/list", &token);
    assert_eq!(list.status, 200, "list: {}", list.body);
    let creds = parse_cred_lines(&list.body);
    assert_eq!(creds.len(), 2, "both credentials listed: {}", list.body);
    assert_eq!(creds[0], (cred_a.clone(), "laptop".to_owned()));
    assert_eq!(creds[1], (cred_b.clone(), "yubikey".to_owned()));

    // --- 3. NAME (rename) one credential; the new label is reflected in a
    // subsequent list, and the OTHER credential's label is untouched.
    let rename = node.post(
        "/webauthn/credentials/name",
        &format!("{token}\n{cred_a}\nwork-laptop"),
    );
    assert_eq!(rename.status, 200, "name: {}", rename.body);
    assert!(
        rename.body.contains("work-laptop"),
        "rename ack echoes the new label: {}",
        rename.body
    );
    let after_rename = parse_cred_lines(&node.post("/webauthn/credentials/list", &token).body);
    assert_eq!(after_rename[0], (cred_a.clone(), "work-laptop".to_owned()));
    assert_eq!(after_rename[1], (cred_b.clone(), "yubikey".to_owned()));

    // --- 4. REVOKE cred_a (not the last one — succeeds immediately, no
    // confirm needed).
    let revoke_a = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{cred_a}"),
    );
    assert_eq!(revoke_a.status, 200, "revoke non-last: {}", revoke_a.body);
    let after_revoke_a = parse_cred_lines(&node.post("/webauthn/credentials/list", &token).body);
    assert_eq!(after_revoke_a.len(), 1);
    assert_eq!(after_revoke_a[0].0, cred_b);

    // --- 5. NO-LOCKOUT GUARD: cred_b is now the caller's LAST credential.
    // Revoking it WITHOUT confirmation is refused (409 CONFIRM-REQUIRED); the
    // credential remains live.
    let revoke_last_unconfirmed = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{cred_b}"),
    );
    assert_eq!(
        revoke_last_unconfirmed.status, 409,
        "revoking the last credential without confirm must be refused: {}",
        revoke_last_unconfirmed.body
    );
    assert!(
        revoke_last_unconfirmed
            .body
            .contains("CONFIRM-REQUIRED"),
        "refusal names the confirm gate: {}",
        revoke_last_unconfirmed.body
    );
    let still_there = parse_cred_lines(&node.post("/webauthn/credentials/list", &token).body);
    assert_eq!(still_there.len(), 1, "unconfirmed revoke did not apply");

    // --- 5b. Renaming the LAST credential is always allowed (never gated
    // on lockout — it is purely cosmetic).
    let rename_last = node.post(
        "/webauthn/credentials/name",
        &format!("{token}\n{cred_b}\nlast-key"),
    );
    assert_eq!(
        rename_last.status, 200,
        "renaming the last credential is never lockout-gated: {}",
        rename_last.body
    );

    // --- 6. Revoking the last credential WITH confirmation succeeds; the
    // credential set is now empty.
    let revoke_last_confirmed = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{cred_b}\nconfirm"),
    );
    assert_eq!(
        revoke_last_confirmed.status, 200,
        "confirmed last-credential revoke succeeds: {}",
        revoke_last_confirmed.body
    );
    let empty_again = node.post("/webauthn/credentials/list", &token);
    assert!(
        empty_again.body.trim().is_empty(),
        "credential set is empty after the confirmed revoke: {}",
        empty_again.body
    );

    // --- 7. Revoking / naming an UNKNOWN (or someone else's) credential id
    // is refused not-found, never silently accepted.
    let unknown = base64url_encode(b"never-registered");
    let bad_revoke = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{unknown}"),
    );
    assert_eq!(bad_revoke.status, 404, "unknown credential: {}", bad_revoke.body);
    let bad_name = node.post(
        "/webauthn/credentials/name",
        &format!("{token}\n{unknown}\nnope"),
    );
    assert_eq!(bad_name.status, 404, "unknown credential: {}", bad_name.body);

    // Sanity: base64url_decode round-trips what register_passkey encoded
    // (guards against a helper bug silently making every assertion above a
    // vacuous string-equality check on garbage).
    assert_eq!(base64url_decode(&cred_b).unwrap(), b"cred-passkey-b");
}
