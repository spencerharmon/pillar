//! Acceptance test — `um-passkey-lifecycle` (ROI P1 "User management &
//! lifecycle" roadmap B4).
//!
//! Proves the passkey lifecycle surface (list / name / revoke, with a
//! no-lockout keep->=1 guard) over the existing WebAuthn RP endpoints:
//! `/webauthn/credentials/{list,rename,revoke}`. Black-box: execs the real
//! compiled `pillar` binary as a subprocess and drives its real HTTP portal
//! surface, enrolling credentials with a simulated (non-hardware) Ed25519
//! authenticator — the SAME attestation-object / assertion wire format the
//! real RP (`pillar_web::webauthn::RelyingParty`) verifies for a browser or
//! CTAP2 authenticator.
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
    /// the real two-field node-custody login every portal session uses.
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
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn b64(bytes: &[u8]) -> String {
    pillar_crypto::webauthn::base64url_encode(bytes)
}

// Extract the CHALLENGE token from a `CHALLENGE <b64> ...` OK body.
fn challenge_of(resp: &HttpResponse) -> Vec<u8> {
    assert_eq!(resp.status, 200, "begin failed: {}", resp.body);
    let b = resp
        .body
        .split_whitespace()
        .nth(1)
        .expect("challenge field");
    pillar_crypto::webauthn::base64url_decode(b).expect("b64 challenge")
}

// A simulated (non-hardware) Ed25519 authenticator producing the SAME
// attestation-object wire format the real RP verifies for a browser or a
// CTAP2 authenticator. Returns (attestation_object, secret).
fn webauthn_authenticator(
    label: &str,
    credential_id: &[u8],
    sign_count: u32,
) -> (Vec<u8>, pillar_crypto::SigningSecretKey) {
    let (public, secret) = pillar_crypto::sign::signing_keypair_from_seed(
        &pillar_crypto::Seed::from_bytes(label.as_bytes().to_vec()),
    )
    .unwrap();
    let cose = pillar_crypto::webauthn::ed25519_public_key_to_cose(&public).unwrap();
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&[0u8; 32]);
    auth_data.push(0x40 | 0x01); // AT + UP
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
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
    ciborium::into_writer(&att, &mut out).unwrap();
    (out, secret)
}

fn enroll(node: &Node, token: &str, cred: &[u8], label: &str, rp_id: &str) {
    let (att, _secret) = webauthn_authenticator(label, cred, 0);
    let ch = challenge_of(&node.post(
        "/webauthn/register/begin",
        &format!("{token}\nalice@pillar"),
    ));
    let r = node.post(
        "/webauthn/register/finish",
        &format!(
            "{token}\nalice@pillar\n{}\n{}\n{label}\n{rp_id}",
            b64(&ch),
            b64(&att)
        ),
    );
    assert_eq!(r.status, 200, "{}", r.body);
}

#[test]
fn passkey_list_name_revoke_and_keep_at_least_one_guard() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN_HANDLE}\n{ADMIN_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let token = node.login(ADMIN_HANDLE, ADMIN_PASSWORD);

    // Enroll TWO authenticators, each with its own label + rpId.
    enroll(&node, &token, b"cred-blue", "yubikey-blue", "deleteme.example.com");
    enroll(&node, &token, b"cred-green", "laptop-green", "pillar.example.net");

    // --- LIST returns both, oldest-first, carrying the enrolled metadata.
    let list = node.post("/webauthn/credentials/list", &token);
    assert_eq!(list.status, 200, "{}", list.body);
    let rows: Vec<&str> = list.body.lines().collect();
    assert_eq!(rows.len(), 2, "two credentials listed: {}", list.body);
    assert!(rows[0].contains("yubikey-blue"), "{}", rows[0]);
    assert!(rows[1].contains("laptop-green"), "{}", rows[1]);

    let blue_id = b64(b"cred-blue");
    let green_id = b64(b"cred-green");

    // --- NAME (rename) a credential the caller does NOT own -> 404 (never
    // 403, no probing).
    let bogus_rename = node.post(
        "/webauthn/credentials/rename",
        &format!("{token}\n{}\nnew-label", b64(b"not-a-real-cred")),
    );
    assert_eq!(bogus_rename.status, 404, "{}", bogus_rename.body);

    // --- NAME (rename) the blue credential; LIST reflects the new label
    // and the rpId/created/sign-count are otherwise unchanged.
    let rename = node.post(
        "/webauthn/credentials/rename",
        &format!("{token}\n{blue_id}\nmy-renamed-key"),
    );
    assert_eq!(rename.status, 200, "{}", rename.body);
    assert!(rename.body.starts_with("RENAMED"), "{}", rename.body);

    let list2 = node.post("/webauthn/credentials/list", &token);
    let rows2: Vec<&str> = list2.body.lines().collect();
    assert!(
        rows2.iter().any(|r| r.contains("my-renamed-key")),
        "renamed label visible in list: {}",
        list2.body
    );
    assert!(
        !rows2.iter().any(|r| r.contains("yubikey-blue")),
        "old label gone from list: {}",
        list2.body
    );
    assert!(
        rows2
            .iter()
            .any(|r| r.contains("deleteme.example.com")),
        "rpId unaffected by rename: {}",
        list2.body
    );

    // --- Revoking a credential the caller does NOT own -> 404.
    let bogus_revoke = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{}", b64(b"not-a-real-cred")),
    );
    assert_eq!(bogus_revoke.status, 404, "{}", bogus_revoke.body);

    // --- REVOKE the renamed (blue) credential: allowed (a second remains).
    let rev = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{blue_id}"),
    );
    assert_eq!(rev.status, 200, "{}", rev.body);
    assert!(rev.body.starts_with("REVOKED"), "{}", rev.body);

    let list3 = node.post("/webauthn/credentials/list", &token);
    let rows3: Vec<&str> = list3.body.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(rows3.len(), 1, "one credential remains: {}", list3.body);
    assert!(rows3[0].contains("laptop-green"), "{}", rows3[0]);

    // --- No-lockout keep->=1 guard: revoking the LAST credential WITHOUT
    // confirmation is refused 409 CONFIRM-REQUIRED.
    let last_no_confirm = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{green_id}"),
    );
    assert_eq!(last_no_confirm.status, 409, "{}", last_no_confirm.body);
    assert!(
        last_no_confirm.body.contains("CONFIRM-REQUIRED"),
        "{}",
        last_no_confirm.body
    );
    // The credential must still be present (the guard is fail-closed).
    let list4 = node.post("/webauthn/credentials/list", &token);
    assert!(
        list4.body.contains("laptop-green"),
        "last credential survives the refused revoke: {}",
        list4.body
    );

    // --- With explicit confirmation, the last credential CAN be revoked
    // (a lost/stolen sole key must still be revocable).
    let last_confirmed = node.post(
        "/webauthn/credentials/revoke",
        &format!("{token}\n{green_id}\nconfirm"),
    );
    assert_eq!(last_confirmed.status, 200, "{}", last_confirmed.body);
    let list5 = node.post("/webauthn/credentials/list", &token);
    assert!(
        list5.body.trim().is_empty(),
        "no credentials remain: {}",
        list5.body
    );
}
