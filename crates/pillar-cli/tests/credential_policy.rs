//! Acceptance test — `um-credential-policy` (ROI Priority 1 "User management &
//! lifecycle" roadmap B2).
//!
//! Proves that a freshly bootstrapped cell auto-materializes the cell-wide
//! `CredentialPolicy` floor object: the shipped default credential policy
//! (`pillar_cli::credential_policy::bootstrap_credential_policy_manifest`) is
//! applied for real at `POST /bootstrap/create-cell` time — no manual
//! `pillar apply` needed — and it is a real, user-viewable/editable resource
//! (`pillar get` / `pillar apply -f -`) whose EXISTENCE is bootstrap-guaranteed
//! (a `pillar delete` against it is refused), exactly like the default
//! `RetentionPolicy` floor. It further proves the resource is EDITABLE (an
//! operator apply changes its spec, existence pinned) and that the enforcement
//! the change/reset ceremonies run (`evaluate_new_password`) reads that same
//! policy and the runtime-supplied breach list.
//!
//! Black-box: boots the real compiled `pillar` binary exactly as
//! `default_resourceset_bootstrap.rs` does and drives the live resource plane
//! over the real pillar-UDP resource-op transport.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test credential_policy --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{apply_manifest_text, delete_resource, get_resource};
use pillar_cli::credential_policy::{
    evaluate_new_password, BreachList, CredentialPolicy, CredentialPolicyViolation,
    CREDENTIAL_POLICY_NAME,
};

const PASSWORD: &str = "correct horse battery staple 2026 credential-policy";
const HANDLE: &str = "spencer";

struct HttpResponse {
    status: u16,
    body: String,
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

    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        body: resp_body,
    })
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .expect("claim free udp port")
}

struct Node {
    child: Child,
    http_port: u16,
    resource_op_port: u16,
    data_dir: std::path::PathBuf,
}

impl Node {
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let resource_op_port = free_udp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env(
                "PILLAR_RESOURCE_OP_UDP_BIND",
                format!("127.0.0.1:{resource_op_port}"),
            )
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node {
            child,
            http_port,
            resource_op_port,
            data_dir: data_dir.to_path_buf(),
        };
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

    fn resource_op_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.resource_op_port)
            .parse()
            .unwrap()
    }

    fn identity_key_bytes(&self) -> Vec<u8> {
        std::fs::read(self.data_dir.join("identity.key")).expect("read identity.key")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

fn signer_subject_hex(public: &pillar_crypto::SigningPublicKey) -> String {
    hex_encode(public.as_bytes())
}

#[test]
fn cell_bootstrap_seeds_the_editable_credential_policy_floor_read_by_the_ceremonies() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP: bootstrap a cell + first user, admit this test's resource-op
    // signing key. `create-cell` must, as a side effect, seed the cell-wide
    // CredentialPolicy floor.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"credential-policy-test-signer".to_vec());
    let (signer_public, signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&signer_seed).expect("signing keypair");
    let subject_hex = signer_subject_hex(&signer_public);
    let admit = node.post("/bootstrap/admit-resource-signer", &subject_hex);
    assert_eq!(admit.status, 200, "admit-resource-signer: {}", admit.body);

    let (cell_id_bytes, seed_bytes) = cell_material(&node.identity_key_bytes());

    std::env::set_var(
        "PILLAR_RESOURCE_OP_ADDR",
        node.resource_op_addr().to_string(),
    );
    std::env::set_var("PILLAR_CELL_ID_HEX", hex_encode(&cell_id_bytes));
    std::env::set_var("PILLAR_CELL_SEED_HEX", hex_encode(&seed_bytes));
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(signer_public.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(signer_secret.as_bytes()),
    );

    // --- 1. Existence is bootstrap-guaranteed: the CredentialPolicy floor is
    // already LIVE — no `pillar apply` was ever sent for it.
    let live = get_resource("CredentialPolicy", Some(CREDENTIAL_POLICY_NAME))
        .expect("credential-policy is auto-seeded at bootstrap");
    assert!(
        live.contains(&format!("name: {CREDENTIAL_POLICY_NAME}")),
        "seeded credential policy CRD: {live}"
    );
    assert!(
        live.contains("pillar.dev/floor"),
        "seeded default carries the floor label: {live}"
    );

    // --- 2. A delete of the floor object is refused (existence self-heals).
    let (ack, _tier) = delete_resource(&format!("CredentialPolicy/{CREDENTIAL_POLICY_NAME}"))
        .expect("delete send succeeds");
    assert!(
        ack.starts_with("ERR"),
        "floor delete must be refused: {ack}"
    );
    assert!(
        ack.contains("floor") && ack.contains("refused"),
        "refusal explains the floor guarantee: {ack}"
    );
    let still_there = get_resource("CredentialPolicy", Some(CREDENTIAL_POLICY_NAME))
        .expect("credential policy still exists after the refused delete");
    assert!(still_there.contains(&format!("name: {CREDENTIAL_POLICY_NAME}")));

    // --- 3. The floor is EDITABLE: an operator apply changes its spec (only
    // existence is pinned, not content). Tighten the minimum strength to 5.
    let edited = format!(
        concat!(
            "apiVersion: pillar.dev/v1\n",
            "kind: CredentialPolicy\n",
            "metadata:\n",
            "  name: {name}\n",
            "spec:\n",
            "  minPasswordStrength: 5\n",
            "  reuseHistory: 3\n",
            "  breachCheck: true\n",
        ),
        name = CREDENTIAL_POLICY_NAME
    );
    let acks = apply_manifest_text(&edited).expect("apply edited credential policy");
    assert!(acks[0].ack.starts_with("OK"), "{}", acks[0].ack);
    let after = get_resource("CredentialPolicy", Some(CREDENTIAL_POLICY_NAME))
        .expect("edited credential policy is readable");
    assert!(
        after.contains("minPasswordStrength: 5"),
        "operator edit took effect: {after}"
    );

    // --- 4. The enforcement the change/reset ceremonies run reads THIS policy
    // (min strength 5 here) plus the runtime-supplied breach list. This is the
    // exact function the ceremonies call before sealing a new password.
    let policy = CredentialPolicy {
        min_password_strength: 5,
        max_password_age_secs: None,
        reuse_history: 3,
        breach_check: true,
    };
    let breach = BreachList::from_entries([b"Breached-Passw0rd!".to_vec()]);

    // Too weak for the tightened floor.
    assert!(matches!(
        evaluate_new_password(&policy, b"abc", &[], &breach),
        Err(CredentialPolicyViolation::TooWeak { .. })
    ));
    // Strong enough, but present in the runtime breach list.
    assert_eq!(
        evaluate_new_password(&policy, b"Breached-Passw0rd!", &[], &breach),
        Err(CredentialPolicyViolation::Breached)
    );
    // Reused within the history window.
    let history = vec![b"Str0ng-Passw0rd!".to_vec()];
    assert_eq!(
        evaluate_new_password(&policy, b"Str0ng-Passw0rd!", &history, &breach),
        Err(CredentialPolicyViolation::Reused)
    );
    // A strong, unbreached, unused password is admitted.
    assert_eq!(
        evaluate_new_password(&policy, b"Fresh-N0vel-Passw0rd!", &history, &breach),
        Ok(())
    );

    // --- 5. A non-floor resource is NOT protected — proving the floor guard is
    // scoped to bootstrap-seeded objects, not a blanket lockout of the kind.
    let operator = concat!(
        "apiVersion: pillar.dev/v1\n",
        "kind: CredentialPolicy\n",
        "metadata:\n",
        "  name: operator-authored-policy\n",
        "spec:\n",
        "  minPasswordStrength: 2\n",
    );
    let acks = apply_manifest_text(operator).expect("apply operator credential policy");
    assert!(acks[0].ack.starts_with("OK"), "{}", acks[0].ack);
    let (del_ack, _tier) =
        delete_resource("CredentialPolicy/operator-authored-policy").expect("delete send succeeds");
    assert!(
        del_ack.starts_with("OK"),
        "operator-authored resource deletes normally: {del_ack}"
    );
}
