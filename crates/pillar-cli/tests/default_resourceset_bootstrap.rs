//! Acceptance test — `default-resourceset-bootstrap` (ROI Priority 1
//! deliverable #2, 2026-09-14).
//!
//! Proves that a freshly bootstrapped cell auto-materializes its Default
//! ResourceSet floor: the shipped default `RetentionPolicy` set
//! (`pillar_cli::defaults::bootstrap_default_manifests`) is applied for real
//! at `POST /bootstrap/create-cell` time — no manual `pillar apply` needed —
//! and each seeded object is a real, user-viewable/editable resource
//! (`pillar get`) whose EXISTENCE is bootstrap-guaranteed: a `pillar delete`
//! against it is refused rather than silently tombstoning it away.
//!
//! Black-box: boots the real compiled `pillar` binary exactly as
//! `cli_apply_over_pillar_message.rs` does, drives the one-time HTTP SETUP
//! (`create-cell` / `create-user` / `admit-resource-signer`), then reads/
//! mutates the live resource plane over the real pillar-UDP resource-op
//! transport via `pillar_cli::apply_over_pillar_message::{get_resource,
//! delete_resource}` — the exact library the `pillar` binary's `get`/`delete`
//! verbs dispatch to.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test default_resourceset_bootstrap --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{delete_resource, get_resource};

const PASSWORD: &str = "correct horse battery staple 2026 resourceset";
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

/// A booted `pillar node run` subprocess with its HTTPS (SETUP-only) and
/// resource-op pillar-UDP tiers bound; killed on drop.
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

    /// Read the raw on-disk identity key bytes — EXACTLY
    /// `pillar_cli::run::load_or_create_identity`'s persisted form
    /// (`Keypair::to_protobuf_encoding()`), so this test can reproduce the
    /// node's `cell_id`/`cell_group_key` derivation independently, with no
    /// RPC of any kind to obtain them.
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

/// Reproduce the node's `identity_seed_material`/`cell_id` derivation
/// (`pillar_cli::run::run`) from the raw on-disk identity key bytes alone —
/// a pure function of `<data_dir>/identity.key`, no network call involved.
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
fn cell_bootstrap_seeds_the_default_resourceset_floor_and_refuses_its_deletion() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this
    // test's own resource-op signing key. This IS the bootstrap step under
    // test — `create-cell` must, as a side effect, seed the Default
    // ResourceSet's floor RetentionPolicy resources.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"resourceset-bootstrap-test-signer".to_vec());
    let (signer_public, signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&signer_seed).expect("signing keypair");
    let subject_hex = signer_subject_hex(&signer_public);
    let admit = node.post("/bootstrap/admit-resource-signer", &subject_hex);
    assert_eq!(admit.status, 200, "admit-resource-signer: {}", admit.body);

    // --- The REAL cell material, derived purely from the node's on-disk
    // identity key — no RPC of any kind reveals it.
    let (cell_id_bytes, seed_bytes) = cell_material(&node.identity_key_bytes());

    // --- Wire the pillar-client env the CLI's `get`/`delete` read from.
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

    // --- 1. Existence is bootstrap-guaranteed: the three shipped default
    // RetentionPolicy resources are already LIVE — no `pillar apply` was
    // ever sent by this test.
    let metrics = get_resource("RetentionPolicy", Some("metrics-default"))
        .expect("metrics-default RetentionPolicy is auto-seeded at bootstrap");
    assert!(
        metrics.contains("name: metrics-default"),
        "seeded metrics-default CRD: {metrics}"
    );
    assert!(
        metrics.contains("pillar.dev/floor"),
        "seeded default carries the floor label: {metrics}"
    );

    let logs = get_resource("RetentionPolicy", Some("logs-default"))
        .expect("logs-default RetentionPolicy is auto-seeded at bootstrap");
    assert!(logs.contains("name: logs-default"), "{logs}");

    let traces = get_resource("RetentionPolicy", Some("traces-default"))
        .expect("traces-default RetentionPolicy is auto-seeded at bootstrap");
    assert!(traces.contains("name: traces-default"), "{traces}");

    // --- 2. These are ordinary, user-viewable resources: listing the whole
    // kind shows all three, exactly like any other `pillar get` output.
    let all = get_resource("RetentionPolicy", None).expect("list RetentionPolicy");
    for name in ["metrics-default", "logs-default", "traces-default"] {
        assert!(
            all.contains(&format!("name: {name}")),
            "listing includes {name}: {all}"
        );
    }

    // --- 3. A delete of a floor object is refused — existence self-heals by
    // never actually being removed. The ack is an `ERR ...` explaining why,
    // never a silent success.
    let (ack, _tier) =
        delete_resource("RetentionPolicy/metrics-default").expect("delete send succeeds");
    assert!(
        ack.starts_with("ERR"),
        "floor delete must be refused: {ack}"
    );
    assert!(
        ack.contains("floor") && ack.contains("refused"),
        "refusal explains the floor guarantee: {ack}"
    );

    // The object is still there after the refused delete attempt.
    let still_there = get_resource("RetentionPolicy", Some("metrics-default"))
        .expect("metrics-default still exists after the refused delete");
    assert!(
        still_there.contains("name: metrics-default"),
        "{still_there}"
    );

    // --- 4. A non-floor (operator-authored) resource is NOT protected: an
    // ordinary apply + delete round-trips exactly as it always has, proving
    // the floor guard is scoped to bootstrap-seeded objects, not a blanket
    // delete lockout.
    use pillar_cli::apply_over_pillar_message::apply_manifest_text;
    let operator_manifest = concat!(
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: operator-authored\n",
        "spec:\n",
        "  signalKind: Metric\n",
        "  window: 3600\n",
    );
    let acks = apply_manifest_text(operator_manifest).expect("apply operator resource");
    assert!(acks[0].ack.starts_with("OK"), "{}", acks[0].ack);
    let (del_ack, _tier) =
        delete_resource("RetentionPolicy/operator-authored").expect("delete send succeeds");
    assert!(
        del_ack.starts_with("OK"),
        "operator-authored resource deletes normally: {del_ack}"
    );
}
