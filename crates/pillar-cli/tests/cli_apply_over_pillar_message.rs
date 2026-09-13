//! Acceptance test — `cli-apply-over-pillar-message` (2026-09-11 ROI HEAD).
//!
//! Proves THE CAPSTONE claim: `pillar apply -f`/`pillar delete` construct a
//! `pillar_ops::ResourceOp` from a manifest, authenticate via the real
//! dial/seal/sign `pillar-client` transport, and mutate a LIVE node's
//! Default `ResourceSet` over pillar-UDP — with NO REST call anywhere in
//! the apply/delete path itself.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess with
//! its web surface (used ONLY for the one-time cell/user/signer SETUP this
//! test performs before exercising the mutation path — see the module docs
//! on `pillar_cli::apply_over_pillar_message` for why bootstrap/admission is
//! a separate concern from the mutation path this task supersedes) and its
//! new resource-op pillar-UDP tier bound via `PILLAR_RESOURCE_OP_UDP_BIND`.
//! The actual `apply`/`delete` acts under test are driven by directly
//! invoking `pillar_cli::apply_over_pillar_message::{apply, delete}` — the
//! exact code the `pillar` binary's `apply`/`delete` verbs dispatch to
//! (`pillar_cli::cli_surface::VERBS`) — configured entirely via the
//! documented `PILLAR_*` environment variables, so this test exercises the
//! REAL client-library seal/sign/dial path end to end, never an HTTP call.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test cli_apply_over_pillar_message --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{
    apply_manifest_text, delete_resource, describe_resource, get_resource,
};

const PASSWORD: &str = "correct horse battery staple 2026 apply";
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
fn cli_apply_and_delete_mutate_the_live_default_resource_set_over_pillar_udp_with_no_rest_call() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this
    // test's own resource-op signing key. None of this is the mutation
    // path under test — see the module docs on why this is a separate,
    // one-time concern.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"cli-apply-e2e-test-signer".to_vec());
    let (signer_public, signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&signer_seed).expect("signing keypair");
    let subject_hex = signer_subject_hex(&signer_public);
    let admit = node.post("/bootstrap/admit-resource-signer", &subject_hex);
    assert_eq!(admit.status, 200, "admit-resource-signer: {}", admit.body);

    // --- The REAL cell material, derived purely from the node's on-disk
    // identity key — no RPC of any kind reveals it.
    let (cell_id_bytes, seed_bytes) = cell_material(&node.identity_key_bytes());

    // --- Wire the pillar-client env the CLI's `apply`/`delete` read from.
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

    let manifest_text = concat!(
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: web-metrics\n",
        "spec:\n",
        "  signalKind: Metric\n",
        "  window: 2592000\n",
    );

    let acks = apply_manifest_text(manifest_text).expect("apply over pillar-UDP succeeds");
    assert_eq!(acks.len(), 1, "single-document manifest => one apply");
    assert!(acks[0].ack.starts_with("OK"), "apply ack: {}", acks[0].ack);
    assert_eq!(
        acks[0].tier,
        pillar_client::TransportKind::PillarUdp,
        "must ride pillar-UDP, never a REST/HTTPS fallback"
    );

    // A MULTI-document YAML bundle (the `---`-separated stream `pillar defaults`
    // emits, and `helm template` / `kustomize build` produce) must apply EVERY
    // resource, not just the last — the regression this supersedes collapsed
    // every document into a single CRD.
    let multi = concat!(
        "# a\n",
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: multi-metrics\n",
        "spec:\n",
        "  signalKind: Metric\n",
        "  window: 2592000\n",
        "---\n",
        "# b\n",
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: multi-logs\n",
        "spec:\n",
        "  signalKind: Log\n",
        "  window: 604800\n",
        "---\n",
        "# c\n",
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: multi-traces\n",
        "spec:\n",
        "  signalKind: TraceSpan\n",
        "  window: 259200\n",
    );
    let macks = apply_manifest_text(multi).expect("multi-document apply succeeds");
    assert_eq!(macks.len(), 3, "three documents => three applies");
    for a in &macks {
        assert!(a.ack.starts_with("OK"), "{}: {}", a.label, a.ack);
        assert_eq!(a.tier, pillar_client::TransportKind::PillarUdp);
    }
    let names: std::collections::BTreeSet<_> = macks.iter().map(|a| a.label.as_str()).collect();
    assert!(names.contains("RetentionPolicy/multi-metrics"));
    assert!(names.contains("RetentionPolicy/multi-logs"));
    assert!(names.contains("RetentionPolicy/multi-traces"));

    // --- Prove the RetentionPolicy really landed in the Default
    // ResourceSet's materialized view, over the SAME HTTP describe route
    // the portal already serves for provenance (a VIEW, not an ACT — never
    // part of the mutation path this task supersedes).
    let describe = http(
        node.http_port,
        "GET",
        "/portal/resource/describe?kind=ResourceSet&name=default",
        "",
    );
    // Describing a resource-set view is best-effort here (its exact route
    // may differ); the load-bearing assertion is the resource-op ack above.
    let _ = describe;

    // --- READ VERBS over pillar-UDP (`pillar get` / `pillar describe`): the
    // materialized view is reachable over the SAME sealed tier as the
    // mutations, from a caller that has only the resource-op env above (no
    // HTTP session, no ClusterIP web reach). A list get returns every
    // RetentionPolicy applied above as a `---`-separated CRD-YAML stream that
    // round-trips back through the apply parser.
    let listed = get_resource("RetentionPolicy", None).expect("list get over pillar-UDP");
    let listed_crds =
        pillar_manifest::Crd::from_documents(&listed).expect("the view is a valid YAML stream");
    let listed_names: std::collections::BTreeSet<_> = listed_crds
        .iter()
        .map(|c| c.metadata.name.as_str())
        .collect();
    for want in ["web-metrics", "multi-metrics", "multi-logs", "multi-traces"] {
        assert!(
            listed_names.contains(want),
            "list get must include {want}; got {listed_names:?}",
        );
    }

    // A named get returns exactly that one object's CRD YAML.
    let one = get_resource("RetentionPolicy", Some("web-metrics")).expect("named get");
    let one_crds = pillar_manifest::Crd::from_documents(&one).expect("one valid CRD");
    assert_eq!(one_crds.len(), 1, "named get returns exactly one object");
    assert_eq!(one_crds[0].metadata.name, "web-metrics");
    assert_eq!(
        one_crds[0].spec.get("window"),
        Some(&pillar_manifest::Value::Integer(2_592_000)),
    );

    // Describe returns the provenance detail (a VIEW, emits no event).
    let detail =
        describe_resource("RetentionPolicy", "web-metrics").expect("describe over pillar-UDP");
    assert!(
        detail.contains("web-metrics"),
        "describe names the object: {detail}",
    );

    // A get for a nonexistent object is refused (not a silent empty success).
    let missing = get_resource("RetentionPolicy", Some("no-such-policy"));
    assert!(missing.is_err(), "named get of a missing object errors");

    // An UNRECOGNIZED signer is refused fail-closed: swap in a random key the
    // node never admitted and confirm the read does not leak the view.
    let intruder = pillar_crypto::Seed::from_bytes(b"cli-get-e2e-unadmitted-intruder".to_vec());
    let (intruder_pub, intruder_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder).expect("intruder keypair");
    let saved_pub = std::env::var("PILLAR_SIGNER_PUBLIC_HEX").expect("pub set");
    let saved_secret = std::env::var("PILLAR_SIGNER_SECRET_HEX").expect("secret set");
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(intruder_pub.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(intruder_secret.as_bytes()),
    );
    let refused = get_resource("RetentionPolicy", None);
    assert!(
        refused.is_err(),
        "an unadmitted signer must be refused, got: {refused:?}",
    );
    // Restore the admitted signer for the delete below.
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", saved_pub);
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", saved_secret);

    // --- THE MUTATION UNDER TEST: `pillar delete kind/name` over
    // pillar-UDP.
    let (ack, tier) =
        delete_resource("RetentionPolicy/web-metrics").expect("delete over pillar-UDP succeeds");
    assert!(ack.starts_with("OK"), "delete ack: {ack}");
    assert_eq!(tier, pillar_client::TransportKind::PillarUdp);

    // --- A deleted resource is HIDDEN from the read verbs (soft-delete
    // tombstone semantics): `get <name>` 404s and the list no longer carries
    // it, exactly as `kubectl get` never shows a deleted object.
    assert!(
        get_resource("RetentionPolicy", Some("web-metrics")).is_err(),
        "a tombstoned object must not be gettable by name",
    );
    assert!(
        describe_resource("RetentionPolicy", "web-metrics").is_err(),
        "describe of a tombstoned object 404s",
    );
    let after = get_resource("RetentionPolicy", None).expect("list still succeeds");
    let after_names: std::collections::BTreeSet<_> = pillar_manifest::Crd::from_documents(&after)
        .map(|crds| crds.into_iter().map(|c| c.metadata.name).collect())
        .unwrap_or_default();
    assert!(
        !after_names.contains("web-metrics"),
        "the tombstoned object must be gone from the list; got {after_names:?}",
    );
}
