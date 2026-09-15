//! Acceptance test — `data-query-tier-remote-surface` (ROI Priority 1
//! data-layer doctrine: "a real remote query surface, over pillar-message").
//!
//! Proves the load-bearing DoD/GATE claim: a LIVE `pillar node run` serves a
//! typed `QueryOp` (`pillar_wire::Body::QueryOp`) over the SAME sealed, signed
//! resource-op pillar-UDP tier as the apply/control tiers, and the `pillar kv`
//! / `pillar doc` / `pillar sql` CLI verbs round-trip a REAL answer against the
//! node's live keyed store (K/V + Document) and its SQL views — never a
//! crate-level fold round-trip and never a portal `GET .../get?kind=` shim.
//!
//! Black-box: boots the real compiled `pillar` binary as a subprocess with its
//! web surface (used ONLY for the one-time cell/user/signer SETUP), and drives
//! the query acts by directly invoking the exact functions the `pillar kv`/
//! `doc`/`sql` verbs dispatch to (`pillar_cli::apply_over_pillar_message::
//! query_op`, the query-op sibling of `send_op`/`send_control_op`), configured
//! entirely via the documented `PILLAR_*` env vars — so this test exercises the
//! REAL client-library seal/sign/dial path end to end, never an HTTP call.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test data_query_tier_remote_surface --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{DocOp, KvOp, QueryOp, SqlOp};

const PASSWORD: &str = "correct horse battery staple 2026 data query";
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

    /// The raw on-disk identity key bytes — EXACTLY the node's persisted form,
    /// so this test can reproduce the node's `cell_id`/`cell_group_key`
    /// derivation with no RPC.
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

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).unwrap();
        let lo = (chunk[1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
    }
    out
}

/// Reproduce the node's `cell_id`/seed derivation from the on-disk identity key
/// bytes alone (mirrors `cli_apply_over_pillar_message`'s `cell_material`).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

#[test]
fn cli_kv_doc_sql_round_trip_a_real_query_against_the_live_node_over_pillar_udp() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key. None of this is the query path under test.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"data-query-e2e-test-signer".to_vec());
    let (signer_public, signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&signer_seed).expect("signing keypair");
    let subject_hex = hex_encode(signer_public.as_bytes());
    let admit = node.post("/bootstrap/admit-resource-signer", &subject_hex);
    assert_eq!(admit.status, 200, "admit-resource-signer: {}", admit.body);

    // --- The REAL cell material, derived purely from the node's on-disk key.
    let (cell_id_bytes, seed_bytes) = cell_material(&node.identity_key_bytes());

    // --- Wire the pillar-client env the query verbs read from.
    std::env::set_var(
        "PILLAR_RESOURCE_OP_ADDR",
        node.resource_op_addr().to_string(),
    );
    std::env::set_var("PILLAR_CELL_ID_HEX", hex_encode(&cell_id_bytes));
    std::env::set_var("PILLAR_CELL_SEED_HEX", hex_encode(&seed_bytes));
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", hex_encode(signer_public.as_bytes()));
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", hex_encode(signer_secret.as_bytes()));

    // === K/V surface ========================================================
    // A signed PUT lands a value on the LIVE node over pillar-UDP.
    let ack = query_op(&QueryOp::Kv(KvOp::Put {
        collection: "config".into(),
        key: "greeting".into(),
        value_hex: hex_encode(b"hello world"),
    }))
    .expect("kv put over pillar-UDP succeeds");
    assert!(ack.starts_with("KV-PUT"), "kv put ack: {ack}");
    assert!(ack.contains("EVENT-CID"), "kv put emits a signed event: {ack}");

    // A member-gated GET reads the REAL value back (hex, round-trips to bytes).
    let got = query_op(&QueryOp::Kv(KvOp::Get {
        collection: "config".into(),
        key: "greeting".into(),
    }))
    .expect("kv get over pillar-UDP");
    assert_eq!(
        hex_decode(got.trim()),
        b"hello world",
        "kv get returns the real live value; got {got:?}"
    );

    // A second key, then a KEYS browse lists both, live.
    query_op(&QueryOp::Kv(KvOp::Put {
        collection: "config".into(),
        key: "farewell".into(),
        value_hex: hex_encode(b"bye"),
    }))
    .expect("second kv put");
    let keys = query_op(&QueryOp::Kv(KvOp::Keys {
        collection: "config".into(),
    }))
    .expect("kv keys");
    let key_set: std::collections::BTreeSet<_> = keys.lines().collect();
    assert!(key_set.contains("greeting"), "keys: {keys:?}");
    assert!(key_set.contains("farewell"), "keys: {keys:?}");

    // COLLECTIONS lists the config collection.
    let cols = query_op(&QueryOp::Kv(KvOp::Collections)).expect("kv collections");
    assert!(cols.lines().any(|c| c == "config"), "collections: {cols:?}");

    // A DELETE tombstones the key; a subsequent GET fail-closed 404s.
    query_op(&QueryOp::Kv(KvOp::Delete {
        collection: "config".into(),
        key: "farewell".into(),
    }))
    .expect("kv delete");
    assert!(
        query_op(&QueryOp::Kv(KvOp::Get {
            collection: "config".into(),
            key: "farewell".into(),
        }))
        .is_err(),
        "a tombstoned key must not be gettable"
    );

    // === Document surface ===================================================
    for (id, name, status) in [
        ("u1", "alice", "on"),
        ("u2", "bob", "off"),
        ("u3", "carol", "on"),
    ] {
        query_op(&QueryOp::Doc(DocOp::PutField {
            collection: "users".into(),
            id: id.into(),
            field: "name".into(),
            value: name.into(),
        }))
        .expect("doc put name");
        query_op(&QueryOp::Doc(DocOp::PutField {
            collection: "users".into(),
            id: id.into(),
            field: "status".into(),
            value: status.into(),
        }))
        .expect("doc put status");
    }
    let name = query_op(&QueryOp::Doc(DocOp::GetField {
        collection: "users".into(),
        id: "u1".into(),
        field: "name".into(),
    }))
    .expect("doc get field");
    assert_eq!(name.trim(), "alice", "doc get returns the live field value");

    let ids = query_op(&QueryOp::Doc(DocOp::Ids {
        collection: "users".into(),
    }))
    .expect("doc ids");
    let id_set: std::collections::BTreeSet<_> = ids.lines().collect();
    for want in ["u1", "u2", "u3"] {
        assert!(id_set.contains(want), "doc ids must include {want}; got {ids:?}");
    }
    let fields = query_op(&QueryOp::Doc(DocOp::Fields {
        collection: "users".into(),
        id: "u1".into(),
    }))
    .expect("doc fields");
    let field_set: std::collections::BTreeSet<_> = fields.lines().collect();
    assert!(field_set.contains("name") && field_set.contains("status"), "fields: {fields:?}");

    // === SQL views over the Document store ==================================
    // CREATE a materialized view of active users (status == "on"), projecting
    // just the name. This is real DDL (a `__catalog` doc), a signed act.
    let ddl = query_op(&QueryOp::Sql(SqlOp::CreateView {
        name: "active_users".into(),
        source: "users".into(),
        filter_field: Some("status".into()),
        filter_value: Some("on".into()),
        project: Some(vec!["name".into()]),
    }))
    .expect("sql create-view over pillar-UDP");
    assert!(ddl.contains("EVENT-CID"), "create-view emits a signed event: {ddl}");

    // VIEWS lists it.
    let views = query_op(&QueryOp::Sql(SqlOp::Views)).expect("sql views");
    assert!(views.lines().any(|v| v == "active_users"), "views: {views:?}");

    // Materializing the VIEW folds the LIVE source collection and returns only
    // the active rows (u1, u3) — the folded, root-cached view the ROI mandates,
    // served over the real dial/seal/sign client stack.
    let rows = query_op(&QueryOp::Sql(SqlOp::View {
        name: "active_users".into(),
    }))
    .expect("sql view materializes over pillar-UDP");
    let row_ids: std::collections::BTreeSet<_> =
        rows.lines().filter_map(|l| l.split('\t').next()).collect();
    assert!(row_ids.contains("u1"), "active view includes u1 (on): {rows:?}");
    assert!(row_ids.contains("u3"), "active view includes u3 (on): {rows:?}");
    assert!(!row_ids.contains("u2"), "active view excludes u2 (off): {rows:?}");
    // The projection kept only `name`; each active row carries `name=<val>`.
    assert!(rows.contains("name=alice"), "projected name for u1: {rows:?}");
    assert!(rows.contains("name=carol"), "projected name for u3: {rows:?}");

    // === Fail-closed: an UNADMITTED signer is refused on a read ==============
    let intruder = pillar_crypto::Seed::from_bytes(b"data-query-e2e-unadmitted".to_vec());
    let (intruder_pub, intruder_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder).expect("intruder keypair");
    let saved_pub = std::env::var("PILLAR_SIGNER_PUBLIC_HEX").expect("pub set");
    let saved_secret = std::env::var("PILLAR_SIGNER_SECRET_HEX").expect("secret set");
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", hex_encode(intruder_pub.as_bytes()));
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", hex_encode(intruder_secret.as_bytes()));
    assert!(
        query_op(&QueryOp::Kv(KvOp::Get {
            collection: "config".into(),
            key: "greeting".into(),
        }))
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on a query read"
    );
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", saved_pub);
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", saved_secret);
}
