//! Acceptance test — `data-query-portal-explore-panels`.
//!
//! ROI Priority 1 data-layer doctrine, UI half of
//! `data-query-tier-remote-surface`: a read-only browse/query panel per
//! primitive (K/V, Document, SQL-view) in the portal, rendering the SAME live
//! `WebAuthContext::keyed_store` substrate the `pillar kv`/`pillar doc`/
//! `pillar sql` query-tier CLI verbs already read over pillar-UDP — never a
//! second store, never a mutation shim.
//!
//! Black-box: boots the real compiled `pillar` binary as a subprocess, seeds
//! the keyed store over the REAL query tier (the same `query_op` client path
//! `data_query_tier_remote_surface` proves), then drives the new
//! `/portal/data/{kv,doc,sql}/*` browse routes as a real HTTP/1.1 client would
//! — asserting the routes return the LIVE K/V keys, document fields, and
//! materialized view rows, and that they are session-gated like every other
//! portal capability.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test data_query_portal_explore_panels --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{DocOp, KvOp, QueryOp, SqlOp};

const PASSWORD: &str = "correct horse battery staple 2026 explore panels";
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

/// A booted `pillar node run` subprocess with its HTTPS (SETUP + portal) and
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

    fn get(&self, path: &str) -> HttpResponse {
        http(self.http_port, "GET", path, "").expect("GET succeeds")
    }

    fn resource_op_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.resource_op_port)
            .parse()
            .unwrap()
    }

    /// The raw on-disk identity key bytes — reproduces the node's `cell_id`/
    /// `cell_group_key` derivation with no RPC.
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

/// Reproduce the node's `cell_id`/seed derivation from the on-disk identity
/// key bytes alone (mirrors `data_query_tier_remote_surface`'s
/// `cell_material`).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

/// The real node-side custody login over HTTP: `GET /nonce`, then `POST
/// /login` (two fields + nonce id). Returns the admitted session token (read
/// off the `X-Pillar-Session` response header via `raw_response`, since the
/// minimal `http()` client above discards headers).
fn login(node: &Node) -> String {
    let nonce = node.get("/nonce");
    assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
    let id: u64 = nonce
        .body
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("nonce id");
    raw_response(
        node.http_port,
        "POST",
        "/login",
        &format!("{HANDLE}\n{PASSWORD}\n{id}"),
    )
    .expect("login carries a session token")
}

/// A login round-trip that returns the `X-Pillar-Session` header value.
fn raw_response(port: u16, method: &str, path: &str, body: &str) -> Option<String> {
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
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("X-Pillar-Session: ") {
            return Some(v.trim().to_owned());
        }
    }
    None
}

#[test]
fn explore_panels_render_the_live_kv_doc_and_sql_view_data_over_the_portal() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP: bootstrap a cell + first user, admit this test's own signing
    // key for the query tier.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"explore-panels-e2e-signer".to_vec());
    let (signer_public, signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&signer_seed).expect("signing keypair");
    let subject_hex = hex_encode(signer_public.as_bytes());
    let admit = node.post("/bootstrap/admit-resource-signer", &subject_hex);
    assert_eq!(admit.status, 200, "admit-resource-signer: {}", admit.body);

    let (cell_id_bytes, seed_bytes) = cell_material(&node.identity_key_bytes());
    std::env::set_var(
        "PILLAR_RESOURCE_OP_ADDR",
        node.resource_op_addr().to_string(),
    );
    std::env::set_var("PILLAR_CELL_ID_HEX", hex_encode(&cell_id_bytes));
    std::env::set_var("PILLAR_CELL_SEED_HEX", hex_encode(&seed_bytes));
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", hex_encode(signer_public.as_bytes()));
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(signer_secret.as_bytes()),
    );

    // --- Seed the K/V, Document, and SQL-view primitives over the REAL query
    // tier (pillar-UDP) — never touching the portal.
    query_op(&QueryOp::Kv(KvOp::Put {
        collection: "config".into(),
        key: "greeting".into(),
        value_hex: hex_encode(b"hello portal"),
    }))
    .expect("kv put over pillar-UDP");
    query_op(&QueryOp::Kv(KvOp::Put {
        collection: "config".into(),
        key: "farewell".into(),
        value_hex: hex_encode(b"bye"),
    }))
    .expect("second kv put");

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

    query_op(&QueryOp::Sql(SqlOp::CreateView {
        name: "active_users".into(),
        source: "users".into(),
        filter_field: Some("status".into()),
        filter_value: Some("on".into()),
        project: Some(vec!["name".into()]),
    }))
    .expect("sql create-view over pillar-UDP");

    // --- Log into the PORTAL (a distinct trust boundary from the query
    // tier's signer) to obtain a session token for the browse routes.
    let token = login(&node);

    // === K/V Explore panel ===================================================
    let cols = node.get(&format!("/portal/data/kv/collections?token={token}"));
    assert_eq!(cols.status, 200, "kv collections: {}", cols.body);
    assert!(
        cols.body.lines().any(|c| c == "config"),
        "kv collections must list the live 'config' collection: {}",
        cols.body
    );

    let keys = node.get(&format!("/portal/data/kv/keys?token={token}&collection=config"));
    assert_eq!(keys.status, 200, "kv keys: {}", keys.body);
    let key_set: std::collections::BTreeSet<_> = keys.body.lines().collect();
    assert!(key_set.contains("greeting"), "kv keys: {}", keys.body);
    assert!(key_set.contains("farewell"), "kv keys: {}", keys.body);

    let got = node.get(&format!(
        "/portal/data/kv/get?token={token}&collection=config&key=greeting"
    ));
    assert_eq!(got.status, 200, "kv get: {}", got.body);
    assert_eq!(
        hex_decode(got.body.trim()),
        b"hello portal",
        "kv get must return the LIVE value written over the query tier; got {:?}",
        got.body
    );

    let missing = node.get(&format!(
        "/portal/data/kv/get?token={token}&collection=config&key=nonexistent"
    ));
    assert_eq!(missing.status, 404, "kv get of a missing key must 404");

    // === Document Explore panel ==============================================
    let ids = node.get(&format!("/portal/data/doc/ids?token={token}&collection=users"));
    assert_eq!(ids.status, 200, "doc ids: {}", ids.body);
    let id_set: std::collections::BTreeSet<_> = ids.body.lines().collect();
    for want in ["u1", "u2", "u3"] {
        assert!(id_set.contains(want), "doc ids: {}", ids.body);
    }

    let fields = node.get(&format!(
        "/portal/data/doc/fields?token={token}&collection=users&id=u1"
    ));
    assert_eq!(fields.status, 200, "doc fields: {}", fields.body);
    let field_set: std::collections::BTreeSet<_> = fields.body.lines().collect();
    assert!(
        field_set.contains("name") && field_set.contains("status"),
        "doc fields: {}",
        fields.body
    );

    let name = node.get(&format!(
        "/portal/data/doc/get?token={token}&collection=users&id=u1&field=name"
    ));
    assert_eq!(name.status, 200, "doc get: {}", name.body);
    assert_eq!(
        name.body.trim(),
        "alice",
        "doc get must return the LIVE field value written over the query tier"
    );

    // === SQL-view Explore panel ==============================================
    let views = node.get(&format!("/portal/data/sql/views?token={token}"));
    assert_eq!(views.status, 200, "sql views: {}", views.body);
    assert!(
        views.body.lines().any(|v| v == "active_users"),
        "sql views: {}",
        views.body
    );

    let rows = node.get(&format!("/portal/data/sql/view?token={token}&name=active_users"));
    assert_eq!(rows.status, 200, "sql view: {}", rows.body);
    let row_ids: std::collections::BTreeSet<_> = rows
        .body
        .lines()
        .filter_map(|l| l.split('\t').next())
        .collect();
    assert!(row_ids.contains("u1"), "active view includes u1 (on): {}", rows.body);
    assert!(row_ids.contains("u3"), "active view includes u3 (on): {}", rows.body);
    assert!(
        !row_ids.contains("u2"),
        "active view excludes u2 (off): {}",
        rows.body
    );
    assert!(
        rows.body.contains("name=alice"),
        "projected name for u1: {}",
        rows.body
    );
    assert!(
        rows.body.contains("name=carol"),
        "projected name for u3: {}",
        rows.body
    );

    let missing_view = node.get(&format!("/portal/data/sql/view?token={token}&name=no-such-view"));
    assert_eq!(missing_view.status, 404, "materializing an unknown view must 404");
}

#[test]
fn explore_panel_routes_refuse_an_unauthenticated_caller() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // No session at all.
    let no_session = node.get("/portal/data/kv/collections");
    assert_eq!(
        no_session.status, 401,
        "unauthenticated kv/collections must be 401, got {}: {}",
        no_session.status, no_session.body
    );

    // A bad session token.
    let bad_session = node.get("/portal/data/sql/views?token=not-a-real-session");
    assert_eq!(
        bad_session.status, 401,
        "unauthenticated sql/views must be 401, got {}: {}",
        bad_session.status, bad_session.body
    );

    let bad_doc = node.get("/portal/data/doc/ids?token=not-a-real-session&collection=users");
    assert_eq!(
        bad_doc.status, 401,
        "unauthenticated doc/ids must be 401, got {}: {}",
        bad_doc.status, bad_doc.body
    );
}
