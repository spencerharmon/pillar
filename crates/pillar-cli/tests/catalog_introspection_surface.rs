//! Acceptance test — `catalog-introspection-surface` (ROI Priority 1
//! deliverable #1 catalog half: "The full CLI surface and default resources
//! ship").
//!
//! Proves the load-bearing DoD claim over the SAME real-remote
//! QueryOp-against-a-live-node acceptance gate the keyed-store/SQL tasks carry
//! (never a crate-fold round-trip and never a portal GET shim): a LIVE
//! `pillar node run` answers the catalog-introspection surface —
//! `pillar catalog {databases,collections,describe,views}` PLUS the SQL-native
//! equivalents (`SHOW TABLES`, `DESCRIBE <t>`, `SELECT ... FROM __catalog`) —
//! by folding the `__catalog` Document collection and the keyed store's live
//! collections over the sealed, signed resource-op pillar-UDP tier. Discovery
//! is a QUERY, not hard-coded help.
//!
//! `pillar catalog describe <collection>` reports, per collection, its SURFACE
//! (keyed → kv/doc/sql), SCHEMA, CONSISTENCY (AP), VISIBILITY class, and
//! PLACEMENT tags + the LIVE participating-node list (from
//! `data-placement-collection-tags`).
//!
//! Black-box: boots the real compiled `pillar` binary as a subprocess with its
//! web surface (used ONLY for the one-time cell/user/signer SETUP), and drives
//! the catalog acts by invoking the exact function the `pillar catalog`/
//! `pillar sql` verbs dispatch to (`pillar_cli::apply_over_pillar_message::
//! query_op`), configured entirely via the documented `PILLAR_*` env vars — so
//! this test exercises the REAL client-library seal/sign/dial path end to end,
//! never an HTTP call.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test catalog_introspection_surface --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{CatalogOp, DocOp, KvOp, QueryOp, SqlOp};

const PASSWORD: &str = "correct horse battery staple 2026 catalog";
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

/// Reproduce the node's `cell_id`/seed derivation from the on-disk identity key
/// bytes alone (mirrors `data_query_tier_remote_surface`'s `cell_material`).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

#[test]
fn catalog_introspection_surface_folds_the_live_catalog_over_pillar_udp() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key. None of this is the query path under test.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"catalog-e2e-test-signer".to_vec());
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

    // === Seed live data so the catalog has something to fold ================
    // A K/V collection with a namespace prefix ("app.config" → database "app").
    query_op(&QueryOp::Kv(KvOp::Put {
        collection: "app.config".into(),
        key: "greeting".into(),
        value_hex: hex_encode(b"hello"),
    }))
    .expect("kv put");
    // A Document collection with a namespace prefix ("app.users").
    for (id, name, status) in [("u1", "alice", "on"), ("u2", "bob", "off")] {
        query_op(&QueryOp::Doc(DocOp::PutField {
            collection: "app.users".into(),
            id: id.into(),
            field: "name".into(),
            value: name.into(),
        }))
        .expect("doc put name");
        query_op(&QueryOp::Doc(DocOp::PutField {
            collection: "app.users".into(),
            id: id.into(),
            field: "status".into(),
            value: status.into(),
        }))
        .expect("doc put status");
    }
    // A SQL view (a `__catalog` DDL doc) over the users collection.
    query_op(&QueryOp::Sql(SqlOp::CreateView {
        name: "active_users".into(),
        source: "app.users".into(),
        filter_field: Some("status".into()),
        filter_value: Some("on".into()),
        project: Some(vec!["name".into()]),
    }))
    .expect("sql create-view");

    // === pillar catalog databases ==========================================
    // Databases are the namespace prefixes of live collections; "app" appears,
    // and the __catalog system collection is NOT a database.
    let dbs = query_op(&QueryOp::Catalog(CatalogOp::Databases)).expect("catalog databases");
    let db_set: std::collections::BTreeSet<_> = dbs.lines().collect();
    assert!(db_set.contains("app"), "databases include app: {dbs:?}");
    assert!(
        !db_set.contains("__catalog"),
        "the __catalog system collection is not a database: {dbs:?}"
    );

    // === pillar catalog collections ========================================
    // Every live collection + the view, never the __catalog system collection.
    let cols = query_op(&QueryOp::Catalog(CatalogOp::Collections)).expect("catalog collections");
    let col_set: std::collections::BTreeSet<_> = cols.lines().collect();
    assert!(col_set.contains("app.config"), "collections: {cols:?}");
    assert!(col_set.contains("app.users"), "collections: {cols:?}");
    assert!(col_set.contains("active_users"), "view listed: {cols:?}");
    assert!(
        !col_set.contains("__catalog"),
        "the __catalog system collection is hidden: {cols:?}"
    );

    // === pillar catalog views ==============================================
    let views = query_op(&QueryOp::Catalog(CatalogOp::Views)).expect("catalog views");
    assert!(views.lines().any(|v| v == "active_users"), "views: {views:?}");

    // === pillar catalog describe <collection> ==============================
    // A keyed Document collection: reports SURFACE keyed doc, its live SCHEMA
    // (name,status), CONSISTENCY AP, VISIBILITY cell, PLACEMENT whole-cell +
    // the LIVE participating-node list (the solo node registers itself).
    let describe = query_op(&QueryOp::Catalog(CatalogOp::Describe {
        collection: "app.users".into(),
    }))
    .expect("catalog describe app.users");
    assert!(
        describe.contains("COLLECTION app.users"),
        "describe: {describe:?}"
    );
    assert!(describe.contains("SURFACE keyed doc"), "surface: {describe:?}");
    assert!(describe.contains("SCHEMA name,status"), "schema: {describe:?}");
    assert!(describe.contains("CONSISTENCY AP"), "consistency: {describe:?}");
    assert!(describe.contains("VISIBILITY cell"), "visibility: {describe:?}");
    assert!(
        describe.contains("PLACEMENT whole-cell"),
        "placement tags: {describe:?}"
    );
    assert!(
        describe.contains("NODES pillar-node"),
        "live participating-node list: {describe:?}"
    );

    // Describing the VIEW reports its `sql` surface + source.
    let describe_view = query_op(&QueryOp::Catalog(CatalogOp::Describe {
        collection: "active_users".into(),
    }))
    .expect("catalog describe active_users");
    assert!(
        describe_view.contains("SURFACE keyed sql source=app.users"),
        "view surface: {describe_view:?}"
    );

    // A K/V collection reports SURFACE keyed kv and its keys as schema.
    let describe_kv = query_op(&QueryOp::Catalog(CatalogOp::Describe {
        collection: "app.config".into(),
    }))
    .expect("catalog describe app.config");
    assert!(
        describe_kv.contains("SURFACE keyed kv"),
        "kv surface: {describe_kv:?}"
    );
    assert!(
        describe_kv.contains("SCHEMA greeting"),
        "kv schema (keys): {describe_kv:?}"
    );

    // Describing a nonexistent collection fails closed.
    assert!(
        query_op(&QueryOp::Catalog(CatalogOp::Describe {
            collection: "does_not_exist".into(),
        }))
        .is_err(),
        "describing a nonexistent collection must error"
    );

    // === SQL-native catalog equivalents ====================================
    // SHOW TABLES == catalog views, folded from __catalog.
    let show = query_op(&QueryOp::Sql(SqlOp::ShowTables)).expect("SHOW TABLES");
    assert!(
        show.lines().any(|v| v == "active_users"),
        "SHOW TABLES: {show:?}"
    );

    // DESCRIBE <table> folds the __catalog def.
    let desc_table = query_op(&QueryOp::Sql(SqlOp::DescribeTable {
        table: "active_users".into(),
    }))
    .expect("DESCRIBE active_users");
    assert!(
        desc_table.contains("TABLE active_users") && desc_table.contains("source=app.users"),
        "DESCRIBE <table>: {desc_table:?}"
    );

    // SELECT ... FROM __catalog: the catalog IS a queryable collection.
    let select = query_op(&QueryOp::Sql(SqlOp::SelectCatalog)).expect("SELECT FROM __catalog");
    assert!(
        select.contains("active_users") && select.contains("source=app.users"),
        "SELECT FROM __catalog: {select:?}"
    );

    // === Fail-closed: an UNADMITTED signer is refused on a catalog read =====
    let intruder = pillar_crypto::Seed::from_bytes(b"catalog-e2e-unadmitted".to_vec());
    let (intruder_pub, intruder_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder).expect("intruder keypair");
    let saved_pub = std::env::var("PILLAR_SIGNER_PUBLIC_HEX").expect("pub set");
    let saved_secret = std::env::var("PILLAR_SIGNER_SECRET_HEX").expect("secret set");
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", hex_encode(intruder_pub.as_bytes()));
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", hex_encode(intruder_secret.as_bytes()));
    assert!(
        query_op(&QueryOp::Catalog(CatalogOp::Collections)).is_err(),
        "an unadmitted signer must be refused (fail-closed) on a catalog read"
    );
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", saved_pub);
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", saved_secret);
}
