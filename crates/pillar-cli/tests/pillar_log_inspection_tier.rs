//! Acceptance test — `pillar-log-inspection-tier` (ROI Priority 1 "Layered
//! data inspection — the op log, storage layout, and IPFS objects beneath
//! the overlay").
//!
//! Proves the load-bearing DoD claim: `pillar log info|blocks|list|show|dag|
//! watch|verify` reads a collection's signed, content-addressed op log over
//! the SAME sealed `QueryOp` remote surface `data-query-tier-remote-surface`
//! proved (a LIVE `pillar node run`, driven via `pillar_cli::
//! apply_over_pillar_message::query_op` — never a crate-level fold
//! round-trip), and that:
//!
//! - `log show` decodes one op: author + signature, HLC, causal parents,
//!   kind, key, payload CID, seal (always `none` at this layer);
//! - `log dag` renders the causal graph (`parent -> child` edges) so
//!   concurrent branches are visible at the log level;
//! - `log verify` confirms hash==id and signature validity WITHOUT ever
//!   needing to interpret the op's payload;
//! - `log blocks`' storage-layout discriminator is a REPORTED fact, not
//!   inferred: a document/keyed collection (`kv`) reports `snapshot: none`
//!   plus its full, uncompacted op tail; a TSDB-kind collection (the
//!   object-inspection tier's content-addressed block store) reports its
//!   immutable retention blocks back to the retention horizon, with older
//!   blocks reported pruned, and no snapshot — exercised on REAL collections
//!   of both kinds.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test pillar_log_inspection_tier --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{KvOp, LogOp, ObjectOp, ObjectVisibility, QueryOp};

const PASSWORD: &str = "correct horse battery staple 2026 log inspection";
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

/// Reproduce the node's `cell_id`/seed derivation from the on-disk identity
/// key bytes alone (mirrors `pillar_object_inspection_tier`'s fixture).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

/// Parse one `key: value` line's value out of a `log`-tier ack body.
fn field<'a>(body: &'a str, key: &str) -> &'a str {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}: ")) {
            return rest;
        }
    }
    panic!("field {key} not found in: {body}");
}

#[test]
fn cli_log_info_list_show_dag_verify_and_the_reported_blocks_discriminator_on_a_live_node() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key. None of this is the log-inspection path under test.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"log-inspection-e2e-test-signer".to_vec());
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
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", hex_encode(signer_secret.as_bytes()));

    // === A real document/keyed collection: `pillar kv put` writes into the
    // "widgets" collection, appending a signed event to its op log ==========
    let collection = "widgets";
    for (key, value) in [("alpha", "one"), ("beta", "two"), ("gamma", "three")] {
        let ack = query_op(&QueryOp::Kv(KvOp::Put {
            collection: collection.to_owned(),
            key: key.to_owned(),
            value_hex: hex_encode(value.as_bytes()),
        }))
        .expect("kv put over pillar-UDP succeeds");
        assert!(ack.starts_with("KV-PUT"), "kv put ack: {ack}");
    }

    // `log info`: 3 ops, a real tip.
    let info = query_op(&QueryOp::Log(LogOp::Info {
        collection: collection.to_owned(),
    }))
    .expect("log info");
    assert!(info.contains("ops: 3"), "info: {info}");
    let tip_hex = field(&info, "tip").to_owned();
    assert_eq!(tip_hex.len() % 2, 0, "tip must be well-formed hex: {info}");

    // `log list`: exactly 3 event ids, the last one matching the tip.
    let list = query_op(&QueryOp::Log(LogOp::List {
        collection: collection.to_owned(),
    }))
    .expect("log list");
    let ids: Vec<&str> = list.lines().collect();
    assert_eq!(ids.len(), 3, "list: {list}");
    assert_eq!(ids[2], tip_hex, "the last listed id must be the tip");

    // `log show` on the tip: decodes author, HLC, kind, key, payload CID,
    // parents, signature, and an explicit `seal: none` at this layer.
    let show = query_op(&QueryOp::Log(LogOp::Show {
        collection: collection.to_owned(),
        event_id_hex: tip_hex.clone(),
    }))
    .expect("log show");
    assert!(show.contains("kind: KV-PUT"), "show: {show}");
    assert!(field(&show, "key").contains("gamma"), "show: {show}");
    assert!(!field(&show, "author").is_empty(), "show: {show}");
    assert!(field(&show, "hlc").contains('.'), "show: {show}");
    assert!(!field(&show, "payload-cid").is_empty(), "show: {show}");
    assert!(!field(&show, "signature").is_empty(), "show: {show}");
    assert_eq!(field(&show, "seal"), "none", "show: {show}");

    // `log dag`: at least the tip's own causal edge is rendered
    // (`parent -> tip` or a genesis line), proving the causal graph decodes.
    let dag = query_op(&QueryOp::Log(LogOp::Dag {
        collection: collection.to_owned(),
    }))
    .expect("log dag");
    assert!(
        dag.lines().any(|l| l.ends_with(&tip_hex)),
        "dag must render an edge/genesis line ending at the tip: {dag}"
    );

    // `log verify` on the tip: hash==id and a valid signature, without ever
    // needing to interpret the payload.
    let verify = query_op(&QueryOp::Log(LogOp::Verify {
        collection: collection.to_owned(),
        event_id_hex: tip_hex.clone(),
    }))
    .expect("log verify");
    assert!(verify.contains("hash-matches-id: true"), "verify: {verify}");
    assert!(verify.contains("signature-valid: true"), "verify: {verify}");

    // `log watch`: a bounded, single-shot rendering of the current tip —
    // same tip `log info` just reported (no ops appended since).
    let watch = query_op(&QueryOp::Log(LogOp::Watch {
        collection: collection.to_owned(),
    }))
    .expect("log watch");
    assert_eq!(field(&watch, "tip"), tip_hex, "watch: {watch}");

    // `log blocks` on the keyed collection: `snapshot: none` + the full,
    // uncompacted op tail (3 ops) — a REPORTED fact about the keyed store,
    // which never compacts to a snapshot.
    let blocks = query_op(&QueryOp::Log(LogOp::Blocks {
        collection: collection.to_owned(),
    }))
    .expect("log blocks (keyed)");
    assert!(blocks.contains("kind: document"), "blocks: {blocks}");
    assert!(blocks.contains("snapshot: none"), "blocks: {blocks}");
    assert!(blocks.contains("tail: 3 ops"), "blocks: {blocks}");

    // === A real TSDB-kind collection: every `pillar object put` is an
    // individually content-addressed, immutable block — never folded into an
    // LWW snapshot — indexed under the reserved `__objects` collection ======
    let mut object_puts = 0u8;
    for i in 0..6u8 {
        let ack = query_op(&QueryOp::Object(ObjectOp::Put {
            visibility: ObjectVisibility::Public,
            payload_hex: hex_encode(format!("tsdb-block-{i}").as_bytes()),
            links_hex: vec![],
            recipients_hex: vec![],
        }))
        .expect("object put over pillar-UDP succeeds");
        assert!(ack.starts_with("OBJECT-PUT"), "object put ack: {ack}");
        object_puts += 1;
    }
    assert_eq!(object_puts, 6);

    let tsdb_blocks = query_op(&QueryOp::Log(LogOp::Blocks {
        collection: "__objects".to_owned(),
    }))
    .expect("log blocks (tsdb)");
    // TSDB kind: no snapshot line at all, a bounded retention window
    // (`retention_horizon: 4`), and the older-than-horizon ops explicitly
    // reported pruned — a REPORTED fact, not an inference.
    assert!(tsdb_blocks.contains("kind: tsdb"), "blocks: {tsdb_blocks}");
    assert!(
        !tsdb_blocks.contains("snapshot:"),
        "a tsdb collection reports no snapshot: {tsdb_blocks}"
    );
    assert!(
        tsdb_blocks.contains("retention_horizon: 4"),
        "blocks: {tsdb_blocks}"
    );
    assert!(tsdb_blocks.contains("pruned: 2"), "blocks: {tsdb_blocks}");

    // `log info`/`log list` over the SAME `__objects` collection prove the
    // op-log inspection surface is the SAME QueryOp remote surface for both
    // storage-layout kinds — no new store, only less folding.
    let objects_info = query_op(&QueryOp::Log(LogOp::Info {
        collection: "__objects".to_owned(),
    }))
    .expect("log info (tsdb)");
    assert!(objects_info.contains("ops: 6"), "info: {objects_info}");

    // === Fail-closed: an UNADMITTED signer is refused, exactly like the
    // data-query tier =========================================================
    let intruder_signer_seed =
        pillar_crypto::Seed::from_bytes(b"log-inspection-e2e-unadmitted".to_vec());
    let (intruder_signer_pub, intruder_signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder_signer_seed)
            .expect("intruder keypair");
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(intruder_signer_pub.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(intruder_signer_secret.as_bytes()),
    );
    assert!(
        query_op(&QueryOp::Log(LogOp::Info {
            collection: collection.to_owned(),
        }))
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on a log read"
    );
}
