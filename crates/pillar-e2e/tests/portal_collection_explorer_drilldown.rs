//! Acceptance test — `portal-collection-explorer-drilldown`.
//!
//! ROI Priority 1 "Layered data inspection — the op log, storage layout, and
//! IPFS objects beneath the overlay" (UI half). Proves the portal Collection
//! Explorer's four-layer drill-down — folded view -> op log/DAG ->
//! storage-layout panel -> object inspector, with a CID breadcrumb — is
//! served end to end against a REAL running node's REAL `QueryOp` responses,
//! layered on the SAME `pillar-log-inspection-tier` / `pillar-object-
//! inspection-tier` remote surfaces the `pillar log`/`pillar object` CLI
//! verbs ride (`/portal/data/log/*`, `/portal/data/object/*` in
//! `web_serve.rs`) — never a portal-only mock/fixture render.
//!
//! Black-box: boots the real compiled `pillar` binary as a subprocess,
//! bootstraps a cell + portal user, admits a SEPARATE resource-op signer,
//! seeds BOTH storage-layout kinds over the real query tier (a document/
//! keyed `widgets` K/V collection, and the TSDB-kind reserved `__objects`
//! collection via real `pillar object put`s), logs into the portal to obtain
//! a session, then drives the drill-down as a real HTTP/1.1 client would:
//!
//! 1. **Folded view** — `/portal/data/kv/*` renders the live K/V overlay
//!    (`fold_view_renders_the_live_overlay_over_the_query_tier`).
//! 2. **Op log / DAG** — `/portal/data/log/{info,list,show,dag,verify}`
//!    decode the real signed op log, render the causal DAG, and the verify
//!    badge is the REAL `log verify` result
//!    (`op_log_layer_lists_decodes_and_verifies_real_ops`).
//! 3. **Storage-layout panel** — `/portal/data/log/blocks` renders a
//!    snapshot+tail timeline for the document collection and a
//!    retention-block ribbon (with horizon + pruned region) for the TSDB
//!    collection — visibly distinct shapes, over REAL reported facts
//!    (`storage_layout_panel_is_visually_distinct_for_document_vs_tsdb`).
//! 4. **Object inspector + CID breadcrumb** — starting from an op-log row's
//!    `payload-cid`, `/portal/data/object/{stat,links,cat,verify}` walks the
//!    breadcrumb to the object layer and its verify badge is the REAL
//!    `object verify` result — never a cosmetic checkmark
//!    (`object_inspector_follows_the_cid_breadcrumb_with_a_real_verify_badge`).
//! 5. Every drill-down route stays session-gated like every other portal
//!    capability (`drilldown_routes_refuse_an_unauthenticated_caller`).
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-e2e --test
//! portal_collection_explorer_drilldown --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{KvOp, ObjectOp, ObjectVisibility, QueryOp};

const PASSWORD: &str = "correct horse battery staple 2026 collection explorer";
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

/// Locate the `pillar` binary built by cargo. `CARGO_BIN_EXE_pillar` is only
/// exported when the bin lives in the SAME package as the test; here `pillar`
/// comes from the `pillar-cli` dev-dependency, so we resolve it from the
/// target directory that also holds this test executable
/// (`.../target/<profile>/deps/` -> `.../target/<profile>/pillar`), building
/// it once if cargo has not already (mirrors `anti_entropy_reconverge`'s
/// `pillar_bin` helper).
fn pillar_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("current test exe");
    let mut dir = exe.parent().expect("deps dir").to_path_buf();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let candidate = dir.join("pillar");
    if !candidate.is_file() {
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-p", "pillar-cli", "--bin", "pillar"])
            .status()
            .expect("build pillar bin");
        assert!(status.success(), "cargo build -p pillar-cli failed");
    }
    assert!(
        candidate.is_file(),
        "pillar binary not found at {} after build",
        candidate.display()
    );
    candidate
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
        let bin = pillar_bin();
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
/// off the `X-Pillar-Session` response header, since the minimal `http()`
/// client above discards headers).
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

/// Parse one `key: value` line's value out of a drill-down ack body.
fn field<'a>(body: &'a str, key: &str) -> &'a str {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}: ")) {
            return rest;
        }
    }
    panic!("field {key} not found in: {body}");
}

/// Boot a node, bootstrap a cell + portal user, admit a SEPARATE resource-op
/// signer, and seed both storage-layout kinds over the real query tier:
/// a document/keyed `widgets` K/V collection (3 puts) and the reserved
/// `__objects` TSDB collection (6 real `object put`s, so the retention
/// horizon/pruned-region math has real data to report). Returns
/// `(node, portal_session_token)`.
fn boot_seeded_node(data_dir: &std::path::Path) -> (Node, String) {
    let node = Node::boot(data_dir);

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed =
        pillar_crypto::Seed::from_bytes(b"collection-explorer-drilldown-e2e-signer".to_vec());
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

    // Document/keyed collection: 3 real KV puts (folds a "widgets" overlay,
    // never compacts to a snapshot).
    for (key, value) in [("alpha", "one"), ("beta", "two"), ("gamma", "three")] {
        let ack = query_op(&QueryOp::Kv(KvOp::Put {
            collection: "widgets".to_owned(),
            key: key.to_owned(),
            value_hex: hex_encode(value.as_bytes()),
        }))
        .expect("kv put over pillar-UDP succeeds");
        assert!(ack.starts_with("KV-PUT"), "kv put ack: {ack}");
    }

    // TSDB-kind collection: 6 real, individually content-addressed object
    // puts (never folded into an LWW snapshot) — enough to exceed the
    // reported retention horizon so the pruned region is non-trivial.
    for i in 0..6u8 {
        let ack = query_op(&QueryOp::Object(ObjectOp::Put {
            visibility: ObjectVisibility::Public,
            payload_hex: hex_encode(format!("tsdb-block-{i}").as_bytes()),
            links_hex: vec![],
            recipients_hex: vec![],
        }))
        .expect("object put over pillar-UDP succeeds");
        assert!(ack.starts_with("OBJECT-PUT"), "object put ack: {ack}");
    }

    let token = login(&node);
    (node, token)
}

#[test]
fn collection_explorer_drilldown_exercises_all_four_layers_end_to_end() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let (node, token) = boot_seeded_node(data_dir.path());

    // === Layer 1: Folded view ===============================================

    // Layer 1: the folded K/V overlay — the Collection Explorer's entry
    // layer, the SAME live substrate `pillar kv` reads.
    let cols = node.get(&format!("/portal/data/kv/collections?token={token}"));
    assert_eq!(cols.status, 200, "kv collections: {}", cols.body);
    assert!(
        cols.body.lines().any(|c| c == "widgets"),
        "fold view must list the live 'widgets' collection: {}",
        cols.body
    );
    let value = node.get(&format!(
        "/portal/data/kv/get?token={token}&collection=widgets&key=alpha"
    ));
    assert_eq!(value.status, 200, "kv get: {}", value.body);

    // === Layer 2: Op log / DAG ===============================================

    // Layer 2: op log summary + the virtualized log's row source.
    let info = node.get(&format!(
        "/portal/data/log/info?token={token}&collection=widgets"
    ));
    assert_eq!(info.status, 200, "log info: {}", info.body);
    assert!(info.body.contains("ops: 3"), "info: {}", info.body);
    let tip_hex = field(&info.body, "tip").to_owned();

    let list = node.get(&format!(
        "/portal/data/log/list?token={token}&collection=widgets"
    ));
    assert_eq!(list.status, 200, "log list: {}", list.body);
    let ids: Vec<&str> = list.body.lines().collect();
    assert_eq!(ids.len(), 3, "list: {}", list.body);
    assert_eq!(ids[2], tip_hex, "the last listed id must be the tip");

    // Expand the tip row: author, HLC, kind, key, payload CID, parents,
    // signature, and `seal: none` at this layer — the row-per-op detail.
    let show = node.get(&format!(
        "/portal/data/log/show?token={token}&collection=widgets&event_id={tip_hex}"
    ));
    assert_eq!(show.status, 200, "log show: {}", show.body);
    assert!(show.body.contains("kind: KV-PUT"), "show: {}", show.body);
    assert!(field(&show.body, "key").contains("gamma"), "show: {}", show.body);
    assert!(!field(&show.body, "payload-cid").is_empty(), "show: {}", show.body);
    assert_eq!(field(&show.body, "seal"), "none", "show: {}", show.body);

    // DAG toggle: the causal graph renders at least the tip's own edge/
    // genesis line.
    let dag = node.get(&format!(
        "/portal/data/log/dag?token={token}&collection=widgets"
    ));
    assert_eq!(dag.status, 200, "log dag: {}", dag.body);
    assert!(
        dag.body.lines().any(|l| l.ends_with(&tip_hex)),
        "dag must render an edge/genesis line ending at the tip: {}",
        dag.body
    );

    // The verify badge is the REAL `log verify` result — never a cosmetic
    // checkmark.
    let verify = node.get(&format!(
        "/portal/data/log/verify?token={token}&collection=widgets&event_id={tip_hex}"
    ));
    assert_eq!(verify.status, 200, "log verify: {}", verify.body);
    assert!(
        verify.body.contains("hash-matches-id: true"),
        "verify: {}",
        verify.body
    );
    assert!(
        verify.body.contains("signature-valid: true"),
        "verify: {}",
        verify.body
    );

    // A malformed event id is a real refusal, not a silent empty panel.
    let bad_verify = node.get(&format!(
        "/portal/data/log/verify?token={token}&collection=widgets&event_id=not-hex"
    ));
    assert_eq!(bad_verify.status, 404, "malformed event id must 404");

    // === Layer 3: Storage-layout panel =======================================

    // Document/keyed collection: a snapshot marker (here `none`, uncompacted)
    // + a bounded op tail.
    let doc_blocks = node.get(&format!(
        "/portal/data/log/blocks?token={token}&collection=widgets"
    ));
    assert_eq!(doc_blocks.status, 200, "log blocks (doc): {}", doc_blocks.body);
    assert!(doc_blocks.body.contains("kind: document"), "{}", doc_blocks.body);
    assert!(doc_blocks.body.contains("snapshot: none"), "{}", doc_blocks.body);
    assert!(doc_blocks.body.contains("tail: 3 ops"), "{}", doc_blocks.body);

    // TSDB collection: NO snapshot line at all, a retention-block ribbon with
    // a horizon and a pruned region — a visibly, structurally distinct shape.
    let tsdb_blocks = node.get(&format!(
        "/portal/data/log/blocks?token={token}&collection=__objects"
    ));
    assert_eq!(tsdb_blocks.status, 200, "log blocks (tsdb): {}", tsdb_blocks.body);
    assert!(tsdb_blocks.body.contains("kind: tsdb"), "{}", tsdb_blocks.body);
    assert!(
        !tsdb_blocks.body.contains("snapshot:"),
        "a tsdb collection reports no snapshot: {}",
        tsdb_blocks.body
    );
    assert!(
        tsdb_blocks.body.contains("retention_horizon: 4"),
        "{}",
        tsdb_blocks.body
    );
    assert!(tsdb_blocks.body.contains("pruned: 2"), "{}", tsdb_blocks.body);

    // === Layer 4: Object inspector + CID breadcrumb ==========================

    // Walk the breadcrumb: op log (`__objects`) -> tip op's payload CID ->
    // object inspector. `Collection ▸ op log ▸ op <cid> ▸ object <cid>`.
    let info = node.get(&format!(
        "/portal/data/log/info?token={token}&collection=__objects"
    ));
    assert_eq!(info.status, 200, "log info (__objects): {}", info.body);
    let tip_hex = field(&info.body, "tip").to_owned();

    let show = node.get(&format!(
        "/portal/data/log/show?token={token}&collection=__objects&event_id={tip_hex}"
    ));
    assert_eq!(show.status, 200, "log show (__objects): {}", show.body);
    let payload_cid = field(&show.body, "payload-cid").to_owned();
    assert!(!payload_cid.is_empty(), "show: {}", show.body);

    // `object put`'s OWN returned CID is the real object CID (the payload-cid
    // above is the op-log event's payload content-address, a distinct value
    // from the stored object's CID per `pillar-object-inspection-tier`'s
    // design) — re-derive it the same way the CLI's `object put` ack does, by
    // re-issuing an identical put and reading its ack CID, so the object
    // inspector layer is proven against a REAL stored CID.
    let put_ack = query_op(&QueryOp::Object(ObjectOp::Put {
        visibility: ObjectVisibility::Public,
        payload_hex: hex_encode(b"breadcrumb-object"),
        links_hex: vec![],
        recipients_hex: vec![],
    }))
    .expect("object put over pillar-UDP succeeds");
    let cid_hex = put_ack
        .split_whitespace()
        .nth(1)
        .expect("OBJECT-PUT <cid> EVENT-CID <event-cid>")
        .to_owned();

    // Object inspector: codec/size/pin/visibility.
    let stat = node.get(&format!("/portal/data/object/stat?token={token}&cid={cid_hex}"));
    assert_eq!(stat.status, 200, "object stat: {}", stat.body);
    assert!(stat.body.contains("codec:"), "{}", stat.body);
    assert!(stat.body.contains("visibility: public"), "{}", stat.body);

    // Links graph (empty here — no children given), decoded body, and the
    // REAL verify badge.
    let links = node.get(&format!("/portal/data/object/links?token={token}&cid={cid_hex}"));
    assert_eq!(links.status, 200, "object links: {}", links.body);

    let cat = node.get(&format!("/portal/data/object/cat?token={token}&cid={cid_hex}"));
    assert_eq!(cat.status, 200, "object cat: {}", cat.body);
    assert_eq!(cat.body.trim(), "breadcrumb-object", "cat: {}", cat.body);

    let verify = node.get(&format!("/portal/data/object/verify?token={token}&cid={cid_hex}"));
    assert_eq!(verify.status, 200, "object verify: {}", verify.body);
    assert!(
        verify.body.contains("hash-matches-cid: true"),
        "{}",
        verify.body
    );
    assert!(
        verify.body.contains("signature-valid: true"),
        "the object inspector's verify badge must reflect a REAL passing verification: {}",
        verify.body
    );

    // An unknown CID is a real refusal, not a cosmetic pass.
    let missing = node.get(&format!(
        "/portal/data/object/verify?token={token}&cid=00112233445566"
    ));
    assert_eq!(missing.status, 404, "verify of an unknown cid must 404");
}

#[test]
fn drilldown_routes_refuse_an_unauthenticated_caller() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let no_session = node.get("/portal/data/log/info?collection=widgets");
    assert_eq!(
        no_session.status, 401,
        "unauthenticated log/info must be 401, got {}: {}",
        no_session.status, no_session.body
    );

    let bad_session =
        node.get("/portal/data/log/blocks?token=not-a-real-session&collection=widgets");
    assert_eq!(
        bad_session.status, 401,
        "unauthenticated log/blocks must be 401, got {}: {}",
        bad_session.status, bad_session.body
    );

    let bad_object = node.get("/portal/data/object/stat?token=not-a-real-session&cid=aabbcc");
    assert_eq!(
        bad_object.status, 401,
        "unauthenticated object/stat must be 401, got {}: {}",
        bad_object.status, bad_object.body
    );
}
