//! Acceptance test — `data-query-portal-explore-panels`.
//!
//! ROI Priority 1 data-layer doctrine — the UI half of
//! `data-query-tier-remote-surface`: a browse/query panel per primitive (K/V,
//! Document, SQL-view) in the portal/Explore UI, rendering the SAME live
//! `WebAuthContext::keyed_store` substrate the query tier's `pillar kv`/
//! `pillar doc`/`pillar sql` CLI verbs read/write — never a second store,
//! never a mutation shim.
//!
//! Black-box: this suite is a black-box HTTP observer exactly like
//! `portal_swarm_surface` — it speaks only real HTTP/1.1 over a real TCP
//! socket to a node web surface bound on an ephemeral loopback port and served
//! by the production `web_serve::serve` accept loop. It seeds the keyed store
//! by invoking [`pillar_cli::web_serve::WebAuthContext::query_op`] directly —
//! the EXACT dispatch function the sealed pillar-UDP query tier calls on a
//! `Body::QueryOp` frame (proven live end-to-end by
//! `data_query_tier_remote_surface`) — so the seed writes ride the SAME
//! decider/store the browse routes below read, never a second path. It then
//! asserts the new read-only portal browse routes
//! (`GET /portal/data/{kv,doc,sql}`) return the LIVE K/V keys, document
//! fields, and materialized view rows, and that they are gated behind an
//! admitted session exactly like every other portal read.
//!
//! RED if a browse route ever misses a seeded key/field/row, if it accepts an
//! unauthenticated caller, or if it diverges from the query tier's own
//! decider (e.g. reads across membership). GREEN when the portal Explore
//! panels and the `pillar kv`/`doc`/`sql` CLI verbs drive the SAME live
//! substrate over the real served surface.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test data_query_portal_explore_panels --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::time::Duration;

use pillar_cli::web_serve::{bind, serve, WebAuthContext};
use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_ops::{DocOp, KvOp, QueryOp, SqlOp};
use pillar_web::node_custody::Cid;

const PASSWORD: &str = "correct horse battery staple - data query portal explore";
const SECRET: &str = "operational-key-material-data-query-portal-explore";

/// One HTTP response the black-box client parsed off the wire.
struct HttpResponse {
    status: u16,
    session_token: Option<String>,
    body: String,
}

/// Send one real HTTP/1.1 request to `addr` and read the full response back —
/// the black-box client's ONLY view of the node.
fn http(addr: &str, method: &str, path: &str, body: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect to served surface");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).expect("header line");
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    HttpResponse {
        status,
        session_token,
        body: resp_body,
    }
}

/// Stand a real node web surface up on an ephemeral loopback port, admit +
/// provision a user so the black-box client can log in, and seed the live
/// keyed store (K/V + Document + a materialized SQL view) by dispatching real
/// `QueryOp`s through [`WebAuthContext::query_op`] — the SAME function the
/// sealed query tier calls. Returns `(addr, token)`.
fn serve_seeded() -> (String, String) {
    let listener = bind(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0).expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let subkey = NodeSubkey::from("op-subkey-alice-data-query");
    let mut ctx = WebAuthContext::new(
        "https://node.example.com",
        NodeId::from("this-node"),
        "this-node-secret",
        NodeId::from("owner"),
        4,
    );
    let actor = subkey.node_id();
    ctx.admit_subject(actor.clone(), 4);
    ctx.provision_offer(
        "alice@node",
        "Alice",
        Cid::from("cid-alice-data-query"),
        subkey,
        PASSWORD,
        SECRET,
    );

    // Seed K/V: a live collection with two keys.
    ctx.query_op(
        &actor,
        &QueryOp::Kv(KvOp::Put {
            collection: "settings".to_owned(),
            key: "theme".to_owned(),
            value_hex: hex_encode(b"dark"),
        }),
    )
    .expect("seed kv put theme");
    ctx.query_op(
        &actor,
        &QueryOp::Kv(KvOp::Put {
            collection: "settings".to_owned(),
            key: "locale".to_owned(),
            value_hex: hex_encode(b"en-US"),
        }),
    )
    .expect("seed kv put locale");

    // Seed a Document: one id with two fields.
    ctx.query_op(
        &actor,
        &QueryOp::Doc(DocOp::PutField {
            collection: "users".to_owned(),
            id: "u1".to_owned(),
            field: "name".to_owned(),
            value: "Alice".to_owned(),
        }),
    )
    .expect("seed doc put field name");
    ctx.query_op(
        &actor,
        &QueryOp::Doc(DocOp::PutField {
            collection: "users".to_owned(),
            id: "u1".to_owned(),
            field: "role".to_owned(),
            value: "admin".to_owned(),
        }),
    )
    .expect("seed doc put field role");

    // Seed a materialized SQL view over the document collection.
    ctx.query_op(
        &actor,
        &QueryOp::Sql(SqlOp::CreateView {
            name: "admins".to_owned(),
            source: "users".to_owned(),
            filter_field: Some("role".to_owned()),
            filter_value: Some("admin".to_owned()),
            project: None,
        }),
    )
    .expect("seed sql create view");

    std::thread::spawn(move || serve(listener, &mut ctx));
    // Give the accept loop a moment to start.
    std::thread::sleep(Duration::from_millis(100));

    let token = login(&addr);
    (addr, token)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The real node-side custody login over HTTP: `GET /nonce`, then `POST /login`
/// (two fields + nonce id). Returns the admitted session token.
fn login(addr: &str) -> String {
    let nonce = http(addr, "GET", "/nonce", "");
    assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
    let id: u64 = nonce
        .body
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("nonce id");
    let resp = http(addr, "POST", "/login", &format!("alice@node\n{PASSWORD}\n{id}"));
    assert_eq!(resp.status, 200, "login: {}", resp.body);
    resp.session_token.expect("session token")
}

#[test]
fn kv_browse_returns_live_collections_keys_and_value() {
    let (addr, token) = serve_seeded();

    // No collection: lists the live collections.
    let collections = http(&addr, "GET", &format!("/portal/data/kv?token={token}"), "");
    assert_eq!(collections.status, 200, "kv collections: {}", collections.body);
    assert!(
        collections.body.contains("COLLECTION settings"),
        "must list the live collection, got: {}",
        collections.body
    );

    // Collection only: lists the live keys.
    let keys = http(
        &addr,
        "GET",
        &format!("/portal/data/kv?token={token}&collection=settings"),
        "",
    );
    assert_eq!(keys.status, 200, "kv keys: {}", keys.body);
    assert!(
        keys.body.contains("KEY theme") && keys.body.contains("KEY locale"),
        "must list the live keys, got: {}",
        keys.body
    );

    // Collection + key: returns the live value, hex-encoded.
    let value = http(
        &addr,
        "GET",
        &format!("/portal/data/kv?token={token}&collection=settings&key=theme"),
        "",
    );
    assert_eq!(value.status, 200, "kv value: {}", value.body);
    assert!(
        value.body.contains(&format!("VALUE {}", hex_encode(b"dark"))),
        "must return the live value, got: {}",
        value.body
    );

    // A missing key 404s.
    let missing = http(
        &addr,
        "GET",
        &format!("/portal/data/kv?token={token}&collection=settings&key=nope"),
        "",
    );
    assert_eq!(missing.status, 404, "missing key: {}", missing.body);
}

#[test]
fn doc_browse_returns_live_ids_and_fields() {
    let (addr, token) = serve_seeded();

    // Collection only: lists the live document ids.
    let ids = http(
        &addr,
        "GET",
        &format!("/portal/data/doc?token={token}&collection=users"),
        "",
    );
    assert_eq!(ids.status, 200, "doc ids: {}", ids.body);
    assert!(
        ids.body.contains("ID u1"),
        "must list the live document id, got: {}",
        ids.body
    );

    // Collection + id: lists the live fields.
    let fields = http(
        &addr,
        "GET",
        &format!("/portal/data/doc?token={token}&collection=users&id=u1"),
        "",
    );
    assert_eq!(fields.status, 200, "doc fields: {}", fields.body);
    assert!(
        fields.body.contains("FIELD name") && fields.body.contains("FIELD role"),
        "must list the live fields, got: {}",
        fields.body
    );

    // Collection + id + field: returns the live value.
    let value = http(
        &addr,
        "GET",
        &format!("/portal/data/doc?token={token}&collection=users&id=u1&field=name"),
        "",
    );
    assert_eq!(value.status, 200, "doc field value: {}", value.body);
    assert!(
        value.body.contains("VALUE Alice"),
        "must return the live field value, got: {}",
        value.body
    );

    // Missing `collection` is a 400.
    let missing_collection = http(&addr, "GET", &format!("/portal/data/doc?token={token}"), "");
    assert_eq!(missing_collection.status, 400, "missing collection: {}", missing_collection.body);
}

#[test]
fn sql_browse_returns_live_views_and_materialized_rows() {
    let (addr, token) = serve_seeded();

    // No name: lists the live views.
    let views = http(&addr, "GET", &format!("/portal/data/sql?token={token}"), "");
    assert_eq!(views.status, 200, "sql views: {}", views.body);
    assert!(
        views.body.contains("VIEW admins"),
        "must list the live view, got: {}",
        views.body
    );

    // Name: materializes the live rows — the seeded admin document.
    let rows = http(&addr, "GET", &format!("/portal/data/sql?token={token}&name=admins"), "");
    assert_eq!(rows.status, 200, "sql view rows: {}", rows.body);
    assert!(
        rows.body.contains("ROW u1") && rows.body.contains("role=admin"),
        "must return the live materialized row, got: {}",
        rows.body
    );

    // An unknown view 404s.
    let unknown = http(&addr, "GET", &format!("/portal/data/sql?token={token}&name=nope"), "");
    assert_eq!(unknown.status, 404, "unknown view: {}", unknown.body);
}

#[test]
fn all_three_browse_routes_are_gated_behind_an_admitted_session() {
    let (addr, _token) = serve_seeded();

    let kv = http(&addr, "GET", "/portal/data/kv", "");
    assert_eq!(kv.status, 401, "unauthenticated kv browse must be 401: {}", kv.body);

    let doc = http(&addr, "GET", "/portal/data/doc?collection=users", "");
    assert_eq!(doc.status, 401, "unauthenticated doc browse must be 401: {}", doc.body);

    let sql = http(&addr, "GET", "/portal/data/sql", "");
    assert_eq!(sql.status, 401, "unauthenticated sql browse must be 401: {}", sql.body);

    let bad_token = http(&addr, "GET", "/portal/data/kv?token=not-a-real-session", "");
    assert_eq!(
        bad_token.status, 401,
        "a bad session token must be 401: {}",
        bad_token.body
    );
}
