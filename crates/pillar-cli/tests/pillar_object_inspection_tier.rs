//! Acceptance test — `pillar-object-inspection-tier` (ROI Priority 1
//! "Layered data inspection — the op log, storage layout, and IPFS objects
//! beneath the overlay").
//!
//! Proves the load-bearing DoD claim: `pillar object stat|links|get|cat|
//! verify` address any content-addressed block by CID over the SAME sealed
//! `QueryOp` remote surface `data-query-tier-remote-surface` proved (a LIVE
//! `pillar node run`, driven via `pillar_cli::apply_over_pillar_message::
//! query_op` — never a crate-level fold round-trip and never a portal GET
//! shim), and that access + verifiability hold as hard requirements:
//!
//! - a REAL sealed object's body is returned ONLY to a holder of one of its
//!   recipients' X25519 secret keys — everyone else (including the signer of
//!   the wire request itself) sees only the envelope;
//! - a REAL public object has no such barrier;
//! - `object verify` confirms hash == CID and signature validity WITHOUT ever
//!   decrypting, for a sealed object it can never open.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test pillar_object_inspection_tier --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::query_op;
use pillar_ops::{ObjectOp, ObjectVisibility, QueryOp};

const PASSWORD: &str = "correct horse battery staple 2026 object inspection";
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
/// key bytes alone (mirrors `data_query_tier_remote_surface`'s fixture).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

#[test]
fn cli_object_stat_links_get_cat_verify_round_trip_real_sealed_and_public_blocks_on_a_live_node() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key. None of this is the object-inspection path under test.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"object-inspection-e2e-test-signer".to_vec());
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

    // === A real PUBLIC object: no access barrier ============================
    let public_payload = b"a public, unsealed pillar object";
    let put_ack = query_op(&QueryOp::Object(ObjectOp::Put {
        visibility: ObjectVisibility::Public,
        payload_hex: hex_encode(public_payload),
        links_hex: vec![],
        recipients_hex: vec![],
    }))
    .expect("object put (public) over pillar-UDP succeeds");
    assert!(put_ack.starts_with("OBJECT-PUT"), "object put ack: {put_ack}");
    assert!(put_ack.contains("EVENT-CID"), "object put emits a signed event: {put_ack}");
    let public_cid = put_ack
        .split_whitespace()
        .nth(1)
        .expect("OBJECT-PUT <cid> EVENT-CID <cid>")
        .to_owned();

    // stat reports real codec/size/pin status from the live node.
    let stat = query_op(&QueryOp::Object(ObjectOp::Stat {
        cid_hex: public_cid.clone(),
    }))
    .expect("object stat");
    assert!(stat.contains("codec:"), "stat: {stat}");
    assert!(stat.contains("visibility: public"), "stat: {stat}");
    assert!(stat.contains("pinned:"), "stat: {stat}");
    assert!(!stat.contains("(none)"), "a freshly-put object is pinned: {stat}");

    // cat/get return the real plaintext with NO barrier.
    let cat = query_op(&QueryOp::Object(ObjectOp::Cat {
        cid_hex: public_cid.clone(),
        sealing_secret_hex: None,
    }))
    .expect("object cat (public)");
    assert_eq!(cat, String::from_utf8(public_payload.to_vec()).unwrap());

    let get = query_op(&QueryOp::Object(ObjectOp::Get {
        cid_hex: public_cid.clone(),
        sealing_secret_hex: None,
    }))
    .expect("object get (public)");
    assert_eq!(hex_decode(&get), public_payload, "get returns raw hex bytes");

    // verify confirms hash==CID and a valid signature.
    let verify = query_op(&QueryOp::Object(ObjectOp::Verify {
        cid_hex: public_cid.clone(),
    }))
    .expect("object verify (public)");
    assert!(verify.contains("hash-matches-cid: true"), "verify: {verify}");
    assert!(verify.contains("signature-valid: true"), "verify: {verify}");

    // === A real SEALED object: access follows the seal, verifiable without
    // decrypting =============================================================
    let recipient_seed = pillar_crypto::Seed::from_bytes(b"object-inspection-e2e-recipient".to_vec());
    let (recipient_pub, recipient_secret) =
        pillar_crypto::seal::sealing_keypair_from_seed(&recipient_seed).expect("seal keypair");
    let intruder_seed = pillar_crypto::Seed::from_bytes(b"object-inspection-e2e-intruder".to_vec());
    let (_intruder_pub, intruder_secret) =
        pillar_crypto::seal::sealing_keypair_from_seed(&intruder_seed).expect("seal keypair");

    let secret_payload = b"only the recipient may ever read this";
    let child_link = hex_encode(b"a-child-block-placeholder-cid");
    let put_ack = query_op(&QueryOp::Object(ObjectOp::Put {
        visibility: ObjectVisibility::Sealed,
        payload_hex: hex_encode(secret_payload),
        links_hex: vec![child_link.clone()],
        recipients_hex: vec![hex_encode(recipient_pub.as_bytes())],
    }))
    .expect("object put (sealed) over pillar-UDP succeeds");
    let sealed_cid = put_ack
        .split_whitespace()
        .nth(1)
        .expect("OBJECT-PUT <cid> EVENT-CID <cid>")
        .to_owned();

    // links is readable in the clear — no secret required.
    let links = query_op(&QueryOp::Object(ObjectOp::Links {
        cid_hex: sealed_cid.clone(),
    }))
    .expect("object links (sealed)");
    assert!(links.contains(&child_link), "links: {links}");

    // No secret at all -> envelope only, plaintext never leaks.
    let no_secret = query_op(&QueryOp::Object(ObjectOp::Cat {
        cid_hex: sealed_cid.clone(),
        sealing_secret_hex: None,
    }))
    .expect("object cat with no secret still returns the envelope");
    assert!(no_secret.starts_with("SEALED"), "no_secret: {no_secret}");
    assert!(
        !no_secret.contains("only the recipient"),
        "the plaintext must never leak without the right key: {no_secret}"
    );

    // The WRONG secret (an intruder's) -> still envelope only.
    let wrong_secret = query_op(&QueryOp::Object(ObjectOp::Cat {
        cid_hex: sealed_cid.clone(),
        sealing_secret_hex: Some(hex_encode(intruder_secret.as_bytes())),
    }))
    .expect("object cat with wrong secret still returns the envelope");
    assert!(wrong_secret.starts_with("SEALED"), "wrong_secret: {wrong_secret}");

    // The REAL recipient's secret -> the real plaintext, in place.
    let opened = query_op(&QueryOp::Object(ObjectOp::Cat {
        cid_hex: sealed_cid.clone(),
        sealing_secret_hex: Some(hex_encode(recipient_secret.as_bytes())),
    }))
    .expect("object cat with the real recipient secret opens the body");
    assert_eq!(opened, String::from_utf8(secret_payload.to_vec()).unwrap());

    // stat reports the sealed visibility + recipient count without opening.
    let stat = query_op(&QueryOp::Object(ObjectOp::Stat {
        cid_hex: sealed_cid.clone(),
    }))
    .expect("object stat (sealed)");
    assert!(stat.contains("sealed"), "stat: {stat}");
    assert!(stat.contains("1 recipients"), "stat: {stat}");

    // verify NEVER opens the sealed body, yet still proves integrity +
    // authorship — the headline non-negotiable of this task.
    let verify = query_op(&QueryOp::Object(ObjectOp::Verify {
        cid_hex: sealed_cid,
    }))
    .expect("object verify (sealed) never needs to decrypt");
    assert!(verify.contains("hash-matches-cid: true"), "verify: {verify}");
    assert!(verify.contains("signature-valid: true"), "verify: {verify}");

    // === Fail-closed: an UNADMITTED signer is refused, exactly like the
    // data-query tier =========================================================
    let intruder_signer_seed =
        pillar_crypto::Seed::from_bytes(b"object-inspection-e2e-unadmitted".to_vec());
    let (intruder_signer_pub, intruder_signer_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder_signer_seed)
            .expect("intruder keypair");
    let saved_pub = std::env::var("PILLAR_SIGNER_PUBLIC_HEX").expect("pub set");
    let saved_secret = std::env::var("PILLAR_SIGNER_SECRET_HEX").expect("secret set");
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(intruder_signer_pub.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(intruder_signer_secret.as_bytes()),
    );
    assert!(
        query_op(&QueryOp::Object(ObjectOp::Stat {
            cid_hex: public_cid,
        }))
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on an object read"
    );
    std::env::set_var("PILLAR_SIGNER_PUBLIC_HEX", saved_pub);
    std::env::set_var("PILLAR_SIGNER_SECRET_HEX", saved_secret);
}
