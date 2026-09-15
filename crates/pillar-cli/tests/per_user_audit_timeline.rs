//! Acceptance test — `um-per-user-audit-timeline` (ROI P1 "User management &
//! lifecycle" roadmap D1).
//!
//! Proves a per-user audit timeline over the signed `act_log`: every
//! `pillar user invite|disable|enable|require-change|set-password` admin act
//! on a handle is a chronological, verifiable (hash==CID + signature) event
//! readable back through the EXISTING `pillar-log-inspection-tier` `QueryOp`
//! remote surface (`pillar log info|list|show|dag|verify`) over the reserved
//! `__user:<handle>` collection — no new op, no new authority gate, no new
//! TLA+ gate: read-only inspection of acts already signed by
//! `WebAuthContext::perform_signed_act`.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess, drives
//! its resource-op pillar-UDP tier via `pillar_cli::apply_over_pillar_message`
//! for BOTH the admin acts (`ControlOp::User`) and the audit-timeline reads
//! (`QueryOp::Log`) — a LIVE `pillar node run`, never a crate-level fold
//! round-trip.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test per_user_audit_timeline --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{query_op, send_control_op};
use pillar_ops::{ControlOp, LogOp, QueryOp, UserOp};

const PASSWORD: &str = "correct horse battery staple 2026 per-user audit";
const HANDLE: &str = "spencer";
const SUBJECT_HANDLE: &str = "audited-user";

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
/// key bytes alone (mirrors `pillar_log_inspection_tier`'s fixture).
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

/// Send a `ControlOp::User` admin act and unwrap its ack the same way the CLI's
/// private `control_op` helper does — mirrors `apply_over_pillar_message::
/// query_op` for the query-op class.
fn user_op(op: UserOp) -> Result<String, String> {
    let (ack, _tier) = send_control_op(&ControlOp::User(op)).map_err(|e| e.to_string())?;
    if let Some(payload) = ack.strip_prefix("OK ") {
        Ok(payload.to_owned())
    } else if ack == "OK" {
        Ok(String::new())
    } else {
        Err(ack.strip_prefix("ERR ").unwrap_or(&ack).to_owned())
    }
}

#[test]
fn cli_user_admin_acts_render_a_chronological_verifiable_per_user_audit_timeline_on_a_live_node() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key as a resource signer. None of this is the audit-
    // timeline path under test.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed =
        pillar_crypto::Seed::from_bytes(b"per-user-audit-timeline-e2e-signer".to_vec());
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
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(signer_public.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(signer_secret.as_bytes()),
    );

    // === Drive four real admin acts on SUBJECT_HANDLE over the delegated-
    // signed `ControlOp::User(...)` tier ======================================
    let invite = user_op(UserOp::Invite {
        handle: SUBJECT_HANDLE.to_owned(),
        email: "audited-user@example.com".to_owned(),
        force_password_change: false,
        require_passkey: false,
        password: Some("initial-temp-password-2026".to_owned()),
    })
    .expect("invite succeeds");
    assert!(invite.starts_with("INVITED"), "invite: {invite}");

    let disable = user_op(UserOp::Disable {
        handle: SUBJECT_HANDLE.to_owned(),
    })
    .expect("disable succeeds");
    assert!(disable.contains("Disabled"), "disable: {disable}");

    let enable = user_op(UserOp::Enable {
        handle: SUBJECT_HANDLE.to_owned(),
    })
    .expect("enable succeeds");
    assert!(enable.contains("Active"), "enable: {enable}");

    let require_change = user_op(UserOp::RequireChange {
        handle: SUBJECT_HANDLE.to_owned(),
    })
    .expect("require-change succeeds");
    assert!(
        require_change.contains("RequireChange"),
        "require-change: {require_change}"
    );

    let set_password = user_op(UserOp::SetPassword {
        handle: SUBJECT_HANDLE.to_owned(),
        password: "reset-password-2026".to_owned(),
        force: true,
    })
    .expect("set-password succeeds");
    assert!(
        set_password.contains("PASSWORD-SET"),
        "set-password: {set_password}"
    );

    let collection = format!("__user:{SUBJECT_HANDLE}");

    // `log info`: exactly 5 acts recorded, chronologically, in append order.
    let info = query_op(&QueryOp::Log(LogOp::Info {
        collection: collection.clone(),
    }))
    .expect("log info over the per-user audit collection");
    assert!(info.contains("ops: 5"), "info: {info}");
    let tip_hex = field(&info, "tip").to_owned();
    assert_eq!(tip_hex.len() % 2, 0, "tip must be well-formed hex: {info}");

    // `log list`: exactly 5 event ids, the last matching the tip (the most
    // recent act — the password reset).
    let list = query_op(&QueryOp::Log(LogOp::List {
        collection: collection.clone(),
    }))
    .expect("log list");
    let ids: Vec<&str> = list.lines().collect();
    assert_eq!(ids.len(), 5, "list: {list}");
    assert_eq!(ids[4], tip_hex, "the last listed id must be the tip");

    // `log show` on each event, IN ORDER, decodes the exact admin act kind —
    // proving this really is a CHRONOLOGICAL per-user timeline, not just a
    // bag of events.
    let expected_kinds = [
        "USER-INVITE",
        "USER-DISABLE",
        "USER-ENABLE",
        "USER-REQUIRE-CHANGE",
        "USER-RESET",
    ];
    for (id, expected_kind) in ids.iter().zip(expected_kinds.iter()) {
        let show = query_op(&QueryOp::Log(LogOp::Show {
            collection: collection.clone(),
            event_id_hex: (*id).to_owned(),
        }))
        .expect("log show");
        assert!(
            show.contains(&format!("kind: {expected_kind}")),
            "show for {id}: expected kind {expected_kind}, got: {show}"
        );
        assert!(field(&show, "key").contains(SUBJECT_HANDLE), "show: {show}");
        assert!(!field(&show, "author").is_empty(), "show: {show}");
        assert!(!field(&show, "payload-cid").is_empty(), "show: {show}");
        assert!(!field(&show, "signature").is_empty(), "show: {show}");
    }

    // `log dag`: at least the tip's own causal edge is rendered, proving the
    // causal graph decodes over the per-user collection too.
    let dag = query_op(&QueryOp::Log(LogOp::Dag {
        collection: collection.clone(),
    }))
    .expect("log dag");
    assert!(
        dag.lines().any(|l| l.ends_with(&tip_hex)),
        "dag must render an edge/genesis line ending at the tip: {dag}"
    );

    // `log verify` on EVERY event: hash==id and a valid signature — the
    // "verifiable" half of the DoD claim.
    for id in &ids {
        let verify = query_op(&QueryOp::Log(LogOp::Verify {
            collection: collection.clone(),
            event_id_hex: (*id).to_owned(),
        }))
        .expect("log verify");
        assert!(
            verify.contains("hash-matches-id: true"),
            "verify for {id}: {verify}"
        );
        assert!(
            verify.contains("signature-valid: true"),
            "verify for {id}: {verify}"
        );
    }

    // === Isolation: a DIFFERENT user's per-user collection does not exist —
    // the timeline is genuinely PER-USER, not a shared global act list =======
    let other_collection = "__user:someone-else-entirely";
    assert!(
        query_op(&QueryOp::Log(LogOp::Info {
            collection: other_collection.to_owned(),
        }))
        .is_err(),
        "an unadmitted/nonexistent handle's audit collection must not exist"
    );

    // === Fail-closed: an UNADMITTED signer is refused reading the audit
    // timeline, exactly like every other `pillar log` read ====================
    let intruder_signer_seed =
        pillar_crypto::Seed::from_bytes(b"per-user-audit-timeline-e2e-unadmitted".to_vec());
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
            collection,
        }))
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on an audit-timeline read"
    );
}
