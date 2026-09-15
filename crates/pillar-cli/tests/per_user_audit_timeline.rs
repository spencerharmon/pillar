//! Acceptance test — `um-per-user-audit-timeline` (ROI P1 "User management &
//! lifecycle" roadmap D1).
//!
//! Proves `pillar user audit <handle>` renders a chronological,
//! cryptographically VERIFIABLE (hash==id + valid signature) per-user event
//! history over the SAME sealed `ControlOp::User(...)` remote surface the rest
//! of IAM user admin rides (driven via `pillar_cli::apply_over_pillar_message::
//! user_op` against a LIVE `pillar node run`, never a crate-level fold
//! round-trip), and that it:
//!
//! - folds the node's signed `act_log` — the SAME signed events every
//!   `iam:users:write` mutation (`invite`/`disable`/`enable`/`require-change`/
//!   `set-password`) appends — into ONE per-subject timeline;
//! - includes ONLY the acts that named the subject handle (a mutation of a
//!   DIFFERENT user never leaks into this user's timeline);
//! - renders each event with its verifiability proof: `hash-matches-id=true`
//!   (reaching the event by its content-address id already proves it) and
//!   `signature-valid=true` (the real Ed25519 authorship check), so the
//!   timeline is auditable WITHOUT trusting the fold;
//! - is read-only (no new authority, no new event): a second read returns the
//!   identical count;
//! - fails closed: an UNADMITTED signer is refused, exactly like every other
//!   member-gated remote op.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test per_user_audit_timeline --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::user_op;
use pillar_ops::UserOp;

const PASSWORD: &str = "correct horse battery staple 2026 per-user audit";
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
/// key bytes alone (mirrors `pillar_log_inspection_tier`'s fixture).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

/// Parse a `key=value` token out of one audit-timeline event line.
fn tok<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
}

/// The `acts: N` trailer count of a timeline body.
fn acts_count(body: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("acts: ") {
            return rest.trim().parse().expect("acts count parses");
        }
    }
    panic!("no `acts:` trailer in timeline body: {body}");
}

#[test]
fn user_audit_timeline_is_a_chronological_verifiable_per_user_history_over_the_control_op_surface()
{
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key as a cell member (so it satisfies the `iam:users:write`
    // decider, exactly like the log-inspection tier's `data:write` signer).
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"per-user-audit-e2e-test-signer".to_vec());
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

    // === Drive a real per-user lifecycle over the control-op tier: every
    // mutation appends a signed act to the node's `act_log`. ==================
    let subject = "bob";
    let other = "carol";

    let invite = user_op(&UserOp::Invite {
        handle: subject.to_owned(),
        email: "bob@example.com".to_owned(),
        force_password_change: false,
        require_passkey: false,
        password: Some("bob-initial-pw".to_owned()),
    })
    .expect("invite bob over control-op tier");
    assert!(invite.contains("INVITED handle=bob"), "invite: {invite}");

    // A mutation of a DIFFERENT user — must NOT leak into bob's timeline.
    let invite_other = user_op(&UserOp::Invite {
        handle: other.to_owned(),
        email: "carol@example.com".to_owned(),
        force_password_change: false,
        require_passkey: false,
        password: Some("carol-initial-pw".to_owned()),
    })
    .expect("invite carol over control-op tier");
    assert!(
        invite_other.contains("INVITED handle=carol"),
        "invite carol: {invite_other}"
    );

    user_op(&UserOp::Disable {
        handle: subject.to_owned(),
    })
    .expect("disable bob");
    user_op(&UserOp::Enable {
        handle: subject.to_owned(),
    })
    .expect("enable bob");
    user_op(&UserOp::RequireChange {
        handle: subject.to_owned(),
    })
    .expect("require-change bob");

    // === The per-user audit timeline over the SAME control-op surface ========
    let timeline = user_op(&UserOp::AuditTimeline {
        handle: subject.to_owned(),
    })
    .expect("audit timeline for bob");

    assert!(
        timeline.contains(&format!("audit-timeline handle={subject}")),
        "header: {timeline}"
    );

    // Exactly the FOUR acts that named bob (invite, disable, enable,
    // require-change) — carol's invite is excluded.
    let event_lines: Vec<&str> = timeline
        .lines()
        .filter(|l| l.starts_with("event="))
        .collect();
    assert_eq!(
        event_lines.len(),
        4,
        "exactly bob's four acts, carol excluded: {timeline}"
    );
    assert_eq!(acts_count(&timeline), 4, "acts trailer: {timeline}");

    // Chronological ORDER: the acts appear in the order they were applied.
    let acts: Vec<&str> = event_lines
        .iter()
        .map(|l| tok(l, "act").expect("act token"))
        .collect();
    assert_eq!(
        acts,
        vec![
            "USER-INVITE",
            "USER-DISABLE",
            "USER-ENABLE",
            "USER-REQUIRE-CHANGE"
        ],
        "chronological act order: {timeline}"
    );

    // Every event carries its verifiability proof: hash==id AND a valid
    // signature — the timeline is auditable WITHOUT trusting the fold.
    for line in &event_lines {
        assert_eq!(
            tok(line, "hash-matches-id"),
            Some("true"),
            "hash==id: {line}"
        );
        assert_eq!(
            tok(line, "signature-valid"),
            Some("true"),
            "signature valid: {line}"
        );
        assert!(
            tok(line, "event").is_some_and(|e| e.len() % 2 == 0 && !e.is_empty()),
            "well-formed event id hex: {line}"
        );
    }

    // No carol act leaked into bob's timeline.
    assert!(
        !timeline.contains("carol"),
        "carol must not appear in bob's timeline: {timeline}"
    );

    // Read-only: a second read returns the identical count (no new event).
    let timeline_again = user_op(&UserOp::AuditTimeline {
        handle: subject.to_owned(),
    })
    .expect("re-read bob timeline");
    assert_eq!(
        acts_count(&timeline_again),
        4,
        "a timeline read appends no event: {timeline_again}"
    );

    // A user with no admin acts beyond its own invite still renders honestly.
    let carol_timeline = user_op(&UserOp::AuditTimeline {
        handle: other.to_owned(),
    })
    .expect("carol timeline");
    assert_eq!(
        acts_count(&carol_timeline),
        1,
        "carol has exactly her invite act: {carol_timeline}"
    );

    // === Fail-closed: an UNADMITTED signer is refused, exactly like every
    // other member-gated remote op. ==========================================
    let intruder_seed = pillar_crypto::Seed::from_bytes(b"per-user-audit-e2e-unadmitted".to_vec());
    let (intruder_pub, intruder_secret) =
        pillar_crypto::sign::signing_keypair_from_seed(&intruder_seed).expect("intruder keypair");
    std::env::set_var(
        "PILLAR_SIGNER_PUBLIC_HEX",
        hex_encode(intruder_pub.as_bytes()),
    );
    std::env::set_var(
        "PILLAR_SIGNER_SECRET_HEX",
        hex_encode(intruder_secret.as_bytes()),
    );
    assert!(
        user_op(&UserOp::AuditTimeline {
            handle: subject.to_owned(),
        })
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on an audit-timeline read"
    );
}
