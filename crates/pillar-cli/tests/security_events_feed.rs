//! Acceptance test — `um-security-events-feed` (ROI P1 "User management &
//! lifecycle" roadmap D2).
//!
//! Proves `pillar user security-events [kind]` renders a chronological,
//! filterable, cryptographically VERIFIABLE (hash==id + valid signature)
//! CELL-WIDE derived view over the SAME signed `act_log` the per-user audit
//! timeline (`um-per-user-audit-timeline`) folds — driven via
//! `pillar_cli::apply_over_pillar_message::{user_op, control_op}` against a
//! LIVE `pillar node run`, never a crate-level fold round-trip — and that it:
//!
//! - folds every signed act across every subject (an account-lockout act on
//!   one user AND a privilege elevation on another both land in the SAME
//!   feed, unlike the per-user timeline which is scoped to one handle);
//! - classifies each act into exactly one security category: `lockout`
//!   (`USER-DISABLE`/`USER-ENABLE`), `elevation` (`MEMBER-ADD`/`MEMBER-ROLE`),
//!   `rotation` (`IDENTITY-ROTATE`), `revocation`
//!   (`SESSION-REVOKE`/`SESSION-REVOKE-ALL`);
//! - excludes non-security acts (a plain `USER-INVITE` never appears);
//! - `kind` narrows the feed to exactly one category, and an unrecognized
//!   `kind` renders zero events (never silently "all");
//! - renders each event with its verifiability proof:
//!   `hash-matches-id=true`/`signature-valid=true`, exactly like the per-user
//!   timeline;
//! - is read-only (a second read returns the identical count);
//! - fails closed: an UNADMITTED signer is refused.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test security_events_feed --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{control_op, user_op};
use pillar_ops::{ControlOp, IdentityOp, MembersOp, SessionOp, UserOp};

const PASSWORD: &str = "correct horse battery staple 2026 security events feed";
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
/// key bytes alone (mirrors `per_user_audit_timeline`'s fixture).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

/// Parse a `key=value` token out of one security-events-feed line.
fn tok<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
}

/// The `events: N` trailer count of a feed body.
fn events_count(body: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("events: ") {
            return rest.trim().parse().expect("events count parses");
        }
    }
    panic!("no `events:` trailer in feed body: {body}");
}

#[test]
fn security_events_feed_is_a_filterable_verifiable_cell_wide_view_over_the_control_op_surface() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key as a cell member.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed =
        pillar_crypto::Seed::from_bytes(b"security-events-feed-e2e-test-signer".to_vec());
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

    // === Drive a real mixed lifecycle across MULTIPLE subjects and ops, each
    // appending a signed act to the node's shared `act_log`. =================
    let bob = "bob";
    let carol = "carol";

    // A non-security act — must NEVER appear in the feed.
    let invite_bob = user_op(&UserOp::Invite {
        handle: bob.to_owned(),
        email: "bob@example.com".to_owned(),
        force_password_change: false,
        require_passkey: false,
        password: Some("bob-initial-pw".to_owned()),
    })
    .expect("invite bob over control-op tier");
    assert!(
        invite_bob.contains("INVITED handle=bob"),
        "invite: {invite_bob}"
    );

    let invite_carol = user_op(&UserOp::Invite {
        handle: carol.to_owned(),
        email: "carol@example.com".to_owned(),
        force_password_change: false,
        require_passkey: false,
        password: Some("carol-initial-pw".to_owned()),
    })
    .expect("invite carol over control-op tier");
    assert!(
        invite_carol.contains("INVITED handle=carol"),
        "invite carol: {invite_carol}"
    );

    // lockout category: disable bob.
    user_op(&UserOp::Disable {
        handle: bob.to_owned(),
    })
    .expect("disable bob");

    // elevation category: add carol as a cell member with an elevated role.
    control_op(&ControlOp::Members(MembersOp::Add {
        handle: carol.to_owned(),
        role: "admin".to_owned(),
    }))
    .expect("add carol as admin member");

    // rotation category: rotate the global identity primary key.
    control_op(&ControlOp::Identity(IdentityOp::Rotate {
        new_primary: "test-rotated-key".to_owned(),
    }))
    .expect("rotate identity primary");

    // revocation category: revoke-all sessions for bob.
    control_op(&ControlOp::Session(SessionOp::RevokeAll {
        principal: bob.to_owned(),
    }))
    .expect("revoke-all bob sessions");

    // === The cell-wide, unfiltered feed =======================================
    let feed =
        user_op(&UserOp::SecurityEventsFeed { kind: None }).expect("security events feed (all)");
    assert!(
        feed.contains("security-events-feed kind=all"),
        "header: {feed}"
    );

    let event_lines: Vec<&str> = feed.lines().filter(|l| l.starts_with("event=")).collect();
    // Exactly the four security-relevant acts: disable, member-add,
    // identity-rotate, session-revoke-all. Neither invite ever appears.
    assert_eq!(
        event_lines.len(),
        4,
        "exactly the four security-relevant acts: {feed}"
    );
    assert_eq!(events_count(&feed), 4, "events trailer: {feed}");
    assert!(
        !feed.contains("USER-INVITE"),
        "a plain invite is not security-relevant: {feed}"
    );

    let categories: Vec<&str> = event_lines
        .iter()
        .map(|l| tok(l, "category").expect("category token"))
        .collect();
    assert_eq!(
        categories,
        vec!["lockout", "elevation", "rotation", "revocation"],
        "chronological category order: {feed}"
    );

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

    // === `kind` narrows to exactly one category ===============================
    let lockout_only = user_op(&UserOp::SecurityEventsFeed {
        kind: Some("lockout".to_owned()),
    })
    .expect("security events feed (lockout)");
    assert_eq!(
        events_count(&lockout_only),
        1,
        "only bob's disable: {lockout_only}"
    );
    assert!(
        lockout_only.contains("category=lockout"),
        "lockout body: {lockout_only}"
    );
    assert!(
        !lockout_only.contains("category=elevation")
            && !lockout_only.contains("category=rotation")
            && !lockout_only.contains("category=revocation"),
        "no other category leaks into the lockout filter: {lockout_only}"
    );

    // An unrecognized `kind` renders zero events — never silently "all".
    let unknown_kind = user_op(&UserOp::SecurityEventsFeed {
        kind: Some("not-a-real-category".to_owned()),
    })
    .expect("security events feed (unknown kind)");
    assert_eq!(
        events_count(&unknown_kind),
        0,
        "unrecognized kind renders zero, not all: {unknown_kind}"
    );

    // Read-only: a second unfiltered read returns the identical count.
    let feed_again =
        user_op(&UserOp::SecurityEventsFeed { kind: None }).expect("re-read security events feed");
    assert_eq!(
        events_count(&feed_again),
        4,
        "a feed read appends no event: {feed_again}"
    );

    // === Fail-closed: an UNADMITTED signer is refused, exactly like every
    // other member-gated remote op. ==========================================
    let intruder_seed =
        pillar_crypto::Seed::from_bytes(b"security-events-feed-e2e-unadmitted".to_vec());
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
        user_op(&UserOp::SecurityEventsFeed { kind: None }).is_err(),
        "an unadmitted signer must be refused (fail-closed) on a security-events-feed read"
    );
}
