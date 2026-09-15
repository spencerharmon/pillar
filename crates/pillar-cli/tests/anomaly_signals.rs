//! Acceptance test — `um-anomaly-signals` (ROI P1 "User management &
//! lifecycle" roadmap D3).
//!
//! Proves `pillar user login-observe <handle> <origin> <lat> <lon> [--at
//! <secs>]` is an ADVISORY anomaly-detection hook over login events, driven
//! via `pillar_cli::apply_over_pillar_message::{user_op, control_op}` against
//! a LIVE `pillar node run` — never a crate-level fold round-trip — and
//! that it:
//!
//! - always records the observation and NEVER denies/gates the login itself
//!   (every call succeeds regardless of anomaly detection);
//! - detects IMPOSSIBLE-TRAVEL: two logins for the SAME handle, far apart
//!   geographically, too close together in time to be a real trip, sign
//!   exactly one `USER-ANOMALY-IMPOSSIBLE-TRAVEL` event;
//! - detects NEW-ORIGIN: a login from an origin never seen before for this
//!   handle (after at least one prior login) signs exactly one
//!   `USER-ANOMALY-NEW-ORIGIN` event;
//! - a plausible, same-origin, nearby/slow login signs NO anomaly at all;
//! - a RETURNING origin (seen before) never re-trips NEW-ORIGIN;
//! - every emitted anomaly signal folds into `pillar user security-events
//!   anomaly` (`um-security-events-feed`'s cell-wide view) with the SAME
//!   verifiability proof (`hash-matches-id=true`/`signature-valid=true`) as
//!   every other security category;
//! - fails closed: an UNADMITTED signer is refused.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test anomaly_signals --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::user_op;
use pillar_ops::UserOp;

const PASSWORD: &str = "correct horse battery staple 2026 anomaly signals";
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
/// key bytes alone (mirrors `security_events_feed`'s fixture).
fn cell_material(identity_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_bytes = b"pillar-streamdb/segment-signer/v1:".to_vec();
    seed_bytes.extend_from_slice(identity_key_bytes);
    let mut cell_id_bytes = b"pillar-streamdb/cell-id/v1:".to_vec();
    cell_id_bytes.extend_from_slice(&seed_bytes);
    (cell_id_bytes, seed_bytes)
}

/// Parse a `key=value` token out of one response line.
fn tok<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
}

/// The `anomalies: N` trailer count of a `login-observe` response body.
fn anomalies_count(body: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("anomalies: ") {
            return rest.trim().parse().expect("anomalies count parses");
        }
    }
    panic!("no `anomalies:` trailer in login-observe body: {body}");
}

/// The `events: N` trailer count of a security-events-feed body.
fn events_count(body: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("events: ") {
            return rest.trim().parse().expect("events count parses");
        }
    }
    panic!("no `events:` trailer in feed body: {body}");
}

#[test]
fn login_observe_detects_impossible_travel_and_new_origin_and_never_denies_the_login() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // --- SETUP (HTTP): bootstrap a cell + first user, and admit this test's
    // own signing key as a cell member.
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let signer_seed = pillar_crypto::Seed::from_bytes(b"anomaly-signals-e2e-test-signer".to_vec());
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

    let bob = "bob";

    // === First login ever for bob: no prior history, so NEITHER anomaly can
    // fire (no baseline to compare against). =================================
    let first = user_op(&UserOp::LoginObserve {
        handle: bob.to_owned(),
        origin: "chrome/macos/198.51.100.9".to_owned(),
        lat: "37.7749".to_owned(),  // San Francisco
        lon: "-122.4194".to_owned(),
        at: 1_000,
    })
    .expect("first login observation");
    assert_eq!(
        anomalies_count(&first),
        0,
        "a handle's very first login has no baseline: {first}"
    );

    // === A plausible follow-up login: same origin, same place, later time.
    // No anomaly. ==============================================================
    let plausible = user_op(&UserOp::LoginObserve {
        handle: bob.to_owned(),
        origin: "chrome/macos/198.51.100.9".to_owned(),
        lat: "37.7750".to_owned(),
        lon: "-122.4195".to_owned(),
        at: 1_000 + 3600, // one hour later
    })
    .expect("plausible follow-up login");
    assert_eq!(
        anomalies_count(&plausible),
        0,
        "same origin, negligible distance, an hour later is plausible: {plausible}"
    );

    // === IMPOSSIBLE TRAVEL: next login from New York, 60 seconds later — no
    // real traveler covers ~4100km in a minute. ===============================
    let impossible = user_op(&UserOp::LoginObserve {
        handle: bob.to_owned(),
        origin: "chrome/macos/198.51.100.9".to_owned(),
        lat: "40.7128".to_owned(), // New York
        lon: "-74.0060".to_owned(),
        at: 1_000 + 3600 + 60,
    })
    .expect("impossible-travel login");
    assert_eq!(
        anomalies_count(&impossible),
        1,
        "impossible travel must be flagged exactly once: {impossible}"
    );
    assert!(
        impossible.contains("USER-ANOMALY-IMPOSSIBLE-TRAVEL"),
        "impossible-travel verb present: {impossible}"
    );
    // The login itself is NEVER denied — it always succeeds and records.
    assert!(
        impossible.starts_with("OBSERVED"),
        "login-observe never denies the login: {impossible}"
    );

    // === NEW ORIGIN: same place (New York), new device, right after. ========
    let new_origin = user_op(&UserOp::LoginObserve {
        handle: bob.to_owned(),
        origin: "firefox/windows/203.0.113.5".to_owned(),
        lat: "40.7128".to_owned(),
        lon: "-74.0060".to_owned(),
        at: 1_000 + 3600 + 120,
    })
    .expect("new-origin login");
    assert_eq!(
        anomalies_count(&new_origin),
        1,
        "a never-before-seen origin must be flagged exactly once: {new_origin}"
    );
    assert!(
        new_origin.contains("USER-ANOMALY-NEW-ORIGIN"),
        "new-origin verb present: {new_origin}"
    );

    // === A RETURNING origin never re-trips NEW-ORIGIN: bob logs back in
    // from the ORIGINAL chrome/macos origin, still in New York (no more
    // impossible travel either — same place as last time, negligible time). ==
    let returning = user_op(&UserOp::LoginObserve {
        handle: bob.to_owned(),
        origin: "chrome/macos/198.51.100.9".to_owned(),
        lat: "40.7128".to_owned(),
        lon: "-74.0060".to_owned(),
        at: 1_000 + 3600 + 180,
    })
    .expect("returning-origin login");
    assert_eq!(
        anomalies_count(&returning),
        0,
        "a previously-seen origin must never re-trip new-origin: {returning}"
    );

    // === Every emitted anomaly signal folds into the cell-wide security
    // events feed's `anomaly` category, with full verifiability proof. ========
    let anomaly_feed = user_op(&UserOp::SecurityEventsFeed {
        kind: Some("anomaly".to_owned()),
    })
    .expect("security events feed (anomaly)");
    assert_eq!(
        events_count(&anomaly_feed),
        2,
        "exactly the impossible-travel + new-origin signals: {anomaly_feed}"
    );
    for line in anomaly_feed.lines().filter(|l| l.starts_with("event=")) {
        assert_eq!(
            tok(line, "category"),
            Some("anomaly"),
            "anomaly-only filter: {line}"
        );
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
    }

    // === Fail-closed: an UNADMITTED signer is refused, exactly like every
    // other member-gated remote op. ==========================================
    let intruder_seed =
        pillar_crypto::Seed::from_bytes(b"anomaly-signals-e2e-unadmitted".to_vec());
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
        user_op(&UserOp::LoginObserve {
            handle: bob.to_owned(),
            origin: "chrome/macos/198.51.100.9".to_owned(),
            lat: "40.7128".to_owned(),
            lon: "-74.0060".to_owned(),
            at: 1_000 + 3600 + 240,
        })
        .is_err(),
        "an unadmitted signer must be refused (fail-closed) on a login-observe"
    );
}
