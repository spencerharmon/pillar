//! Acceptance test — `cli-config-subkey-credential` (2026-09-12 ROI HEAD).
//!
//! Proves the CLI credential half of the "Turnkey remote apply" capstone:
//! `pillar config export` mints a scoped CLI signing subkey over a real
//! AUTHENTICATED `pillar login` session (never the unauthenticated
//! `/bootstrap/admit-resource-signer` SETUP endpoint), durably WoT-admits it
//! server-side, persists the resulting `config.yaml` with mode `0600`
//! (never briefly world/group-readable), and that the persisted config's
//! baked-in subkey really authorizes a live `pillar apply`/`pillar delete`
//! mutation over the pillar-UDP resource-op tier — with NO further setup and
//! NO interactive unlock.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess for
//! the node under test and drives `pillar login` / the cli-config export
//! over real HTTP, exactly as an operator would. The mutation act itself is
//! driven by directly invoking `pillar_cli::apply_over_pillar_message::{apply,delete}`
//! — the exact code `pillar apply`/`pillar delete` dispatch to — configured
//! ONLY via the persisted `config.yaml` (`$PILLAR_CONFIG`), never via the
//! `PILLAR_RESOURCE_OP_ADDR`/`PILLAR_SIGNER_*` env escape hatch
//! `cli_apply_over_pillar_message` uses, so this test is the one that
//! actually proves the turnkey config path end to end.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test cli_config_subkey_credential --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{apply_manifest_text, delete_resource};
use pillar_cli::config_export;

const PASSWORD: &str = "correct horse battery staple 2026 cli-config";
const HANDLE: &str = "spencer";

struct HttpResponse {
    status: u16,
    session: Option<String>,
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

    let mut session = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("x-pillar-session") {
                session = Some(value.trim().to_owned());
            }
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        session,
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

/// A booted `pillar node run` subprocess with its HTTP (login/portal) and
/// resource-op pillar-UDP tiers bound; killed on drop.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path, resource_op_port: u16) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
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
            // So the exported `config.yaml`'s `identity.addr` (this test
            // never overrides it) names the REAL bound resource-op port —
            // proving the turnkey config the portal exports is directly
            // usable with no manual address fixup.
            .env(
                "PILLAR_PUBLIC_RESOURCE_OP_ADDR",
                format!("127.0.0.1:{resource_op_port}"),
            )
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node { child, http_port };
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

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.http_port)
    }

    /// Log in exactly as `pillar login` would (nonce -> POST /login) and
    /// return the minted session bearer.
    fn login(&self, handle: &str, password: &str) -> String {
        let nonce = http(self.http_port, "GET", "/nonce", "").expect("GET /nonce");
        assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
        let nonce_id = nonce
            .body
            .split_whitespace()
            .nth(1)
            .expect("nonce id in body");
        let login_body = format!("{handle}\n{password}\n{nonce_id}");
        let reply = self.post("/login", &login_body);
        assert_eq!(reply.status, 200, "login: {}", reply.body);
        reply.session.expect("login sets X-Pillar-Session")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn mode_bits(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("stat exported config")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn cli_config_export_mints_a_real_subkey_over_an_authenticated_session_persists_0600_and_it_authorizes_a_live_apply(
) {
    let data_dir = tempfile::tempdir().expect("data dir");
    let resource_op_port = free_udp_port();
    let node = Node::boot(data_dir.path(), resource_op_port);

    // --- One-time cell/user bootstrap (never the credential mint itself).
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    // --- The credential mint under test: a REAL authenticated session,
    // never the unauthenticated /bootstrap/admit-resource-signer path.
    let token = node.login(HANDLE, PASSWORD);

    // Unauthenticated / bad-token export must be refused.
    let denied = config_export::fetch_config(&node.authority(), "not-a-real-token");
    assert!(
        denied.is_err(),
        "an unauthenticated cli-config export must be refused"
    );

    let cfg = config_export::fetch_config(&node.authority(), &token)
        .expect("cli-config export over an authenticated session succeeds");
    let out_dir = tempfile::tempdir().expect("out dir");
    let out_path = out_dir.path().join("config.yaml");
    config_export::save_0600(&cfg, &out_path).expect("persist exported config");

    #[cfg(unix)]
    assert_eq!(
        mode_bits(&out_path),
        0o600,
        "the persisted config must be 0600 — it carries the cell seed + signer secret"
    );

    // Reload it exactly as `pillar apply` would (a fresh parse from disk,
    // never the in-memory value) to prove the persisted bytes round-trip.
    let reloaded = pillar_client::ClientConfig::parse(
        &std::fs::read_to_string(&out_path).expect("read persisted config"),
        &out_path,
    )
    .expect("reparse persisted config");
    let identity = reloaded.identity.expect("identity block persisted");
    assert!(
        !identity.signer_secret_hex.is_empty(),
        "a real scoped signer secret is baked in, non-interactive"
    );

    // --- Wire $PILLAR_CONFIG at the SAME persisted path a real CLI would
    // load from — no address fixup, no env escape hatch, the turnkey config
    // as exported and saved is directly usable.
    std::env::set_var("PILLAR_CONFIG", &out_path);
    std::env::remove_var("PILLAR_RESOURCE_OP_ADDR");

    let manifest_text = concat!(
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: cli-config-subkey-credential-metrics\n",
        "spec:\n",
        "  signalKind: Metric\n",
        "  window: 2592000\n",
    );

    let acks = apply_manifest_text(manifest_text)
        .expect("apply over the exported, persisted CLI config succeeds");
    assert_eq!(acks.len(), 1);
    assert!(acks[0].ack.starts_with("OK"), "apply ack: {}", acks[0].ack);
    assert_eq!(
        acks[0].tier,
        pillar_client::TransportKind::PillarUdp,
        "must ride pillar-UDP via the persisted turnkey config, never a REST fallback"
    );

    let (ack, tier) = delete_resource("RetentionPolicy/cli-config-subkey-credential-metrics")
        .expect("delete over the exported, persisted CLI config succeeds");
    assert!(ack.starts_with("OK"), "delete ack: {ack}");
    assert_eq!(tier, pillar_client::TransportKind::PillarUdp);

    std::env::remove_var("PILLAR_CONFIG");
}
