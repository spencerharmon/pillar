//! Acceptance test — `ui-cli-config-export` (2026-09-12 ROI HEAD),
//! ROI Priority 1 "Turnkey remote apply" change #2 UI half + turnkey CAPSTONE.
//!
//! This is the capstone that ties the whole "Turnkey remote apply" story
//! together end to end from the *profile page's* point of view:
//!
//!   A freshly-installed pillar node, plus a `config.yaml` obtained EXACTLY
//!   the way the authenticated profile-page "Download CLI config" button
//!   obtains it (`POST /portal/profile/cli-config` over the user's real
//!   `pillar login` session — driven here through
//!   `pillar_cli::config_export::fetch_config`, the identical code path the
//!   web-UI button and `pillar config export` both invoke), and NOTHING else
//!   (only `$PILLAR_CONFIG` at the persisted path — no `PILLAR_RESOURCE_OP_ADDR`,
//!   no `PILLAR_SIGNER_*` env escape hatch), applies a `RetentionPolicy` into
//!   the live cell's Default `ResourceSet` over the pillar-UDP resource-op tier.
//!
//! The capstone has two halves, both asserted here:
//!
//!  1. **Turnkey DEFAULT wiring is deterministic** (`turnkey_default_*` test):
//!     a freshly-installed node — no `PILLAR_RESOURCE_OP_UDP_BIND`, no
//!     `PILLAR_PUBLIC_*` — BINDS the well-known default resource-op UDP port
//!     ([`pillar_net::DEFAULT_RESOURCE_OP_UDP_PORT`], from
//!     `resource-op-tier-default-listen`) with ZERO env, and its profile
//!     export BAKES that same default `host:port` into the `config.yaml`'s
//!     `identity.addr` with no address fixup. This is asserted without routing
//!     live traffic through the globally-shared default port (which peer
//!     acceptance nodes on the same host also use), so it is race-free.
//!  2. **The exported, persisted config drives a LIVE apply** (`profile_*`
//!     test): the profile-exported config, persisted 0600, is directly usable
//!     for a real `pillar apply`/`pillar delete` over pillar-UDP with nothing
//!     but `$PILLAR_CONFIG`, proving the turnkey path end to end. To keep this
//!     isolated from peer nodes that share the fixed default port on a CI host,
//!     the node under test binds a private ephemeral resource-op port and
//!     advertises it via `PILLAR_PUBLIC_RESOURCE_OP_ADDR` — the SAME wiring a
//!     real deploy uses to publish its externally-reachable endpoint — so the
//!     baked `identity.addr` names this node and the datagram cannot be
//!     load-balanced to a stranger's default-port socket.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess for the
//! node under test and drives `pillar login` + the profile cli-config export
//! over real HTTP, exactly as an operator using the web UI would.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test ui_cli_config_export --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::apply_over_pillar_message::{apply_manifest_text, delete_resource};
use pillar_cli::config_export;

const PASSWORD: &str = "correct horse battery staple 2026 ui-cli-config-export";
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

/// How the node under test binds + advertises its resource-op pillar-UDP tier.
enum ResourceOp {
    /// A freshly-installed node: NEITHER `PILLAR_RESOURCE_OP_UDP_BIND` nor any
    /// `PILLAR_PUBLIC_*` set. The node binds the well-known DEFAULT port with
    /// zero env and its export bakes the default `127.0.0.1:<default>` addr.
    /// Used to prove the turnkey default WIRING (never to route live traffic —
    /// the default port is globally shared with peer acceptance nodes).
    TurnkeyDefault,
    /// An isolated private port, advertised via `PILLAR_PUBLIC_RESOURCE_OP_ADDR`
    /// exactly as a real deploy publishes its reachable endpoint. Used for the
    /// LIVE apply so the datagram cannot be misrouted to a peer's default-port
    /// socket on a shared CI host.
    Isolated(u16),
}

/// A booted `pillar node run` subprocess with its HTTP (login/portal) tier on
/// a free ephemeral port; killed on drop.
struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path, resource_op: ResourceOp) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let mut cmd = Command::new(bin);
        cmd.arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match resource_op {
            // Zero resource-op config: the node must bind the DEFAULT port and
            // bake the DEFAULT addr entirely on its own.
            ResourceOp::TurnkeyDefault => {}
            ResourceOp::Isolated(port) => {
                cmd.env("PILLAR_RESOURCE_OP_UDP_BIND", format!("127.0.0.1:{port}"))
                    .env(
                        "PILLAR_PUBLIC_RESOURCE_OP_ADDR",
                        format!("127.0.0.1:{port}"),
                    );
            }
        }
        let child = cmd.spawn().expect("spawn pillar node run");
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

    /// One-time cell + user bootstrap (the "install", never the export).
    fn provision(&self) {
        let create_cell = self.post("/bootstrap/create-cell", "cell-genesis");
        assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
        let create_user = self.post("/bootstrap/create-user", &format!("{HANDLE}\n{PASSWORD}"));
        assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);
    }

    /// Log in exactly as `pillar login` (and the web UI's auth flow) would
    /// (nonce -> POST /login) and return the minted session bearer.
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

/// CAPSTONE half 1 — the turnkey DEFAULT wiring, asserted deterministically
/// (no live traffic over the globally-shared default port). A freshly-installed
/// node with ZERO resource-op env BINDS the well-known default UDP port and its
/// profile export BAKES that same default `host:port` into the config's
/// `identity.addr` — so a fresh node is directly reachable by `pillar apply`
/// with no config and no address fixup.
#[test]
fn turnkey_default_node_binds_and_exports_the_well_known_default_resource_op_port() {
    // (a) The zero-config bind resolution is the well-known default port on the
    //     wildcard host — this is the `resource-op-tier-default-listen` policy
    //     the fresh node relies on.
    let resolved = pillar_net::resolve_resource_op_bind(None);
    assert_eq!(
        resolved.addr,
        SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            pillar_net::DEFAULT_RESOURCE_OP_UDP_PORT
        )),
        "a freshly-installed node binds 0.0.0.0:<default> for the resource-op tier with no env"
    );
    assert!(resolved.invalid_override.is_none());

    // (b) A freshly-installed node (no PILLAR_PUBLIC_* / no bind override) bakes
    //     the DEFAULT `127.0.0.1:<default>` endpoint into its profile export —
    //     directly usable with no address fixup.
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path(), ResourceOp::TurnkeyDefault);
    node.provision();
    let token = node.login(HANDLE, PASSWORD);

    let cfg = config_export::fetch_config(&node.authority(), &token)
        .expect("profile cli-config export over an authenticated session succeeds");
    let identity = cfg.identity.expect("identity block present");
    assert_eq!(
        identity.addr,
        format!("127.0.0.1:{}", pillar_net::DEFAULT_RESOURCE_OP_UDP_PORT),
        "a freshly-installed node must export the well-known default resource-op endpoint \
         with no PILLAR_PUBLIC_* supplied"
    );
}

/// CAPSTONE half 2 — the profile-exported, persisted (0600) config drives a
/// LIVE `pillar apply`/`pillar delete` over pillar-UDP with nothing but
/// `$PILLAR_CONFIG`. Proves the turnkey export path end to end. Isolated on a
/// private resource-op port (advertised via `PILLAR_PUBLIC_RESOURCE_OP_ADDR`,
/// the real deploy mechanism) so it never races peer nodes that share the
/// globally-fixed default port on a CI host.
#[test]
fn a_profile_exported_persisted_config_applies_a_retention_policy_over_pillar_udp() {
    let resource_op_port = free_udp_port();
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path(), ResourceOp::Isolated(resource_op_port));
    node.provision();

    // --- The profile-page "Download CLI config" action: authenticate exactly
    // as the web UI does, then hit the SAME `POST /portal/profile/cli-config`
    // the button hits, via the SAME `config_export::fetch_config` code path the
    // browser button and `pillar config export` both invoke.
    let token = node.login(HANDLE, PASSWORD);

    // An unauthenticated / bad-session export must be refused (the button is
    // gated on a real login session).
    let denied = config_export::fetch_config(&node.authority(), "not-a-real-token");
    assert!(
        denied.is_err(),
        "an unauthenticated profile cli-config export must be refused"
    );

    let cfg = config_export::fetch_config(&node.authority(), &token)
        .expect("profile cli-config export over an authenticated session succeeds");

    // The exported config is pre-filled: cell, user, node endpoint, transport
    // order, and real baked-in signer material — everything the CLI needs.
    let identity = cfg.identity.clone().expect("identity block present");
    assert_eq!(
        identity.addr,
        format!("127.0.0.1:{resource_op_port}"),
        "the exported endpoint names this node's advertised resource-op addr"
    );
    assert!(
        !identity.signer_secret_hex.is_empty() && !identity.signer_public_hex.is_empty(),
        "a real scoped signer keypair is baked in, non-interactive"
    );
    assert_eq!(
        cfg.cell.as_deref().map(str::is_empty),
        Some(false),
        "the cell name is pre-filled"
    );
    assert!(
        cfg.user.as_deref().is_some_and(|u| u.contains(HANDLE)),
        "the authenticated user is pre-filled (got {:?})",
        cfg.user
    );
    assert_eq!(
        cfg.transport.as_deref(),
        Some(pillar_client::DEFAULT_TRANSPORT_ORDER.as_slice()),
        "the transport order is pre-filled (pillar-UDP first)"
    );

    // --- Persist it EXACTLY as the CLI does after the download: 0600, at a real
    // on-disk path (`save_0600` is what `pillar config export` calls).
    let out_dir = tempfile::tempdir().expect("out dir");
    let out_path = out_dir.path().join("config.yaml");
    config_export::save_0600(&cfg, &out_path).expect("persist exported config 0600");

    #[cfg(unix)]
    assert_eq!(
        mode_bits(&out_path),
        0o600,
        "the persisted config must be 0600 — it carries the cell seed + signer secret"
    );

    // Reload it exactly as `pillar apply` would (a fresh parse from disk, never
    // the in-memory value) to prove the persisted bytes round-trip.
    let reloaded = pillar_client::ClientConfig::parse(
        &std::fs::read_to_string(&out_path).expect("read persisted config"),
        &out_path,
    )
    .expect("reparse persisted config");
    assert_eq!(
        reloaded.identity.expect("identity persisted").addr,
        format!("127.0.0.1:{resource_op_port}"),
    );

    // --- "nothing else": wire ONLY $PILLAR_CONFIG at the persisted path a real
    // CLI would load from — no address fixup, no `PILLAR_RESOURCE_OP_ADDR`, no
    // signer env escape hatch. The turnkey config as exported+saved is directly
    // usable, and the mutation rides pillar-UDP.
    std::env::set_var("PILLAR_CONFIG", &out_path);
    std::env::remove_var("PILLAR_RESOURCE_OP_ADDR");

    let manifest_text = concat!(
        "apiVersion: pillar.dev/v1\n",
        "kind: RetentionPolicy\n",
        "metadata:\n",
        "  name: ui-cli-config-export-metrics\n",
        "spec:\n",
        "  signalKind: Metric\n",
        "  window: 2592000\n",
    );

    let acks = apply_manifest_text(manifest_text)
        .expect("apply over the profile-exported, persisted turnkey config succeeds");
    assert_eq!(acks.len(), 1);
    assert!(acks[0].ack.starts_with("OK"), "apply ack: {}", acks[0].ack);
    assert_eq!(
        acks[0].tier,
        pillar_client::TransportKind::PillarUdp,
        "the mutation must ride pillar-UDP via the turnkey config, never a REST fallback"
    );

    let (ack, tier) = delete_resource("RetentionPolicy/ui-cli-config-export-metrics")
        .expect("delete over the profile-exported, persisted turnkey config succeeds");
    assert!(ack.starts_with("OK"), "delete ack: {ack}");
    assert_eq!(tier, pillar_client::TransportKind::PillarUdp);

    std::env::remove_var("PILLAR_CONFIG");
}
