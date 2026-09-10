//! Acceptance test — `psl-message-api` (2026-09-09 ROI HEAD).
//!
//! Proves the ONE shared `PillarMessage` PSL/obs query contract
//! (`pillar_wire::PslQueryRequest`/`PslQueryResponse`) actually rides all
//! three transport tiers a live `pillar node run` process serves it on —
//! pillar-UDP, QUIC, and HTTPS — with IDENTICAL results, and that the CLI's
//! fallback dialer (`pillar_cli::psl_client::query_with_fallback`) really
//! falls to the next tier when the preferred one is unreachable (never a
//! silent failure). It also proves the Yew UI's path — a direct HTTPS
//! request to `/portal/obs/query/message` — sees the SAME contract and the
//! SAME data, so the CLI and the UI can never drift on what a query means.
//!
//! Black-box: execs the real compiled `pillar` binary as a subprocess with
//! its web surface AND the two extra `psl-message-api` tiers bound via
//! `PILLAR_PSL_UDP_BIND`/`PILLAR_PSL_QUIC_BIND`, logs in over real HTTP to
//! get an admitted session token exactly like an operator would, waits for
//! the node's self-metrics producer to ingest at least one real signal, then
//! drives every tier for real.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test psl_message_api --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::psl_client::{query_with_fallback, Tier, TierAddr};
use pillar_wire::PslQueryResponse;

const PASSWORD: &str = "correct horse battery staple 2026 psl";
const HANDLE: &str = "spencer";

/// One HTTP response the black-box client parsed off the wire.
struct HttpResponse {
    status: u16,
    session_token: Option<String>,
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

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        session_token,
        body: resp_body,
    })
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

/// Claim a free UDP port (used for both the pillar-UDP and QUIC binds — each
/// needs its own free port; a `UdpSocket` bind/drop is enough to reserve one
/// since both tiers open their own real socket at boot).
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .expect("claim free udp port")
}

/// A booted `pillar node run` subprocess with its HTTPS, pillar-UDP, and
/// QUIC `psl-message-api` tiers all bound; killed on drop.
struct Node {
    child: Child,
    http_port: u16,
    udp_port: u16,
    quic_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let udp_port = free_udp_port();
        let quic_port = free_udp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("PILLAR_PSL_UDP_BIND", format!("127.0.0.1:{udp_port}"))
            .env("PILLAR_PSL_QUIC_BIND", format!("127.0.0.1:{quic_port}"))
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node {
            child,
            http_port,
            udp_port,
            quic_port,
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

    fn get(&self, path: &str) -> HttpResponse {
        http(self.http_port, "GET", path, "").expect("GET succeeds")
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        http(self.http_port, "POST", path, body).expect("POST succeeds")
    }

    fn login(&self, handle: &str, password: &str) -> HttpResponse {
        let nonce = self.get("/nonce");
        assert_eq!(nonce.status, 200, "nonce: {}", nonce.body);
        let id: u64 = nonce
            .body
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("nonce id");
        self.post("/login", &format!("{handle}\n{password}\n{id}"))
    }

    fn udp_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.udp_port).parse().unwrap()
    }
    fn quic_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.quic_port).parse().unwrap()
    }
    fn https_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.http_port).parse().unwrap()
    }

    /// Every tier, in the CLI's real preference order.
    fn all_tiers(&self) -> Vec<TierAddr> {
        vec![
            TierAddr {
                tier: Tier::PillarUdp,
                addr: self.udp_addr(),
            },
            TierAddr {
                tier: Tier::Quic,
                addr: self.quic_addr(),
            },
            TierAddr {
                tier: Tier::Https,
                addr: self.https_addr(),
            },
        ]
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Query rows the returned response actually holds (empty on anything but
/// `Ok`) — used to compare tiers for identical results.
fn rows_of(resp: &PslQueryResponse) -> Vec<pillar_wire::PslSignalRow> {
    match resp {
        PslQueryResponse::Ok(result) => result.rows.clone(),
        _ => Vec::new(),
    }
}

/// Poll `f` until it returns `Some`, or panic past the deadline — used to
/// wait for the node's self-metrics producer to ingest at least one real
/// `metric` signal (it ticks every 15s; give it ample headroom).
fn wait_for<T>(within: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(v) = f() {
            return v;
        }
        if Instant::now() >= deadline {
            panic!("condition did not become true within {within:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

const QUERY: &str = "select: metrics range: now-5m";

#[test]
fn cli_over_every_tier_and_the_ui_over_https_see_identical_psl_query_results() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{HANDLE}\n{PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let login = node.login(HANDLE, PASSWORD);
    assert_eq!(login.status, 200, "login: {}", login.body);
    let token = login.session_token.expect("session token");

    // Wait for the node's self-metrics producer to ingest at least one real
    // signal, using the HTTPS tier directly (the "UI path") as the probe —
    // real live data, never fabricated.
    let ui_result = wait_for(Duration::from_secs(25), || {
        let outcome = query_with_fallback(
            &[TierAddr {
                tier: Tier::Https,
                addr: node.https_addr(),
            }],
            &token,
            QUERY,
        )
        .expect("https tier reachable");
        assert_eq!(outcome.tier, Tier::Https);
        let rows = rows_of(&outcome.response);
        if rows.is_empty() {
            None
        } else {
            Some(rows)
        }
    });
    assert!(
        !ui_result.is_empty(),
        "the UI's HTTPS path must see real self-metric signals"
    );

    // The CLI dialing its FULL preferred tier list must reach the pillar-UDP
    // tier FIRST and see the IDENTICAL rows the UI saw over HTTPS.
    let cli_outcome = query_with_fallback(&node.all_tiers(), &token, QUERY)
        .expect("at least one tier reachable");
    assert_eq!(
        cli_outcome.tier,
        Tier::PillarUdp,
        "with every tier up, the CLI must prefer pillar-UDP"
    );
    let cli_rows = rows_of(&cli_outcome.response);
    assert_eq!(
        cli_rows, ui_result,
        "pillar-UDP tier must return the identical result the HTTPS tier saw"
    );

    // Dialing the QUIC tier alone must also see the identical rows.
    let quic_outcome = query_with_fallback(
        &[TierAddr {
            tier: Tier::Quic,
            addr: node.quic_addr(),
        }],
        &token,
        QUERY,
    )
    .expect("quic tier reachable");
    assert_eq!(quic_outcome.tier, Tier::Quic);
    assert_eq!(
        rows_of(&quic_outcome.response),
        ui_result,
        "QUIC tier must return the identical result the HTTPS tier saw"
    );

    // A bad token must be refused identically over EVERY tier — a shared
    // contract, not per-tier drift.
    for t in node.all_tiers() {
        let outcome = query_with_fallback(&[t.clone()], "not-a-real-token", QUERY)
            .unwrap_or_else(|e| panic!("{:?} tier unreachable: {e}", t.tier));
        assert_eq!(
            outcome.response,
            PslQueryResponse::Unauthorized,
            "{:?} tier must refuse an unadmitted token",
            t.tier
        );
    }
}

#[test]
fn cli_falls_back_past_a_down_pillar_udp_tier_to_quic_then_https() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    node.post("/bootstrap/create-cell", "cell-genesis");
    node.post(
        "/bootstrap/create-user",
        &format!("{HANDLE}\n{PASSWORD}"),
    );
    let login = node.login(HANDLE, PASSWORD);
    let token = login.session_token.expect("session token");

    wait_for(Duration::from_secs(25), || {
        let outcome = query_with_fallback(
            &[TierAddr {
                tier: Tier::Https,
                addr: node.https_addr(),
            }],
            &token,
            QUERY,
        )
        .ok()?;
        if rows_of(&outcome.response).is_empty() {
            None
        } else {
            Some(())
        }
    });

    // A pillar-UDP tier address that names a port NOTHING is bound to —
    // "the tier is down" — must be skipped in favor of the next tier.
    let down_udp_port = free_udp_port();
    let tiers_udp_down = vec![
        TierAddr {
            tier: Tier::PillarUdp,
            addr: format!("127.0.0.1:{down_udp_port}").parse().unwrap(),
        },
        TierAddr {
            tier: Tier::Quic,
            addr: node.quic_addr(),
        },
        TierAddr {
            tier: Tier::Https,
            addr: node.https_addr(),
        },
    ];
    let outcome =
        query_with_fallback(&tiers_udp_down, &token, QUERY).expect("falls back to quic");
    assert_eq!(
        outcome.tier,
        Tier::Quic,
        "with pillar-UDP down, the CLI must fall back to QUIC"
    );
    assert!(!rows_of(&outcome.response).is_empty());

    // Both pillar-UDP AND QUIC down: must fall all the way to HTTPS.
    let down_quic_port = free_udp_port();
    let tiers_both_down = vec![
        TierAddr {
            tier: Tier::PillarUdp,
            addr: format!("127.0.0.1:{down_udp_port}").parse().unwrap(),
        },
        TierAddr {
            tier: Tier::Quic,
            addr: format!("127.0.0.1:{down_quic_port}").parse().unwrap(),
        },
        TierAddr {
            tier: Tier::Https,
            addr: node.https_addr(),
        },
    ];
    let outcome =
        query_with_fallback(&tiers_both_down, &token, QUERY).expect("falls back to https");
    assert_eq!(
        outcome.tier,
        Tier::Https,
        "with pillar-UDP AND QUIC down, the CLI must fall back to HTTPS"
    );
    assert!(!rows_of(&outcome.response).is_empty());

    // Every tier down: the fallback dialer must fail rather than hang/panic.
    let down_http_port = free_tcp_port();
    let tiers_all_down = vec![
        TierAddr {
            tier: Tier::PillarUdp,
            addr: format!("127.0.0.1:{down_udp_port}").parse().unwrap(),
        },
        TierAddr {
            tier: Tier::Quic,
            addr: format!("127.0.0.1:{down_quic_port}").parse().unwrap(),
        },
        TierAddr {
            tier: Tier::Https,
            addr: format!("127.0.0.1:{down_http_port}").parse().unwrap(),
        },
    ];
    assert!(query_with_fallback(&tiers_all_down, &token, QUERY).is_err());
}
