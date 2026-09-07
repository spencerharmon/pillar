//! Real-effect acceptance for the `pillar ingress-lb-udp serve` external
//! surface (`pillar-ingress-lb-udp-external-surface`).
//!
//! This is BLACK-BOX and REAL: it execs the actual compiled `pillar` binary
//! (`CARGO_BIN_EXE_pillar`) with an `ingress-lb-udp` manifest, spawns real UDP
//! echo backends on real loopback sockets, sends a REAL client UDP datagram to
//! the bound VIP the binary prints, and asserts a real backend served the reply
//! — never an in-process `UdpDataplane::bind` call, never a modelled forward.
//! It proves the library dataplane is reachable via the wired CLI verb on the
//! published binary.
//!
//! Runs under a plain `cargo test --all` (no acceptance feature) so it is part
//! of the task's `Check: cargo test --all` definition of done.

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// A real UDP echo backend on a real loopback socket. For every datagram it
/// echoes `"<id>:<payload>"` so the client can tell WHICH backend served it; it
/// echoes the dataplane's health probe verbatim so an alive backend stays
/// healthy. Returns its bound address and a stop flag + thread handle.
struct EchoBackend {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

/// The health probe payload the dataplane sends; must match
/// `pillar_net::HEALTH_PROBE` so an alive backend answers it.
const HEALTH_PROBE: &[u8] = b"\x00pillar-udp-health\x00";

impl EchoBackend {
    fn spawn(id: &str) -> EchoBackend {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind echo backend");
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let id = id.to_owned();
        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            while !stop_t.load(Ordering::SeqCst) {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let payload = &buf[..n];
                        let reply: Vec<u8> = if payload == HEALTH_PROBE {
                            payload.to_vec()
                        } else {
                            let mut r = id.clone().into_bytes();
                            r.push(b':');
                            r.extend_from_slice(payload);
                            r
                        };
                        let _ = sock.send_to(&reply, from);
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });
        EchoBackend {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EchoBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A running `pillar ingress-lb-udp serve` child that kills itself on drop.
struct ServeProcess(Child);
impl Drop for ServeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Send `payload` to `vip` from a fresh real client socket and return the
/// serving-backend id (the prefix before the first `:`), or `None` on timeout.
fn round_trip(vip: SocketAddr, payload: &[u8]) -> Option<String> {
    let client = UdpSocket::bind("127.0.0.1:0").ok()?;
    client.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    client.connect(vip).ok()?;
    client.send(payload).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = client.recv(&mut buf).ok()?;
    let reply = &buf[..n];
    let colon = reply.iter().position(|&b| b == b':')?;
    Some(String::from_utf8_lossy(&reply[..colon]).into_owned())
}

/// Boot the real binary with a manifest, wait for its `vip=<ip:port>` line, and
/// drive real datagrams through it: three echo backends, RoundRobin, ephemeral
/// VIP. Assert EVERY backend serves at least one datagram — proving real
/// per-datagram selection + forwarding through the wired external surface.
#[test]
fn cli_ingress_lb_udp_serve_forwards_real_udp_through_wired_dataplane() {
    let b1 = EchoBackend::spawn("b1");
    let b2 = EchoBackend::spawn("b2");
    let b3 = EchoBackend::spawn("b3");

    let manifest = format!(
        "# real-effect ingress-lb-udp manifest\n\
         frontend udp-fe 127.0.0.1\n\
         listen 0\n\
         algorithm round-robin\n\
         affinity none\n\
         health active 200\n\
         backend b1 {}\n\
         backend b2 {}\n\
         backend b3 {}\n",
        b1.addr, b2.addr, b3.addr
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("ingress-lb-udp.manifest");
    std::fs::write(&manifest_path, manifest).expect("write manifest");

    let bin = env!("CARGO_BIN_EXE_pillar");
    let mut child = Command::new(bin)
        .arg("ingress-lb-udp")
        .arg("serve")
        .arg(&manifest_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pillar ingress-lb-udp serve");

    // Read the machine-readable listening line from the child's real stdout to
    // learn the concrete bound VIP port (an ephemeral `:0` listen resolves it).
    let stdout = child.stdout.take().expect("child stdout");
    let mut proc = ServeProcess(child);

    let vip = read_listening_vip(stdout, &mut proc);

    // Drive a stream of real client datagrams; RoundRobin must spread them
    // across all three real backends.
    let mut seen = std::collections::HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.len() < 3 && Instant::now() < deadline {
        for i in 0..9 {
            if let Some(id) = round_trip(vip, format!("ping-{i}").as_bytes()) {
                seen.insert(id);
            }
        }
        if seen.len() < 3 {
            thread::sleep(Duration::from_millis(100));
        }
    }

    assert_eq!(
        seen,
        ["b1", "b2", "b3"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<std::collections::HashSet<_>>(),
        "every real backend must serve at least one datagram forwarded through \
         the wired `pillar ingress-lb-udp serve` external surface; saw: {seen:?}"
    );

    drop((b1, b2, b3));
}

/// Read the `ingress-lb-udp listening vip=<ip:port> backends=<n>` line the real
/// binary prints, returning the parsed VIP. Fails the test (printing captured
/// child stderr) if the line never arrives within the timeout.
fn read_listening_vip(stdout: std::process::ChildStdout, proc: &mut ServeProcess) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("ingress-lb-udp listening ") {
                if let Some(vip_tok) = rest.split_whitespace().find_map(|t| t.strip_prefix("vip=")) {
                    let _ = tx.send(vip_tok.to_owned());
                    return;
                }
            }
        }
    });

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(vip_s) => vip_s.parse().expect("parse printed vip"),
        Err(_) => {
            // Surface the child's stderr to make a boot failure debuggable.
            let mut err = String::new();
            if let Some(mut se) = proc.0.stderr.take() {
                let _ = se.read_to_string(&mut err);
            }
            panic!("pillar ingress-lb-udp serve never printed a `vip=` listening line.\nchild stderr:\n{err}");
        }
    }
}

/// The binary rejects a manifest with no backends (a real argv/exit-code
/// contract of the external surface), never silently binding an empty dataplane.
#[test]
fn cli_ingress_lb_udp_serve_rejects_manifest_without_backends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("bad.manifest");
    std::fs::write(&manifest_path, "frontend f 127.0.0.1\nlisten 0\n").expect("write");

    let bin = env!("CARGO_BIN_EXE_pillar");
    let out = Command::new(bin)
        .arg("ingress-lb-udp")
        .arg("serve")
        .arg(&manifest_path)
        .output()
        .expect("run pillar ingress-lb-udp serve");
    assert!(
        !out.status.success(),
        "serving a backend-less manifest must fail with a non-zero exit"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("backend"),
        "error should name the missing backend directive; got: {stderr}"
    );
}
