//! Trivial UDP echo binary — the acceptance test's "image" for
//! `workload-oci-runtime-real`. Not a placeholder: a real standalone
//! executable, spawned as a real child process and bound to a real
//! listening UDP socket by the OCI runtime layer under test
//! (`pillar_controller::runtime::SupervisedWorkload`).
//!
//! Usage: `udp_echo <port> [id]`.
//!
//! - With ONLY a `<port>`, it echoes every datagram back VERBATIM — the
//!   contract `oci_runtime_real.rs` and `deployment_kind.rs` depend on.
//! - With an optional `<id>` second argument, it prefixes every NON-health
//!   reply with `"<id>:"` so a load-balancer client can tell WHICH backend
//!   (i.e. which pillar node's replica) served each datagram — the exact
//!   `"<backend-id>:<payload>"` framing `udp_dataplane.rs` uses. This is what
//!   the end-to-end `real_workload_acceptance.rs` capstone relies on to prove
//!   the dataplane spread client traffic across all three real nodes. The
//!   health probe (`pillar_net::HEALTH_PROBE`, the fixed bytes `b"PILLARHC"`)
//!   is ALWAYS echoed verbatim so the dataplane's active probe still marks an
//!   alive backend healthy regardless of id framing.
use std::net::UdpSocket;

/// Mirror of `pillar_net::HEALTH_PROBE` — kept as a local literal so this
/// trivial "image" binary needs no dependency on the networking crate. Any
/// drift here would only cause a live backend to be probed as unhealthy, which
/// the acceptance harness would catch immediately.
const HEALTH_PROBE: &[u8] = b"PILLARHC";

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .expect("udp_echo requires a port argument")
        .parse()
        .expect("port argument must be a valid u16");
    let id: Option<String> = std::env::args().nth(2);

    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind udp echo socket");

    let mut buf = [0u8; 1024];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let payload = &buf[..n];
        let reply: Vec<u8> = match &id {
            // Identifying framing for the load-balancer capstone: prefix
            // application datagrams with `<id>:`, but always echo the health
            // probe verbatim so the dataplane's liveness check still passes.
            Some(id) if payload != HEALTH_PROBE => {
                let mut r = id.clone().into_bytes();
                r.push(b':');
                r.extend_from_slice(payload);
                r
            }
            // No id, or a health probe: verbatim echo (the original contract).
            _ => payload.to_vec(),
        };
        let _ = socket.send_to(&reply, from);
    }
}
