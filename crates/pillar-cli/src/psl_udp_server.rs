//! The `psl-message-api` pillar-UDP tier (`psl-message-api`, 2026-09-09 ROI
//! HEAD): a minimal, real one-shot-datagram RPC server for the shared
//! [`pillar_wire::PslQueryRequest`]/[`pillar_wire::PslQueryResponse`]
//! contract, so the CLI's preferred transport
//! ([`pillar_net::pillar_udp_posture::select_preferred_transport`]) can reach
//! this SAME PSL query engine without opening a TCP/QUIC connection first.
//!
//! Scope note: this is an APPLICATION-LEVEL request/response RPC over a bare
//! UDP socket — it is deliberately narrower than the full libp2p pillar-UDP
//! swarm transport ([`pillar_net::PillarUdpTransport`]), which handles
//! node<->node clustered multipath streaming. A `psl-message-api` query is a
//! single small request and a single small response, so one datagram each
//! way is sufficient; a request/response that would not fit a single
//! datagram is rejected with a [`pillar_wire::PslQueryResponse::Error`]
//! rather than silently truncated.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use crate::web_serve::WebAuthContext;

/// The largest UDP datagram this tier accepts. Well under the practical
/// path-MTU-safe ceiling for a single unfragmented UDP datagram over
/// Ethernet-class links, and generous for a PSL query request (typically a
/// few hundred bytes of query text).
const MAX_DATAGRAM: usize = 60_000;

/// Bind the pillar-UDP `psl-message-api` tier on `bind` and serve requests
/// against `ctx` until the process exits. Blocking — run on a dedicated
/// thread. Returns the bound address so the caller can log/advertise it.
pub fn spawn(bind: SocketAddr, ctx: Arc<Mutex<WebAuthContext>>) -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind(bind)?;
    let local_addr = socket.local_addr()?;
    std::thread::spawn(move || serve(socket, ctx));
    Ok(local_addr)
}

fn serve(socket: UdpSocket, ctx: Arc<Mutex<WebAuthContext>>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let resp = handle_datagram(&buf[..n], &ctx);
        if let Ok(bytes) = pillar_wire::encode_response(&resp) {
            if bytes.len() > MAX_DATAGRAM {
                let too_big = pillar_wire::PslQueryResponse::Error(
                    "RESULT-TOO-LARGE-FOR-PILLAR-UDP-TIER".to_owned(),
                );
                if let Ok(bytes) = pillar_wire::encode_response(&too_big) {
                    let _ = socket.send_to(&bytes, peer);
                }
                continue;
            }
            let _ = socket.send_to(&bytes, peer);
        }
    }
}

fn handle_datagram(
    bytes: &[u8],
    ctx: &Arc<Mutex<WebAuthContext>>,
) -> pillar_wire::PslQueryResponse {
    let req = match pillar_wire::decode_request(bytes) {
        Ok(req) => req,
        Err(e) => return pillar_wire::PslQueryResponse::Error(format!("BAD-CBOR {e}")),
    };
    let guard = ctx.lock().expect("shared web auth context lock");
    if guard.login_session_for(&req.token).is_none() {
        return pillar_wire::PslQueryResponse::Unauthorized;
    }
    match guard.live_obs_psl_message(&req.query_text) {
        Some(resp) => resp,
        None => pillar_wire::PslQueryResponse::Error("NO-LIVE-SUBSTRATE".to_owned()),
    }
}
