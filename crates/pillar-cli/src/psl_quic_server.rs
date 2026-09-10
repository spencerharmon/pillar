//! The `psl-message-api` QUIC tier (`psl-message-api`, 2026-09-09 ROI HEAD):
//! a real QUIC (RFC 9000, via `quinn`) request/response server for the same
//! shared [`pillar_wire::PslQueryRequest`]/[`pillar_wire::PslQueryResponse`]
//! contract the pillar-UDP and HTTPS tiers serve — the FALLBACK tier the CLI
//! reaches for when no pillar-UDP-capable peer is available
//! ([`pillar_net::pillar_udp_posture::select_preferred_transport`]'s
//! `NoPillarUdpPeerAvailable`/`LegacyInteropIngress` reasons), before it
//! falls further to plain HTTPS.
//!
//! This is a direct `quinn`/`rustls` QUIC endpoint independent of the libp2p
//! `quic` transport used for node<->node swarm traffic — a deliberately
//! narrow, single-purpose RPC channel: one client-opened bidirectional
//! stream per query, request bytes written + `finish()`, response bytes read
//! to EOF. It uses a freshly generated self-signed certificate (this is an
//! RPC-of-convenience tier behind pillar-UDP/HTTPS, not a public TLS-PKI
//! surface); a client that cannot/will not skip verification of this
//! self-signed cert simply treats the tier as unreachable and falls back,
//! exactly like an unreachable port.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::web_serve::WebAuthContext;

/// The largest request/response this tier accepts on one stream — generous
/// for a PSL query/result, and small enough to bound a misbehaving peer.
const MAX_MESSAGE: usize = 1 << 20;

/// Build a minimal self-signed QUIC server endpoint bound at `bind`, and
/// spawn a background task serving `psl-message-api` requests against `ctx`
/// until the process exits. Returns the bound local address.
pub fn spawn(
    bind: SocketAddr,
    ctx: Arc<Mutex<WebAuthContext>>,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["pillar-psl-quic".to_owned()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("psl-quic key: {e}").into()
            },
        )?;

    let server_config = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der)?;
    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    let local_addr = endpoint.local_addr()?;

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            let ctx = Arc::clone(&ctx);
                            tokio::spawn(async move {
                                let Ok(bytes) = recv.read_to_end(MAX_MESSAGE).await else {
                                    return;
                                };
                                let resp = handle_request(&bytes, &ctx);
                                if let Ok(out) = pillar_wire::encode_response(&resp) {
                                    let _ = send.write_all(&out).await;
                                    let _ = send.finish();
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    Ok(local_addr)
}

fn handle_request(bytes: &[u8], ctx: &Arc<Mutex<WebAuthContext>>) -> pillar_wire::PslQueryResponse {
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
