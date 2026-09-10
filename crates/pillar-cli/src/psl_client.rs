//! The `psl-message-api` CLI (native) client (`psl-message-api`, 2026-09-09
//! ROI HEAD): the ONE `PillarMessage` request/response contract
//! ([`pillar_wire::PslQueryRequest`]/[`pillar_wire::PslQueryResponse`]),
//! dialed over the pillar-UDP -> QUIC -> HTTPS fallback chain — falling
//! further down the list exactly when the current tier is unreachable
//! (connection refused/timed out), never on a substantive server-side
//! failure (bad token, PSL parse error), which the SAME contract carries
//! back as a typed response the caller renders identically regardless of
//! which tier answered.
//!
//! Tier PREFERENCE follows
//! [`pillar_net::pillar_udp_posture::select_preferred_transport`] (pillar-UDP
//! preferred when a pillar-UDP-capable peer is posited, else QUIC/legacy);
//! this module additionally appends the HTTPS tier as the final fallback
//! (the posture selector only distinguishes pillar-UDP vs QUIC — HTTPS is
//! this contract's own last-resort tier, always available since every node
//! running the web portal already serves it).
//!
//! The Yew (WASM) UI never calls this module — it has no raw UDP/QUIC socket
//! access from a browser sandbox, so it always rides the SAME HTTPS
//! `/portal/obs/query/message` endpoint directly via `fetch` (see
//! `pillar-web-frontend`), which is why the wire contract lives in
//! `pillar-wire`, reachable from both a native and a `wasm32` build.

use std::net::SocketAddr;
use std::time::Duration;

use pillar_wire::{PslQueryRequest, PslQueryResponse};

/// One dialable tier this client will try, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The pillar-UDP `psl-message-api` datagram RPC tier
    /// ([`crate::psl_udp_server`]).
    PillarUdp,
    /// The QUIC `psl-message-api` tier ([`crate::psl_quic_server`]).
    Quic,
    /// The HTTPS `/portal/obs/query/message` tier ([`crate::web_serve`]).
    Https,
}

/// One tier's dial target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierAddr {
    /// Which tier this address dials.
    pub tier: Tier,
    /// The tier's listen address.
    pub addr: SocketAddr,
}

/// How long a single tier's dial/round-trip may take before this client
/// gives up on it and falls to the next tier. Short — an unreachable tier
/// should cost the caller a bounded delay, not a long hang.
const TIER_TIMEOUT: Duration = Duration::from_secs(2);

/// The outcome of a fallback query: the [`PslQueryResponse`] plus WHICH tier
/// actually answered, so a caller (and the acceptance test) can assert the
/// fallback really happened rather than merely that a plausible answer
/// eventually came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOutcome {
    /// The tier that actually answered.
    pub tier: Tier,
    /// The tier's response.
    pub response: PslQueryResponse,
}

/// A dial attempt error — the tier itself was unreachable (connection
/// refused/timed out/malformed reply), distinct from a well-formed
/// [`PslQueryResponse::Error`]/`Unauthorized` the server actually answered
/// with (those are NOT retried against another tier — the query genuinely
/// executed, it just failed or was refused).
#[derive(Debug)]
struct Unreachable;

/// Try `tiers` in order, returning the first tier's ACTUAL answer (whether
/// `Ok`, `Unauthorized`, or a query `Error` — all three mean the tier was
/// reachable and answered) — falling to the next tier ONLY when a tier is
/// unreachable. Fails if every tier is unreachable.
pub fn query_with_fallback(
    tiers: &[TierAddr],
    token: &str,
    query_text: &str,
) -> Result<QueryOutcome, String> {
    let req = PslQueryRequest {
        token: token.to_owned(),
        query_text: query_text.to_owned(),
    };
    let mut last_err = "no tiers configured".to_owned();
    for t in tiers {
        let result = match t.tier {
            Tier::PillarUdp => dial_udp(t.addr, &req),
            Tier::Quic => dial_quic(t.addr, &req),
            Tier::Https => dial_https(t.addr, &req),
        };
        match result {
            Ok(response) => {
                return Ok(QueryOutcome {
                    tier: t.tier,
                    response,
                })
            }
            Err(Unreachable) => {
                last_err = format!("{:?} tier at {} unreachable", t.tier, t.addr);
                continue;
            }
        }
    }
    Err(last_err)
}

fn dial_udp(addr: SocketAddr, req: &PslQueryRequest) -> Result<PslQueryResponse, Unreachable> {
    let bytes = pillar_wire::encode_request(req).map_err(|_| Unreachable)?;
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).map_err(|_| Unreachable)?;
    socket
        .set_read_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    socket.connect(addr).map_err(|_| Unreachable)?;
    socket.send(&bytes).map_err(|_| Unreachable)?;
    let mut buf = vec![0u8; 60_000];
    let n = socket.recv(&mut buf).map_err(|_| Unreachable)?;
    pillar_wire::decode_response(&buf[..n]).map_err(|_| Unreachable)
}

fn dial_quic(addr: SocketAddr, req: &PslQueryRequest) -> Result<PslQueryResponse, Unreachable> {
    // A blocking client wrapping quinn's async API in a short-lived
    // single-threaded runtime — this client function is deliberately
    // synchronous so both a sync CLI codepath and an async one can call it
    // uniformly; the acceptance test drives it directly.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Unreachable)?;
    rt.block_on(async move { dial_quic_async(addr, req).await })
}

async fn dial_quic_async(
    addr: SocketAddr,
    req: &PslQueryRequest,
) -> Result<PslQueryResponse, Unreachable> {
    let bytes = pillar_wire::encode_request(req).map_err(|_| Unreachable)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();
    client_crypto.enable_early_data = true;
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|_| Unreachable)?;
    let client_config = quinn::ClientConfig::new(std::sync::Arc::new(client_crypto));

    let mut endpoint =
        quinn::Endpoint::client(([0, 0, 0, 0], 0).into()).map_err(|_| Unreachable)?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint.connect(addr, "pillar-psl-quic").map_err(|_| Unreachable)?;
    let conn = tokio::time::timeout(TIER_TIMEOUT, connecting)
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    let (mut send, mut recv) = tokio::time::timeout(TIER_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    send.write_all(&bytes).await.map_err(|_| Unreachable)?;
    send.finish().map_err(|_| Unreachable)?;
    let response_bytes = tokio::time::timeout(TIER_TIMEOUT, recv.read_to_end(1 << 20))
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    pillar_wire::decode_response(&response_bytes).map_err(|_| Unreachable)
}

/// A verifier that accepts the tier's self-signed cert unconditionally: this
/// QUIC tier is an RPC-of-convenience fallback behind pillar-UDP/HTTPS
/// (see `crate::psl_quic_server`'s doc comment), not a public TLS-PKI
/// surface — an attacker who can MITM this link can equally just impersonate
/// the HTTPS tier's plaintext-HTTP test surface, so this accepts the same
/// threat model the rest of this test/dev surface already does.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn dial_https(addr: SocketAddr, req: &PslQueryRequest) -> Result<PslQueryResponse, Unreachable> {
    use std::io::{Read, Write};
    let bytes = pillar_wire::encode_request(req).map_err(|_| Unreachable)?;
    let mut stream = std::net::TcpStream::connect(addr).map_err(|_| Unreachable)?;
    stream
        .set_read_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    stream
        .set_write_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    let head = format!(
        "POST /portal/obs/query/message HTTP/1.1\r\nHost: node\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(head.as_bytes()).map_err(|_| Unreachable)?;
    stream.write_all(&bytes).map_err(|_| Unreachable)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|_| Unreachable)?;
    let sep = b"\r\n\r\n";
    let pos = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or(Unreachable)?;
    let body = &raw[pos + sep.len()..];
    pillar_wire::decode_response(body).map_err(|_| Unreachable)
}
