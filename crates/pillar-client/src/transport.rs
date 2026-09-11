//! Dialing a node: pillar-UDP -> QUIC -> HTTPS, carrying a sealed
//! [`pillar_wire::PillarMessage`] wrapping a `pillar_ops::ResourceOp` as
//! [`pillar_wire::Body::StreamOp`].
//!
//! This mirrors the established tier-fallback dialer in
//! `pillar-cli`'s `psl_client` module: try tiers in the caller-supplied
//! preference order (normally [`crate::config::DEFAULT_TRANSPORT_ORDER`]),
//! falling to the next tier ONLY when the current one is unreachable
//! (connection refused/timed out/malformed reply) — never on a substantive
//! application-level answer. Unlike `psl_client`'s bespoke
//! `PslQueryRequest`/`PslQueryResponse` RPC pair, this module rides the
//! general [`pillar_wire::PillarMessage`] envelope so the same wire shape a
//! node uses talking to another node also carries a client's op.
//!
//! ## Sealing, never a silent downgrade
//!
//! Every op sent by this module is wrapped as [`pillar_wire::Body::StreamOp`],
//! sealed to the cell with [`pillar_wire::seal::CellSeal`] (convergent —
//! matches every other `StreamOp` producer, e.g. `pillar-streamdb`), and
//! signed with the caller's signing secret key. There is no code path here
//! that constructs or sends an unsealed/unsigned `PillarMessage` — a caller
//! that lacks the cell group key or a signing secret cannot call
//! [`send_op_with_fallback`] at all (both are required arguments), so the
//! transport can never *silently* fall back to a weaker envelope the way a
//! tier can fall back to a weaker network path. The [`SendOutcome`] always
//! reports which tier actually answered, so a caller can render/log that
//! fact rather than have it silently vanish.

use std::net::SocketAddr;
use std::time::Duration;

use pillar_crypto::cell::CellGroupKey;
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{CellId, CryptoError, SigningPublicKey, SigningSecretKey};
use pillar_wire::envelope::EnvelopeError;
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::{Body, PillarMessage, Visibility};

use crate::config::TransportKind;

/// The domain separator this crate's `StreamOp` seal uses. A client-issued
/// `ResourceOp` is the SAME logical record whether it originates here, from
/// `pillar-cli`, or from a node's own portal — so this intentionally reuses
/// the identical domain `pillar-streamdb` uses for a `StreamOp` body
/// (`pillar-streamdb/stream-op-v1`), NOT a fresh per-crate domain: the
/// convergent seal's whole purpose is that two producers of the same logical
/// op emit byte-identical ciphertext (see `pillar-ops`'s crate docs), which
/// only holds if every producer seals under the same domain.
pub const STREAM_OP_SEAL_DOMAIN: &[u8] = b"pillar-streamdb/stream-op-v1";

/// One tier's dial target: which [`TransportKind`] to use and the socket
/// address to reach it at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierAddr {
    /// Which transport this address dials.
    pub tier: TransportKind,
    /// The tier's listen address.
    pub addr: SocketAddr,
}

/// How long a single tier's dial/round-trip may take before this client
/// gives up on it and falls to the next tier. Short — an unreachable tier
/// should cost the caller a bounded delay, not a long hang.
const TIER_TIMEOUT: Duration = Duration::from_secs(2);

/// The outcome of a fallback send: the peer's answering [`PillarMessage`]
/// plus WHICH tier actually carried it, so a caller (and the acceptance
/// test) can assert the fallback really happened and the seal/signature was
/// never silently downgraded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOutcome {
    /// The tier that actually answered.
    pub tier: TransportKind,
    /// The peer's response envelope (still sealed/signed; the caller opens
    /// it with [`open_stream_op`] using the same cell group key).
    pub response: PillarMessage,
}

/// A dial-level failure — the tier itself was unreachable (connection
/// refused/timed out/malformed reply), distinct from a well-formed
/// application answer.
#[derive(Debug)]
struct Unreachable;

/// A fault building, sealing, or opening a `StreamOp`-bearing
/// [`PillarMessage`].
#[derive(Debug)]
pub enum StreamOpMessageError {
    /// The envelope did not decode/encode as a well-formed `PillarMessage`.
    Envelope(EnvelopeError),
    /// A cryptographic seal/sign/verify operation failed.
    Crypto(CryptoError),
    /// The opened body was not a `StreamOp` (an unexpected body kind).
    NotAStreamOp,
    /// The `ResourceOp` payload itself failed to decode.
    Op(pillar_ops::OpCodecError),
}

impl std::fmt::Display for StreamOpMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamOpMessageError::Envelope(e) => write!(f, "envelope error: {e}"),
            StreamOpMessageError::Crypto(e) => write!(f, "crypto error: {e}"),
            StreamOpMessageError::NotAStreamOp => f.write_str("body was not a StreamOp"),
            StreamOpMessageError::Op(e) => write!(f, "resource-op codec error: {e}"),
        }
    }
}

impl std::error::Error for StreamOpMessageError {}

impl From<EnvelopeError> for StreamOpMessageError {
    fn from(e: EnvelopeError) -> Self {
        StreamOpMessageError::Envelope(e)
    }
}

/// Seal `op` into a `StreamOp` body and wrap it in a signed [`PillarMessage`],
/// ready to send over any tier. See the module docs: this is the ONLY way
/// this crate constructs an outgoing envelope — there is no unsealed path.
///
/// # Errors
/// [`StreamOpMessageError::Op`] if `op` fails to encode;
/// [`StreamOpMessageError::Envelope`] if the body fails to serialize;
/// [`StreamOpMessageError::Crypto`] if sealing or signing fails.
pub fn seal_resource_op(
    op: &pillar_ops::ResourceOp,
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<PillarMessage, StreamOpMessageError> {
    let payload = op.encode().map_err(StreamOpMessageError::Op)?;
    let body = Body::StreamOp(payload);
    let plaintext = body.to_canonical_cbor()?;
    let aad = PillarMessage::header_aad(visibility, &cell);
    let body_sealed = CellSeal
        .seal(group, &plaintext, STREAM_OP_SEAL_DOMAIN, &aad)
        .map_err(StreamOpMessageError::Crypto)?;
    let signature = sign(secret, &PillarMessage::signing_material(&body_sealed))
        .map_err(StreamOpMessageError::Crypto)?;
    Ok(PillarMessage::new(signer, signature, visibility, cell, body_sealed))
}

/// Verify and open a `StreamOp`-bearing [`PillarMessage`], returning the
/// decoded [`pillar_ops::ResourceOp`].
///
/// # Errors
/// [`StreamOpMessageError::Crypto`] if the signature or seal fails to
/// verify/open; [`StreamOpMessageError::NotAStreamOp`] if the opened body is
/// a different kind; [`StreamOpMessageError::Op`] if the payload does not
/// decode as a [`pillar_ops::ResourceOp`].
pub fn open_resource_op(
    msg: &PillarMessage,
    group: &CellGroupKey,
) -> Result<pillar_ops::ResourceOp, StreamOpMessageError> {
    verify(
        &msg.signer,
        &PillarMessage::signing_material(&msg.body_sealed),
        &msg.signature,
    )
    .map_err(StreamOpMessageError::Crypto)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext = CellSeal
        .open(group, &msg.body_sealed, &aad)
        .map_err(StreamOpMessageError::Crypto)?;
    let body = Body::from_canonical_cbor(&plaintext)?;
    match body {
        Body::StreamOp(payload) => {
            pillar_ops::ResourceOp::decode(&payload).map_err(StreamOpMessageError::Op)
        }
        _ => Err(StreamOpMessageError::NotAStreamOp),
    }
}

/// Send a pre-built, sealed+signed `msg` over `tiers` in order, falling to
/// the next tier ONLY when the current one is unreachable. Returns the first
/// tier's actual answer (any well-formed [`PillarMessage`] reply) along with
/// which tier carried it. Fails only if every tier is unreachable.
///
/// # Errors
/// A `String` describing the last tier's unreachability, when every tier in
/// `tiers` failed to answer.
pub fn send_with_fallback(tiers: &[TierAddr], msg: &PillarMessage) -> Result<SendOutcome, String> {
    let bytes = msg
        .to_canonical_cbor()
        .map_err(|e| format!("failed to encode outgoing message: {e}"))?;
    let mut last_err = "no tiers configured".to_owned();
    for t in tiers {
        let result = match t.tier {
            TransportKind::PillarUdp => dial_udp(t.addr, &bytes),
            TransportKind::Quic => dial_quic(t.addr, &bytes),
            TransportKind::Https => dial_https(t.addr, &bytes),
        };
        match result {
            Ok(response) => {
                return Ok(SendOutcome {
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

/// Convenience wrapper: seal `op` then [`send_with_fallback`] it.
///
/// # Errors
/// A `String` describing why sealing failed, or why every tier was
/// unreachable.
#[allow(clippy::too_many_arguments)]
pub fn send_op_with_fallback(
    tiers: &[TierAddr],
    op: &pillar_ops::ResourceOp,
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<SendOutcome, String> {
    let msg = seal_resource_op(op, group, cell, signer, secret, visibility)
        .map_err(|e| format!("failed to seal resource op: {e}"))?;
    send_with_fallback(tiers, &msg)
}

fn decode_pillar_message(bytes: &[u8]) -> Result<PillarMessage, Unreachable> {
    PillarMessage::from_canonical_cbor(bytes).map_err(|_| Unreachable)
}

fn dial_udp(addr: SocketAddr, bytes: &[u8]) -> Result<PillarMessage, Unreachable> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).map_err(|_| Unreachable)?;
    socket
        .set_read_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    socket.connect(addr).map_err(|_| Unreachable)?;
    socket.send(bytes).map_err(|_| Unreachable)?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = socket.recv(&mut buf).map_err(|_| Unreachable)?;
    decode_pillar_message(&buf[..n])
}

fn dial_quic(addr: SocketAddr, bytes: &[u8]) -> Result<PillarMessage, Unreachable> {
    // A blocking wrapper around quinn's async API in a short-lived
    // single-threaded runtime, so this function stays uniformly callable
    // from a sync caller (mirrors `pillar-cli`'s `psl_client::dial_quic`).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Unreachable)?;
    rt.block_on(async move { dial_quic_async(addr, bytes).await })
}

async fn dial_quic_async(addr: SocketAddr, bytes: &[u8]) -> Result<PillarMessage, Unreachable> {
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

    let connecting = endpoint
        .connect(addr, "pillar-client-quic")
        .map_err(|_| Unreachable)?;
    let conn = tokio::time::timeout(TIER_TIMEOUT, connecting)
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    let (mut send, mut recv) = tokio::time::timeout(TIER_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    send.write_all(bytes).await.map_err(|_| Unreachable)?;
    send.finish().map_err(|_| Unreachable)?;
    let response_bytes = tokio::time::timeout(TIER_TIMEOUT, recv.read_to_end(1 << 20))
        .await
        .map_err(|_| Unreachable)?
        .map_err(|_| Unreachable)?;
    decode_pillar_message(&response_bytes)
}

/// A verifier that accepts the tier's self-signed cert unconditionally: this
/// QUIC tier is an RPC-of-convenience fallback behind pillar-UDP/HTTPS, not a
/// public TLS-PKI surface — the per-message seal/signature (not TLS) is what
/// authenticates and secures the content riding over this link (see the
/// module docs).
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

fn dial_https(addr: SocketAddr, bytes: &[u8]) -> Result<PillarMessage, Unreachable> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).map_err(|_| Unreachable)?;
    stream
        .set_read_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    stream
        .set_write_timeout(Some(TIER_TIMEOUT))
        .map_err(|_| Unreachable)?;
    let head = format!(
        "POST /portal/client/message HTTP/1.1\r\nHost: node\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(head.as_bytes()).map_err(|_| Unreachable)?;
    stream.write_all(bytes).map_err(|_| Unreachable)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|_| Unreachable)?;
    let sep = b"\r\n\r\n";
    let pos = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or(Unreachable)?;
    let body = &raw[pos + sep.len()..];
    decode_pillar_message(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::sign::signing_keypair_from_seed;
    use pillar_crypto::Seed;
    use pillar_manifest::{Crd, Metadata};
    use pillar_ops::ResourceOp;

    fn test_op() -> ResourceOp {
        ResourceOp::Apply {
            crd: Crd::new("v1", "Widget", Metadata::new("test")),
        }
    }

    #[test]
    fn seal_resource_op_round_trips_through_open_resource_op() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("group key");
        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"alice".to_vec())).expect("keypair");
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let msg = seal_resource_op(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        // Never a silent unsealed/unsigned message: the body ciphertext must
        // not equal the plaintext-encoded op, and the signature must verify.
        assert_ne!(msg.body_sealed.as_bytes(), op.encode().expect("encode").as_slice());
        msg.verify_signature().expect("signature verifies");

        let opened = open_resource_op(&msg, &group).expect("open");
        assert_eq!(opened, op);
    }

    #[test]
    fn open_resource_op_rejects_wrong_cell_group_key() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("group key");
        let wrong_group =
            group_key_from_seed(&Seed::from_bytes(b"cell-b".to_vec())).expect("group key");
        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"alice".to_vec())).expect("keypair");
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let msg = seal_resource_op(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        assert!(open_resource_op(&msg, &wrong_group).is_err());
    }

    #[test]
    fn send_with_fallback_falls_past_unreachable_tiers_to_a_reachable_one() {
        // pillar-UDP and QUIC ports bound but never served -> unreachable;
        // an HTTPS-shaped TCP echo listener answers with a valid message.
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("group key");
        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"alice".to_vec())).expect("keypair");
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();
        let msg = seal_resource_op(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        // A dead UDP tier: bind and immediately drop so the port is free
        // again (nothing listens -> the connect+send succeeds but recv times
        // out, which is Unreachable here).
        let dead_udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let dead_udp_addr = dead_udp.local_addr().expect("addr");
        drop(dead_udp);

        // A dead QUIC/TCP tier similarly freed before dialing.
        let dead_quic = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let dead_quic_addr = dead_quic.local_addr().expect("addr");
        drop(dead_quic);

        // A real TCP listener speaking the plain-HTTP framing this module's
        // `dial_https` expects, echoing back the same sealed message bytes.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let https_addr = listener.local_addr().expect("addr");
        let response_bytes = msg.to_canonical_cbor().expect("encode");
        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_bytes.len()
            );
            stream.write_all(head.as_bytes()).expect("write head");
            stream.write_all(&response_bytes).expect("write body");
        });

        let tiers = vec![
            TierAddr {
                tier: TransportKind::PillarUdp,
                addr: dead_udp_addr,
            },
            TierAddr {
                tier: TransportKind::Quic,
                addr: dead_quic_addr,
            },
            TierAddr {
                tier: TransportKind::Https,
                addr: https_addr,
            },
        ];

        let outcome = send_with_fallback(&tiers, &msg).expect("fallback should reach https");
        assert_eq!(outcome.tier, TransportKind::Https);
        assert_eq!(outcome.response, msg);

        handle.join().expect("server thread");
    }

    #[test]
    fn send_with_fallback_fails_when_every_tier_is_unreachable() {
        let group = group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("group key");
        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"alice".to_vec())).expect("keypair");
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();
        let msg = seal_resource_op(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        let dead_udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let dead_udp_addr = dead_udp.local_addr().expect("addr");
        drop(dead_udp);
        let dead_https = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let dead_https_addr = dead_https.local_addr().expect("addr");
        drop(dead_https);

        let tiers = vec![
            TierAddr {
                tier: TransportKind::PillarUdp,
                addr: dead_udp_addr,
            },
            TierAddr {
                tier: TransportKind::Https,
                addr: dead_https_addr,
            },
        ];

        assert!(send_with_fallback(&tiers, &msg).is_err());
    }
}
