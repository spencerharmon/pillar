//! Handshakeless pillar-UDP: every libp2p payload rides a [`PillarMessage`],
//! and each pillar-UDP datagram is sealed to the peer's WoT static X25519 key
//! — **no libp2p Noise handshake** (method #1 step (f), the cutover; design of
//! record: `docs/papers/pillar-message-format.md` §6).
//!
//! This is the executable core of the Noise→pillar-crypto cutover for the
//! pillar-UDP transport:
//!
//! 1. **Every** libp2p control payload (opsync / anti-entropy / blob / gossip)
//!    is wrapped as a [`PillarMessage`] whose [`Body::Control`] carries the raw
//!    protocol bytes ([`wrap_control`]). The body is cell-sealed exactly like
//!    a streamdb op or an observability signal, so even a fallback transport
//!    (QUIC / TCP+TLS) never sees plaintext application content.
//! 2. Each pillar-UDP **datagram** is the canonical-CBOR of that
//!    [`PillarMessage`], sealed with
//!    [`pillar_crypto::seal::seal_to_recipients`] to the peer's static X25519
//!    [`SealingPublicKey`] — an ephemeral-static ECDH sealed box, **no
//!    handshake, no round-trip, no session state** ([`seal_datagram_to_peer`]).
//!    The peer opens it with [`pillar_crypto::seal::unseal`]
//!    ([`open_datagram`]). The WoT *is* the key distribution a Noise handshake
//!    would otherwise perform — this is what "handshakeless due to the
//!    distributed WoT" means concretely (§6.1).
//! 3. The libp2p Noise upgrade is **removed** from the pillar-UDP transport:
//!    [`handshakeless_pillar_udp_transport`] wires the raw
//!    [`crate::PillarUdpTransport`] with a bare yamux multiplex and NO
//!    `noise::Config` authenticate step — the datagram seal (2) supplies the
//!    wire confidentiality Noise used to (§6.4). QUIC/TCP keep their native
//!    encryption; the fallback ordering (pillar-UDP → QUIC → TCP+TLS) is
//!    unchanged (§6.3).
//! 4. The breaking cutover is gated behind the version spine + compat
//!    negotiation ([`negotiate_handshakeless_peer`]): a peer whose declared
//!    running pillar-UDP protocol version is outside the compat window — most
//!    importantly a Noise-era peer that never bumped it — is **refused
//!    cleanly** rather than mis-framed (`NegotiationRefusesIncompatible`), and
//!    a mixed Noise/pillar-crypto swarm coexists without partitioning
//!    (`RollingCoexistence`): a compatible peer links, an incompatible one is
//!    rejected, and neither outcome corrupts the other peers' sessions.

use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade::Version;
use libp2p::identity::Keypair;
use libp2p::{yamux, PeerId, Transport};

use pillar_crypto::seal::{seal_to_recipients, unseal};
use pillar_crypto::{
    cell::group_key_from_seed, CellId, NegotiationRefused, SealedEnvelope, SealingPublicKey,
    SealingSecretKey, Seed, SurfaceVersion,
};
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::store::Visibility;
use pillar_wire::{Body, PillarMessage};

use crate::pillar_udp::{
    MIN_PROTOCOL_VERSION as UDP_MIN_PROTOCOL_VERSION, PROTOCOL_COMPAT_WINDOW as UDP_COMPAT_WINDOW,
    PROTOCOL_SURFACE as UDP_SURFACE, PROTOCOL_VERSION as UDP_PROTOCOL_VERSION,
};
use crate::pillar_udp_transport::PillarUdpTransport;

/// The libp2p control protocol a wrapped [`PillarMessage`] carries: which of
/// the four request/response/gossip payloads
/// (opsync / anti-entropy / blob / gossip) rode the envelope. Preserved so the
/// unwrapping side can dispatch the inner bytes to the right handler exactly as
/// it would a raw libp2p payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlProtocol {
    /// The op-log sync request/response (`/pillar/opsync`).
    OpSync,
    /// The anti-entropy set-reconciliation request/response
    /// (`/pillar/anti-entropy`).
    AntiEntropy,
    /// The content-addressed blob request/response (`/pillar/blob`).
    Blob,
    /// A gossipsub event-log publication (the pub/sub broadcast).
    Gossip,
}

impl ControlProtocol {
    /// The one-byte on-wire tag prefixed to the raw control bytes inside the
    /// [`Body::Control`] payload, so the unwrapping side recovers which
    /// protocol the bytes belong to.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            ControlProtocol::OpSync => 1,
            ControlProtocol::AntiEntropy => 2,
            ControlProtocol::Blob => 3,
            ControlProtocol::Gossip => 4,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(ControlProtocol::OpSync),
            2 => Some(ControlProtocol::AntiEntropy),
            3 => Some(ControlProtocol::Blob),
            4 => Some(ControlProtocol::Gossip),
            _ => None,
        }
    }
}

/// A fault wrapping/unwrapping a libp2p control payload into/out of a
/// [`PillarMessage`], or sealing/opening a pillar-UDP datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakelessError {
    /// The envelope/body could not be canonical-CBOR (de)serialized, or its
    /// version stamp was outside the supported window.
    Envelope(pillar_wire::envelope::EnvelopeError),
    /// The datagram could not be sealed to / opened by the peer key (not a
    /// recipient, malformed sealed-envelope, or an unsupported seal version).
    Seal(pillar_crypto::CryptoError),
    /// The decoded body was a [`Body::Control`] whose leading protocol tag was
    /// not one of the known [`ControlProtocol`]s.
    UnknownControlProtocol(u8),
    /// The decoded body was empty (no protocol tag).
    EmptyControlBody,
    /// The decoded envelope carried a non-`Control` body where a libp2p
    /// control payload was expected.
    NotAControlBody,
    /// The envelope signature did not verify.
    BadSignature,
}

impl std::fmt::Display for HandshakelessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakelessError::Envelope(e) => write!(f, "pillar-message envelope error: {e}"),
            HandshakelessError::Seal(e) => write!(f, "pillar-UDP datagram seal error: {e}"),
            HandshakelessError::UnknownControlProtocol(t) => {
                write!(f, "unknown libp2p control protocol tag {t}")
            }
            HandshakelessError::EmptyControlBody => f.write_str("empty control body (no tag)"),
            HandshakelessError::NotAControlBody => {
                f.write_str("expected a Control body, found another Body variant")
            }
            HandshakelessError::BadSignature => f.write_str("pillar-message signature is invalid"),
        }
    }
}

impl std::error::Error for HandshakelessError {}

/// Wrap a raw libp2p control payload as a signed, cell-sealed
/// [`PillarMessage`]: the bytes become a tagged [`Body::Control`], sealed to
/// the `cell` group key (so only a cell member opens the application content),
/// then signed by `signer`. The result is the envelope every one of
/// opsync/anti-entropy/blob/gossip now rides — the "every libp2p message rides
/// inside the PillarMessage envelope" requirement (§6).
///
/// `cell_seed` derives BOTH the cell group key the body is sealed to and the
/// [`CellId`] header, so a caller with the same cell seed round-trips the body.
///
/// # Errors
/// [`HandshakelessError::Envelope`] on an encoding fault, or
/// [`HandshakelessError::Seal`] on an AEAD fault.
pub fn wrap_control(
    protocol: ControlProtocol,
    raw: &[u8],
    cell_seed: &str,
    signer_seed: &str,
) -> Result<PillarMessage, HandshakelessError> {
    // Tag the raw control bytes with their protocol so the unwrapping side can
    // dispatch them, then carry that as the Control body.
    let mut tagged = Vec::with_capacity(1 + raw.len());
    tagged.push(protocol.tag());
    tagged.extend_from_slice(raw);
    let body = Body::Control(tagged);
    let plaintext = body
        .to_canonical_cbor()
        .map_err(HandshakelessError::Envelope)?;

    let cell = CellId::from_bytes(format!("cell::{cell_seed}").into_bytes());
    let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
        .map_err(HandshakelessError::Seal)?;
    let aad = PillarMessage::header_aad(Visibility::Cell, &cell);
    let body_sealed = CellSeal
        .seal(&group, &plaintext, &aad)
        .map_err(HandshakelessError::Seal)?;

    let (signer, secret) = pillar_crypto::sign::signing_keypair_from_seed(&Seed::from_bytes(
        signer_seed.as_bytes().to_vec(),
    ))
    .map_err(HandshakelessError::Seal)?;
    let signature =
        pillar_crypto::sign::sign(&secret, &PillarMessage::signing_material(&body_sealed))
            .map_err(HandshakelessError::Seal)?;

    Ok(PillarMessage::new(
        signer,
        signature,
        Visibility::Cell,
        cell,
        body_sealed,
    ))
}

/// Recover the `(protocol, raw bytes)` of a control payload from a
/// [`PillarMessage`] produced by [`wrap_control`]: verify the signature, open
/// the cell-sealed body with the `cell_seed`'s group key, and split off the
/// leading protocol tag.
///
/// # Errors
/// [`HandshakelessError::BadSignature`] on a bad signature,
/// [`HandshakelessError::NotAControlBody`] / [`HandshakelessError::EmptyControlBody`]
/// / [`HandshakelessError::UnknownControlProtocol`] on a malformed body,
/// otherwise [`HandshakelessError::Envelope`] / [`HandshakelessError::Seal`].
pub fn unwrap_control(
    msg: &PillarMessage,
    cell_seed: &str,
) -> Result<(ControlProtocol, Vec<u8>), HandshakelessError> {
    msg.verify_signature()
        .map_err(|_| HandshakelessError::BadSignature)?;

    let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
        .map_err(HandshakelessError::Seal)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext = CellSeal
        .open(&group, &msg.body_sealed, &aad)
        .map_err(HandshakelessError::Seal)?;

    let body = Body::from_canonical_cbor(&plaintext).map_err(HandshakelessError::Envelope)?;
    let tagged = match body {
        Body::Control(bytes) => bytes,
        _ => return Err(HandshakelessError::NotAControlBody),
    };
    let (tag, raw) = tagged
        .split_first()
        .ok_or(HandshakelessError::EmptyControlBody)?;
    let protocol =
        ControlProtocol::from_tag(*tag).ok_or(HandshakelessError::UnknownControlProtocol(*tag))?;
    Ok((protocol, raw.to_vec()))
}

/// Seal a [`PillarMessage`] into a pillar-UDP **datagram** to a single peer:
/// canonical-CBOR the envelope, then [`seal_to_recipients`] it to the peer's
/// static X25519 [`SealingPublicKey`] (the WoT-published key). Ephemeral-static
/// ECDH sealed box — **handshakeless**: no round-trip, no session state (§6.1).
///
/// # Errors
/// [`HandshakelessError::Envelope`] on an envelope encoding fault, or
/// [`HandshakelessError::Seal`] on a seal fault.
pub fn seal_datagram_to_peer(
    msg: &PillarMessage,
    peer_sealing_pubkey: &SealingPublicKey,
) -> Result<SealedEnvelope, HandshakelessError> {
    let cbor = msg
        .to_canonical_cbor()
        .map_err(HandshakelessError::Envelope)?;
    seal_to_recipients(&cbor, std::slice::from_ref(peer_sealing_pubkey))
        .map_err(HandshakelessError::Seal)
}

/// Open a pillar-UDP datagram sealed by [`seal_datagram_to_peer`] with the
/// recipient's static X25519 [`SealingSecretKey`], recovering the
/// [`PillarMessage`]. The counterpart of [`seal_datagram_to_peer`]; no session
/// state is consulted (handshakeless).
///
/// # Errors
/// [`HandshakelessError::Seal`] if `secret` is not the datagram's recipient (or
/// the sealed envelope is malformed / an unsupported version), or
/// [`HandshakelessError::Envelope`] if the recovered bytes are not a supported
/// [`PillarMessage`].
pub fn open_datagram(
    datagram: &SealedEnvelope,
    secret: &SealingSecretKey,
) -> Result<PillarMessage, HandshakelessError> {
    let cbor = unseal(datagram, secret).map_err(HandshakelessError::Seal)?;
    PillarMessage::from_canonical_cbor(&cbor).map_err(HandshakelessError::Envelope)
}

/// Negotiate the handshakeless pillar-UDP cutover with a peer that declared
/// `remote_udp_version` as its running pillar-UDP protocol version, BEFORE any
/// of its datagrams are trusted. A Noise-era peer that never bumped past this
/// build's window is refused CLEANLY here rather than mis-framed as corruption
/// — `NegotiationRefusesIncompatible`. A peer inside
/// [`crate::pillar_udp::PROTOCOL_COMPAT_WINDOW`] links; the refusal is scoped to
/// the one incompatible relationship, so a mixed Noise/pillar-crypto swarm
/// coexists without partitioning (`RollingCoexistence`).
///
/// # Errors
/// [`NegotiationRefused`] when the declared versions differ by more than
/// [`crate::pillar_udp::PROTOCOL_COMPAT_WINDOW`], or the remote version is below
/// the minimum this build understands.
pub fn negotiate_handshakeless_peer(
    remote_udp_version: SurfaceVersion,
) -> Result<(), NegotiationRefused> {
    // A version below what this build can decode at all is out of the window
    // (a Noise-era peer whose pre-cutover UDP version predates MIN); surface it
    // as a clean negotiation refusal rather than a mis-frame.
    if remote_udp_version.0 < UDP_MIN_PROTOCOL_VERSION.0 {
        return Err(NegotiationRefused {
            surface: UDP_SURFACE,
            local: UDP_PROTOCOL_VERSION,
            remote: remote_udp_version,
            window: UDP_COMPAT_WINDOW,
        });
    }
    pillar_crypto::negotiate_surface(
        UDP_SURFACE,
        UDP_PROTOCOL_VERSION,
        remote_udp_version,
        UDP_COMPAT_WINDOW,
    )
}

/// The pillar-UDP libp2p [`Transport`] with the Noise upgrade **removed**: the
/// raw reliable-ordered [`PillarUdpTransport`] byte stream, upgraded with yamux
/// multiplexing ONLY — no `noise::Config` authenticate step. Wire
/// confidentiality is supplied by the per-datagram seal
/// ([`seal_datagram_to_peer`]), not a Noise session (§6.4), so this is the
/// concrete cutover: pillar-UDP no longer runs libp2p Noise.
///
/// A peer-id derived from the local keypair is still attached (yamux needs a
/// remote peer id; here the local id is used as the endpoint identity) so the
/// transport composes into a libp2p swarm exactly where the Noise-wrapped one
/// did — but no Diffie-Hellman handshake round-trip occurs on the wire.
#[must_use]
pub fn handshakeless_pillar_udp_transport(keypair: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    let local_peer_id = keypair.public().to_peer_id();
    PillarUdpTransport::new(keypair.clone())
        // NO `.authenticate(noise::Config::new(..))` — the Noise upgrade is
        // deliberately removed. `NoiselessUpgrade` exchanges peer ids in
        // plaintext (identity announcement only, NO Diffie-Hellman handshake,
        // NO session key); the per-datagram seal carries confidentiality.
        .upgrade(Version::V1Lazy)
        .authenticate(NoiselessUpgrade { local_peer_id })
        .multiplex(yamux::Config::default())
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed()
}

/// A libp2p authentication upgrade that installs NO cryptographic handshake:
/// it exchanges the two ends' [`PeerId`]s in PLAINTEXT (an identity
/// announcement so the swarm learns the remote peer id — which libp2p requires
/// to match a dialed address) and then hands the connection through verbatim.
/// There is no Diffie-Hellman, no session key, no Noise — this is exactly the
/// removal of the libp2p Noise upgrade from the pillar-UDP transport (§6.4);
/// confidentiality is supplied one layer up by the per-datagram
/// [`seal_to_recipients`] seal.
#[derive(Clone, Copy)]
struct NoiselessUpgrade {
    local_peer_id: PeerId,
}

mod noiseless {
    use super::NoiselessUpgrade;
    use futures::future::BoxFuture;
    use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
    use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
    use libp2p::PeerId;
    use std::iter::Once;

    /// The single protocol name the no-op upgrade advertises. Distinct from
    /// `/noise` so a Noise-era peer's multistream-select negotiation fails to
    /// find a common protocol — one mechanism by which a Noise peer is refused
    /// cleanly rather than mis-framed.
    const PROTOCOL: &str = "/pillar/udp-handshakeless/1.0.0";

    impl UpgradeInfo for NoiselessUpgrade {
        type Info = &'static str;
        type InfoIter = Once<&'static str>;
        fn protocol_info(&self) -> Self::InfoIter {
            std::iter::once(PROTOCOL)
        }
    }

    /// Plaintext peer-id exchange (NO Diffie-Hellman, NO session key): write
    /// our 38-byte multihash peer id, read the remote's. This is an identity
    /// announcement only — the confidentiality layer is the per-datagram seal,
    /// not this exchange.
    async fn exchange_peer_ids<C>(mut socket: C, local: PeerId) -> std::io::Result<(PeerId, C)>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let local_bytes = local.to_bytes();
        let len = u16::try_from(local_bytes.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "peer id too long")
        })?;
        socket.write_all(&len.to_be_bytes()).await?;
        socket.write_all(&local_bytes).await?;
        socket.flush().await?;

        let mut len_buf = [0u8; 2];
        socket.read_exact(&mut len_buf).await?;
        let remote_len = u16::from_be_bytes(len_buf) as usize;
        if remote_len == 0 || remote_len > 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "implausible remote peer id length",
            ));
        }
        let mut remote_bytes = vec![0u8; remote_len];
        socket.read_exact(&mut remote_bytes).await?;
        let remote = PeerId::from_bytes(&remote_bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad remote peer id")
        })?;
        Ok((remote, socket))
    }

    impl<C> InboundConnectionUpgrade<C> for NoiselessUpgrade
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        type Output = (PeerId, C);
        type Error = std::io::Error;
        type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;
        fn upgrade_inbound(self, socket: C, _: Self::Info) -> Self::Future {
            exchange_peer_ids(socket, self.local_peer_id).boxed()
        }
    }

    impl<C> OutboundConnectionUpgrade<C> for NoiselessUpgrade
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        type Output = (PeerId, C);
        type Error = std::io::Error;
        type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;
        fn upgrade_outbound(self, socket: C, _: Self::Info) -> Self::Future {
            exchange_peer_ids(socket, self.local_peer_id).boxed()
        }
    }
}

/// The static X25519 [`SealingPublicKey`] a peer publishes through the WoT, as
/// this build derives it from a stable seed. In a live deployment the WoT
/// authority publishes each peer's static sealing key; here the derivation is
/// exposed so a caller (and the acceptance test) can obtain the exact keypair a
/// peer would advertise.
#[must_use]
pub fn peer_sealing_keypair(seed: &str) -> (SealingPublicKey, SealingSecretKey) {
    pillar_crypto::seal::sealing_keypair_from_seed(&Seed::from_bytes(seed.as_bytes().to_vec()))
        .expect("X25519 sealing keypair derivation is infallible for an in-memory seed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_payload_round_trips_through_the_envelope() {
        for (proto, raw) in [
            (ControlProtocol::OpSync, b"opsync-request-bytes".as_ref()),
            (ControlProtocol::AntiEntropy, b"anti-entropy-set".as_ref()),
            (ControlProtocol::Blob, b"blob-response".as_ref()),
            (ControlProtocol::Gossip, b"gossip-event-log-msg".as_ref()),
        ] {
            let msg = wrap_control(proto, raw, "cell-x", "signer-x").expect("wrap");
            // The application content is NOT plaintext in the envelope.
            assert_ne!(msg.body_sealed.as_bytes(), raw);
            let (got_proto, got_raw) = unwrap_control(&msg, "cell-x").expect("unwrap");
            assert_eq!(got_proto, proto);
            assert_eq!(got_raw, raw);
        }
    }

    #[test]
    fn datagram_seals_to_peer_and_only_that_peer_opens_it() {
        let (peer_pk, peer_sk) = peer_sealing_keypair("peer-1");
        let (_other_pk, other_sk) = peer_sealing_keypair("peer-2");

        let msg =
            wrap_control(ControlProtocol::OpSync, b"payload", "cell-a", "signer-a").expect("wrap");
        let datagram = seal_datagram_to_peer(&msg, &peer_pk).expect("seal");

        // The intended peer recovers the exact envelope...
        let opened = open_datagram(&datagram, &peer_sk).expect("open");
        assert_eq!(opened, msg);
        let (proto, raw) = unwrap_control(&opened, "cell-a").expect("unwrap");
        assert_eq!(proto, ControlProtocol::OpSync);
        assert_eq!(raw, b"payload");

        // ...and a different peer cannot.
        assert!(matches!(
            open_datagram(&datagram, &other_sk),
            Err(HandshakelessError::Seal(_))
        ));
    }

    #[test]
    fn negotiation_admits_a_matching_peer_and_refuses_a_noise_era_peer() {
        // A peer declaring the current UDP protocol version links.
        assert!(negotiate_handshakeless_peer(UDP_PROTOCOL_VERSION).is_ok());

        // A Noise-era peer whose declared version is below the minimum this
        // build understands is refused cleanly.
        let noise_era = SurfaceVersion(UDP_MIN_PROTOCOL_VERSION.0.saturating_sub(1));
        if noise_era.0 < UDP_MIN_PROTOCOL_VERSION.0 {
            assert!(negotiate_handshakeless_peer(noise_era).is_err());
        }

        // A far-future peer outside the compat window is also refused.
        let future = SurfaceVersion(UDP_PROTOCOL_VERSION.0 + UDP_COMPAT_WINDOW.0 + 1);
        let err = negotiate_handshakeless_peer(future).unwrap_err();
        assert_eq!(err.surface, UDP_SURFACE);
    }
}
