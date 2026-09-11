//! The **browser pillar client** — the Yew console's HTTP(S) transport for
//! `pillar-ops` CRUD ops, superseding the legacy `token\n...`-text-body
//! portal-REST mutation path (see `resources_console`'s `act_request_body`)
//! for the two verbs [`pillar_ops::ResourceOp`] covers (`Apply`/`Delete`).
//!
//! ROI Priority 1 "The pillar client library" (2026-09-11): the console
//! becomes a real pillar client emitting the SAME ops the CLI's
//! `apply-over-pillar-message` command sends, reusing:
//!
//! * the wasm-safe CRUD vocabulary — [`pillar_ops::ResourceOp`] (no
//!   transport/crypto deps at all, so it byte-round-trips identically
//!   whether produced by the CLI, a node's own portal, or this browser
//!   client); and
//! * the wasm seal/sign path — [`pillar_wire::seal::CellSeal`] (convergent
//!   seal) + [`pillar_crypto::sign::sign`], the EXACT recipe
//!   `pillar_client::transport::seal_resource_op` uses natively. That
//!   function cannot be called directly from wasm (`pillar-client` depends
//!   on `tokio`/`quinn`, neither wasm32-portable), so [`seal_and_sign`]/
//!   [`open_and_verify`] below re-implement the identical
//!   encode -> `Body::StreamOp` -> canonical-CBOR -> seal -> sign pipeline
//!   using only wasm-safe crates (`pillar-ops`, `pillar-wire` with
//!   `default-features = false`, `pillar-crypto`), under the SAME
//!   [`STREAM_OP_SEAL_DOMAIN`] domain separator so a browser-issued op
//!   converges to the identical ciphertext a CLI-issued copy of the same
//!   logical op would produce.
//!
//! ## Wire endpoint
//!
//! The real transport speaks the SAME `POST /portal/client/message`
//! contract `pillar_client::transport::dial_https` already uses natively
//! (`Content-Type: application/cbor`, a canonical-CBOR [`PillarMessage`]
//! body, a canonical-CBOR [`PillarMessage`] response) — never a bespoke
//! browser-only protocol — so a node cannot tell a browser client's request
//! apart from the CLI's over the wire.
//!
//! ## Host-testable orchestration
//!
//! Exactly the `webauthn` module's pattern: the request/response round trip
//! is abstracted behind [`StreamOpTransport`], so [`submit_resource_op`]'s
//! encode -> POST -> decode sequence is asserted with a native `cargo test`
//! against a [`StreamOpTransport`] mock; the real, DOM-touching
//! [`BrowserTransport`] (behind the `yew` feature) drives an actual `fetch`
//! via `gloo-net`, posting/parsing the exact same bytes.

use pillar_crypto::cell::CellGroupKey;
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{CellId, CryptoError, SigningPublicKey, SigningSecretKey};
use pillar_ops::{OpCodecError, ResourceOp};
use pillar_wire::envelope::EnvelopeError;
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::{Body, PillarMessage, Visibility};

/// The domain separator a `StreamOp` seal uses — IDENTICAL to
/// `pillar_client::transport::STREAM_OP_SEAL_DOMAIN` and
/// `pillar-streamdb`'s own `StreamOp` domain, so a browser-issued op
/// converges to the same ciphertext as any other producer of the same
/// logical op (see `pillar-ops`'s crate docs on convergent content-addressing).
pub const STREAM_OP_SEAL_DOMAIN: &[u8] = b"pillar-streamdb/stream-op-v1";

/// The `/portal/client/message` path `pillar_client::transport::dial_https`
/// already POSTs a sealed [`PillarMessage`] to — the same endpoint this
/// browser client targets.
pub const STREAM_OP_ENDPOINT: &str = "/portal/client/message";

/// A fault sealing/opening/transporting a `StreamOp`-bearing [`PillarMessage`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserOpError {
    /// `op` failed to encode (see [`pillar_ops::OpCodecError`]).
    Op(OpCodecError),
    /// The `Body`/`PillarMessage` envelope failed to (de)serialize.
    Envelope(EnvelopeError),
    /// Sealing, opening, signing, or verifying failed.
    Crypto(CryptoError),
    /// The opened body was not a `StreamOp` (a `Signal`/`Control` reply).
    NotAStreamOp,
    /// The transport itself failed (network error / non-2xx status).
    Transport(String),
}

impl std::fmt::Display for BrowserOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserOpError::Op(e) => write!(f, "resource-op codec error: {e}"),
            BrowserOpError::Envelope(e) => write!(f, "envelope error: {e}"),
            BrowserOpError::Crypto(e) => write!(f, "crypto error: {e}"),
            BrowserOpError::NotAStreamOp => f.write_str("body was not a StreamOp"),
            BrowserOpError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for BrowserOpError {}

/// Seal `op` into a `StreamOp` body and wrap it in a signed [`PillarMessage`]
/// — the wasm-safe twin of `pillar_client::transport::seal_resource_op`
/// (identical pipeline, identical domain, byte-identical output for the
/// same inputs).
///
/// # Errors
/// [`BrowserOpError::Op`] if `op` fails to encode; [`BrowserOpError::Envelope`]
/// if the body fails to serialize; [`BrowserOpError::Crypto`] if sealing or
/// signing fails.
pub fn seal_and_sign(
    op: &ResourceOp,
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<PillarMessage, BrowserOpError> {
    let payload = op.encode().map_err(BrowserOpError::Op)?;
    let body = Body::StreamOp(payload);
    let plaintext = body.to_canonical_cbor().map_err(BrowserOpError::Envelope)?;
    let aad = PillarMessage::header_aad(visibility, &cell);
    let body_sealed = CellSeal
        .seal(group, &plaintext, STREAM_OP_SEAL_DOMAIN, &aad)
        .map_err(BrowserOpError::Crypto)?;
    let signature = sign(secret, &PillarMessage::signing_material(&body_sealed))
        .map_err(BrowserOpError::Crypto)?;
    Ok(PillarMessage::new(
        signer,
        signature,
        visibility,
        cell,
        body_sealed,
    ))
}

/// Verify and open a `StreamOp`-bearing [`PillarMessage`], returning the
/// decoded [`ResourceOp`] — the wasm-safe twin of
/// `pillar_client::transport::open_resource_op`.
///
/// # Errors
/// [`BrowserOpError::Crypto`] if the signature or seal fails to verify/open;
/// [`BrowserOpError::NotAStreamOp`] if the opened body is a different kind;
/// [`BrowserOpError::Op`] if the payload does not decode as a [`ResourceOp`].
pub fn open_and_verify(
    msg: &PillarMessage,
    group: &CellGroupKey,
) -> Result<ResourceOp, BrowserOpError> {
    verify(
        &msg.signer,
        &PillarMessage::signing_material(&msg.body_sealed),
        &msg.signature,
    )
    .map_err(BrowserOpError::Crypto)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext = CellSeal
        .open(group, &msg.body_sealed, &aad)
        .map_err(BrowserOpError::Crypto)?;
    let body = Body::from_canonical_cbor(&plaintext).map_err(BrowserOpError::Envelope)?;
    match body {
        Body::StreamOp(payload) => ResourceOp::decode(&payload).map_err(BrowserOpError::Op),
        _ => Err(BrowserOpError::NotAStreamOp),
    }
}

/// The `POST /portal/client/message` round trip, abstracted so
/// [`submit_resource_op`]'s orchestration is host-testable against a mock.
/// The real impl ([`BrowserTransport`], behind `yew`) POSTs with
/// `gloo-net`'s `fetch`-backed `Request`, binary body/response.
pub trait StreamOpTransport {
    /// POST the canonical-CBOR-encoded sealed message, returning the
    /// canonical-CBOR-encoded sealed reply.
    fn post(&self, body: Vec<u8>) -> Result<Vec<u8>, BrowserOpError>;
}

/// Seal+sign `op`, POST it over `transport`, and open+verify the reply —
/// the browser-client analogue of
/// `pillar_client::transport::send_op_with_fallback` (minus the multi-tier
/// UDP/QUIC fallback a browser cannot dial: HTTP(S) is the browser's one
/// reachable tier).
///
/// # Errors
/// Any [`BrowserOpError`] the seal, transport, or open/verify step raises.
pub fn submit_resource_op(
    transport: &impl StreamOpTransport,
    op: &ResourceOp,
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<ResourceOp, BrowserOpError> {
    let msg = seal_and_sign(op, group, cell, signer, secret, visibility)?;
    let bytes = msg.to_canonical_cbor().map_err(BrowserOpError::Envelope)?;
    let reply_bytes = transport.post(bytes)?;
    let reply = PillarMessage::from_canonical_cbor(&reply_bytes).map_err(BrowserOpError::Envelope)?;
    open_and_verify(&reply, group)
}

// ---------------------------------------------------------------------
// The real, DOM-touching transport (behind `yew`).
// ---------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use browser::{submit_resource_op_async, BrowserTransport};

#[cfg(feature = "yew")]
mod browser {
    use super::*;
    use gloo_net::http::Request;
    use js_sys::Uint8Array;

    /// The real `POST /portal/client/message` transport, driven with
    /// `gloo-net`'s `fetch`-backed `Request` over a binary body/response —
    /// byte-for-byte the same wire shape
    /// `pillar_client::transport::dial_https` speaks natively.
    pub struct BrowserTransport {
        /// The origin the endpoint is relative to (empty for same-origin
        /// relative requests).
        pub base_url: String,
    }

    impl BrowserTransport {
        /// A transport posting to a same-origin relative
        /// [`super::STREAM_OP_ENDPOINT`].
        pub fn new() -> Self {
            BrowserTransport { base_url: String::new() }
        }

        async fn post_async(&self, body: Vec<u8>) -> Result<Vec<u8>, BrowserOpError> {
            let url = format!("{}{}", self.base_url, STREAM_OP_ENDPOINT);
            let resp = Request::post(&url)
                .header("Content-Type", "application/cbor")
                .body(Uint8Array::from(body.as_slice()))
                .map_err(|e| BrowserOpError::Transport(e.to_string()))?
                .send()
                .await
                .map_err(|e| BrowserOpError::Transport(e.to_string()))?;
            let status = resp.status();
            let bytes = resp
                .binary()
                .await
                .map_err(|e| BrowserOpError::Transport(e.to_string()))?;
            if !(200..300).contains(&status) {
                return Err(BrowserOpError::Transport(format!(
                    "server returned status {status}"
                )));
            }
            Ok(bytes)
        }
    }

    impl Default for BrowserTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Seal+sign `op`, POST it to a real node over `fetch`, and open+verify
    /// the reply. The real, DOM-touching analogue of
    /// [`super::submit_resource_op`].
    ///
    /// # Errors
    /// Any [`BrowserOpError`] the seal, `fetch`, or open/verify step raises.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_resource_op_async(
        op: &ResourceOp,
        group: &CellGroupKey,
        cell: CellId,
        signer: SigningPublicKey,
        secret: &SigningSecretKey,
        visibility: Visibility,
    ) -> Result<ResourceOp, BrowserOpError> {
        let msg = seal_and_sign(op, group, cell, signer, secret, visibility)?;
        let bytes = msg.to_canonical_cbor().map_err(BrowserOpError::Envelope)?;
        let transport = BrowserTransport::new();
        let reply_bytes = transport.post_async(bytes).await?;
        let reply =
            PillarMessage::from_canonical_cbor(&reply_bytes).map_err(BrowserOpError::Envelope)?;
        open_and_verify(&reply, group)
    }
}

// ---------------------------------------------------------------------
// Tests — the seal/sign/open pipeline + orchestration, host-tested.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::sign::signing_keypair_from_seed;
    use pillar_crypto::Seed;

    fn test_group() -> CellGroupKey {
        pillar_crypto::cell::group_key_from_seed(&Seed::from_bytes(b"test-seed-material".to_vec()))
            .expect("group key derivation")
    }

    fn test_keypair() -> (SigningPublicKey, SigningSecretKey) {
        signing_keypair_from_seed(&Seed::from_bytes(b"test-signing-seed".to_vec()))
            .expect("signing keypair derivation")
    }

    fn test_op() -> ResourceOp {
        ResourceOp::Delete {
            kind: "Deployment".to_owned(),
            name: "example".to_owned(),
        }
    }

    #[test]
    fn seal_then_open_round_trips_the_same_op() {
        let group = test_group();
        let (signer, secret) = test_keypair();
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let msg = seal_and_sign(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal_and_sign");
        let opened = open_and_verify(&msg, &group).expect("open_and_verify");
        assert_eq!(opened, op);
    }

    #[test]
    fn two_producers_of_the_same_logical_op_converge_to_identical_ciphertext() {
        // The convergent-seal property `pillar-ops`'s docs promise: a
        // browser-issued copy of the same logical op seals to the SAME
        // ciphertext bytes as any other producer would (same key material,
        // domain, and AAD) -- never a fresh, incidentally-different blob.
        let group = test_group();
        let (signer, secret) = test_keypair();
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let a = seal_and_sign(&op, &group, cell.clone(), signer.clone(), &secret, Visibility::Cell)
            .expect("seal a");
        let b = seal_and_sign(&op, &group, cell, signer, &secret, Visibility::Cell).expect("seal b");
        assert_eq!(a.body_sealed, b.body_sealed);
    }

    #[test]
    fn wrong_group_key_fails_to_open() {
        let group = test_group();
        let other_group =
            pillar_crypto::cell::group_key_from_seed(&Seed::from_bytes(b"different-seed".to_vec()))
                .expect("other group key");
        let (signer, secret) = test_keypair();
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let msg = seal_and_sign(&op, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal_and_sign");
        let err = open_and_verify(&msg, &other_group).expect_err("must not open under wrong key");
        assert!(matches!(err, BrowserOpError::Crypto(_)));
    }

    /// A [`StreamOpTransport`] mock that unseals+re-seals the request as its
    /// own reply (as if a node echoed the applied op back), so
    /// [`submit_resource_op`]'s full encode -> POST -> decode orchestration
    /// is exercised without any network/DOM surface.
    struct EchoTransport {
        group: CellGroupKey,
        cell: CellId,
        signer: SigningPublicKey,
        secret: SigningSecretKey,
    }

    impl StreamOpTransport for EchoTransport {
        fn post(&self, body: Vec<u8>) -> Result<Vec<u8>, BrowserOpError> {
            let msg =
                PillarMessage::from_canonical_cbor(&body).map_err(BrowserOpError::Envelope)?;
            let op = open_and_verify(&msg, &self.group)?;
            let reply = seal_and_sign(
                &op,
                &self.group,
                self.cell.clone(),
                self.signer.clone(),
                &self.secret,
                Visibility::Cell,
            )?;
            reply.to_canonical_cbor().map_err(BrowserOpError::Envelope)
        }
    }

    #[test]
    fn submit_resource_op_round_trips_through_a_transport() {
        let group = test_group();
        let (signer, secret) = test_keypair();
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let transport = EchoTransport {
            group: group.clone(),
            cell: cell.clone(),
            signer: signer.clone(),
            secret: secret.clone(),
        };
        let result = submit_resource_op(
            &transport,
            &op,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        )
        .expect("submit_resource_op");
        assert_eq!(result, op);
    }

    #[test]
    fn submit_resource_op_surfaces_transport_failure() {
        struct FailingTransport;
        impl StreamOpTransport for FailingTransport {
            fn post(&self, _body: Vec<u8>) -> Result<Vec<u8>, BrowserOpError> {
                Err(BrowserOpError::Transport("connection refused".to_owned()))
            }
        }

        let group = test_group();
        let (signer, secret) = test_keypair();
        let cell = CellId::from_bytes(b"cell-a".to_vec());
        let op = test_op();

        let err = submit_resource_op(
            &FailingTransport,
            &op,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        )
        .expect_err("must surface transport failure");
        assert!(matches!(err, BrowserOpError::Transport(_)));
    }
}
