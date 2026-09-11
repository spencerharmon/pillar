//! The **browser pillar-client** — the Yew console's mutation path, redone as a
//! real Pillar client instead of a privileged portal-REST caller.
//!
//! ## Why this exists
//!
//! Historically the console mutated a cell by `POST`ing to a node's
//! `/portal/resource/*` HTTP surface: a *privileged REST call* the node had to
//! trust because it arrived on an authenticated portal session. That is exactly
//! the shape `cli-apply-over-pillar-message` abolished for the CLI: a Pillar
//! mutation is not an RPC to a privileged server, it is a **signed, cell-sealed
//! [`pillar_wire::PillarMessage`] carrying a [`pillar_ops::ResourceOp`]** that
//! every node applies through the same replay/materialize path. This module
//! gives the browser the SAME act: it builds a `ResourceOp`, seals it to the
//! cell and signs it with the operator's own ed25519 key **in the browser**,
//! and hands back the exact HTTPS request (`url` + CBOR `body`) to send.
//!
//! ## Byte-identical to the CLI (the load-bearing property)
//!
//! The seal/sign here is not a parallel reimplementation: it composes the exact
//! wasm-safe subset of what `pillar_client::transport::seal_resource_op` does on
//! native — [`pillar_ops::ResourceOp::encode`] → [`pillar_wire::Body::StreamOp`]
//! → [`pillar_wire::seal::CellSeal`] under [`STREAM_OP_SEAL_DOMAIN`] → ed25519
//! [`pillar_crypto::sign::sign`] over
//! [`pillar_wire::PillarMessage::signing_material`]. Because the seal is
//! *convergent* and the op codec is deterministic, the console, the CLI, and a
//! node's own portal produce **byte-identical** sealed envelopes for the same
//! logical op — they content-address to one streamdb op id and the CRDT op-log
//! dedups them. `browser_client_matches_cli_seal` in the acceptance suite pins
//! this equality directly against `pillar_client::transport::seal_resource_op`.
//!
//! We deliberately do NOT depend on `pillar-client` itself: that crate pulls
//! tokio/quinn/rustls for the native UDP→QUIC→TCP dialer and does not build for
//! `wasm32-unknown-unknown`. A browser has no raw UDP anyway — it sends over
//! HTTPS (the node's HTTP/3-or-HTTPS resource-op ingress), so only the
//! *seal/sign* half of the client is reused here, from the wasm-safe crates
//! (`pillar-ops`, `pillar-wire` sans its `ipfs` feature, `pillar-crypto`).

use pillar_crypto::cell::{group_key_from_seed, CellGroupKey};
use pillar_crypto::sign::sign;
use pillar_crypto::{CellId, Seed, SigningPublicKey, SigningSecretKey};
use pillar_ops::{Crd, ResourceOp};
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::{Body, PillarMessage, Visibility};

/// The seal domain a client-issued `ResourceOp` is sealed under. Reused
/// verbatim from `pillar-client`'s `STREAM_OP_SEAL_DOMAIN` /
/// `pillar-streamdb`'s `StreamOp` body domain — the convergent seal only
/// yields byte-identical ciphertext across producers if every producer seals
/// under the SAME domain (see the module docs' byte-identical property).
pub const STREAM_OP_SEAL_DOMAIN: &[u8] = b"pillar-streamdb/stream-op-v1";

/// The path on the node's HTTPS surface that ingests a raw, client-sealed
/// resource-op [`PillarMessage`] — the HTTP analogue of the CLI's
/// pillar-UDP resource-op tier. A browser cannot open a raw UDP socket, so the
/// console reaches the same op-ingest over HTTPS at this path. The node
/// authenticates the producer from the envelope's ed25519 signature alone (the
/// same admission the pillar-UDP tier does), NOT from a portal session — so
/// this path carries no bearer token and is not a privileged REST mutation.
pub const RESOURCE_OP_INGEST_PATH: &str = "/pillar/resource-op";

/// Everything the browser client needs to seal+sign an op for a cell: where to
/// send, which cell, the cell's group-key seed, and the operator's signing
/// keypair. Mirrors the CLI's `PILLAR_*` connect environment (see
/// `pillar_cli::apply_over_pillar_message`) but sourced from the browser's
/// unlocked session rather than process env.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserClientConfig {
    /// Base URL of the node's HTTPS resource-op ingress (scheme + host[:port]),
    /// e.g. `https://node.example.com`. The request URL is this joined with
    /// [`RESOURCE_OP_INGEST_PATH`].
    pub node_base_url: String,
    /// The target cell id's raw bytes.
    pub cell_id: Vec<u8>,
    /// The per-cell seed the node derived its `cell_group_key` from; this
    /// client derives the same group key from it via
    /// [`group_key_from_seed`], so the raw symmetric key never travels.
    pub cell_seed: Vec<u8>,
    /// The operator's ed25519 signing public key bytes.
    pub signer_public: Vec<u8>,
    /// The operator's ed25519 signing secret key bytes (held only in the
    /// unlocked in-memory session; never persisted by this module).
    pub signer_secret: Vec<u8>,
}

/// A ready-to-send HTTPS request emitting a signed resource op: the absolute
/// `url` to `POST` to and the CBOR-encoded, sealed+signed [`PillarMessage`]
/// `body`. The caller's `fetch` glue sends these bytes with
/// `Content-Type: application/cbor`; there is deliberately no bearer token —
/// the ed25519 signature over the sealed body IS the authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpRequest {
    /// Absolute request URL (`node_base_url` + [`RESOURCE_OP_INGEST_PATH`]).
    pub url: String,
    /// The canonical-CBOR bytes of the sealed+signed [`PillarMessage`].
    pub body: Vec<u8>,
}

/// A fault building a signed op request — a malformed key/seed, or a
/// seal/sign/encode failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The cell seed did not yield a valid group key.
    BadSeed,
    /// Encoding the op payload failed.
    Encode(String),
    /// A seal or signature operation failed.
    Crypto(String),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::BadSeed => f.write_str("cell seed did not derive a group key"),
            ClientError::Encode(e) => write!(f, "encoding resource op: {e}"),
            ClientError::Crypto(e) => write!(f, "sealing/signing resource op: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl BrowserClientConfig {
    fn group_key(&self) -> Result<CellGroupKey, ClientError> {
        group_key_from_seed(&Seed::from_bytes(self.cell_seed.clone()))
            .map_err(|_| ClientError::BadSeed)
    }

    fn request_url(&self) -> String {
        let base = self.node_base_url.trim_end_matches('/');
        format!("{base}{RESOURCE_OP_INGEST_PATH}")
    }
}

/// Seal `op` to the cell and sign it, returning the CBOR bytes of the resulting
/// [`PillarMessage`]. This is the wasm-safe twin of
/// `pillar_client::transport::seal_resource_op` followed by
/// [`PillarMessage::to_canonical_cbor`] — identical steps, identical bytes.
///
/// # Errors
/// [`ClientError`] for a bad seed, an encode failure, or a seal/sign failure.
pub fn seal_signed_op_bytes(
    op: &ResourceOp,
    config: &BrowserClientConfig,
) -> Result<Vec<u8>, ClientError> {
    let group = config.group_key()?;
    let cell = CellId::from_bytes(config.cell_id.clone());
    let signer = SigningPublicKey::from_bytes(config.signer_public.clone());
    let secret = SigningSecretKey::from_bytes(config.signer_secret.clone());
    let visibility = Visibility::Cell;

    let payload = op.encode().map_err(|e| ClientError::Encode(e.to_string()))?;
    let body = Body::StreamOp(payload);
    let plaintext = body
        .to_canonical_cbor()
        .map_err(|e| ClientError::Encode(e.to_string()))?;
    let aad = PillarMessage::header_aad(visibility, &cell);
    let body_sealed = CellSeal
        .seal(&group, &plaintext, STREAM_OP_SEAL_DOMAIN, &aad)
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    let signature = sign(&secret, &PillarMessage::signing_material(&body_sealed))
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    let msg = PillarMessage::new(signer, signature, visibility, cell, body_sealed);
    msg.to_canonical_cbor()
        .map_err(|e| ClientError::Encode(e.to_string()))
}

/// Build the HTTPS [`OpRequest`] that applies `crd` — the console's
/// supersession of a `POST /portal/resource/apply` privileged REST call.
///
/// # Errors
/// [`ClientError`] if sealing/signing the op fails.
pub fn apply_request(
    crd: Crd,
    config: &BrowserClientConfig,
) -> Result<OpRequest, ClientError> {
    let body = seal_signed_op_bytes(&ResourceOp::Apply { crd }, config)?;
    Ok(OpRequest {
        url: config.request_url(),
        body,
    })
}

/// Build the HTTPS [`OpRequest`] that deletes `kind`/`name` — the console's
/// supersession of a `POST /portal/resource/delete` privileged REST call.
///
/// # Errors
/// [`ClientError`] if sealing/signing the op fails.
pub fn delete_request(
    kind: impl Into<String>,
    name: impl Into<String>,
    config: &BrowserClientConfig,
) -> Result<OpRequest, ClientError> {
    let op = ResourceOp::Delete {
        kind: kind.into(),
        name: name.into(),
    };
    let body = seal_signed_op_bytes(&op, config)?;
    Ok(OpRequest {
        url: config.request_url(),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{Metadata, Value};

    fn config() -> BrowserClientConfig {
        // A REAL ed25519 keypair (derived from a fixed seed) so the emitted
        // envelope's signature actually verifies the way a node checks it.
        let (public, secret) =
            pillar_crypto::sign::signing_keypair_from_seed(&Seed::from_bytes(vec![3u8; 32]))
                .expect("keypair");
        BrowserClientConfig {
            node_base_url: "https://node.example.com/".into(),
            cell_id: vec![7u8; 32],
            cell_seed: vec![9u8; 32],
            signer_public: public.into_bytes(),
            signer_secret: secret.into_bytes(),
        }
    }

    fn workload_crd() -> Crd {
        Crd::new(
            "pillar.dev/v1",
            "Workload",
            Metadata::new("web").with_label("pillar.dev/managed-by", "console"),
        )
        .with_spec("replicas", Value::Integer(3))
    }

    #[test]
    fn apply_request_url_joins_base_and_ingest_path_without_double_slash() {
        let req = apply_request(workload_crd(), &config()).expect("apply");
        assert_eq!(req.url, "https://node.example.com/pillar/resource-op");
        assert!(!req.body.is_empty());
    }

    #[test]
    fn the_sealed_body_opens_back_to_the_same_op_under_the_cell_key() {
        // A node receiving this body verifies the signature, opens the seal,
        // and decodes the SAME ResourceOp — proving the console emits a real,
        // node-applicable signed op, not an opaque REST payload.
        let cfg = config();
        let req = apply_request(workload_crd(), &cfg).expect("apply");
        let msg = PillarMessage::from_canonical_cbor(&req.body).expect("decode envelope");

        // signature verifies over the signing material
        pillar_crypto::sign::verify(
            &msg.signer,
            &PillarMessage::signing_material(&msg.body_sealed),
            &msg.signature,
        )
        .expect("signature verifies");

        // seal opens under the cell group key and decodes to our op
        let group = cfg.group_key().expect("group key");
        let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
        let plaintext = CellSeal.open(&group, &msg.body_sealed, &aad).expect("open");
        match Body::from_canonical_cbor(&plaintext).expect("body") {
            Body::StreamOp(payload) => {
                let op = ResourceOp::decode(&payload).expect("op decode");
                assert!(matches!(op, ResourceOp::Apply { crd } if crd.kind == "Workload"));
            }
            other => panic!("expected StreamOp body, got {other:?}"),
        }
    }

    #[test]
    fn delete_request_emits_a_signed_delete_op() {
        let cfg = config();
        let req = delete_request("Workload", "web", &cfg).expect("delete");
        let msg = PillarMessage::from_canonical_cbor(&req.body).expect("decode");
        let group = cfg.group_key().expect("group");
        let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
        let plaintext = CellSeal.open(&group, &msg.body_sealed, &aad).expect("open");
        match Body::from_canonical_cbor(&plaintext).expect("body") {
            Body::StreamOp(payload) => {
                assert_eq!(
                    ResourceOp::decode(&payload).expect("decode"),
                    ResourceOp::Delete {
                        kind: "Workload".into(),
                        name: "web".into()
                    }
                );
            }
            other => panic!("expected StreamOp, got {other:?}"),
        }
    }

    #[test]
    fn same_logical_op_seals_deterministically() {
        // The convergent property, exercised at the console layer: two
        // independently-built configs with the same cell/keys seal the same
        // logical op to byte-identical envelopes.
        let a = apply_request(workload_crd(), &config()).expect("a");
        let b = apply_request(workload_crd(), &config()).expect("b");
        assert_eq!(a.body, b.body, "same op -> identical sealed bytes");
    }
}
