//! streamdb ops as `PillarMessage::StreamOp` bodies (method #1 step (d),
//! `docs/papers/pillar-message-format.md`).
//!
//! A streamdb op no longer travels the IPFS-backed [`crate::store::ContentStore`]
//! as a bare plaintext payload: it is canonical-CBOR-encoded as
//! [`pillar_wire::Body::StreamOp`], sealed to the cell group key with the
//! **convergent** [`pillar_crypto::cell::cell_seal_convergent`] primitive (so
//! the SAME logical op sealed by the SAME author under the SAME cell key
//! yields byte-identical ciphertext — and therefore an identical
//! [`pillar_wire::Cid`] — on every node), signed, and wrapped in a
//! [`pillar_wire::PillarMessage`] envelope. No CRDT/Merkle-root behavior
//! changes: the op-log identity ([`crate::OpId`]) and [`crate::MerkleRoot`]
//! still fold over the PLAINTEXT op payload exactly as before — only the
//! durable/wire REPRESENTATION of that payload changes.
//!
//! The legacy `v1` wire shape (the bare op payload, no envelope) stays a
//! READ-compatibility decode path: [`decode_stream_op_segment_payload`] tries
//! the `v2` envelope first and falls back to treating the bytes as a raw
//! legacy payload only when they do not parse as a [`pillar_wire::PillarMessage`]
//! at all — the version-stamp `pillar_wire::envelope::PILLAR_MESSAGE_MIN_SUPPORTED`
//! draws the exact line the design paper's §7 read-compat window calls for.

use pillar_crypto::cell::{cell_open_convergent, cell_seal_convergent, CellGroupKey};
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{CellId, CryptoError, SigningPublicKey, SigningSecretKey};

use pillar_wire::envelope::EnvelopeError;
use pillar_wire::{Body, PillarMessage, Visibility};

/// Domain separator for the convergent seal — keeps a streamdb op's
/// convergent-equality leak (two sealed ops are provably byte-identical)
/// scoped to this record class, never crossing into e.g. an observability
/// signal sealed under the same cell key (`obs-signal-pillarmsg-ipfs`).
const STREAM_OP_SEAL_DOMAIN: &[u8] = b"pillar-streamdb/stream-op-v1";

/// A fault building or opening a `PillarMessage::StreamOp` envelope.
#[derive(Debug)]
pub enum StreamOpMessageError {
    /// The sealed body did not decode to a [`Body::StreamOp`] variant (a
    /// different `PillarMessage` body kind, or corrupt CBOR).
    NotAStreamOp,
    /// The envelope's canonical-CBOR codec rejected the bytes.
    Envelope(EnvelopeError),
    /// A signing/sealing/opening cryptographic primitive failed — for an
    /// open, this is also the "non-member cannot open" case: opening with the
    /// wrong cell group key fails AEAD authentication here.
    Crypto(CryptoError),
}

impl std::fmt::Display for StreamOpMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamOpMessageError::NotAStreamOp => {
                write!(f, "PillarMessage body is not a StreamOp")
            }
            StreamOpMessageError::Envelope(e) => write!(f, "envelope error: {e}"),
            StreamOpMessageError::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for StreamOpMessageError {}

impl From<EnvelopeError> for StreamOpMessageError {
    fn from(e: EnvelopeError) -> Self {
        StreamOpMessageError::Envelope(e)
    }
}

/// Build a signed, cell-sealed `PillarMessage::StreamOp` envelope for a
/// streamdb op's raw payload.
///
/// Sealing is **convergent**
/// ([`cell_seal_convergent`]/[`STREAM_OP_SEAL_DOMAIN`]): sealing the SAME
/// `payload` under the SAME `group`/`cell`/`visibility` twice, then signing
/// with the SAME `secret`, yields a byte-identical [`PillarMessage`] (Ed25519
/// signing is itself deterministic) — so re-appending the same op converges
/// to the same envelope `Cid`, matching the op-log's own idempotent-append
/// contract (`crate::OpLog::append`).
///
/// # Errors
/// [`StreamOpMessageError::Envelope`] if the body fails to canonical-CBOR-
/// encode (never in practice for an in-memory payload);
/// [`StreamOpMessageError::Crypto`] if sealing or signing fails.
pub fn seal_stream_op(
    payload: &[u8],
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<PillarMessage, StreamOpMessageError> {
    let body = Body::StreamOp(payload.to_vec());
    let plaintext = body.to_canonical_cbor()?;
    let aad = PillarMessage::header_aad(visibility, &cell);
    let body_sealed = cell_seal_convergent(group, &plaintext, STREAM_OP_SEAL_DOMAIN, &aad)
        .map_err(StreamOpMessageError::Crypto)?;
    let signature = sign(secret, &PillarMessage::signing_material(&body_sealed))
        .map_err(StreamOpMessageError::Crypto)?;
    Ok(PillarMessage::new(
        signer,
        signature,
        visibility,
        cell,
        body_sealed,
    ))
}

/// Open a `PillarMessage::StreamOp` envelope back to its raw op payload.
///
/// Verifies the envelope's authorship signature, then opens the sealed body
/// under `group` (the cell group key). A cell non-member — anyone without
/// `group` — cannot open the body: [`cell_open_convergent`] fails AEAD
/// authentication for a wrong (or absent) key, surfacing as
/// [`StreamOpMessageError::Crypto`].
///
/// # Errors
/// [`StreamOpMessageError::Crypto`] if signature verification or the seal
/// open fails (including the non-member case); [`StreamOpMessageError::Envelope`]
/// on a malformed sealed-body encoding; [`StreamOpMessageError::NotAStreamOp`]
/// if the opened body is a different `PillarMessage` body kind.
pub fn open_stream_op(
    msg: &PillarMessage,
    group: &CellGroupKey,
) -> Result<Vec<u8>, StreamOpMessageError> {
    verify(
        &msg.signer,
        &PillarMessage::signing_material(&msg.body_sealed),
        &msg.signature,
    )
    .map_err(StreamOpMessageError::Crypto)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext =
        cell_open_convergent(group, &msg.body_sealed, &aad).map_err(StreamOpMessageError::Crypto)?;
    let body = Body::from_canonical_cbor(&plaintext)?;
    match body {
        Body::StreamOp(payload) => Ok(payload),
        _ => Err(StreamOpMessageError::NotAStreamOp),
    }
}

/// Encode a `v2` `PillarMessage::StreamOp` segment payload: build + seal +
/// canonical-CBOR-encode the envelope in one call, for the durable-store
/// write path ([`crate::ipfs_persist::IpfsPersistentStream::append`]).
///
/// # Errors
/// See [`seal_stream_op`]; additionally propagates the (never-in-practice)
/// envelope encode failure.
pub fn encode_stream_op_segment_payload(
    payload: &[u8],
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<Vec<u8>, StreamOpMessageError> {
    let msg = seal_stream_op(payload, group, cell, signer, secret, visibility)?;
    Ok(msg.to_canonical_cbor()?)
}

/// Decode a segment's stored payload back to the raw op payload, preferring
/// the `v2` `PillarMessage::StreamOp` envelope and falling back to the legacy
/// `v1` bare-payload shape (read-compat) only when the bytes do not parse as
/// a `PillarMessage` at all.
///
/// This is the version-stamp-gated read-compat path the task card calls for:
/// a `v2` envelope carries its own [`pillar_wire::envelope::PILLAR_MESSAGE_MAX_SUPPORTED`]-
/// window version stamp and is opened accordingly; bytes that fail to decode
/// as any supported `PillarMessage` version are treated as a pre-migration
/// `v1` segment whose payload IS the op bytes, unwrapped.
///
/// # Errors
/// [`StreamOpMessageError::Crypto`] if a recognized `v2` envelope fails to
/// open under `group` (including the non-member case) — a `v1` legacy
/// payload can never hit this path since it never attempts to open anything.
pub fn decode_stream_op_segment_payload(
    bytes: &[u8],
    group: &CellGroupKey,
) -> Result<Vec<u8>, StreamOpMessageError> {
    match PillarMessage::from_canonical_cbor(bytes) {
        Ok(msg) => open_stream_op(&msg, group),
        // Malformed / unsupported version: not a v2 envelope at all -> read
        // the legacy v1 shape, the bare op payload itself.
        Err(_) => Ok(bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::sign::signing_keypair_from_seed;
    use pillar_crypto::Seed;

    fn fixture(
        cell_seed: &str,
        signer_seed: &str,
    ) -> (CellGroupKey, CellId, SigningPublicKey, SigningSecretKey) {
        let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
            .expect("cell key");
        let cell = CellId::from_bytes(format!("cell::{cell_seed}").into_bytes());
        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(signer_seed.as_bytes().to_vec()))
                .expect("keygen");
        (group, cell, signer, secret)
    }

    /// Envelope round-trip: seal a `StreamOp`, encode, decode, open, and
    /// recover the exact original payload.
    #[test]
    fn stream_op_envelope_round_trips() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"streamdb op payload".to_vec();
        let msg = seal_stream_op(
            &payload,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        )
        .expect("seal");

        let encoded = msg.to_canonical_cbor().expect("encode");
        let decoded = PillarMessage::from_canonical_cbor(&encoded).expect("decode");
        let opened = open_stream_op(&decoded, &group).expect("open");
        assert_eq!(opened, payload);
    }

    /// Sealing the SAME payload under the SAME cell/signer twice yields a
    /// byte-identical envelope, hence the same content-addressed `Cid` — the
    /// convergent-dedup property the durable store's append idempotence
    /// relies on.
    #[test]
    fn identical_payload_seals_converge_to_the_same_cid() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"same op payload".to_vec();

        let a = encode_stream_op_segment_payload(
            &payload,
            &group,
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
        )
        .expect("seal a");
        let b = encode_stream_op_segment_payload(
            &payload,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        )
        .expect("seal b");

        assert_eq!(a, b, "identical op -> byte-identical envelope");
        assert_eq!(
            pillar_wire::Cid::of(&a),
            pillar_wire::Cid::of(&b),
            "byte-identical envelope -> identical Cid"
        );
    }

    /// The legacy `v1` bare-payload shape still decodes: bytes that are not a
    /// valid `PillarMessage` envelope are treated as the raw op payload.
    #[test]
    fn legacy_v1_bare_payload_is_read_compat() {
        let (group, _cell, _signer, _secret) = fixture("cell-a", "author-a");
        let legacy_payload = b"pre-migration raw op bytes".to_vec();
        let decoded =
            decode_stream_op_segment_payload(&legacy_payload, &group).expect("read-compat decode");
        assert_eq!(decoded, legacy_payload);
    }

    /// A non-member — anyone without the cell group key — cannot open a
    /// cell-sealed `StreamOp` body.
    #[test]
    fn non_member_cannot_open_cell_sealed_op() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"secret op".to_vec();
        let msg = seal_stream_op(&payload, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        let wrong_group = group_key_from_seed(&Seed::from_bytes(b"cell-b".to_vec()))
            .expect("wrong cell key");
        assert!(
            open_stream_op(&msg, &wrong_group).is_err(),
            "wrong cell key must not open the sealed body"
        );
    }
}
