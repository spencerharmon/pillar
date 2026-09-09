//! Observability signals as `PillarMessage::Signal` bodies over the pillar-wire
//! IPFS `ContentStore` (method #1 step (e), `obs-signal-pillarmsg-ipfs`,
//! `docs/papers/pillar-message-format.md`).
//!
//! A signal (metric/log/trace/profile/metadata) is persisted to the SAME
//! pillar-wire [`pillar_wire::ContentStore`] substrate streamdb uses — there is
//! NO parallel observability store. Its raw payload is canonical-CBOR-encoded
//! as [`pillar_wire::Body::Signal`], sealed to the cell group key with the
//! **convergent** [`pillar_crypto::cell::cell_seal_convergent`] primitive (so
//! the SAME logical signal sealed by the SAME author under the SAME cell key
//! yields byte-identical ciphertext — and therefore an identical
//! [`pillar_wire::Cid`] — on every node), signed, and wrapped in a
//! [`pillar_wire::PillarMessage`] envelope.
//!
//! The convergent-seal DOMAIN separator ([`SIGNAL_SEAL_DOMAIN`]) keeps a
//! signal's convergent-equality leak scoped to THIS record class: a signal and
//! a streamdb op (`pillar_streamdb`'s `stream-op-v1` domain) sealed under the
//! same cell key can never be confused, even though they share the substrate.
//!
//! Content-addressing identity is unchanged: a `SignalId`
//! ([`crate::block::SignalId`]) still folds over the PLAINTEXT signal payload
//! exactly as before — only the durable/wire REPRESENTATION of that payload
//! changes to the sealed `PillarMessage::Signal` envelope.
//!
//! The legacy bare-payload wire shape stays a READ-compatibility decode path:
//! [`decode_signal_segment_payload`] tries the envelope first and falls back to
//! treating the bytes as a raw legacy payload only when they do not parse as a
//! [`pillar_wire::PillarMessage`] at all.

use pillar_crypto::cell::{cell_open_convergent, cell_seal_convergent, CellGroupKey};
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{CellId, CryptoError, SigningPublicKey, SigningSecretKey};

use pillar_wire::envelope::EnvelopeError;
use pillar_wire::{Body, PillarMessage, Visibility};

/// Domain separator for the convergent seal — keeps an observability signal's
/// convergent-equality leak (two sealed signals are provably byte-identical)
/// scoped to this record class, never crossing into e.g. a streamdb op sealed
/// under the same cell key (`pillar-streamdb/stream-op-v1`).
const SIGNAL_SEAL_DOMAIN: &[u8] = b"pillar-observability/signal-v1";

/// A fault building or opening a `PillarMessage::Signal` envelope.
#[derive(Debug)]
pub enum SignalMessageError {
    /// The sealed body did not decode to a [`Body::Signal`] variant (a
    /// different `PillarMessage` body kind, or corrupt CBOR).
    NotASignal,
    /// The envelope's canonical-CBOR codec rejected the bytes.
    Envelope(EnvelopeError),
    /// A signing/sealing/opening cryptographic primitive failed — for an
    /// open, this is also the "non-member cannot open" case: opening with the
    /// wrong cell group key fails AEAD authentication here.
    Crypto(CryptoError),
}

impl std::fmt::Display for SignalMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalMessageError::NotASignal => {
                write!(f, "PillarMessage body is not a Signal")
            }
            SignalMessageError::Envelope(e) => write!(f, "envelope error: {e}"),
            SignalMessageError::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for SignalMessageError {}

impl From<EnvelopeError> for SignalMessageError {
    fn from(e: EnvelopeError) -> Self {
        SignalMessageError::Envelope(e)
    }
}

/// Build a signed, cell-sealed `PillarMessage::Signal` envelope for an
/// observability signal's raw payload.
///
/// Sealing is **convergent**
/// ([`cell_seal_convergent`]/[`SIGNAL_SEAL_DOMAIN`]): sealing the SAME
/// `payload` under the SAME `group`/`cell`/`visibility` twice, then signing
/// with the SAME `secret`, yields a byte-identical [`PillarMessage`] (Ed25519
/// signing is itself deterministic) — so re-recording the same signal converges
/// to the same envelope `Cid`, matching the content-addressed op-log's own
/// idempotent-append contract.
///
/// # Errors
/// [`SignalMessageError::Envelope`] if the body fails to canonical-CBOR-encode
/// (never in practice for an in-memory payload);
/// [`SignalMessageError::Crypto`] if sealing or signing fails.
pub fn seal_signal(
    payload: &[u8],
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<PillarMessage, SignalMessageError> {
    let body = Body::Signal(payload.to_vec());
    let plaintext = body.to_canonical_cbor()?;
    let aad = PillarMessage::header_aad(visibility, &cell);
    let body_sealed = cell_seal_convergent(group, &plaintext, SIGNAL_SEAL_DOMAIN, &aad)
        .map_err(SignalMessageError::Crypto)?;
    let signature = sign(secret, &PillarMessage::signing_material(&body_sealed))
        .map_err(SignalMessageError::Crypto)?;
    Ok(PillarMessage::new(
        signer,
        signature,
        visibility,
        cell,
        body_sealed,
    ))
}

/// Open a `PillarMessage::Signal` envelope back to its raw signal payload.
///
/// Verifies the envelope's authorship signature, then opens the sealed body
/// under `group` (the cell group key). A cell non-member — anyone without
/// `group` — cannot open the body: [`cell_open_convergent`] fails AEAD
/// authentication for a wrong (or absent) key, surfacing as
/// [`SignalMessageError::Crypto`].
///
/// # Errors
/// [`SignalMessageError::Crypto`] if signature verification or the seal open
/// fails (including the non-member case); [`SignalMessageError::Envelope`] on a
/// malformed sealed-body encoding; [`SignalMessageError::NotASignal`] if the
/// opened body is a different `PillarMessage` body kind.
pub fn open_signal(
    msg: &PillarMessage,
    group: &CellGroupKey,
) -> Result<Vec<u8>, SignalMessageError> {
    verify(
        &msg.signer,
        &PillarMessage::signing_material(&msg.body_sealed),
        &msg.signature,
    )
    .map_err(SignalMessageError::Crypto)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext =
        cell_open_convergent(group, &msg.body_sealed, &aad).map_err(SignalMessageError::Crypto)?;
    let body = Body::from_canonical_cbor(&plaintext)?;
    match body {
        Body::Signal(payload) => Ok(payload),
        _ => Err(SignalMessageError::NotASignal),
    }
}

/// Encode a `PillarMessage::Signal` segment payload: build + seal +
/// canonical-CBOR-encode the envelope in one call, for the durable
/// `ContentStore` write path.
///
/// # Errors
/// See [`seal_signal`]; additionally propagates the (never-in-practice)
/// envelope encode failure.
pub fn encode_signal_segment_payload(
    payload: &[u8],
    group: &CellGroupKey,
    cell: CellId,
    signer: SigningPublicKey,
    secret: &SigningSecretKey,
    visibility: Visibility,
) -> Result<Vec<u8>, SignalMessageError> {
    let msg = seal_signal(payload, group, cell, signer, secret, visibility)?;
    Ok(msg.to_canonical_cbor()?)
}

/// Decode a segment's stored payload back to the raw signal payload, preferring
/// the `PillarMessage::Signal` envelope and falling back to the legacy
/// bare-payload shape (read-compat) only when the bytes do not parse as a
/// `PillarMessage` at all.
///
/// # Errors
/// [`SignalMessageError::Crypto`] if a recognized envelope fails to open under
/// `group` (including the non-member case) — a legacy bare payload can never
/// hit this path since it never attempts to open anything.
pub fn decode_signal_segment_payload(
    bytes: &[u8],
    group: &CellGroupKey,
) -> Result<Vec<u8>, SignalMessageError> {
    match PillarMessage::from_canonical_cbor(bytes) {
        Ok(msg) => open_signal(&msg, group),
        // Malformed / unsupported version: not an envelope at all -> read the
        // legacy shape, the bare signal payload itself.
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

    /// Envelope round-trip: seal a `Signal`, encode, decode, open, and recover
    /// the exact original payload — the persisted `ContentStore` representation
    /// of a signal is a `PillarMessage::Signal` body, not a bare payload.
    #[test]
    fn signal_envelope_round_trips_as_pillar_message_signal() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"metric cpu 0.9".to_vec();
        let msg = seal_signal(&payload, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        // It really is a Signal body kind (opening any other body kind errors).
        let encoded = msg.to_canonical_cbor().expect("encode");
        let decoded = PillarMessage::from_canonical_cbor(&encoded).expect("decode");
        let opened = open_signal(&decoded, &group).expect("open");
        assert_eq!(opened, payload);
    }

    /// Sealing the SAME signal payload under the SAME cell/signer twice yields
    /// a byte-identical envelope, hence the same content-addressed `Cid` — the
    /// convergent-dedup property the durable store's append idempotence relies
    /// on, identical to streamdb's op path over the shared substrate.
    #[test]
    fn identical_signal_seals_converge_to_the_same_cid() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"same signal payload".to_vec();

        let a = encode_signal_segment_payload(
            &payload,
            &group,
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
        )
        .expect("seal a");
        let b = encode_signal_segment_payload(
            &payload,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        )
        .expect("seal b");

        assert_eq!(a, b, "identical signal -> byte-identical envelope");
        assert_eq!(
            pillar_wire::Cid::of(&a),
            pillar_wire::Cid::of(&b),
            "byte-identical envelope -> identical Cid"
        );
    }

    /// The legacy bare-payload shape still decodes: bytes that are not a valid
    /// `PillarMessage` envelope are treated as the raw signal payload.
    #[test]
    fn legacy_bare_payload_is_read_compat() {
        let (group, _cell, _signer, _secret) = fixture("cell-a", "author-a");
        let legacy_payload = b"pre-migration raw signal bytes".to_vec();
        let decoded =
            decode_signal_segment_payload(&legacy_payload, &group).expect("read-compat decode");
        assert_eq!(decoded, legacy_payload);
    }

    /// A non-member — anyone without the cell group key — cannot open a
    /// cell-sealed `Signal` body.
    #[test]
    fn non_member_cannot_open_cell_sealed_signal() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"secret signal".to_vec();
        let msg = seal_signal(&payload, &group, cell, signer, &secret, Visibility::Cell)
            .expect("seal");

        let wrong_group =
            group_key_from_seed(&Seed::from_bytes(b"cell-b".to_vec())).expect("wrong cell key");
        assert!(
            open_signal(&msg, &wrong_group).is_err(),
            "wrong cell key must not open the sealed body"
        );
    }

    /// A signal envelope and a streamdb op sealed with the SAME payload under
    /// the SAME cell key are NOT byte-identical — the per-record-class domain
    /// separator ([`SIGNAL_SEAL_DOMAIN`] vs streamdb's `stream-op-v1`) keeps the
    /// convergent-equality leak scoped, so the shared substrate never conflates
    /// the two record classes.
    #[test]
    fn signal_and_streamdb_op_do_not_collide_on_the_shared_substrate() {
        let (group, cell, signer, secret) = fixture("cell-a", "author-a");
        let payload = b"identical bytes".to_vec();

        let signal_env = encode_signal_segment_payload(
            &payload,
            &group,
            cell.clone(),
            signer.clone(),
            &secret,
            Visibility::Cell,
        )
        .expect("seal signal");
        let op_env = pillar_streamdb_pillarmsg_encode(
            &payload,
            &group,
            cell,
            signer,
            &secret,
            Visibility::Cell,
        );

        assert_ne!(
            pillar_wire::Cid::of(&signal_env),
            pillar_wire::Cid::of(&op_env),
            "distinct record-class seal domains must not converge to the same Cid"
        );
    }

    // Locally reproduce a streamdb-op seal WITHOUT depending on the
    // `pillar-streamdb` crate (this crate depends on pillar-wire only): reuse
    // the wire primitives with streamdb's own `stream-op-v1` domain separator
    // and `Body::StreamOp` to prove the two classes stay distinct.
    fn pillar_streamdb_pillarmsg_encode(
        payload: &[u8],
        group: &CellGroupKey,
        cell: CellId,
        signer: SigningPublicKey,
        secret: &SigningSecretKey,
        visibility: Visibility,
    ) -> Vec<u8> {
        const STREAM_OP_SEAL_DOMAIN: &[u8] = b"pillar-streamdb/stream-op-v1";
        let body = Body::StreamOp(payload.to_vec());
        let plaintext = body.to_canonical_cbor().expect("cbor");
        let aad = PillarMessage::header_aad(visibility, &cell);
        let body_sealed =
            cell_seal_convergent(group, &plaintext, STREAM_OP_SEAL_DOMAIN, &aad).expect("seal");
        let signature =
            sign(secret, &PillarMessage::signing_material(&body_sealed)).expect("sign");
        PillarMessage::new(signer, signature, visibility, cell, body_sealed)
            .to_canonical_cbor()
            .expect("encode")
    }
}
