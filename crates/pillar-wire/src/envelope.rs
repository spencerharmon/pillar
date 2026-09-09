//! `PillarMessage` — the one versioned, content-addressed envelope for every
//! byte Pillar persists or transmits (design of record:
//! `docs/papers/pillar-message-format.md`).
//!
//! ```text
//! PillarMessage { version, signer, signature, visibility, cell, body_sealed }
//! Cid = content_address( canonical_cbor(PillarMessage) )
//! ```
//!
//! `body_sealed` is the [`crate::seal::ContentSeal`]-sealed, canonical-CBOR
//! encoding of a [`Body`] variant. Signing covers the ciphertext
//! (`body_sealed`), so signature verification needs no cell key; only
//! decryption does — the two are independent, exactly as the design paper
//! specifies.
//!
//! ## Canonical encoding
//!
//! The envelope and [`Body`] are encoded via `ciborium` with every field
//! serialized **positionally** (as a CBOR array, `#[serde(...)]` untagged
//! struct-as-sequence — `ciborium`'s default for a plain Rust struct/enum) —
//! never as a CBOR map. This sidesteps RFC 8949 §4.2.1's canonical-map-key-
//! sorting question entirely: there are no map keys to sort, so two
//! encoders — on any node, in any implementation — necessarily produce
//! byte-identical output for the same logical value; encoding is a pure,
//! deterministic function of the field values, in field-declaration order,
//! with `ciborium`'s always-shortest-form integer encoding. This is the
//! "canonical (deterministic) CBOR" the task calls for: what canonical form
//! must guarantee (determinism, so the derived [`crate::store::Cid`] is
//! stable across nodes) rather than the specific RFC 8949 map-sorting
//! mechanism (irrelevant when there are no maps).

use serde::{Deserialize, Serialize};

use pillar_crypto::{Ciphertext, CellId, Signature, SigningPublicKey, SurfaceVersion};

use crate::store::{Cid, Visibility};

/// The lowest [`PillarMessage::version`] this build can still read/write.
/// `v1` is the legacy `SignedSegment` length-prefixed compatibility path (see
/// the design paper §7); this crate's canonical-CBOR envelope begins at `v2`.
pub const PILLAR_MESSAGE_MIN_SUPPORTED: SurfaceVersion = SurfaceVersion(1);

/// The highest [`PillarMessage::version`] this build understands.
pub const PILLAR_MESSAGE_MAX_SUPPORTED: SurfaceVersion = SurfaceVersion(2);

/// The canonical-CBOR envelope version this crate produces for a NEW message.
/// (`v1` is read-compat only — see [`PILLAR_MESSAGE_MIN_SUPPORTED`].)
pub const PILLAR_MESSAGE_CURRENT_VERSION: SurfaceVersion = PILLAR_MESSAGE_MAX_SUPPORTED;

fn vis_to_u8(v: Visibility) -> u8 {
    match v {
        Visibility::Public => 0,
        Visibility::Cell => 1,
        Visibility::Sealed => 2,
    }
}

fn vis_from_u8(b: u8) -> Option<Visibility> {
    match b {
        0 => Some(Visibility::Public),
        1 => Some(Visibility::Cell),
        2 => Some(Visibility::Sealed),
        _ => None,
    }
}

/// The wire-shape `ciborium` actually (de)serializes: every field a plain
/// scalar/`Vec<u8>`, so encoding is a pure function of bytes with no
/// dependency on any `pillar-crypto` type deriving `serde` (it does not).
/// Never constructed directly outside this module — [`PillarMessage`] is the
/// public, typed surface; this is purely the canonical codec's shape.
#[derive(Serialize, Deserialize)]
struct WireEnvelope {
    version: u16,
    signer: Vec<u8>,
    signature: Vec<u8>,
    visibility: u8,
    cell: Vec<u8>,
    body_sealed: Vec<u8>,
}

/// A fault decoding a [`PillarMessage`] from canonical-CBOR bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes are not well-formed canonical CBOR for this shape at all
    /// (truncated, wrong type, garbage) — a hard reject, never a negotiation
    /// candidate.
    Malformed,
    /// The bytes decoded cleanly and carry a legible [`SurfaceVersion`], but
    /// it falls outside `[MIN, MAX]` this build supports — most importantly a
    /// version newer than this build knows (see `pillar_crypto::version`).
    UnsupportedVersion(SurfaceVersion),
    /// The decoded `visibility` byte is not one of the known
    /// [`Visibility`] tags.
    UnknownVisibility(u8),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Malformed => f.write_str("malformed PillarMessage (parse error)"),
            EnvelopeError::UnsupportedVersion(v) => {
                write!(f, "unsupported PillarMessage version {v}")
            }
            EnvelopeError::UnknownVisibility(b) => {
                write!(f, "unknown PillarMessage visibility tag {b}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// The one Pillar record — persisted and transmitted (design paper §4).
///
/// `body_sealed` is the [`crate::seal::ContentSeal`]-sealed, canonical-CBOR
/// bytes of a logical [`Body`]; this type does not itself open/seal it (that
/// is [`crate::seal::ContentSeal`]'s job, taking `PillarMessage`'s own
/// [`PillarMessage::signing_material`]/header bytes as AAD) — keeping the
/// envelope's codec independent of which seal implementation is in use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PillarMessage {
    /// Independently-incrementable envelope surface version.
    pub version: SurfaceVersion,
    /// Author identity + signature over `body_sealed`.
    pub signer: SigningPublicKey,
    /// The ed25519 signature over `body_sealed` (see [`Self::signing_material`]).
    pub signature: Signature,
    /// DHT/propagation reach (unchanged semantics from `Visibility`).
    pub visibility: Visibility,
    /// The cell this record's body is sealed to.
    pub cell: CellId,
    /// The [`crate::seal::ContentSeal`]-sealed, canonical-CBOR-encoded
    /// [`Body`]. Never plaintext on disk or wire.
    pub body_sealed: Ciphertext,
}

/// What the sealed body decodes to once a cell node opens it (design paper
/// §4). Each variant carries its inner payload as opaque canonical-CBOR-ready
/// bytes: the concrete `StreamOpBody`/`SignalBody`/`ControlBody` shapes are
/// each owned by the crate that migrates onto this envelope
/// (`streamdb-pillarmsg-migration`, `obs-signal-pillarmsg-ipfs`,
/// `pillar-net-pillarmsg-handshakeless-udp`); `pillar-wire` only needs to
/// carry, address, and dispatch on the tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    /// A streamdb operation (the CRDT op-log payload).
    StreamOp(Vec<u8>),
    /// An observability signal (one of the five kinds).
    Signal(Vec<u8>),
    /// A libp2p control message (opsync/antientropy/blob/gossip), wrapped so
    /// it too rides the envelope.
    Control(Vec<u8>),
}

impl Body {
    /// Canonical-CBOR-encode this body (see the module docs: positional
    /// struct-as-sequence, deterministic, no map-key-sorting question).
    ///
    /// # Errors
    /// Never fails for an in-memory `Body` (`ciborium`'s writer is a
    /// `Vec<u8>`); the `Result` is threaded through for a fallible sink.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|_| EnvelopeError::Malformed)?;
        Ok(out)
    }

    /// Decode a canonical-CBOR-encoded body. `Err(Malformed)` on truncated or
    /// otherwise non-conforming bytes.
    ///
    /// # Errors
    /// [`EnvelopeError::Malformed`] if `bytes` do not decode to a `Body`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        ciborium::from_reader(bytes).map_err(|_| EnvelopeError::Malformed)
    }
}

impl PillarMessage {
    /// Build a new `v2` envelope. The caller has already: canonical-CBOR-
    /// encoded the logical [`Body`], sealed it with a [`crate::seal::ContentSeal`]
    /// (binding [`Self::header_aad`] as AAD), and signed the resulting
    /// ciphertext — this constructor just assembles the stamped record.
    #[must_use]
    pub fn new(
        signer: SigningPublicKey,
        signature: Signature,
        visibility: Visibility,
        cell: CellId,
        body_sealed: Ciphertext,
    ) -> Self {
        PillarMessage {
            version: PILLAR_MESSAGE_CURRENT_VERSION,
            signer,
            signature,
            visibility,
            cell,
            body_sealed,
        }
    }

    /// The associated data a [`crate::seal::ContentSeal`] must bind when
    /// sealing/opening this envelope's body: the header fields OTHER than
    /// the seal output itself (`visibility` + `cell`), so a sealed body can
    /// never be replayed under a different header (a different visibility
    /// class or cell) without failing authentication.
    #[must_use]
    pub fn header_aad(visibility: Visibility, cell: &CellId) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + cell.as_bytes().len());
        aad.push(vis_to_u8(visibility));
        aad.extend_from_slice(cell.as_bytes());
        aad
    }

    /// The exact bytes the author signs: the sealed ciphertext
    /// (`body_sealed`), domain-separated. Signature verification therefore
    /// needs no cell key — only [`Self::open_body`] does — matching the
    /// design paper's "signing is over `body_sealed`" invariant.
    #[must_use]
    pub fn signing_material(body_sealed: &Ciphertext) -> Vec<u8> {
        const DOMAIN: &[u8] = b"pillar-wire/pillar-message/signature-v1";
        let mut m = Vec::with_capacity(DOMAIN.len() + body_sealed.as_bytes().len());
        m.extend_from_slice(DOMAIN);
        m.extend_from_slice(body_sealed.as_bytes());
        m
    }

    /// Verify this envelope's authorship signature over `body_sealed`.
    ///
    /// # Errors
    /// Propagates [`pillar_crypto::sign::verify`]'s error on a tampered or
    /// forged envelope.
    pub fn verify_signature(&self) -> pillar_crypto::Result<()> {
        pillar_crypto::sign::verify(
            &self.signer,
            &Self::signing_material(&self.body_sealed),
            &self.signature,
        )
    }

    /// Canonical-CBOR-encode this envelope (see the module docs).
    ///
    /// # Errors
    /// Never fails for an in-memory `PillarMessage`; threaded through for a
    /// fallible sink.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, EnvelopeError> {
        let wire = WireEnvelope {
            version: self.version.0,
            signer: self.signer.as_bytes().to_vec(),
            signature: self.signature.as_bytes().to_vec(),
            visibility: vis_to_u8(self.visibility),
            cell: self.cell.as_bytes().to_vec(),
            body_sealed: self.body_sealed.as_bytes().to_vec(),
        };
        let mut out = Vec::new();
        ciborium::into_writer(&wire, &mut out).map_err(|_| EnvelopeError::Malformed)?;
        Ok(out)
    }

    /// Decode a canonical-CBOR-encoded envelope, checking its version stamp
    /// against `[PILLAR_MESSAGE_MIN_SUPPORTED, PILLAR_MESSAGE_MAX_SUPPORTED]`.
    ///
    /// A stamped-but-unknown-future version is rejected DISTINCTLY
    /// ([`EnvelopeError::UnsupportedVersion`]) from a parse error
    /// ([`EnvelopeError::Malformed`]), per the design paper §7 / the
    /// `versioning-compat-migration-spec`.
    ///
    /// # Errors
    /// [`EnvelopeError::Malformed`] on truncated/non-conforming bytes;
    /// [`EnvelopeError::UnsupportedVersion`] on an out-of-window version;
    /// [`EnvelopeError::UnknownVisibility`] on an unrecognized visibility tag.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let wire: WireEnvelope =
            ciborium::from_reader(bytes).map_err(|_| EnvelopeError::Malformed)?;
        let version = SurfaceVersion(wire.version);
        version
            .check_supported(PILLAR_MESSAGE_MIN_SUPPORTED, PILLAR_MESSAGE_MAX_SUPPORTED)
            .map_err(|_| EnvelopeError::UnsupportedVersion(version))?;
        let visibility =
            vis_from_u8(wire.visibility).ok_or(EnvelopeError::UnknownVisibility(wire.visibility))?;
        Ok(PillarMessage {
            version,
            signer: SigningPublicKey::from_bytes(wire.signer),
            signature: Signature::from_bytes(wire.signature),
            visibility,
            cell: CellId::from_bytes(wire.cell),
            body_sealed: Ciphertext::from_bytes(wire.body_sealed),
        })
    }

    /// `Cid = content_address(canonical_cbor(PillarMessage))` — design paper
    /// §4.2. A pure function of the envelope's canonical encoding; two nodes
    /// that construct byte-identical envelopes (same version/signer/
    /// signature/visibility/cell/sealed-body) necessarily agree on it.
    ///
    /// # Errors
    /// Propagates [`Self::to_canonical_cbor`]'s (never-in-practice) failure.
    pub fn cid(&self) -> Result<Cid, EnvelopeError> {
        Ok(Cid::of(&self.to_canonical_cbor()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{CellSeal, ContentSeal};
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed};
    use pillar_crypto::Seed;

    fn build_message(body: &Body, cell_seed: &str, signer_seed: &str) -> PillarMessage {
        let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
            .expect("cell key");
        let cell = CellId::from_bytes(format!("cell::{cell_seed}").into_bytes());
        let plaintext = body.to_canonical_cbor().expect("encode body");
        let aad = PillarMessage::header_aad(Visibility::Cell, &cell);
        let body_sealed = CellSeal.seal(&group, &plaintext, &aad).expect("seal");

        let (signer, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(signer_seed.as_bytes().to_vec()))
                .expect("keygen");
        let signature = sign(&secret, &PillarMessage::signing_material(&body_sealed)).expect("sign");

        PillarMessage::new(signer, signature, Visibility::Cell, cell, body_sealed)
    }

    /// The envelope round-trips through canonical CBOR byte-identically, its
    /// `Cid` is deterministic, and its signature verifies.
    #[test]
    fn envelope_round_trips_and_cid_is_deterministic() {
        let body = Body::Signal(b"a signal payload".to_vec());
        let msg = build_message(&body, "cell-a", "author-a");

        let encoded = msg.to_canonical_cbor().expect("encode");
        let decoded = PillarMessage::from_canonical_cbor(&encoded).expect("decode");
        assert_eq!(decoded, msg, "round trip must be byte-for-byte faithful");
        decoded.verify_signature().expect("signature verifies");

        // Two independent encodings of the same logical value produce the
        // SAME bytes -> the same Cid on every node (ContentAddressStable).
        let encoded_again = msg.to_canonical_cbor().expect("encode again");
        assert_eq!(encoded, encoded_again, "canonical encoding is deterministic");
        assert_eq!(
            msg.cid().expect("cid"),
            PillarMessage::from_canonical_cbor(&encoded_again)
                .expect("decode again")
                .cid()
                .expect("cid again"),
            "Cid is a pure function of the canonical encoding"
        );
    }

    /// A single-bit change to any header field changes the `Cid`
    /// (content-address avalanche, same property `store::Cid` already has).
    #[test]
    fn distinct_envelopes_yield_distinct_cids() {
        let body = Body::StreamOp(b"op payload".to_vec());
        let a = build_message(&body, "cell-a", "author-a");
        let b = build_message(&body, "cell-b", "author-a");
        assert_ne!(
            a.cid().expect("cid a"),
            b.cid().expect("cid b"),
            "different cell -> different sealed bytes -> different Cid"
        );
    }

    /// A tampered signature is rejected on verification.
    #[test]
    fn tampered_signature_fails_verification() {
        let body = Body::Control(b"control payload".to_vec());
        let mut msg = build_message(&body, "cell-a", "author-a");
        let mut sig_bytes = msg.signature.as_bytes().to_vec();
        sig_bytes[0] ^= 0x01;
        msg.signature = Signature::from_bytes(sig_bytes);
        assert!(msg.verify_signature().is_err());
    }

    /// A body sealed under the correct cell key + AAD opens back to the exact
    /// plaintext; the wrong header AAD (a different visibility/cell) fails.
    #[test]
    fn body_seal_binds_the_header_as_aad() {
        let body = Body::Signal(b"observability signal".to_vec());
        let msg = build_message(&body, "cell-a", "author-a");

        let group =
            group_key_from_seed(&Seed::from_bytes(b"cell-a".to_vec())).expect("cell key");
        let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
        let opened = CellSeal.open(&group, &msg.body_sealed, &aad).expect("open");
        let decoded_body = Body::from_canonical_cbor(&opened).expect("decode body");
        assert_eq!(decoded_body, body);

        // Wrong AAD (claiming Public instead of Cell) is rejected.
        let wrong_aad = PillarMessage::header_aad(Visibility::Public, &msg.cell);
        assert!(CellSeal.open(&group, &msg.body_sealed, &wrong_aad).is_err());
    }

    /// A stamped-but-unknown-future version is rejected distinctly from a
    /// parse error (mirrors `pillar_crypto::version`'s contract).
    #[test]
    fn unsupported_future_version_is_rejected_distinctly_from_malformed() {
        let body = Body::Signal(b"x".to_vec());
        let msg = build_message(&body, "cell-a", "author-a");
        let mut encoded = msg.to_canonical_cbor().expect("encode");

        // Corrupt to a clearly-truncated buffer -> Malformed.
        let truncated = &encoded[..encoded.len() / 4];
        assert_eq!(
            PillarMessage::from_canonical_cbor(truncated),
            Err(EnvelopeError::Malformed)
        );

        // Re-encode with a future version number -> UnsupportedVersion, not
        // Malformed (decodes cleanly, just an out-of-window version).
        let wire = WireEnvelope {
            version: PILLAR_MESSAGE_MAX_SUPPORTED.0 + 1,
            signer: msg.signer.as_bytes().to_vec(),
            signature: msg.signature.as_bytes().to_vec(),
            visibility: vis_to_u8(msg.visibility),
            cell: msg.cell.as_bytes().to_vec(),
            body_sealed: msg.body_sealed.as_bytes().to_vec(),
        };
        encoded.clear();
        ciborium::into_writer(&wire, &mut encoded).expect("encode future version");
        assert_eq!(
            PillarMessage::from_canonical_cbor(&encoded),
            Err(EnvelopeError::UnsupportedVersion(SurfaceVersion(
                PILLAR_MESSAGE_MAX_SUPPORTED.0 + 1
            )))
        );
    }
}
