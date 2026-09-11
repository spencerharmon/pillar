//! `pillar-ops` — the shared Pillar **op vocabulary**.
//!
//! A mutation to a Pillar cell is not an RPC to a privileged server; it is a
//! signed, cell-sealed [`pillar_wire::PillarMessage`] carrying an **op** that
//! every node applies through the same replay/materialize path. There are two
//! disjoint op families, kept separate because they ride different substrates:
//!
//! - **streamdb CRUD ops** *(this crate)* — create/update/delete of a resource
//!   CRD (`RetentionPolicy`, `ResourceSet`, `Workload`, `CronJob`, …). These
//!   ride the streamdb op-log: the rollup/replay/materialized format whose
//!   `apply`-on-replay yields the resource view.
//! - **tsdb / observability messages** *(owned by `pillar-observability`)* —
//!   the five telemetry signal kinds (metric/log/trace/profile/metadata).
//!   These ride a **different** IPFS block format (time-series blocks, not the
//!   streamdb rollup) and are deliberately NOT modelled here.
//!
//! This crate owns only the streamdb CRUD family, and only its **payload**:
//! the [`ResourceOp`] enum and its deterministic byte codec ([`ResourceOp::encode`]
//! / [`ResourceOp::decode`]). Wrapping the payload into a [`Body::StreamOp`],
//! sealing it to the cell, and signing it are the transport layer's job
//! (`pillar-client`, native) — deliberately not here, so this crate stays
//! dependency-light and **wasm-safe** (only `pillar-manifest` + serde), which
//! is what lets the browser client reuse the exact same op encoding the CLI
//! and node use. The load-bearing property: two producers of the same logical
//! op — the CLI, the node's portal, the browser — emit **byte-identical**
//! payloads, so they content-address to the same streamdb op id and the CRDT
//! op-log dedups them.
//!
//! [`Body::StreamOp`]: https://docs.rs/pillar-wire

use serde::{Deserialize, Serialize};

pub use pillar_manifest::Crd;

/// The codec version prefixed to every encoded [`ResourceOp`] payload so the
/// on-the-wire/on-log format can evolve without ambiguity. Bumped only on a
/// breaking payload-shape change; a decoder rejects any version it does not
/// understand rather than mis-parsing.
pub const OP_CODEC_VERSION: u8 = 1;

/// A CRUD operation on a resource CRD — the streamdb op the CLI, the node's
/// portal, and the browser client all emit identically. Applied by every node
/// on op-log replay to converge the materialized resource view.
///
/// The set is deliberately **generic over kind**: one `Apply` upserts any CRD
/// (a `RetentionPolicy`, a `ResourceSet`, a `Workload`), one `Delete` removes
/// any resource by kind + name. New resource kinds need no new op variant —
/// they ride `Apply`/`Delete` the moment their schema is registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ResourceOp {
    /// Create-or-update: declaratively apply a full CRD body (the CRUD
    /// "upsert"). The node authorizes the signer for this kind's write policy,
    /// then applies the CRD into the resource plane.
    Apply {
        /// The full CRD body to upsert.
        crd: Crd,
    },
    /// Delete a resource identified by its `kind` and `metadata.name`.
    Delete {
        /// The resource kind (e.g. `RetentionPolicy`).
        kind: String,
        /// The resource's `metadata.name`.
        name: String,
    },
}

impl ResourceOp {
    /// The resource kind this op targets — for `Apply`, the CRD's `kind`; for
    /// `Delete`, the named `kind`. The node routes write-policy authorization
    /// on this.
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            ResourceOp::Apply { crd } => &crd.kind,
            ResourceOp::Delete { kind, .. } => kind,
        }
    }

    /// The resource `metadata.name` this op targets.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            ResourceOp::Apply { crd } => &crd.metadata.name,
            ResourceOp::Delete { name, .. } => name,
        }
    }

    /// Encode this op to its deterministic streamdb op payload: a single
    /// [`OP_CODEC_VERSION`] byte followed by the canonical JSON of the op.
    /// Deterministic because every field map in a [`Crd`] is a `BTreeMap`
    /// (serialized in sorted key order) and the op's own fields are fixed —
    /// so two producers of the same logical op emit identical bytes.
    ///
    /// # Errors
    /// [`OpCodecError::Encode`] if serialization fails (not expected for an
    /// in-memory op).
    pub fn encode(&self) -> Result<Vec<u8>, OpCodecError> {
        let json = serde_json::to_vec(self).map_err(|e| OpCodecError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + json.len());
        out.push(OP_CODEC_VERSION);
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode a streamdb op payload produced by [`Self::encode`], checking the
    /// leading codec-version byte.
    ///
    /// # Errors
    /// [`OpCodecError::Empty`] on an empty payload;
    /// [`OpCodecError::UnsupportedVersion`] on an unknown codec version;
    /// [`OpCodecError::Decode`] if the remaining bytes are not a well-formed
    /// [`ResourceOp`].
    pub fn decode(bytes: &[u8]) -> Result<Self, OpCodecError> {
        let (&version, rest) = bytes.split_first().ok_or(OpCodecError::Empty)?;
        if version != OP_CODEC_VERSION {
            return Err(OpCodecError::UnsupportedVersion(version));
        }
        serde_json::from_slice(rest).map_err(|e| OpCodecError::Decode(e.to_string()))
    }
}

/// A fault encoding or decoding a [`ResourceOp`] payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpCodecError {
    /// The payload was empty (no version byte).
    Empty,
    /// The payload's codec-version byte is not one this build understands.
    UnsupportedVersion(u8),
    /// The op could not be serialized.
    Encode(String),
    /// The payload's body is not a well-formed [`ResourceOp`].
    Decode(String),
}

impl std::fmt::Display for OpCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpCodecError::Empty => f.write_str("empty resource-op payload"),
            OpCodecError::UnsupportedVersion(v) => {
                write!(f, "unsupported resource-op codec version {v}")
            }
            OpCodecError::Encode(e) => write!(f, "encoding resource op: {e}"),
            OpCodecError::Decode(e) => write!(f, "decoding resource op: {e}"),
        }
    }
}

impl std::error::Error for OpCodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{Metadata, Value};

    /// The shipped default `metrics-default` RetentionPolicy CRD, as the CLI's
    /// `render defaults` would build it (metrics, 30d window).
    fn metrics_default_crd() -> Crd {
        Crd::new(
            "pillar.dev/v1",
            "RetentionPolicy",
            Metadata::new("metrics-default").with_label("pillar.dev/managed-by", "defaults"),
        )
        .with_spec("signalKind", Value::String("Metric".into()))
        .with_spec("window", Value::Integer(2_592_000))
    }

    #[test]
    fn apply_round_trips_through_the_payload_codec() {
        let op = ResourceOp::Apply {
            crd: metrics_default_crd(),
        };
        let bytes = op.encode().expect("encode");
        assert_eq!(bytes[0], OP_CODEC_VERSION, "version-prefixed");
        let back = ResourceOp::decode(&bytes).expect("decode");
        assert_eq!(back, op, "apply round-trips byte-faithfully");
        assert_eq!(back.kind(), "RetentionPolicy");
        assert_eq!(back.name(), "metrics-default");
    }

    #[test]
    fn delete_round_trips_through_the_payload_codec() {
        let op = ResourceOp::Delete {
            kind: "RetentionPolicy".into(),
            name: "metrics-default".into(),
        };
        let bytes = op.encode().expect("encode");
        let back = ResourceOp::decode(&bytes).expect("decode");
        assert_eq!(back, op);
        assert_eq!(back.kind(), "RetentionPolicy");
        assert_eq!(back.name(), "metrics-default");
    }

    /// The load-bearing property: the SAME logical op encodes to the SAME
    /// bytes every time (and therefore across producers), so it content-
    /// addresses to one streamdb op id and the CRDT op-log dedups it.
    #[test]
    fn encoding_is_deterministic_across_producers() {
        // Two independently-built copies of the same logical op (spec fields
        // inserted in DIFFERENT order to prove the BTreeMap canonicalizes).
        let a = ResourceOp::Apply {
            crd: Crd::new("pillar.dev/v1", "RetentionPolicy", Metadata::new("m"))
                .with_spec("window", Value::Integer(2_592_000))
                .with_spec("signalKind", Value::String("Metric".into())),
        };
        let b = ResourceOp::Apply {
            crd: Crd::new("pillar.dev/v1", "RetentionPolicy", Metadata::new("m"))
                .with_spec("signalKind", Value::String("Metric".into()))
                .with_spec("window", Value::Integer(2_592_000)),
        };
        assert_eq!(
            a.encode().expect("a"),
            b.encode().expect("b"),
            "same logical op -> identical bytes regardless of insert order"
        );
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(ResourceOp::decode(&[]), Err(OpCodecError::Empty));
    }

    #[test]
    fn unknown_codec_version_is_rejected_distinctly() {
        let mut bytes = ResourceOp::Delete {
            kind: "K".into(),
            name: "n".into(),
        }
        .encode()
        .expect("encode");
        bytes[0] = 0xFF;
        assert_eq!(
            ResourceOp::decode(&bytes),
            Err(OpCodecError::UnsupportedVersion(0xFF))
        );
    }

    #[test]
    fn garbage_body_after_a_valid_version_is_a_decode_error() {
        let bytes = [OP_CODEC_VERSION, b'{', b'!'];
        assert!(matches!(
            ResourceOp::decode(&bytes),
            Err(OpCodecError::Decode(_))
        ));
    }
}
