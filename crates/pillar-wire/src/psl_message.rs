//! The ONE PSL/obs query `PillarMessage` contract (`psl-message-api`,
//! 2026-09-09 ROI HEAD): a single shared request/response wire shape for the
//! PSL live-observability query surface, ridden by BOTH clients that speak to
//! a running `pillar node run` process:
//!
//! - the CLI (native), over whichever transport tier
//!   [`pillar_net::pillar_udp_posture`] prefers for the link (pillar-UDP ->
//!   QUIC -> HTTPS, falling back down the list as tiers go unreachable), and
//! - the Yew web UI (WASM), which always rides HTTPS (no raw-UDP/QUIC socket
//!   access from a browser sandbox; a future WebTransport tier slots in here
//!   without changing this contract).
//!
//! This SUPERSEDES the plaintext line-protocol the CLI's `/portal/obs/live/
//! query` HTTP path used ad hoc (`SIGNAL <id> KIND <kind> ... PAYLOAD ...`
//! text lines) for any NEW transport tier: every tier now serializes the
//! SAME [`PslQueryRequest`]/[`PslQueryResponse`] pair as canonical CBOR, so
//! the CLI and the UI can never drift on what a query means or how its
//! result is shaped — one contract, three tiers, one server-side query
//! engine (`pillar_observability::psl`) underneath.
//!
//! This crate (`pillar-wire`) owns only the WIRE SHAPE + its canonical CBOR
//! codec, matching this crate's charter as the shared-substrate crate for
//! every byte Pillar transmits. It deliberately does NOT depend on
//! `pillar-observability` (a downstream crate) or know how to actually RUN a
//! PSL query — a server binds these types to the real query engine
//! (`pillar-cli`'s `web_serve::WebAuthContext`), and the wire `kind` tag here
//! is a plain string mirroring `pillar_cli`'s existing `signal_kind_tag`
//! rendering, not a `pillar_observability::SignalKind` value.

use serde::{Deserialize, Serialize};

/// A PSL/obs query request: an admitted session token (mirrors the
/// `/portal/obs/live/query` text-framing's `<token>\n<psl-text>` gate, now a
/// structured field instead of a line prefix) plus the raw PSL query text
/// (`pillar_observability::parse_psl` remains the ONE parser; this contract
/// never re-implements PSL parsing on the wire).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PslQueryRequest {
    /// The caller's admitted session token, checked server-side exactly as
    /// the existing HTTP text-framed path checks it.
    pub token: String,
    /// The raw PSL query text, e.g. `select * where kind=metric range 5m`.
    pub query_text: String,
}

/// One matched signal row, structurally identical to the fields the existing
/// text rendering emits (`SIGNAL <id> KIND <kind> TICK <tick> TS <ts> LABELS
/// <k=v;...> PAYLOAD <payload>`) but as typed CBOR fields instead of an
/// escaped text line — so a client parses a value, never a string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PslSignalRow {
    /// The signal's content-addressed id, hex-encoded (matches the existing
    /// text rendering's `<id>` and the `GROUP ... MEMBERS <id,...>` hex
    /// form).
    pub id: String,
    /// The signal kind tag (`metric`, `log`, `trace_span`, `profile_sample`,
    /// `metadata_sample`) — the same tag `signal_kind_tag` renders.
    pub kind: String,
    /// The store tick the signal was ingested at.
    pub tick: u64,
    /// The signal's wall-clock timestamp in Unix millis, when known.
    pub unix_millis: Option<u64>,
    /// The signal's labels as ordered key/value pairs.
    pub labels: Vec<(String, String)>,
    /// The signal's payload (already the same string the text rendering
    /// escapes into `PAYLOAD <payload>` — this contract carries it raw,
    /// un-escaped, since CBOR needs no line-based escaping).
    pub payload: String,
}

/// One correlate group, structurally identical to a `GROUP <anchor> MEMBERS
/// <id,id,...>` text line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PslCorrelateGroup {
    /// The anchor signal id (hex).
    pub anchor: String,
    /// The member signal ids (hex), including the anchor.
    pub members: Vec<String>,
}

/// The successful result of a PSL query: the matched rows plus any correlate
/// groups, exactly mirroring what `WebAuthContext::live_obs_psl`'s text
/// rendering carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PslQueryResult {
    /// The matched signal rows.
    pub rows: Vec<PslSignalRow>,
    /// Any correlate groups the query's `correlate` clause produced.
    pub groups: Vec<PslCorrelateGroup>,
}

/// A PSL/obs query response: either the real result, or a structured error
/// (a PSL parse error, or the caller's session was not admitted) — never a
/// bare HTTP status code a caller must interpret differently per transport
/// tier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PslQueryResponse {
    /// The query executed; here is its result (possibly empty).
    Ok(PslQueryResult),
    /// The caller's session token was not admitted (mirrors the HTTP path's
    /// 401 `DENIED`).
    Unauthorized,
    /// The query failed to parse/execute; carries the same message
    /// `pillar_observability::parse_psl`/`psl_query` would have produced.
    Error(String),
}

/// A codec error: the bytes were not valid canonical CBOR for the expected
/// type.
#[derive(Debug)]
pub struct PslMessageCodecError(pub String);

impl std::fmt::Display for PslMessageCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "psl-message codec error: {}", self.0)
    }
}
impl std::error::Error for PslMessageCodecError {}

/// Encode a [`PslQueryRequest`] as canonical CBOR bytes — the ONE encoding
/// every transport tier (pillar-UDP datagram, QUIC stream, HTTPS body) uses.
pub fn encode_request(req: &PslQueryRequest) -> Result<Vec<u8>, PslMessageCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).map_err(|e| PslMessageCodecError(e.to_string()))?;
    Ok(buf)
}

/// Decode a [`PslQueryRequest`] from canonical CBOR bytes.
pub fn decode_request(bytes: &[u8]) -> Result<PslQueryRequest, PslMessageCodecError> {
    ciborium::from_reader(bytes).map_err(|e| PslMessageCodecError(e.to_string()))
}

/// Encode a [`PslQueryResponse`] as canonical CBOR bytes.
pub fn encode_response(resp: &PslQueryResponse) -> Result<Vec<u8>, PslMessageCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(resp, &mut buf).map_err(|e| PslMessageCodecError(e.to_string()))?;
    Ok(buf)
}

/// Decode a [`PslQueryResponse`] from canonical CBOR bytes.
pub fn decode_response(bytes: &[u8]) -> Result<PslQueryResponse, PslMessageCodecError> {
    ciborium::from_reader(bytes).map_err(|e| PslMessageCodecError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_canonical_cbor() {
        let req = PslQueryRequest {
            token: "tok-123".to_owned(),
            query_text: "select * where kind=metric range 5m".to_owned(),
        };
        let bytes = encode_request(&req).expect("encode");
        let back = decode_request(&bytes).expect("decode");
        assert_eq!(req, back);
    }

    #[test]
    fn response_round_trips_ok_variant() {
        let resp = PslQueryResponse::Ok(PslQueryResult {
            rows: vec![PslSignalRow {
                id: "abc123".to_owned(),
                kind: "metric".to_owned(),
                tick: 7,
                unix_millis: Some(42),
                labels: vec![("service".to_owned(), "pillar".to_owned())],
                payload: "1.0".to_owned(),
            }],
            groups: vec![PslCorrelateGroup {
                anchor: "abc123".to_owned(),
                members: vec!["abc123".to_owned(), "def456".to_owned()],
            }],
        });
        let bytes = encode_response(&resp).expect("encode");
        let back = decode_response(&bytes).expect("decode");
        assert_eq!(resp, back);
    }

    #[test]
    fn response_round_trips_unauthorized_and_error_variants() {
        for resp in [
            PslQueryResponse::Unauthorized,
            PslQueryResponse::Error("PSL-PARSE bad token".to_owned()),
        ] {
            let bytes = encode_response(&resp).expect("encode");
            let back = decode_response(&bytes).expect("decode");
            assert_eq!(resp, back);
        }
    }
}
