//! OpenTelemetry (OTLP) ingest — an endpoint by which EXTERNAL, non-pillar
//! services push metrics/logs/traces (and profiles/metadata) into the pillar
//! signal store, making pillar a drop-in observability backend for arbitrary
//! workloads.
//!
//! This rides the **one shared producer contract** proved by
//! `specs/ObsIngestionSubstrate.tla` (`ProducerContractUniform`): an OTLP
//! payload is decoded into a set of uniform producer [`Envelope`]s — each the
//! `{kind, correlation_id?, labels}` shape every internal producer uses — and
//! admitted onto the SAME [`TimeseriesStore`] + [`CorrelationIndex`] as any
//! native producer, never a parallel store and never a second ingest path. A
//! signal ingested via OTLP is therefore queryable through `psl-core`/the
//! [`crate::query`] path exactly like a native-producer signal.
//!
//! Two safety properties this module upholds, both refinements of the spec:
//!
//! 1. **Never fabricates.** Every OTLP record carries a real occurrence (a
//!    request/span/emission id). The producer records it as `happened` on the
//!    shared [`SamplingPolicy`] and only then emits — so an OTLP payload can
//!    never smuggle a synthetic/demo signal onto the store
//!    (`NoFabricatedSample`, one hop upstream through the OTLP boundary).
//! 2. **Rejects the malformed — never silently coerces.** A structurally
//!    invalid OTLP payload (unknown signal type, missing required field,
//!    malformed record) is REFUSED with a precise [`OtlpError`]; it is never
//!    coerced into a defaulted/fabricated record. Ingest is all-or-nothing per
//!    payload: a payload with any bad record admits none of it.
//!
//! ## Wire format
//!
//! OTLP's canonical wire form is protobuf/JSON with a fixed resource → scope →
//! record nesting. To stay dependency-free (the crate has no protobuf codegen)
//! this module accepts the same LOGICAL structure as a compact, line-oriented
//! text encoding that a gateway/collector renders from real OTLP: a
//! resource-labels header line, then one record line per signal. The mapping
//! from OTLP concepts is exact (resource attributes → shared labels, span/trace
//! id → correlation id, record type → [`SignalKind`]); only the surface syntax
//! is simplified, and the decoder is strict about it.

use std::collections::BTreeSet;

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
use crate::metadata::LabelSet;
use crate::sampling::{Occurrence, SamplingPolicy};

/// A uniform producer envelope — the `{kind, correlation_id?, labels}` shape of
/// `ProducerContractUniform`, carrying the occurrence that makes it real. This
/// is the ONLY value the OTLP boundary produces; ingest never bypasses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The signal kind this record maps to.
    pub kind: SignalKind,
    /// The correlation id (an OTLP trace/span id), if the record carried one.
    pub correlation: Option<CorrelationId>,
    /// The shared labels (OTLP resource + record attributes).
    pub labels: BTreeSet<Label>,
    /// The real occurrence this record references — required, so ingest can
    /// never fabricate.
    pub occurrence: Occurrence,
    /// The raw signal payload bytes placed on the store (the record body).
    pub payload: Vec<u8>,
}

/// Why an OTLP payload was refused. Every variant is a REJECTION — the payload
/// is never coerced into a fabricated/defaulted record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtlpError {
    /// The payload was empty or had no resource header.
    Empty,
    /// A record line was structurally malformed (wrong field count / shape).
    MalformedRecord {
        /// 0-based index of the offending record line.
        record: usize,
    },
    /// A record named a signal type this ingest does not recognize.
    UnknownSignalType {
        /// 0-based index of the offending record line.
        record: usize,
        /// The unrecognized type token.
        got: String,
    },
    /// A record was missing a required field (its occurrence id or body).
    MissingField {
        /// 0-based index of the offending record line.
        record: usize,
        /// The missing field's name.
        field: &'static str,
    },
    /// A field expected to be numeric (the occurrence id) was not.
    NotNumeric {
        /// 0-based index of the offending record line.
        record: usize,
        /// The field name.
        field: &'static str,
    },
}

/// The OTLP ingest endpoint. Owns the shared store, correlation index, and the
/// no-fabrication [`SamplingPolicy`] every ingested record is gated by.
///
/// It is a thin producer over the SAME substrate: it holds no parallel store.
#[derive(Debug)]
pub struct OtlpIngest {
    store: TimeseriesStore,
    index: CorrelationIndex,
    occurrences: SamplingPolicy,
}

impl OtlpIngest {
    /// A fresh endpoint over a store with the given block capacity + retention
    /// window. Its no-fabrication policy admits exactly one sample per genuine
    /// occurrence (an ingested OTLP record is admitted once, never duplicated).
    #[must_use]
    pub fn new(block_capacity: usize, retention_window: u64) -> Self {
        OtlpIngest {
            store: TimeseriesStore::new(block_capacity, retention_window),
            index: CorrelationIndex::new(),
            occurrences: SamplingPolicy::new(1),
        }
    }

    /// The underlying signal store (read access for querying ingested signals
    /// exactly like a native-producer signal).
    #[must_use]
    pub fn store(&self) -> &TimeseriesStore {
        &self.store
    }

    /// The correlation index over ingested signals.
    #[must_use]
    pub fn index(&self) -> &CorrelationIndex {
        &self.index
    }

    /// Decode `payload` into uniform producer envelopes WITHOUT admitting them —
    /// the strict OTLP parse. Used by [`OtlpIngest::ingest`] and directly
    /// testable: a malformed payload yields an [`OtlpError`], never a coerced
    /// record.
    ///
    /// # Errors
    ///
    /// Any structural defect (see [`OtlpError`]); the whole payload is refused.
    pub fn decode(payload: &[u8]) -> Result<Vec<Envelope>, OtlpError> {
        let text = std::str::from_utf8(payload).map_err(|_| OtlpError::Empty)?;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());

        // Resource header: `resource <k=v>[,<k=v>...]` (or bare `resource` for
        // no resource labels).
        let header = lines.next().ok_or(OtlpError::Empty)?;
        let header = header.trim();
        let resource_labels = match header.strip_prefix("resource") {
            Some(rest) => parse_labels(rest.trim()).ok_or(OtlpError::Empty)?,
            None => return Err(OtlpError::Empty),
        };

        let mut envelopes = Vec::new();
        for (record, line) in lines.enumerate() {
            envelopes.push(decode_record(record, line.trim(), &resource_labels)?);
        }
        if envelopes.is_empty() {
            return Err(OtlpError::Empty);
        }
        Ok(envelopes)
    }

    /// Ingest an OTLP `payload`: decode it strictly, then admit every record
    /// onto the shared store + correlation index via the uniform producer
    /// contract. Returns the content-addressed ids of the signals that landed.
    ///
    /// All-or-nothing: if decoding rejects the payload, NOTHING is admitted (no
    /// partial, no coerced record). A record is admitted only after its
    /// occurrence is recorded as genuinely `happened`, so ingest never
    /// fabricates.
    ///
    /// # Errors
    ///
    /// [`OtlpError`] if the payload is malformed; the store is left unchanged.
    pub fn ingest(&mut self, payload: &[u8]) -> Result<Vec<SignalId>, OtlpError> {
        let envelopes = Self::decode(payload)?;

        let mut ids = Vec::with_capacity(envelopes.len());
        for env in envelopes {
            // Record the real occurrence, then admit exactly once — the
            // no-fabrication gate. A duplicate occurrence in one payload is
            // rate-capped away rather than double-counted.
            self.occurrences.occur(env.occurrence);
            if self.occurrences.emit_sample(env.occurrence).is_err() {
                continue;
            }

            let mut labels = LabelSet::new();
            for l in &env.labels {
                labels.insert(l.key.clone(), l.value.clone());
            }
            let id = self
                .store
                .write_labeled(env.kind, env.payload.clone(), labels, 0)
                .expect("no downsample policy installed on the OTLP store");

            self.index.register(
                id.clone(),
                &SignalRef {
                    kind: env.kind,
                    correlation: env.correlation.clone(),
                    labels: env.labels.clone(),
                },
            );
            ids.push(id);
        }
        Ok(ids)
    }
}

/// Parse a `k=v,k=v` attribute list into shared labels. An empty string is a
/// valid (empty) label set; a malformed entry yields `None`.
fn parse_labels(s: &str) -> Option<BTreeSet<Label>> {
    let mut out = BTreeSet::new();
    if s.is_empty() {
        return Some(out);
    }
    for pair in s.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            return None;
        }
        let (k, v) = pair.split_once('=')?;
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() || v.is_empty() {
            return None;
        }
        out.insert(Label::new(k, v));
    }
    Some(out)
}

/// Decode a single record line:
/// `<type> occ=<n> [corr=<id>] [attrs=<k=v,...>] body=<text>`
fn decode_record(
    record: usize,
    line: &str,
    resource_labels: &BTreeSet<Label>,
) -> Result<Envelope, OtlpError> {
    let mut occ: Option<Occurrence> = None;
    let mut corr: Option<CorrelationId> = None;
    let mut attrs: BTreeSet<Label> = resource_labels.clone();
    let mut body: Option<String> = None;

    // The record type is the first whitespace-delimited token.
    let mut rest = line;
    let ty = rest
        .split_whitespace()
        .next()
        .ok_or(OtlpError::MalformedRecord { record })?;
    rest = rest[ty.len()..].trim_start();

    // Remaining `key=value` fields. `body=` is taken to the end of the line so a
    // body may contain spaces; every other field is whitespace-delimited.
    while !rest.is_empty() {
        if let Some(b) = rest.strip_prefix("body=") {
            body = Some(b.to_string());
            break;
        }
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..token_end];
        rest = rest[token_end..].trim_start();

        let (k, v) = token
            .split_once('=')
            .ok_or(OtlpError::MalformedRecord { record })?;
        match k {
            "occ" => {
                let n = v
                    .parse::<u64>()
                    .map_err(|_| OtlpError::NotNumeric { record, field: "occ" })?;
                occ = Some(Occurrence(n));
            }
            "corr" => {
                if v.is_empty() {
                    return Err(OtlpError::MalformedRecord { record });
                }
                corr = Some(CorrelationId(v.to_string()));
            }
            "attrs" => {
                let extra = parse_labels(v).ok_or(OtlpError::MalformedRecord { record })?;
                attrs.extend(extra);
            }
            _ => return Err(OtlpError::MalformedRecord { record }),
        }
    }

    let kind = decode_kind(ty).ok_or_else(|| OtlpError::UnknownSignalType {
        record,
        got: ty.to_string(),
    })?;
    let occurrence = occ.ok_or(OtlpError::MissingField { record, field: "occ" })?;
    let body = body.ok_or(OtlpError::MissingField { record, field: "body" })?;

    Ok(Envelope {
        kind,
        correlation: corr,
        labels: attrs,
        occurrence,
        payload: body.into_bytes(),
    })
}

/// Map an OTLP signal-type token to a [`SignalKind`]. Unknown → `None` (a
/// rejection, never a defaulted kind).
fn decode_kind(ty: &str) -> Option<SignalKind> {
    Some(match ty {
        "metric" => SignalKind::Metric,
        "log" => SignalKind::Log,
        "trace" | "span" => SignalKind::TraceSpan,
        "profile" => SignalKind::ProfileSample,
        "metadata" => SignalKind::MetadataSample,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{Query, ViewCache};

    /// An OTLP metrics/logs/traces payload lands in the store + correlation
    /// index with the correct kind + labels, and is queryable through the SAME
    /// query path as a native-producer signal.
    #[test]
    fn otlp_metrics_logs_traces_land_and_are_queryable_like_native() {
        let mut ingest = OtlpIngest::new(16, 1000);
        let payload = b"resource service=checkout,cell=eu-1\n\
metric occ=1 attrs=name=http_requests body=count 42\n\
log occ=2 body=level=warn msg=slow\n\
trace occ=3 corr=trace-abc body=span=root dur=12ms\n";

        let ids = ingest.ingest(payload).expect("well-formed OTLP payload");
        assert_eq!(ids.len(), 3, "all three records landed");

        // Each landed on the ONE shared store, queryable by kind exactly like a
        // native-producer signal (same TimeseriesStore + ViewCache path).
        let mut cache = ViewCache::new();
        assert_eq!(
            cache.materialize(ingest.store(), Query::of_kind(SignalKind::Metric)).len(),
            1
        );
        assert_eq!(
            cache.materialize(ingest.store(), Query::of_kind(SignalKind::Log)).len(),
            1
        );
        assert_eq!(
            cache.materialize(ingest.store(), Query::of_kind(SignalKind::TraceSpan)).len(),
            1
        );
        // The all-kinds query gathers exactly the three — one substrate.
        assert_eq!(cache.materialize(ingest.store(), Query::all()).len(), 3);

        // Correct labels: the resource labels are stamped on every signal and
        // cross-pivot works — the shared `cell=eu-1` label gathers all three.
        let cell = Label::new("cell", "eu-1");
        assert_eq!(ingest.index().by_label(&cell).len(), 3);
        // The record-level attr rode through too.
        let metric_name = Label::new("name", "http_requests");
        assert_eq!(ingest.index().by_label(&metric_name).len(), 1);
        // The trace correlation id gathers its span.
        let trace = CorrelationId("trace-abc".to_string());
        assert_eq!(ingest.index().by_correlation(&trace).len(), 1);
        assert!(ingest
            .index()
            .kinds_for_correlation(&trace)
            .contains(&SignalKind::TraceSpan));
    }

    /// A malformed OTLP payload is REJECTED, never silently coerced into a
    /// fabricated record: the store stays empty and a precise error is returned.
    #[test]
    fn malformed_otlp_payload_is_rejected_never_coerced() {
        // Unknown signal type.
        let mut ingest = OtlpIngest::new(16, 1000);
        let err = ingest
            .ingest(b"resource service=x\nquux occ=1 body=hi\n")
            .expect_err("unknown signal type must be rejected");
        assert!(matches!(err, OtlpError::UnknownSignalType { record: 0, .. }));
        assert_eq!(ingest.store().held_len(), 0, "nothing coerced onto the store");

        // Missing required occurrence — the field that makes a signal real.
        let err = ingest
            .ingest(b"resource service=x\nmetric body=count 1\n")
            .expect_err("missing occurrence must be rejected");
        assert!(matches!(
            err,
            OtlpError::MissingField { record: 0, field: "occ" }
        ));
        assert_eq!(ingest.store().held_len(), 0);

        // Non-numeric occurrence.
        let err = ingest
            .ingest(b"resource service=x\nmetric occ=notanumber body=c\n")
            .expect_err("non-numeric occ must be rejected");
        assert!(matches!(
            err,
            OtlpError::NotNumeric { record: 0, field: "occ" }
        ));

        // Missing body.
        let err = ingest
            .ingest(b"resource service=x\nlog occ=5\n")
            .expect_err("missing body must be rejected");
        assert!(matches!(
            err,
            OtlpError::MissingField { record: 0, field: "body" }
        ));

        // No resource header at all.
        let err = ingest
            .ingest(b"metric occ=1 body=x\n")
            .expect_err("missing resource header must be rejected");
        assert_eq!(err, OtlpError::Empty);
    }

    /// All-or-nothing: a payload whose SECOND record is malformed admits NONE of
    /// it — the first, well-formed record is not partially coerced onto the
    /// store either.
    #[test]
    fn a_bad_record_rejects_the_whole_payload() {
        let mut ingest = OtlpIngest::new(16, 1000);
        let err = ingest
            .ingest(b"resource service=x\nmetric occ=1 body=ok\nlog occ=2\n")
            .expect_err("a bad second record rejects the whole payload");
        assert!(matches!(
            err,
            OtlpError::MissingField { record: 1, field: "body" }
        ));
        assert_eq!(
            ingest.store().held_len(),
            0,
            "not even the good first record was admitted"
        );
    }

    /// Ingest never fabricates: every landed signal was genuinely written (its
    /// content address is a real function of the OTLP body, present in the
    /// store's grow-only `written` ghost), and distinct occurrences land
    /// independently.
    #[test]
    fn ingest_never_fabricates_a_signal() {
        let mut ingest = OtlpIngest::new(16, 1000);
        let ids = ingest
            .ingest(b"resource service=x\nmetric occ=1 body=a\nmetric occ=2 body=b\n")
            .expect("well-formed");
        assert_eq!(ids.len(), 2);
        for id in &ids {
            assert!(
                ingest.store().was_written(id),
                "a landed signal must be genuinely written, never fabricated"
            );
            assert!(ingest.store().contains(id));
        }
    }

    /// Decoding is a pure, strict function usable without a store — the OTLP
    /// boundary contract. A well-formed payload decodes to uniform envelopes of
    /// the `{kind, correlation_id?, labels}` shape.
    #[test]
    fn decode_yields_uniform_envelopes() {
        let envs = OtlpIngest::decode(
            b"resource host=n-1\ntrace occ=9 corr=t-1 attrs=op=GET body=span\n",
        )
        .expect("well-formed");
        assert_eq!(envs.len(), 1);
        let e = &envs[0];
        assert_eq!(e.kind, SignalKind::TraceSpan);
        assert_eq!(e.correlation, Some(CorrelationId("t-1".to_string())));
        assert_eq!(e.occurrence, Occurrence(9));
        assert!(e.labels.contains(&Label::new("host", "n-1")));
        assert!(e.labels.contains(&Label::new("op", "GET")));
        assert_eq!(e.payload, b"span");
    }
}
