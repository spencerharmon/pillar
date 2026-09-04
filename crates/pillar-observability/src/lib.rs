//! Built-in distributed observability — the Rust refinement of
//! `specs/Observability.tla`.
//!
//! An observability signal (a metric point, log line, trace span, profiling
//! sample, or metadata sample) is just another append-only, content-addressed
//! event on the existing streaming DB op-log (`pillar_streamdb`). This crate
//! adds — on top of, never forking, that op-log — the three safety properties
//! `Observability.tla` proves, plus the operational surface the ROI P3
//! addendum (2026-08-26) asks for:
//!
//! 1. **Retention/compaction is bounded and lossless** ([`TimeseriesStore`]).
//!    Signals are grouped into *configurable-size immutable timeseries blocks*
//!    (NOT state-stream snapshotting): a block seals at a fixed capacity and is
//!    thereafter never mutated, only dropped whole once every event it holds
//!    has passed its own retention deadline. Retention is implemented now;
//!    resampling/downsampling is explicitly deferred (see [`RETENTION_NOTE`]).
//!    Refines `LogSubsetOfWritten` / `NoLossBeforeExpiry` and the `Compact`
//!    guard (`tick >= expiry[e]`, never early, never for another event).
//!
//! 2. **Metadata sampling never double-counts or fabricates** ([`SamplingPolicy`]).
//!    A sample is admitted only for an occurrence that genuinely `happened`
//!    (`NoFabricatedSample`) and at most `SampleCap` times per occurrence
//!    (`NoDoubleCountSample`).
//!
//! 3. **Read authority via the single RBAC decider** ([`SignalReader`],
//!    [`NodeRoleConfig`]). A peer may materialize/read a signal view only under
//!    a currently-live, fully-fresh capability decided by the SAME
//!    owner-anchored `pillar_wot_authority` decider every other action uses —
//!    composed, never a second authority path. `ReadRequiresAuthority` /
//!    `FailClosedReadUnderStaleView`. Role declarations (subscribe/serve) are
//!    carried as *signed node-role config*, verified against that same decider.
//!
//! Raw queries and their materialized views are served over the message bus
//! with a cache ([`ViewCache`]) keyed on the content-addressed op-set root, so
//! a raw query is recomputed only when the underlying set changed. That same
//! `(query, root)` key generalizes into a **named, durably-persisted**
//! materialized view ([`PersistedMaterializedView`]) that survives a process
//! restart — the resource a Dashboard panel or RecordingRule references by
//! name, reusing this one mechanism rather than a bespoke blob store.

#![forbid(unsafe_code)]

pub mod block;
pub mod correlation;
pub mod ingest;
pub mod metadata;
pub mod otlp;
pub mod profiling;
pub mod query;
pub mod retention;
pub mod role;
pub mod sampling;
pub mod signal_config;
pub mod traces;

pub use block::{Signal, SignalId, SignalKind, TimeseriesBlock, TimeseriesStore, RETENTION_NOTE};
pub use correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
pub use ingest::{MetricKind, MetricSource, MetricsProducer, NodeCounters, NodeMetricSource};
pub use metadata::{
    EntityId, LabelDiff, LabelObservation, LabelSet, LabelTransition, MetadataStore,
};
pub use otlp::{Envelope, OtlpError, OtlpIngest};
pub use profiling::{
    NodeProfileSource, ProfileKind, ProfileReading, ProfileSource, ProfilingProducer,
};
pub use query::{PersistedMaterializedView, Query, ViewCache, ViewPersistError};
pub use retention::{
    EffectiveRetention, LabelSelector, RetentionPolicy, RetentionPolicySet, RetentionPolicySpec,
};
pub use role::{NodeRole, NodeRoleConfig, RoleError, SignedNodeRole};
pub use sampling::{Occurrence, SampleError, SamplingPolicy};
pub use signal_config::{
    default_on, gated_ingest, signal_kind_from_source, signal_source_name, SignalConfigMatrix,
    SignalConfigSpec,
};
pub use traces::{SpanEvent, TraceProducer};

use pillar_core::NodeId;
use pillar_wot_authority::{ActError, FencedActor, WotAuthority};

/// A record of a successful signal-view read — the Rust stand-in for the
/// spec's ghost `lastRead`, letting a test assert `ReadRequiresAuthority`
/// (the reader WAS authoritative at the exact moment it read) and
/// `FailClosedReadUnderStaleView`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadSnapshot {
    /// The reader who materialized the view.
    pub reader: NodeId,
    /// The signal that was read.
    pub signal: SignalId,
    /// The global revocation watermark in effect at the moment of the read
    /// (fencing forces the reader's own watermark to equal this).
    pub watermark: u64,
}

/// A peer that materializes/reads signal views, gated EXACTLY like
/// `pillar_wot_authority::FencedActor::act` — the composed single decider,
/// never a parallel authority path.
///
/// `ReadSignalView` in the spec: the read is enabled only when this reader's
/// fenced watermark is fully caught up (`freshMark[reader] = RevCount`) AND
/// the reader is currently authoritative under that (necessarily current)
/// view. A stale local view fails closed rather than serving an optimistic
/// grant.
#[derive(Clone, Debug, Default)]
pub struct SignalReader {
    actor: FencedActor,
}

impl SignalReader {
    /// A brand-new reader with a maximally-stale (zero) watermark — refuses
    /// every read until it [`refresh`](Self::refresh)es.
    #[must_use]
    pub fn new() -> Self {
        SignalReader {
            actor: FencedActor::new(),
        }
    }

    /// This reader's current local revocation watermark.
    #[must_use]
    pub fn watermark(&self) -> u64 {
        self.actor.watermark()
    }

    /// Catch this reader's fenced view fully up to `authority`'s current
    /// revocation watermark.
    pub fn refresh(&mut self, authority: &WotAuthority) {
        self.actor.refresh(authority);
    }

    /// Attempt to read/materialize `signal`'s view as `reader`.
    ///
    /// Delegates to the SAME `FencedActor::act` revoke-before-act guard the
    /// rest of Pillar uses: succeeds only under a fully-fresh, currently-
    /// authoritative capability. On success returns a [`ReadSnapshot`]
    /// recording that the reader was authoritative at that moment.
    ///
    /// # Errors
    ///
    /// [`ActError::StaleView`] if this reader's watermark lags the current
    /// global one (fail-closed); [`ActError::NotAuthoritative`] if fresh but
    /// `reader` is not authoritative.
    pub fn read_signal_view(
        &self,
        authority: &WotAuthority,
        reader: &NodeId,
        signal: SignalId,
    ) -> Result<ReadSnapshot, ActError> {
        let acted = self.actor.act(authority, reader)?;
        Ok(ReadSnapshot {
            reader: reader.clone(),
            signal,
            watermark: acted.watermark,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId(s.to_string())
    }

    /// `ReadRequiresAuthority`: a fresh, authoritative reader materializes the
    /// view, and the recorded snapshot shows it was authoritative at read time.
    #[test]
    fn fresh_authoritative_reader_may_materialize_a_signal_view() {
        let authority = WotAuthority::new(n("owner"), 3);
        let mut reader = SignalReader::new();
        reader.refresh(&authority);

        let snap = reader
            .read_signal_view(&authority, &n("owner"), SignalId::from_test_seed(7))
            .expect("owner is authoritative and fresh");
        assert_eq!(snap.reader, n("owner"));
        assert_eq!(snap.signal, SignalId::from_test_seed(7));
        assert!(authority.is_authoritative(&snap.reader));
        assert_eq!(snap.watermark, authority.rev_count());
    }

    /// `FailClosedReadUnderStaleView`: a reader whose watermark lags the
    /// current global one is refused with `StaleView` — never served an
    /// optimistic grant — even though it would be authoritative.
    #[test]
    fn stale_reader_fails_closed_even_when_authoritative() {
        let mut authority = WotAuthority::new(n("owner"), 3);
        let mut reader = SignalReader::new();
        reader.refresh(&authority);

        // A revocation bumps the global watermark; the reader does NOT refresh.
        authority.revoke_grant(n("stranger"));
        assert!(reader.watermark() < authority.rev_count());

        let err = reader
            .read_signal_view(&authority, &n("owner"), SignalId::from_test_seed(1))
            .expect_err("stale view must fail closed");
        match err {
            ActError::StaleView { local, current } => {
                assert!(local < current);
            }
            other => panic!("expected StaleView, got {other:?}"),
        }
    }

    /// A fresh reader who is NOT authoritative is refused `NotAuthoritative`
    /// (the read is gated on the real decider, not merely on freshness).
    #[test]
    fn fresh_but_unauthoritative_reader_is_refused() {
        let authority = WotAuthority::new(n("owner"), 3);
        let mut reader = SignalReader::new();
        reader.refresh(&authority);

        let err = reader
            .read_signal_view(&authority, &n("outsider"), SignalId::from_test_seed(3))
            .expect_err("outsider is not authoritative");
        assert!(matches!(err, ActError::NotAuthoritative));
    }

    /// Each of the five DISTINCT signal kinds ingests into the ONE substrate
    /// and reads back — metric, log, trace, profile, metadata — with no
    /// parallel store: every kind is held by the same [`TimeseriesStore`] and
    /// answered by the same query path.
    #[test]
    fn all_five_signal_kinds_ingest_and_read_back_on_one_substrate() {
        let mut store = TimeseriesStore::new(16, 1000);
        let m = store.write(SignalKind::Metric, b"cpu 0.9".to_vec(), 0);
        let l = store.write(SignalKind::Log, b"level=warn msg=hot".to_vec(), 0);
        let t = store.write(SignalKind::TraceSpan, b"span=1 parent=0".to_vec(), 0);
        let p = store.write(SignalKind::ProfileSample, b"stack=a;b;c".to_vec(), 0);
        let d = store.write(
            SignalKind::MetadataSample,
            b"entity=n-1 role=worker".to_vec(),
            0,
        );

        // All five read back from the single store.
        for id in [m, l, t, p, d] {
            assert!(
                store.contains(&id),
                "kind read-back missing on one substrate"
            );
        }
        assert_eq!(store.held_len(), 5);

        // Each kind is independently queryable off the SAME store — no second
        // store, no second query path.
        let mut cache = ViewCache::new();
        for kind in [
            SignalKind::Metric,
            SignalKind::Log,
            SignalKind::TraceSpan,
            SignalKind::ProfileSample,
            SignalKind::MetadataSample,
        ] {
            let view = cache.materialize(&store, Query::of_kind(kind));
            assert_eq!(view.len(), 1, "exactly one signal of each kind read back");
        }
        // The all-kinds query gathers exactly the five, proving one substrate.
        assert_eq!(cache.materialize(&store, Query::all()).len(), 5);
    }

    /// The metadata kind materializes a current-labels view AND a transition
    /// history, and cross-pivots to the other kinds by a shared correlation id
    /// and a shared label — the correlation-overlay role of the fifth kind.
    #[test]
    fn metadata_view_and_cross_pivot_by_correlation_and_label() {
        use correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
        use metadata::{EntityId, LabelObservation, LabelSet, MetadataStore};
        use std::collections::BTreeSet;

        // Metadata: label-set-over-time for an entity.
        let mut meta = MetadataStore::new();
        let entity = EntityId("n-1".to_string());
        let mut set1 = LabelSet::new();
        set1.insert("role".to_string(), "worker".to_string());
        meta.ingest(LabelObservation::new(entity.clone(), set1.clone(), 0));
        let mut set2 = set1.clone();
        set2.insert("role".to_string(), "drained".to_string());
        meta.ingest(LabelObservation::new(entity.clone(), set2.clone(), 5));

        assert_eq!(meta.current_labels(&entity), Some(&set2));
        assert_eq!(meta.transitions(&entity).len(), 2);

        // Cross-pivot: a trace id gathering signals of several kinds, plus a
        // shared node label gathering metric + metadata.
        let mut index = CorrelationIndex::new();
        let trace = CorrelationId("trace-1".to_string());
        let node = Label::new("node", "n-1");
        let with_node: BTreeSet<Label> = std::iter::once(node.clone()).collect();

        index.register(
            SignalId::from_test_seed(1),
            &SignalRef {
                kind: SignalKind::TraceSpan,
                correlation: Some(trace.clone()),
                labels: with_node.clone(),
            },
        );
        index.register(
            SignalId::from_test_seed(2),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: Some(trace.clone()),
                labels: with_node.clone(),
            },
        );
        index.register(
            SignalId::from_test_seed(3),
            &SignalRef {
                kind: SignalKind::MetadataSample,
                correlation: None,
                labels: with_node.clone(),
            },
        );

        assert_eq!(index.by_correlation(&trace).len(), 2);
        assert!(index
            .kinds_for_correlation(&trace)
            .contains(&SignalKind::TraceSpan));
        assert!(index
            .kinds_for_correlation(&trace)
            .contains(&SignalKind::Metric));
        // Shared label crosses kinds including metadata.
        assert_eq!(index.by_label(&node).len(), 3);
    }

    /// A revoked-then-refreshed reader observes the revocation and (if it lost
    /// authority) is refused — the composed decider's own
    /// `NoActionAfterRevocation` fencing is intact for this new action.
    #[test]
    fn refreshed_reader_observes_revocation_of_its_own_grant() {
        let mut authority = WotAuthority::new(n("owner"), 3);
        authority.issue_edge(n("owner"), n("alice"), 2);
        let mut reader = SignalReader::new();
        reader.refresh(&authority);
        assert!(reader
            .read_signal_view(&authority, &n("alice"), SignalId::from_test_seed(9))
            .is_ok());

        authority.revoke_grant(n("alice"));
        reader.refresh(&authority);
        assert!(matches!(
            reader.read_signal_view(&authority, &n("alice"), SignalId::from_test_seed(9)),
            Err(ActError::NotAuthoritative)
        ));
    }
}
