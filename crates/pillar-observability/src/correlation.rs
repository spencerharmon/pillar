//! The shared **correlation spine** — the common label/time/correlation-id
//! model that lets all five signal kinds cross-pivot.
//!
//! Metric, log, trace, profile, and metadata are five distinct kinds on ONE
//! substrate, but they are only useful together if a metric spike, the logs
//! around it, the trace that caused it, the profile taken during it, and the
//! entity metadata in effect at the time can all be pivoted to one another.
//! That pivot is done here, over two shared axes every signal carries:
//!
//! - a **correlation id** — a trace id or an event CID that ties otherwise
//!   independent signals to the same causal thread; and
//! - **shared labels** — the common label dimensions (domain / cell / node /
//!   user / resource + topology tiers) every kind stamps, so signals of any
//!   kinds sharing a label value can be gathered.
//!
//! The metadata signal ([`crate::metadata`]) is the correlation *overlay*: the
//! other four pivot against an entity's labels-in-effect. This module models
//! the id/label indexing that makes both pivots O(matches), not O(all
//! signals).

use std::collections::{BTreeMap, BTreeSet};

use crate::block::{SignalId, SignalKind};

/// A correlation id shared across signals on the same causal thread: a trace
/// id, or a content-addressed event CID. Opaque here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrelationId(pub String);

/// A `(key, value)` shared-label dimension (e.g. `("node", "n-7")`,
/// `("cell", "eu-1")`, `("user", "alice")`). The common dimensions every
/// signal kind stamps so cross-kind pivots by a shared value are possible.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label {
    /// The label dimension name.
    pub key: String,
    /// The label value.
    pub value: String,
}

impl Label {
    /// A shared label dimension.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Label {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// The correlation metadata every signal stamps onto the shared spine: its
/// kind, its correlation id (if any), and its shared labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalRef {
    /// The signal's kind.
    pub kind: SignalKind,
    /// The correlation id tying it to a causal thread, if any.
    pub correlation: Option<CorrelationId>,
    /// The shared label dimensions it stamps.
    pub labels: BTreeSet<Label>,
}

/// The cross-pivot index: registers each signal's correlation id and shared
/// labels, then answers "every signal (of any kind) sharing this correlation
/// id" and "every signal sharing this label" — the join that makes the five
/// kinds one correlated substrate.
#[derive(Clone, Debug, Default)]
pub struct CorrelationIndex {
    by_correlation: BTreeMap<CorrelationId, BTreeSet<SignalId>>,
    by_label: BTreeMap<Label, BTreeSet<SignalId>>,
    kinds: BTreeMap<SignalId, SignalKind>,
    /// The correlation id (if any) each registered signal was stamped with —
    /// the inverse of `by_correlation`, letting a caller (e.g. `psl`) look up
    /// a specific signal's correlation id to find its causal-thread peers.
    correlation_of: BTreeMap<SignalId, CorrelationId>,
}

impl CorrelationIndex {
    /// A fresh, empty index.
    #[must_use]
    pub fn new() -> Self {
        CorrelationIndex::default()
    }

    /// Register `signal` on the spine under its correlation id (if any) and
    /// every shared label it stamps. Idempotent per signal id.
    pub fn register(&mut self, signal: SignalId, spine: &SignalRef) {
        self.kinds.insert(signal.clone(), spine.kind);
        if let Some(cid) = &spine.correlation {
            self.by_correlation
                .entry(cid.clone())
                .or_default()
                .insert(signal.clone());
            self.correlation_of.insert(signal.clone(), cid.clone());
        }
        for label in &spine.labels {
            self.by_label
                .entry(label.clone())
                .or_default()
                .insert(signal.clone());
        }
    }

    /// Every signal (of ANY kind) tied to `correlation` — the trace-id / CID
    /// pivot across kinds.
    #[must_use]
    pub fn by_correlation(&self, correlation: &CorrelationId) -> BTreeSet<SignalId> {
        self.by_correlation
            .get(correlation)
            .cloned()
            .unwrap_or_default()
    }

    /// Every signal (of ANY kind) stamping `label` — the shared-label pivot
    /// across kinds.
    #[must_use]
    pub fn by_label(&self, label: &Label) -> BTreeSet<SignalId> {
        self.by_label.get(label).cloned().unwrap_or_default()
    }

    /// The correlation id `signal` was registered under, if any.
    #[must_use]
    pub fn correlation_of(&self, signal: &SignalId) -> Option<CorrelationId> {
        self.correlation_of.get(signal).cloned()
    }

    /// The distinct signal *kinds* correlated to `correlation` — proves a
    /// pivot genuinely crosses kinds (e.g. a trace id gathering a span AND the
    /// logs AND the profile taken under it).
    #[must_use]
    pub fn kinds_for_correlation(&self, correlation: &CorrelationId) -> BTreeSet<SignalKind> {
        self.by_correlation(correlation)
            .iter()
            .filter_map(|id| self.kinds.get(id).copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeSet<Label> {
        pairs.iter().map(|(k, v)| Label::new(*k, *v)).collect()
    }

    /// A correlation id pivots across DISTINCT signal kinds: a trace span, the
    /// logs, and the profile sample sharing one trace id are all gathered by it.
    #[test]
    fn correlation_id_pivots_across_distinct_kinds() {
        let mut index = CorrelationIndex::new();
        let trace = CorrelationId("trace-abc".to_string());

        index.register(
            SignalId::from_test_seed(1),
            &SignalRef {
                kind: SignalKind::TraceSpan,
                correlation: Some(trace.clone()),
                labels: labels(&[("node", "n-1")]),
            },
        );
        index.register(
            SignalId::from_test_seed(2),
            &SignalRef {
                kind: SignalKind::Log,
                correlation: Some(trace.clone()),
                labels: labels(&[("node", "n-1")]),
            },
        );
        index.register(
            SignalId::from_test_seed(3),
            &SignalRef {
                kind: SignalKind::ProfileSample,
                correlation: Some(trace.clone()),
                labels: labels(&[("node", "n-1")]),
            },
        );
        // An unrelated metric on a different trace is NOT gathered.
        index.register(
            SignalId::from_test_seed(4),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: Some(CorrelationId("trace-other".to_string())),
                labels: labels(&[("node", "n-1")]),
            },
        );

        let gathered = index.by_correlation(&trace);
        assert_eq!(gathered.len(), 3);
        assert!(gathered.contains(&SignalId::from_test_seed(1)));
        assert!(gathered.contains(&SignalId::from_test_seed(2)));
        assert!(gathered.contains(&SignalId::from_test_seed(3)));
        assert!(!gathered.contains(&SignalId::from_test_seed(4)));

        // The pivot genuinely crosses kinds.
        let kinds = index.kinds_for_correlation(&trace);
        assert!(kinds.contains(&SignalKind::TraceSpan));
        assert!(kinds.contains(&SignalKind::Log));
        assert!(kinds.contains(&SignalKind::ProfileSample));
        assert_eq!(kinds.len(), 3);
    }

    /// A shared label pivots across kinds: every signal stamping `node=n-7`,
    /// whatever its kind, is gathered by that label.
    #[test]
    fn shared_label_pivots_across_kinds() {
        let mut index = CorrelationIndex::new();
        let node = Label::new("node", "n-7");

        index.register(
            SignalId::from_test_seed(10),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: None,
                labels: labels(&[("node", "n-7"), ("cell", "eu-1")]),
            },
        );
        index.register(
            SignalId::from_test_seed(11),
            &SignalRef {
                kind: SignalKind::MetadataSample,
                correlation: None,
                labels: labels(&[("node", "n-7")]),
            },
        );
        index.register(
            SignalId::from_test_seed(12),
            &SignalRef {
                kind: SignalKind::Log,
                correlation: None,
                labels: labels(&[("node", "n-99")]),
            },
        );

        let gathered = index.by_label(&node);
        assert_eq!(gathered.len(), 2);
        assert!(gathered.contains(&SignalId::from_test_seed(10)));
        assert!(gathered.contains(&SignalId::from_test_seed(11)));
        assert!(!gathered.contains(&SignalId::from_test_seed(12)));
    }

    /// A signal with no correlation id is still pivotable by its shared labels
    /// (the two axes are independent).
    #[test]
    fn labels_pivot_independently_of_correlation_id() {
        let mut index = CorrelationIndex::new();
        index.register(
            SignalId::from_test_seed(1),
            &SignalRef {
                kind: SignalKind::Metric,
                correlation: None,
                labels: labels(&[("user", "alice")]),
            },
        );
        assert!(index
            .by_correlation(&CorrelationId("none".to_string()))
            .is_empty());
        assert_eq!(index.by_label(&Label::new("user", "alice")).len(), 1);
    }
}
