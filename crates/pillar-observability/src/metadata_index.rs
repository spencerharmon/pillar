//! The **metadata index API** — the typeahead / autofill source for the Yew
//! Explore query builders.
//!
//! An Explore builder needs to offer, as a user types, the REAL vocabulary of
//! the observability substrate: which metric series exist, which label KEYS
//! are in use, which VALUES a given key actually takes, and which signals a
//! correlation id ties together. Every one of those answers is derived HERE
//! straight from the live [`TimeseriesStore`] held set (and the
//! [`CorrelationIndex`] for the id pivot) — never from a hardcoded, fabricated,
//! or demo list. The distinction the ROI P0 "Explore typeahead source" item
//! insists on: a label-values lookup returns exactly the values that appear in
//! ingested data and **empty for an unknown key**, never a placeholder set.
//!
//! Because the source of truth is the held set, the index is inherently
//! consistent with what a query would actually match: if the typeahead offers
//! `cell=eu-1`, a query for `cell=eu-1` finds real signals, because the offer
//! came from those same signals. There is no second, drift-prone catalog.
//!
//! Metric NAMES are the distinct values of the conventional `metric` label the
//! metrics producer stamps on every metric signal (see
//! [`crate::ingest::MetricsProducer`]); a metric signal with no `metric` label
//! contributes no name (there is nothing real to offer). Label KEYS and VALUES
//! are enumerated over every held signal's [`crate::LabelSet`], across all
//! kinds, so the Explore builder for any signal kind autofills from the actual
//! dimensions present.

use std::collections::{BTreeSet, BTreeMap};

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::correlation::{CorrelationId, CorrelationIndex};

/// The conventional label key under which the metrics producer records a
/// metric series name (see [`crate::ingest::MetricsProducer::sample`]). The
/// metric-names typeahead is exactly the distinct set of this label's values
/// over held metric signals.
pub const METRIC_NAME_LABEL: &str = "metric";

/// A read-only typeahead index over a [`TimeseriesStore`]'s held signals: the
/// autofill source the Explore builders query for metric names, label keys,
/// label values, and (via a [`CorrelationIndex`]) correlation-id membership.
///
/// It holds no signals of its own — it is a projection built from the live
/// held set, so every answer reflects exactly what is currently ingested.
/// Rebuild it (cheaply) whenever the underlying set changes; it never caches a
/// stale vocabulary.
#[derive(Clone, Debug, Default)]
pub struct MetadataIndex {
    /// Distinct metric series names (values of the `metric` label on held
    /// metric signals), sorted.
    metric_names: BTreeSet<String>,
    /// Distinct label values actually present per label key, across every held
    /// signal of every kind. A key absent here has NO values — the lookup
    /// returns empty, never a placeholder.
    label_values: BTreeMap<String, BTreeSet<String>>,
}

impl MetadataIndex {
    /// Build the typeahead index from the store's currently-held signals.
    ///
    /// Enumerates real data only: a label key/value pair enters the index only
    /// because some held signal actually stamped it, and a metric name enters
    /// only because a held metric signal carried it under the `metric` label.
    /// Nothing is fabricated or seeded.
    #[must_use]
    pub fn from_store(store: &TimeseriesStore) -> Self {
        let mut index = MetadataIndex::default();
        for signal in store.held_signals() {
            for (key, value) in signal.labels() {
                index
                    .label_values
                    .entry(key.clone())
                    .or_default()
                    .insert(value.clone());
                if signal.kind() == SignalKind::Metric && key == METRIC_NAME_LABEL {
                    index.metric_names.insert(value.clone());
                }
            }
        }
        index
    }

    /// Every metric series name present in ingested data, sorted — the metric
    /// typeahead. Empty when no real metric series has been ingested.
    #[must_use]
    pub fn metric_names(&self) -> Vec<String> {
        self.metric_names.iter().cloned().collect()
    }

    /// Every label KEY in use across held signals, sorted — the label-key
    /// typeahead. Empty when nothing labeled has been ingested.
    #[must_use]
    pub fn label_keys(&self) -> Vec<String> {
        self.label_values.keys().cloned().collect()
    }

    /// The label VALUES actually present for `key`, sorted — the label-value
    /// typeahead.
    ///
    /// Returns ONLY values that appear in ingested data for `key`. An unknown
    /// key (never stamped by any held signal) returns an EMPTY list, never a
    /// fabricated/placeholder set — the exact contract the Explore builders
    /// rely on to avoid offering a value that would match nothing.
    #[must_use]
    pub fn label_values(&self, key: &str) -> Vec<String> {
        self.label_values
            .get(key)
            .map(|vs| vs.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether `key` is a known label key (some held signal stamped it). A
    /// convenience over [`label_values`](Self::label_values) being non-empty.
    #[must_use]
    pub fn has_label_key(&self, key: &str) -> bool {
        self.label_values.contains_key(key)
    }

    /// Correlation-id lookup: every signal tied to `correlation`, delegated to
    /// the shared [`CorrelationIndex`] (the ONE cross-pivot spine) so the
    /// typeahead's id lookup and a real cross-kind pivot agree by construction.
    /// Empty for an unknown correlation id.
    #[must_use]
    pub fn signals_for_correlation(
        correlation: &CorrelationId,
        index: &CorrelationIndex,
    ) -> BTreeSet<SignalId> {
        index.by_correlation(correlation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::SignalKind;
    use crate::correlation::{CorrelationId, CorrelationIndex, Label, SignalRef};
    use crate::ingest::{MetricKind, MetricsProducer, MetricSource};
    use crate::metadata::LabelSet;
    use std::collections::BTreeMap;

    fn labels(pairs: &[(&str, &str)]) -> LabelSet {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A deterministic real source: genuine readings for exactly the metrics it
    /// was given, `None` otherwise (no fabrication).
    #[derive(Default)]
    struct FixedSource {
        readings: BTreeMap<MetricKind, u64>,
    }
    impl FixedSource {
        fn with(mut self, m: MetricKind, v: u64) -> Self {
            self.readings.insert(m, v);
            self
        }
    }
    impl MetricSource for FixedSource {
        fn read(&self, metric: MetricKind) -> Option<u64> {
            self.readings.get(&metric).copied()
        }
    }

    /// A label-values lookup for a real key returns ONLY the values actually
    /// present in ingested data for that key — never a fabricated superset.
    /// FAILS without the index deriving values from the live held set.
    #[test]
    fn label_values_returns_only_values_present_in_ingested_data() {
        let mut store = TimeseriesStore::new(64, 10_000);
        // Real ingested signals stamping the `cell` dimension with two values.
        store.write_labeled(
            SignalKind::Log,
            b"a".to_vec(),
            labels(&[("cell", "eu-1"), ("node", "n-1")]),
            0,
        );
        store.write_labeled(
            SignalKind::Metric,
            b"b".to_vec(),
            labels(&[("cell", "us-2"), ("metric", "node_cpu_ticks")]),
            0,
        );
        // A second signal reusing an existing cell value must not duplicate it.
        store.write_labeled(
            SignalKind::TraceSpan,
            b"c".to_vec(),
            labels(&[("cell", "eu-1")]),
            0,
        );

        let index = MetadataIndex::from_store(&store);
        // Exactly the two real values for `cell`, sorted, de-duplicated.
        assert_eq!(index.label_values("cell"), vec!["eu-1", "us-2"]);
        // NOT a fabricated value that was never ingested.
        assert!(!index.label_values("cell").contains(&"ap-3".to_string()));
    }

    /// An UNKNOWN label key returns an EMPTY list — never a placeholder list.
    /// This is the core anti-fabrication contract of the typeahead source.
    #[test]
    fn unknown_label_key_returns_empty_never_a_placeholder() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::Log,
            b"x".to_vec(),
            labels(&[("cell", "eu-1")]),
            0,
        );
        let index = MetadataIndex::from_store(&store);

        assert!(index.label_values("nonexistent-key").is_empty());
        assert!(!index.has_label_key("nonexistent-key"));
        // A key that IS present is reported as such (contrast).
        assert!(index.has_label_key("cell"));
        assert_eq!(index.label_values("cell"), vec!["eu-1"]);
    }

    /// Metric NAMES come from the real `metric` label the producer stamps, and
    /// only from genuinely-ingested metric series — never a static list. A
    /// metric the source cannot observe contributes no name.
    #[test]
    fn metric_names_are_the_real_ingested_series_only() {
        // A source that genuinely observes exactly two of the named metrics.
        let source = FixedSource::default()
            .with(MetricKind::Cpu, 42)
            .with(MetricKind::RequestCount, 7);
        let producer = MetricsProducer::new(source);
        let mut store = TimeseriesStore::new(64, 10_000);
        assert_eq!(producer.sample(&mut store, 0), 2);

        let index = MetadataIndex::from_store(&store);
        let names = index.metric_names();
        assert_eq!(
            names,
            vec![
                MetricKind::Cpu.name().to_string(),
                MetricKind::RequestCount.name().to_string(),
            ]
        );
        // The four unobserved metrics contribute NO fabricated name.
        for m in [
            MetricKind::Mem,
            MetricKind::StreamdbOps,
            MetricKind::P2pPeers,
            MetricKind::IngestBytes,
        ] {
            assert!(!names.contains(&m.name().to_string()));
        }
    }

    /// Label KEYS enumerate every dimension present across held signals of any
    /// kind, sorted and de-duplicated — the label-key typeahead.
    #[test]
    fn label_keys_enumerate_every_present_dimension() {
        let mut store = TimeseriesStore::new(64, 10_000);
        store.write_labeled(
            SignalKind::Log,
            b"a".to_vec(),
            labels(&[("cell", "eu-1"), ("node", "n-1")]),
            0,
        );
        store.write_labeled(
            SignalKind::Metric,
            b"b".to_vec(),
            labels(&[("metric", "node_mem_bytes"), ("node", "n-2")]),
            0,
        );
        let index = MetadataIndex::from_store(&store);
        assert_eq!(index.label_keys(), vec!["cell", "metric", "node"]);
    }

    /// An empty store offers an empty vocabulary — no fabricated defaults.
    #[test]
    fn empty_store_offers_no_fabricated_vocabulary() {
        let store = TimeseriesStore::new(8, 100);
        let index = MetadataIndex::from_store(&store);
        assert!(index.metric_names().is_empty());
        assert!(index.label_keys().is_empty());
        assert!(index.label_values("cell").is_empty());
    }

    /// Correlation-id lookup returns the real signal set the shared spine ties
    /// to that id, and empty for an unknown id.
    #[test]
    fn correlation_lookup_returns_real_membership_and_empty_for_unknown() {
        let mut ci = CorrelationIndex::new();
        let trace = CorrelationId("trace-1".to_string());
        let node: BTreeSet<Label> = std::iter::once(Label::new("node", "n-1")).collect();
        ci.register(
            SignalId::from_test_seed(1),
            &SignalRef {
                kind: SignalKind::TraceSpan,
                correlation: Some(trace.clone()),
                labels: node.clone(),
            },
        );
        ci.register(
            SignalId::from_test_seed(2),
            &SignalRef {
                kind: SignalKind::Log,
                correlation: Some(trace.clone()),
                labels: node.clone(),
            },
        );

        let hit = MetadataIndex::signals_for_correlation(&trace, &ci);
        assert_eq!(hit.len(), 2);
        assert!(hit.contains(&SignalId::from_test_seed(1)));

        let miss = MetadataIndex::signals_for_correlation(
            &CorrelationId("no-such-trace".to_string()),
            &ci,
        );
        assert!(miss.is_empty());
    }
}
