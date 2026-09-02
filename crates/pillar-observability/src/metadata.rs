//! The **metadata** signal kind — a *label-set-over-time* signal with NO
//! numeric value.
//!
//! This is the novel fifth signal kind the ROI P3 rework asks for, not found
//! in Prometheus/Loki/Jaeger/pprof. It generalizes the info-metric
//! anti-pattern (`node_info`/`*_info`/kube-state-metrics: a metric pinned to a
//! constant value purely so its *labels* carry the real payload) by making the
//! payload itself the label set for an entity — the observable of interest
//! being *WHEN the labels change*.
//!
//! Like the other four signal kinds it is timeseries-class: label-set
//! observations are **append-only, immutable** samples on the same substrate
//! (see [`crate::TimeseriesStore`]). On top of that append-only history this
//! module materializes two derived views per entity:
//!
//! 1. a **current labels** view — the label set in effect *now* for an entity
//!    (the latest observation), the direct analog of the info-metric's current
//!    value but as a first-class query rather than a scrape-time constant; and
//! 2. a **transition history** — every time an entity's label set *changed*
//!    and to what, with the diff (added / removed / changed keys) between each
//!    consecutive distinct observation.
//!
//! A repeated observation identical to the entity's current labels is NOT a
//! transition (the labels did not change), so the history records genuine
//! change points only — never a spurious transition per sample. This makes
//! "when did this entity's labels change, and to what?" a first-class query.

use std::collections::BTreeMap;

/// The identity of an entity whose label set evolves over time (a node, a
/// user, a resource, a cell, …). Opaque here — any stable string key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId(pub String);

/// An immutable label set: an ordered key→value map. Ordering makes two label
/// sets with the same pairs compare equal regardless of insertion order, so a
/// re-observation in a different key order is correctly NOT a change.
pub type LabelSet = BTreeMap<String, String>;

/// A single, immutable label-set observation for an entity at a logical tick —
/// the append-only unit of the metadata signal (payload = the label set; there
/// is deliberately no numeric value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelObservation {
    entity: EntityId,
    labels: LabelSet,
    tick: u64,
}

impl LabelObservation {
    /// A label-set observation for `entity` at `tick`.
    #[must_use]
    pub fn new(entity: EntityId, labels: LabelSet, tick: u64) -> Self {
        LabelObservation {
            entity,
            labels,
            tick,
        }
    }

    /// The observed entity.
    #[must_use]
    pub fn entity(&self) -> &EntityId {
        &self.entity
    }

    /// The observed label set.
    #[must_use]
    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    /// The logical tick of the observation.
    #[must_use]
    pub fn tick(&self) -> u64 {
        self.tick
    }
}

/// The diff between two consecutive distinct label sets of one entity: which
/// keys were added, removed, or had their value changed. The heart of the
/// transition-history answer ("…and to what?").
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LabelDiff {
    /// Keys present in the new set but not the old (`key`→`new value`).
    pub added: BTreeMap<String, String>,
    /// Keys present in the old set but not the new (`key`→`old value`).
    pub removed: BTreeMap<String, String>,
    /// Keys present in both but with a changed value (`key`→`(old, new)`).
    pub changed: BTreeMap<String, (String, String)>,
}

impl LabelDiff {
    /// The diff turning `old` into `new`.
    #[must_use]
    pub fn between(old: &LabelSet, new: &LabelSet) -> Self {
        let mut diff = LabelDiff::default();
        for (k, nv) in new {
            match old.get(k) {
                None => {
                    diff.added.insert(k.clone(), nv.clone());
                }
                Some(ov) if ov != nv => {
                    diff.changed.insert(k.clone(), (ov.clone(), nv.clone()));
                }
                Some(_) => {}
            }
        }
        for (k, ov) in old {
            if !new.contains_key(k) {
                diff.removed.insert(k.clone(), ov.clone());
            }
        }
        diff
    }

    /// Whether this diff records any actual change.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// A single recorded label-set transition for an entity: the tick it occurred,
/// the resulting label set, and the diff from the previous set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelTransition {
    /// The tick at which the entity's labels changed.
    pub tick: u64,
    /// The label set in effect *after* this transition.
    pub labels: LabelSet,
    /// What changed relative to the previous label set (empty `removed`/
    /// `changed` for the entity's first-ever observation — everything is
    /// `added`).
    pub diff: LabelDiff,
}

/// The materialized metadata signal: the append-only observation history plus
/// the two derived views (current labels per entity, transition history per
/// entity).
///
/// It ingests immutable [`LabelObservation`]s (timeseries-class, append-only)
/// and derives, without ever mutating past observations:
/// - [`current_labels`](Self::current_labels): the entity's label set now.
/// - [`transitions`](Self::transitions): every genuine change point + diff.
///
/// A re-observation identical to the current labels is a no-op transition-wise
/// (the labels did not change) — history holds real change points only.
#[derive(Clone, Debug, Default)]
pub struct MetadataStore {
    /// Latest (current) label set per entity.
    current: BTreeMap<EntityId, LabelSet>,
    /// Ordered change history per entity.
    history: BTreeMap<EntityId, Vec<LabelTransition>>,
}

impl MetadataStore {
    /// A fresh, empty metadata store.
    #[must_use]
    pub fn new() -> Self {
        MetadataStore::default()
    }

    /// Ingest an immutable label-set observation.
    ///
    /// Records a transition only if the observed labels DIFFER from the
    /// entity's current labels (or the entity has never been observed). A
    /// re-observation of the same labels advances no history — the observable
    /// of interest is *when the labels change*, so an unchanged sample is not
    /// a change. Returns the recorded [`LabelTransition`] if this observation
    /// was a genuine change, else `None`.
    pub fn ingest(&mut self, obs: LabelObservation) -> Option<LabelTransition> {
        let LabelObservation {
            entity,
            labels,
            tick,
        } = obs;
        let previous = self.current.get(&entity);
        let diff = match previous {
            Some(prev) => LabelDiff::between(prev, &labels),
            None => LabelDiff::between(&LabelSet::new(), &labels),
        };
        // First-ever observation with an empty label set, or a re-observation
        // of identical labels: no change point.
        if diff.is_empty() {
            self.current.entry(entity).or_insert(labels);
            return None;
        }
        let transition = LabelTransition {
            tick,
            labels: labels.clone(),
            diff,
        };
        self.current.insert(entity.clone(), labels);
        self.history
            .entry(entity)
            .or_default()
            .push(transition.clone());
        Some(transition)
    }

    /// The entity's label set in effect NOW (the latest observation), if it has
    /// ever been observed — the materialized "current labels" view.
    #[must_use]
    pub fn current_labels(&self, entity: &EntityId) -> Option<&LabelSet> {
        self.current.get(entity)
    }

    /// The entity's full transition history: every time its labels changed and
    /// to what (with the diff), in chronological order. Empty for an entity
    /// with at most one distinct label set.
    #[must_use]
    pub fn transitions(&self, entity: &EntityId) -> &[LabelTransition] {
        self.history.get(entity).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Every entity currently known to the store.
    pub fn entities(&self) -> impl Iterator<Item = &EntityId> {
        self.current.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(s: &str) -> EntityId {
        EntityId(s.to_string())
    }

    fn labels(pairs: &[(&str, &str)]) -> LabelSet {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Metadata is a label-set-over-time signal with NO numeric value: an
    /// observation carries only an entity and its label set, and materializes
    /// a "current labels" view per entity.
    #[test]
    fn materializes_a_current_labels_view_per_entity() {
        let mut store = MetadataStore::new();
        store.ingest(LabelObservation::new(
            e("node-1"),
            labels(&[("role", "worker"), ("zone", "a")]),
            0,
        ));
        store.ingest(LabelObservation::new(
            e("node-2"),
            labels(&[("role", "control"), ("zone", "b")]),
            0,
        ));

        assert_eq!(
            store.current_labels(&e("node-1")),
            Some(&labels(&[("role", "worker"), ("zone", "a")]))
        );
        assert_eq!(
            store.current_labels(&e("node-2")),
            Some(&labels(&[("role", "control"), ("zone", "b")]))
        );
        assert_eq!(store.current_labels(&e("unknown")), None);
    }

    /// The transition-history query returns every label change plus its diff —
    /// "when did this entity's labels change, and to what?"
    #[test]
    fn transition_history_records_every_change_with_its_diff() {
        let mut store = MetadataStore::new();
        let entity = e("node-1");
        store.ingest(LabelObservation::new(
            entity.clone(),
            labels(&[("role", "worker"), ("zone", "a")]),
            0,
        ));
        // Change: zone a->b, add "tier", remove nothing.
        store.ingest(LabelObservation::new(
            entity.clone(),
            labels(&[("role", "worker"), ("zone", "b"), ("tier", "hot")]),
            5,
        ));
        // Change: drop "tier".
        store.ingest(LabelObservation::new(
            entity.clone(),
            labels(&[("role", "worker"), ("zone", "b")]),
            9,
        ));

        let transitions = store.transitions(&entity);
        assert_eq!(transitions.len(), 3);

        // First transition = the entity's first observation (all added).
        assert_eq!(transitions[0].tick, 0);
        assert_eq!(transitions[0].diff.added.len(), 2);
        assert!(transitions[0].diff.removed.is_empty());
        assert!(transitions[0].diff.changed.is_empty());

        // Second: zone changed, tier added.
        assert_eq!(transitions[1].tick, 5);
        assert_eq!(
            transitions[1].diff.changed.get("zone"),
            Some(&("a".to_string(), "b".to_string()))
        );
        assert_eq!(
            transitions[1].diff.added.get("tier"),
            Some(&"hot".to_string())
        );

        // Third: tier removed.
        assert_eq!(transitions[2].tick, 9);
        assert_eq!(
            transitions[2].diff.removed.get("tier"),
            Some(&"hot".to_string())
        );

        // Current view reflects the latest set.
        assert_eq!(
            store.current_labels(&entity),
            Some(&labels(&[("role", "worker"), ("zone", "b")]))
        );
    }

    /// A re-observation of identical labels is NOT a transition — the observable
    /// of interest is *when the labels change*, so an unchanged sample records
    /// no spurious change point (no double-count of a non-change).
    #[test]
    fn re_observing_identical_labels_is_not_a_transition() {
        let mut store = MetadataStore::new();
        let entity = e("node-1");
        let set = labels(&[("role", "worker")]);
        assert!(store
            .ingest(LabelObservation::new(entity.clone(), set.clone(), 0))
            .is_some());
        // Same labels again, different tick and key insertion order: no change.
        let reordered: LabelSet = set.clone();
        assert!(store
            .ingest(LabelObservation::new(entity.clone(), reordered, 3))
            .is_none());
        assert_eq!(store.transitions(&entity).len(), 1);
        assert_eq!(store.current_labels(&entity), Some(&set));
    }

    /// An entity observed exactly once has current labels but no *changes* yet
    /// beyond its first observation.
    #[test]
    fn single_observation_has_current_labels_and_one_initial_transition() {
        let mut store = MetadataStore::new();
        let entity = e("solo");
        store.ingest(LabelObservation::new(
            entity.clone(),
            labels(&[("k", "v")]),
            0,
        ));
        assert_eq!(store.current_labels(&entity), Some(&labels(&[("k", "v")])));
        assert_eq!(store.transitions(&entity).len(), 1);
    }
}
