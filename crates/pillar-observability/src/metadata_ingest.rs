//! Real node/cell **metadata sampling** — the running node periodically
//! captures a genuine snapshot of ITS OWN metadata (peer identity, a cell
//! membership snapshot, version/build info) and writes it into the shared
//! [`crate::TimeseriesStore`] through the SAME single producer contract every
//! other kind uses (`specs/ObsIngestionSubstrate.tla`'s one `Produce` path, a
//! default-on/off matrix, a per-producer config toggle).
//!
//! This is the periodic *producer* for the metadata signal kind — distinct
//! from [`crate::metadata`], which is the label-set-over-time *data structure*
//! ([`MetadataStore`]) the samples materialize into. Metadata sampling is
//! **ON by default** (`default_on(SignalKind::MetadataSample) == true`, the
//! spec's `DefaultOn = {metrics, logs, metadata}`), so a freshly booted node
//! ingests real metadata samples with no configuration at all.
//!
//! # Periodic sampling
//!
//! Unlike a per-event producer (traces), metadata is sampled on a fixed
//! **period**: [`MetadataProducer::sample`] writes a snapshot only on ticks
//! that fall on a period boundary (`tick % period == 0`), so a run of ticks
//! produces a bounded series of periodic samples rather than one per tick. The
//! period is a config knob: [`MetadataProducer::set_period`] changes how often
//! the node samples, exactly the substrate spec's per-producer config override
//! applied to the sampling cadence.
//!
//! # No fabrication
//!
//! A [`MetadataSource`] NEVER invents a snapshot. The real source
//! ([`NodeMetadataSource`]) reports genuine values of the running node — its
//! own peer id, the live cell membership it currently sees, and the crate's
//! real compiled-in version/build info. A source with no genuine snapshot to
//! report returns `None`, and the producer writes nothing for that round —
//! there is no placeholder, no constant, no demo metadata.

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::metadata::{EntityId, LabelObservation, LabelSet, MetadataStore};

/// A source of a REAL metadata snapshot for the running node.
///
/// The single seam through which a [`MetadataProducer`] obtains the label set
/// to sample. An implementation returns `Some((entity, labels))` ONLY for a
/// genuine, currently-observable snapshot, and `None` if it has nothing real
/// to report — the producer never invents one.
pub trait MetadataSource {
    /// The node/cell entity this snapshot describes (its stable identity).
    fn entity(&self) -> EntityId;

    /// The current real metadata label set for the node — peer identity, a
    /// cell membership snapshot, version/build info — or `None` if no genuine
    /// snapshot can be taken right now (never a placeholder set).
    fn snapshot(&self) -> Option<LabelSet>;
}

/// The real metadata source for a running node: its own peer id, the live cell
/// membership it currently sees, and the crate's real compiled-in
/// version/build info. Every value is a genuine fact of THIS node — nothing is
/// synthesized.
#[derive(Clone, Debug)]
pub struct NodeMetadataSource {
    /// This node's stable peer identity.
    peer_id: String,
    /// The cell this node is a member of.
    cell: String,
    /// The current membership snapshot the node sees (sorted peer ids).
    members: Vec<String>,
    /// The node's real compiled-in version (crate semver).
    version: String,
    /// The node's real build info (e.g. target triple / profile), when known.
    build: Option<String>,
}

impl NodeMetadataSource {
    /// A source describing a running node: its `peer_id`, its `cell`, the live
    /// `members` snapshot, and the real compiled-in `version` / optional
    /// `build` info.
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        cell: impl Into<String>,
        members: impl IntoIterator<Item = String>,
        version: impl Into<String>,
        build: Option<String>,
    ) -> Self {
        let mut members: Vec<String> = members.into_iter().collect();
        members.sort();
        members.dedup();
        NodeMetadataSource {
            peer_id: peer_id.into(),
            cell: cell.into(),
            members,
            version: version.into(),
            build,
        }
    }

    /// Update the live membership snapshot this source reports (the node
    /// observed a real membership change).
    pub fn set_members(&mut self, members: impl IntoIterator<Item = String>) {
        let mut m: Vec<String> = members.into_iter().collect();
        m.sort();
        m.dedup();
        self.members = m;
    }

    /// This node's peer id.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

impl MetadataSource for NodeMetadataSource {
    fn entity(&self) -> EntityId {
        EntityId(self.peer_id.clone())
    }

    fn snapshot(&self) -> Option<LabelSet> {
        let mut labels = LabelSet::new();
        // Peer identity.
        labels.insert("peer".to_string(), self.peer_id.clone());
        // Cell membership snapshot.
        labels.insert("cell".to_string(), self.cell.clone());
        labels.insert("members".to_string(), self.members.join(","));
        labels.insert(
            "member_count".to_string(),
            self.members.len().to_string(),
        );
        // Version/build info.
        labels.insert("version".to_string(), self.version.clone());
        if let Some(build) = &self.build {
            labels.insert("build".to_string(), build.clone());
        }
        Some(labels)
    }
}

/// How the metadata period sampling default is defined for a running node: the
/// number of logical ticks between two metadata snapshots. A period of 1
/// samples every tick; the default is a small, non-trivial cadence.
pub const DEFAULT_METADATA_PERIOD: u64 = 4;

/// The `metadata` producer: on a period boundary
/// ([`MetadataProducer::sample`]) it captures a real snapshot from its
/// [`MetadataSource`] and writes a metadata signal onto the shared substrate
/// through the single producer contract — the ONLY path onto the store —
/// while also feeding the label-set-over-time [`MetadataStore`] so a
/// re-observation of unchanged labels records no spurious transition.
///
/// **ON by default** (`metadata` is in `DefaultOn`). A config override
/// ([`MetadataProducer::set_enabled`]) disabling it stops new writes; a
/// separate override ([`MetadataProducer::set_period`]) changes the sampling
/// cadence. A `sample` while disabled, or off a period boundary, writes
/// nothing and returns `None`.
pub struct MetadataProducer<S: MetadataSource> {
    source: S,
    enabled: bool,
    /// Ticks between two snapshots; a `sample` writes only when
    /// `tick % period == 0`. Never zero (guarded on set).
    period: u64,
    /// Whether the enabled state was set explicitly by config (vs. the
    /// default-on), mirroring the substrate spec's `overridden` set.
    enabled_overridden: bool,
    /// Whether the period was set explicitly by config (vs. the default).
    period_overridden: bool,
}

impl<S: MetadataSource> MetadataProducer<S> {
    /// A producer at its DEFAULT state: **enabled** (`metadata` is in
    /// `DefaultOn`) at the [`DEFAULT_METADATA_PERIOD`] cadence, neither knob
    /// overridden by config yet.
    #[must_use]
    pub fn new(source: S) -> Self {
        debug_assert!(
            crate::signal_config::default_on(SignalKind::MetadataSample),
            "metadata must default ON"
        );
        MetadataProducer {
            source,
            enabled: true,
            period: DEFAULT_METADATA_PERIOD,
            enabled_overridden: false,
            period_overridden: false,
        }
    }

    /// Whether this producer is currently live (writing samples).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The current sampling period (ticks between snapshots).
    #[must_use]
    pub fn period(&self) -> u64 {
        self.period
    }

    /// Whether the enabled state was set by an explicit config override.
    #[must_use]
    pub fn is_enabled_overridden(&self) -> bool {
        self.enabled_overridden
    }

    /// Whether the sampling period was set by an explicit config override.
    #[must_use]
    pub fn is_period_overridden(&self) -> bool {
        self.period_overridden
    }

    /// Apply a config override flipping this producer on/off — the substrate
    /// spec's `ConfigToggle`. Disabling stops future `sample`s from writing.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.enabled_overridden = true;
    }

    /// Apply a config override changing the sampling period — how often the
    /// node captures a metadata snapshot. A `period` of 0 is clamped to 1 (a
    /// non-positive cadence makes no sense; sample every tick instead).
    pub fn set_period(&mut self, period: u64) {
        self.period = period.max(1);
        self.period_overridden = true;
    }

    /// The producer's metadata source (for inspection/testing).
    #[must_use]
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Whether `tick` falls on a sampling boundary for the current period.
    #[must_use]
    fn is_sampling_tick(&self, tick: u64) -> bool {
        tick % self.period == 0
    }

    /// Sample one periodic metadata snapshot into `store` at logical `tick`,
    /// also feeding `meta` (the label-set-over-time view).
    ///
    /// Writes a metadata signal (payload `"entity=<id> <k=v ...> @<tick>"`,
    /// carrying the snapshot's labels + an `entity` label) through the store's
    /// single producer path, and ingests the same observation into `meta` so
    /// the current-labels/transition views stay in sync. Returns the written
    /// signal id, or `None` when: the producer is disabled, `tick` is off a
    /// period boundary, or the source has no genuine snapshot — never a
    /// fabricated sample.
    pub fn sample(
        &self,
        store: &mut TimeseriesStore,
        meta: &mut MetadataStore,
        tick: u64,
    ) -> Option<SignalId> {
        if !self.enabled || !self.is_sampling_tick(tick) {
            return None;
        }
        let entity = self.source.entity();
        let snapshot = self.source.snapshot()?;

        // Feed the label-set-over-time view (dedups unchanged snapshots).
        meta.ingest(LabelObservation::new(
            entity.clone(),
            snapshot.clone(),
            tick,
        ));

        // Signal labels = snapshot labels + the entity id.
        let mut labels = snapshot.clone();
        labels.insert("entity".to_string(), entity.0.clone());

        let mut kv: Vec<String> = snapshot
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        kv.sort();
        let payload = format!("entity={} {} @{}", entity.0, kv.join(" "), tick);

        store.write_labeled(
            SignalKind::MetadataSample,
            payload.into_bytes(),
            labels,
            tick,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use crate::signal_config::default_on;
    use crate::ViewCache;

    fn node_source() -> NodeMetadataSource {
        NodeMetadataSource::new(
            "peer-1",
            "cell-a",
            ["peer-1".to_string(), "peer-2".to_string()],
            "0.3.1",
            Some("x86_64-unknown-linux-gnu/release".to_string()),
        )
    }

    /// A booted (default-on) node's store contains periodic REAL metadata
    /// samples after a short run — the metadata producer actually instruments
    /// the node. FAILS if the producer does not sample, or defaults off.
    #[test]
    fn booted_node_ingests_periodic_real_metadata_samples() {
        assert!(
            default_on(SignalKind::MetadataSample),
            "metadata must default ON"
        );
        let producer = MetadataProducer::new(node_source());
        assert!(producer.is_enabled(), "metadata producer is ON by default");
        assert!(!producer.is_enabled_overridden(), "no override on fresh boot");
        assert_eq!(producer.period(), DEFAULT_METADATA_PERIOD);

        let mut store = TimeseriesStore::new(64, 10_000);
        let mut meta = MetadataStore::new();

        // A short run over more ticks than one period.
        let ticks = DEFAULT_METADATA_PERIOD * 3;
        let mut written = 0;
        for tick in 0..ticks {
            if producer.sample(&mut store, &mut meta, tick).is_some() {
                written += 1;
            }
        }
        // Periodic: one sample per period boundary (ticks 0, P, 2P over
        // [0, 3P)).
        assert_eq!(written, 3, "a booted node ingests periodic metadata samples");

        // The samples are real MetadataSample signals on the one substrate.
        let mut cache = ViewCache::new();
        let ids = cache.materialize(&store, Query::of_kind(SignalKind::MetadataSample));
        assert_eq!(ids.len(), 3, "periodic metadata samples ingested onto substrate");

        // Each sample carries the real snapshot: peer identity, cell
        // membership snapshot, version/build info.
        for s in store
            .held_signals()
            .filter(|s| s.kind() == SignalKind::MetadataSample)
        {
            assert_eq!(s.labels().get("peer").map(String::as_str), Some("peer-1"));
            assert_eq!(s.labels().get("cell").map(String::as_str), Some("cell-a"));
            assert_eq!(
                s.labels().get("members").map(String::as_str),
                Some("peer-1,peer-2")
            );
            assert_eq!(s.labels().get("version").map(String::as_str), Some("0.3.1"));
            assert!(s.labels().get("build").is_some(), "build info carried");
        }

        // The label-set-over-time view reflects the node's current labels.
        let ent = EntityId("peer-1".to_string());
        let current = meta.current_labels(&ent).expect("metadata materialized");
        assert_eq!(current.get("cell").map(String::as_str), Some("cell-a"));
    }

    /// A config override changing the sampling PERIOD changes how often the
    /// node samples: a shorter period yields more periodic samples over the
    /// same run, a longer one yields fewer. FAILS if the period knob is not
    /// honored.
    #[test]
    fn config_override_changes_the_sampling_period() {
        let ticks = 12u64;

        // Default period: samples on 0,4,8 over [0,12) -> 3 samples.
        let default_producer = MetadataProducer::new(node_source());
        assert_eq!(default_producer.period(), 4);
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut meta = MetadataStore::new();
        let mut default_count = 0;
        for tick in 0..ticks {
            if default_producer.sample(&mut store, &mut meta, tick).is_some() {
                default_count += 1;
            }
        }
        assert_eq!(default_count, 3, "default cadence samples 3 times");

        // Override to a SHORTER period (every 2 ticks): 0,2,4,6,8,10 -> 6.
        let mut faster = MetadataProducer::new(node_source());
        faster.set_period(2);
        assert!(faster.is_period_overridden(), "period toggle recorded");
        assert_eq!(faster.period(), 2);
        let mut store2 = TimeseriesStore::new(64, 10_000);
        let mut meta2 = MetadataStore::new();
        let mut faster_count = 0;
        for tick in 0..ticks {
            if faster.sample(&mut store2, &mut meta2, tick).is_some() {
                faster_count += 1;
            }
        }
        assert_eq!(faster_count, 6, "shorter period samples more often");

        // Override to a LONGER period (every 6 ticks): 0,6 -> 2.
        let mut slower = MetadataProducer::new(node_source());
        slower.set_period(6);
        let mut store3 = TimeseriesStore::new(64, 10_000);
        let mut meta3 = MetadataStore::new();
        let mut slower_count = 0;
        for tick in 0..ticks {
            if slower.sample(&mut store3, &mut meta3, tick).is_some() {
                slower_count += 1;
            }
        }
        assert_eq!(slower_count, 2, "longer period samples less often");

        assert!(
            faster_count > default_count && default_count > slower_count,
            "the sampling period genuinely controls the cadence"
        );
    }

    /// A config override disabling metadata stops new writes — the substrate
    /// spec's `ConfigToggle` off.
    #[test]
    fn config_override_disabling_metadata_stops_new_writes() {
        let mut producer = MetadataProducer::new(node_source());
        producer.set_period(1); // sample every tick to make the test crisp
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut meta = MetadataStore::new();

        assert!(producer.sample(&mut store, &mut meta, 0).is_some());
        let held_after_enabled = store.held_len();
        assert_eq!(held_after_enabled, 1);

        producer.set_enabled(false);
        assert!(!producer.is_enabled());
        assert!(producer.is_enabled_overridden());
        for tick in 1..5 {
            assert!(
                producer.sample(&mut store, &mut meta, tick).is_none(),
                "disabled producer writes nothing"
            );
        }
        assert_eq!(
            store.held_len(),
            held_after_enabled,
            "no new writes after the disabling override"
        );
    }

    /// `NoFabricatedSample`: a source with no genuine snapshot yields NO
    /// sample — never a synthetic placeholder — even on a period boundary.
    #[test]
    fn no_fabricated_metadata_sample_when_source_has_no_snapshot() {
        struct EmptySource;
        impl MetadataSource for EmptySource {
            fn entity(&self) -> EntityId {
                EntityId("peer-x".to_string())
            }
            fn snapshot(&self) -> Option<LabelSet> {
                None
            }
        }

        let producer = MetadataProducer::new(EmptySource);
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut meta = MetadataStore::new();
        // Tick 0 is a period boundary, yet nothing is written.
        assert!(producer.sample(&mut store, &mut meta, 0).is_none());
        assert_eq!(store.held_len(), 0, "no fabricated metadata sample");
        assert!(
            meta.current_labels(&EntityId("peer-x".to_string())).is_none(),
            "nothing materialized from an absent snapshot"
        );
    }

    /// An unchanged snapshot re-sampled on later period boundaries records no
    /// spurious transition in the label-set-over-time view (the observable is
    /// *when the labels change*), while a real membership change DOES.
    #[test]
    fn periodic_resampling_records_transitions_only_on_real_change() {
        let mut src = node_source();
        let mut producer = MetadataProducer::new(src.clone());
        producer.set_period(1);
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut meta = MetadataStore::new();
        let ent = EntityId("peer-1".to_string());

        // Same snapshot sampled three times: one transition (the first
        // observation), no spurious ones.
        for tick in 0..3 {
            producer.sample(&mut store, &mut meta, tick);
        }
        assert_eq!(
            meta.transitions(&ent).len(),
            1,
            "unchanged periodic samples record no spurious transition"
        );

        // A real membership change: rebuild the producer with an updated
        // source snapshot and sample again -> a genuine transition.
        src.set_members(["peer-1".to_string(), "peer-2".to_string(), "peer-3".to_string()]);
        producer = MetadataProducer::new(src);
        producer.set_period(1);
        producer.sample(&mut store, &mut meta, 3);
        assert_eq!(
            meta.transitions(&ent).len(),
            2,
            "a real membership change records a transition"
        );
    }
}
