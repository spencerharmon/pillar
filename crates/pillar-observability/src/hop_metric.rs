//! The `pillar_message_hops` metric — the `pillar-message-hop-metric` ROI
//! item (2026-09-09 ROI HEAD): at terminal `PillarMessage` processing (this
//! node IS the addressed destination, not a mid-path relay), the destination
//! emits ingest->destination hop count, labeled with the ingest and
//! destination topology tiers + `cell`/`route`/`route_kind`.
//!
//! This is a thin, event-driven wrapper over [`crate::block::TimeseriesStore::
//! write_labeled`] — the SAME "shared correlation spine" every other signal
//! kind rides (see `crate::correlation`), never a parallel metrics path.
//! Unlike [`crate::ingest::MetricsProducer`] (a periodic self-sample loop
//! over local `/proc`/atomic counters), this is a one-shot emission at the
//! exact moment a message is delivered — the natural shape for a per-message
//! metric.
//!
//! Label values (topology tiers, cell, route, route kind) are supplied by the
//! caller (`pillar-net`, which resolves them at the terminal-delivery point)
//! rather than computed here, so this crate need not depend on
//! `pillar-wire`'s envelope-routing concepts beyond what it already uses.
//! Callers that want the "placement-facing rollups use ATTESTED labels"
//! requirement MUST pass tiers resolved via
//! `pillar_topology::Topology::attested_placement` (never `::placement`,
//! which falls back to self-declared) — this module does not itself enforce
//! that (it just writes whatever labels it is given), so it's a caller
//! contract, documented at the one call site
//! (`pillar_net::hop_metric::record_terminal_hops`).

use crate::block::{SignalId, SignalKind, TimeseriesStore};
use crate::metadata::LabelSet;

/// The stable series name for the hop metric, carried both in the payload and
/// the `metric` label (matching `MetricKind::name()`'s convention in
/// `crate::ingest`).
pub const MESSAGE_HOPS_METRIC: &str = "pillar_message_hops";

/// Write one `pillar_message_hops` sample: `hops` real forwarding hops the
/// message travelled from its ingest node to this (destination) node, at
/// `write_tick`, carrying `labels` (tier=value pairs + `cell`/`route`/
/// `route_kind`) on the shared correlation spine.
///
/// `labels` is caller-supplied so this crate stays agnostic of the topology
/// and routing types that produce it (`pillar-topology`/`pillar-manifest`/
/// `pillar-wire`'s `CellId`, all already stringified by the caller) — see the
/// module docs for the ATTESTED-label contract callers must honor.
///
/// Returns `None` only if the write was downsampled away by a configured
/// [`crate::retention::RetentionPolicy`] for this signal's labels — never a
/// fabricated/dropped-for-no-reason value.
pub fn record_message_hops(
    store: &mut TimeseriesStore,
    hops: u32,
    mut labels: LabelSet,
    write_tick: u64,
) -> Option<SignalId> {
    labels.insert("metric".to_string(), MESSAGE_HOPS_METRIC.to_string());
    let payload = format!("{MESSAGE_HOPS_METRIC} {hops} @{write_tick}");
    store.write_labeled(SignalKind::Metric, payload.into_bytes(), labels, write_tick)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_real_hop_count_with_labels_and_is_queryable() {
        let mut store = TimeseriesStore::new(64, 1_000);
        let mut labels = LabelSet::new();
        labels.insert("ingest_region".to_string(), "us-east".to_string());
        labels.insert("destination_region".to_string(), "us-west".to_string());
        labels.insert("cell".to_string(), "cell-a".to_string());
        labels.insert("route".to_string(), "checkout".to_string());
        labels.insert("route_kind".to_string(), "PillarNative".to_string());

        let id = record_message_hops(&mut store, 3, labels.clone(), 10)
            .expect("not downsampled away");

        let signal = store
            .held_signals()
            .find(|s| s.id() == id)
            .expect("the written signal is retrievable by its content id");
        assert_eq!(signal.kind(), SignalKind::Metric);
        let payload = String::from_utf8(signal.payload().to_vec()).expect("utf8 payload");
        assert_eq!(payload, "pillar_message_hops 3 @10");
        assert_eq!(
            signal.labels().get("metric").map(String::as_str),
            Some(MESSAGE_HOPS_METRIC)
        );
        assert_eq!(
            signal.labels().get("cell").map(String::as_str),
            Some("cell-a")
        );
        assert_eq!(
            signal.labels().get("route_kind").map(String::as_str),
            Some("PillarNative")
        );
    }
}
