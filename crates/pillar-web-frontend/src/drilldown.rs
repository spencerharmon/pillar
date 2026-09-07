//! One-click **signal drilldown** — pivot from a single metric-spike data
//! point to the correlated logs, trace spans, profile samples, and entity
//! metadata around it, surfaced in the Yew UI alongside the per-signal Explore
//! builders (`crate::explore`).
//!
//! The pivot is NEVER a fabricated or static cross-reference. It runs entirely
//! over the ONE shared correlation spine
//! ([`pillar_observability::CorrelationIndex`], already implemented by
//! `obs-five-signals-impl`) and the real held signal set
//! ([`pillar_observability::TimeseriesStore`]): from a chosen anchor signal
//! (the metric spike), [`drilldown_from`] gathers exactly the OTHER-kind
//! signals that genuinely share the anchor's correlation id (trace id / event
//! CID) OR a shared label with it, bounded to the same time `window` the
//! existing `correlate:` clause uses — the SAME O(matches) join
//! `pillar_observability::psl::execute` performs for a `correlate:` query,
//! never a second, parallel correlation model. Drilling from a point that has
//! no correlated data in a given kind yields an EMPTY group for that kind —
//! never a placeholder row.
//!
//! Like `crate::explore` and `crate::panels`, the join logic is pure,
//! host-testable Rust (`cargo test -p pillar-web-frontend`, no browser); only
//! the DOM rendering in [`DrilldownPanel`] lives behind the `yew` feature.

use std::collections::{BTreeMap, BTreeSet};

use pillar_observability::correlation::Label;
use pillar_observability::{CorrelationIndex, SignalId, SignalKind, TimeseriesStore};

#[cfg(feature = "yew")]
use yew::prelude::*;

/// The signal kind a drilldown starts FROM: the metric spike the operator
/// clicked. The pivot deliberately excludes this kind from its results (you
/// drill OUT to the other four kinds), mirroring
/// [`crate::explore::correlate_candidates`].
pub const DRILLDOWN_ANCHOR_KIND: SignalKind = SignalKind::Metric;

/// The four OTHER signal kinds a metric-spike drilldown pivots TO, in a fixed
/// render order: the correlated logs, the trace, the profile, and the entity
/// metadata. Never includes [`DRILLDOWN_ANCHOR_KIND`] (metrics) itself.
#[must_use]
pub fn drilldown_target_kinds() -> Vec<SignalKind> {
    vec![
        SignalKind::Log,
        SignalKind::TraceSpan,
        SignalKind::ProfileSample,
        SignalKind::MetadataSample,
    ]
}

/// The result of drilling down from one anchor: the correlated signal ids
/// grouped by their kind. Every id in a group is a REAL held signal that
/// genuinely shares the anchor's correlation id or a shared label within the
/// window — never a fabricated cross-reference. A kind with no correlated
/// signal is simply absent from [`by_kind`](Self::by_kind) (and
/// [`kind`](Self::kind) returns an empty vec for it) — never a placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drilldown {
    /// The anchor (metric-spike) signal this drilldown pivots from.
    pub anchor: SignalId,
    /// The correlated peers, grouped by their kind. Content-address ordered
    /// within each kind; only kinds with at least one real correlated peer
    /// appear.
    pub by_kind: BTreeMap<SignalKind, Vec<SignalId>>,
}

impl Drilldown {
    /// The correlated peers of `kind` — the logs/trace/profile/metadata
    /// sharing the anchor's correlation id or a shared label within the
    /// window. Empty (never a placeholder) when nothing of that kind
    /// correlates.
    #[must_use]
    pub fn kind(&self, kind: SignalKind) -> Vec<SignalId> {
        self.by_kind.get(&kind).cloned().unwrap_or_default()
    }

    /// Whether this drilldown found NO correlated peer in ANY other kind —
    /// the honest "nothing correlates here" state the UI renders as empty
    /// groups rather than a fabricated row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_kind.values().all(Vec::is_empty)
    }
}

/// Drill down from `anchor` (a metric-spike signal) into the correlated
/// OTHER-kind signals, over the real `store`/`index`, bounded to `window_seconds`
/// around the anchor's write tick, as of logical time `now`.
///
/// A peer of another kind is included iff it is currently held, its write tick
/// is within `[anchor_tick - window, anchor_tick + window]` AND `<= now`, and
/// it genuinely relates to the anchor on the shared spine — either it shares
/// the anchor's correlation id (the trace-id / CID pivot,
/// [`CorrelationIndex::by_correlation`]) or it shares at least one of the
/// anchor's labels (the shared-label pivot, [`CorrelationIndex::by_label`]).
/// This is exactly the join `pillar_observability::psl::execute` performs for a
/// `correlate:` clause — reused here, never re-invented.
///
/// The metric anchor kind is never a target: a signal of
/// [`DRILLDOWN_ANCHOR_KIND`] is excluded even if it correlates. A kind with no
/// correlated peer does not appear in the result — no placeholder.
#[must_use]
pub fn drilldown_from(
    store: &TimeseriesStore,
    index: &CorrelationIndex,
    anchor: &SignalId,
    window_seconds: u64,
    now: u64,
) -> Drilldown {
    let mut by_kind: BTreeMap<SignalKind, Vec<SignalId>> = BTreeMap::new();

    let Some(anchor_tick) = store.write_tick_of(anchor) else {
        // An anchor that is no longer held has no drilldown.
        return Drilldown {
            anchor: anchor.clone(),
            by_kind,
        };
    };

    // Gather the candidate peers from the ONE shared spine: the anchor's
    // correlation-id thread AND every signal sharing one of the anchor's
    // labels. Both are real CorrelationIndex lookups — never a fabricated set.
    let mut candidates: BTreeSet<SignalId> = BTreeSet::new();
    if let Some(cid) = index.correlation_of(anchor) {
        candidates.extend(index.by_correlation(&cid));
    }
    if let Some(anchor_signal) = store.held_signals().find(|s| &s.id() == anchor) {
        for (key, value) in anchor_signal.labels() {
            let label = Label::new(key.clone(), value.clone());
            candidates.extend(index.by_label(&label));
        }
    }

    let range_lo = anchor_tick.saturating_sub(window_seconds);
    let range_hi = anchor_tick.saturating_add(window_seconds).min(now);

    for peer in candidates {
        if &peer == anchor {
            continue; // the anchor is the origin, not a drilldown result
        }
        let Some(signal) = store.held_signals().find(|s| s.id() == peer) else {
            continue; // no longer held
        };
        let kind = signal.kind();
        if kind == DRILLDOWN_ANCHOR_KIND {
            continue; // drill OUT to the other four kinds, never back to metrics
        }
        let Some(peer_tick) = store.write_tick_of(&peer) else {
            continue;
        };
        if peer_tick < range_lo || peer_tick > range_hi {
            continue; // outside the correlate window
        }
        by_kind.entry(kind).or_default().push(peer);
    }

    for ids in by_kind.values_mut() {
        ids.sort();
        ids.dedup();
    }

    Drilldown {
        anchor: anchor.clone(),
        by_kind,
    }
}

#[cfg(feature = "yew")]
/// Props for [`DrilldownPanel`].
#[derive(Properties, PartialEq)]
pub struct DrilldownPanelProps {
    /// The computed drilldown to render — the correlated logs/trace/profile/
    /// metadata for the metric spike the operator drilled from.
    pub drilldown: Drilldown,
}

#[cfg(feature = "yew")]
/// Renders a computed [`Drilldown`] alongside the Explore builders: one
/// section per target kind (logs, trace, profile, metadata), each listing the
/// real correlated signal ids. A kind with no correlated data renders an empty
/// section — never a fabricated placeholder row.
#[function_component(DrilldownPanel)]
pub fn drilldown_panel(props: &DrilldownPanelProps) -> Html {
    let drilldown = &props.drilldown;
    html! {
        <section data-panel="drilldown">
            <h2>{ "Drilldown" }</h2>
            { for drilldown_target_kinds().into_iter().map(|kind| {
                let ids = drilldown.kind(kind);
                let label = format!("{kind:?}");
                html! {
                    <section data-role="drilldown-kind" data-kind={label.clone()}>
                        <h3>{ label }</h3>
                        <ul data-role="drilldown-results">
                            { for ids.iter().map(|id| html! {
                                <li>{ format!("{:?}", id) }</li>
                            }) }
                        </ul>
                    </section>
                }
            }) }
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_observability::correlation::{CorrelationId, SignalRef};
    use pillar_observability::metadata::LabelSet;
    use std::collections::BTreeSet as StdBTreeSet;

    fn label_set(pairs: &[(&str, &str)]) -> LabelSet {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn spine_labels(pairs: &[(&str, &str)]) -> StdBTreeSet<Label> {
        pairs.iter().map(|(k, v)| Label::new(*k, *v)).collect()
    }

    /// Write a signal into the store AND register it on the correlation spine
    /// with the SAME labels/correlation id, exactly as the real ingest path
    /// does — so the drilldown joins over genuinely-correlated data, never a
    /// fabricated cross-reference.
    fn write_and_register(
        store: &mut TimeseriesStore,
        index: &mut CorrelationIndex,
        kind: SignalKind,
        payload: &[u8],
        labels: &[(&str, &str)],
        correlation: Option<&str>,
        tick: u64,
    ) -> SignalId {
        let id = store
            .write_labeled(kind, payload.to_vec(), label_set(labels), tick)
            .expect("signal is held");
        index.register(
            id.clone(),
            &SignalRef {
                kind,
                correlation: correlation.map(|c| CorrelationId(c.to_string())),
                labels: spine_labels(labels),
            },
        );
        id
    }

    /// A one-click drilldown from a metric spike surfaces the correlated logs,
    /// trace, and profile that genuinely share the metric's correlation id
    /// within the window — and ONLY those. FAILS without `drilldown_from`
    /// joining over the real `CorrelationIndex`/`TimeseriesStore`.
    #[test]
    fn drilldown_surfaces_only_the_genuinely_correlated_signals() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        // The metric spike we drill from, on trace "t-1" at tick 100.
        let anchor = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Metric,
            b"spike",
            &[("node", "n-1")],
            Some("t-1"),
            100,
        );
        // The log, trace span, and profile sample sharing that trace id, all
        // within the window — the real correlated results.
        let log = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Log,
            b"log-a",
            &[("node", "n-1")],
            Some("t-1"),
            102,
        );
        let span = write_and_register(
            &mut store,
            &mut index,
            SignalKind::TraceSpan,
            b"span-a",
            &[("node", "n-1")],
            Some("t-1"),
            98,
        );
        let profile = write_and_register(
            &mut store,
            &mut index,
            SignalKind::ProfileSample,
            b"prof-a",
            &[("node", "n-1")],
            Some("t-1"),
            101,
        );

        // A log that shares NEITHER axis with the anchor — a different trace
        // id AND different labels — must NOT be gathered (proves the result is
        // never a fabricated cross-ref, only the real correlation-id/shared-
        // label join).
        let _other_trace_log = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Log,
            b"log-other",
            &[("node", "n-9")],
            Some("t-2"),
            103,
        );
        // A correlated log OUTSIDE the window — must NOT be gathered.
        let _out_of_window_log = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Log,
            b"log-late",
            &[("node", "n-1")],
            Some("t-1"),
            500,
        );

        let result = drilldown_from(&store, &index, &anchor, 5, 1_000);

        // Logs: exactly the one correlated log within the window.
        assert_eq!(result.kind(SignalKind::Log), vec![log.clone()]);
        // Trace + profile: the genuinely-correlated peers.
        assert_eq!(result.kind(SignalKind::TraceSpan), vec![span.clone()]);
        assert_eq!(result.kind(SignalKind::ProfileSample), vec![profile.clone()]);

        // The result never includes the anchor kind (metrics) itself, and
        // never the off-trace / out-of-window logs.
        assert!(result.kind(SignalKind::Metric).is_empty());
        assert!(!result.kind(SignalKind::Log).contains(&_other_trace_log));
        assert!(!result.kind(SignalKind::Log).contains(&_out_of_window_log));
        assert!(!result.is_empty());
    }

    /// Drilling from a metric spike whose thread has NO correlated data in
    /// other kinds returns EMPTY groups — never a placeholder. FAILS if the
    /// pivot fabricates a static cross-reference.
    #[test]
    fn drilldown_with_no_correlated_peers_is_empty_never_a_placeholder() {
        let mut store = TimeseriesStore::new(64, 10_000);
        let mut index = CorrelationIndex::new();

        // A lone metric spike: unique trace id, unique labels, nothing else
        // shares either axis.
        let anchor = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Metric,
            b"lonely-spike",
            &[("node", "n-solo")],
            Some("t-solo"),
            50,
        );
        // Unrelated signals of other kinds — different trace, different labels.
        let _unrelated_log = write_and_register(
            &mut store,
            &mut index,
            SignalKind::Log,
            b"unrelated",
            &[("node", "n-9")],
            Some("t-9"),
            50,
        );

        let result = drilldown_from(&store, &index, &anchor, 60, 1_000);

        assert!(result.is_empty(), "no correlated data ⇒ empty, not a placeholder");
        for kind in drilldown_target_kinds() {
            assert!(result.kind(kind).is_empty());
        }
    }

    /// The drilldown pivots to the four OTHER kinds — never back to metrics.
    #[test]
    fn drilldown_targets_the_four_other_kinds_never_metrics() {
        let kinds = drilldown_target_kinds();
        assert!(!kinds.contains(&SignalKind::Metric));
        assert!(kinds.contains(&SignalKind::Log));
        assert!(kinds.contains(&SignalKind::TraceSpan));
        assert!(kinds.contains(&SignalKind::ProfileSample));
        assert!(kinds.contains(&SignalKind::MetadataSample));
        assert_eq!(kinds.len(), 4);
    }
}
