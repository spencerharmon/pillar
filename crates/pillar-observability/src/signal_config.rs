//! Per-node signal producer enable/disable, expressed as a **built-in
//! resource** — the `SignalConfig` manifest — rather than a hardcoded flag,
//! following the exact convention [`crate::retention::RetentionPolicy`]
//! already established for this crate.
//!
//! `specs/ObsIngestionSubstrate.tla` proves, at the design-spec layer, that a
//! freshly booted node's producers come up at exactly the declared
//! `DefaultOn = {metrics, logs, metadata}` matrix (`DefaultsMatchSpec`) and
//! that a config toggle flips exactly its named producer and no other
//! (`ConfigOverrideHonored`). This module is the Rust delivery of that
//! contract: at cell creation the node seeds a DEFAULT [`SignalConfigMatrix`]
//! matching that same matrix (see
//! [`crate::signal_config::default_matrix`]), each signal source is an
//! ordinary manifest the user can view/edit
//! ([`pillar_manifest::builtin::default_signal_config_manifests`] builds the
//! wire form), and [`SignalConfigMatrix::apply_spec`] is the ONE decider a
//! manifest edit runs through to change live producer behavior
//! ([`gated_ingest`] is the producer gate every ingestion path should call).
//!
//! [`SignalConfigSpec`] is, like [`crate::retention::RetentionPolicySpec`], a
//! crate-local, dependency-free projection of a validated manifest `spec` —
//! this crate depends only on the parsed spec, never on the manifest crate.

use std::collections::BTreeMap;

use crate::block::{SignalId, SignalKind, TimeseriesStore};

/// Parse a [`SignalKind`] from its `SignalConfig` manifest `source` name —
/// the exact lowercase names
/// `pillar_manifest::builtin::SIGNAL_CONFIG_SOURCES` declares
/// (`metrics`/`logs`/`traces`/`profiles`/`metadata`).
#[must_use]
pub fn signal_kind_from_source(source: &str) -> Option<SignalKind> {
    match source {
        "metrics" => Some(SignalKind::Metric),
        "logs" => Some(SignalKind::Log),
        "traces" => Some(SignalKind::TraceSpan),
        "profiles" => Some(SignalKind::ProfileSample),
        "metadata" => Some(SignalKind::MetadataSample),
        _ => None,
    }
}

/// The manifest `source` name a [`SignalKind`] is declared under — the
/// inverse of [`signal_kind_from_source`].
#[must_use]
pub fn signal_source_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Metric => "metrics",
        SignalKind::Log => "logs",
        SignalKind::TraceSpan => "traces",
        SignalKind::ProfileSample => "profiles",
        SignalKind::MetadataSample => "metadata",
    }
}

/// Whether `kind` defaults ON at cell creation — the Rust-side mirror of
/// `specs/ObsIngestionSubstrate.tla`'s proven `DefaultOn = {metrics, logs,
/// metadata}` (tracing and profiling default OFF). The SAME rule
/// `pillar_manifest::builtin::signal_config_default_on` declares, keyed here
/// by [`SignalKind`] rather than by manifest string.
#[must_use]
pub fn default_on(kind: SignalKind) -> bool {
    matches!(
        kind,
        SignalKind::Metric | SignalKind::Log | SignalKind::MetadataSample
    )
}

/// The minimal validated manifest fields a [`SignalConfigMatrix`] update is
/// lowered from — the crate-local, dependency-free projection of a
/// `SignalConfig` manifest's `spec` (mirrors
/// [`crate::retention::RetentionPolicySpec`]'s doc contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalConfigSpec {
    /// `spec.source` — one of [`signal_kind_from_source`]'s recognized names.
    pub source: String,
    /// `spec.enabled`.
    pub enabled: bool,
}

/// The live per-node signal-producer enable/disable state — every producer's
/// current on/off value. A fresh matrix ([`SignalConfigMatrix::default`])
/// equals the declared [`default_on`] matrix on every kind
/// (`DefaultsMatchSpec`); [`SignalConfigMatrix::apply_spec`] flips exactly one
/// named producer and leaves every other untouched
/// (`ConfigOverrideHonored`); [`SignalConfigMatrix::reset_to_default`] falls a
/// single kind back to its declared default (the delete-resets-to-default
/// contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalConfigMatrix {
    enabled: BTreeMap<SignalKind, bool>,
}

/// Every signal kind, in a fixed order — used to build/iterate a complete
/// matrix.
const ALL_KINDS: [SignalKind; 5] = [
    SignalKind::Metric,
    SignalKind::Log,
    SignalKind::TraceSpan,
    SignalKind::ProfileSample,
    SignalKind::MetadataSample,
];

impl Default for SignalConfigMatrix {
    /// A freshly booted node's producer matrix — exactly the declared
    /// `DefaultOn` matrix (`DefaultsMatchSpec`).
    fn default() -> Self {
        SignalConfigMatrix {
            enabled: ALL_KINDS.into_iter().map(|k| (k, default_on(k))).collect(),
        }
    }
}

impl SignalConfigMatrix {
    /// A freshly booted node's producer matrix (alias of [`Default::default`]
    /// for call-site clarity at a cell's creation).
    #[must_use]
    pub fn default_matrix() -> Self {
        Self::default()
    }

    /// Whether `kind`'s producer is currently enabled.
    #[must_use]
    pub fn is_enabled(&self, kind: SignalKind) -> bool {
        self.enabled.get(&kind).copied().unwrap_or(false)
    }

    /// Apply a validated `SignalConfig` manifest edit: flips EXACTLY the
    /// named producer to `spec.enabled` and leaves every other kind's value
    /// untouched (`ConfigOverrideHonored`). Returns the affected
    /// [`SignalKind`], or `None` if `spec.source` names no recognized kind
    /// (the schema layer should already have rejected such a manifest; this
    /// defends against an unknown source string rather than panicking).
    pub fn apply_spec(&mut self, spec: &SignalConfigSpec) -> Option<SignalKind> {
        let kind = signal_kind_from_source(&spec.source)?;
        self.enabled.insert(kind, spec.enabled);
        Some(kind)
    }

    /// Delete/reset a `SignalConfig` manifest: falls exactly `kind`'s
    /// producer back to its declared [`default_on`] value, leaving every
    /// other kind's current value untouched.
    pub fn reset_to_default(&mut self, kind: SignalKind) {
        self.enabled.insert(kind, default_on(kind));
    }
}

/// The producer gate every ingestion path should call INSTEAD OF writing
/// directly to a [`TimeseriesStore`]: writes the signal and returns its id
/// only if `config` currently has `kind` enabled; a disabled producer writes
/// nothing and returns `None`. This is the delivery-as-manifest wiring: an
/// edited `SignalConfig` manifest (lowered into `config` via
/// [`SignalConfigMatrix::apply_spec`]) changes live producer behavior on the
/// very next call, with no separate re-proof needed —
/// `ObsIngestionSubstrate.tla`'s `ConfigOverrideHonored` already proves the
/// config-surface half of this contract.
pub fn gated_ingest(
    store: &mut TimeseriesStore,
    config: &SignalConfigMatrix,
    kind: SignalKind,
    payload: Vec<u8>,
    tick: u64,
) -> Option<SignalId> {
    if !config.is_enabled(kind) {
        return None;
    }
    Some(store.write(kind, payload, tick))
}

#[cfg(test)]
mod tests {
    use super::*;

    // DefaultsMatchSpec: a freshly booted node's matrix equals the declared
    // DefaultOn matrix — metrics/logs/metadata ON, traces/profiles OFF.
    #[test]
    fn fresh_matrix_matches_the_declared_defaults() {
        let matrix = SignalConfigMatrix::default_matrix();
        assert!(matrix.is_enabled(SignalKind::Metric));
        assert!(matrix.is_enabled(SignalKind::Log));
        assert!(matrix.is_enabled(SignalKind::MetadataSample));
        assert!(!matrix.is_enabled(SignalKind::TraceSpan));
        assert!(!matrix.is_enabled(SignalKind::ProfileSample));
    }

    // ConfigOverrideHonored: editing one SignalConfig manifest flips exactly
    // its named producer; every other kind keeps its default value.
    #[test]
    fn applying_a_spec_flips_exactly_its_named_producer() {
        let mut matrix = SignalConfigMatrix::default_matrix();
        let affected = matrix.apply_spec(&SignalConfigSpec {
            source: "traces".to_owned(),
            enabled: true,
        });
        assert_eq!(affected, Some(SignalKind::TraceSpan));

        // The named producer flipped...
        assert!(matrix.is_enabled(SignalKind::TraceSpan));
        // ...and every other producer is untouched (still its default).
        assert!(matrix.is_enabled(SignalKind::Metric));
        assert!(matrix.is_enabled(SignalKind::Log));
        assert!(matrix.is_enabled(SignalKind::MetadataSample));
        assert!(!matrix.is_enabled(SignalKind::ProfileSample));
    }

    #[test]
    fn applying_a_spec_with_an_unrecognized_source_is_refused() {
        let mut matrix = SignalConfigMatrix::default_matrix();
        let affected = matrix.apply_spec(&SignalConfigSpec {
            source: "not-a-real-source".to_owned(),
            enabled: true,
        });
        assert_eq!(affected, None);
        // Untouched — still exactly the default matrix.
        assert_eq!(matrix, SignalConfigMatrix::default_matrix());
    }

    // The wired producer gate: editing a SignalConfig manifest actually
    // changes live producer behavior — flipping tracing ON makes a trace
    // signal land on the store; flipping metrics OFF makes a metric signal
    // vanish (never written), proving the edit is not cosmetic.
    #[test]
    fn editing_a_manifest_changes_live_producer_behavior() {
        let mut store = TimeseriesStore::new(16, 1000);
        let mut config = SignalConfigMatrix::default_matrix();

        // Tracing defaults OFF: a trace signal is refused (nothing written).
        assert_eq!(
            gated_ingest(
                &mut store,
                &config,
                SignalKind::TraceSpan,
                b"span=1".to_vec(),
                0,
            ),
            None
        );
        assert_eq!(store.held_len(), 0);

        // Edit the manifest: flip tracing ON.
        config.apply_spec(&SignalConfigSpec {
            source: "traces".to_owned(),
            enabled: true,
        });

        // The SAME producer path now actually writes — live behavior changed.
        let id = gated_ingest(
            &mut store,
            &config,
            SignalKind::TraceSpan,
            b"span=1".to_vec(),
            0,
        )
        .expect("tracing is now enabled");
        assert!(store.contains(&id));
        assert_eq!(store.held_len(), 1);

        // Metrics still defaults ON and still ingests, untouched by the edit.
        let metric_id = gated_ingest(
            &mut store,
            &config,
            SignalKind::Metric,
            b"cpu 0.5".to_vec(),
            0,
        )
        .expect("metrics still enabled by default");
        assert!(store.contains(&metric_id));

        // Now edit metrics OFF: the producer stops landing new signals.
        config.apply_spec(&SignalConfigSpec {
            source: "metrics".to_owned(),
            enabled: false,
        });
        assert_eq!(
            gated_ingest(
                &mut store,
                &config,
                SignalKind::Metric,
                b"cpu 0.9".to_vec(),
                1,
            ),
            None
        );
        // Held count unchanged by the refused write.
        assert_eq!(store.held_len(), 2);
    }

    // Delete/reset falls a SignalConfig manifest's kind back to its declared
    // default, independent of every other kind's current (possibly
    // overridden) value.
    #[test]
    fn reset_falls_back_to_the_declared_default() {
        let mut matrix = SignalConfigMatrix::default_matrix();
        matrix.apply_spec(&SignalConfigSpec {
            source: "profiles".to_owned(),
            enabled: true,
        });
        matrix.apply_spec(&SignalConfigSpec {
            source: "logs".to_owned(),
            enabled: false,
        });
        assert!(matrix.is_enabled(SignalKind::ProfileSample));
        assert!(!matrix.is_enabled(SignalKind::Log));

        // Reset (a manifest delete) only the profiles kind.
        matrix.reset_to_default(SignalKind::ProfileSample);
        assert!(!matrix.is_enabled(SignalKind::ProfileSample));
        // logs stays at its (still-overridden) current value — reset is
        // per-kind, not a whole-matrix wipe.
        assert!(!matrix.is_enabled(SignalKind::Log));

        matrix.reset_to_default(SignalKind::Log);
        assert!(matrix.is_enabled(SignalKind::Log));
    }

    // signal_kind_from_source / signal_source_name round-trip for every
    // declared source name.
    #[test]
    fn source_name_round_trips_for_every_kind() {
        for kind in ALL_KINDS {
            let name = signal_source_name(kind);
            assert_eq!(signal_kind_from_source(name), Some(kind));
        }
        assert_eq!(signal_kind_from_source("bogus"), None);
    }
}
