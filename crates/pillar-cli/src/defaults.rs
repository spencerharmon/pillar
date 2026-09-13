//! The binary-shipped DEFAULTS bundle + the defaults-merge advisory.
//!
//! The bundle is a **seed / offer**, never a reconcile target — this is the
//! load-bearing distinction proven in `specs/Defaults.tla`. A node version bump
//! ships a (possibly newer) bundle, but must never modify a cell's Default
//! ResourceSet. Operators freely add/edit/delete members; none of that is
//! "drift" against the binary. New shipped defaults surface only as an ADDITIVE
//! advisory (net-new "available"), adopted per operator choice.
//!
//! This module is the PURE core both the web plane and the CLI call:
//! - [`shipped_default_bundle`] — the embedded, versioned default policies.
//! - [`DefaultPolicy::to_crd`] / [`DefaultPolicy::to_manifest`] — render one
//!   default as a provenance-labeled `RetentionPolicy` (typed or as applyable
//!   manifest text for `pillar render defaults`).
//! - [`defaults_advisory`] — the Rust image of the TLA advisory
//!   `Available == (bundleNames \ present) \ tombstoned`, classifying every
//!   shipped default as Present / Available / Edited / Tombstoned.

use std::collections::BTreeSet;

use pillar_manifest::{Crd, Metadata, Value};

/// The current shipped-bundle version. Monotonic across binary releases
/// (`VersionMonotone` in `specs/Defaults.tla`); bump when the shipped default
/// set changes.
pub const DEFAULT_BUNDLE_VERSION: u32 = 1;

/// Provenance label marking a resource as one this binary's defaults seeded.
/// Its presence lets the console/CLI tag a member `defaults@vK` vs
/// operator-authored; it is NOT ownership — operators edit/delete freely.
pub const DEFAULTS_MANAGED_BY_LABEL: &str = "pillar.dev/managed-by";
/// The value [`DEFAULTS_MANAGED_BY_LABEL`] carries for a seeded default.
pub const DEFAULTS_MANAGED_BY_VALUE: &str = "defaults";
/// Label recording which bundle version seeded a resource.
pub const DEFAULT_BUNDLE_LABEL: &str = "pillar.dev/default-bundle";

const BUNDLE_API_VERSION: &str = "pillar.dev/v1";
const RETENTION_POLICY_KIND: &str = "RetentionPolicy";

/// One shipped default policy (a `RetentionPolicy` in the current bundle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultPolicy {
    /// The resource name (`RetentionPolicy/<name>`).
    pub name: &'static str,
    /// The signal kind this policy retains (`Metric`/`Log`/`TraceSpan`/…).
    pub signal_kind: &'static str,
    /// Comma-separated label selector; empty = match all of the kind.
    pub match_labels: &'static str,
    /// Retention window, in seconds.
    pub window_secs: u64,
    /// Optional downsample interval, in seconds.
    pub downsample_secs: Option<u64>,
}

/// The shipped default bundle: a monotonic version + its policies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultBundle {
    /// The bundle's monotonic version (`DEFAULT_BUNDLE_VERSION`).
    pub version: u32,
    /// The shipped default policies.
    pub policies: Vec<DefaultPolicy>,
}

/// The binary-shipped default bundle. Real observability retention tiers —
/// metrics 30d, logs 7d, traces 3d — sensible cell defaults (not placeholders).
#[must_use]
pub fn shipped_default_bundle() -> DefaultBundle {
    const DAY: u64 = 86_400;
    DefaultBundle {
        version: DEFAULT_BUNDLE_VERSION,
        policies: vec![
            DefaultPolicy {
                name: "metrics-default",
                signal_kind: "Metric",
                match_labels: "",
                window_secs: 30 * DAY,
                downsample_secs: None,
            },
            DefaultPolicy {
                name: "logs-default",
                signal_kind: "Log",
                match_labels: "",
                window_secs: 7 * DAY,
                downsample_secs: None,
            },
            DefaultPolicy {
                name: "traces-default",
                signal_kind: "TraceSpan",
                match_labels: "",
                window_secs: 3 * DAY,
                downsample_secs: None,
            },
        ],
    }
}

impl DefaultPolicy {
    /// Render this default as a provenance-labeled `RetentionPolicy` [`Crd`].
    #[must_use]
    pub fn to_crd(&self, version: u32) -> Crd {
        let meta = Metadata::new(self.name)
            .with_label(DEFAULTS_MANAGED_BY_LABEL, DEFAULTS_MANAGED_BY_VALUE)
            .with_label(DEFAULT_BUNDLE_LABEL, version.to_string());
        let mut crd = Crd::new(BUNDLE_API_VERSION, RETENTION_POLICY_KIND, meta)
            .with_spec("signalKind", Value::String(self.signal_kind.to_string()))
            .with_spec("window", Value::Integer(self.window_secs as i64));
        if !self.match_labels.is_empty() {
            crd = crd.with_spec("matchLabels", Value::String(self.match_labels.to_string()));
        }
        if let Some(ds) = self.downsample_secs {
            crd = crd.with_spec("downsampleInterval", Value::Integer(ds as i64));
        }
        crd
    }

    /// Render this default as an applyable **YAML** manifest document — the CRD
    /// shape `pillar apply -f` ([`pillar_manifest::Crd::from_documents`])
    /// consumes, so `pillar render defaults/<name>` output round-trips through
    /// `apply`. Provenance labels are included (via [`Self::to_crd`]).
    #[must_use]
    pub fn to_manifest(&self, version: u32) -> String {
        self.to_crd(version)
            .to_yaml()
            .expect("an in-memory CRD serializes to YAML")
    }
}

/// The classification of a shipped default relative to a cell's live state —
/// the Rust image of the `specs/Defaults.tla` advisory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultStatus {
    /// Applied and unchanged from ship.
    Present,
    /// Net-new: shipped but not present and not tombstoned — adoptable.
    Available,
    /// Applied but the operator has diverged it from ship.
    Edited,
    /// Operator-deleted — never resurrected by seed/bump (`NoResurrect`).
    Tombstoned,
}

impl DefaultStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DefaultStatus::Present => "Present",
            DefaultStatus::Available => "Available",
            DefaultStatus::Edited => "Edited",
            DefaultStatus::Tombstoned => "Tombstoned",
        }
    }
}

/// One shipped default's advisory line: its name and classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultAdvisory {
    pub name: String,
    pub status: DefaultStatus,
}

/// Classify every shipped default against the cell's live state — the pure Rust
/// image of `specs/Defaults.tla`:
///   Tombstoned  (operator-deleted; wins — never resurrected)
///   Edited      (present but diverged from ship)
///   Present     (present and matches ship)
///   Available   (net-new: `(bundleNames \ present) \ tombstoned`)
///
/// `present`/`edited`/`tombstoned` are name sets computed from the resource
/// plane view (present = a `RetentionPolicy/<name>` exists; edited = its applied
/// spec differs from the shipped policy; tombstoned = recorded deletions). The
/// advisory is returned in bundle order.
#[must_use]
pub fn defaults_advisory(
    bundle: &DefaultBundle,
    present: &BTreeSet<String>,
    edited: &BTreeSet<String>,
    tombstoned: &BTreeSet<String>,
) -> Vec<DefaultAdvisory> {
    bundle
        .policies
        .iter()
        .map(|p| {
            let name = p.name.to_string();
            let status = if tombstoned.contains(&name) {
                DefaultStatus::Tombstoned
            } else if present.contains(&name) {
                if edited.contains(&name) {
                    DefaultStatus::Edited
                } else {
                    DefaultStatus::Present
                }
            } else {
                DefaultStatus::Available
            };
            DefaultAdvisory { name, status }
        })
        .collect()
}

/// The count of net-new adoptable defaults — the `DEFAULTS` advisory number the
/// list surface / console badge shows.
#[must_use]
pub fn available_count(advisory: &[DefaultAdvisory]) -> usize {
    advisory
        .iter()
        .filter(|a| a.status == DefaultStatus::Available)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::Crd;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn shipped_bundle_is_versioned_and_nonempty() {
        let b = shipped_default_bundle();
        assert_eq!(b.version, DEFAULT_BUNDLE_VERSION);
        assert!(b.policies.iter().any(|p| p.name == "metrics-default"));
        assert!(b.policies.iter().any(|p| p.name == "logs-default"));
        assert!(b.policies.iter().any(|p| p.name == "traces-default"));
    }

    #[test]
    fn default_renders_provenance_labeled_crd() {
        let p = shipped_default_bundle().policies[0];
        let crd = p.to_crd(7);
        assert_eq!(crd.kind, "RetentionPolicy");
        assert_eq!(crd.metadata.name, "metrics-default");
        assert_eq!(
            crd.metadata
                .labels
                .get(DEFAULTS_MANAGED_BY_LABEL)
                .map(String::as_str),
            Some("defaults")
        );
        assert_eq!(
            crd.metadata
                .labels
                .get(DEFAULT_BUNDLE_LABEL)
                .map(String::as_str),
            Some("7")
        );
        assert_eq!(
            crd.spec.get("signalKind"),
            Some(&Value::String("Metric".into()))
        );
        assert_eq!(crd.spec.get("window"), Some(&Value::Integer(2_592_000)));
    }

    #[test]
    fn manifest_yaml_round_trips_through_from_documents() {
        for p in shipped_default_bundle().policies {
            let text = p.to_manifest(DEFAULT_BUNDLE_VERSION);
            let crds = Crd::from_documents(&text).expect("shipped default YAML must parse");
            assert_eq!(crds.len(), 1, "one document per policy");
            let crd = &crds[0];
            assert_eq!(crd.metadata.name, p.name);
            assert_eq!(crd.kind, "RetentionPolicy");
            assert_eq!(
                crd.spec.get("signalKind"),
                Some(&Value::String(p.signal_kind.into()))
            );
            assert_eq!(
                crd.spec.get("window"),
                Some(&Value::Integer(p.window_secs as i64))
            );
            // Provenance survives the round trip.
            assert_eq!(
                crd.metadata
                    .labels
                    .get(DEFAULTS_MANAGED_BY_LABEL)
                    .map(String::as_str),
                Some("defaults")
            );
        }
    }

    #[test]
    fn advisory_classifies_present_available_edited_tombstoned() {
        let bundle = shipped_default_bundle();
        // metrics present+unchanged, logs edited, traces tombstoned => only the
        // absent ones (none here) are Available; add a 4th-less scenario below.
        let adv = defaults_advisory(
            &bundle,
            &set(&["metrics-default", "logs-default"]),
            &set(&["logs-default"]),
            &set(&["traces-default"]),
        );
        let by = |n: &str| adv.iter().find(|a| a.name == n).unwrap().status;
        assert_eq!(by("metrics-default"), DefaultStatus::Present);
        assert_eq!(by("logs-default"), DefaultStatus::Edited);
        assert_eq!(by("traces-default"), DefaultStatus::Tombstoned);
        assert_eq!(available_count(&adv), 0);
    }

    #[test]
    fn absent_untombstoned_default_is_available_and_counted() {
        let bundle = shipped_default_bundle();
        // Fresh cell: nothing present, nothing tombstoned => all Available.
        let adv = defaults_advisory(&bundle, &set(&[]), &set(&[]), &set(&[]));
        assert!(adv.iter().all(|a| a.status == DefaultStatus::Available));
        assert_eq!(available_count(&adv), bundle.policies.len());

        // Tombstone wins over "absent" — a deleted default is NOT re-offered.
        let adv2 = defaults_advisory(&bundle, &set(&[]), &set(&[]), &set(&["logs-default"]));
        let logs = adv2.iter().find(|a| a.name == "logs-default").unwrap();
        assert_eq!(logs.status, DefaultStatus::Tombstoned);
        assert_eq!(available_count(&adv2), bundle.policies.len() - 1);
    }
}
