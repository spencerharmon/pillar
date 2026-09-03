//! Per-signal / per-label retention + downsampling expressed as a **built-in
//! resource** — a manifest, not a hardcoded config flag — layered over the
//! store's existing compaction ([`crate::TimeseriesStore::compact`]).
//!
//! ROI P0 "synergy everywhere": rather than growing a bespoke config surface,
//! retention and downsampling are declared the SAME way every other pillar
//! feature is — as a resource with a spec that pillar reconciles. A
//! [`RetentionPolicy`] targets a [`SignalKind`] and a [`LabelSelector`] and
//! declares (a) a retention `window` shorter than the store default, and/or
//! (b) a `downsample` interval that coarsens the retained series. The store
//! applies the SHORTEST matching window at write time and admits at most one
//! representative per downsample bucket — so a policy shortens/downsamples
//! exactly the data its selector picks and leaves everything else untouched.
//!
//! The wire form is the built-in `RetentionPolicy` manifest under
//! `apiVersion: pillar.dev/v1` (the one registry every built-in kind shares);
//! [`RetentionPolicy::from_spec`] lowers a validated manifest `spec` into this
//! in-memory policy, so the resource model — not a config flag — is the single
//! source of truth.

use std::collections::BTreeMap;

use crate::block::SignalKind;
use crate::metadata::LabelSet;

/// The built-in resource `apiVersion`/`kind` a retention policy is declared as.
pub const RETENTION_POLICY_API_VERSION: &str = "pillar.dev/v1";
/// The built-in resource `kind` a retention policy is declared as.
pub const RETENTION_POLICY_KIND: &str = "RetentionPolicy";

/// A label selector: an equality match over a set of `label = value` pairs. A
/// signal matches when it carries EVERY selector pair with the exact value
/// (superset match). An empty selector matches every signal of the target
/// kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LabelSelector {
    match_labels: LabelSet,
}

impl LabelSelector {
    /// A selector matching every signal (of its policy's kind).
    #[must_use]
    pub fn everything() -> Self {
        LabelSelector {
            match_labels: LabelSet::new(),
        }
    }

    /// A selector requiring exactly the given `label = value` equality pairs.
    #[must_use]
    pub fn matching<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        LabelSelector {
            match_labels: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// The selector's required equality pairs.
    #[must_use]
    pub fn match_labels(&self) -> &LabelSet {
        &self.match_labels
    }

    /// Whether `labels` satisfies this selector — it must carry every required
    /// pair with the exact value. An empty selector matches anything.
    #[must_use]
    pub fn matches(&self, labels: &LabelSet) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| labels.get(k).is_some_and(|got| got == v))
    }

    /// A stable, unique key for this selector — used to bucket downsampling so
    /// two distinct selectors never share a bucket namespace.
    #[must_use]
    fn key(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.match_labels {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push(';');
        }
        s
    }
}

/// One per-signal / per-label retention + downsampling policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// The signal kind this policy governs.
    pub kind: SignalKind,
    /// The label selector this policy applies to.
    pub selector: LabelSelector,
    /// The retention window (ticks) for matching signals — shorter than the
    /// store default shortens their lifetime. `None` = do not change retention
    /// (a pure downsample policy).
    pub window: Option<u64>,
    /// The downsample interval (ticks): at most one representative matching
    /// signal is retained per `interval`-tick bucket. `None` = no downsampling.
    pub downsample: Option<u64>,
}

impl RetentionPolicy {
    /// Whether this policy applies to a signal of `kind` carrying `labels`.
    #[must_use]
    pub fn matches(&self, kind: SignalKind, labels: &LabelSet) -> bool {
        self.kind == kind && self.selector.matches(labels)
    }

    /// The bucket-namespace key `(kind, selector)` this policy downsamples in.
    #[must_use]
    fn bucket_key(&self) -> String {
        format!("{:?}|{}", self.kind, self.selector.key())
    }
}

/// The effective retention decision for a written signal, after applying every
/// matching policy in a [`RetentionPolicySet`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveRetention {
    /// The shortest matching policy window, or `None` when no policy set one
    /// (the store then uses its default window).
    pub window: Option<u64>,
    /// `Some((bucket_key, interval))` when a matching policy downsamples.
    pub downsample: Option<(String, u64)>,
}

/// The installed set of retention/downsampling policies — the built-in
/// resource state the store consults on every write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionPolicySet {
    policies: Vec<RetentionPolicy>,
}

impl RetentionPolicySet {
    /// The empty policy set (every signal uses the store default window, no
    /// downsampling).
    #[must_use]
    pub fn empty() -> Self {
        RetentionPolicySet {
            policies: Vec::new(),
        }
    }

    /// A policy set from an explicit list of policies.
    #[must_use]
    pub fn from_policies(policies: Vec<RetentionPolicy>) -> Self {
        RetentionPolicySet { policies }
    }

    /// Add a policy to the set.
    pub fn add(&mut self, policy: RetentionPolicy) {
        self.policies.push(policy);
    }

    /// The installed policies.
    #[must_use]
    pub fn policies(&self) -> &[RetentionPolicy] {
        &self.policies
    }

    /// The effective retention for a signal of `kind` carrying `labels`: the
    /// shortest window over every matching policy, plus the first matching
    /// downsample directive. A signal matched by NO policy yields an empty
    /// [`EffectiveRetention`] (the store falls back to its default) — so a
    /// policy never applies beyond its own selector.
    #[must_use]
    pub fn effective(&self, kind: SignalKind, labels: &LabelSet) -> EffectiveRetention {
        let mut eff = EffectiveRetention::default();
        for policy in &self.policies {
            if !policy.matches(kind, labels) {
                continue;
            }
            if let Some(w) = policy.window {
                eff.window = Some(match eff.window {
                    Some(existing) => existing.min(w),
                    None => w,
                });
            }
            if let (None, Some(interval)) = (&eff.downsample, policy.downsample) {
                eff.downsample = Some((policy.bucket_key(), interval));
            }
        }
        eff
    }
}

/// The minimal validated manifest fields a [`RetentionPolicy`] is lowered from.
/// A real deployment obtains these from the shared manifest/`SchemaRegistry`
/// path (`pillar-manifest`'s built-in resource machinery); this struct is the
/// crate-local, dependency-free projection of that validated `spec` so the
/// observability store depends only on the parsed policy, not the manifest
/// crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicySpec {
    /// `spec.signalKind` — one of the [`SignalKind`] variants, by name.
    pub signal_kind: String,
    /// `spec.selector.matchLabels` — the equality selector.
    pub match_labels: BTreeMap<String, String>,
    /// `spec.window` — retention window in ticks (optional).
    pub window: Option<u64>,
    /// `spec.downsampleInterval` — downsample bucket size in ticks (optional).
    pub downsample_interval: Option<u64>,
}

impl RetentionPolicy {
    /// Lower a validated manifest `spec` into an in-memory policy. Returns
    /// `None` for an unknown `signalKind` (the schema layer rejects a malformed
    /// manifest before this; the `None` here defends against an unknown kind
    /// string).
    #[must_use]
    pub fn from_spec(spec: &RetentionPolicySpec) -> Option<RetentionPolicy> {
        let kind = signal_kind_from_str(&spec.signal_kind)?;
        Some(RetentionPolicy {
            kind,
            selector: LabelSelector::matching(spec.match_labels.clone()),
            window: spec.window,
            downsample: spec.downsample_interval,
        })
    }
}

/// Parse a [`SignalKind`] from its manifest name.
#[must_use]
pub fn signal_kind_from_str(s: &str) -> Option<SignalKind> {
    match s {
        "Metric" => Some(SignalKind::Metric),
        "Log" => Some(SignalKind::Log),
        "TraceSpan" => Some(SignalKind::TraceSpan),
        "ProfileSample" => Some(SignalKind::ProfileSample),
        "MetadataSample" => Some(SignalKind::MetadataSample),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::TimeseriesStore;

    fn labels(pairs: &[(&str, &str)]) -> LabelSet {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// A retention policy for a given signal kind + label selector actually
    /// shortens the matched data's lifetime in the store: a fixture written
    /// then aged past the POLICY window (well before the default window) is
    /// compacted away — verified against a real store, not a mock.
    #[test]
    fn a_policy_shortens_matched_datas_lifetime_in_the_store() {
        // Default window is long (1000). The policy shortens Metric{app=web}
        // to a 10-tick window.
        let mut store = TimeseriesStore::new(1, 1000);
        let mut policies = RetentionPolicySet::empty();
        policies.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::matching([("app", "web")]),
            window: Some(10),
            downsample: None,
        });
        store.set_policies(policies);

        // Write the matched fixture at tick 0, then a second signal so the
        // matched block seals (capacity 1 seals immediately).
        let matched = store
            .write_labeled(
                SignalKind::Metric,
                b"cpu{app=web}".to_vec(),
                labels(&[("app", "web")]),
                0,
            )
            .expect("not downsampled");
        store.write_labeled(SignalKind::Metric, b"open".to_vec(), LabelSet::new(), 0);

        // The policy fixed the deadline at the POLICY window (10), not the
        // store default (1000).
        assert_eq!(store.expiry_of(&matched), Some(10));
        assert!(store.contains(&matched));

        // Age past the policy window but FAR short of the default window.
        assert_eq!(store.compact(9), 0, "not yet past the policy window");
        assert!(store.contains(&matched));
        assert_eq!(store.compact(10), 1, "past the policy window -> dropped");
        assert!(!store.contains(&matched));
        // Retention drops, never rewrites history.
        assert!(store.was_written(&matched));
    }

    /// A policy for one signal/label selector does NOT affect data outside its
    /// selector: a signal of a different kind, and one of the same kind but
    /// with non-matching labels, keep the store default (long) lifetime and
    /// survive well past the policy window (no over-broad application).
    #[test]
    fn a_policy_does_not_affect_data_outside_its_selector() {
        let mut store = TimeseriesStore::new(1, 1000);
        let mut policies = RetentionPolicySet::empty();
        policies.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::matching([("app", "web")]),
            window: Some(10),
            downsample: None,
        });
        store.set_policies(policies);

        // Same kind, DIFFERENT label value -> selector misses -> default window.
        let other_labels = store
            .write_labeled(
                SignalKind::Metric,
                b"cpu{app=db}".to_vec(),
                labels(&[("app", "db")]),
                0,
            )
            .expect("not downsampled");
        // Different KIND entirely -> selector misses -> default window.
        let other_kind = store
            .write_labeled(
                SignalKind::Log,
                b"log{app=web}".to_vec(),
                labels(&[("app", "web")]),
                0,
            )
            .expect("not downsampled");
        // Seal both blocks.
        store.write_labeled(SignalKind::Metric, b"open".to_vec(), LabelSet::new(), 0);

        assert_eq!(store.expiry_of(&other_labels), Some(1000));
        assert_eq!(store.expiry_of(&other_kind), Some(1000));

        // Well past the policy window (10) but short of the default (1000):
        // neither out-of-selector signal is dropped.
        assert_eq!(store.compact(500), 0, "out-of-selector data must survive");
        assert!(store.contains(&other_labels));
        assert!(store.contains(&other_kind));
    }

    /// The empty selector matches every signal of its kind; a value mismatch or
    /// a missing label misses.
    #[test]
    fn selector_matches_are_exact_equality_supersets() {
        let sel = LabelSelector::matching([("app", "web")]);
        assert!(sel.matches(&labels(&[("app", "web")])));
        assert!(sel.matches(&labels(&[("app", "web"), ("zone", "a")])));
        assert!(!sel.matches(&labels(&[("app", "db")])));
        assert!(!sel.matches(&labels(&[("zone", "a")])));
        assert!(LabelSelector::everything().matches(&LabelSet::new()));
    }

    /// The shortest matching window wins when several policies overlap.
    #[test]
    fn shortest_matching_window_wins() {
        let mut set = RetentionPolicySet::empty();
        set.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::everything(),
            window: Some(100),
            downsample: None,
        });
        set.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::matching([("app", "web")]),
            window: Some(10),
            downsample: None,
        });
        assert_eq!(
            set.effective(SignalKind::Metric, &labels(&[("app", "web")]))
                .window,
            Some(10)
        );
        assert_eq!(
            set.effective(SignalKind::Metric, &labels(&[("app", "db")]))
                .window,
            Some(100)
        );
        assert_eq!(set.effective(SignalKind::Log, &LabelSet::new()).window, None);
    }

    /// A downsample policy admits at most one representative per bucket for its
    /// selector, and never affects signals outside the selector.
    #[test]
    fn downsample_coarsens_only_the_selected_series() {
        let mut store = TimeseriesStore::new(16, 1000);
        let mut policies = RetentionPolicySet::empty();
        policies.add(RetentionPolicy {
            kind: SignalKind::Metric,
            selector: LabelSelector::matching([("app", "web")]),
            window: None,
            downsample: Some(10),
        });
        store.set_policies(policies);

        // Three matched writes within one 10-tick bucket -> one admitted.
        let first = store.write_labeled(
            SignalKind::Metric,
            b"m1".to_vec(),
            labels(&[("app", "web")]),
            0,
        );
        let second = store.write_labeled(
            SignalKind::Metric,
            b"m2".to_vec(),
            labels(&[("app", "web")]),
            3,
        );
        let third = store.write_labeled(
            SignalKind::Metric,
            b"m3".to_vec(),
            labels(&[("app", "web")]),
            9,
        );
        assert!(first.is_some());
        assert!(second.is_none(), "same bucket -> downsampled away");
        assert!(third.is_none(), "same bucket -> downsampled away");

        // Next bucket -> admitted again.
        let next_bucket = store.write_labeled(
            SignalKind::Metric,
            b"m4".to_vec(),
            labels(&[("app", "web")]),
            10,
        );
        assert!(next_bucket.is_some());

        // Out-of-selector signal is never downsampled.
        let other = store.write_labeled(
            SignalKind::Metric,
            b"o1".to_vec(),
            labels(&[("app", "db")]),
            0,
        );
        let other2 = store.write_labeled(
            SignalKind::Metric,
            b"o2".to_vec(),
            labels(&[("app", "db")]),
            3,
        );
        assert!(other.is_some());
        assert!(other2.is_some(), "out-of-selector data is not downsampled");
    }

    /// A policy is lowered from a validated manifest `spec` — the built-in
    /// resource path, not a config flag.
    #[test]
    fn policy_is_lowered_from_a_manifest_spec() {
        let spec = RetentionPolicySpec {
            signal_kind: "Metric".to_string(),
            match_labels: labels(&[("app", "web")]),
            window: Some(30),
            downsample_interval: Some(5),
        };
        let policy = RetentionPolicy::from_spec(&spec).expect("valid kind");
        assert_eq!(policy.kind, SignalKind::Metric);
        assert!(policy.selector.matches(&labels(&[("app", "web")])));
        assert_eq!(policy.window, Some(30));
        assert_eq!(policy.downsample, Some(5));

        // Unknown kind name is rejected.
        let bad = RetentionPolicySpec {
            signal_kind: "Nonsense".to_string(),
            match_labels: BTreeMap::new(),
            window: None,
            downsample_interval: None,
        };
        assert!(RetentionPolicy::from_spec(&bad).is_none());
    }
}
