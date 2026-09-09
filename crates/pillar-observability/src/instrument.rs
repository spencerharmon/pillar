//! The uniform per-component instrumentation spine.
//!
//! Prior to this module a running node instrumented exactly ONE component —
//! itself — through a closed [`crate::MetricKind`] enum of seven node
//! self-metrics. Every *other* pillar component (streamdb, ipam, rbac, the
//! reconciling controller, …) had no first-class way to emit a named metric,
//! a component-scoped log/span/profile, or a metadata observation, so
//! "comprehensive observability" was structurally impossible: the emit paths
//! only knew node-self quantities.
//!
//! This module lifts the two limits that blocked full coverage without
//! forking the op-log or adding a second authority path:
//!
//! 1. **Open metric typing** ([`MetricType`], [`MetricDescriptor`],
//!    [`MetricRegistry`]). A component registers each series it instruments
//!    ONCE, declaring whether it is a monotonic [`MetricType::Counter`], an
//!    instantaneous [`MetricType::Gauge`], or a [`MetricType::Histogram`],
//!    plus its unit. The descriptor rides every emitted sample as indexed
//!    labels (`mtype`, `unit`, `component`) so a reader (the query console)
//!    can render/aggregate correctly — e.g. `rate()` is only meaningful on a
//!    counter. This REPLACES the closed [`crate::MetricKind`] for
//!    component-defined series; the node self-metrics keep their enum.
//!
//! 2. **Correlation-first context** ([`Cx`]). A single [`Cx`] threaded through
//!    a request/reconcile/op carries the causal thread's
//!    [`CorrelationId`](crate::CorrelationId) (and the current span id, so the
//!    next span parents correctly), so a log, a metric, a span, and a profile
//!    emitted for the SAME operation pivot together through the existing
//!    [`CorrelationIndex`](crate::CorrelationIndex).
//!
//! The emit surface itself — the generic labeled writes and the
//! [`ComponentProbe`](crate::ComponentProbe) handle each component holds —
//! lives on [`LiveObservabilitySubstrate`](crate::LiveObservabilitySubstrate),
//! because it needs the one shared store/index every producer already writes.
//! This module holds only the dependency-free, host-tested *types*.

use std::collections::BTreeMap;

use crate::correlation::CorrelationId;
use crate::metadata::EntityId;

/// The label key carrying a metric's [`MetricType`] on every emitted sample,
/// so a reader knows which aggregations are valid (`rate()` on a counter, a
/// last-value on a gauge, a bucket rollup on a histogram).
pub const METRIC_TYPE_LABEL: &str = "mtype";
/// The label key carrying a metric's unit (`bytes`, `seconds`, `1`, …).
pub const METRIC_UNIT_LABEL: &str = "unit";
/// The label key carrying the emitting component on every signal.
pub const COMPONENT_LABEL: &str = "component";

/// How a metric series is interpreted by a reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricType {
    /// A value that only ever increases (until a process restart resets it).
    /// A rate/delta is the meaningful derived view; the raw value is a
    /// running total.
    Counter,
    /// An instantaneous value that can move in either direction. The raw
    /// value is the meaningful view; a rate is NOT meaningful.
    Gauge,
    /// A distribution of observations. The emitted value is one observation;
    /// a reader rolls observations into buckets/quantiles.
    Histogram,
}

impl MetricType {
    /// The stable wire tag carried in the [`METRIC_TYPE_LABEL`] label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
        }
    }

    /// Parse the wire tag back into a [`MetricType`].
    #[must_use]
    pub fn from_tag(s: &str) -> Option<MetricType> {
        match s {
            "counter" => Some(MetricType::Counter),
            "gauge" => Some(MetricType::Gauge),
            "histogram" => Some(MetricType::Histogram),
            _ => None,
        }
    }

    /// Whether a rate/delta over time is a meaningful derived view of this
    /// series (true only for a monotonic counter).
    #[must_use]
    pub fn supports_rate(self) -> bool {
        matches!(self, MetricType::Counter)
    }
}

/// The descriptor for one metric series a component instruments.
///
/// The `name` is the stable series identity carried in the `metric` label
/// (`crate::METRIC_NAME_LABEL`) exactly as the node self-metrics use it, so a
/// component series and a node series are queried/rendered through the one
/// path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricDescriptor {
    /// The stable series name, e.g. `ipam_allocations_total`. Carried in the
    /// `metric` label AND the payload's leading token.
    pub name: String,
    /// Whether this series is a counter/gauge/histogram.
    pub ty: MetricType,
    /// The unit (`bytes`, `seconds`, `1` for a dimensionless count).
    pub unit: String,
    /// The component that owns/emits this series (`ipam`, `streamdb`, …).
    pub component: String,
}

impl MetricDescriptor {
    /// A descriptor with an explicit unit.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        ty: MetricType,
        unit: impl Into<String>,
        component: impl Into<String>,
    ) -> MetricDescriptor {
        MetricDescriptor {
            name: name.into(),
            ty,
            unit: unit.into(),
            component: component.into(),
        }
    }

    /// A dimensionless counter (`unit = "1"`).
    #[must_use]
    pub fn counter(name: impl Into<String>, component: impl Into<String>) -> MetricDescriptor {
        MetricDescriptor::new(name, MetricType::Counter, "1", component)
    }

    /// A dimensionless gauge (`unit = "1"`).
    #[must_use]
    pub fn gauge(name: impl Into<String>, component: impl Into<String>) -> MetricDescriptor {
        MetricDescriptor::new(name, MetricType::Gauge, "1", component)
    }

    /// The descriptor dimensions promoted onto every emitted sample as indexed
    /// labels (`mtype`, `unit`, `component`), so a reader can filter/aggregate
    /// by type/unit/owner without parsing the payload.
    #[must_use]
    pub fn label_pairs(&self) -> [(&'static str, String); 3] {
        [
            (METRIC_TYPE_LABEL, self.ty.as_str().to_owned()),
            (METRIC_UNIT_LABEL, self.unit.clone()),
            (COMPONENT_LABEL, self.component.clone()),
        ]
    }
}

/// The process-wide registry of metric descriptors.
///
/// A component registers each series it instruments once (at startup); the
/// substrate consults the registry on every
/// [`emit_metric`](crate::LiveObservabilitySubstrate::emit_metric) to stamp
/// the series' type/unit/component labels. An unregistered name is REJECTED at
/// emit time (fail-closed) rather than emitted with a fabricated type — a
/// metric whose interpretation is unknown is worse than absent, because a
/// reader would apply the wrong aggregation to it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricRegistry {
    descriptors: BTreeMap<String, MetricDescriptor>,
}

impl MetricRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> MetricRegistry {
        MetricRegistry {
            descriptors: BTreeMap::new(),
        }
    }

    /// Register a series descriptor. Re-registering the SAME name with the
    /// SAME descriptor is idempotent; re-registering with a DIFFERENT type/
    /// unit is a caller bug (two owners disagree on a series' meaning) and is
    /// rejected with `false`, leaving the first registration authoritative.
    pub fn register(&mut self, descriptor: MetricDescriptor) -> bool {
        match self.descriptors.get(&descriptor.name) {
            Some(existing) if existing == &descriptor => true,
            Some(_) => false,
            None => {
                self.descriptors.insert(descriptor.name.clone(), descriptor);
                true
            }
        }
    }

    /// The descriptor for `name`, if registered.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&MetricDescriptor> {
        self.descriptors.get(name)
    }

    /// Whether `name` is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.descriptors.contains_key(name)
    }

    /// The number of registered series.
    #[must_use]
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Every registered descriptor, sorted by name.
    pub fn descriptors(&self) -> impl Iterator<Item = &MetricDescriptor> {
        self.descriptors.values()
    }
}

/// The correlation context threaded through one causal operation so that every
/// signal kind it emits (log, metric, span, profile, metadata) shares a
/// [`CorrelationId`] and composes into one trace.
///
/// A component creates a root [`Cx`] at an operation boundary (an inbound
/// request, a reconcile pass, an applied op) and passes it down; each emitted
/// span advances `span` so the next child parents correctly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cx {
    /// The causal thread id — becomes the `trace` label and the
    /// [`CorrelationId`] on every signal emitted under this context.
    pub correlation: CorrelationId,
    /// The current span id, if a span is open — the parent for the next child
    /// span emitted under this context. `None` at the root before the first
    /// span.
    pub span: Option<String>,
    /// The subject entity under operation (e.g. `workload/web-0`,
    /// `ipam-pool/default`), stamped as the `entity` label so an operation's
    /// signals pivot to the entity's metadata-over-time.
    pub entity: Option<EntityId>,
}

impl Cx {
    /// A root context for causal thread `correlation`, no span open yet.
    #[must_use]
    pub fn new(correlation: impl Into<String>) -> Cx {
        Cx {
            correlation: CorrelationId(correlation.into()),
            span: None,
            entity: None,
        }
    }

    /// This context tagged with the entity under operation.
    #[must_use]
    pub fn with_entity(mut self, entity: EntityId) -> Cx {
        self.entity = Some(entity);
        self
    }

    /// A child context whose parent span is `span_id` — returned after opening
    /// a span so subsequently-emitted spans nest under it.
    #[must_use]
    pub fn in_span(&self, span_id: impl Into<String>) -> Cx {
        Cx {
            correlation: self.correlation.clone(),
            span: Some(span_id.into()),
            entity: self.entity.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_type_wire_tag_round_trips_and_gates_rate() {
        for ty in [
            MetricType::Counter,
            MetricType::Gauge,
            MetricType::Histogram,
        ] {
            assert_eq!(MetricType::from_tag(ty.as_str()), Some(ty));
        }
        assert_eq!(MetricType::from_tag("bogus"), None);
        assert!(MetricType::Counter.supports_rate());
        assert!(!MetricType::Gauge.supports_rate());
        assert!(!MetricType::Histogram.supports_rate());
    }

    #[test]
    fn descriptor_promotes_type_unit_component_labels() {
        let d = MetricDescriptor::new("ipam_pool_used_bytes", MetricType::Gauge, "bytes", "ipam");
        let pairs = d.label_pairs();
        assert_eq!(pairs[0], (METRIC_TYPE_LABEL, "gauge".to_owned()));
        assert_eq!(pairs[1], (METRIC_UNIT_LABEL, "bytes".to_owned()));
        assert_eq!(pairs[2], (COMPONENT_LABEL, "ipam".to_owned()));
    }

    #[test]
    fn registry_is_idempotent_on_same_and_fail_closed_on_conflict() {
        let mut reg = MetricRegistry::new();
        let c = MetricDescriptor::counter("ipam_allocations_total", "ipam");
        assert!(reg.register(c.clone()));
        // Same descriptor again -> idempotent OK, no duplicate.
        assert!(reg.register(c.clone()));
        assert_eq!(reg.len(), 1);
        // Same NAME, different TYPE -> rejected; first registration stands.
        let conflict =
            MetricDescriptor::new("ipam_allocations_total", MetricType::Gauge, "1", "ipam");
        assert!(!reg.register(conflict));
        assert_eq!(
            reg.get("ipam_allocations_total").unwrap().ty,
            MetricType::Counter
        );
        assert!(reg.contains("ipam_allocations_total"));
        assert!(!reg.contains("unknown"));
    }

    #[test]
    fn cx_threads_correlation_and_advances_span_parent() {
        let root = Cx::new("req-42").with_entity(EntityId("workload/web-0".to_owned()));
        assert_eq!(root.correlation, CorrelationId("req-42".to_owned()));
        assert!(root.span.is_none());
        let child = root.in_span("span-1");
        assert_eq!(child.correlation, root.correlation);
        assert_eq!(child.span.as_deref(), Some("span-1"));
        // Entity is inherited by the child span.
        assert_eq!(child.entity, root.entity);
    }
}
