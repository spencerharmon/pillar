//! Core Pillar types shared across crates.
//!
//! Nothing here reaches the network or the filesystem; these are the value
//! types that the formally-specified protocols operate over. Keeping them
//! dependency-free keeps the model/implementation correspondence auditable.

use std::fmt;

/// A participating node identity.
///
/// In production a node is authenticated by an OpenPGP node-subkey; this
/// newtype carries the stable fingerprint string used as its identity in the
/// coordination protocol. It deliberately does not embed key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_owned())
    }
}

/// A monotonic fencing token.
///
/// Corresponds to `Epochs` in `specs/CoordinationCore.tla`. A higher epoch
/// fences all lower ones: downstream consumers must reject actions carrying a
/// stale epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The initial epoch.
    pub const ZERO: Epoch = Epoch(0);

    /// The next epoch after this one.
    #[must_use]
    pub fn next(self) -> Epoch {
        Epoch(self.0 + 1)
    }
}

/// How a resource's side effects behave, which determines the minimum
/// consistency a view over it may declare.
///
/// This is the classification a controller author MUST make (see
/// `docs/consistency-model.md`). The platform refuses to run an [`Exclusive`]
/// action under a [`ViewPolicy::Relaxed`] view.
///
/// [`Exclusive`]: SideEffect::Exclusive
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideEffect {
    /// Non-idempotent and/or requires exactly-one execution: firing a cronjob
    /// that emails customers, claiming a public DNS name, allocating a unique
    /// address, running a stateful singleton. Requires the CP coordination
    /// core.
    Exclusive,
    /// Idempotent / convergent / cheaply reclaimable: a stateless replica, an
    /// ECMP-absorbed route advertisement, an allocation that is later GC'd.
    /// Spurious duplication is tolerable; may run under a relaxed view.
    Convergent,
}

/// The consistency policy a view opts into for its underlying stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewPolicy {
    /// Quorum-fenced: exclusive actions are gated on the coordination core.
    /// A minority partition refuses to act.
    Strict,
    /// Eventually-consistent (CRDT) merge; no exclusivity guarantee.
    Relaxed,
}

impl ViewPolicy {
    /// Whether this policy is permitted to authorize the given side effect.
    ///
    /// Safe-by-default: only a [`Strict`] view may authorize an [`Exclusive`]
    /// action.
    ///
    /// [`Strict`]: ViewPolicy::Strict
    /// [`Exclusive`]: SideEffect::Exclusive
    #[must_use]
    pub fn admits(self, effect: SideEffect) -> bool {
        match (self, effect) {
            (ViewPolicy::Strict, _) => true,
            (ViewPolicy::Relaxed, SideEffect::Convergent) => true,
            (ViewPolicy::Relaxed, SideEffect::Exclusive) => false,
        }
    }
}

// =====================================================================
// Dependency-inverted observability seam.
// =====================================================================
//
// `pillar-observability` depends on the low-level crates (streamdb, topology,
// wot-authority, manifest, core), so those crates CANNOT depend back on it to
// instrument themselves without forming a cycle. The seam below lives here in
// dependency-free `pillar-core` — which every crate already depends on — so any
// crate can emit a metric/log/span/profile through an injected
// [`ObserverHook`] trait object WITHOUT linking `pillar-observability`.
//
// `pillar-observability` provides the concrete adapter (`ProbeObserver`) that
// implements this trait by forwarding to a `ComponentProbe`; the composition
// root (`pillar node run`) constructs the adapter once and injects it. A crate
// that is handed no observer uses [`NoopObserver`], so instrumentation is
// always safe to call and never a hard dependency.
//
// These are pure value types + a trait: no wire format, no store, no tick
// clock (the adapter stamps the current logical tick), so they add no new
// distributed invariant and need no TLA+ change.

/// How an emitted metric series is interpreted by a reader, mirroring
/// `pillar_observability::MetricType` without creating a dependency edge. The
/// adapter maps this 1:1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObsMetricType {
    /// A monotonically increasing running total; a rate/delta is the
    /// meaningful derived view.
    Counter,
    /// An instantaneous value that can move either direction.
    Gauge,
    /// One observation of a distribution.
    Histogram,
}

/// The severity of an emitted log occurrence, mirroring
/// `pillar_observability::LogLevel` (same order/variants) without a dependency
/// edge. The adapter maps this 1:1 and the substrate's min-level gate applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObsLevel {
    /// Fine-grained diagnostic detail.
    Trace,
    /// Diagnostic detail useful in development.
    Debug,
    /// Normal operational information.
    Info,
    /// A recoverable, noteworthy condition.
    Warn,
    /// A failure condition.
    Error,
}

/// The causal-thread context a crate threads through one operation so its
/// emissions correlate, mirroring `pillar_observability::Cx` without a
/// dependency edge. `correlation` becomes the trace id; `span` is the open
/// parent span, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObsCx {
    /// The causal-thread id shared by every signal emitted under this context.
    pub correlation: String,
    /// The current open span id — the parent for the next child span, if any.
    pub span: Option<String>,
}

impl ObsCx {
    /// A root context for causal thread `correlation`, no span open yet.
    #[must_use]
    pub fn new(correlation: impl Into<String>) -> ObsCx {
        ObsCx {
            correlation: correlation.into(),
            span: None,
        }
    }

    /// A child context whose parent span is `span_id`.
    #[must_use]
    pub fn in_span(&self, span_id: impl Into<String>) -> ObsCx {
        ObsCx {
            correlation: self.correlation.clone(),
            span: Some(span_id.into()),
        }
    }
}

/// The dependency-inverted instrumentation surface a crate emits through.
///
/// A crate holds an `Arc<dyn ObserverHook>` (defaulting to [`NoopObserver`]),
/// registers each metric series once at construction, and emits at its real
/// event points. The adapter injected by the composition root stamps the
/// current logical tick and forwards to the shared substrate, so a crate never
/// needs a tick clock, the wire format, or a link to `pillar-observability`.
///
/// All methods take `&self` (an observer is shared, `Send + Sync`); the adapter
/// serializes writes internally. Every method has a semantics identical to the
/// substrate emit surface it forwards to — e.g. an unregistered metric name is
/// dropped fail-closed, a log below the min level is dropped.
pub trait ObserverHook: Send + Sync {
    /// Register a metric series this component will emit (idempotent; a
    /// conflicting redefinition is rejected downstream). `component` is the
    /// emitting crate/subsystem; `unit` is e.g. `bytes`, `seconds`, `1`.
    fn register_metric(&self, name: &str, ty: ObsMetricType, unit: &str, component: &str);

    /// Emit one reading of a previously-registered metric series. An
    /// unregistered `name` is dropped fail-closed.
    fn metric(&self, name: &str, value: f64);

    /// Emit one component log occurrence, optionally correlated by `cx`.
    fn log(&self, level: ObsLevel, message: &str, cx: Option<&ObsCx>);

    /// Emit one trace span for operation `operation` with id `span_id`,
    /// correlated by `cx` (its `correlation` is the trace id; its `span`, if
    /// set, is the parent).
    fn span(&self, cx: &ObsCx, span_id: &str, operation: &str);

    /// Convenience: emit `value` for `name` at the default level of detail.
    /// Provided so a call site reads as an increment/gauge-set without the
    /// caller repeating the running total plumbing.
    fn gauge(&self, name: &str, value: f64) {
        self.metric(name, value);
    }
}

/// An [`ObserverHook`] that drops every emission. The default a crate uses when
/// the composition root injects no real observer, so instrumentation calls are
/// always safe and never a hard dependency.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopObserver;

impl ObserverHook for NoopObserver {
    fn register_metric(&self, _name: &str, _ty: ObsMetricType, _unit: &str, _component: &str) {}
    fn metric(&self, _name: &str, _value: f64) {}
    fn log(&self, _level: ObsLevel, _message: &str, _cx: Option<&ObsCx>) {}
    fn span(&self, _cx: &ObsCx, _span_id: &str, _operation: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_monotonic() {
        assert!(Epoch::ZERO < Epoch::ZERO.next());
        assert_eq!(Epoch::ZERO.next(), Epoch(1));
    }

    #[test]
    fn relaxed_view_refuses_exclusive_effects() {
        // The guardrail from docs/consistency-model.md, in code.
        assert!(!ViewPolicy::Relaxed.admits(SideEffect::Exclusive));
        assert!(ViewPolicy::Relaxed.admits(SideEffect::Convergent));
        assert!(ViewPolicy::Strict.admits(SideEffect::Exclusive));
        assert!(ViewPolicy::Strict.admits(SideEffect::Convergent));
    }

    // A spy observer proving a crate can emit through the inverted seam with no
    // link to pillar-observability. This is exactly the shape a real crate
    // (ipam, streamdb, controller) uses.
    #[derive(Default)]
    struct SpyObserver {
        registered: std::sync::Mutex<Vec<(String, ObsMetricType, String, String)>>,
        metrics: std::sync::Mutex<Vec<(String, f64)>>,
        logs: std::sync::Mutex<Vec<(ObsLevel, String, Option<String>)>>,
        spans: std::sync::Mutex<Vec<(String, Option<String>, String, String)>>,
    }

    impl ObserverHook for SpyObserver {
        fn register_metric(&self, name: &str, ty: ObsMetricType, unit: &str, component: &str) {
            self.registered.lock().unwrap().push((
                name.to_owned(),
                ty,
                unit.to_owned(),
                component.to_owned(),
            ));
        }
        fn metric(&self, name: &str, value: f64) {
            self.metrics.lock().unwrap().push((name.to_owned(), value));
        }
        fn log(&self, level: ObsLevel, message: &str, cx: Option<&ObsCx>) {
            self.logs.lock().unwrap().push((
                level,
                message.to_owned(),
                cx.map(|c| c.correlation.clone()),
            ));
        }
        fn span(&self, cx: &ObsCx, span_id: &str, operation: &str) {
            self.spans.lock().unwrap().push((
                cx.correlation.clone(),
                cx.span.clone(),
                span_id.to_owned(),
                operation.to_owned(),
            ));
        }
    }

    #[test]
    fn a_crate_emits_through_the_injected_observer() {
        let spy = std::sync::Arc::new(SpyObserver::default());
        let obs: std::sync::Arc<dyn ObserverHook> = spy.clone();
        obs.register_metric(
            "ipam_allocations_total",
            ObsMetricType::Counter,
            "1",
            "ipam",
        );
        obs.metric("ipam_allocations_total", 3.0);
        let cx = ObsCx::new("req-1");
        obs.log(ObsLevel::Warn, "pool nearly full", Some(&cx));
        let child = cx.in_span("s1");
        obs.span(&child, "s2", "allocate");

        assert_eq!(spy.registered.lock().unwrap()[0].1, ObsMetricType::Counter);
        assert_eq!(
            spy.metrics.lock().unwrap()[0],
            ("ipam_allocations_total".to_owned(), 3.0)
        );
        assert_eq!(
            spy.logs.lock().unwrap()[0],
            (
                ObsLevel::Warn,
                "pool nearly full".to_owned(),
                Some("req-1".to_owned())
            )
        );
        // The child span carries the parent span id from the Cx.
        assert_eq!(spy.spans.lock().unwrap()[0].1, Some("s1".to_owned()));
    }

    #[test]
    fn noop_observer_drops_everything_safely() {
        let obs: std::sync::Arc<dyn ObserverHook> = std::sync::Arc::new(NoopObserver);
        obs.register_metric("x", ObsMetricType::Gauge, "1", "c");
        obs.metric("x", 1.0);
        obs.log(ObsLevel::Info, "hi", None);
        obs.span(&ObsCx::new("t"), "s", "op");
        // No panic, no state — a crate with no real observer is unaffected.
    }

    #[test]
    fn obs_level_orders_by_severity() {
        assert!(ObsLevel::Trace < ObsLevel::Warn);
        assert!(ObsLevel::Warn < ObsLevel::Error);
    }
}
