//! Built-in resource kinds — the "synergy spine" (ROI Priority 0).
//!
//! A manifest may declare a resource kind pillar validates and reconciles
//! **natively**: [`BuiltinKind::Dashboard`], [`BuiltinKind::RecordingRule`],
//! [`BuiltinKind::Alert`], [`BuiltinKind::SignalConfig`], [`BuiltinKind::Job`],
//! and [`BuiltinKind::CronJob`]. The load-bearing property is that a built-in
//! kind is NOT a special-cased fork of the manifest/controller machinery: its
//! schema is one more entry in the ordinary [`SchemaRegistry`] ([`register`]
//! populates it exactly the way a caller registers any third-party schema),
//! and its reconcile hook is one more entry in the ordinary
//! [`ControllerRegistry`], dispatched by [`ControllerRegistry::dispatch`]
//! through the SAME `(apiVersion, kind)` lookup a third-party CRD's hook goes
//! through. There is no `if kind.is_builtin() { .. } else { .. }` branch
//! anywhere in the dispatch path — built-ins and third-party resources share
//! one interface.
//!
//! An unknown kind (neither a registered built-in nor a registered
//! third-party hook) is simply absent from the registry, so
//! [`ControllerRegistry::dispatch`] returns [`None`] for it exactly as it
//! would for any other unregistered kind — falling through to whatever
//! third-party handling the caller already has, unaffected by this module.

use std::collections::BTreeMap;

use crate::{Crd, FieldType, Schema, SchemaRegistry};

/// The single `apiVersion` every built-in kind is declared under.
pub const BUILTIN_API_VERSION: &str = "pillar.dev/v1";

/// The fixed set of resource kinds pillar validates and reconciles natively,
/// on the same manifest/controller path a third-party CRD uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BuiltinKind {
    /// A visualization dashboard definition.
    Dashboard,
    /// A metrics recording rule (pre-computed expression).
    RecordingRule,
    /// An alerting rule.
    Alert,
    /// A signal/telemetry source configuration.
    SignalConfig,
    /// A one-shot batch job.
    Job,
    /// A schedule-driven recurring job.
    CronJob,
}

impl BuiltinKind {
    /// Every built-in kind, in a fixed order — the platform's complete list.
    pub const ALL: [BuiltinKind; 6] = [
        BuiltinKind::Dashboard,
        BuiltinKind::RecordingRule,
        BuiltinKind::Alert,
        BuiltinKind::SignalConfig,
        BuiltinKind::Job,
        BuiltinKind::CronJob,
    ];

    /// The Kubernetes-CRD-compatible `kind` string this built-in declares
    /// itself as, e.g. `Dashboard`.
    #[must_use]
    pub fn kind_str(self) -> &'static str {
        match self {
            BuiltinKind::Dashboard => "Dashboard",
            BuiltinKind::RecordingRule => "RecordingRule",
            BuiltinKind::Alert => "Alert",
            BuiltinKind::SignalConfig => "SignalConfig",
            BuiltinKind::Job => "Job",
            BuiltinKind::CronJob => "CronJob",
        }
    }

    /// The `(apiVersion, kind)` key this built-in is registered under — the
    /// SAME key shape a third-party CRD registers under.
    #[must_use]
    pub fn key(self) -> (String, String) {
        (BUILTIN_API_VERSION.to_owned(), self.kind_str().to_owned())
    }

    /// The built-in kind a CRD body declares, if any. A body naming any other
    /// `apiVersion`/`kind` — including an unrecognized one — yields [`None`];
    /// callers fall through to third-party handling unaffected.
    #[must_use]
    pub fn of(crd: &Crd) -> Option<BuiltinKind> {
        if crd.api_version != BUILTIN_API_VERSION {
            return None;
        }
        BuiltinKind::ALL
            .into_iter()
            .find(|k| k.kind_str() == crd.kind)
    }

    /// The OpenAPI-style schema this built-in kind validates its `spec`
    /// against — an ordinary [`Schema`], registered into a [`SchemaRegistry`]
    /// exactly the way any third-party kind's schema is.
    #[must_use]
    pub fn schema(self) -> Schema {
        let base = Schema::new(BUILTIN_API_VERSION, self.kind_str());
        match self {
            BuiltinKind::Dashboard => base
                .required("title", FieldType::String)
                .property("panels", FieldType::Integer),
            BuiltinKind::RecordingRule => base
                .required("record", FieldType::String)
                .required("expr", FieldType::String)
                .property("interval", FieldType::Integer),
            BuiltinKind::Alert => base
                .required("expr", FieldType::String)
                .required("for", FieldType::Integer)
                .property("severity", FieldType::String),
            BuiltinKind::SignalConfig => base
                .required("source", FieldType::String)
                .property("enabled", FieldType::Boolean),
            BuiltinKind::Job => base
                .required("command", FieldType::String)
                .property("backoffLimit", FieldType::Integer),
            BuiltinKind::CronJob => base
                .required("schedule", FieldType::String)
                .required("command", FieldType::String)
                .property("suspend", FieldType::Boolean),
        }
    }
}

/// Register every built-in kind's schema into `registry` — the identical
/// [`SchemaRegistry::register`] call a caller makes for a third-party CRD's
/// schema. After this call a Dashboard/RecordingRule/Alert/SignalConfig/Job/
/// CronJob manifest validates (or is rejected) exactly like any other
/// registered kind.
pub fn register_builtin_schemas(registry: &mut SchemaRegistry) {
    for kind in BuiltinKind::ALL {
        registry.register(kind.schema());
    }
}

/// The result of one controller reconcile invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The resource was reconciled to the desired state.
    Reconciled,
    /// Reconcile failed; the message is a human-readable reason.
    Failed(String),
}

/// A native controller hook for one resource kind — the SAME shape a
/// third-party CRD's controller hook implements. Nothing in this trait, or in
/// [`ControllerRegistry`]'s dispatch, distinguishes a built-in kind's hook
/// from a third-party one: both are just a `Box<dyn ControllerHook>` reached
/// by `(apiVersion, kind)`.
pub trait ControllerHook {
    /// Reconcile `crd` to its desired state. Called through the identical
    /// invocation path regardless of whether `crd`'s kind is built-in or
    /// third-party.
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome;

    /// Retire (prune) `crd` from the cell — the delete half of the apply path,
    /// invoked when a GitOps reconcile finds a previously-applied manifest gone
    /// from its source repo (see [`crate::gitops`]). Reached through the SAME
    /// `(apiVersion, kind)` dispatch as [`ControllerHook::reconcile`]; there is
    /// no per-kind prune fork. Defaults to a successful no-op so a hook that
    /// only ever applies need not implement it; a real hook overrides it to
    /// actually delete the backing object.
    fn delete(&self, _crd: &Crd) -> ReconcileOutcome {
        ReconcileOutcome::Reconciled
    }
}

/// A no-op-but-real reconcile hook: it accepts the CRD and reports success. // realness-exempt: documented extension-point default, overridden by a real deployment
/// without touching any external system. This is the DEFAULT hook
/// [`register_builtin_controllers`] wires up for each built-in kind — a real
/// deployment replaces it with a hook that actually drives the dashboard/
/// alerting/job backend, by calling [`ControllerRegistry::register`] again
/// with its own implementation, same as it would to override or add any
/// third-party hook.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopControllerHook;

impl ControllerHook for NoopControllerHook {
    fn reconcile(&self, _crd: &Crd) -> ReconcileOutcome {
        ReconcileOutcome::Reconciled
    }
}

/// A registry of per-kind controller hooks, keyed by `apiVersion/kind` —
/// the controller-invocation analogue of [`SchemaRegistry`]. A built-in
/// kind's hook and a third-party kind's hook are registered with the exact
/// same [`ControllerRegistry::register`] call and reached by the exact same
/// [`ControllerRegistry::dispatch`] lookup: there is no special-cased branch
/// for "is this kind built-in?" anywhere in this type.
#[derive(Default)]
pub struct ControllerRegistry {
    hooks: BTreeMap<(String, String), Box<dyn ControllerHook>>,
}

impl ControllerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        ControllerRegistry {
            hooks: BTreeMap::new(),
        }
    }

    /// Register (or replace) the controller hook for `api_version/kind`. Used
    /// identically for a built-in kind and a third-party CRD's kind.
    pub fn register(
        &mut self,
        api_version: impl Into<String>,
        kind: impl Into<String>,
        hook: Box<dyn ControllerHook>,
    ) {
        self.hooks.insert((api_version.into(), kind.into()), hook);
    }

    /// Whether a hook is registered for `crd`'s kind.
    #[must_use]
    pub fn contains(&self, crd: &Crd) -> bool {
        self.hooks
            .contains_key(&(crd.api_version.clone(), crd.kind.clone()))
    }

    /// Dispatch `crd` to its registered controller hook, through the SAME
    /// `(apiVersion, kind)` lookup regardless of whether the hook backs a
    /// built-in kind or a third-party CRD. Returns [`None`] when no hook is
    /// registered for `crd`'s kind — an unknown kind (built-in-shaped or
    /// not) falls through unaffected, exactly as an unregistered third-party
    /// kind would.
    #[must_use]
    pub fn dispatch(&self, crd: &Crd) -> Option<ReconcileOutcome> {
        self.hooks
            .get(&(crd.api_version.clone(), crd.kind.clone()))
            .map(|hook| hook.reconcile(crd))
    }

    /// Retire `crd` through its registered controller hook's
    /// [`ControllerHook::delete`] — the prune half of the apply path, reached
    /// by the SAME `(apiVersion, kind)` lookup as [`dispatch`]. Returns a
    /// [`ReconcileOutcome::Failed`] if no hook is registered for the kind (a
    /// GitOps prune only ever targets a previously-applied manifest, whose hook
    /// was present when it was applied, so this is a should-not-happen guard).
    ///
    /// [`dispatch`]: ControllerRegistry::dispatch
    #[must_use]
    pub fn delete(&self, crd: &Crd) -> ReconcileOutcome {
        match self
            .hooks
            .get(&(crd.api_version.clone(), crd.kind.clone()))
        {
            Some(hook) => hook.delete(crd),
            None => ReconcileOutcome::Failed(format!(
                "no controller registered to prune {}/{}",
                crd.api_version, crd.kind
            )),
        }
    }
}

/// Register a [`NoopControllerHook`] for every built-in kind into `registry`
/// — the identical [`ControllerRegistry::register`] call a caller makes to
/// wire up a third-party CRD's hook. A real deployment overrides these with
/// hooks that actually drive each kind's backend.
pub fn register_builtin_controllers(registry: &mut ControllerRegistry) {
    for kind in BuiltinKind::ALL {
        let (api_version, k) = kind.key();
        registry.register(api_version, k, Box::new(NoopControllerHook));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Metadata, Value};
    use std::cell::RefCell;
    use std::rc::Rc;

    fn valid_crd(kind: BuiltinKind) -> Crd {
        let name = format!("{}-sample", kind.kind_str().to_lowercase());
        let crd = Crd::new(BUILTIN_API_VERSION, kind.kind_str(), Metadata::new(name));
        match kind {
            BuiltinKind::Dashboard => crd.with_spec("title", Value::String("Overview".into())),
            BuiltinKind::RecordingRule => crd
                .with_spec("record", Value::String("job:rate".into()))
                .with_spec("expr", Value::String("rate(x[5m])".into())),
            BuiltinKind::Alert => crd
                .with_spec("expr", Value::String("up == 0".into()))
                .with_spec("for", Value::Integer(300)),
            BuiltinKind::SignalConfig => crd.with_spec("source", Value::String("otlp".into())),
            BuiltinKind::Job => crd.with_spec("command", Value::String("echo hi".into())),
            BuiltinKind::CronJob => crd
                .with_spec("schedule", Value::String("*/5 * * * *".into()))
                .with_spec("command", Value::String("echo hi".into())),
        }
    }

    #[test]
    fn every_builtin_kind_manifest_validates_against_its_own_schema() {
        let mut registry = SchemaRegistry::new();
        register_builtin_schemas(&mut registry);
        for kind in BuiltinKind::ALL {
            let crd = valid_crd(kind);
            assert_eq!(
                registry.validate(&crd),
                Ok(()),
                "{} should validate against its built-in schema",
                kind.kind_str()
            );
        }
    }

    #[test]
    fn every_builtin_kind_rejects_a_malformed_manifest() {
        let mut registry = SchemaRegistry::new();
        register_builtin_schemas(&mut registry);
        for kind in BuiltinKind::ALL {
            // Drop every spec field: each built-in kind has at least one
            // required field, so an empty spec must be rejected.
            let crd = Crd::new(BUILTIN_API_VERSION, kind.kind_str(), Metadata::new("bad"));
            assert!(
                registry.validate(&crd).is_err(),
                "{} should reject a manifest missing its required fields",
                kind.kind_str()
            );
        }
    }

    #[test]
    fn of_recognizes_every_builtin_kind_and_rejects_others() {
        for kind in BuiltinKind::ALL {
            let crd = valid_crd(kind);
            assert_eq!(BuiltinKind::of(&crd), Some(kind));
        }
        let third_party = Crd::new("acme.example/v1", "Widget", Metadata::new("w"));
        assert_eq!(BuiltinKind::of(&third_party), None);
        let unrelated_kind_same_api = Crd::new(BUILTIN_API_VERSION, "Ghost", Metadata::new("g"));
        assert_eq!(BuiltinKind::of(&unrelated_kind_same_api), None);
    }

    /// A hook that records how many times — and on which kind key — it was
    /// invoked, so we can prove a built-in kind and a third-party kind are
    /// dispatched through the literal same code path rather than a
    /// special-cased fork.
    struct CountingHook {
        calls: Rc<RefCell<Vec<(String, String)>>>,
    }

    impl ControllerHook for CountingHook {
        fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
            self.calls
                .borrow_mut()
                .push((crd.api_version.clone(), crd.kind.clone()));
            ReconcileOutcome::Reconciled
        }
    }

    #[test]
    fn a_builtin_kinds_reconcile_is_dispatched_through_the_same_path_as_a_third_party_crd() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut registry = ControllerRegistry::new();

        // Register a built-in kind's hook and a third-party kind's hook with
        // the exact same `register` call — no builtin-specific method.
        registry.register(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Box::new(CountingHook {
                calls: Rc::clone(&calls),
            }),
        );
        registry.register(
            "acme.example/v1",
            "Widget",
            Box::new(CountingHook {
                calls: Rc::clone(&calls),
            }),
        );

        let dashboard = valid_crd(BuiltinKind::Dashboard);
        let widget = Crd::new("acme.example/v1", "Widget", Metadata::new("w"));

        // The exact same `dispatch` call handles both — no branch on "is this
        // a built-in kind?" anywhere in the path.
        assert_eq!(
            registry.dispatch(&dashboard),
            Some(ReconcileOutcome::Reconciled)
        );
        assert_eq!(
            registry.dispatch(&widget),
            Some(ReconcileOutcome::Reconciled)
        );

        assert_eq!(
            *calls.borrow(),
            vec![
                (BUILTIN_API_VERSION.to_owned(), "Dashboard".to_owned()),
                ("acme.example/v1".to_owned(), "Widget".to_owned()),
            ]
        );
    }

    #[test]
    fn an_unknown_kind_falls_through_unaffected_whether_or_not_it_looks_builtin() {
        let mut registry = ControllerRegistry::new();
        register_builtin_controllers(&mut registry);

        // A kind under the built-in apiVersion that was never registered.
        let unknown_builtin_shaped = Crd::new(BUILTIN_API_VERSION, "Ghost", Metadata::new("g"));
        // An ordinary unregistered third-party kind.
        let unknown_third_party = Crd::new("acme.example/v1", "Widget", Metadata::new("w"));

        assert_eq!(registry.dispatch(&unknown_builtin_shaped), None);
        assert_eq!(registry.dispatch(&unknown_third_party), None);
        assert!(!registry.contains(&unknown_builtin_shaped));
        assert!(!registry.contains(&unknown_third_party));
    }

    #[test]
    fn registered_builtin_controllers_reconcile_successfully() {
        let mut registry = ControllerRegistry::new();
        register_builtin_controllers(&mut registry);
        for kind in BuiltinKind::ALL {
            let crd = valid_crd(kind);
            assert_eq!(registry.dispatch(&crd), Some(ReconcileOutcome::Reconciled));
        }
    }
}
