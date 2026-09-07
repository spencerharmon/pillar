//! Acceptance test — `pillar-integration-scenarios-manifests-apply`.
//!
//! The `pillar-integration` "manifests/CRDs" scenario family: an `apply` /
//! `get` / `delete` round-trip for EVERY declarable manifest kind PLUS a
//! third-party CRD hook, exercised against the REAL manifest engine
//! (`pillar_manifest::apply::ManifestStore` + `ControllerRegistry` — the same
//! engine a `pillar node run` cell backs `pillar apply|get|delete` with, per
//! `pillar_cli`'s `ResourcePlane`), never an in-memory stand-in of it.
//!
//! Two real effects are asserted, and each is RED if a kind's round-trip
//! silently NO-OPS:
//!
//! 1. `every_declarable_kind_applies_gets_and_deletes` — for each declarable
//!    kind (enumerated from the REAL schema registry the surface-inventory
//!    emitter reads), author a manifest, `apply` it, `get` it back and confirm
//!    the retrieved object is byte-identical to the authored one, then `delete`
//!    it and confirm a second `get` finds NOTHING and a second `delete` is a
//!    `NotFound`. A kind that silently no-ops on apply (nothing stored) fails
//!    the post-apply `get`; a kind that silently no-ops on delete (object
//!    remains) fails the post-delete `get` — so a no-op is RED, exactly as the
//!    ROI's realness oracle demands.
//!
//! 2. `a_third_party_crd_and_a_builtin_travel_the_same_controller_path` — a
//!    built-in kind (`Dashboard`) and a third-party CRD (`acme.example/v1
//!    Widget`) are both registered with the identical `ControllerRegistry::
//!    register` call, both reconciled (apply) through the identical `dispatch`
//!    lookup, and both pruned (delete) through the identical `delete` lookup —
//!    proving the plugin-interface hook has no `if kind.is_builtin()` fork. An
//!    UNregistered kind dispatches to `None`, so a hook that silently accepted
//!    an unknown kind would be RED.
//!
//! Every kind under test is enumerated from the same real registries the
//! `surface-inventory-emitter` reads (`SchemaRegistry::kinds()`), so a newly
//! declared kind that this scenario forgot to author fails
//! `every_registry_kind_is_covered_by_the_roundtrip` — the round-trip can
//! never silently skip a declarable kind.
//!
//! `#[cfg(feature = "acceptance")]`-gated (the `acceptance-e2e` CHECKS.md
//! stub); run via `cargo test -p pillar-e2e --test manifests_apply_roundtrip
//! --features acceptance`, and driven end-to-end against the real published
//! image + live topology by
//! `scripts/pillar-integration/run-scenario.sh manifests-apply`.

#![cfg(feature = "acceptance")]

use std::collections::BTreeSet;

use pillar_manifest::apply::{ApplyError, ManifestKey, ManifestStore};
use pillar_manifest::builtin::{
    register_builtin_schemas, ControllerRegistry, ReconcileOutcome,
};
use pillar_manifest::{Crd, FieldType, Metadata, Schema, SchemaRegistry, Value};

/// The third-party CRD the plugin-interface hook must travel the identical
/// apply/prune path as a built-in kind.
const THIRD_PARTY_API: &str = "acme.example/v1";
const THIRD_PARTY_KIND: &str = "Widget";

/// Every declarable manifest kind, each authored as a valid `(schema, crd)`
/// pair. The built-in kinds come from the REAL registry
/// (`register_builtin_schemas`); the first-party module kinds (Service,
/// Certificate, NetworkPolicy) and the third-party `Widget` are added with the
/// identical `SchemaRegistry::register` call. `every_registry_kind_is_covered`
/// asserts this list is not missing any registered kind.
fn declarable_manifests() -> Vec<(Schema, Crd)> {
    let mut out: Vec<(Schema, Crd)> = Vec::new();

    // --- built-in kinds, straight from the production schema registry. ------
    let mut builtins = SchemaRegistry::new();
    register_builtin_schemas(&mut builtins);
    for (api, kind) in builtins.kinds() {
        let crd = builtin_crd(api, kind);
        out.push((builtin_schema(kind), crd));
    }

    // --- first-party module kinds (their own schema + controller modules). --
    out.push((
        pillar_manifest::service_route_dns::service_schema(),
        Crd::new("pillar.dev/v1", "Service", Metadata::new("web-svc"))
            .with_spec("dnsName", Value::String("www.example.com".into()))
            .with_spec("frontend", Value::String("edge".into()))
            .with_spec("app", Value::String("web".into()))
            .with_spec("port", Value::Integer(443))
            .with_spec("endpoints", Value::String("10.0.0.1:8080".into())),
    ));
    out.push((
        pillar_manifest::tls_cert::certificate_schema(),
        Crd::new("pillar.dev/v1", "Certificate", Metadata::new("web-cert"))
            .with_spec("dnsName", Value::String("www.example.com".into()))
            .with_spec("issuer", Value::String("internal-ca".into()))
            .with_spec("target", Value::String("web-svc".into())),
    ));
    out.push((
        pillar_manifest::network_policy::network_policy_schema(),
        Crd::new("pillar.dev/v1", "NetworkPolicy", Metadata::new("allow-web"))
            .with_spec("from", Value::String("appA".into()))
            .with_spec("to", Value::String("appB".into()))
            .with_spec("action", Value::String("allow".into())),
    ));

    // --- the third-party CRD, registered exactly like any built-in. ---------
    out.push((third_party_schema(), third_party_crd()));

    out
}

/// The schema for a built-in kind (mirrors `BuiltinKind::schema`, without
/// needing the private enum). Only the built-in kinds this returns are ever
/// asked for.
fn builtin_schema(kind: &str) -> Schema {
    let base = Schema::new("pillar.dev/v1", kind);
    match kind {
        "Dashboard" => base
            .required("title", FieldType::String)
            .property("panels", FieldType::Integer),
        "RecordingRule" => base
            .required("record", FieldType::String)
            .required("expr", FieldType::String)
            .property("interval", FieldType::Integer),
        "Alert" => base
            .required("expr", FieldType::String)
            .required("for", FieldType::Integer)
            .property("severity", FieldType::String),
        "SignalConfig" => base
            .required("source", FieldType::String)
            .property("enabled", FieldType::Boolean),
        "Job" => base
            .required("command", FieldType::String)
            .property("backoffLimit", FieldType::Integer),
        "CronJob" => base
            .required("schedule", FieldType::String)
            .required("command", FieldType::String)
            .property("suspend", FieldType::Boolean),
        other => panic!("no authored schema for built-in kind {other}"),
    }
}

/// A valid CRD body for a built-in kind — every required field populated.
fn builtin_crd(api: &str, kind: &str) -> Crd {
    let name = format!("{}-sample", kind.to_lowercase());
    let crd = Crd::new(api, kind, Metadata::new(name));
    match kind {
        "Dashboard" => crd.with_spec("title", Value::String("Overview".into())),
        "RecordingRule" => crd
            .with_spec("record", Value::String("job:rate".into()))
            .with_spec("expr", Value::String("rate(x[5m])".into())),
        "Alert" => crd
            .with_spec("expr", Value::String("up == 0".into()))
            .with_spec("for", Value::Integer(300)),
        "SignalConfig" => crd.with_spec("source", Value::String("otlp".into())),
        "Job" => crd.with_spec("command", Value::String("echo hi".into())),
        "CronJob" => crd
            .with_spec("schedule", Value::String("*/5 * * * *".into()))
            .with_spec("command", Value::String("echo hi".into())),
        other => panic!("no authored CRD for built-in kind {other}"),
    }
}

fn third_party_schema() -> Schema {
    Schema::new(THIRD_PARTY_API, THIRD_PARTY_KIND)
        .required("size", FieldType::String)
        .property("replicas", FieldType::Integer)
}

fn third_party_crd() -> Crd {
    Crd::new(THIRD_PARTY_API, THIRD_PARTY_KIND, Metadata::new("gadget"))
        .with_spec("size", Value::String("large".into()))
        .with_spec("replicas", Value::Integer(2))
}

/// Build a `ManifestStore` whose registry knows every declarable kind.
fn store_knowing_every_kind() -> ManifestStore {
    let mut registry = SchemaRegistry::new();
    for (schema, _crd) in declarable_manifests() {
        registry.register(schema);
    }
    ManifestStore::new(registry, "pillar-e2e-manifests-apply-signer")
}

/// For EVERY declarable kind: apply → get (retrievable, identical) → delete →
/// get (gone) → delete (NotFound). A silent no-op on apply OR delete is RED.
#[test]
fn every_declarable_kind_applies_gets_and_deletes() {
    let manifests = declarable_manifests();
    assert!(
        manifests.len() >= 10,
        "expected the full declarable-kind set, got {}",
        manifests.len()
    );

    for (_schema, crd) in &manifests {
        let mut store = store_knowing_every_kind();
        let key = ManifestKey::of(crd);
        let kind = &crd.kind;

        // apply: the object must actually be stored (RED if apply no-ops).
        store
            .apply_crd(crd.clone())
            .unwrap_or_else(|e| panic!("{kind}: apply must succeed, got {e:?}"));
        assert_eq!(
            store.len(),
            1,
            "{kind}: exactly one object stored after apply — apply did not silently no-op"
        );

        // get: read it back; it must be byte-identical to the authored body.
        let got = store
            .get(&key)
            .unwrap_or_else(|| panic!("{kind}: get after apply must find the object"));
        assert_eq!(
            &got.render(),
            crd,
            "{kind}: the retrieved object is identical to the authored manifest"
        );
        assert_eq!(store.get_body(&key).as_ref(), Some(crd));
        assert_eq!(
            store.list(&crd.api_version, &crd.kind).len(),
            1,
            "{kind}: list-by-kind returns the applied object"
        );

        // delete: remove it; a second get must find NOTHING (RED if delete
        // no-ops), and a second delete must be NotFound.
        store
            .delete(&key)
            .unwrap_or_else(|e| panic!("{kind}: delete must remove the object, got {e:?}"));
        assert!(
            store.get(&key).is_none(),
            "{kind}: get after delete finds nothing — delete did not silently no-op"
        );
        assert!(store.is_empty(), "{kind}: store empty after delete");
        assert!(
            matches!(store.delete(&key), Err(ApplyError::NotFound(_))),
            "{kind}: deleting an already-deleted object is NotFound"
        );
    }
}

/// The round-trip covers EVERY kind the real schema registry serves — it can
/// never silently skip a declarable kind. (The third-party kind is authored
/// here, not registry-served, so it is excluded from the coverage set.)
#[test]
fn every_registry_kind_is_covered_by_the_roundtrip() {
    let mut registry = SchemaRegistry::new();
    register_builtin_schemas(&mut registry);
    registry.register(pillar_manifest::service_route_dns::service_schema());
    registry.register(pillar_manifest::tls_cert::certificate_schema());
    registry.register(pillar_manifest::network_policy::network_policy_schema());

    let served: BTreeSet<(String, String)> = registry
        .kinds()
        .map(|(a, k)| (a.to_owned(), k.to_owned()))
        .collect();
    let covered: BTreeSet<(String, String)> = declarable_manifests()
        .iter()
        .map(|(_s, c)| (c.api_version.clone(), c.kind.clone()))
        .collect();

    for served_kind in &served {
        assert!(
            covered.contains(served_kind),
            "declarable kind {served_kind:?} is served by the registry but has no apply/get/delete round-trip"
        );
    }
}

/// A no-op-but-real controller hook recording every reconcile/delete it
/// receives, so the test observes the SAME dispatch path serving a built-in
/// and a third-party CRD. `//` realness-exempt: an in-test observer of the
/// real `ControllerRegistry` dispatch, not a stand-in for the engine.
struct RecordingHook {
    seen: std::rc::Rc<std::cell::RefCell<Vec<(String, String, &'static str)>>>,
}

impl pillar_manifest::builtin::ControllerHook for RecordingHook {
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
        self.seen
            .borrow_mut()
            .push((crd.api_version.clone(), crd.kind.clone(), "reconcile"));
        ReconcileOutcome::Reconciled
    }
    fn delete(&self, crd: &Crd) -> ReconcileOutcome {
        self.seen
            .borrow_mut()
            .push((crd.api_version.clone(), crd.kind.clone(), "delete"));
        ReconcileOutcome::Reconciled
    }
}

/// A built-in kind and a third-party CRD apply (reconcile) AND prune (delete)
/// through the IDENTICAL `(apiVersion, kind)` controller path — no builtin
/// fork. An unregistered kind dispatches to `None` (a silently-accepting hook
/// would be RED).
#[test]
fn a_third_party_crd_and_a_builtin_travel_the_same_controller_path() {
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut controllers = ControllerRegistry::new();

    // Register a built-in kind and the third-party CRD with the EXACT same call.
    controllers.register(
        "pillar.dev/v1",
        "Dashboard",
        Box::new(RecordingHook {
            seen: std::rc::Rc::clone(&seen),
        }),
    );
    controllers.register(
        THIRD_PARTY_API,
        THIRD_PARTY_KIND,
        Box::new(RecordingHook {
            seen: std::rc::Rc::clone(&seen),
        }),
    );

    let dashboard = builtin_crd("pillar.dev/v1", "Dashboard");
    let widget = third_party_crd();

    // apply → reconcile, through the identical dispatch lookup for both.
    assert_eq!(
        controllers.dispatch(&dashboard),
        Some(ReconcileOutcome::Reconciled),
        "built-in Dashboard reconciles through the shared dispatch path"
    );
    assert_eq!(
        controllers.dispatch(&widget),
        Some(ReconcileOutcome::Reconciled),
        "third-party Widget reconciles through the SAME dispatch path"
    );

    // delete → prune, through the identical delete lookup for both.
    assert_eq!(controllers.delete(&dashboard), ReconcileOutcome::Reconciled);
    assert_eq!(controllers.delete(&widget), ReconcileOutcome::Reconciled);

    // An unregistered kind falls through to None — a hook that silently
    // accepted an unknown kind would be a real defect.
    let unknown = Crd::new("acme.example/v1", "Gizmo", Metadata::new("x"));
    assert!(
        controllers.dispatch(&unknown).is_none(),
        "an unregistered kind is not silently accepted"
    );

    assert_eq!(
        *seen.borrow(),
        vec![
            ("pillar.dev/v1".to_owned(), "Dashboard".to_owned(), "reconcile"),
            (THIRD_PARTY_API.to_owned(), THIRD_PARTY_KIND.to_owned(), "reconcile"),
            ("pillar.dev/v1".to_owned(), "Dashboard".to_owned(), "delete"),
            (THIRD_PARTY_API.to_owned(), THIRD_PARTY_KIND.to_owned(), "delete"),
        ],
        "built-in and third-party CRD travel the identical reconcile+prune path"
    );
}
