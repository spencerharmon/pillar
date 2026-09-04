//! Acceptance-narrative step 1 (ROI Priority 0): an operator authors YAML,
//! submits it with `pillar apply -f`, and the object round-trips through the
//! REAL manifest envelope — not a Rust builder, not a test fixture.
//!
//! This integration test asserts the two deliverables of
//! `manifest-serialization-and-apply`:
//!
//! 1. **Real `serde` (de)serialization for EVERY declarable kind** — a
//!    YAML/JSON round-trip per kind (author YAML → deserialize → re-serialize →
//!    equal), covering Deployment, Frontend, Route, LoadBalancerPolicy, Service,
//!    Job, CronJob, Dashboard, RecordingRule, Alert, and SignalConfig.
//! 2. **`pillar apply -f` / `pillar get` / `pillar delete`** over the real
//!    manifest envelope — apply submits an authored manifest through
//!    `Envelope::import`, `get` reads it back identically, `delete` removes it.

use pillar_manifest::apply::{ApplyError, ManifestKey, ManifestStore};
use pillar_manifest::{Crd, FieldType, Schema, SchemaRegistry, Value};

const API: &str = "pillar.dev/v1";

/// Every declarable kind this ROI specifies, each authored as a YAML manifest
/// an operator would write, paired with the schema its `spec` validates
/// against. The kind is a string field on the SAME generic `Crd` shape — one
/// (de)serialization path covers all of them.
fn declarable_kinds() -> Vec<(&'static str, String, Schema)> {
    vec![
        (
            "Deployment",
            "\
apiVersion: pillar.dev/v1
kind: Deployment
metadata:
  name: echo
  labels:
    app: echo
spec:
  image: echo:v1
  replicas: 3
"
            .to_owned(),
            Schema::new(API, "Deployment")
                .required("image", FieldType::String)
                .property("replicas", FieldType::Integer),
        ),
        (
            "Frontend",
            "\
apiVersion: pillar.dev/v1
kind: Frontend
metadata:
  name: edge-fe
spec:
  vip: 10.0.0.1
  port: 443
  tls: true
"
            .to_owned(),
            Schema::new(API, "Frontend")
                .required("vip", FieldType::String)
                .required("port", FieldType::Integer)
                .property("tls", FieldType::Boolean),
        ),
        (
            "Route",
            "\
apiVersion: pillar.dev/v1
kind: Route
metadata:
  name: default-route
  labels:
    tier: edge
spec:
  prefix: 10.0.0.0/8
  metric: 100
  blackhole: false
"
            .to_owned(),
            Schema::new(API, "Route")
                .required("prefix", FieldType::String)
                .required("metric", FieldType::Integer)
                .property("blackhole", FieldType::Boolean),
        ),
        (
            "LoadBalancerPolicy",
            "\
apiVersion: pillar.dev/v1
kind: LoadBalancerPolicy
metadata:
  name: rr
spec:
  algorithm: round-robin
  exclusive: false
"
            .to_owned(),
            Schema::new(API, "LoadBalancerPolicy")
                .required("algorithm", FieldType::String)
                .property("exclusive", FieldType::Boolean),
        ),
        (
            "Service",
            "\
apiVersion: pillar.dev/v1
kind: Service
metadata:
  name: web
spec:
  dnsName: web.svc
  port: 8080
"
            .to_owned(),
            Schema::new(API, "Service")
                .required("dnsName", FieldType::String)
                .required("port", FieldType::Integer),
        ),
        (
            "Job",
            "\
apiVersion: pillar.dev/v1
kind: Job
metadata:
  name: batch
spec:
  command: echo hi
  backoffLimit: 4
"
            .to_owned(),
            Schema::new(API, "Job")
                .required("command", FieldType::String)
                .property("backoffLimit", FieldType::Integer),
        ),
        (
            "CronJob",
            "\
apiVersion: pillar.dev/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: '*/5 * * * *'
  command: echo hi
  suspend: false
"
            .to_owned(),
            Schema::new(API, "CronJob")
                .required("schedule", FieldType::String)
                .required("command", FieldType::String)
                .property("suspend", FieldType::Boolean),
        ),
        (
            "Dashboard",
            "\
apiVersion: pillar.dev/v1
kind: Dashboard
metadata:
  name: overview
spec:
  title: Overview
  panels: 6
"
            .to_owned(),
            Schema::new(API, "Dashboard")
                .required("title", FieldType::String)
                .property("panels", FieldType::Integer),
        ),
        (
            "RecordingRule",
            "\
apiVersion: pillar.dev/v1
kind: RecordingRule
metadata:
  name: job-rate
spec:
  record: job:rate
  expr: rate(x[5m])
  interval: 30
"
            .to_owned(),
            Schema::new(API, "RecordingRule")
                .required("record", FieldType::String)
                .required("expr", FieldType::String)
                .property("interval", FieldType::Integer),
        ),
        (
            "Alert",
            "\
apiVersion: pillar.dev/v1
kind: Alert
metadata:
  name: up
spec:
  expr: up == 0
  for: 300
  severity: critical
"
            .to_owned(),
            Schema::new(API, "Alert")
                .required("expr", FieldType::String)
                .required("for", FieldType::Integer)
                .property("severity", FieldType::String),
        ),
        (
            "SignalConfig",
            "\
apiVersion: pillar.dev/v1
kind: SignalConfig
metadata:
  name: otlp
spec:
  source: otlp
  enabled: true
"
            .to_owned(),
            Schema::new(API, "SignalConfig")
                .required("source", FieldType::String)
                .property("enabled", FieldType::Boolean),
        ),
    ]
}

#[test]
fn every_declarable_kind_yaml_round_trips_loss_free() {
    for (kind, yaml, _schema) in declarable_kinds() {
        // author YAML -> deserialize
        let crd = Crd::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("{kind}: authored YAML must deserialize: {e}"));
        assert_eq!(crd.kind, kind, "{kind}: kind field preserved");
        assert_eq!(crd.api_version, API, "{kind}: apiVersion preserved");

        // -> re-serialize -> deserialize again -> equal (canonical round-trip)
        let reserialized = crd
            .to_yaml()
            .unwrap_or_else(|e| panic!("{kind}: CRD must re-serialize to YAML: {e}"));
        let crd2 = Crd::from_yaml(&reserialized)
            .unwrap_or_else(|e| panic!("{kind}: re-serialized YAML must deserialize: {e}"));
        assert_eq!(crd, crd2, "{kind}: YAML round-trip is loss-free");
    }
}

#[test]
fn every_declarable_kind_json_round_trips_loss_free() {
    for (kind, yaml, _schema) in declarable_kinds() {
        // The SAME authored object encoded as JSON round-trips identically —
        // JSON and YAML are two encodings of one serde model.
        let crd = Crd::from_yaml(&yaml).expect("author");
        let json = crd
            .to_json()
            .unwrap_or_else(|e| panic!("{kind}: CRD must serialize to JSON: {e}"));
        let crd_from_json =
            Crd::from_json(&json).unwrap_or_else(|e| panic!("{kind}: JSON must deserialize: {e}"));
        assert_eq!(crd, crd_from_json, "{kind}: JSON round-trip is loss-free");
    }
}

#[test]
fn spec_scalars_serialize_as_native_yaml_not_a_tagged_enum() {
    // A spec value must be a bare scalar in the emitted document — the plain
    // CRD a human authors — never a `String: ...`/`Integer: ...` tagged form.
    let crd = Crd::from_yaml(
        "\
apiVersion: pillar.dev/v1
kind: Route
metadata:
  name: r
spec:
  prefix: 10.0.0.0/8
  metric: 100
  blackhole: false
",
    )
    .expect("author");
    let yaml = crd.to_yaml().expect("serialize");
    assert!(
        yaml.contains("metric: 100"),
        "integer is a native scalar:\n{yaml}"
    );
    assert!(
        yaml.contains("blackhole: false"),
        "boolean is a native scalar:\n{yaml}"
    );
    assert!(
        !yaml.contains("Integer:") && !yaml.contains("String:") && !yaml.contains("Boolean:"),
        "no tagged-enum form leaks into the document:\n{yaml}"
    );
    // And the decoded values carry their real types.
    assert_eq!(crd.spec.get("metric"), Some(&Value::Integer(100)));
    assert_eq!(crd.spec.get("blackhole"), Some(&Value::Boolean(false)));
    assert_eq!(
        crd.spec.get("prefix"),
        Some(&Value::String("10.0.0.0/8".to_owned()))
    );
}

#[test]
fn apply_get_delete_over_the_real_envelope() {
    // Build a store whose registry knows every declarable kind's schema.
    let mut registry = SchemaRegistry::new();
    for (_kind, _yaml, schema) in declarable_kinds() {
        registry.register(schema);
    }
    let mut store = ManifestStore::new(registry, "OPERATOR-FPR");

    // pillar apply -f echo.yaml for EVERY kind: submit the authored manifest
    // through the real envelope.
    for (_kind, yaml, _schema) in declarable_kinds() {
        store
            .apply_yaml(&yaml)
            .unwrap_or_else(|e| panic!("apply must succeed: {e}"));
    }
    assert_eq!(store.len(), declarable_kinds().len());

    // pillar get echo: read one object back and confirm it is IDENTICAL to what
    // was authored (round-trips through the sealed envelope).
    let authored = Crd::from_yaml(
        "\
apiVersion: pillar.dev/v1
kind: Deployment
metadata:
  name: echo
  labels:
    app: echo
spec:
  image: echo:v1
  replicas: 3
",
    )
    .expect("author");
    let key = ManifestKey::of(&authored);
    let got = store.get(&key).expect("get finds the applied object");
    // The stored object is a REAL signed envelope, and its body is exactly the
    // authored manifest.
    assert!(
        got.verify(),
        "the stored object is a validly-signed envelope"
    );
    assert_eq!(got.render(), authored, "get returns the authored object");
    assert_eq!(store.get_body(&key), Some(authored.clone()));

    // pillar delete echo: remove it; a second get finds nothing.
    let removed = store.delete(&key).expect("delete removes the object");
    assert_eq!(removed.render(), authored);
    assert!(store.get(&key).is_none(), "get after delete finds nothing");
    assert!(
        matches!(store.delete(&key), Err(ApplyError::NotFound(_))),
        "deleting an absent object is NotFound"
    );
}

#[test]
fn apply_refuses_a_body_that_fails_its_schema_and_stores_nothing() {
    let mut registry = SchemaRegistry::new();
    registry.register(
        Schema::new(API, "Route")
            .required("prefix", FieldType::String)
            .required("metric", FieldType::Integer),
    );
    let mut store = ManifestStore::new(registry, "OPERATOR-FPR");

    // Missing the required `metric` field -> schema refusal, nothing stored.
    let bad = "\
apiVersion: pillar.dev/v1
kind: Route
metadata:
  name: r
spec:
  prefix: 10.0.0.0/8
";
    assert!(
        matches!(store.apply_yaml(bad), Err(ApplyError::Schema(_))),
        "an invalid body is refused"
    );
    assert!(store.is_empty(), "a refused apply stores nothing");
}
