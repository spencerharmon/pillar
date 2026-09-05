//! The `pillar` CLI engine: kubectl-style `apply` / `get` / `describe` over
//! signed manifests, plus `kustomize`- and `helm`-style renderers that reuse
//! the ecosystem's text ergonomics **without** a Kubernetes control plane.
//!
//! The model is deliberately inverted from Kubernetes:
//!
//! - **`apply`** validates a CRD body against its registered schema, asks the
//!   **WoT/RBAC decider** whether the acting node may perform the capability,
//!   and — only if authorized — signs the body into a [`pillar_manifest`]
//!   [`Envelope`] and emits ONE signed [`pillar_eventlog`] event. An
//!   unauthorized apply changes nothing: no envelope is sealed, no event is
//!   logged. Authority is the same [`RbacDecider`] the controller and UI use,
//!   so a CLI apply can never be admitted on authority the controller would
//!   refuse.
//! - **`get` / `describe`** render a **materialized view** folded from the
//!   event log. Status is a *view*, never written back: reading it does not
//!   mutate the log, seal a manifest, or touch a resource. `describe`
//!   additionally surfaces the envelope provenance (signer, content-hash,
//!   causal-parents, capability-scope) of the manifest currently in force.
//! - **`kustomize` / `helm`** are pure *renderers*: they turn a base plus
//!   overlay (kustomize) or a template plus values (helm) into a CRD body in
//!   the shared manifest **text format**, which then `apply`s through the exact
//!   same authorized path. Reuse of the ecosystem's authoring ergonomics, with
//!   Pillar's signed-intent semantics underneath.
//!
//! Everything here is pure and in-memory: no network, no filesystem. The
//! binary ([`crate`]'s `main`) is a thin argv shell over this library so the
//! behavior is exercised by ordinary unit tests.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod cli_surface;
pub mod cluster;
pub mod health;
pub mod identity_trust_cli;
pub mod ingress_lb_udp_serve;
pub mod observability_ui;
pub mod onboard;
pub mod polish;
pub mod resource;
pub mod run;
pub mod secrets_audit_rotation_mfa;
pub mod session_cli;
pub mod stream_cli;
pub mod surface_inventory;
pub mod topology_cli;
pub mod trust_rbac_authz;
pub mod versioning_rollout;
pub mod web_serve;
pub mod webauthn_cli;
pub mod workload_reconcile;

use std::collections::BTreeMap;
use std::fmt;

use pillar_core::NodeId;
use pillar_eventlog::{Author, EventId, EventLog};
use pillar_manifest::{
    Capability as ManifestCapability, ContentHash, Crd, Envelope, FieldType, Metadata, SchemaError,
    SchemaRegistry, Value,
};
use pillar_rbac::{
    Capability as RbacCapability, Decision, ExplicitGrant, PolicyEvent, RbacDecider, Request,
};
use pillar_wot_authority::WotAuthority;

/// The identity of a resource in the materialized view: its `apiVersion`,
/// `kind`, and `metadata.name`. Two applies to the same triple are two
/// revisions of the one resource; the latest-applied wins in the view.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceKey {
    /// `apiVersion`.
    pub api_version: String,
    /// `kind`.
    pub kind: String,
    /// `metadata.name`.
    pub name: String,
}

impl ResourceKey {
    /// The key naming the resource a CRD body describes.
    #[must_use]
    pub fn of(crd: &Crd) -> Self {
        ResourceKey {
            api_version: crd.api_version.clone(),
            kind: crd.kind.clone(),
            name: crd.metadata.name.clone(),
        }
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} {}", self.api_version, self.kind, self.name)
    }
}

/// Why an [`Platform::apply`] was refused. In every case the event log and the
/// manifest store are left exactly as they were — an apply is all-or-nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The CRD body failed schema validation against its registered kind.
    Schema(SchemaError),
    /// The WoT/RBAC decider refused the acting node this capability.
    Unauthorized {
        /// The node that attempted the apply.
        actor: NodeId,
        /// The capability it was refused.
        capability: String,
    },
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Schema(e) => write!(f, "schema validation failed: {e}"),
            ApplyError::Unauthorized { actor, capability } => {
                write!(f, "node {actor} is not authorized for `{capability}`")
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// The record of one successful apply: the emitted event and the sealed
/// manifest's content-hash. Returned so a caller can correlate the CLI action
/// with the log entry it produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The id of the signed event emitted for this apply.
    pub event: EventId,
    /// The content-hash of the manifest body sealed by this apply.
    pub content_hash: ContentHash,
}

/// What a `--dry-run` preview of an apply-shaped act WOULD produce, computed
/// by running the identical validate-then-authorize decision path
/// [`Platform::apply`] uses (see [`Platform::preview`]) — WITHOUT sealing an
/// envelope or appending an event. `content_hash` is the SAME content-hash a
/// real apply of this exact body would seal, so `preview(..).content_hash ==
/// apply(..).content_hash` holds whenever both succeed: predicted ==
/// enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Previewed {
    /// The content-hash the sealed envelope would carry if applied for real.
    pub content_hash: ContentHash,
}

/// The in-memory platform the CLI acts against: the schema registry, the
/// WoT/RBAC authority inputs, the content-addressed manifest store, and the
/// append-only signed event log. `apply` is the ONLY mutator; `get`/`describe`
/// are pure reads over a view folded from the log.
pub struct Platform {
    registry: SchemaRegistry,
    authority: WotAuthority,
    policies: Vec<PolicyEvent>,
    grants: Vec<ExplicitGrant>,
    log: EventLog,
    /// Content-addressed store of every sealed manifest, keyed by body hash.
    store: BTreeMap<ContentHash, Envelope>,
    /// The apply order of manifests (as content-hashes), one per emitted
    /// event — the sequence the view folds over. Derived from the log, never
    /// an authority of its own.
    applied: Vec<ContentHash>,
    /// The event id (log CID) emitted for each applied manifest, parallel to
    /// [`Self::applied`]. Lets a `describe` surface the **event CID** of the
    /// record that put the resource in force — the pillar-specific provenance
    /// kubectl lacks.
    applied_events: Vec<EventId>,
}

impl Platform {
    /// Build a platform over a schema registry and the WoT/RBAC decision
    /// inputs (authority graph, live policy events, explicit grants).
    #[must_use]
    pub fn new(
        registry: SchemaRegistry,
        authority: WotAuthority,
        policies: Vec<PolicyEvent>,
        grants: Vec<ExplicitGrant>,
    ) -> Self {
        Platform {
            registry,
            authority,
            policies,
            grants,
            log: EventLog::new(),
            store: BTreeMap::new(),
            applied: Vec::new(),
            applied_events: Vec::new(),
        }
    }

    /// The number of events emitted so far — the log length. A `get`/`describe`
    /// never changes it; only a successful `apply` does.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.log.len()
    }

    /// Whether the acting node may perform `capability`, per the SAME
    /// [`RbacDecider`] the controller enforces and the UI predicts.
    #[must_use]
    pub fn authorized(&self, actor: &NodeId, capability: &str) -> bool {
        let decider = RbacDecider::new(&self.authority, &self.policies, &self.grants);
        let request = Request::new(actor.clone(), RbacCapability(capability.to_owned()));
        decider.decide(&request) == Decision::Allow
    }

    /// `pillar apply` — validate, authorize, sign, and emit.
    ///
    /// Validates `body` against its registered schema, asks the WoT/RBAC
    /// decider whether `actor` may perform `capability`, and only then seals
    /// `body` into an [`Envelope`] (signed by `actor`, carrying the given
    /// causal-parents and capability-scope) and appends ONE signed event to
    /// the log. On any failure NOTHING is mutated.
    ///
    /// # Errors
    /// [`ApplyError::Schema`] if the body fails schema validation;
    /// [`ApplyError::Unauthorized`] if the decider refuses `actor` the
    /// capability. Either way the log and store are unchanged.
    pub fn apply(
        &mut self,
        actor: &NodeId,
        capability: &str,
        body: Crd,
        causal_parents: impl IntoIterator<Item = ContentHash>,
        capability_scope: impl IntoIterator<Item = ManifestCapability>,
    ) -> Result<Applied, ApplyError> {
        let causal_parents: Vec<ContentHash> = causal_parents.into_iter().collect();
        let capability_scope: Vec<ManifestCapability> = capability_scope.into_iter().collect();

        // Run the IDENTICAL validate-then-authorize decision `preview` (a
        // `--dry-run`) runs — the single decider both paths share, so a
        // preview's verdict can never diverge from what this apply enforces.
        self.preview(actor, capability, &body)?;

        let envelope = Envelope::import(body, actor.0.clone(), causal_parents, capability_scope);
        let content_hash = envelope.content_hash();

        // Emit exactly one signed event; its payload names the sealed
        // manifest by content-hash — the view resolves it from the store.
        let author = Author(actor.0.clone());
        let event = self.log.append(&author, content_hash.as_bytes().to_vec());

        self.store.insert(content_hash.clone(), envelope);
        self.applied.push(content_hash.clone());
        self.applied_events.push(event.clone());

        Ok(Applied {
            event,
            content_hash,
        })
    }

    /// `--dry-run` (VIEW): preview what [`Platform::apply`] of this EXACT
    /// `(actor, capability, body)` WOULD do — running the identical
    /// validate-then-authorize decision `apply` itself calls first (see
    /// `apply`'s implementation) — WITHOUT sealing an envelope or appending
    /// an event. The decider decision `preview` observes and the one `apply`
    /// enforces are the SAME call, so `preview(..).is_ok() ==
    /// apply(..).is_ok()` holds structurally, not merely by test coverage
    /// (the single-decider invariant, applied to the resource plane).
    ///
    /// # Errors
    /// [`ApplyError::Schema`] if the body fails schema validation;
    /// [`ApplyError::Unauthorized`] if the decider would refuse `actor` this
    /// capability — INCLUDING a refusal, since the whole point of a preview
    /// is to show the SAME decision the real act would produce.
    pub fn preview(
        &self,
        actor: &NodeId,
        capability: &str,
        body: &Crd,
    ) -> Result<Previewed, ApplyError> {
        self.registry.validate(body).map_err(ApplyError::Schema)?;

        if !self.authorized(actor, capability) {
            return Err(ApplyError::Unauthorized {
                actor: actor.clone(),
                capability: capability.to_owned(),
            });
        }

        // Compute the content-hash a real apply of this body would seal,
        // without storing anything — pure.
        let envelope = Envelope::import(body.clone(), actor.0.clone(), [], []);
        Ok(Previewed {
            content_hash: envelope.content_hash(),
        })
    }

    /// The materialized view: the resource state folded from the event log in
    /// apply order (latest apply of each [`ResourceKey`] wins). This is a pure
    /// projection — computing it mutates nothing.
    #[must_use]
    pub fn view(&self) -> BTreeMap<ResourceKey, Envelope> {
        let mut view = BTreeMap::new();
        for hash in &self.applied {
            if let Some(env) = self.store.get(hash) {
                view.insert(ResourceKey::of(env.body()), env.clone());
            }
        }
        view
    }

    /// `pillar get` — the CRD body currently in force for a resource, rendered
    /// from the view. Returns `None` if no manifest for that kind/name has been
    /// applied. Reading NEVER writes back.
    #[must_use]
    pub fn get(&self, api_version: &str, kind: &str, name: &str) -> Option<Crd> {
        let key = ResourceKey {
            api_version: api_version.to_owned(),
            kind: kind.to_owned(),
            name: name.to_owned(),
        };
        self.view().get(&key).map(Envelope::render)
    }

    /// `pillar describe` — a human-readable rendering of the resource in force,
    /// including its envelope provenance (signer, content-hash, causal-parents,
    /// capability-scope) drawn from the view. Returns `None` if absent. Reading
    /// NEVER writes back.
    #[must_use]
    pub fn describe(&self, api_version: &str, kind: &str, name: &str) -> Option<String> {
        self.describe_impl(api_version, kind, name)
    }

    /// The **event CID** (log id) of the record that last put `key` in force,
    /// or `None` if no manifest for that key has been applied — the provenance a
    /// `describe` surfaces alongside the envelope signer. A pure read.
    #[must_use]
    pub fn event_cid(&self, key: &ResourceKey) -> Option<EventId> {
        self.applied
            .iter()
            .zip(self.applied_events.iter())
            .rev()
            .find_map(|(hash, ev)| {
                let env = self.store.get(hash)?;
                (ResourceKey::of(env.body()) == *key).then_some(ev.clone())
            })
    }

    fn describe_impl(&self, api_version: &str, kind: &str, name: &str) -> Option<String> {
        let key = ResourceKey {
            api_version: api_version.to_owned(),
            kind: kind.to_owned(),
            name: name.to_owned(),
        };
        let env = self.view().get(&key)?.clone();
        let body = env.render();

        let mut out = String::new();
        out.push_str(&format!("Name:        {}\n", body.metadata.name));
        out.push_str(&format!(
            "Kind:        {}/{}\n",
            body.api_version, body.kind
        ));
        if !body.metadata.labels.is_empty() {
            out.push_str("Labels:\n");
            for (k, v) in &body.metadata.labels {
                out.push_str(&format!("  {k}={v}\n"));
            }
        }
        out.push_str("Spec:\n");
        for (k, v) in &body.spec {
            out.push_str(&format!("  {k}: {}\n", value_to_text(v)));
        }
        out.push_str("Envelope:\n");
        out.push_str(&format!("  Signer:        {}\n", env.signer()));
        out.push_str(&format!("  Content-Hash:  {}\n", env.content_hash()));
        if let Some(cid) = self.event_cid(&key) {
            out.push_str(&format!("  Event-CID:     {}\n", cid.0));
        }
        out.push_str(&format!(
            "  Exercised-Authority: {}\n",
            self.exercised_authority(&env)
        ));
        out.push_str("  Causal-Parents:");
        if env.causal_parents().is_empty() {
            out.push_str(" (none)\n");
        } else {
            out.push('\n');
            for p in env.causal_parents() {
                out.push_str(&format!("    {p}\n"));
            }
        }
        out.push_str("  Capability-Scope:");
        if env.capability_scope().is_empty() {
            out.push_str(" (none)\n");
        } else {
            out.push('\n');
            for c in env.capability_scope() {
                out.push_str(&format!("    {}\n", c.0));
            }
        }
        out.push_str(&format!(
            "  Verified:      {}\n",
            if env.verify() { "yes" } else { "no" }
        ));
        Some(out)
    }

    /// The **exercised authority** behind the signer's admission for an
    /// envelope's capability-scope — WHICH rung of the RBAC precedence
    /// lattice ([`pillar_rbac::Exercised`]) the decider actually exercised —
    /// rendered for `describe`. Uniform across every kind: a workload, an
    /// identity object, or anything else on this plane. Re-derives the
    /// decision through the SAME decider `apply`/`authorized` use (never a
    /// second, divergent explanation path); returns a plain "none declared"
    /// note (never a fabricated chain) when the envelope carries no
    /// capability-scope to explain.
    #[must_use]
    fn exercised_authority(&self, env: &Envelope) -> String {
        let Some(capability) = env.capability_scope().iter().next() else {
            return "(no capability-scope on this envelope; nothing to explain)".to_owned();
        };
        let decider = RbacDecider::new(&self.authority, &self.policies, &self.grants);
        let request = Request::new(
            NodeId::from(env.signer()),
            RbacCapability(capability.0.clone()),
        );
        decider.explain(&request).to_string()
    }
}

/// Render a spec [`Value`] to the shared text format's scalar syntax.
fn value_to_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        Value::Boolean(b) => b.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Shared manifest TEXT format — the ecosystem-friendly surface `kustomize` and
// `helm` both render into, and `apply` reads. Line-oriented, dependency-free.
// ---------------------------------------------------------------------------

/// A `kind: string`/`integer`/`boolean` typed scalar in the text format,
/// mirroring the schema field types.
fn parse_typed_value(ty: &str, raw: &str) -> Result<Value, TextError> {
    match ty {
        "string" => Ok(Value::String(raw.to_owned())),
        "integer" => raw
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| TextError::BadInteger(raw.to_owned())),
        "boolean" => match raw {
            "true" => Ok(Value::Boolean(true)),
            "false" => Ok(Value::Boolean(false)),
            other => Err(TextError::BadBoolean(other.to_owned())),
        },
        other => Err(TextError::UnknownType(other.to_owned())),
    }
}

fn field_type_token(ty: FieldType) -> &'static str {
    match ty {
        FieldType::String => "string",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
    }
}

/// Serialize a CRD body to the shared manifest text format. Round-trips with
/// [`parse_crd`]: `parse_crd(&to_text(c)) == Ok(c)`.
#[must_use]
pub fn to_text(crd: &Crd) -> String {
    let mut out = String::new();
    out.push_str(&format!("apiVersion: {}\n", crd.api_version));
    out.push_str(&format!("kind: {}\n", crd.kind));
    out.push_str(&format!("name: {}\n", crd.metadata.name));
    for (k, v) in &crd.metadata.labels {
        out.push_str(&format!("label {k}: {v}\n"));
    }
    for (k, v) in &crd.spec {
        let ty = match v {
            Value::String(_) => "string",
            Value::Integer(_) => "integer",
            Value::Boolean(_) => "boolean",
        };
        out.push_str(&format!("spec {k} {ty}: {}\n", value_to_text(v)));
    }
    out
}

/// Why parsing the manifest text format failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    /// A line was not recognized.
    BadLine(String),
    /// A required header (`apiVersion`/`kind`/`name`) was missing.
    MissingHeader(&'static str),
    /// A `spec` line was not `spec <field> <type>: <value>`.
    BadSpecLine(String),
    /// An `integer`-typed value did not parse.
    BadInteger(String),
    /// A `boolean`-typed value was not `true`/`false`.
    BadBoolean(String),
    /// A field type token was not `string`/`integer`/`boolean`.
    UnknownType(String),
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TextError::BadLine(l) => write!(f, "unrecognized line: {l}"),
            TextError::MissingHeader(h) => write!(f, "missing required header `{h}`"),
            TextError::BadSpecLine(l) => write!(f, "malformed spec line: {l}"),
            TextError::BadInteger(v) => write!(f, "not an integer: {v}"),
            TextError::BadBoolean(v) => write!(f, "not a boolean: {v}"),
            TextError::UnknownType(t) => write!(f, "unknown field type: {t}"),
        }
    }
}

impl std::error::Error for TextError {}

/// Parse the shared manifest text format into a CRD body. Ignores blank lines
/// and `#` comments; round-trips with [`to_text`].
///
/// # Errors
/// A [`TextError`] describing the first malformed or missing element.
pub fn parse_crd(text: &str) -> Result<Crd, TextError> {
    let mut api_version: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut name: Option<String> = None;
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    let mut spec: BTreeMap<String, Value> = BTreeMap::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("apiVersion:") {
            api_version = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("kind:") {
            kind = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("name:") {
            name = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("label ") {
            let (k, v) = rest
                .split_once(':')
                .ok_or_else(|| TextError::BadLine(line.to_owned()))?;
            labels.insert(k.trim().to_owned(), v.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("spec ") {
            // spec <field> <type>: <value>
            let (lhs, value) = rest
                .split_once(':')
                .ok_or_else(|| TextError::BadSpecLine(line.to_owned()))?;
            let mut parts = lhs.split_whitespace();
            let field = parts
                .next()
                .ok_or_else(|| TextError::BadSpecLine(line.to_owned()))?;
            let ty = parts
                .next()
                .ok_or_else(|| TextError::BadSpecLine(line.to_owned()))?;
            if parts.next().is_some() {
                return Err(TextError::BadSpecLine(line.to_owned()));
            }
            spec.insert(field.to_owned(), parse_typed_value(ty, value.trim())?);
        } else {
            return Err(TextError::BadLine(line.to_owned()));
        }
    }

    let mut metadata = Metadata::new(name.ok_or(TextError::MissingHeader("name"))?);
    metadata.labels = labels;
    Ok(Crd {
        api_version: api_version.ok_or(TextError::MissingHeader("apiVersion"))?,
        kind: kind.ok_or(TextError::MissingHeader("kind"))?,
        metadata,
        spec,
    })
}

// ---------------------------------------------------------------------------
// kustomize (text overlay) — a base plus additive name-prefix, labels, and
// spec patches, rendered to the shared text format.
// ---------------------------------------------------------------------------

/// A kustomize-style overlay: a base CRD plus an additive name-prefix, extra
/// labels, and spec patches. [`render`](Kustomization::render) produces the
/// shared manifest text, which `apply`s through the ordinary authorized path.
#[derive(Clone, Debug, Default)]
pub struct Kustomization {
    base: Option<Crd>,
    name_prefix: String,
    labels: BTreeMap<String, String>,
    spec_patches: BTreeMap<String, Value>,
}

impl Kustomization {
    /// An empty overlay.
    #[must_use]
    pub fn new() -> Self {
        Kustomization::default()
    }

    /// Set the base resource this overlay customizes.
    #[must_use]
    pub fn base(mut self, base: Crd) -> Self {
        self.base = Some(base);
        self
    }

    /// Prepend a name prefix to `metadata.name` (kustomize's `namePrefix`).
    #[must_use]
    pub fn name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = prefix.into();
        self
    }

    /// Add a common label (kustomize's `commonLabels`).
    #[must_use]
    pub fn label(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.labels.insert(k.into(), v.into());
        self
    }

    /// Patch (add or override) a spec field.
    #[must_use]
    pub fn patch(mut self, field: impl Into<String>, value: Value) -> Self {
        self.spec_patches.insert(field.into(), value);
        self
    }

    /// Render the overlaid CRD body.
    ///
    /// # Errors
    /// [`RenderError::NoBase`] if no base was set.
    pub fn render_crd(&self) -> Result<Crd, RenderError> {
        let mut crd = self.base.clone().ok_or(RenderError::NoBase)?;
        crd.metadata.name = format!("{}{}", self.name_prefix, crd.metadata.name);
        for (k, v) in &self.labels {
            crd.metadata.labels.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.spec_patches {
            crd.spec.insert(k.clone(), v.clone());
        }
        Ok(crd)
    }

    /// Render to the shared manifest text format.
    ///
    /// # Errors
    /// [`RenderError::NoBase`] if no base was set.
    pub fn render(&self) -> Result<String, RenderError> {
        Ok(to_text(&self.render_crd()?))
    }
}

// ---------------------------------------------------------------------------
// helm-as-renderer — a text template with `{{ key }}` holes filled from values.
// ---------------------------------------------------------------------------

/// A helm-style renderer: a manifest text template with `{{ key }}`
/// placeholders substituted from a values map, producing manifest text that
/// `apply`s through the ordinary authorized path. Helm is used purely as a
/// renderer here — no tiller, no cluster.
#[derive(Clone, Debug)]
pub struct HelmChart {
    template: String,
}

impl HelmChart {
    /// A chart from a text template. Placeholders are `{{ key }}` (surrounding
    /// whitespace inside the braces is ignored).
    #[must_use]
    pub fn new(template: impl Into<String>) -> Self {
        HelmChart {
            template: template.into(),
        }
    }

    /// Render the template by substituting every `{{ key }}` with its value.
    ///
    /// # Errors
    /// [`RenderError::MissingValue`] naming the first placeholder with no value.
    pub fn render(&self, values: &BTreeMap<String, String>) -> Result<String, RenderError> {
        let mut out = String::new();
        let mut rest = self.template.as_str();
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let close = after
                .find("}}")
                .ok_or_else(|| RenderError::UnterminatedPlaceholder(rest[open..].to_owned()))?;
            let key = after[..close].trim();
            let value = values
                .get(key)
                .ok_or_else(|| RenderError::MissingValue(key.to_owned()))?;
            out.push_str(value);
            rest = &after[close + 2..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// Render straight to a CRD body (render text, then [`parse_crd`]).
    ///
    /// # Errors
    /// [`RenderError`] on a missing value or unterminated placeholder, or a
    /// wrapped [`TextError`] if the rendered text is malformed.
    pub fn render_crd(&self, values: &BTreeMap<String, String>) -> Result<Crd, RenderError> {
        let text = self.render(values)?;
        parse_crd(&text).map_err(RenderError::Text)
    }
}

/// Why a `kustomize`/`helm` render failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// A kustomization had no base resource.
    NoBase,
    /// A helm placeholder `{{ key }}` had no value supplied.
    MissingValue(String),
    /// A helm `{{` was never closed by a `}}`.
    UnterminatedPlaceholder(String),
    /// The rendered text did not parse as a manifest.
    Text(TextError),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::NoBase => write!(f, "kustomization has no base"),
            RenderError::MissingValue(k) => write!(f, "no value supplied for `{{{{ {k} }}}}`"),
            RenderError::UnterminatedPlaceholder(s) => {
                write!(f, "unterminated placeholder near: {s}")
            }
            RenderError::Text(e) => write!(f, "rendered manifest is invalid: {e}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Convenience: a schema field-type token, exposed so callers building schemas
/// alongside text manifests can name types consistently with the text format.
#[must_use]
pub fn type_token(ty: FieldType) -> &'static str {
    field_type_token(ty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{Schema, SchemaRegistry};
    use pillar_rbac::{default_resource_class_policies, Capability as RbacCapability};

    const OWNER: &str = "OWNER-FPR";
    const STRANGER: &str = "STRANGER-FPR";
    const API: &str = "pillar.dev/v1";
    const KIND: &str = "Route";
    const CAP: &str = "net/route";

    fn route_schema() -> Schema {
        Schema::new(API, KIND)
            .required("prefix", FieldType::String)
            .required("metric", FieldType::Integer)
            .property("blackhole", FieldType::Boolean)
    }

    fn registry() -> SchemaRegistry {
        let mut reg = SchemaRegistry::new();
        reg.register(route_schema());
        reg
    }

    /// A platform whose owner is authorized for `CAP` (near the trust root),
    /// and a stranger who is unreachable — so authorization is a real WoT
    /// decision, not a stub.
    fn platform() -> Platform {
        let authority = WotAuthority::new(NodeId::from(OWNER), 5);
        let policies = default_resource_class_policies(&RbacCapability(CAP.to_owned()));
        Platform::new(registry(), authority, policies, Vec::new())
    }

    fn route_crd(name: &str) -> Crd {
        Crd::new(API, KIND, Metadata::new(name).with_label("tier", "edge"))
            .with_spec("prefix", Value::String("10.0.0.0/8".into()))
            .with_spec("metric", Value::Integer(100))
    }

    #[test]
    fn apply_by_authorized_actor_emits_one_signed_event() {
        let mut p = platform();
        assert_eq!(p.event_count(), 0);
        let applied = p
            .apply(
                &NodeId::from(OWNER),
                CAP,
                route_crd("default"),
                [],
                [ManifestCapability::from(CAP)],
            )
            .expect("owner is authorized");
        // Exactly one signed event was emitted, and it is authentic.
        assert_eq!(p.event_count(), 1);
        let event = p_get_event(&p, applied.event);
        assert!(event.is_authentic());
        assert_eq!(event.content().author().0, OWNER);
    }

    // The log is private; expose a tiny read helper just for the test.
    fn p_get_event(p: &Platform, id: EventId) -> pillar_eventlog::Event {
        p.log.get(&id).expect("event exists").clone()
    }

    #[test]
    fn unauthorized_apply_changes_nothing() {
        let mut p = platform();
        let err = p
            .apply(
                &NodeId::from(STRANGER),
                CAP,
                route_crd("default"),
                [],
                [ManifestCapability::from(CAP)],
            )
            .expect_err("stranger is not authorized");
        assert!(matches!(err, ApplyError::Unauthorized { .. }));
        // No event logged, no manifest sealed, nothing in the view.
        assert_eq!(p.event_count(), 0);
        assert!(p.view().is_empty());
    }

    #[test]
    fn apply_with_invalid_body_is_rejected_and_logs_nothing() {
        let mut p = platform();
        let bad = Crd::new(API, KIND, Metadata::new("default"))
            .with_spec("prefix", Value::String("x".into())); // missing required `metric`
        let err = p
            .apply(&NodeId::from(OWNER), CAP, bad, [], [])
            .expect_err("schema invalid");
        assert!(matches!(err, ApplyError::Schema(_)));
        assert_eq!(p.event_count(), 0);
    }

    #[test]
    fn get_and_describe_render_the_view_without_writing_back() {
        let mut p = platform();
        p.apply(
            &NodeId::from(OWNER),
            CAP,
            route_crd("default"),
            [],
            [ManifestCapability::from(CAP)],
        )
        .unwrap();
        let before = p.event_count();

        // get renders the applied body...
        let got = p.get(API, KIND, "default").expect("resource in view");
        assert_eq!(got, route_crd("default"));
        // describe surfaces provenance...
        let described = p.describe(API, KIND, "default").expect("resource in view");
        assert!(described.contains("Signer:"));
        assert!(described.contains(OWNER));
        assert!(described.contains("Verified:      yes"));
        // Provenance also names WHICH rung of the RBAC lattice authorized
        // this signer for its exercised capability — never fabricated, and
        // uniform across every kind on this plane.
        assert!(described.contains("Exercised-Authority:"));
        assert!(described.contains("WoT-depth default"));

        // ...and neither wrote anything back to the log.
        assert_eq!(p.event_count(), before);
        // Reading an absent resource is None, still no write-back.
        assert!(p.get(API, KIND, "missing").is_none());
        assert!(p.describe(API, KIND, "missing").is_none());
        assert_eq!(p.event_count(), before);
    }

    #[test]
    fn describe_exercised_authority_reflects_an_explicit_grant_and_never_fabricates_with_no_scope()
    {
        let owner = NodeId::from(OWNER);
        // An explicit ALLOW grant is the rung actually exercised here.
        let grants = vec![ExplicitGrant {
            subject: owner.clone(),
            capability: RbacCapability(CAP.to_owned()),
            effect: pillar_rbac::GrantEffect::Allow,
        }];
        let mut p = Platform::new(
            registry(),
            WotAuthority::new(owner.clone(), 5),
            default_resource_class_policies(&RbacCapability(CAP.to_owned())),
            grants,
        );
        p.apply(
            &owner,
            CAP,
            route_crd("granted"),
            [],
            [ManifestCapability::from(CAP)],
        )
        .unwrap();
        let described = p.describe(API, KIND, "granted").unwrap();
        assert!(described.contains("Exercised-Authority: explicit grant (allow)"));

        // An envelope applied with NO capability-scope has nothing to
        // explain — describe says so plainly rather than guessing a rung.
        p.apply(&owner, CAP, route_crd("scopeless"), [], [])
            .unwrap();
        let described = p.describe(API, KIND, "scopeless").unwrap();
        assert!(described.contains("Exercised-Authority: (no capability-scope"));
    }

    #[test]
    fn latest_apply_wins_in_the_view() {
        let mut p = platform();
        p.apply(&NodeId::from(OWNER), CAP, route_crd("r"), [], [])
            .unwrap();
        let updated = route_crd("r").with_spec("metric", Value::Integer(200));
        p.apply(&NodeId::from(OWNER), CAP, updated.clone(), [], [])
            .unwrap();
        assert_eq!(p.event_count(), 2);
        assert_eq!(p.get(API, KIND, "r").unwrap(), updated);
    }

    #[test]
    fn text_format_round_trips() {
        let crd = route_crd("default").with_spec("blackhole", Value::Boolean(false));
        let text = to_text(&crd);
        assert_eq!(parse_crd(&text), Ok(crd));
    }

    #[test]
    fn kustomize_output_applies() {
        let mut p = platform();
        let kust = Kustomization::new()
            .base(route_crd("base"))
            .name_prefix("prod-")
            .label("env", "prod")
            .patch("metric", Value::Integer(50));
        let text = kust.render().expect("renders");
        let crd = parse_crd(&text).expect("valid text");
        // The rendered overlay applies through the ordinary authorized path.
        p.apply(&NodeId::from(OWNER), CAP, crd, [], [])
            .expect("kustomize output applies");
        assert_eq!(p.event_count(), 1);
        let got = p.get(API, KIND, "prod-base").expect("renamed resource");
        assert_eq!(got.metadata.labels.get("env"), Some(&"prod".to_owned()));
        assert_eq!(got.spec.get("metric"), Some(&Value::Integer(50)));
    }

    #[test]
    fn helm_output_applies() {
        let mut p = platform();
        let chart = HelmChart::new(
            "apiVersion: {{ apiVersion }}\n\
             kind: {{ kind }}\n\
             name: {{ name }}\n\
             spec prefix string: {{ prefix }}\n\
             spec metric integer: {{ metric }}\n",
        );
        let mut values = BTreeMap::new();
        values.insert("apiVersion".to_owned(), API.to_owned());
        values.insert("kind".to_owned(), KIND.to_owned());
        values.insert("name".to_owned(), "released".to_owned());
        values.insert("prefix".to_owned(), "192.0.2.0/24".to_owned());
        values.insert("metric".to_owned(), "42".to_owned());

        let crd = chart.render_crd(&values).expect("renders and parses");
        p.apply(&NodeId::from(OWNER), CAP, crd, [], [])
            .expect("helm output applies");
        assert_eq!(p.event_count(), 1);
        let got = p.get(API, KIND, "released").expect("resource applied");
        assert_eq!(got.spec.get("metric"), Some(&Value::Integer(42)));
    }

    #[test]
    fn helm_missing_value_is_an_error() {
        let chart = HelmChart::new("name: {{ name }}\n");
        let err = chart.render(&BTreeMap::new()).expect_err("no value");
        assert_eq!(err, RenderError::MissingValue("name".to_owned()));
    }
}
