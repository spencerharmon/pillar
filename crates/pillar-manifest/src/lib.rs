//! Signed intent manifests: look like a CRD, do **not** be Kubernetes.
//!
//! A Pillar manifest is a Kubernetes-CRD-*compatible* body — `apiVersion`,
//! `kind`, `metadata.{name,labels}`, and a typed `spec` validated against an
//! OpenAPI-style schema registered per kind — carried inside a **pillar-native
//! envelope** that a plain CRD does not have:
//!
//! - **signer-key** — the identity that signed this intent (an OpenPGP
//!   fingerprint string, as [`pillar_identity`] models keys);
//! - **causal-parents** — the content-addresses of the manifests this one
//!   causally follows, so a manifest is a node on the same merkle-DAG the
//!   [`pillar_eventlog`] rides (a hash-linked, tamper-evident history);
//! - **content-hash** — the canonical content address of the CRD body, a real
//!   collision-resistant cryptographic multihash (SHA2-256 via
//!   [`pillar_crypto::content::content_address`]), NOT a checksum;
//! - **capability-scope** — the set of capabilities this signed intent claims
//!   authority over.
//!
//! The relationship to Kubernetes is a **superset, not a copy**: an
//! [`Envelope`] *renders* to a plain [`Crd`] (drop the envelope, keep the
//! body), and any plain [`Crd`] *imports* into an [`Envelope`] by being signed
//! into one ([`Envelope::import`]). Round-tripping either direction is loss-
//! free for the CRD body — that is the compatibility contract. Nothing here
//! reaches the network or the filesystem; these are pure value types with a
//! deterministic, cross-platform canonical serialization, so two nodes holding
//! the same manifest necessarily agree on its content-hash and its signature.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pillar_crypto::content::content_address;
use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
use pillar_crypto::{Seed, Signature, SigningPublicKey, SigningSecretKey};

pub mod bgp_lb;
pub mod ingress;

/// The content-address of a manifest body — a real collision-resistant
/// cryptographic multihash (SHA2-256, self-describing `<code><len><digest>`
/// bytes) produced by [`pillar_crypto::content::content_address`], the SAME
/// content-address primitive every other Pillar layer uses. Two nodes holding
/// the same CRD body necessarily agree on its [`ContentHash`]; a single-bit
/// change to the body flips it, and finding two distinct bodies with the same
/// hash is cryptographically infeasible (it is NOT a 64-bit checksum).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(pub Vec<u8>);

impl ContentHash {
    /// Borrow the raw multihash bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A capability a signed intent claims authority over (an opaque scope string,
/// e.g. `net/route`, `ipam/allocate`). Held as an ordered set so the envelope
/// serializes canonically regardless of insertion order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability(pub String);

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_owned())
    }
}

/// The CRD `metadata` block: a name plus arbitrary string labels — exactly the
/// Kubernetes shape a controller expects to read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.labels` — an ordered map so the canonical bytes are stable.
    pub labels: BTreeMap<String, String>,
}

impl Metadata {
    /// A metadata block with the given name and no labels.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Metadata {
            name: name.into(),
            labels: BTreeMap::new(),
        }
    }

    /// Add a label, builder-style.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// A Kubernetes-CRD-compatible resource body: `apiVersion`, `kind`,
/// `metadata`, and a typed `spec`. This is exactly what a controller sees; the
/// [`Envelope`] wraps it without changing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crd {
    /// `apiVersion`, e.g. `pillar.dev/v1`.
    pub api_version: String,
    /// `kind`, e.g. `Route`.
    pub kind: String,
    /// `metadata`.
    pub metadata: Metadata,
    /// `spec` — a flat, typed field map validated against the kind's schema.
    pub spec: BTreeMap<String, Value>,
}

/// A `spec` field value. A deliberately small, typed subset — enough to model
/// an OpenAPI object schema's leaf types while staying dependency-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An OpenAPI `string`.
    String(String),
    /// An OpenAPI `integer`.
    Integer(i64),
    /// An OpenAPI `boolean`.
    Boolean(bool),
}

impl Value {
    fn ty(&self) -> FieldType {
        match self {
            Value::String(_) => FieldType::String,
            Value::Integer(_) => FieldType::Integer,
            Value::Boolean(_) => FieldType::Boolean,
        }
    }

    fn canonical_tag(&self) -> u8 {
        match self {
            Value::String(_) => 0,
            Value::Integer(_) => 1,
            Value::Boolean(_) => 2,
        }
    }
}

impl Crd {
    /// Build a CRD body with an empty spec.
    #[must_use]
    pub fn new(
        api_version: impl Into<String>,
        kind: impl Into<String>,
        metadata: Metadata,
    ) -> Self {
        Crd {
            api_version: api_version.into(),
            kind: kind.into(),
            metadata,
            spec: BTreeMap::new(),
        }
    }

    /// Set a spec field, builder-style.
    #[must_use]
    pub fn with_spec(mut self, field: impl Into<String>, value: Value) -> Self {
        self.spec.insert(field.into(), value);
        self
    }

    /// The canonical, deterministic byte serialization of this CRD body. Fed to
    /// the content-address; stable across runs and platforms so two nodes
    /// holding the same body necessarily agree on its [`ContentHash`].
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        push_str(&mut b, &self.api_version);
        push_str(&mut b, &self.kind);
        push_str(&mut b, &self.metadata.name);
        b.extend_from_slice(&(self.metadata.labels.len() as u64).to_le_bytes());
        // BTreeMap iterates in sorted key order — canonical regardless of insert order.
        for (k, v) in &self.metadata.labels {
            push_str(&mut b, k);
            push_str(&mut b, v);
        }
        b.extend_from_slice(&(self.spec.len() as u64).to_le_bytes());
        for (k, v) in &self.spec {
            push_str(&mut b, k);
            b.push(v.canonical_tag());
            match v {
                Value::String(s) => push_str(&mut b, s),
                Value::Integer(i) => b.extend_from_slice(&i.to_le_bytes()),
                Value::Boolean(x) => b.push(u8::from(*x)),
            }
        }
        b
    }

    /// The content address of this CRD body.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        // SHA2-256 multihash over the canonical body bytes. `content_address`
        // is infallible for an in-memory buffer; a real error would be a bug in
        // the crypto layer, so surface it loudly rather than silently masking.
        let cid = content_address(&self.canonical_bytes())
            .expect("content_address over an in-memory buffer cannot fail");
        ContentHash(cid.into_bytes())
    }
}

fn push_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// The OpenAPI leaf types a schema field may require.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// `type: string`.
    String,
    /// `type: integer`.
    Integer,
    /// `type: boolean`.
    Boolean,
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FieldType::String => "string",
            FieldType::Integer => "integer",
            FieldType::Boolean => "boolean",
        })
    }
}

/// The OpenAPI-style schema for one kind's `spec`: a set of typed properties,
/// some required. Extra fields not in the schema are rejected (closed schema),
/// as is a required field left absent or a field whose value has the wrong
/// type — the structural validation a CRD's `openAPIV3Schema` performs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    api_version: String,
    kind: String,
    properties: BTreeMap<String, FieldType>,
    required: BTreeSet<String>,
}

impl Schema {
    /// A schema for `<api_version>/<kind>` with no properties yet.
    #[must_use]
    pub fn new(api_version: impl Into<String>, kind: impl Into<String>) -> Self {
        Schema {
            api_version: api_version.into(),
            kind: kind.into(),
            properties: BTreeMap::new(),
            required: BTreeSet::new(),
        }
    }

    /// Declare an optional property of the given type.
    #[must_use]
    pub fn property(mut self, name: impl Into<String>, ty: FieldType) -> Self {
        self.properties.insert(name.into(), ty);
        self
    }

    /// Declare a required property of the given type.
    #[must_use]
    pub fn required(mut self, name: impl Into<String>, ty: FieldType) -> Self {
        let name = name.into();
        self.properties.insert(name.clone(), ty);
        self.required.insert(name);
        self
    }

    /// Validate a CRD body against this schema: the `apiVersion`/`kind` must
    /// match, every required property must be present, and every present spec
    /// field must be declared and carry a value of its declared type.
    ///
    /// # Errors
    /// Returns the first [`SchemaError`] found.
    pub fn validate(&self, crd: &Crd) -> Result<(), SchemaError> {
        if crd.api_version != self.api_version || crd.kind != self.kind {
            return Err(SchemaError::KindMismatch {
                expected: format!("{}/{}", self.api_version, self.kind),
                found: format!("{}/{}", crd.api_version, crd.kind),
            });
        }
        for req in &self.required {
            if !crd.spec.contains_key(req) {
                return Err(SchemaError::MissingRequired(req.clone()));
            }
        }
        for (field, value) in &crd.spec {
            match self.properties.get(field) {
                None => return Err(SchemaError::UnknownField(field.clone())),
                Some(&ty) if ty != value.ty() => {
                    return Err(SchemaError::TypeMismatch {
                        field: field.clone(),
                        expected: ty,
                        found: value.ty(),
                    })
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

/// A registry of per-kind schemas, keyed by `apiVersion/kind` — the platform's
/// view of "every registered CRD kind and how to validate it".
#[derive(Clone, Debug, Default)]
pub struct SchemaRegistry {
    schemas: BTreeMap<(String, String), Schema>,
}

impl SchemaRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        SchemaRegistry {
            schemas: BTreeMap::new(),
        }
    }

    /// Register (or replace) the schema for its `apiVersion/kind`.
    pub fn register(&mut self, schema: Schema) {
        self.schemas
            .insert((schema.api_version.clone(), schema.kind.clone()), schema);
    }

    /// The schema for a CRD body's kind, if registered.
    #[must_use]
    pub fn schema_for(&self, crd: &Crd) -> Option<&Schema> {
        self.schemas
            .get(&(crd.api_version.clone(), crd.kind.clone()))
    }

    /// Validate a CRD body against its registered schema.
    ///
    /// # Errors
    /// [`SchemaError::UnregisteredKind`] if no schema is registered for the
    /// body's kind, otherwise whatever [`Schema::validate`] returns.
    pub fn validate(&self, crd: &Crd) -> Result<(), SchemaError> {
        match self.schema_for(crd) {
            None => Err(SchemaError::UnregisteredKind(format!(
                "{}/{}",
                crd.api_version, crd.kind
            ))),
            Some(schema) => schema.validate(crd),
        }
    }
}

/// Why a CRD body failed schema validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// No schema is registered for the body's `apiVersion/kind`.
    UnregisteredKind(String),
    /// The body's `apiVersion/kind` does not match the schema's.
    KindMismatch {
        /// The schema's `apiVersion/kind`.
        expected: String,
        /// The body's `apiVersion/kind`.
        found: String,
    },
    /// A required property is absent from `spec`.
    MissingRequired(String),
    /// A `spec` field is not declared in the schema.
    UnknownField(String),
    /// A `spec` field's value is the wrong type.
    TypeMismatch {
        /// The offending field.
        field: String,
        /// The type the schema requires.
        expected: FieldType,
        /// The type the value actually has.
        found: FieldType,
    },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::UnregisteredKind(k) => write!(f, "no schema registered for kind {k}"),
            SchemaError::KindMismatch { expected, found } => {
                write!(f, "kind mismatch: schema is {expected}, body is {found}")
            }
            SchemaError::MissingRequired(field) => {
                write!(f, "required spec field `{field}` is missing")
            }
            SchemaError::UnknownField(field) => {
                write!(f, "spec field `{field}` is not in the schema")
            }
            SchemaError::TypeMismatch {
                field,
                expected,
                found,
            } => write!(
                f,
                "spec field `{field}` should be {expected} but is {found}"
            ),
        }
    }
}

impl std::error::Error for SchemaError {}

/// A **real ed25519 signature** over an [`Envelope`]'s binding — a detached
/// asymmetric signature, not a self-recomputable digest. Verification uses only
/// the recorded verifying (public) key, so holding it cannot forge a signature
/// (the asymmetry [`pillar_crypto::sign`] guarantees).
///
/// The signature is bound to the envelope's **binding message**: the CRD body's
/// content-hash together with the signer, the causal-parents, and the
/// capability-scope. Rewriting any of those after signing changes the message
/// and the signature no longer verifies — tamper-evidence over the whole
/// signed intent, not just the CRD body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestSignature {
    signer: String,
    /// The ed25519 verifying key the signature checks against, bound to the
    /// signer identity (derived deterministically from it).
    verifying_key: SigningPublicKey,
    /// The detached ed25519 signature over the binding message.
    signature: Signature,
}

impl ManifestSignature {
    /// The fingerprint of the key that signed the manifest.
    #[must_use]
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// The ed25519 verifying (public) key this signature checks against.
    #[must_use]
    pub fn verifying_key(&self) -> &SigningPublicKey {
        &self.verifying_key
    }
}

/// A signed intent manifest: a CRD body plus the pillar-native envelope
/// (signer-key, causal-parents, content-hash, capability-scope) and the
/// signature binding them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    signer: String,
    causal_parents: BTreeSet<ContentHash>,
    content_hash: ContentHash,
    capability_scope: BTreeSet<Capability>,
    body: Crd,
    signature: ManifestSignature,
}

impl Envelope {
    /// Compute the **binding message** the signature covers: content-hash +
    /// signer + sorted causal-parents + sorted capability-scope. Pure and
    /// canonical — the exact bytes fed to ed25519 sign/verify.
    fn binding_message(
        content_hash: &ContentHash,
        signer: &str,
        parents: &BTreeSet<ContentHash>,
        scope: &BTreeSet<Capability>,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"pillar-manifest/envelope-binding-v1");
        b.extend_from_slice(&(content_hash.0.len() as u64).to_le_bytes());
        b.extend_from_slice(&content_hash.0);
        push_str(&mut b, signer);
        b.extend_from_slice(&(parents.len() as u64).to_le_bytes());
        for p in parents {
            b.extend_from_slice(&(p.0.len() as u64).to_le_bytes());
            b.extend_from_slice(&p.0);
        }
        b.extend_from_slice(&(scope.len() as u64).to_le_bytes());
        for c in scope {
            push_str(&mut b, &c.0);
        }
        b
    }

    /// Derive the ed25519 signing keypair bound to a `signer` identity.
    ///
    /// The signer string IS the key material: a domain-separated seed derives a
    /// real ed25519 keypair deterministically (so two nodes signing as the same
    /// identity produce a verifiable signature, and re-import is stable),
    /// through [`pillar_crypto::sign::signing_keypair_from_seed`]. A production
    /// deployment binds `signer` to an operator-held secret key instead; the
    /// contract — a real asymmetric signature whose forgery is infeasible from
    /// the public key alone — is identical.
    fn keypair_for_signer(signer: &str) -> (SigningPublicKey, SigningSecretKey) {
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(b"pillar-manifest/signer-key-v1/");
        seed_material.extend_from_slice(signer.as_bytes());
        let seed = Seed::from_bytes(seed_material);
        signing_keypair_from_seed(&seed).expect("ed25519 keygen from seed cannot fail")
    }

    /// Import a plain CRD by **signing it into an envelope**: derive the body's
    /// content-hash, attach the causal-parents and capability-scope, and bind a
    /// real ed25519 signature by `signer`. This is how a plain Kubernetes CRD
    /// becomes a Pillar signed-intent — the superset direction.
    #[must_use]
    pub fn import(
        body: Crd,
        signer: impl Into<String>,
        causal_parents: impl IntoIterator<Item = ContentHash>,
        capability_scope: impl IntoIterator<Item = Capability>,
    ) -> Self {
        let signer = signer.into();
        let content_hash = body.content_hash();
        let causal_parents: BTreeSet<ContentHash> = causal_parents.into_iter().collect();
        let capability_scope: BTreeSet<Capability> = capability_scope.into_iter().collect();
        let message =
            Self::binding_message(&content_hash, &signer, &causal_parents, &capability_scope);
        let (verifying_key, secret) = Self::keypair_for_signer(&signer);
        let signature = sign(&secret, &message).expect("ed25519 signing cannot fail");
        Envelope {
            signer: signer.clone(),
            causal_parents,
            content_hash,
            capability_scope,
            body,
            signature: ManifestSignature {
                signer,
                verifying_key,
                signature,
            },
        }
    }

    /// **Render** to the plain CRD body — drop the envelope, keep exactly the
    /// Kubernetes-compatible resource a controller reads. The inverse of
    /// [`Envelope::import`] for the body.
    #[must_use]
    pub fn render(&self) -> Crd {
        self.body.clone()
    }

    /// The CRD body carried by this manifest (borrowed).
    #[must_use]
    pub fn body(&self) -> &Crd {
        &self.body
    }

    /// The signer-key of this manifest.
    #[must_use]
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// The causal-parents of this manifest on the merkle-DAG.
    #[must_use]
    pub fn causal_parents(&self) -> &BTreeSet<ContentHash> {
        &self.causal_parents
    }

    /// The content-hash the envelope records for its body.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash.clone()
    }

    /// The capability-scope this signed intent claims.
    #[must_use]
    pub fn capability_scope(&self) -> &BTreeSet<Capability> {
        &self.capability_scope
    }

    /// The signature over this manifest's binding.
    #[must_use]
    pub fn signature(&self) -> &ManifestSignature {
        &self.signature
    }

    /// Whether this manifest is authentic and internally consistent:
    ///
    /// 1. the recorded `content_hash` still equals the body's recomputed
    ///    content address (the body was not rewritten after sealing), and
    /// 2. the verifying key is the one bound to the recorded signer, AND the
    ///    real ed25519 signature verifies over the envelope's recomputed
    ///    binding message (no field — body, signer, parents, or scope — was
    ///    tampered after signing). Verification is asymmetric: it uses only the
    ///    public key, so a forged signature is cryptographically infeasible.
    #[must_use]
    pub fn verify(&self) -> bool {
        if self.body.content_hash() != self.content_hash {
            return false;
        }
        if self.signature.signer != self.signer {
            return false;
        }
        // The verifying key MUST be the one bound to the claimed signer — a
        // forged envelope cannot swap in a key it controls and still name the
        // real signer.
        let (expected_key, _) = Self::keypair_for_signer(&self.signer);
        if self.signature.verifying_key != expected_key {
            return false;
        }
        let message = Self::binding_message(
            &self.content_hash,
            &self.signer,
            &self.causal_parents,
            &self.capability_scope,
        );
        verify(
            &self.signature.verifying_key,
            &message,
            &self.signature.signature,
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct test content-hash — a real multihash over a label, so parent
    /// hashes are the same shape real bodies produce.
    fn ch(n: u64) -> ContentHash {
        let cid = content_address(format!("test-parent-{n}").as_bytes()).expect("address");
        ContentHash(cid.into_bytes())
    }

    fn route_schema() -> Schema {
        Schema::new("pillar.dev/v1", "Route")
            .required("prefix", FieldType::String)
            .required("metric", FieldType::Integer)
            .property("blackhole", FieldType::Boolean)
    }

    fn route_crd() -> Crd {
        Crd::new(
            "pillar.dev/v1",
            "Route",
            Metadata::new("default-route").with_label("tier", "edge"),
        )
        .with_spec("prefix", Value::String("10.0.0.0/8".into()))
        .with_spec("metric", Value::Integer(100))
    }

    #[test]
    fn crd_imports_into_envelope_and_renders_back_identically() {
        let crd = route_crd();
        let env = Envelope::import(crd.clone(), "AAAA-FPR", [], []);
        // The envelope renders back to exactly the CRD body: loss-free round-trip.
        assert_eq!(env.render(), crd);
    }

    #[test]
    fn envelope_to_crd_to_envelope_round_trip_is_stable() {
        let crd = route_crd();
        let scope = [Capability::from("net/route")];
        let parents = [ch(42)];
        let env = Envelope::import(crd, "AAAA-FPR", parents, scope);

        // Render to a plain CRD, then re-import with the SAME envelope fields.
        let rendered = env.render();
        let reimported = Envelope::import(
            rendered,
            env.signer(),
            env.causal_parents().iter().cloned(),
            env.capability_scope().iter().cloned(),
        );
        assert_eq!(reimported, env);
        assert!(reimported.verify());
    }

    #[test]
    fn re_rendering_an_imported_crd_reproduces_the_original() {
        let crd = route_crd();
        let env = Envelope::import(crd.clone(), "AAAA-FPR", [ch(7)], []);
        // CRD import re-renders: import(render(env)) yields the same body twice.
        assert_eq!(env.render(), crd);
        let env2 = Envelope::import(env.render(), "AAAA-FPR", [ch(7)], []);
        assert_eq!(env2.render(), crd);
        assert_eq!(env2, env);
    }

    #[test]
    fn per_kind_schema_admits_a_valid_body() {
        let mut reg = SchemaRegistry::new();
        reg.register(route_schema());
        assert_eq!(reg.validate(&route_crd()), Ok(()));
    }

    #[test]
    fn schema_rejects_missing_required_field() {
        let schema = route_schema();
        let crd = Crd::new("pillar.dev/v1", "Route", Metadata::new("r"))
            .with_spec("prefix", Value::String("10.0.0.0/8".into()));
        assert_eq!(
            schema.validate(&crd),
            Err(SchemaError::MissingRequired("metric".into()))
        );
    }

    #[test]
    fn schema_rejects_wrong_type() {
        let schema = route_schema();
        let crd = route_crd().with_spec("metric", Value::String("oops".into()));
        assert_eq!(
            schema.validate(&crd),
            Err(SchemaError::TypeMismatch {
                field: "metric".into(),
                expected: FieldType::Integer,
                found: FieldType::String,
            })
        );
    }

    #[test]
    fn schema_rejects_unknown_field() {
        let schema = route_schema();
        let crd = route_crd().with_spec("bogus", Value::Boolean(true));
        assert_eq!(
            schema.validate(&crd),
            Err(SchemaError::UnknownField("bogus".into()))
        );
    }

    #[test]
    fn registry_rejects_unregistered_kind() {
        let reg = SchemaRegistry::new();
        assert_eq!(
            reg.validate(&route_crd()),
            Err(SchemaError::UnregisteredKind("pillar.dev/v1/Route".into()))
        );
    }

    #[test]
    fn schema_rejects_kind_mismatch() {
        let schema = route_schema();
        let crd = Crd::new("pillar.dev/v1", "Service", Metadata::new("s"));
        assert!(matches!(
            schema.validate(&crd),
            Err(SchemaError::KindMismatch { .. })
        ));
    }

    #[test]
    fn signature_and_content_hash_verify_on_a_sealed_manifest() {
        let env = Envelope::import(
            route_crd(),
            "AAAA-FPR",
            [ch(1), ch(2)],
            [Capability::from("net/route")],
        );
        assert!(env.verify());
        assert_eq!(env.content_hash(), env.body().content_hash());
        assert_eq!(env.signature().signer(), "AAAA-FPR");
    }

    #[test]
    fn tampering_the_body_breaks_content_hash_and_signature() {
        let env = Envelope::import(route_crd(), "AAAA-FPR", [], []);
        let mut tampered = env.clone();
        tampered.body = tampered
            .body
            .clone()
            .with_spec("metric", Value::Integer(999));
        // content_hash no longer matches the rewritten body.
        assert!(!tampered.verify());
    }

    #[test]
    fn tampering_the_capability_scope_breaks_the_signature() {
        let env = Envelope::import(route_crd(), "AAAA-FPR", [], [Capability::from("net/route")]);
        let mut tampered = env.clone();
        tampered
            .capability_scope
            .insert(Capability::from("ipam/allocate"));
        // Body/content-hash still agree, but the binding digest changed.
        assert_eq!(tampered.body().content_hash(), tampered.content_hash());
        assert!(!tampered.verify());
    }

    #[test]
    fn tampering_the_causal_parents_breaks_the_signature() {
        let env = Envelope::import(route_crd(), "AAAA-FPR", [ch(1)], []);
        let mut tampered = env.clone();
        tampered.causal_parents.insert(ch(9999));
        assert!(!tampered.verify());
    }

    #[test]
    fn a_different_signer_does_not_verify() {
        let env = Envelope::import(route_crd(), "AAAA-FPR", [], []);
        let mut tampered = env.clone();
        tampered.signer = "BBBB-FPR".into();
        assert!(!tampered.verify());
    }

    #[test]
    fn the_content_hash_is_a_real_sha256_multihash_not_a_checksum() {
        // A sha2-256 multihash is `<0x12><0x20><32-byte digest>` = 34 bytes,
        // never a 8-byte little-endian u64 checksum.
        let crd = route_crd();
        let ch = crd.content_hash();
        assert_eq!(ch.as_bytes().len(), 34, "sha2-256 multihash is 34 bytes");
        assert_eq!(ch.as_bytes()[0], 0x12, "multicodec sha2-256");
        assert_eq!(ch.as_bytes()[1], 0x20, "32-byte digest length");
    }

    #[test]
    fn a_forged_signature_from_a_foreign_key_cannot_be_substituted() {
        // Real asymmetry: an attacker who re-signs the SAME binding message
        // with their OWN key and swaps in their verifying key must NOT verify,
        // because the verifying key is bound to the claimed signer identity.
        let env = Envelope::import(route_crd(), "AAAA-FPR", [], [Capability::from("net/route")]);
        assert!(env.verify());

        let message = Envelope::binding_message(
            &env.content_hash,
            &env.signer,
            &env.causal_parents,
            &env.capability_scope,
        );
        let (foreign_pub, foreign_secret) = Envelope::keypair_for_signer("MALLORY-FPR");
        let foreign_sig = sign(&foreign_secret, &message).expect("sign");

        let mut forged = env.clone();
        // Attacker forges a valid signature under their own key but still
        // claims to be AAAA-FPR.
        forged.signature.verifying_key = foreign_pub;
        forged.signature.signature = foreign_sig;
        assert!(
            !forged.verify(),
            "a signature under a foreign key must not verify for the claimed signer"
        );
    }

    #[test]
    fn content_hash_is_deterministic_and_order_independent() {
        let a = Crd::new(
            "pillar.dev/v1",
            "Route",
            Metadata::new("r").with_label("z", "1").with_label("a", "2"),
        )
        .with_spec("metric", Value::Integer(5))
        .with_spec("prefix", Value::String("p".into()));
        let b = Crd::new(
            "pillar.dev/v1",
            "Route",
            Metadata::new("r").with_label("a", "2").with_label("z", "1"),
        )
        .with_spec("prefix", Value::String("p".into()))
        .with_spec("metric", Value::Integer(5));
        // Same content, different insertion order → identical content-hash.
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn distinct_bodies_have_distinct_content_hashes() {
        let a = route_crd();
        let b = route_crd().with_spec("metric", Value::Integer(200));
        assert_ne!(a.content_hash(), b.content_hash());
    }
}
