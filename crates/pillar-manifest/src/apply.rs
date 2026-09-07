//! `pillar apply -f <file>` / `pillar get` / `pillar delete` over the REAL
//! manifest envelope.
//!
//! This is acceptance-narrative step 1: an operator authors a YAML manifest and
//! submits it. The submission path is NOT a Rust builder and NOT a test
//! fixture — it is the real [`Envelope`]:
//!
//! 1. **decode** the authored YAML/JSON into a plain [`Crd`] body
//!    (`Crd::from_yaml` / `Crd::from_json`);
//! 2. **validate** the body against its registered per-kind [`Schema`] in the
//!    [`SchemaRegistry`] (an unregistered kind, a missing required field, an
//!    unknown field, or a type mismatch is REFUSED — nothing is stored);
//! 3. **sign** the body into an [`Envelope`] (`Envelope::import`) — the real
//!    pillar-native envelope (signer-key, content-hash, causal-parents,
//!    capability-scope, ed25519 signature), not a bare struct;
//! 4. **store** the sealed envelope keyed by its `(apiVersion, kind, name)`
//!    address.
//!
//! `get`/`delete` operate over that same keyed store: `get` returns the sealed
//! [`Envelope`] (whose body round-trips identically to the authored manifest),
//! `delete` removes it.
//!
//! The store is deliberately in-memory and pure — no network, no filesystem —
//! so the whole apply→get→delete lifecycle over the real envelope is exercised
//! by an ordinary test. A deployed node backs the identical operations with the
//! event log and the WoT decider (see `pillar-cli`'s `ResourcePlane`); the
//! envelope contract is the same.

use std::collections::BTreeMap;

use crate::serialize::ManifestFormatError;
use crate::{Capability, ContentHash, Crd, Envelope, SchemaError, SchemaRegistry};

/// The `(apiVersion, kind, name)` address a stored manifest is keyed by — the
/// object identity `pillar get <kind>/<name>` resolves.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestKey {
    /// The CRD `apiVersion`.
    pub api_version: String,
    /// The CRD `kind`.
    pub kind: String,
    /// The `metadata.name`.
    pub name: String,
}

impl ManifestKey {
    /// The key a CRD body resolves to.
    #[must_use]
    pub fn of(crd: &Crd) -> Self {
        ManifestKey {
            api_version: crd.api_version.clone(),
            kind: crd.kind.clone(),
            name: crd.metadata.name.clone(),
        }
    }
}

/// Why an `apply`/`get`/`delete` over the manifest store was refused.
#[derive(Debug)]
pub enum ApplyError {
    /// The authored document did not decode to a well-formed CRD.
    Decode(ManifestFormatError),
    /// The decoded body failed schema validation.
    Schema(SchemaError),
    /// A `delete`/`get` targeted an address absent from the store.
    NotFound(ManifestKey),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Decode(e) => write!(f, "{e}"),
            ApplyError::Schema(e) => write!(f, "{e}"),
            ApplyError::NotFound(k) => write!(
                f,
                "no manifest {}/{} named `{}`",
                k.api_version, k.kind, k.name
            ),
        }
    }
}

impl std::error::Error for ApplyError {}

/// An in-memory manifest store implementing the `apply`/`get`/`delete` verbs
/// over the REAL [`Envelope`]. Every applied object is validated against its
/// registered schema and sealed into a signed envelope before it is stored.
pub struct ManifestStore {
    registry: SchemaRegistry,
    signer: String,
    objects: BTreeMap<ManifestKey, Envelope>,
}

impl ManifestStore {
    /// A store that validates applies against `registry` and signs every
    /// sealed envelope as `signer`.
    #[must_use]
    pub fn new(registry: SchemaRegistry, signer: impl Into<String>) -> Self {
        ManifestStore {
            registry,
            signer: signer.into(),
            objects: BTreeMap::new(),
        }
    }

    /// `pillar apply -f <file>` from an authored **YAML** document: decode →
    /// validate → sign into an [`Envelope`] → store. Returns the sealed
    /// envelope's content-hash on success. An upsert: applying the same address
    /// again replaces the stored object.
    ///
    /// # Errors
    /// [`ApplyError::Decode`] if the YAML is not a CRD, [`ApplyError::Schema`]
    /// if the body fails validation — in either case NOTHING is stored.
    pub fn apply_yaml(&mut self, yaml: &str) -> Result<ContentHash, ApplyError> {
        let crd = Crd::from_yaml(yaml).map_err(ApplyError::Decode)?;
        self.apply_crd(crd)
    }

    /// `pillar apply -f <file>` from an authored **JSON** document — the same
    /// path as [`ManifestStore::apply_yaml`] for a JSON source.
    ///
    /// # Errors
    /// As [`ManifestStore::apply_yaml`].
    pub fn apply_json(&mut self, json: &str) -> Result<ContentHash, ApplyError> {
        let crd = Crd::from_json(json).map_err(ApplyError::Decode)?;
        self.apply_crd(crd)
    }

    /// Apply an already-decoded [`Crd`] body: validate → sign → store. The
    /// shared tail of [`ManifestStore::apply_yaml`] / [`ManifestStore::apply_json`].
    ///
    /// # Errors
    /// [`ApplyError::Schema`] if the body fails validation; nothing is stored.
    pub fn apply_crd(&mut self, crd: Crd) -> Result<ContentHash, ApplyError> {
        self.registry.validate(&crd).map_err(ApplyError::Schema)?;
        let key = ManifestKey::of(&crd);
        // Seal the body into the REAL pillar-native envelope — a signed intent,
        // not a bare struct. The capability-scope is the object's kind so a
        // consumer can gate on it.
        let scope = [Capability::from(crd.kind.as_str())];
        let envelope = Envelope::import(crd, self.signer.clone(), [], scope);
        let hash = envelope.content_hash();
        self.objects.insert(key, envelope);
        Ok(hash)
    }

    /// `pillar get <kind>/<name>` — read the stored sealed [`Envelope`] back.
    /// Its body round-trips identically to the authored manifest.
    #[must_use]
    pub fn get(&self, key: &ManifestKey) -> Option<&Envelope> {
        self.objects.get(key)
    }

    /// The rendered CRD body a `pillar get` prints — exactly the object that was
    /// authored and applied.
    #[must_use]
    pub fn get_body(&self, key: &ManifestKey) -> Option<Crd> {
        self.objects.get(key).map(Envelope::render)
    }

    /// `pillar get <kind>` — every stored object of a kind, in key order.
    #[must_use]
    pub fn list(&self, api_version: &str, kind: &str) -> Vec<&Envelope> {
        self.objects
            .iter()
            .filter(|(k, _)| k.api_version == api_version && k.kind == kind)
            .map(|(_, v)| v)
            .collect()
    }

    /// `pillar delete <kind>/<name>` — remove the stored object. Returns the
    /// removed envelope.
    ///
    /// # Errors
    /// [`ApplyError::NotFound`] if no object is stored at `key`.
    pub fn delete(&mut self, key: &ManifestKey) -> Result<Envelope, ApplyError> {
        self.objects
            .remove(key)
            .ok_or_else(|| ApplyError::NotFound(key.clone()))
    }

    /// The number of objects currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the store holds no objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}
