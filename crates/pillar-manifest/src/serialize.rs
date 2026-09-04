//! Real `serde` (de)serialization for the manifest envelope and the CRD body.
//!
//! This is the on-the-wire manifest format an operator AUTHORS — a
//! Kubernetes-CRD-shaped YAML/JSON document — and the format `pillar apply -f
//! <file>` deserializes through. It is deliberately the plain CRD shape a
//! human writes:
//!
//! ```yaml
//! apiVersion: pillar.dev/v1
//! kind: Route
//! metadata:
//!   name: default-route
//!   labels:
//!     tier: edge
//! spec:
//!   prefix: 10.0.0.0/8
//!   metric: 100
//!   blackhole: false
//! ```
//!
//! Every declarable kind (Deployment, Frontend, Route, LoadBalancerPolicy,
//! Service, Job, CronJob, Dashboard, RecordingRule, Alert, SignalConfig)
//! rides the SAME generic [`Crd`] shape — `apiVersion`/`kind`/`metadata`/`spec`
//! — so one (de)serialization path covers them all: the kind is a string field,
//! not a per-kind Rust struct with its own serde impl.
//!
//! Two guarantees this module carries:
//!
//! - **Loss-free round-trip.** Deserialize a document to a [`Crd`], re-serialize
//!   it, and deserialize again: the two [`Crd`] values are equal. `metadata.labels`
//!   and `spec` are ordered maps ([`BTreeMap`]), so the emitted document is
//!   canonical regardless of the input key order — the same property the
//!   content-hash relies on.
//! - **Native scalar `spec` values.** A [`Value`] serializes as a native YAML/JSON
//!   scalar (a bare string, integer, or boolean) — NOT a tagged enum — so the
//!   document is exactly what a human writes and what `kubectl`-trained eyes read.
//!   Deserialization maps each scalar back to the corresponding [`Value`] variant.

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;

use crate::{Crd, Metadata, Value};

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // A spec value serializes as a NATIVE scalar — a bare string, integer,
        // or boolean — so the document is the plain CRD a human authors, never
        // a `{"String": "..."}` tagged form.
        match self {
            Value::String(s) => serializer.serialize_str(s),
            Value::Integer(i) => serializer.serialize_i64(*i),
            Value::Boolean(b) => serializer.serialize_bool(*b),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;

        impl Visitor<'_> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string, integer, or boolean spec value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Boolean(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Integer(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Value, E>
            where
                E: de::Error,
            {
                i64::try_from(v)
                    .map(Value::Integer)
                    .map_err(|_| de::Error::custom("integer spec value out of i64 range"))
            }

            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // `labels` is omitted entirely when empty, so a no-label object
        // round-trips to the SAME `Metadata { labels: {} }` rather than
        // gaining an empty `labels: {}` map on re-read.
        let has_labels = !self.labels.is_empty();
        let mut st = serializer.serialize_struct("Metadata", 1 + usize::from(has_labels))?;
        st.serialize_field("name", &self.name)?;
        if has_labels {
            st.serialize_field("labels", &self.labels)?;
        } else {
            st.skip_field("labels")?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Name,
            Labels,
        }

        struct MetadataVisitor;

        impl<'de> Visitor<'de> for MetadataVisitor {
            type Value = Metadata;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CRD metadata block with a `name` and optional `labels`")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Metadata, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut name: Option<String> = None;
                let mut labels: Option<BTreeMap<String, String>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        Field::Labels => {
                            if labels.is_some() {
                                return Err(de::Error::duplicate_field("labels"));
                            }
                            labels = Some(map.next_value()?);
                        }
                    }
                }
                Ok(Metadata {
                    name: name.ok_or_else(|| de::Error::missing_field("name"))?,
                    labels: labels.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(MetadataVisitor)
    }
}

impl Serialize for Crd {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Emit the Kubernetes-CRD field names verbatim: `apiVersion`, `kind`,
        // `metadata`, `spec`. `spec` is always present (possibly empty) so the
        // document is a well-formed CRD.
        let mut st = serializer.serialize_struct("Crd", 4)?;
        st.serialize_field("apiVersion", &self.api_version)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("metadata", &self.metadata)?;
        st.serialize_field("spec", &self.spec)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Crd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "apiVersion")]
            ApiVersion,
            #[serde(rename = "kind")]
            Kind,
            #[serde(rename = "metadata")]
            Metadata,
            #[serde(rename = "spec")]
            Spec,
        }

        struct CrdVisitor;

        impl<'de> Visitor<'de> for CrdVisitor {
            type Value = Crd;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CRD manifest with apiVersion/kind/metadata/spec")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Crd, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut api_version: Option<String> = None;
                let mut kind: Option<String> = None;
                let mut metadata: Option<Metadata> = None;
                let mut spec: Option<BTreeMap<String, Value>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ApiVersion => {
                            if api_version.is_some() {
                                return Err(de::Error::duplicate_field("apiVersion"));
                            }
                            api_version = Some(map.next_value()?);
                        }
                        Field::Kind => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            kind = Some(map.next_value()?);
                        }
                        Field::Metadata => {
                            if metadata.is_some() {
                                return Err(de::Error::duplicate_field("metadata"));
                            }
                            metadata = Some(map.next_value()?);
                        }
                        Field::Spec => {
                            if spec.is_some() {
                                return Err(de::Error::duplicate_field("spec"));
                            }
                            spec = Some(map.next_value()?);
                        }
                    }
                }
                Ok(Crd {
                    api_version: api_version
                        .ok_or_else(|| de::Error::missing_field("apiVersion"))?,
                    kind: kind.ok_or_else(|| de::Error::missing_field("kind"))?,
                    metadata: metadata.ok_or_else(|| de::Error::missing_field("metadata"))?,
                    spec: spec.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(CrdVisitor)
    }
}

/// Why a manifest document failed to (de)serialize.
#[derive(Debug)]
pub enum ManifestFormatError {
    /// The YAML text was not a valid CRD manifest.
    Yaml(serde_yaml::Error),
    /// The JSON text was not a valid CRD manifest.
    Json(serde_json::Error),
}

impl fmt::Display for ManifestFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestFormatError::Yaml(e) => write!(f, "manifest YAML error: {e}"),
            ManifestFormatError::Json(e) => write!(f, "manifest JSON error: {e}"),
        }
    }
}

impl std::error::Error for ManifestFormatError {}

impl Crd {
    /// Serialize this CRD body to a canonical YAML manifest document — the
    /// plain CRD shape an operator authors and `pillar apply -f` reads.
    ///
    /// # Errors
    /// [`ManifestFormatError::Yaml`] if the serializer fails (should not occur
    /// for an in-memory CRD).
    pub fn to_yaml(&self) -> Result<String, ManifestFormatError> {
        serde_yaml::to_string(self).map_err(ManifestFormatError::Yaml)
    }

    /// Deserialize a CRD body from a YAML manifest document.
    ///
    /// # Errors
    /// [`ManifestFormatError::Yaml`] if the text is not a well-formed CRD.
    pub fn from_yaml(text: &str) -> Result<Crd, ManifestFormatError> {
        serde_yaml::from_str(text).map_err(ManifestFormatError::Yaml)
    }

    /// Serialize this CRD body to a canonical JSON manifest document.
    ///
    /// # Errors
    /// [`ManifestFormatError::Json`] if the serializer fails.
    pub fn to_json(&self) -> Result<String, ManifestFormatError> {
        serde_json::to_string_pretty(self).map_err(ManifestFormatError::Json)
    }

    /// Deserialize a CRD body from a JSON manifest document.
    ///
    /// # Errors
    /// [`ManifestFormatError::Json`] if the text is not a well-formed CRD.
    pub fn from_json(text: &str) -> Result<Crd, ManifestFormatError> {
        serde_json::from_str(text).map_err(ManifestFormatError::Json)
    }
}
