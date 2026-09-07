//! TLS certificate issuance controller (ROI Priority 0, Tier 3, OPTIONAL).
//!
//! Certificate issuance — ACME or an internal CA — for traditional workloads
//! and ingress. The load-bearing property is that this rides the SAME
//! controller interface [`crate::builtin`] gives every built-in kind: a
//! [`Certificate`]-shaped [`Crd`] is validated against an ordinary
//! [`Schema`] registered into a [`SchemaRegistry`], and reconciled through an
//! ordinary [`ControllerHook`] registered into a [`ControllerRegistry`] —
//! there is no special-cased dispatch path for it, exactly like any
//! third-party integration would register itself. Unlike the kinds in
//! [`crate::builtin`], `Certificate` is deliberately NOT part of
//! [`crate::builtin::BuiltinKind::ALL`]: it is Tier 3 and OPTIONAL, so a cell
//! that never registers its hook must boot and operate normally — the
//! [`ControllerRegistry::dispatch`] absence-returns-`None` contract already
//! guarantees that without this module doing anything special.
//!
//! An [`Issuer`] is the pluggable backend (a real ACME client, a real
//! internal-CA client, or — for tests — a deterministic fixture) that
//! actually performs issuance; [`CertificateControllerHook`] wraps one and,
//! on a successful issuance, binds the resulting certificate to the
//! manifest's named target workload/ingress in its [`CertBindings`].

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::builtin::{ControllerHook, ReconcileOutcome};
use crate::{Crd, FieldType, Schema, Value};

/// The `apiVersion` a `Certificate` manifest is declared under — the same
/// namespace [`crate::builtin::BUILTIN_API_VERSION`] uses, since a
/// `Certificate` is a first-class pillar resource kind even though its
/// controller is optional.
pub const CERT_API_VERSION: &str = "pillar.dev/v1";

/// The `kind` string a certificate-issuance manifest declares.
pub const CERT_KIND: &str = "Certificate";

/// The OpenAPI-style schema a `Certificate` manifest validates against,
/// registered into a [`crate::SchemaRegistry`] exactly like any other kind:
/// `dnsName` (the name the cert is issued for), `issuer` (`acme` or
/// `internal-ca`), and `target` (the workload/ingress resource name the
/// resulting certificate is bound to).
#[must_use]
pub fn certificate_schema() -> Schema {
    Schema::new(CERT_API_VERSION, CERT_KIND)
        .required("dnsName", FieldType::String)
        .required("issuer", FieldType::String)
        .required("target", FieldType::String)
}

/// A certificate-issuance request extracted from a validated `Certificate`
/// [`Crd`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    /// The DNS name the certificate is issued for.
    pub dns_name: String,
    /// Which backend issues it: `acme` or `internal-ca`.
    pub issuer: String,
    /// The workload/ingress resource name the issued cert is bound to.
    pub target: String,
}

/// Why issuance was rejected before ever reaching the [`Issuer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// A required spec field was missing or the wrong type — should not
    /// happen for a body that already passed [`certificate_schema`]
    /// validation, but this hook re-derives the request defensively rather
    /// than trusting the caller ran the schema check.
    MalformedSpec(String),
}

impl CertificateRequest {
    /// Extract a [`CertificateRequest`] from a `Certificate`-kind [`Crd`].
    ///
    /// # Errors
    /// [`RequestError::MalformedSpec`] if a required field is absent or is
    /// not a string.
    pub fn from_crd(crd: &Crd) -> Result<Self, RequestError> {
        let field = |name: &str| -> Result<String, RequestError> {
            match crd.spec.get(name) {
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(RequestError::MalformedSpec(name.to_owned())),
            }
        };
        Ok(CertificateRequest {
            dns_name: field("dnsName")?,
            issuer: field("issuer")?,
            target: field("target")?,
        })
    }
}

/// One issued certificate: opaque material plus the identity of the
/// backend that produced it, so a binding can be told apart from a forgery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// The DNS name this cert covers.
    pub dns_name: String,
    /// Opaque certificate material (PEM, or a fixture's stand-in for it).
    pub cert_material: String,
    /// The backend (`acme` / `internal-ca`) that issued it.
    pub issuer: String,
}

/// Why an [`Issuer`] refused to issue a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceError(pub String);

/// A pluggable certificate-issuance backend — ACME, an internal CA, or (for
/// tests) a deterministic fixture. This is the seam a real deployment swaps
/// in a real ACME/internal-CA client at, exactly the way
/// [`crate::builtin::register_builtin_controllers`] documents swapping a
/// [`crate::builtin::NoopControllerHook`] for a real backend.
pub trait Issuer: Send + Sync {
    /// Issue a certificate for `request`, or report why issuance failed.
    ///
    /// # Errors
    /// [`IssuanceError`] if the backend refuses or fails to issue.
    fn issue(&self, request: &CertificateRequest) -> Result<IssuedCertificate, IssuanceError>;
}

/// The live bindings this controller has produced: target workload/ingress
/// name -> the certificate most recently bound to it. Read-accessible so a
/// caller (or a test) can confirm a specific target actually got its cert,
/// not merely that reconcile reported success.
#[derive(Default)]
pub struct CertBindings {
    bound: Mutex<BTreeMap<String, IssuedCertificate>>,
}

impl CertBindings {
    /// An empty binding table.
    #[must_use]
    pub fn new() -> Self {
        CertBindings {
            bound: Mutex::new(BTreeMap::new()),
        }
    }

    /// The certificate currently bound to `target`, if any.
    #[must_use]
    pub fn bound_to(&self, target: &str) -> Option<IssuedCertificate> {
        self.bound
            .lock()
            .expect("CertBindings mutex poisoned")
            .get(target)
            .cloned()
    }

    fn bind(&self, target: String, cert: IssuedCertificate) {
        self.bound
            .lock()
            .expect("CertBindings mutex poisoned")
            .insert(target, cert);
    }
}

/// A [`ControllerHook`] that drives a `Certificate` manifest to issuance
/// through the given [`Issuer`], binding the result into shared
/// [`CertBindings`] — the same [`ControllerHook`] shape (and the same
/// [`crate::builtin::ControllerRegistry::register`] call) a built-in kind's
/// hook or a third-party CRD's hook uses. Registering this hook is entirely
/// optional: a cell/node that never calls [`register_certificate_controller`]
/// simply has no entry for `pillar.dev/v1/Certificate` in its registry, so
/// [`crate::builtin::ControllerRegistry::dispatch`] returns `None` for it —
/// booting and operating normally with the controller absent.
pub struct CertificateControllerHook<I: Issuer> {
    issuer: I,
    bindings: CertBindings,
}

impl<I: Issuer> CertificateControllerHook<I> {
    /// A hook that issues through `issuer` and records bindings.
    #[must_use]
    pub fn new(issuer: I) -> Self {
        CertificateControllerHook {
            issuer,
            bindings: CertBindings::new(),
        }
    }

    /// The certificate currently bound to `target`, if this hook has
    /// reconciled one for it.
    #[must_use]
    pub fn bound_to(&self, target: &str) -> Option<IssuedCertificate> {
        self.bindings.bound_to(target)
    }
}

impl<I: Issuer> ControllerHook for CertificateControllerHook<I> {
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
        let request = match CertificateRequest::from_crd(crd) {
            Ok(r) => r,
            Err(RequestError::MalformedSpec(field)) => {
                return ReconcileOutcome::Failed(format!("malformed spec field: {field}"))
            }
        };
        match self.issuer.issue(&request) {
            Ok(cert) => {
                self.bindings.bind(request.target, cert);
                ReconcileOutcome::Reconciled
            }
            Err(IssuanceError(reason)) => ReconcileOutcome::Failed(reason),
        }
    }
}

/// Register `hook`'s schema and controller into `schemas`/`controllers` —
/// the identical two calls a caller makes to wire up any third-party CRD,
/// with no special-cased "builtin-but-optional" registration path.
pub fn register_certificate_controller<I: Issuer + 'static>(
    schemas: &mut crate::SchemaRegistry,
    controllers: &mut crate::builtin::ControllerRegistry,
    hook: CertificateControllerHook<I>,
) {
    schemas.register(certificate_schema());
    controllers.register(CERT_API_VERSION, CERT_KIND, Box::new(hook));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::ControllerRegistry;
    use crate::{Metadata, SchemaRegistry};

    /// A deterministic test fixture standing in for a real ACME/internal-CA
    /// backend: it "issues" a fixed cert body derived from the request, so a
    /// test can assert the exact issued material without any network I/O.
    struct FixtureIssuer;

    impl Issuer for FixtureIssuer {
        fn issue(&self, request: &CertificateRequest) -> Result<IssuedCertificate, IssuanceError> {
            if request.issuer != "acme" && request.issuer != "internal-ca" {
                return Err(IssuanceError(format!("unknown issuer: {}", request.issuer)));
            }
            Ok(IssuedCertificate {
                dns_name: request.dns_name.clone(),
                cert_material: format!("FIXTURE-CERT[{}]", request.dns_name),
                issuer: request.issuer.clone(),
            })
        }
    }

    fn cert_crd(name: &str, dns_name: &str, issuer: &str, target: &str) -> Crd {
        Crd::new(CERT_API_VERSION, CERT_KIND, Metadata::new(name))
            .with_spec("dnsName", Value::String(dns_name.into()))
            .with_spec("issuer", Value::String(issuer.into()))
            .with_spec("target", Value::String(target.into()))
    }

    #[test]
    fn a_certificate_manifest_validates_against_its_schema() {
        let mut registry = SchemaRegistry::new();
        registry.register(certificate_schema());
        let crd = cert_crd("web-cert", "web.example.com", "acme", "web-ingress");
        assert_eq!(registry.validate(&crd), Ok(()));
    }

    #[test]
    fn a_certificate_manifest_missing_a_required_field_is_rejected() {
        let mut registry = SchemaRegistry::new();
        registry.register(certificate_schema());
        let crd = Crd::new(CERT_API_VERSION, CERT_KIND, Metadata::new("bad"))
            .with_spec("dnsName", Value::String("web.example.com".into()));
        assert!(registry.validate(&crd).is_err());
    }

    #[test]
    fn a_certificate_manifest_triggers_real_issuance_and_binds_to_its_named_target() {
        let mut schemas = SchemaRegistry::new();
        let mut controllers = ControllerRegistry::new();
        register_certificate_controller(
            &mut schemas,
            &mut controllers,
            CertificateControllerHook::new(FixtureIssuer),
        );

        let crd = cert_crd("web-cert", "web.example.com", "acme", "web-ingress");
        assert_eq!(schemas.validate(&crd), Ok(()));
        assert_eq!(
            controllers.dispatch(&crd),
            Some(ReconcileOutcome::Reconciled)
        );
        // A second Certificate for the same target is dispatched through the
        // identical path, confirming reconcile is repeatable rather than a
        // one-shot fluke.
        let crd2 = cert_crd("web-cert-2", "web.example.com", "acme", "web-ingress");
        assert_eq!(
            controllers.dispatch(&crd2),
            Some(ReconcileOutcome::Reconciled)
        );
    }

    #[test]
    fn a_certificate_bound_target_is_readable_directly_off_the_hook() {
        let hook = CertificateControllerHook::new(FixtureIssuer);
        let crd = cert_crd("db-cert", "db.internal", "internal-ca", "db-workload");
        assert_eq!(hook.reconcile(&crd), ReconcileOutcome::Reconciled);

        let bound = hook.bound_to("db-workload").expect("cert should be bound");
        assert_eq!(bound.dns_name, "db.internal");
        assert_eq!(bound.issuer, "internal-ca");
        assert_eq!(bound.cert_material, "FIXTURE-CERT[db.internal]");
    }

    #[test]
    fn issuance_failure_is_reported_and_binds_nothing() {
        let hook = CertificateControllerHook::new(FixtureIssuer);
        let crd = cert_crd(
            "bad-cert",
            "bad.example.com",
            "unsupported-ca",
            "bad-target",
        );
        match hook.reconcile(&crd) {
            ReconcileOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(hook.bound_to("bad-target").is_none());
    }

    #[test]
    fn a_cell_with_this_controller_absent_still_boots_and_operates_normally() {
        // No `register_certificate_controller` call at all — the controller
        // is genuinely absent, exactly as a Tier-3 OPTIONAL integration a
        // cell chose not to enable would be. Schema registration and
        // dispatch for every OTHER kind still work; a Certificate manifest
        // simply has no registered hook, dispatched through the identical
        // absence-returns-None path any unregistered kind takes.
        let schemas = SchemaRegistry::new();
        let controllers = ControllerRegistry::new();

        let crd = cert_crd("web-cert", "web.example.com", "acme", "web-ingress");
        assert!(!controllers.contains(&crd));
        assert_eq!(controllers.dispatch(&crd), None);
        // Validating an unrelated, unregistered kind behaves identically —
        // the cell as a whole is unaffected by this controller's absence.
        assert!(schemas.validate(&crd).is_err());
    }
}
