//! DNS-based service-discovery + routing controller for TRADITIONAL
//! workloads (ROI Priority 0, Tier 3, OPTIONAL).
//!
//! Legacy web services expect the Kubernetes-`Service` shape: a stable DNS
//! name that resolves to a set of backing workload endpoints, fronted by an
//! L4-L7 load balancer. This module gives them exactly that WITHOUT inventing
//! a parallel networking stack: a [`Service`]-shaped [`Crd`] is validated
//! against an ordinary [`Schema`] and reconciled through an ordinary
//! [`ControllerHook`], and the reconcile wires the service's endpoints
//! straight into the EXISTING pillar LB substrate — a [`crate::ingress::Route`]
//! attaching to a [`crate::ingress::Frontend`], selected by a
//! [`crate::ingress::LoadBalancerPolicy`]. There is no bespoke routing path:
//! DNS resolution reads the SAME derived [`crate::ingress::RoutingTable`] the
//! ingress module already derives, so a Service is just a DNS-fronted view of
//! an ingress Route.
//!
//! The load-bearing OPTIONAL property matches [`crate::tls_cert`]: `Service`
//! is deliberately NOT part of [`crate::builtin::BuiltinKind::ALL`]; it rides
//! the third-party controller interface exactly as an external integration
//! would. A cell/node that never calls [`register_service_route_controller`]
//! has no hook for `pillar.dev/v1/Service`, so
//! [`crate::builtin::ControllerRegistry::dispatch`] returns `None` for it and
//! the cell boots and operates normally with the controller absent — this is
//! NEVER a setup/bootstrap dependency.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::builtin::{ControllerHook, ReconcileOutcome};
use crate::ingress::{
    derive_routing_table, Backend, Frontend, Route, RouteKind, RouteStatus, RoutingTable,
};
use crate::{Crd, FieldType, Schema, Value};

use pillar_core::NodeId;
use pillar_trust_artifacts::TrustStore;

/// The `apiVersion` a `Service` manifest is declared under — the shared
/// pillar resource namespace, since a `Service` is a first-class pillar
/// resource kind even though its controller is optional.
pub const SERVICE_API_VERSION: &str = "pillar.dev/v1";

/// The `kind` string a DNS service-route manifest declares.
pub const SERVICE_KIND: &str = "Service";

/// The OpenAPI-style schema a `Service` manifest validates against,
/// registered into a [`crate::SchemaRegistry`] exactly like any other kind:
///
/// - `dnsName` — the DNS name legacy clients resolve to reach the service;
/// - `frontend` — the name of the existing [`Frontend`] this service fronts;
/// - `app` — the identity of the app owning the service (must hold a live
///   `route:attach` grant over `frontend` — reusing the ingress module's
///   WoT/attestation gate verbatim);
/// - `port` — the L4 port the service listens on;
/// - `endpoints` — a comma-separated list of backing workload endpoint ids
///   that DNS resolves to, wired as ingress [`Backend`]s.
#[must_use]
pub fn service_schema() -> Schema {
    Schema::new(SERVICE_API_VERSION, SERVICE_KIND)
        .required("dnsName", FieldType::String)
        .required("frontend", FieldType::String)
        .required("app", FieldType::String)
        .required("port", FieldType::Integer)
        .required("endpoints", FieldType::String)
}

/// A service-route request extracted from a validated `Service` [`Crd`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRequest {
    /// The service resource name (from `metadata.name`).
    pub name: String,
    /// The DNS name clients resolve to reach the service.
    pub dns_name: String,
    /// The existing [`Frontend`] this service fronts.
    pub frontend: String,
    /// The app identity attaching the service's Route.
    pub app: String,
    /// The L4 port the service listens on.
    pub port: u16,
    /// The backing workload endpoint ids DNS resolves to.
    pub endpoints: Vec<String>,
}

/// Why a `Service` body could not be turned into a [`ServiceRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// A required spec field was absent or the wrong type. Should not happen
    /// for a body that already passed [`service_schema`] validation, but the
    /// request is re-derived defensively rather than trusting the caller.
    MalformedSpec(String),
    /// `port` was outside the valid u16 range.
    PortOutOfRange(i64),
    /// `endpoints` was empty — a service with no backends resolves to
    /// nothing, which is a malformed request rather than a valid one.
    NoEndpoints,
}

impl ServiceRequest {
    /// Extract a [`ServiceRequest`] from a `Service`-kind [`Crd`].
    ///
    /// # Errors
    /// [`RequestError`] if a required field is absent/mistyped, `port` does
    /// not fit a u16, or `endpoints` is empty.
    pub fn from_crd(crd: &Crd) -> Result<Self, RequestError> {
        let string = |name: &str| -> Result<String, RequestError> {
            match crd.spec.get(name) {
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(RequestError::MalformedSpec(name.to_owned())),
            }
        };
        let port_raw = match crd.spec.get("port") {
            Some(Value::Integer(i)) => *i,
            _ => return Err(RequestError::MalformedSpec("port".to_owned())),
        };
        let port =
            u16::try_from(port_raw).map_err(|_| RequestError::PortOutOfRange(port_raw))?;
        let endpoints: Vec<String> = string("endpoints")?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if endpoints.is_empty() {
            return Err(RequestError::NoEndpoints);
        }
        Ok(ServiceRequest {
            name: crd.metadata.name.clone(),
            dns_name: string("dnsName")?,
            frontend: string("frontend")?,
            app: string("app")?,
            port,
            endpoints,
        })
    }

    /// Project this request into the ingress [`Route`] the LB substrate
    /// routes through — the app attaches to the named Frontend as a plain
    /// TCP route selecting the service's endpoints as [`Backend`]s. This is
    /// the SAME `Route` type the ingress module derives its routing table
    /// from: a Service does not fork the routing model, it feeds it.
    #[must_use]
    pub fn to_route(&self) -> Route {
        let mut route = Route::new(
            self.name.clone(),
            NodeId::from(self.app.as_str()),
            self.frontend.clone(),
            RouteKind::Tcp,
        );
        for ep in &self.endpoints {
            route = route.with_backend(Backend::new(ep.clone()));
        }
        route
    }
}

/// One resolved service-discovery record: the DNS name a legacy client
/// resolves and the backing workload endpoints it resolves to — computed
/// ONLY when the underlying ingress Route is [`RouteStatus::Attached`], so a
/// refused or dangling route resolves to nothing (no traffic to an
/// unauthorized or non-existent frontend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResolution {
    /// The DNS name resolved.
    pub dns_name: String,
    /// The L4 port clients connect to.
    pub port: u16,
    /// The backing workload endpoints, in declaration order — the answer a
    /// DNS query for `dns_name` returns.
    pub endpoints: Vec<String>,
}

/// The live DNS records this controller has reconciled: dns name -> the
/// resolution wired through the ingress substrate. Read-accessible so a
/// caller (or a test) can confirm a specific service actually resolves to the
/// correct backends, not merely that reconcile reported success.
#[derive(Default)]
pub struct DnsRegistry {
    records: Mutex<BTreeMap<String, ServiceResolution>>,
}

impl DnsRegistry {
    /// An empty DNS registry.
    #[must_use]
    pub fn new() -> Self {
        DnsRegistry {
            records: Mutex::new(BTreeMap::new()),
        }
    }

    /// Resolve `dns_name` to its backing endpoints, if a service with that
    /// name is currently reconciled and attached.
    #[must_use]
    pub fn resolve(&self, dns_name: &str) -> Option<ServiceResolution> {
        self.records
            .lock()
            .expect("DnsRegistry mutex poisoned")
            .get(dns_name)
            .cloned()
    }

    fn publish(&self, resolution: ServiceResolution) {
        self.records
            .lock()
            .expect("DnsRegistry mutex poisoned")
            .insert(resolution.dns_name.clone(), resolution);
    }

    fn withdraw(&self, dns_name: &str) {
        self.records
            .lock()
            .expect("DnsRegistry mutex poisoned")
            .remove(dns_name);
    }
}

/// The infrastructure a [`ServiceRouteControllerHook`] resolves against: the
/// existing set of ingress [`Frontend`]s and the [`TrustStore`] whose live
/// `route:attach` attests authorize a service's Route. Both are the SAME
/// substrate the ingress module already uses — the controller does not own a
/// parallel copy.
pub trait ServiceSubstrate: Send + Sync {
    /// The ingress Frontends currently defined.
    fn frontends(&self) -> Vec<Frontend>;
    /// The trust store whose live attests gate route attachment.
    fn trust_store(&self) -> &TrustStore;
}

/// A [`ControllerHook`] that drives a `Service` manifest into a DNS record by
/// wiring it through the existing ingress LB substrate: it projects the
/// service into an ingress [`Route`], DERIVES the routing table over the
/// substrate's Frontends + trust store (reusing [`derive_routing_table`]
/// verbatim), and publishes a resolvable DNS record ONLY when that derivation
/// says the Route is [`RouteStatus::Attached`]. An unauthorized or dangling
/// service is reconciled as a failure and resolves to nothing.
///
/// Registering this hook is entirely optional (see the module docs): a cell
/// that never calls [`register_service_route_controller`] simply has no entry
/// for `pillar.dev/v1/Service`.
pub struct ServiceRouteControllerHook<S: ServiceSubstrate> {
    substrate: S,
    dns: DnsRegistry,
}

impl<S: ServiceSubstrate> ServiceRouteControllerHook<S> {
    /// A hook resolving services against `substrate`.
    #[must_use]
    pub fn new(substrate: S) -> Self {
        ServiceRouteControllerHook {
            substrate,
            dns: DnsRegistry::new(),
        }
    }

    /// Resolve `dns_name` to its backing endpoints, if this hook has
    /// reconciled an attached service for it.
    #[must_use]
    pub fn resolve(&self, dns_name: &str) -> Option<ServiceResolution> {
        self.dns.resolve(dns_name)
    }

    /// Derive the routing table for `request`'s Route over the current
    /// substrate — the SAME derivation the ingress module performs.
    fn derive(&self, route: &Route) -> RoutingTable {
        let frontends = self.substrate.frontends();
        derive_routing_table(
            &frontends,
            std::slice::from_ref(route),
            self.substrate.trust_store(),
        )
    }
}

impl<S: ServiceSubstrate> ControllerHook for ServiceRouteControllerHook<S> {
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
        let request = match ServiceRequest::from_crd(crd) {
            Ok(r) => r,
            Err(e) => return ReconcileOutcome::Failed(format!("malformed Service: {e:?}")),
        };
        let route = request.to_route();
        let table = self.derive(&route);
        match table.status_of(&request.name) {
            Some(RouteStatus::Attached) => {
                self.dns.publish(ServiceResolution {
                    dns_name: request.dns_name.clone(),
                    port: request.port,
                    endpoints: request.endpoints.clone(),
                });
                ReconcileOutcome::Reconciled
            }
            Some(RouteStatus::Refused) => ReconcileOutcome::Failed(format!(
                "service {} refused: app holds no route:attach grant over frontend {}",
                request.name, request.frontend
            )),
            Some(RouteStatus::NoSuchFrontend) => ReconcileOutcome::Failed(format!(
                "service {} targets non-existent frontend {}",
                request.name, request.frontend
            )),
            None => ReconcileOutcome::Failed(format!(
                "service {} produced no routing-table entry",
                request.name
            )),
        }
    }

    fn delete(&self, crd: &Crd) -> ReconcileOutcome {
        match ServiceRequest::from_crd(crd) {
            Ok(request) => {
                self.dns.withdraw(&request.dns_name);
                ReconcileOutcome::Reconciled
            }
            Err(e) => ReconcileOutcome::Failed(format!("malformed Service on prune: {e:?}")),
        }
    }
}

/// Register `hook`'s schema and controller into `schemas`/`controllers` —
/// the identical two calls a caller makes to wire up any third-party CRD,
/// with no special-cased "builtin-but-optional" registration path.
pub fn register_service_route_controller<S: ServiceSubstrate + 'static>(
    schemas: &mut crate::SchemaRegistry,
    controllers: &mut crate::builtin::ControllerRegistry,
    hook: ServiceRouteControllerHook<S>,
) {
    schemas.register(service_schema());
    controllers.register(SERVICE_API_VERSION, SERVICE_KIND, Box::new(hook));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::ControllerRegistry;
    use crate::{Metadata, SchemaRegistry};
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    /// Grant `app` a live `route:attach` over `frontend`, exactly as the
    /// ingress module's own tests do — proving the service controller reuses
    /// the SAME WoT/attestation gate rather than a parallel one.
    fn grant_attach(store: &mut TrustStore, genesis: &NodeId, app: &NodeId, frontend: &str) {
        let attest = Attest {
            issuer: genesis.clone(),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: app.clone(),
            predicate: Predicate::new(crate::ingress::ATTACH_ACTION, frontend),
            scope: "default".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        store.issue_attest(attest).expect("grant issues");
    }

    /// A fixed substrate standing in for the live ingress state: a known set
    /// of Frontends and a trust store, wired so a test can assert exactly
    /// which services resolve.
    struct FixtureSubstrate {
        frontends: Vec<Frontend>,
        store: TrustStore,
    }

    impl ServiceSubstrate for FixtureSubstrate {
        fn frontends(&self) -> Vec<Frontend> {
            self.frontends.clone()
        }
        fn trust_store(&self) -> &TrustStore {
            &self.store
        }
    }

    fn service_crd(
        name: &str,
        dns_name: &str,
        frontend: &str,
        app: &str,
        port: i64,
        endpoints: &str,
    ) -> Crd {
        Crd::new(SERVICE_API_VERSION, SERVICE_KIND, Metadata::new(name))
            .with_spec("dnsName", Value::String(dns_name.into()))
            .with_spec("frontend", Value::String(frontend.into()))
            .with_spec("app", Value::String(app.into()))
            .with_spec("port", Value::Integer(port))
            .with_spec("endpoints", Value::String(endpoints.into()))
    }

    #[test]
    fn a_service_manifest_validates_against_its_schema() {
        let mut registry = SchemaRegistry::new();
        registry.register(service_schema());
        let crd = service_crd(
            "web",
            "web.svc.example.com",
            "edge",
            "app-a",
            8080,
            "ep-1,ep-2",
        );
        assert_eq!(registry.validate(&crd), Ok(()));
    }

    #[test]
    fn a_service_manifest_missing_a_required_field_is_rejected() {
        let mut registry = SchemaRegistry::new();
        registry.register(service_schema());
        let crd = Crd::new(SERVICE_API_VERSION, SERVICE_KIND, Metadata::new("bad"))
            .with_spec("dnsName", Value::String("web.svc.example.com".into()));
        assert!(registry.validate(&crd).is_err());
    }

    #[test]
    fn a_service_manifest_resolves_via_dns_to_its_backing_workload_endpoints() {
        // The load-bearing test: a Service-shaped manifest resolves via DNS
        // to the correct backing workload endpoints, wired through the
        // existing LB substrate (an authorized ingress Route over a real
        // Frontend).
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "edge");
        let substrate = FixtureSubstrate {
            frontends: vec![Frontend::new("edge", "10.0.0.1")],
            store,
        };

        let mut schemas = SchemaRegistry::new();
        let mut controllers = ControllerRegistry::new();
        register_service_route_controller(
            &mut schemas,
            &mut controllers,
            ServiceRouteControllerHook::new(substrate),
        );

        let crd = service_crd(
            "web",
            "web.svc.example.com",
            "edge",
            "app-a",
            8080,
            "ep-1,ep-2,ep-3",
        );
        assert_eq!(schemas.validate(&crd), Ok(()));
        assert_eq!(
            controllers.dispatch(&crd),
            Some(ReconcileOutcome::Reconciled)
        );
    }

    #[test]
    fn resolution_returns_the_endpoints_in_order_off_the_hook() {
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "edge");
        let hook = ServiceRouteControllerHook::new(FixtureSubstrate {
            frontends: vec![Frontend::new("edge", "10.0.0.1")],
            store,
        });

        let crd = service_crd(
            "web",
            "web.svc.example.com",
            "edge",
            "app-a",
            8080,
            "ep-1,ep-2,ep-3",
        );
        assert_eq!(hook.reconcile(&crd), ReconcileOutcome::Reconciled);

        let res = hook
            .resolve("web.svc.example.com")
            .expect("service should resolve");
        assert_eq!(res.port, 8080);
        assert_eq!(res.endpoints, vec!["ep-1", "ep-2", "ep-3"]);
        // An unknown name resolves to nothing.
        assert!(hook.resolve("nope.example.com").is_none());
    }

    #[test]
    fn an_unauthorized_service_is_refused_and_resolves_to_nothing() {
        // No grant issued: the underlying ingress Route is Refused, so the
        // service reconcile fails and no DNS record is published — the SAME
        // WoT gate the ingress module enforces, reused verbatim.
        let genesis = n("genesis");
        let store = TrustStore::new(genesis);
        let hook = ServiceRouteControllerHook::new(FixtureSubstrate {
            frontends: vec![Frontend::new("edge", "10.0.0.1")],
            store,
        });

        let crd = service_crd("web", "web.svc.example.com", "edge", "app-a", 8080, "ep-1");
        match hook.reconcile(&crd) {
            ReconcileOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(hook.resolve("web.svc.example.com").is_none());
    }

    #[test]
    fn a_service_targeting_a_missing_frontend_is_refused() {
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "ghost");
        let hook = ServiceRouteControllerHook::new(FixtureSubstrate {
            frontends: vec![], // no frontend named "ghost"
            store,
        });

        let crd = service_crd("web", "web.svc.example.com", "ghost", "app-a", 8080, "ep-1");
        match hook.reconcile(&crd) {
            ReconcileOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(hook.resolve("web.svc.example.com").is_none());
    }

    #[test]
    fn a_service_with_no_endpoints_is_malformed() {
        let hook = ServiceRouteControllerHook::new(FixtureSubstrate {
            frontends: vec![Frontend::new("edge", "10.0.0.1")],
            store: TrustStore::new(n("genesis")),
        });
        let crd = service_crd("web", "web.svc.example.com", "edge", "app-a", 8080, "  ,  ");
        match hook.reconcile(&crd) {
            ReconcileOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn pruning_a_service_withdraws_its_dns_record() {
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "edge");
        let hook = ServiceRouteControllerHook::new(FixtureSubstrate {
            frontends: vec![Frontend::new("edge", "10.0.0.1")],
            store,
        });
        let crd = service_crd("web", "web.svc.example.com", "edge", "app-a", 8080, "ep-1");
        assert_eq!(hook.reconcile(&crd), ReconcileOutcome::Reconciled);
        assert!(hook.resolve("web.svc.example.com").is_some());
        assert_eq!(hook.delete(&crd), ReconcileOutcome::Reconciled);
        assert!(hook.resolve("web.svc.example.com").is_none());
    }

    #[test]
    fn a_cell_with_this_controller_absent_still_boots_and_operates_normally() {
        // No `register_service_route_controller` call at all — the controller
        // is genuinely absent, exactly as a Tier-3 OPTIONAL integration a
        // cell chose not to enable would be. A Service manifest simply has no
        // registered hook, dispatched through the identical
        // absence-returns-None path any unregistered kind takes; the cell as
        // a whole is unaffected. This is the property: no bootstrap-path
        // reference to this controller — nothing registers it implicitly.
        let schemas = SchemaRegistry::new();
        let controllers = ControllerRegistry::new();

        let crd = service_crd("web", "web.svc.example.com", "edge", "app-a", 8080, "ep-1");
        assert!(!controllers.contains(&crd));
        assert_eq!(controllers.dispatch(&crd), None);
        // Validating the unregistered kind behaves identically to any other
        // unregistered kind — the controller's absence changes nothing.
        assert!(schemas.validate(&crd).is_err());
    }
}
