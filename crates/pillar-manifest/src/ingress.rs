//! LB / ingress manifest model: infra-owned [`Frontend`] vs app-owned
//! [`Route`], a [`LoadBalancerPolicy`], and the DERIVED [`RoutingTable`].
//!
//! Applies the Gateway-API lessons the ROI calls out, without copying
//! Gateway-API's mistakes:
//!
//! - **`Frontend`** (infra-owned): VIP / listeners / protocols / TLS.
//! - **`Route`** (app-owned, protocol-typed): first-class for every
//!   [`RouteKind`] — HTTP, HTTP/3, TCP, UDP, QUIC, and pillar-native are all
//!   equally first-class; none is a second-class citizen bolted on via a
//!   stringly-typed annotation. Every field is a typed schema field or a
//!   typed extension kind — never a free-form annotation string.
//! - **Attachment is WoT/attestation-gated.** A [`Route`] does not attach to
//!   a [`Frontend`] merely by naming it: the attaching app must hold a live,
//!   chain-verified [`pillar_trust_artifacts::Attest`] granting it the
//!   `route:attach` action over that Frontend's resource name. This reuses
//!   `pillar_trust_artifacts` verbatim (via [`TrustStore::graph_edges`]) —
//!   no parallel authorization path.
//! - **The routing table is DERIVED**, never independently authored:
//!   [`derive_routing_table`] projects a fixed set of Frontends/Routes plus
//!   the trust store's live attests into a [`RoutingTable`], and a route's
//!   [`RouteStatus`] is *computed* by that derivation — it is not a settable
//!   field on [`Route`] (there is no `Route::set_status`).
//! - **`LoadBalancerPolicy`** carries algorithm / affinity / locality
//!   (topology-tier aware, reusing [`pillar_topology`]) / health /
//!   consistency-class (reusing [`pillar_core::SideEffect`]'s
//!   idempotent-vs-exclusive reversibility classification: an
//!   [`pillar_core::SideEffect::Exclusive`] policy routes same-key requests
//!   to the same backend, never splitting them).

use std::collections::BTreeMap;

use pillar_core::{NodeId, SideEffect};
use pillar_topology::Topology;
use pillar_trust_artifacts::TrustStore;

/// The action string a Route-attach [`pillar_trust_artifacts::Attest`]
/// carries: `issuer` grants `subject` (the attaching app identity) the right
/// to attach a Route to the Frontend named by the predicate's `resource`.
pub const ATTACH_ACTION: &str = "route:attach";

/// A protocol-agnostic, first-class Route kind. No kind is second-class
/// relative to another: every variant round-trips through the identical
/// typed [`Route`]/[`Frontend`] schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteKind {
    /// Plain HTTP/1.1 or HTTP/2.
    Http,
    /// HTTP/3 over QUIC.
    Http3,
    /// Raw TCP.
    Tcp,
    /// Raw UDP.
    Udp,
    /// Raw QUIC (non-HTTP).
    Quic,
    /// The pillar-native transport (see `pillar_udp_transport`).
    PillarNative,
}

/// A typed TLS configuration for a [`Listener`] — never a free-form
/// annotation string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    /// The reference (e.g. a signer-key fingerprint or cert store key) to
    /// the certificate material. Opaque to this model; resolved elsewhere.
    pub cert_ref: String,
}

/// One typed listener on a [`Frontend`]: a port bound to a [`RouteKind`],
/// optionally terminating TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    /// The port this listener binds.
    pub port: u16,
    /// The protocol this listener speaks.
    pub protocol: RouteKind,
    /// TLS termination config, if this listener terminates TLS.
    pub tls: Option<TlsConfig>,
}

/// **`Frontend`** — infra-owned: a VIP plus its typed listeners. Created and
/// updated only by an infra-authorized principal (enforced by whatever
/// authorizes writes to the manifest store; out of scope here — this type
/// models the resource body, not that gate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontend {
    /// The Frontend's resource name — the exact string a Route-attach
    /// [`pillar_trust_artifacts::Predicate::resource`] must name.
    pub name: String,
    /// The virtual IP this Frontend fronts.
    pub vip: String,
    /// The typed listeners bound on this Frontend's VIP.
    pub listeners: Vec<Listener>,
}

impl Frontend {
    /// A Frontend with no listeners yet.
    #[must_use]
    pub fn new(name: impl Into<String>, vip: impl Into<String>) -> Self {
        Frontend {
            name: name.into(),
            vip: vip.into(),
            listeners: Vec::new(),
        }
    }

    /// Add a listener, builder-style.
    #[must_use]
    pub fn with_listener(mut self, listener: Listener) -> Self {
        self.listeners.push(listener);
        self
    }
}

/// One backend a [`Route`] may select, optionally placed in a topology zone
/// (reusing [`pillar_topology`]'s tier labels) for locality-aware LB.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Backend {
    /// The backend's identity/address (opaque to this model).
    pub id: String,
}

impl Backend {
    /// A backend identified by `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Backend { id: id.into() }
    }
}

/// **`Route`** — app-owned, protocol-typed: which [`Frontend`] it wants to
/// attach to, its [`RouteKind`], and the backends it selects among. The
/// attaching app's identity is carried so attachment authorization can be
/// checked against the trust store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// This Route's own name.
    pub name: String,
    /// The identity of the app attaching this Route (must hold a live
    /// `route:attach` grant over `frontend` to attach successfully).
    pub app: NodeId,
    /// The Frontend this Route wants to attach to (by name).
    pub frontend: String,
    /// The protocol this Route carries — first-class for every
    /// [`RouteKind`], never a second-class annotation.
    pub kind: RouteKind,
    /// The backends this Route selects among.
    pub backends: Vec<Backend>,
}

impl Route {
    /// A Route with no backends yet.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        app: impl Into<NodeId>,
        frontend: impl Into<String>,
        kind: RouteKind,
    ) -> Self {
        Route {
            name: name.into(),
            app: app.into(),
            frontend: frontend.into(),
            kind,
            backends: Vec::new(),
        }
    }

    /// Add a backend, builder-style.
    #[must_use]
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.backends.push(backend);
        self
    }
}

/// A Route's **status** — a computed VIEW, never an independently-settable
/// field. The only way to obtain one is [`derive_routing_table`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteStatus {
    /// The attaching app holds no live `route:attach` grant over the named
    /// Frontend: refused, absent from the routing table.
    Refused,
    /// The attach is authorized and the Frontend exists: the Route appears
    /// in the derived routing table.
    Attached,
    /// The attach is authorized but the named Frontend does not exist.
    NoSuchFrontend,
}

/// The LB algorithm a [`LoadBalancerPolicy`] selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Round-robin over backends.
    RoundRobin,
    /// Least-outstanding-connections.
    LeastConn,
    /// Consistent-hash over a request key.
    ConsistentHash,
}

/// Session affinity behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Affinity {
    /// No affinity: any backend may serve any request.
    None,
    /// Sticky affinity keyed by an opaque client key.
    Sticky,
}

/// Active/passive health-probe configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthCheck {
    /// Whether an active probe is enabled (vs passive-only, inferred from
    /// live traffic failures).
    pub active: bool,
    /// The probe interval in milliseconds.
    pub interval_ms: u32,
}

/// **`LoadBalancerPolicy`** — algorithm, affinity, topology-tier-aware
/// locality, health, and **consistency-class** (reusing
/// [`pillar_core::SideEffect`]'s idempotent-vs-exclusive reversibility
/// classification, never a parallel one): [`SideEffect::Exclusive`] means
/// backend selection for a given key is exclusive — the same key always
/// lands on the same backend, never split across two; [`SideEffect::Convergent`]
/// permits ordinary load-spread reselection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadBalancerPolicy {
    /// The LB algorithm.
    pub algorithm: Algorithm,
    /// Session affinity behaviour.
    pub affinity: Affinity,
    /// The topology tier locality-aware LB prefers to keep traffic within
    /// (e.g. `"zone"`) — `None` disables locality preference.
    pub locality_tier: Option<String>,
    /// Health-probe configuration.
    pub health: HealthCheck,
    /// The reversibility classification of this policy's backend selection.
    /// [`SideEffect::Exclusive`] pins a key to one backend permanently (an
    /// exclusive resource, e.g. a stateful session); [`SideEffect::Convergent`]
    /// allows ordinary reselection.
    pub consistency_class: SideEffect,
}

impl LoadBalancerPolicy {
    /// A convergent, round-robin, no-affinity, no-locality-preference
    /// default policy with active health checking every second.
    #[must_use]
    pub fn round_robin() -> Self {
        LoadBalancerPolicy {
            algorithm: Algorithm::RoundRobin,
            affinity: Affinity::None,
            locality_tier: None,
            health: HealthCheck {
                active: true,
                interval_ms: 1000,
            },
            consistency_class: SideEffect::Convergent,
        }
    }

    /// The same policy with `consistency_class` set to
    /// [`SideEffect::Exclusive`] (same-key requests always route to the
    /// same backend) and a consistent-hash algorithm, builder-style.
    #[must_use]
    pub fn exclusive(mut self) -> Self {
        self.consistency_class = SideEffect::Exclusive;
        self.algorithm = Algorithm::ConsistentHash;
        self
    }

    /// The same policy preferring backends in the given topology tier
    /// (e.g. `"zone"`), builder-style.
    #[must_use]
    pub fn prefer_locality(mut self, tier: impl Into<String>) -> Self {
        self.locality_tier = Some(tier.into());
        self
    }

    /// Select a backend for `key` among `candidates`, given each
    /// candidate's node identity for topology lookups and the client's own
    /// node identity (for locality preference).
    ///
    /// - [`SideEffect::Exclusive`]: a pure, deterministic hash of `key` picks
    ///   exactly one candidate — the SAME candidate every time for the same
    ///   `key` and the same candidate set (never split across two
    ///   backends).
    /// - [`SideEffect::Convergent`] with a locality tier set: prefer a
    ///   candidate whose placement at `locality_tier` matches the client's,
    ///   falling back to the first candidate if none match.
    /// - Otherwise: the first candidate (round-robin's single-call
    ///   projection).
    ///
    /// Returns `None` if `candidates` is empty.
    #[must_use]
    pub fn select<'a>(
        &self,
        key: &str,
        candidates: &'a [(NodeId, Backend)],
        client: &NodeId,
        topology: &Topology,
    ) -> Option<&'a Backend> {
        if candidates.is_empty() {
            return None;
        }
        if self.consistency_class == SideEffect::Exclusive {
            let idx = consistent_hash(key, candidates.len());
            return candidates.get(idx).map(|(_, b)| b);
        }
        if let Some(tier) = &self.locality_tier {
            let client_value = topology.placement(client).at(tier).map(str::to_owned);
            if let Some(client_value) = client_value {
                if let Some((_, b)) = candidates.iter().find(|(node, _)| {
                    topology.placement(node).at(tier) == Some(client_value.as_str())
                }) {
                    return Some(b);
                }
            }
        }
        candidates.first().map(|(_, b)| b)
    }
}

/// A deterministic, dependency-free hash of `key` into `[0, len)` — pure and
/// stable across calls, so the same `key` against the same candidate count
/// always yields the same index (the exclusive-consistency guarantee).
fn consistent_hash(key: &str, len: usize) -> usize {
    // non-security: LB hash, not a security primitive
    use std::collections::hash_map::DefaultHasher; // non-security: LB hash, not a security primitive
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new(); // non-security: LB hash, not a security primitive
    key.hash(&mut h);
    (h.finish() as usize) % len
}

/// One entry in the [`RoutingTable`]: a Route's computed [`RouteStatus`]
/// plus (when [`RouteStatus::Attached`]) the backends it selects among.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// The Route this entry derives from.
    pub route: String,
    /// The Frontend it targets.
    pub frontend: String,
    /// The computed status — never independently settable.
    pub status: RouteStatus,
}

/// The DERIVED routing table: a projection of Frontends + Routes + the trust
/// store's live attests. Never independently authored — the only
/// constructor is [`derive_routing_table`].
#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    entries: Vec<RouteEntry>,
}

impl RoutingTable {
    /// Every entry, in derivation order.
    #[must_use]
    pub fn entries(&self) -> &[RouteEntry] {
        &self.entries
    }

    /// The computed status of the named route, if it was part of the
    /// derivation.
    #[must_use]
    pub fn status_of(&self, route: &str) -> Option<&RouteStatus> {
        self.entries
            .iter()
            .find(|e| e.route == route)
            .map(|e| &e.status)
    }

    /// Whether the named route is attached (present with
    /// [`RouteStatus::Attached`]).
    #[must_use]
    pub fn is_attached(&self, route: &str) -> bool {
        matches!(self.status_of(route), Some(RouteStatus::Attached))
    }
}

/// Whether `app` holds a live, chain-verified `route:attach` grant over
/// `frontend` in `store` — the WoT/attestation gate a Route's attachment
/// must pass. Reuses [`TrustStore::graph_edges`] verbatim: no parallel
/// authorization path.
#[must_use]
pub fn is_attach_authorized(store: &TrustStore, app: &NodeId, frontend: &str) -> bool {
    let label_suffix = format!("{ATTACH_ACTION}({frontend})");
    store
        .graph_edges()
        .into_iter()
        .any(|e| &e.to == app && e.label.ends_with(&label_suffix))
}

/// **Derive** the [`RoutingTable`] from a fixed set of Frontends, Routes,
/// and the trust store's currently-live attests. This is the ONLY way a
/// [`RouteStatus`] comes into existence — status is a VIEW, never a field a
/// caller sets directly.
#[must_use]
pub fn derive_routing_table(
    frontends: &[Frontend],
    routes: &[Route],
    store: &TrustStore,
) -> RoutingTable {
    let by_name: BTreeMap<&str, &Frontend> =
        frontends.iter().map(|f| (f.name.as_str(), f)).collect();
    let entries = routes
        .iter()
        .map(|r| {
            let status = if !is_attach_authorized(store, &r.app, &r.frontend) {
                RouteStatus::Refused
            } else if !by_name.contains_key(r.frontend.as_str()) {
                RouteStatus::NoSuchFrontend
            } else {
                RouteStatus::Attached
            };
            RouteEntry {
                route: r.name.clone(),
                frontend: r.frontend.clone(),
                status,
            }
        })
        .collect();
    RoutingTable { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_topology::TierHierarchy;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn grant_attach(store: &mut TrustStore, genesis: &NodeId, app: &NodeId, frontend: &str) {
        let attest = Attest {
            issuer: genesis.clone(),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: app.clone(),
            predicate: Predicate::new(ATTACH_ACTION, frontend),
            scope: "default".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        store.issue_attest(attest).expect("grant issues");
    }

    #[test]
    fn unauthorized_route_attach_is_refused() {
        let genesis = n("genesis");
        let store = TrustStore::new(genesis);
        let frontend = Frontend::new("edge", "10.0.0.1");
        let route = Route::new("r1", n("app-a"), "edge", RouteKind::Http);
        let table = derive_routing_table(&[frontend], &[route], &store);
        assert_eq!(table.status_of("r1"), Some(&RouteStatus::Refused));
        assert!(!table.is_attached("r1"));
    }

    #[test]
    fn authorized_attach_appears_in_the_derived_routing_table() {
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "edge");

        let frontend = Frontend::new("edge", "10.0.0.1");
        let route = Route::new("r1", app, "edge", RouteKind::Http);
        let table = derive_routing_table(&[frontend], &[route], &store);
        assert_eq!(table.status_of("r1"), Some(&RouteStatus::Attached));
        assert!(table.is_attached("r1"));
    }

    #[test]
    fn authorized_attach_to_missing_frontend_is_reported() {
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "ghost");

        let route = Route::new("r1", app, "ghost", RouteKind::Http);
        let table = derive_routing_table(&[], &[route], &store);
        assert_eq!(table.status_of("r1"), Some(&RouteStatus::NoSuchFrontend));
    }

    #[test]
    fn each_route_kind_round_trips_through_the_same_typed_schema() {
        for kind in [
            RouteKind::Http,
            RouteKind::Http3,
            RouteKind::Tcp,
            RouteKind::Udp,
            RouteKind::Quic,
            RouteKind::PillarNative,
        ] {
            let route = Route::new("r", n("app"), "edge", kind)
                .with_backend(Backend::new("b1"))
                .with_backend(Backend::new("b2"));
            // Round-trips through the identical typed struct: no
            // annotation-string escape hatch, same fields for every kind.
            assert_eq!(route.kind, kind);
            assert_eq!(route.backends.len(), 2);
        }
    }

    #[test]
    fn status_is_computed_not_settable() {
        // Route carries no status field at all -- the only way to obtain a
        // RouteStatus is through derive_routing_table's projection. This
        // test documents/enforces that by construction: Route's public API
        // has no `status` field or setter (a compile-time property), and
        // the runtime status always matches the derivation's own decision.
        let genesis = n("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = n("app-a");
        grant_attach(&mut store, &genesis, &app, "edge");
        let frontend = Frontend::new("edge", "10.0.0.1");
        let route = Route::new("r1", app.clone(), "edge", RouteKind::Tcp);
        let table1 = derive_routing_table(
            std::slice::from_ref(&frontend),
            std::slice::from_ref(&route),
            &store,
        );
        assert_eq!(table1.status_of("r1"), Some(&RouteStatus::Attached));

        // Revoking the grant and re-deriving flips the computed status --
        // proving it is a live view over the trust store, not a cached
        // field on Route.
        let cid = store
            .graph_edges()
            .into_iter()
            .find(|e| e.to == app)
            .expect("edge present")
            .cid;
        store
            .revoke(&pillar_trust_artifacts::Revoke::signed(cid, genesis))
            .expect("revoke succeeds");
        let table2 = derive_routing_table(&[frontend], &[route], &store);
        assert_eq!(table2.status_of("r1"), Some(&RouteStatus::Refused));
    }

    #[test]
    fn exclusive_consistency_class_routes_same_key_to_the_same_backend() {
        let policy = LoadBalancerPolicy::round_robin().exclusive();
        let topology = Topology::new(TierHierarchy::default());
        let candidates = vec![
            (n("node-a"), Backend::new("b1")),
            (n("node-b"), Backend::new("b2")),
            (n("node-c"), Backend::new("b3")),
        ];
        let client = n("client-1");
        let first = policy
            .select("session-42", &candidates, &client, &topology)
            .cloned();
        for _ in 0..10 {
            let again = policy
                .select("session-42", &candidates, &client, &topology)
                .cloned();
            assert_eq!(first, again);
        }
        // A different key may (and typically will) land elsewhere, but the
        // SAME key is pinned every time -- the exclusive guarantee.
        assert!(first.is_some());
    }

    #[test]
    fn locality_aware_lb_prefers_a_same_zone_backend() {
        let mut topology = Topology::new(TierHierarchy::default());
        let client = n("client-1");
        let near = n("node-near");
        let far = n("node-far");
        topology.declare(client.clone(), &[pillar_topology::Label::new("zone", "z1")]);
        topology.declare(near.clone(), &[pillar_topology::Label::new("zone", "z1")]);
        topology.declare(far.clone(), &[pillar_topology::Label::new("zone", "z2")]);

        let policy = LoadBalancerPolicy::round_robin().prefer_locality("zone");
        // Put the far (wrong-zone) candidate FIRST so the naive "pick
        // first" fallback would get it wrong -- proves locality actually
        // steers the choice.
        let candidates = vec![
            (far, Backend::new("far-backend")),
            (near, Backend::new("near-backend")),
        ];
        let chosen = policy
            .select("req-1", &candidates, &client, &topology)
            .expect("a candidate is chosen");
        assert_eq!(chosen.id, "near-backend");
    }
}
