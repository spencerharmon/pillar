//! The extensible resource-type + controller model.
//!
//! Pillar reconciles *resources*: a declaration rides the streaming DB as a
//! content-addressed op payload, and a controller on the target peer turns that
//! declaration into a running resource by passing it through every safety layer
//! ([`crate::Controller`] is the workload vertical). This module generalizes
//! that pattern into ONE interface every controller — in-tree or out-of-tree —
//! implements, so new resource types are added by writing a controller against
//! a stable public API rather than by editing the core.
//!
//! Three pieces:
//!
//! * [`ResourceController`] — the object-safe interface a controller implements.
//!   It reconciles an *encoded declaration* (the same bytes that ride the
//!   streaming DB) read through a [`ReconcileContext`], into a uniform
//!   [`ReconcileOutcome`], or refuses with a [`ControllerError`]. Because the
//!   declaration is bytes and the outcome is uniform, controllers for entirely
//!   different resource types share the exact same signature.
//! * [`ReconcileContext`] — the ambient state a reconcile reads: the identity
//!   and capability registries, the coordination lease + epoch, the stream
//!   view, and an [`ImageSource`] for pulling content-addressed bytes. One
//!   context drives every controller uniformly.
//! * [`ControllerRegistry`] — routes a declaration to the controller registered
//!   for its [`ResourceType`]. Registering a new controller (from any crate) is
//!   the whole extension mechanism; the registry never needs to know the
//!   concrete controller type.
//!
//! The in-tree [`Controller`](crate::Controller) is the first client: it
//! `impl`s [`ResourceController`] for the `pillar.workload` resource type
//! ([`WORKLOAD_RESOURCE_TYPE`]) by delegating to its own
//! [`authorize_fetch`](crate::Controller::authorize_fetch) /
//! [`AdmittedFetch::run`](crate::AdmittedFetch::run) vertical. An out-of-tree
//! controller reconciles identically through the same interface — see the
//! `tests/plugin_interface.rs` integration test.

use std::collections::HashMap;

use pillar_core::Epoch;
use pillar_coordination::LeaseRegister;
use pillar_identity::capability::CapabilityRegistry;
use pillar_identity::Registry;
use pillar_net::{BlobDigest, BlobStore};
use pillar_streamdb::View;

use crate::{Controller, WorkloadSpec};

/// The stable resource-type name of the in-tree workload controller.
pub const WORKLOAD_RESOURCE_TYPE: &str = "pillar.workload";

/// A stable identifier for a resource type, used to route a declaration to the
/// controller that reconciles it.
///
/// It is the ONLY coupling between a declaration and its controller: a
/// declaration names its resource type, and the [`ControllerRegistry`]
/// dispatches on it, so in-tree and out-of-tree controllers are
/// indistinguishable at the routing layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceType(String);

impl ResourceType {
    /// The resource-type name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ResourceType {
    fn from(s: &str) -> Self {
        ResourceType(s.to_owned())
    }
}

impl From<String> for ResourceType {
    fn from(s: String) -> Self {
        ResourceType(s)
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolves content-addressed bytes (an OCI image, a config blob) by digest for
/// a reconcile.
///
/// The reconcile is decoupled from *how* the bytes arrive: the in-cluster
/// integration test resolves over the real libp2p blob substrate, while unit
/// tests resolve from an in-memory [`BlobStore`]. A controller only ever asks
/// the [`ReconcileContext`] for a digest.
pub trait ImageSource {
    /// Return the bytes for `digest`, or [`None`] if this source does not hold
    /// them.
    fn fetch(&self, digest: BlobDigest) -> Option<Vec<u8>>;
}

impl ImageSource for BlobStore {
    fn fetch(&self, digest: BlobDigest) -> Option<Vec<u8>> {
        self.get(digest).map(<[u8]>::to_vec)
    }
}

/// The ambient state a reconcile reads, passed uniformly to every controller.
///
/// It bundles exactly the inputs [`Controller::authorize_fetch`] needs — the
/// identity and capability registries, the coordination lease and the epoch
/// being acted in, and the stream view the declaration is read through — plus
/// an [`ImageSource`] so a controller can pull content-addressed bytes without
/// knowing the transport.
pub struct ReconcileContext<'a> {
    identity: &'a Registry,
    caps: &'a CapabilityRegistry,
    lease: &'a LeaseRegister,
    epoch: Epoch,
    view: &'a View<'a>,
    images: &'a dyn ImageSource,
}

impl<'a> ReconcileContext<'a> {
    /// Assemble the reconcile context from its ambient parts.
    #[must_use]
    pub fn new(
        identity: &'a Registry,
        caps: &'a CapabilityRegistry,
        lease: &'a LeaseRegister,
        epoch: Epoch,
        view: &'a View<'a>,
        images: &'a dyn ImageSource,
    ) -> Self {
        ReconcileContext {
            identity,
            caps,
            lease,
            epoch,
            view,
            images,
        }
    }

    /// The identity registry admitting node subkeys.
    #[must_use]
    pub fn identity(&self) -> &Registry {
        self.identity
    }

    /// The capability registry granting authority to admitted subkeys.
    #[must_use]
    pub fn caps(&self) -> &CapabilityRegistry {
        self.caps
    }

    /// The coordination lease register fencing exclusive effects.
    #[must_use]
    pub fn lease(&self) -> &LeaseRegister {
        self.lease
    }

    /// The epoch the reconcile is acting under.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The stream view the declaration is read through.
    #[must_use]
    pub fn view(&self) -> &View<'a> {
        self.view
    }

    /// Resolve content-addressed bytes for `digest`, or [`None`] if the source
    /// does not hold them.
    #[must_use]
    pub fn fetch_image(&self, digest: BlobDigest) -> Option<Vec<u8>> {
        self.images.fetch(digest)
    }
}

/// A uniform record that reconciliation actually produced a running resource.
///
/// Controllers reconcile heterogeneous resource types, so the outcome is
/// deliberately type-erased down to the facts every resource shares: which
/// resource type it is, its declared name, and the coordination epoch it was
/// authorized under. The rich, resource-specific handle (e.g.
/// [`RunningWorkload`](crate::RunningWorkload)) stays on the concrete
/// controller's own API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileOutcome {
    resource_type: ResourceType,
    name: String,
    epoch: Epoch,
}

impl ReconcileOutcome {
    /// Record that `resource_type`/`name` was reconciled under `epoch`.
    #[must_use]
    pub fn new(resource_type: ResourceType, name: impl Into<String>, epoch: Epoch) -> Self {
        ReconcileOutcome {
            resource_type,
            name: name.into(),
            epoch,
        }
    }

    /// The resource type that was reconciled.
    #[must_use]
    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    /// The declared name of the reconciled resource.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The coordination epoch the resource was authorized under.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Why a controller refused (or could not attempt) a reconcile through the
/// uniform interface.
///
/// Resource-specific refusal detail (e.g. [`ReconcileError`](crate::ReconcileError)
/// for a workload) is flattened to its string rendering so every controller —
/// whatever its internal error type — reports refusals through one enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerError {
    /// No controller is registered for the requested resource type.
    NoController(ResourceType),
    /// The declaration payload could not be decoded for this resource type.
    Malformed(String),
    /// A required input (e.g. the declared image bytes) was not available.
    Unavailable(String),
    /// A resource-specific safety gate refused the reconcile.
    Refused(String),
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControllerError::NoController(t) => {
                write!(f, "no controller registered for resource type {t}")
            }
            ControllerError::Malformed(m) => write!(f, "malformed declaration: {m}"),
            ControllerError::Unavailable(m) => write!(f, "reconcile input unavailable: {m}"),
            ControllerError::Refused(m) => write!(f, "reconcile refused: {m}"),
        }
    }
}

impl std::error::Error for ControllerError {}

/// The one interface every resource controller implements — in-tree or
/// out-of-tree.
///
/// It is object-safe so a [`ControllerRegistry`] can hold controllers for many
/// different resource types behind `Box<dyn ResourceController>`. A controller
/// declares the [`ResourceType`] it handles and reconciles an *encoded
/// declaration* (the bytes that ride the streaming DB) read through a
/// [`ReconcileContext`], yielding a uniform [`ReconcileOutcome`] or a
/// [`ControllerError`].
pub trait ResourceController {
    /// The resource type this controller reconciles.
    fn resource_type(&self) -> ResourceType;

    /// Reconcile `declaration` (an encoded resource spec, exactly as it rides
    /// the streaming DB) read through `ctx`, into a running resource — or refuse
    /// at the first gate.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] if the declaration cannot be decoded, a
    /// required input is unavailable, or a safety gate refuses.
    fn reconcile(
        &self,
        ctx: &ReconcileContext<'_>,
        declaration: &[u8],
    ) -> Result<ReconcileOutcome, ControllerError>;
}

/// The in-tree workload controller is the FIRST client of the plugin interface:
/// it reconciles a [`WorkloadSpec`] declaration by delegating to its own
/// [`authorize_fetch`](Controller::authorize_fetch) vertical, pulling the
/// authorized image from the context's [`ImageSource`], and verifying it via
/// [`AdmittedFetch::run`](crate::AdmittedFetch::run).
impl ResourceController for Controller {
    fn resource_type(&self) -> ResourceType {
        ResourceType::from(WORKLOAD_RESOURCE_TYPE)
    }

    fn reconcile(
        &self,
        ctx: &ReconcileContext<'_>,
        declaration: &[u8],
    ) -> Result<ReconcileOutcome, ControllerError> {
        let spec =
            WorkloadSpec::decode(declaration).map_err(|e| ControllerError::Malformed(e.to_string()))?;
        let admitted = self
            .authorize_fetch(
                ctx.identity(),
                ctx.caps(),
                ctx.lease(),
                ctx.epoch(),
                ctx.view(),
                &spec,
            )
            .map_err(|e| ControllerError::Refused(e.to_string()))?;
        let bytes = ctx.fetch_image(admitted.digest()).ok_or_else(|| {
            ControllerError::Unavailable(format!(
                "image {:?} not available to reconcile",
                admitted.digest()
            ))
        })?;
        let running = admitted
            .run(bytes)
            .map_err(|e| ControllerError::Refused(e.to_string()))?;
        Ok(ReconcileOutcome::new(
            self.resource_type(),
            running.name().to_owned(),
            running.epoch(),
        ))
    }
}

/// Routes a declaration to the controller registered for its resource type.
///
/// This is the whole extension mechanism: registering a controller (from any
/// crate) makes its resource type reconcilable; the registry never knows the
/// concrete controller type. In-tree and out-of-tree controllers are dispatched
/// through the identical path.
#[derive(Default)]
pub struct ControllerRegistry {
    controllers: HashMap<ResourceType, Box<dyn ResourceController>>,
}

impl ControllerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        ControllerRegistry {
            controllers: HashMap::new(),
        }
    }

    /// Register `controller` for the resource type it declares.
    ///
    /// Returns the controller previously registered for that resource type, if
    /// any (the new one replaces it).
    pub fn register(
        &mut self,
        controller: Box<dyn ResourceController>,
    ) -> Option<Box<dyn ResourceController>> {
        let resource_type = controller.resource_type();
        self.controllers.insert(resource_type, controller)
    }

    /// Whether a controller is registered for `resource_type`.
    #[must_use]
    pub fn handles(&self, resource_type: &ResourceType) -> bool {
        self.controllers.contains_key(resource_type)
    }

    /// The resource types this registry can reconcile.
    pub fn resource_types(&self) -> impl Iterator<Item = &ResourceType> {
        self.controllers.keys()
    }

    /// Reconcile `declaration` for `resource_type` by routing to its registered
    /// controller.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NoController`] if no controller is registered
    /// for `resource_type`, otherwise the controller's own reconcile result.
    pub fn reconcile(
        &self,
        resource_type: &ResourceType,
        ctx: &ReconcileContext<'_>,
        declaration: &[u8],
    ) -> Result<ReconcileOutcome, ControllerError> {
        match self.controllers.get(resource_type) {
            Some(controller) => controller.reconcile(ctx, declaration),
            None => Err(ControllerError::NoController(resource_type.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::{NodeId, SideEffect};
    use pillar_coordination::LeaseRegister;
    use pillar_identity::capability::Capability;
    use pillar_identity::{NodeSubkey, Signature, UserPrimary};
    use pillar_net::BlobStore;
    use pillar_streamdb::Stream;

    use crate::RUN_WORKLOAD_CAPABILITY;

    const IMAGE: &[u8] = b"plugin-interface-image-payload";

    fn admitted_controller() -> (Registry, CapabilityRegistry, Controller) {
        let mut identity = Registry::new();
        let primary = UserPrimary::from("op-primary");
        let key = NodeSubkey::from("controller-node");
        identity.register(primary.clone());
        identity.issue_subkey(Signature::new(key.clone(), primary));
        identity.handshake(&key).unwrap();
        let mut caps = CapabilityRegistry::new();
        caps.grant(key.clone(), Capability::from(RUN_WORKLOAD_CAPABILITY));
        (identity, caps, Controller::new(key))
    }

    fn lease_held_by(holder: &NodeId, epoch: Epoch) -> LeaseRegister {
        let mut lease = LeaseRegister::new(3);
        lease.grant(NodeId::from("v1"), holder.clone(), epoch).unwrap();
        lease.grant(NodeId::from("v2"), holder.clone(), epoch).unwrap();
        assert!(lease.try_acquire(holder, epoch));
        lease
    }

    /// The in-tree controller reconciles a workload through the uniform
    /// interface, producing the outcome record.
    #[test]
    fn in_tree_controller_reconciles_through_interface() {
        let (identity, caps, controller) = admitted_controller();
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("web", controller.node(), digest, SideEffect::Exclusive);
        let mut stream = Stream::new();
        stream.try_append(spec.encode(), spec.effect()).unwrap();
        let view = stream.view();
        let mut store = BlobStore::new();
        store.insert(IMAGE.to_vec());

        let ctx = ReconcileContext::new(&identity, &caps, &lease, epoch, &view, &store);
        let outcome = controller.reconcile(&ctx, &spec.encode()).unwrap();
        assert_eq!(outcome.resource_type().as_str(), WORKLOAD_RESOURCE_TYPE);
        assert_eq!(outcome.name(), "web");
        assert_eq!(outcome.epoch(), epoch);
    }

    /// The registry routes by resource type and reports NoController for an
    /// unregistered type.
    #[test]
    fn registry_routes_by_resource_type() {
        let (identity, caps, controller) = admitted_controller();
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("web", controller.node(), digest, SideEffect::Exclusive);
        let mut stream = Stream::new();
        stream.try_append(spec.encode(), spec.effect()).unwrap();
        let view = stream.view();
        let mut store = BlobStore::new();
        store.insert(IMAGE.to_vec());

        let mut registry = ControllerRegistry::new();
        registry.register(Box::new(controller));
        assert!(registry.handles(&ResourceType::from(WORKLOAD_RESOURCE_TYPE)));

        let ctx = ReconcileContext::new(&identity, &caps, &lease, epoch, &view, &store);
        let outcome = registry
            .reconcile(
                &ResourceType::from(WORKLOAD_RESOURCE_TYPE),
                &ctx,
                &spec.encode(),
            )
            .unwrap();
        assert_eq!(outcome.name(), "web");

        let unknown = registry.reconcile(&ResourceType::from("no.such.type"), &ctx, &spec.encode());
        assert_eq!(
            unknown,
            Err(ControllerError::NoController(ResourceType::from(
                "no.such.type"
            )))
        );
    }

    /// A refusal from the underlying vertical surfaces as ControllerError.
    #[test]
    fn reconcile_surfaces_refusal() {
        let (identity, _caps, controller) = admitted_controller();
        let ungranted = CapabilityRegistry::new();
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("web", controller.node(), digest, SideEffect::Exclusive);
        let stream = Stream::new();
        let view = stream.view();
        let store = BlobStore::new();

        let ctx = ReconcileContext::new(&identity, &ungranted, &lease, epoch, &view, &store);
        let err = controller.reconcile(&ctx, &spec.encode()).unwrap_err();
        assert!(matches!(err, ControllerError::Refused(_)));
    }
}
