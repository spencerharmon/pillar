//! Out-of-tree controller proof: a controller defined ENTIRELY outside the
//! `pillar-controller` crate — using only its public API, exactly as a
//! third-party plugin crate would — reconciles a resource identically to the
//! in-tree workload controller, through the one shared
//! [`ResourceController`](pillar_controller::ResourceController) interface and
//! the same [`ControllerRegistry`](pillar_controller::ControllerRegistry)
//! dispatch path.
//!
//! This is the P3 extensibility proof: adding a resource type is writing a
//! controller against the public interface, and the registry treats it exactly
//! like the built-in one.

use pillar_controller::{
    Controller, ControllerRegistry, ReconcileContext, ReconcileOutcome, ResourceController,
    ResourceType, WorkloadSpec, RUN_WORKLOAD_CAPABILITY, WORKLOAD_RESOURCE_TYPE,
};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, Registry, Signature, UserPrimary};
use pillar_net::{BlobDigest, BlobStore};
use pillar_streamdb::Stream;

const IMAGE: &[u8] = b"out-of-tree-controller-image-payload";

/// An OUT-OF-TREE controller: it lives in this integration test (not the
/// `pillar-controller` crate) and is built purely from the crate's public
/// interface. It reconciles the SAME workload declaration by delegating to the
/// public [`Controller`] vertical — the only coupling to the core is the
/// published [`ResourceController`] trait. It registers under its own resource
/// type to prove the registry routes it identically to the built-in one.
struct OutOfTreeWorkloadController {
    inner: Controller,
    resource_type: ResourceType,
}

impl OutOfTreeWorkloadController {
    fn new(inner: Controller, resource_type: &str) -> Self {
        OutOfTreeWorkloadController {
            inner,
            resource_type: ResourceType::from(resource_type),
        }
    }
}

impl ResourceController for OutOfTreeWorkloadController {
    fn resource_type(&self) -> ResourceType {
        self.resource_type.clone()
    }

    fn reconcile(
        &self,
        ctx: &ReconcileContext<'_>,
        declaration: &[u8],
    ) -> Result<ReconcileOutcome, pillar_controller::ControllerError> {
        // Reconcile through exactly the public interface the in-tree controller
        // uses; only the reported resource type differs.
        let outcome = self.inner.reconcile(ctx, declaration)?;
        Ok(ReconcileOutcome::new(
            self.resource_type(),
            outcome.name().to_owned(),
            outcome.epoch(),
        ))
    }
}

fn admitted_controller(node_name: &str) -> (Registry, CapabilityRegistry, Controller) {
    let mut identity = Registry::new();
    let primary = UserPrimary::from("operator-primary");
    let key = NodeSubkey::from(node_name);
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

/// The out-of-tree controller, dispatched through the registry, produces the
/// SAME reconcile outcome (name + epoch) as the in-tree controller for the same
/// declaration and context — differing only in its declared resource type. The
/// registry routes both through the identical path.
#[test]
fn out_of_tree_controller_reconciles_identically_to_in_tree() {
    let epoch = Epoch(1);
    let digest = BlobDigest::of(IMAGE);

    // Two identically-authorized controllers acting as the same node identity,
    // one in-tree and one out-of-tree.
    let (identity, caps, in_tree) = admitted_controller("shared-controller-node");
    let (_id2, _caps2, inner_for_out_of_tree) = admitted_controller("shared-controller-node");
    let out_of_tree =
        OutOfTreeWorkloadController::new(inner_for_out_of_tree, "example.out-of-tree-workload");

    // Both controllers act as the same node, so one lease/spec drives both.
    let lease = lease_held_by(&in_tree.node(), epoch);
    let spec = WorkloadSpec::new("web", in_tree.node(), digest, SideEffect::Exclusive);
    let mut stream = Stream::new();
    stream
        .try_append(spec.encode(), spec.effect())
        .expect("strict stream admits the declaration");
    let view = stream.view();
    let mut store = BlobStore::new();
    store.insert(IMAGE.to_vec());

    let out_of_tree_type = out_of_tree.resource_type();

    let mut registry = ControllerRegistry::new();
    registry.register(Box::new(in_tree));
    registry.register(Box::new(out_of_tree));

    // The registry treats both uniformly: both resource types are handled and
    // dispatched through the same reconcile path.
    assert!(registry.handles(&ResourceType::from(WORKLOAD_RESOURCE_TYPE)));
    assert!(registry.handles(&out_of_tree_type));

    let ctx = ReconcileContext::new(&identity, &caps, &lease, epoch, &view, &store);

    let in_tree_outcome = registry
        .reconcile(
            &ResourceType::from(WORKLOAD_RESOURCE_TYPE),
            &ctx,
            &spec.encode(),
        )
        .expect("in-tree controller reconciles");
    let out_of_tree_outcome = registry
        .reconcile(&out_of_tree_type, &ctx, &spec.encode())
        .expect("out-of-tree controller reconciles");

    // Identical reconcile: same name, same authorized epoch. The ONLY
    // difference is each controller's declared resource type — the routing key.
    assert_eq!(in_tree_outcome.name(), out_of_tree_outcome.name());
    assert_eq!(in_tree_outcome.epoch(), out_of_tree_outcome.epoch());
    assert_eq!(
        in_tree_outcome.resource_type().as_str(),
        WORKLOAD_RESOURCE_TYPE
    );
    assert_eq!(out_of_tree_outcome.resource_type(), &out_of_tree_type);
}
