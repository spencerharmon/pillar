//! Proof that the plugin interface is truly shared, not in-tree-privileged:
//! a resource type and controller defined ENTIRELY in this integration test
//! (standing in for an out-of-tree crate — it uses only `pillar_controller`'s
//! public API, never a private helper) get the exact same safety pipeline as
//! the in-tree `WorkloadSpec`/`Controller` — same gates, same order, same
//! errors — by implementing `ResourceSpec` and going through the public
//! `ResourceReconciler`.
//!
//! Method #2 (docs/tasks/plugin-interface.md): each in-tree
//! `pillar_controller::tests` case (in `src/lib.rs`) reconciling a
//! `WorkloadSpec` has a mirrored case here reconciling this out-of-tree
//! `ConfigResource` through the identical public interface, with identical
//! outcomes.

use pillar_controller::{
    Admitted, ReconcileContext, ReconcileError, ResourceReconciler, ResourceSpec,
};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, Registry, Signature, UserPrimary};
use pillar_streamdb::Stream;

/// The capability an out-of-tree config-sync controller requires — chosen
/// independently of `pillar_controller::RUN_WORKLOAD_CAPABILITY`, proving
/// the interface imposes no in-tree vocabulary on its clients.
const SYNC_CONFIG_CAPABILITY: &str = "config:sync";

/// An out-of-tree resource type: declares that a config blob (identified by
/// an opaque version tag) should be synced to `target_node`. Nothing here
/// reuses `pillar_controller::WorkloadSpec` or any private type — it is
/// exactly what an out-of-tree crate would write against the public
/// `ResourceSpec` trait alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigResource {
    version: String,
    target_node: NodeId,
    effect: SideEffect,
}

impl ResourceSpec for ConfigResource {
    fn target_node(&self) -> &NodeId {
        &self.target_node
    }

    fn effect(&self) -> SideEffect {
        self.effect
    }
}

/// The out-of-tree controller's own "materialize" step: once
/// `ResourceReconciler::authorize` admits a `ConfigResource`, this is the
/// resource-specific work that stays entirely outside `pillar_controller` —
/// mirroring how `AdmittedFetch::run` is workload-specific in-tree.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SyncedConfig {
    version: String,
    node: NodeId,
    epoch: Epoch,
}

fn sync(admitted: Admitted<ConfigResource>) -> SyncedConfig {
    SyncedConfig {
        version: admitted.spec().version.clone(),
        node: admitted.node().clone(),
        epoch: admitted.epoch(),
    }
}

/// Build an identity registry admitting a controller node and a foreign node
/// under the same registered primary (mirrors `pillar_controller`'s own
/// `tests::admitted` helper, independently reimplemented here since an
/// out-of-tree crate has no access to it).
fn admitted_identity() -> (Registry, NodeSubkey, NodeSubkey) {
    let mut reg = Registry::new();
    let primary = UserPrimary::from("op-primary");
    let controller = NodeSubkey::from("config-controller-node");
    let foreign = NodeSubkey::from("foreign-node");
    reg.register(primary.clone());
    reg.issue_subkey(Signature::new(controller.clone(), primary.clone()));
    reg.issue_subkey(Signature::new(foreign.clone(), primary));
    reg.handshake(&controller).unwrap();
    reg.handshake(&foreign).unwrap();
    (reg, controller, foreign)
}

fn granted(controller: &NodeSubkey) -> CapabilityRegistry {
    let mut caps = CapabilityRegistry::new();
    caps.grant(controller.clone(), Capability::from(SYNC_CONFIG_CAPABILITY));
    caps
}

fn lease_held_by(holder: &NodeId, epoch: Epoch) -> LeaseRegister {
    let mut lease = LeaseRegister::new(3);
    lease
        .grant(NodeId::from("v1"), holder.clone(), epoch)
        .unwrap();
    lease
        .grant(NodeId::from("v2"), holder.clone(), epoch)
        .unwrap();
    assert!(lease.try_acquire(holder, epoch));
    lease
}

/// Happy path: an admitted, capability-granted out-of-tree controller
/// reconciles a `ConfigResource` through the public interface exactly as the
/// in-tree `Controller` reconciles a `WorkloadSpec`
/// (`pillar_controller::tests::full_vertical_authorizes_and_runs`).
#[test]
fn out_of_tree_controller_authorizes_and_syncs() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = granted(&controller_key);
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    let lease = lease_held_by(&reconciler.node(), epoch);

    let resource = ConfigResource {
        version: "v42".to_owned(),
        target_node: reconciler.node(),
        effect: SideEffect::Exclusive,
    };

    let mut stream = Stream::new(); // strict by default
    stream
        .try_append(b"config-declaration".to_vec(), resource.effect())
        .expect("strict stream admits the declaration");
    let view = stream.view();

    let ctx = ReconcileContext::new(&identity, &caps, &lease, epoch, &view);
    let admitted = reconciler
        .authorize(&ctx, &resource)
        .expect("all gates admit");

    let synced = sync(admitted);
    assert_eq!(synced.version, "v42");
    assert_eq!(synced.node, reconciler.node());
    assert_eq!(synced.epoch, epoch);
}

/// Controller layer: an admitted subkey never granted the capability is
/// refused — identical to
/// `pillar_controller::tests::ungranted_controller_is_unauthorized`.
#[test]
fn out_of_tree_ungranted_controller_is_unauthorized() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = CapabilityRegistry::new(); // nothing granted
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    let lease = lease_held_by(&reconciler.node(), epoch);
    let resource = ConfigResource {
        version: "v1".to_owned(),
        target_node: reconciler.node(),
        effect: SideEffect::Exclusive,
    };
    let stream = Stream::new();
    let err = reconciler
        .authorize(
            &ReconcileContext::new(&identity, &caps, &lease, epoch, &stream.view()),
            &resource,
        )
        .unwrap_err();
    assert!(matches!(err, ReconcileError::Unauthorized(_)));
}

/// Controller layer: a resource declared for a different node is refused —
/// identical to `pillar_controller::tests::workload_for_other_node_is_refused`.
#[test]
fn out_of_tree_resource_for_other_node_is_refused() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = granted(&controller_key);
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    let lease = lease_held_by(&reconciler.node(), epoch);
    let resource = ConfigResource {
        version: "v1".to_owned(),
        target_node: NodeId::from("some-other-peer"),
        effect: SideEffect::Exclusive,
    };
    let stream = Stream::new();
    let err = reconciler
        .authorize(
            &ReconcileContext::new(&identity, &caps, &lease, epoch, &stream.view()),
            &resource,
        )
        .unwrap_err();
    assert!(matches!(err, ReconcileError::NotTargetNode { .. }));
}

/// View layer: an exclusive resource declared on a Relaxed (AP) stream is
/// refused — identical to
/// `pillar_controller::tests::relaxed_view_refuses_exclusive_workload`.
#[test]
fn out_of_tree_relaxed_view_refuses_exclusive_resource() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = granted(&controller_key);
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    let lease = lease_held_by(&reconciler.node(), epoch);
    let resource = ConfigResource {
        version: "v1".to_owned(),
        target_node: reconciler.node(),
        effect: SideEffect::Exclusive,
    };
    let relaxed = Stream::with_policy(pillar_core::ViewPolicy::Relaxed);
    let err = reconciler
        .authorize(
            &ReconcileContext::new(&identity, &caps, &lease, epoch, &relaxed.view()),
            &resource,
        )
        .unwrap_err();
    assert_eq!(
        err,
        ReconcileError::ViewRefusedEffect {
            effect: SideEffect::Exclusive
        }
    );
}

/// Coordination layer: an exclusive resource is refused when the controller
/// does not hold the lease for the epoch — identical to
/// `pillar_controller::tests::minority_without_lease_refuses_exclusive_workload`.
#[test]
fn out_of_tree_minority_without_lease_refuses_exclusive_resource() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = granted(&controller_key);
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    // Minority: only one of three voters backs the controller.
    let mut lease = LeaseRegister::new(3);
    lease
        .grant(NodeId::from("v1"), reconciler.node(), epoch)
        .unwrap();
    assert!(!lease.try_acquire(&reconciler.node(), epoch));

    let resource = ConfigResource {
        version: "v1".to_owned(),
        target_node: reconciler.node(),
        effect: SideEffect::Exclusive,
    };
    let mut stream = Stream::new();
    stream
        .try_append(b"config-declaration".to_vec(), resource.effect())
        .expect("strict stream admits the declaration");
    let err = reconciler
        .authorize(
            &ReconcileContext::new(&identity, &caps, &lease, epoch, &stream.view()),
            &resource,
        )
        .unwrap_err();
    assert_eq!(err, ReconcileError::NotLeaseHolder { epoch });
}

/// A CONVERGENT resource needs no lease — identical to
/// `pillar_controller::tests::convergent_workload_runs_without_lease`.
#[test]
fn out_of_tree_convergent_resource_syncs_without_lease() {
    let (identity, controller_key, _foreign) = admitted_identity();
    let caps = granted(&controller_key);
    let reconciler: ResourceReconciler<ConfigResource> =
        ResourceReconciler::new(controller_key, SYNC_CONFIG_CAPABILITY);
    let epoch = Epoch(1);
    let lease = LeaseRegister::new(3); // nobody holds anything

    let resource = ConfigResource {
        version: "v7".to_owned(),
        target_node: reconciler.node(),
        effect: SideEffect::Convergent,
    };
    let relaxed = Stream::with_policy(pillar_core::ViewPolicy::Relaxed);
    let admitted = reconciler
        .authorize(
            &ReconcileContext::new(&identity, &caps, &lease, epoch, &relaxed.view()),
            &resource,
        )
        .expect("convergent resource needs no lease");
    let synced = sync(admitted);
    assert_eq!(synced.version, "v7");
}
