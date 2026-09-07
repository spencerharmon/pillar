//! The **Deployment** kind — a long-running, replicated workload (explicitly
//! NOT the Job/CronJob one-shots): `replicas` copies of a workload, PLACED
//! across distinct failure domains by the real `pillar_topology::Topology`
//! spread engine (never a re-derived in-crate heuristic), and EXECUTED as
//! real supervised OS processes via [`crate::runtime::SupervisedWorkload`] —
//! the same real-process execution layer `RunningWorkload::spawn_process`
//! gives a single workload. A [`RestartPolicy`] governs what happens when the
//! runtime observes a replica has actually died: [`RestartPolicy::Always`]
//! re-execs the SAME verified image bytes as a fresh real process (a new
//! pid, a rebound socket), not a modeled state flip.
//!
//! The scheduler (placement, via [`DeploymentSpec::place`]) and the runtime
//! (execution + restart, via [`Deployment::reconcile_restarts`]) are composed
//! here exactly as the acceptance narrative requires: real placement
//! decisions feeding real process execution.

use pillar_core::NodeId;
use pillar_topology::{PlacementError, Topology};

use crate::runtime::{RuntimeError, SupervisedWorkload};

/// Whether a replica the runtime observes as no longer alive is
/// automatically restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    /// A dead replica is re-spawned from the same verified image bytes.
    Always,
    /// A dead replica is left dead — no automatic restart.
    Never,
}

/// A declared Deployment: run `replicas` long-running copies of a workload,
/// spread across distinct values of `spread_tier` among candidate nodes, with
/// `restart_policy` governing replica lifecycle.
#[derive(Clone, Debug)]
pub struct DeploymentSpec {
    name: String,
    replicas: usize,
    spread_tier: String,
    restart_policy: RestartPolicy,
}

impl DeploymentSpec {
    /// Declare a Deployment named `name` with `replicas` replicas, spread
    /// across distinct values of `spread_tier`, governed by
    /// `restart_policy`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        replicas: usize,
        spread_tier: impl Into<String>,
        restart_policy: RestartPolicy,
    ) -> Self {
        DeploymentSpec {
            name: name.into(),
            replicas,
            spread_tier: spread_tier.into(),
            restart_policy,
        }
    }

    /// The Deployment's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared replica count.
    #[must_use]
    pub fn replicas(&self) -> usize {
        self.replicas
    }

    /// The topology tier replicas are spread across.
    #[must_use]
    pub fn spread_tier(&self) -> &str {
        &self.spread_tier
    }

    /// This Deployment's restart policy.
    #[must_use]
    pub fn restart_policy(&self) -> RestartPolicy {
        self.restart_policy
    }

    /// Place this Deployment's replicas: choose [`Self::replicas`] DISTINCT
    /// nodes from `candidates` at [`Self::spread_tier`], via the REAL
    /// `Topology::spread` placement engine — the scheduler's actual
    /// placement decision, never a re-derived heuristic.
    ///
    /// # Errors
    ///
    /// Returns the topology engine's [`PlacementError`] verbatim — e.g. too
    /// few distinct failure domains among `candidates` to satisfy the
    /// requested replica count / spread.
    pub fn place(
        &self,
        topology: &Topology,
        candidates: &[NodeId],
    ) -> Result<Vec<NodeId>, PlacementError> {
        topology.spread(candidates, self.replicas, &self.spread_tier)
    }
}

/// One running replica of a [`DeploymentSpec`]: the node it was PLACED on and
/// the REAL supervised OS process EXECUTING it.
pub struct DeploymentReplica {
    node: NodeId,
    process: SupervisedWorkload,
}

impl DeploymentReplica {
    /// A replica placed on `node`, executing as the real supervised
    /// `process`.
    #[must_use]
    pub fn new(node: NodeId, process: SupervisedWorkload) -> Self {
        DeploymentReplica { node, process }
    }

    /// The node this replica was placed on.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// The real supervised process executing this replica.
    #[must_use]
    pub fn process(&self) -> &SupervisedWorkload {
        &self.process
    }

    /// Mutable access to the real supervised process (liveness checks,
    /// stop/restart).
    #[must_use]
    pub fn process_mut(&mut self) -> &mut SupervisedWorkload {
        &mut self.process
    }
}

/// A running Deployment: every PLACED replica's REAL supervised process, plus
/// the restart policy governing their lifecycle.
pub struct Deployment {
    spec: DeploymentSpec,
    replicas: Vec<DeploymentReplica>,
}

impl Deployment {
    /// A running Deployment over already-placed-and-spawned `replicas`.
    #[must_use]
    pub fn new(spec: DeploymentSpec, replicas: Vec<DeploymentReplica>) -> Self {
        Deployment { spec, replicas }
    }

    /// The declared spec.
    #[must_use]
    pub fn spec(&self) -> &DeploymentSpec {
        &self.spec
    }

    /// Every running replica.
    #[must_use]
    pub fn replicas(&self) -> &[DeploymentReplica] {
        &self.replicas
    }

    /// Mutable access to every running replica.
    pub fn replicas_mut(&mut self) -> &mut [DeploymentReplica] {
        &mut self.replicas
    }

    /// Poll every replica's REAL liveness
    /// ([`SupervisedWorkload::is_alive`]) and, under
    /// [`RestartPolicy::Always`], actually RESTART
    /// ([`SupervisedWorkload::restart`]) any replica the runtime observes has
    /// died — a real re-exec of the same verified image bytes, a fresh pid
    /// and rebound socket, never a modeled state flip. Returns the nodes
    /// restarted this pass.
    ///
    /// # Errors
    ///
    /// Returns the first [`RuntimeError`] a liveness check or restart raises.
    pub async fn reconcile_restarts(&mut self) -> Result<Vec<NodeId>, RuntimeError> {
        let mut restarted = Vec::new();
        for replica in &mut self.replicas {
            let alive = replica.process.is_alive()?;
            if !alive && self.spec.restart_policy == RestartPolicy::Always {
                replica.process.restart().await?;
                restarted.push(replica.node.clone());
            }
        }
        Ok(restarted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_topology::{Label, TierHierarchy};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn topo_with_three_racks() -> Topology {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("node-a"), &[Label::new("rack", "r1")]);
        topo.declare(n("node-b"), &[Label::new("rack", "r2")]);
        topo.declare(n("node-c"), &[Label::new("rack", "r3")]);
        topo
    }

    #[test]
    fn deployment_spec_places_replicas_across_distinct_racks() {
        let topo = topo_with_three_racks();
        let spec = DeploymentSpec::new("web", 3, "rack", RestartPolicy::Always);
        let placed = spec
            .place(&topo, &[n("node-a"), n("node-b"), n("node-c")])
            .expect("three distinct racks satisfy 3 replicas");
        assert_eq!(placed.len(), 3);
        let racks: std::collections::BTreeSet<_> = placed
            .iter()
            .map(|nd| topo.placement(nd).at("rack").unwrap().to_owned())
            .collect();
        assert_eq!(racks.len(), 3, "each replica lands on a distinct rack");
    }

    #[test]
    fn deployment_spec_placement_refuses_insufficient_domains() {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(n("node-a"), &[Label::new("rack", "r1")]);
        topo.declare(n("node-b"), &[Label::new("rack", "r1")]);
        let spec = DeploymentSpec::new("web", 2, "rack", RestartPolicy::Never);
        let err = spec
            .place(&topo, &[n("node-a"), n("node-b")])
            .unwrap_err();
        assert_eq!(
            err,
            PlacementError::InsufficientDomains {
                tier: "rack".to_owned(),
                available: 1,
                requested: 2,
            }
        );
    }
}
