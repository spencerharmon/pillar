//! The **workload-runtime reconcile loop** wired into the shipped, running
//! `pillar node run` process.
//!
//! Every piece of the workload vertical — real fetch-by-CID over live libp2p
//! ([`pillar_net::build_blob_swarm`]/[`pillar_net::BlobStore`]), real
//! digest-verified admission ([`pillar_controller::Controller::authorize_fetch`]),
//! real topology-spread replica placement ([`pillar_topology`]), and real
//! supervised-process execution
//! ([`pillar_controller::RunningWorkload::spawn_process`]) — was, before this
//! module, reachable ONLY from an in-process Rust acceptance test that built
//! its own identity/capability/lease/view stack and called the library APIs by
//! hand. The web portal's `/portal/resource/apply`+`/scale` routes only emitted
//! a signed manifest-log event; nothing in the node RECONCILED that event into
//! a real fetch + admission + spawn.
//!
//! This module closes that gap. [`WorkloadReconciler`] is instantiated in the
//! node boot path ([`crate::run::run`]) and handed to the web plane; on every
//! authorized `apply`/`scale` of a `Workload`, the web plane calls
//! [`WorkloadReconciler::reconcile`], which drives the SAME
//! authorization/admission path the in-process acceptance tests prove — just
//! triggered by the real node's own reconcile loop instead of a hand-built
//! harness — and brings the declared replicas up as REAL supervised OS
//! processes bound to REAL listening sockets.
//!
//! The resulting real effects are exposed on the node's external surface so a
//! black-box harness can observe them WITHOUT linking any pillar crate: a
//! `/workload/replicas` HTTP oracle (served on the health surface) reports each
//! replica's real pid, real bound port, and the content-addressed image digest
//! it was admitted under, and each reconcile logs a
//! `pillar workload reconciled` line the harness can grep (the same
//! black-box-observation pattern the streamdb-persistence scenario already uses
//! via `topology_node_op_cids`/`topology_node_streamdb_ops`).
//!
//! ## Image reference encoding
//!
//! A `Workload`'s `image` field is a content-addressed reference the node
//! fetches by CID over real libp2p. To keep the fetch honest (a real request
//! to a real provider that answers by content address), the image string is:
//!
//! ```text
//! blob:<provider-multiaddr-with-/p2p/<peer-id>>|<digest-hex>
//! ```
//!
//! e.g. `blob:/ip4/127.0.0.1/tcp/40001/p2p/12D3.../|a1b2c3...`. The node dials
//! the provider, requests the digest over the `/pillar/blob/1.0.0`
//! request-response protocol, verifies the returned bytes hash to the declared
//! digest through [`pillar_controller::AdmittedFetch::run`], and spawns them.
//! A plain (non-`blob:`) image string names no fetchable content and is
//! reconciled as a no-op (nothing to run) — the manifest event is still
//! recorded, exactly as before.

use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;

use pillar_controller::{
    Controller, RunningWorkload, SupervisedWorkload, WorkloadSpec, RUN_WORKLOAD_CAPABILITY,
};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_crypto::ContentId;
use pillar_identity::capability::{Capability, CapabilityRegistry};
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry};
use pillar_net::{build_blob_swarm, BlobBehaviourEvent, BlobDigest, BlobRequest};
use pillar_streamdb::{OpId, Stream};
use pillar_topology::{Label, TierHierarchy, Topology};

/// The tier the reconcile loop spreads replicas across (single-node dev-mode
/// admits locally, but the spread engine is exercised for real).
const SPREAD_TIER: &str = "rack";

/// A parse of a `Workload` `image` field into a fetchable content reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef {
    /// The dialable provider multiaddr (terminating in `/p2p/<peer-id>`).
    pub provider: Multiaddr,
    /// The content-addressed digest the provider must answer.
    pub digest: BlobDigest,
}

impl ImageRef {
    /// Parses `blob:<multiaddr>|<digest-hex>`; returns `None` for any other
    /// (non-fetchable) image string.
    pub fn parse(image: &str) -> Option<ImageRef> {
        let rest = image.strip_prefix("blob:")?;
        let (addr, hex) = rest.rsplit_once('|')?;
        let provider: Multiaddr = addr.parse().ok()?;
        let bytes = decode_hex(hex)?;
        let digest = BlobDigest(OpId(ContentId::from_bytes(bytes)));
        Some(ImageRef { provider, digest })
    }

    /// Renders the `blob:<multiaddr>|<digest-hex>` image string for `provider`
    /// serving `digest` — the inverse of [`ImageRef::parse`], used by tests and
    /// tooling that publish an image for the node to fetch.
    pub fn encode(provider: &Multiaddr, digest: &BlobDigest) -> String {
        format!("blob:{provider}|{}", encode_hex(digest.as_bytes()))
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One live replica of a reconciled workload: a real supervised OS process
/// bound to a real listening UDP socket.
struct Replica {
    node: NodeId,
    port: u16,
    process: SupervisedWorkload,
}

/// The reconciled state of one `Workload` object.
struct WorkloadState {
    /// The content-addressed digest the replicas were admitted under.
    digest: BlobDigest,
    /// The verified image bytes (kept so a restart re-spawns the SAME
    /// content-addressed image without re-fetching).
    running: RunningWorkload,
    /// The desired replica count.
    replicas_desired: usize,
    /// The live replicas.
    replicas: Vec<Replica>,
}

/// An observable snapshot of one replica for the black-box HTTP oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaObservation {
    /// The workload name.
    pub workload: String,
    /// The placement node this replica was spread onto.
    pub node: String,
    /// The real OS pid of the supervised process (0 if it has exited).
    pub pid: u32,
    /// The real bound UDP port the replica listens on.
    pub port: u16,
    /// The content-addressed image digest (hex) the replica was admitted under.
    pub image_digest: String,
}

/// Drives the real workload-runtime vertical inside the running node.
///
/// A single instance is created at boot and shared (behind an `Arc<Mutex<…>>`)
/// with the web plane and the oracle HTTP server. It is `Send` and its methods
/// take `&mut self`, so all reconcile mutations are serialized under the mutex.
pub struct WorkloadReconciler {
    /// The node's identity as a controller subject, admitted + capability-
    /// granted for `workload:run` — the SAME gate stack the acceptance tests
    /// build by hand.
    identity: Registry,
    caps: CapabilityRegistry,
    controller: Controller,
    lease: LeaseRegister,
    epoch: Epoch,
    /// The topology the spread engine places over. Single-node dev-mode
    /// declares this node on its own rack; a real multi-node cluster declares
    /// the discovered peer set.
    topology: Topology,
    /// The candidate placement nodes (this node, in dev-mode).
    candidates: Vec<NodeId>,
    /// Reconciled workloads by name.
    workloads: HashMap<String, WorkloadState>,
    /// A dedicated, persistent Tokio runtime that OWNS every supervised child
    /// process for its whole lifetime. `spawn_process` registers the child with
    /// the runtime's IO/signal driver and that runtime must outlive the child
    /// (else its pidfd reaper panics on drop), so all fetch/spawn/liveness/
    /// restart operations run entered on THIS runtime — never a short-lived or
    /// borrowed one. Declared LAST so it is dropped AFTER `workloads` (the
    /// children are reaped while the runtime is still alive).
    runtime: tokio::runtime::Runtime,
}

/// Why a reconcile could not complete.
#[derive(Debug)]
pub enum ReconcileError {
    /// The image reference did not name fetchable content (a no-op reconcile).
    NotFetchable,
    /// The blob could not be fetched from the declared provider over libp2p.
    Fetch(String),
    /// The controller refused to admit the workload.
    Admit(String),
    /// The verified image failed to spawn as a real process.
    Spawn(String),
    /// Replica placement across the topology failed.
    Placement(String),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::NotFetchable => write!(f, "image is not a fetchable blob reference"),
            ReconcileError::Fetch(e) => write!(f, "blob fetch over libp2p: {e}"),
            ReconcileError::Admit(e) => write!(f, "controller admission: {e}"),
            ReconcileError::Spawn(e) => write!(f, "supervised spawn: {e}"),
            ReconcileError::Placement(e) => write!(f, "replica placement: {e}"),
        }
    }
}
impl std::error::Error for ReconcileError {}

impl WorkloadReconciler {
    /// Builds a reconciler whose controller identity is derived from
    /// `node_seed` (stable across restarts so the SAME subject reconciles), the
    /// node placed on its own rack as the sole placement candidate (dev-mode).
    pub fn new(node_seed: &[u8], node_id: NodeId) -> WorkloadReconciler {
        let mut identity = Registry::new();
        let primary =
            PrimaryKeypair::from_secret_seed(&pillar_crypto::Seed::from_bytes(node_seed.to_vec()));
        let controller_key = NodeSubkey::from("pillar-node-workload-controller");
        identity.register(primary.primary());
        identity.issue_subkey(primary.certify(&controller_key));
        let _ = identity.handshake(&controller_key);

        let mut caps = CapabilityRegistry::new();
        caps.grant(
            controller_key.clone(),
            Capability::from(RUN_WORKLOAD_CAPABILITY),
        );
        let controller = Controller::new(controller_key);

        let epoch = Epoch(1);
        let mut lease = LeaseRegister::new(3);
        // Two peer voters grant this node the lease for the epoch; a real
        // multi-node deployment collects these from live peers, dev-mode
        // synthesizes them so the exclusive-effect admission gate has a
        // holder — exactly as the in-process acceptance tests do.
        let _ = lease.grant(NodeId::from("workload-voter-1"), controller.node(), epoch);
        let _ = lease.grant(NodeId::from("workload-voter-2"), controller.node(), epoch);
        lease.try_acquire(&controller.node(), epoch);

        let mut topology = Topology::new(TierHierarchy::default());
        // Place THIS node on its own rack so the real spread engine has a
        // domain to place a replica in. A real cluster declares each peer on
        // its own rack as it is discovered.
        topology.declare(node_id.clone(), &[Label::new(SPREAD_TIER, "rack-local")]);
        let candidates = vec![node_id];

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build the reconciler's dedicated tokio runtime");

        WorkloadReconciler {
            identity,
            caps,
            controller,
            lease,
            epoch,
            topology,
            candidates,
            workloads: HashMap::new(),
            runtime,
        }
    }

    /// The controller subject this reconciler admits under (its placement node
    /// identity).
    pub fn controller_node(&self) -> NodeId {
        self.controller.node()
    }

    /// Reconcile one `Workload` to `replicas` copies of `image`.
    ///
    /// Fetches the image bytes by CID over real libp2p, verifies the digest
    /// through the controller's admission gate, places replicas across the
    /// topology, and spawns each as a real supervised process. Idempotent:
    /// re-reconciling the same (name,image) to the same replica count is a
    /// no-op beyond restarting any replica that has died; a changed replica
    /// count scales up (spawn more) or down (stop the excess).
    ///
    /// A non-`blob:` image reconciles to `NotFetchable` — the manifest event
    /// is still recorded by the caller; there is simply no content to run.
    pub fn reconcile(
        &mut self,
        name: &str,
        image: &str,
        replicas: usize,
    ) -> Result<Vec<ReplicaObservation>, ReconcileError> {
        let image_ref = ImageRef::parse(image).ok_or(ReconcileError::NotFetchable)?;

        // If we have not yet admitted this exact (name,digest), fetch+admit it.
        let need_admit = match self.workloads.get(name) {
            Some(state) => state.digest != image_ref.digest,
            None => true,
        };

        if need_admit {
            // Fetch runs on the runtime via block_on (NO enter guard held here,
            // to avoid a nested-runtime panic).
            let bytes = fetch_blob(&self.runtime, &image_ref)?;
            let running = self.admit(name, image_ref.digest.clone(), bytes)?;
            self.workloads.insert(
                name.to_owned(),
                WorkloadState {
                    digest: image_ref.digest.clone(),
                    running,
                    replicas_desired: 0,
                    replicas: Vec::new(),
                },
            );
        }

        // Spawning children requires the runtime CONTEXT (not block_on): enter
        // it so `spawn_process` registers each child with this persistent
        // runtime, which owns and outlives them.
        let handle = self.runtime.handle().clone();
        {
            let _guard = handle.enter();
            self.scale(name, replicas)?;
            self.reconcile_restarts_entered(name);
        }

        tracing::info!(
            workload = name,
            image_digest = %encode_hex(image_ref.digest.as_bytes()),
            replicas = replicas,
            "pillar workload reconciled"
        );

        Ok(self.observe(name))
    }

    /// Admit `bytes` (verified against `digest`) through the full controller
    /// gate, yielding a runnable, digest-verified workload.
    fn admit(
        &mut self,
        name: &str,
        digest: BlobDigest,
        bytes: Vec<u8>,
    ) -> Result<RunningWorkload, ReconcileError> {
        let spec = WorkloadSpec::new(name, self.controller.node(), digest, SideEffect::Exclusive);
        // A strict stream that admits the exclusive declaration — the SAME
        // view-admission gate the acceptance tests exercise.
        let mut stream = Stream::new();
        stream
            .try_append(spec.encode(), spec.effect())
            .map_err(|e| ReconcileError::Admit(format!("stream refused declaration: {e:?}")))?;
        let view = stream.view();

        let admitted = self
            .controller
            .authorize_fetch(
                &self.identity,
                &self.caps,
                &self.lease,
                self.epoch,
                &view,
                &spec,
            )
            .map_err(|e| ReconcileError::Admit(format!("{e:?}")))?;

        admitted
            .run(bytes)
            .map_err(|e| ReconcileError::Admit(format!("digest verify: {e:?}")))
    }

    /// Bring the workload's live replica count to `desired`, placing new
    /// replicas across the topology and stopping any excess.
    fn scale(&mut self, name: &str, desired: usize) -> Result<(), ReconcileError> {
        // Placement first (immutable borrow of topology/candidates) so the
        // mutable workload borrow below does not overlap it.
        let placement = self
            .topology
            .spread(&self.candidates, desired.max(1), SPREAD_TIER)
            .or_else(|_| {
                // Single-domain dev-mode: the spread engine refuses N>domains,
                // so fall back to placing every replica on the sole candidate.
                if self.candidates.is_empty() {
                    Err(ReconcileError::Placement("no candidate nodes".to_owned()))
                } else {
                    Ok((0..desired)
                        .map(|i| self.candidates[i % self.candidates.len()].clone())
                        .collect())
                }
            })?;

        let state = self
            .workloads
            .get_mut(name)
            .expect("admit inserted the workload state");
        state.replicas_desired = desired;

        // Scale down: stop and drop the excess.
        while state.replicas.len() > desired {
            if let Some(r) = state.replicas.pop() {
                // The process is kill-on-drop, so dropping it tears it down.
                drop(r);
            }
        }

        // Scale up: spawn the shortfall on placed nodes.
        let running = state.running.clone();
        while state.replicas.len() < desired {
            let idx = state.replicas.len();
            let node = placement
                .get(idx % placement.len().max(1))
                .cloned()
                .unwrap_or_else(|| self.candidates[0].clone());
            let port = free_udp_port();
            let process = running
                .spawn_process(&[port.to_string()])
                .map_err(|e| ReconcileError::Spawn(format!("{e:?}")))?;
            state.replicas.push(Replica {
                node,
                port,
                process,
            });
        }
        Ok(())
    }

    /// RestartPolicy::Always: any replica whose real process has died is
    /// re-spawned from the SAME verified image bytes onto the same port.
    /// Returns the nodes whose replicas were restarted.
    pub fn reconcile_restarts(&mut self, name: &str) -> Vec<String> {
        let handle = self.runtime.handle().clone();
        let _guard = handle.enter();
        self.reconcile_restarts_entered(name)
    }

    /// Restart sweep body, assuming the reconciler's runtime context is already
    /// entered (the caller holds the enter guard). Spawns children on that
    /// runtime.
    fn reconcile_restarts_entered(&mut self, name: &str) -> Vec<String> {
        let Some(state) = self.workloads.get_mut(name) else {
            return Vec::new();
        };
        let running = state.running.clone();
        let mut restarted = Vec::new();
        for replica in state.replicas.iter_mut() {
            let dead = match replica.process.is_alive() {
                Ok(alive) => !alive,
                Err(_) => true,
            };
            if dead {
                if let Ok(process) = running.spawn_process(&[replica.port.to_string()]) {
                    replica.process = process;
                    restarted.push(replica.node.to_string());
                }
            }
        }
        restarted
    }

    /// Sweep every reconciled workload for dead replicas and restart them.
    /// Driven periodically by the node's boot loop.
    pub fn reconcile_all_restarts(&mut self) -> Vec<String> {
        let handle = self.runtime.handle().clone();
        let _guard = handle.enter();
        let names: Vec<String> = self.workloads.keys().cloned().collect();
        let mut restarted = Vec::new();
        for name in names {
            restarted.extend(self.reconcile_restarts_entered(&name));
        }
        restarted
    }

    /// The observable replica snapshot for `name`.
    fn observe(&mut self, name: &str) -> Vec<ReplicaObservation> {
        let Some(state) = self.workloads.get_mut(name) else {
            return Vec::new();
        };
        let digest_hex = encode_hex(state.digest.as_bytes());
        let mut out = Vec::new();
        for r in state.replicas.iter_mut() {
            let pid = r.process.pid().unwrap_or(0);
            out.push(ReplicaObservation {
                workload: name.to_owned(),
                node: r.node.to_string(),
                pid,
                port: r.port,
                image_digest: digest_hex.clone(),
            });
        }
        out
    }

    /// The observable snapshot across ALL reconciled workloads — what the
    /// black-box HTTP oracle serves.
    pub fn observe_all(&mut self) -> Vec<ReplicaObservation> {
        let names: Vec<String> = self.workloads.keys().cloned().collect();
        let mut out = Vec::new();
        for name in names {
            out.extend(self.observe(&name));
        }
        out
    }

    /// Render the oracle body: one `REPLICA` line per live replica, in the
    /// stable `REPLICA <workload> <node> pid=<pid> port=<port> digest=<hex>`
    /// form a black-box harness greps — the same shape as the streamdb
    /// scenario's log oracles.
    pub fn render_oracle(&mut self) -> String {
        let mut lines = Vec::new();
        for obs in self.observe_all() {
            lines.push(format!(
                "REPLICA {} {} pid={} port={} digest={}",
                obs.workload, obs.node, obs.pid, obs.port, obs.image_digest
            ));
        }
        lines.push(format!("REPLICAS {}", lines.len()));
        lines.join("\n")
    }
}

/// A shared, thread-safe handle to the reconciler for the web plane + oracle.
pub type SharedReconciler = Arc<Mutex<WorkloadReconciler>>;

/// Claim a free localhost UDP port by binding then immediately dropping — the
/// spawned child binds it for real.
fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

/// Fetch `image_ref`'s bytes by CID over a real libp2p blob swarm: dial the
/// provider, request the digest over `/pillar/blob/1.0.0`, return the raw bytes
/// the provider answered (verified against the digest by the caller's
/// admission gate). Runs its own short-lived tokio runtime so it can be called
/// from the synchronous web-plane path.
fn fetch_blob(
    runtime: &tokio::runtime::Runtime,
    image_ref: &ImageRef,
) -> Result<Vec<u8>, ReconcileError> {
    let provider = image_ref.provider.clone();
    let digest = image_ref.digest.clone();

    async fn run(provider: Multiaddr, digest: BlobDigest) -> Result<Vec<u8>, ReconcileError> {
        let mut fetcher = build_blob_swarm(libp2p::identity::Keypair::generate_ed25519())
            .map_err(|e| ReconcileError::Fetch(e.to_string()))?;

        // Split off the /p2p/<peer-id> component to learn the provider PeerId.
        let mut dial_addr = provider.clone();
        let provider_peer_id = match dial_addr.pop() {
            Some(Protocol::P2p(peer_id)) => peer_id,
            _ => {
                return Err(ReconcileError::Fetch(
                    "provider multiaddr must terminate in /p2p/<peer-id>".to_owned(),
                ))
            }
        };
        fetcher
            .dial(provider.clone())
            .map_err(|e| ReconcileError::Fetch(format!("dial: {e}")))?;

        let fetched = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                match fetcher.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. }
                        if peer_id == provider_peer_id =>
                    {
                        fetcher.behaviour_mut().blob.send_request(
                            &provider_peer_id,
                            BlobRequest {
                                digest: digest.clone(),
                            },
                        );
                    }
                    SwarmEvent::Behaviour(BlobBehaviourEvent::Blob(
                        libp2p::request_response::Event::Message {
                            message: libp2p::request_response::Message::Response { response, .. },
                            ..
                        },
                    )) => {
                        return response.bytes;
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| ReconcileError::Fetch("timed out fetching blob".to_owned()))?;

        fetched.ok_or_else(|| ReconcileError::Fetch("provider did not serve the blob".to_owned()))
    }

    // Run the fetch on the reconciler's own persistent runtime.
    runtime.block_on(run(provider, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let bytes = vec![0u8, 1, 2, 255, 128, 16];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes));
    }

    #[test]
    fn image_ref_parses_blob_reference() {
        let digest = BlobDigest::of(b"hello-image");
        let addr: Multiaddr =
            "/ip4/127.0.0.1/tcp/40001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn"
                .parse()
                .unwrap();
        let image = ImageRef::encode(&addr, &digest);
        let parsed = ImageRef::parse(&image).expect("blob ref parses");
        assert_eq!(parsed.provider, addr);
        assert_eq!(parsed.digest, digest);
    }

    #[test]
    fn plain_image_is_not_fetchable() {
        assert_eq!(ImageRef::parse("app:v1"), None);
        assert_eq!(ImageRef::parse("blob:nonsense"), None);
    }

    #[test]
    fn reconciler_admits_under_a_stable_subject() {
        let a = WorkloadReconciler::new(b"seed-abc", NodeId::from("node-a"));
        let b = WorkloadReconciler::new(b"seed-abc", NodeId::from("node-a"));
        assert_eq!(a.controller_node(), b.controller_node());
    }
}
