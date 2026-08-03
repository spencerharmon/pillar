//! Reconciling controller — the vertical slice that ties every Pillar layer
//! together into one authorization decision.
//!
//! A workload declaration (a [`WorkloadSpec`]: which OCI image to run, on
//! which peer) is published as an ordinary content-addressed op on the
//! streaming DB (`pillar_streamdb`). A [`Controller`] running on the target
//! peer reconciles that declaration into a [`RunningWorkload`]. The whole
//! point of this crate is that reconciliation is *not* a bare "start the
//! container" call: it passes, in order, through every safety layer the rest
//! of the codebase formalizes, and refuses the moment any one of them is not
//! satisfied. The vertical is:
//!
//! ```text
//!   substrate     — the image bytes are pulled over the libp2p blob
//!                   request/response protocol (crates/pillar-net::blob) and
//!                   verified against their content address before they may
//!                   run (AdmittedFetch::run).
//!        |
//!   coordination  — running a workload is an EXCLUSIVE (non-idempotent,
//!                   exactly-once) side effect, so the controller must hold
//!                   the quorum-fenced lease for the epoch it acts in
//!                   (pillar_coordination::LeaseRegister). A minority
//!                   partition never acquires the lease and so never runs the
//!                   singleton — no split brain.
//!        |
//!   view          — the declaration is read through a View over the stream,
//!                   and that view's policy must ADMIT the workload's side
//!                   effect. A stream classified Relaxed (AP) refuses an
//!                   exclusive workload outright (pillar_core::ViewPolicy).
//!        |
//!   controller    — the controller acts under a node SUBKEY that must be both
//!                   admitted by the identity registry AND explicitly granted
//!                   the `workload:run` capability. Bare admission confers no
//!                   authority (pillar_identity::capability).
//!        |
//!   workload      — only once all of the above hold does the image become a
//!                   RunningWorkload, stamped with the epoch it was authorized
//!                   under.
//! ```
//!
//! Reconciliation is split into two steps so the pure authorization decision
//! is unit-testable without a network, while the integration test drives the
//! real transport between them:
//!
//! 1. [`Controller::authorize_fetch`] runs every non-network gate (identity /
//!    capability, view policy, coordination lease, target-node match) and, on
//!    success, yields an [`AdmittedFetch`] — the *authorization* to pull the
//!    declared image digest, and nothing more.
//! 2. The caller pulls the bytes for [`AdmittedFetch::digest`] over the libp2p
//!    blob substrate, then [`AdmittedFetch::run`] verifies those bytes hash to
//!    the authorized digest and produces the [`RunningWorkload`].

#![forbid(unsafe_code)]

use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId, SideEffect};
use pillar_identity::capability::{Capability, CapabilityRegistry, ScopeError};
use pillar_identity::{NodeSubkey, Registry};
use pillar_net::BlobDigest;
use pillar_streamdb::View;

/// The capability a subkey must hold to run a workload through a controller.
///
/// Named once here so the declaration side (whoever grants it) and the
/// enforcement side ([`Controller::authorize_fetch`]) cannot drift.
pub const RUN_WORKLOAD_CAPABILITY: &str = "workload:run";

/// A declared workload: run `image` on `target_node`, whose side-effect class
/// is `effect`.
///
/// Rides the streaming DB as an ordinary op payload — [`encode`](Self::encode)
/// / [`decode`](Self::decode) are the pure, dependency-free wire format, the
/// same pattern `pillar_net::overlay::MeshPeerRecord` uses so declarations
/// need no bespoke transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadSpec {
    name: String,
    target_node: NodeId,
    image: BlobDigest,
    effect: SideEffect,
}

impl WorkloadSpec {
    /// Declare `name` to run `image` on `target_node`, with side-effect class
    /// `effect`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        target_node: NodeId,
        image: BlobDigest,
        effect: SideEffect,
    ) -> Self {
        WorkloadSpec {
            name: name.into(),
            target_node,
            image,
            effect,
        }
    }

    /// The workload's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The node this workload is declared to run on.
    #[must_use]
    pub fn target_node(&self) -> &NodeId {
        &self.target_node
    }

    /// The content address of the OCI image to run.
    #[must_use]
    pub fn image(&self) -> BlobDigest {
        self.image
    }

    /// The workload's side-effect class.
    #[must_use]
    pub fn effect(&self) -> SideEffect {
        self.effect
    }

    /// Encode to a streaming-DB op payload: newline-delimited UTF-8
    /// (`name`, `target_node`, `image-digest`, `effect`), dependency-free so
    /// the declaration can ride any content-addressed op log.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let effect = match self.effect {
            SideEffect::Exclusive => "exclusive",
            SideEffect::Convergent => "convergent",
        };
        format!(
            "{}\n{}\n{}\n{}",
            self.name, self.target_node.0, self.image.0, effect
        )
        .into_bytes()
    }

    /// Decode a payload previously produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`SpecDecodeError`] if the payload is not valid UTF-8, is
    /// missing a field, or has a malformed digest or effect token.
    pub fn decode(bytes: &[u8]) -> Result<Self, SpecDecodeError> {
        let text = std::str::from_utf8(bytes).map_err(|_| SpecDecodeError::NotUtf8)?;
        let mut lines = text.lines();
        let name = lines.next().ok_or(SpecDecodeError::MissingField)?;
        let target = lines.next().ok_or(SpecDecodeError::MissingField)?;
        let image = lines.next().ok_or(SpecDecodeError::MissingField)?;
        let effect = lines.next().ok_or(SpecDecodeError::MissingField)?;
        let image = image
            .parse::<u64>()
            .map_err(|_| SpecDecodeError::InvalidDigest)?;
        let effect = match effect {
            "exclusive" => SideEffect::Exclusive,
            "convergent" => SideEffect::Convergent,
            _ => return Err(SpecDecodeError::InvalidEffect),
        };
        Ok(WorkloadSpec {
            name: name.to_owned(),
            target_node: NodeId(target.to_owned()),
            image: BlobDigest(image),
            effect,
        })
    }
}

/// A [`WorkloadSpec::decode`] failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecDecodeError {
    /// The payload was not valid UTF-8.
    NotUtf8,
    /// A required field line was absent.
    MissingField,
    /// The image digest field was not a valid u64 content address.
    InvalidDigest,
    /// The effect field was neither `exclusive` nor `convergent`.
    InvalidEffect,
}

impl std::fmt::Display for SpecDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            SpecDecodeError::NotUtf8 => "workload spec payload was not valid UTF-8",
            SpecDecodeError::MissingField => "workload spec payload was missing a field",
            SpecDecodeError::InvalidDigest => "workload spec image digest was not a valid u64",
            SpecDecodeError::InvalidEffect => "workload spec effect was not exclusive/convergent",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SpecDecodeError {}

/// Why reconciliation refused to run a declared workload.
///
/// Each variant is exactly one safety layer of the vertical saying "no"; a
/// successful reconcile means every layer said "yes".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileError {
    /// The controller subkey is not admitted, or not granted the
    /// `workload:run` capability — the controller layer's authority gate.
    Unauthorized(ScopeError),
    /// The workload is declared for a different node than this controller
    /// runs on: a controller only reconciles its own peer's workloads.
    NotTargetNode {
        /// The node the workload was declared for.
        declared: NodeId,
        /// The node this controller acts as.
        controller: NodeId,
    },
    /// The stream's view policy does not admit the workload's side effect —
    /// e.g. an exclusive workload declared on a Relaxed (AP) stream. The view
    /// layer's admission gate.
    ViewRefusedEffect {
        /// The effect the workload requires.
        effect: SideEffect,
    },
    /// The workload is exclusive but the controller does not hold the
    /// coordination lease for the epoch it is acting in — the coordination
    /// layer's exclusivity gate. A minority partition lands here and refuses
    /// to run the singleton.
    NotLeaseHolder {
        /// The epoch the controller tried to act under.
        epoch: Epoch,
    },
    /// The bytes pulled over the substrate do not hash to the authorized image
    /// digest — the substrate layer's content-addressing gate. A peer can
    /// never be tricked into running the wrong image for a digest.
    ImageDigestMismatch {
        /// The digest the workload declared (and was authorized for).
        expected: BlobDigest,
        /// The digest the pulled bytes actually hash to.
        actual: BlobDigest,
    },
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::Unauthorized(e) => {
                write!(
                    f,
                    "controller subkey not authorized to run workloads: {e:?}"
                )
            }
            ReconcileError::NotTargetNode {
                declared,
                controller,
            } => write!(
                f,
                "workload declared for node {declared} but controller runs as {controller}"
            ),
            ReconcileError::ViewRefusedEffect { effect } => {
                write!(f, "stream view policy refuses a {effect:?} workload effect")
            }
            ReconcileError::NotLeaseHolder { epoch } => write!(
                f,
                "controller does not hold the coordination lease for epoch {epoch:?}"
            ),
            ReconcileError::ImageDigestMismatch { expected, actual } => write!(
                f,
                "pulled image bytes hash to {actual:?}, not the authorized {expected:?}"
            ),
        }
    }
}

impl std::error::Error for ReconcileError {}

/// A controller acting under an admitted, capability-granted node subkey.
#[derive(Clone, Debug)]
pub struct Controller {
    subkey: NodeSubkey,
    action: Capability,
}

impl Controller {
    /// A controller that acts under `subkey`, enforcing the standard
    /// [`RUN_WORKLOAD_CAPABILITY`].
    #[must_use]
    pub fn new(subkey: NodeSubkey) -> Self {
        Controller {
            subkey,
            action: Capability::from(RUN_WORKLOAD_CAPABILITY),
        }
    }

    /// The node identity this controller acts as.
    #[must_use]
    pub fn node(&self) -> NodeId {
        self.subkey.node_id()
    }

    /// Run every non-network safety gate against `spec`, read through `view`,
    /// authorizing the controller to PULL the declared image.
    ///
    /// In order: the controller subkey must be admitted by `identity` and
    /// granted `workload:run` by `caps`; the workload must target this
    /// controller's node; the `view`'s policy must admit the workload's side
    /// effect; and, for an exclusive workload, the controller must hold the
    /// `lease` for `epoch`. On success the returned [`AdmittedFetch`] carries
    /// only the authorization to fetch the image digest — the bytes are pulled
    /// over the substrate and verified separately by [`AdmittedFetch::run`].
    ///
    /// # Errors
    ///
    /// Returns the [`ReconcileError`] for the first gate that refuses.
    pub fn authorize_fetch(
        &self,
        identity: &Registry,
        caps: &CapabilityRegistry,
        lease: &LeaseRegister,
        epoch: Epoch,
        view: &View<'_>,
        spec: &WorkloadSpec,
    ) -> Result<AdmittedFetch, ReconcileError> {
        // Controller layer: the subkey must be admitted AND explicitly granted
        // the run-workload capability. Bare admission is not enough.
        let node = caps
            .authorize(identity, &self.subkey, &self.action)
            .map_err(ReconcileError::Unauthorized)?;

        // A controller only reconciles workloads declared for its own peer.
        if spec.target_node != node {
            return Err(ReconcileError::NotTargetNode {
                declared: spec.target_node.clone(),
                controller: node,
            });
        }

        // View layer: the stream's policy must admit this workload's side
        // effect (a Relaxed/AP stream refuses an exclusive workload).
        if !view.admits(spec.effect) {
            return Err(ReconcileError::ViewRefusedEffect {
                effect: spec.effect,
            });
        }

        // Coordination layer: an exclusive workload is a fenced singleton — the
        // controller may run it only while it holds the lease for `epoch`.
        if spec.effect == SideEffect::Exclusive && lease.holder(epoch) != Some(&node) {
            return Err(ReconcileError::NotLeaseHolder { epoch });
        }

        Ok(AdmittedFetch {
            node,
            spec: spec.clone(),
            epoch,
        })
    }
}

/// The authorization to pull and run a specific workload image, produced by
/// [`Controller::authorize_fetch`] once every non-network gate has passed.
///
/// It grants nothing beyond fetching [`digest`](Self::digest); the bytes must
/// still verify against it in [`run`](Self::run) before the workload runs.
#[derive(Clone, Debug)]
pub struct AdmittedFetch {
    node: NodeId,
    spec: WorkloadSpec,
    epoch: Epoch,
}

impl AdmittedFetch {
    /// The content address of the image the controller is authorized to pull
    /// over the substrate.
    #[must_use]
    pub fn digest(&self) -> BlobDigest {
        self.spec.image
    }

    /// The node the workload will run on.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Verify `image_bytes` (pulled over the substrate) against the authorized
    /// digest and produce the [`RunningWorkload`].
    ///
    /// This is the substrate layer's final gate: the controller re-derives the
    /// content address of the received bytes and refuses to run them unless it
    /// matches the digest it was authorized for, so a peer can never be tricked
    /// into running the wrong image.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcileError::ImageDigestMismatch`] if the bytes do not hash
    /// to the authorized digest.
    pub fn run(self, image_bytes: Vec<u8>) -> Result<RunningWorkload, ReconcileError> {
        let actual = BlobDigest::of(&image_bytes);
        if actual != self.spec.image {
            return Err(ReconcileError::ImageDigestMismatch {
                expected: self.spec.image,
                actual,
            });
        }
        Ok(RunningWorkload {
            name: self.spec.name,
            node: self.node,
            image: self.spec.image,
            image_bytes,
            epoch: self.epoch,
        })
    }
}

/// A workload that reconciliation has actually started: every safety layer
/// admitted it, its image was pulled and content-verified, and it is stamped
/// with the coordination epoch it was authorized under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningWorkload {
    name: String,
    node: NodeId,
    image: BlobDigest,
    image_bytes: Vec<u8>,
    epoch: Epoch,
}

impl RunningWorkload {
    /// The workload's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The node it is running on.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// The content address of the image it is running.
    #[must_use]
    pub fn image(&self) -> BlobDigest {
        self.image
    }

    /// The verified image bytes it is running.
    #[must_use]
    pub fn image_bytes(&self) -> &[u8] {
        &self.image_bytes
    }

    /// The coordination epoch it was authorized under.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_coordination::LeaseRegister;
    use pillar_identity::{Signature, UserPrimary};
    use pillar_net::BlobStore;
    use pillar_streamdb::Stream;

    const IMAGE: &[u8] = b"oci-image-layer-payload-v1";

    /// Build an identity registry admitting a controller node and a foreign
    /// node under the same registered primary, plus the capability registry
    /// (nothing granted yet).
    fn admitted() -> (Registry, NodeSubkey, NodeSubkey) {
        let mut reg = Registry::new();
        let primary = UserPrimary::from("op-primary");
        let controller = NodeSubkey::from("controller-node");
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
        caps.grant(
            controller.clone(),
            Capability::from(RUN_WORKLOAD_CAPABILITY),
        );
        caps
    }

    /// A 3-node lease register in which `holder` has acquired `epoch`.
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

    /// Append a spec to a strict stream and return (stream, digest).
    fn declare(stream: &mut Stream, spec: &WorkloadSpec) {
        stream
            .try_append(spec.encode(), spec.effect())
            .expect("strict stream admits the declaration");
    }

    /// The declaration round-trips through the streaming DB op payload.
    #[test]
    fn spec_round_trips_through_stream_payload() {
        let spec = WorkloadSpec::new(
            "web",
            NodeId::from("controller-node"),
            BlobDigest::of(IMAGE),
            SideEffect::Exclusive,
        );
        let decoded = WorkloadSpec::decode(&spec.encode()).unwrap();
        assert_eq!(decoded, spec);
    }

    #[test]
    fn decode_rejects_malformed_payload() {
        assert_eq!(
            WorkloadSpec::decode(b"only-a-name"),
            Err(SpecDecodeError::MissingField)
        );
        assert_eq!(
            WorkloadSpec::decode(b"n\nnode\nnot-a-number\nexclusive"),
            Err(SpecDecodeError::InvalidDigest)
        );
        assert_eq!(
            WorkloadSpec::decode(b"n\nnode\n42\nmysterious"),
            Err(SpecDecodeError::InvalidEffect)
        );
    }

    /// The happy path across every layer: admitted+granted controller, strict
    /// view, held lease, digest-verified image -> a RunningWorkload stamped
    /// with the epoch.
    #[test]
    fn full_vertical_authorizes_and_runs() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);

        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("web", controller.node(), digest, SideEffect::Exclusive);

        let mut stream = Stream::new(); // strict by default
        declare(&mut stream, &spec);
        let view = stream.view();

        let admitted = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &view, &spec)
            .expect("all gates admit");
        assert_eq!(admitted.digest(), digest);

        // Pull the image from a content-addressed store (the substrate stand-in
        // for the integration test's real libp2p fetch) and run it.
        let mut store = BlobStore::new();
        store.insert(IMAGE.to_vec());
        let bytes = store.get(admitted.digest()).unwrap().to_vec();

        let running = admitted.run(bytes).expect("verified image runs");
        assert_eq!(running.node(), &controller.node());
        assert_eq!(running.image(), digest);
        assert_eq!(running.image_bytes(), IMAGE);
        assert_eq!(running.epoch(), epoch);
    }

    /// Controller layer: an admitted subkey that was never granted the
    /// capability cannot run a workload (never ambient authority).
    #[test]
    fn ungranted_controller_is_unauthorized() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = CapabilityRegistry::new(); // nothing granted
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let spec = WorkloadSpec::new(
            "web",
            controller.node(),
            BlobDigest::of(IMAGE),
            SideEffect::Exclusive,
        );
        let stream = Stream::new();
        let err = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &stream.view(), &spec)
            .unwrap_err();
        assert!(matches!(err, ReconcileError::Unauthorized(_)));
    }

    /// Controller layer: a workload declared for a different node is refused by
    /// this controller.
    #[test]
    fn workload_for_other_node_is_refused() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let spec = WorkloadSpec::new(
            "web",
            NodeId::from("some-other-peer"),
            BlobDigest::of(IMAGE),
            SideEffect::Exclusive,
        );
        let stream = Stream::new();
        let err = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &stream.view(), &spec)
            .unwrap_err();
        assert!(matches!(err, ReconcileError::NotTargetNode { .. }));
    }

    /// View layer: an exclusive workload declared on a Relaxed (AP) stream is
    /// refused — the view will not admit the effect. (The declaration itself is
    /// also refused by the stream, so we build the relaxed view directly.)
    #[test]
    fn relaxed_view_refuses_exclusive_workload() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let spec = WorkloadSpec::new(
            "singleton",
            controller.node(),
            BlobDigest::of(IMAGE),
            SideEffect::Exclusive,
        );
        let relaxed = Stream::with_policy(pillar_core::ViewPolicy::Relaxed);
        let err = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &relaxed.view(), &spec)
            .unwrap_err();
        assert_eq!(
            err,
            ReconcileError::ViewRefusedEffect {
                effect: SideEffect::Exclusive
            }
        );
    }

    /// Coordination layer: an exclusive workload is refused when the controller
    /// does not hold the lease for the epoch — a minority partition never runs
    /// the singleton.
    #[test]
    fn minority_without_lease_refuses_exclusive_workload() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        // Minority: only one of three voters backs the controller, so it never
        // acquires the lease.
        let mut lease = LeaseRegister::new(3);
        lease
            .grant(NodeId::from("v1"), controller.node(), epoch)
            .unwrap();
        assert!(!lease.try_acquire(&controller.node(), epoch));

        let spec = WorkloadSpec::new(
            "singleton",
            controller.node(),
            BlobDigest::of(IMAGE),
            SideEffect::Exclusive,
        );
        let mut stream = Stream::new();
        declare(&mut stream, &spec);
        let err = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &stream.view(), &spec)
            .unwrap_err();
        assert_eq!(err, ReconcileError::NotLeaseHolder { epoch });
    }

    /// A CONVERGENT workload needs no lease: idempotent effects run under a
    /// relaxed view without holding the coordination core.
    #[test]
    fn convergent_workload_runs_without_lease() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = LeaseRegister::new(3); // nobody holds anything

        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("replica", controller.node(), digest, SideEffect::Convergent);
        let relaxed = Stream::with_policy(pillar_core::ViewPolicy::Relaxed);
        let admitted = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &relaxed.view(), &spec)
            .expect("convergent workload needs no lease");
        let running = admitted.run(IMAGE.to_vec()).unwrap();
        assert_eq!(running.image(), digest);
    }

    /// Substrate layer: bytes that do not hash to the authorized digest are
    /// refused — a peer cannot be tricked into running the wrong image.
    #[test]
    fn wrong_image_bytes_are_refused() {
        let (identity, controller_key, _foreign) = admitted();
        let caps = granted(&controller_key);
        let controller = Controller::new(controller_key);
        let epoch = Epoch(1);
        let lease = lease_held_by(&controller.node(), epoch);
        let digest = BlobDigest::of(IMAGE);
        let spec = WorkloadSpec::new("web", controller.node(), digest, SideEffect::Exclusive);
        let mut stream = Stream::new();
        declare(&mut stream, &spec);
        let admitted = controller
            .authorize_fetch(&identity, &caps, &lease, epoch, &stream.view(), &spec)
            .unwrap();
        let err = admitted.run(b"tampered-image".to_vec()).unwrap_err();
        assert!(matches!(err, ReconcileError::ImageDigestMismatch { .. }));
    }
}
