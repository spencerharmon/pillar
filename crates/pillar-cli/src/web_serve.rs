//! Serves the web PORTAL from the deployed `pillar node run` process on a
//! configurable, **non-loopback** bind (`--web-bind`/`PILLAR_WEB_BIND`), so a
//! k8s Service can reach it (flux's `pillar-web-ingress-tls` gates on this).
//!
//! `pillar --web` (see `pillar-cli/src/main.rs`) stays localhost-only for the
//! no-identity-yet bootstrap flow; THIS surface is the one that leaves the
//! host, and it never inherits that surface's loopback exemption.
//!
//! ## Node-side custody login (the REVISED model)
//!
//! This portal implements **node-side key custody on a trusted node** (see
//! [`pillar_web::node_custody`], refining `specs/NodeCustodyLogin.tla`). It
//! SUPERSEDES the old client-side model that asked for THREE fields (handle +
//! CID + password). The user now supplies exactly **TWO** inputs — a user
//! identifier and an unlock factor (password/passkey); **no CID field** (a
//! third field would be a bug for a trusted node). The NODE resolves the
//! user's node-sealed key offer from the cell DB (CID → sealed blob), strips
//! the node-seal with its node key, unlocks the operational key SERVER-SIDE
//! (argon2id last line), signs the origin+expiry nonce, runs the shared
//! WoT/RBAC decider, and admits the user into an authenticated portal view
//! greeting them by handle with node management. Nonce/sign/verify stay hidden
//! plumbing.
//!
//! SECURITY MODEL — the password crosses TLS to the trusted node, which holds
//! the key ONLY because the cell sealed an offer to it (per-node, revocable —
//! that per-node seal IS the access control), NOT a blanket leak. Client-side
//! signing / caBLE ([`pillar_web::key_login`]) remains only the
//! untrusted/foreign-node path; passkey/WebAuthn stays an optional stronger
//! unlock factor.
//!
//! ## First-run bootstrap (operator-driven)
//!
//! On a FRESH, unbootstrapped node the `/` page guides the OPERATOR to (a)
//! create the cell, then (b) create the first user in the same guided step,
//! which links cell↔initial-user and CONSUMES the one-shot
//! `cell_key_can_create_user` capability (auto-flips false after the first
//! create — see [`pillar_web::node_custody::CellBootstrap`]). A bootstrapped
//! node shows the two-field login screen directly. The swarm DELIVERS this
//! flow; it never runs it — the operator drives it.
//!
//! ## Transport: HTTP/1.1
//!
//! The surface speaks HTTP/1.1 so a browser, `curl`, or a k8s Ingress can
//! reach it. Endpoints:
//!
//! - `GET /` — the graphical portal UI (HTML, 200): the two-field login (or,
//!   on a fresh node, the create-cell → create-first-user bootstrap flow).
//! - `GET /nonce` — a fresh origin/expiry-bound challenge nonce; body
//!   `NONCE <id> <expiry>`.
//! - `POST /login` — body `<identifier>\n<password>`: node-side custody
//!   login; 200 `OK` (+ `X-Pillar-Session`) with the greeted handle, or 401
//!   `DENIED <reason>`.
//! - `GET /bootstrap/status` — `FRESH` (unbootstrapped) or `BOOTSTRAPPED`.
//! - `POST /bootstrap/create` — body `<cell-id>\n<handle>\n<password>`: the
//!   ONE atomic bootstrap the portal drives — create the cell AND the first
//!   user together, so a reload between steps can never strand a cell with no
//!   first user. 200 `OK BOOTSTRAPPED <handle>` or 409 `DENIED <reason>`.
//! - `POST /bootstrap/create-cell` — body `<cell-id>`: operator step (a), the
//!   lower-level cell-only step (also used by the CLI + request flow).
//! - `POST /bootstrap/create-user` — body `<handle>\n<password>`: operator
//!   step (b), consuming the one-shot capability AND, atomically, applying
//!   the key-distribution label to this node + escrowing the new user's
//!   node-sealed operational-key offer to it, so this node can resolve it at
//!   the very next login.
//! - Every portal mutation (member add/role, custody migrate/rotate/seal/
//!   revoke, attestation build, identity enroll/rotate/recover) is a REAL
//!   signed act: gated through
//!   [`pillar_web::authorize_nonloopback_signing_action`] (a non-loopback
//!   peer must present an admitted session), then decider-authorized by
//!   [`WebAuthContext::perform_signed_act`] — the SAME `pillar_rbac`
//!   WoT/RBAC decider the CLI acts use — before it emits ONE signed event
//!   naming the act to this node's portal act log. The result renders
//!   provenance: the signer, the exercised WoT authority, and the event's
//!   CID. There is no `/ping` demonstration stub — every mutation goes
//!   through this real path, and an unauthorized act is refused with a
//!   clear message (never silently dropped).
//!
//! ## Identity & domain UI, and user/member management (ROI "Web portal / UI
//! ## rework", low priority)
//!
//! `GET /` also renders an **identity & domain** tile and a **members** tile
//! for an admitted session, backed by [`pillar_identity::global_identity::IdentityLog`]
//! — the same CID-addressed self-certifying log `specs/GlobalIdentity.tla`
//! models. No server-side database: every mutating action here is a signed
//! act over that in-process log (or the `layouts` streaming-DB resource);
//! nothing is persisted to a relational store.
//!
//! - `GET /portal/identity` — the identity view: the stable global CID, the
//!   current primary generation, and every certified per-domain key (the
//!   "multi-domain view": one global identity across its domains/cells with
//!   per-domain keys).
//! - `POST /portal/identity/enroll` — body `<token>\n<domain>`: certify ONE
//!   per-domain operational subkey for `domain`, signed by the current
//!   primary.
//! - `POST /portal/identity/rotate` — body `<token>\n<new-primary>`: rotate
//!   the primary, signed by the CURRENT primary. The global CID is invariant
//!   across the rotation (it addresses the genesis, never the current key).
//! - `POST /portal/identity/recover` — body `<token>`: rotate using the
//!   genesis-committed recovery key (when the current primary is lost), also
//!   CID-preserving.
//! - `GET /portal/domains` — the domain (**naming-only**) grouping view: for
//!   each domain, the cells it groups. Per `naming-authority-plane-spec` a
//!   domain here is NAMING-only: this view exposes NO domain-signing /
//!   granting / coordinating action — it is a read tile only, never a route
//!   that signs on a domain's behalf (property: a domain signs nothing).
//! - `GET /portal/members` — list this cell's members and their roles.
//! - `POST /portal/members/add` — body `<token>\n<handle>\n<role>`: add or
//!   invite a member with a role, as a signed act (requires an admitted
//!   session; refused unauthorized).
//! - `POST /portal/members/role` — body `<token>\n<handle>\n<role>`: change
//!   an existing member's role, as a signed act (refused unauthorized, and
//!   for an unknown member).
//!
//! ## Resource / workload UI (ROI "Web portal / UI rework", low priority)
//!
//! `GET /` also drives a **resource/workload** panel reusing the CLI's
//! polymorphic verb surface ([`crate::resource::ResourcePlane`] over the SAME
//! signed, WoT/RBAC-authorized [`crate::Platform`] a manifest apply rides).
//! Views sign nothing; acts emit exactly ONE decider-authorized signed event
//! (an unauthorized act appends nothing). No server-side database — resource
//! state is folded from the platform's append-only signed event log, and
//! UI-persisted layouts ride the signed IPFS+streaming-DB `layouts` resource.
//!
//! - `GET /portal/resource/get?token&kind[&selector]` — list a kind's objects
//!   (`kind/name replicas=N` lines) with an `EVENTS <n>` trailer proving the
//!   view signed nothing. Polymorphic over workload AND identity kinds.
//! - `GET /portal/resource/describe?token&kind&name` — full detail INCLUDING
//!   provenance (signer + authorizing capability + event CID).
//! - `GET /portal/resource/dry-run?token` — the `--dry-run`-style PREDICTED
//!   decider decision, signing nothing; equals the enforced act's outcome.
//! - `GET /portal/resource/{logs,exec,forward}?token&name[&cmd|&port]` — reach
//!   a running workload's runtime; signs nothing.
//! - `POST /portal/resource/{apply,edit,scale,rollout}` — body
//!   `<token>\n<name>\n<arg>`: a signed act emitting exactly one
//!   decider-authorized event (`EVENT <cid>`); refused (403) unauthorized.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::Instant;

use pillar_bootstrap::custody::parse_custody_kind;
use pillar_bootstrap::{
    BootstrapRequestId, BootstrapRequestKind, BootstrapRequestQueue, CustodyKind, NodeIdentity,
    RequestError,
};
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};
use pillar_eventlog::{Author, EventId, EventLog};
use pillar_identity::global_identity::{
    Domain as IdentityDomain, Genesis as IdentityGenesis, IdentityLog, KeyId as IdentityKeyId,
    Rotation as IdentityRotation,
};
use pillar_identity::session_registry::{RevokeError, Session, SessionRegistry};
use pillar_identity::NodeSubkey;
use pillar_rbac::{
    default_resource_class_policies, Capability as RbacCapability, Decision, PolicyEvent,
    PolicyTarget, RbacDecider, Request as RbacRequest, ResourceClass,
};
use pillar_streamdb::{OpId, OpLog};
use pillar_trust_artifacts::{
    parse_quota, Attest, Capacity as TrustCapacity, Cid as TrustCid, GraphEdge, Predicate,
    Proof as TrustProof, Sig as TrustSig, TrustError, TrustStore,
};
use pillar_web::key_login::{LoginSession, Origin};
use pillar_web::node_custody::{
    BootstrapError, CellBootstrap, CellNameRegistry, CellNameStatus, Cid, InMemoryCellNameRegistry,
    NodeCustodyError, NodeCustodySession, NodeCustodyVerifier, NodeKey, CELL_NAME_IN_USE_MESSAGE,
};
use pillar_web::{authorize_nonloopback_signing_action, bind_web};
use pillar_wot_authority::{FencedActor, WotAuthority};

use crate::observability_ui::ObservabilityBuilders;
use crate::resource::{Address, ResourceError, ResourcePlane, Selector};
use crate::Platform;
use pillar_manifest::{
    Crd, FieldType, Metadata as CrdMetadata, Schema, SchemaRegistry, Value as CrdValue,
};
use pillar_observability::SignalKind;
use pillar_topology::{
    Assignment as TopologyAssignment, Label as TopologyLabel, Mismatch as TopologyMismatch,
    TierHierarchy, Topology as TopologyRegistry, ATTEST_ACTION as TOPOLOGY_ATTEST_ACTION,
};

/// A read-only snapshot of this node's identity/reachability, as the
/// authenticated portal renders it: [`NodeId`]-derived peer id, the
/// multiaddrs this node listens on, and the peers it currently considers
/// connected. Real values are supplied by the boot-time `pillar-net` swarm
/// (see `crates/pillar-cli/src/run.rs`); the default here is an empty view
/// (a node with no configured listen/dial peers yet) until wired via
/// [`WebAuthContext::with_identity`].
#[derive(Clone, Debug, Default)]
pub struct NodeIdentitySnapshot {
    /// This node's libp2p-style peer id (derived from its identity keypair).
    pub peer_id: String,
    /// The multiaddrs this node listens on.
    pub listen_addrs: Vec<String>,
    /// The peers this node currently considers connected (peer ids).
    pub connected_peers: Vec<String>,
}

/// The server-side state the node-side-custody portal needs: the node-custody
/// verifier (holding this node's node key + its cell-DB view of node-sealed
/// offers), the shared WoT authority/actor login admission resolves through
/// (never a parallel one), the one-shot bootstrap capability state, and the
/// admitted portal sessions keyed by the bearer token handed to the client.
pub struct WebAuthContext {
    verifier: NodeCustodyVerifier,
    authority: WotAuthority,
    actor: FencedActor,
    bootstrap: CellBootstrap,
    /// The best-effort, peer-sourced cell-name registry the create-cell step
    /// queries BEFORE generating the cell key, so the web-UI bootstrap enforces
    /// the SAME network name-uniqueness rule as the CLI (both call the shared
    /// [`CellBootstrap::create_cell_checked`]). A real node resolves the
    /// pillar-scoped cell-name pointer over the swarm; the default here is an
    /// empty [`InMemoryCellNameRegistry`] (every name FREE) until a swarm-backed
    /// resolver is injected via [`WebAuthContext::with_cell_name_registry`].
    name_registry: Box<dyn CellNameRegistry + Send + Sync>,
    /// Admitted node-custody portal sessions, keyed by the `X-Pillar-Session`
    /// bearer. HTTP is connection-per-request, so an admitted session must
    /// outlive the connection it was minted on.
    sessions: HashMap<String, NodeCustodySession>,
    /// The `pillar_web` login-session view (for the shared non-loopback gate).
    login_sessions: HashMap<String, LoginSession>,
    next_session: u64,
    /// The node/user bootstrap-request queue for the cell this node serves.
    /// `None` until the cell is created (a request joins an EXISTING cell).
    requests: Option<BootstrapRequestQueue>,
    /// This node's identity/reachability snapshot (PeerId, listen addrs, the
    /// peers it considers connected) — the authenticated portal's "node
    /// status" tile reads this. Defaults empty; wire the real swarm-derived
    /// values via [`WebAuthContext::with_identity`].
    identity: NodeIdentitySnapshot,
    /// When this context was created — the portal reports uptime as the
    /// elapsed time since.
    started_at: Instant,
    /// The quorum-fenced lease register backing the portal's "lease holder"
    /// tile (see `pillar-coordination`). A fresh node is its own single
    /// voter/candidate, self-granting `lease_epoch` at construction so a
    /// solo node reports itself as holder; a real multi-node cell wires
    /// additional voters over the streaming DB / gossip layer.
    lease: LeaseRegister,
    /// The epoch the portal reads the lease holder at.
    lease_epoch: Epoch,
    /// UI-persisted layouts, stored as signed, content-addressed ops riding
    /// the streaming DB (`pillar-streamdb`) — never a server-side database.
    /// Each stored op's payload is `<signer-handle>\n<layout-content>`; its
    /// content-addressed [`OpId`] is the resource's CID, and
    /// `OpLog::root()` is the resource's streaming tip.
    layouts: OpLog,
    /// The authenticated session's global identity log — the identity &
    /// domain UI's substrate (enroll/rotate/recover, per-domain keys).
    identity_log: IdentityLog,
    /// A domain (naming-only) grouping: the cells each domain names. Grown
    /// only by `enroll` (never a domain-signing action) — a domain here is
    /// purely a naming label over a set of cells, per
    /// `naming-authority-plane-spec`.
    domain_cells: BTreeMap<String, Vec<String>>,
    /// This cell's members and their roles — the user/member management UI's
    /// substrate. `(handle -> role)`.
    members: BTreeMap<String, String>,
    /// The server-side, per-principal [`SessionRegistry`] (ROI "Web portal /
    /// UI rework: Session management UI") — the session-management panel's
    /// substrate: lists every ADMITTED-login-token's principal's active
    /// sessions with a countdown-able expiry, and backs individual
    /// (`revoke <id>`) and sign-out-everywhere (`revoke-all`) revocation. A
    /// portal session token doubles as this registry's slot id, so revoking
    /// it here is what makes the corresponding entry in `sessions` /
    /// `login_sessions` (the bearer-admission maps every other tile checks)
    /// fail closed. No server-side database — see module docs.
    session_registry: SessionRegistry,
    /// A monotonically increasing logical clock ticked on every mint —
    /// stands in for the wall clock so `issued_at`/`expiry` are deterministic
    /// in tests while still ordering real logins correctly.
    session_clock: u64,
    /// The trust & attestation UI's substrate (ROI "Web portal / UI rework":
    /// trust & attestation UI + trust-graph visualization) — every attest
    /// artifact issued through the attestation builder lives here,
    /// content-addressed, capacity-checked at signing time by
    /// `pillar-trust-artifacts`. Anchored at this node's WoT authority root
    /// (the `owner` `WebAuthContext::new` was constructed with), which
    /// unconditionally holds every capacity.
    trust: TrustStore,
    /// The key & offer UI's substrate (ROI "Web portal / UI rework": custody
    /// migration, rotation, seal/escrow, revoke) — a signed act per
    /// operation, keyed by handle. No server-side database: this is an
    /// in-process record mirroring the node-sealed offer the real
    /// `pillar_key_distribution`/`NodeCustodyVerifier` custodies.
    custody: BTreeMap<String, CustodyRecord>,
    /// The portal's real signed-action surface: every mutating portal act
    /// (member add/role, custody migrate/rotate/seal/revoke, attestation
    /// build, identity enroll/rotate/recover) that is authorized by
    /// [`Self::perform_signed_act`] emits exactly ONE signed
    /// [`pillar_eventlog::Event`] here, content-addressed and appended in
    /// this node's per-actor event-DAG — REPLACING the old `/ping`
    /// demonstration stub. No server-side database: this is the same
    /// append-only, hash-linked log every other Pillar layer signs into.
    act_log: EventLog,
    /// The kubectl-parity resource plane substrate (ROI "Web portal / UI
    /// rework": resource/workload UI). The SAME signed, WoT/RBAC-authorized
    /// [`Platform`] the CLI ([`crate::resource::ResourcePlane`]) acts against
    /// — so the web UI's get/apply/edit/scale/rollout/describe reuse the
    /// identical verb surface and the identical decider a manifest apply
    /// rides. Views sign nothing; acts emit exactly one decider-authorized
    /// signed event. No server-side database: state is folded from the
    /// platform's append-only signed event log.
    resource_platform: Platform,
    /// The `apiVersion` the resource plane's kinds share.
    resource_api: String,
    /// The WoT authority the resource plane authorizes acts against — the
    /// SAME graph the portal admits login subjects into, so a logged-in
    /// user's admitted subject IS an authorized resource actor and a
    /// non-admitted one is refused. Kept alongside so `admit_subject` can
    /// re-chain into a freshly rebuilt plane if needed.
    resource_authority: WotAuthority,
    /// The topology explorer's substrate (ROI "Web portal / UI rework": UI
    /// half of the P2 topology section) — the derived
    /// `region->...->rack->chassis->node` tier tree, declared/attested label
    /// assignments (attestation reuses `pillar_trust_artifacts` verbatim
    /// through `self.trust`, no new signing primitive), and the placement
    /// payoff (failure-domain spread/rollup) the explorer's overlays read.
    /// No server-side database: this is the same in-process registry a real
    /// node folds from its own topology-label event stream.
    topology: TopologyRegistry,
    /// Live per-node health status + capacity the explorer tree renders
    /// alongside each node's resolved placement path, and rolls up per tier.
    /// `node-id -> (health, capacity)`.
    topology_nodes: BTreeMap<String, (String, u64)>,
    /// The observability UI's substrate (ROI P3 addendum "Web portal / UI
    /// rework": observability explore/query/dashboard) — the five-kind
    /// (metric/log/trace/profile/metadata) explore+query builders layered over
    /// [`pillar_observability`], plus the signed streaming-DB resource logs the
    /// saved-query/dashboard builders persist to. Views (explore/query) sign
    /// nothing; a dashboard SAVE is ONE signed, content-addressed streaming-DB
    /// resource event — no server-side database, exactly like `layouts`.
    observability: ObservabilityBuilders,
}

/// One handle's custody record, as the key & offer UI renders/drives it: the
/// current holder node, the offer's [`TrustCid`], whether it is currently
/// sealed (escrowed) to that holder, and a monotonic rotation generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyRecord {
    /// The node currently custodying this handle's operational-key offer.
    pub holder: NodeId,
    /// The offer's content address.
    pub cid: Cid,
    /// Whether the offer is currently sealed (escrowed) to `holder`.
    pub sealed: bool,
    /// Bumped by every `rotate` — the current key-material generation.
    pub generation: u64,
}

/// The HTTP INGEST API surface's own EXPLICIT version stamp (ROI P1
/// "Versioning, compatibility & safe rollout") — versioned INDEPENDENTLY of
/// any event/message/body it carries. This is the distinct wire surface a
/// browser/`curl`/k8s Ingress speaks to this portal; it advances on its OWN
/// line (`v1`, `v2`, …) as request/response framing changes, unrelated to the
/// event-envelope or pillar-message version numbers. Every response advertises
/// it via [`API_VERSION_HEADER`], and a request MAY assert the version it
/// speaks; the server checks that assertion against `[MIN_API_VERSION,
/// API_VERSION]` with the shared [`pillar_crypto::SurfaceVersion`] primitive.
pub const API_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);
/// The OLDEST HTTP ingest API version this build still accepts on a request —
/// the low bound of the supported window (a version below it is
/// [`pillar_crypto::VersionError::Unsupported`], a retired surface). Currently
/// equal to [`API_VERSION`] (a single-version window), it moves independently
/// as old framings are retired.
pub const MIN_API_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);
/// The response/request header carrying the HTTP ingest API [`SurfaceVersion`]
/// stamp (rendered `vN` via its `Display`). Emitted on EVERY response so any
/// client can see the version it was served at; OPTIONALLY sent by a request
/// to assert the version it speaks (a request without it is served backward-
/// compatibly at [`API_VERSION`]).
const API_VERSION_HEADER: &str = "X-Pillar-Api-Version";

/// The `apiVersion` every resource-plane kind on the web UI shares.
const RESOURCE_API: &str = "pillar.dev/v1";
/// The capability every resource act is gated on, per the shared RBAC
/// resource-class policies (compute/network/storage).
const RESOURCE_CAP: &str = "resource/act";
/// A workload kind the resource UI drives (Deployment-like: a `replicas`
/// spec `scale`/`rollout` act over).
const WORKLOAD_KIND: &str = "Workload";
/// An identity-object kind the SAME verb surface is polymorphic over.
const IDENTITY_KIND: &str = "User";

/// Build the resource plane's schema registry: a workload kind (with an
/// `image` + `replicas` spec the UI scales/rolls-out) and an identity kind,
/// proving the plane is polymorphic over both.
fn resource_registry() -> SchemaRegistry {
    let mut reg = SchemaRegistry::new();
    reg.register(
        Schema::new(RESOURCE_API, WORKLOAD_KIND)
            .required("image", FieldType::String)
            .property("replicas", FieldType::Integer)
            .property("generation", FieldType::Integer),
    );
    reg.register(Schema::new(RESOURCE_API, IDENTITY_KIND).required("handle", FieldType::String));
    reg
}

/// A portal session-management panel's per-session view: `(id, node/domain,
/// issued-at, expiry, whether this IS the caller's own current session)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// The session id (== the portal bearer token it was minted for).
    pub id: String,
    /// The node/domain this session was issued on (this node's own peer id
    /// — a portal session is always local-node scoped).
    pub node: String,
    /// Logical issue time.
    pub issued_at: u64,
    /// Logical expiry time — the panel derives its live countdown from this.
    pub expiry: u64,
    /// Whether this is the session the panel's own caller is viewing under.
    pub is_current: bool,
}

/// The fixed session lifetime (logical-clock ticks) every portal login mints
/// under — long enough that a same-pass test sequence never trips it, short
/// enough to be a real bound.
const SESSION_TTL_TICKS: u64 = 1_000_000;

impl WebAuthContext {
    /// A fresh context for a node identified by `node`, holding node key
    /// `node_secret`, serving `origin`, with `owner` as the WoT authority root
    /// at `max_depth`. The node starts UNBOOTSTRAPPED (its `/` serves the
    /// create-cell → create-first-user flow) with no offers provisioned yet.
    #[must_use]
    pub fn new(
        origin: impl Into<String>,
        node: NodeId,
        node_secret: impl Into<String>,
        owner: NodeId,
        max_depth: u8,
    ) -> Self {
        let origin = origin.into();
        let owner_for_lease = owner.clone();
        let owner_for_trust = owner.clone();
        let owner_for_resource = owner.clone();
        let node_for_identity = node.clone();
        let authority = WotAuthority::new(owner, max_depth);
        // The resource plane authorizes acts against a WoT authority rooted at
        // the SAME owner (the login-admitted subject is chained into it too),
        // gated by the shared RBAC resource-class policies — so the web UI's
        // acts ride the identical decider a CLI/manifest apply does.
        let resource_authority = WotAuthority::new(owner_for_resource, max_depth);
        let resource_platform = Platform::new(
            resource_registry(),
            resource_authority.clone(),
            default_resource_class_policies(&RbacCapability(RESOURCE_CAP.to_owned())),
            Vec::new(),
        );
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        let node_key = NodeKey::new(node, node_secret);
        let mut lease = LeaseRegister::new(1);
        let lease_epoch = Epoch(1);
        // A solo node is its own voter and candidate: self-grant + acquire so
        // a fresh node reports itself as the lease holder out of the box.
        let _ = lease.grant(
            owner_for_lease.clone(),
            owner_for_lease.clone(),
            lease_epoch,
        );
        let _ = lease.try_acquire(&owner_for_lease, lease_epoch);
        WebAuthContext {
            verifier: NodeCustodyVerifier::new(node_key, Origin::from(origin.as_str())),
            authority,
            actor,
            bootstrap: CellBootstrap::new(),
            name_registry: Box::new(InMemoryCellNameRegistry::new()),
            sessions: HashMap::new(),
            login_sessions: HashMap::new(),
            next_session: 0,
            requests: None,
            identity: NodeIdentitySnapshot {
                peer_id: node_for_identity.to_string(),
                listen_addrs: Vec::new(),
                connected_peers: Vec::new(),
            },
            started_at: Instant::now(),
            lease,
            lease_epoch,
            layouts: OpLog::new(),
            identity_log: IdentityLog::genesis(IdentityGenesis {
                initial_primary: IdentityKeyId::from("primary:0"),
                recovery: Some(IdentityKeyId::from("recovery")),
            }),
            domain_cells: BTreeMap::new(),
            members: BTreeMap::new(),
            session_registry: SessionRegistry::new(),
            session_clock: 0,
            trust: TrustStore::new(owner_for_trust),
            custody: BTreeMap::new(),
            act_log: EventLog::new(),
            resource_platform,
            resource_api: RESOURCE_API.to_owned(),
            resource_authority,
            topology: TopologyRegistry::new(TierHierarchy::default()),
            topology_nodes: BTreeMap::new(),
            observability: ObservabilityBuilders::new(),
        }
    }

    /// Inject this node's real identity/reachability snapshot (PeerId, listen
    /// addrs, connected peers) as `run.rs` observes it from the live swarm.
    #[must_use]
    pub fn with_identity(mut self, identity: NodeIdentitySnapshot) -> Self {
        self.identity = identity;
        self
    }

    /// The current identity/reachability snapshot the portal renders.
    #[must_use]
    pub fn identity(&self) -> &NodeIdentitySnapshot {
        &self.identity
    }

    /// Seconds elapsed since this context was created — the portal's uptime.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// The current holder of this node's lease epoch, if any.
    #[must_use]
    pub fn lease_holder(&self) -> Option<&NodeId> {
        self.lease.holder(self.lease_epoch)
    }

    /// Persist a UI layout as a signed, content-addressed op riding the
    /// streaming DB — no server-side database. `signer` is the authenticated
    /// handle that produced `content` (the portal only ever calls this for an
    /// admitted session). Returns the resource's content-addressed [`OpId`]
    /// (its CID).
    pub fn store_layout(&mut self, signer: &str, content: &str) -> OpId {
        let payload = format!("{signer}\n{content}");
        self.layouts.append(payload.into_bytes())
    }

    /// Resolve a previously stored layout by its CID, returning
    /// `(signer, content)`.
    #[must_use]
    pub fn get_layout(&self, id: &OpId) -> Option<(String, String)> {
        self.layouts
            .order()
            .into_iter()
            .find(|op| &op.id() == id)
            .and_then(|op| {
                let text = String::from_utf8_lossy(op.payload());
                let mut lines = text.splitn(2, '\n');
                let signer = lines.next()?.to_owned();
                let content = lines.next().unwrap_or("").to_owned();
                Some((signer, content))
            })
    }

    /// The streaming tip (Merkle root) of the layout resource log.
    #[must_use]
    pub fn layout_tip(&self) -> pillar_streamdb::MerkleRoot {
        self.layouts.root()
    }

    /// The observability explore builder for `kind`, rendered as one
    /// `SIGNAL <id> KIND <kind> PAYLOAD <payload>` line per held signal of
    /// that kind. A pure read — signs nothing.
    pub fn observability_explore(&mut self, kind: SignalKind) -> String {
        let mut body = String::new();
        for r in self.observability.explore(kind) {
            body.push_str(&format!(
                "SIGNAL {} KIND {} PAYLOAD {}\n",
                r.id.0,
                signal_kind_tag(kind),
                r.payload
            ));
        }
        body
    }

    /// The observability per-kind query builder: metric/log/trace substring
    /// query, profile `top`, or metadata entity query, rendered as text. A
    /// pure read — signs nothing.
    pub fn observability_query(&mut self, kind: SignalKind, filter: Option<&str>) -> String {
        let mut body = String::new();
        match kind {
            SignalKind::MetadataSample => {
                for (entity, view) in self.observability.metadata_query(filter) {
                    let labels = view
                        .current
                        .map(|ls| {
                            ls.iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    body.push_str(&format!("ENTITY {} LABELS {}\n", entity.0, labels));
                }
            }
            _ => {
                let records = match kind {
                    SignalKind::Metric => self.observability.metric_query(filter),
                    SignalKind::Log => self.observability.log_query(filter),
                    SignalKind::TraceSpan => self.observability.trace_search(filter),
                    // Profile has no substring query; `top <n>` is its query
                    // verb — an optional numeric `filter` picks `n`.
                    SignalKind::ProfileSample => {
                        let n = filter.and_then(|f| f.parse::<usize>().ok()).unwrap_or(20);
                        self.observability.profile_top(n)
                    }
                    SignalKind::MetadataSample => unreachable!("handled above"),
                };
                for r in records {
                    body.push_str(&format!(
                        "SIGNAL {} KIND {} PAYLOAD {}\n",
                        r.id.0,
                        signal_kind_tag(kind),
                        r.payload
                    ));
                }
            }
        }
        body
    }

    /// Persist a named observability dashboard as ONE signed, content-addressed
    /// streaming-DB resource (the SAME no-server-side-database pattern
    /// [`Self::store_layout`] uses for UI layouts): returns the resource's CID
    /// and the dashboard log's new streaming tip. The portal only ever calls
    /// this for an admitted session (`signer` is that session's handle).
    pub fn save_observability_dashboard(
        &mut self,
        signer: &str,
        name: &str,
        spec: &str,
    ) -> (OpId, pillar_streamdb::MerkleRoot) {
        let cid = self.observability.create_dashboard(signer, name, spec);
        (cid, self.observability.dashboard_tip())
    }

    /// Read-only access to this session's global identity log — the
    /// identity & domain UI's substrate.
    #[must_use]
    pub fn identity_log(&self) -> &IdentityLog {
        &self.identity_log
    }

    /// Enroll `domain`: certify ONE per-domain operational subkey, signed by
    /// the current primary, and register the domain's default cell in the
    /// naming-only grouping view. Errs exactly as
    /// [`IdentityLog::certify_domain_subkey`].
    pub fn identity_enroll(
        &mut self,
        domain: &str,
    ) -> Result<IdentityKeyId, pillar_identity::global_identity::IdentityLogError> {
        let issuer = self.identity_log.current_primary().clone();
        let subkey = IdentityKeyId::from(format!("sub:{domain}").as_str());
        self.identity_log.certify_domain_subkey(
            IdentityDomain::from(domain),
            subkey.clone(),
            &issuer,
        )?;
        self.domain_cells
            .entry(domain.to_owned())
            .or_default()
            .push(format!("{domain}-cell-1"));
        Ok(subkey)
    }

    /// Rotate the primary to `new_primary`, signed by the CURRENT primary.
    /// The global CID is unaffected. Returns the newly installed generation.
    pub fn identity_rotate(
        &mut self,
        new_primary: &str,
    ) -> Result<u64, pillar_identity::global_identity::IdentityLogError> {
        let signer = self.identity_log.current_primary().clone();
        self.identity_log.rotate(IdentityRotation::signed_by(
            IdentityKeyId::from(new_primary),
            signer.0,
        ))
    }

    /// Recover: rotate to a fresh primary using the genesis-committed
    /// recovery key (never the current primary). Errs
    /// [`pillar_identity::global_identity::IdentityLogError::UnauthorizedRotation`]
    /// if this identity has no recovery key.
    pub fn identity_recover(
        &mut self,
    ) -> Result<u64, pillar_identity::global_identity::IdentityLogError> {
        let recovery = self
            .identity_log
            .recovery_key()
            .cloned()
            .unwrap_or_else(|| IdentityKeyId::from("no-recovery-configured"));
        let gen = self.identity_log.head_generation() + 1;
        self.identity_log.rotate(IdentityRotation::signed_by(
            IdentityKeyId::from(format!("recovered-primary-{gen}").as_str()),
            recovery.0,
        ))
    }

    /// The domain (naming-only) grouping view: each domain's cells. Read-only
    /// — never grown by anything but `identity_enroll`, and exposes no
    /// domain-signing/granting/coordinating action.
    #[must_use]
    pub fn domain_cells(&self) -> &BTreeMap<String, Vec<String>> {
        &self.domain_cells
    }

    /// This cell's members and their roles.
    #[must_use]
    pub fn members(&self) -> &BTreeMap<String, String> {
        &self.members
    }

    /// Add or invite a member with `role` — a signed act (the caller already
    /// checked the presented session is admitted).
    pub fn add_member(&mut self, handle: &str, role: &str) {
        self.members.insert(handle.to_owned(), role.to_owned());
    }

    /// Change an existing member's role — a signed act. `false` if `handle`
    /// is not a known member (no-op).
    pub fn set_member_role(&mut self, handle: &str, role: &str) -> bool {
        if let Some(r) = self.members.get_mut(handle) {
            *r = role.to_owned();
            true
        } else {
            false
        }
    }

    /// The portal's single real signed-action gate: authorize `actor` for
    /// `capability` through the SAME `pillar_rbac` WoT/RBAC decider the CLI
    /// acts use (see `pillar-cli::Platform::apply`) — a subject reachable
    /// AT ALL in this node's WoT authority graph (`self.authority`, grown
    /// by `admit_subject` at login) satisfies the catch-all policy at
    /// `depth_threshold: 0`; a subject the graph has never admitted is
    /// refused, fail-closed, exactly like every other rung of the lattice
    /// when nothing authorizes it. On `Decision::Allow`, appends ONE signed
    /// event to [`Self::act_log`] naming this act (`payload`) and returns
    /// its content-addressed [`EventId`] for the caller to render as
    /// provenance. On `Decision::Deny`, mutates nothing and returns the
    /// refused actor.
    ///
    /// # Errors
    /// Returns `Err(actor.clone())` when the decider refuses `capability`
    /// to `actor`.
    pub fn perform_signed_act(
        &mut self,
        actor: &NodeId,
        capability: &str,
        payload: &str,
    ) -> Result<EventId, NodeId> {
        let policies = [PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: RbacCapability::from(capability),
            depth_threshold: 0,
        }];
        let decider = RbacDecider::new(&self.authority, &policies, &[]);
        let request = RbacRequest::new(actor.clone(), RbacCapability::from(capability));
        if decider.decide(&request) != Decision::Allow {
            return Err(actor.clone());
        }
        let author = Author(actor.to_string());
        Ok(self.act_log.append(&author, payload.as_bytes().to_vec()))
    }

    /// The exercised-authority sentence for `actor` — the WoT-reachable
    /// depth (from `self.authority`) that satisfied
    /// [`Self::perform_signed_act`]'s catch-all policy, rendered for the
    /// result's provenance line. Never fabricates a chain: an actor the
    /// graph does not admit renders as unreachable.
    #[must_use]
    pub fn exercised_authority(&self, actor: &NodeId) -> String {
        match self.authority.reachable_depth(actor) {
            Some(depth) => {
                format!("WoT-depth-default (reachable-depth {depth} satisfies threshold 0)")
            }
            None => "(unreachable; no authority to exercise)".to_owned(),
        }
    }

    /// The attestation builder — ROI "Web portal / UI rework: trust &
    /// attestation UI": composes and issues one [`Attest`] artifact,
    /// signed by `issuer` acting in `capacity` (`self`, or `<role>@<scope>`
    /// checked against the store's pure walk AT SIGNING TIME —
    /// [`TrustError::CapacityNotHeld`] if `issuer` does not currently hold
    /// it), authorizing `subject` to `action` over `resource` within
    /// `scope`, optionally quantified by `quota` (a budget, never a bare
    /// boolean — see `pillar_trust_artifacts::Predicate::with_quota`).
    /// `authority` is the proof-pointer [`TrustCid`] of the prior grant
    /// `issuer` is exercising (`None` for the genesis/self-capacity case).
    ///
    /// On success, renders BOTH the natural-language sentence AND the full
    /// [`TrustProof`] chain (via [`TrustStore::verify`]) — the builder's
    /// audit view.
    ///
    /// # Errors
    ///
    /// Propagates [`TrustError`] — notably [`TrustError::CapacityNotHeld`]
    /// when `issuer` does not (yet, or any longer) hold the declared
    /// capacity.
    #[allow(clippy::too_many_arguments)]
    pub fn build_attestation(
        &mut self,
        issuer: NodeId,
        capacity: TrustCapacity,
        authority: Option<TrustCid>,
        subject: NodeId,
        action: &str,
        resource: &str,
        quota: Option<u64>,
        scope: &str,
    ) -> Result<(TrustCid, TrustProof), TrustError> {
        let epoch = self.trust.epoch();
        let mut predicate = Predicate::new(action, resource);
        if let Some(q) = quota {
            predicate = predicate.with_quota(q);
        }
        let attest = Attest {
            issuer: issuer.clone(),
            capacity,
            authority,
            subject,
            predicate,
            scope: scope.to_owned(),
            epoch,
            sig: TrustSig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let _ = &issuer;
        let cid = self.trust.issue_attest(attest)?;
        let proof = self
            .trust
            .verify(&cid)
            .map_err(|_| TrustError::CapacityNotHeld {
                issuer: self.trust.genesis().clone(),
            })?;
        Ok((cid, proof))
    }

    /// The trust-graph visualization — a PURE view (no signing, no
    /// mutation): every currently-live attest as one edge `issuer ->
    /// subject`.
    #[must_use]
    pub fn trust_graph_edges(&self) -> Vec<GraphEdge> {
        self.trust.graph_edges()
    }

    /// Read-only access to the trust store, e.g. to re-render a builder
    /// result's proof chain.
    #[must_use]
    pub fn trust_store(&self) -> &TrustStore {
        &self.trust
    }

    /// Register (or update) a node's LIVE health status + capacity — the
    /// topology explorer tree's per-node leaf data (ROI "Web portal / UI
    /// rework": topology UI). A real node folds this from telemetry; the
    /// swarm's own tests/UI wiring drives it directly.
    pub fn topology_register_node(&mut self, node: &str, health: &str, capacity: u64) {
        self.topology_nodes
            .insert(node.to_owned(), (health.to_owned(), capacity));
    }

    /// Read-only access to the topology registry (hierarchy + resolved
    /// placements) — e.g. so a facet filter can resolve a tier=value
    /// membership set, or a workload panel can consume `spread`/
    /// `quorum_is_safe` directly.
    #[must_use]
    pub fn topology(&self) -> &TopologyRegistry {
        &self.topology
    }

    /// Self-declare topology labels for `node` — ADVISORY only, never a
    /// basis for safety-critical placement (attested labels take
    /// precedence; see [`TopologyRegistry::placement`]).
    pub fn topology_declare(&mut self, node: NodeId, labels: Vec<TopologyLabel>) {
        self.topology.declare(node, &labels);
    }

    /// Attest ONE topology label for `subject`, signed by `issuer` acting in
    /// `capacity` — checked against the trust store's pure walk AT SIGNING
    /// TIME exactly like [`WebAuthContext::build_attestation`], reusing the
    /// SAME `topology:label` attest predicate
    /// ([`pillar_topology::ATTEST_ACTION`]) rather than a new signing
    /// primitive. Records the issued attest into both the trust store (audit
    /// chain / trust-graph visualization) and the topology registry, which
    /// re-verifies the chain before recording (declared-vs-attested
    /// mismatches — see [`WebAuthContext::topology_mismatches`] — surface any
    /// disagreement with a prior self-declaration).
    ///
    /// # Errors
    ///
    /// Propagates [`TrustError`] — notably
    /// [`TrustError::CapacityNotHeld`] when `issuer` does not hold the
    /// declared capacity.
    pub fn topology_attest(
        &mut self,
        issuer: NodeId,
        capacity: TrustCapacity,
        authority: Option<TrustCid>,
        subject: NodeId,
        label: &TopologyLabel,
        scope: &str,
    ) -> Result<TrustCid, TrustError> {
        let epoch = self.trust.epoch();
        let attest = Attest {
            issuer: issuer.clone(),
            capacity,
            authority,
            subject,
            predicate: Predicate::new(TOPOLOGY_ATTEST_ACTION, label.resource()),
            scope: scope.to_owned(),
            epoch,
            sig: TrustSig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let _ = &issuer;
        let cid = self.trust.issue_attest(attest.clone())?;
        let assignment = TopologyAssignment::Attested {
            attest: Box::new(attest),
            cid: cid.clone(),
        };
        // The attest was just issued into THIS store under the capacity check
        // above, so its chain necessarily verifies here.
        self.topology
            .attest(&assignment, &self.trust)
            .expect("a just-issued, capacity-checked attest verifies through the same store");
        Ok(cid)
    }

    /// Every declared-vs-attested [`TopologyMismatch`] — the label editor's
    /// inline "declared X, attested Y" surfacing.
    #[must_use]
    pub fn topology_mismatches(&self) -> Vec<TopologyMismatch> {
        self.topology.mismatches()
    }

    /// Render the derived tier tree (CONFIG-ordered hierarchy — never
    /// hardcoded) with every registered node's resolved placement path, live
    /// health/capacity, and a per-`rollup_tier` capacity rollup.
    #[must_use]
    pub fn topology_tree(&self, rollup_tier: &str) -> String {
        let mut body = String::new();
        body.push_str(&format!(
            "TIERS {}\n",
            self.topology.hierarchy().tiers().join(",")
        ));
        let mut values: Vec<(NodeId, u64)> = Vec::new();
        for (node_str, (health, capacity)) in &self.topology_nodes {
            let node = NodeId::from(node_str.as_str());
            let path = self
                .topology
                .placement(&node)
                .path(self.topology.hierarchy())
                .iter()
                .map(TopologyLabel::resource)
                .collect::<Vec<_>>()
                .join(",");
            body.push_str(&format!(
                "NODE {node_str} PATH {path} HEALTH {health} CAPACITY {capacity}\n"
            ));
            values.push((node, *capacity));
        }
        for (domain, total) in self.topology.rollup(rollup_tier, &values) {
            let domain = if domain.is_empty() {
                "(unlabeled)".to_owned()
            } else {
                domain
            };
            body.push_str(&format!("ROLLUP {rollup_tier} {domain}={total}\n"));
        }
        body
    }

    /// The failure-domain overlay: for each of `nodes`, resolve its value at
    /// `tier`, then flag a SAME-failure-domain warning when 2+ nodes are
    /// given but fewer than 2 distinct domains are spanned (a workload's
    /// replicas landing entirely in one rack). Returns
    /// `(per-node domain assignment, warn)`.
    #[must_use]
    pub fn topology_failure_domain_overlay(
        &self,
        nodes: &[NodeId],
        tier: &str,
    ) -> (Vec<(NodeId, Option<String>)>, bool) {
        let assignments: Vec<(NodeId, Option<String>)> = nodes
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    self.topology.placement(n).at(tier).map(str::to_owned),
                )
            })
            .collect();
        let domains = self.topology.domains_at(tier, nodes);
        let warn = nodes.len() >= 2 && domains.len() < 2;
        (assignments, warn)
    }

    /// Nodes currently carrying `tier = value` in their RESOLVED placement —
    /// the facet primitive a workload/telemetry/logs panel filters by.
    #[must_use]
    pub fn topology_nodes_at(&self, tier: &str, value: &str) -> Vec<String> {
        self.topology_nodes
            .keys()
            .filter(|n| self.topology.placement(&NodeId::from(n.as_str())).at(tier) == Some(value))
            .cloned()
            .collect()
    }

    /// The key & offer UI's custody record for `handle`, if any.
    #[must_use]
    pub fn custody_of(&self, handle: &str) -> Option<&CustodyRecord> {
        self.custody.get(handle)
    }

    /// Custody migration — ROI "Web portal / UI rework: key & offer UI": move
    /// `handle`'s offer to a NEW holder node, replacing its content address.
    /// A signed act (the caller already checked the presented session is
    /// admitted); creates the record if `handle` has none yet.
    pub fn custody_migrate(&mut self, handle: &str, new_holder: NodeId, new_cid: Cid) {
        let generation = self.custody.get(handle).map_or(0, |r| r.generation);
        self.custody.insert(
            handle.to_owned(),
            CustodyRecord {
                holder: new_holder,
                cid: new_cid,
                sealed: true,
                generation,
            },
        );
    }

    /// Custody rotation: reseal `handle`'s offer under fresh key material
    /// (a new content address) to its SAME current holder, bumping the
    /// generation counter. `false` if `handle` has no custody record yet.
    pub fn custody_rotate(&mut self, handle: &str, new_cid: Cid) -> bool {
        if let Some(r) = self.custody.get_mut(handle) {
            r.cid = new_cid;
            r.generation += 1;
            r.sealed = true;
            true
        } else {
            false
        }
    }

    /// Seal/escrow: mark `handle`'s existing custody record sealed (escrowed)
    /// to its current holder. `false` if `handle` has no custody record.
    pub fn custody_seal_escrow(&mut self, handle: &str) -> bool {
        if let Some(r) = self.custody.get_mut(handle) {
            r.sealed = true;
            true
        } else {
            false
        }
    }

    /// Revoke: drop `handle`'s custody record entirely — fail-closed, the
    /// same handle resolves no offer from this node from this point on.
    /// `false` if `handle` had no custody record.
    pub fn custody_revoke(&mut self, handle: &str) -> bool {
        self.custody.remove(handle).is_some()
    }

    /// Chain `subject` to the authority root at `level`, admitting it as
    /// WoT-authoritative — required before a login for its operational subkey
    /// can admit.
    pub fn admit_subject(&mut self, subject: NodeId, level: u8) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject.clone(), level);
        self.actor.refresh(&self.authority);
        // Mirror the admission into the resource plane's authority so the
        // logged-in subject is an authorized resource actor too, and rebuild
        // the plane's platform over the updated authority. Admission always
        // precedes any resource act (login happens before the UI acts), so no
        // already-emitted resource event is ever discarded here — asserted by
        // rebuilding only while the plane's event log is still empty.
        let resource_root = self.resource_authority.owner().clone();
        self.resource_authority
            .issue_edge(resource_root, subject, level);
        if self.resource_platform.event_count() == 0 {
            self.resource_platform = Platform::new(
                resource_registry(),
                self.resource_authority.clone(),
                default_resource_class_policies(&RbacCapability(RESOURCE_CAP.to_owned())),
                Vec::new(),
            );
        }
    }

    // ---- resource / workload UI (kubectl-parity, ROI "Web portal / UI rework") --

    /// The number of signed resource events emitted so far — a view NEVER
    /// changes this; only a decider-authorized act does. Used to assert the
    /// views-vs-acts split at the UI layer.
    #[must_use]
    pub fn resource_event_count(&self) -> usize {
        self.resource_platform.event_count()
    }

    /// `get <kind> [-l sel] [-L cols]` (VIEW): list objects of a kind, one
    /// `kind/name replicas` line each. Signs nothing.
    #[must_use]
    pub fn resource_get(&self, kind: &str, selector: &Selector) -> Vec<String> {
        let mut out = Vec::new();
        for (key, env) in self.resource_platform.view() {
            if key.api_version != self.resource_api || key.kind != kind {
                continue;
            }
            if !selector.matches(&env.body().metadata.labels) {
                continue;
            }
            let replicas = env.body().spec.get("replicas").and_then(|v| match v {
                CrdValue::Integer(n) => Some(*n),
                _ => None,
            });
            match replicas {
                Some(n) => out.push(format!("{kind}/{} replicas={n}", key.name)),
                None => out.push(format!("{kind}/{}", key.name)),
            }
        }
        out
    }

    /// `describe <kind>/<name>` (VIEW): full detail INCLUDING provenance —
    /// the signer (which subkey authorized the last change), the authorizing
    /// capability, and the event CID of the record in force. Signs nothing.
    #[must_use]
    pub fn resource_describe(&self, kind: &str, name: &str) -> Option<String> {
        self.resource_platform
            .describe(&self.resource_api, kind, name)
    }

    /// The `--dry-run`-style preview of an act: the decider's ALLOW/DENY for
    /// `actor` WITHOUT signing or appending anything, returned as the PREDICTED
    /// decision. The enforced act (below) runs the SAME decider, so a UI can
    /// assert `predicted == enforced`. Signs nothing.
    #[must_use]
    pub fn resource_dry_run(&self, actor: &NodeId) -> bool {
        self.resource_platform.authorized(actor, RESOURCE_CAP)
    }

    fn workload_body(&self, name: &str, image: &str, replicas: i64) -> Crd {
        Crd::new(&self.resource_api, WORKLOAD_KIND, CrdMetadata::new(name))
            .with_spec("image", CrdValue::String(image.to_owned()))
            .with_spec("replicas", CrdValue::Integer(replicas))
    }

    /// `apply` (ACT): declarative upsert of a workload, emitting exactly one
    /// decider-authorized signed event if `actor` is authorized; an
    /// unauthorized act appends nothing. Returns the event CID string.
    pub fn resource_apply(
        &mut self,
        actor: &NodeId,
        name: &str,
        image: &str,
        replicas: i64,
    ) -> Result<String, ResourceError> {
        let body = self.workload_body(name, image, replicas);
        let mut plane = ResourcePlane::new(&mut self.resource_platform, &self.resource_api);
        plane
            .apply(actor, RESOURCE_CAP, body)
            .map(|applied| format!("{}", applied.event.0))
    }

    /// `edit` (ACT): apply an edited workload body (here, a new image) as one
    /// signed patch act — reuses the same authorized apply path as `apply`.
    pub fn resource_edit(
        &mut self,
        actor: &NodeId,
        name: &str,
        new_image: &str,
    ) -> Result<String, ResourceError> {
        let mut plane = ResourcePlane::new(&mut self.resource_platform, &self.resource_api);
        plane
            .patch(
                actor,
                RESOURCE_CAP,
                &Address::new(WORKLOAD_KIND, name),
                "image",
                CrdValue::String(new_image.to_owned()),
            )
            .map(|applied| format!("{}", applied.event.0))
    }

    /// `scale --replicas N` (ACT): emit one signed scale event.
    pub fn resource_scale(
        &mut self,
        actor: &NodeId,
        name: &str,
        replicas: i64,
    ) -> Result<String, ResourceError> {
        let mut plane = ResourcePlane::new(&mut self.resource_platform, &self.resource_api);
        plane
            .scale(
                actor,
                RESOURCE_CAP,
                &Address::new(WORKLOAD_KIND, name),
                replicas,
            )
            .map(|applied| format!("{}", applied.event.0))
    }

    /// `rollout restart` (ACT): bump the workload's `pillar.dev/restarted-at`
    /// generation as one signed event — a rollout is just an authorized
    /// re-apply through the same decider, so it is a decider-authorized act
    /// exactly like scale/edit.
    pub fn resource_rollout(
        &mut self,
        actor: &NodeId,
        name: &str,
    ) -> Result<String, ResourceError> {
        let generation = self
            .resource_platform
            .get(&self.resource_api, WORKLOAD_KIND, name)
            .and_then(|c| c.spec.get("generation").cloned())
            .and_then(|v| match v {
                CrdValue::Integer(n) => Some(n),
                _ => None,
            })
            .unwrap_or(0)
            + 1;
        let mut plane = ResourcePlane::new(&mut self.resource_platform, &self.resource_api);
        plane
            .patch(
                actor,
                RESOURCE_CAP,
                &Address::new(WORKLOAD_KIND, name),
                "generation",
                CrdValue::Integer(generation),
            )
            .map(|applied| format!("{}", applied.event.0))
    }

    /// `logs`/`exec`/`port-forward` (VIEW-shaped runtime reach): these reach a
    /// RUNNING workload's runtime rather than the signed manifest log, so they
    /// sign nothing. They succeed only for a workload that exists in the view
    /// (a proxy for "running"), returning the runtime stream text; a missing
    /// workload is [`ResourceError::NotFound`].
    pub fn resource_logs(&self, name: &str) -> Result<String, ResourceError> {
        self.reach_running(name, "LOGS")
    }

    /// `exec <cmd>` into a running workload — signs nothing (runtime reach).
    pub fn resource_exec(&self, name: &str, cmd: &str) -> Result<String, ResourceError> {
        self.reach_running(name, &format!("EXEC {cmd}"))
    }

    /// `port-forward` to a running workload — signs nothing (runtime reach).
    pub fn resource_forward(&self, name: &str, port: u16) -> Result<String, ResourceError> {
        self.reach_running(name, &format!("FORWARD {port}"))
    }

    fn reach_running(&self, name: &str, what: &str) -> Result<String, ResourceError> {
        if self
            .resource_platform
            .get(&self.resource_api, WORKLOAD_KIND, name)
            .is_some()
        {
            Ok(format!("{what} {WORKLOAD_KIND}/{name}"))
        } else {
            Err(ResourceError::NotFound(Address::new(WORKLOAD_KIND, name)))
        }
    }

    /// Test-only: admit `subject` into the LOGIN custody authority ONLY (so it
    /// can log in) WITHOUT granting it any resource-plane authority — the
    /// resource decider then refuses its acts. Chains at level 0 (farthest
    /// from the root) so even the login authority barely admits it.
    #[cfg(test)]
    pub fn admit_subject_login_only(&mut self, subject: NodeId) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject, 0);
        self.actor.refresh(&self.authority);
    }

    /// Test-only: an actor authorized on the resource plane (the owner root).
    #[cfg(test)]
    #[must_use]
    pub fn identity_actor_for_test(&self) -> NodeId {
        self.resource_authority.owner().clone()
    }

    /// Test-only: seed an identity-kind object through the shared resource
    /// plane, proving the get/describe verbs are polymorphic over it.
    #[cfg(test)]
    pub fn apply_identity_for_test(&mut self, actor: &NodeId, handle: &str) {
        let body = Crd::new(&self.resource_api, IDENTITY_KIND, CrdMetadata::new(handle))
            .with_spec("handle", CrdValue::String(format!("@{handle}")));
        let mut plane = ResourcePlane::new(&mut self.resource_platform, &self.resource_api);
        plane
            .apply(actor, RESOURCE_CAP, body)
            .expect("owner authorized to seed identity");
    }

    /// Provision a node-sealed key offer this node custodies (the cell sealed
    /// it to THIS node): the user `identifier` (greeted by `handle`) resolves
    /// to `cid`, whose blob unlocks the operational `subkey` under `password`
    /// (`secret` = the operational-key material). In a real node the label +
    /// offer arrive via `pillar_key_distribution`.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: pillar_identity::NodeSubkey,
        password: &str,
        secret: &str,
    ) {
        self.verifier
            .provision_offer(identifier, handle, cid, subkey, password, secret);
    }

    /// Mutable access to the one-shot bootstrap capability state — the `/`
    /// bootstrap flow drives this.
    pub fn bootstrap_mut(&mut self) -> &mut CellBootstrap {
        &mut self.bootstrap
    }

    /// Step (b) of the bootstrap flow, DONE ATOMICALLY: create the first user
    /// AND seal their operational key's offer to THIS node — applying the
    /// key-distribution label + escrowing the node-sealed L1 offer (per the
    /// always-node-sealed offer mechanism) — so the very node that created
    /// the user can immediately resolve, strip, and unlock it at first login.
    /// Without this, a fresh bootstrap node correctly reports the untrusted-
    /// node `no-offer-for-user` mode even for the user it just created — the
    /// observed bug. Shared by both the CLI and the web-UI create-first-user
    /// steps (crates/pillar-cli/src/web_serve.rs) so neither drifts.
    ///
    /// `password` is the user's chosen unlock factor (never retained in the
    /// clear beyond this call); the scoped, revocable OPERATIONAL key is what
    /// gets escrowed — the cold root is never touched, and node authority is
    /// unchanged (this node only ever holds what the cell explicitly seals to
    /// it, per-node/opt-in/revocable).
    ///
    /// # Errors
    ///
    /// Propagates [`BootstrapError`] from the underlying [`CellBootstrap`]
    /// step (no cell yet / capability already spent) — the offer is escrowed
    /// only once that step succeeds.
    pub fn bootstrap_create_first_user(
        &mut self,
        handle: impl Into<String>,
        password: &str,
    ) -> Result<(), BootstrapError> {
        let handle = handle.into();
        self.bootstrap.create_first_user(handle.clone())?;

        // (1) Apply the key-distribution label: chain the new user's
        // operational subkey into the WoT authority at the root's own
        // budget, so it is authoritative once admitted.
        let subkey = NodeSubkey::from(format!("op-subkey-{handle}").as_str());
        let level = self.authority.max_depth();
        self.admit_subject(subkey.node_id(), level);

        // (2) Escrow the scoped operational key as a node-sealed L1 offer to
        // THIS bootstrap node's own node key — the per-node seal IS the
        // access control; no other node custodies this offer.
        let cid = Cid::from(format!("cid-{handle}").as_str());
        let secret = format!("operational-key-material-{handle}");
        self.provision_offer(handle.clone(), handle, cid, subkey, password, &secret);

        Ok(())
    }

    /// The bootstrap capability state.
    #[must_use]
    pub fn bootstrap(&self) -> &CellBootstrap {
        &self.bootstrap
    }

    /// Inject the swarm-backed cell-name registry used for the create-cell
    /// network name-uniqueness pre-check. A real node passes a resolver that
    /// queries the pillar-scoped cell-name pointer over the swarm; tests pass a
    /// deterministic [`InMemoryCellNameRegistry`].
    #[must_use]
    pub fn with_cell_name_registry(
        mut self,
        registry: Box<dyn CellNameRegistry + Send + Sync>,
    ) -> Self {
        self.name_registry = registry;
        self
    }

    /// The create-cell step BOTH surfaces route through: run the shared network
    /// name-uniqueness pre-check (`CellBootstrap::create_cell_checked` over this
    /// context's registry) BEFORE the cell key is generated, refusing a name a
    /// peer already serves. This is the single shared implementation the web UI
    /// uses; the CLI bootstrap calls the same `create_cell_checked`.
    ///
    /// # Errors
    ///
    /// The matching [`BootstrapError`] — notably
    /// [`BootstrapError::CellNameInUse`] when the network already claims it.
    /// A live, best-effort peer-sourced lookup of whether a proposed cell NAME
    /// is already claimed on the network — the SAME `name_registry` (and thus
    /// the same peer resolution) [`WebAuthContext::create_cell`] validates
    /// against, exposed for the web UI's INLINE pre-submit uniqueness hint. Per
    /// the best-effort rule, an unreachable / no-peer-serving name resolves
    /// [`CellNameStatus::Free`], so the hint never blocks a create merely
    /// because the network could not be reached.
    #[must_use]
    pub fn name_status(&self, name: &NodeId) -> CellNameStatus {
        self.name_registry.lookup(name)
    }

    /// Create a cell, enforcing name-registry uniqueness.
    pub fn create_cell(&mut self, cell: NodeId) -> Result<(), BootstrapError> {
        self.bootstrap
            .create_cell_checked(cell.clone(), self.name_registry.as_ref())?;
        // The cell now exists: open the bootstrap-request queue for it so fresh
        // nodes/users can request to join.
        self.requests = Some(BootstrapRequestQueue::new(cell, std::iter::empty()));
        Ok(())
    }

    /// The ONE atomic bootstrap step the web portal drives: create the cell AND
    /// the first user in a single call, so the node is only ever FRESH or fully
    /// BOOTSTRAPPED — never stranded with a cell but no first user (the bug the
    /// split create-cell/create-user flow left behind when the operator hit the
    /// back button / reloaded between the two steps). If a cell already exists
    /// from an older half-completed bootstrap, the cell step is skipped and only
    /// the missing first-user step runs, so this endpoint also RECOVERS such a
    /// stranded node.
    ///
    /// # Errors
    ///
    /// Propagates [`BootstrapError`] — a name a peer already serves
    /// ([`BootstrapError::CellNameInUse`]) from the cell step, or a spent
    /// capability from the first-user step.
    pub fn bootstrap_cell_and_first_user(
        &mut self,
        cell: NodeId,
        handle: &str,
        password: &str,
    ) -> Result<(), BootstrapError> {
        if self.bootstrap.cell().is_none() {
            self.create_cell(cell)?;
        }
        self.bootstrap_create_first_user(handle, password)
    }

    fn store_session(&mut self, session: NodeCustodySession) -> String {
        let token = format!("s{}", self.next_session);
        self.next_session += 1;
        // Mirror a `pillar_web` login-session view keyed by the same token so
        // the shared non-loopback signing gate can resolve it.
        self.login_sessions.insert(
            token.clone(),
            LoginSession {
                subject: session.subject.clone(),
                nonce_id: session.nonce_id,
                watermark: session.watermark,
            },
        );
        // Mint the SAME token as a slot id in the server-side
        // `SessionRegistry`, principal-keyed on the admitted subject — the
        // session-management panel's substrate (list/revoke/revoke-all).
        let issued_at = self.session_clock;
        self.session_clock += 1;
        self.session_registry.mint(
            session.subject.to_string(),
            token.clone(),
            issued_at,
            issued_at + SESSION_TTL_TICKS,
        );
        self.sessions.insert(token.clone(), session);
        token
    }

    fn login_session_for(&self, token: &str) -> Option<&LoginSession> {
        self.login_sessions.get(token)
    }

    /// Drop token `token`'s admitted-session bearer state — the shared step
    /// [`revoke_session`](Self::revoke_session) and
    /// [`revoke_all_sessions`](Self::revoke_all_sessions) both take after
    /// bumping the [`SessionRegistry`]'s revocation stamp, so every OTHER
    /// tile's admission check (`login_session_for`, `perform_signed_act`, layout, member
    /// management, …) fails closed on the very next call — the registry
    /// revocation and the bearer-map drop happen atomically in the same
    /// call, never one without the other.
    fn drop_session_bearer(&mut self, token: &str) {
        self.login_sessions.remove(token);
        self.sessions.remove(token);
    }

    /// Every currently-active session belonging to `principal` (the
    /// session-management panel's list), each flagged whether it is
    /// `viewer_token`'s own current session.
    #[must_use]
    pub fn list_sessions(&self, principal: &str, viewer_token: &str) -> Vec<SessionSummary> {
        let now = self.session_clock;
        self.session_registry
            .ls(principal, now)
            .into_iter()
            .map(|s: &Session| SessionSummary {
                id: s.id.clone(),
                node: self.identity.peer_id.clone(),
                issued_at: s.issued_at,
                expiry: s.expiry,
                is_current: s.id == viewer_token,
            })
            .collect()
    }

    /// Revoke exactly ONE of `principal`'s sessions by id — a
    /// decider-authorized act (the caller already proved `principal` via
    /// their own admitted session; see `dispatch_sessions_revoke`). Bumps the
    /// registry's global epoch and drops the matching bearer-map entry so the
    /// session's bearer actions fail closed starting the very next call.
    ///
    /// # Errors
    ///
    /// [`RevokeError::NoSuchSession`] if `principal` has no session `id`.
    pub fn revoke_session(&mut self, principal: &str, id: &str) -> Result<(), RevokeError> {
        self.session_registry.revoke_one(principal, id)?;
        self.drop_session_bearer(id);
        Ok(())
    }

    /// Sign out everywhere: revoke every one of `principal`'s sessions
    /// atomically (one epoch bump), then drop each one's bearer-map entry so
    /// none of them admits any further bearer action.
    pub fn revoke_all_sessions(&mut self, principal: &str) {
        // Snapshot ids first (an immutable borrow over the pre-sweep active
        // set), then revoke + drop — avoids mutating `session_registry` and
        // `sessions`/`login_sessions` while still holding that borrow.
        let ids: Vec<String> = self
            .session_registry
            .ls(principal, self.session_clock)
            .into_iter()
            .map(|s| s.id.clone())
            .collect();
        self.session_registry.revoke_all(principal);
        for id in ids {
            self.drop_session_bearer(&id);
        }
    }
}

/// Bind the portal listener on `addr:port` — `addr` MAY be non-loopback (see
/// module docs); the caller must still gate every signing action through
/// [`authorize_nonloopback_signing_action`].
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the address/port cannot be bound.
pub fn bind(addr: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    bind_web(addr, port)
}

/// Serve HTTP/1.1 on `listener` until it errors or the process is torn down.
/// Blocking — run on a dedicated thread.
pub fn serve(listener: TcpListener, ctx: &mut WebAuthContext) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        handle_connection(stream, ctx);
    }
}

/// The graphical portal UI served at `GET /` — a real login page (two fields:
/// user identifier + unlock factor, NO CID), whose embedded script drives the
/// `GET /nonce` → `POST /login` handshake as hidden plumbing and, on success,
/// transitions into an authenticated portal view greeting the user by handle
/// with node management. On a FRESH node the same page guides the operator
/// through the create-cell → create-first-user bootstrap flow. The origin is
/// derived from the browser (`location`) at runtime, so no infrastructure
/// identifier is embedded in this public source.
const LANDING_PAGE: &str = include_str!("web_login.html");

/// A parsed HTTP request: method, path, body, and the OPTIONAL asserted HTTP
/// ingest API version ([`API_VERSION_HEADER`]).
struct HttpRequest {
    method: String,
    path: String,
    body: String,
    /// The raw `X-Pillar-Api-Version` header value the client sent, if any.
    /// `None` means the request asserted no version — served backward-
    /// compatibly at [`API_VERSION`]. `Some` is validated by
    /// [`dispatch_http`] (parsed, then bounds-checked against
    /// `[MIN_API_VERSION, API_VERSION]`).
    api_version: Option<String>,
}

/// Read and parse one HTTP/1.1 request from `reader`. Returns `None` on a
/// closed connection or an unparseable request line.
fn read_http_request(reader: &mut impl BufRead) -> Option<HttpRequest> {
    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    let mut api_version = None;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.trim().eq_ignore_ascii_case(API_VERSION_HEADER) {
                // Retain the raw value verbatim; legibility (parse) and
                // supported-window checks are `dispatch_http`'s job so it can
                // distinguish a malformed value (400) from a stamped-but-
                // unknown FUTURE version (505) — the two failure modes the
                // shared `pillar_crypto::VersionError` keeps distinct.
                api_version = Some(value.trim().to_owned());
            }
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_ok() {
            body = String::from_utf8_lossy(&buf).into_owned();
        }
    }

    Some(HttpRequest {
        method,
        path,
        body,
        api_version,
    })
}

/// An HTTP response to write back.
struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    session_token: Option<String>,
    body: String,
}

impl HttpResponse {
    fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
            API_VERSION_HEADER,
            API_VERSION,
        );
        if let Some(token) = &self.session_token {
            head.push_str(&format!("X-Pillar-Session: {token}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())?;
        stream.flush()
    }
}

fn handle_connection(mut stream: TcpStream, ctx: &mut WebAuthContext) {
    let Ok(peer) = stream.peer_addr() else { return };
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let Some(request) = read_http_request(&mut reader) else {
        return;
    };
    let response = dispatch_http(ctx, &peer, &request);
    let _ = response.write_to(&mut stream);
}

/// Map an HTTP request onto the portal action, preserving the auth gate.
fn dispatch_http(
    ctx: &mut WebAuthContext,
    peer: &SocketAddr,
    request: &HttpRequest,
) -> HttpResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    // Validate the OPTIONAL request-side API-version assertion BEFORE routing.
    // A request without the header is accepted (backward compatible) and served
    // at `API_VERSION`. A present header is checked with the shared
    // `pillar_crypto` primitive, which keeps the two failure modes distinct:
    //   * a malformed (illegible) value  → 400 Bad Request (a parse error),
    //   * a legible-but-unknown FUTURE (or retired) version → 505 HTTP Version
    //     Not Supported — a DISTINCT status from a 404/parse/malformed path so
    //     a newer client is told precisely which API version was rejected.
    if let Some(err) = check_request_api_version(request) {
        return err;
    }
    match (request.method.as_str(), path) {
        ("GET", "/") => HttpResponse {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            session_token: None,
            body: LANDING_PAGE.to_owned(),
        },
        ("GET", "/bootstrap/status") => {
            // BOOTSTRAPPED only once the first USER exists — not merely the
            // cell. A cell-created-but-no-user node is still FRESH so the
            // portal keeps showing the (atomic) bootstrap form; reporting
            // BOOTSTRAPPED on a cell alone is exactly what stranded the
            // operator (the login form showed but no user could log in).
            let status = if ctx.bootstrap().initial_user().is_some() {
                "BOOTSTRAPPED"
            } else {
                "FRESH"
            };
            text_response(200, "OK", status.to_owned())
        }
        ("POST", "/bootstrap/create-cell") => {
            let cell = request.body.trim();
            if cell.is_empty() {
                return text_response(400, "Bad Request", "MISSING cell id".to_owned());
            }
            match ctx.create_cell(NodeId::from(cell)) {
                Ok(()) => text_response(200, "OK", "CELL-CREATED".to_owned()),
                Err(BootstrapError::CellNameInUse) => text_response(
                    409,
                    "Conflict",
                    format!("DENIED {CELL_NAME_IN_USE_MESSAGE}"),
                ),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("GET", "/bootstrap/name-check") => {
            // INLINE, live cell-name uniqueness for the web UI: resolve the
            // proposed name through the SAME peer-sourced `name_registry` the
            // create-cell step validates against, so the operator sees an "in
            // use" hint BEFORE submit. Best-effort: an unreachable / free name
            // reports FREE (never blocks a create on a network hiccup).
            let name = query_value(&request.path, "name").unwrap_or("").trim();
            if name.is_empty() {
                return text_response(400, "Bad Request", "MISSING name".to_owned());
            }
            match ctx.name_status(&NodeId::from(name)) {
                CellNameStatus::Claimed => {
                    text_response(200, "OK", format!("IN-USE {CELL_NAME_IN_USE_MESSAGE}"))
                }
                CellNameStatus::Free => text_response(200, "OK", "FREE".to_owned()),
            }
        }
        ("POST", "/bootstrap/create-user") => {
            // Body: "<handle>\n<password>" — the operator's chosen unlock
            // factor for the new user, escrowed atomically (see
            // `bootstrap_create_first_user`) so login works immediately.
            let mut lines = request.body.lines();
            let handle = lines.next().unwrap_or("").trim();
            let password = lines.next().unwrap_or("").trim();
            if handle.is_empty() || password.is_empty() {
                return text_response(400, "Bad Request", "MISSING handle-or-password".to_owned());
            }
            match ctx.bootstrap_create_first_user(handle, password) {
                Ok(()) => text_response(200, "OK", format!("USER-CREATED {handle}")),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("POST", "/bootstrap/create") => {
            // Body: "<cell>\n<handle>\n<password>" — the ONE atomic bootstrap
            // action the portal uses (cell + first user together, so a reload
            // between steps can never strand a cell with no first user). See
            // `bootstrap_cell_and_first_user`.
            let mut lines = request.body.lines();
            let cell = lines.next().unwrap_or("").trim();
            let handle = lines.next().unwrap_or("").trim();
            let password = lines.next().unwrap_or("").trim();
            if cell.is_empty() || handle.is_empty() || password.is_empty() {
                return text_response(
                    400,
                    "Bad Request",
                    "MISSING cell-handle-or-password".to_owned(),
                );
            }
            match ctx.bootstrap_cell_and_first_user(NodeId::from(cell), handle, password) {
                Ok(()) => text_response(200, "OK", format!("BOOTSTRAPPED {handle}")),
                Err(BootstrapError::CellNameInUse) => text_response(
                    409,
                    "Conflict",
                    format!("DENIED {CELL_NAME_IN_USE_MESSAGE}"),
                ),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("GET", "/nonce") => {
            let nonce = ctx.verifier.issue_nonce(u64::MAX);
            text_response(
                200,
                "OK",
                format!("NONCE {} {}", nonce.id(), nonce.expiry()),
            )
        }
        ("POST", "/login") => dispatch_login(ctx, request),
        ("POST", "/bootstrap/request/node") => dispatch_request_submit(ctx, request, true),
        ("POST", "/bootstrap/request/user") => dispatch_request_submit(ctx, request, false),
        ("GET", "/bootstrap/request/list") => dispatch_request_list(ctx),
        ("POST", "/bootstrap/request/approve") => dispatch_request_decide(ctx, request, true),
        ("POST", "/bootstrap/request/reject") => dispatch_request_decide(ctx, request, false),
        ("GET", "/portal/status") => dispatch_portal_status(ctx, request),
        ("POST", "/portal/layout") => dispatch_layout_store(ctx, request),
        ("GET", "/portal/layout") => dispatch_layout_get(ctx, request),
        ("GET", "/portal/identity") => dispatch_identity_view(ctx, request),
        ("POST", "/portal/identity/enroll") => dispatch_identity_enroll(ctx, request),
        ("POST", "/portal/identity/rotate") => dispatch_identity_rotate(ctx, request),
        ("POST", "/portal/identity/recover") => dispatch_identity_recover(ctx, request),
        ("GET", "/portal/domains") => dispatch_domain_view(ctx, request),
        ("GET", "/portal/members") => dispatch_members_view(ctx, request),
        ("POST", "/portal/members/add") => dispatch_members_add(ctx, peer, request),
        ("POST", "/portal/members/role") => dispatch_members_role(ctx, request),
        ("GET", "/portal/sessions") => dispatch_sessions_view(ctx, request),
        ("POST", "/portal/sessions/revoke") => dispatch_sessions_revoke(ctx, request),
        ("POST", "/portal/sessions/revoke-all") => dispatch_sessions_revoke_all(ctx, request),
        ("POST", "/portal/attestations/build") => dispatch_attestation_build(ctx, request),
        ("GET", "/portal/trust-graph") => dispatch_trust_graph_view(ctx, request),
        ("GET", p) if p.starts_with("/portal/topology/tree") => {
            dispatch_topology_tree(ctx, request)
        }
        ("GET", p) if p.starts_with("/portal/topology/mismatches") => {
            dispatch_topology_mismatches(ctx, request)
        }
        ("POST", "/portal/topology/label/declare") => dispatch_topology_label_declare(ctx, request),
        ("POST", "/portal/topology/label/attest") => dispatch_topology_label_attest(ctx, request),
        ("GET", p) if p.starts_with("/portal/topology/failure-domain") => {
            dispatch_topology_failure_domain(ctx, request)
        }
        ("GET", p) if p.starts_with("/portal/topology/facet") => {
            dispatch_topology_facet(ctx, request)
        }
        ("POST", "/portal/custody/migrate") => dispatch_custody_migrate(ctx, request),
        ("POST", "/portal/custody/rotate") => dispatch_custody_rotate(ctx, request),
        ("POST", "/portal/custody/seal") => dispatch_custody_seal(ctx, request),
        ("POST", "/portal/custody/revoke") => dispatch_custody_revoke(ctx, request),
        ("GET", p) if p.starts_with("/portal/resource/get") => dispatch_resource_get(ctx, request),
        ("GET", p) if p.starts_with("/portal/resource/describe") => {
            dispatch_resource_describe(ctx, request)
        }
        ("GET", p) if p.starts_with("/portal/resource/dry-run") => {
            dispatch_resource_dry_run(ctx, request)
        }
        ("GET", p) if p.starts_with("/portal/resource/logs") => {
            dispatch_resource_runtime(ctx, request, RuntimeReach::Logs)
        }
        ("GET", p) if p.starts_with("/portal/resource/exec") => {
            dispatch_resource_runtime(ctx, request, RuntimeReach::Exec)
        }
        ("GET", p) if p.starts_with("/portal/resource/forward") => {
            dispatch_resource_runtime(ctx, request, RuntimeReach::Forward)
        }
        ("POST", "/portal/resource/apply") => {
            dispatch_resource_act(ctx, request, ResourceAct::Apply)
        }
        ("POST", "/portal/resource/edit") => dispatch_resource_act(ctx, request, ResourceAct::Edit),
        ("POST", "/portal/resource/scale") => {
            dispatch_resource_act(ctx, request, ResourceAct::Scale)
        }
        ("POST", "/portal/resource/rollout") => {
            dispatch_resource_act(ctx, request, ResourceAct::Rollout)
        }
        ("GET", p) if p.starts_with("/portal/obs/explore") => dispatch_obs_explore(ctx, request),
        ("GET", p) if p.starts_with("/portal/obs/query") => dispatch_obs_query(ctx, request),
        ("POST", "/portal/obs/dashboard") => dispatch_obs_dashboard(ctx, request),
        _ => text_response(404, "Not Found", "not found".to_owned()),
    }
}

/// Extract `key`'s value from `path`'s query string (`GET /x?a=1&b=2`), if
/// present. A bare helper — this portal has no framework, so query params are
/// parsed by hand exactly like the existing header/body parsing above.
fn query_value<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// Map a `kind=<...>` query-param token to its [`SignalKind`], for the
/// observability explore/query endpoints.
fn parse_signal_kind(s: &str) -> Option<SignalKind> {
    match s {
        "metric" => Some(SignalKind::Metric),
        "log" => Some(SignalKind::Log),
        "trace" => Some(SignalKind::TraceSpan),
        "profile" => Some(SignalKind::ProfileSample),
        "metadata" => Some(SignalKind::MetadataSample),
        _ => None,
    }
}

/// The stable text tag for a [`SignalKind`] the observability views render.
fn signal_kind_tag(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Metric => "metric",
        SignalKind::Log => "log",
        SignalKind::TraceSpan => "trace",
        SignalKind::ProfileSample => "profile",
        SignalKind::MetadataSample => "metadata",
    }
}

/// Which runtime-reach verb a `/portal/resource/{logs,exec,forward}` request is.
#[derive(Clone, Copy)]
enum RuntimeReach {
    Logs,
    Exec,
    Forward,
}

/// Which signed resource ACT a `/portal/resource/{apply,edit,scale,rollout}`
/// request is.
#[derive(Clone, Copy)]
enum ResourceAct {
    Apply,
    Edit,
    Scale,
    Rollout,
}

/// The resource/workload UI's list VIEW: `GET
/// /portal/resource/get?token=<session>&kind=<kind>[&selector=<k=v,…>]`.
/// Requires an admitted session; signs nothing. Renders one `kind/name
/// replicas=N` line per matching object plus an `EVENTS <n>` trailer proving
/// the view emitted no event.
fn dispatch_resource_get(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let kind = query_value(&request.path, "kind").unwrap_or(WORKLOAD_KIND);
    let selector = match query_value(&request.path, "selector") {
        Some(s) => match Selector::parse(s) {
            Ok(sel) => sel,
            Err(e) => return text_response(400, "Bad Request", format!("BAD-SELECTOR {e}")),
        },
        None => Selector::new(),
    };
    let before = ctx.resource_event_count();
    let rows = ctx.resource_get(kind, &selector);
    let mut body = String::new();
    for row in &rows {
        body.push_str(row);
        body.push('\n');
    }
    // A view signs nothing: the event count is unchanged.
    body.push_str(&format!("EVENTS {}\n", ctx.resource_event_count()));
    debug_assert_eq!(before, ctx.resource_event_count());
    text_response(200, "OK", body)
}

/// `describe`: `GET /portal/resource/describe?token=<s>&kind=<k>&name=<n>`.
/// Requires an admitted session; renders provenance (signer/authority/event
/// CID). Signs nothing.
fn dispatch_resource_describe(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let kind = query_value(&request.path, "kind").unwrap_or(WORKLOAD_KIND);
    let Some(name) = query_value(&request.path, "name") else {
        return text_response(400, "Bad Request", "MISSING name".to_owned());
    };
    match ctx.resource_describe(kind, name) {
        Some(detail) => text_response(200, "OK", detail),
        None => text_response(404, "Not Found", "DENIED unknown-resource".to_owned()),
    }
}

/// The `--dry-run`-style preview: `GET
/// /portal/resource/dry-run?token=<s>`. Renders the PREDICTED decider
/// decision for the session's admitted actor WITHOUT signing anything, so a
/// caller can confirm `predicted == enforced` against the subsequent act.
fn dispatch_resource_dry_run(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    let Some(session) = ctx.login_session_for(token).cloned() else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let predicted = ctx.resource_dry_run(&session.subject);
    text_response(
        200,
        "OK",
        format!("PREDICTED {}", if predicted { "ALLOW" } else { "DENY" }),
    )
}

/// `logs`/`exec`/`port-forward`: `GET
/// /portal/resource/{logs,exec,forward}?token=<s>&name=<n>[&cmd=…|&port=…]`.
/// Reaches a RUNNING workload's runtime — signs nothing.
fn dispatch_resource_runtime(
    ctx: &WebAuthContext,
    request: &HttpRequest,
    reach: RuntimeReach,
) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let Some(name) = query_value(&request.path, "name") else {
        return text_response(400, "Bad Request", "MISSING name".to_owned());
    };
    let result = match reach {
        RuntimeReach::Logs => ctx.resource_logs(name),
        RuntimeReach::Exec => {
            let cmd = query_value(&request.path, "cmd").unwrap_or("sh");
            ctx.resource_exec(name, cmd)
        }
        RuntimeReach::Forward => {
            let port = query_value(&request.path, "port")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(8080);
            ctx.resource_forward(name, port)
        }
    };
    match result {
        Ok(stream) => text_response(200, "OK", stream),
        Err(e) => text_response(404, "Not Found", format!("DENIED {e}")),
    }
}

/// The signed resource ACTS: `POST /portal/resource/{apply,edit,scale,rollout}`
/// with body `<token>\n<name>\n<arg>`. Requires an admitted session; emits
/// exactly ONE decider-authorized signed event on success — an unauthorized
/// act appends nothing (403). The response carries `EVENT <cid>` and the new
/// event count so a caller can assert exactly one event was emitted.
fn dispatch_resource_act(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
    act: ResourceAct,
) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let name = lines.next().unwrap_or("").trim().to_owned();
    let arg = lines.next().unwrap_or("").trim().to_owned();
    let Some(session) = ctx.login_session_for(token).cloned() else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    if name.is_empty() {
        return text_response(400, "Bad Request", "MISSING name".to_owned());
    }
    let actor = session.subject.clone();
    // The predicted decision (dry-run) MUST equal the enforced one — same
    // decider, so we compute it before acting and compare after.
    let predicted = ctx.resource_dry_run(&actor);
    let result = match act {
        ResourceAct::Apply => {
            let image = if arg.is_empty() { "app:v1" } else { &arg };
            ctx.resource_apply(&actor, &name, image, 1)
        }
        ResourceAct::Edit => {
            let image = if arg.is_empty() { "app:v2" } else { &arg };
            ctx.resource_edit(&actor, &name, image)
        }
        ResourceAct::Scale => {
            let replicas = arg.parse::<i64>().unwrap_or(1);
            ctx.resource_scale(&actor, &name, replicas)
        }
        ResourceAct::Rollout => ctx.resource_rollout(&actor, &name),
    };
    match result {
        Ok(cid) => {
            debug_assert!(predicted, "an authorized act must have predicted ALLOW");
            text_response(
                200,
                "OK",
                format!("EVENT {cid}\nEVENTS {}", ctx.resource_event_count()),
            )
        }
        Err(ResourceError::Apply(crate::ApplyError::Unauthorized { .. })) => {
            debug_assert!(!predicted, "a refused act must have predicted DENY");
            text_response(403, "Forbidden", "DENIED unauthorized".to_owned())
        }
        Err(e) => text_response(409, "Conflict", format!("DENIED {e}")),
    }
}

/// The real authenticated portal's identity/reachability + lease-holder tile:
/// `GET /portal/status?token=<session>`. Requires an admitted session — an
/// unauthenticated (or unknown/expired-token) request is refused, exactly
/// like every other signing/read action gated behind login. Renders PeerId,
/// listen addrs, connected peer count + list, uptime, and the current lease
/// holder — all read from this node's live [`WebAuthContext`] state, never a
/// server-side database.
fn dispatch_portal_status(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let identity = ctx.identity();
    let lease_holder = ctx
        .lease_holder()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let mut body = String::new();
    body.push_str(&format!("PEER-ID {}\n", identity.peer_id));
    body.push_str(&format!("LISTEN {}\n", identity.listen_addrs.join(",")));
    body.push_str(&format!("PEER-COUNT {}\n", identity.connected_peers.len()));
    body.push_str(&format!("PEERS {}\n", identity.connected_peers.join(",")));
    body.push_str(&format!("UPTIME-SECS {}\n", ctx.uptime_secs()));
    body.push_str(&format!("LEASE-HOLDER {lease_holder}\n"));
    text_response(200, "OK", body)
}

/// Persist a UI layout as a signed, content-addressed streaming-DB resource:
/// `POST /portal/layout`, body `<token>\n<content>`. Requires an admitted
/// session (the resource is signed by that session's handle); returns the
/// resource's content address (CID) and the log's new streaming tip.
fn dispatch_layout_store(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let content: String = lines.collect::<Vec<_>>().join("\n");
    let Some(session) = ctx.login_session_for(token).cloned() else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let cid = ctx.store_layout(&session.subject.to_string(), &content);
    text_response(
        200,
        "OK",
        format!("LAYOUT-CID {} TIP {}", cid, ctx.layout_tip()),
    )
}

/// Retrieve a previously stored UI layout: `GET
/// /portal/layout?token=<session>&cid=<id>`. Requires an admitted session;
/// the resource's own signer + content are returned so a differently
/// authenticated viewer can see who produced the layout.
fn dispatch_layout_get(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let Some(cid_raw) = query_value(&request.path, "cid") else {
        return text_response(400, "Bad Request", "MISSING cid".to_owned());
    };
    let Some(cid) = OpId::from_hex(cid_raw) else {
        return text_response(400, "Bad Request", "BAD cid".to_owned());
    };
    match ctx.get_layout(&cid) {
        Some((signer, content)) => {
            text_response(200, "OK", format!("SIGNER {signer}\nCONTENT {content}"))
        }
        None => text_response(404, "Not Found", "DENIED unknown-layout".to_owned()),
    }
}

/// The identity view: `GET /portal/identity?token=<session>`. Requires an
/// admitted session; renders the stable global CID, current primary
/// generation, and every certified per-domain key — the multi-domain view.
fn dispatch_identity_view(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let log = ctx.identity_log();
    let mut body = String::new();
    body.push_str(&format!("CID {}\n", log.cid().0));
    body.push_str(&format!("GEN {}\n", log.head_generation()));
    for (domain, key) in log.domains() {
        body.push_str(&format!("DOMAIN {} KEY {}\n", domain.0, key.0));
    }
    text_response(200, "OK", body)
}

/// Enroll in a domain: `POST /portal/identity/enroll`, body
/// `<token>\n<domain>`. Certifies ONE per-domain subkey signed by the current
/// primary.
fn dispatch_identity_enroll(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let domain = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if domain.is_empty() {
        return text_response(400, "Bad Request", "MISSING domain".to_owned());
    }
    match ctx.identity_enroll(domain) {
        Ok(key) => text_response(200, "OK", format!("DOMAIN {domain} KEY {}", key.0)),
        Err(e) => text_response(409, "Conflict", format!("DENIED {}", identity_reason(&e))),
    }
}

/// Rotate the primary: `POST /portal/identity/rotate`, body
/// `<token>\n<new-primary>`. Signed by the current primary; the CID is
/// invariant.
fn dispatch_identity_rotate(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let new_primary = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if new_primary.is_empty() {
        return text_response(400, "Bad Request", "MISSING new-primary".to_owned());
    }
    match ctx.identity_rotate(new_primary) {
        Ok(gen) => text_response(
            200,
            "OK",
            format!("GEN {gen} CID {}", ctx.identity_log().cid().0),
        ),
        Err(e) => text_response(409, "Conflict", format!("DENIED {}", identity_reason(&e))),
    }
}

/// Recover: `POST /portal/identity/recover`, body `<token>`. Rotates using
/// the genesis-committed recovery key; the CID is invariant.
fn dispatch_identity_recover(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = request.body.lines().next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    match ctx.identity_recover() {
        Ok(gen) => text_response(
            200,
            "OK",
            format!("RECOVERED GEN {gen} CID {}", ctx.identity_log().cid().0),
        ),
        Err(e) => text_response(409, "Conflict", format!("DENIED {}", identity_reason(&e))),
    }
}

fn identity_reason(e: &pillar_identity::global_identity::IdentityLogError) -> String {
    use pillar_identity::global_identity::IdentityLogError as E;
    match e {
        E::UnauthorizedRotation { signer } => format!("unauthorized-rotation-by-{}", signer.0),
        E::DomainAlreadyCertified(d) => format!("already-certified-{}", d.0),
        E::DomainNotCertified(d) => format!("not-certified-{}", d.0),
        E::DomainRevoked(d) => format!("revoked-{}", d.0),
        E::OfferAlreadySealed(d) => format!("offer-already-sealed-{}", d.0),
        E::TwoHopCertification { issuer } => format!("two-hop-{}", issuer.0),
    }
}

/// The domain (naming-only) grouping view: `GET /portal/domains?token=...`.
/// Requires an admitted session. Read-only: exposes NO domain-signing /
/// granting / coordinating action — a domain here groups cells under a name,
/// and nothing else (property: a domain signs nothing).
fn dispatch_domain_view(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let mut body = String::new();
    for (domain, cells) in ctx.domain_cells() {
        body.push_str(&format!("DOMAIN {domain} CELLS {}\n", cells.join(",")));
    }
    text_response(200, "OK", body)
}

/// List members: `GET /portal/members?token=...`.
fn dispatch_members_view(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let mut body = String::new();
    for (handle, role) in ctx.members() {
        body.push_str(&format!("MEMBER {handle} ROLE {role}\n"));
    }
    text_response(200, "OK", body)
}

/// Add/invite a member: `POST /portal/members/add`, body
/// `<token>\n<handle>\n<role>` — the portal's REPRESENTATIVE real signed
/// act (replacing the old `/ping` demonstration stub). Gated first through
/// [`authorize_nonloopback_signing_action`] (a non-loopback peer must
/// present an admitted session), then through
/// [`WebAuthContext::perform_signed_act`] — the same WoT/RBAC decider the
/// CLI acts use — which emits ONE signed event and is the ONLY thing that
/// lets `add_member` mutate anything; an unauthorized/unauthenticated
/// attempt changes nothing and is refused with a clear message. On success
/// the response carries provenance: the signer, the exercised WoT
/// authority, and the emitted event's CID.
fn dispatch_members_add(
    ctx: &mut WebAuthContext,
    peer: &SocketAddr,
    request: &HttpRequest,
) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    let role = lines.next().unwrap_or("member").trim();
    let session = ctx.login_session_for(token).cloned();
    if let Err(e) = authorize_nonloopback_signing_action(peer, session.as_ref()) {
        return text_response(403, "Forbidden", format!("REFUSED {e:?}"));
    }
    let Some(session) = session else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    if handle.is_empty() {
        return text_response(400, "Bad Request", "MISSING handle".to_owned());
    }
    let role = if role.is_empty() { "member" } else { role };
    let actor = session.subject.clone();
    let payload = format!("MEMBER-ADD {handle} {role}");
    match ctx.perform_signed_act(&actor, "portal:members:write", &payload) {
        Ok(event) => {
            ctx.add_member(handle, role);
            let exercised = ctx.exercised_authority(&actor);
            let mut body = format!("MEMBER {handle} ROLE {role}\n");
            body.push_str(&format!("SIGNER {actor}\n"));
            body.push_str(&format!("EVENT-CID {}\n", event.0));
            body.push_str(&format!("EXERCISED-AUTHORITY {exercised}\n"));
            text_response(200, "OK", body)
        }
        Err(actor) => text_response(
            403,
            "Forbidden",
            format!("REFUSED unauthorized actor {actor} for portal:members:write"),
        ),
    }
}

/// Change a member's role: `POST /portal/members/role`, body
/// `<token>\n<handle>\n<role>`. A signed act — refused unauthorized, and for
/// an unknown member.
fn dispatch_members_role(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    let role = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if handle.is_empty() || role.is_empty() {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    if ctx.set_member_role(handle, role) {
        text_response(200, "OK", format!("MEMBER {handle} ROLE {role}"))
    } else {
        text_response(404, "Not Found", "DENIED unknown-member".to_owned())
    }
}

/// The session-management panel: `GET /portal/sessions?token=<session>`.
/// Requires an admitted session. Lists every ACTIVE server-side session
/// belonging to the caller's own principal (never another principal's — the
/// caller has no way to name one), one per line: `SESSION <id> NODE <node>
/// ISSUED <issued_at> EXPIRY <expiry> CURRENT <yes|no>`. The panel derives
/// its live expiry COUNTDOWN client-side from `EXPIRY` (a logical-clock
/// tick count here; a real deployment reports wall-clock seconds).
fn dispatch_sessions_view(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    let Some(session) = ctx.login_session_for(token) else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let principal = session.subject.to_string();
    let mut body = String::new();
    for s in ctx.list_sessions(&principal, token) {
        body.push_str(&format!(
            "SESSION {} NODE {} ISSUED {} EXPIRY {} CURRENT {}\n",
            s.id,
            s.node,
            s.issued_at,
            s.expiry,
            if s.is_current { "yes" } else { "no" },
        ));
    }
    text_response(200, "OK", body)
}

/// Revoke ONE of the caller's own sessions: `POST /portal/sessions/revoke`,
/// body `<token>\n<id>`. A decider-authorized act — `token` proves the
/// caller's own principal, and only THAT principal's sessions are ever
/// revocable through this endpoint (never another's). The revoked session's
/// bearer actions fail closed starting the very next call.
fn dispatch_sessions_revoke(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let id = lines.next().unwrap_or("").trim();
    let Some(session) = ctx.login_session_for(token) else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let principal = session.subject.to_string();
    if id.is_empty() {
        return text_response(400, "Bad Request", "MISSING id".to_owned());
    }
    match ctx.revoke_session(&principal, id) {
        Ok(()) => text_response(200, "OK", format!("REVOKED {id}")),
        Err(RevokeError::NoSuchSession) => {
            text_response(404, "Not Found", "DENIED unknown-session".to_owned())
        }
    }
}

/// Sign out everywhere: `POST /portal/sessions/revoke-all`, body `<token>`.
/// Revokes every one of the caller's own sessions (never another
/// principal's) in one atomic sweep; each one's bearer actions fail closed
/// starting the very next call.
fn dispatch_sessions_revoke_all(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = request.body.lines().next().unwrap_or("").trim();
    let Some(session) = ctx.login_session_for(token) else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let principal = session.subject.to_string();
    ctx.revoke_all_sessions(&principal);
    text_response(200, "OK", "REVOKED-ALL".to_owned())
}

fn trust_error_reason(e: &TrustError) -> String {
    match e {
        TrustError::SignerMismatch => "signer-mismatch".to_owned(),
        TrustError::CapacityNotHeld { issuer } => format!("capacity-not-held-{}", issuer.0),
        TrustError::StaleEpoch { attempted, current } => {
            format!("stale-epoch-{attempted}-vs-{current}")
        }
        TrustError::UnknownTarget(cid) => format!("unknown-target-{}", cid.0),
        TrustError::NotAQuotaPredicate => "not-a-quota-predicate".to_owned(),
        TrustError::QuotaExceeded {
            requested,
            remaining,
        } => {
            format!("quota-exceeded-{requested}-remaining-{remaining}")
        }
    }
}

/// The attestation builder: `POST /portal/attestations/build`, body
/// `<token>\n<issuer>\n<capacity>\n<authority-cid-or-empty>\n<subject>\n
/// <action>\n<resource>\n<quota-spec-or-empty>\n<scope>`, where `capacity`
/// is `self` or `<role>@<scope>` and `quota-spec` is the `--quota
/// <resource>=<amount>[m]` budget form (e.g. `cpu=1000m`). Requires an
/// admitted session. On success renders BOTH the composed sentence AND the
/// full proof chain; refused ([`TrustError::CapacityNotHeld`]) when `issuer`
/// does not currently hold the declared capacity.
fn dispatch_attestation_build(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let issuer = lines.next().unwrap_or("").trim();
    let capacity_spec = lines.next().unwrap_or("").trim();
    let authority = lines.next().unwrap_or("").trim();
    let subject = lines.next().unwrap_or("").trim();
    let action = lines.next().unwrap_or("").trim();
    let resource = lines.next().unwrap_or("").trim();
    let quota_spec = lines.next().unwrap_or("").trim();
    let scope = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if issuer.is_empty()
        || subject.is_empty()
        || action.is_empty()
        || resource.is_empty()
        || scope.is_empty()
    {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    let capacity = if capacity_spec == "self" {
        TrustCapacity::SelfCap
    } else if let Some((role, cap_scope)) = capacity_spec.split_once('@') {
        TrustCapacity::Role {
            role: role.to_owned(),
            scope: cap_scope.to_owned(),
        }
    } else {
        return text_response(400, "Bad Request", "BAD capacity".to_owned());
    };
    let authority_cid = if authority.is_empty() {
        None
    } else {
        Some(TrustCid(authority.to_owned()))
    };
    let quota = if quota_spec.is_empty() {
        None
    } else {
        parse_quota(quota_spec).map(|(_, amt)| amt)
    };
    match ctx.build_attestation(
        NodeId::from(issuer),
        capacity,
        authority_cid,
        NodeId::from(subject),
        action,
        resource,
        quota,
        scope,
    ) {
        Ok((cid, proof)) => {
            let mut body = format!("CID {}\n", cid.0);
            body.push_str(&format!("SENTENCE {}\n", proof.sentence));
            for c in &proof.chain {
                body.push_str(&format!("CHAIN {}\n", c.0));
            }
            text_response(200, "OK", body)
        }
        Err(e) => text_response(
            403,
            "Forbidden",
            format!("DENIED {}", trust_error_reason(&e)),
        ),
    }
}

/// The trust-graph visualization: `GET /portal/trust-graph?token=...`. A
/// PURE view — signs and mutates nothing.
fn dispatch_trust_graph_view(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let mut body = String::new();
    for e in ctx.trust_graph_edges() {
        body.push_str(&format!(
            "EDGE {} -> {} LABEL {}\n",
            e.from.0, e.to.0, e.label
        ));
    }
    text_response(200, "OK", body)
}

/// The observability explore view: `GET
/// /portal/obs/explore?token=<s>&kind=metric|log|trace|profile|metadata`.
/// Requires an admitted session (an unauthenticated request is refused, like
/// every other read endpoint). Renders every held signal of `kind` as a
/// `SIGNAL <id> KIND <kind> PAYLOAD <payload>` line. A pure view — signs
/// nothing.
fn dispatch_obs_explore(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let Some(kind) = parse_signal_kind(query_value(&request.path, "kind").unwrap_or("metric"))
    else {
        return text_response(400, "Bad Request", "BAD kind".to_owned());
    };
    text_response(200, "OK", ctx.observability_explore(kind))
}

/// The observability per-kind query view: `GET
/// /portal/obs/query?token=<s>&kind=<k>[&filter=<f>]`. Requires an admitted
/// session. `filter` is a plain substring match (metric/log/trace) or an
/// entity-id prefix (metadata); for `profile` an optional numeric `filter`
/// picks the `top <n>` sample count. A pure view — signs nothing.
fn dispatch_obs_query(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let Some(kind) = parse_signal_kind(query_value(&request.path, "kind").unwrap_or("metric"))
    else {
        return text_response(400, "Bad Request", "BAD kind".to_owned());
    };
    let filter = query_value(&request.path, "filter").filter(|f| !f.is_empty());
    text_response(200, "OK", ctx.observability_query(kind, filter))
}

/// Save an observability dashboard: `POST /portal/obs/dashboard`, body
/// `<token>\n<name>: <spec>`. Requires an admitted session. Persists the
/// dashboard as ONE signed, content-addressed streaming-DB resource (the SAME
/// no-server-side-database path the UI-layout store uses), returning its CID
/// and the dashboard log's new streaming tip — `OBS-DASHBOARD-CID <cid> TIP
/// <tip>`.
fn dispatch_obs_dashboard(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let rest = lines.collect::<Vec<_>>().join("\n");
    let Some(session) = ctx.login_session_for(token).cloned() else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let Some((name, spec)) = rest.split_once(": ") else {
        return text_response(400, "Bad Request", "MISSING name-spec".to_owned());
    };
    let (name, spec) = (name.trim(), spec.trim());
    if name.is_empty() {
        return text_response(400, "Bad Request", "MISSING name".to_owned());
    }
    let (cid, tip) = ctx.save_observability_dashboard(&session.subject.to_string(), name, spec);
    text_response(200, "OK", format!("OBS-DASHBOARD-CID {cid} TIP {tip}"))
}

/// The topology explorer tree: `GET
/// /portal/topology/tree?token=<s>[&rollup-tier=<tier>]` (default rollup
/// tier `rack`). Renders the CONFIG-ordered tier hierarchy, every registered
/// node's resolved placement path + live health/capacity, and the per-tier
/// capacity rollup. A pure view — signs nothing.
fn dispatch_topology_tree(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let rollup_tier = query_value(&request.path, "rollup-tier").unwrap_or("rack");
    text_response(200, "OK", ctx.topology_tree(rollup_tier))
}

/// Declared-vs-attested mismatches: `GET
/// /portal/topology/mismatches?token=<s>`. A pure view — signs nothing.
fn dispatch_topology_mismatches(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let mut body = String::new();
    for m in ctx.topology_mismatches() {
        body.push_str(&format!(
            "MISMATCH {} tier={} declared={} attested={}\n",
            m.node.0, m.tier, m.declared, m.attested
        ));
    }
    text_response(200, "OK", body)
}

/// The label editor's self-declare action: `POST
/// /portal/topology/label/declare`, body `<token>\n<node>\n<tier>\n<value>`.
/// Advisory only — records nothing into the trust store. Requires an
/// admitted session.
fn dispatch_topology_label_declare(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let node = lines.next().unwrap_or("").trim();
    let tier = lines.next().unwrap_or("").trim();
    let value = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if node.is_empty() || tier.is_empty() || value.is_empty() {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    ctx.topology_declare(NodeId::from(node), vec![TopologyLabel::new(tier, value)]);
    text_response(200, "OK", "DECLARED".to_owned())
}

/// The label editor's attest action: `POST /portal/topology/label/attest`,
/// body
/// `<token>\n<issuer>\n<capacity-spec>\n<authority-cid-or-empty>\n<subject>\n<tier>\n<value>\n<scope>`
/// (`capacity-spec` is `self` or `<role>@<scope>`, exactly like the
/// attestation builder). Emits ONE signed `topology:label` attest event;
/// refused (403) if `issuer` does not hold the declared capacity.
fn dispatch_topology_label_attest(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let issuer = lines.next().unwrap_or("").trim();
    let capacity_spec = lines.next().unwrap_or("").trim();
    let authority = lines.next().unwrap_or("").trim();
    let subject = lines.next().unwrap_or("").trim();
    let tier = lines.next().unwrap_or("").trim();
    let value = lines.next().unwrap_or("").trim();
    let scope = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if issuer.is_empty()
        || subject.is_empty()
        || tier.is_empty()
        || value.is_empty()
        || scope.is_empty()
    {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    let capacity = if capacity_spec == "self" {
        TrustCapacity::SelfCap
    } else if let Some((role, cap_scope)) = capacity_spec.split_once('@') {
        TrustCapacity::Role {
            role: role.to_owned(),
            scope: cap_scope.to_owned(),
        }
    } else {
        return text_response(400, "Bad Request", "BAD capacity".to_owned());
    };
    let authority_cid = if authority.is_empty() {
        None
    } else {
        Some(TrustCid(authority.to_owned()))
    };
    let label = TopologyLabel::new(tier, value);
    match ctx.topology_attest(
        NodeId::from(issuer),
        capacity,
        authority_cid,
        NodeId::from(subject),
        &label,
        scope,
    ) {
        Ok(cid) => text_response(200, "OK", format!("ATTESTED CID {}", cid.0)),
        Err(e) => text_response(
            403,
            "Forbidden",
            format!("DENIED {}", trust_error_reason(&e)),
        ),
    }
}

/// The failure-domain overlay: `GET
/// /portal/topology/failure-domain?token=<s>&tier=<tier>&nodes=<a,b,c>`.
/// Computes each named node's replica spread across `tier` and warns when
/// 2+ replicas land in the SAME failure domain (e.g. the same rack). A pure
/// view — signs nothing.
fn dispatch_topology_failure_domain(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let tier = query_value(&request.path, "tier").unwrap_or("rack");
    let nodes: Vec<NodeId> = query_value(&request.path, "nodes")
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(NodeId::from)
        .collect();
    let (assignments, warn) = ctx.topology_failure_domain_overlay(&nodes, tier);
    let mut body = String::new();
    for (node, domain) in assignments {
        body.push_str(&format!(
            "REPLICA {} {}={}\n",
            node.0,
            tier,
            domain.unwrap_or_else(|| "(unlabeled)".to_owned())
        ));
    }
    body.push_str(if warn {
        "WARN same-rack\n"
    } else {
        "SPREAD-OK\n"
    });
    text_response(200, "OK", body)
}

/// The global topology facet: `GET
/// /portal/topology/facet?token=<s>&tier=<tier>&value=<value>` — nodes
/// currently carrying `tier = value` in their resolved placement, the
/// primitive workload/telemetry/logs panels filter by. A pure view.
fn dispatch_topology_facet(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let tier = query_value(&request.path, "tier").unwrap_or("");
    let value = query_value(&request.path, "value").unwrap_or("");
    if tier.is_empty() || value.is_empty() {
        return text_response(400, "Bad Request", "MISSING tier-or-value".to_owned());
    }
    let mut body = String::new();
    for n in ctx.topology_nodes_at(tier, value) {
        body.push_str(&format!("NODE {n}\n"));
    }
    text_response(200, "OK", body)
}

/// Custody migration: `POST /portal/custody/migrate`, body
/// `<token>\n<handle>\n<new-holder>\n<new-cid>`. A signed act — requires an
/// admitted session; refused unauthorized.
fn dispatch_custody_migrate(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    let holder = lines.next().unwrap_or("").trim();
    let cid = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if handle.is_empty() || holder.is_empty() || cid.is_empty() {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    ctx.custody_migrate(handle, NodeId::from(holder), Cid::from(cid));
    text_response(200, "OK", format!("MIGRATED {handle}"))
}

/// Custody rotation: `POST /portal/custody/rotate`, body
/// `<token>\n<handle>\n<new-cid>`. A signed act — requires an admitted
/// session; refused unauthorized, and for a handle with no existing custody
/// record.
fn dispatch_custody_rotate(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    let cid = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if handle.is_empty() || cid.is_empty() {
        return text_response(400, "Bad Request", "MISSING field".to_owned());
    }
    if ctx.custody_rotate(handle, Cid::from(cid)) {
        text_response(200, "OK", format!("ROTATED {handle}"))
    } else {
        text_response(404, "Not Found", "DENIED unknown-custody".to_owned())
    }
}

/// Seal/escrow: `POST /portal/custody/seal`, body `<token>\n<handle>`. A
/// signed act — requires an admitted session; refused unauthorized, and for
/// a handle with no existing custody record.
fn dispatch_custody_seal(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if handle.is_empty() {
        return text_response(400, "Bad Request", "MISSING handle".to_owned());
    }
    if ctx.custody_seal_escrow(handle) {
        text_response(200, "OK", format!("SEALED {handle}"))
    } else {
        text_response(404, "Not Found", "DENIED unknown-custody".to_owned())
    }
}

/// Revoke: `POST /portal/custody/revoke`, body `<token>\n<handle>`. A signed
/// act — requires an admitted session; refused unauthorized, and for a
/// handle with no existing custody record.
fn dispatch_custody_revoke(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let handle = lines.next().unwrap_or("").trim();
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    if handle.is_empty() {
        return text_response(400, "Bad Request", "MISSING handle".to_owned());
    }
    if ctx.custody_revoke(handle) {
        text_response(200, "OK", format!("REVOKED {handle}"))
    } else {
        text_response(404, "Not Found", "DENIED unknown-custody".to_owned())
    }
}

/// Drive one node-side custody login: parse the TWO fields (identifier +
/// password), issue nothing here (the client already fetched a nonce), and let
/// the node resolve+strip+unlock+sign+admit SERVER-SIDE.
fn dispatch_login(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    // Body: "<identifier>\n<password>\n<nonce_id>". The client fetched the
    // nonce via GET /nonce and echoes its id so the server can bind the login
    // to that exact challenge; the password + identifier are the two human
    // fields. The CID is NEVER in the body — the node resolves it.
    let mut lines = request.body.lines();
    let identifier = lines.next().unwrap_or("").trim();
    let password = lines.next().unwrap_or("").trim();
    let nonce_id: u64 = lines
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .unwrap_or(u64::MAX);

    if identifier.is_empty() || password.is_empty() {
        return text_response(401, "Unauthorized", "DENIED missing-field".to_owned());
    }

    let authority = ctx.authority.clone();
    let actor = ctx.actor.clone();
    match ctx
        .verifier
        .admit(identifier, password, nonce_id, 0, &authority, &actor)
    {
        Ok(session) => {
            let handle = session.handle.clone();
            let token = ctx.store_session(session);
            HttpResponse {
                status: 200,
                reason: "OK",
                content_type: "text/plain; charset=utf-8",
                session_token: Some(token),
                body: format!("OK {handle}\n"),
            }
        }
        Err(e) => {
            let reason = login_reason(&e);
            text_response(401, "Unauthorized", format!("DENIED {reason}"))
        }
    }
}

fn parse_custody_field(token: &str) -> CustodyKind {
    parse_custody_kind(token).unwrap_or(CustodyKind::Password)
}

/// Submit a node/user bootstrap request. `is_node` selects the kind; the body
/// carries the requester's identifying info as newline-separated fields (see
/// the CLI `pillar bootstrap node`/`user` clients for the exact framing).
/// Requires the cell to exist (a request joins an EXISTING cell).
fn dispatch_request_submit(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
    is_node: bool,
) -> HttpResponse {
    let Some(queue) = ctx.requests.as_mut() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    let mut lines = request.body.lines();
    let subject = lines.next().unwrap_or("").trim();
    if subject.is_empty() {
        return text_response(400, "Bad Request", "MISSING subject".to_owned());
    }
    let subject = NodeId::from(subject);
    let id = if is_node {
        // Fields: <subject>\n<peer_id>\n<version>\n<os>\n<public_key_cid>\n<custody>
        // then any number of `pub=<addr>` / `priv=<addr>` / `label=<l>` lines.
        let peer_id = lines.next().unwrap_or("").trim().to_owned();
        let version = lines.next().unwrap_or("").trim().to_owned();
        let os = lines.next().unwrap_or("").trim().to_owned();
        let public_key_cid = lines.next().unwrap_or("").trim().to_owned();
        let custody = parse_custody_field(lines.next().unwrap_or("").trim());
        let mut identity = NodeIdentity::new(peer_id);
        identity.version = version;
        identity.os = os;
        identity.public_key_cid = public_key_cid;
        let mut labels = Vec::new();
        for line in lines {
            let line = line.trim();
            if let Some(a) = line.strip_prefix("pub=") {
                identity.public_addrs.push(a.to_owned());
            } else if let Some(a) = line.strip_prefix("priv=") {
                identity.private_addrs.push(a.to_owned());
            } else if let Some(l) = line.strip_prefix("label=") {
                labels.push(l.to_owned());
            }
        }
        queue.submit_node(subject, identity, custody, labels)
    } else {
        // Fields: <subject>\n<custody> then any number of `label=<l>` lines.
        let custody = parse_custody_field(lines.next().unwrap_or("").trim());
        let labels: Vec<String> = lines
            .filter_map(|l| l.trim().strip_prefix("label=").map(str::to_owned))
            .collect();
        queue.submit_user(subject, custody, labels)
    };
    text_response(200, "OK", format!("REQUEST {}", id.0))
}

/// List the pending bootstrap requests, one per line: `<id> <kind> <subject>`.
fn dispatch_request_list(ctx: &WebAuthContext) -> HttpResponse {
    let Some(queue) = ctx.requests.as_ref() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    let mut body = String::new();
    for req in queue.pending() {
        let kind = match req.kind() {
            BootstrapRequestKind::Node => "node",
            BootstrapRequestKind::User => "user",
        };
        body.push_str(&format!("{} {} {}\n", req.id().0, kind, req.subject().0));
    }
    text_response(200, "OK", body)
}

/// Approve or reject a pending request. The body is `<id>\n<session-token>`.
/// The presented session token must resolve to an admitted login session; its
/// subject is the authorized member that decides the request. A NODE approval
/// seals the cell key and returns its CID; a USER approval escrows the offer.
fn dispatch_request_decide(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
    approve: bool,
) -> HttpResponse {
    let mut lines = request.body.lines();
    let id_raw = lines.next().unwrap_or("").trim();
    let token = lines.next().unwrap_or("").trim();
    let Ok(id) = id_raw.parse::<u64>() else {
        return text_response(400, "Bad Request", "MISSING request-id".to_owned());
    };
    // Authenticated member = the subject of a valid login session.
    let Some(session) = ctx.login_sessions.get(token) else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let member = session.subject.clone();
    let Some(queue) = ctx.requests.as_mut() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    // An authenticated (WoT-authoritative) login IS an authorized member.
    queue.add_member(member.clone());
    let id = BootstrapRequestId(id);
    if approve {
        match queue.approve(id, &member) {
            Ok(Some(sealed)) => text_response(200, "OK", format!("APPROVED {}", sealed.cid)),
            Ok(None) => text_response(200, "OK", format!("ESCROWED {}", id.0)),
            Err(e) => text_response(409, "Conflict", format!("DENIED {}", request_reason(&e))),
        }
    } else {
        match queue.reject(id, &member) {
            Ok(()) => text_response(200, "OK", format!("REJECTED {}", id.0)),
            Err(e) => text_response(409, "Conflict", format!("DENIED {}", request_reason(&e))),
        }
    }
}

fn request_reason(e: &RequestError) -> &'static str {
    match e {
        RequestError::UnknownRequest => "unknown-request",
        RequestError::NotPending => "already-decided",
        RequestError::NotAuthorizedMember => "not-authorized-member",
    }
}

/// Map a [`NodeCustodyError`] onto a stable in-UI reason token — including the
/// NEW node-custody mode "this node lacks the key-distribution label / has no
/// offer for this user".
fn login_reason(e: &NodeCustodyError) -> &'static str {
    match e {
        NodeCustodyError::NoOfferForUser => "no-offer-for-user",
        NodeCustodyError::NoCustody => "no-custody-on-this-node",
        NodeCustodyError::UnlockFailed => "unlock-failed",
        NodeCustodyError::NotAuthorized(_) => "not-authorized",
        NodeCustodyError::BadNonce => "bad-nonce",
    }
}

/// Validate a request's OPTIONAL [`API_VERSION_HEADER`] assertion, returning
/// the DISTINCT error response to short-circuit on when it is unacceptable, or
/// `None` when the request may proceed (no header, or a supported version).
///
/// The two rejections are deliberately different HTTP statuses so a client can
/// tell them apart — mirroring the [`pillar_crypto::VersionError`] split:
///
/// * an illegible value (`VersionError::Malformed`, or not a `vN`/`N` number)
///   → `400 Bad Request`, a PARSE error, the same family as any other
///   malformed-request refusal; and
/// * a legible but out-of-window version (`VersionError::Unsupported`, e.g. a
///   FUTURE `v2` this build does not know, or a retired one) → `505 HTTP
///   Version Not Supported`, NAMING the unsupported version — distinct from a
///   404/parse/normal-response path.
fn check_request_api_version(request: &HttpRequest) -> Option<HttpResponse> {
    let raw = request.api_version.as_deref()?;
    // Accept both the `Display` form (`v1`) and a bare number (`1`), so a
    // client may echo back exactly what a response advertised.
    let digits = raw
        .strip_prefix('v')
        .or_else(|| raw.strip_prefix('V'))
        .unwrap_or(raw);
    let Ok(n) = digits.parse::<u16>() else {
        // Illegible: a parse error (400), NOT the unsupported-version case.
        return Some(text_response(
            400,
            "Bad Request",
            format!("MALFORMED api version header {raw:?}"),
        ));
    };
    let found = pillar_crypto::SurfaceVersion(n);
    match found.check_supported(MIN_API_VERSION, API_VERSION) {
        Ok(()) => None,
        Err(_) => Some(text_response(
            505,
            "HTTP Version Not Supported",
            format!(
                "UNSUPPORTED api version {found} (this build supports {MIN_API_VERSION}..={API_VERSION})"
            ),
        )),
    }
}

fn text_response(status: u16, reason: &'static str, mut body: String) -> HttpResponse {
    if !body.ends_with('\n') {
        body.push('\n');
    }
    HttpResponse {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        session_token: None,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_identity::NodeSubkey;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "operational-key-material";
    const ORIGIN: &str = "https://pillar.example.com";

    fn remote_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4242)
    }

    // A node that already custodies an offer for alice, WoT-chained + admitted.
    fn provisioned_ctx() -> (WebAuthContext, NodeSubkey) {
        let subkey = NodeSubkey::from("op-subkey-alice");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        ctx.admit_subject(subkey.node_id(), 4);
        ctx.provision_offer(
            "alice@pillar",
            "Alice",
            Cid::from("cid-alice"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        (ctx, subkey)
    }

    fn get(ctx: &mut WebAuthContext, path: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "GET".into(),
                path: path.into(),
                body: String::new(),
                api_version: None,
            },
        )
    }

    fn post(ctx: &mut WebAuthContext, path: &str, body: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                body: body.into(),
                api_version: None,
            },
        )
    }

    // A GET carrying an explicit `X-Pillar-Api-Version` assertion.
    fn get_with_api_version(ctx: &mut WebAuthContext, path: &str, version: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "GET".into(),
                path: path.into(),
                body: String::new(),
                api_version: Some(version.into()),
            },
        )
    }

    #[test]
    fn node_run_web_surface_binds_a_non_loopback_address() {
        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            !addr.ip().is_loopback(),
            "node-run web surface must bind a non-loopback address"
        );
    }

    // The full HTTP node-side custody login: GET /nonce, then POST /login with
    // exactly TWO fields (identifier + password, NO CID) — the node resolves
    // the offer, strips the seal, unlocks the key, signs, and admits. Then a
    // real signed act (POST /portal/members/add) with and without the
    // session token, proving the auth gate + provenance on the real
    // signed-action surface (there is no /ping demonstration stub).
    #[test]
    fn two_field_node_custody_login_then_signed_act_dispatch_preserves_the_auth_gate() {
        let (mut ctx, _subkey) = provisioned_ctx();

        // Unauthenticated signing action against a non-loopback peer: 403.
        let refused = post(&mut ctx, "/portal/members/add", "\nbob\nmember");
        assert_eq!(
            refused.status, 403,
            "unauthenticated non-loopback act must be refused"
        );

        // GET /nonce.
        let nonce_resp = get(&mut ctx, "/nonce");
        assert_eq!(nonce_resp.status, 200);
        let mut parts = nonce_resp.body.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id");

        // POST /login — TWO fields + the nonce id (hidden plumbing). NO CID.
        let login_body = format!("alice@pillar\n{PASSWORD}\n{id}");
        let login_resp = post(&mut ctx, "/login", &login_body);
        assert_eq!(login_resp.status, 200, "login body: {}", login_resp.body);
        assert!(
            login_resp.body.starts_with("OK Alice"),
            "the node greets the user by handle: {}",
            login_resp.body
        );
        let token = login_resp.session_token.expect("a session token");

        // POST /portal/members/add WITH the token → 200, one signed,
        // decider-authorized event with provenance (signer, exercised
        // authority, event CID).
        let act_resp = post(
            &mut ctx,
            "/portal/members/add",
            &format!("{token}\ncarol\nmember"),
        );
        assert_eq!(
            act_resp.status, 200,
            "authenticated signed act: {}",
            act_resp.body
        );
        assert!(act_resp.body.contains("MEMBER carol ROLE member"));
        assert!(act_resp.body.contains("SIGNER"), "got: {}", act_resp.body);
        assert!(
            act_resp.body.contains("EVENT-CID"),
            "got: {}",
            act_resp.body
        );
        assert!(
            act_resp.body.contains("EXERCISED-AUTHORITY"),
            "got: {}",
            act_resp.body
        );
    }

    #[test]
    fn login_form_asks_two_fields_only_no_cid_field() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("text/html"));
        let body = &resp.body;

        // A real graphical login FORM with EXACTLY the two human inputs.
        assert!(body.contains("<form"), "must render a login form");
        assert!(
            body.contains("id=\"identifier\"") && body.contains("id=\"password\""),
            "must present the identifier + unlock-factor inputs"
        );
        // NO CID field — a third field would be a bug for node-side custody.
        assert!(
            !body.contains("id=\"cid\"") && !body.contains("id=\"keymat\""),
            "the node-side custody login must NOT ask for a CID / key material"
        );
        // The script drives the handshake as hidden plumbing.
        assert!(body.contains("<script"), "must embed a client-side script");
        assert!(
            body.contains("/nonce") && body.contains("/login"),
            "the script must drive the /nonce and /login endpoints itself"
        );
        // It transitions into an authenticated portal view.
        assert!(
            body.contains("id=\"portal\""),
            "must transition into an authenticated portal view"
        );
    }

    #[test]
    fn root_page_is_the_interactive_portal_not_the_protocol_description() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let lower = resp.body.to_lowercase();
        assert!(
            !(lower.contains("get <code>/nonce</code> for a challenge")
                || lower.contains("post the signature to")),
            "the page must NOT be the bare protocol-description text"
        );
    }

    #[test]
    fn get_root_over_http_yields_a_2xx_response_with_a_body() {
        use std::io::Read as _;

        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(!addr.ip().is_loopback(), "must bind a non-loopback address");

        let handle = std::thread::spawn(move || {
            let (mut ctx, _subkey) = provisioned_ctx();
            let stream = listener
                .incoming()
                .next()
                .expect("one connection")
                .expect("accept");
            super::handle_connection(stream, &mut ctx);
        });

        let connect = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let mut client = TcpStream::connect(connect).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: pillar.example.com\r\n\r\n")
            .expect("write request");
        let mut raw = String::new();
        client.read_to_string(&mut raw).expect("read response");
        handle.join().expect("server thread");

        let status_line = raw.lines().next().expect("a status line");
        assert!(
            status_line.starts_with("HTTP/1.1 2"),
            "expected an HTTP/1.1 2xx status line, got: {status_line}"
        );
        let (_, body) = raw.split_once("\r\n\r\n").expect("a header/body separator");
        assert!(!body.is_empty(), "expected a non-empty response body");
    }

    #[test]
    fn every_response_carries_the_current_api_version_header() {
        // The HTTP ingest API's OWN version stamp is advertised on EVERY
        // response — asserted against served raw response bytes, so a client
        // (or Ingress) always learns the API version it was served at. This is
        // independent of any message/event version the body carries.
        use std::io::Read as _;

        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");

        let handle = std::thread::spawn(move || {
            let (mut ctx, _subkey) = provisioned_ctx();
            let stream = listener
                .incoming()
                .next()
                .expect("one connection")
                .expect("accept");
            super::handle_connection(stream, &mut ctx);
        });

        let connect = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let mut client = TcpStream::connect(connect).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: pillar.example.com\r\n\r\n")
            .expect("write request");
        let mut raw = String::new();
        client.read_to_string(&mut raw).expect("read response");
        handle.join().expect("server thread");

        let expected = format!("{API_VERSION_HEADER}: {API_VERSION}");
        assert_eq!(
            expected, "X-Pillar-Api-Version: v1",
            "the advertised header line is the stable v1 stamp"
        );
        assert!(
            raw.lines().any(|l| l.trim_end() == expected),
            "every response must carry `{expected}`, got:\n{raw}"
        );
    }

    #[test]
    fn a_request_without_the_api_version_header_is_served_normally() {
        // Backward compatibility: a request that asserts NO API version is
        // accepted and served at the current version (the `get`/`post` helpers
        // send `api_version: None`).
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/bootstrap/status");
        assert_eq!(
            resp.status, 200,
            "a header-less request is served backward-compatibly"
        );
    }

    #[test]
    fn a_future_api_version_is_rejected_distinctly_from_a_404_or_parse_path() {
        // A legible-but-unknown FUTURE version (`v2`) is Unsupported — a
        // DISTINCT 505, NAMING the version — never confused with a 404
        // (unknown route) or a 400 (malformed request/parse) path.
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get_with_api_version(&mut ctx, "/bootstrap/status", "v2");
        assert_eq!(
            resp.status, 505,
            "a future API version yields the distinct unsupported-version status"
        );
        assert!(
            resp.body.contains("UNSUPPORTED") && resp.body.contains("v2"),
            "the body must name the unsupported API version, got: {}",
            resp.body
        );
        // Distinct from an unknown-route 404 …
        let not_found = get(&mut ctx, "/no-such-route");
        assert_eq!(not_found.status, 404);
        assert_ne!(
            resp.status, not_found.status,
            "unsupported-version must NOT be the 404 path"
        );
        // … and distinct from a normal (accepted) served response.
        let ok = get_with_api_version(&mut ctx, "/bootstrap/status", "v1");
        assert_eq!(ok.status, 200, "the CURRENT version is accepted");
        assert_ne!(resp.status, ok.status);
    }

    #[test]
    fn a_malformed_api_version_header_is_a_parse_error_not_the_unsupported_case() {
        // A garbage header value is a PARSE error (400) — the malformed
        // family — deliberately distinct from the stamped-but-unknown-future
        // (505) case above.
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get_with_api_version(&mut ctx, "/bootstrap/status", "not-a-version");
        assert_eq!(
            resp.status, 400,
            "an illegible API version header is a parse error (400)"
        );
        assert!(
            resp.body.contains("MALFORMED"),
            "the body must flag the malformed header, got: {}",
            resp.body
        );
        // And it is NOT the 505 unsupported-version status.
        let future = get_with_api_version(&mut ctx, "/bootstrap/status", "v2");
        assert_eq!(future.status, 505);
        assert_ne!(
            resp.status, future.status,
            "malformed (400) and unsupported-version (505) must be distinct"
        );
    }

    #[test]
    fn a_wrong_password_surfaces_a_clear_unlock_failed_message() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let resp = post(&mut ctx, "/login", &format!("alice@pillar\nwrong\n{id}"));
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("unlock-failed"), "got: {}", resp.body);
    }

    #[test]
    fn a_node_without_an_offer_surfaces_the_new_no_offer_mode() {
        // A node that holds NO offer for this user (or lacks the label) must
        // surface the NEW node-custody mode, distinct from a wrong password.
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let resp = post(
            &mut ctx,
            "/login",
            &format!("nobody@pillar\n{PASSWORD}\n{id}"),
        );
        assert_eq!(resp.status, 401);
        assert!(
            resp.body.contains("no-offer-for-user"),
            "got: {}",
            resp.body
        );
    }

    // The first-run BOOTSTRAP flow: a fresh node serves the create-cell ->
    // create-first-user flow; the first create consumes the one-shot
    // capability (a second cell-key create-user is refused) and links
    // cell<->initial-user; a bootstrapped node reports BOOTSTRAPPED.
    #[test]
    fn fresh_node_serves_create_cell_then_create_first_user_consuming_the_capability() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        // Fresh: status FRESH.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        // Cannot create a user before the cell.
        let early = post(
            &mut ctx,
            "/bootstrap/create-user",
            &format!("spencer\n{PASSWORD}"),
        );
        assert_eq!(early.status, 409);
        assert!(early.body.contains("NoCellYet"), "got: {}", early.body);

        // (a) create the cell.
        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        assert!(cell.body.contains("CELL-CREATED"));

        // (b) create the first user — consumes the one-shot capability.
        let user = post(
            &mut ctx,
            "/bootstrap/create-user",
            &format!("spencer\n{PASSWORD}"),
        );
        assert_eq!(user.status, 200);
        assert!(user.body.contains("USER-CREATED spencer"));

        // Now BOOTSTRAPPED, cell<->user linked.
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));

        // A SECOND cell-key create-user is refused (capability spent).
        let second = post(
            &mut ctx,
            "/bootstrap/create-user",
            &format!("second-user\n{PASSWORD}"),
        );
        assert_eq!(second.status, 409);
        assert!(
            second.body.contains("CapabilitySpent"),
            "got: {}",
            second.body
        );
    }

    // Regression: the observed bug — after create-cell -> create-first-user
    // on a fresh bootstrap node, login used to fail "no offer for you" for
    // the very user just created. The bootstrap create-first-user step MUST
    // atomically apply the key-distribution label + escrow the new user's
    // node-sealed offer to this node, so the FIRST login succeeds
    // immediately, with no separate operator provisioning step.
    #[test]
    fn first_login_immediately_after_bootstrap_succeeds_with_no_extra_provisioning() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        let user = post(
            &mut ctx,
            "/bootstrap/create-user",
            &format!("spencer\n{PASSWORD}"),
        );
        assert_eq!(user.status, 200, "got: {}", user.body);

        // Log in as the just-created user with NO further offer provisioning.
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let login = post(&mut ctx, "/login", &format!("spencer\n{PASSWORD}\n{id}"));
        assert_eq!(
            login.status, 200,
            "first login right after bootstrap must succeed, got: {}",
            login.body
        );
        assert!(login.body.contains("spencer"), "got: {}", login.body);

        // A wrong password on the same identifier is still a plain
        // unlock-failed, never the no-offer mode — proving the offer really
        // is present and the failure mode is unlock-specific.
        let nonce_resp2 = get(&mut ctx, "/nonce");
        let id2: u64 = nonce_resp2
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let bad = post(&mut ctx, "/login", &format!("spencer\nwrong\n{id2}"));
        assert_eq!(bad.status, 401);
        assert!(bad.body.contains("unlock-failed"), "got: {}", bad.body);
    }

    #[test]
    fn a_bootstrapped_node_reports_bootstrapped_directly() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // A node is BOOTSTRAPPED only once it has a cell AND its first user;
        // a cell alone is still FRESH (see the status endpoint). Bootstrap it
        // fully through the atomic step.
        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("cell-genesis\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
    }

    #[test]
    fn create_cell_refuses_a_name_already_claimed_on_the_network_with_a_clear_message() {
        use pillar_web::node_custody::InMemoryCellNameRegistry;
        // A node whose swarm view already serves a pointer for "cell-genesis".
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("cell-genesis");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        )
        .with_cell_name_registry(Box::new(registry));

        // The web-UI create-cell step must REFUSE with the clear message and
        // must NOT create the colliding cell.
        let resp = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(resp.status, 409);
        assert!(
            resp.body
                .contains("cell name already in use — choose another"),
            "got: {}",
            resp.body
        );
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
        assert!(!ctx.bootstrap().is_bootstrapped());

        // A DIFFERENT, free name is accepted (best-effort check does not block
        // an unclaimed name).
        let ok = post(&mut ctx, "/bootstrap/create-cell", "cell-unique");
        assert_eq!(ok.status, 200);
        assert!(ok.body.contains("CELL-CREATED"), "got: {}", ok.body);
        // Cell created but NO first user yet — still FRESH (BOOTSTRAPPED is
        // reserved for a cell WITH its first user), so a reload keeps showing
        // the bootstrap form instead of stranding on the login form.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
    }

    // The atomic single-step bootstrap (POST /bootstrap/create): one request
    // creates the cell AND the first user, leaving the node fully
    // BOOTSTRAPPED, and the just-created user can log in immediately.
    #[test]
    fn atomic_bootstrap_creates_cell_and_first_user_in_one_step() {
        let (mut ctx, _subkey) = provisioned_ctx();
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("spencer-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert!(
            done.body.contains("BOOTSTRAPPED spencer"),
            "got: {}",
            done.body
        );
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));

        // The just-created user logs in immediately (offer escrowed atomically).
        let nonce = get(&mut ctx, "/nonce");
        let id: u64 = nonce
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let login = post(&mut ctx, "/login", &format!("spencer\n{PASSWORD}\n{id}"));
        assert_eq!(login.status, 200, "got: {}", login.body);
    }

    // Recovery: a node stranded in the OLD bug's half-state (cell created, no
    // first user) is completed by the atomic endpoint rather than erroring —
    // exactly the reload/back-button situation the operator hit.
    #[test]
    fn atomic_bootstrap_recovers_a_half_created_cell_without_a_user() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // Simulate the stranded state: only the cell was created (old step a).
        let cell = post(&mut ctx, "/bootstrap/create-cell", "spencer-cell");
        assert_eq!(cell.status, 200);
        // Status is still FRESH (no first user yet) — so the portal re-shows the
        // bootstrap form on reload, and the atomic create completes it.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("spencer-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert!(
            done.body.contains("BOOTSTRAPPED spencer"),
            "got: {}",
            done.body
        );
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));
    }

    // Log alice in through the real HTTP handshake and return her session token.
    fn login_alice(ctx: &mut WebAuthContext) -> String {
        let nonce = get(ctx, "/nonce");
        let nonce_id = nonce.body.split_whitespace().nth(1).unwrap().to_owned();
        let login = post(
            ctx,
            "/login",
            &format!("alice@pillar\n{PASSWORD}\n{nonce_id}"),
        );
        assert_eq!(login.status, 200, "login body: {}", login.body);
        login.session_token.expect("session token")
    }

    #[test]
    fn node_bootstrap_request_can_be_submitted_listed_and_approved_returning_a_cid() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // A request can only join an EXISTING cell.
        assert_eq!(
            post(&mut ctx, "/bootstrap/request/node", "new-node").status,
            409
        );
        assert_eq!(
            post(&mut ctx, "/bootstrap/create-cell", "spencer-cell").status,
            200
        );

        // Submit a node request carrying identifying info.
        let body = "new-node\n12D3KooWpeer\npillar 0.0.0\nlinux\nbafy-nodekey\ntpm\npub=/ip4/203.0.113.7/tcp/4001\nlabel=edge";
        let submitted = post(&mut ctx, "/bootstrap/request/node", body);
        assert_eq!(submitted.status, 200);
        assert!(
            submitted.body.starts_with("REQUEST "),
            "got: {}",
            submitted.body
        );
        let id = submitted.body.trim_start_matches("REQUEST ").trim();

        // It shows up in the pending list.
        let list = get(&mut ctx, "/bootstrap/request/list");
        assert!(list.body.contains("node new-node"), "got: {}", list.body);

        // Approving without authentication is refused.
        let unauth = post(
            &mut ctx,
            "/bootstrap/request/approve",
            &format!("{id}\nnot-a-token"),
        );
        assert_eq!(unauth.status, 401);

        // Authenticated approval seals the cell key and returns its CID.
        let token = login_alice(&mut ctx);
        let approved = post(
            &mut ctx,
            "/bootstrap/request/approve",
            &format!("{id}\n{token}"),
        );
        assert_eq!(approved.status, 200, "got: {}", approved.body);
        assert!(
            approved.body.contains("APPROVED bafy-cellkey-"),
            "got: {}",
            approved.body
        );

        // The request is terminal: a second decision is refused.
        let again = post(
            &mut ctx,
            "/bootstrap/request/approve",
            &format!("{id}\n{token}"),
        );
        assert_eq!(again.status, 409);
    }

    #[test]
    fn user_bootstrap_request_approval_escrows_and_returns_no_cell_key() {
        let (mut ctx, _subkey) = provisioned_ctx();
        assert_eq!(
            post(&mut ctx, "/bootstrap/create-cell", "spencer-cell").status,
            200
        );
        let submitted = post(
            &mut ctx,
            "/bootstrap/request/user",
            "new-user\npassword\nlabel=ops",
        );
        assert_eq!(submitted.status, 200);
        let id = submitted
            .body
            .trim_start_matches("REQUEST ")
            .trim()
            .to_owned();
        let token = login_alice(&mut ctx);
        let approved = post(
            &mut ctx,
            "/bootstrap/request/approve",
            &format!("{id}\n{token}"),
        );
        assert_eq!(approved.status, 200, "got: {}", approved.body);
        assert!(approved.body.contains("ESCROWED"), "got: {}", approved.body);
    }

    // The real authenticated portal: an unauthenticated request for node
    // identity/peer/lease status is refused, exactly like every other
    // signing/read action gated behind login.
    #[test]
    fn portal_status_requires_an_admitted_session() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/portal/status?token=not-a-token");
        assert_eq!(resp.status, 401);
        assert!(
            resp.body.contains("not-authenticated"),
            "got: {}",
            resp.body
        );
    }

    // Once admitted, the portal renders node/identity status (PeerId, listen
    // addrs, uptime), peer list + count, and the lease holder — all from this
    // node's live view, never a server-side database.
    #[test]
    fn authenticated_portal_renders_identity_status_peer_list_and_lease_holder() {
        let (mut ctx, _subkey) = provisioned_ctx();
        ctx = ctx.with_identity(NodeIdentitySnapshot {
            peer_id: "12D3KooWThisNode".to_owned(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/4001".to_owned()],
            connected_peers: vec!["peer-a".to_owned(), "peer-b".to_owned()],
        });
        let token = login_alice(&mut ctx);

        let resp = get(&mut ctx, &format!("/portal/status?token={token}"));
        assert_eq!(resp.status, 200, "got: {}", resp.body);
        assert!(
            resp.body.contains("PEER-ID 12D3KooWThisNode"),
            "got: {}",
            resp.body
        );
        assert!(
            resp.body.contains("LISTEN /ip4/0.0.0.0/tcp/4001"),
            "got: {}",
            resp.body
        );
        assert!(resp.body.contains("PEER-COUNT 2"), "got: {}", resp.body);
        assert!(
            resp.body.contains("PEERS peer-a,peer-b"),
            "got: {}",
            resp.body
        );
        assert!(resp.body.contains("UPTIME-SECS"), "got: {}", resp.body);
        // A solo node self-grants its lease at construction, so it reports
        // itself ("owner") as holder out of the box.
        assert!(
            resp.body.contains("LEASE-HOLDER owner"),
            "got: {}",
            resp.body
        );
    }

    // A UI-persisted layout is a signed, content-addressed resource riding the
    // streaming DB (`pillar-streamdb`) — never a server-side database. Storing
    // The identity & domain UI: enroll --domain (one per-domain subkey),
    // shows per-domain keys, rotate-primary preserves the identity CID,
    // and offers recover — also CID-preserving.
    #[test]
    fn identity_ui_enroll_shows_per_domain_keys_rotate_preserves_cid_and_recover_works() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthenticated view/enroll is refused.
        assert_eq!(get(&mut ctx, "/portal/identity?token=nope").status, 401);
        assert_eq!(
            post(&mut ctx, "/portal/identity/enroll", "nope\nwork").status,
            401
        );

        let cid_before = ctx.identity_log().cid().0.clone();

        let enrolled = post(
            &mut ctx,
            "/portal/identity/enroll",
            &format!("{token}\nwork"),
        );
        assert_eq!(enrolled.status, 200, "got: {}", enrolled.body);
        assert!(
            enrolled.body.contains("DOMAIN work KEY"),
            "got: {}",
            enrolled.body
        );

        // A second enroll for the SAME domain is refused — one subkey per
        // domain.
        let dup = post(
            &mut ctx,
            "/portal/identity/enroll",
            &format!("{token}\nwork"),
        );
        assert_eq!(dup.status, 409, "got: {}", dup.body);

        let view = get(&mut ctx, &format!("/portal/identity?token={token}"));
        assert_eq!(view.status, 200, "got: {}", view.body);
        assert!(
            view.body.contains(&format!("CID {cid_before}")),
            "got: {}",
            view.body
        );
        assert!(
            view.body.contains("DOMAIN work KEY"),
            "must show the per-domain key: {}",
            view.body
        );

        // rotate-primary preserves the identity CID.
        let rotated = post(
            &mut ctx,
            "/portal/identity/rotate",
            &format!("{token}\nprimary-2"),
        );
        assert_eq!(rotated.status, 200, "got: {}", rotated.body);
        assert!(
            rotated.body.contains(&format!("CID {cid_before}")),
            "got: {}",
            rotated.body
        );
        assert_eq!(ctx.identity_log().cid().0, cid_before);
        assert_eq!(ctx.identity_log().head_generation(), 1);

        // recover also preserves the CID and installs a fresh primary,
        // authorized by the genesis recovery key (never the current primary).
        let recovered = post(&mut ctx, "/portal/identity/recover", token.as_str());
        assert_eq!(recovered.status, 200, "got: {}", recovered.body);
        assert!(
            recovered.body.contains(&format!("CID {cid_before}")),
            "got: {}",
            recovered.body
        );
        assert_eq!(ctx.identity_log().head_generation(), 2);
        assert_eq!(ctx.identity_log().cid().0, cid_before);
    }

    // The domain (naming-only) grouping view: lists cells per domain and
    // exposes NO domain-signing/granting/coordinating route — a domain here
    // signs nothing (property, per naming-authority-plane-spec).
    #[test]
    fn domain_grouping_view_lists_cells_and_signs_nothing() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        post(
            &mut ctx,
            "/portal/identity/enroll",
            &format!("{token}\nwork"),
        );

        assert_eq!(get(&mut ctx, "/portal/domains?token=nope").status, 401);
        let view = get(&mut ctx, &format!("/portal/domains?token={token}"));
        assert_eq!(view.status, 200, "got: {}", view.body);
        assert!(
            view.body.contains("DOMAIN work CELLS"),
            "must list the domain's cells: {}",
            view.body
        );
        assert!(view.body.contains("work-cell-1"), "got: {}", view.body);

        // Property: no domain-signing/granting/coordinating route exists.
        assert_eq!(
            post(&mut ctx, "/portal/domains/sign", &format!("{token}\nwork")).status,
            404
        );
        assert_eq!(
            post(&mut ctx, "/portal/domains/grant", &format!("{token}\nwork")).status,
            404
        );
        assert_eq!(
            post(
                &mut ctx,
                "/portal/domains/coordinate",
                &format!("{token}\nwork")
            )
            .status,
            404
        );
    }

    // User/member management: add/invite/role changes are signed acts
    // (unauthorized refused); the identity view also renders the
    // multi-domain view (one global identity across its domains/cells).
    #[test]
    fn member_management_signed_acts_and_multi_domain_view() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthorized add/role-change is refused. `/portal/members/add` is
        // gated first through the non-loopback signing-action peer gate (a
        // bad/absent session on a non-loopback peer is always 403), then
        // through the decider; `/portal/members/role` has no peer gate, so
        // an unauthenticated caller reads 401.
        assert_eq!(
            post(&mut ctx, "/portal/members/add", "bad-token\nbob\nmember").status,
            403
        );
        assert_eq!(
            post(&mut ctx, "/portal/members/role", "bad-token\nbob\nadmin").status,
            401
        );

        let added = post(
            &mut ctx,
            "/portal/members/add",
            &format!("{token}\nbob\nmember"),
        );
        assert_eq!(added.status, 200, "got: {}", added.body);
        assert!(
            added.body.contains("MEMBER bob ROLE member"),
            "got: {}",
            added.body
        );
        // The real signed-action surface: provenance is rendered — signer,
        // the exercised WoT authority, and the emitted event's CID.
        assert!(added.body.contains("SIGNER"), "got: {}", added.body);
        assert!(added.body.contains("EVENT-CID"), "got: {}", added.body);
        assert!(
            added.body.contains("EXERCISED-AUTHORITY"),
            "got: {}",
            added.body
        );

        let listed = get(&mut ctx, &format!("/portal/members?token={token}"));
        assert_eq!(listed.status, 200, "got: {}", listed.body);
        assert!(
            listed.body.contains("MEMBER bob ROLE member"),
            "got: {}",
            listed.body
        );

        let role_changed = post(
            &mut ctx,
            "/portal/members/role",
            &format!("{token}\nbob\nadmin"),
        );
        assert_eq!(role_changed.status, 200, "got: {}", role_changed.body);
        assert!(
            role_changed.body.contains("MEMBER bob ROLE admin"),
            "got: {}",
            role_changed.body
        );

        // Role change on an unknown member is refused.
        let unknown = post(
            &mut ctx,
            "/portal/members/role",
            &format!("{token}\nghost\nadmin"),
        );
        assert_eq!(unknown.status, 404, "got: {}", unknown.body);

        // Multi-domain view: one global identity across multiple domains,
        // each with its own per-domain key.
        post(
            &mut ctx,
            "/portal/identity/enroll",
            &format!("{token}\nwork"),
        );
        post(
            &mut ctx,
            "/portal/identity/enroll",
            &format!("{token}\nhome"),
        );
        let view = get(&mut ctx, &format!("/portal/identity?token={token}"));
        assert!(view.body.contains("DOMAIN work KEY"), "got: {}", view.body);
        assert!(view.body.contains("DOMAIN home KEY"), "got: {}", view.body);
    }

    // `perform_signed_act` IS the real decider-authorized signed-action
    // surface: a subject `admit_subject` has grown into this node's WoT
    // authority graph is authorized (real WoT-authorized event, one
    // signed event emitted), while a subject the graph has never admitted
    // is refused, fail-closed, mutating nothing — never a placeholder
    // in-memory toggle.
    #[test]
    fn perform_signed_act_authorizes_wot_reachable_subjects_and_refuses_unreachable_ones() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        let session = ctx
            .login_session_for(&token)
            .cloned()
            .expect("admitted session");
        let admitted = session.subject.clone();

        let before = ctx.act_log.len();
        let event = ctx
            .perform_signed_act(&admitted, "portal:members:write", "MEMBER-ADD bob member")
            .expect("an admitted (WoT-reachable) subject is authorized");
        assert_eq!(
            ctx.act_log.len(),
            before + 1,
            "exactly one signed event emitted"
        );
        assert!(ctx
            .exercised_authority(&admitted)
            .contains("WoT-depth-default"));
        let _ = event;

        let stranger = NodeId::from("never-admitted-stranger");
        let before = ctx.act_log.len();
        let refused =
            ctx.perform_signed_act(&stranger, "portal:members:write", "MEMBER-ADD ghost member");
        assert_eq!(
            refused,
            Err(stranger.clone()),
            "an unreachable subject is refused"
        );
        assert_eq!(ctx.act_log.len(), before, "a refused act emits no event");
        assert_eq!(
            ctx.exercised_authority(&stranger),
            "(unreachable; no authority to exercise)"
        );
    }

    // The portal HTML renders the identity/domain and members tiles.
    #[test]
    fn portal_renders_identity_domain_and_member_management_ui() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let body = &resp.body;
        assert!(
            body.contains("id=\"identity-tile\""),
            "must render the identity tile"
        );
        assert!(
            body.contains("id=\"identity-domain-input\""),
            "must offer enroll --domain"
        );
        assert!(
            body.contains("id=\"identity-rotate-btn\""),
            "must offer rotate-primary"
        );
        assert!(
            body.contains("id=\"identity-recover-btn\""),
            "must offer recover"
        );
        assert!(
            body.contains("id=\"identity-domain-keys\""),
            "must show per-domain keys"
        );
        assert!(
            body.contains("id=\"domain-tile\""),
            "must render the domain grouping view"
        );
        assert!(
            body.contains("id=\"members-tile\""),
            "must render user/member management"
        );
        assert!(
            body.contains("id=\"member-add-form\""),
            "must offer add/invite"
        );
        assert!(
            body.contains("id=\"sessions-tile\""),
            "must render the session-management panel"
        );
        assert!(
            body.contains("id=\"session-list\""),
            "must render the active-sessions list"
        );
        assert!(
            body.contains("id=\"signout-everywhere-btn\""),
            "must offer sign-out-everywhere"
        );
    }

    // The UI-persisted layout resource, signed and content-addressed over the
    // streaming DB (`pillar-streamdb`), applies unchanged: the portal's UI
    // requires an admitted session (the resource is signed by that session's
    // subject); it round-trips by its content-addressed CID and advances the
    // log's streaming tip.
    #[test]
    fn ui_persisted_layout_round_trips_as_a_signed_streaming_db_resource() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthenticated store is refused.
        let refused = post(&mut ctx, "/portal/layout", "bad-token\n{\"widgets\":[]}");
        assert_eq!(refused.status, 401);

        let tip_before = ctx.layout_tip();
        let stored = post(
            &mut ctx,
            "/portal/layout",
            &format!("{token}\n{{\"widgets\":[\"peers\",\"inbox\"]}}"),
        );
        assert_eq!(stored.status, 200, "got: {}", stored.body);
        assert!(
            stored.body.starts_with("LAYOUT-CID "),
            "got: {}",
            stored.body
        );
        let cid: String = stored.body.split_whitespace().nth(1).unwrap().to_owned();
        // The streaming tip (Merkle root) advanced once the op was appended.
        assert_ne!(ctx.layout_tip(), tip_before);

        // Unauthenticated fetch is refused.
        let refused_get = get(&mut ctx, &format!("/portal/layout?token=nope&cid={cid}"));
        assert_eq!(refused_get.status, 401);

        // Authenticated fetch round-trips the signed content, attributed to
        // the storing session's subject.
        let fetched = get(&mut ctx, &format!("/portal/layout?token={token}&cid={cid}"));
        assert_eq!(fetched.status, 200, "got: {}", fetched.body);
        assert!(fetched.body.contains("SIGNER"), "got: {}", fetched.body);
        assert!(
            fetched
                .body
                .contains("CONTENT {\"widgets\":[\"peers\",\"inbox\"]}"),
            "got: {}",
            fetched.body
        );
    }

    // The request-approval inbox UI: the portal HTML renders the pending
    // request's fields and Approve/Reject controls wired to the existing
    // backend endpoints (no bare protocol description — a real UI).
    #[test]
    fn request_inbox_ui_renders_list_and_approve_reject_controls() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let body = &resp.body;
        assert!(
            body.contains("id=\"inbox-list\""),
            "must render an inbox list container"
        );
        assert!(
            body.contains("/bootstrap/request/list"),
            "must fetch the pending request list"
        );
        assert!(
            body.contains("/bootstrap/request/approve")
                && body.contains("/bootstrap/request/reject"),
            "must dispatch Approve/Reject through the existing endpoints"
        );
        assert!(
            body.contains("Approve") && body.contains("Reject"),
            "got: {}",
            body
        );
        // The identity/peer/lease-holder tile is also rendered.
        assert!(
            body.contains("id=\"portal-peer-id\""),
            "must render node identity"
        );
        assert!(
            body.contains("id=\"portal-lease-holder\""),
            "must render lease holder"
        );
    }

    // The shipped bootstrap flow + status semantics still pass unchanged —
    // regression guard against this task's additions.
    #[test]
    fn bootstrap_flow_and_status_semantics_are_unregressed_by_the_portal_additions() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("regress-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
    }

    // UX hardening: a LIVE cell-name uniqueness check surfaces an in-UI "already
    // in use" BEFORE submit, using the SAME peer-sourced name registry the
    // create-cell step validates against. Best-effort: an unreachable/unclaimed
    // name resolves FREE (never blocks).
    #[test]
    fn live_cell_name_uniqueness_check_surfaces_in_use_before_submit() {
        use pillar_web::node_custody::InMemoryCellNameRegistry;
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("cell-genesis");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        )
        .with_cell_name_registry(Box::new(registry));

        // A claimed name reports IN-USE with the clear shared message, WITHOUT
        // creating anything (still FRESH afterwards).
        let taken = get(&mut ctx, "/bootstrap/name-check?name=cell-genesis");
        assert_eq!(taken.status, 200, "got: {}", taken.body);
        assert!(taken.body.starts_with("IN-USE"), "got: {}", taken.body);
        assert!(
            taken
                .body
                .contains("cell name already in use — choose another"),
            "got: {}",
            taken.body
        );

        // A free (or unreachable) name reports FREE — the best-effort rule.
        let free = get(&mut ctx, "/bootstrap/name-check?name=cell-unique");
        assert_eq!(free.status, 200, "got: {}", free.body);
        assert_eq!(free.body.trim(), "FREE");

        // The check is non-mutating: the node is still un-bootstrapped.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
        assert!(!ctx.bootstrap().is_bootstrapped());

        // The web UI wires this endpoint into the cell-name field for the inline
        // hint (a real in-UI surface, not just a backend route).
        let page = get(&mut ctx, "/");
        assert!(
            page.body.contains("/bootstrap/name-check"),
            "the portal must query the live name-check for an inline hint"
        );
        assert!(
            page.body.contains("id=\"cell-name-hint\""),
            "the portal must render an inline cell-name validation hint"
        );
    }

    // UX hardening: a representative mutating control asserts a pending/disabled
    // state while its signed event is in flight (no double-submit) and
    // re-enables on the result.
    #[test]
    fn a_representative_act_shows_a_pending_disabled_state_with_no_double_submit() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let body = get(&mut ctx, "/").body;
        // The pending-state helper exists and gates double-submit + re-enables.
        assert!(
            body.contains("withPending"),
            "must have a pending-state wrapper"
        );
        assert!(
            body.contains("aria-busy") && body.contains("guard double-submit"),
            "must set a busy state and guard against double-submit"
        );
        assert!(
            body.contains("btn.disabled = true") && body.contains("btn.disabled = false"),
            "must disable while in flight and re-enable on the result"
        );
        // The representative act (inbox approve/reject) routes its click through
        // the pending wrapper.
        assert!(
            body.contains("decideRequest(btn,"),
            "the approve/reject act must run through the pending wrapper"
        );
    }

    // UX hardening: copy-to-clipboard affordances render for a CID / PeerId /
    // fingerprint field.
    #[test]
    fn copy_to_clipboard_affordances_render_for_cid_peerid_fingerprint() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let body = get(&mut ctx, "/").body;
        assert!(
            body.contains("data-copy-field=\"PeerId\""),
            "PeerId must have a copy affordance"
        );
        assert!(
            body.contains("data-copy-field=\"fingerprint\""),
            "a fingerprint must have a copy affordance"
        );
        // The CID copy affordance is applied to an approval's returned CID at
        // runtime (data-copy-field=\"CID\"), and the clipboard helper exists.
        assert!(
            body.contains("data-copy-field=\"CID\""),
            "an approval's CID must get a copy affordance"
        );
        assert!(
            body.contains("copyText") && body.contains("attachCopyButton"),
            "must ship a copy-to-clipboard implementation"
        );
    }

    // UX hardening: an approval AND an attestation each render a plain-language
    // "what happens next" explainer describing what the signed act authorizes.
    #[test]
    fn approval_and_attestation_each_render_a_what_happens_next_explainer() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let body = get(&mut ctx, "/").body;
        // The bootstrap (first signed cell/attestation act) explainer.
        assert!(
            body.contains("id=\"bootstrap-explainer\""),
            "the bootstrap attestation act must render a what-happens-next explainer"
        );
        // The inbox approval explainer, describing the attestation the approval
        // signs.
        assert!(
            body.contains("What happens next") && body.contains("signs an attestation"),
            "the approval act must render a what-happens-next explainer"
        );
        assert!(
            body.contains("class=\"explainer\""),
            "explainers must render as a distinct UI affordance"
        );
    }

    // The session-management panel: lists the registry's active sessions for
    // the authenticated user with expiry, marking the caller's own current
    // session; requires an admitted session (unauthenticated refused).
    #[test]
    fn session_panel_lists_active_sessions_with_expiry_and_marks_current() {
        let (mut ctx, _subkey) = provisioned_ctx();

        // Unauthenticated is refused.
        assert_eq!(get(&mut ctx, "/portal/sessions?token=nope").status, 401);

        let first = login_alice(&mut ctx);
        let listed = get(&mut ctx, &format!("/portal/sessions?token={first}"));
        assert_eq!(listed.status, 200, "got: {}", listed.body);
        assert!(
            listed.body.contains(&format!("SESSION {first} ")),
            "got: {}",
            listed.body
        );
        assert!(
            listed.body.contains("ISSUED") && listed.body.contains("EXPIRY"),
            "must render issued-at and expiry for a live countdown: {}",
            listed.body
        );
        assert!(
            listed
                .body
                .contains(&format!("SESSION {first} NODE this-node")),
            "must render the node/domain the session was issued on: {}",
            listed.body
        );
        assert!(
            listed.body.contains("CURRENT yes"),
            "the caller's own session must be marked current: {}",
            listed.body
        );

        // A second concurrent login for the same principal shows up too, and
        // is correctly marked NOT current from the first session's own view.
        let second = login_alice(&mut ctx);
        assert_ne!(first, second);
        let listed2 = get(&mut ctx, &format!("/portal/sessions?token={first}"));
        assert!(
            listed2.body.contains(&format!("SESSION {second} "))
                && listed2
                    .body
                    .contains(&format!("SESSION {second} NODE this-node ISSUED"))
                && listed2
                    .body
                    .lines()
                    .find(|l| l.contains(&format!("SESSION {second} ")))
                    .expect("second session line")
                    .contains("CURRENT no"),
            "got: {}",
            listed2.body
        );
    }

    // Revoke ONE session: emits exactly one decider-authorized act; the
    // session drops and its bearer actions (here a real signed act,
    // /portal/members/add) fail closed, while a sibling session for the
    // same principal is untouched.
    #[test]
    fn revoke_one_session_drops_it_and_fails_its_bearer_actions_closed() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let victim = login_alice(&mut ctx);
        let survivor = login_alice(&mut ctx);

        // The victim session currently admits a bearer action.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/members/add",
                &format!("{victim}\ndan\nmember")
            )
            .status,
            200
        );

        // Unauthorized revoke attempt (bad caller token) is refused.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/sessions/revoke",
                &format!("bad-token\n{victim}")
            )
            .status,
            401
        );
        // Revoking an unknown id is refused.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/sessions/revoke",
                &format!("{survivor}\nno-such-id")
            )
            .status,
            404
        );

        let revoked = post(
            &mut ctx,
            "/portal/sessions/revoke",
            &format!("{survivor}\n{victim}"),
        );
        assert_eq!(revoked.status, 200, "got: {}", revoked.body);
        assert!(
            revoked.body.contains(&format!("REVOKED {victim}")),
            "got: {}",
            revoked.body
        );

        // The revoked session's bearer actions now fail closed.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/members/add",
                &format!("{victim}\neve\nmember")
            )
            .status,
            403
        );
        // The surviving sibling session is untouched.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/members/add",
                &format!("{survivor}\nfrank\nmember")
            )
            .status,
            200
        );

        // The panel no longer lists the revoked session.
        let listed = get(&mut ctx, &format!("/portal/sessions?token={survivor}"));
        assert!(
            !listed.body.contains(&format!("SESSION {victim} ")),
            "got: {}",
            listed.body
        );
    }

    // Sign out everywhere: revoke-all drops EVERY one of the caller's
    // sessions, all of them failing closed afterward.
    #[test]
    fn sign_out_everywhere_revokes_all_sessions() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let one = login_alice(&mut ctx);
        let two = login_alice(&mut ctx);
        let three = login_alice(&mut ctx);

        // Unauthorized revoke-all attempt is refused.
        assert_eq!(
            post(&mut ctx, "/portal/sessions/revoke-all", "bad-token").status,
            401
        );

        let resp = post(&mut ctx, "/portal/sessions/revoke-all", &one);
        assert_eq!(resp.status, 200, "got: {}", resp.body);
        assert!(resp.body.contains("REVOKED-ALL"), "got: {}", resp.body);

        for token in [&one, &two, &three] {
            assert_eq!(
                post(
                    &mut ctx,
                    "/portal/members/add",
                    &format!("{token}\ngrace\nmember")
                )
                .status,
                403,
                "every session must fail closed after sign-out-everywhere"
            );
        }
    }

    // The attestation builder composes an attestation with capacity
    // `<role>@<scope>`, subject, predicate (incl. the `--quota cpu=1000m`
    // budget form), scope — and renders BOTH the natural-language sentence
    // AND the full proof chain. The genesis identity ("owner") holds every
    // capacity unconditionally.
    #[test]
    fn attestation_builder_composes_capacity_predicate_quota_and_renders_sentence_and_chain() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthorized build is refused.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/attestations/build",
                "bad-token\nowner\noperator@cell-b\n\nzoe\nstream:append\ncell-b/streams/*\ncpu=1000m\ncell-b",
            )
            .status,
            401
        );

        let built = post(
            &mut ctx,
            "/portal/attestations/build",
            &format!(
                "{token}\nowner\noperator@cell-b\n\nzoe\nstream:append\ncell-b/streams/*\ncpu=1000m\ncell-b"
            ),
        );
        assert_eq!(built.status, 200, "got: {}", built.body);
        assert!(built.body.starts_with("CID "), "got: {}", built.body);
        assert!(
            built.body.contains("SENTENCE owner attests zoe may stream:append cell-b/streams/* as role:operator@cell-b (scope cell-b"),
            "must render the composed sentence: {}",
            built.body
        );
        assert!(
            built.body.contains("rooted at genesis owner"),
            "sentence must render the full proof chain back to genesis: {}",
            built.body
        );
        assert!(
            built.body.contains("CHAIN "),
            "must render the CID chain: {}",
            built.body
        );
    }

    // An attestation the signer lacks capacity for is refused
    // (`TrustError::CapacityNotHeld`), never silently issued.
    #[test]
    fn attestation_the_signer_lacks_capacity_for_is_refused() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        let refused = post(
            &mut ctx,
            "/portal/attestations/build",
            &format!(
                "{token}\nmallory\noperator@cell-b\n\nzoe\nstream:append\ncell-b/streams/*\n\ncell-b"
            ),
        );
        assert_eq!(refused.status, 403, "got: {}", refused.body);
        assert!(
            refused.body.contains("capacity-not-held-mallory"),
            "got: {}",
            refused.body
        );
    }

    // The trust-graph view renders edges — a pure view: no signing, no
    // mutation of the underlying store.
    #[test]
    fn trust_graph_view_renders_edges() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        assert_eq!(get(&mut ctx, "/portal/trust-graph?token=nope").status, 401);

        // Empty before any attestation is issued.
        let empty = get(&mut ctx, &format!("/portal/trust-graph?token={token}"));
        assert_eq!(empty.status, 200);
        assert!(empty.body.trim().is_empty(), "got: {}", empty.body);

        post(
            &mut ctx,
            "/portal/attestations/build",
            &format!(
                "{token}\nowner\noperator@cell-b\n\nzoe\nstream:append\ncell-b/streams/*\n\ncell-b"
            ),
        );

        let view = get(&mut ctx, &format!("/portal/trust-graph?token={token}"));
        assert_eq!(view.status, 200, "got: {}", view.body);
        assert!(
            view.body.contains("EDGE owner -> zoe LABEL"),
            "got: {}",
            view.body
        );
    }

    // Key & offer UI: custody migration/rotation/seal-escrow/revoke each
    // drive a signed act (unauthorized refused).
    #[test]
    fn key_offer_ui_drives_custody_migration_rotation_seal_escrow_revoke_as_signed_acts() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthorized attempts are refused for every custody act.
        assert_eq!(
            post(
                &mut ctx,
                "/portal/custody/migrate",
                "bad\nalice\nnode-2\ncid-2"
            )
            .status,
            401
        );
        assert_eq!(
            post(&mut ctx, "/portal/custody/rotate", "bad\nalice\ncid-3").status,
            401
        );
        assert_eq!(
            post(&mut ctx, "/portal/custody/seal", "bad\nalice").status,
            401
        );
        assert_eq!(
            post(&mut ctx, "/portal/custody/revoke", "bad\nalice").status,
            401
        );

        // Rotate/seal on an unknown handle is refused (no custody record yet).
        assert_eq!(
            post(
                &mut ctx,
                "/portal/custody/rotate",
                &format!("{token}\nalice\ncid-3")
            )
            .status,
            404
        );
        assert_eq!(
            post(&mut ctx, "/portal/custody/seal", &format!("{token}\nalice")).status,
            404
        );

        // Migrate creates the record as a signed act.
        let migrated = post(
            &mut ctx,
            "/portal/custody/migrate",
            &format!("{token}\nalice\nnode-2\ncid-2"),
        );
        assert_eq!(migrated.status, 200, "got: {}", migrated.body);
        assert!(
            migrated.body.contains("MIGRATED alice"),
            "got: {}",
            migrated.body
        );
        assert_eq!(
            ctx.custody_of("alice").unwrap().holder,
            NodeId::from("node-2")
        );

        // Rotate now succeeds against the existing record.
        let rotated = post(
            &mut ctx,
            "/portal/custody/rotate",
            &format!("{token}\nalice\ncid-3"),
        );
        assert_eq!(rotated.status, 200, "got: {}", rotated.body);
        assert_eq!(ctx.custody_of("alice").unwrap().generation, 1);

        // Seal/escrow succeeds against the existing record.
        let sealed = post(&mut ctx, "/portal/custody/seal", &format!("{token}\nalice"));
        assert_eq!(sealed.status, 200, "got: {}", sealed.body);
        assert!(ctx.custody_of("alice").unwrap().sealed);

        // Revoke drops the record; a second revoke is refused (already gone).
        let revoked = post(
            &mut ctx,
            "/portal/custody/revoke",
            &format!("{token}\nalice"),
        );
        assert_eq!(revoked.status, 200, "got: {}", revoked.body);
        assert!(ctx.custody_of("alice").is_none());
        assert_eq!(
            post(
                &mut ctx,
                "/portal/custody/revoke",
                &format!("{token}\nalice")
            )
            .status,
            404
        );
    }

    // ---- resource / workload UI (ROI "Web portal / UI rework") -------------

    // The resource UI drives get/apply/edit/scale/rollout for a WORKLOAD kind:
    // a view (get) emits NO event; each act emits exactly ONE decider-
    // authorized signed event; an unauthenticated act is refused and signs
    // nothing.
    #[test]
    fn resource_ui_drives_get_apply_edit_scale_rollout_over_a_workload() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthenticated get/apply are refused.
        assert_eq!(get(&mut ctx, "/portal/resource/get?token=nope").status, 401);
        assert_eq!(
            post(&mut ctx, "/portal/resource/apply", "nope\nweb\napp:v1").status,
            401
        );

        // An empty get is a view: zero events.
        let before = ctx.resource_event_count();
        let empty = get(
            &mut ctx,
            &format!("/portal/resource/get?token={token}&kind=Workload"),
        );
        assert_eq!(empty.status, 200, "got: {}", empty.body);
        assert!(
            empty.body.contains("EVENTS 0"),
            "a view signs nothing: {}",
            empty.body
        );
        assert_eq!(ctx.resource_event_count(), before);

        // apply → exactly one event.
        let applied = post(
            &mut ctx,
            "/portal/resource/apply",
            &format!("{token}\nweb\napp:v1"),
        );
        assert_eq!(applied.status, 200, "got: {}", applied.body);
        assert!(applied.body.starts_with("EVENT "), "got: {}", applied.body);
        assert_eq!(ctx.resource_event_count(), 1, "one act, one event");

        // get now lists the workload, still signing nothing.
        let listed = get(
            &mut ctx,
            &format!("/portal/resource/get?token={token}&kind=Workload"),
        );
        assert!(
            listed.body.contains("Workload/web replicas=1"),
            "got: {}",
            listed.body
        );
        assert!(
            listed.body.contains("EVENTS 1"),
            "a view added no event: {}",
            listed.body
        );
        assert_eq!(ctx.resource_event_count(), 1);

        // edit → one more event.
        let edited = post(
            &mut ctx,
            "/portal/resource/edit",
            &format!("{token}\nweb\napp:v2"),
        );
        assert_eq!(edited.status, 200, "got: {}", edited.body);
        assert_eq!(ctx.resource_event_count(), 2);

        // scale → one more event, and the view reflects the new replica count.
        let scaled = post(
            &mut ctx,
            "/portal/resource/scale",
            &format!("{token}\nweb\n5"),
        );
        assert_eq!(scaled.status, 200, "got: {}", scaled.body);
        assert_eq!(ctx.resource_event_count(), 3);
        let listed = get(
            &mut ctx,
            &format!("/portal/resource/get?token={token}&kind=Workload"),
        );
        assert!(
            listed.body.contains("Workload/web replicas=5"),
            "got: {}",
            listed.body
        );

        // rollout → one more event.
        let rolled = post(
            &mut ctx,
            "/portal/resource/rollout",
            &format!("{token}\nweb\n"),
        );
        assert_eq!(rolled.status, 200, "got: {}", rolled.body);
        assert_eq!(ctx.resource_event_count(), 4);
    }

    // An UNAUTHORIZED act (a session whose admitted subject the decider
    // refuses) emits NO event.
    #[test]
    fn an_unauthorized_resource_act_is_refused_and_signs_nothing() {
        // A node whose portal subject is NOT chained deep enough into the
        // resource authority to be authorized: it can log in (custody) but the
        // decider refuses its acts.
        let subkey = NodeSubkey::from("op-subkey-stranger");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        // Admit for LOGIN into the custody authority only (level 0 — too far
        // from the root to satisfy the resource-class depth threshold), but do
        // NOT grant resource authority.
        ctx.admit_subject_login_only(subkey.node_id());
        ctx.provision_offer(
            "stranger@pillar",
            "Stranger",
            Cid::from("cid-stranger"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        let nonce = get(&mut ctx, "/nonce");
        let nonce_id = nonce.body.split_whitespace().nth(1).unwrap().to_owned();
        let login = post(
            &mut ctx,
            "/login",
            &format!("stranger@pillar\n{PASSWORD}\n{nonce_id}"),
        );
        assert_eq!(login.status, 200, "got: {}", login.body);
        let token = login.session_token.expect("session token");

        let before = ctx.resource_event_count();
        let refused = post(
            &mut ctx,
            "/portal/resource/apply",
            &format!("{token}\nweb\napp:v1"),
        );
        assert_eq!(
            refused.status, 403,
            "an unauthorized act must be refused: {}",
            refused.body
        );
        assert_eq!(
            ctx.resource_event_count(),
            before,
            "an unauthorized act appends nothing"
        );
    }

    // A dry-run preview shows the PREDICTED decision, and it equals the
    // ENFORCED decision (same decider) — predicted == enforced.
    #[test]
    fn a_dry_run_preview_shows_predicted_equals_enforced() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // The preview signs nothing and predicts ALLOW for the authorized actor.
        let before = ctx.resource_event_count();
        let preview = get(&mut ctx, &format!("/portal/resource/dry-run?token={token}"));
        assert_eq!(preview.status, 200, "got: {}", preview.body);
        assert!(
            preview.body.contains("PREDICTED ALLOW"),
            "got: {}",
            preview.body
        );
        assert_eq!(
            ctx.resource_event_count(),
            before,
            "a dry-run signs nothing"
        );

        // The ENFORCED act then succeeds — the predicted ALLOW matches the
        // enforced outcome (the debug_assert in the handler also checks this).
        let applied = post(
            &mut ctx,
            "/portal/resource/apply",
            &format!("{token}\nweb\napp:v1"),
        );
        assert_eq!(applied.status, 200, "predicted==enforced: {}", applied.body);
    }

    // describe renders provenance: signer, authorizing capability, and the
    // event CID of the record in force.
    #[test]
    fn describe_renders_provenance_signer_authority_and_event_cid() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        post(
            &mut ctx,
            "/portal/resource/apply",
            &format!("{token}\nweb\napp:v1"),
        );

        let desc = get(
            &mut ctx,
            &format!("/portal/resource/describe?token={token}&kind=Workload&name=web"),
        );
        assert_eq!(desc.status, 200, "got: {}", desc.body);
        assert!(
            desc.body.contains("Signer:"),
            "provenance signer: {}",
            desc.body
        );
        assert!(
            desc.body.contains("Event-CID:"),
            "provenance event CID: {}",
            desc.body
        );
        // The signer is the admitted portal subject (the authority that signed).
        assert!(
            desc.body.contains("op-subkey-alice"),
            "signer identity: {}",
            desc.body
        );

        // Unauthenticated describe is refused.
        assert_eq!(
            get(
                &mut ctx,
                "/portal/resource/describe?token=nope&kind=Workload&name=web"
            )
            .status,
            401
        );
    }

    // logs/exec/forward reach a RUNNING workload's runtime (they sign nothing);
    // a missing workload is refused.
    #[test]
    fn logs_exec_forward_reach_a_running_workload() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        post(
            &mut ctx,
            "/portal/resource/apply",
            &format!("{token}\nweb\napp:v1"),
        );
        let events_after_apply = ctx.resource_event_count();

        let logs = get(
            &mut ctx,
            &format!("/portal/resource/logs?token={token}&name=web"),
        );
        assert_eq!(logs.status, 200, "got: {}", logs.body);
        assert!(
            logs.body.contains("LOGS Workload/web"),
            "got: {}",
            logs.body
        );

        let exec = get(
            &mut ctx,
            &format!("/portal/resource/exec?token={token}&name=web&cmd=sh"),
        );
        assert_eq!(exec.status, 200, "got: {}", exec.body);
        assert!(exec.body.contains("EXEC sh"), "got: {}", exec.body);

        let fwd = get(
            &mut ctx,
            &format!("/portal/resource/forward?token={token}&name=web&port=8080"),
        );
        assert_eq!(fwd.status, 200, "got: {}", fwd.body);
        assert!(fwd.body.contains("FORWARD 8080"), "got: {}", fwd.body);

        // Runtime reach signs nothing.
        assert_eq!(ctx.resource_event_count(), events_after_apply);

        // A missing workload is refused; unauthenticated reach is refused.
        assert_eq!(
            get(
                &mut ctx,
                &format!("/portal/resource/logs?token={token}&name=ghost")
            )
            .status,
            404
        );
        assert_eq!(
            get(&mut ctx, "/portal/resource/logs?token=nope&name=web").status,
            401
        );
    }

    // The resource UI is polymorphic over an IDENTITY kind too, using the SAME
    // get/describe verbs — proving the plane is not workload-only.
    #[test]
    fn the_resource_ui_verbs_are_polymorphic_over_an_identity_kind() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        // apply is workload-shaped in the UI, but get is polymorphic: seed an
        // identity object directly through the shared plane substrate.
        let sub = ctx.identity_actor_for_test();
        ctx.apply_identity_for_test(&sub, "alice");
        let listed = get(
            &mut ctx,
            &format!("/portal/resource/get?token={token}&kind=User"),
        );
        assert_eq!(listed.status, 200, "got: {}", listed.body);
        assert!(listed.body.contains("User/alice"), "got: {}", listed.body);
    }

    // A UI-persisted layout artifact is a signed IPFS+streaming-DB resource:
    // storing it yields a content address (CID) and a streaming tip; a
    // differently-authenticated viewer sees who signed it. (Re-asserts the
    // layout resource is the persistence substrate for the resource UI, per
    // the card.)
    #[test]
    fn resource_ui_persisted_layout_is_a_signed_ipfs_streaming_resource() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);
        let stored = post(
            &mut ctx,
            "/portal/layout",
            &format!("{token}\nworkload-grid: [web, db]"),
        );
        assert_eq!(stored.status, 200, "got: {}", stored.body);
        assert!(
            stored.body.contains("LAYOUT-CID "),
            "content address: {}",
            stored.body
        );
        assert!(
            stored.body.contains(" TIP "),
            "streaming tip: {}",
            stored.body
        );
        let cid = stored
            .body
            .split_whitespace()
            .nth(1)
            .expect("cid token")
            .to_owned();
        let fetched = get(&mut ctx, &format!("/portal/layout?token={token}&cid={cid}"));
        assert_eq!(fetched.status, 200, "got: {}", fetched.body);
        assert!(
            fetched.body.contains("SIGNER "),
            "signed by its author: {}",
            fetched.body
        );
        assert!(
            fetched.body.contains("workload-grid"),
            "content preserved: {}",
            fetched.body
        );
    }

    // The topology explorer renders the derived tier tree (config-ordered
    // hierarchy) with per-node health/capacity, plus a per-tier rollup.
    #[test]
    fn topology_explorer_renders_the_tier_tree_with_health_capacity_and_rollup() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        assert_eq!(
            get(&mut ctx, "/portal/topology/tree?token=nope").status,
            401
        );

        ctx.topology_declare(
            NodeId::from("node-a"),
            vec![
                TopologyLabel::new("rack", "r1"),
                TopologyLabel::new("zone", "z1"),
            ],
        );
        ctx.topology_declare(
            NodeId::from("node-b"),
            vec![
                TopologyLabel::new("rack", "r2"),
                TopologyLabel::new("zone", "z1"),
            ],
        );
        ctx.topology_register_node("node-a", "ok", 10);
        ctx.topology_register_node("node-b", "degraded", 20);

        let view = get(
            &mut ctx,
            &format!("/portal/topology/tree?token={token}&rollup-tier=rack"),
        );
        assert_eq!(view.status, 200, "got: {}", view.body);
        assert!(view
            .body
            .starts_with("TIERS region,zone,site,room,cage,rack,chassis,node"));
        assert!(
            view.body
                .contains("NODE node-a PATH rack=r1,zone=z1 HEALTH ok CAPACITY 10")
                || view
                    .body
                    .contains("NODE node-a PATH zone=z1,rack=r1 HEALTH ok CAPACITY 10"),
            "got: {}",
            view.body
        );
        assert!(
            view.body.contains("HEALTH degraded CAPACITY 20"),
            "got: {}",
            view.body
        );
        assert!(
            view.body.contains("ROLLUP rack r1=10\n"),
            "got: {}",
            view.body
        );
        assert!(
            view.body.contains("ROLLUP rack r2=20\n"),
            "got: {}",
            view.body
        );
    }

    // The label editor emits signed label/attestation events — the attested
    // label verifies through the trust store — and surfaces a
    // declared-vs-attested mismatch inline.
    #[test]
    fn label_editor_attests_a_label_and_surfaces_declared_vs_attested_mismatch() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // The node lies about its own rack.
        let declared = post(
            &mut ctx,
            "/portal/topology/label/declare",
            &format!("{token}\nnode-7\nrack\nr99"),
        );
        assert_eq!(declared.status, 200, "got: {}", declared.body);

        // Unauthorized attest (owner lacks the declared capacity) is refused.
        let refused = post(
            &mut ctx,
            "/portal/topology/label/attest",
            &format!("{token}\nmallory\ncell-authority@cell-b\n\nnode-7\nrack\nr7\ncell-b"),
        );
        assert_eq!(refused.status, 403, "got: {}", refused.body);

        // owner is the trust-store genesis and unconditionally holds every
        // capacity — a genuine cell-authority attest, signed and verified.
        let attested = post(
            &mut ctx,
            "/portal/topology/label/attest",
            &format!("{token}\nowner\ncell-authority@cell-b\n\nnode-7\nrack\nr7\ncell-b"),
        );
        assert_eq!(attested.status, 200, "got: {}", attested.body);
        assert!(
            attested.body.starts_with("ATTESTED CID "),
            "got: {}",
            attested.body
        );

        // The attested label is now the trust-graph's edge too (reuses the
        // SAME attest primitive, no new signing plane).
        let graph = get(&mut ctx, &format!("/portal/trust-graph?token={token}"));
        assert!(
            graph.body.contains("EDGE owner -> node-7 ") && graph.body.contains("rack=r7"),
            "got: {}",
            graph.body
        );

        // The mismatch view surfaces the declared-vs-attested disagreement.
        let mismatches = get(
            &mut ctx,
            &format!("/portal/topology/mismatches?token={token}"),
        );
        assert_eq!(mismatches.status, 200, "got: {}", mismatches.body);
        assert!(
            mismatches
                .body
                .contains("MISMATCH node-7 tier=rack declared=r99 attested=r7"),
            "got: {}",
            mismatches.body
        );
    }

    // The failure-domain overlay computes replica spread and warns on
    // same-rack.
    #[test]
    fn failure_domain_overlay_computes_spread_and_warns_on_same_rack() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        ctx.topology_declare(NodeId::from("a"), vec![TopologyLabel::new("rack", "r1")]);
        ctx.topology_declare(NodeId::from("b"), vec![TopologyLabel::new("rack", "r1")]);
        ctx.topology_declare(NodeId::from("c"), vec![TopologyLabel::new("rack", "r2")]);

        // a, b share a rack: a warning.
        let warned = get(
            &mut ctx,
            &format!("/portal/topology/failure-domain?token={token}&tier=rack&nodes=a,b"),
        );
        assert_eq!(warned.status, 200, "got: {}", warned.body);
        assert!(
            warned.body.contains("REPLICA a rack=r1"),
            "got: {}",
            warned.body
        );
        assert!(
            warned.body.contains("REPLICA b rack=r1"),
            "got: {}",
            warned.body
        );
        assert!(
            warned.body.contains("WARN same-rack"),
            "got: {}",
            warned.body
        );

        // a, c span distinct racks: no warning.
        let ok = get(
            &mut ctx,
            &format!("/portal/topology/failure-domain?token={token}&tier=rack&nodes=a,c"),
        );
        assert!(ok.body.contains("SPREAD-OK"), "got: {}", ok.body);
        assert!(!ok.body.contains("WARN"), "got: {}", ok.body);
    }

    // Workload/telemetry/logs panels expose topology facets that filter by
    // tier — the shared facet primitive nodes-at(tier, value).
    #[test]
    fn topology_facet_filters_nodes_by_tier_value() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        ctx.topology_declare(NodeId::from("a"), vec![TopologyLabel::new("rack", "r1")]);
        ctx.topology_declare(NodeId::from("b"), vec![TopologyLabel::new("rack", "r1")]);
        ctx.topology_declare(NodeId::from("c"), vec![TopologyLabel::new("rack", "r2")]);
        ctx.topology_register_node("a", "ok", 1);
        ctx.topology_register_node("b", "ok", 1);
        ctx.topology_register_node("c", "ok", 1);

        let facet = get(
            &mut ctx,
            &format!("/portal/topology/facet?token={token}&tier=rack&value=r1"),
        );
        assert_eq!(facet.status, 200, "got: {}", facet.body);
        assert!(facet.body.contains("NODE a\n"), "got: {}", facet.body);
        assert!(facet.body.contains("NODE b\n"), "got: {}", facet.body);
        assert!(!facet.body.contains("NODE c\n"), "got: {}", facet.body);
    }

    // Saved topology dashboards/layouts are signed IPFS+streaming-tip
    // resources — the topology explorer reuses the SAME `layouts` resource
    // the resource UI's dashboards persist to (no server-side database).
    #[test]
    fn saved_topology_dashboard_is_a_signed_ipfs_streaming_resource() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        let stored = post(
            &mut ctx,
            "/portal/layout",
            &format!("{token}\ntopology-dashboard: {{tier: rack, view: elevation}}"),
        );
        assert_eq!(stored.status, 200, "got: {}", stored.body);
        assert!(stored.body.contains("LAYOUT-CID "), "got: {}", stored.body);
        assert!(stored.body.contains(" TIP "), "got: {}", stored.body);
        let cid = stored
            .body
            .split_whitespace()
            .nth(1)
            .expect("cid token")
            .to_owned();
        let fetched = get(&mut ctx, &format!("/portal/layout?token={token}&cid={cid}"));
        assert_eq!(fetched.status, 200, "got: {}", fetched.body);
        assert!(
            fetched.body.contains("topology-dashboard"),
            "got: {}",
            fetched.body
        );
    }

    // ---------------------------------------------------------------------
    // Per-feature UI CONFIRMATION suite (one test per banked `ui-*` task).
    //
    // These assert the SURFACE the operator actually sees: the served `/`
    // page (web_login.html, the client SPA) must WIRE each banked feature's
    // endpoint(s) and render its controls. An endpoint that exists but is
    // never fetched by the SPA is invisible to the user, so asserting the
    // dispatch handler alone is not enough -- each test asserts the served
    // page itself calls the feature's `/portal/*` endpoint. Not fakeable
    // with a dead <div>: the fetch URL means the panel is really wired.
    // ---------------------------------------------------------------------

    // Assert the served "/" page contains every one of `needles`.
    fn assert_ui_wires(feature: &str, needles: &[&str]) {
        let (mut ctx, _subkey) = provisioned_ctx();
        let page = get(&mut ctx, "/").body;
        for n in needles {
            assert!(
                page.contains(n),
                "the served portal UI is missing the {feature} feature: \
                 web_login.html does not contain `{n}` -- the endpoint may \
                 exist server-side but the SPA never surfaces it"
            );
        }
    }

    #[test]
    fn ui_confirms_request_inbox_panel() {
        assert_ui_wires(
            "request-inbox",
            &["/bootstrap/request/list", "inbox-approve", "inbox-reject"],
        );
    }

    #[test]
    fn ui_confirms_identity_panel() {
        assert_ui_wires(
            "identity",
            &[
                "/portal/identity",
                "/portal/identity/enroll",
                "/portal/identity/rotate",
                "/portal/identity/recover",
            ],
        );
    }

    #[test]
    fn ui_confirms_domain_panel() {
        assert_ui_wires("domain", &["/portal/domains"]);
    }

    #[test]
    fn ui_confirms_member_management_panel() {
        assert_ui_wires(
            "member-management",
            &["/portal/members", "/portal/members/add"],
        );
    }

    #[test]
    fn ui_confirms_session_management_panel() {
        assert_ui_wires(
            "session-management",
            &[
                "/portal/sessions",
                "/portal/sessions/revoke",
                "/portal/sessions/revoke-all",
            ],
        );
    }

    #[test]
    fn ui_confirms_trust_and_key_builder_panel() {
        assert_ui_wires(
            "trust-and-key-builders",
            &[
                "/portal/trust-graph",
                "/portal/attestations/build",
                "/portal/custody/rotate",
            ],
        );
    }

    #[test]
    fn ui_confirms_resource_workload_panel() {
        assert_ui_wires(
            "resource-workload",
            &[
                "/portal/resource/get",
                "/portal/resource/apply",
                "/portal/resource/dry-run",
            ],
        );
    }

    #[test]
    fn ui_confirms_topology_explorer_panel() {
        assert_ui_wires(
            "topology-explorer",
            &[
                "/portal/topology/tree",
                "/portal/topology/label/attest",
                "/portal/topology/failure-domain",
            ],
        );
    }

    #[test]
    fn ui_confirms_observability_panel() {
        assert_ui_wires(
            "observability",
            &[
                "/portal/obs/explore",
                "/portal/obs/query",
                "/portal/obs/dashboard",
            ],
        );
    }
}
