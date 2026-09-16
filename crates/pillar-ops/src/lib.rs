//! `pillar-ops` — the shared Pillar **op vocabulary**.
//!
//! A mutation to a Pillar cell is not an RPC to a privileged server; it is a
//! signed, cell-sealed [`pillar_wire::PillarMessage`] carrying an **op** that
//! every node applies through the same replay/materialize path. There are two
//! disjoint op families, kept separate because they ride different substrates:
//!
//! - **streamdb CRUD ops** *(this crate)* — create/update/delete of a resource
//!   CRD (`RetentionPolicy`, `ResourceSet`, `Workload`, `CronJob`, …). These
//!   ride the streamdb op-log: the rollup/replay/materialized format whose
//!   `apply`-on-replay yields the resource view.
//! - **tsdb / observability messages** *(owned by `pillar-observability`)* —
//!   the five telemetry signal kinds (metric/log/trace/profile/metadata).
//!   These ride a **different** IPFS block format (time-series blocks, not the
//!   streamdb rollup) and are deliberately NOT modelled here.
//!
//! This crate owns only the streamdb CRUD family, and only its **payload**:
//! the [`ResourceOp`] enum and its deterministic byte codec ([`ResourceOp::encode`]
//! / [`ResourceOp::decode`]). Wrapping the payload into a [`Body::StreamOp`],
//! sealing it to the cell, and signing it are the transport layer's job
//! (`pillar-client`, native) — deliberately not here, so this crate stays
//! dependency-light and **wasm-safe** (only `pillar-manifest` + serde), which
//! is what lets the browser client reuse the exact same op encoding the CLI
//! and node use. The load-bearing property: two producers of the same logical
//! op — the CLI, the node's portal, the browser — emit **byte-identical**
//! payloads, so they content-address to the same streamdb op id and the CRDT
//! op-log dedups them.
//!
//! [`Body::StreamOp`]: https://docs.rs/pillar-wire

use serde::{Deserialize, Serialize};

pub use pillar_manifest::Crd;

/// The codec version prefixed to every encoded [`ResourceOp`] payload so the
/// on-the-wire/on-log format can evolve without ambiguity. Bumped only on a
/// breaking payload-shape change; a decoder rejects any version it does not
/// understand rather than mis-parsing.
pub const OP_CODEC_VERSION: u8 = 1;

/// A CRUD operation on a resource CRD — the streamdb op the CLI, the node's
/// portal, and the browser client all emit identically. Applied by every node
/// on op-log replay to converge the materialized resource view.
///
/// The set is deliberately **generic over kind**: one `Apply` upserts any CRD
/// (a `RetentionPolicy`, a `ResourceSet`, a `Workload`), one `Delete` removes
/// any resource by kind + name. New resource kinds need no new op variant —
/// they ride `Apply`/`Delete` the moment their schema is registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ResourceOp {
    /// Create-or-update: declaratively apply a full CRD body (the CRUD
    /// "upsert"). The node authorizes the signer for this kind's write policy,
    /// then applies the CRD into the resource plane.
    Apply {
        /// The full CRD body to upsert.
        crd: Crd,
    },
    /// Delete a resource identified by its `kind` and `metadata.name`.
    Delete {
        /// The resource kind (e.g. `RetentionPolicy`).
        kind: String,
        /// The resource's `metadata.name`.
        name: String,
    },
    /// Read the materialized resource view (a VIEW: the node emits NO event
    /// and mutates nothing). `name` `None` lists every object of `kind` as a
    /// `---`-separated CRD-YAML stream; `Some` renders that one object's CRD
    /// YAML. Served over the same signed, sealed resource-op tier as the
    /// mutations so `pillar get` reaches a live cell from anywhere the mutate
    /// tier is reachable; the node gates it on the signer being a recognized
    /// cell member (fail-closed), exactly as the web read tier gates on a
    /// session.
    Get {
        /// The resource kind to read (e.g. `RetentionPolicy`).
        kind: String,
        /// The single object's `metadata.name`, or `None` to list the kind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Describe one resource (a VIEW): full detail INCLUDING provenance (the
    /// signer, authorizing capability, and event CID of the record in force).
    /// Like [`ResourceOp::Get`] it emits no event and is member-gated.
    Describe {
        /// The resource kind (e.g. `RetentionPolicy`).
        kind: String,
        /// The resource's `metadata.name`.
        name: String,
    },
}

impl ResourceOp {
    /// The resource kind this op targets — for `Apply`, the CRD's `kind`; for
    /// `Delete`/`Get`/`Describe`, the named `kind`. The node routes write-policy
    /// authorization on this (reads are member-gated, not routed on name).
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            ResourceOp::Apply { crd } => &crd.kind,
            ResourceOp::Delete { kind, .. }
            | ResourceOp::Get { kind, .. }
            | ResourceOp::Describe { kind, .. } => kind,
        }
    }

    /// The resource `metadata.name` this op targets, if it names a single
    /// object. `None` for a [`ResourceOp::Get`] that lists a whole kind.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            ResourceOp::Apply { crd } => Some(&crd.metadata.name),
            ResourceOp::Delete { name, .. } | ResourceOp::Describe { name, .. } => Some(name),
            ResourceOp::Get { name, .. } => name.as_deref(),
        }
    }

    /// Whether this op is a read-only VIEW (`Get`/`Describe`) — the node serves
    /// it from the materialized view and emits no signed event.
    #[must_use]
    pub fn is_read(&self) -> bool {
        matches!(self, ResourceOp::Get { .. } | ResourceOp::Describe { .. })
    }

    /// Encode this op to its deterministic streamdb op payload: a single
    /// [`OP_CODEC_VERSION`] byte followed by the canonical JSON of the op.
    /// Deterministic because every field map in a [`Crd`] is a `BTreeMap`
    /// (serialized in sorted key order) and the op's own fields are fixed —
    /// so two producers of the same logical op emit identical bytes.
    ///
    /// # Errors
    /// [`OpCodecError::Encode`] if serialization fails (not expected for an
    /// in-memory op).
    pub fn encode(&self) -> Result<Vec<u8>, OpCodecError> {
        let json = serde_json::to_vec(self).map_err(|e| OpCodecError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + json.len());
        out.push(OP_CODEC_VERSION);
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode a streamdb op payload produced by [`Self::encode`], checking the
    /// leading codec-version byte.
    ///
    /// # Errors
    /// [`OpCodecError::Empty`] on an empty payload;
    /// [`OpCodecError::UnsupportedVersion`] on an unknown codec version;
    /// [`OpCodecError::Decode`] if the remaining bytes are not a well-formed
    /// [`ResourceOp`].
    pub fn decode(bytes: &[u8]) -> Result<Self, OpCodecError> {
        let (&version, rest) = bytes.split_first().ok_or(OpCodecError::Empty)?;
        if version != OP_CODEC_VERSION {
            return Err(OpCodecError::UnsupportedVersion(version));
        }
        serde_json::from_slice(rest).map_err(|e| OpCodecError::Decode(e.to_string()))
    }
}

/// The codec version prefixed to every encoded [`ControlOp`] payload. Kept
/// SEPARATE from [`OP_CODEC_VERSION`] so the two op families evolve
/// independently.
pub const CONTROL_OP_CODEC_VERSION: u8 = 1;

/// The typed CLI **control-op** vocabulary: one arm per command family. Where
/// [`ResourceOp`] models streamdb CRUD (rides [`pillar_wire::Body::StreamOp`]),
/// a `ControlOp` drives the node's portal/authority substrate (members, trust,
/// sessions, IAM, cluster, obs, …) over the SAME sealed, signed resource-op UDP
/// tier — it rides `Body::ControlOp`. The set grows one typed arm per family as
/// each CLI family is wired to the wire; a node decodes only the arms this build
/// understands and rejects the rest, so the vocabulary can extend without a
/// codec bump. Wasm-safe (serde only), like the rest of this crate, so the
/// browser client can build the identical typed op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOp {
    /// Cell-membership management (`pillar member …`).
    Members(MembersOp),
    /// Server-side session management (`pillar session …`) over the live
    /// per-principal session registry.
    Session(SessionOp),
    /// Web-of-trust views (`pillar wot …`) over the live trust store — the
    /// SAME substrate the web trust-graph panel renders.
    Wot(WotOp),
    /// Observability reads (`pillar obs …`) over the node's live obs substrate
    /// (historical + live explore/query/retention/dashboard).
    Obs(ObsOp),
    /// Global-identity views + acts (`pillar identity …`) over the node's live
    /// identity log.
    Identity(IdentityOp),
    /// IAM user views + lifecycle acts (`pillar user …`) over the node's live
    /// IAM user store.
    User(UserOp),
    /// Cluster bootstrap-request queue + topology views (`pillar cluster …` /
    /// `pillar request …`) over the node's live request queue + topology
    /// registry.
    Cluster(ClusterOp),
    /// Trust-artifact + explicit-grant management (`pillar attest|grant|caps|
    /// trust …`) over the node's live trust store, WoT authority, and explicit
    /// grant set — the SAME substrate the web trust/attestation panels drive.
    Trust(TrustOp),
    /// IAM role / group / oauth-client management (`pillar role|group|oauth …`)
    /// over the node's live role set, managed-group set, and OAuth client
    /// registry — the SAME substrate the IAM admin panels drive.
    Iam(IamOp),
    /// M-of-N quorum-authorized break-glass recovery of a locked-out user's
    /// operational key (`pillar recovery start|approve …`, ROI P1 "User
    /// management & lifecycle" roadmap A4). No single admin can unilaterally
    /// reset a subject: a recovery is OPENED by `Start` and only FIRES on the
    /// Mth distinct fresh-admin `Approve`, at which point the node rotates the
    /// subject's key (old generation dead forever) and mints a CONTAINED
    /// one-time recovery credential (no usable authority until onboarding),
    /// never regranting more than the subject's prior authority. Model-checked
    /// by `specs/BreakGlassRecovery.tla`.
    Recovery(RecoveryOp),
}

/// M-of-N quorum-authorized break-glass recovery ops (`pillar recovery …`),
/// refining `specs/BreakGlassRecovery.tla`'s `Recover`/`Approve` actions. Each
/// arm is a signed act gated on `iam:users:write` (the SAME decider every
/// admin user-mutation rides): a `Start` opens a recovery for a locked-out
/// subject and declares the quorum threshold `m`; each `Approve` records one
/// distinct currently-authoritative admin's co-signature, and the Mth distinct
/// approval FIRES the rotate/revoke/contained-mint. A sub-quorum approval set
/// can never fire the recovery (`SubThresholdNeverRecovers`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RecoveryOp {
    /// Open a break-glass recovery for a locked-out `subject`, declaring the
    /// M-of-N quorum threshold `m` (the number of distinct fresh-admin
    /// approvals required before the recovery fires). Re-opening an existing
    /// open recovery is idempotent (the threshold is not lowered under it).
    Start {
        /// The locked-out subject user handle to recover.
        subject: String,
        /// The quorum threshold M: distinct fresh-admin approvals required.
        m: u32,
    },
    /// Record one currently-authoritative admin's co-signature on the subject's
    /// open recovery. The Mth DISTINCT approval fires the recovery: the
    /// subject's operational key is rotated (old generation retired) and a
    /// contained one-time recovery credential minted. A repeated approval by an
    /// admin already counted does not advance the quorum.
    Approve {
        /// The subject whose open recovery is being approved.
        subject: String,
    },
}

/// IAM role / group / oauth-client ops (`pillar role|group|oauth …`) over the
/// node's live role set, managed-group set, and OAuth client registry. `*Add`/
/// `*Rm`/`AddMember`/`Register` are signed acts (gated on `iam:roles:write` /
/// `iam:groups:write` / `iam:oauth:write`); `*List`/`*Show` are member-gated
/// VIEWS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum IamOp {
    /// Create/replace a named capability set (`pillar role add <name> --grant
    /// <cap>…`).
    RoleAdd {
        /// The role name.
        name: String,
        /// The capabilities the role grants.
        capabilities: Vec<String>,
    },
    /// Remove a role (`pillar role rm <name>`).
    RoleRm {
        /// The role name.
        name: String,
    },
    /// List every role (`pillar role list`).
    RoleList,
    /// Show one role's capabilities (`pillar role show <name>`).
    RoleShow {
        /// The role name.
        name: String,
    },
    /// Create a managed group bound to `roles` (`pillar group add <name>
    /// --role <r>…`).
    GroupAdd {
        /// The group name.
        name: String,
        /// The roles the group confers.
        roles: Vec<String>,
    },
    /// Add a member handle to a group (`pillar group add-member <name>
    /// <handle>`).
    GroupAddMember {
        /// The group name.
        name: String,
        /// The member handle to add.
        handle: String,
    },
    /// Remove a group (`pillar group rm <name>`).
    GroupRm {
        /// The group name.
        name: String,
    },
    /// List every group (`pillar group list`).
    GroupList,
    /// Show one group's roles + members (`pillar group show <name>`).
    GroupShow {
        /// The group name.
        name: String,
    },
    /// Register an OAuth/OIDC client (`pillar oauth register <client-id>
    /// --type <public|confidential> --redirect <uri>… --scope <s>… --grant
    /// <g>…`).
    OauthRegister {
        /// The stable public client id.
        client_id: String,
        /// `public` or `confidential`.
        client_type: String,
        /// The redirect-URI allow-list.
        redirect_uris: Vec<String>,
        /// The permitted scopes.
        scopes: Vec<String>,
        /// The permitted grant-type tokens.
        grants: Vec<String>,
    },
    /// List every registered client (`pillar oauth list`).
    OauthList,
    /// Show one client's registration (`pillar oauth show <client-id>`).
    OauthShow {
        /// The client id.
        client_id: String,
    },
}

/// Trust-artifact + explicit-grant ops (`pillar attest|grant|caps|trust …`)
/// over the node's live [`pillar_trust_artifacts::TrustStore`], WoT authority,
/// and explicit grant set. `AttestBuild`/`GrantAdd`/`GrantRm`/`Edge` are signed
/// acts (capacity-checked at signing time / capability-gated); `Audit`/
/// `GrantCheck`/`WhoCan`/`Caps`/`Path` are member-gated VIEWS that route
/// through the SAME `RbacDecider`/trust walk every act consults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum TrustOp {
    /// Install a WoT trust edge from the signer to `subject`, bounding onward
    /// delegation at `depth` (`pillar trust <subject> --depth N`).
    Edge {
        /// The delegatee subject id.
        subject: String,
        /// The onward-delegation depth bound.
        depth: u8,
    },
    /// Issue a capacity-checked attestation (`pillar attest …`). Capacity is
    /// verified AT SIGNING TIME by the trust store — the issuer must currently
    /// HOLD the declared capacity.
    AttestBuild {
        /// The issuing identity.
        issuer: String,
        /// The capacity spec: `self` or `<role>@<scope>`.
        capacity: String,
        /// An optional prior attest CID this one is authorized by.
        authority: String,
        /// The subject the claim is about.
        subject: String,
        /// The permitted action (attest predicate action).
        action: String,
        /// The resource the action applies to.
        resource: String,
        /// An optional quota budget (`--quota key=N` → the N).
        quota: Option<u64>,
        /// The scope the claim is bounded to.
        scope: String,
    },
    /// Add an explicit ALLOW/DENY grant of `capability` to `subject`
    /// (`pillar grant add <cap> --to <subject> [--allow|--deny]`).
    GrantAdd {
        /// The grantee subject id.
        subject: String,
        /// The capability string.
        capability: String,
        /// Allow (true) or deny (false).
        allow: bool,
    },
    /// Remove any explicit grant for `(subject, capability)`
    /// (`pillar grant rm <cap> --to <subject>`). Idempotent.
    GrantRm {
        /// The grantee subject id.
        subject: String,
        /// The capability string.
        capability: String,
    },
    /// Verify an attestation's proof chain (`pillar audit <cid>`).
    Audit {
        /// The attest artifact content-address.
        cid: String,
    },
    /// Ask the decider whether `subject` holds `capability`
    /// (`pillar grant check <cap> --as <subject>`).
    GrantCheck {
        /// The subject to probe.
        subject: String,
        /// The capability string.
        capability: String,
    },
    /// Every subject with an explicit ALLOW of `capability`
    /// (`pillar grant who-can <cap>`).
    WhoCan {
        /// The capability string.
        capability: String,
    },
    /// The effective ALLOW set the decider computes for `subject` across the
    /// named `candidates` capability universe (`pillar caps <subject> --probe
    /// <cap>…`).
    Caps {
        /// The subject to compute effective caps for.
        subject: String,
        /// The capability universe to probe.
        candidates: Vec<String>,
    },
    /// The reachable trust depth from the authority root to `subject`
    /// (`pillar trust path <subject>`).
    Path {
        /// The subject to resolve.
        subject: String,
    },
}

/// Portal-member management ops (`pillar member ls|add|role`). A `List` is a
/// VIEW (emits no event); `Add`/`SetRole` are signed acts gated on the
/// `portal:members:write` capability of the AUTHENTICATED signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum MembersOp {
    /// List the cell's members and their roles.
    List,
    /// Add or invite a member with a role.
    Add {
        /// The member handle.
        handle: String,
        /// The role to grant (e.g. `member`, `admin`).
        role: String,
    },
    /// Change an existing member's role.
    SetRole {
        /// The member handle.
        handle: String,
        /// The new role.
        role: String,
    },
}

/// Server-side session-management ops (`pillar session ls|show|revoke|
/// revoke-all`) against a node's live per-principal session registry — the
/// SAME substrate the web session panel lists/revokes. `List`/`Show` are VIEWS;
/// `Revoke`/`RevokeAll` are signed acts. Every op names the target `principal`
/// (the login subject whose sessions to act on) explicitly: on the wire the
/// signing key is the credential, so — unlike the web panel, which auto-scopes
/// to the caller's login bearer — the target principal is an argument, and the
/// node authorizes by the AUTHENTICATED signer's authority (a view needs cell
/// membership; an act runs the same signed-act decider `member` acts use).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SessionOp {
    /// List `principal`'s currently-active sessions.
    List {
        /// The login subject whose sessions to list.
        principal: String,
    },
    /// Show one session record (`id`) of `principal`.
    Show {
        /// The login subject that owns the session.
        principal: String,
        /// The session slot id.
        id: String,
    },
    /// Revoke one session (`id`) of `principal`.
    Revoke {
        /// The login subject that owns the session.
        principal: String,
        /// The session slot id to revoke.
        id: String,
    },
    /// Revoke every one of `principal`'s sessions (sign-out-everywhere).
    RevokeAll {
        /// The login subject whose sessions to sweep.
        principal: String,
    },
}

/// Web-of-trust view ops (`pillar wot graph|list-trust|list-signatures|
/// list-attestations`). All VIEWS over the live trust store; member-gated, no
/// event emitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum WotOp {
    /// The node-link trust graph (every node fingerprint + edge signature cid).
    Graph,
    /// The trust edges.
    ListTrust,
    /// The signature records.
    ListSignatures,
    /// The attestation records.
    ListAttestations,
}

/// Observability VIEW ops (`pillar obs …`) over the node's live obs substrate.
/// All reads; member-gated, no event emitted. `kind` is a signal-kind tag
/// (`metric`/`log`/`trace`/`profile`/`metadata`); the node parses it and
/// refuses an unknown tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ObsOp {
    /// Historical explore of one signal kind.
    Explore {
        /// Signal-kind tag.
        kind: String,
    },
    /// Historical query of one signal kind, optional filter expression.
    Query {
        /// Signal-kind tag.
        kind: String,
        /// Optional filter expression.
        filter: Option<String>,
    },
    /// Live explore of one signal kind.
    LiveExplore {
        /// Signal-kind tag.
        kind: String,
    },
    /// The live signal kinds present.
    LiveKinds,
    /// A live PSL (pillar-signal-language) query.
    Psl {
        /// The PSL query text.
        query: String,
    },
    /// Live metric names.
    MetricNames,
    /// Live label keys.
    LabelKeys,
    /// Live label values for one key.
    LabelValues {
        /// The label key.
        key: String,
    },
    /// The current retention policy.
    RetentionGet,
    /// Set the retention policy from a spec `body`.
    RetentionSet {
        /// The retention spec body.
        body: String,
    },
    /// Install/update a recording rule from `spec`.
    Recording {
        /// The recording-rule spec.
        spec: String,
    },
    /// Install/update an alert rule from `spec`.
    Alert {
        /// The alert-rule spec.
        spec: String,
    },
    /// Save a dashboard `name` with layout `spec`.
    DashboardSave {
        /// The dashboard name.
        name: String,
        /// The dashboard layout spec.
        spec: String,
    },
    /// Read back a saved dashboard by its content-addressed hex id.
    DashboardGet {
        /// The dashboard content-addressed hex id.
        id: String,
    },
}

/// Global-identity ops (`pillar identity …`). `Show`/`Domains` are member-gated
/// VIEWS; `Enroll`/`Rotate`/`Recover` are signed acts gated on
/// `portal:identity:write` (the SAME WoT decider every portal write uses).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum IdentityOp {
    /// The identity log head (CID, generation, per-domain subkeys).
    Show,
    /// The domain (naming-only) grouping: each domain's cells.
    Domains,
    /// Enroll the cell identity in a domain (certifies a per-domain subkey).
    Enroll {
        /// The domain to enroll in.
        domain: String,
    },
    /// Rotate the primary to `new_primary`, signed by the current primary.
    Rotate {
        /// The new primary key id.
        new_primary: String,
    },
    /// Recover: rotate to a fresh primary using the genesis recovery key.
    Recover,
}

/// IAM user ops (`pillar user …`). `List`/`Show` are member-gated VIEWS;
/// `Invite`/`Disable`/`Enable`/`RequireChange`/`SetPassword` are signed acts
/// gated on `iam:users:write` (the SAME decider the `/portal/users/*` routes
/// use).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum UserOp {
    /// Every IAM user: `<handle> status=<s> force_password_change=<b> roles=…`.
    List,
    /// The per-user AUDIT TIMELINE (`um-per-user-audit-timeline`, ROI P1 "User
    /// management & lifecycle" roadmap D1): a chronological, cryptographically
    /// VERIFIABLE (hash==id + valid signature) history of every signed
    /// user-admin act (`USER-INVITE`/`USER-DISABLE`/`USER-ENABLE`/
    /// `USER-REQUIRE-CHANGE`/`USER-RESET`) that named `handle`, folded from the
    /// node's signed `act_log` — the SAME signed events `perform_signed_act`
    /// appends on every `iam:users:write` mutation. A member-gated VIEW (no new
    /// authority, no new event, read-only).
    AuditTimeline {
        /// The subject user whose admin-act history is rendered.
        handle: String,
    },
    /// The cell-wide SECURITY EVENTS FEED (`um-security-events-feed`, ROI P1
    /// "User management & lifecycle" roadmap D2): a chronological, filterable,
    /// cryptographically VERIFIABLE (hash==id + valid signature) derived view
    /// over the SAME signed `act_log` [`Self::AuditTimeline`] folds — but
    /// cell-wide (every subject, not one handle) and restricted to the acts
    /// this feed classifies as security-relevant: account lockouts/restores
    /// (`USER-DISABLE`/`USER-ENABLE`), privilege elevations
    /// (`MEMBER-ADD`/`MEMBER-ROLE`), identity key rotations
    /// (`IDENTITY-ROTATE`), and session revocations
    /// (`SESSION-REVOKE`/`SESSION-REVOKE-ALL`). Read-only (no new authority, no
    /// new event); `kind` optionally narrows to ONE category
    /// (`lockout`/`elevation`/`rotation`/`revocation`); `None` renders every
    /// category.
    SecurityEventsFeed {
        /// Optional category filter (`lockout`/`elevation`/`rotation`/
        /// `revocation`); `None` renders every security-relevant category.
        kind: Option<String>,
    },
    /// Observe one LOGIN for `handle` (`um-anomaly-signals`, ROI P1 "User
    /// management & lifecycle" roadmap D3): an ADVISORY anomaly-detection
    /// hook over the node's per-handle login history. `origin` is an
    /// opaque device/IP tag (the SAME shape `pillar_identity::
    /// session_registry` origins use, e.g. `chrome/macos/198.51.100.9`);
    /// `lat`/`lon` are the login's geo coordinates and `at` its logical
    /// timestamp (whole seconds) — ALL infra-supplied at runtime (geo/IP
    /// enrichment is never performed here). Compares against this handle's
    /// prior observations and, when either an IMPOSSIBLE-TRAVEL (too far,
    /// too fast since the last login) or a NEW-ORIGIN (an origin string
    /// never seen before for this handle, when at least one prior
    /// observation exists) anomaly is detected, emits exactly ONE signed
    /// `act_log` event per anomaly kind — folded into
    /// [`Self::SecurityEventsFeed`]'s `anomaly` category — alongside always
    /// recording the observation. Advisory only: detecting an anomaly signs
    /// a signal, never denies or gates the login itself (no new authority,
    /// no enforcement decision).
    LoginObserve {
        /// The logging-in user's handle.
        handle: String,
        /// Opaque device/IP origin tag.
        origin: String,
        /// Login latitude, in degrees (decimal string, e.g. `"37.7749"`) —
        /// a `String` (not `f64`) so the op stays `Eq`, like every other
        /// wire-carried numeric field in this crate.
        lat: String,
        /// Login longitude, in degrees (decimal string).
        lon: String,
        /// Logical login timestamp, in whole seconds.
        at: u64,
    },
    /// One IAM user's row.
    Show {
        /// The user handle.
        handle: String,
    },
    /// Admin invite of a NEW user. When `password` is `None` the node mints a
    /// one-time temporary password and returns it (revealed once).
    Invite {
        /// The new user handle.
        handle: String,
        /// The new user's email.
        email: String,
        /// Require a password change at first login (Keycloak default ON).
        force_password_change: bool,
        /// Require passkey enrollment at onboarding (default OFF).
        require_passkey: bool,
        /// Explicit initial password, or `None` to mint a temp one.
        password: Option<String>,
    },
    /// Disable a user (revokes live sessions; record retained).
    Disable {
        /// The user handle.
        handle: String,
    },
    /// Re-enable a disabled user.
    Enable {
        /// The user handle.
        handle: String,
    },
    /// Set the forced-password-change onboarding action.
    RequireChange {
        /// The user handle.
        handle: String,
    },
    /// Admin reset of a user's password (`force` = require change at next
    /// login).
    SetPassword {
        /// The user handle.
        handle: String,
        /// The new password.
        password: String,
        /// Require a password change at next login.
        force: bool,
    },
}

/// Cluster ops (`pillar cluster …` / `pillar request …`). `RequestList`/
/// `TopologyTree`/`NodesAt`/`Domains`/`Members` are member-gated VIEWS; the
/// request submit/approve/reject variants are member-gated acts over the live
/// bootstrap-request queue (the SAME queue the `/portal/request/*` routes use).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ClusterOp {
    /// The pending bootstrap requests: `<id> <kind> <subject>` per line.
    RequestList,
    /// File a NODE join request for `subject`.
    RequestSubmitNode {
        /// The joining node's subject id.
        subject: String,
        /// The libp2p peer id.
        peer_id: String,
        /// The node's version string.
        version: String,
        /// The node's OS string.
        os: String,
        /// The content-addressed public key id.
        public_key_cid: String,
        /// The custody-kind token (defaults to password when absent).
        custody: Option<String>,
        /// Public dial addresses.
        pub_addrs: Vec<String>,
        /// Private dial addresses.
        priv_addrs: Vec<String>,
        /// Topology labels.
        labels: Vec<String>,
    },
    /// File a USER join request for `subject`.
    RequestSubmitUser {
        /// The joining user's subject id.
        subject: String,
        /// The custody-kind token (defaults to password when absent).
        custody: Option<String>,
        /// Topology labels.
        labels: Vec<String>,
    },
    /// Approve a pending request (node approval seals the cell key; user
    /// approval escrows the offer).
    RequestApprove {
        /// The request id.
        id: u64,
    },
    /// Reject a pending request.
    RequestReject {
        /// The request id.
        id: u64,
    },
    /// The topology tree rolled up to `tier`.
    TopologyTree {
        /// The rollup tier.
        tier: String,
    },
    /// The nodes at a `tier`=`value` topology facet.
    NodesAt {
        /// The topology tier.
        tier: String,
        /// The tier value.
        value: String,
    },
    /// The domain (naming-only) grouping: each domain's cells.
    Domains,
    /// This cell's members and their roles.
    Members,
}

impl ControlOp {
    /// Encode to a control-op payload: a single [`CONTROL_OP_CODEC_VERSION`]
    /// byte followed by the canonical JSON of the op. Deterministic, like
    /// [`ResourceOp::encode`].
    ///
    /// # Errors
    /// [`OpCodecError::Encode`] if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, OpCodecError> {
        let json = serde_json::to_vec(self).map_err(|e| OpCodecError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + json.len());
        out.push(CONTROL_OP_CODEC_VERSION);
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode a control-op payload produced by [`Self::encode`], checking the
    /// leading codec-version byte.
    ///
    /// # Errors
    /// [`OpCodecError::Empty`] on an empty payload;
    /// [`OpCodecError::UnsupportedVersion`] on an unknown codec version;
    /// [`OpCodecError::Decode`] if the body is not a well-formed [`ControlOp`].
    pub fn decode(bytes: &[u8]) -> Result<Self, OpCodecError> {
        let (&version, rest) = bytes.split_first().ok_or(OpCodecError::Empty)?;
        if version != CONTROL_OP_CODEC_VERSION {
            return Err(OpCodecError::UnsupportedVersion(version));
        }
        serde_json::from_slice(rest).map_err(|e| OpCodecError::Decode(e.to_string()))
    }

    /// Whether this op is a read-only VIEW (the node serves it from live state
    /// and emits no signed event) — the wire dispatcher routes reads through the
    /// member-gated view path and acts through the capability-gated act path.
    #[must_use]
    pub fn is_read(&self) -> bool {
        matches!(
            self,
            ControlOp::Members(MembersOp::List)
                | ControlOp::Session(SessionOp::List { .. })
                | ControlOp::Session(SessionOp::Show { .. })
                | ControlOp::Wot(_)
                | ControlOp::Obs(
                    ObsOp::Explore { .. }
                        | ObsOp::Query { .. }
                        | ObsOp::LiveExplore { .. }
                        | ObsOp::LiveKinds
                        | ObsOp::Psl { .. }
                        | ObsOp::MetricNames
                        | ObsOp::LabelKeys
                        | ObsOp::LabelValues { .. }
                        | ObsOp::RetentionGet
                        | ObsOp::DashboardGet { .. },
                )
                | ControlOp::Identity(IdentityOp::Show)
                | ControlOp::Identity(IdentityOp::Domains)
                | ControlOp::User(UserOp::List)
                | ControlOp::User(UserOp::Show { .. })
                | ControlOp::User(UserOp::AuditTimeline { .. })
                | ControlOp::User(UserOp::SecurityEventsFeed { .. })
                | ControlOp::Cluster(ClusterOp::RequestList)
                | ControlOp::Cluster(ClusterOp::TopologyTree { .. })
                | ControlOp::Cluster(ClusterOp::NodesAt { .. })
                | ControlOp::Cluster(ClusterOp::Domains)
                | ControlOp::Cluster(ClusterOp::Members)
                | ControlOp::Trust(
                    TrustOp::Audit { .. }
                        | TrustOp::GrantCheck { .. }
                        | TrustOp::WhoCan { .. }
                        | TrustOp::Caps { .. }
                        | TrustOp::Path { .. },
                )
                | ControlOp::Iam(
                    IamOp::RoleList
                        | IamOp::RoleShow { .. }
                        | IamOp::GroupList
                        | IamOp::GroupShow { .. }
                        | IamOp::OauthList
                        | IamOp::OauthShow { .. },
                )
        )
    }
}

/// The codec version prefixed to every encoded [`QueryOp`] payload. Kept
/// SEPARATE from [`OP_CODEC_VERSION`] / [`CONTROL_OP_CODEC_VERSION`] so the
/// data-query op family evolves independently of the CRUD and control ones.
pub const QUERY_OP_CODEC_VERSION: u8 = 1;

/// The typed **data-query op** vocabulary (`data-query-tier-remote-surface`):
/// a real remote read/query surface over a node's keyed store (K/V + Document)
/// and its SQL views, riding [`pillar_wire::Body::QueryOp`] over the SAME
/// sealed, signed resource-op tier as [`ResourceOp`] (streamdb CRUD) and
/// [`ControlOp`] (portal/authority). This is the generalization of the
/// existing PSL query server into a first-class client query tier: `pillar kv`,
/// `pillar doc`, and `pillar sql` all emit one of these ops, the node folds the
/// live view and returns it, and the CLI round-trips a real answer.
///
/// Writes (`KvPut`/`KvDelete`/`DocPutField`/`DocDeleteField`/`CreateView`/
/// `DropView`) are signed acts gated on the AUTHENTICATED signer's
/// `data:write` authority; reads (every `*Get`/`*Keys`/`*Ids`/`Collections`/
/// `View`/`ListViews`) are member-gated VIEWS that emit no event. Wasm-safe
/// (serde only) like the rest of this crate, so the browser client builds the
/// identical typed op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryOp {
    /// Keyed K/V surface (`pillar kv …`).
    Kv(KvOp),
    /// Structured Document surface (`pillar doc …`).
    Doc(DocOp),
    /// SQL views over the Document store (`pillar sql …`).
    Sql(SqlOp),
    /// The IPFS object-inspection tier (`pillar object …`,
    /// `pillar-object-inspection-tier`): the bottom layer of the inspection
    /// stack, addressing any content-addressed block by CID.
    Object(ObjectOp),
    /// Catalog-introspection surface (`pillar catalog …`) — every variant a
    /// member-gated VIEW folded from the live `__catalog` collection + the
    /// keyed store's live collections + the collection-placement registry.
    Catalog(CatalogOp),
    /// The op-log inspection tier (`pillar log ...`, `pillar-log-inspection-
    /// tier`): the middle layer of the inspection stack in
    /// `docs/data-inspection.md` -- a collection's signed, content-addressed
    /// op log (the SAME `EventLog` every `Kv`/`Doc`/`Sql`/`Object` write
    /// already appends to), one hop above the raw content-addressed blocks
    /// [`ObjectOp`] exposes and one hop below the folded document/kv/sql
    /// view.
    Log(LogOp),
}

/// The op-log inspection ops (`pillar log info|blocks|list|show|dag|watch|
/// verify`). Every variant is a member-gated VIEW -- the op log itself is
/// written only as a side effect of a `Kv`/`Doc`/`Sql`/`Object` write, never
/// directly through this surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum LogOp {
    /// Summary: op count + current tip(s) of `collection`'s op log.
    Info {
        /// The collection whose op log is inspected.
        collection: String,
    },
    /// The REPORTED (never inferred) physical storage layout backing
    /// `collection`: a document/keyed collection reports its snapshot CID (or
    /// `none` when never compacted) plus its live op tail; a TSDB collection
    /// reports its immutable retention blocks back to the retention horizon,
    /// with older data pruned and no snapshot.
    Blocks {
        /// The collection to report the storage layout of.
        collection: String,
    },
    /// Every op-log event id (lowercase hex content address) of `collection`,
    /// in append order.
    List {
        /// The collection whose op log is listed.
        collection: String,
    },
    /// Decode one op: author + signature, HLC, causal parents, kind, key,
    /// payload CID, and seal (always `none` -- op-log entries are never
    /// sealed bodies; see [`ObjectOp`] for a sealed block).
    Show {
        /// The collection the event belongs to.
        collection: String,
        /// The event's content-addressed id, lowercase hex.
        event_id_hex: String,
    },
    /// Render the causal graph (`prev`/`parents` hash-links) of
    /// `collection`'s op log, so concurrent CRDT-merged branches are visible
    /// at the log level.
    Dag {
        /// The collection whose causal graph is rendered.
        collection: String,
    },
    /// The current tip(s) of `collection`'s op log -- a bounded, single-shot
    /// stand-in for a live subscription (there is no persistent streaming
    /// transport on this remote surface): a caller re-issues `Watch` to
    /// observe the tip advance.
    Watch {
        /// The collection to watch.
        collection: String,
    },
    /// Confirm hash==id and signature validity of one event WITHOUT ever
    /// needing to interpret its (possibly opaque) payload -- the log-level
    /// analogue of [`ObjectOp::Verify`].
    Verify {
        /// The collection the event belongs to.
        collection: String,
        /// The event's content-addressed id, lowercase hex.
        event_id_hex: String,
    },
}

/// The visibility class of a `pillar object put` block: whether the body
/// travels sealed to a fixed recipient set or in the clear.
///
/// Mirrors the `public`/`sealed` distinction `docs/data-inspection.md`'s
/// "What you can see" section calls for: a `public` object carries NO access
/// barrier (`object cat`/`get` always returns its plaintext); a `sealed`
/// object's body is opened only by a holder of one of its recipients' X25519
/// secret keys — everyone else still sees the envelope (author, size,
/// recipient count, links) but never the plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectVisibility {
    /// No access barrier: `cat`/`get` always return the plaintext body.
    Public,
    /// Sealed to a fixed recipient set (X25519, `RecipientSeal`): `cat`/`get`
    /// return plaintext only when the caller supplies a recipient secret that
    /// opens the envelope; otherwise only the envelope (author/size/
    /// recipient-count/links) is returned.
    Sealed,
}

/// The content-addressed **object** surface (`pillar object …`): the bottom
/// tier of the inspection stack (`docs/data-inspection.md`) — any block,
/// reached over the SAME sealed `QueryOp` remote surface as `kv`/`doc`/`sql`.
/// `Put` authors a new signed, content-addressed block (a signed act, gated
/// on `data:write`, exactly like a `Kv`/`Doc` write); `Stat`/`Links`/`Get`/
/// `Cat`/`Verify` are member-gated VIEWS over an existing block by CID.
///
/// `Get`/`Cat` accept an optional `sealing_secret_hex` (the caller's X25519
/// sealing secret, lowercase hex) so a `Sealed` object's body can be opened
/// IN PLACE against the node's held ciphertext — never by weakening the
/// seal itself: an absent or non-matching secret yields the envelope-only
/// view (no plaintext), and a `Public` object's plaintext is always
/// returned regardless. `Verify` never takes a secret: it confirms the
/// block's hash equals its CID and its authorship signature is valid
/// WITHOUT ever attempting to open the sealed body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ObjectOp {
    /// Author a new content-addressed block. `payload_hex` is the plaintext
    /// body (lowercase hex); for `Sealed` visibility it is sealed to every
    /// key in `recipients_hex` (lowercase-hex X25519 `SealingPublicKey`s)
    /// before storage — the plaintext itself is never stored for a `Sealed`
    /// object. `links_hex` names this block's child CIDs (one DAG hop),
    /// stored in the clear as envelope metadata so `Links` never needs to
    /// open the body.
    Put {
        /// `Public` (no barrier) or `Sealed` (recipient-gated) visibility.
        visibility: ObjectVisibility,
        /// The plaintext body, lowercase hex.
        payload_hex: String,
        /// Child CIDs (one DAG hop), lowercase hex multihash, in the clear.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        links_hex: Vec<String>,
        /// Recipient `SealingPublicKey`s (lowercase hex), required (non-empty)
        /// for `Sealed` visibility; ignored for `Public`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recipients_hex: Vec<String>,
    },
    /// Codec/size/pin-status + which nodes pin the block named by `cid_hex`.
    Stat {
        /// The block's CID, lowercase hex multihash.
        cid_hex: String,
    },
    /// The child CIDs (one DAG hop) `cid_hex` names, from the block's
    /// in-the-clear envelope metadata — never requires opening the body.
    Links {
        /// The block's CID, lowercase hex multihash.
        cid_hex: String,
    },
    /// The raw body bytes (hex): plaintext for `Public`; for `Sealed`, the
    /// plaintext only if `sealing_secret_hex` opens it, else the envelope.
    Get {
        /// The block's CID, lowercase hex multihash.
        cid_hex: String,
        /// The caller's X25519 sealing secret, lowercase hex, to attempt
        /// opening a `Sealed` body. Ignored for `Public`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sealing_secret_hex: Option<String>,
    },
    /// The decoded payload, rendered for display: plaintext for `Public`; for
    /// `Sealed`, the plaintext only if `sealing_secret_hex` opens it, else the
    /// envelope (author/HLC-less size/recipient-count/links; a `Sealed`
    /// object's plaintext is never guessed at or partially revealed).
    Cat {
        /// The block's CID, lowercase hex multihash.
        cid_hex: String,
        /// The caller's X25519 sealing secret, lowercase hex, to attempt
        /// opening a `Sealed` body. Ignored for `Public`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sealing_secret_hex: Option<String>,
    },
    /// Recompute the block's hash and confirm it equals `cid_hex`, and check
    /// its authorship signature — WITHOUT ever attempting to open/decrypt
    /// the sealed body. Proves integrity + authorship to a reader who cannot
    /// decrypt.
    Verify {
        /// The block's CID, lowercase hex multihash.
        cid_hex: String,
    },
}

/// Catalog-introspection ops (`pillar catalog databases|collections|views|
/// describe`). Every variant is a member-gated VIEW that emits no signed
/// event — discovery is a QUERY folded from the live `__catalog` Document
/// collection plus the keyed store's live collections, never hard-coded help.
///
/// A `Describe` answer reports, per collection, its SURFACE (keyed → kv/doc/
/// sql vs tsdb → obs/psl), its live SCHEMA (folded field names), its
/// CONSISTENCY class (AP/CP), its VISIBILITY class, and its PLACEMENT tags +
/// the LIVE participating-node list resolved from the collection-placement
/// registry (`data-placement-collection-tags`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum CatalogOp {
    /// List every logical database (the namespace prefix of a collection name,
    /// the part before the first `.`; a bare name is its own database).
    Databases,
    /// List every live collection (keyed store collections + defined views),
    /// excluding the `__catalog` system collection itself.
    Collections,
    /// List every view currently defined in the catalog (the SQL-native
    /// `SHOW TABLES` over the folded `__catalog` collection).
    Views,
    /// Describe one collection's full introspection surface: surface class,
    /// schema, consistency, visibility, placement tags + participating nodes.
    Describe {
        /// The collection (or view) to describe.
        collection: String,
    },
}

/// K/V surface ops (`pillar kv put|get|delete|keys|collections`). `Put`/
/// `Delete` are signed acts; `Get`/`Keys`/`Collections` are member-gated VIEWS.
/// A value travels as a lowercase-hex string so an opaque (possibly non-UTF-8)
/// K/V payload round-trips faithfully over the text ack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum KvOp {
    /// Put an opaque value (`value_hex`) for `key` in `collection`.
    Put {
        /// The collection namespace.
        collection: String,
        /// The K/V key.
        key: String,
        /// The opaque value, lowercase hex.
        value_hex: String,
    },
    /// Delete `key` from `collection` (tombstone).
    Delete {
        /// The collection namespace.
        collection: String,
        /// The K/V key.
        key: String,
    },
    /// Read the live value of `key` in `collection` (returned as lowercase hex).
    Get {
        /// The collection namespace.
        collection: String,
        /// The K/V key.
        key: String,
    },
    /// List every live key of `collection`.
    Keys {
        /// The collection namespace.
        collection: String,
    },
    /// List every collection with at least one live op.
    Collections,
}

/// Document surface ops (`pillar doc put|get|delete|fields|ids`). `Put`/
/// `Delete` are signed acts; `Get`/`Fields`/`Ids` are member-gated VIEWS. A
/// field value travels as a UTF-8 scalar string (the common document-leaf
/// case).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum DocOp {
    /// Put a scalar `value` for `field` of document `id` in `collection`.
    PutField {
        /// The collection namespace.
        collection: String,
        /// The document id.
        id: String,
        /// The (possibly dotted) field name.
        field: String,
        /// The scalar field value (UTF-8 text).
        value: String,
    },
    /// Delete `field` of document `id` in `collection` (tombstone).
    DeleteField {
        /// The collection namespace.
        collection: String,
        /// The document id.
        id: String,
        /// The field name.
        field: String,
    },
    /// Read the live value of `field` (dotted path allowed) of document `id`.
    GetField {
        /// The collection namespace.
        collection: String,
        /// The document id.
        id: String,
        /// The (possibly dotted) field path.
        field: String,
    },
    /// List the live field names of document `id` in `collection`.
    Fields {
        /// The collection namespace.
        collection: String,
        /// The document id.
        id: String,
    },
    /// List every live document id of `collection`.
    Ids {
        /// The collection namespace.
        collection: String,
    },
}

/// SQL-view ops (`pillar sql create-view|drop-view|view|views`). `CreateView`/
/// `DropView` are signed acts (DDL, written as a `__catalog` document);
/// `View`/`Views` are member-gated VIEWS that fold the live source collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SqlOp {
    /// `CREATE MATERIALIZED VIEW <name> OVER <source>` (optional equality
    /// filter `field`=`value`, optional projection `project`).
    CreateView {
        /// The view name.
        name: String,
        /// The source collection folded into the view.
        source: String,
        /// Optional equality-filter field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter_field: Option<String>,
        /// Optional equality-filter value (UTF-8 scalar text).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter_value: Option<String>,
        /// Optional projected field paths (`None` keeps every field).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<Vec<String>>,
    },
    /// `DROP VIEW <name>`.
    DropView {
        /// The view name.
        name: String,
    },
    /// Materialize the view `name` (fold its source live) and return its rows.
    View {
        /// The view name.
        name: String,
    },
    /// List every view currently defined in the catalog.
    Views,
    /// `SHOW TABLES` — the SQL-native alias for listing every view/table
    /// defined in the catalog (folds the `__catalog` collection). Member-gated
    /// VIEW, identical answer to [`SqlOp::Views`].
    ShowTables,
    /// `DESCRIBE <table>` — the SQL-native alias for describing one catalog
    /// entry's definition (source, filter, projection), folded from the
    /// `__catalog` collection. Member-gated VIEW.
    DescribeTable {
        /// The view/table name to describe.
        table: String,
    },
    /// `SELECT * FROM __catalog` — the SQL-native catalog query: materialize
    /// the `__catalog` system collection itself as rows (name → def), proving
    /// the catalog IS a queryable collection, not a hard-coded surface.
    /// Member-gated VIEW.
    SelectCatalog,
}

impl QueryOp {
    /// Encode to a query-op payload: a single [`QUERY_OP_CODEC_VERSION`] byte
    /// followed by canonical JSON. Deterministic, like [`ResourceOp::encode`].
    ///
    /// # Errors
    /// [`OpCodecError::Encode`] if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, OpCodecError> {
        let json = serde_json::to_vec(self).map_err(|e| OpCodecError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + json.len());
        out.push(QUERY_OP_CODEC_VERSION);
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode a query-op payload produced by [`Self::encode`], checking the
    /// leading codec-version byte.
    ///
    /// # Errors
    /// [`OpCodecError::Empty`] on an empty payload;
    /// [`OpCodecError::UnsupportedVersion`] on an unknown codec version;
    /// [`OpCodecError::Decode`] if the body is not a well-formed [`QueryOp`].
    pub fn decode(bytes: &[u8]) -> Result<Self, OpCodecError> {
        let (&version, rest) = bytes.split_first().ok_or(OpCodecError::Empty)?;
        if version != QUERY_OP_CODEC_VERSION {
            return Err(OpCodecError::UnsupportedVersion(version));
        }
        serde_json::from_slice(rest).map_err(|e| OpCodecError::Decode(e.to_string()))
    }

    /// Whether this op is a read-only VIEW (served from live state, emits no
    /// signed event) — the wire dispatcher routes reads through the member-
    /// gated view path and writes through the capability-gated act path.
    #[must_use]
    pub fn is_read(&self) -> bool {
        match self {
            QueryOp::Kv(op) => {
                matches!(op, KvOp::Get { .. } | KvOp::Keys { .. } | KvOp::Collections)
            }
            QueryOp::Doc(op) => matches!(
                op,
                DocOp::GetField { .. } | DocOp::Fields { .. } | DocOp::Ids { .. }
            ),
            QueryOp::Sql(op) => matches!(
                op,
                SqlOp::View { .. }
                    | SqlOp::Views
                    | SqlOp::ShowTables
                    | SqlOp::DescribeTable { .. }
                    | SqlOp::SelectCatalog
            ),
            QueryOp::Object(op) => !matches!(op, ObjectOp::Put { .. }),
            // Every catalog op is a read-only introspection VIEW.
            QueryOp::Catalog(_) => true,
            // Every log op is a read-only introspection VIEW — the op log
            // itself is written only as a side effect of a Kv/Doc/Sql/Object
            // write, never directly through this surface.
            QueryOp::Log(_) => true,
        }
    }
}

/// A fault encoding or decoding a [`ResourceOp`] payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpCodecError {
    /// The payload was empty (no version byte).
    Empty,
    /// The payload's codec-version byte is not one this build understands.
    UnsupportedVersion(u8),
    /// The op could not be serialized.
    Encode(String),
    /// The payload's body is not a well-formed [`ResourceOp`].
    Decode(String),
}

impl std::fmt::Display for OpCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpCodecError::Empty => f.write_str("empty resource-op payload"),
            OpCodecError::UnsupportedVersion(v) => {
                write!(f, "unsupported resource-op codec version {v}")
            }
            OpCodecError::Encode(e) => write!(f, "encoding resource op: {e}"),
            OpCodecError::Decode(e) => write!(f, "decoding resource op: {e}"),
        }
    }
}

impl std::error::Error for OpCodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{Metadata, Value};

    /// The shipped default `metrics-default` RetentionPolicy CRD, as the CLI's
    /// `render defaults` would build it (metrics, 30d window).
    fn metrics_default_crd() -> Crd {
        Crd::new(
            "pillar.dev/v1",
            "RetentionPolicy",
            Metadata::new("metrics-default").with_label("pillar.dev/managed-by", "defaults"),
        )
        .with_spec("signalKind", Value::String("Metric".into()))
        .with_spec("window", Value::Integer(2_592_000))
    }

    #[test]
    fn apply_round_trips_through_the_payload_codec() {
        let op = ResourceOp::Apply {
            crd: metrics_default_crd(),
        };
        let bytes = op.encode().expect("encode");
        assert_eq!(bytes[0], OP_CODEC_VERSION, "version-prefixed");
        let back = ResourceOp::decode(&bytes).expect("decode");
        assert_eq!(back, op, "apply round-trips byte-faithfully");
        assert_eq!(back.kind(), "RetentionPolicy");
        assert_eq!(back.name(), Some("metrics-default"));
    }

    #[test]
    fn delete_round_trips_through_the_payload_codec() {
        let op = ResourceOp::Delete {
            kind: "RetentionPolicy".into(),
            name: "metrics-default".into(),
        };
        let bytes = op.encode().expect("encode");
        let back = ResourceOp::decode(&bytes).expect("decode");
        assert_eq!(back, op);
        assert_eq!(back.kind(), "RetentionPolicy");
        assert_eq!(back.name(), Some("metrics-default"));
    }

    #[test]
    fn get_and_describe_read_verbs_round_trip_and_report_read() {
        let list = ResourceOp::Get {
            kind: "RetentionPolicy".into(),
            name: None,
        };
        let bytes = list.encode().expect("encode");
        let back = ResourceOp::decode(&bytes).expect("decode");
        assert_eq!(back, list, "list get round-trips");
        assert_eq!(back.kind(), "RetentionPolicy");
        assert_eq!(back.name(), None, "a list get names no single object");
        assert!(back.is_read(), "get is a view");

        let one = ResourceOp::Get {
            kind: "RetentionPolicy".into(),
            name: Some("metrics-default".into()),
        };
        let back = ResourceOp::decode(&one.encode().expect("encode")).expect("decode");
        assert_eq!(back, one);
        assert_eq!(back.name(), Some("metrics-default"));
        assert!(back.is_read());

        let desc = ResourceOp::Describe {
            kind: "RetentionPolicy".into(),
            name: "metrics-default".into(),
        };
        let back = ResourceOp::decode(&desc.encode().expect("encode")).expect("decode");
        assert_eq!(back, desc);
        assert!(back.is_read());
        assert!(list.is_read(), "a list get is a view");
        assert!(
            !ResourceOp::Delete {
                kind: "K".into(),
                name: "n".into()
            }
            .is_read(),
            "delete is a mutation, not a view"
        );
    }

    /// The load-bearing property: the SAME logical op encodes to the SAME
    /// bytes every time (and therefore across producers), so it content-
    /// addresses to one streamdb op id and the CRDT op-log dedups it.
    #[test]
    fn encoding_is_deterministic_across_producers() {
        // Two independently-built copies of the same logical op (spec fields
        // inserted in DIFFERENT order to prove the BTreeMap canonicalizes).
        let a = ResourceOp::Apply {
            crd: Crd::new("pillar.dev/v1", "RetentionPolicy", Metadata::new("m"))
                .with_spec("window", Value::Integer(2_592_000))
                .with_spec("signalKind", Value::String("Metric".into())),
        };
        let b = ResourceOp::Apply {
            crd: Crd::new("pillar.dev/v1", "RetentionPolicy", Metadata::new("m"))
                .with_spec("signalKind", Value::String("Metric".into()))
                .with_spec("window", Value::Integer(2_592_000)),
        };
        assert_eq!(
            a.encode().expect("a"),
            b.encode().expect("b"),
            "same logical op -> identical bytes regardless of insert order"
        );
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(ResourceOp::decode(&[]), Err(OpCodecError::Empty));
    }

    #[test]
    fn unknown_codec_version_is_rejected_distinctly() {
        let mut bytes = ResourceOp::Delete {
            kind: "K".into(),
            name: "n".into(),
        }
        .encode()
        .expect("encode");
        bytes[0] = 0xFF;
        assert_eq!(
            ResourceOp::decode(&bytes),
            Err(OpCodecError::UnsupportedVersion(0xFF))
        );
    }

    #[test]
    fn garbage_body_after_a_valid_version_is_a_decode_error() {
        let bytes = [OP_CODEC_VERSION, b'{', b'!'];
        assert!(matches!(
            ResourceOp::decode(&bytes),
            Err(OpCodecError::Decode(_))
        ));
    }

    #[test]
    fn control_op_members_round_trips_and_classifies_read_vs_act() {
        let list = ControlOp::Members(MembersOp::List);
        let bytes = list.encode().expect("encode");
        assert_eq!(bytes[0], CONTROL_OP_CODEC_VERSION, "version-prefixed");
        assert_eq!(ControlOp::decode(&bytes).expect("decode"), list);
        assert!(list.is_read(), "member ls is a view");

        let add = ControlOp::Members(MembersOp::Add {
            handle: "alice".into(),
            role: "admin".into(),
        });
        assert_eq!(
            ControlOp::decode(&add.encode().expect("encode")).expect("decode"),
            add
        );
        assert!(!add.is_read(), "member add is a signed act");

        let set = ControlOp::Members(MembersOp::SetRole {
            handle: "bob".into(),
            role: "member".into(),
        });
        assert_eq!(
            ControlOp::decode(&set.encode().expect("encode")).expect("decode"),
            set
        );
        assert!(!set.is_read());
    }

    #[test]
    fn control_op_session_round_trips_and_classifies_read_vs_act() {
        let list = ControlOp::Session(SessionOp::List {
            principal: "spencer".into(),
        });
        assert_eq!(
            ControlOp::decode(&list.encode().expect("encode")).expect("decode"),
            list
        );
        assert!(list.is_read(), "session ls is a view");

        let show = ControlOp::Session(SessionOp::Show {
            principal: "spencer".into(),
            id: "s3".into(),
        });
        assert_eq!(
            ControlOp::decode(&show.encode().expect("encode")).expect("decode"),
            show
        );
        assert!(show.is_read(), "session show is a view");

        let revoke = ControlOp::Session(SessionOp::Revoke {
            principal: "spencer".into(),
            id: "s3".into(),
        });
        assert_eq!(
            ControlOp::decode(&revoke.encode().expect("encode")).expect("decode"),
            revoke
        );
        assert!(!revoke.is_read(), "session revoke is a signed act");

        let revoke_all = ControlOp::Session(SessionOp::RevokeAll {
            principal: "spencer".into(),
        });
        assert_eq!(
            ControlOp::decode(&revoke_all.encode().expect("encode")).expect("decode"),
            revoke_all
        );
        assert!(!revoke_all.is_read());
    }

    #[test]
    fn control_op_wot_and_obs_round_trip_and_are_reads() {
        for op in [
            ControlOp::Wot(WotOp::Graph),
            ControlOp::Wot(WotOp::ListTrust),
            ControlOp::Wot(WotOp::ListSignatures),
            ControlOp::Wot(WotOp::ListAttestations),
            ControlOp::Obs(ObsOp::Explore {
                kind: "metric".into(),
            }),
            ControlOp::Obs(ObsOp::Query {
                kind: "log".into(),
                filter: Some("level=error".into()),
            }),
            ControlOp::Obs(ObsOp::LiveKinds),
            ControlOp::Obs(ObsOp::Psl {
                query: "metric http_requests".into(),
            }),
            ControlOp::Obs(ObsOp::LabelValues { key: "job".into() }),
            ControlOp::Obs(ObsOp::RetentionGet),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "wot/obs ops are views: {op:?}");
        }
    }

    #[test]
    fn control_op_obs_acts_round_trip_and_are_not_reads() {
        for op in [
            ControlOp::Obs(ObsOp::RetentionSet {
                body: "metric=30d".into(),
            }),
            ControlOp::Obs(ObsOp::Recording {
                spec: "rule x = sum(y)".into(),
            }),
            ControlOp::Obs(ObsOp::Alert {
                spec: "alert z when q > 1".into(),
            }),
            ControlOp::Obs(ObsOp::DashboardSave {
                name: "slo".into(),
                spec: "{panels:[]}".into(),
            }),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(!op.is_read(), "obs acts are not reads: {op:?}");
        }
        let get = ControlOp::Obs(ObsOp::DashboardGet {
            id: "1220ab".into(),
        });
        assert_eq!(
            ControlOp::decode(&get.encode().expect("encode")).expect("decode"),
            get
        );
        assert!(get.is_read(), "dashboard get is a read");
    }

    #[test]
    fn control_op_identity_and_user_round_trip() {
        let acts = [
            ControlOp::Identity(IdentityOp::Enroll {
                domain: "acme".into(),
            }),
            ControlOp::Identity(IdentityOp::Rotate {
                new_primary: "key-2".into(),
            }),
            ControlOp::Identity(IdentityOp::Recover),
            ControlOp::User(UserOp::Invite {
                handle: "bob".into(),
                email: "bob@example.com".into(),
                force_password_change: true,
                require_passkey: false,
                password: None,
            }),
            ControlOp::User(UserOp::Disable {
                handle: "bob".into(),
            }),
            ControlOp::User(UserOp::SetPassword {
                handle: "bob".into(),
                password: "s3cret".into(),
                force: true,
            }),
        ];
        for op in &acts {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                *op
            );
            assert!(!op.is_read(), "identity/user acts are not reads: {op:?}");
        }
        for op in [
            ControlOp::Identity(IdentityOp::Show),
            ControlOp::Identity(IdentityOp::Domains),
            ControlOp::User(UserOp::List),
            ControlOp::User(UserOp::Show {
                handle: "bob".into(),
            }),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "identity/user views are reads: {op:?}");
        }
    }

    #[test]
    fn control_op_cluster_round_trip() {
        let acts = [
            ControlOp::Cluster(ClusterOp::RequestSubmitNode {
                subject: "node-b".into(),
                peer_id: "12D3".into(),
                version: "0.1.0".into(),
                os: "linux".into(),
                public_key_cid: "1220ab".into(),
                custody: Some("password".into()),
                pub_addrs: vec!["/ip4/192.0.2.1/tcp/4001".into()],
                priv_addrs: vec![],
                labels: vec!["region=us".into()],
            }),
            ControlOp::Cluster(ClusterOp::RequestSubmitUser {
                subject: "carol".into(),
                custody: None,
                labels: vec![],
            }),
            ControlOp::Cluster(ClusterOp::RequestApprove { id: 7 }),
            ControlOp::Cluster(ClusterOp::RequestReject { id: 8 }),
        ];
        for op in &acts {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                *op
            );
            assert!(!op.is_read(), "cluster request acts are not reads: {op:?}");
        }
        for op in [
            ControlOp::Cluster(ClusterOp::RequestList),
            ControlOp::Cluster(ClusterOp::TopologyTree {
                tier: "region".into(),
            }),
            ControlOp::Cluster(ClusterOp::NodesAt {
                tier: "region".into(),
                value: "us".into(),
            }),
            ControlOp::Cluster(ClusterOp::Domains),
            ControlOp::Cluster(ClusterOp::Members),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "cluster views are reads: {op:?}");
        }
    }

    #[test]
    fn control_op_iam_round_trip_and_classify() {
        let acts = [
            ControlOp::Iam(IamOp::RoleAdd {
                name: "deployer".into(),
                capabilities: vec!["resource:apply".into(), "obs:read".into()],
            }),
            ControlOp::Iam(IamOp::RoleRm {
                name: "deployer".into(),
            }),
            ControlOp::Iam(IamOp::GroupAdd {
                name: "ops".into(),
                roles: vec!["deployer".into()],
            }),
            ControlOp::Iam(IamOp::GroupAddMember {
                name: "ops".into(),
                handle: "alice".into(),
            }),
            ControlOp::Iam(IamOp::GroupRm { name: "ops".into() }),
            ControlOp::Iam(IamOp::OauthRegister {
                client_id: "portal".into(),
                client_type: "public".into(),
                redirect_uris: vec!["https://example.com/cb".into()],
                scopes: vec!["openid".into()],
                grants: vec!["authorization_code".into()],
            }),
        ];
        for op in &acts {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                *op
            );
            assert!(!op.is_read(), "iam acts are not reads: {op:?}");
        }
        for op in [
            ControlOp::Iam(IamOp::RoleList),
            ControlOp::Iam(IamOp::RoleShow {
                name: "deployer".into(),
            }),
            ControlOp::Iam(IamOp::GroupList),
            ControlOp::Iam(IamOp::GroupShow { name: "ops".into() }),
            ControlOp::Iam(IamOp::OauthList),
            ControlOp::Iam(IamOp::OauthShow {
                client_id: "portal".into(),
            }),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "iam views are reads: {op:?}");
        }
    }

    #[test]
    fn control_op_trust_round_trip_and_classify() {
        let acts = [
            ControlOp::Trust(TrustOp::Edge {
                subject: "gid:node-b".into(),
                depth: 3,
            }),
            ControlOp::Trust(TrustOp::AttestBuild {
                issuer: "gid:root".into(),
                capacity: "role@acme".into(),
                authority: String::new(),
                subject: "gid:alice".into(),
                action: "deploy".into(),
                resource: "cell/acme".into(),
                quota: Some(1000),
                scope: "acme".into(),
            }),
            ControlOp::Trust(TrustOp::GrantAdd {
                subject: "gid:alice".into(),
                capability: "portal:members:write".into(),
                allow: true,
            }),
            ControlOp::Trust(TrustOp::GrantRm {
                subject: "gid:alice".into(),
                capability: "portal:members:write".into(),
            }),
        ];
        for op in &acts {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                *op
            );
            assert!(!op.is_read(), "trust acts are not reads: {op:?}");
        }
        for op in [
            ControlOp::Trust(TrustOp::Audit {
                cid: "1220ab".into(),
            }),
            ControlOp::Trust(TrustOp::GrantCheck {
                subject: "gid:alice".into(),
                capability: "portal:members:write".into(),
            }),
            ControlOp::Trust(TrustOp::WhoCan {
                capability: "portal:members:write".into(),
            }),
            ControlOp::Trust(TrustOp::Caps {
                subject: "gid:alice".into(),
                candidates: vec!["portal:members:write".into(), "iam:users:write".into()],
            }),
            ControlOp::Trust(TrustOp::Path {
                subject: "gid:alice".into(),
            }),
        ] {
            assert_eq!(
                ControlOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "trust views are reads: {op:?}");
        }
    }

    #[test]
    fn query_op_round_trips_and_classifies_read_vs_write() {
        let acts = [
            QueryOp::Kv(KvOp::Put {
                collection: "cfg".into(),
                key: "greeting".into(),
                value_hex: "68656c6c6f".into(),
            }),
            QueryOp::Kv(KvOp::Delete {
                collection: "cfg".into(),
                key: "greeting".into(),
            }),
            QueryOp::Doc(DocOp::PutField {
                collection: "users".into(),
                id: "u1".into(),
                field: "name".into(),
                value: "alice".into(),
            }),
            QueryOp::Doc(DocOp::DeleteField {
                collection: "users".into(),
                id: "u1".into(),
                field: "name".into(),
            }),
            QueryOp::Sql(SqlOp::CreateView {
                name: "active".into(),
                source: "users".into(),
                filter_field: Some("status".into()),
                filter_value: Some("on".into()),
                project: Some(vec!["name".into()]),
            }),
            QueryOp::Sql(SqlOp::DropView {
                name: "active".into(),
            }),
        ];
        for op in &acts {
            let bytes = op.encode().expect("encode");
            assert_eq!(bytes[0], QUERY_OP_CODEC_VERSION, "version-prefixed");
            assert_eq!(&QueryOp::decode(&bytes).expect("decode"), op);
            assert!(!op.is_read(), "query write is not a read: {op:?}");
        }
        for op in [
            QueryOp::Kv(KvOp::Get {
                collection: "cfg".into(),
                key: "greeting".into(),
            }),
            QueryOp::Kv(KvOp::Keys {
                collection: "cfg".into(),
            }),
            QueryOp::Kv(KvOp::Collections),
            QueryOp::Doc(DocOp::GetField {
                collection: "users".into(),
                id: "u1".into(),
                field: "name".into(),
            }),
            QueryOp::Doc(DocOp::Fields {
                collection: "users".into(),
                id: "u1".into(),
            }),
            QueryOp::Doc(DocOp::Ids {
                collection: "users".into(),
            }),
            QueryOp::Sql(SqlOp::View {
                name: "active".into(),
            }),
            QueryOp::Sql(SqlOp::Views),
        ] {
            assert_eq!(
                QueryOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "query view is a read: {op:?}");
        }
    }

    #[test]
    fn object_op_round_trips_and_classifies_read_vs_write() {
        let put = QueryOp::Object(ObjectOp::Put {
            visibility: ObjectVisibility::Sealed,
            payload_hex: "68656c6c6f".into(),
            links_hex: vec!["aa".into()],
            recipients_hex: vec!["bb".into()],
        });
        let bytes = put.encode().expect("encode");
        assert_eq!(&QueryOp::decode(&bytes).expect("decode"), &put);
        assert!(!put.is_read(), "object put is a write");

        for op in [
            QueryOp::Object(ObjectOp::Stat {
                cid_hex: "cc".into(),
            }),
            QueryOp::Object(ObjectOp::Links {
                cid_hex: "cc".into(),
            }),
            QueryOp::Object(ObjectOp::Get {
                cid_hex: "cc".into(),
                sealing_secret_hex: Some("dd".into()),
            }),
            QueryOp::Object(ObjectOp::Cat {
                cid_hex: "cc".into(),
                sealing_secret_hex: None,
            }),
            QueryOp::Object(ObjectOp::Verify {
                cid_hex: "cc".into(),
            }),
        ] {
            assert_eq!(
                QueryOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "object view is a read: {op:?}");
        }
    }

    #[test]
    fn log_op_round_trips_and_is_always_a_read() {
        for op in [
            QueryOp::Log(LogOp::Info {
                collection: "users".into(),
            }),
            QueryOp::Log(LogOp::Blocks {
                collection: "users".into(),
            }),
            QueryOp::Log(LogOp::List {
                collection: "users".into(),
            }),
            QueryOp::Log(LogOp::Show {
                collection: "users".into(),
                event_id_hex: "aa".into(),
            }),
            QueryOp::Log(LogOp::Dag {
                collection: "users".into(),
            }),
            QueryOp::Log(LogOp::Watch {
                collection: "users".into(),
            }),
            QueryOp::Log(LogOp::Verify {
                collection: "users".into(),
                event_id_hex: "aa".into(),
            }),
        ] {
            assert_eq!(
                QueryOp::decode(&op.encode().expect("encode")).expect("decode"),
                op
            );
            assert!(op.is_read(), "log op is always a read: {op:?}");
        }
    }

    #[test]
    fn query_op_rejects_empty_and_unknown_version() {
        assert_eq!(QueryOp::decode(&[]), Err(OpCodecError::Empty));
        let mut bytes = QueryOp::Kv(KvOp::Collections).encode().expect("encode");
        bytes[0] = 0xFD;
        assert_eq!(
            QueryOp::decode(&bytes),
            Err(OpCodecError::UnsupportedVersion(0xFD))
        );
    }

    #[test]
    fn control_op_rejects_empty_and_unknown_version() {
        assert_eq!(ControlOp::decode(&[]), Err(OpCodecError::Empty));
        let mut bytes = ControlOp::Members(MembersOp::List)
            .encode()
            .expect("encode");
        bytes[0] = 0xFE;
        assert_eq!(
            ControlOp::decode(&bytes),
            Err(OpCodecError::UnsupportedVersion(0xFE))
        );
    }
}
