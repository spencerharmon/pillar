//! The `pillar {domain|cell|space|node|peer|lease|request}` families — the
//! `cli-cluster-stream-impl` task against
//! [`docs/cli-surface.md`](../../../docs/cli-surface.md) §§ "Naming: `pillar
//! domain`" and "Topology: cell / space / node / peer / lease / request".
//!
//! Same split as [`crate::session_cli`]/[`crate::observability_ui`]: each
//! family is a small, fully unit-tested engine type; the argv shell in
//! `main.rs` only parses flags and prints, this module is the authoritative
//! surface a test (or a future HTTP front-end) drives directly.
//!
//! # `pillar domain` is naming-only
//!
//! A domain disambiguates `kind/name` addresses across a federation and maps
//! a friendly name to the cells it names — nothing more. It carries **no**
//! authority: a domain command never signs, never grants, never coordinates.
//! [`DomainCli`] holds no [`pillar_eventlog::EventLog`] at all — there is
//! structurally no way for `new`/`add-cell`/`rm-cell` to append an event, so
//! "a domain command emits no authority event" is a type-level guarantee, the
//! same discipline [`crate::session_cli::SessionCli`] uses for its views.

use std::collections::{BTreeMap, BTreeSet};

use pillar_bootstrap::request::{
    BootstrapRequest, BootstrapRequestId, BootstrapRequestQueue, NodeIdentity, RequestError,
    SealedCellKey,
};
use pillar_bootstrap::CustodyKind;
use pillar_cells::Cell;
use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};

// ---------------------------------------------------------------------------
// `pillar domain` — naming-only, no authority, no event log.
// ---------------------------------------------------------------------------

/// One domain's naming record: the listeners it maps to and the cells it
/// currently names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainRecord {
    /// The `host:port` (or similar) listeners this domain resolves to.
    pub listeners: Vec<String>,
    /// The cells currently grouped under this domain's naming root.
    pub cells: BTreeSet<String>,
}

/// Why a `pillar domain` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    /// `new` of a domain name already registered.
    AlreadyExists(String),
    /// `show`/`add-cell`/`rm-cell` of a domain that was never registered.
    NoSuchDomain(String),
    /// `rm-cell` of a cell not currently grouped under the domain.
    NoSuchCell(String),
}

/// The naming-only `pillar domain` engine: a friendly name -> `{listeners,
/// cells}` map. Deliberately holds no event log, no WoT authority, and no
/// coordination lease — per `docs/cli-surface.md` § "Naming: `pillar
/// domain`", a domain NEVER signs/grants/coordinates.
#[derive(Clone, Debug, Default)]
pub struct DomainCli {
    domains: BTreeMap<String, DomainRecord>,
}

impl DomainCli {
    /// A registry with no domains.
    #[must_use]
    pub fn new() -> Self {
        DomainCli::default()
    }

    /// `pillar domain list` — every registered domain name, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<&str> {
        self.domains.keys().map(String::as_str).collect()
    }

    /// `pillar domain show <domain>` — the record for `domain`.
    ///
    /// # Errors
    /// [`DomainError::NoSuchDomain`] if unregistered.
    pub fn show(&self, domain: &str) -> Result<&DomainRecord, DomainError> {
        self.domains
            .get(domain)
            .ok_or_else(|| DomainError::NoSuchDomain(domain.to_owned()))
    }

    /// `pillar domain new <domain> [--listener <addr>...]` — register a fresh
    /// naming root with no cells grouped under it yet.
    ///
    /// # Errors
    /// [`DomainError::AlreadyExists`] if `domain` is already registered.
    pub fn new_domain(
        &mut self,
        domain: impl Into<String>,
        listeners: Vec<String>,
    ) -> Result<(), DomainError> {
        let domain = domain.into();
        if self.domains.contains_key(&domain) {
            return Err(DomainError::AlreadyExists(domain));
        }
        self.domains.insert(
            domain,
            DomainRecord {
                listeners,
                cells: BTreeSet::new(),
            },
        );
        Ok(())
    }

    /// `pillar domain add-cell <domain> <cell>` — group `cell` under
    /// `domain`'s naming root. A pure naming-grouping change: it never touches
    /// cell membership, keys, or authority — see the module doc.
    ///
    /// # Errors
    /// [`DomainError::NoSuchDomain`] if `domain` is unregistered.
    pub fn add_cell(&mut self, domain: &str, cell: impl Into<String>) -> Result<(), DomainError> {
        let record = self
            .domains
            .get_mut(domain)
            .ok_or_else(|| DomainError::NoSuchDomain(domain.to_owned()))?;
        record.cells.insert(cell.into());
        Ok(())
    }

    /// `pillar domain rm-cell <domain> <cell>` — ungroup `cell` from
    /// `domain`'s naming root. Naming-only, same as [`Self::add_cell`].
    ///
    /// # Errors
    /// [`DomainError::NoSuchDomain`] if `domain` is unregistered;
    /// [`DomainError::NoSuchCell`] if `cell` was not grouped under it.
    pub fn rm_cell(&mut self, domain: &str, cell: &str) -> Result<(), DomainError> {
        let record = self
            .domains
            .get_mut(domain)
            .ok_or_else(|| DomainError::NoSuchDomain(domain.to_owned()))?;
        if !record.cells.remove(cell) {
            return Err(DomainError::NoSuchCell(cell.to_owned()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `pillar cell` — status / members / health / rotate-key, over pillar_cells.
// ---------------------------------------------------------------------------

/// One-screen `pillar cell status` summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellStatus {
    /// Current group-key epoch.
    pub key_epoch: u64,
    /// Number of current members.
    pub member_count: usize,
    /// Whether a key-rotation fence is currently open.
    pub rotating: bool,
}

/// `pillar cell health`: a coarse readiness signal derived from the same
/// state `status`/`members` report — never a second, divergent source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellHealth {
    /// At least one member, no rotation fence open.
    Healthy,
    /// A rotation fence is open — writes are fenced until `end_rotate`.
    Rotating,
    /// Zero members: nothing has been admitted yet.
    Empty,
}

/// Why a `pillar cell` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellCliError {
    /// The underlying [`pillar_cells::Cell`] refused the operation (fenced by
    /// a rotation, or a membership precondition).
    Cell(pillar_cells::CellError),
}

impl From<pillar_cells::CellError> for CellCliError {
    fn from(e: pillar_cells::CellError) -> Self {
        CellCliError::Cell(e)
    }
}

/// The `pillar cell` engine: one [`Cell`] plus the locally-tracked member
/// roster `pillar cell members` renders (`Cell` exposes only `is_member`, a
/// per-node membership check; the roster is maintained in lock-step with
/// every `admit`/`leave` this type performs so it is never a second source of
/// truth, only a listable projection of the same admits/leaves).
#[derive(Debug, Default)]
pub struct CellCli {
    cell: Cell,
    roster: BTreeSet<NodeId>,
}

impl CellCli {
    /// A fresh, empty cell.
    #[must_use]
    pub fn new() -> Self {
        CellCli {
            cell: Cell::new(),
            roster: BTreeSet::new(),
        }
    }

    /// Admit a member (mirrors [`Cell::admit`], keeping the roster in sync).
    ///
    /// # Errors
    /// As [`Cell::admit`].
    pub fn admit(&mut self, node: NodeId) -> Result<(), CellCliError> {
        self.cell.admit(node.clone())?;
        self.roster.insert(node);
        Ok(())
    }

    /// Remove a member (mirrors [`Cell::leave`], keeping the roster in sync).
    ///
    /// # Errors
    /// As [`Cell::leave`].
    pub fn leave(&mut self, node: &NodeId) -> Result<(), CellCliError> {
        self.cell.leave(node)?;
        self.roster.remove(node);
        Ok(())
    }

    /// `pillar cell status` — a VIEW over the cell's key-epoch/rotation state.
    #[must_use]
    pub fn status(&self) -> CellStatus {
        CellStatus {
            key_epoch: self.cell.key_epoch(),
            member_count: self.roster.len(),
            rotating: self.cell.is_rotating(),
        }
    }

    /// `pillar cell members` — the current member roster, sorted.
    #[must_use]
    pub fn members(&self) -> Vec<&NodeId> {
        self.roster.iter().collect()
    }

    /// `pillar cell health` — derived from [`Self::status`] alone.
    #[must_use]
    pub fn health(&self) -> CellHealth {
        let status = self.status();
        if status.rotating {
            CellHealth::Rotating
        } else if status.member_count == 0 {
            CellHealth::Empty
        } else {
            CellHealth::Healthy
        }
    }

    /// `pillar cell rotate-key` — a full rotation cycle (`begin_rotate` then
    /// `end_rotate`), returning the new key epoch. Refused (leaving state
    /// unchanged) if a rotation is already in flight.
    ///
    /// # Errors
    /// [`CellCliError::Cell`] if a rotation fence is already open.
    pub fn rotate_key(&mut self) -> Result<u64, CellCliError> {
        self.cell.begin_rotate()?;
        self.cell.end_rotate()?;
        Ok(self.cell.key_epoch())
    }
}

// ---------------------------------------------------------------------------
// `pillar space` — CRUD over sub-partitions within a cell.
// ---------------------------------------------------------------------------

/// A `space`: a named sub-partition within a cell, carrying only operator
/// labels (the confidentiality/authority boundary is the cell's job, per
/// `docs/cli-surface.md`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Space {
    /// Operator labels attached to this space.
    pub labels: BTreeMap<String, String>,
}

/// Why a `pillar space` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpaceError {
    /// `create` of a space name already in use.
    AlreadyExists(String),
    /// `get`/`update`/`delete` of a space that does not exist.
    NoSuchSpace(String),
}

/// The `pillar space` CRUD engine: a name -> [`Space`] map, scoped to one
/// cell (the caller supplies the cell context; this type is per-cell).
#[derive(Clone, Debug, Default)]
pub struct SpaceCli {
    spaces: BTreeMap<String, Space>,
}

impl SpaceCli {
    /// An empty space registry.
    #[must_use]
    pub fn new() -> Self {
        SpaceCli::default()
    }

    /// `pillar get space` (list) — every space name, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<&str> {
        self.spaces.keys().map(String::as_str).collect()
    }

    /// `pillar get space/<name>` / `pillar describe space/<name>`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Space> {
        self.spaces.get(name)
    }

    /// `pillar create space/<name>`.
    ///
    /// # Errors
    /// [`SpaceError::AlreadyExists`] if `name` is already in use.
    pub fn create(
        &mut self,
        name: impl Into<String>,
        labels: BTreeMap<String, String>,
    ) -> Result<(), SpaceError> {
        let name = name.into();
        if self.spaces.contains_key(&name) {
            return Err(SpaceError::AlreadyExists(name));
        }
        self.spaces.insert(name, Space { labels });
        Ok(())
    }

    /// `pillar label space/<name> k=v` — merge labels into an existing space.
    ///
    /// # Errors
    /// [`SpaceError::NoSuchSpace`] if `name` does not exist.
    pub fn update_labels(
        &mut self,
        name: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), SpaceError> {
        let space = self
            .spaces
            .get_mut(name)
            .ok_or_else(|| SpaceError::NoSuchSpace(name.to_owned()))?;
        space.labels.extend(labels);
        Ok(())
    }

    /// `pillar delete space/<name>`.
    ///
    /// # Errors
    /// [`SpaceError::NoSuchSpace`] if `name` does not exist.
    pub fn delete(&mut self, name: &str) -> Result<(), SpaceError> {
        self.spaces
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| SpaceError::NoSuchSpace(name.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// `pillar node` — list / describe / cordon / uncordon / drain / taint.
// ---------------------------------------------------------------------------

/// A materialized node record: cluster-scoped (no cell/space), admitted via
/// the bootstrap handshake ([`crate::bootstrap`]) and thereafter managed by
/// this family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    /// Operator labels.
    pub labels: BTreeMap<String, String>,
    /// Taints (`key=value:effect`-style tokens): repel scheduling of anything
    /// that does not tolerate them.
    pub taints: Vec<String>,
    /// Whether the node currently accepts new scheduling. `cordon` sets this
    /// `false`; `uncordon` sets it back `true`. Independent of `draining`.
    pub schedulable: bool,
    /// Whether a `drain` is in effect (evacuating existing workload; distinct
    /// from `schedulable`, which only gates NEW placement).
    pub draining: bool,
}

impl NodeRecord {
    fn new() -> Self {
        NodeRecord {
            labels: BTreeMap::new(),
            taints: Vec::new(),
            schedulable: true,
            draining: false,
        }
    }
}

/// Why a `pillar node` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeError {
    /// The named node is not in the cluster-scoped registry.
    NoSuchNode(String),
    /// `describe`/`cordon`/etc. of a node id already registered, on a `new`
    /// (i.e. duplicate admission).
    AlreadyExists(String),
}

/// The cluster-scoped `pillar node` registry.
#[derive(Clone, Debug, Default)]
pub struct NodeCli {
    nodes: BTreeMap<String, NodeRecord>,
}

impl NodeCli {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        NodeCli::default()
    }

    /// Admit a node into the registry (models the bootstrap handshake having
    /// already approved it — see `pillar request node-approve`). Fresh nodes
    /// are schedulable, untainted, not draining.
    ///
    /// # Errors
    /// [`NodeError::AlreadyExists`] if `id` is already registered.
    pub fn admit(&mut self, id: impl Into<String>) -> Result<(), NodeError> {
        let id = id.into();
        if self.nodes.contains_key(&id) {
            return Err(NodeError::AlreadyExists(id));
        }
        self.nodes.insert(id, NodeRecord::new());
        Ok(())
    }

    /// `pillar get node` (list) — every node id, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<&str> {
        self.nodes.keys().map(String::as_str).collect()
    }

    /// `pillar describe node/<id>`.
    #[must_use]
    pub fn describe(&self, id: &str) -> Option<&NodeRecord> {
        self.nodes.get(id)
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut NodeRecord, NodeError> {
        self.nodes
            .get_mut(id)
            .ok_or_else(|| NodeError::NoSuchNode(id.to_owned()))
    }

    /// `pillar node cordon <id>` (a `delete`-family act in the surface doc's
    /// mapping table): mark the node unschedulable for NEW workload. Existing
    /// workload is untouched — that is `drain`'s job.
    ///
    /// # Errors
    /// [`NodeError::NoSuchNode`] if `id` is unregistered.
    pub fn cordon(&mut self, id: &str) -> Result<(), NodeError> {
        self.get_mut(id)?.schedulable = false;
        Ok(())
    }

    /// `pillar node uncordon <id>`: the exact inverse of `cordon` — mark the
    /// node schedulable again. Idempotent.
    ///
    /// # Errors
    /// [`NodeError::NoSuchNode`] if `id` is unregistered.
    pub fn uncordon(&mut self, id: &str) -> Result<(), NodeError> {
        self.get_mut(id)?.schedulable = true;
        Ok(())
    }

    /// `pillar node drain <id>`: cordon (if not already) and mark draining —
    /// evacuating existing workload is the caller's/controller's job; this
    /// records the intent.
    ///
    /// # Errors
    /// [`NodeError::NoSuchNode`] if `id` is unregistered.
    pub fn drain(&mut self, id: &str) -> Result<(), NodeError> {
        let node = self.get_mut(id)?;
        node.schedulable = false;
        node.draining = true;
        Ok(())
    }

    /// `pillar node taint <id> <taint>`: add a taint token.
    ///
    /// # Errors
    /// [`NodeError::NoSuchNode`] if `id` is unregistered.
    pub fn taint(&mut self, id: &str, taint: impl Into<String>) -> Result<(), NodeError> {
        self.get_mut(id)?.taints.push(taint.into());
        Ok(())
    }

    /// Remove a taint token exactly matching `taint`, if present.
    ///
    /// # Errors
    /// [`NodeError::NoSuchNode`] if `id` is unregistered.
    pub fn untaint(&mut self, id: &str, taint: &str) -> Result<(), NodeError> {
        let node = self.get_mut(id)?;
        node.taints.retain(|t| t != taint);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `pillar peer` — ls / dial / ping / addrs (read-only libp2p peer view, plus
// dial/ping session-open probes).
// ---------------------------------------------------------------------------

/// A discovered libp2p peer's known multiaddrs. A peer becomes a `node` only
/// via the bootstrap admission handshake (`docs/cli-surface.md`); this family
/// never admits, it only reads (and, for `dial`/`ping`, probes) the libp2p
/// peer view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerRecord {
    /// Known multiaddrs for this peer.
    pub addrs: Vec<String>,
    /// Whether the peer is currently reachable (last known liveness, as
    /// observed/injected by the caller — this engine never dials a real
    /// socket, it models the decision path a real dial/ping would drive).
    pub reachable: bool,
}

/// Why a `pillar peer` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerError {
    /// `describe`/`dial`/`ping`/`addrs` of an unknown peer id.
    NoSuchPeer(String),
}

/// The read-only `pillar peer` view: cluster-scoped, sourced from whatever
/// discovery the running node performed (injected here via [`Self::observe`]
/// rather than re-implemented — this type is the CLI-facing projection, not a
/// second discovery mechanism).
#[derive(Clone, Debug, Default)]
pub struct PeerCli {
    peers: BTreeMap<String, PeerRecord>,
}

impl PeerCli {
    /// An empty peer view.
    #[must_use]
    pub fn new() -> Self {
        PeerCli::default()
    }

    /// Record (or refresh) discovery for `peer_id` — models libp2p having
    /// observed this peer at these addrs, reachable or not.
    pub fn observe(&mut self, peer_id: impl Into<String>, addrs: Vec<String>, reachable: bool) {
        self.peers
            .insert(peer_id.into(), PeerRecord { addrs, reachable });
    }

    /// `pillar peer ls` — every known peer id, sorted.
    #[must_use]
    pub fn ls(&self) -> Vec<&str> {
        self.peers.keys().map(String::as_str).collect()
    }

    /// `pillar peer addrs <id>` — the peer's known multiaddrs.
    ///
    /// # Errors
    /// [`PeerError::NoSuchPeer`] if `id` is unknown.
    pub fn addrs(&self, id: &str) -> Result<&[String], PeerError> {
        self.peers
            .get(id)
            .map(|p| p.addrs.as_slice())
            .ok_or_else(|| PeerError::NoSuchPeer(id.to_owned()))
    }

    /// `pillar peer dial <id>` — attempt to open a transport connection.
    /// Returns whether the peer is currently reachable, per the last
    /// [`Self::observe`]. A view over discovery state, not a new liveness
    /// mechanism.
    ///
    /// # Errors
    /// [`PeerError::NoSuchPeer`] if `id` is unknown.
    pub fn dial(&self, id: &str) -> Result<bool, PeerError> {
        self.peers
            .get(id)
            .map(|p| p.reachable)
            .ok_or_else(|| PeerError::NoSuchPeer(id.to_owned()))
    }

    /// `pillar peer ping <id>` — same reachability probe as `dial`, the
    /// verb kubectl/libp2p operators expect for a liveness check.
    ///
    /// # Errors
    /// [`PeerError::NoSuchPeer`] if `id` is unknown.
    pub fn ping(&self, id: &str) -> Result<bool, PeerError> {
        self.dial(id)
    }
}

// ---------------------------------------------------------------------------
// `pillar lease` — list / show / acquire / release / status, over
// pillar_coordination::LeaseRegister.
// ---------------------------------------------------------------------------

/// `pillar lease show <epoch>` / `pillar lease status <epoch>` projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseStatus {
    /// The epoch queried.
    pub epoch: u64,
    /// The current holder, if any.
    pub holder: Option<NodeId>,
}

/// The `pillar lease` engine: a thin, unit-tested CLI wrapper over the
/// proven [`LeaseRegister`] (`specs/CoordinationCore.tla`). `list`/`show`/
/// `status` are VIEWS (`&self`, cannot mutate); `acquire`/`release` are the
/// only mutators, and are exactly [`LeaseRegister::try_acquire`] /
/// [`LeaseRegister::release`] — no private decision path.
#[derive(Clone, Debug)]
pub struct LeaseCli {
    register: LeaseRegister,
    /// Every epoch ever acquired here, so `list` can enumerate — the
    /// register itself only remembers CURRENT holders, not history, and
    /// `list` needs the known epoch set to iterate `status` over.
    known_epochs: BTreeSet<u64>,
}

impl LeaseCli {
    /// A lease engine over a cluster of `cluster_size` voting nodes.
    #[must_use]
    pub fn new(cluster_size: usize) -> Self {
        LeaseCli {
            register: LeaseRegister::new(cluster_size),
            known_epochs: BTreeSet::new(),
        }
    }

    /// Record a voter's grant (pass-through to
    /// [`LeaseRegister::grant`]) — the caller drives quorum formation exactly
    /// as `pillar-coordination`'s own tests do; this CLI layer adds no
    /// private grant path.
    ///
    /// # Errors
    /// As [`LeaseRegister::grant`].
    pub fn grant(
        &mut self,
        voter: NodeId,
        candidate: NodeId,
        epoch: Epoch,
    ) -> Result<(), pillar_coordination::GrantError> {
        self.known_epochs.insert(epoch.0);
        self.register.grant(voter, candidate, epoch)
    }

    /// `pillar lease acquire <epoch>` for `candidate` — exactly
    /// [`LeaseRegister::try_acquire`].
    pub fn acquire(&mut self, candidate: &NodeId, epoch: Epoch) -> bool {
        self.known_epochs.insert(epoch.0);
        self.register.try_acquire(candidate, epoch)
    }

    /// `pillar lease release <epoch>` for `holder` — exactly
    /// [`LeaseRegister::release`]: the round-trip counterpart of `acquire`.
    pub fn release(&mut self, holder: &NodeId, epoch: Epoch) -> bool {
        self.register.release(holder, epoch)
    }

    /// `pillar lease show <epoch>` / `pillar lease status <epoch>` — a VIEW.
    #[must_use]
    pub fn status(&self, epoch: Epoch) -> LeaseStatus {
        LeaseStatus {
            epoch: epoch.0,
            holder: self.register.holder(epoch).cloned(),
        }
    }

    /// `pillar lease list` — every epoch this engine has seen a
    /// grant/acquire/release for, with its current status. A VIEW.
    #[must_use]
    pub fn list(&self) -> Vec<LeaseStatus> {
        self.known_epochs
            .iter()
            .map(|&e| self.status(Epoch(e)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// `pillar request` — ls / approve / reject over the join-request queue.
// ---------------------------------------------------------------------------

/// The `pillar request` engine: a thin CLI wrapper over the proven
/// [`BootstrapRequestQueue`] (`specs/BootstrapRequest.tla`) — no private
/// approval path. `ls`/`describe` are views; `approve`/`reject` are exactly
/// [`BootstrapRequestQueue::approve`]/[`BootstrapRequestQueue::reject`].
#[derive(Debug)]
pub struct RequestCli {
    queue: BootstrapRequestQueue,
}

impl RequestCli {
    /// A request queue for `cell`, decidable by `members`.
    #[must_use]
    pub fn new(cell: NodeId, members: impl IntoIterator<Item = NodeId>) -> Self {
        RequestCli {
            queue: BootstrapRequestQueue::new(cell, members),
        }
    }

    /// Submit a node join request (models a fresh node's bootstrap submit).
    pub fn submit_node(
        &mut self,
        subject: NodeId,
        identity: NodeIdentity,
        custody: CustodyKind,
        labels: Vec<String>,
    ) -> BootstrapRequestId {
        self.queue.submit_node(subject, identity, custody, labels)
    }

    /// Submit a user join request.
    pub fn submit_user(
        &mut self,
        subject: NodeId,
        custody: CustodyKind,
        labels: Vec<String>,
    ) -> BootstrapRequestId {
        self.queue.submit_user(subject, custody, labels)
    }

    /// `pillar request ls` — every pending request. A VIEW.
    #[must_use]
    pub fn ls(&self) -> Vec<&BootstrapRequest> {
        self.queue.pending()
    }

    /// `pillar request describe <id>` — the request's full record, decided or
    /// not. A VIEW.
    #[must_use]
    pub fn describe(&self, id: BootstrapRequestId) -> Option<&BootstrapRequest> {
        self.queue.all().iter().find(|r| r.id() == id)
    }

    /// `pillar request approve <id>` (the `node-approve` case, when the
    /// request is a NODE request, returns the sealed-cell-key CID; for a USER
    /// request it returns `None` — the offer was escrowed instead). Exactly
    /// [`BootstrapRequestQueue::approve`].
    ///
    /// # Errors
    /// As [`BootstrapRequestQueue::approve`].
    pub fn approve(
        &mut self,
        id: BootstrapRequestId,
        member: &NodeId,
    ) -> Result<Option<SealedCellKey>, RequestError> {
        self.queue.approve(id, member)
    }

    /// `pillar request reject <id>` — refuses; delivers no key material.
    ///
    /// # Errors
    /// As [`BootstrapRequestQueue::reject`].
    pub fn reject(&mut self, id: BootstrapRequestId, member: &NodeId) -> Result<(), RequestError> {
        self.queue.reject(id, member)
    }

    /// Shared access to the underlying queue, for a caller that needs the
    /// full [`BootstrapRequestQueue`] API (e.g. `sealed_cell_key`,
    /// `is_escrowed`).
    #[must_use]
    pub fn queue(&self) -> &BootstrapRequestQueue {
        &self.queue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_eventlog::EventLog;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    // ---- domain: naming-only, no authority event ----

    /// `domain add-cell`/`rm-cell` change the naming grouping and emit NO
    /// authority event — a PROPERTY, checked here by driving both operations
    /// against a real [`EventLog`] the domain engine never even holds a
    /// reference to, then asserting the log is untouched. [`DomainCli`] has
    /// no field capable of appending, so this is belt-and-suspenders over the
    /// type-level guarantee the module doc describes.
    #[test]
    fn domain_add_rm_cell_change_grouping_and_emit_no_authority_event() {
        let log = EventLog::new();
        let before_len = log.len();

        let mut domains = DomainCli::new();
        domains.new_domain("example.com", vec!["10.0.0.1:8080".into()]).unwrap();
        assert_eq!(domains.show("example.com").unwrap().cells, BTreeSet::new());

        domains.add_cell("example.com", "cellA").unwrap();
        assert!(domains.show("example.com").unwrap().cells.contains("cellA"));

        domains.add_cell("example.com", "cellB").unwrap();
        assert_eq!(domains.show("example.com").unwrap().cells.len(), 2);

        domains.rm_cell("example.com", "cellA").unwrap();
        let cells = &domains.show("example.com").unwrap().cells;
        assert!(!cells.contains("cellA"));
        assert!(cells.contains("cellB"));

        // No authority event was ever appended anywhere the domain engine
        // could have reached — the log is byte-for-byte unchanged.
        assert_eq!(log.len(), before_len, "domain commands sign nothing");
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn domain_rm_cell_of_ungrouped_cell_is_refused() {
        let mut domains = DomainCli::new();
        domains.new_domain("example.com", vec![]).unwrap();
        assert_eq!(
            domains.rm_cell("example.com", "ghost"),
            Err(DomainError::NoSuchCell("ghost".into()))
        );
    }

    #[test]
    fn domain_new_is_refused_on_a_duplicate_name() {
        let mut domains = DomainCli::new();
        domains.new_domain("example.com", vec![]).unwrap();
        assert_eq!(
            domains.new_domain("example.com", vec![]),
            Err(DomainError::AlreadyExists("example.com".into()))
        );
    }

    // ---- cell ----

    #[test]
    fn cell_status_members_health_rotate_key() {
        let mut cell = CellCli::new();
        assert_eq!(cell.health(), CellHealth::Empty);

        cell.admit(n("alice")).unwrap();
        cell.admit(n("bob")).unwrap();
        assert_eq!(cell.members(), vec![&n("alice"), &n("bob")]);
        assert_eq!(cell.status().member_count, 2);
        assert_eq!(cell.health(), CellHealth::Healthy);

        let epoch = cell.rotate_key().unwrap();
        assert_eq!(epoch, 1, "rotate-key bumps the epoch by exactly one");
        assert_eq!(cell.status().key_epoch, 1);
        assert!(!cell.status().rotating, "rotate-key completes the fence");

        cell.leave(&n("bob")).unwrap();
        assert_eq!(cell.members(), vec![&n("alice")]);
    }

    // ---- space ----

    #[test]
    fn space_crud_round_trips() {
        let mut spaces = SpaceCli::new();
        let mut labels = BTreeMap::new();
        labels.insert("tier".to_owned(), "edge".to_owned());
        spaces.create("web", labels.clone()).unwrap();
        assert_eq!(spaces.list(), vec!["web"]);
        assert_eq!(spaces.get("web").unwrap().labels, labels);

        assert_eq!(
            spaces.create("web", BTreeMap::new()),
            Err(SpaceError::AlreadyExists("web".into()))
        );

        let mut more = BTreeMap::new();
        more.insert("env".to_owned(), "prod".to_owned());
        spaces.update_labels("web", more).unwrap();
        assert_eq!(spaces.get("web").unwrap().labels.len(), 2);

        spaces.delete("web").unwrap();
        assert!(spaces.get("web").is_none());
        assert_eq!(
            spaces.delete("web"),
            Err(SpaceError::NoSuchSpace("web".into()))
        );
    }

    // ---- node: cordon/uncordon toggles schedulability ----

    #[test]
    fn node_cordon_uncordon_toggles_schedulability() {
        let mut nodes = NodeCli::new();
        nodes.admit("node1").unwrap();
        assert!(nodes.describe("node1").unwrap().schedulable);

        nodes.cordon("node1").unwrap();
        assert!(!nodes.describe("node1").unwrap().schedulable);

        nodes.uncordon("node1").unwrap();
        assert!(nodes.describe("node1").unwrap().schedulable);

        // drain cordons AND marks draining.
        nodes.drain("node1").unwrap();
        let rec = nodes.describe("node1").unwrap();
        assert!(!rec.schedulable);
        assert!(rec.draining);

        // Unknown node is refused for every mutator.
        assert_eq!(
            nodes.cordon("ghost"),
            Err(NodeError::NoSuchNode("ghost".into()))
        );
    }

    #[test]
    fn node_taint_untaint() {
        let mut nodes = NodeCli::new();
        nodes.admit("node1").unwrap();
        nodes.taint("node1", "dedicated=gpu:NoSchedule").unwrap();
        assert_eq!(nodes.describe("node1").unwrap().taints.len(), 1);
        nodes.untaint("node1", "dedicated=gpu:NoSchedule").unwrap();
        assert!(nodes.describe("node1").unwrap().taints.is_empty());
    }

    // ---- peer ----

    #[test]
    fn peer_ls_dial_ping_addrs() {
        let mut peers = PeerCli::new();
        peers.observe("peerA", vec!["/ip4/192.0.2.1/tcp/4001".into()], true);
        peers.observe("peerB", vec![], false);

        assert_eq!(peers.ls(), vec!["peerA", "peerB"]);
        assert_eq!(peers.addrs("peerA").unwrap().len(), 1);
        assert!(peers.dial("peerA").unwrap());
        assert!(peers.ping("peerA").unwrap());
        assert!(!peers.dial("peerB").unwrap());
        assert_eq!(peers.dial("ghost"), Err(PeerError::NoSuchPeer("ghost".into())));
    }

    // ---- lease: acquire/release round-trips pillar-coordination ----

    #[test]
    fn lease_acquire_release_round_trips_pillar_coordination() {
        let mut leases = LeaseCli::new(3);
        leases.grant(n("n1"), n("n1"), Epoch(1)).unwrap();
        leases.grant(n("n2"), n("n1"), Epoch(1)).unwrap();

        assert!(leases.acquire(&n("n1"), Epoch(1)));
        assert_eq!(leases.status(Epoch(1)).holder, Some(n("n1")));

        assert!(leases.release(&n("n1"), Epoch(1)));
        assert_eq!(leases.status(Epoch(1)).holder, None);

        // Round-trips: the same candidate can re-acquire after release.
        assert!(leases.acquire(&n("n1"), Epoch(1)));
        assert_eq!(leases.status(Epoch(1)).holder, Some(n("n1")));

        // list() enumerates every epoch this engine has seen.
        let statuses = leases.list();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].epoch, 1);
    }

    #[test]
    fn lease_release_by_non_holder_is_refused_as_a_no_op() {
        let mut leases = LeaseCli::new(3);
        leases.grant(n("n1"), n("n1"), Epoch(1)).unwrap();
        leases.grant(n("n2"), n("n1"), Epoch(1)).unwrap();
        assert!(leases.acquire(&n("n1"), Epoch(1)));

        assert!(!leases.release(&n("n2"), Epoch(1)));
        assert_eq!(leases.status(Epoch(1)).holder, Some(n("n1")));
    }

    // ---- request: approve returns sealed-cell-key CID, reject refuses ----

    fn node_identity() -> NodeIdentity {
        NodeIdentity::new("12D3KooWpeer")
    }

    #[test]
    fn request_approve_node_returns_sealed_cell_key_cid() {
        let mut requests = RequestCli::new(n("cellA"), [n("m1")]);
        let id = requests.submit_node(
            n("newnode"),
            node_identity(),
            CustodyKind::Password,
            vec![],
        );
        assert_eq!(requests.ls().len(), 1);

        let sealed = requests.approve(id, &n("m1")).unwrap();
        let sealed = sealed.expect("a node approval seals the cell key");
        assert_eq!(sealed.sealed_to, n("newnode"));
        assert_eq!(sealed.sealed_by, n("m1"));
        assert!(sealed.cid.starts_with("bafy-"), "the CID is content-addressed");

        // No longer pending, and it is discoverable via describe.
        assert!(requests.ls().is_empty());
        assert!(requests.describe(id).is_some());
    }

    #[test]
    fn request_reject_delivers_no_key_material() {
        let mut requests = RequestCli::new(n("cellA"), [n("m1")]);
        let id = requests.submit_node(
            n("newnode"),
            node_identity(),
            CustodyKind::Password,
            vec![],
        );
        requests.reject(id, &n("m1")).unwrap();
        assert_eq!(requests.queue().sealed_cell_key(id), None);
        assert!(requests.ls().is_empty());
    }

    #[test]
    fn request_approve_reject_refuse_an_unauthorized_member() {
        let mut requests = RequestCli::new(n("cellA"), [n("m1")]);
        let id = requests.submit_node(
            n("newnode"),
            node_identity(),
            CustodyKind::Password,
            vec![],
        );
        assert_eq!(
            requests.approve(id, &n("mallory")),
            Err(RequestError::NotAuthorizedMember)
        );
        assert_eq!(
            requests.reject(id, &n("mallory")),
            Err(RequestError::NotAuthorizedMember)
        );
        // Still pending: neither refusal decided it.
        assert_eq!(requests.ls().len(), 1);
    }
}
