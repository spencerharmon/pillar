//! The `pillar` session/context family and the kubectl-parity resource plane.
//!
//! This module implements the CORE of the pillar CLI specified in
//! [`docs/cli-surface.md`](../../../docs/cli-surface.md): the entry points that
//! establish *who you are* (`login`/`logout`/`whoami`/`status`) and *what you
//! are pointed at* (`use`/`ctx`), and the polymorphic resource plane whose verbs
//! (`get`/`describe`/`apply`/`create`/`delete`/`patch`/`label`/`annotate`/
//! `explain`/`diff`/`scale`/…) work over EVERY kind — workload and identity
//! objects alike.
//!
//! The load-bearing invariant is the **views-vs-acts split** the surface doc
//! calls out (§1): a [`Verb`] is exactly one of two kinds, and the kind is a
//! platform-level property, not a per-command convention.
//!
//! - A **view** ([`Verb::kind`] == [`VerbKind::View`]) READS materialized state
//!   and SIGNS NOTHING: it never appends to the event log. `get`, `describe`,
//!   `explain`, `diff`, `watch`, `whoami`, `status` are views.
//! - An **act** ([`VerbKind::Act`]) EMITS exactly one signed, WoT-authorized
//!   event through the SAME [`crate::Platform`] decider path a manifest `apply`
//!   rides — and only if the decider ALLOWs. An unauthorized act appends
//!   nothing. `apply`, `create`, `edit`, `delete`, `patch`, `label`,
//!   `annotate`, `scale`, `autoscale` are acts.
//!
//! `diff` runs the decider (to compute the ALLOW/DENY and the event that WOULD
//! be appended) and signs nothing — the read-only presentation analogue of
//! `--dry-run`.
//!
//! Everything here is pure and in-memory (no network, no filesystem), so the
//! views-vs-acts contract, the decider authorization, the polymorphism over any
//! kind, and the `-l`/`-L` selector/column handling are all exercised by
//! ordinary unit tests.

use std::collections::BTreeMap;
use std::fmt;

use pillar_bootstrap::token::{LoginTokenError, TokenIssuer, TokenStore};
use pillar_core::NodeId;
use pillar_manifest::{Capability as ManifestCapability, Crd, Metadata, Value};

use crate::{Applied, ApplyError, Platform, Previewed};

// ---------------------------------------------------------------------------
// Session / context family (§3.1)
// ---------------------------------------------------------------------------

/// A saved `{domain, token-ref, cell}` triple — the pillar analogue of a
/// kubeconfig context (surface doc §3.1 / the kubectl→pillar mapping).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// The naming root this context reads/acts against (`PILLAR_DOMAIN`).
    pub domain: String,
    /// The bearer token minted by `pillar login` (`PILLAR_TOKEN`), if any.
    pub token: Option<String>,
    /// The active cell (the `-n` namespace analogue), if pinned.
    pub cell: Option<String>,
}

impl Context {
    /// A context pointed only at a domain, with no token or cell yet.
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Context {
            domain: domain.into(),
            token: None,
            cell: None,
        }
    }
}

/// The local CLI configuration written under `~/.config/pillar/context`: a set
/// of named [`Context`]s plus which one is current. Held in memory here; the
/// `main` shell is responsible for persistence. `use` / `ctx set|unset` are the
/// **local-only** commands that touch this and neither the node nor a signature
/// (surface doc §1 classification: local).
#[derive(Clone, Debug, Default)]
pub struct ContextStore {
    contexts: BTreeMap<String, Context>,
    current: Option<String>,
}

impl ContextStore {
    /// An empty store with no contexts.
    #[must_use]
    pub fn new() -> Self {
        ContextStore::default()
    }

    /// `pillar ctx add <name>` (local): register or overwrite a named context.
    pub fn add(&mut self, name: impl Into<String>, ctx: Context) {
        let name = name.into();
        if self.current.is_none() {
            self.current = Some(name.clone());
        }
        self.contexts.insert(name, ctx);
    }

    /// `pillar ctx rm <name>` (local): remove a named context. Clears `current`
    /// if it was the removed one. Returns whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        let existed = self.contexts.remove(name).is_some();
        if self.current.as_deref() == Some(name) {
            self.current = self.contexts.keys().next().cloned();
        }
        existed
    }

    /// `pillar ctx rename <old> <new>` (local). Returns whether `old` existed.
    pub fn rename(&mut self, old: &str, new: impl Into<String>) -> bool {
        let Some(ctx) = self.contexts.remove(old) else {
            return false;
        };
        let new = new.into();
        if self.current.as_deref() == Some(old) {
            self.current = Some(new.clone());
        }
        self.contexts.insert(new, ctx);
        true
    }

    /// `pillar use <name>` / `pillar ctx <name>` (local): select the current
    /// context. Returns whether the name is known.
    pub fn use_context(&mut self, name: &str) -> bool {
        if self.contexts.contains_key(name) {
            self.current = Some(name.to_owned());
            true
        } else {
            false
        }
    }

    /// `pillar ctx current` (view): the current context's name, if any.
    #[must_use]
    pub fn current_name(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// `pillar ctx show` / `ctx current` (view): the current [`Context`].
    #[must_use]
    pub fn current(&self) -> Option<&Context> {
        self.current.as_ref().and_then(|n| self.contexts.get(n))
    }

    /// A named context (view).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Context> {
        self.contexts.get(name)
    }

    /// `pillar ctx ls` (view): the context names, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<&str> {
        self.contexts.keys().map(String::as_str).collect()
    }

    /// `pillar use cell/<cell>` (local): pin the active cell on the current
    /// context. Returns whether there was a current context to set it on.
    pub fn use_cell(&mut self, cell: impl Into<String>) -> bool {
        let Some(name) = self.current.clone() else {
            return false;
        };
        if let Some(ctx) = self.contexts.get_mut(&name) {
            ctx.cell = Some(cell.into());
            true
        } else {
            false
        }
    }
}

/// An authenticated CLI session: the token an act presents to the node, plus
/// the identity it resolves to. `login` MINTS one (surface doc §3.1: the only
/// command that mints `PILLAR_TOKEN`); `logout` CLEARS it. This is the CLI-side
/// object `whoami`/`status` read and every act carries.
#[derive(Clone, Debug)]
pub struct Session {
    store: TokenStore,
    user: String,
}

impl Session {
    /// `pillar login --domain <D> --user <id>` (ACT): forward the presented
    /// credential to the node-side custody [`TokenIssuer`] (the sole minter),
    /// mint a session token bound to `(user, domain)`, and hold it. This is the
    /// login handshake specified in the surface doc §3.1 — proven fail-closed in
    /// `specs/LoginToken.tla`.
    ///
    /// # Errors
    /// The [`LoginTokenError`] the issuer returns (bad credential, non-positive
    /// TTL) — an unauthenticated login mints NO token.
    pub fn login(
        issuer: &mut TokenIssuer,
        domain: &str,
        user: &str,
        credential: &str,
        now: u64,
        ttl: u64,
    ) -> Result<Self, LoginTokenError> {
        let token = issuer.forward_and_mint(user, domain, credential, now, ttl)?;
        Ok(Session {
            store: TokenStore::new(token.domain(), token.value()),
            user: token.user().to_owned(),
        })
    }

    /// The `export PILLAR_DOMAIN=… PILLAR_TOKEN=…` lines `pillar login` prints
    /// for the shell to `eval`.
    #[must_use]
    pub fn export_lines(&self) -> String {
        self.store.export_lines()
    }

    /// The bound domain (`PILLAR_DOMAIN`).
    #[must_use]
    pub fn domain(&self) -> &str {
        self.store.domain()
    }

    /// The bearer token value (`PILLAR_TOKEN`).
    #[must_use]
    pub fn token(&self) -> &str {
        self.store.token()
    }

    /// `pillar whoami` (VIEW): the authenticated identity resolved from the
    /// current token. Signs nothing.
    #[must_use]
    pub fn whoami(&self) -> &str {
        &self.user
    }

    /// `pillar status` (VIEW): confirm the held token still authenticates against
    /// the node at `now`. Signs nothing; returns the authenticated user or the
    /// fail-closed error.
    ///
    /// # Errors
    /// The [`LoginTokenError`] for an expired/revoked/unknown/wrong-domain token.
    pub fn status(&self, issuer: &TokenIssuer, now: u64) -> Result<String, LoginTokenError> {
        self.store.authenticate(issuer, now)
    }

    /// `pillar logout` (ACT): revoke this session's token on the node (the
    /// server call) so it can no longer authenticate. The local context clear is
    /// the caller's job (drop this `Session`).
    pub fn logout(self, issuer: &mut TokenIssuer) {
        issuer.revoke(self.store.token());
    }
}

// ---------------------------------------------------------------------------
// Resource plane (§3.2): the one small verb vocabulary, polymorphic over kinds
// ---------------------------------------------------------------------------

/// The two-fold rule (surface doc §1): every resource verb is exactly one of
/// these, and it is a platform-level property — a view can never sign, an act
/// always routes through the decider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerbKind {
    /// Reads materialized state and SIGNS NOTHING (never appends to the log).
    View,
    /// Emits exactly one signed, WoT-authorized event through the decider.
    Act,
}

/// A resource-plane verb, carrying its fixed [`VerbKind`]. The classification
/// here is the executable form of the surface doc §1 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    // views
    /// `get` — list/read materialized objects of a kind.
    Get,
    /// `describe` — full detail of one object including provenance.
    Describe,
    /// `explain` — document a kind's schema.
    Explain,
    /// `diff` — what an `apply` WOULD change; runs the decider, signs nothing.
    Diff,
    /// `watch` — stream materialized changes for a kind.
    Watch,
    // acts
    /// `apply` — declarative upsert of one object.
    Apply,
    /// `create` — imperative create; refuses if it already exists.
    Create,
    /// `edit` — apply an edited body as a patch act.
    Edit,
    /// `delete` — emit a delete/tombstone event.
    Delete,
    /// `patch` — a strategic/merge patch as one signed event.
    Patch,
    /// `label` — add/overwrite/remove operator labels.
    Label,
    /// `annotate` — same, for non-selecting annotations.
    Annotate,
    /// `scale` — emit a scale event.
    Scale,
    /// `autoscale` — install an autoscaler resource.
    Autoscale,
}

impl Verb {
    /// This verb's fixed kind (surface doc §1). Views sign nothing; acts route
    /// through the decider.
    #[must_use]
    pub fn kind(self) -> VerbKind {
        match self {
            Verb::Get | Verb::Describe | Verb::Explain | Verb::Diff | Verb::Watch => VerbKind::View,
            Verb::Apply
            | Verb::Create
            | Verb::Edit
            | Verb::Delete
            | Verb::Patch
            | Verb::Label
            | Verb::Annotate
            | Verb::Scale
            | Verb::Autoscale => VerbKind::Act,
        }
    }

    /// Whether this verb is a view (surface doc §1): reads state, signs nothing.
    #[must_use]
    pub fn is_view(self) -> bool {
        self.kind() == VerbKind::View
    }

    /// Whether this verb is an act: emits one signed, authorized event.
    #[must_use]
    pub fn is_act(self) -> bool {
        self.kind() == VerbKind::Act
    }
}

/// A URI-like resource address `kind/name` (surface doc §2), reused by every
/// verb across every kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The resource type (`cell`, `node`, `user`, `key`, `stream`, or any
    /// out-of-tree kind) — polymorphic; the plane treats every kind uniformly.
    pub kind: String,
    /// The object's name within its kind.
    pub name: String,
}

impl Address {
    /// An address from a kind and name.
    #[must_use]
    pub fn new(kind: impl Into<String>, name: impl Into<String>) -> Self {
        Address {
            kind: kind.into(),
            name: name.into(),
        }
    }

    /// Parse the `kind/name` grammar (surface doc §2). The optional `@<cell>`
    /// suffix and `<domain>::` prefix are stripped by the caller before this.
    ///
    /// # Errors
    /// [`ResourceError::BadAddress`] if the input is not `kind/name`.
    pub fn parse(s: &str) -> Result<Self, ResourceError> {
        let (kind, name) = s
            .split_once('/')
            .ok_or_else(|| ResourceError::BadAddress(s.to_owned()))?;
        if kind.is_empty() || name.is_empty() {
            return Err(ResourceError::BadAddress(s.to_owned()));
        }
        Ok(Address::new(kind, name))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.name)
    }
}

/// A `-l/--selector` label selector (surface doc §2): a conjunction of `k=v`
/// (equality) and `k!=v` (inequality) requirements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    equals: Vec<(String, String)>,
    not_equals: Vec<(String, String)>,
}

impl Selector {
    /// An empty selector — matches everything.
    #[must_use]
    pub fn new() -> Self {
        Selector::default()
    }

    /// Parse `k=v,k2!=v2,…` (kubectl's `-l` grammar).
    ///
    /// # Errors
    /// [`ResourceError::BadSelector`] on a term that is neither `k=v` nor `k!=v`.
    pub fn parse(s: &str) -> Result<Self, ResourceError> {
        let mut sel = Selector::new();
        for term in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if let Some((k, v)) = term.split_once("!=") {
                sel.not_equals
                    .push((k.trim().to_owned(), v.trim().to_owned()));
            } else if let Some((k, v)) = term.split_once('=') {
                sel.equals.push((k.trim().to_owned(), v.trim().to_owned()));
            } else {
                return Err(ResourceError::BadSelector(term.to_owned()));
            }
        }
        Ok(sel)
    }

    /// Whether a resource's labels satisfy every requirement.
    #[must_use]
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.equals
            .iter()
            .all(|(k, v)| labels.get(k).map(String::as_str) == Some(v.as_str()))
            && self
                .not_equals
                .iter()
                .all(|(k, v)| labels.get(k).map(String::as_str) != Some(v.as_str()))
    }
}

/// One row of a `get` list view: the object's kind/name plus the `-L` label
/// columns projected out of its metadata (surface doc §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The object's `kind/name` address.
    pub address: Address,
    /// The requested `-L` label columns, in request order — `None` where the
    /// object carries no such label.
    pub columns: Vec<Option<String>>,
}

/// Why a resource-plane operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// An address was not the `kind/name` grammar.
    BadAddress(String),
    /// A `-l` selector term was malformed.
    BadSelector(String),
    /// A `create` targeted an object that already exists.
    AlreadyExists(Address),
    /// A verb-required object did not exist in the view.
    NotFound(Address),
    /// The underlying signed-apply failed (schema/authorization).
    Apply(ApplyError),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceError::BadAddress(s) => write!(f, "bad address `{s}` (want `kind/name`)"),
            ResourceError::BadSelector(s) => write!(f, "bad selector term `{s}`"),
            ResourceError::AlreadyExists(a) => write!(f, "`{a}` already exists"),
            ResourceError::NotFound(a) => write!(f, "`{a}` not found"),
            ResourceError::Apply(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResourceError {}

/// The result of a resource ACT: the one signed event it emitted (surface doc
/// §1 — an act emits exactly one authorized event).
pub type ActResult = Result<Applied, ResourceError>;

/// The result of a `--dry-run` preview of a resource ACT: the SAME
/// [`ResourceError`] the real act would return (INCLUDING a refusal), or the
/// content-hash the real act would seal — but with NO event emitted and NO
/// state mutated either way.
pub type DryRunResult = Result<Previewed, ResourceError>;

/// The kubectl-parity resource plane over a [`Platform`], polymorphic over
/// EVERY kind. Every act ([`ResourcePlane::apply`], `create`, `delete`,
/// `patch`, `label`, `annotate`, `scale`) routes the intended change through the
/// SAME decider a manifest apply rides and emits exactly one signed event if
/// ALLOWed; every view (`get`, `describe`, `diff`, `explain`) reads the
/// materialized view and signs nothing.
///
/// It is a thin, uniform façade — the authority, signing, and event log all live
/// in [`Platform`]; this layer only maps kubectl-shaped verbs to that one
/// authorized path and applies `-l`/`-L` on the read side.
pub struct ResourcePlane<'p> {
    platform: &'p mut Platform,
    api_version: String,
}

impl<'p> ResourcePlane<'p> {
    /// A plane over `platform` whose objects live under `api_version` (the CRD
    /// `apiVersion` every kind on this plane shares; the plane is polymorphic
    /// over the `kind` within it).
    #[must_use]
    pub fn new(platform: &'p mut Platform, api_version: impl Into<String>) -> Self {
        ResourcePlane {
            platform,
            api_version: api_version.into(),
        }
    }

    // --- views (sign nothing) ------------------------------------------------

    /// `pillar get <kind> [-l sel] [-L cols]` (VIEW): list the objects of a
    /// kind, filtered by an optional label selector and projecting the requested
    /// `-L` label columns. Reads the materialized view; signs nothing.
    #[must_use]
    pub fn get(&self, kind: &str, selector: &Selector, columns: &[String]) -> Vec<Row> {
        let mut rows = Vec::new();
        for (key, env) in self.platform.view() {
            if key.api_version != self.api_version || key.kind != kind {
                continue;
            }
            let labels = &env.body().metadata.labels;
            if !selector.matches(labels) {
                continue;
            }
            rows.push(Row {
                address: Address::new(kind, key.name.clone()),
                columns: columns.iter().map(|c| labels.get(c).cloned()).collect(),
            });
        }
        rows
    }

    /// `pillar describe <kind>/<name>` (VIEW): full detail of one object
    /// INCLUDING provenance — the signer (which subkey authorized the last
    /// change) and the event CID / content-hash in the log. Signs nothing.
    #[must_use]
    pub fn describe(&self, addr: &Address) -> Option<String> {
        self.platform
            .describe(&self.api_version, &addr.kind, &addr.name)
    }

    /// `pillar diff <kind>/<name>` (VIEW): what an act WOULD do — the decider's
    /// ALLOW/DENY for `capability` and the body that would be applied — WITHOUT
    /// signing or appending anything (surface doc §3.2: `diff` runs the decider
    /// and signs nothing). Returns the decision; the event count is unchanged.
    #[must_use]
    pub fn diff(&self, actor: &NodeId, capability: &str) -> bool {
        self.platform.authorized(actor, capability)
    }

    // --- acts (emit exactly one signed, authorized event) --------------------

    /// `pillar apply -f <file>` (ACT): declarative upsert of one object — decode,
    /// run the decider, and sign+append the resulting event if authorized.
    ///
    /// # Errors
    /// [`ResourceError::Apply`] wrapping the schema/authorization failure; on
    /// any failure NOTHING is mutated.
    pub fn apply(&mut self, actor: &NodeId, capability: &str, body: Crd) -> ActResult {
        self.platform
            .apply(
                actor,
                capability,
                body,
                [],
                [ManifestCapability::from(capability)],
            )
            .map_err(ResourceError::Apply)
    }

    /// `pillar apply -f <file> --dry-run` (VIEW): preview what
    /// [`ResourcePlane::apply`] of this EXACT body WOULD do — running the
    /// SAME decider decision `apply` enforces (see [`Platform::preview`]) —
    /// emitting NO event and mutating NOTHING. Shows the identical outcome
    /// `apply` would produce, including a refusal (predicted == enforced,
    /// the single-decider invariant).
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `apply` would return for this body.
    pub fn dry_run_apply(&self, actor: &NodeId, capability: &str, body: &Crd) -> DryRunResult {
        self.platform
            .preview(actor, capability, body)
            .map_err(ResourceError::Apply)
    }

    /// `pillar create <kind>/<name>` (ACT): imperative create; refuses if the
    /// object already exists in the view.
    ///
    /// # Errors
    /// [`ResourceError::AlreadyExists`] if present; else the apply's error.
    pub fn create(&mut self, actor: &NodeId, capability: &str, body: Crd) -> ActResult {
        if self
            .platform
            .get(&self.api_version, &body.kind, &body.metadata.name)
            .is_some()
        {
            return Err(ResourceError::AlreadyExists(Address::new(
                body.kind.clone(),
                body.metadata.name.clone(),
            )));
        }
        self.apply(actor, capability, body)
    }

    /// `pillar create --dry-run` (VIEW): preview [`ResourcePlane::create`) —
    /// the SAME already-exists check plus the SAME decider decision the real
    /// create would enforce, with no mutation.
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `create` would return for this body.
    pub fn dry_run_create(&self, actor: &NodeId, capability: &str, body: &Crd) -> DryRunResult {
        if self
            .platform
            .get(&self.api_version, &body.kind, &body.metadata.name)
            .is_some()
        {
            return Err(ResourceError::AlreadyExists(Address::new(
                body.kind.clone(),
                body.metadata.name.clone(),
            )));
        }
        self.dry_run_apply(actor, capability, body)
    }

    /// `pillar delete <kind>/<name>` (ACT): emit a delete/tombstone event. The
    /// tombstone is a signed body carrying the `pillar.dev/deleted` label, so it
    /// rides the identical authorized apply path.
    ///
    /// # Errors
    /// [`ResourceError::NotFound`] if the object is absent; else the apply error.
    pub fn delete(&mut self, actor: &NodeId, capability: &str, addr: &Address) -> ActResult {
        let existing = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        let mut tombstone = existing;
        tombstone
            .metadata
            .labels
            .insert("pillar.dev/deleted".to_owned(), "true".to_owned());
        self.apply(actor, capability, tombstone)
    }

    /// `pillar delete --dry-run` (VIEW): preview [`ResourcePlane::delete`] —
    /// the SAME not-found check plus the SAME decider decision, with no
    /// mutation.
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `delete` would return for this address.
    pub fn dry_run_delete(&self, actor: &NodeId, capability: &str, addr: &Address) -> DryRunResult {
        let existing = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        let mut tombstone = existing;
        tombstone
            .metadata
            .labels
            .insert("pillar.dev/deleted".to_owned(), "true".to_owned());
        self.dry_run_apply(actor, capability, &tombstone)
    }

    /// `pillar label <kind>/<name> k=v` (ACT): add/overwrite an operator label
    /// (a `k-` suffix removes it) and re-apply the object as one signed event.
    ///
    /// # Errors
    /// [`ResourceError::NotFound`] if absent; else the apply error.
    pub fn label(
        &mut self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        key: &str,
        value: Option<&str>,
    ) -> ActResult {
        let mut body = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        match value {
            Some(v) => {
                body.metadata.labels.insert(key.to_owned(), v.to_owned());
            }
            None => {
                body.metadata.labels.remove(key);
            }
        }
        self.apply(actor, capability, body)
    }

    /// `pillar label --dry-run` (VIEW): preview [`ResourcePlane::label`] with
    /// no mutation.
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `label` would return.
    pub fn dry_run_label(
        &self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        key: &str,
        value: Option<&str>,
    ) -> DryRunResult {
        let mut body = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        match value {
            Some(v) => {
                body.metadata.labels.insert(key.to_owned(), v.to_owned());
            }
            None => {
                body.metadata.labels.remove(key);
            }
        }
        self.dry_run_apply(actor, capability, &body)
    }

    /// `pillar patch <kind>/<name>` (ACT): overwrite a spec field on the object
    /// and re-apply it as one signed event.
    ///
    /// # Errors
    /// [`ResourceError::NotFound`] if absent; else the apply error.
    pub fn patch(
        &mut self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        field: &str,
        value: Value,
    ) -> ActResult {
        let mut body = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        body.spec.insert(field.to_owned(), value);
        self.apply(actor, capability, body)
    }

    /// `pillar patch --dry-run` (VIEW): preview [`ResourcePlane::patch`] with
    /// no mutation.
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `patch` would return.
    pub fn dry_run_patch(
        &self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        field: &str,
        value: Value,
    ) -> DryRunResult {
        let mut body = self
            .platform
            .get(&self.api_version, &addr.kind, &addr.name)
            .ok_or_else(|| ResourceError::NotFound(addr.clone()))?;
        body.spec.insert(field.to_owned(), value);
        self.dry_run_apply(actor, capability, &body)
    }

    /// `pillar scale <kind>/<name> --replicas N` (ACT): patch the object's
    /// `replicas` spec field and re-apply as one signed event.
    ///
    /// # Errors
    /// [`ResourceError::NotFound`] if absent; else the apply error.
    pub fn scale(
        &mut self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        replicas: i64,
    ) -> ActResult {
        self.patch(
            actor,
            capability,
            addr,
            "replicas",
            Value::Integer(replicas),
        )
    }

    /// `pillar scale --dry-run` (VIEW): preview [`ResourcePlane::scale`] with
    /// no mutation.
    ///
    /// # Errors
    /// The SAME [`ResourceError`] `scale` would return.
    pub fn dry_run_scale(
        &self,
        actor: &NodeId,
        capability: &str,
        addr: &Address,
        replicas: i64,
    ) -> DryRunResult {
        self.dry_run_patch(
            actor,
            capability,
            addr,
            "replicas",
            Value::Integer(replicas),
        )
    }
}

/// Build a delete/tombstone body from a name (a convenience for imperative
/// creates in tests and the shell): a minimal CRD carrying the deleted marker.
#[must_use]
pub fn tombstone(api_version: &str, kind: &str, name: &str) -> Crd {
    Crd::new(
        api_version,
        kind,
        Metadata::new(name).with_label("pillar.dev/deleted", "true"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{FieldType, Schema, SchemaRegistry};
    use pillar_rbac::{default_resource_class_policies, Capability as RbacCapability};
    use pillar_wot_authority::WotAuthority;

    const OWNER: &str = "OWNER-FPR";
    const STRANGER: &str = "STRANGER-FPR";
    const API: &str = "pillar.dev/v1";
    const WORKLOAD: &str = "Service"; // a workload kind
    const IDENTITY: &str = "User"; // an identity kind
    const CAP: &str = "net/route";

    fn registry() -> SchemaRegistry {
        let mut reg = SchemaRegistry::new();
        // A workload kind and an identity kind share the plane — proving the
        // resource plane is polymorphic over EVERY kind, not workload-only.
        reg.register(
            Schema::new(API, WORKLOAD)
                .required("image", FieldType::String)
                .property("replicas", FieldType::Integer),
        );
        reg.register(
            Schema::new(API, IDENTITY)
                .required("handle", FieldType::String)
                .property("depth", FieldType::Integer),
        );
        reg
    }

    fn platform() -> Platform {
        let authority = WotAuthority::new(NodeId::from(OWNER), 5);
        let policies = default_resource_class_policies(&RbacCapability(CAP.to_owned()));
        Platform::new(registry(), authority, policies, Vec::new())
    }

    fn workload(name: &str) -> Crd {
        Crd::new(
            API,
            WORKLOAD,
            Metadata::new(name).with_label("tier", "edge"),
        )
        .with_spec("image", Value::String("app:v1".into()))
        .with_spec("replicas", Value::Integer(1))
    }

    fn identity(name: &str) -> Crd {
        Crd::new(
            API,
            IDENTITY,
            Metadata::new(name).with_label("tier", "core"),
        )
        .with_spec("handle", Value::String(format!("@{name}")))
    }

    fn issuer() -> TokenIssuer {
        let mut i = TokenIssuer::new();
        i.register_user("alice@pillar", "s3cret");
        i
    }

    // --- session / context ---------------------------------------------------

    #[test]
    fn login_mints_a_token_and_whoami_status_read_it() {
        let mut i = issuer();
        let session = Session::login(&mut i, "cellA", "alice@pillar", "s3cret", 0, 100)
            .expect("valid credential mints a session");
        assert_eq!(session.whoami(), "alice@pillar");
        assert_eq!(session.domain(), "cellA");
        assert_eq!(session.status(&i, 50).unwrap(), "alice@pillar");
        // The exports carry both vars for the shell to eval.
        let exports = session.export_lines();
        assert!(exports.contains("PILLAR_DOMAIN=cellA"));
        assert!(exports.contains(&format!("PILLAR_TOKEN={}", session.token())));
    }

    #[test]
    fn a_bad_login_credential_mints_no_session() {
        let mut i = issuer();
        assert_eq!(
            Session::login(&mut i, "cellA", "alice@pillar", "wrong", 0, 100)
                .expect_err("bad credential"),
            LoginTokenError::BadCredential
        );
    }

    #[test]
    fn logout_clears_the_session_token_fail_closed() {
        let mut i = issuer();
        let session = Session::login(&mut i, "cellA", "alice@pillar", "s3cret", 0, 100).unwrap();
        // Before logout the token authenticates.
        assert!(session.status(&i, 10).is_ok());
        let store = TokenStore::new(session.domain(), session.token());
        session.logout(&mut i);
        // After logout the SAME token is revoked — fail-closed.
        assert_eq!(
            store
                .authenticate(&i, 10)
                .expect_err("revoked after logout"),
            LoginTokenError::Revoked
        );
    }

    #[test]
    fn context_family_is_local_only_use_and_ctx() {
        let mut store = ContextStore::new();
        store.add("prod", Context::new("cellA"));
        store.add("dev", Context::new("cellB"));
        // First add becomes current.
        assert_eq!(store.current_name(), Some("prod"));
        // ls shows both, sorted.
        assert_eq!(store.list(), vec!["dev", "prod"]);
        // use switches current.
        assert!(store.use_context("dev"));
        assert_eq!(store.current().unwrap().domain, "cellB");
        // use cell/<cell> pins the active cell locally.
        assert!(store.use_cell("teamX"));
        assert_eq!(store.current().unwrap().cell.as_deref(), Some("teamX"));
        // rename and rm keep current coherent.
        assert!(store.rename("dev", "staging"));
        assert_eq!(store.current_name(), Some("staging"));
        assert!(store.remove("staging"));
        assert_eq!(store.current_name(), Some("prod"));
        assert!(!store.use_context("nope"));
    }

    // --- verb classification (the two-fold rule) -----------------------------

    #[test]
    fn views_and_acts_are_classified_by_the_verb_not_convention() {
        for v in [
            Verb::Get,
            Verb::Describe,
            Verb::Explain,
            Verb::Diff,
            Verb::Watch,
        ] {
            assert!(v.is_view(), "{v:?} must be a view");
            assert!(!v.is_act());
        }
        for v in [
            Verb::Apply,
            Verb::Create,
            Verb::Edit,
            Verb::Delete,
            Verb::Patch,
            Verb::Label,
            Verb::Annotate,
            Verb::Scale,
            Verb::Autoscale,
        ] {
            assert!(v.is_act(), "{v:?} must be an act");
            assert!(!v.is_view());
        }
    }

    // --- a view emits no event ----------------------------------------------

    #[test]
    fn a_view_emits_no_event() {
        let mut p = platform();
        // Seed one object via an act so there is state to view.
        {
            let mut plane = ResourcePlane::new(&mut p, API);
            plane
                .apply(&NodeId::from(OWNER), CAP, workload("web"))
                .expect("owner authorized");
        }
        let before = p.event_count();
        let plane = ResourcePlane::new(&mut p, API);
        // get / describe / diff are all views — they sign NOTHING.
        let rows = plane.get(WORKLOAD, &Selector::new(), &[]);
        assert_eq!(rows.len(), 1);
        assert!(plane.describe(&Address::new(WORKLOAD, "web")).is_some());
        assert!(plane.diff(&NodeId::from(OWNER), CAP)); // decider allow, no emit
        assert_eq!(p.event_count(), before, "no view may append an event");
    }

    // --- an act emits exactly one decider-authorized event -------------------

    #[test]
    fn an_authorized_act_emits_exactly_one_event() {
        let mut p = platform();
        let mut plane = ResourcePlane::new(&mut p, API);
        assert_eq!(plane.platform.event_count(), 0);
        plane
            .apply(&NodeId::from(OWNER), CAP, workload("web"))
            .expect("owner authorized");
        assert_eq!(plane.platform.event_count(), 1, "one act, one event");
    }

    #[test]
    fn an_unauthorized_act_is_refused_and_emits_nothing() {
        let mut p = platform();
        let mut plane = ResourcePlane::new(&mut p, API);
        let err = plane
            .apply(&NodeId::from(STRANGER), CAP, workload("web"))
            .expect_err("stranger unauthorized");
        assert!(matches!(
            err,
            ResourceError::Apply(ApplyError::Unauthorized { .. })
        ));
        assert_eq!(p.event_count(), 0, "an unauthorized act appends nothing");
    }

    // --- polymorphic over a workload AND an identity kind ---------------------

    #[test]
    fn the_plane_is_polymorphic_over_a_workload_and_an_identity_kind() {
        let mut p = platform();
        {
            let mut plane = ResourcePlane::new(&mut p, API);
            plane
                .apply(&NodeId::from(OWNER), CAP, workload("web"))
                .expect("workload act");
            plane
                .apply(&NodeId::from(OWNER), CAP, identity("alice"))
                .expect("identity act");
        }
        let plane = ResourcePlane::new(&mut p, API);
        // The SAME get verb reads both kinds.
        assert_eq!(plane.get(WORKLOAD, &Selector::new(), &[]).len(), 1);
        assert_eq!(plane.get(IDENTITY, &Selector::new(), &[]).len(), 1);
        // And describe surfaces provenance for the identity kind too — the
        // signer AND the event CID of the record in force (surface doc §3.2).
        let d = plane.describe(&Address::new(IDENTITY, "alice")).unwrap();
        assert!(d.contains("Signer:"));
        assert!(d.contains("Event-CID:"), "describe shows the event CID");
        assert!(d.contains(OWNER));
    }

    // --- -l selectors + -L columns everywhere --------------------------------

    #[test]
    fn selector_filters_and_label_columns_project() {
        let mut p = platform();
        {
            let mut plane = ResourcePlane::new(&mut p, API);
            let edge = workload("web"); // tier=edge
            let mut core = workload("db");
            core.metadata
                .labels
                .insert("tier".to_owned(), "core".to_owned());
            plane.apply(&NodeId::from(OWNER), CAP, edge).unwrap();
            plane.apply(&NodeId::from(OWNER), CAP, core).unwrap();
        }
        let plane = ResourcePlane::new(&mut p, API);
        // -l tier=edge filters to just `web`.
        let sel = Selector::parse("tier=edge").unwrap();
        let rows = plane.get(WORKLOAD, &sel, &["tier".to_owned()]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address, Address::new(WORKLOAD, "web"));
        // -L tier projects the label value as a column.
        assert_eq!(rows[0].columns, vec![Some("edge".to_owned())]);
        // -l tier!=edge excludes `web`, keeps `db`.
        let sel = Selector::parse("tier!=edge").unwrap();
        let rows = plane.get(WORKLOAD, &sel, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address, Address::new(WORKLOAD, "db"));
    }

    // --- diff signs nothing --------------------------------------------------

    #[test]
    fn diff_runs_the_decider_and_signs_nothing() {
        let mut p = platform();
        let plane = ResourcePlane::new(&mut p, API);
        let before = plane.platform.event_count();
        // diff returns the decider ALLOW for the owner, DENY for the stranger...
        assert!(plane.diff(&NodeId::from(OWNER), CAP));
        assert!(!plane.diff(&NodeId::from(STRANGER), CAP));
        // ...and emits nothing either way.
        assert_eq!(plane.platform.event_count(), before);
    }

    // --- act verbs are polymorphic and each emit one event -------------------

    #[test]
    fn create_refuses_duplicates_and_delete_label_patch_scale_each_emit_one_event() {
        let mut p = platform();
        let owner = NodeId::from(OWNER);
        let mut plane = ResourcePlane::new(&mut p, API);
        // create
        plane.create(&owner, CAP, workload("web")).expect("create");
        assert!(matches!(
            plane.create(&owner, CAP, workload("web")).expect_err("dup"),
            ResourceError::AlreadyExists(_)
        ));
        // label, patch, scale each re-apply as ONE event.
        let addr = Address::new(WORKLOAD, "web");
        let n0 = plane.platform.event_count();
        plane
            .label(&owner, CAP, &addr, "env", Some("prod"))
            .expect("label");
        plane
            .patch(&owner, CAP, &addr, "replicas", Value::Integer(3))
            .expect("patch");
        plane.scale(&owner, CAP, &addr, 5).expect("scale");
        assert_eq!(plane.platform.event_count(), n0 + 3);
        // The label and scale took effect in the view.
        let got = plane.platform.get(API, WORKLOAD, "web").expect("in view");
        assert_eq!(got.metadata.labels.get("env"), Some(&"prod".to_owned()));
        assert_eq!(got.spec.get("replicas"), Some(&Value::Integer(5)));
        // delete emits a tombstone act.
        plane.delete(&owner, CAP, &addr).expect("delete");
        let deleted = plane.platform.get(API, WORKLOAD, "web").unwrap();
        assert_eq!(
            deleted.metadata.labels.get("pillar.dev/deleted"),
            Some(&"true".to_owned())
        );
    }

    #[test]
    fn address_and_selector_parsing_reject_malformed_input() {
        assert_eq!(
            Address::parse("web").unwrap_err(),
            ResourceError::BadAddress("web".to_owned())
        );
        assert_eq!(
            Address::parse("cell/cellA").unwrap(),
            Address::new("cell", "cellA")
        );
        assert!(matches!(
            Selector::parse("bogus").unwrap_err(),
            ResourceError::BadSelector(_)
        ));
    }

    // --- --dry-run: previewed decision == real decision, no event emitted ---

    #[test]
    fn dry_run_apply_previews_an_allowed_act_and_emits_no_event_incl_an_identity_kind() {
        let mut p = platform();
        let plane = ResourcePlane::new(&mut p, API);
        let before = plane.platform.event_count();
        // A representative WORKLOAD act.
        let preview = plane
            .dry_run_apply(&NodeId::from(OWNER), CAP, &workload("web"))
            .expect("owner authorized to preview");
        assert_eq!(
            plane.platform.event_count(),
            before,
            "dry-run emits no event"
        );
        // An IDENTITY-kind act previews identically.
        let id_preview = plane
            .dry_run_apply(&NodeId::from(OWNER), CAP, &identity("alice"))
            .expect("owner authorized to preview an identity kind too");
        assert_eq!(
            plane.platform.event_count(),
            before,
            "dry-run emits no event"
        );

        // Now perform the REAL acts: predicted == enforced — same outcome,
        // same content-hash, and the log only advances on the REAL act.
        drop(plane);
        let mut plane = ResourcePlane::new(&mut p, API);
        let applied = plane
            .apply(&NodeId::from(OWNER), CAP, workload("web"))
            .expect("the real act succeeds too, matching the preview");
        assert_eq!(applied.content_hash, preview.content_hash);
        let applied_id = plane
            .apply(&NodeId::from(OWNER), CAP, identity("alice"))
            .expect("the real identity act succeeds too");
        assert_eq!(applied_id.content_hash, id_preview.content_hash);
        assert_eq!(plane.platform.event_count(), before + 2);
    }

    #[test]
    fn dry_run_apply_previews_a_denied_act_identically_to_the_real_refusal() {
        let mut p = platform();
        let plane = ResourcePlane::new(&mut p, API);
        let before = plane.platform.event_count();
        let preview_err = plane
            .dry_run_apply(&NodeId::from(STRANGER), CAP, &workload("web"))
            .expect_err("stranger is refused in preview too");
        assert!(matches!(
            preview_err,
            ResourceError::Apply(ApplyError::Unauthorized { .. })
        ));
        assert_eq!(
            plane.platform.event_count(),
            before,
            "a denied dry-run emits nothing"
        );

        // The REAL act refuses IDENTICALLY.
        drop(plane);
        let mut plane = ResourcePlane::new(&mut p, API);
        let real_err = plane
            .apply(&NodeId::from(STRANGER), CAP, workload("web"))
            .expect_err("stranger is refused for real too");
        assert!(matches!(
            real_err,
            ResourceError::Apply(ApplyError::Unauthorized { .. })
        ));
        assert_eq!(
            plane.platform.event_count(),
            before,
            "the real refusal emits nothing either"
        );
    }

    #[test]
    fn dry_run_create_delete_label_patch_scale_each_preview_with_no_mutation() {
        let mut p = platform();
        let owner = NodeId::from(OWNER);
        {
            let mut plane = ResourcePlane::new(&mut p, API);
            plane.create(&owner, CAP, workload("web")).expect("seed");
        }
        let plane = ResourcePlane::new(&mut p, API);
        let addr = Address::new(WORKLOAD, "web");
        let before = plane.platform.event_count();

        // create dry-run on an EXISTING name refuses identically to create.
        assert!(matches!(
            plane
                .dry_run_create(&owner, CAP, &workload("web"))
                .expect_err("dup previewed"),
            ResourceError::AlreadyExists(_)
        ));
        plane
            .dry_run_label(&owner, CAP, &addr, "env", Some("prod"))
            .expect("label previewed");
        plane
            .dry_run_patch(&owner, CAP, &addr, "replicas", Value::Integer(3))
            .expect("patch previewed");
        plane
            .dry_run_scale(&owner, CAP, &addr, 5)
            .expect("scale previewed");
        plane
            .dry_run_delete(&owner, CAP, &addr)
            .expect("delete previewed");

        // None of the previews mutated the view or emitted an event.
        assert_eq!(
            plane.platform.event_count(),
            before,
            "no dry-run may append an event"
        );
        let still_unchanged = plane.platform.get(API, WORKLOAD, "web").unwrap();
        assert_eq!(still_unchanged.metadata.labels.get("env"), None);
        assert_eq!(
            still_unchanged.spec.get("replicas"),
            Some(&Value::Integer(1))
        );
        assert_eq!(
            still_unchanged.metadata.labels.get("pillar.dev/deleted"),
            None
        );
    }
}
