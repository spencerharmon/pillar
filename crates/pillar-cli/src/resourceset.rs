//! ResourceSet — pillar's ArgoCD-Application analog.
//!
//! A ResourceSet is a declarative grouping that OWNS a set of member resources
//! and reconciles the live world toward its declared membership. This module is
//! the PURE core: lowering a `ResourceSet` manifest to a typed spec, the
//! reconcile decision (what to adopt / what to prune / whether it is synced),
//! the health roll-up, and the resource-graph derivation the console renders.
//!
//! The reconcile decision mirrors `specs/ResourceSet.tla` (proven under TLC):
//! `to_adopt` is the declared-but-not-owned set, `to_prune` is the owned-but-
//! no-longer-declared set, and a set is `Synced` exactly when its live owned
//! membership equals its declared membership. The health roll-up and graph are
//! pure derivations (no protocol, hence no TLA+ per pillar-method).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use pillar_manifest::{Crd, Envelope, Value};
use pillar_observability::RetentionPolicySpec;

use crate::defaults::{self, DefaultAdvisory};
use crate::ResourceKey;

/// The `ResourceSet` kind string (matches
/// [`pillar_manifest::builtin::BuiltinKind::ResourceSet`]).
pub const RESOURCE_SET_KIND: &str = "ResourceSet";
/// The well-known Default ResourceSet name; it implicitly owns every
/// RetentionPolicy resource on the cell.
pub const DEFAULT_RESOURCE_SET: &str = "default";
/// The ownership-tracking label an explicit ResourceSet stamps on the resources
/// it owns (ArgoCD tracking-label analog).
pub const RESOURCE_SET_LABEL: &str = "pillar.dev/resource-set";
/// The RetentionPolicy kind string — the Default set's implicit membership.
pub const RETENTION_POLICY_KIND: &str = "RetentionPolicy";

/// The resource-plane materialized view both the web plane and the CLI read:
/// every applied resource keyed by `(apiVersion, kind, name)`.
pub type ResourceView = BTreeMap<ResourceKey, Envelope>;

/// A reference to a member resource, rendered `<Kind>/<name>` — the same
/// `kind`/`name` pair a resource is applied and listed under on the resource
/// plane.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberRef {
    pub kind: String,
    pub name: String,
}

impl MemberRef {
    #[must_use]
    pub fn new(kind: impl Into<String>, name: impl Into<String>) -> Self {
        MemberRef {
            kind: kind.into(),
            name: name.into(),
        }
    }

    /// Parse a `<Kind>/<name>` reference. Rejects an empty kind or name, or a
    /// token without exactly one `/` separator.
    pub fn parse(token: &str) -> Result<MemberRef, String> {
        let token = token.trim();
        let (kind, name) = token
            .split_once('/')
            .ok_or_else(|| format!("member {token:?} is not <Kind>/<name>"))?;
        let kind = kind.trim();
        let name = name.trim();
        if kind.is_empty() || name.is_empty() {
            return Err(format!("member {token:?} has an empty kind or name"));
        }
        if name.contains('/') {
            return Err(format!("member {token:?} has more than one '/'"));
        }
        Ok(MemberRef::new(kind, name))
    }
}

impl fmt::Display for MemberRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.name)
    }
}

/// The typed spec of a ResourceSet, lowered from a validated manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceSetSpec {
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<MemberRef>,
}

impl ResourceSetSpec {
    /// Lower a validated `ResourceSet` manifest [`Crd`] into a typed spec. The
    /// schema layer has already checked field presence/types; this decodes the
    /// flat comma-separated `members` string (`Kind/name, Kind/name`) into a
    /// deduplicated, ordered member list. An empty `members` string is a valid
    /// zero-member set (e.g. the Default set before anything is grouped).
    ///
    /// # Errors
    /// A message when `members` is missing/mistyped or a member ref is
    /// malformed.
    pub fn from_crd(crd: &Crd) -> Result<ResourceSetSpec, String> {
        let members_raw = match crd.spec.get("members") {
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err("ResourceSet spec.members must be a string".to_string()),
            None => return Err("ResourceSet spec.members is required".to_string()),
        };
        let description = match crd.spec.get("description") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("ResourceSet spec.description must be a string".to_string()),
        };
        Ok(ResourceSetSpec {
            name: crd.metadata.name.clone(),
            description,
            members: parse_members(&members_raw)?,
        })
    }
}

/// Decode the flat `members` selector string (`Kind/name, Kind/name`). Empty
/// (or whitespace-only) entries are skipped; the result is deduplicated while
/// preserving first-seen order.
fn parse_members(raw: &str) -> Result<Vec<MemberRef>, String> {
    let mut out: Vec<MemberRef> = Vec::new();
    for token in raw.split(',') {
        if token.trim().is_empty() {
            continue;
        }
        let m = MemberRef::parse(token)?;
        if !out.contains(&m) {
            out.push(m);
        }
    }
    Ok(out)
}

/// Per-member health as observed on the live resource plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberHealth {
    /// The member exists and reports healthy.
    Healthy,
    /// The member exists but reports a problem.
    Degraded,
    /// The member is declared but does not exist on the plane.
    Missing,
}

impl MemberHealth {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MemberHealth::Healthy => "Healthy",
            MemberHealth::Degraded => "Degraded",
            MemberHealth::Missing => "Missing",
        }
    }
}

/// The rolled-up health of a whole ResourceSet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetHealth {
    /// Every member exists and is healthy.
    Healthy,
    /// At least one member is missing or degraded.
    Degraded,
    /// The set declares no members.
    Empty,
}

impl SetHealth {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SetHealth::Healthy => "Healthy",
            SetHealth::Degraded => "Degraded",
            SetHealth::Empty => "Empty",
        }
    }
}

/// Roll a set's member healths up into one set-level health: `Empty` when there
/// are no members, `Healthy` iff every member is `Healthy`, else `Degraded`.
#[must_use]
pub fn roll_up_health(members: &[MemberHealth]) -> SetHealth {
    if members.is_empty() {
        return SetHealth::Empty;
    }
    if members.iter().all(|h| *h == MemberHealth::Healthy) {
        SetHealth::Healthy
    } else {
        SetHealth::Degraded
    }
}

/// Whether a set's live owned membership matches its declaration exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// Live owned membership equals declared membership.
    Synced,
    /// The set has members to adopt and/or prune.
    OutOfSync,
}

impl SyncStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SyncStatus::Synced => "Synced",
            SyncStatus::OutOfSync => "OutOfSync",
        }
    }
}

/// The reconcile plan for one ResourceSet, mirroring `specs/ResourceSet.tla`:
/// `to_adopt` = declared members not yet owned/live; `to_prune` = owned/live
/// members no longer declared; `synced` iff both are empty (live owned set ==
/// declared set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub to_adopt: Vec<MemberRef>,
    pub to_prune: Vec<MemberRef>,
    pub synced: bool,
}

impl ReconcilePlan {
    #[must_use]
    pub fn sync_status(&self) -> SyncStatus {
        if self.synced {
            SyncStatus::Synced
        } else {
            SyncStatus::OutOfSync
        }
    }
}

/// Compute the reconcile plan from the declared members and the members this
/// set currently OWNS on the live plane (a resource is owned by the set that
/// carries its ownership label). This is the pure Rust image of the TLA
/// `CreateMember`/`PruneMember` decision: adopt the declared-but-unowned,
/// prune the owned-but-undeclared.
#[must_use]
pub fn plan_reconcile(declared: &[MemberRef], owned_live: &[MemberRef]) -> ReconcilePlan {
    let declared_set: BTreeSet<&MemberRef> = declared.iter().collect();
    let owned_set: BTreeSet<&MemberRef> = owned_live.iter().collect();
    let to_adopt: Vec<MemberRef> = declared
        .iter()
        .filter(|m| !owned_set.contains(*m))
        .cloned()
        .collect();
    let to_prune: Vec<MemberRef> = owned_live
        .iter()
        .filter(|m| !declared_set.contains(*m))
        .cloned()
        .collect();
    let synced = to_adopt.is_empty() && to_prune.is_empty();
    ReconcilePlan {
        to_adopt,
        to_prune,
        synced,
    }
}

/// One member's rendered live status: its reference and observed health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberStatus {
    pub reference: MemberRef,
    pub health: MemberHealth,
}

/// The `Kind` string of a member whose live replicas can be descended into a
/// third graph depth (`ResourceSet -> Workload -> replica`). Matches
/// `web_serve::WORKLOAD_KIND` — kept as a plain string here (rather than a
/// cross-module const) since `resourceset` is the pure core and does not
/// depend on the web plane.
pub const WORKLOAD_MEMBER_KIND: &str = "Workload";

/// One live replica of a `Workload` member, as surfaced by the
/// `/portal/resource/replicas` oracle — the minimal shape [`build_graph`]
/// needs to render a `Workload -> replica` graph edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaNode {
    /// The rendered node label, e.g. `Replica/<node>:<port>`.
    pub label: String,
    /// The replica's health (always `Healthy` — an observed replica is, by
    /// construction, live; a dead one is reconciled away or restarted before
    /// ever being observed).
    pub health: String,
}

/// One node of a [`ResourceGraph`]: a label plus a per-node health+sync token
/// (ArgoCD-parity "resource health at a glance" — every node in the tree, not
/// only the set root, carries its own status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphNode {
    pub label: String,
    pub health: String,
    pub sync: String,
}

impl GraphNode {
    #[must_use]
    pub fn new(label: impl Into<String>, health: impl Into<String>, sync: impl Into<String>) -> Self {
        GraphNode {
            label: label.into(),
            health: health.into(),
            sync: sync.into(),
        }
    }
}

/// The node-link graph the console renders for a ResourceSet: node 0 is the
/// set itself; nodes `1..=n` are its members (in `members` order); a
/// `Workload` member is further descended into its live replicas (the
/// `/portal/resource/replicas` oracle's per-workload observations), appended
/// after all top-level member nodes. Each node carries its own health+sync
/// token. This is the `(nodes, edges)` shape the console's Tree/Graph
/// primitives render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceGraph {
    pub nodes: Vec<GraphNode>,
    /// `(from_index, to_index, edge_label)`.
    pub edges: Vec<(usize, usize, String)>,
}

/// Derive the resource graph for one set from its member statuses, descending
/// any `Workload` member into its live replicas (`replicas_by_workload` maps a
/// workload name to its observed replica nodes — empty/absent when no
/// reconciler is wired or the workload has no live replicas yet).
#[must_use]
pub fn build_graph(
    set_name: &str,
    set_health: SetHealth,
    set_sync: SyncStatus,
    members: &[MemberStatus],
    replicas_by_workload: &BTreeMap<String, Vec<ReplicaNode>>,
) -> ResourceGraph {
    let mut nodes = Vec::with_capacity(members.len() + 1);
    nodes.push(GraphNode::new(
        format!("ResourceSet/{set_name}"),
        set_health.as_str(),
        set_sync.as_str(),
    ));
    let mut edges = Vec::with_capacity(members.len());
    for (i, m) in members.iter().enumerate() {
        let member_idx = i + 1;
        nodes.push(GraphNode::new(
            m.reference.to_string(),
            m.health.as_str(),
            m.health.as_str(),
        ));
        edges.push((0, member_idx, m.health.as_str().to_string()));

        if m.reference.kind == WORKLOAD_MEMBER_KIND {
            if let Some(replicas) = replicas_by_workload.get(&m.reference.name) {
                for r in replicas {
                    let replica_idx = nodes.len();
                    nodes.push(GraphNode::new(r.label.clone(), r.health.clone(), "Live"));
                    edges.push((member_idx, replica_idx, r.health.clone()));
                }
            }
        }
    }
    ResourceGraph { nodes, edges }
}

// ---------------------------------------------------------------------------
// Resource-plane synthesis (SHARED by the web plane and the CLI).
//
// These were previously private methods on the web `WebAuthContext`; pushed
// down here as pure functions over the materialized view so `pillar get/
// describe`, the portal routes, and the console all derive an IDENTICAL model
// (the operator's "surface the semantic in both UI and CLI" requirement).
// ---------------------------------------------------------------------------

/// Every `RetentionPolicy/<name>` resource in the view — the implicit
/// membership of the synthesized Default ResourceSet.
#[must_use]
pub fn all_retention_policy_refs(view: &ResourceView) -> Vec<MemberRef> {
    view.keys()
        .filter(|k| k.kind == RETENTION_POLICY_KIND)
        .map(|k| MemberRef::new(RETENTION_POLICY_KIND, &k.name))
        .collect()
}

/// Collect the declared ResourceSets from the view, plus the synthesized
/// Default set (declaring every RetentionPolicy resource) when no explicit
/// `default` ResourceSet has been applied.
#[must_use]
pub fn collect_resourcesets(view: &ResourceView) -> Vec<ResourceSetSpec> {
    let mut sets: Vec<ResourceSetSpec> = Vec::new();
    let mut have_default = false;
    for (key, env) in view {
        if key.kind != RESOURCE_SET_KIND {
            continue;
        }
        if let Ok(spec) = ResourceSetSpec::from_crd(&env.render()) {
            if spec.name == DEFAULT_RESOURCE_SET {
                have_default = true;
            }
            sets.push(spec);
        }
    }
    if !have_default {
        sets.insert(
            0,
            ResourceSetSpec {
                name: DEFAULT_RESOURCE_SET.to_owned(),
                description: Some("default retention policies".to_owned()),
                members: all_retention_policy_refs(view),
            },
        );
    }
    sets
}

/// The live members a set currently OWNS. The Default set implicitly owns every
/// RetentionPolicy it declares; an explicit set owns the resources carrying its
/// `pillar.dev/resource-set` ownership label.
#[must_use]
pub fn owned_live(view: &ResourceView, spec: &ResourceSetSpec) -> Vec<MemberRef> {
    if spec.name == DEFAULT_RESOURCE_SET {
        return spec
            .members
            .iter()
            .filter(|m| view.keys().any(|k| k.kind == m.kind && k.name == m.name))
            .cloned()
            .collect();
    }
    view.iter()
        .filter(|(_, env)| {
            env.body()
                .metadata
                .labels
                .get(RESOURCE_SET_LABEL)
                .map(|owner| owner == &spec.name)
                .unwrap_or(false)
        })
        .map(|(k, _)| MemberRef::new(&k.kind, &k.name))
        .collect()
}

/// Each declared member's live status: present (Healthy) or absent (Missing).
#[must_use]
pub fn member_statuses(view: &ResourceView, spec: &ResourceSetSpec) -> Vec<MemberStatus> {
    spec.members
        .iter()
        .map(|m| {
            let present = view.keys().any(|k| k.kind == m.kind && k.name == m.name);
            MemberStatus {
                reference: m.clone(),
                health: if present {
                    MemberHealth::Healthy
                } else {
                    MemberHealth::Missing
                },
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Defaults provenance + advisory (SHARED). The binary-shipped default bundle is
// a seed/offer, not a reconcile target (see `crate::defaults` +
// `specs/Defaults.tla`). These derive the two-axis model: SYNC stays declared<->
// live (above); the defaults advisory is a SEPARATE additive signal.
// ---------------------------------------------------------------------------

/// The provenance of a live member resource, read from its applied labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberOrigin {
    /// Seeded from the defaults bundle at the given version stamp.
    Defaults(String),
    /// Operator-authored (or provenance-stripped).
    Operator,
}

impl MemberOrigin {
    /// A compact tag for the CLI/console: `defaults@<v>` or `operator`.
    #[must_use]
    pub fn as_tag(&self) -> String {
        match self {
            MemberOrigin::Defaults(v) if v.is_empty() => "defaults".to_string(),
            MemberOrigin::Defaults(v) => format!("defaults@{v}"),
            MemberOrigin::Operator => "operator".to_string(),
        }
    }
}

/// Read a member's provenance from its applied labels: `defaults@<v>` when it
/// carries the defaults `managed-by` label, else `operator`.
#[must_use]
pub fn member_origin(view: &ResourceView, member: &MemberRef) -> MemberOrigin {
    for (k, env) in view {
        if k.kind == member.kind && k.name == member.name {
            let labels = &env.body().metadata.labels;
            if labels
                .get(defaults::DEFAULTS_MANAGED_BY_LABEL)
                .map(String::as_str)
                == Some(defaults::DEFAULTS_MANAGED_BY_VALUE)
            {
                let v = labels
                    .get(defaults::DEFAULT_BUNDLE_LABEL)
                    .cloned()
                    .unwrap_or_default();
                return MemberOrigin::Defaults(v);
            }
            return MemberOrigin::Operator;
        }
    }
    MemberOrigin::Operator
}

/// Compute the shipped-defaults advisory against the live view: classify each
/// shipped default as Present / Available / Edited / Tombstoned. `present` and
/// `edited` are read from the view (a `RetentionPolicy/<name>` exists; its
/// applied spec differs from the shipped spec by content); `tombstoned` is the
/// operator's recorded deletions (durable-deletion tracking is the follow-up
/// slice — callers pass the known set, empty when none).
#[must_use]
pub fn defaults_advisory_for_view(
    view: &ResourceView,
    tombstoned: &BTreeSet<String>,
) -> Vec<DefaultAdvisory> {
    let bundle = defaults::shipped_default_bundle();
    let mut present: BTreeSet<String> = BTreeSet::new();
    let mut edited: BTreeSet<String> = BTreeSet::new();
    for p in &bundle.policies {
        let applied = view
            .iter()
            .find(|(k, _)| k.kind == RETENTION_POLICY_KIND && k.name == p.name)
            .map(|(_, env)| env.render());
        if let Some(applied_crd) = applied {
            present.insert(p.name.to_string());
            // Content divergence: lower BOTH through the SAME manifest lowering
            // and compare the typed specs (ignores version/provenance labels).
            if let (Ok(a), Ok(s)) = (
                RetentionPolicySpec::from_crd(&applied_crd),
                RetentionPolicySpec::from_crd(&p.to_crd(bundle.version)),
            ) {
                if a != s {
                    edited.insert(p.name.to_string());
                }
            }
        }
    }
    defaults::defaults_advisory(&bundle, &present, &edited, tombstoned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_manifest::{Crd, Metadata};

    fn refs(items: &[(&str, &str)]) -> Vec<MemberRef> {
        items.iter().map(|(k, n)| MemberRef::new(*k, *n)).collect()
    }

    #[test]
    fn member_ref_parses_and_rejects_malformed() {
        assert_eq!(
            MemberRef::parse("RetentionPolicy/web-metrics").unwrap(),
            MemberRef::new("RetentionPolicy", "web-metrics")
        );
        // Whitespace is trimmed.
        assert_eq!(
            MemberRef::parse("  Job / nightly ").unwrap(),
            MemberRef::new("Job", "nightly")
        );
        assert!(MemberRef::parse("no-slash").is_err());
        assert!(MemberRef::parse("/empty-kind").is_err());
        assert!(MemberRef::parse("EmptyName/").is_err());
        assert!(MemberRef::parse("Too/many/slashes").is_err());
        assert_eq!(MemberRef::new("Job", "x").to_string(), "Job/x".to_string());
    }

    #[test]
    fn from_crd_lowers_members_and_description_dedups_and_skips_blanks() {
        let crd = Crd::new("pillar.dev/v1", "ResourceSet", Metadata::new("default"))
            .with_spec(
                "members",
                Value::String("RetentionPolicy/a, Job/b ,, RetentionPolicy/a , Dashboard/c".into()),
            )
            .with_spec("description", Value::String("the default set".into()));
        let spec = ResourceSetSpec::from_crd(&crd).expect("valid manifest lowers");
        assert_eq!(spec.name, "default");
        assert_eq!(spec.description.as_deref(), Some("the default set"));
        // De-duplicated (RetentionPolicy/a once), blanks skipped, order kept.
        assert_eq!(
            spec.members,
            refs(&[("RetentionPolicy", "a"), ("Job", "b"), ("Dashboard", "c"),])
        );
    }

    #[test]
    fn from_crd_accepts_an_empty_member_list_and_rejects_a_missing_field() {
        let empty = Crd::new("pillar.dev/v1", "ResourceSet", Metadata::new("default"))
            .with_spec("members", Value::String("".into()));
        let spec = ResourceSetSpec::from_crd(&empty).expect("empty members is a valid set");
        assert!(spec.members.is_empty());
        assert_eq!(spec.description, None);

        let missing = Crd::new("pillar.dev/v1", "ResourceSet", Metadata::new("x"));
        assert!(ResourceSetSpec::from_crd(&missing).is_err());
    }

    #[test]
    fn plan_reconcile_matches_the_tla_adopt_prune_synced_decision() {
        let declared = refs(&[("RetentionPolicy", "a"), ("Job", "b")]);
        let owned = refs(&[("Job", "b"), ("Dashboard", "old")]);
        let plan = plan_reconcile(&declared, &owned);
        // Adopt the declared-but-unowned (RetentionPolicy/a).
        assert_eq!(plan.to_adopt, refs(&[("RetentionPolicy", "a")]));
        // Prune the owned-but-undeclared (Dashboard/old).
        assert_eq!(plan.to_prune, refs(&[("Dashboard", "old")]));
        assert!(!plan.synced);
        assert_eq!(plan.sync_status(), SyncStatus::OutOfSync);

        // Owned == declared => Synced, nothing to do.
        let synced = plan_reconcile(&declared, &declared);
        assert!(synced.synced);
        assert!(synced.to_adopt.is_empty() && synced.to_prune.is_empty());
        assert_eq!(synced.sync_status(), SyncStatus::Synced);
    }

    #[test]
    fn health_rolls_up_empty_healthy_degraded() {
        assert_eq!(roll_up_health(&[]), SetHealth::Empty);
        assert_eq!(
            roll_up_health(&[MemberHealth::Healthy, MemberHealth::Healthy]),
            SetHealth::Healthy
        );
        assert_eq!(
            roll_up_health(&[MemberHealth::Healthy, MemberHealth::Missing]),
            SetHealth::Degraded
        );
        assert_eq!(
            roll_up_health(&[MemberHealth::Degraded]),
            SetHealth::Degraded
        );
    }

    #[test]
    fn graph_has_the_set_as_root_with_a_labeled_edge_per_member() {
        let members = vec![
            MemberStatus {
                reference: MemberRef::new("RetentionPolicy", "a"),
                health: MemberHealth::Healthy,
            },
            MemberStatus {
                reference: MemberRef::new("Job", "b"),
                health: MemberHealth::Missing,
            },
        ];
        let g = build_graph(
            "default",
            SetHealth::Degraded,
            SyncStatus::OutOfSync,
            &members,
            &BTreeMap::new(),
        );
        assert_eq!(
            g.nodes,
            vec![
                GraphNode::new("ResourceSet/default", "Degraded", "OutOfSync"),
                GraphNode::new("RetentionPolicy/a", "Healthy", "Healthy"),
                GraphNode::new("Job/b", "Missing", "Missing"),
            ]
        );
        assert_eq!(
            g.edges,
            vec![(0, 1, "Healthy".to_string()), (0, 2, "Missing".to_string()),]
        );
    }

    #[test]
    fn graph_descends_a_workload_member_into_its_live_replicas() {
        let members = vec![MemberStatus {
            reference: MemberRef::new(WORKLOAD_MEMBER_KIND, "web"),
            health: MemberHealth::Healthy,
        }];
        let mut replicas = BTreeMap::new();
        replicas.insert(
            "web".to_string(),
            vec![
                ReplicaNode {
                    label: "Replica/node-a:9001".to_string(),
                    health: "Healthy".to_string(),
                },
                ReplicaNode {
                    label: "Replica/node-b:9002".to_string(),
                    health: "Healthy".to_string(),
                },
            ],
        );
        let g = build_graph(
            "default",
            SetHealth::Healthy,
            SyncStatus::Synced,
            &members,
            &replicas,
        );
        assert_eq!(
            g.nodes,
            vec![
                GraphNode::new("ResourceSet/default", "Healthy", "Synced"),
                GraphNode::new("Workload/web", "Healthy", "Healthy"),
                GraphNode::new("Replica/node-a:9001", "Healthy", "Live"),
                GraphNode::new("Replica/node-b:9002", "Healthy", "Live"),
            ]
        );
        // Edge 0: set -> workload; edges 1,2: workload -> each replica.
        assert_eq!(
            g.edges,
            vec![
                (0, 1, "Healthy".to_string()),
                (1, 2, "Healthy".to_string()),
                (1, 3, "Healthy".to_string()),
            ]
        );
    }
}
