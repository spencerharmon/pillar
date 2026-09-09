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

use std::collections::BTreeSet;
use std::fmt;

use pillar_manifest::{Crd, Value};

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

/// The node-link graph the console renders for a ResourceSet: node 0 is the set
/// itself, nodes `1..=n` are its members (in `members` order), and each edge
/// runs from the set to a member labeled with the member's health. This is the
/// exact `(nodes, edges)` shape `pillar_web_frontend::primitives::Graph`
/// consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceGraph {
    pub nodes: Vec<String>,
    /// `(from_index, to_index, edge_label)`.
    pub edges: Vec<(usize, usize, String)>,
}

/// Derive the resource graph for one set from its member statuses.
#[must_use]
pub fn build_graph(set_name: &str, members: &[MemberStatus]) -> ResourceGraph {
    let mut nodes = Vec::with_capacity(members.len() + 1);
    nodes.push(format!("ResourceSet/{set_name}"));
    let mut edges = Vec::with_capacity(members.len());
    for (i, m) in members.iter().enumerate() {
        nodes.push(m.reference.to_string());
        edges.push((0, i + 1, m.health.as_str().to_string()));
    }
    ResourceGraph { nodes, edges }
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
        let g = build_graph("default", &members);
        assert_eq!(
            g.nodes,
            vec![
                "ResourceSet/default".to_string(),
                "RetentionPolicy/a".to_string(),
                "Job/b".to_string(),
            ]
        );
        assert_eq!(
            g.edges,
            vec![(0, 1, "Healthy".to_string()), (0, 2, "Missing".to_string()),]
        );
    }
}
