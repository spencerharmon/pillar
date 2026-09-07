//! Label-driven node grouping over a **config-ordered tier hierarchy**, with
//! self-declared (advisory) vs **attested** topology labels and the placement
//! payoff that hierarchy buys: failure-domain spread / anti-affinity, quorum
//! safety, per-tier telemetry rollups, and locality routing.
//!
//! # Model
//!
//! - [`TierHierarchy`] — the canonical, **ordered** list of tier names from
//!   the coarsest failure domain to the leaf. The default is
//!   `region > zone > site > room > cage > rack > chassis > node` (node the
//!   leaf), but the order is **CONFIG, never hardcoded**: an operator may
//!   [`TierHierarchy::reorder`] the tiers or [`TierHierarchy::insert_after`] a
//!   custom tier (`pdu`, `switch`, …) and every downstream computation —
//!   nesting, spread, rollups — respects the new order.
//! - [`Label`] — one `tier = value` assignment for a node (e.g. `rack = r7`).
//!   A node's [`Placement`] is the set of its labels, understood as a path
//!   down the hierarchy so nesting (which rack is in which zone) is known for
//!   failure-domain spread and rollups.
//! - **Self-declared vs attested.** A node may *declare* its own labels
//!   ([`Assignment::declared`]) — advisory only. A **cell authority** may
//!   *attest* a label ([`Assignment::attested`]) by reusing the exact
//!   [`pillar_trust_artifacts::Attest`] artifact (`subject = node`,
//!   predicate `topology:label` over `<tier>=<value>`) — no new signing
//!   primitive. [`Topology::verify_attested`] verifies the attestation's chain
//!   through the [`pillar_trust_artifacts::TrustStore`], and
//!   [`Topology::mismatches`] surfaces every **declared-vs-attested** mismatch
//!   so an operator sees where a node lies about its own placement.
//! - **Placement payoff.** [`PlacementPolicy`] lives ON a workload and
//!   references topology *tiers* (spread across `rack`, anti-affinity on
//!   `zone`, a failure-domain-aware quorum tier). A scheduler consumes the
//!   derived failure domains: [`Topology::spread`] places replicas across
//!   distinct values of a tier, [`Topology::quorum_is_safe`] refuses a quorum
//!   that lands entirely in one failure domain (never a quorum in one rack),
//!   and [`Topology::rollup`] aggregates a per-node leaf value up to any tier.
//!
//! Nothing here reaches the network or the filesystem; these are pure value
//! types. Attestation reuses `pillar_trust_artifacts` verbatim — the naming
//! plane adds no second trust primitive.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use pillar_core::NodeId;
use pillar_trust_artifacts::{Attest, Cid, Predicate, TrustStore};

/// The action string a topology-label [`Attest`] carries. A cell authority
/// signs "node N is in `<tier>=<value>`" as an attest whose predicate action
/// is exactly this and whose resource is `<tier>=<value>`.
pub const ATTEST_ACTION: &str = "topology:label";

/// A single `tier = value` topology assignment (e.g. `rack = r7`). The `tier`
/// must be a member of the active [`TierHierarchy`]; `value` names the
/// specific failure domain at that tier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Label {
    /// The hierarchy tier this label assigns (e.g. `"rack"`).
    pub tier: String,
    /// The value at that tier (e.g. `"r7"`).
    pub value: String,
}

impl Label {
    /// A label assigning `value` at `tier`.
    #[must_use]
    pub fn new(tier: impl Into<String>, value: impl Into<String>) -> Self {
        Label {
            tier: tier.into(),
            value: value.into(),
        }
    }

    /// The canonical `<tier>=<value>` resource string an [`Attest`] predicate
    /// carries for this label.
    #[must_use]
    pub fn resource(&self) -> String {
        format!("{}={}", self.tier, self.value)
    }

    /// Parse a `<tier>=<value>` resource string back into a [`Label`].
    #[must_use]
    pub fn from_resource(resource: &str) -> Option<Label> {
        let (tier, value) = resource.split_once('=')?;
        if tier.is_empty() || value.is_empty() {
            return None;
        }
        Some(Label::new(tier, value))
    }
}

/// The canonical, **ordered** tier hierarchy — coarsest failure domain first,
/// leaf last. Order is CONFIG: [`TierHierarchy::reorder`] and
/// [`TierHierarchy::insert_after`] let an operator add/reorder tiers without a
/// code change, and every nesting/spread/rollup computation reads THIS order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierHierarchy {
    tiers: Vec<String>,
}

/// Why a [`TierHierarchy`] mutation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TierError {
    /// A tier name referenced in the operation is not (or, for an insert,
    /// already is) a member of the hierarchy.
    UnknownTier(String),
    /// An insert whose new tier name already exists.
    DuplicateTier(String),
    /// A reorder whose set of tiers does not equal the current set (a tier was
    /// dropped or invented) — a reorder permutes, it never adds/removes.
    NotAPermutation,
}

impl Default for TierHierarchy {
    /// The default `region > zone > site > room > cage > rack > chassis >
    /// node` hierarchy (node the leaf).
    fn default() -> Self {
        TierHierarchy {
            tiers: [
                "region", "zone", "site", "room", "cage", "rack", "chassis", "node",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        }
    }
}

impl TierHierarchy {
    /// A hierarchy from an explicit ordered tier list (coarsest first, leaf
    /// last). Empty and duplicate tiers are rejected.
    #[must_use]
    pub fn from_order<I, S>(tiers: I) -> Option<TierHierarchy>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let tiers: Vec<String> = tiers.into_iter().map(Into::into).collect();
        if tiers.iter().any(String::is_empty) {
            return None;
        }
        let mut seen = BTreeSet::new();
        for t in &tiers {
            if !seen.insert(t.clone()) {
                return None;
            }
        }
        if tiers.is_empty() {
            return None;
        }
        Some(TierHierarchy { tiers })
    }

    /// The tiers in canonical order, coarsest first.
    #[must_use]
    pub fn tiers(&self) -> &[String] {
        &self.tiers
    }

    /// The leaf (finest) tier.
    #[must_use]
    pub fn leaf(&self) -> &str {
        self.tiers
            .last()
            .map(String::as_str)
            .expect("hierarchy is non-empty by construction")
    }

    /// The rank of `tier` (0 = coarsest), or `None` if not a member. A lower
    /// rank nests a higher one.
    #[must_use]
    pub fn rank(&self, tier: &str) -> Option<usize> {
        self.tiers.iter().position(|t| t == tier)
    }

    /// Whether `coarser` nests `finer` (strictly lower rank). Used to
    /// understand which failure domain contains another.
    #[must_use]
    pub fn nests(&self, coarser: &str, finer: &str) -> bool {
        match (self.rank(coarser), self.rank(finer)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        }
    }

    /// Reorder the hierarchy to `new_order`, which MUST be a permutation of
    /// the current tiers (a reorder never adds or drops a tier).
    pub fn reorder<I, S>(&mut self, new_order: I) -> Result<(), TierError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let new_order: Vec<String> = new_order.into_iter().map(Into::into).collect();
        let current: BTreeSet<&String> = self.tiers.iter().collect();
        let proposed: BTreeSet<&String> = new_order.iter().collect();
        if new_order.len() != self.tiers.len() || current != proposed {
            return Err(TierError::NotAPermutation);
        }
        self.tiers = new_order;
        Ok(())
    }

    /// Insert a new custom tier `tier` immediately after the existing tier
    /// `after` (e.g. `insert_after("rack", "pdu")`). Fails if `after` is not a
    /// member or `tier` already exists.
    pub fn insert_after(&mut self, after: &str, tier: impl Into<String>) -> Result<(), TierError> {
        let tier = tier.into();
        if self.tiers.iter().any(|t| t == &tier) {
            return Err(TierError::DuplicateTier(tier));
        }
        let Some(idx) = self.rank(after) else {
            return Err(TierError::UnknownTier(after.to_owned()));
        };
        self.tiers.insert(idx + 1, tier);
        Ok(())
    }
}

/// The provenance of a node's topology labels: self-declared (advisory) or
/// attested by a cell authority (reusing [`pillar_trust_artifacts`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assignment {
    /// The node declared these labels about itself — ADVISORY only, never a
    /// basis for safety-critical placement.
    Declared {
        /// The node the labels are about.
        node: NodeId,
        /// The self-declared `tier = value` labels.
        labels: Vec<Label>,
    },
    /// A cell authority attested one label about a node, carried as an
    /// [`Attest`] (`subject = node`, predicate [`ATTEST_ACTION`] over the
    /// label's `<tier>=<value>` resource). Its [`Cid`] lets a verifier walk
    /// the attestation chain through the [`TrustStore`].
    Attested {
        /// The underlying attest artifact.
        attest: Box<Attest>,
        /// Its content address (for chain verification).
        cid: Cid,
    },
}

impl Assignment {
    /// A self-declared (advisory) assignment.
    #[must_use]
    pub fn declared(node: impl Into<NodeId>, labels: Vec<Label>) -> Assignment {
        Assignment::Declared {
            node: node.into(),
            labels,
        }
    }

    /// Build an attested assignment: a cell `authority`-signed [`Attest`] that
    /// node `node` carries `label`, reusing the trust-artifact predicate shape
    /// (`topology:label` over `<tier>=<value>`). The `authority_proof` is the
    /// [`Cid`] of the prior grant proving the authority holds the signing
    /// capacity (`None` only for the genesis anchor).
    #[must_use]
    pub fn attested(
        authority: impl Into<NodeId>,
        node: impl Into<NodeId>,
        label: &Label,
        capacity: pillar_trust_artifacts::Capacity,
        authority_proof: Option<Cid>,
        scope: impl Into<String>,
        epoch: u64,
    ) -> Assignment {
        let attest = Attest {
            issuer: authority.into(),
            capacity,
            authority: authority_proof,
            subject: node.into(),
            predicate: Predicate::new(ATTEST_ACTION, label.resource()),
            scope: scope.into(),
            epoch,
            sig: pillar_trust_artifacts::Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let cid = attest.cid();
        Assignment::Attested {
            attest: Box::new(attest),
            cid,
        }
    }

    /// The node this assignment is about.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        match self {
            Assignment::Declared { node, .. } => node,
            Assignment::Attested { attest, .. } => &attest.subject,
        }
    }
}

/// A node's resolved placement: its `tier -> value` labels understood as a
/// path down the hierarchy.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Placement {
    labels: BTreeMap<String, String>,
}

impl Placement {
    /// The value assigned at `tier`, if any.
    #[must_use]
    pub fn at(&self, tier: &str) -> Option<&str> {
        self.labels.get(tier).map(String::as_str)
    }

    /// Every `tier = value` label, coarsest-tier-first per the hierarchy.
    #[must_use]
    pub fn path(&self, hierarchy: &TierHierarchy) -> Vec<Label> {
        hierarchy
            .tiers()
            .iter()
            .filter_map(|t| self.at(t).map(|v| Label::new(t.clone(), v.to_owned())))
            .collect()
    }
}

/// A declared-vs-attested disagreement about one tier's value for one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The node whose placement disagrees.
    pub node: NodeId,
    /// The tier at which declared and attested values differ.
    pub tier: String,
    /// The value the node declared for itself (advisory).
    pub declared: String,
    /// The value the cell authority attested (authoritative).
    pub attested: String,
}

/// A workload's placement policy, referencing topology *tiers* (never node
/// ids). The scheduler consumes the derived failure domains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementPolicy {
    /// Spread replicas across DISTINCT values of this tier (e.g. `"rack"`).
    pub spread_tier: Option<String>,
    /// No two replicas may share a value at this tier (anti-affinity).
    pub anti_affinity_tier: Option<String>,
    /// A quorum must span more than one distinct value of this tier — never a
    /// quorum in a single failure domain (e.g. `"rack"`).
    pub quorum_tier: Option<String>,
}

impl PlacementPolicy {
    /// An empty policy (no constraints).
    #[must_use]
    pub fn new() -> Self {
        PlacementPolicy {
            spread_tier: None,
            anti_affinity_tier: None,
            quorum_tier: None,
        }
    }

    /// Reference a spread tier, builder-style.
    #[must_use]
    pub fn spread_across(mut self, tier: impl Into<String>) -> Self {
        self.spread_tier = Some(tier.into());
        self
    }

    /// Reference an anti-affinity tier, builder-style.
    #[must_use]
    pub fn anti_affinity(mut self, tier: impl Into<String>) -> Self {
        self.anti_affinity_tier = Some(tier.into());
        self
    }

    /// Reference a failure-domain quorum tier, builder-style.
    #[must_use]
    pub fn quorum_over(mut self, tier: impl Into<String>) -> Self {
        self.quorum_tier = Some(tier.into());
        self
    }
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        PlacementPolicy::new()
    }
}

/// Why a placement request could not be satisfied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementError {
    /// The policy references a tier not in the active hierarchy.
    UnknownTier(String),
    /// Not enough distinct failure domains at the requested tier to place the
    /// requested number of replicas / satisfy anti-affinity.
    InsufficientDomains {
        /// The tier over which spread was requested.
        tier: String,
        /// Distinct domains available at that tier.
        available: usize,
        /// Replicas requested.
        requested: usize,
    },
}

/// The topology registry: the active [`TierHierarchy`], the resolved
/// [`Placement`] per node (attested labels take precedence over declared for
/// safety-critical decisions), and the raw declared/attested assignments so
/// mismatches can be surfaced.
#[derive(Clone, Debug)]
pub struct Topology {
    hierarchy: TierHierarchy,
    declared: HashMap<NodeId, BTreeMap<String, String>>,
    attested: HashMap<NodeId, BTreeMap<String, String>>,
}

impl Topology {
    /// A fresh topology over `hierarchy`, with no assignments.
    #[must_use]
    pub fn new(hierarchy: TierHierarchy) -> Self {
        Topology {
            hierarchy,
            declared: HashMap::new(),
            attested: HashMap::new(),
        }
    }

    /// The active tier hierarchy.
    #[must_use]
    pub fn hierarchy(&self) -> &TierHierarchy {
        &self.hierarchy
    }

    /// Mutable access to the tier hierarchy, so an operator can reorder / add
    /// tiers at runtime (config-driven order).
    pub fn hierarchy_mut(&mut self) -> &mut TierHierarchy {
        &mut self.hierarchy
    }

    /// Record a **self-declared** (advisory) assignment. Labels naming a tier
    /// outside the hierarchy are ignored.
    pub fn declare(&mut self, node: impl Into<NodeId>, labels: &[Label]) {
        let node = node.into();
        let entry = self.declared.entry(node).or_default();
        for l in labels {
            if self.hierarchy.rank(&l.tier).is_some() {
                entry.insert(l.tier.clone(), l.value.clone());
            }
        }
    }

    /// Record an **attested** assignment, VERIFYING its chain through `store`
    /// first: the attest must carry the [`ATTEST_ACTION`] predicate and its
    /// authority chain must verify (non-revoked, terminating at genesis). A
    /// label naming a tier outside the hierarchy, a wrong action, or a broken
    /// chain is refused.
    pub fn attest(
        &mut self,
        assignment: &Assignment,
        store: &TrustStore,
    ) -> Result<(), TopologyError> {
        let Assignment::Attested { attest, cid } = assignment else {
            return Err(TopologyError::NotAttested);
        };
        if attest.predicate.action != ATTEST_ACTION {
            return Err(TopologyError::WrongAction(attest.predicate.action.clone()));
        }
        let Some(label) = Label::from_resource(&attest.predicate.resource) else {
            return Err(TopologyError::MalformedLabel(
                attest.predicate.resource.clone(),
            ));
        };
        if self.hierarchy.rank(&label.tier).is_none() {
            return Err(TopologyError::UnknownTier(label.tier));
        }
        store
            .verify(cid)
            .map_err(|_| TopologyError::UnverifiedAttestation(cid.clone()))?;
        self.attested
            .entry(attest.subject.clone())
            .or_default()
            .insert(label.tier, label.value);
        Ok(())
    }

    /// Whether the attestation `assignment` verifies through `store` — a pure
    /// read used to gate safety-critical placement on attested labels.
    #[must_use]
    pub fn verify_attested(&self, assignment: &Assignment, store: &TrustStore) -> bool {
        matches!(assignment, Assignment::Attested { cid, .. } if store.verify(cid).is_ok())
    }

    /// A node's resolved [`Placement`]: attested labels take precedence over
    /// declared ones (safety-critical decisions trust the authority, not the
    /// node's self-report), falling back to declared where no attestation
    /// exists.
    #[must_use]
    pub fn placement(&self, node: &NodeId) -> Placement {
        let mut labels = BTreeMap::new();
        if let Some(d) = self.declared.get(node) {
            for (t, v) in d {
                labels.insert(t.clone(), v.clone());
            }
        }
        if let Some(a) = self.attested.get(node) {
            for (t, v) in a {
                labels.insert(t.clone(), v.clone());
            }
        }
        Placement { labels }
    }

    /// The **attested-only** placement (ignores self-declared labels) — the
    /// view safety-critical placement uses.
    #[must_use]
    pub fn attested_placement(&self, node: &NodeId) -> Placement {
        Placement {
            labels: self.attested.get(node).cloned().unwrap_or_default(),
        }
    }

    /// Every declared-vs-attested [`Mismatch`]: for each node and tier where
    /// the node declared one value but the authority attested a different one,
    /// one mismatch is surfaced (attested is authoritative).
    #[must_use]
    pub fn mismatches(&self) -> Vec<Mismatch> {
        let mut out = Vec::new();
        for (node, declared) in &self.declared {
            let Some(attested) = self.attested.get(node) else {
                continue;
            };
            for (tier, dval) in declared {
                if let Some(aval) = attested.get(tier) {
                    if aval != dval {
                        out.push(Mismatch {
                            node: node.clone(),
                            tier: tier.clone(),
                            declared: dval.clone(),
                            attested: aval.clone(),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            (a.node.0.as_str(), a.tier.as_str()).cmp(&(b.node.0.as_str(), b.tier.as_str()))
        });
        out
    }

    /// The distinct failure domains (values) present at `tier` across `nodes`,
    /// using attested-then-declared placement. Empty if the tier is unknown.
    #[must_use]
    pub fn domains_at(&self, tier: &str, nodes: &[NodeId]) -> BTreeSet<String> {
        if self.hierarchy.rank(tier).is_none() {
            return BTreeSet::new();
        }
        nodes
            .iter()
            .filter_map(|n| self.placement(n).at(tier).map(str::to_owned))
            .collect()
    }

    /// **Spread**: pick up to `replicas` nodes from `candidates` landing on
    /// DISTINCT values of `policy.spread_tier` (failure-domain spread /
    /// anti-affinity). Refuses (`InsufficientDomains`) if fewer distinct
    /// domains exist than replicas requested. Returns the chosen node ids.
    pub fn spread(
        &self,
        candidates: &[NodeId],
        replicas: usize,
        tier: &str,
    ) -> Result<Vec<NodeId>, PlacementError> {
        if self.hierarchy.rank(tier).is_none() {
            return Err(PlacementError::UnknownTier(tier.to_owned()));
        }
        let mut used: BTreeSet<String> = BTreeSet::new();
        let mut chosen = Vec::new();
        for n in candidates {
            let Some(domain) = self.placement(n).at(tier).map(str::to_owned) else {
                continue;
            };
            if used.insert(domain) {
                chosen.push(n.clone());
                if chosen.len() == replicas {
                    return Ok(chosen);
                }
            }
        }
        if chosen.len() < replicas {
            return Err(PlacementError::InsufficientDomains {
                tier: tier.to_owned(),
                available: used.len(),
                requested: replicas,
            });
        }
        Ok(chosen)
    }

    /// **Quorum safety**: a set of quorum members is safe iff it does NOT land
    /// entirely within a single failure domain at `tier` — a quorum must span
    /// more than one distinct value (never a quorum in one rack). A single
    /// member, or members with no label at that tier, is treated
    /// conservatively as unsafe unless it genuinely spans ≥2 domains.
    #[must_use]
    pub fn quorum_is_safe(&self, members: &[NodeId], tier: &str) -> bool {
        if self.hierarchy.rank(tier).is_none() {
            return false;
        }
        let domains = self.domains_at(tier, members);
        // Every member must carry a label at the tier AND span ≥2 domains.
        let all_labeled = members.iter().all(|n| self.placement(n).at(tier).is_some());
        all_labeled && domains.len() >= 2
    }

    /// **Per-tier rollup**: aggregate a per-node leaf `value` up to `tier` by
    /// summing every node's value into the failure domain (tier value) that
    /// contains it. Nodes with no label at `tier` are grouped under the empty
    /// key `""`. Uses attested-then-declared placement.
    #[must_use]
    pub fn rollup(&self, tier: &str, values: &[(NodeId, u64)]) -> BTreeMap<String, u64> {
        let mut out: BTreeMap<String, u64> = BTreeMap::new();
        if self.hierarchy.rank(tier).is_none() {
            return out;
        }
        for (node, v) in values {
            let domain = self
                .placement(node)
                .at(tier)
                .map(str::to_owned)
                .unwrap_or_default();
            *out.entry(domain).or_insert(0) += *v;
        }
        out
    }
}

/// Why recording an attested assignment on a [`Topology`] was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologyError {
    /// The assignment was self-declared, not attested — [`Topology::attest`]
    /// requires an attested one.
    NotAttested,
    /// The attest's predicate action is not [`ATTEST_ACTION`].
    WrongAction(String),
    /// The attest's resource is not a `<tier>=<value>` label.
    MalformedLabel(String),
    /// The attest names a tier outside the active hierarchy.
    UnknownTier(String),
    /// The attestation's chain does not verify through the trust store
    /// (broken, cyclic, or revoked).
    UnverifiedAttestation(Cid),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_trust_artifacts::{Capacity, Sig};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn role(r: &str, s: &str) -> Capacity {
        Capacity::Role {
            role: r.to_owned(),
            scope: s.to_owned(),
        }
    }

    // --- config-driven tier order: reorder / add a tier respected ----------

    #[test]
    fn default_hierarchy_is_region_to_node_leaf() {
        let h = TierHierarchy::default();
        assert_eq!(h.tiers().first().unwrap(), "region");
        assert_eq!(h.leaf(), "node");
        assert!(h.nests("region", "rack"));
        assert!(h.nests("rack", "node"));
        assert!(!h.nests("node", "rack"));
    }

    #[test]
    fn reorder_permutes_and_downstream_nesting_respects_new_order() {
        let mut h = TierHierarchy::from_order(["region", "zone", "rack", "node"]).unwrap();
        // A reorder that is not a permutation is refused.
        assert_eq!(
            h.reorder(["region", "zone", "rack"]),
            Err(TierError::NotAPermutation)
        );
        assert_eq!(
            h.reorder(["region", "zone", "rack", "node", "extra"]),
            Err(TierError::NotAPermutation)
        );
        // A genuine permutation swaps zone/rack nesting.
        assert!(h.nests("zone", "rack"));
        h.reorder(["region", "rack", "zone", "node"]).unwrap();
        assert!(h.nests("rack", "zone"));
        assert!(!h.nests("zone", "rack"));
    }

    #[test]
    fn insert_after_adds_a_custom_tier_respected_by_nesting() {
        let mut h = TierHierarchy::from_order(["zone", "rack", "node"]).unwrap();
        h.insert_after("rack", "pdu").unwrap();
        assert_eq!(h.tiers(), &["zone", "rack", "pdu", "node"]);
        assert!(h.nests("rack", "pdu"));
        assert!(h.nests("pdu", "node"));
        // Duplicate / unknown anchor refused.
        assert_eq!(
            h.insert_after("rack", "pdu"),
            Err(TierError::DuplicateTier("pdu".to_owned()))
        );
        assert_eq!(
            h.insert_after("nope", "switch"),
            Err(TierError::UnknownTier("nope".to_owned()))
        );
    }

    // --- attested label verifies + declared-vs-attested mismatch surfaced --

    fn attest_label(
        store: &mut TrustStore,
        authority: &NodeId,
        node: &NodeId,
        label: &Label,
    ) -> Assignment {
        // Grant the authority the signing capacity from genesis.
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("cell-authority", "cell-b"),
            authority: None,
            subject: authority.clone(),
            predicate: Predicate::new("topology:sign", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let grant_cid = store.issue_attest(grant).unwrap();
        let a = Assignment::attested(
            authority.clone(),
            node.clone(),
            label,
            role("cell-authority", "cell-b"),
            Some(grant_cid),
            "cell-b",
            store.epoch(),
        );
        if let Assignment::Attested { attest, .. } = &a {
            store.issue_attest((**attest).clone()).unwrap();
        }
        a
    }

    #[test]
    fn attested_label_verifies_and_is_recorded() {
        let mut store = TrustStore::new(n("owner"));
        let mut topo = Topology::new(TierHierarchy::default());
        let auth = n("cell-b-authority");
        let node = n("node-7");
        let label = Label::new("rack", "r7");
        let assignment = attest_label(&mut store, &auth, &node, &label);

        assert!(topo.verify_attested(&assignment, &store));
        topo.attest(&assignment, &store)
            .expect("verifies + recorded");
        assert_eq!(topo.attested_placement(&node).at("rack"), Some("r7"));
    }

    #[test]
    fn unverified_attestation_is_refused() {
        let store = TrustStore::new(n("owner"));
        let mut topo = Topology::new(TierHierarchy::default());
        // An attest whose authority chain was never issued into the store.
        let assignment = Assignment::attested(
            n("rogue"),
            n("node-9"),
            &Label::new("rack", "r9"),
            role("cell-authority", "cell-b"),
            Some(Cid("trust:phantom".to_owned())),
            "cell-b",
            0,
        );
        assert!(!topo.verify_attested(&assignment, &store));
        assert!(matches!(
            topo.attest(&assignment, &store),
            Err(TopologyError::UnverifiedAttestation(_))
        ));
    }

    #[test]
    fn declared_vs_attested_mismatch_is_surfaced() {
        let mut store = TrustStore::new(n("owner"));
        let mut topo = Topology::new(TierHierarchy::default());
        let node = n("node-7");
        // Node lies: declares rack r99.
        topo.declare(node.clone(), &[Label::new("rack", "r99")]);
        // Authority attests the truth: rack r7.
        let assignment = attest_label(&mut store, &n("auth"), &node, &Label::new("rack", "r7"));
        topo.attest(&assignment, &store).unwrap();

        let mm = topo.mismatches();
        assert_eq!(mm.len(), 1);
        assert_eq!(mm[0].node, node);
        assert_eq!(mm[0].tier, "rack");
        assert_eq!(mm[0].declared, "r99");
        assert_eq!(mm[0].attested, "r7");
        // Safety-critical placement uses the attested value, not the lie.
        assert_eq!(topo.placement(&node).at("rack"), Some("r7"));
    }

    #[test]
    fn no_mismatch_when_declared_matches_attested() {
        let mut store = TrustStore::new(n("owner"));
        let mut topo = Topology::new(TierHierarchy::default());
        let node = n("node-7");
        topo.declare(node.clone(), &[Label::new("rack", "r7")]);
        let assignment = attest_label(&mut store, &n("auth"), &node, &Label::new("rack", "r7"));
        topo.attest(&assignment, &store).unwrap();
        assert!(topo.mismatches().is_empty());
    }

    // --- spread / anti-affinity across distinct racks; quorum safety -------

    fn labeled_topo() -> Topology {
        let mut topo = Topology::new(TierHierarchy::default());
        topo.declare(
            n("a"),
            &[Label::new("rack", "r1"), Label::new("zone", "z1")],
        );
        topo.declare(
            n("b"),
            &[Label::new("rack", "r1"), Label::new("zone", "z1")],
        );
        topo.declare(
            n("c"),
            &[Label::new("rack", "r2"), Label::new("zone", "z1")],
        );
        topo.declare(
            n("d"),
            &[Label::new("rack", "r3"), Label::new("zone", "z2")],
        );
        topo
    }

    #[test]
    fn spread_places_replicas_across_distinct_racks() {
        let topo = labeled_topo();
        let chosen = topo
            .spread(&[n("a"), n("b"), n("c"), n("d")], 3, "rack")
            .expect("3 distinct racks available");
        // a(r1), then b(r1) skipped, c(r2), d(r3).
        assert_eq!(chosen, vec![n("a"), n("c"), n("d")]);
        // Distinct racks.
        let racks: BTreeSet<_> = chosen
            .iter()
            .map(|nd| topo.placement(nd).at("rack").unwrap().to_owned())
            .collect();
        assert_eq!(racks.len(), 3);
    }

    #[test]
    fn spread_refuses_when_too_few_distinct_domains() {
        let topo = labeled_topo();
        // Only racks r1 present among a,b -> cannot place 2 distinct.
        assert_eq!(
            topo.spread(&[n("a"), n("b")], 2, "rack"),
            Err(PlacementError::InsufficientDomains {
                tier: "rack".to_owned(),
                available: 1,
                requested: 2,
            })
        );
        assert_eq!(
            topo.spread(&[n("a")], 1, "nonexistent-tier"),
            Err(PlacementError::UnknownTier("nonexistent-tier".to_owned()))
        );
    }

    #[test]
    fn quorum_refused_when_all_in_one_rack() {
        let topo = labeled_topo();
        // a,b both in r1 -> a quorum in one rack is unsafe.
        assert!(!topo.quorum_is_safe(&[n("a"), n("b")], "rack"));
        // a(r1), c(r2), d(r3) spans three racks -> safe.
        assert!(topo.quorum_is_safe(&[n("a"), n("c"), n("d")], "rack"));
    }

    // --- per-tier rollup aggregates leaf values ----------------------------

    #[test]
    fn rollup_aggregates_leaf_values_by_tier() {
        let topo = labeled_topo();
        let values = vec![(n("a"), 10), (n("b"), 5), (n("c"), 7), (n("d"), 3)];
        // By rack: r1 = a+b = 15, r2 = c = 7, r3 = d = 3.
        let by_rack = topo.rollup("rack", &values);
        assert_eq!(by_rack.get("r1"), Some(&15));
        assert_eq!(by_rack.get("r2"), Some(&7));
        assert_eq!(by_rack.get("r3"), Some(&3));
        // By zone: z1 = a+b+c = 22, z2 = d = 3.
        let by_zone = topo.rollup("zone", &values);
        assert_eq!(by_zone.get("z1"), Some(&22));
        assert_eq!(by_zone.get("z2"), Some(&3));
    }

    // --- placement policy references tiers + scheduler consumes them -------

    #[test]
    fn placement_policy_references_tiers_and_scheduler_consumes_them() {
        let topo = labeled_topo();
        // Policy lives on the workload and references tiers by name only.
        let policy = PlacementPolicy::new()
            .spread_across("rack")
            .anti_affinity("rack")
            .quorum_over("rack");

        // Scheduler consumes the failure domains derived from the policy's
        // referenced tiers.
        let spread_tier = policy.spread_tier.as_deref().unwrap();
        let chosen = topo
            .spread(&[n("a"), n("b"), n("c"), n("d")], 3, spread_tier)
            .unwrap();
        assert_eq!(chosen.len(), 3);
        // Anti-affinity: no two chosen share the tier value.
        let domains: BTreeSet<_> = chosen
            .iter()
            .map(|nd| {
                topo.placement(nd)
                    .at(policy.anti_affinity_tier.as_deref().unwrap())
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(domains.len(), chosen.len());
        // Quorum over the referenced tier must span >1 domain.
        assert!(topo.quorum_is_safe(&chosen, policy.quorum_tier.as_deref().unwrap()));
    }

    #[test]
    fn reordered_hierarchy_changes_rollup_grouping_at_runtime() {
        // Config-driven order is honored by placement/rollup post-reorder.
        let mut topo = Topology::new(TierHierarchy::from_order(["zone", "rack", "node"]).unwrap());
        topo.hierarchy_mut().insert_after("rack", "pdu").unwrap();
        topo.declare(n("x"), &[Label::new("pdu", "p1")]);
        topo.declare(n("y"), &[Label::new("pdu", "p1")]);
        topo.declare(n("z"), &[Label::new("pdu", "p2")]);
        let values = vec![(n("x"), 2), (n("y"), 3), (n("z"), 4)];
        let by_pdu = topo.rollup("pdu", &values);
        assert_eq!(by_pdu.get("p1"), Some(&5));
        assert_eq!(by_pdu.get("p2"), Some(&4));
    }
}
