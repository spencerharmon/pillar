//! Data placement — the collection is the pinning boundary, selected over
//! node tags (ROI Priority 1, operator 2026-09-14; `pillar-data-layer`
//! design §6).
//!
//! A [`CollectionPlacement`] binds one collection (a plain collection name,
//! the same `(collection, id)` key every data-layer API uses) to a
//! [`NodeSelector`] over node TAGS. The selector reuses the EXISTING attested
//! topology-label machinery ([`pillar_topology::Topology`] /
//! [`pillar_topology::Label`]) — the same `tier=value` node tags RBAC policy
//! targeting already selects on — so this introduces **no new tagging
//! mechanism**. A tag `(tier, value)` matches a node iff that node carries the
//! value at that tier; multiple tags AND together (subset semantics, mirroring
//! [`pillar_rbac`]'s `LabelSet::matches` `is_subset`).
//!
//! Placement narrows the subscribing + IPFS-pinning node set **within a
//! cell** — the cell stays the confidentiality/replication boundary and there
//! is NO separate replication-factor / `minReplicas` knob (design §6.2/§6.5):
//!
//! * An **empty / omitted** selector ⇒ every cell node (the default:
//!   whole-cell placement).
//! * A **non-empty** selector narrows to the cell nodes matching every tag.
//!
//! The final node-set is therefore `selector-match ∩ cell-members`: the caller
//! supplies the cell's member node-set (`cell_members`) — placement can only
//! ever narrow it, never widen it or cross a cell boundary.
//!
//! Tag matching reads [`Topology::attested_placement`] EXCLUSIVELY, never
//! [`Topology::placement`] (which falls back to self-declared labels a node
//! could lie about) — identical to the safety rule
//! [`crate::hop_metric`] follows for placement-facing rollups.
//!
//! A materialized view is servable on a node iff that node pins ALL the view's
//! source collections; [`view_placement`] expands a view's placement to the
//! INTERSECTION of its sources' node-sets, so a node never holds a view
//! without every collection the view reads.

use pillar_core::NodeId;
use pillar_topology::{Label, Topology};
use std::collections::BTreeSet;

/// A selector over node TAGS (attested topology `tier=value` labels).
///
/// An empty selector (no tags) means "every cell node" — the whole-cell
/// default. A non-empty selector narrows to nodes carrying EVERY listed tag
/// (AND / subset semantics), reusing the existing attested topology-label
/// machinery rather than any new tagging mechanism.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeSelector {
    /// The tags a node must ALL carry to match. Deduplicated and order-
    /// independent (a `BTreeSet`), so `{role=db, region=eu}` selects the same
    /// set regardless of insertion order.
    tags: BTreeSet<Label>,
}

impl NodeSelector {
    /// The empty selector — matches every cell node (whole-cell default).
    #[must_use]
    pub fn whole_cell() -> Self {
        NodeSelector {
            tags: BTreeSet::new(),
        }
    }

    /// A selector requiring every one of `tags`.
    #[must_use]
    pub fn new(tags: impl IntoIterator<Item = Label>) -> Self {
        NodeSelector {
            tags: tags.into_iter().collect(),
        }
    }

    /// Whether this selector is empty (⇒ whole-cell placement).
    #[must_use]
    pub fn is_whole_cell(&self) -> bool {
        self.tags.is_empty()
    }

    /// The required tags, in canonical (sorted) order.
    #[must_use]
    pub fn tags(&self) -> &BTreeSet<Label> {
        &self.tags
    }

    /// Add a required tag, returning the extended selector (builder style).
    #[must_use]
    pub fn with_tag(mut self, tier: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(Label::new(tier, value));
        self
    }

    /// Whether `node` matches this selector, judged against its ATTESTED
    /// topology placement in `topology` (never its self-declared labels).
    ///
    /// An empty selector matches every node. A non-empty selector matches iff
    /// the node carries the attested `value` at EVERY tag's `tier`.
    #[must_use]
    pub fn matches(&self, topology: &Topology, node: &NodeId) -> bool {
        if self.tags.is_empty() {
            return true;
        }
        let placement = topology.attested_placement(node);
        self.tags
            .iter()
            .all(|tag| placement.at(&tag.tier) == Some(tag.value.as_str()))
    }
}

/// The placement rule for one collection: which cell nodes subscribe to and
/// IPFS-pin it, expressed as a [`NodeSelector`] over node tags.
///
/// The `collection` is a plain collection name (`app.users`) — the same key
/// component every keyed-store / op-stream API uses. Resolving the placement
/// against a cell's member set (via [`CollectionPlacement::node_set`]) yields
/// the exact node-set that holds the collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionPlacement {
    collection: String,
    selector: NodeSelector,
}

impl CollectionPlacement {
    /// A placement binding `collection` to `selector`.
    #[must_use]
    pub fn new(collection: impl Into<String>, selector: NodeSelector) -> Self {
        CollectionPlacement {
            collection: collection.into(),
            selector,
        }
    }

    /// The default whole-cell placement for `collection` (empty selector) —
    /// every cell node pins it. This is the ROI default: "every collection on
    /// every cell node".
    #[must_use]
    pub fn whole_cell(collection: impl Into<String>) -> Self {
        CollectionPlacement::new(collection, NodeSelector::whole_cell())
    }

    /// The collection name this placement governs.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// The tag selector.
    #[must_use]
    pub fn selector(&self) -> &NodeSelector {
        &self.selector
    }

    /// The node-set that subscribes to + pins this collection: the cell
    /// members matching the selector, i.e. `selector-match ∩ cell_members`.
    ///
    /// `cell_members` is the collection's cell membership (the confidentiality
    /// boundary). Placement can only NARROW it — a node outside the cell is
    /// never returned, and an empty selector returns the whole cell. Matching
    /// reads ATTESTED topology labels only.
    #[must_use]
    pub fn node_set(
        &self,
        topology: &Topology,
        cell_members: &BTreeSet<NodeId>,
    ) -> BTreeSet<NodeId> {
        cell_members
            .iter()
            .filter(|node| self.selector.matches(topology, node))
            .cloned()
            .collect()
    }

    /// The live count of participating nodes (for CLI/UI surfacing), computed
    /// as the size of [`node_set`](Self::node_set).
    #[must_use]
    pub fn participant_count(
        &self,
        topology: &Topology,
        cell_members: &BTreeSet<NodeId>,
    ) -> usize {
        self.node_set(topology, cell_members).len()
    }
}

/// The node-set on which a materialized view is servable: the INTERSECTION of
/// its source collections' node-sets.
///
/// A view is servable on a node iff that node pins ALL the view's source
/// collections (design §6) — placing/serving a view expands to pinning its
/// sources on the same node-set, so a node never holds a view without every
/// collection it reads. With no sources the view is servable nowhere (an empty
/// set), never everywhere.
#[must_use]
pub fn view_placement<'a>(
    sources: impl IntoIterator<Item = &'a CollectionPlacement>,
    topology: &Topology,
    cell_members: &BTreeSet<NodeId>,
) -> BTreeSet<NodeId> {
    let mut iter = sources.into_iter();
    let Some(first) = iter.next() else {
        return BTreeSet::new();
    };
    let mut acc = first.node_set(topology, cell_members);
    for source in iter {
        let next = source.node_set(topology, cell_members);
        acc = acc.intersection(&next).cloned().collect();
        if acc.is_empty() {
            break;
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_topology::{Assignment, TierHierarchy};
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};

    /// Genesis-self-issue an ATTESTED `tier=value` topology label onto `node`
    /// (the exact attested-tag fixture `hop_metric.rs` uses).
    fn attest_tier(
        topology: &mut Topology,
        store: &mut TrustStore,
        node: &str,
        tier: &str,
        value: &str,
    ) {
        let label = Label::new(tier, value);
        let attest = Attest {
            issuer: store.genesis().clone(),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: NodeId::from(node),
            predicate: Predicate::new(pillar_topology::ATTEST_ACTION, label.resource()),
            scope: "default".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let cid = store
            .issue_attest(attest.clone())
            .expect("genesis self-issue succeeds");
        let assignment = Assignment::Attested {
            attest: Box::new(attest),
            cid,
        };
        topology
            .attest(&assignment, store)
            .expect("attestation verifies through the store");
    }

    fn members(nodes: &[&str]) -> BTreeSet<NodeId> {
        nodes.iter().map(|n| NodeId::from(*n)).collect()
    }

    fn node_topology() -> (Topology, TrustStore) {
        let mut trust = TrustStore::new(NodeId::from("genesis"));
        let mut topology = Topology::new(TierHierarchy::default());
        // Tags are real hierarchy tiers (`region`, `zone`). db-* nodes sit in
        // the `db` zone; the two db nodes are in different regions. web-eu is a
        // separate zone; "plain" carries no attested labels at all.
        attest_tier(&mut topology, &mut trust, "db-eu", "region", "eu");
        attest_tier(&mut topology, &mut trust, "db-eu", "zone", "db");
        attest_tier(&mut topology, &mut trust, "db-us", "region", "us");
        attest_tier(&mut topology, &mut trust, "db-us", "zone", "db");
        attest_tier(&mut topology, &mut trust, "web-eu", "region", "eu");
        attest_tier(&mut topology, &mut trust, "web-eu", "zone", "web");
        (topology, trust)
    }

    /// The ROI default: an empty selector places a collection on EVERY cell
    /// node, and never on a node outside the cell.
    #[test]
    fn data_placement_collection_tags_empty_selector_is_whole_cell() {
        let (topology, _trust) = node_topology();
        let cell = members(&["db-eu", "db-us", "web-eu", "plain"]);
        let placement = CollectionPlacement::whole_cell("app.users");

        assert!(placement.selector().is_whole_cell());
        assert_eq!(placement.node_set(&topology, &cell), cell);
        assert_eq!(placement.participant_count(&topology, &cell), 4);

        // A node outside the cell is never placed, even with an empty selector.
        let smaller = members(&["db-eu", "db-us"]);
        assert_eq!(placement.node_set(&topology, &smaller), smaller);
    }

    /// A non-empty selector narrows to the cell nodes carrying EVERY tag
    /// (AND / subset semantics).
    #[test]
    fn data_placement_collection_tags_selector_narrows_within_cell() {
        let (topology, _trust) = node_topology();
        let cell = members(&["db-eu", "db-us", "web-eu", "plain"]);

        // role=db ⇒ both db nodes.
        let db = CollectionPlacement::new(
            "app.users",
            NodeSelector::whole_cell().with_tag("zone", "db"),
        );
        assert_eq!(db.node_set(&topology, &cell), members(&["db-eu", "db-us"]));

        // role=db AND region=eu ⇒ only db-eu (tags AND together).
        let db_eu = CollectionPlacement::new(
            "app.users",
            NodeSelector::new([Label::new("zone", "db"), Label::new("region", "eu")]),
        );
        assert_eq!(db_eu.node_set(&topology, &cell), members(&["db-eu"]));
        assert_eq!(db_eu.participant_count(&topology, &cell), 1);
    }

    /// Placement only NARROWS within a cell: a selector matching a node that
    /// is NOT a cell member never places on it (cell stays the boundary).
    #[test]
    fn data_placement_collection_tags_never_crosses_cell_boundary() {
        let (topology, _trust) = node_topology();
        // db-us matches role=db but is NOT in this cell.
        let cell = members(&["db-eu", "web-eu", "plain"]);
        let db = CollectionPlacement::new(
            "app.users",
            NodeSelector::whole_cell().with_tag("zone", "db"),
        );
        assert_eq!(
            db.node_set(&topology, &cell),
            members(&["db-eu"]),
            "db-us matches the selector but is outside the cell — never placed"
        );
    }

    /// Selection reads ATTESTED labels only: a node self-DECLARING a matching
    /// tag is NOT placed (it could lie its way onto a placement otherwise).
    #[test]
    fn data_placement_collection_tags_uses_attested_labels_only() {
        let (mut topology, _trust) = node_topology();
        // "plain" lies via a self-declared label; it must never match.
        topology.declare(NodeId::from("plain"), &[Label::new("zone", "db")]);
        let cell = members(&["db-eu", "plain"]);
        let db = CollectionPlacement::new(
            "app.users",
            NodeSelector::whole_cell().with_tag("zone", "db"),
        );
        assert_eq!(
            db.node_set(&topology, &cell),
            members(&["db-eu"]),
            "ATTESTED label used, never the lying self-declared one"
        );
    }

    /// A materialized view is servable only where ALL its source collections
    /// are pinned: the view node-set is the INTERSECTION of its sources'.
    #[test]
    fn data_placement_collection_tags_view_is_intersection_of_sources() {
        let (topology, _trust) = node_topology();
        let cell = members(&["db-eu", "db-us", "web-eu", "plain"]);

        // orders pinned on all db nodes; users pinned only in eu.
        let orders = CollectionPlacement::new(
            "app.orders",
            NodeSelector::whole_cell().with_tag("zone", "db"),
        );
        let users = CollectionPlacement::new(
            "app.users",
            NodeSelector::whole_cell().with_tag("region", "eu"),
        );

        // A view over both is servable only where BOTH are pinned: db-eu.
        assert_eq!(
            view_placement([&orders, &users], &topology, &cell),
            members(&["db-eu"]),
            "a node never serves a view without every source collection it reads"
        );

        // A view over a single source equals that source's node-set.
        assert_eq!(
            view_placement([&orders], &topology, &cell),
            orders.node_set(&topology, &cell)
        );

        // A view with no sources is servable nowhere (never everywhere).
        let none: [&CollectionPlacement; 0] = [];
        assert!(view_placement(none, &topology, &cell).is_empty());
    }

    /// Selector equality/dedup is order-independent (BTreeSet-backed).
    #[test]
    fn data_placement_collection_tags_selector_is_order_independent() {
        let a = NodeSelector::new([Label::new("zone", "db"), Label::new("region", "eu")]);
        let b = NodeSelector::new([Label::new("region", "eu"), Label::new("zone", "db")]);
        assert_eq!(a, b);
        assert!(!a.is_whole_cell());
    }
}
