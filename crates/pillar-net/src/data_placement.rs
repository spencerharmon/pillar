//! `data-placement-collection-tags` — ROI Priority 1 "Data placement — the
//! collection is the pinning boundary, over node tags".
//!
//! # Model
//!
//! - The **cell** remains the confidentiality boundary; it is also the
//!   default replication set. There is no separate replication-factor /
//!   `minReplicas` knob — by default every collection is pinned on every
//!   node in the cell.
//! - A [`CollectionPlacement`] selects, per collection, the subset of the
//!   cell's nodes that pin (subscribe to + persist) that collection, by
//!   TAG — reusing [`pillar_rbac::LabelSet`] verbatim, the exact node-tag
//!   machinery `pillar-rbac`'s [`pillar_rbac::PolicyTarget::LabelSet`] and
//!   the topology-label attestation machinery in `pillar-topology` already
//!   use for RBAC targeting. No new tagging mechanism is introduced.
//! - An **empty/omitted selector means whole-cell**: every node in the cell
//!   pins the collection, matching the ROI default.
//! - A **materialized view is servable on a node iff that node pins ALL of
//!   the view's source collections** — placing/serving a view expands to
//!   pinning its sources on the same node-set. A node never holds a view
//!   without holding its data.
//! - Placement only narrows WITHIN a cell; it never widens across cells (the
//!   selector is evaluated against `cell_nodes`, which the caller must
//!   already have scoped to one cell).

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_rbac::LabelSet;

/// Where one collection is pinned within a cell: an optional tag
/// [`LabelSet`] selector over the cell's attested node tags.
///
/// `selector = None` (or a [`LabelSet`] wrapping an empty set) means
/// **whole-cell**: every node in the cell pins this collection — the ROI
/// default, since the cell itself is already the replication set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionPlacement {
    /// The collection name this placement governs (the same string
    /// [`pillar_keyedstore::KeyedStore::collections`] would report).
    pub collection: String,
    /// The tag selector narrowing which cell nodes pin this collection.
    /// `None` (or an empty [`LabelSet`]) selects every node in the cell.
    pub selector: Option<LabelSet>,
}

impl CollectionPlacement {
    /// A whole-cell placement: every node in the cell pins `collection`.
    #[must_use]
    pub fn whole_cell(collection: impl Into<String>) -> Self {
        CollectionPlacement {
            collection: collection.into(),
            selector: None,
        }
    }

    /// A placement narrowed to the cell's nodes carrying every tag in
    /// `tags`.
    #[must_use]
    pub fn tagged(collection: impl Into<String>, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let labels = LabelSet::new(tags);
        CollectionPlacement {
            collection: collection.into(),
            // An empty tag set is equivalent to whole-cell: normalize it so
            // `is_whole_cell`/`participating_nodes` need not special-case it
            // twice.
            selector: if labels.0.is_empty() { None } else { Some(labels) },
        }
    }

    /// Whether this placement is the whole-cell default (no narrowing
    /// selector, or a selector with no tags — both mean "every node").
    #[must_use]
    pub fn is_whole_cell(&self) -> bool {
        match &self.selector {
            None => true,
            Some(labels) => labels.0.is_empty(),
        }
    }

    /// Whether `node_tags` (a cell node's attested tag set) satisfies this
    /// placement's selector. A whole-cell placement admits every node.
    #[must_use]
    pub fn admits(&self, node_tags: &BTreeSet<String>) -> bool {
        match &self.selector {
            None => true,
            Some(labels) => labels.matches(node_tags),
        }
    }

    /// The live, sorted list of nodes (out of `cell_nodes`) that pin this
    /// collection right now — the CLI/UI's per-collection participating-node
    /// surface. `cell_nodes` maps each node in the cell to its current
    /// attested tag set; callers scope this to exactly one cell (placement
    /// narrows WITHIN a cell, never across cells).
    #[must_use]
    pub fn participating_nodes(&self, cell_nodes: &BTreeMap<NodeId, BTreeSet<String>>) -> Vec<NodeId> {
        cell_nodes
            .iter()
            .filter(|(_, tags)| self.admits(tags))
            .map(|(node, _)| node.clone())
            .collect()
    }

    /// The live participating-node COUNT — the CLI/UI's per-collection
    /// summary figure, without materializing the full node list.
    #[must_use]
    pub fn participating_count(&self, cell_nodes: &BTreeMap<NodeId, BTreeSet<String>>) -> usize {
        cell_nodes.values().filter(|tags| self.admits(tags)).count()
    }
}

/// A materialized view's placement, DERIVED from its source collections'
/// placements: a view is servable on a node iff that node pins EVERY one of
/// the view's source collections (view placement expands to pinning all of
/// its sources on the same node-set — a node never holds a view without
/// holding its data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewPlacement {
    /// The view's name.
    pub view: String,
    /// The source collections this view is derived from. Never empty for a
    /// real view (a view with no sources trivially has no data to serve).
    pub sources: Vec<String>,
}

impl ViewPlacement {
    /// A view over the named source collections.
    #[must_use]
    pub fn new(view: impl Into<String>, sources: impl IntoIterator<Item = impl Into<String>>) -> Self {
        ViewPlacement {
            view: view.into(),
            sources: sources.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `node` — identified by its attested tag set `node_tags` —
    /// can serve this view: it must be admitted by EVERY source collection's
    /// placement (`placements` maps collection name -> its
    /// [`CollectionPlacement`]; a source collection missing from
    /// `placements` is treated as whole-cell, the ROI default). A view with
    /// no sources is never servable (there is no data to serve).
    #[must_use]
    pub fn servable_on(
        &self,
        node_tags: &BTreeSet<String>,
        placements: &BTreeMap<String, CollectionPlacement>,
    ) -> bool {
        if self.sources.is_empty() {
            return false;
        }
        self.sources.iter().all(|source| {
            placements
                .get(source)
                .map(|p| p.admits(node_tags))
                .unwrap_or(true)
        })
    }

    /// The live, sorted list of nodes (out of `cell_nodes`) that can serve
    /// this view: the intersection of every source collection's
    /// participating node-set.
    #[must_use]
    pub fn participating_nodes(
        &self,
        cell_nodes: &BTreeMap<NodeId, BTreeSet<String>>,
        placements: &BTreeMap<String, CollectionPlacement>,
    ) -> Vec<NodeId> {
        cell_nodes
            .iter()
            .filter(|(_, tags)| self.servable_on(tags, placements))
            .map(|(node, _)| node.clone())
            .collect()
    }
}

#[cfg(test)]
mod data_placement_collection_tags {
    use super::*;

    fn cell(nodes: &[(&str, &[&str])]) -> BTreeMap<NodeId, BTreeSet<String>> {
        nodes
            .iter()
            .map(|(id, tags)| {
                (
                    NodeId((*id).to_string()),
                    tags.iter().map(|t| t.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn whole_cell_default_admits_every_node() {
        let placement = CollectionPlacement::whole_cell("orders");
        assert!(placement.is_whole_cell());
        let nodes = cell(&[("n1", &[]), ("n2", &["gpu"]), ("n3", &["gpu", "us-east"])]);
        assert_eq!(placement.participating_count(&nodes), 3);
        let mut got: Vec<String> = placement
            .participating_nodes(&nodes)
            .into_iter()
            .map(|n| n.0)
            .collect();
        got.sort();
        assert_eq!(got, vec!["n1", "n2", "n3"]);
    }

    #[test]
    fn empty_selector_normalizes_to_whole_cell() {
        let empty: [&str; 0] = [];
        let placement = CollectionPlacement::tagged("orders", empty);
        assert!(placement.is_whole_cell());
        assert!(placement.selector.is_none());
    }

    #[test]
    fn tagged_selector_narrows_within_the_cell() {
        let placement = CollectionPlacement::tagged("hot-inventory", ["gpu", "us-east"]);
        assert!(!placement.is_whole_cell());
        let nodes = cell(&[
            ("n1", &[]),
            ("n2", &["gpu"]),
            ("n3", &["gpu", "us-east"]),
            ("n4", &["gpu", "us-east", "extra"]),
        ]);
        let mut got: Vec<String> = placement
            .participating_nodes(&nodes)
            .into_iter()
            .map(|n| n.0)
            .collect();
        got.sort();
        assert_eq!(got, vec!["n3", "n4"]);
        assert_eq!(placement.participating_count(&nodes), 2);
    }

    #[test]
    fn view_is_servable_only_where_every_source_is_pinned() {
        let mut placements = BTreeMap::new();
        placements.insert(
            "orders".to_string(),
            CollectionPlacement::tagged("orders", ["gpu"]),
        );
        placements.insert(
            "inventory".to_string(),
            CollectionPlacement::tagged("inventory", ["us-east"]),
        );
        let view = ViewPlacement::new("orders-by-region", ["orders", "inventory"]);

        let nodes = cell(&[
            ("gpu-only", &["gpu"]),
            ("east-only", &["us-east"]),
            ("both", &["gpu", "us-east"]),
        ]);

        let mut got: Vec<String> = view
            .participating_nodes(&nodes, &placements)
            .into_iter()
            .map(|n| n.0)
            .collect();
        got.sort();
        assert_eq!(got, vec!["both"]);

        assert!(view.servable_on(&BTreeSet::from(["gpu".to_string(), "us-east".to_string()]), &placements));
        assert!(!view.servable_on(&BTreeSet::from(["gpu".to_string()]), &placements));
    }

    #[test]
    fn view_source_missing_from_placements_defaults_whole_cell() {
        // A source collection with no explicit CollectionPlacement is
        // whole-cell (the ROI default), so it never blocks servability.
        let placements: BTreeMap<String, CollectionPlacement> = BTreeMap::new();
        let view = ViewPlacement::new("simple", ["orders"]);
        assert!(view.servable_on(&BTreeSet::new(), &placements));
    }

    #[test]
    fn view_with_no_sources_is_never_servable() {
        let placements: BTreeMap<String, CollectionPlacement> = BTreeMap::new();
        let empty: [&str; 0] = [];
        let view = ViewPlacement::new("orphan", empty);
        assert!(!view.servable_on(&BTreeSet::new(), &placements));
    }
}
