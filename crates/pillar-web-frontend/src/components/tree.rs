//! `Tree` — an expand/collapse hierarchical list (feeds Phase 4's topology
//! tree).
//!
//! The tree→visible-rows flattening is **pure logic** ([`TreeNode`],
//! [`flatten`], [`FlatRow`]) so the traversal / expansion is host-tested; the
//! [`Tree`] Yew component renders the flattened rows with indentation.

/// One node in a [`TreeNode`] hierarchy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    /// A stable id used to toggle expansion.
    pub id: String,
    /// The node label.
    pub label: String,
    /// Child nodes (empty for a leaf).
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    /// A leaf node.
    #[must_use]
    pub fn leaf(id: impl Into<String>, label: impl Into<String>) -> TreeNode {
        TreeNode {
            id: id.into(),
            label: label.into(),
            children: Vec::new(),
        }
    }

    /// A branch node with children.
    #[must_use]
    pub fn branch(
        id: impl Into<String>,
        label: impl Into<String>,
        children: Vec<TreeNode>,
    ) -> TreeNode {
        TreeNode {
            id: id.into(),
            label: label.into(),
            children,
        }
    }
}

/// One visible row produced by [`flatten`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlatRow {
    /// The node id.
    pub id: String,
    /// The node label.
    pub label: String,
    /// Nesting depth (0 = root).
    pub depth: usize,
    /// Whether the node has children.
    pub has_children: bool,
    /// Whether the node is currently expanded (only meaningful when
    /// `has_children`).
    pub expanded: bool,
}

/// Flatten `roots` into the visible row sequence, descending into a branch only
/// when its id is present in `expanded`. A collapsed branch still appears as a
/// row (so it can be expanded) but its subtree is hidden.
#[must_use]
pub fn flatten(roots: &[TreeNode], expanded: &[String]) -> Vec<FlatRow> {
    fn walk(nodes: &[TreeNode], depth: usize, expanded: &[String], out: &mut Vec<FlatRow>) {
        for node in nodes {
            let has_children = !node.children.is_empty();
            let is_open = has_children && expanded.iter().any(|e| e == &node.id);
            out.push(FlatRow {
                id: node.id.clone(),
                label: node.label.clone(),
                depth,
                has_children,
                expanded: is_open,
            });
            if is_open {
                walk(&node.children, depth + 1, expanded, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(roots, 0, expanded, &mut out);
    out
}

/// Toggle `id` in the `expanded` set, returning the new set (idempotent add /
/// remove). Keeps the pure logic host-testable and out of the component.
#[must_use]
pub fn toggle(expanded: &[String], id: &str) -> Vec<String> {
    if expanded.iter().any(|e| e == id) {
        expanded.iter().filter(|e| *e != id).cloned().collect()
    } else {
        let mut next = expanded.to_vec();
        next.push(id.to_owned());
        next
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::{Tree, TreeProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{flatten, toggle, TreeNode};
    use yew::prelude::*;

    /// Props for [`Tree`].
    #[derive(Properties, PartialEq)]
    pub struct TreeProps {
        /// The root nodes.
        pub roots: Vec<TreeNode>,
        /// Node ids expanded initially.
        #[prop_or_default]
        pub default_expanded: Vec<String>,
    }

    /// An expand/collapse hierarchical list. Toggling a branch runs the pure
    /// [`toggle`]/[`flatten`] functions and re-renders the visible rows.
    #[function_component(Tree)]
    pub fn tree(props: &TreeProps) -> Html {
        let expanded = use_state(|| props.default_expanded.clone());
        let rows = flatten(&props.roots, &expanded);
        html! {
            <ul class="pillar-tree" role="tree">
                { for rows.into_iter().map(|row| {
                    let onclick = {
                        let expanded = expanded.clone();
                        let id = row.id.clone();
                        Callback::from(move |_: MouseEvent| {
                            expanded.set(toggle(&expanded, &id));
                        })
                    };
                    let toggle_char = if !row.has_children {
                        ""
                    } else if row.expanded {
                        "\u{25BC} "
                    } else {
                        "\u{25B6} "
                    };
                    html! {
                        <li
                            class="pillar-tree__row"
                            role="treeitem"
                            aria-expanded={row.has_children.then(|| row.expanded.to_string())}
                            style={format!("--depth: {}", row.depth)}
                            onclick={onclick}
                        >
                            <span class="pillar-tree__toggle">{ toggle_char }</span>
                            { row.label }
                        </li>
                    }
                }) }
            </ul>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<TreeNode> {
        vec![TreeNode::branch(
            "root",
            "Root",
            vec![
                TreeNode::leaf("a", "A"),
                TreeNode::branch("b", "B", vec![TreeNode::leaf("b1", "B1")]),
            ],
        )]
    }

    #[test]
    fn collapsed_root_shows_only_the_root_row() {
        let rows = flatten(&sample(), &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "root");
        assert!(rows[0].has_children);
        assert!(!rows[0].expanded);
    }

    #[test]
    fn expanding_root_reveals_direct_children_only() {
        let rows = flatten(&sample(), &["root".into()]);
        // root, a, b — but NOT b1 (b still collapsed).
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["root", "a", "b"]
        );
        assert_eq!(rows[1].depth, 1);
    }

    #[test]
    fn expanding_nested_branch_reveals_its_subtree() {
        let rows = flatten(&sample(), &["root".into(), "b".into()]);
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["root", "a", "b", "b1"]
        );
        assert_eq!(rows[3].depth, 2);
        assert!(!rows[3].has_children);
    }

    #[test]
    fn toggle_adds_then_removes_idempotently() {
        let e = toggle(&[], "x");
        assert_eq!(e, vec!["x".to_string()]);
        let e2 = toggle(&e, "x");
        assert!(e2.is_empty());
    }
}
