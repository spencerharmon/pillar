//! The Topology & Trust console (Phase 4) — turns the node's already-served
//! `/portal/topology/*` and `/portal/trust-graph` text views into an
//! interactive placement tree, failure-domain overlays, and a node-link web of
//! trust, instead of the raw `<pre>` dumps the debug portal rendered.
//!
//! Every parser here is pinned to the exact line format the backend dispatchers
//! emit (`NODE … PATH … HEALTH … CAPACITY …`, `ROLLUP …`, `MISMATCH …`,
//! `REPLICA … <tier>=<domain>` + `WARN`/`SPREAD-OK`, `EDGE a -> b LABEL l`) and
//! is unit-tested on the host; the `yew` components are thin wrappers over them
//! plus the shared design-system primitives (`Tree`, `Graph`, `DataTable`,
//! `Badge`).

// ---------------------------------------------------------------------------
// Topology tree (pure)
// ---------------------------------------------------------------------------

/// One placed node from `GET /portal/topology/tree`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopoNode {
    /// The node id.
    pub name: String,
    /// Its resolved placement path, coarsest tier first.
    pub path: Vec<String>,
    /// The health string.
    pub health: String,
    /// The declared capacity.
    pub capacity: String,
}

/// A parsed topology tree body.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TopologyTree {
    /// The declared tier names, coarsest first.
    pub tiers: Vec<String>,
    /// Every placed node.
    pub nodes: Vec<TopoNode>,
    /// The rollups: `(tier, domain, total)`.
    pub rollups: Vec<(String, String, String)>,
}

/// Parse the `topology_tree` body (`TIERS …`, `NODE … PATH … HEALTH … CAPACITY
/// …`, `ROLLUP <tier> <domain>=<total>`). Unknown lines are skipped.
#[must_use]
pub fn parse_topology_tree(body: &str) -> TopologyTree {
    let mut tree = TopologyTree::default();
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("TIERS ") {
            tree.tiers = rest
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        } else if let Some(rest) = line.strip_prefix("NODE ") {
            if let Some(n) = parse_node_line(rest) {
                tree.nodes.push(n);
            }
        } else if let Some(rest) = line.strip_prefix("ROLLUP ") {
            // `<tier> <domain>=<total>`
            if let Some((tier, kv)) = rest.split_once(' ') {
                if let Some((domain, total)) = kv.rsplit_once('=') {
                    tree.rollups
                        .push((tier.to_owned(), domain.to_owned(), total.to_owned()));
                }
            }
        }
    }
    tree
}

fn parse_node_line(rest: &str) -> Option<TopoNode> {
    // `<name> PATH <p1,p2,…> HEALTH <health> CAPACITY <capacity>`
    let (name, after) = rest.split_once(" PATH ")?;
    let (path_str, after) = after.split_once(" HEALTH ")?;
    let (health, capacity) = after.split_once(" CAPACITY ")?;
    let path = if path_str.is_empty() {
        Vec::new()
    } else {
        path_str.split(',').map(str::to_owned).collect()
    };
    Some(TopoNode {
        name: name.to_owned(),
        path,
        health: health.to_owned(),
        capacity: capacity.to_owned(),
    })
}

/// A pure mirror of the design-system tree node, built here so the placement
/// grouping is host-testable without the `yew` feature; the component maps it
/// onto [`crate::primitives::TreeNode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopoTreeNode {
    /// The branch/leaf label (a path segment, or a node id at the leaf).
    pub label: String,
    /// The health status for a leaf node, else `None`.
    pub status: Option<String>,
    /// Child nodes.
    pub children: Vec<TopoTreeNode>,
}

/// Group placed nodes into a nested placement tree by their path segments; each
/// leaf is a node id carrying its health status. Nodes with an empty path hang
/// directly off the root under an `(unplaced)` branch so they are never
/// dropped.
#[must_use]
pub fn build_placement_tree(nodes: &[TopoNode]) -> Vec<TopoTreeNode> {
    let mut roots: Vec<TopoTreeNode> = Vec::new();
    for node in nodes {
        let path = if node.path.is_empty() {
            vec!["(unplaced)".to_owned()]
        } else {
            node.path.clone()
        };
        let mut level = &mut roots;
        for seg in &path {
            // Find or create the branch for this segment at this level.
            let idx = match level.iter().position(|n| n.label == *seg) {
                Some(i) => i,
                None => {
                    level.push(TopoTreeNode {
                        label: seg.clone(),
                        status: None,
                        children: Vec::new(),
                    });
                    level.len() - 1
                }
            };
            level = &mut level[idx].children;
        }
        // Leaf: the node id with its health.
        level.push(TopoTreeNode {
            label: node.name.clone(),
            status: Some(node.health.clone()),
            children: Vec::new(),
        });
    }
    roots
}

// ---------------------------------------------------------------------------
// Mismatches / failure domain (pure)
// ---------------------------------------------------------------------------

/// A declared-vs-attested topology mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The node id.
    pub node: String,
    /// The tier the mismatch is at.
    pub tier: String,
    /// The self-declared value.
    pub declared: String,
    /// The attested value.
    pub attested: String,
}

/// Parse the `topology_mismatches` body: `MISMATCH <node> tier=<t>
/// declared=<d> attested=<a>` lines.
#[must_use]
pub fn parse_mismatches(body: &str) -> Vec<Mismatch> {
    let mut out = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.trim().strip_prefix("MISMATCH ") else {
            continue;
        };
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let field = |p: &str, key: &str| p.strip_prefix(key).map(str::to_owned);
        let (Some(tier), Some(declared), Some(attested)) = (
            field(parts[1], "tier="),
            field(parts[2], "declared="),
            field(parts[3], "attested="),
        ) else {
            continue;
        };
        out.push(Mismatch {
            node: parts[0].to_owned(),
            tier,
            declared,
            attested,
        });
    }
    out
}

/// The parsed failure-domain overlay: per-node domain assignment plus whether
/// the backend flagged a same-domain spread warning.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SpreadOverlay {
    /// `(node, domain)` for each queried node.
    pub assignments: Vec<(String, String)>,
    /// True when the backend emitted `WARN same-rack` (replicas share a domain).
    pub warn: bool,
}

/// Parse the `failure-domain` body: `REPLICA <node> <tier>=<domain>` lines plus
/// a trailing `WARN same-rack` / `SPREAD-OK`.
#[must_use]
pub fn parse_spread(body: &str) -> SpreadOverlay {
    let mut overlay = SpreadOverlay::default();
    for line in body.lines() {
        let line = line.trim();
        if line == "WARN same-rack" {
            overlay.warn = true;
        } else if let Some(rest) = line.strip_prefix("REPLICA ") {
            if let Some((node, kv)) = rest.split_once(' ') {
                let domain = kv.split_once('=').map(|(_, v)| v).unwrap_or(kv);
                overlay
                    .assignments
                    .push((node.to_owned(), domain.to_owned()));
            }
        }
    }
    overlay
}

// ---------------------------------------------------------------------------
// Trust graph (pure)
// ---------------------------------------------------------------------------

/// A trust-graph edge: `from` trusts `to` under `label`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustEdge {
    /// The trusting node.
    pub from: String,
    /// The trusted node.
    pub to: String,
    /// The relation label.
    pub label: String,
}

/// Parse the `trust-graph` body: `EDGE <from> -> <to> LABEL <label>` lines.
#[must_use]
pub fn parse_trust_edges(body: &str) -> Vec<TrustEdge> {
    let mut out = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.trim().strip_prefix("EDGE ") else {
            continue;
        };
        let Some((from, rest)) = rest.split_once(" -> ") else {
            continue;
        };
        let Some((to, label)) = rest.split_once(" LABEL ") else {
            continue;
        };
        out.push(TrustEdge {
            from: from.to_owned(),
            to: to.to_owned(),
            label: label.to_owned(),
        });
    }
    out
}

/// Reduce trust edges to the unique node id list (in first-seen order) plus the
/// edges expressed as index pairs into that list — the exact input a node-link
/// [`crate::primitives::Graph`] needs.
#[must_use]
pub fn trust_node_index(edges: &[TrustEdge]) -> (Vec<String>, Vec<(usize, usize, String)>) {
    let mut nodes: Vec<String> = Vec::new();
    let idx_of = |nodes: &mut Vec<String>, id: &str| -> usize {
        match nodes.iter().position(|n| n == id) {
            Some(i) => i,
            None => {
                nodes.push(id.to_owned());
                nodes.len() - 1
            }
        }
    };
    let mut indexed = Vec::new();
    for e in edges {
        let a = idx_of(&mut nodes, &e.from);
        let b = idx_of(&mut nodes, &e.to);
        indexed.push((a, b, e.label.clone()));
    }
    (nodes, indexed)
}

// ---------------------------------------------------------------------------
// Yew component
// ---------------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use yew_impl::{TopologyConsole, TrustGraphConsole};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        build_placement_tree, parse_mismatches, parse_spread, parse_topology_tree,
        parse_trust_edges, trust_node_index, TopoTreeNode, TopologyTree,
    };
    use crate::auth::use_auth;
    use crate::components::use_toast_error;
    use crate::portal::{get_url, http, input_value};
    use crate::primitives::{Badge, DataTable, Graph, GraphEdge, Tabs, Tone, Tree, TreeNode};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    fn to_tree_node(n: &TopoTreeNode) -> TreeNode {
        TreeNode {
            label: n.label.clone(),
            status: n.status.clone(),
            children: n.children.iter().map(to_tree_node).collect(),
        }
    }

    /// The Topology section: an interactive placement tree, capacity rollups,
    /// declared-vs-attested mismatches, and a failure-domain spread checker.
    #[function_component(TopologyConsole)]
    pub fn topology_console() -> Html {
        let auth = use_auth();
        let tab = use_state(|| 0usize);
        let tree = use_state(TopologyTree::default);
        let mismatches = use_state(Vec::new);
        let spread_nodes = use_state(String::new);
        let spread_tier = use_state(|| "rack".to_owned());
        let spread = use_state(super::SpreadOverlay::default);
        let toast_error = use_toast_error();

        // Load the placement tree + mismatches on mount / token change.
        {
            let (auth, tree, mismatches, toast_error) = (
                auth.clone(),
                tree.clone(),
                mismatches.clone(),
                toast_error.clone(),
            );
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let (tree, mismatches, toast_error) =
                        (tree.clone(), mismatches.clone(), toast_error.clone());
                    let tree_url = get_url("/portal/topology/tree", &token, &[]);
                    let mm_url = get_url("/portal/topology/mismatches", &token, &[]);
                    spawn_local(async move {
                        match http("GET", &tree_url, None).await {
                            Ok(r) if r.ok() => tree.set(parse_topology_tree(&r.body)),
                            Ok(_) => {}
                            Err(e) => {
                                toast_error.emit(format!("Couldn't load the placement tree: {e:?}"))
                            }
                        }
                        match http("GET", &mm_url, None).await {
                            Ok(r) if r.ok() => mismatches.set(parse_mismatches(&r.body)),
                            Ok(_) => {}
                            Err(e) => {
                                toast_error.emit(format!("Couldn't load mismatches: {e:?}"));
                            }
                        }
                    });
                }
                || ()
            });
        }

        let on_spread_nodes = {
            let spread_nodes = spread_nodes.clone();
            Callback::from(move |e: InputEvent| spread_nodes.set(input_value(&e)))
        };
        let on_spread_tier = {
            let spread_tier = spread_tier.clone();
            Callback::from(move |e: InputEvent| spread_tier.set(input_value(&e)))
        };
        let check_spread = {
            let (auth, spread_nodes, spread_tier, spread, toast_error) = (
                auth.clone(),
                spread_nodes.clone(),
                spread_tier.clone(),
                spread.clone(),
                toast_error.clone(),
            );
            Callback::from(move |_: MouseEvent| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let url = get_url(
                    "/portal/topology/failure-domain",
                    &token,
                    &[("tier", &spread_tier), ("nodes", &spread_nodes)],
                );
                let (spread, toast_error) = (spread.clone(), toast_error.clone());
                spawn_local(async move {
                    match http("GET", &url, None).await {
                        Ok(r) if r.ok() => spread.set(parse_spread(&r.body)),
                        Ok(r) => {
                            toast_error.emit(format!("Spread check failed: {}", r.body.trim()))
                        }
                        Err(e) => toast_error.emit(format!("Spread check failed: {e:?}")),
                    }
                });
            })
        };

        let tabs = vec![
            "Placement".to_owned(),
            "Rollups".to_owned(),
            "Mismatches".to_owned(),
            "Spread check".to_owned(),
        ];
        let onselect = {
            let tab = tab.clone();
            Callback::from(move |i: usize| tab.set(i))
        };

        let body = match *tab {
            0 => {
                let roots: Vec<TreeNode> = build_placement_tree(&tree.nodes)
                    .iter()
                    .map(to_tree_node)
                    .collect();
                if roots.is_empty() {
                    html! { <p class="ds-empty">{ "No placed nodes reported." }</p> }
                } else {
                    html! {
                        <>
                            <p class="ds-empty">{ format!("Tiers: {}", tree.tiers.join(" \u{203a} ")) }</p>
                            <Tree roots={roots} />
                        </>
                    }
                }
            }
            1 => {
                let cols = vec![
                    "tier".to_owned(),
                    "domain".to_owned(),
                    "capacity".to_owned(),
                ];
                let rows: Vec<Vec<String>> = tree
                    .rollups
                    .iter()
                    .map(|(t, d, n)| vec![t.clone(), d.clone(), n.clone()])
                    .collect();
                if rows.is_empty() {
                    html! { <p class="ds-empty">{ "No rollups." }</p> }
                } else {
                    html! { <DataTable columns={cols} rows={rows} /> }
                }
            }
            2 => {
                if mismatches.is_empty() {
                    html! { <p class="ds-empty">{ "No declared-vs-attested mismatches \u{2014} placement is consistent." }</p> }
                } else {
                    html! {
                        <table class="ds-table">
                            <thead><tr><th>{ "node" }</th><th>{ "tier" }</th>
                                <th>{ "declared" }</th><th>{ "attested" }</th></tr></thead>
                            <tbody>
                                { for mismatches.iter().map(|m| html! {
                                    <tr>
                                        <td>{ &m.node }</td>
                                        <td>{ &m.tier }</td>
                                        <td>{ &m.declared }</td>
                                        <td><Badge label={m.attested.clone()} tone={Tone::Warn} /></td>
                                    </tr>
                                }) }
                            </tbody>
                        </table>
                    }
                }
            }
            _ => {
                let assign_cols = vec!["node".to_owned(), "domain".to_owned()];
                let assign_rows: Vec<Vec<String>> = spread
                    .assignments
                    .iter()
                    .map(|(n, d)| vec![n.clone(), d.clone()])
                    .collect();
                html! {
                    <div class="res-change">
                        <div class="res-toolbar">
                            <input class="ds-table__filter" type="text" placeholder="tier (e.g. rack)"
                                   value={(*spread_tier).clone()} oninput={on_spread_tier} />
                            <input class="ds-table__filter" type="text" placeholder="nodes (comma-separated)"
                                   value={(*spread_nodes).clone()} oninput={on_spread_nodes} />
                            <button class="ds-tab" onclick={check_spread}>{ "Check spread" }</button>
                        </div>
                        if !assign_rows.is_empty() {
                            <DataTable columns={assign_cols} rows={assign_rows} />
                            <div class="res-verdict">
                                { if spread.warn {
                                    html! { <Badge label="replicas share a failure domain" tone={Tone::Danger} /> }
                                } else {
                                    html! { <Badge label="spread across domains" tone={Tone::Success} /> }
                                } }
                            </div>
                        }
                    </div>
                }
            }
        };

        html! {
            <div class="tile" id="topology-console">
                <h3>{ "Topology" }</h3>
                <p>{ "Node placement across the failure-domain hierarchy, capacity \
                      rollups, declared-vs-attested mismatches, and a replica spread \
                      checker." }</p>
                <Tabs tabs={tabs} selected={*tab} onselect={onselect} />
                <div class="obs-tabpanel">{ body }</div>
            </div>
        }
    }

    /// The Trust section: the web of trust rendered as an interactive node-link
    /// graph over `/portal/trust-graph`.
    #[function_component(TrustGraphConsole)]
    pub fn trust_graph_console() -> Html {
        let auth = use_auth();
        let edges = use_state(Vec::new);
        let toast_error = use_toast_error();

        {
            let (auth, edges, toast_error) = (auth.clone(), edges.clone(), toast_error.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let (edges, toast_error) = (edges.clone(), toast_error.clone());
                    let url = get_url("/portal/trust-graph", &token, &[]);
                    spawn_local(async move {
                        match http("GET", &url, None).await {
                            Ok(r) if r.ok() => edges.set(parse_trust_edges(&r.body)),
                            Ok(_) => {}
                            Err(e) => {
                                toast_error.emit(format!("Couldn't load the trust graph: {e:?}"));
                            }
                        }
                    });
                }
                || ()
            });
        }

        let (nodes, indexed) = trust_node_index(&edges);
        let graph_edges: Vec<GraphEdge> = indexed
            .into_iter()
            .map(|(from, to, label)| GraphEdge { from, to, label })
            .collect();

        html! {
            <div class="tile" id="trust-graph-console">
                <h3>{ "Trust Graph" }</h3>
                <p>{ "The web of trust: who has admitted whom, and under which \
                      relation." }</p>
                if nodes.is_empty() {
                    <p class="ds-empty">{ "No trust edges yet." }</p>
                } else {
                    <>
                        <Graph nodes={nodes} edges={graph_edges} />
                        <p class="ds-empty">{ format!("{} nodes in the web of trust.", (*edges).len()) }</p>
                    </>
                }
            </div>
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_tree_parses_tiers_nodes_and_rollups() {
        let body = "TIERS region,rack\n\
                    NODE a PATH us,r1 HEALTH ok CAPACITY 10\n\
                    NODE b PATH us,r2 HEALTH degraded CAPACITY 5\n\
                    ROLLUP rack r1=10\n\
                    ROLLUP rack r2=5\n";
        let t = parse_topology_tree(body);
        assert_eq!(t.tiers, vec!["region", "rack"]);
        assert_eq!(t.nodes.len(), 2);
        assert_eq!(
            t.nodes[0],
            TopoNode {
                name: "a".into(),
                path: vec!["us".into(), "r1".into()],
                health: "ok".into(),
                capacity: "10".into(),
            }
        );
        assert_eq!(t.rollups[1], ("rack".into(), "r2".into(), "5".into()));
    }

    #[test]
    fn placement_tree_groups_by_path_and_keeps_health() {
        let t = parse_topology_tree(
            "NODE a PATH us,r1 HEALTH ok CAPACITY 1\n\
             NODE b PATH us,r1 HEALTH bad CAPACITY 1\n\
             NODE c PATH us,r2 HEALTH ok CAPACITY 1\n",
        );
        let roots = build_placement_tree(&t.nodes);
        // one region root 'us'.
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].label, "us");
        // two racks under it.
        assert_eq!(roots[0].children.len(), 2);
        let r1 = &roots[0].children[0];
        assert_eq!(r1.label, "r1");
        // a and b are leaves under r1, each carrying its health.
        assert_eq!(r1.children.len(), 2);
        assert_eq!(r1.children[1].label, "b");
        assert_eq!(r1.children[1].status.as_deref(), Some("bad"));
    }

    #[test]
    fn unplaced_nodes_are_never_dropped() {
        let t = parse_topology_tree("NODE lonely PATH  HEALTH ok CAPACITY 1\n");
        assert_eq!(t.nodes[0].path.len(), 0);
        let roots = build_placement_tree(&t.nodes);
        assert_eq!(roots[0].label, "(unplaced)");
        assert_eq!(roots[0].children[0].label, "lonely");
    }

    #[test]
    fn mismatches_parse_all_fields() {
        let m = parse_mismatches("MISMATCH a tier=rack declared=r1 attested=r2\n");
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0],
            Mismatch {
                node: "a".into(),
                tier: "rack".into(),
                declared: "r1".into(),
                attested: "r2".into(),
            }
        );
        assert!(parse_mismatches("MISMATCH short\n").is_empty());
    }

    #[test]
    fn spread_parses_assignments_and_warn() {
        let warn = parse_spread("REPLICA a rack=r1\nREPLICA b rack=r1\nWARN same-rack\n");
        assert_eq!(warn.assignments.len(), 2);
        assert_eq!(warn.assignments[0], ("a".into(), "r1".into()));
        assert!(warn.warn);
        let ok = parse_spread("REPLICA a rack=r1\nREPLICA b rack=r2\nSPREAD-OK\n");
        assert!(!ok.warn);
    }

    #[test]
    fn trust_edges_parse_and_index() {
        let edges =
            parse_trust_edges("EDGE root -> alice LABEL admin\nEDGE alice -> bob LABEL member\n");
        assert_eq!(edges.len(), 2);
        assert_eq!(
            edges[0],
            TrustEdge {
                from: "root".into(),
                to: "alice".into(),
                label: "admin".into(),
            }
        );
        let (nodes, indexed) = trust_node_index(&edges);
        // unique nodes in first-seen order.
        assert_eq!(nodes, vec!["root", "alice", "bob"]);
        // edges reference node indices.
        assert_eq!(indexed[0], (0, 1, "admin".into()));
        assert_eq!(indexed[1], (1, 2, "member".into()));
    }

    #[test]
    fn trust_edges_skip_malformed() {
        assert!(parse_trust_edges("EDGE nope\ngarbage\n").is_empty());
    }
}
