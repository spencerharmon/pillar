//! Cell-name discovery: resolving a cell name to its live ingest nodes and
//! their published sealing keys via pillar-IPNS.
//!
//! This wraps the existing IPNS-format cell-naming pointer/resolution
//! (`pillar-cells`'s `Cell::name_ptr` / `pillar-bootstrap`'s peer-sourced
//! cell-name lookup) for an EXTERNAL client caller, rather than reintroducing
//! a new resolution mechanism. Two paths, exactly mirroring
//! [`crate::config::ConnectParams::needs_discovery`]:
//!
//! 1. **No cached nodes** — [`resolve`] asks a [`CellDiscovery`] backend (a
//!    real node resolves the cell's IPNS pointer over the swarm to its
//!    current published root, then reads the ingest-node set + sealing keys
//!    it names) for the cell's current [`IngestNode`]s.
//! 2. **Cached nodes** (from `pillar-client-config`'s `nodes:` layer) — skip
//!    discovery entirely and dial the cached addresses directly; this is the
//!    faster reconnect path.
//!
//! A cell name that resolves to no live peer is a DISTINCT
//! [`DiscoveryError::CellNotFound`], never a generic timeout — a caller can
//! tell "this cell has no reachable node right now" apart from "the network
//! didn't answer in time".

use crate::config::ConnectParams;

/// A single live ingest node for a cell: its dialable address and the
/// sealing key it published for this cell, as resolved off the IPNS-format
/// naming pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestNode {
    /// The node's dialable multiaddr (e.g.
    /// `/ip4/192.0.2.10/udp/4001/p-pillar/p2p/<peer-id>`).
    pub multiaddr: String,
    /// The node's published sealing key for this cell (opaque bytes; the
    /// concrete key material format is owned by `pillar-crypto` /
    /// `pillar-key-distribution`, not reinterpreted here).
    pub sealing_key: Vec<u8>,
}

/// A best-effort resolver for a cell name's current ingest-node set, mirroring
/// the peer-sourced, fail-open resolution contract
/// `pillar_bootstrap::name::CellNameRegistry` already establishes for cell
/// **name uniqueness**: this trait is the same shape applied to cell
/// **discovery** — resolve the cell's IPNS-format naming pointer over the
/// swarm and read the ingest-node set + sealing keys the published root
/// names. A real implementation asks the swarm; [`InMemoryCellDiscovery`] is
/// the deterministic stand-in the tests (and this module's own tests) drive.
pub trait CellDiscovery {
    /// Resolve `cell` to its currently-live ingest nodes (address + sealing
    /// key). An empty result means no peer currently serves a live node for
    /// this cell — the caller turns that into
    /// [`DiscoveryError::CellNotFound`], never a raw empty list.
    fn resolve(&self, cell: &str) -> Vec<IngestNode>;
}

impl<F> CellDiscovery for F
where
    F: Fn(&str) -> Vec<IngestNode>,
{
    fn resolve(&self, cell: &str) -> Vec<IngestNode> {
        (self)(cell)
    }
}

/// An in-memory [`CellDiscovery`] over a fixed cell -> node-set map — the
/// deterministic stand-in the tests drive (a real client resolves the
/// pointer over the pillar-IPNS swarm). A cell absent from the map resolves
/// to an empty set, modelling both a genuinely nonexistent cell and one whose
/// nodes are all currently unreachable identically.
#[derive(Clone, Debug, Default)]
pub struct InMemoryCellDiscovery {
    cells: std::collections::BTreeMap<String, Vec<IngestNode>>,
}

impl InMemoryCellDiscovery {
    /// An empty discovery backend — every cell resolves to no live nodes.
    #[must_use]
    pub fn new() -> Self {
        InMemoryCellDiscovery::default()
    }

    /// Publish `nodes` as the live ingest-node set for `cell`.
    pub fn publish(&mut self, cell: impl Into<String>, nodes: Vec<IngestNode>) {
        self.cells.insert(cell.into(), nodes);
    }
}

impl CellDiscovery for InMemoryCellDiscovery {
    fn resolve(&self, cell: &str) -> Vec<IngestNode> {
        self.cells.get(cell).cloned().unwrap_or_default()
    }
}

/// The resolved set of nodes a client should dial, tagging WHICH path
/// produced it so a caller (and its logs/metrics) can tell the fast cached
/// reconnect apart from a full IPNS discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedNodes {
    /// `config.yaml`'s cached `nodes:` were used; discovery was skipped
    /// entirely (the faster path). Only addresses are cached — no sealing
    /// keys, since this path dials directly without re-resolving them.
    Cached(Vec<String>),
    /// Freshly resolved via pillar-IPNS: at least one live ingest node with
    /// its published sealing key.
    Discovered(Vec<IngestNode>),
}

impl ResolvedNodes {
    /// True when this result came from the cached-nodes fast path (discovery
    /// was skipped).
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self, ResolvedNodes::Cached(_))
    }

    /// The dialable multiaddrs, regardless of which path produced them.
    #[must_use]
    pub fn addrs(&self) -> Vec<&str> {
        match self {
            ResolvedNodes::Cached(nodes) => nodes.iter().map(String::as_str).collect(),
            ResolvedNodes::Discovered(nodes) => {
                nodes.iter().map(|n| n.multiaddr.as_str()).collect()
            }
        }
    }
}

/// A fault resolving a cell name to live nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The cell name resolved to no live ingest node — distinct from a
    /// generic timeout/transport fault, so a caller can tell "this cell has
    /// no reachable node right now" apart from "the network didn't answer".
    CellNotFound(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::CellNotFound(cell) => {
                write!(f, "cell '{cell}' not found: no live ingest node")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Resolve the nodes a client should dial for `params`: skip discovery and
/// use the cached `nodes:` directly when present
/// ([`ConnectParams::needs_discovery`] is `false`, the faster path);
/// otherwise resolve the cell name via `discovery` (pillar-IPNS). An empty
/// discovery result is [`DiscoveryError::CellNotFound`], never silently
/// returned as an empty node set for the caller to time out against.
///
/// # Errors
/// [`DiscoveryError::CellNotFound`] when discovery ran (no cached nodes) and
/// resolved to no live ingest node for `params.cell`.
pub fn resolve(
    params: &ConnectParams,
    discovery: &(impl CellDiscovery + ?Sized),
) -> Result<ResolvedNodes, DiscoveryError> {
    if !params.needs_discovery() {
        return Ok(ResolvedNodes::Cached(params.nodes.clone()));
    }

    let nodes = discovery.resolve(&params.cell);
    if nodes.is_empty() {
        return Err(DiscoveryError::CellNotFound(params.cell.clone()));
    }
    Ok(ResolvedNodes::Discovered(nodes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;
    use std::path::Path;

    fn params_with(yaml: &str) -> ConnectParams {
        ClientConfig::parse(yaml, Path::new("t.yaml"))
            .expect("parse")
            .resolve()
            .expect("resolve")
    }

    fn node(addr: &str, key: &[u8]) -> IngestNode {
        IngestNode {
            multiaddr: addr.to_owned(),
            sealing_key: key.to_vec(),
        }
    }

    #[test]
    fn cached_nodes_skip_discovery_entirely() {
        let params = params_with(
            "cell: my-cell\nuser: alice\ntoken: tok\nnodes:\n  - /ip4/192.0.2.10/udp/4001/p-pillar/p2p/peerA\n",
        );
        // A discovery backend that would panic if ever consulted, proving the
        // cached path never calls it.
        let discovery = |_: &str| -> Vec<IngestNode> { panic!("discovery must be skipped") };
        let resolved = resolve(&params, &discovery).expect("resolve");
        assert!(resolved.is_cached());
        assert_eq!(
            resolved.addrs(),
            vec!["/ip4/192.0.2.10/udp/4001/p-pillar/p2p/peerA"]
        );
    }

    #[test]
    fn no_cached_nodes_resolves_via_discovery_backend() {
        let params = params_with("cell: my-cell\nuser: alice\ntoken: tok\n");
        let mut discovery = InMemoryCellDiscovery::new();
        discovery.publish(
            "my-cell",
            vec![
                node("/ip4/192.0.2.10/udp/4001/p-pillar/p2p/peerA", b"seal-key-a"),
                node("/ip4/192.0.2.11/udp/4001/p-pillar/p2p/peerB", b"seal-key-b"),
            ],
        );

        let resolved = resolve(&params, &discovery).expect("resolve");
        assert!(!resolved.is_cached());
        match &resolved {
            ResolvedNodes::Discovered(nodes) => {
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].sealing_key, b"seal-key-a");
            }
            ResolvedNodes::Cached(_) => panic!("expected discovery path"),
        }
        assert_eq!(
            resolved.addrs(),
            vec![
                "/ip4/192.0.2.10/udp/4001/p-pillar/p2p/peerA",
                "/ip4/192.0.2.11/udp/4001/p-pillar/p2p/peerB",
            ]
        );
    }

    #[test]
    fn a_cell_name_with_no_live_peer_is_a_distinct_not_found_error() {
        let params = params_with("cell: ghost-cell\nuser: alice\ntoken: tok\n");
        // Empty registry: no peer serves a pointer for any cell.
        let discovery = InMemoryCellDiscovery::new();

        let err = resolve(&params, &discovery).expect_err("no live node");
        assert_eq!(err, DiscoveryError::CellNotFound("ghost-cell".to_owned()));
        // Distinct, readable message — not a generic timeout string.
        assert_eq!(
            err.to_string(),
            "cell 'ghost-cell' not found: no live ingest node"
        );
    }

    #[test]
    fn discovery_absent_cell_yields_empty_which_the_resolver_turns_into_not_found() {
        let discovery = InMemoryCellDiscovery::new();
        assert!(discovery.resolve("anything").is_empty());
    }

    #[test]
    fn closure_backends_satisfy_the_celldiscovery_trait() {
        let params = params_with("cell: c\nuser: u\ntoken: t\n");
        let backend = |cell: &str| -> Vec<IngestNode> {
            if cell == "c" {
                vec![node("/ip4/192.0.2.1/udp/4001/p-pillar/p2p/peerX", b"k")]
            } else {
                vec![]
            }
        };
        let resolved = resolve(&params, &backend).expect("resolve");
        assert!(!resolved.is_cached());
    }

    /// Acceptance-level scenario: a client with no cached nodes discovers a
    /// cell's live ingest set via the IPNS backend, dials the fast cached
    /// path on a subsequent reconnect once nodes are cached, and gets the
    /// distinct not-found error for a cell nobody serves — the three
    /// end-to-end behaviors the task card describes, exercised together.
    #[cfg(feature = "acceptance")]
    #[test]
    fn acceptance_full_discovery_then_cached_reconnect_flow() {
        let mut discovery = InMemoryCellDiscovery::new();
        discovery.publish(
            "prod-cell",
            vec![node(
                "/ip4/192.0.2.20/udp/4001/p-pillar/p2p/peerC",
                b"prod-seal-key",
            )],
        );

        // First connect: no cached nodes, must discover.
        let first = params_with("cell: prod-cell\nuser: alice\ntoken: tok\n");
        let resolved = resolve(&first, &discovery).expect("discover");
        let ResolvedNodes::Discovered(nodes) = &resolved else {
            panic!("expected discovery on first connect");
        };
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].sealing_key, b"prod-seal-key");

        // Second connect: caller caches the discovered address in
        // config.yaml's `nodes:` layer; the client now skips discovery.
        let cached_yaml = format!(
            "cell: prod-cell\nuser: alice\ntoken: tok\nnodes:\n  - {}\n",
            nodes[0].multiaddr
        );
        let second = params_with(&cached_yaml);
        let panics_if_called = |_: &str| -> Vec<IngestNode> { panic!("must not re-discover") };
        let fast = resolve(&second, &panics_if_called).expect("cached resolve");
        assert!(fast.is_cached());
        assert_eq!(
            fast.addrs(),
            vec!["/ip4/192.0.2.20/udp/4001/p-pillar/p2p/peerC"]
        );

        // A cell nobody serves gets the distinct not-found error, not a
        // generic timeout.
        let missing = params_with("cell: nowhere\nuser: alice\ntoken: tok\n");
        let err = resolve(&missing, &discovery).expect_err("not found");
        assert_eq!(err, DiscoveryError::CellNotFound("nowhere".to_owned()));
    }
}
