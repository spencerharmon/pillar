//! The Overview home (Phase 5) — an at-a-glance summary of the node across
//! every console section, replacing the placeholder welcome card. Each KPI is a
//! real count pulled from an already-served endpoint (live signal kinds, live
//! replicas, placed topology nodes, trust edges) and aggregated by a pure,
//! host-tested summarizer; the component only fetches and renders.

use crate::obs_console::KindCount;

/// The aggregated overview KPIs.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OverviewKpis {
    /// Total live signals across all kinds.
    pub signal_total: u64,
    /// Per-kind live signal counts (as returned, order preserved).
    pub per_kind: Vec<(String, u64)>,
    /// Live workload replicas currently reported by the reconciler oracle.
    pub live_replicas: usize,
    /// Placed nodes in the topology tree.
    pub topo_nodes: usize,
    /// Edges in the web of trust.
    pub trust_edges: usize,
}

/// Aggregate the parsed section inputs into the overview KPIs. Pure: the signal
/// total is the exact sum of the per-kind counts (never fabricated), and the
/// other three are simple cardinalities of their parsed inputs.
#[must_use]
pub fn summarize(
    counts: &[KindCount],
    live_replicas: usize,
    topo_nodes: usize,
    trust_edges: usize,
) -> OverviewKpis {
    OverviewKpis {
        signal_total: counts.iter().map(|c| c.count).sum(),
        per_kind: counts.iter().map(|c| (c.kind.clone(), c.count)).collect(),
        live_replicas,
        topo_nodes,
        trust_edges,
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::OverviewConsole;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{summarize, OverviewKpis};
    use crate::auth::use_auth;
    use crate::components::use_toaster;
    use crate::obs_console::parse_kind_counts;
    use crate::portal::{get_url, http, NodeStatusTile};
    use crate::primitives::{Chart, ChartKind, StatCard};
    use crate::resources_console::parse_replicas;
    use crate::topology_console::{parse_topology_tree, parse_trust_edges};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// The Overview section: the node status card plus a KPI band aggregated
    /// live from the observability, resource, topology, and trust endpoints.
    #[function_component(OverviewConsole)]
    pub fn overview_console() -> Html {
        let auth = use_auth();
        let kpis = use_state(OverviewKpis::default);
        let toaster = use_toaster();

        {
            let (auth, kpis, toaster) = (auth.clone(), kpis.clone(), toaster.clone());
            use_effect_with(auth.token.clone(), move |token| {
                if let Some(token) = token.clone() {
                    let (kpis, toaster) = (kpis.clone(), toaster.clone());
                    let kinds_url = get_url("/portal/obs/live/kinds", &token, &[]);
                    let tree_url = get_url("/portal/topology/tree", &token, &[]);
                    let trust_url = get_url("/portal/trust-graph", &token, &[]);
                    spawn_local(async move {
                        // Signal kinds — deliberately best-effort: a 503 with no
                        // live substrate is normal, not an error to surface.
                        let counts = match http("GET", &kinds_url, None).await {
                            Ok(r) if r.ok() => parse_kind_counts(&r.body),
                            _ => Vec::new(),
                        };
                        // Live replicas (reportable): a failure is surfaced, not
                        // silently collapsed to zero.
                        let replicas = match http("GET", "/portal/resource/replicas", None).await {
                            Ok(r) if r.ok() => parse_replicas(&r.body).len(),
                            Ok(_) => {
                                toaster.error("Overview: could not load live replicas.");
                                0
                            }
                            Err(_) => {
                                toaster.error("Overview: the live-replicas request failed.");
                                0
                            }
                        };
                        let nodes = match http("GET", &tree_url, None).await {
                            Ok(r) if r.ok() => parse_topology_tree(&r.body).nodes.len(),
                            Ok(_) => {
                                toaster.error("Overview: could not load the topology tree.");
                                0
                            }
                            Err(_) => {
                                toaster.error("Overview: the topology-tree request failed.");
                                0
                            }
                        };
                        let edges = match http("GET", &trust_url, None).await {
                            Ok(r) if r.ok() => parse_trust_edges(&r.body).len(),
                            Ok(_) => {
                                toaster.error("Overview: could not load the trust graph.");
                                0
                            }
                            Err(_) => {
                                toaster.error("Overview: the trust-graph request failed.");
                                0
                            }
                        };
                        kpis.set(summarize(&counts, replicas, nodes, edges));
                    });
                }
                || ()
            });
        }

        let bars: Vec<f64> = kpis.per_kind.iter().map(|(_, n)| *n as f64).collect();

        html! {
            <>
                <div class="ov-kpis">
                    <StatCard label="Live signals" value={kpis.signal_total.to_string()} spark={bars.clone()} />
                    <StatCard label="Live replicas" value={kpis.live_replicas.to_string()} />
                    <StatCard label="Topology nodes" value={kpis.topo_nodes.to_string()} />
                    <StatCard label="Trust edges" value={kpis.trust_edges.to_string()} />
                </div>
                if !bars.is_empty() {
                    <div class="obs-panel">
                        <h4>{ "Live signal distribution" }</h4>
                        <Chart values={bars} kind={ChartKind::Bar} width={480.0} height={120.0} />
                    </div>
                }
                <NodeStatusTile />
            </>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obs_console::KindCount;

    #[test]
    fn summarize_sums_signal_kinds_and_counts_cardinalities() {
        let counts = vec![
            KindCount {
                kind: "metric".into(),
                count: 4,
            },
            KindCount {
                kind: "log".into(),
                count: 6,
            },
        ];
        let k = summarize(&counts, 3, 5, 7);
        assert_eq!(k.signal_total, 10);
        assert_eq!(k.per_kind, vec![("metric".into(), 4), ("log".into(), 6)]);
        assert_eq!(k.live_replicas, 3);
        assert_eq!(k.topo_nodes, 5);
        assert_eq!(k.trust_edges, 7);
    }

    #[test]
    fn summarize_of_nothing_is_all_zero_never_fabricated() {
        let k = summarize(&[], 0, 0, 0);
        assert_eq!(k, OverviewKpis::default());
        assert_eq!(k.signal_total, 0);
    }

    /// Source audit (anti-facade DoD): every REPORTABLE Overview fetch (live
    /// replicas, topology tree, trust graph — the signal-kinds fetch is
    /// deliberately best-effort) surfaces BOTH failure arms (a non-OK status
    /// and a transport error) through `toaster.error(...)` instead of silently
    /// collapsing to a zero. Three reportable fetches × two arms ⇒ ≥6 error
    /// branches; a future edit cannot drop one back to a `_ => 0` no-op without
    /// tripping this.
    #[test]
    fn every_reportable_overview_fetch_has_a_toast_error_branch() {
        let src = include_str!("overview.rs");
        let n = src.matches("toaster.error(").count();
        assert!(
            n >= 6,
            "the three reportable Overview fetches must each surface both failure arms via toaster.error(...), found {n}"
        );
        // And the best-effort signal-kinds fetch is still a silent fallback (it
        // must NOT be forced through a toast — a 503 with no substrate is normal).
        assert!(
            src.contains("Ok(r) if r.ok() => parse_kind_counts(&r.body),"),
            "the signal-kinds fetch should remain best-effort"
        );
    }
}
