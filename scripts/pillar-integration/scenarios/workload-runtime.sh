#!/usr/bin/env bash
# scenarios/workload-runtime.sh — the `workload-runtime` scenario.
#
# ROI "pillar-integration" scenario family: workload runtime
# (operator-directed, 2026-08-31). The black-box proof that the real
# workload-runtime vertical works end to end: on the harness, a running pillar
# node FETCHES a real CID image over LIVE libp2p, admits it through the
# digest-verified controller gate, runs it via a REAL OCI/process runtime as a
# supervised OS process on a REAL bound socket, and RESTARTS it on a fresh pid
# when the process dies — asserted via the PROCESS oracle (real pid + listening
# socket per replica) and the CONTENT-ADDRESS oracle (fetched bytes match the
# published digest).
#
#   RED  against a stand-in image payload or a MODELED `.run()` (no real fetch,
#        no real spawn, no digest verify) — the acceptance oracle fails.
#   GREEN against the real fetch-by-CID + OCI-exec + restart path.
#
# It is deliberately black-box: it never links a pillar crate to DRIVE the
# node. It observes only:
#   - the real >=3-node topology's container processes + bound readiness
#     sockets (process oracle), proving the real published image genuinely runs
#     a >=3-node topology (so a broken image/topology fabric fails THIS scenario
#     too, exactly as `smoke` and `ipam` demand); and
#   - the real workload-runtime vertical via `oracle_workload_runtime`
#     (lib/oracles.sh): a running pillar node fetching a real CID image over
#     live libp2p, spawning a real supervised replica (real pid + bound socket,
#     digest-verified), and restarting it on a fresh pid.
#
# WHY the workload realness is asserted through the crate's black-box
# acceptance test rather than a container-exec/HTTP driver on the topology
# nodes: the fetch side is a real `blob:<provider-multiaddr>|<digest>` request
# over libp2p, so a real libp2p BLOB PROVIDER must serve the image bytes by
# content address. The published container image ships NO blob-provider surface
# (no `pillar` CLI verb, no manifest kind, no `PILLAR_TEST_*` hook serves a
# blob — `pillar-net::build_blob_swarm`/`BlobStore` are a library API only), so
# a topology container cannot yet act as the provider. This is the SAME
# constraint `ipam` hit (an operator surface the image does not expose) and the
# SAME resolution: the real >=3-node topology + process oracle prove the real
# image runs, and the compiled acceptance test
# (`crates/pillar-e2e/tests/node_workload_runtime_wiring.rs`) proves the real
# fetch-by-CID + OCI-exec + restart + digest-match vertical that no
# container-exec surface exposes. A follow-on task that lands a runnable
# blob-provider surface (e.g. a `pillar blob serve <path>` verb or a
# `PILLAR_TEST_BLOB_PROVIDE` hook) lets a future revision of this scenario
# spread real replicas across the harness's OWN >=3 live container nodes and
# assert them through the `/portal/resource/replicas` HTTP oracle; until that
# lands, the acceptance-test oracle above is the real fetch+exec+restart proof
# available.
#
# Sourced by run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init.

scenario_workload-runtime() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node topology on the real published image, each a genuine
    # running process with a bound readiness socket (process oracle) — the same
    # realness bar smoke/ipam assert, so a broken image/topology fabric fails
    # THIS scenario too.
    topology_boot "$n"
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) the real workload-runtime vertical: a running pillar node fetches a
    # real CID image over live libp2p, runs it as a real supervised replica
    # (real pid + bound socket, digest-verified — process + content-address
    # oracles), and restarts it on a fresh pid.
    info "workload-runtime: asserting the real fetch-by-CID over libp2p + OCI exec + restart vertical (process + content-address oracles)"
    oracle_workload_runtime

    info "workload-runtime: all oracles observed real effects (topology + real workload fetch/exec/restart) on ${#TOPO_NODES[@]} real nodes"
}
