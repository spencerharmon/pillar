#!/usr/bin/env bash
# scenarios/soak-stress.sh — the soak / stress scenario.
#
# The `pillar-integration` ROI's soak/stress scenario family (operator-directed,
# 2026-08-31), deps=pillar-integration-harness,surface-inventory-emitter. It
# drives the REAL published image SOLELY through its external surfaces — no
# pillar crate is linked — against a real >=3-node meshed cell, and runs
# SUSTAINED load + churn over an extended budget on real nodes, asserting the
# RESOURCE-USAGE oracle: no unbounded growth in the dedup table, event log, or
# history, observed via a real OS footprint sampled over the soak window.
#
# Why a soak (not a short-lived scenario): a leak in the dedup table, the event
# log, or the materialized-view history is INVISIBLE to a one-shot scenario —
# it only manifests as a slow, unbounded climb in memory or file descriptors
# under repeated create/delete + churn. This scenario provokes exactly that and
# watches for it.
#
# Real external effects it observes (never a return code):
#
#   1. LIVENESS — every node is a real running process with a bound readiness
#      socket before load starts (the process oracle).
#
#   2. SUSTAINED LOAD + CHURN — over PILLAR_IT_SOAK_CYCLES churn cycles, a
#      non-seed node is repeatedly FLAPPED (real kill/restart onto its durable
#      content-addressed volume) and re-publishes a fresh event-log op each
#      cycle (real gossip append the seed dedups + the cell persists as a new
#      content-addressed segment), plus a real key-rotation CLI verb is
#      exercised against the real image bytes. This exercises the exact
#      subsystems the ROI names — dedup table, event log, history, key
#      rotation, and peer-connection (re-dial) churn.
#
#   3. RESOURCE-USAGE PLATEAU — the long-lived SEED node's REAL OS process
#      footprint (VmRSS + open-fd count, read from the host kernel's
#      /proc/<host-pid>/ for the container process) is SAMPLED across the whole
#      window. The oracle asserts the later half of samples has not grown
#      materially over the earlier half for either RSS or fd: the resource
#      PLATEAUED rather than climbing without bound. RED if a monitored
#      resource grows unbounded across the soak window, GREEN when it plateaus.
#
# The topology, its named per-node data-dir volumes, and its dedicated bridge
# network are all labelled into the fixture namespace, so the harness's
# UNCONDITIONAL teardown + leak detector reclaim every real resource even on
# failure. Sourced by run-scenario.sh, which has already sourced the lib layer
# and run fixtures_init.
#
# Budget knobs (defaults keep the check runnable in the sandbox while still
# spanning a window long enough for an unbounded climb to separate from a
# plateau; raise them for a longer real soak):
#   PILLAR_IT_SOAK_CYCLES   churn cycles over the window          (default 20)
#   PILLAR_IT_SOAK_SAMPLE   sample the seed footprint every N cyc (default 2)
#   PILLAR_IT_SOAK_RSS_TOL_PCT / PILLAR_IT_SOAK_FD_TOL            (see oracle)

scenario_soak-stress() {
    local n="${PILLAR_IT_NODES:-3}"
    local cycles="${PILLAR_IT_SOAK_CYCLES:-20}"
    local every="${PILLAR_IT_SOAK_SAMPLE:-2}"

    # (1) real >=3-node MESHED topology on the real ghcr image, each node's
    # durable data dir on its own named volume so the flap node restarts onto
    # the SAME content-addressed store each churn cycle.
    topology_boot_meshed "$n"

    # Liveness gate: every node a real running process with a bound socket.
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2)+(3) SUSTAINED LOAD + CHURN over the extended budget while SAMPLING the
    # long-lived seed (node0) footprint, asserting no unbounded growth. The flap
    # node is a non-seed node (node1) so the seed stays up the whole window and
    # its RSS/fd trend is a clean leak signal.
    info "soak-stress: driving $cycles churn cycles (flap+publish+rotate), sampling seed footprint every $every cycle(s)"
    oracle_resource_usage 0 1 "$cycles" "$every"

    info "soak-stress: sustained load + churn over $cycles cycles left the seed's dedup table / event log / history footprint PLATEAUED on ${#TOPO_NODES[@]} real nodes — no unbounded growth"
}
