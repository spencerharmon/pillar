#!/usr/bin/env bash
# scenarios/streamdb-persistence.sh — the streamdb / persistence scenario.
#
# The `pillar-integration` ROI's streamdb/persistence scenario family
# (operator-directed, 2026-08-31). It drives the REAL published image SOLELY
# through its external surfaces — no pillar crate is linked — against a real
# >=3-node meshed cell with durable, content-addressed (IPFS-style) streamdb
# persistence, and asserts the STATE-SURVIVAL oracle: append an op to the cell,
# kill a node, and prove the killed node's materialized view RECONVERGES from
# its durable content-addressed segments rather than being lost.
#
# Real external effects it observes (never a return code):
#
#   1. APPEND / PERSIST — node1 gossips one real event-log op to the cell; every
#      other node (node0, node2) is observed to RECEIVE it over libp2p (its own
#      transcript prints `received gossip event payload=...`) and to PERSIST it
#      durably as a content-addressed segment under its streamdb `ops/` store
#      (the CID filename is copied out of the distroless container and named).
#
#   2. STATE-SURVIVAL on kill+restart — a node holding the durably-persisted op
#      is KILLED (real process kill) and restarted onto its SAME data-dir
#      volume. The restarted node is observed to come back READY, to REOPEN its
#      durable store and REHYDRATE the SAME materialized-view op count from the
#      persisted segments (its boot log reports `ops=N`, N>=pre-kill count —
#      not zero, which would be state LOST), and to hold the IDENTICAL
#      content-addressed op set (no dropped CID). This is the "rehydrates from
#      IPFS-pinned segments, not local disk is discarded" survival oracle:
#      RED if a killed node's state fails to reconverge, GREEN when it does.
#
# The topology, its named per-node data-dir volumes, and its dedicated bridge
# network are all labelled into the fixture namespace, so the harness's
# UNCONDITIONAL teardown + leak detector reclaim every real resource even on
# failure. Sourced by run-scenario.sh, which has already sourced the lib layer
# and run fixtures_init.

scenario_streamdb-persistence() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node MESHED topology on the real ghcr image, each node's
    # durable data dir on its own named volume so a killed node can restart
    # onto the SAME content-addressed store.
    topology_boot_meshed "$n"

    # Every node must be a real running process with a bound readiness socket
    # before we drive traffic — reuse the process oracle as the liveness gate.
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) APPEND one real op to the cell from node1 and assert it converges to
    # and durably persists on the other two nodes (node0, node2).
    local op="streamdb-op-$$-$(date -u +%s)"
    oracle_streamdb_append 1 "$op" 0 2

    # (3) STATE-SURVIVAL: kill node0 (a node that received+persisted the op via
    # gossip, not the publisher) and prove it rehydrates its materialized view
    # from the durable content-addressed segments after restart.
    oracle_state_survival 0

    info "streamdb-persistence: append converged + durably persisted on the cell, and a killed node rehydrated its materialized view from persisted content-addressed segments on ${#TOPO_NODES[@]} real nodes"
}
