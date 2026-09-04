#!/usr/bin/env bash
# topology.sh — the topology-as-code fabric.
#
# Boots a real multi-node pillar topology from the real published container
# image and tears it down. This is the smoke fabric: a single-LAN N-node
# topology on the container runtime's default bridge network, each node a real
# `pillar node run` process (the image's entrypoint) with its readiness/
# liveness probe published to an ephemeral host port.
#
# The richer fabrics the ROI enumerates (multi-site, asymmetric/multipath,
# NAT'd clients, dual-stack, split-horizon) and the impairment matrix (loss,
# latency+jitter, reordering, duplication, bandwidth cap, MTU shrink, one-way
# loss, partition/heal) are layered ON this same provision/observe/teardown
# contract by the per-family scenario tasks using containerlab + tc/netem;
# this file establishes the contract and the single-LAN base every family
# builds on. It observes nodes SOLELY from outside (container state + published
# probe socket) — no shared state with pillar internals.

# topology_boot <n> : boot an N-node single-LAN topology of the real image.
# Populates the arrays TOPO_NODES (names) and TOPO_PROBE_ADDRS (host ip:port of
# each node's published readiness/liveness probe). Every node is labelled into
# the scenario's fixture namespace so teardown/leak-detection reclaim it.
topology_boot() {
    local n="$1"
    [ "$n" -ge 3 ] || fail "topology_boot: the ROI requires >=3 real nodes (got $n)"
    TOPO_NODES=()
    TOPO_PROBE_ADDRS=()

    info "topology: booting a real ${n}-node single-LAN topology on image $PILLAR_IMAGE"
    # Pull the real published image up front so a boot failure is a clear image
    # problem, not a per-node timeout. (Idempotent — a cached image is reused.)
    "$CONTAINER_RUNTIME" pull "$PILLAR_IMAGE" >/dev/null 2>&1 \
        || fail "could not pull the real published image $PILLAR_IMAGE (is container-image-ghcr-publish landed?)"

    local i name cid
    for i in $(seq 0 $((n - 1))); do
        name="pillar-it-${FIXTURE_SCENARIO}-node${i}"
        cid=$("$CONTAINER_RUNTIME" run -d \
            --name "$name" \
            --label "$FIXTURE_LABEL" \
            -p "127.0.0.1::${PILLAR_PROBE_PORT}" \
            "$PILLAR_IMAGE" 2>&1) \
            || fail "node${i} failed to start: $cid"
        TOPO_NODES+=("$name")
    done

    # Resolve each node's published probe host-port (observed, not assumed).
    for name in "${TOPO_NODES[@]}"; do
        local addr
        addr=$("$CONTAINER_RUNTIME" port "$name" "$PILLAR_PROBE_PORT" 2>/dev/null | head -1)
        [ -n "$addr" ] || fail "could not resolve published probe port for $name"
        TOPO_PROBE_ADDRS+=("$addr")
    done
    info "topology: ${#TOPO_NODES[@]} nodes up: ${TOPO_NODES[*]}"
}

# topology_node_pid <name> : the real host PID of a node's container process
# (the process oracle observes this).
topology_node_pid() {
    "$CONTAINER_RUNTIME" inspect "$1" --format '{{.State.Pid}}' 2>/dev/null
}

# topology_node_running <name> : exit 0 iff the node's container process is
# really running.
topology_node_running() {
    [ "$("$CONTAINER_RUNTIME" inspect "$1" --format '{{.State.Running}}' 2>/dev/null)" = "true" ]
}

# topology_node_logs <name> : stream a node's stdout/stderr (the packet/gossip
# oracles grep this for wire-observed effects).
topology_node_logs() {
    "$CONTAINER_RUNTIME" logs "$1" 2>&1
}
