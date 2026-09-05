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

# topology_boot_scheduler <n> <job-name> <period-secs> : boot an N-node
# single-LAN topology of the real image, each node carrying the integration-rig
# `PILLAR_TEST_CRONJOB=<job-name>|<period-secs>|/bin/pillar` hook so a REAL
# CronJob is registered into the live node's scheduler runtime and fires on the
# node's real wall clock. The staged image bytes are the real published
# `/bin/pillar` binary (present in the distroless image) re-exec'd with no args
# — it prints usage and exits 0, so each due fire is a REAL supervised process
# (a real pid) that exits cleanly and is reaped back into the ONE scheduler
# engine, surfaced on the node's stdout as `job-run: <name> <status> pid=<pid>`.
# Populates TOPO_NODES / TOPO_PROBE_ADDRS exactly like topology_boot. All
# resources are labelled into the fixture namespace for teardown/leak-check.
#
# A due workload fire STAGES the image bytes to a temp file under $TMPDIR and
# execs it; the distroless image has no /tmp, so we point TMPDIR at the image's
# writable data dir (/var/lib/pillar/data) — otherwise every spawn fails with
# "failed to stage workload image as executable: No such file or directory".
topology_boot_scheduler() {
    local n="$1" job="$2" period="$3"
    [ "$n" -ge 3 ] || fail "topology_boot_scheduler: the ROI requires >=3 real nodes (got $n)"
    TOPO_NODES=()
    TOPO_PROBE_ADDRS=()

    info "topology: booting a real ${n}-node scheduler topology on image $PILLAR_IMAGE (CronJob '$job' period=${period}s)"
    "$CONTAINER_RUNTIME" pull "$PILLAR_IMAGE" >/dev/null 2>&1 \
        || fail "could not pull the real published image $PILLAR_IMAGE (is container-image-ghcr-publish landed?)"

    local i name cid
    for i in $(seq 0 $((n - 1))); do
        name="pillar-it-${FIXTURE_SCENARIO}-node${i}"
        cid=$("$CONTAINER_RUNTIME" run -d \
            --name "$name" \
            --label "$FIXTURE_LABEL" \
            -e "TMPDIR=${PILLAR_IT_NODE_TMPDIR:-/var/lib/pillar/data}" \
            -e "PILLAR_TEST_CRONJOB=${job}|${period}|/bin/pillar" \
            -p "127.0.0.1::${PILLAR_PROBE_PORT}" \
            "$PILLAR_IMAGE" 2>&1) \
            || fail "node${i} failed to start: $cid"
        TOPO_NODES+=("$name")
    done

    for name in "${TOPO_NODES[@]}"; do
        local addr
        addr=$("$CONTAINER_RUNTIME" port "$name" "$PILLAR_PROBE_PORT" 2>/dev/null | head -1)
        [ -n "$addr" ] || fail "could not resolve published probe port for $name"
        TOPO_PROBE_ADDRS+=("$addr")
    done
    info "topology: ${#TOPO_NODES[@]} scheduler nodes up: ${TOPO_NODES[*]}"
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

# --- meshed persistence fabric ---------------------------------------------
#
# The single-LAN `topology_boot` above publishes each node's readiness probe
# but leaves the nodes libp2p-ISOLATED (no `--dial`), which is all the smoke /
# process oracle needs. The streamdb/persistence family needs the nodes to
# form a REAL libp2p mesh over a dedicated bridge network so a gossiped
# event-log op converges to every node's durable, content-addressed store, and
# needs each node's data-dir on a NAMED VOLUME so a KILLED node can be
# restarted onto the SAME store and its rehydrated materialized view observed.
# `topology_boot_meshed` provides exactly that on top of the same
# provision/observe/teardown contract, all resources labelled into the fixture
# namespace.
#
# It populates, in addition to TOPO_NODES / TOPO_PROBE_ADDRS:
#   TOPO_NET      — the dedicated bridge network name.
#   TOPO_VOLS     — per-node named data-dir volume (index-aligned with TOPO_NODES).
#   TOPO_P2P_PORT — the in-container libp2p listen tcp port every node binds.

TOPO_P2P_PORT="${PILLAR_IT_P2P_PORT:-4001}"

# _topology_node_bridge_ip <name> : the node's IP on the scenario bridge
# network (observed, used to build a dialable libp2p multiaddr for its peers).
_topology_node_bridge_ip() {
    "$CONTAINER_RUNTIME" inspect "$1" \
        --format "{{(index .NetworkSettings.Networks \"$TOPO_NET\").IPAddress}}" 2>/dev/null
}

# topology_boot_meshed <n> : boot an N-node (>=3) meshed topology of the real
# image on a dedicated labelled bridge, each node's data dir on a labelled
# named volume so it survives a container kill/restart. The nodes are dialed
# into a real libp2p mesh (each non-seed dials node0), so an event-log op
# gossiped by any node converges to every node's durable store.
topology_boot_meshed() {
    local n="$1"
    [ "$n" -ge 3 ] || fail "topology_boot_meshed: the ROI requires >=3 real nodes (got $n)"
    TOPO_NODES=()
    TOPO_PROBE_ADDRS=()
    TOPO_VOLS=()

    info "topology: booting a real ${n}-node MESHED topology on image $PILLAR_IMAGE"
    "$CONTAINER_RUNTIME" pull "$PILLAR_IMAGE" >/dev/null 2>&1 \
        || fail "could not pull the real published image $PILLAR_IMAGE (is container-image-ghcr-publish landed?)"

    # Dedicated bridge so nodes reach each other's libp2p listener directly.
    TOPO_NET="pillar-it-${FIXTURE_SCENARIO}-net"
    "$CONTAINER_RUNTIME" network rm "$TOPO_NET" >/dev/null 2>&1 || true
    "$CONTAINER_RUNTIME" network create --label "$FIXTURE_LABEL" "$TOPO_NET" >/dev/null 2>&1 \
        || fail "could not create scenario network $TOPO_NET"

    # Boot node0 (the seed the rest dial) first so we can resolve its bridge IP
    # and hand it to every other node as a --dial target.
    local i name vol
    for i in $(seq 0 $((n - 1))); do
        name="pillar-it-${FIXTURE_SCENARIO}-node${i}"
        vol="pillar-it-${FIXTURE_SCENARIO}-vol${i}"
        "$CONTAINER_RUNTIME" volume rm -f "$vol" >/dev/null 2>&1 || true
        "$CONTAINER_RUNTIME" volume create --label "$FIXTURE_LABEL" "$vol" >/dev/null 2>&1 \
            || fail "could not create data-dir volume $vol for node${i}"
        TOPO_VOLS+=("$vol")
    done

    # node0 (seed): no dial target, publishes nothing yet.
    _topology_boot_one 0 "" ""
    local seed_ip
    seed_ip=$(_topology_node_bridge_ip "pillar-it-${FIXTURE_SCENARIO}-node0")
    [ -n "$seed_ip" ] || fail "could not resolve node0 bridge IP for mesh formation"
    local seed_dial="/ip4/${seed_ip}/tcp/${TOPO_P2P_PORT}"
    info "topology: mesh seed node0 dialable at $seed_dial"

    # The remaining nodes dial the seed, forming a real libp2p mesh.
    for i in $(seq 1 $((n - 1))); do
        _topology_boot_one "$i" "$seed_dial" ""
    done

    # Resolve each node's published probe host-port (observed, not assumed).
    for name in "${TOPO_NODES[@]}"; do
        local addr
        addr=$("$CONTAINER_RUNTIME" port "$name" "$PILLAR_PROBE_PORT" 2>/dev/null | head -1)
        [ -n "$addr" ] || fail "could not resolve published probe port for $name"
        TOPO_PROBE_ADDRS+=("$addr")
    done
    info "topology: ${#TOPO_NODES[@]} meshed nodes up on $TOPO_NET: ${TOPO_NODES[*]}"
}

# _topology_boot_one <index> <dial-multiaddr|""> <test-publish-value|""> :
# start ONE meshed node (real image, on the scenario bridge, data dir on its
# named volume), optionally dialing <dial-multiaddr> and/or publishing
# <test-publish-value> once to the event-log gossipsub topic after settle.
# Appends its name to TOPO_NODES.
_topology_boot_one() {
    local idx="$1" dial="$2" publish="$3"
    _topology_start_node "$idx" "$dial" "$publish"
    TOPO_NODES+=("pillar-it-${FIXTURE_SCENARIO}-node${idx}")
}

# _topology_run_node : no-op shim kept so the boot ordering above reads
# linearly; the actual per-node start is _topology_boot_one.
_topology_run_node() { return 0; }

# topology_restart_node <index> : KILL then restart node <index> onto its SAME
# named data-dir volume (a real crash + recovery), so the state-survival oracle
# can assert the node rehydrates its durable materialized view from the
# persisted content-addressed segments rather than losing state.
topology_restart_node() {
    local idx="$1"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    info "topology: killing node${idx} ($name) — real process kill"
    "$CONTAINER_RUNTIME" kill "$name" >/dev/null 2>&1 \
        || fail "could not kill node${idx} ($name)"
    "$CONTAINER_RUNTIME" start "$name" >/dev/null 2>&1 \
        || fail "could not restart node${idx} ($name) onto its persisted store"
}

# topology_publish_op <index> <value> : make node <index> gossip <value> once
# to the event-log topic by (re)starting it with PILLAR_TEST_PUBLISH set,
# dialing the seed so it joins the existing mesh. Every meshed node folds the
# received op into its durable store. Used to APPEND a real op to the cell.
# The node already exists in TOPO_NODES (booted by topology_boot_meshed), so
# this recreates it in place WITHOUT re-appending to the node arrays.
topology_publish_op() {
    local idx="$1" value="$2"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    local seed_ip
    seed_ip=$(_topology_node_bridge_ip "pillar-it-${FIXTURE_SCENARIO}-node0")
    [ -n "$seed_ip" ] || fail "publish: could not resolve seed IP"
    info "topology: node${idx} will publish op '$value' to the event-log topic"
    "$CONTAINER_RUNTIME" rm -f "$name" >/dev/null 2>&1 || true
    _topology_start_node "$idx" "/ip4/${seed_ip}/tcp/${TOPO_P2P_PORT}" "$value"
}

# _topology_start_node <index> <dial|""> <publish|""> : start (or restart) ONE
# meshed node container in place, WITHOUT touching the TOPO_NODES / node arrays
# (used to recreate an already-tracked node, e.g. to have it publish an op).
_topology_start_node() {
    local idx="$1" dial="$2" publish="$3"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    local vol="pillar-it-${FIXTURE_SCENARIO}-vol${idx}"
    local -a envs=(-e "PILLAR_LISTEN=/ip4/0.0.0.0/tcp/${TOPO_P2P_PORT}")
    [ -n "$dial" ] && envs+=(-e "PILLAR_DIAL=$dial")
    [ -n "$publish" ] && envs+=(-e "PILLAR_TEST_PUBLISH=$publish")
    local cid
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$name" \
        --label "$FIXTURE_LABEL" \
        --network "$TOPO_NET" \
        -v "${vol}:/var/lib/pillar/data" \
        -p "127.0.0.1::${PILLAR_PROBE_PORT}" \
        "${envs[@]}" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "node${idx} failed to (re)start: $cid"
}

# topology_node_streamdb_ops <index> : print the node's CURRENTLY-OPENED
# streamdb op count as the node itself reports it in its boot log
# (`streaming DB opened ... ops=N`) — the LAST such line, i.e. the count after
# the most recent (re)hydration. This is the node's OWN materialized-view size,
# observed black-box from its log, not a return code.
topology_node_streamdb_ops() {
    local idx="$1"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    "$CONTAINER_RUNTIME" logs "$name" 2>&1 \
        | sed -n 's/.*streaming DB opened.*ops=\([0-9][0-9]*\).*/\1/p' \
        | tail -1
}

# topology_node_received_op <index> <value> : exit 0 iff node <index>'s log
# shows it really received <value> as a gossip event over the wire (the
# real cross-process convergence effect, observed from the transcript).
topology_node_received_op() {
    local idx="$1" value="$2"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    "$CONTAINER_RUNTIME" logs "$name" 2>&1 \
        | grep -q "received gossip event payload=${value}"
}

# topology_node_op_cids <index> : print the content-address (CID) filenames of
# every persisted op under the node's durable streamdb `ops/` store, copied out
# of the (distroless) container via `<runtime> cp`. Each name is the op's real
# content address — a resolvable-CID artifact, not a return code.
topology_node_op_cids() {
    local idx="$1"
    local name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    local dest="${FIXTURE_ROOT}/opscp-node${idx}"
    rm -rf "$dest"; mkdir -p "$dest"
    "$CONTAINER_RUNTIME" cp "${name}:/var/lib/pillar/data/streamdb" "$dest" >/dev/null 2>&1 || return 1
    # ops files are named by content address; list them (basename only).
    find "$dest" -type f -path '*/ops/*' -printf '%f\n' 2>/dev/null
}
