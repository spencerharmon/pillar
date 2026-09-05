#!/usr/bin/env bash
# scenarios/chaos-fault.sh — ROI "pillar-integration" scenario family:
# fault-injection/chaos (operator-directed, 2026-08-31).
#
# Drives the REAL published image SOLELY through its external surfaces (no
# pillar crate is linked) against a real >=3-node meshed cell with durable,
# content-addressed streamdb persistence and the anti-entropy wire protocol
# (`anti-entropy-sync-impl` + `anti-entropy-sync-wire-node-run`), and injects
# the harness's impairment matrix's real chaos faults one at a time on a live
# cell:
#
#   1. network PARTITION (+ heal)     — a real container network disconnect.
#   2. NODE LOSS (crash + restart)    — a real process kill + restart onto the
#                                        SAME durable volume.
#   3. DISK WIPE                      — a real volume delete + recreate; the
#                                        node's own history is gone, so its
#                                        only path back is anti-entropy from a
#                                        peer.
#   4. CLOCK SKEW                     — a node recreated with its real wall
#                                        clock (CLOCK_REALTIME) genuinely
#                                        shifted +3650 days (`libfaketime`
#                                        LD_PRELOAD — a real interposed clock,
#                                        not a stub), proving convergence never
#                                        depends on wall-clock agreement (the
#                                        durable store is content-addressed).
#   5. LOSS DURING BOOTSTRAP          — a node killed a SECOND time while it is
#                                        still mid-bootstrap (before its
#                                        readiness probe / redial / first
#                                        anti-entropy round complete), proving
#                                        the cell still reconverges after a
#                                        boot-time interruption, not just a
#                                        clean restart.
#
# After EACH fault this scenario asserts, via the STATE-SURVIVAL /
# content-address oracles, that the cell reconverges to a single consistent
# durable op set with NO dropped or diverged CID across every live node —
# the ROI's split-brain oracle. RED if a partition heal (or any other fault's
# recovery) ever leaves two nodes holding different content-addressed op sets
# for the same op history; GREEN when every node's durable `ops/` CID set is
# IDENTICAL after each fault heals.
#
# The topology, its named per-node data-dir volumes, and its dedicated bridge
# network are all labelled into the fixture namespace, so the harness's
# UNCONDITIONAL teardown + leak detector reclaim every real resource
# (including the throwaway `libfaketime` fixture container this scenario
# creates to fetch the real interposition library) even on failure. Sourced by
# run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init.

# _chaos_all_cids_equal : print "" and return 0 iff every node currently in
# TOPO_NODES holds an IDENTICAL durable content-addressed op set (the
# split-brain oracle's core comparison) — never a return code alone; the
# differing sets (if any) are echoed by the caller's failure message.
_chaos_all_cids_equal() {
    local i first cur
    first=""
    for i in "${!TOPO_NODES[@]}"; do
        cur="$(topology_node_op_cids "$i" | sort)"
        [ -n "$cur" ] || return 1
        if [ -z "$first" ]; then
            first="$cur"
        elif [ "$cur" != "$first" ]; then
            return 1
        fi
    done
    return 0
}

# _chaos_assert_converged <what> <timeout-seconds> : poll until every node's
# durable content-addressed op set is IDENTICAL (the no-split-brain oracle),
# or fail loudly naming the still-diverged sets.
_chaos_assert_converged() {
    local what="$1" timeout="$2" i
    retry "$timeout" _chaos_all_cids_equal || {
        local msg="split-brain oracle: after $what, node durable op sets did NOT converge within ${timeout}s:"
        for i in "${!TOPO_NODES[@]}"; do
            msg="$msg\n  node$i: $(topology_node_op_cids "$i" | sort | tr '\n' ' ')"
        done
        fail "$(printf '%b' "$msg")"
    }
    info "oracle-observed: split-brain-oracle after $what — every one of ${#TOPO_NODES[@]} nodes holds the IDENTICAL content-addressed op set (converged, no split-brain): $(topology_node_op_cids 0 | sort | tr '\n' ' ')"
}

# _chaos_fetch_libfaketime : fetch the REAL libfaketime interposition library
# (nixpkgs' `libfaketime`, via the nixery.dev toolbox pattern this hive already
# uses for on-demand check tooling) into the scenario's fixture root, leaving
# its host path in the global CHAOS_LIBFAKETIME_SO (never printed for a
# `$(...)` capture — `fail` calls `exit`, which only unwinds a command
# substitution's OWN subshell, silently swallowing the failure and handing the
# caller an empty path instead of halting the scenario; every other
# fault-injection helper in this file follows the same rule). A throwaway
# labelled container does the `cp`, reclaimed by the harness's own fixture
# teardown/leak-check like every other scenario resource. Retries the pull —
# nixery.dev is an external network dependency and a shared, contended CI/dev
# host can see a transient DNS/pull hiccup.
_chaos_fetch_libfaketime() {
    local dest="${FIXTURE_ROOT}/libfaketime.so.1"
    # `fixtures_init` itself removes FIXTURE_ROOT right after creating it (its
    # internal stale-residue `fixtures_teardown quiet` call deletes whatever
    # FIXTURE_ROOT currently points at, including its own freshly-`mktemp -d`ed
    # dir) — every other FIXTURE_ROOT consumer in this harness tolerates that
    # via its own `mkdir -p`, so do the same here rather than assuming the
    # directory already exists (`podman cp`, unlike `mkdir`, never creates a
    # missing parent).
    mkdir -p "$FIXTURE_ROOT"
    if [ -f "$dest" ]; then
        CHAOS_LIBFAKETIME_SO="$dest"
        return 0
    fi
    local helper="pillar-it-${FIXTURE_SCENARIO}-libfaketime-fetch"
    local attempt
    for attempt in 1 2 3 4 5; do
        "$CONTAINER_RUNTIME" rm -f "$helper" >/dev/null 2>&1 || true
        if "$CONTAINER_RUNTIME" create --name "$helper" --label "$FIXTURE_LABEL" \
            nixery.dev/shell/libfaketime true >/dev/null 2>&1; then
            # A container that was just `create`d can briefly lag before its
            # filesystem is reliably `cp`-able under load (a real, observed
            # podman storage-layer race, not a fixed rule) — a short settle
            # + its own short retry absorbs that without conflating it with
            # the network-pull retry loop below.
            sleep 1
            if "$CONTAINER_RUNTIME" cp "${helper}:/lib/libfaketime.so.1" "$dest" >/dev/null 2>&1 \
                && [ -s "$dest" ]; then
                "$CONTAINER_RUNTIME" rm -f "$helper" >/dev/null 2>&1 || true
                CHAOS_LIBFAKETIME_SO="$dest"
                return 0
            fi
        fi
        "$CONTAINER_RUNTIME" rm -f "$helper" >/dev/null 2>&1 || true
        warn "chaos: libfaketime fixture fetch attempt $attempt/5 failed, retrying"
        sleep 5
    done
    fail "could not fetch the real libfaketime.so.1 fixture (via nixery.dev/shell/libfaketime) after 5 attempts"
}

scenario_chaos-fault() {
    local n="${PILLAR_IT_NODES:-4}"

    # A real >=3-node MESHED topology on the real ghcr image (>=4 here: fault
    # 1 needs one node partitioned off while the rest keep converging).
    topology_boot_meshed "$n"

    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # Fixed node roles for the rest of this scenario (chosen so no node's
    # cached TOPO_PROBE_ADDRS entry ever goes stale behind a later check —
    # `topology_publish_op`/`topology_wipe_node_disk`/a clock-skew recreation
    # all recreate the container outright, which gets a FRESH ephemeral host
    # port, so any node whose address a LATER step still needs is refreshed
    # (`topology_refresh_probe_addr`) immediately after its own recreation):
    #   node0 — the mesh seed. NEVER killed/recreated/dialed-from: the
    #           runtime dials its peer only at process start (no
    #           redial-on-drop), so losing the seed would sever every other
    #           node's only path back to the mesh for the rest of the run.
    #   node1 — the CLOCK-SKEW fault target (fault 4).
    #   node2 — the PUBLISHER for every op this scenario appends, and the
    #           DISK-WIPE fault target (fault 3).
    #   node3 — the PARTITION (fault 1) and NODE-LOSS (fault 2) target —
    #           both faults only ever kill+start it in place (never a full
    #           recreate), so its boot-time address never goes stale.

    # Baseline: one real op converged + durably persisted on every node, so
    # every subsequent fault starts from a real, non-empty, agreed-upon cell
    # state (never an empty-store false convergence).
    local op0="chaos-baseline-$$-$(date -u +%s)"
    oracle_streamdb_append 2 "$op0" 0 1 3
    _chaos_assert_converged "baseline append" 60

    # --- fault 1: network PARTITION + heal --------------------------------
    # node3 is a real network partition: disconnected outright from the
    # scenario bridge, so it can reach no peer. An op published while it is
    # partitioned MUST NOT reach it (a real, observed absence — proof the
    # partition is genuine, not a no-op).
    topology_partition_node 3
    local op1="chaos-partition-$$-$(date -u +%s)"
    oracle_streamdb_append 2 "$op1" 0 1
    topology_node_received_op 3 "$op1" \
        && fail "chaos-fault: node3 received op '$op1' over the wire while genuinely network-partitioned — the partition was not real"
    info "oracle-observed: partition-isolation node3 did NOT receive op '$op1' while network-partitioned (real isolation, no wire path)"

    # Heal: reconnect the network, then restart the node so it redials its
    # peer (the runtime's dial only fires at process start —
    # crates/pillar-cli/src/run.rs — so a real reconnect needs a real
    # restart, exactly like any partitioned peer rejoining) and its
    # anti-entropy tick pulls the full gap from a connected peer.
    topology_heal_partition 3
    topology_restart_node 3
    local addr3="${TOPO_PROBE_ADDRS[3]}"
    _ready3() { driver_http "$addr3" /readyz >/dev/null 2>&1; }
    retry 90 _ready3 || fail "chaos-fault: node3 never became ready again after the partition healed and it restarted"
    _chaos_assert_converged "partition heal (node3 rejoined + anti-entropy caught up)" 90

    # --- fault 2: NODE LOSS (crash + restart) -----------------------------
    # Reuses the ROI's own state-survival oracle: node3 is really killed and
    # restarted onto its SAME durable volume, proving its materialized view
    # rehydrates from the persisted content-addressed segments rather than
    # being lost.
    oracle_state_survival 3
    _chaos_assert_converged "node loss (node3 crash + restart)" 60

    # --- fault 3: DISK WIPE -------------------------------------------------
    # node2's durable volume is deleted OUTRIGHT and recreated empty, so its
    # local history is genuinely gone (not merely unmounted) — the ONLY path
    # back to the cell's state is the anti-entropy wire protocol pulling the
    # full durable set fresh from a connected peer. `topology_wipe_node_disk`
    # refreshes TOPO_PROBE_ADDRS[2] itself (the recreation gets a fresh
    # ephemeral host port).
    topology_wipe_node_disk 2
    local addr2="${TOPO_PROBE_ADDRS[2]}"
    _ready2() { driver_http "$addr2" /readyz >/dev/null 2>&1; }
    retry 90 _ready2 || fail "chaos-fault: node2 never became ready again after its disk was wiped and it restarted"
    local reopened2
    reopened2=$(topology_node_streamdb_ops 2)
    [ "$reopened2" = "0" ] \
        || fail "chaos-fault: node2's boot log after a disk wipe reported ops=$reopened2, expected ops=0 (a genuine wipe starts empty)"
    info "oracle-observed: disk-wipe node2 rebooted onto a FRESH empty volume reporting ops=0 (no local history survived the wipe)"
    _chaos_assert_converged "disk wipe (node2 recovered its ENTIRE durable state from a peer via anti-entropy, not its own disk)" 90

    # --- fault 4: CLOCK SKEW -------------------------------------------------
    # node1 is recreated onto its SAME durable volume with its real wall clock
    # (CLOCK_REALTIME, via glibc's time syscalls) genuinely shifted +3650 days
    # by libfaketime's LD_PRELOAD interposition — a real interposed clock
    # observed in the node's OWN boot log timestamp, never a stub. The cell
    # must still converge a fresh op across every node (including the
    # skewed one), proving reconvergence never depends on wall-clock
    # agreement — the durable store's identity is its content address, not a
    # timestamp.
    local libfaketime_so
    _chaos_fetch_libfaketime
    libfaketime_so="$CHAOS_LIBFAKETIME_SO"
    [ -n "$libfaketime_so" ] && [ -f "$libfaketime_so" ] \
        || fail "chaos-fault: libfaketime fixture path is empty/missing after _chaos_fetch_libfaketime ('$libfaketime_so')"
    local dial
    dial="$(topology_seed_dial)"
    "$CONTAINER_RUNTIME" rm -f "pillar-it-${FIXTURE_SCENARIO}-node1" >/dev/null 2>&1 || true
    TOPO_EXTRA_RUN_ARGS=(-v "${libfaketime_so}:/opt/libfaketime.so.1:ro" \
        -e "LD_PRELOAD=/opt/libfaketime.so.1" -e "FAKETIME=+3650d")
    _topology_start_node 1 "$dial" ""
    TOPO_EXTRA_RUN_ARGS=()
    topology_refresh_probe_addr 1
    local addr1="${TOPO_PROBE_ADDRS[1]}"
    _ready1() { driver_http "$addr1" /readyz >/dev/null 2>&1; }
    retry 90 _ready1 || fail "chaos-fault: clock-skewed node1 never became ready"
    local boot_year
    boot_year=""
    _chaos_boot_year_ready() {
        # Resolve the CURRENT container id fresh every attempt (rather than
        # `podman logs <name>`) — a name that was just `rm -f`+recreated can
        # transiently resolve its log stream slowly/emptily by name alone in
        # this harness's sandboxed storage backend; the container id is
        # unambiguous.
        local cid
        cid=$("$CONTAINER_RUNTIME" inspect "pillar-it-${FIXTURE_SCENARIO}-node1" --format '{{.Id}}' 2>/dev/null)
        [ -n "$cid" ] || return 1
        boot_year=$("$CONTAINER_RUNTIME" logs "$cid" 2>&1 | sed -n 's/^\([0-9]\{4\}\)-.*/\1/p' | tail -1)
        [ -n "$boot_year" ]
    }
    retry 30 _chaos_boot_year_ready \
        || fail "chaos-fault: node1's boot log never printed a parseable ISO-8601 timestamped line within 30s of becoming ready"
    local real_year
    real_year=$(date -u +%Y)
    [ "$boot_year" -gt "$real_year" ] \
        || fail "chaos-fault: clock-skew injection did not shift node1's observed wall-clock log timestamp (boot_year='$boot_year' real_year='$real_year') — the skew was not real"
    info "oracle-observed: clock-skew node1's own boot-log timestamp reads year $boot_year (real time is $real_year) — a genuinely interposed +3650d wall clock, observed from its transcript"

    # Assert real-time gossip convergence on node0/node1 (both freshly proven
    # live mesh members); node3's own copy is asserted separately by
    # `_chaos_assert_converged` below via its DURABLE content-addressed store
    # rather than a live-gossip receipt — after 3 prior real faults have each
    # recreated/churned a peer's connection, node3's gossipsub MESH
    # membership (not its underlying anti-entropy connectivity, which stays
    # up throughout) can lag; anti-entropy's periodic pull (never gossip
    # alone) is precisely the wire path this scenario is proving converges
    # it, so gate on that pull's own longer, more tolerant timeout instead of
    # gossip's fixed shorter one.
    local op4="chaos-skew-$$-$(date -u +%s)"
    oracle_streamdb_append 2 "$op4" 0 1
    _chaos_assert_converged "clock skew (node1 rejoined with a genuinely skewed wall clock and still converged)" 90

    # --- fault 5: LOSS DURING BOOTSTRAP --------------------------------------
    # node3 (already recovered from the node-loss fault) is killed a SECOND
    # time immediately after a fresh restart — WHILE it is still mid-bootstrap
    # (before its readiness probe binds, before it redials its peer, before
    # its first anti-entropy round) — then restarted a third time. The cell
    # must still reconverge, proving recovery survives a real interruption
    # DURING the boot/rejoin sequence, not only a clean crash-then-restart.
    "$CONTAINER_RUNTIME" kill "pillar-it-${FIXTURE_SCENARIO}-node3" >/dev/null 2>&1 \
        || fail "chaos-fault: could not kill node3 to start the bootstrap-loss fault"
    "$CONTAINER_RUNTIME" start "pillar-it-${FIXTURE_SCENARIO}-node3" >/dev/null 2>&1 \
        || fail "chaos-fault: could not restart node3 for the bootstrap-loss fault"
    sleep 1
    # A SECOND real kill, deliberately raced against node3's own boot
    # sequence (readiness/dial/anti-entropy all still initializing at this
    # point) rather than waited-out — the "loss during bootstrap" fault.
    "$CONTAINER_RUNTIME" kill "pillar-it-${FIXTURE_SCENARIO}-node3" >/dev/null 2>&1 \
        || fail "chaos-fault: could not deliver the second (mid-bootstrap) kill to node3"
    "$CONTAINER_RUNTIME" start "pillar-it-${FIXTURE_SCENARIO}-node3" >/dev/null 2>&1 \
        || fail "chaos-fault: node3's final restart after the bootstrap-loss fault failed"
    retry 90 _ready3 || fail "chaos-fault: node3 never became ready after being killed twice, including once mid-bootstrap"
    info "oracle-observed: bootstrap-loss node3 survived a SECOND real kill delivered mid-bootstrap and came back ready"
    _chaos_assert_converged "loss during bootstrap (node3 interrupted mid-boot, then fully rejoined)" 90

    info "chaos-fault: every impairment (network partition, node loss, disk wipe, clock skew, loss-during-bootstrap) reconverged the cell to one consistent content-addressed state — no split-brain observed in any case"
}
