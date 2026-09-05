#!/usr/bin/env bash
# scenarios/smoke.sh — the smoke scenario.
#
# The minimal end-to-end proof that the whole harness works against the REAL
# published image, and the definition-of-done check for the harness task
# (`run-scenario.sh smoke`):
#
#   1. boot a real >=3-node topology on the real ghcr image;
#   2. apply one "manifest" through the CLI driver (drive the real image's CLI
#      surface, asserting its real crypto onboarding effect);
#   3. pass one real-effect oracle — the PROCESS oracle observes a real pid +
#      a real bound listening socket on every node;
#   4. tear the topology down; a leak-detector pass confirms zero residue.
#
# It is deliberately black-box: it never links a pillar crate, never reads
# pillar's internal state — it observes only containers, sockets, and CLI
# output. Sourced by run-scenario.sh, which has already sourced the lib layer
# and run fixtures_init.

scenario_smoke() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node topology on the real ghcr image.
    topology_boot "$n"

    # (2) apply one manifest through the CLI driver: exercise the real image's
    # CLI surface and assert its real cryptographic effect (real keygen ->
    # node-key signing -> cross-user trust -> policy, fail-closed).
    info "smoke: applying a manifest through the CLI driver (real-image onboard)"
    oracle_crypto_realness

    # (3) process oracle on every node: a real pid + a real listening socket.
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    info "smoke: all oracles observed real external effects on ${#TOPO_NODES[@]} real nodes"
}
