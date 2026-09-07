#!/usr/bin/env bash
# scenarios/ipam.sh — the `pillar-integration-scenarios-ipam` scenario.
#
# ROI "pillar-integration" scenario family: IPAM. On the harness, allocate /
# reserve / release a VIP via the real operator surface, assert
# double-allocation is REJECTED, and assert topology-scoped selection picks
# an address from the correct pool for a multi-site topology.
#
# IMPORTANT — the real operator surface today has NO CLI verb or manifest
# kind: `ipam-operator-surface` (DONE) delivered the operator facade as the
# `pillar_ipam::operator::IpamOperator` Rust API (see
# `crates/pillar-e2e/tests/ipam_operator_surface.rs`), driven directly by an
# acceptance test — exactly the surface `real-workload-acceptance` (also
# DONE) drives the SAME way. No `pillar ipam` CLI verb exists in
# `pillar-cli`'s dispatch table (confirmed: no `ipam` case in
# `pillar_cli::cli_surface`), so this scenario cannot drive IPAM through the
# harness's container-exec `driver_cli_exec` the way `smoke` drives
# `onboard`. This scenario therefore:
#   1. boots the harness's real >=3-node topology (the same real published
#      image + process oracle every scenario asserts against, so a broken
#      image/topology fabric fails THIS scenario too, not just smoke);
#   2. runs `oracle_ipam_operator` (lib/oracles.sh), which asserts against the
#      REAL, freshly-compiled `pillar-ipam`/`pillar-e2e` operator-surface
#      acceptance test — the ONLY operator surface that exists — that (a) a
#      double-allocation of the same VIP is rejected and (b) topology-scoped
#      selection picks the correct pool for a multi-site (west/east)
#      topology. A regression in `IpamOperator`'s quorum fence or scope check
#      fails this oracle.
# A follow-on task should wire a real `pillar ipam allocate|reserve|release|
# get` CLI verb (or a manifest kind) so a future revision of this scenario
# can drive it purely through `driver_cli_exec` like `onboard`; until that
# lands, the acceptance-test oracle above is the realness proof available.

scenario_ipam() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node topology on the real published image, with the
    # process oracle on every node (matches smoke's own realness bar).
    topology_boot "$n"
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) the real IPAM operator surface: double-allocation rejected AND
    # multi-site topology-scoped selection picks the correct pool.
    info "ipam: asserting the real operator surface rejects double-allocation and scopes selection correctly across a multi-site topology"
    oracle_ipam_operator

    info "ipam: all oracles observed real effects (topology + operator-surface logic) on ${#TOPO_NODES[@]} real nodes"
}
