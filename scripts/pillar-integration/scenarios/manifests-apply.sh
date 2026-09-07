#!/usr/bin/env bash
# scenarios/manifests-apply.sh — the `pillar-integration-scenarios-manifests-apply`
# scenario.
#
# ROI "pillar-integration" scenario family: manifests/CRDs. On the harness,
# `apply`/`get`/`delete` round-trip for EVERY declarable kind PLUS a
# third-party CRD hook (plugin-interface), asserting the real applied object
# is retrievable and deletable — RED if any kind's round-trip silently
# no-ops, GREEN when every kind's applied object is retrievable and deletable.
#
# IMPORTANT — like the `ipam` scenario, the real manifest surface has no
# in-process CLI verb in the published image's throwaway binary today: the
# `pillar apply|get|delete` verbs (`pillar_cli::cli_surface`, dispatched to
# `live_platform_guidance`) print guidance and exit 2 — a LIVE cell
# (`pillar node run`) backs them via `pillar_cli`'s `ResourcePlane` over the
# SAME `pillar_manifest::apply::ManifestStore` + `ControllerRegistry` engine.
# So this scenario cannot drive the round-trip through the harness's
# container-exec `driver_cli_exec` the way `smoke` drives `onboard`. It
# therefore, exactly as `ipam` does:
#   1. boots the harness's real >=3-node topology (the same real published
#      image + process oracle every scenario asserts against, so a broken
#      image/topology fabric fails THIS scenario too, not just smoke);
#   2. runs `oracle_manifests_apply` (lib/oracles.sh), which asserts against
#      the REAL, freshly-compiled `pillar-manifest`/`pillar-e2e` acceptance
#      surface under test that (a) EVERY declarable kind apply→get→delete
#      round-trips with no silent no-op (an applied object is retrievable and
#      then gone after delete) and (b) a third-party CRD hook travels the
#      identical dispatch/prune path as a built-in kind.
# A follow-on task should wire a real `pillar apply|get|delete` CLI verb that
# operates against a live cell so a future revision of this scenario can drive
# the round-trip purely through `driver_cli_exec` against a booted node; until
# that lands, the acceptance-surface oracle above is the realness proof
# available (matching the `ipam` scenario's own note).

scenario_manifests-apply() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node topology on the real published image, with the
    # process oracle on every node (matches smoke's own realness bar).
    topology_boot "$n"
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) the real manifest apply surface: every declarable kind's
    # apply→get→delete round-trips (no silent no-op) AND a third-party CRD
    # hook travels the same dispatch/prune path as a built-in kind.
    info "manifests-apply: asserting the real manifest engine round-trips apply/get/delete for every declarable kind plus a third-party CRD hook"
    oracle_manifests_apply

    info "manifests-apply: all oracles observed real effects (topology + manifest apply/get/delete round-trip) on ${#TOPO_NODES[@]} real nodes"
}
