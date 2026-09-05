#!/usr/bin/env bash
# scenarios/versioning-rollout.sh — the "pillar-integration" scenario family
# covering versioning / rollout (operator-directed, 2026-08-31).
#
# Rolls a mixed-version cell through a REAL compat-window negotiation on the
# black-box integration harness and asserts the four safe-rollout invariants
# the ROI names, driving the REAL published image SOLELY through its external
# surfaces (its `/readyz` HTTP probe and its `pillar rollout` CLI verb), never
# linking a pillar crate:
#
#   1. NO mid-rollout node serves traffic before readiness — every node is held
#      OUT of service until its real readiness probe passes (asserted by the
#      `oracle_process` realness oracle observing a real pid + a real bound
#      socket answering `GET /readyz -> 200 'ready'` on every node BEFORE any
#      rollout traffic is driven);
#   2. NO data loss across the migration — the real image's `rollout` verb
#      asserts the new materialized view's content-addressed Merkle root equals
#      the old view's over the same op log and that no op is dropped at cutover;
#   3. readiness GATING holds a node out of service until its real probe passes
#      — the `rollout` verb asserts an un-upgraded live member blocks cutover
#      and is never served the new view early;
#   4. a rollback restores the prior version cleanly — the `rollout` verb
#      asserts the prior declared version is restored exactly and the
#      content-addressed exchange log is uncorrupted.
#
#   RED  if a mid-rollout node answers ready before its probe passes, OR the
#        real image's rollout verb reports a FAIL: on any negotiation /
#        migration / rollback / readiness invariant (data loss or a bypassed
#        gate).
#   GREEN when every node is held out until ready AND all five `ok:` rollout
#        steps are observed from the real image.
#
# Sourced by run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init.
scenario_versioning-rollout() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) real >=3-node topology on the real ghcr image.
    topology_boot "$n"

    # (2) HOLD EVERY NODE OUT OF SERVICE UNTIL ITS REAL READINESS PROBE PASSES.
    # The process oracle observes a real pid + a real bound socket answering
    # `GET /readyz -> 200 'ready'` on every node before any rollout traffic is
    # driven; a node serving before readiness would be RED here.
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done
    info "versioning-rollout: every node held OUT of service until its real /readyz probe passed"

    # (3) Drive the real image's `pillar rollout` verb through the CLI driver
    # (a throwaway container running the real image bytes, no crate linkage) and
    # assert every one of the five safe-rollout `ok:` steps is observed.
    oracle_rollout

    info "versioning-rollout: mixed-version cell rolled through a real compat-window negotiation — no traffic before ready, no data loss, readiness-gated cutover, clean rollback, all observed on the real image"
}
