#!/usr/bin/env bash
# scenarios/versioning-rollout.sh — the versioning / rollout scenario.
#
# The `pillar-integration` ROI's versioning/rollout scenario family
# (operator-directed, 2026-08-31). It drives the REAL published image SOLELY
# through its external surfaces — no pillar crate is linked — and asserts the
# ROI's four versioning/rollout guarantees: on the harness, roll a mixed-version
# cell through a REAL compat-window negotiation, assert no data loss across the
# migration, assert readiness gating holds a node OUT of service until its real
# health probe passes, and assert a rollback restores the prior version cleanly.
#
# Real external effects it observes (never a return code):
#
#   1. READINESS GATING (live topology) — a real >=3-node topology on the real
#      ghcr image, each node's Kubernetes-style readiness probe (health.rs
#      `/readyz` over a real bound socket) is polled by the PROCESS oracle: a
#      node is admitted to service ONLY once it answers `200 ready` on its real
#      socket (a mid-rollout node that has not converged answers `503 not-ready`
#      and is held out). This is the ROI's "readiness gating holds a node out of
#      service until its real health probe passes", observed on the live cell.
#
#   2. COMPAT NEGOTIATION + NO-DATA-LOSS MIGRATION + ROLLBACK (real image CLI) —
#      the `pillar versioning-rollout` verb, run against the REAL published image
#      via the CLI driver, exercises the real `pillar_crypto::compat`
#      negotiation, the real `pillar_cells::migration::MigrationCoordinator`
#      rolling cutover, the real readiness decision, and a real rollback in one
#      process. It prints one `ok: <step>` line per guarantee and fails closed
#      (non-zero, no `ok:` line) the instant any invariant is violated:
#        - compat-window-negotiation      — a mixed-version cell negotiates the
#          migrating surface within the N-1 window; an out-of-window member is
#          cleanly REFUSED, never silently mis-linked.
#        - migration-no-data-loss         — a rolling migration cutover leaves
#          the content-addressed Merkle root IDENTICAL to the pre-migration op
#          set: no op dropped across the migration (RED if data is lost).
#        - readiness-gating-holds-node-out — a not-yet-rehydrated node's real
#          readiness surface returns `503 not-ready: views-rehydrated`,
#          flipping to `200 ready` only once every real condition holds (RED if
#          an unready node serves traffic before readiness).
#        - rollback-restores-prior-version — a rollback drives the prior version
#          back over the SAME op set and restores the original op-set root
#          cleanly.
#
# Together these assert the ROI's RED/GREEN contract: RED if a mid-rollout node
# serves traffic before readiness or loses data across the migration, GREEN when
# both hold. Sourced by run-scenario.sh, which has already sourced the lib layer
# and run fixtures_init. All resources are labelled into the fixture namespace,
# so the harness's UNCONDITIONAL teardown + leak detector reclaim every real
# resource even on failure.

scenario_versioning-rollout() {
    local n="${PILLAR_IT_NODES:-3}"

    # Ensure the image the scenario drives ACTUALLY serves the versioning/
    # rollout CLI surface (`versioning-rollout`). If the published image lags
    # the working tree — or cannot be pulled at all — this builds a
    # reproducible image-under-test from the flake and repoints $PILLAR_IMAGE
    # at it, so both `topology_boot` and the `oracle_versioning_rollout` CLI
    # driver run against an image that really dispatches the verb (the exact
    # gap trust-rbac.sh closes with `image_require_verb apply-authz`). Without
    # this the scenario spuriously FAILs on the stale published image with
    # "unknown verb `versioning-rollout`" (or "could not pull") — not because
    # the surface is broken but because the published image is behind.
    image_require_verb versioning-rollout

    # (1) real >=3-node topology on the real ghcr image.
    topology_boot "$n"

    # READINESS GATING on the live cell: every node must be a real running
    # process that is admitted to service ONLY once its real readiness probe
    # answers `200 ready` on its bound socket (the process oracle polls
    # /readyz and FAILS if a node reports anything but ready). This is the
    # live-topology half of the ROI's "readiness gating holds a node out of
    # service until its real health probe passes".
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) COMPAT NEGOTIATION + NO-DATA-LOSS MIGRATION + READINESS-GATE +
    # ROLLBACK: drive the real image's `versioning-rollout` verb and assert
    # every guarantee's `ok:` line.
    oracle_versioning_rollout

    info "versioning-rollout: readiness gating admitted ${#TOPO_NODES[@]} real nodes only when ready, and the real image rolled a mixed-version cell through compat negotiation, a no-data-loss migration, readiness gating, and a clean rollback"
}
