#!/usr/bin/env bash
# scenarios/scheduler.sh — the `scheduler` scenario.
#
# The `pillar-integration` scheduler family's black-box proof: on a real
# multi-node topology of the REAL published image, a CronJob registered into
# each live node's scheduler runtime fires on the node's REAL wall clock and
# spawns/exits a REAL OS process per its declared schedule — driven through the
# ONE shared `pillar_manifest::scheduler` engine (`scheduler-controller-impl`)
# wired to real supervised processes on a live node
# (`scheduler-node-runtime-wiring`), with no second, private scheduler.
#
#   RED  if a job silently no-ops on schedule (no real process ever spawned).
#   GREEN when a real process is observed spawned/exited per the CronJob's
#         declared schedule.
#
# It is deliberately black-box: it never links a pillar crate and never reads
# pillar's internal state. It observes only:
#   - the node's real container process + bound readiness socket (process
#     oracle), proving the node is genuinely up; and
#   - the node's own stdout `job-run: <name> <status> pid=<pid>` lines (the
#     scheduler node runtime's black-box surface), proving each real scheduler
#     run — a fresh real pid per due period, reaped to a terminal status.
#
# The scheduler engine's concurrency-policy, bounded-backoff, and identical
# workload/observability dispatch (OneEngineNoFork) invariants are refined in
# `specs/SchedulerController.tla` and covered by the deps' merged unit tests
# (`cargo test -p pillar-manifest scheduler::`,
# `cargo test -p pillar-controller scheduler_runtime::`); this scenario asserts
# the one effect only a REAL, live node can produce and a unit test cannot: a
# CronJob spawning and reaping a REAL OS process on a real wall clock.
#
# Sourced by run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init.

scenario_scheduler() {
    local n="${PILLAR_IT_NODES:-3}"
    local job="${PILLAR_IT_CRONJOB_NAME:-it-cron}"
    local period="${PILLAR_IT_CRONJOB_PERIOD:-2}"
    local min_runs="${PILLAR_IT_CRONJOB_MIN_RUNS:-2}"

    # (1) real >=3-node topology on the real ghcr image, each node carrying the
    # rig CronJob hook (a real CronJob registered into its live scheduler
    # runtime, firing on the node's real wall clock).
    topology_boot_scheduler "$n" "$job" "$period"

    # (2) the node is genuinely a real running process with a bound readiness
    # socket before we assert its scheduler behaviour.
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (3) the scheduler oracle on every node: a real CronJob fires on the real
    # wall clock and spawns/exits a real process per its declared schedule.
    for i in "${!TOPO_NODES[@]}"; do
        oracle_scheduler_cronjob "${TOPO_NODES[$i]}" "$job" "$period" "$min_runs"
    done

    info "scheduler: all oracles observed real scheduled process spawns/exits on ${#TOPO_NODES[@]} real nodes"
}
