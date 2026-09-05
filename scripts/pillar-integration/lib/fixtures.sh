#!/usr/bin/env bash
# fixtures.sh — the fixture / lifecycle manager.
#
# Owns provision + idempotent teardown + leak detection for the resources a
# scenario needs (its container nodes, per-scenario data dirs, and the label
# namespace that isolates one scenario's resources from another's). It holds
# NO state shared with pillar internals — a fixture is a real external
# resource (a container, a temp dir) the harness created and can independently
# observe and reclaim.
#
# Isolation: every resource a scenario creates is stamped with the label
# `pillar-it-scenario=<id>` (containers) and lives under a per-scenario temp
# root, so two scenarios never touch the same fixture resource — the executable
# analogue of PillarIntegration.tla's NoSharedFixtureState.
#
# Idempotent teardown + leak detection: `fixtures_teardown` removes every
# labelled resource and is safe to call repeatedly (matching
# TeardownReleasesFixtures); `fixtures_leak_check` then asserts ZERO residue
# remains for the scenario (NoResidueWhenSealed) and fails loudly otherwise.

# fixtures_init <scenario-id> : establish the isolated fixture namespace.
fixtures_init() {
    FIXTURE_SCENARIO="$1"
    FIXTURE_LABEL="pillar-it-scenario=${FIXTURE_SCENARIO}"
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pillar-it-${FIXTURE_SCENARIO}.XXXXXX")"
    export FIXTURE_SCENARIO FIXTURE_LABEL FIXTURE_ROOT
    # Best-effort clean of any residue from a previous aborted run of the SAME
    # scenario, so provision starts from a known-empty fixture namespace
    # (idempotent provision).
    fixtures_teardown quiet
    info "fixtures: scenario=$FIXTURE_SCENARIO root=$FIXTURE_ROOT label=$FIXTURE_LABEL"
}

# fixtures_list_containers : print the ids of every container this scenario owns.
fixtures_list_containers() {
    "$CONTAINER_RUNTIME" ps -aq --filter "label=${FIXTURE_LABEL}" 2>/dev/null
}

# fixtures_teardown [quiet] : idempotently release every fixture resource.
# Safe to call any number of times, including when nothing was provisioned.
fixtures_teardown() {
    local quiet="${1:-}"
    local cids
    cids="$(fixtures_list_containers)"
    if [ -n "$cids" ]; then
        [ "$quiet" = quiet ] || info "fixtures: tearing down $(echo "$cids" | wc -l | tr -d ' ') container(s)"
        # shellcheck disable=SC2086
        "$CONTAINER_RUNTIME" rm -f $cids >/dev/null 2>&1 || true
    fi
    [ -n "${FIXTURE_ROOT:-}" ] && rm -rf "$FIXTURE_ROOT" 2>/dev/null || true
}

# fixtures_leak_check : assert NO residue remains for this scenario. Exit 0 =
# leak detector clean (no leaked container, no surviving fixture root).
fixtures_leak_check() {
    local leaked cids
    leaked=0
    cids="$(fixtures_list_containers)"
    if [ -n "$cids" ]; then
        warn "leak: scenario $FIXTURE_SCENARIO left container(s): $cids"
        leaked=1
    fi
    if [ -n "${FIXTURE_ROOT:-}" ] && [ -e "$FIXTURE_ROOT" ]; then
        warn "leak: scenario $FIXTURE_SCENARIO left fixture root: $FIXTURE_ROOT"
        leaked=1
    fi
    if [ "$leaked" -ne 0 ]; then
        return 1
    fi
    info "leak-detector: clean — scenario $FIXTURE_SCENARIO holds zero residue"
    return 0
}
