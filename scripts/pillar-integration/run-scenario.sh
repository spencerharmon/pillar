#!/usr/bin/env bash
# run-scenario.sh — the pillar black-box integration harness entrypoint.
#
# Usage: run-scenario.sh <scenario> [scenario-args...]
#
# Stands up a real, multi-node pillar topology from the REAL published
# container image, drives pillar SOLELY through its external surfaces (CLI /
# HTTP / wire / manifest apply — never linking a pillar crate), asserts a
# realness oracle that observes a real external effect (a pid, a bound socket,
# a decryptable ciphertext, a resolvable CID — never a return code), then tears
# the topology down IDEMPOTENTLY even on failure and leak-checks for zero
# residue.
#
# This is the harness every `pillar-integration` scenario family builds ON: the
# topology fabric (lib/topology.sh), the driver layer (lib/drivers.sh), the
# oracle library (lib/oracles.sh), and the fixture/lifecycle manager
# (lib/fixtures.sh). It has NO shared state with pillar internals.
#
# `smoke` is the harness's own definition-of-done: a >=3-node topology on the
# real image, one manifest applied through the CLI driver, one real-effect
# oracle (the process oracle), clean idempotent teardown, and a clean leak
# detector. A SECOND `smoke` run leaves no leaked resources either.
#
# Exit 0 = the scenario's every oracle observed its real effect AND teardown
#          left zero residue. Exit !0 = the first violated step, printed with
#          diagnostics; teardown STILL runs (unconditional teardown).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/lib"
SCENARIOS="$HERE/scenarios"

# shellcheck source=lib/common.sh
. "$LIB/common.sh"
# shellcheck source=lib/fixtures.sh
. "$LIB/fixtures.sh"
# shellcheck source=lib/topology.sh
. "$LIB/topology.sh"
# shellcheck source=lib/drivers.sh
. "$LIB/drivers.sh"
# shellcheck source=lib/oracles.sh
. "$LIB/oracles.sh"

SCENARIO="${1:-}"
[ -n "$SCENARIO" ] || fail "usage: run-scenario.sh <scenario> [args...] (e.g. 'smoke')"
shift || true

SCENARIO_FILE="$SCENARIOS/${SCENARIO}.sh"
[ -f "$SCENARIO_FILE" ] || fail "unknown scenario '$SCENARIO' (no $SCENARIO_FILE)"
# shellcheck source=/dev/null
. "$SCENARIO_FILE"

FN="scenario_${SCENARIO}"
command -v "$FN" >/dev/null 2>&1 || fail "scenario file $SCENARIO_FILE defines no $FN"

resolve_container_runtime
fixtures_init "$SCENARIO"

# UNCONDITIONAL teardown + leak detection on EVERY exit path (pass or fail),
# matching PillarIntegration.tla's NoStateSkipsTeardown / NoResidueWhenSealed.
LEAK_STATUS=0
finish() {
    local rc=$?
    info "harness: tearing down scenario '$SCENARIO' (unconditional)"
    fixtures_teardown
    if ! fixtures_leak_check; then
        LEAK_STATUS=1
    fi
    if [ "$rc" -eq 0 ] && [ "$LEAK_STATUS" -ne 0 ]; then
        # A clean scenario that leaked resources is itself a failure.
        rc=1
    fi
    if [ "$rc" -eq 0 ]; then
        info "PASS: scenario '$SCENARIO' — every oracle observed a real effect, teardown left zero residue"
    else
        warn "FAIL: scenario '$SCENARIO' (rc=$rc, leak=$LEAK_STATUS)"
    fi
    exit "$rc"
}
trap finish EXIT

info "harness: running scenario '$SCENARIO' against real image $PILLAR_IMAGE"
"$FN" "$@"
