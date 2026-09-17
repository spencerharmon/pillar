#!/usr/bin/env bash
# streamdb-perf-benchmark.sh — the fixed rig for the `streamdb-perf-benchmark`
# CHECKS.md stub (ROI Priority 1 "Streamdb performance is a standing,
# self-perpetuating discipline", extended by "The performance + integration
# harness measures BOTH visibility profiles side by side").
#
# Runs `streamdb-perf-bench` (crates/pillar-streamdb/src/bin/
# streamdb-perf-bench.rs), which measures the streamdb op path
# (build+sign+content-address, optionally AEAD-sealed) and the op-log
# view-fold (Merkle-root materialization) under BOTH visibility profiles:
#
#   - public — Confidentiality::Public: signed + content-addressed, no AEAD
#     seal. The throughput/latency CEILING and the fixed baseline.
#   - cell   — Confidentiality::CellEncrypted: the same op, ADDITIONALLY
#     AEAD-sealed to the cell group key.
#
# Both profiles pay the same signing + hashing cost, so `cell - public`
# isolates the pure encryption (AEAD seal/unseal) overhead as its own
# first-class metric (`encryption_delta_ns`), independent of the shared
# non-crypto hot path. `view_fold_ns_per_op` covers the TSDB-analogous
# read-side fold cost for the op-log's materialized view.
#
# Compares the measured run against the tracked baseline
# (scripts/streamdb-perf-baseline.json, sibling to this script): each metric
# must be within STREAMDB_PERF_TOLERANCE (default 0.35 = 35%) of its recorded
# baseline, OR a live waiver naming a filed tuning follow-up task must cover
# it (scripts/streamdb-perf-waivers.json). No baseline yet -> this run BECOMES
# the baseline (first-run bootstrap) and passes.
#
# Exit 0 = every metric within tolerance of baseline (or waived); baseline
#          missing (bootstrapped this run); or --self-test passed every case.
# Exit !0 = a metric regressed against baseline with no covering waiver, or a
#           self-test assertion failed.
#
# Usage:
#   scripts/streamdb-perf-benchmark.sh              # measure + compare + gate
#   scripts/streamdb-perf-benchmark.sh --self-test   # fixture-driven regression test, no cargo build
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
BASELINE_FILE="$HERE/streamdb-perf-baseline.json"
WAIVERS_FILE="$HERE/streamdb-perf-waivers.json"
TOLERANCE="${STREAMDB_PERF_TOLERANCE:-0.35}"
METRICS=(public_op_ns cell_op_ns encryption_delta_ns view_fold_ns_per_op)

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: required tool '$1' not found" >&2; exit 3; }; }
need jq

# Emit a fresh baseline (all measured metrics as-is) as the tracked baseline.
init_baseline() {
    local current_json="$1"
    jq '{public_op_ns, cell_op_ns, encryption_delta_ns, view_fold_ns_per_op}' <<<"$current_json" \
        >"$BASELINE_FILE"
}

# Whether an active (non-expired) waiver in $WAIVERS_FILE covers $1 (metric
# name). A waiver entry looks like:
#   {"metric":"cell_op_ns","task":"<sm>:<taskid>","until":"2026-12-31T00:00:00Z"}
# `until` is an RFC3339 deadline; a waiver past it no longer covers anything
# (so a stale waiver cannot hide a regression forever).
waiver_covers() {
    local metric="$1"
    [ -f "$WAIVERS_FILE" ] || return 1
    local now
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -e --arg m "$metric" --arg now "$now" \
        '[.[] | select(.metric == $m and .until > $now)] | length > 0' \
        "$WAIVERS_FILE" >/dev/null 2>&1
}

# Compare $current_json against $BASELINE_FILE (or $1 as an override baseline
# for --self-test). Prints one line per metric; returns non-zero iff ANY
# metric regressed beyond tolerance with no covering waiver.
evaluate() {
    local current_json="$1"
    local baseline_json="$2"
    local failed=0
    for metric in "${METRICS[@]}"; do
        local cur base allowed
        cur="$(jq -r --arg m "$metric" '.[$m]' <<<"$current_json")"
        base="$(jq -r --arg m "$metric" '.[$m]' <<<"$baseline_json")"
        if [ "$base" = "null" ] || [ -z "$base" ]; then
            echo "SKIP $metric: no baseline recorded"
            continue
        fi
        allowed="$(jq -n --argjson b "$base" --argjson t "$TOLERANCE" '($b * (1 + $t))')"
        if jq -e -n --argjson c "$cur" --argjson a "$allowed" '$c <= $a' >/dev/null 2>&1; then
            echo "OK   $metric: ${cur}ns <= baseline*${TOLERANCE} allowance ${allowed}ns (baseline ${base}ns)"
        else
            if waiver_covers "$metric"; then
                echo "WAIVED $metric: ${cur}ns > allowance ${allowed}ns (baseline ${base}ns) — covered by an active waiver in $WAIVERS_FILE"
            else
                echo "REGRESSION $metric: ${cur}ns > allowance ${allowed}ns (baseline ${base}ns) — no active waiver; file a tuning follow-up task and either fix it or record a waiver naming that task"
                failed=1
            fi
        fi
    done
    return "$failed"
}

self_test() {
    local ok=1
    local baseline='{"public_op_ns":1000,"cell_op_ns":1500,"encryption_delta_ns":500,"view_fold_ns_per_op":100}'

    # Case 1: every metric within tolerance of baseline -> pass.
    local within='{"public_op_ns":1100,"cell_op_ns":1600,"encryption_delta_ns":520,"view_fold_ns_per_op":110}'
    if evaluate "$within" "$baseline" >/dev/null 2>&1; then
        echo "PASS: within-tolerance run is accepted"
    else
        echo "FAIL: within-tolerance run was rejected" >&2
        ok=0
    fi

    # Case 2: a metric far beyond tolerance with NO waiver -> reject.
    local regressed='{"public_op_ns":1000,"cell_op_ns":5000,"encryption_delta_ns":4000,"view_fold_ns_per_op":100}'
    local tmp_waivers
    tmp_waivers="$(mktemp)"
    echo '[]' >"$tmp_waivers"
    WAIVERS_FILE="$tmp_waivers"
    if evaluate "$regressed" "$baseline" >/dev/null 2>&1; then
        echo "FAIL: unwaived regression was incorrectly accepted" >&2
        ok=0
    else
        echo "PASS: unwaived regression is rejected"
    fi

    # Case 3: same regression, but covered by an active (non-expired) waiver
    # -> accepted (with a WAIVED line, not silently OK).
    cat >"$tmp_waivers" <<'JSON'
[{"metric":"cell_op_ns","task":"pillar:example-tuning-task","until":"2999-01-01T00:00:00Z"},
 {"metric":"encryption_delta_ns","task":"pillar:example-tuning-task","until":"2999-01-01T00:00:00Z"}]
JSON
    local out
    out="$(evaluate "$regressed" "$baseline" 2>&1)"
    if grep -q '^REGRESSION' <<<"$out"; then
        echo "FAIL: waived regression still reported as REGRESSION" >&2
        ok=0
    elif grep -q '^WAIVED cell_op_ns' <<<"$out" && grep -q '^WAIVED encryption_delta_ns' <<<"$out"; then
        echo "PASS: actively-waived regression is accepted and reported as WAIVED"
    else
        echo "FAIL: expected WAIVED lines for cell_op_ns and encryption_delta_ns, got: $out" >&2
        ok=0
    fi

    # Case 4: same regression, but the waiver already EXPIRED -> rejected
    # again (a stale waiver cannot hide a regression forever).
    cat >"$tmp_waivers" <<'JSON'
[{"metric":"cell_op_ns","task":"pillar:example-tuning-task","until":"2000-01-01T00:00:00Z"},
 {"metric":"encryption_delta_ns","task":"pillar:example-tuning-task","until":"2000-01-01T00:00:00Z"}]
JSON
    if evaluate "$regressed" "$baseline" >/dev/null 2>&1; then
        echo "FAIL: expired waiver still accepted a regression" >&2
        ok=0
    else
        echo "PASS: expired waiver no longer covers a regression"
    fi

    rm -f "$tmp_waivers"
    [ "$ok" -eq 1 ]
}

if [ "${1:-}" = "--self-test" ]; then
    if self_test; then
        echo "PASS: streamdb-perf-benchmark.sh made the correct accept/reject decision in every case"
        exit 0
    fi
    echo "FAIL: streamdb-perf-benchmark.sh self-test reported a mismatch" >&2
    exit 1
fi

need cargo
echo "streamdb-perf-benchmark: building + running streamdb-perf-bench (release)..." >&2
current_json="$(cd "$REPO_ROOT" && cargo run -q -p pillar-streamdb --release --bin streamdb-perf-bench 2>/dev/null)"
if ! jq -e . >/dev/null 2>&1 <<<"$current_json"; then
    echo "FAIL: streamdb-perf-bench did not emit valid JSON: $current_json" >&2
    exit 1
fi
echo "measured: $current_json"

if [ ! -f "$BASELINE_FILE" ]; then
    init_baseline "$current_json"
    echo "OK: no tracked baseline found — bootstrapped $BASELINE_FILE from this run"
    exit 0
fi

baseline_json="$(cat "$BASELINE_FILE")"
if evaluate "$current_json" "$baseline_json"; then
    echo "PASS: every metric within ${TOLERANCE} tolerance of the tracked baseline (or waived)"
    exit 0
fi
echo "FAIL: at least one metric regressed against the tracked baseline; see REGRESSION lines above" >&2
exit 1
