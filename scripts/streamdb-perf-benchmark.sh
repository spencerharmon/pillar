#!/usr/bin/env bash
# streamdb-perf-benchmark.sh — the recurring streamdb performance harness
# (ROI P1 "Streamdb performance is a standing, self-perpetuating discipline").
#
# Registered in submodules/pillar/CHECKS.md as the `streamdb-perf-benchmark`
# stub. It measures the REAL streamdb hot paths and gates on a tracked baseline:
#
#   1. Build + run the deterministic Rust harness
#      (`cargo run -p pillar-streamdb --example perf_bench --release`), which
#      exercises the real content-address + Merkle-fold primitives (it aborts
#      if that crypto has been weakened) and emits a JSON metrics blob.
#   2. Compare each metric (ns/op, lower is better) against
#      scripts/streamdb-perf-baseline.json with a regression tolerance
#      (STREAMDB_PERF_TOLERANCE, default 1.40).
#   3. Exit 0 when every metric meets/beats baseline*tolerance.
#      On a REGRESSION (a metric worse than baseline*tolerance) exit 0 ONLY if a
#      tuning follow-up for that metric has been filed (a marker under
#      scripts/streamdb-perf-followups/<metric>.md, the durable record the
#      recurring task drops when it files the follow-up); otherwise exit non-zero
#      so the check FAILS — the real measured effect, never a plausible number.
#
# HARD INVARIANT: a follow-up may only make things faster WITHOUT weakening a
# guarantee (verifiability, per-op signing, content-addressing, per-stream CAP
# posture). The harness asserts the real crypto root before timing; a follow-up
# that drops a hash/signature/seal is a bug and must fail review.
#
# Usage: scripts/streamdb-perf-benchmark.sh [N]
#   N                        op count (default 5000; must match the baseline's n
#                            for an apples-to-apples comparison, else a warning).
#   STREAMDB_PERF_TOLERANCE  allowed slowdown factor vs baseline (default 1.40).
#   STREAMDB_PERF_JSON       if set, write the measured JSON blob to this path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
baseline="$here/streamdb-perf-baseline.json"
followups_dir="$here/streamdb-perf-followups"
n="${1:-5000}"
tolerance="${STREAMDB_PERF_TOLERANCE:-1.40}"

fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required tool '$1' not found"; }
need cargo
need jq

[[ -f "$baseline" ]] || fail "baseline not found: $baseline"

# --- 1. run the harness -----------------------------------------------------
echo "streamdb-perf: building + running harness (n=$n) ..." >&2
measured="$(cd "$repo_root" && cargo run -q -p pillar-streamdb --example perf_bench --release -- "$n" 2>/dev/null)" \
  || fail "perf harness failed to build/run (crypto-realness guard may have tripped — see stderr)"

echo "$measured" | jq -e . >/dev/null 2>&1 || fail "harness did not emit valid JSON: $measured"
echo "streamdb-perf: measured $measured" >&2
if [[ -n "${STREAMDB_PERF_JSON:-}" ]]; then
  printf '%s\n' "$measured" > "$STREAMDB_PERF_JSON"
fi

measured_n="$(echo "$measured" | jq -r '.n')"
baseline_n="$(jq -r '.n' "$baseline")"
if [[ "$measured_n" != "$baseline_n" ]]; then
  echo "WARN: measured n=$measured_n != baseline n=$baseline_n; comparison is not apples-to-apples" >&2
fi

# --- 2/3. compare each metric ----------------------------------------------
metrics=(append_ns_per_op view_fold_ns_per_op merge_ns_per_op compact_ns_per_op)
regressions=0
uncovered=0

for m in "${metrics[@]}"; do
  base="$(jq -r --arg m "$m" '.metrics[$m]' "$baseline")"
  got="$(echo "$measured" | jq -r --arg m "$m" '.[$m]')"
  if [[ -z "$base" || "$base" == "null" ]]; then
    fail "baseline missing metric '$m'"
  fi
  if [[ -z "$got" || "$got" == "null" ]]; then
    fail "measurement missing metric '$m'"
  fi
  # limit = base * tolerance ; regressed = got > limit
  regressed="$(jq -n --argjson g "$got" --argjson b "$base" --argjson t "$tolerance" \
    '($g > ($b * $t))')"
  # ratio for reporting
  ratio="$(jq -n --argjson g "$got" --argjson b "$base" '(($g / $b) * 1000 | round) / 1000')"
  if [[ "$regressed" == "true" ]]; then
    marker="$followups_dir/$m.md"
    if [[ -f "$marker" ]]; then
      echo "REGRESSION (covered by filed follow-up $marker): $m got=$got baseline=$base ratio=${ratio}x" >&2
      regressions=$((regressions + 1))
    else
      echo "REGRESSION (NO follow-up filed): $m got=$got baseline=$base ratio=${ratio}x tolerance=${tolerance}x" >&2
      uncovered=$((uncovered + 1))
    fi
  else
    echo "ok: $m got=$got baseline=$base ratio=${ratio}x" >&2
  fi
done

if (( uncovered > 0 )); then
  fail "$uncovered streamdb metric(s) regressed past ${tolerance}x baseline with no follow-up tuning task filed. Either fix the regression, or file a follow-up tuning task (each with its own measurable before/after DoD, weakening NO guarantee) and drop a marker under scripts/streamdb-perf-followups/<metric>.md."
fi

if (( regressions > 0 )); then
  echo "PASS (with $regressions regression(s) already tracked by filed follow-ups)." >&2
else
  echo "PASS: every streamdb metric meets or beats baseline within ${tolerance}x." >&2
fi
exit 0
