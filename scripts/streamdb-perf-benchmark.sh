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
# This sandbox runs on shared, occasionally-throttled CPUs: a single process
# invocation can land in a multi-second contention/throttling window that no
# amount of in-process trial-taking can see past (the whole process stalls).
# So run several INDEPENDENT process invocations and take the per-metric MIN
# across all of them — the closest a wall-clock harness can get to "cost on
# quiet hardware" in a noisy sandbox. A contention window can only ever make a
# run slower, never faster, so the min isolates the real steady-state cost.
invocations="${STREAMDB_PERF_INVOCATIONS:-3}"
metrics_all=(calib_ns_per_op append_ns_per_op view_fold_ns_per_op merge_ns_per_op compact_ns_per_op)
measured=""
echo "streamdb-perf: building + running harness (n=$n, invocations=$invocations) ..." >&2
for run in $(seq 1 "$invocations"); do
  out="$(cd "$repo_root" && cargo run -q -p pillar-streamdb --example perf_bench --release -- "$n" 2>/dev/null)" \
    || fail "perf harness failed to build/run (crypto-realness guard may have tripped — see stderr)"
  echo "$out" | jq -e . >/dev/null 2>&1 || fail "harness did not emit valid JSON: $out"
  echo "streamdb-perf: run $run/$invocations measured $out" >&2
  if [[ -z "$measured" ]]; then
    measured="$out"
  else
    merged="$measured"
    for m in "${metrics_all[@]}"; do
      a="$(echo "$merged" | jq -r --arg m "$m" '.[$m]')"
      b="$(echo "$out" | jq -r --arg m "$m" '.[$m]')"
      min="$(jq -n --argjson a "$a" --argjson b "$b" 'if $a < $b then $a else $b end')"
      merged="$(echo "$merged" | jq --arg m "$m" --argjson v "$min" '.[$m] = $v')"
    done
    measured="$merged"
  fi
done
echo "streamdb-perf: measured (min across $invocations runs) $measured" >&2
if [[ -n "${STREAMDB_PERF_JSON:-}" ]]; then
  printf '%s\n' "$measured" > "$STREAMDB_PERF_JSON"
fi

measured_n="$(echo "$measured" | jq -r '.n')"
baseline_n="$(jq -r '.n' "$baseline")"
if [[ "$measured_n" != "$baseline_n" ]]; then
  echo "WARN: measured n=$measured_n != baseline n=$baseline_n; comparison is not apples-to-apples" >&2
fi

# --- 2/3. compare each metric ----------------------------------------------
# Every metric is compared as (metric_ns_per_op / calib_ns_per_op) against the
# SAME ratio recorded in the baseline, not as raw ns/op. calib_ns_per_op is a
# fixed, streamdb-free integer workload measured in the exact same process/run
# (see perf_bench.rs); dividing by it cancels out this run's absolute CPU
# throughput (rig identity, thermal/frequency state, container CPU quota) so
# the comparison isolates the streamdb-specific cost the discipline actually
# cares about, instead of flagging "this sandbox's CPU was slower today" as a
# regression.
metrics=(append_ns_per_op view_fold_ns_per_op merge_ns_per_op compact_ns_per_op)
regressions=0
uncovered=0

calib_got="$(echo "$measured" | jq -r '.calib_ns_per_op')"
calib_base="$(jq -r '.metrics.calib_ns_per_op // 1' "$baseline")"
if [[ -z "$calib_got" || "$calib_got" == "null" ]]; then
  fail "measurement missing calib_ns_per_op (rebuild harness — old binary?)"
fi

for m in "${metrics[@]}"; do
  base_raw="$(jq -r --arg m "$m" '.metrics[$m]' "$baseline")"
  got_raw="$(echo "$measured" | jq -r --arg m "$m" '.[$m]')"
  if [[ -z "$base_raw" || "$base_raw" == "null" ]]; then
    fail "baseline missing metric '$m'"
  fi
  if [[ -z "$got_raw" || "$got_raw" == "null" ]]; then
    fail "measurement missing metric '$m'"
  fi
  # normalize both sides to "cost per calibration unit" before comparing.
  base="$(jq -n --argjson v "$base_raw" --argjson c "$calib_base" '$v / $c')"
  got="$(jq -n --argjson v "$got_raw" --argjson c "$calib_got" '$v / $c')"
  # limit = base * tolerance ; regressed = got > limit
  regressed="$(jq -n --argjson g "$got" --argjson b "$base" --argjson t "$tolerance" \
    '($g > ($b * $t))')"
  # ratio for reporting (also calib-normalized, so it is rig-independent)
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
