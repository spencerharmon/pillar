#!/usr/bin/env bash
# streamdb-perf-benchmark.sh — the `streamdb-perf-benchmark` CHECKS.md harness.
#
# Runs the dual-profile streamdb performance test
# (crates/pillar-streamdb/tests/perf_benchmark.rs), which measures op
# throughput/latency and view-fold cost through BOTH visibility profiles
# side by side (PUBLIC = unencrypted ceiling/baseline, CELL-ENCRYPTED =
# guaranteed-confidentiality) and prints a machine-readable
# `STREAMDB_PERF_JSON {...}` line, tracking the public<->encrypted DELTA
# (AEAD seal overhead) as a first-class metric.
#
# This wrapper parses that JSON and compares each latency metric against the
# tracked baseline (scripts/streamdb-perf-baseline.json). Exit code reflects
# the baseline comparison:
#   0  — every metric within baseline * (1 + tolerance): NO regression.
#   1  — a regression against baseline: at least one latency metric exceeds
#        its tolerance band. The recurring task must file a concrete tuning
#        follow-up (see the design doc) before it can be considered handled.
#   2  — harness failure (build/test error, missing baseline, unparseable
#        output): the measurement itself did not run.
#
# The HARD INVARIANT (encrypted profile still seals + signs + content-addresses
# every op; public profile still signs) is asserted INSIDE the test and gates
# the numbers there — a profile that skipped a guarantee fails the test (exit 2
# here) rather than reporting a bogus speedup.
#
# Usage: scripts/streamdb-perf-benchmark.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BASELINE="${SCRIPT_DIR}/streamdb-perf-baseline.json"

fail_harness() { echo "streamdb-perf-benchmark: HARNESS ERROR: $*" >&2; exit 2; }

command -v cargo >/dev/null 2>&1 || fail_harness "cargo not found on PATH"
[ -f "${BASELINE}" ] || fail_harness "tracked baseline missing: ${BASELINE}"

echo "streamdb-perf-benchmark: running dual-profile harness (cargo test) ..." >&2
RAW="$(cd "${REPO_ROOT}" && cargo test -p pillar-streamdb --test perf_benchmark -- --nocapture 2>&1)" \
    || { echo "${RAW}" >&2; fail_harness "perf_benchmark test failed (build/test/invariant error)"; }

JSON="$(printf '%s\n' "${RAW}" | sed -n 's/^STREAMDB_PERF_JSON //p' | tail -n1)"
[ -n "${JSON}" ] || { echo "${RAW}" >&2; fail_harness "no STREAMDB_PERF_JSON line in test output"; }

echo "streamdb-perf-benchmark: measured ${JSON}" >&2

# Pull one numeric field from a flat JSON object ({"k":v,...}). No jq dependency
# so the harness runs anywhere cargo does.
field() {
  local obj="$1" key="$2"
  printf '%s' "${obj}" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([-0-9.]*\).*/\1/p" | head -n1
}

BASELINE_JSON="$(tr -d '\n' < "${BASELINE}")"

TOL="$(field "${BASELINE_JSON}" tolerance)"
[ -n "${TOL}" ] || fail_harness "baseline missing 'tolerance'"

REGRESSED=0
# Latency metrics where LOWER is better; a regression is measured > baseline*(1+tol).
for KEY in public_op_us encrypted_op_us op_delta_us public_fold_ns_per_op encrypted_fold_ns_per_op; do
  MEAS="$(field "${JSON}" "${KEY}")"
  BASE="$(field "${BASELINE_JSON}" "${KEY}")"
  if [ -z "${MEAS}" ] || [ -z "${BASE}" ]; then
    fail_harness "metric '${KEY}' missing (measured='${MEAS}' baseline='${BASE}')"
  fi
  # Bash has no float math; use awk for the comparison.
  VERDICT="$(awk -v m="${MEAS}" -v b="${BASE}" -v t="${TOL}" 'BEGIN{
    limit = b * (1.0 + t);
    if (m > limit) printf "REGRESS %.4f > %.4f", m, limit;
    else printf "ok %.4f <= %.4f", m, limit;
  }')"
  case "${VERDICT}" in
    REGRESS*) echo "streamdb-perf-benchmark: REGRESSION ${KEY}: ${VERDICT#REGRESS }" >&2; REGRESSED=1 ;;
    *)        echo "streamdb-perf-benchmark: ${KEY}: ${VERDICT#ok }" >&2 ;;
  esac
done

if [ "${REGRESSED}" -ne 0 ]; then
  cat >&2 <<'EOF'
streamdb-perf-benchmark: FAIL — a metric regressed past the baseline tolerance.
The recurring task must file a concrete tuning follow-up (own before/after DoD;
must not weaken verifiability/signing/content-addressing/CAP posture) before
this run is considered handled. See
submodules/pillar/docs/bee-streamdb-perf-benchmark-recurring-streamdb-perf-benchmark-recurring.md
EOF
  exit 1
fi

echo "streamdb-perf-benchmark: PASS — all metrics within baseline tolerance (no regression)." >&2
exit 0
