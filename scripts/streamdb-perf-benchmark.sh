#!/usr/bin/env bash
# streamdb performance benchmark harness (`streamdb-perf-benchmark` in
# CHECKS.md; drives task `streamdb-perf-benchmark-recurring`).
#
# Runs `pillar-streamdb`'s `perf_benchmark` binary, which measures op
# throughput/latency (seal+sign -> append -> open+verify) AND view-fold cost
# (`OpLog::root`) through BOTH visibility profiles side by side: PUBLIC
# (unencrypted, the throughput/latency ceiling and fixed baseline) and
# CELL-ENCRYPTED (the guaranteed-confidentiality profile). It compares this
# run against the tracked baseline (`crates/pillar-streamdb/benches/
# perf-baseline.json`) and reports the public<->encrypted delta as a
# first-class metric (the isolated AEAD seal/unseal overhead).
#
# Exit 0 = no metric regressed beyond tolerance against the tracked baseline
#          (or this is the first run and the baseline was just recorded).
# Exit !0 = a metric regressed beyond tolerance — the recurring task files a
#          concrete tuning follow-up naming the regressed metric.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

exec cargo run --quiet --package pillar-streamdb --bin perf_benchmark
