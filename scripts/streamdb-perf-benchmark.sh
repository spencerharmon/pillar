#!/usr/bin/env bash
# Recurring streamdb performance benchmark (registered in CHECKS.md's
# `streamdb-perf-benchmark` stub; ROI P1 "Streamdb performance is a standing,
# self-perpetuating discipline", extended by "the performance + integration
# harness measures BOTH visibility profiles side by side").
#
# Builds and runs `crates/pillar-streamdb/src/bin/streamdb-perf-bench.rs`
# (release mode, for realistic timings), which drives an identical synthetic
# op workload through BOTH the PUBLIC and CELL-ENCRYPTED streamdb visibility
# profiles, measures op-path (seal/sign+open/verify) and view-fold
# (OpLog::append+root) cost for each, prints the measured metrics plus the
# public<->cell delta as JSON, and compares every metric against the tracked
# baseline (scripts/testdata/streamdb-perf-baseline.json) with a tolerance
# factor. Exits non-zero (propagated below) the instant any metric regresses
# past its tolerated ceiling, so this script's own exit code IS the real
# measured pass/fail signal `CHECKS.md` requires -- never a fabricated one.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo build --release -p pillar-streamdb --bin streamdb-perf-bench

exec ./target/release/streamdb-perf-bench
