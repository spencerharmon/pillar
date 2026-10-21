#!/usr/bin/env bash
# Fixed, reproducible workload. Baseline updates are explicit and reviewable.
set -euo pipefail
root="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]}")")")"
update=()
if [[ $# -eq 1 && $1 == --update-baseline ]]; then
    update=(--update-baseline)
elif [[ $# -ne 0 ]]; then
    printf 'Usage: %s [--update-baseline]\n' "$0" >&2
    exit 2
fi
export PYTHONDONTWRITEBYTECODE=1
python3 "$root/scripts/streamdb-perf-compare-test.py"
cargo test --manifest-path "$root/Cargo.toml" --locked --release \
    -p pillar-streamdb --no-default-features --example streamdb_perf_bench
# Preserve raw measurements even on comparator failure, in the build directory.
report_dir="${CARGO_TARGET_DIR:-$root/target}/streamdb-perf"
mkdir -p "$report_dir"
report="$(mktemp "$report_dir/report.XXXXXXXX.json")"
cargo run --manifest-path "$root/Cargo.toml" --locked --release \
    -p pillar-streamdb --no-default-features --example streamdb_perf_bench >"$report"
printf 'StreamDB performance report: %s\n' "$report"
python3 "$root/scripts/streamdb-perf-compare.py" "${update[@]}" \
    "$root/scripts/streamdb-perf-baseline.json" "$report"
