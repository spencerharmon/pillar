# streamdb performance follow-up markers

The recurring `streamdb-perf-benchmark` discipline (ROI P1) drops a marker file
here — `<metric>.md`, e.g. `append_ns_per_op.md` — when a fresh measurement
regresses past `baseline * STREAMDB_PERF_TOLERANCE` for that metric AND it has
filed a concrete tuning follow-up task to recover it. The presence of the marker
tells `scripts/streamdb-perf-benchmark.sh` the regression is *tracked* (so the
recurring check passes rather than failing forever) while the filed follow-up
task carries the real, measurable before/after fix.

A marker MUST name the filed follow-up task id and the regression it tracks. It
is REMOVED once the follow-up lands and a fresh baseline is recorded.

HARD INVARIANT: a tuning follow-up may only make streamdb faster WITHOUT
weakening a guarantee — verifiability, per-op signing, content-addressing, or
per-stream CAP posture. A "speedup" that drops a signature/hash-check/seal is a
bug, not an optimization, and must fail review.

Valid metric names: `append_ns_per_op`, `view_fold_ns_per_op`,
`merge_ns_per_op`, `compact_ns_per_op`.
