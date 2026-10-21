# StreamDB Performance Harness

Run `scripts/streamdb-perf-benchmark.sh` from a checkout with Rust/Cargo and
Python 3. It runs comparator regression tests, Rust correctness/security tests,
and a release-mode measurement, then compares against the tracked baseline.
No daemon, network service, or credentials are needed.

## Workload

The example builds on the earlier dual-profile `streamdb_perf_bench` design,
replacing its OpLog-root stand-in with the real `pillar-observability`
`TimeseriesStore` and `ViewCache`. Both confidentiality profiles use identical
keys, routing visibility, and 2,000 distinct 1-KiB records. Only confidentiality
changes: PUBLIC is signed cleartext; CELL-ENCRYPTED adds the production cell AEAD.

- `*_op_ns`: nanoseconds per complete stream-op round trip: body encoding,
  seal (encrypted only), Ed25519 signature, canonical envelope encoding, Cid
  derivation, received-byte Cid verification, strict envelope decoding, signer
  check, signature verification, open, and asserted plaintext equality.
- `*_fold_ns`: nanoseconds per input record for that same round trip plus real
  TSDB ingestion into 256-record blocks, cold all/kind-filtered materialization,
  cache hit, then another ingestion and both invalidated views. Exact sorted
  content IDs, cardinality and cache hit/miss counters are asserted. Expected IDs
  come independently from fixture plaintext, not from the store's return values.
- `*_delta_pct`: `(encrypted_ns / public_ns - 1) * 100`, signed latency overhead
  in percent. A negative value is measurement noise, not a claimed crypto speedup.

These are in-process stream-op/TSDB composition benchmarks, **not** disk, IPFS,
network, RBAC, or end-to-end observability ingestion benchmarks. In particular,
the observability `Body::Signal` helper currently always encrypts; this harness
uses the existing PUBLIC/CELL `Body::StreamOp` APIs to feed the real TSDB engine,
not an invented cleartext Signal production path. No production implementation
is changed to obtain faster measurements. No hash, signature, or encrypted seal
is bypassed. Wrong hash, forged signature with a recomputed Cid, and wrong cell
key must fail through the same decoder used by the timed workload.

Both paths warm up first. Seven samples alternate profile order; each latency is
the median of those samples, and deltas are derived from the median latencies.
Setup/key derivation and the initial expected-ID oracle are outside timing.
Correctness assertions remain inside timing. Comparisons require identical
workload metadata; changing workload semantics requires a new schema/baseline.

## Baseline and Reports

`streamdb-perf-baseline.json` persists all four measured latencies, both overhead
deltas, workload parameters and six explicit upper targets. Latency targets allow
25% growth; delta targets allow 10 percentage points above the nonnegative
baseline overhead. The independent delta targets catch encryption-only regression
even when neither raw profile reaches its latency limit. Each comparison reports
the target and remaining headroom, in ns or percentage points.

Each run preserves JSON in `target/streamdb-perf/report.*.json` (or under
`CARGO_TARGET_DIR`) even on a regression. Normal checks never rewrite the baseline
and fail closed on missing/invalid metrics, inconsistent deltas, duplicate JSON
keys, nonfinite values, or different workload parameters. Exit 1 means regression;
comparator exit 2 means malformed input. Tests/build failures also propagate.

To intentionally establish a new reference, run
`scripts/streamdb-perf-benchmark.sh --update-baseline`, inspect the resulting
tracked diff and then run the default comparison again. Updating is explicit
acceptance, not proof against the old targets. Keep hardware/compiler/build flags
comparable for recurring runs; a shared runner can still cause timing noise.
Do not automatically ratchet a failing baseline upward. The initial reference was
measured in release mode on x86_64 Linux with rustc 1.98.1 and the workspace's locked dependencies;
these are local regression budgets, not universal hardware-independent SLAs.
