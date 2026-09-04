# PSL — the Pillar Query Language

PSL is Pillar's built-in query surface over the observability signal store
(see [`observability.md`](../observability.md)): metrics, logs, traces,
profiles, and metadata samples, plus the cross-kind correlation spine that
ties them together. PSL has exactly **one** query model
(`crates/pillar-observability/src/psl.rs`), expressed through two
surfaces that always agree:

- a **compact text surface** — what you type at the CLI or paste into a
  query box; and
- a **structured surface** (`PslQueryBuilder`) — the same AST built
  field-by-field, the shape a UI query builder composes against without ever
  round-tripping through text.

`parse(text)?.to_text() == builder.build()?.to_text()`, and the two ASTs
themselves compare equal — text and structured construction of the same
query are indistinguishable to the engine underneath. There is no separate
"UI query language" and "CLI query language"; every PSL surface produces the
same `PslQuery` and executes through the same engine.

## Compact text grammar

```
select: <kind[(pred, ...)]>, ... [where: <pred, ...>] range: now-<duration> [correlate: { window: <duration>, anchor: <kind> }]
```

Clauses appear in this fixed order (`select` → `where` → `range` →
`correlate`); `where` and `correlate` are optional, `select` and `range` are
required.

- **`select:`** — a comma-separated list of signal kinds to match, each with
  its own optional, kind-scoped predicate list in parens. Valid kinds:
  `metrics`, `logs`, `traces`, `profiles`, `metadata`.
- **predicate** — `key = value`, a label equality test. Predicates inside a
  `select:` kind's parens apply ONLY to that kind; predicates in `where:`
  apply across every selected kind.
- **`where:`** — a comma-separated list of predicates applied to every
  selected kind, on top of that kind's own `select:`-scoped predicates.
- **`range:`** — `now-<duration>`, a window ending at the query's evaluation
  time ("now"). A duration is `<number><unit>` with unit one of `s`
  (seconds), `m` (minutes), `h` (hours), `d` (days) — e.g. `30m`, `1h`, `1d`.
- **`correlate:`** — `{ window: <duration>, anchor: <kind> }`. When present,
  every matched signal of the `anchor` kind becomes the center of a
  **correlation group**: every other matched signal sharing its correlation
  id (see below) within `window` of the anchor's timestamp is pulled into
  that group. Signals on the same causal thread but outside the window are
  still matched (they satisfy `select`/`where`/`range`) but are excluded from
  the group.

## Correlation semantics

Every signal optionally carries a **correlation id** — e.g. a trace id or an
event content address tying it to one causal thread — plus its ordinary
labels. `correlate:` does not change what a query *matches*; it changes how
the matched set is *grouped* for presentation:

1. `select`/`where`/`range` first produce the full matched set, exactly as
   they would with no `correlate:` clause at all.
2. For each matched signal of the `anchor` kind, PSL looks up every other
   *matched* signal sharing that anchor's correlation id.
3. Of those, only the ones whose timestamp is within `correlate.window` of
   the anchor's timestamp become members of that anchor's correlation group
   (the anchor itself is always a member).
4. A matched signal that shares the anchor's correlation id but falls
   outside the window is excluded from the group — but remains present in
   the query's flat matched set, so nothing is silently dropped, only
   ungrouped.
5. An anchor signal with no registered correlation id forms a singleton group
   containing just itself.

Groups are returned in a deterministic (content-address) order, so re-running
the same query against the same data always yields the same grouping.

## Worked example

The canonical example (mirrored from `psl-core-spec` and exercised by
`crates/pillar-observability/src/psl.rs`'s test suite against a real
`TimeseriesStore` + `CorrelationIndex`):

```
select: metrics(name = ingest_bandwidth), logs where: cell = testpillarcell range: now-1d correlate: { window: 1s, anchor: metrics }
```

Read as: "over the last day, on cell `testpillarcell`, find every
`ingest_bandwidth` metric point and every log line; for each matched metric,
group it with any matched logs sharing its correlation id that landed within
1 second of it."

The equivalent structured-surface construction:

```rust
PslQueryBuilder::new()
    .select(SignalKind::Metric, vec![Predicate::eq("name", "ingest_bandwidth")])
    .select(SignalKind::Log, vec![])
    .where_eq("cell", "testpillarcell")
    .range_relative(86_400) // 1d, in seconds
    .correlate(1, SignalKind::Metric) // 1s window, anchor = metrics
    .build()?
```

Both forms parse/build to the identical AST and execute to the identical
result: given a metric at tick `T` correlated (via a shared trace id) to a
log at `T+1s` (within the window) and another log on the same trace at
`T+100s` (outside the window), plus unrelated noise on a different cell, a
different metric name, or outside the 1-day range —

- **matched** contains the anchor metric and BOTH same-cell logs (the
  in-window and the out-of-window one) — `where`/`range`/`select` don't know
  about `correlate`'s window;
- **groups** contains exactly one group, anchored on the metric, whose
  members are the anchor and the in-window log only — the out-of-window log
  is matched but not grouped, and neither noise signal appears anywhere.

## Numeric aggregation

On top of `select`/`where`/`range`/`correlate`, PSL composes a small set of
numeric aggregates over the matched set — never a second, parallel query
path:

| Aggregate | Meaning |
|-----------|---------|
| `count` | number of matched signals |
| `rate` | matched count ÷ the query's range, in seconds |
| `sum` | sum of every matched signal's numeric payload value |
| `quantile(q)` | the value at quantile `q` (nearest-rank) over matched numeric values |
| `topk(k)` | the `k` largest matched numeric values, descending |

Any aggregate may be partitioned `by [label, ...]`: one output row per
distinct tuple of those label values (a signal missing a grouping label is
dropped from that particular aggregation), or a single ungrouped row when no
`by` is given.

## Two surfaces, one engine

Whichever surface produces a `PslQuery`, execution is identical: filter the
signal store by kind + range + label predicates, then (if `correlate` is
present) walk the real correlation index to build groups. There is no
separate "compact query executor" and "builder query executor" — a UI query
builder and a hand-typed CLI query are, from the engine's perspective, the
exact same input.

## See also

- [`observability.md`](../observability.md) — the signal event schema,
  retention/compaction policy, and RBAC-gated read authority PSL queries run
  against.
- `specs/PSLCore.tla` / `specs/PSLCore.cfg` — the model-checked correlation
  semantics this document describes in prose.
- Explore UI pages (metrics/logs/traces/profiles/metadata, once built) each
  link back to this document as their query-language reference.
