# Built-in distributed observability

Pillar ships metrics, logging, tracing, profiling, and metadata sampling as
**core services riding the streaming DB** — an observability signal (a metric
point, a log line, a trace span, a profiling sample, or a metadata sample) is
just another append-only, content-addressed, PGP-signed event on the existing
event log (`specs/StreamingDB.tla`), materialized into per-signal views. There
is no external Prometheus/Loki/Jaeger dependency and no parallel storage or
authority path: this feature composes `streamdb-impl`'s content-addressing and
compaction, the single `wot-authority-impl` + `rbac-decider` authority
decider, and `anti-entropy-sync-impl`'s gossip/reconcile — unchanged.

**DESIGN GATE (operator, 2026-08-26):** no `*-impl` task against this section
may land before this design doc + [`specs/Observability.tla`](../specs/Observability.tla)
model-checks green (`specs/check.sh`). It now does.

## Event schema: signals are event-log kinds

Every signal is one more entry kind on the same content-addressed event log
`StreamingDB.tla` already proves lossless/convergent:

| Kind | Payload | Notes |
|------|---------|-------|
| `metric` | name, labels, value, timestamp | a plain append-only point |
| `log` | structured fields, timestamp | a plain append-only point |
| `trace-span` | span id, parent span id, timing, tags | a plain append-only point; spans compose into traces via the parent-id DAG, exactly like `EventDAG.tla`'s causal edges |
| `profile-sample` | stack/cpu/alloc sample, timestamp | a plain append-only point |
| `metadata-sample` | a *sampled* reference to a real occurrence (a request, a connection, a config read) plus whatever metadata policy allows | the ONLY kind gated by the sampling policy below — never fabricated, never over-rate |

### The metadata kind: a label-set-over-time signal

The fifth kind, **metadata**, is a distinct signal with **NO numeric value** —
not found in Prometheus/Loki/Jaeger/pprof. It generalizes the info-metric
anti-pattern (`node_info`/`*_info`/kube-state-metrics: a metric pinned to a
constant value purely to carry labels) by making the *payload itself* the label
set for an entity; the observable of interest is **WHEN the labels change**.

It is timeseries-class like the other four: label-set observations are
append-only, immutable samples on the same substrate. On top of that history
(`crates/pillar-observability/src/metadata.rs`) it materializes two derived
views per entity:

- **current labels** — the label set in effect now (the latest observation),
  the first-class analog of the info-metric's current value; and
- **transition history** — every time an entity's labels changed and to what,
  with the added/removed/changed diff between consecutive distinct
  observations. A re-observation of identical labels is *not* a transition, so
  history records genuine change points only.

Metadata is also the **correlation overlay** the other four kinds pivot
against.

### The shared correlation spine

The five kinds share one correlation model
(`crates/pillar-observability/src/correlation.rs`) so a metric spike, its logs,
the trace that caused it, the profile taken during it, and the entity metadata
in effect all cross-pivot, over two axes every signal stamps:

- a **correlation id** — a trace id or event CID tying signals to one causal
  thread; and
- **shared labels** — the common dimensions (domain / cell / node / user /
  resource + topology tiers).

`CorrelationIndex` answers "every signal of any kind sharing this correlation
id" and "every signal sharing this label", making a cross-kind join
O(matches).

Every event carries the same PGP signature and content address as any other
`streamdb-impl` write; nothing here forks the wire format or the write path.

## Retention and compaction policy

Each signal class declares its own retention window (a duration, modeled as a
tick count in the TLA+ spec) at write time. The **safety property, proven by
`Observability.tla`**:

- `LogSubsetOfWritten` / `NoLossBeforeExpiry`: a signal event never silently
  vanishes from every node before its own declared retention deadline has
  passed, and compaction (`Compact`) is only ever *enabled* once the clock has
  passed that specific event's `expiry` — never early, and never for a
  different event.
- Compaction never fabricates: every event any node ever materializes is one
  that was genuinely written (`log[n] \subseteq written`, the same invariant
  shape `StreamingDB.tla`'s `LogSubsetOfWritten` already proves for the base
  op-log). This composition reuses `streamdb-impl`'s own
  content-addressing/snapshot-compaction machinery rather than a second
  compaction mechanism.
- Cross-peer replication of live signal events is ordinary `anti-entropy-sync-impl`
  gossip (`Gossip` in the spec mirrors `StreamingDB.tla`'s `Gossip` verbatim) —
  no separate replication path for observability data.

## Sampling policy: no double-counting, no fabrication

Metadata sampling (and any other rate-limited signal, e.g. high-frequency
profiling) must never invent a sample that has no corresponding real
occurrence, and must never emit more samples for one occurrence than the
policy's configured rate allows. `Observability.tla` proves both as safety
invariants over a ghost `happened` set (real occurrences, independent of
whether/how they are sampled) and a `sampled` counter per occurrence:

- `NoFabricatedSample`: every recorded `metadata-sample` (or other sampled
  signal) event denotes an occurrence that had genuinely `happened` — a
  sampler can never manufacture a sample event for something that never took
  place.
- `NoDoubleCountSample`: no occurrence is ever sampled more than
  `SampleCap` times, the policy's configured rate — a sampler cannot emit
  the same occurrence twice as if it were two independent events.

This composes with the metadata-privacy posture (see "Read authority" below)
rather than inventing a separate privacy mechanism: a metadata-sampling view's
*emission* is rate/fabrication-safe per the above, and its *read* is gated by
the same RBAC decider as every other signal, honoring whatever privacy
posture that decider encodes (including composing with the optional
onion/Tor overlay's threat model where configured — never a bespoke one).

## Read authority: the single RBAC decider, never a parallel one

A peer may materialize/read a signal's view only under a currently-live,
RBAC-decider-granted capability for that signal + resource scope. This reuses
`wot-authority-impl` + `rbac-decider`'s owner-anchored tsig reachability and
revoke-before-act fencing **unchanged** — `Observability.tla` composes
`WoTAuthority.tla` via `INSTANCE` (the exact pattern `StreamingDB.tla` already
uses to compose `CoordinationCore.tla`), sharing its variables rather than
re-declaring a second authority state machine. The new `ReadSignalView`
action is gated exactly like `WoTAuthority.tla`'s own `Act`:

- `ReadRequiresAuthority`: the most recent read (if any) was performed by a
  reader who was RBAC-authoritative, per the single decider, at the exact
  moment it read.
- `FailClosedReadUnderStaleView`: a reader whose local revocation watermark
  lags the true global one can never appear as the actor of a read most
  recently recorded as fully fresh against the current watermark — a stale
  view fails closed rather than falling back to an optimistic grant.
- The composed decider's own invariants (`NoActionAfterRevocation`,
  `FailClosedUnderStaleView`, `FreshMarkBounded`) are re-checked, imported
  verbatim (`== WOT!<name>`), confirming composition does not disturb the
  underlying authority path — there is exactly one place read authorization
  is decided.

## What this design explicitly reuses (never forks)

- **Storage/content-addressing/compaction**: `streamdb-impl`'s existing
  content-addressed event log (`StreamingDB.tla`).
- **Gossip/reconcile**: `anti-entropy-sync-impl`'s existing anti-entropy
  protocol.
- **Authority/RBAC**: the single `wot-authority-impl` + `rbac-decider` decider
  (`WoTAuthority.tla`), composed via `INSTANCE`.

No `*-impl` task under this ROI section may introduce a second event store,
a second gossip protocol, or a second authority/RBAC decider for
observability signals — any such need is a bug in this design, not a license
to fork.

## Querying signals: PSL

Signals materialized by this design are queried through **PSL**, Pillar's
built-in query language — see
[`query-languages/psl.md`](query-languages/psl.md) for the compact-text and
structured surfaces, the `select`/`where`/`range`/`correlate` grammar, and a
worked example against the correlation spine described above.

## Spec

[`specs/Observability.tla`](../specs/Observability.tla) /
[`specs/Observability.cfg`](../specs/Observability.cfg), wired into
`specs/check.sh`'s `SPECS` list. TLC model-checks (exhaustively, on the
configured finite instance) `TypeOK` plus the invariants named above,
including the composed `WoTAuthority` decider's own invariants, all green.

## Status

Design + TLA+ gate complete (this task). No `*-impl` work is filed yet —
follow-up implementation tasks (metrics/log/trace/profile writers, the
sampling policy engine, and the read-view materializer) are filed against
this design once a work pass picks up the next ROI priority-3 item, each
depending on this task (`observability-design-spec`) being `DONE`.
