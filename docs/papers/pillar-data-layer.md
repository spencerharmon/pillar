# The Pillar Data Layer

*A multi-model streaming database turned inside-out, for a trustless federation.*

**Status:** design of record (operator-directed, 2026-09-14). This paper is the
authoritative specification of Pillar's user-facing data layer and the migration of
Pillar's own internal components onto it. It exists so the intent captured in a design
session is not lost or re-derived differently later. `ROI.md` references this paper;
where the two disagree, this paper is the design of record for the data-layer model and
`ROI.md` is authoritative for prioritization. Implementation remains TLA+-gated for the
original-design core (streamdb, wire format, coordination core) per the repo's
specify-then-build rule.

---

## 0. Thesis

Samza and Kleppmann's "turning the database inside out" showed that a log of immutable
events, plus materialized views folded from that log, is a better factoring than a
mutable-state database: the log is the source of truth, views are derived, caches and
indexes stop being things you invalidate by hand and become things you *rebuild* from
the log. Samza did this **inside a trusted datacenter, on top of a central broker
(Kafka)**.

Pillar does the same inside-out factoring for a **trustless, serverless,
cryptographically-verifiable federation of PGP-trusted peers** — no broker, no central
owner, every record signed and content-addressed, confidentiality and authorization
built into the record format, and the convergence/ordering/coordination invariants
model-checked in TLA+.

The user-visible consequence — and the point of this paper — is that Pillar offers its
users the *same* data primitives it builds itself out of, over the *same* substrate,
through the *same* sealed message envelope. There is no separate "user database" bolted
next to a bespoke internal state store. Every internal plane (manifests, RBAC, sessions,
quota, identity, observability) is a consumer of the same primitives a user app consumes.
This is the doctrine: **build each data primitive once, dogfood it internally, offer it to
users with a real inspect/query surface.**

---

## 1. One substrate, one envelope

Everything in the data layer rides one substrate:

- **The event log is a content-addressed CvRDT op-log** (`crates/pillar-streamdb`). Each
  op is immutable, content-addressed (a real CIDv1 multihash), signed by a PGP-rooted
  identity, and merged by set-union; a deterministic fold produces the materialized view.
  Order within a stream is derived, not wall-clock (see §4 on HLC).
- **One envelope: the Pillar Message Format** (`docs/papers/pillar-message-format.md`,
  `crates/pillar-wire`). streamdb ops, observability signals, and every libp2p control
  message are variants of one sealed, content-addressed, version-stamped `PillarMessage`.
  The cell-seal keeps the `Cid` stable under encryption.
- **Hot path is pubsub/gossip; cold/bootstrap path is IPFS.** Live consumers receive
  changes directly over libp2p pubsub. Durability and backfill ride Pillar's own embedded
  IPFS node (`crates/pillar-ipfs`) — content-addressed, self-hosted, off the public DHT.
  A restarting or new node rehydrates from IPFS-pinned sealed segments plus its
  custody-held key; there is no central broker to replay from.

Everything below is a *model over this one substrate*. The "different databases" a user
sees are different fold/query/retention disciplines over the same signed log — not
different storage systems.

---

## 2. The primitive suite (what a user picks)

An application does not need one storage primitive per CRDT type, nor nine different
stores. It needs a small number of distinct **access patterns**. Pillar offers exactly
three query interfaces over two storage models, plus the raw event log as substrate.

### 2.1 Storage models

| Model | Access pattern | Merge / consistency | Persistence discipline |
|-------|----------------|---------------------|------------------------|
| **Keyed store** — two surfaces: **K/V** (opaque value, point access) and **Document** (structured value, field-queryable). *One engine, two typed surfaces* (K/V = Document with an opaque value + key-only access). | point lookup / structured record | per-field LWW-register by HLC; AP default, CP opt-in per stream | snapshot + log-tail replay; folds to a condensable "current state" |
| **TSDB** (time-series) | time-windowed range; retention/downsample; past-query required | append-only immutable blocks; AP | immutable time-blocks bootstrapped by fetching in-retention blocks; **no** condensable current state |

Both persist to the **same** IPFS content store — there is no parallel store. What
differs is the data model on top: the keyed store folds its op-log to a mutable current
state and snapshots it; the TSDB keeps immutable retention-windowed blocks because
querying the past is a first-class requirement and there is no "current value" to
condense to.

### 2.2 Query interfaces

| Interface | Over | What it is |
|-----------|------|-----------|
| **Keyed get/scan/watch** (`pillar kv` / `pillar doc`) | keyed store | point get, prefix scan, subscribe |
| **SQL views** (`pillar sql`) | keyed store (a **derived-read layer**, owns no storage) | project / filter / join / aggregate / traverse over one or more collections into a materialized view; subscribable; cached |
| **PSL** (`pillar obs`) | TSDB | the compact-text/structured query surface over signals (`docs/query-languages/psl.md`) |

**SQL is a query layer, not a third stored type.** It holds no storage of its own; it
folds the keyed store's collections into materialized views and caches them. Counters
(`SUM`/`GROUP BY`), graph traversals (recursive joins over an edge collection), and
rollups are all **queries** over the keyed store — not separate primitives. There is no
graph database, no standalone counter store, and no "log store" distinct from the
substrate: the streamdb *is* the event log, and code that wants raw event-sourcing folds
it directly.

**Cache is not a user primitive.** It is the maintenance mechanism under SQL/document
views: a `(query, held-set root)`-keyed materialized-view cache
(`crates/pillar-observability/src/query.rs` `ViewCache`) that recomputes only when the
source root changes. It is invisible in the user's mental model.

### 2.3 What a user picks, in one line

> **Keyed store (K/V or Document), SQL views over it, or TSDB.** Three query interfaces,
> two storage models, one substrate. Everything else (counters, graphs, caches, logs) is a
> query pattern, a merge detail, or the substrate itself — not a store to choose.

---

## 3. SQL over the document store — how it actually works

The relational surface presents mutable flat rows, but the storage underneath is the
append-only signed log. The relational illusion is maintained by folding.

### 3.1 The catalog is data

DDL is not special — it writes documents to a system collection (`__catalog`),
event-sourced and gossip-replicated like everything else:

```
CREATE DATABASE app                         → put __catalog/(database, app)
CREATE TABLE app.users(id,name,email,role)  → put __catalog/(table, app.users)
                                                  {schema:[…], collection:'app.users'}
CREATE MATERIALIZED VIEW app.admins AS
  SELECT id,email FROM app.users WHERE role='admin'
                                            → put __catalog/(view, app.admins)
                                                  {source:['app.users'], query:<ast>, since:<root>}
```

A node learns every database/table/view by folding `__catalog`. "What schemas and views
exist and what they are over" is itself replicated, verifiable state.

### 3.2 Data → table association is structural

```
INSERT INTO app.users VALUES('alice','Alice','a@x','admin')
   → put app.users/alice {name:'Alice', email:'a@x', role:'admin'}
```

A row's key **is** `(collection='app.users', id='alice')`. The collection component *is*
the table id. A node never needs a lookup to know which table a document belongs to — it
is in the key. Table membership is a key-prefix match; the op-log is indexed by collection
(and indexed columns) so folding a table is not a full scan.

### 3.3 Row update = append a field-delta, never mutate a flat document

An `UPDATE` compiles to a `put` op carrying **only the changed fields**, with an HLC:

```
UPDATE users SET email='alice@y' WHERE id='alice'
   → append put(users/alice, {email:'alice@y'}, HLC=t2)
```

The stored form is the op sequence. The flat row is **derived** by folding all ops for
the key under per-field LWW:

```
op1 t1: put users/alice {name:'Alice', email:'a@x', role:'admin'}
op2 t2: put users/alice {email:'alice@y'}
──────────────────────────────────────────────── fold (per-field, highest HLC wins)
row:  {name:'Alice'(t1), email:'alice@y'(t2), role:'admin'(t1)}
```

Because each field is its own LWW-register, a single-column update rewrites nothing else,
and concurrent updates to *different* fields both survive (field-level merge); concurrent
updates to the *same* field resolve by highest HLC. `DELETE` appends a tombstone; the view
drops the row, the log keeps the event, and compaction later collapses tombstoned keys out
of the snapshot.

The only literally-flat stored artifacts are **derived and rebuildable**: the in-memory
materialized view a node serves from, and the periodic snapshot segment written to IPFS so
replay does not start at genesis. Neither is edited in place.

### 3.4 Data → view association is derived, not stored

A node serving `app.admins` does **not** consult per-document "which view?" pointers. It
reads the view-def from `__catalog`, folds the source collection(s), applies the
predicate/projection, materializes the rows, and caches the result on
`(view-id, root(source))`. **Views subscribe to sources; sources are oblivious to views.**
Membership is computed, not a pointer.

### 3.5 A new view over existing data (schema change without migration)

This is the headline win of the inside-out model. A schema change is a **new view over the
unchanged source**, built from the existing log:

```
CREATE MATERIALIZED VIEW app.users_v2 AS
  SELECT id, name AS full_name, email FROM app.users
```

What associates the *existing* data with the new view? Nothing is moved or migrated.
`users_v2.source = ['app.users']`, and `app.users`'s ops are immutable and
content-addressed, so the node building `users_v2` folds those same ops from the beginning
(`snapshot + log-tail`) under the new projection. Old view and `users_v2` **coexist,
maintained in parallel**; consumers cut over gradually, then the old view-def is dropped.
Pure Kleppmann: *consume the input log from the beginning, build a new view, no
stop-the-world migration.*

If `users_v2` needs a column old rows lack, either the projection computes/defaults it
(`coalesce(tier,'free') AS tier`) or a one-time backfill appends per-field delta ops
(`put app.users/alice {tier:'pro'}`) that merge by field-level LWW without rewriting
existing fields. The old view is unaffected because it reads its own projection.

### 3.6 Query execution path

`SELECT` → a `QueryOp` `PillarMessage` to a node's query tier (the generalization of the
PSL UDP/QUIC server pattern) → the node runs it against its locally-folded materialized
view and returns rows. Every node folds the same convergent, content-addressed op-set
deterministically, so any node that pins the sources answers identically. `SELECT` signs
nothing (a read); `INSERT/UPDATE/DELETE` compile to put/tombstone ops appended over the
resource-op write tier.

---

## 4. Ordering: HLC is a wire-format requirement

`OpLog::order` sorts by content-address, not by time. That is fine for a pure grow-only
set, but **per-field LWW and any "latest write wins" semantics require a logical clock in
the op payload** — otherwise "latest" is arbitrary (content-hash order). Therefore every
keyed-store `put`/tombstone op **must** carry a Hybrid Logical Clock timestamp, and the
fold resolves same-field conflicts by highest HLC (ties broken deterministically by
author/CID). This is a user-visible wire-format decision and is part of the keyed-store
op schema, gated with the rest of the wire format.

---

## 5. Consistency: AP by default, a CP subset by co-partitioned fold

Pillar cannot pick one CAP point for everyone; it chooses **per view**
(`docs/consistency-model.md`).

- **The AP majority** — sessions, offers, manifests, config, user records, trust edges,
  most everything — is a CRDT keyed store: writes always succeed, merge on heal, per-field
  LWW. `ViewPolicy::Relaxed`.
- **The CP subset** — the handful of genuine hard invariants: exactly-once admission,
  hard quota ceilings, uniqueness — is **not** a relational engine, not a global lock, and
  not foreign keys. It is **Samza's co-partition-and-fold**: put that invariant's key in a
  `ViewPolicy::Strict` partition and enforce the invariant in the reducer over the
  partition's total order.

The one Pillar-specific twist: Samza gets per-partition total order for free from Kafka's
single-leader-per-partition. Pillar's substrate is **leaderless** (concurrent appends,
content-address order), so a Strict partition gets its total order from the
**coordination core** — a quorum-fenced lease (`specs/CoordinationCore.tla`,
`AtMostOneHolderPerEpoch`, `GrantsAreFenced`) — the direct analog of a Kafka partition
leader, **per-key and scoped**, never a global lock. Same model, same "no foreign keys,"
same "no stop-the-world." A minority partition starves rather than splitting the brain;
safety is absolute, availability is sacrificed only in the minority, only for the CP
subset.

`ViewPolicy::admits` refuses an exclusive (non-idempotent) side effect under a Relaxed
view — safe-by-default: an unspecified policy resolves to the stronger posture.

---

## 6. Placement: which node serves which data

Not every node in a cell must serve every collection. Users isolate data to specific
nodes for performance, security, or other reasons. The design goal is that **every layer
— events, K/V, document, SQL, TSDB — inherits one placement decision.**

### 6.1 The boundary is the collection

Every layer already keys on the collection: ops are keyed `(collection, id)`; a document
view is the fold of one collection; a TSDB signal stream *is* a collection; an SQL view's
`source` list is collections. So placement is fundamentally a property of the collection's
**event stream**, and every derived layer inherits automatically because each is a fold of
that stream. Pin a collection on a node and that node can serve its document view, its
TSDB blocks, and any SQL view whose sources it also holds. One boundary, all layers.

### 6.2 Default: every collection on every cell node

The default (no selector) pins a collection across the **entire cell**. The cell is the
replication set — there is no separate replication-factor knob. A single-node cell simply
holds its collections on that one node; there is nothing to warn about. `minReplicas` is
deliberately **not** part of the model: it would raise meaningless warnings on small
clusters and duplicate what cell membership already expresses.

### 6.3 Isolation is opt-in via node tags

A placement resource narrows a collection to a subset of cell nodes by tag selector,
reusing the existing node tagging / attested topology-label machinery (the same selectors
RBAC policy targets already use — no new mechanism):

```
CollectionPlacement {
  collection:   app.users
  nodeSelector: { tags: { role: db, region: eu } }   // omitted/empty ⇒ whole cell
}
```

The selector matches node tags → the set of nodes that subscribe + IPFS-pin that
collection. Empty selector ⇒ every cell node.

### 6.4 Views follow their sources (co-location)

A materialized view is servable on node *N* **iff** *N* pins all of the view's source
collections. Views are therefore placed **by derivation**, not directly. A joined view
forces co-location of its sources: placing/serving a view expands to pinning its source
collections on the same node-set. A node never holds "a view without its data."

### 6.5 Cell stays the outer boundary; routing and inspection

The **cell** remains the confidentiality and key boundary; placement only narrows *within*
a cell (a node serves a collection only if it is a member of that collection's cell).
Query routing is a catalog lookup (view → sources) plus a placement lookup (collection →
node-set via selector + membership), both already-replicated state. The CLI/UI surfaces,
per collection, its placement tags and the live count/list of participating nodes.

---

## 7. Component migration map

Every internal plane becomes a consumer of the primitives above. No plane keeps a bespoke
write path plus a separate hand-rolled store.

| Component (today) | → Primitive |
|-------------------|-------------|
| manifests / resources (`ManifestStore` fold) | **Document** (keyed by kind/name; per-field LWW; CP for exclusive kinds) |
| user records / profile | **Document** |
| session registry, key-distribution offers, secrets refs, topology/naming labels | **K/V** |
| RBAC grants | **Document** collection of signed grant records; decision = decider fold / SQL view; revoke = CP tombstone |
| WoT trust graph | **Document** edge collection + **SQL** traversal query (no graph DB) |
| quota / reservation ledger | **SQL** aggregation (`SUM`) over a reservation-event collection + CP fence on the hard-limit key |
| routing table (LB), dashboards, recording rules | **SQL** derived views |
| observability signals | **TSDB** (the reference implementation — already built) |
| identity rotation, audit, versioning history, eventlog | raw **stream** (append + fold) + a **Document**/SQL "current-state" projection |
| direct messaging / alert notifiers | message bus (transport; optional, deferrable) |

Counters and graphs vanish as storage — a `GROUP BY` and a recursive join. The log vanishes
as a "choice" — it is the substrate everything folds from.

---

## 8. What Pillar has that Samza / Kafka / Mongo do not

Honestly, including where Pillar loses.

**Advantages**

1. **No broker, leaderless.** The log is a P2P-gossiped CvRDT over libp2p — no central
   cluster to run or trust.
2. **Cryptographically verifiable / tamper-evident.** Every op is content-addressed into a
   Merkle-DAG with per-author hash chains and signatures; a lying or faulty node is
   detected. Certificate-Transparency-grade auditability is structural.
3. **Identity, authorization, and encryption in the record format.** Writes are
   PGP-signed; reads/writes gate through a WoT/RBAC decider; data is cell-encrypted or
   recipient-sealed. Not bolted-on ACLs over a trusted operator.
4. **Per-stream CAP knob with proofs.** AP-default / CP-opt-in per stream, convergence and
   coordination model-checked, heal-after-partition — not Kafka's CP-only partitions.
5. **Formally verified (TLA+).** Convergence, ordering, coordination, confidentiality
   invariants are TLC-checked.
6. **Content-addressed durability you self-host** (embedded IPFS, off the public DHT);
   bootstrap from any peer, dedup for free, no broker to replay from.
7. **One envelope, one substrate, many models** — log + state store + query + durability
   unified under one signed envelope, not five systems wired together.
8. **Native subscribe/verify** — clients verify a view's tip themselves and read by
   subscription; the inside-out UX is native.
9. **Federated / mobile** — cross-cell geo-replication via signed grants over
   NAT-traversing libp2p, not a datacenter LAN assumption.

**Where Pillar loses (do not oversell)**

- **Throughput/latency.** Signing, sealing, content-addressing, and gossiping per op is
  heavier than a tuned Kafka append; Pillar is young and unproven at scale.
- **Conflict model.** Per-field LWW is weaker than a single-leader total order for some
  workloads; the AP majority accepts last-writer-wins semantics.
- **Maturity.** Kafka/Mongo are battle-tested; formal proofs are not production hours.

Net: Pillar wins on decentralization, verifiability, built-in identity/crypto, formal
correctness, and multi-model unification. It does not win on raw throughput or maturity.
It is Samza's architecture minus the broker, plus cryptographic trust, plus a unified
state/query/durability layer.

---

## 9. Performance program (the standing concern)

The crypto layer (sign + seal + content-address per op) is real per-op overhead, and it is
the acknowledged cost of §8's advantages. The gap to a plaintext broker is not closed by
abandoning the guarantees — it is closed by engineering:

- **Simplify layers** — remove redundant copies/serializations on the hot path; fuse
  envelope construction with signing; avoid re-hashing bytes already hashed.
- **Efficient and hardware-accelerated algorithms** — AES-NI / AVX for the seal, batched
  and hardware-accelerated hashing, Ed25519 batch verification, signature/verify caching
  keyed on CID, zero-copy segment I/O.
- **Amortize** — batch ops per gossip round, snapshot compaction to shorten replay, lazy
  materialization of cold views.

This is not a one-time task. Performance is a **standing, self-perpetuating discipline**:
a recurring (daily) task measures streamdb op throughput/latency and view-fold cost
against a tracked baseline and, when it finds regressions or headroom, files concrete
follow-up tasks for specific tuning work. See `ROI.md` for the recurring-task definition;
the invariant is that no tuning may weaken a §8 guarantee (verifiability, signing,
per-stream CAP) — performance improves *within* the safety envelope, never by shrinking it.

---

## 10. Verification posture

Consistent with the repo's specify-then-build rule, the original-design core of this data
layer is TLA+-gated before it is trusted: the streamdb CvRDT and its fold, the keyed-store
op schema (including the HLC ordering rule of §4), the coordination core that orders the CP
subset (§5), and the confidentiality/seal invariants of the wire format. The SQL/query
compilation, the catalog documents, the placement resource, and CLI/UI ergonomics ship
test-driven against a live node — including a real remote read/query against a running node
(not a fixed-kind HTTP shim), so the "offer every primitive as an inspectable user service"
doctrine is exercised by a gate, not merely asserted.
