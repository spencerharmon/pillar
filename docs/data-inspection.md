# Inspecting the op log, storage layout, and IPFS objects

The query surfaces in [`database-management.md`](database-management.md) — `pillar kv`,
`doc`, `sql`, `obs` — return **folded views**: the current state a node computes from your
cell's data. This guide covers the three layers *underneath* that overlay, so you can see
exactly how a collection is stored and verify it byte for byte:

- the **op log** — the ordered, signed, content-addressed operations a view is folded from;
- the **storage layout** — whether a collection is laid out as a document *snapshot + log
  tail* or as time-series *retention blocks*;
- the **IPFS object** — each individual content-addressed block, by CID.

> **Scope / status.** This is the design of record for the inspection surface. The
> substrate it inspects — the content-addressed op log and the embedded IPFS node — is
> real; `pillar object` (the bottom, object-inspection tier) is implemented
> (`pillar-object-inspection-tier`) — `stat`/`links`/`get`/`cat`/`verify` address any
> content-addressed block by CID over the sealed `QueryOp` remote surface, with
> `put` authoring a real `public` (no barrier) or `sealed` (X25519 recipient-gated)
> block; `verify` confirms hash==CID and signature validity without ever opening a
> sealed body. The `pillar log` verb tier and the Collection Explorer layers land
> with a follow-on inspection-implementation task. Every read here rides the same
> pillar-message query path and is subject to the same access control as any other read
> (see [What you can see](#what-you-can-see)).

---

## The inspection stack

| Layer | What it is | Explore with |
|-------|-----------|--------------|
| **View overlay** | folded rows / series | `pillar kv` / `doc` / `sql` / `obs` |
| **Op log** | ordered/DAG of signed ops a view folds from | `pillar log …` |
| **Storage layout** | snapshot+tail (document) or retention blocks (time-series) | `pillar log blocks` |
| **IPFS object** | one content-addressed block, by CID | `pillar object …` |

Each lower layer is a lower-level read of the *same* substrate — there is no separate
store beneath the views, only less folding.

---

## Telling how a collection is stored

Two sources agree on a collection's storage: a **declared** field and the **physical**
layout.

`pillar catalog describe <collection>` reports the declared surface — `keyed` (document /
key-value) or `tsdb` (time-series). `pillar log blocks <collection>` shows the physical
layout, whose shape answers "is this a snapshot with ops after it, or blocks back to the
retention horizon?" directly.

**Document / key-value → snapshot + log tail** (current state is condensable):

```
$ pillar log blocks app.users
layout:   snapshot+log
snapshot: bafy…S1  @ hlc=…   (folds 12,904 ops)
tail:     37 ops since snapshot   [bafy…a1 … bafy…z9]
a read loads the snapshot, then replays the 37 tail ops
```

**Time-series → retention blocks** (immutable, no condensable snapshot):

```
$ pillar log blocks svc.metrics
layout:  retention-blocks
window:  30d   horizon: 2026-08-15T00:00Z   blocks: 6
  blk0 [08-15 … 08-20]  bafy…B0
  …
  blk5 [09-10 … now  ]  bafy…B5
data before the horizon is pruned; blocks are immutable and age out at the window edge
```

So a document collection shows **one snapshot CID plus a bounded op tail**; a time-series
collection shows **a ribbon of immutable time-blocks back to the retention horizon**, with
older data pruned. The shape of the output tells you which without reading a label.

> If a document collection has not been compacted yet, `pillar log blocks` shows
> `snapshot: none` and the full op history as the tail — the same discriminator still
> applies.

---

## Op log — `pillar log`

```
pillar log info   <collection>                     # layout + summary (brief)
pillar log blocks <collection>                     # full storage layout (see above)
pillar log list   <collection> [--key k] [--since <hlc|time>] [--kind put|tombstone|append] [--limit n]
pillar log show   <op-cid>                          # one op decoded
pillar log dag    <collection> [--key k]           # causal DAG of ops
pillar log watch  <collection>                      # tail live ops
pillar log verify <collection|op-cid>              # re-check signatures + content-address + DAG
```

`pillar log show <op-cid>` decodes a single operation:

```
$ pillar log show bafy…a1
op:      bafy…a1
kind:    put
key:     (app.users, alice)
author:  did:pillar:…   (signature ✓)
hlc:     …
parents: [bafy…09, bafy…0f]        # causal predecessors
payload: bafy…P7   (sealed · 3 recipients)
```

`pillar log dag` renders the causal graph — the `parents` links between ops. Where two ops
share parents but neither precedes the other, they are **concurrent**, and the graph shows
them as side-by-side branches that merge; this is how a convergent (CRDT) merge looks at
the log level.

---

## IPFS object — `pillar object`

Every op and every payload is a content-addressed block. Address it by CID:

```
pillar object stat   <cid>          # codec, size, pin status, which nodes pin it
pillar object links  <cid>          # child CIDs (DAG edges) + sizes
pillar object get    <cid> [-o raw|json]
pillar object cat    <cid>          # decoded payload (access-gated, see below)
pillar object verify <cid>          # recompute the hash and confirm it equals the CID
```

```
$ pillar object stat bafy…P7
cid:    bafy…P7
codec:  dag-cbor
size:   412 B
pinned: n1, n3            # cell nodes holding this block
sealed: yes (3 recipients)
```

`pillar object links` gives you the child CIDs to descend the DAG one hop at a time, so you
can walk from an op to its payload to that payload's children.

---

## What you can see

Two rules govern inspection, exactly as for the query surfaces:

- **Bodies follow their seal.** `object cat` / `object get` return plaintext only if you
  hold the key and your role authorizes it. Otherwise you still see the **envelope** —
  author, HLC, parents, size, seal-recipient count — but not the sealed contents. A
  `public` collection has no such barrier.
- **Verification never requires decryption.** `object verify` and `log verify` confirm
  that a block's hash equals its CID and that its signature is valid **without** decrypting
  it. You can prove the integrity and authorship of an object you are not allowed to read.

---

## Exploring in the portal

The **Collection Explorer** drills the same four layers, with a breadcrumb
`Collection ▸ op log ▸ op <cid> ▸ object <cid> ▸ child <cid>`:

1. **View layer** — the browse/query panel over folded rows or series, with a *View
   underlying op log* action into layer 2.
2. **Op-log layer** — a virtualized log, one row per op (HLC · author · kind · key ·
   short CID · seal badge · verify ✓), filterable by key/kind/time, with a **DAG toggle**
   that draws the causal graph and shows concurrent branches merging.
3. **Storage-layout panel** — renders by store: a **snapshot marker + tail** timeline for a
   document collection, or a **retention-block ribbon** with a horizon line and a faded
   pruned region for a time-series collection. The two shapes are immediately distinct.
4. **Object inspector** — for a CID: codec, size, pin status and the list of nodes pinning
   it, the decoded body (or a `sealed · N recipients` placeholder when you cannot decrypt),
   and a **links graph** of child CIDs you click to descend. Every object carries a verify
   badge (hash = CID, signature valid).

---

## Command reference

| Command | Purpose |
|---------|---------|
| `pillar log info \| blocks` | storage layout — snapshot+tail vs retention blocks |
| `pillar log list \| show \| dag \| watch` | browse, decode, and follow the op log |
| `pillar log verify` | re-check signatures + content-address + DAG integrity |
| `pillar object stat \| links \| get \| cat` | inspect a content-addressed block by CID |
| `pillar object verify` | confirm a block's hash equals its CID |

See also [`database-management.md`](database-management.md) for the query surfaces above
this stack and [`papers/pillar-data-layer.md`](papers/pillar-data-layer.md) §3/§9/§10 for
the storage model and verification guarantees.
