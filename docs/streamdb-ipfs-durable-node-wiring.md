# streamdb IPFS-backed durable store — real disk durability + node wiring

**Status:** landed (operator-directed). Fixes the observed symptom "a
bootstrapped node re-bootstraps on every redeploy / no persistence between
versions."

## The bug (why a redeploy lost state)

The node opened its durable streaming DB via the local-fs `PersistentStream`
(`crates/pillar-cli/src/run.rs`), which the 2026-08-31 ROI audit **demoted** to
"at most a rebuildable local materialized-view cache — never the durability
layer." The ROI-mandated durability layer, `IpfsPersistentStream`
(`crates/pillar-streamdb/src/ipfs_persist.rs`), and its content-object store
`ContentStore` (`crates/pillar-streamdb/src/store.rs`) were **marked `DONE` but
never actually durable or wired**:

- `ContentStore` was **purely in-memory** (`held: HashMap`, `heads: BTreeMap`,
  no disk). Its DoD (`streamdb-ipfs-store-impl`) and `Check: cargo test --all`
  were satisfied by an in-memory round-trip + a closure `SegmentSource` peer —
  never a restart or a real substrate.
- `run.rs` never constructed `IpfsPersistentStream` at all; the node ran the
  demoted local-fs store, and nothing appended the node's ops through it on a
  solo seed node → `ops=0` on every boot, cell state gone on every redeploy.

Net: the "IPFS-backed persistence" chain was all `DONE` on crate-level
`cargo test` against abstractions, but no node, on a real disk, across a real
restart, ever persisted anything. The classic "a DONE module is not evidence the
FEATURE works" gap.

## What landed

### 1. Disk-backed `ContentStore` (`store.rs`)
`ContentStore::open(root)` opens a **durable** store rooted on the node's
PVC-backed data dir. Every mutation (`put`, `get`-backfill, `pin`, `provide`,
`publish_head`) is mirrored to disk:
```
<root>/segments/<cidhex>   # wire-encoded SignedSegment (block store)
<root>/pinned/<cidhex>     # pin marker
<root>/provided/<cidhex>   # DHT-advertised marker (public-class only)
<root>/heads/<ownerhex>    # wire-encoded HeadRecord (IPNS head, atomic rename)
```
On load, each segment is **re-keyed by the `Cid` recomputed from its own bytes**
and its authorship signature re-verified (a corrupt/forged file is skipped, never
trusted); heads are re-verified against their owner key. Content-addressing is
unchanged — this is the node's local block/pin store, exactly how a real IPFS
node persists pinned blocks (non-negotiable #5 intact: the plugin still owns
content-addressing; nothing re-implements the op-log on disk). `ContentStore::new()`
stays in-memory for peers/tests. New on-disk codec: `SignedSegment::to_wire/from_wire`,
`HeadRecord::to_wire/from_wire`; new coarse-but-`Copy` `StoreError::Io(ErrorKind)`.

### 2. Durable `IpfsPersistentStream::open` (`ipfs_persist.rs`)
The constructor the node uses. Opens a disk-backed `ContentStore`; if a head for
`owner` already exists on disk (a restart) it rebuilds the materialized view by
walking the locally-pinned signed-segment chain — **purely from local disk, no
peer needed** — and returns a **writable** handle (holds the signing secret, so
`append` keeps advancing the same chain). First boot → empty at seq 0. Unlike
`rehydrate` (peer-sourced, read-only until `unseal_signing_key`), a durable
reopen is immediately writable because the node re-supplies its signing secret.

### 3. Node wiring (`run.rs`)
`run()` now opens `IpfsPersistentStream::open(<data>/streamdb, …)` instead of
`PersistentStream`. The segment-signing / IPNS-head keypair is **derived
deterministically from the node's custody-held identity** (`identity.key`) via a
domain-separated `Seed` → `principal_from_seed`. "Persistence follows crypto":
the node's private key stays custody-held and is never written into the store;
the signing key is re-derived from it every boot, so a restarting node recovers
write capability from its own identity alone — no bespoke local-fs op-log, no
sealed key to pin for the solo case. All existing op paths (test-publish append,
gossip-inbound append, op-sync request/answer/apply, readiness counters) flow
through the new store unchanged.

### 4. op-sync generalized (`lib.rs`, `opsync.rs`)
New `pillar_streamdb::OpSyncTarget` trait (impl'd for both `PersistentStream`
and `IpfsPersistentStream`); `pillar_net::apply_op_sync` is now generic over it,
so peer op-sync drives either store through one path. `PersistentStream` and its
tests are untouched behaviourally.

### 5. Acceptance (`tests/persist_survives_restart.rs`)
`cargo test -p pillar-streamdb --test persist_survives_restart` — a **solo-node**
(no peers) restart-survival test: append ops → drop the handle (== process exit)
→ reopen against the same on-disk root → every op survives (as a set; `OpLog` is a
content-ordered CRDT), the head reloads, the handle is writable, and a
post-restart append also survives another restart. Also proves durability is on
disk (a bare `ContentStore::open` on the same root holds the head) and is
per-owner (a different identity sees an empty stream).

## What is NOT in this change (the remaining multi-node piece)

A **real libp2p-backed `SegmentSource`** for cross-node segment backfill is NOT
wired. Reason: the existing `pillar_net::blob` request/response substrate carries
opaque bytes keyed by their own digest and **structurally cannot carry a
`SignedSegment`** (its signature + inner-bytes `Cid`); a real peer backfill needs
a NEW request/response protocol (`SegmentRequest{cid}` / `SegmentResponse{wire}`),
a sync→async bridge for the synchronous `SegmentSource::fetch`, a node
`EventBehaviour` arm, and a consumer decision (WHEN a node rehydrates from a peer
vs. local disk). That is a distributed-protocol feature that must ride
`streamdb-persistence-spec` (TLA-first, per ROI method #1) with a two-node
node-level acceptance — a separate task, not a finishing wire-up. It is **not**
required for the reported symptom: a solo seed node now survives redeploys from
local disk, and multi-node op-set convergence already rides the existing
op-sync/gossip path.

Also separate (as the operator noted): routing the **web `WebAuthContext`
cell-bootstrap ceremony** through the node's durable stream. This change makes
the substrate durable and wires it into the node; a bootstrap op authored via the
web UI still lands only in in-memory `WebAuthContext` until that low-priority
web-context seam is closed. Both together are needed for a UI-bootstrapped cell to
survive a redeploy end-to-end.

## Verification
- `cargo test -p pillar-streamdb` — 43 lib + 2 restart + existing integration, all pass.
- `cargo test -p pillar-net` — all pass (op-sync generalization).
- `cargo check --workspace` — clean.
- `cargo test -p pillar-cli --lib` — passes except 9 pre-existing `web_serve`
  UI-panel tests that require a prebuilt `pillar_frontend.wasm` (environmental,
  unrelated).
