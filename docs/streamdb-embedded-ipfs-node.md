# streamdb persistence on pillar's OWN embedded IPFS node (no daemon)

**Status:** landed (operator-directed). Replaces the hand-rolled in-memory
"IPFS" content store — and the interim external-`kubo`-sidecar backend — with
pillar's own **embeddable IPFS node** (`crates/pillar-ipfs`), built into the
node binary. Satisfies ROI non-negotiables #5 (the IPFS/libp2p layer OWNS
content-addressing) and #7 (durable persistence MUST ride IPFS). **No external
IPFS daemon, no sidecar, no HTTP RPC.** `kubo` appears in the codebase in exactly
one place: an `#[ignore]`d test oracle proving our blocks are real IPFS blocks.

## Why this shape (operator directive)

An earlier iteration ran a real `ipfs/kubo` daemon as a pod sidecar. The
operator ruled that out: pillar must *own* the IPFS primitive as embeddable Rust,
not shell out to a daemon. So the IPFS node is now a first-class pillar crate the
node embeds directly; kubo may only be used to *validate* interop, never at
runtime.

## `crates/pillar-ipfs` — the embeddable node

- **Real CIDv1 addressing** (`cid.rs`): a pillar `ContentId` is a SHA2-256
  multihash — exactly the multihash inside a real IPFS CIDv1(`raw`).
  `to_cidv1_raw`/`from_cidv1_raw` re-encode it as `bafkrei…` (multibase base32).
  These are pure re-encodings, not a second hash.
- **Content-addressed blockstore** (`blockstore.rs`): `FsBlockstore` persists
  each block as one file named by its real CIDv1 string (so the directory is a
  set of real IPFS blocks a reference node could import unchanged);
  `MemBlockstore` for ephemeral peers/tests. Durable pin/provide sets
  (`FsMarkerSet`/`MemMarkerSet`).
- **`IpfsNode`** (`node.rs`): blockstore + pin set + provide set with
  `put_block`/`put_block_checked`/`get_block`/`has_block`/`pin`/`pinned`/
  `provide`/`provided`. Every get re-verifies the bytes hash to the CID; a block
  can never be filed under an id its bytes do not produce. `IpfsNode::open(root)`
  is durable on the PVC; `IpfsNode::in_memory()` is ephemeral.

### Interop, proven against the reference implementation
`tests/kubo_interop.rs` (`#[ignore]`, `PILLAR_TEST_KUBO=1`, `ipfs` CLI on PATH)
runs `ipfs` **offline** as an external oracle and asserts two directions:
1. kubo, given the exact bytes `pillar-ipfs` stores, computes the **identical**
   CIDv1(`raw`,sha2-256) string.
2. kubo can `block get` that block by the CID `pillar-ipfs` computed, returning
   byte-identical content.

Verified against `ipfs/kubo v0.32.1`: both pass. This proves the blocks ARE real
IPFS blocks. kubo is a test oracle only — it is not a dependency of `pillar-ipfs`
or of pillar.

## streamdb + node wiring

- `pillar-streamdb`'s `ContentStore` durability seam (`IpfsBackend`) now has one
  production impl, `NativeIpfsBackend`, a thin adapter over `pillar_ipfs::IpfsNode`
  (blocks/pins/provides) plus an owner-signed head store on the PVC. The old
  `KuboBackend`, its `kubo` cargo feature, and the `ureq` HTTP dependency are
  deleted.
- The node (`crates/pillar-cli/src/run.rs`) opens
  `ContentStore::open(<data>/streamdb)` — the embedded node, no `PILLAR_IPFS_API`,
  no daemon reachability gate. The segment-signing / head key is still derived
  deterministically from the custody-held identity ("persistence follows
  crypto").

## Mutable head
kubo (or any block store) is immutable/content-addressed; a stream's HEAD is a
mutable, owner-signed IPNS-format pointer. Pillar owns head signing and keeps the
owner-signed `HeadRecord` on the PVC (`<data>/streamdb/heads`). Matches the
spec's `publishHead`/`HeadSignedByOwner`.

## What is real now vs the next layer
- **Now (this change):** the durable, content-addressed **storage + addressing**
  layer of a real IPFS node, embedded in-process. A solo node persists every op
  as a real IPFS block, pins it, and **rehydrates its whole op set from its own
  pinned blocks across a restart** — proven by
  `tests/persist_survives_restart.rs`, which reopens a bare `ContentStore::open`
  and finds the view intact. This is the exact ROI acceptance criterion
  (rehydrate from IPFS-pinned segments + the custody key, not a local `ops/`
  dir), and it fixes the "re-bootstraps every redeploy" symptom.
- **Next layer (grown into `IpfsNode`, not faked):** the libp2p **network** —
  bitswap block exchange + Kademlia provider routing on pillar's OWN private
  swarm (off the public DHT). The `provide`/`provided` sets are already the
  anchor bookkeeping that layer publishes; `IpfsNode`'s surface does not change
  when it gains the network, and multi-node bitswap backfill is added there. Not
  claimed done here.

## Why the TLA spec did NOT change
`specs/StreamdbIpfsStore.tla` already models a real IPFS node (put/get by CID,
pin, provide→DHT for public anchors, IPNS-format `publishHead`, bitswap
`Backfill`, invariants `ContentAddressCorrect`/`HeadSequenceMonotonic`/
`HeadSignedByOwner`/`AnchorsOnlyToDHT`/`BackfillReconverges`). The storage layer
is now an honest refinement of the non-network fragment; the network layer will
refine `Backfill`/`Provide`.

## Verification
- `cargo test -p pillar-ipfs` — 5 unit (CID round-trip, base32 vectors, node
  block/pin/provide, durable reopen-from-disk) + the kubo oracle (ignored).
- `cargo test -p pillar-streamdb` — 45 lib + restart-survival + integration, all
  pass on the embedded node.
- `cargo check --workspace` clean; clippy clean for the new/changed files.
