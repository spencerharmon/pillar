# streamdb persistence on a REAL IPFS node (kubo), not a reimplementation

**Status:** landed (operator-directed). Replaces the hand-rolled in-process
"IPFS" content store with a real `ipfs/kubo` node reached over its HTTP RPC API,
per ROI non-negotiables #5 (the IPFS/libp2p plugin OWNS content-addressing) and
#7 (durable persistence MUST ride IPFS). Verified end-to-end against a live kubo
daemon.

## The bug this fixes

`crates/pillar-streamdb/src/store.rs`'s `ContentStore` was a `HashMap` — a
*reimplementation* of IPFS (pins/DHT/heads in process memory), the very thing
its own module doc swore it was "NOT". `SegmentSource`'s real distribution impl
("backfill over pillar's own private libp2p swarm") was never written, and the
node ran the ROI-demoted local-fs store. Result: "no persistence between
versions / re-bootstraps every redeploy," and — more fundamentally — pillar was
not building on IPFS at all.

## Architecture

A private-swarm `ipfs/kubo` daemon runs as a **sidecar** in the `pillar-node`
pod; the node talks to it over the localhost RPC API (`http://127.0.0.1:5001`).

- **`IpfsBackend`** (`src/ipfs_backend.rs`) — the substrate trait
  (`block_put`/`block_get`/`block_has`/`pin`/`pinned`/`provide`/`provided`/
  `put_head`/`heads`). `ContentStore` delegates all durability to it and keeps
  its in-memory maps only as a fast index. Three impls:
  - **`KuboBackend`** (feature `kubo`) — real IPFS over the kubo HTTP RPC.
    Segments are real `raw` IPFS blocks (`block/put`+`pin/add`); a missing block
    is fetched over **bitswap** (`block/get`) from a private-swarm peer — the
    real refinement of the spec's `Backfill`/`BackfillReconverges`. Content
    distribution is IPFS's job; pillar never re-implements it.
  - **`FsBackend`** — an on-disk content-addressed block store (the same
    durability kubo's on-disk blockstore gives, without a daemon); powers the
    no-daemon solo restart-survival test.
  - in-memory (`ContentStore::new`, backend `None`) — ephemeral peers / unit tests.
- **CID semantics** — a segment block stores the **full signed wire form**
  (`to_wire`: bytes + signer + signature + visibility), so its CID addresses the
  whole signed object and a peer fetching it over bitswap gets the authorship
  proof *inside* the block. A pillar `Cid` (SHA2-256 multihash) is exactly the
  multihash inside a real IPFS CIDv1(`raw`); `cid_to_cidv1_raw`/`cidv1_raw_to_cid`
  convert (RFC4648 base32, multibase `b`), unit-tested against known vectors and
  `bafkrei…` shape. The op-log identity (`OpId`) is unchanged.
- **Mutable head** — kubo cannot sign an IPNS record with a *pillar* owner key,
  so pillar owns head signing itself: the owner-signed `HeadRecord` (IPNS-format,
  monotone) is kept on the PVC under `<data>/streamdb/heads`. The immutable
  content it points at lives in kubo; cross-node head propagation rides pillar's
  gossip. This matches the spec's `publishHead`/`HeadSignedByOwner` exactly.
- **Node wiring** (`crates/pillar-cli/src/run.rs`) — the node opens
  `IpfsPersistentStream::open_with_store(ContentStore::with_backend(KuboBackend::connect(PILLAR_IPFS_API, …)))`.
  The segment-signing key is derived deterministically from the custody-held
  identity. **Fail-fast**: if the sidecar is unreachable the node errors out
  rather than silently degrading to a non-durable store — the exact failure this
  change exists to prevent.

## Why the TLA spec did NOT change

`specs/StreamdbIpfsStore.tla` was already a faithful abstract model of a real
IPFS node — `put`/`get` by CID, `pin`, `provide`→DHT (public anchors only),
IPNS-format `publishHead` (owner-signed, monotone), bitswap `Backfill`,
adversarial Partition/Heal, with invariants `ContentAddressCorrect`,
`HeadSequenceMonotonic`, `HeadSignedByOwner`, `AnchorsOnlyToDHT`,
`BackfillReconverges`. The code was never an honest refinement of it; now it is.
The `KuboBackend` is the real refinement (real bitswap = `Backfill`, real pins =
durability, real `routing/provide` = `Provide`).

## Verification
- `cargo test -p pillar-streamdb` (+`--features kubo`) — 47 unit + fs/restart +
  CIDv1/base32 round-trip, all pass; `-p pillar-net` all pass; `cargo build -p
  pillar-cli` clean with the kubo backend.
- **`tests/kubo_backend_roundtrip.rs`** (feature `kubo`, `#[ignore]`, needs
  `PILLAR_TEST_KUBO_API`) — run against a LIVE `ipfs/kubo v0.32.1` daemon: a
  signed block round-trips (`block/put`→`block/get` byte-identical), is pinned
  (`pin/add`, appears in `pin/ls`), and a durable stream **rehydrates its whole
  op set from the real kubo blockstore across a fresh store handle** (a process
  restart) — NOT re-bootstrapped. Both pass. This proves the RPC client against
  a real daemon, not a mock.

## Deploying it
Requires the kubo sidecar (see `submodules/flux/infrastructure/pillar/`) and the
private-swarm key Secret provisioned out-of-band. The pillar image must be
rebuilt (nix flake → ghcr) and repinned via the `repin-pillar-node` workflow.
First boot genesis-inits the durable store against the sidecar; ops persist in
kubo thereafter.

## Follow-ups (separate, not blocking)
- Multi-node bitswap across two live pillar/kubo pods is exercised by the
  deploy; the `#[ignore]` integration test can be extended to two daemons.
- The web `WebAuthContext` cell-bootstrap ceremony still lands in in-memory
  state until it too routes through the durable stream (low-pri web-context seam).
