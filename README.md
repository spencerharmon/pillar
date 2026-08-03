# Pillar

**A control-plane-less orchestrator for a federation of PGP-trusted peers.**

Pillar runs application workloads — OCI images, cronjobs, autoscalers, ingress,
and pluggable resource types — across a set of nodes with **no central control
plane and no single owner**. It is, roughly, "Kubernetes without etcd, for a
cooperative of peers that trust each other through the OpenPGP web of trust."

- **Identity & authorization:** OpenPGP. A user primary key authorizes node
  subkeys; controllers act under capability-scoped subkeys.
- **Messaging & storage:** libp2p (gossipsub, Kademlia, relay, hole-punching,
  QUIC). Content-addressed blobs and images ride the same layer.
- **State:** a materialized view of a streaming database — an append-only,
  content-addressed event log that every stateless peer reduces locally.
- **Consistency:** chosen per view. A quorum-fenced coordination core provides
  strict (CP) exclusivity where it is needed; relaxed (AP) CRDT state is used
  everywhere it is safe. See [docs/consistency-model.md](docs/consistency-model.md).

## Correctness first

Every core protocol is specified in **TLA+** and exhaustively model-checked with
TLC **before** its Rust implementation is trusted; the Rust tests encode the same
invariants. See [`specs/`](specs/) and [`docs/`](docs/).

The split-brain exclusion at the heart of the platform
(`AtMostOneHolderPerEpoch`) is proven in
[`specs/CoordinationCore.tla`](specs/CoordinationCore.tla) and refined by the
[`pillar-coordination`](crates/pillar-coordination) crate.

## Repository layout

```
specs/    TLA+ specifications + `check.sh` (model-checked in CI)
crates/   Rust workspace
  pillar-core          core identity / resource / consistency types
  pillar-coordination  quorum-fenced lease (refines CoordinationCore.tla)
docs/     user-facing design documentation (diagrams + spec references)
```

## Building

```sh
cargo test --all          # build + unit/property tests
( cd specs && ./check.sh ) # model-check every TLA+ spec (needs a JVM 17+)
```

## Status

Early foundational rearchitecture. The previous Python prototype
(2020–2021) is preserved on the [`python-proto-archive`](https://github.com/spencerharmon/pillar/tree/python-proto-archive)
branch.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
