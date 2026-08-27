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

## Container image

A reproducible OCI image (nix `dockerTools.streamLayeredImage`, see
[`flake.nix`](flake.nix)) is built and published to the GitHub Container
Registry by [`.github/workflows/build-image.yaml`](.github/workflows/build-image.yaml)
on every push to `main` that touches the flake/workspace, and weekly to pick
up base-image rebuilds. It authenticates with the repo's built-in
`GITHUB_TOKEN` — no infra secrets or private-registry credentials live in this
public repo.

- `ghcr.io/spencerharmon/pillar:<version>` — the immutable release tag (the
  workspace `Cargo.toml` `[workspace.package] version`).
- `ghcr.io/spencerharmon/pillar:latest` — the moving pointer to the newest
  build. Consumers should pin by the registry-served digest resolved from
  whichever tag they reference, so the moving `latest` tag never causes an
  unpinned pull.

**One-time setup:** after the workflow's first run, the `pillar` package
under this GitHub account/org defaults to **private** visibility even though
the repo is public. Set it to **public** once, in the package's own Settings
(Package settings → Danger Zone → Change visibility) — this cannot be done
from within the workflow itself with `GITHUB_TOKEN` alone — so consumers
(e.g. flux) can pull the image without credentials.

## Status

Early foundational rearchitecture. The previous Python prototype
(2020–2021) is preserved on the [`python-proto-archive`](https://github.com/spencerharmon/pillar/tree/python-proto-archive)
branch.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
