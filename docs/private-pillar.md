# Configuring private pillar

Pillar ships with a **public default swarm**: a well-known, published swarm
key baked into every binary (`pillar_swarm::PUBLIC_PILLAR_ROOT`) plus
well-known public seed **anchors** baked in as `pillar_swarm::PUBLIC_PILLAR_SEEDS`
(libp2p `/dnsaddr/seed.pillar-rs.net` bootstrap addresses at pillar's own
public infrastructure). A fresh node with no `--swarm-key` and no `--seed-node`
joins the public swarm with zero configuration — it derives the public pnet key
and bootstraps the public Kademlia DHT from those anchors. The anchors carry
**no peer id**; the peer id lives in the operator-managed
`_dnsaddr.seed.pillar-rs.net` DNS TXT record (the IPFS/libp2p bootstrap
convention), which pillar's DNS transport resolves at runtime — so seed nodes
rotate by editing a TXT record, never a pillar release. Membership is open, and
authority within that federation is gated by the PGP Web of Trust (WoT), not
by network membership. The public key provides **namespace isolation, not
secrecy**: it keeps pillar's public swarm from co-mingling with unrelated
`libp2p`/IPFS peers, but anyone can join it (they all bake in the same
published value).

An operator can instead run a **fully private pillar network**: mint a
secret **swarm key**, distribute the key file to every node, stand up one or
more nodes as owned seeds, and point every other node only at those owned
seeds. A private network never dials the public seeds and never joins the
public DHT, and a peer configured with a different (or no) key can never
complete a transport handshake with it — the refusal happens below every
higher protocol, at the `libp2p` `pnet` pre-shared-key handshake itself.

**Pillar keeps no swarm state.** There is no swarm registry, no "active
swarm" selection, nothing persisted. A swarm key lives only in the
operator-owned file you generate; a node is told which swarm to join at boot
with `--swarm-key <path>` (and, for a private swarm, its own `--seed-node`s).
The `pillar swarm` CLI offers exactly two read-only/keygen facilities:
`generate` (mint a key, print it to stdout) and `show` (inspect a key's kind
+ fingerprint).

This document covers:

- the swarm-key-vs-cell distinction (read this first — it's the single most
  common point of confusion),
- choosing private vs public pillar,
- generating a swarm key, standing up owned seed nodes, and booting nodes
  onto it,
- one worked example per primitive use case, running fully app-specific
  (private key, owned seeds only, no public key/seeds/DHT).

All hostnames, IPs, and addresses below are neutral placeholders
(`example.com`/`example.net` per RFC 2606, `192.0.2.0/24` per RFC 5737) —
substitute your own infrastructure's real values.

## Swarm key vs. cell — read this first

Pillar has two entirely separate identity concepts, and "private pillar"
changes only one of them:

- **Swarm key** — which *physical swarm* a node's packets can reach at all.
  This is what this document configures. A key is a secret value (for the
  public swarm it is the published baked-in key); two nodes configured with
  the same key can complete a transport handshake and see each other's
  traffic. Two nodes configured with *different* keys can never do so — the
  handshake itself refuses.
- **Cell** — the WoT/identity genesis *within* whichever swarm a node
  joined. A private swarm still has cells, still has PGP-trusted peers, and
  still enforces the identical capability-scoped authorization model
  described in [`identity.md`](identity.md). Configuring a private key does
  **not** change, weaken, or bypass WoT authority in any way — it only
  changes which swarm the node's packets physically reach.

In short: **the swarm key decides who your node can talk to at all; cell/WoT
decides what an authenticated peer inside that swarm is allowed to do.**
Running private pillar is purely a networking decision.

## Choosing private vs. public pillar

Run **public pillar** (the default — no `--swarm-key`) when you want your
node to participate in the shared, open federation and rely on WoT authority
to gate what peers are trusted to do. This is the right default for most
deployments.

Run **private pillar** (a generated swarm key + owned seeds) when you need a
network that is provably isolated from the public federation — for example:

- an app-specific deployment that must never accept or dial public-federation
  peers, regardless of WoT trust decisions (defense in depth: a network-level
  guarantee independent of authorization policy),
- a closed environment (e.g. an internal-only deployment) where public
  discovery is undesirable or disallowed,
- testing/staging swarms that must never cross-talk with production or with
  the public federation.

Every primitive use case below is written as a private-pillar deployment,
since that is the common case for a dedicated, single-purpose swarm.

## Generating a key and standing up owned seed nodes

Every pillar node is inherently a seed node — there is no separate seed
daemon or special "seed mode." Standing up a private, app-specific network
is only:

1. **Generate a swarm key** and save it to a file. `generate` prints only
   the key to stdout, so redirecting yields a clean key file:

   ```
   pillar swarm generate > deployment.key
   ```

   The key is a high-entropy value minted from the OS CSPRNG. Treat the file
   exactly like a credential — it is the join credential for the swarm; store
   it in your own secret manager and distribute it only to nodes you want in
   this network. You can confirm two files name the same swarm without
   comparing the secret by checking their fingerprints:

   ```
   pillar swarm show --swarm-key deployment.key
   ```

2. **Distribute the same key file** to every node you want in this private
   network, and boot each with `--swarm-key` (or `PILLAR_SWARM_KEY`):

   ```
   pillar node run --swarm-key /etc/pillar/deployment.key ...
   # or
   PILLAR_SWARM_KEY=/etc/pillar/deployment.key pillar node run ...
   ```

3. **Point each node at one or more owned seeds**, via `--seed-node`
   (repeatable) or `PILLAR_SEED_NODE` (comma/space separated list). A private
   swarm is transport-isolated from the public seeds, so it needs its own:

   ```
   pillar node run \
     --swarm-key /etc/pillar/deployment.key \
     --seed-node /ip4/192.0.2.10/tcp/4001/p2p/<seed-node-peer-id> \
     --seed-node /ip4/192.0.2.11/tcp/4001/p2p/<seed-node-peer-id> \
     ...
   ```

   The very first node you bring up has nothing to seed from yet — leave
   `--seed-node`/`PILLAR_SEED_NODE` unset for it; it acts as the network's
   first/seed node, and every subsequent node points at it (or at each
   other, once more than one node is up).

That's it — no additional daemon, no separate bootstrap/rendezvous service,
no swarm registry, and no change to identity/cell/WoT configuration. Do
**not** configure `--seed-node`/`PILLAR_SEED_NODE` to point at any
public-federation seed address if you want a fully isolated network; simply
never listing a public seed, combined with the mismatched-key refusal below,
is what gives the "no public key/seeds/DHT" guarantee.

> `--seed-node` supersedes the older `--seed` / `PILLAR_SEED_MULTIADDR`
> spelling, which still works as an alias.

### Why this is safe from public-federation leakage

Two independent, layered guarantees prevent an app-specific private network
from ever touching the public federation:

1. **You never configure a public seed.** Nothing dials out to the public
   federation's known seed addresses unless you put one in
   `--seed-node`/`PILLAR_SEED_NODE` yourself.
2. **The transport itself refuses a mismatched key.** Even if a public-
   federation peer somehow attempted to dial or be dialed by one of your
   private nodes, the `pnet` pre-shared-key handshake — which runs below
   `noise`/`yamux`, before any higher protocol including the DHT protocol
   (`/pillar/kad`) is ever spoken — never completes unless both sides are
   configured with the identical key. A public peer (baked-in public key) and
   a private-key peer can never complete a handshake with each other, in
   either direction.

`--dial`/`PILLAR_DIAL` is a separate, lower-level knob (a raw point-to-point
libp2p dial used by the integration-test rig for mesh formation) and is
**not** the DHT-joining mechanism — it is unrelated to standing up a private
federation and most deployments never need it.

## Other node configuration (for reference)

Alongside the swarm key and seeds, every node also takes:

| flag | env | default |
|------|-----|---------|
| `--identity-key` | `PILLAR_IDENTITY_KEY` | `<data-dir>/identity.key` |
| `--data-dir` | `PILLAR_DATA_DIR` | `./pillar-data` |
| `--listen` (repeatable) | `PILLAR_LISTEN` (comma/space list) | `/ip4/0.0.0.0/tcp/0` |
| `--upnp` (flag) | `PILLAR_UPNP` (truthy) | off |

These are unrelated to the private/public network decision and are set the
same way regardless of which swarm you configure.

`--upnp` asks the local gateway (via UPnP/NAT-PMP) to forward this node's
listen ports and advertises the resulting public address through `identify`,
so a node behind a home NAT becomes publicly dialable — the same gateway path
WireGuard uses. A **public seed** running behind a residential router sets
`--upnp` and a FIXED listen port (e.g. `--listen /ip4/0.0.0.0/tcp/4001`) so
its public address is stable enough to name in a `_dnsaddr` TXT record. If no
UPnP-capable gateway is found the node logs it and keeps running (it is simply
not auto-mapped); a directly reachable node does not need `--upnp`.

## Per-primitive worked examples

Every primitive below uses the **identical** private-pillar pattern from
above: generate one swarm key for the deployment, distribute it to every
node running that workload, and point the nodes at each other as owned seeds.
Only the workload manifest you run on top differs by primitive — there is
no per-primitive networking mechanism. As of this writing, concrete
`ResourceSpec` plugin drivers for these workload types are separate,
individually-scheduled out-of-tree tasks (see
[plugin-surface.md](plugin-surface.md)); this section therefore documents
only the node-level configuration that is common to all of them and defers
to each plugin's own manifest reference (once shipped) for the
workload-specific object shape. Do not treat the manifest snippets below as
authoritative — they illustrate only which node flags to set, not an
unbuilt manifest schema.

In every example below, substitute your own generated key file for
`<deployment>.key` and your own node addresses/peer IDs for the placeholders.
Generate a *different* key per deployment (recommended) so a compromise or
misconfiguration in one workload's network cannot reach another's.

### 1. SQL / relational layer

Stand up a small owned cluster (e.g. 3 nodes) dedicated to this workload:

```
# once: mint the key and distribute the file to all three nodes
pillar swarm generate > sql.key

# node A (first node)
pillar node run --swarm-key sql.key ...

# node B, C (point at A)
pillar node run --swarm-key sql.key \
  --seed-node /ip4/192.0.2.20/tcp/4001/p2p/<node-A-peer-id> ...
```

Deploy your SQL-layer workload's manifest against this swarm once its
`ResourceSpec` plugin driver ships. No public key, seeds, or DHT are ever
configured for this cluster.

### 2. Timeseries layer

Same pattern — an owned, private swarm dedicated to the timeseries workload,
isolated from any other primitive's swarm by using a *different* key file per
deployment:

```
pillar node run --swarm-key timeseries.key \
  --seed-node /ip4/192.0.2.30/tcp/4001/p2p/<seed-peer-id> ...
```

### 3. Key/secret distribution layer

Given this workload's sensitivity, treat the key file with the same care as
any other credential it will distribute (separate secret-manager entry,
restricted access). Node configuration is otherwise identical:

```
pillar node run --swarm-key secret-distribution.key \
  --seed-node /ip4/192.0.2.40/tcp/4001/p2p/<seed-peer-id> ...
```

### 4. Key/value store

```
pillar node run --swarm-key kv.key \
  --seed-node /ip4/192.0.2.50/tcp/4001/p2p/<seed-peer-id> ...
```

### 5. Message bus

```
pillar node run --swarm-key bus.key \
  --seed-node /ip4/192.0.2.60/tcp/4001/p2p/<seed-peer-id> ...
```

### 6. User-management system

```
pillar node run --swarm-key usermgmt.key \
  --seed-node /ip4/192.0.2.70/tcp/4001/p2p/<seed-peer-id> ...
```

Note that this is still independent of WoT identity/authority
([identity.md](identity.md)) — a private key isolates the *network*, while
the user-management workload's own authorization model (however its plugin
defines it) is unaffected by which swarm the underlying pillar transport uses.

### 7. Telemetry API + UI

Pillar's built-in observability signal stream ([observability.md](observability.md))
already runs over the same event-log transport as everything else, so a
telemetry-only deployment gets the identical isolation guarantee for free:

```
pillar node run --swarm-key telemetry.key \
  --seed-node /ip4/192.0.2.80/tcp/4001/p2p/<seed-peer-id> \
  --web-bind 0.0.0.0 --web-port 8642 ...
```

`--web-bind`/`PILLAR_WEB_BIND` (and `--web-port`/`PILLAR_WEB_PORT`, default
`8642`) enable the node's web UI surface, which is otherwise off by default;
they are unrelated to the swarm-key/seed configuration and can be set on any
node regardless of public or private swarm. The web UI's **Swarm** panel is
read-only: it shows which swarm the node is running on (kind + fingerprint +
seeds) and can `generate` a fresh private key to distribute, but it never
repoints the running node — that only happens by rebooting with `--swarm-key`.

## Summary checklist for an app-specific private deployment

- [ ] Generate one swarm key per isolated deployment
      (`pillar swarm generate > <name>.key`); do not reuse across unrelated
      workloads.
- [ ] Distribute that key file and set `--swarm-key`/`PILLAR_SWARM_KEY` to it
      identically on every node in that deployment.
- [ ] Point every node but the first at one or more owned nodes via
      `--seed-node`/`PILLAR_SEED_NODE`.
- [ ] Never list a public-federation seed address.
- [ ] Confirm no node in the deployment has `--swarm-key` unset (an unset key
      falls back to the public swarm and that node will refuse to talk to the
      rest of your private swarm). Confirm all nodes report the same
      fingerprint with `pillar swarm show --swarm-key <name>.key`.
