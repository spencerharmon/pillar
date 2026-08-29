# Configuring private pillar

Pillar ships with a **public default network**: a well-known network root
(no `pnet` pre-shared key) plus well-known public seed nodes. Any node that
knows a public seed can dial in and join the shared federation's Kademlia
DHT — membership is open, and authority within that federation is gated by
the PGP Web of Trust (WoT), not by network membership.

An operator can instead run a **fully private pillar network**: configure a
secret **network root**, stand up one or more nodes as owned seeds, and
point every other node only at those owned seeds. A private network never
dials the public root's seeds and never joins the public DHT, and a peer
configured with a different (or no) root can never complete a transport
handshake with it — the refusal happens below every higher protocol, at the
`libp2p` `pnet` pre-shared-key handshake itself.

This document covers:

- the root-vs-cell distinction (read this first — it's the single most
  common point of confusion),
- choosing private vs public pillar,
- standing up owned seed nodes and configuring a private root,
- one worked example per primitive use case, running fully app-specific
  (private root, owned seeds only, no public root/seeds/DHT).

All hostnames, IPs, and addresses below are neutral placeholders
(`example.com`/`example.net` per RFC 2606, `192.0.2.0/24` per RFC 5737) —
substitute your own infrastructure's real values.

## Root vs. cell — read this first

Pillar has two entirely separate identity concepts, and "private pillar"
changes only one of them:

- **Network root** — which *physical swarm* a node's packets can reach at
  all. This is what this document configures. A root is a secret value; two
  nodes configured with the same root (or both left at the public default)
  can complete a transport handshake and see each other's traffic. Two nodes
  configured with *different* roots can never do so — the handshake itself
  refuses.
- **Cell** — the WoT/identity genesis *within* whichever network a node
  joined. A private network still has cells, still has PGP-trusted peers,
  and still enforces the identical capability-scoped authorization model
  described in [`identity.md`](identity.md). Configuring a private root does
  **not** change, weaken, or bypass WoT authority in any way — it only
  changes which swarm the node's packets physically reach.

In short: **root decides who your node can talk to at all; cell/WoT decides
what an authenticated peer inside that swarm is allowed to do.** Running
private pillar is purely a networking decision.

## Choosing private vs. public pillar

Run **public pillar** (the default — no extra configuration) when you want
your node to participate in the shared, open federation and rely on WoT
authority to gate what peers are trusted to do. This is the right default
for most deployments.

Run **private pillar** (configure a network root + owned seeds) when you
need a network that is provably isolated from the public federation — for
example:

- an app-specific deployment that must never accept or dial public-federation
  peers, regardless of WoT trust decisions (defense in depth: a network-level
  guarantee independent of authorization policy),
- a closed environment (e.g. an internal-only deployment) where public
  discovery is undesirable or disallowed,
- testing/staging swarms that must never cross-talk with production or with
  the public federation.

Every primitive use case below is written as a private-pillar deployment,
since that is the common case for a dedicated, single-purpose swarm.

## Standing up owned seed nodes with a private root

Every pillar node is inherently a seed node — there is no separate seed
daemon or special "seed mode." Standing up a private, app-specific network
is only:

1. Generate a network root secret. Any sufficiently random, sufficiently
   long string works — treat it exactly like a passphrase or a credential
   (Pillar hashes it internally into a fixed-size `pnet` pre-shared key
   under a fixed domain-separation tag, so the input string's exact length
   or format is not itself significant, only its secrecy and uniqueness to
   your network). Store it in your own secret manager; it is never
   transmitted or discoverable by peers that don't already hold it.
2. Set the **same** root on every node you want in this private network,
   via either the flag or the environment variable:

   ```
   pillar node run --network-root '<your-generated-secret>' ...
   # or
   PILLAR_NETWORK_ROOT='<your-generated-secret>' pillar node run ...
   ```

3. Point each node at one or more of your other owned nodes as its seed(s),
   via `--seed` (repeatable) or `PILLAR_SEED_MULTIADDR` (comma/space
   separated list):

   ```
   pillar node run \
     --network-root '<your-generated-secret>' \
     --seed /ip4/192.0.2.10/tcp/4001/p2p/<seed-node-peer-id> \
     --seed /ip4/192.0.2.11/tcp/4001/p2p/<seed-node-peer-id> \
     ...
   ```

   The very first node you bring up has nothing to seed from yet — leave
   `--seed`/`PILLAR_SEED_MULTIADDR` unset for it; it acts as the network's
   first/seed node, and every subsequent node points at it (or at each
   other, once more than one node is up).

That's it — no additional daemon, no separate bootstrap/rendezvous service,
and no change to identity/cell/WoT configuration. Do **not** configure
`--seed`/`PILLAR_SEED_MULTIADDR` to point at any public-federation seed
address if you want a fully isolated network; simply never listing a public
seed, combined with the mismatched-root refusal below, is what gives the "no
public root/seeds/DHT" guarantee.

### Why this is safe from public-federation leakage

Two independent, layered guarantees prevent an app-specific private network
from ever touching the public federation:

1. **You never configure a public seed.** Nothing dials out to the public
   federation's known seed addresses unless you put one in `--seed`/
   `PILLAR_SEED_MULTIADDR` yourself.
2. **The transport itself refuses a mismatched root.** Even if a public-
   federation peer somehow attempted to dial or be dialed by one of your
   private nodes, the `pnet` pre-shared-key handshake — which runs below
   `noise`/`yamux`, before any higher protocol including the DHT protocol
   (`/pillar/kad`) is ever spoken — never completes unless both sides are
   configured with the identical root. A public-default peer (no root
   configured) and a private-root peer can never complete a handshake with
   each other, in either direction.

`--dial`/`PILLAR_DIAL` is a separate, lower-level knob (a raw point-to-point
libp2p dial used by the integration-test rig for mesh formation) and is
**not** the DHT-joining mechanism — it is unrelated to standing up a private
federation and most deployments never need it.

## Other node configuration (for reference)

Alongside root and seed, every node also takes:

| flag | env | default |
|------|-----|---------|
| `--identity-key` | `PILLAR_IDENTITY_KEY` | `<data-dir>/identity.key` |
| `--data-dir` | `PILLAR_DATA_DIR` | `./pillar-data` |
| `--listen` (repeatable) | `PILLAR_LISTEN` (comma/space list) | `/ip4/0.0.0.0/tcp/0` |

These are unrelated to the private/public network decision and are set the
same way regardless of which root you configure.

## Per-primitive worked examples

Every primitive below uses the **identical** private-pillar pattern from
above: generate one root secret for the deployment, set it on every node
running that workload, and point the nodes at each other as owned seeds.
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

In every example below, substitute your own generated secret for
`<root-secret>` and your own node addresses/peer IDs for the placeholders.

### 1. SQL / relational layer

Stand up a small owned cluster (e.g. 3 nodes) dedicated to this workload:

```
# node A (first node)
pillar node run --network-root '<root-secret>' ...

# node B, C (point at A)
pillar node run --network-root '<root-secret>' \
  --seed /ip4/192.0.2.20/tcp/4001/p2p/<node-A-peer-id> ...
```

Deploy your SQL-layer workload's manifest against this swarm once its
`ResourceSpec` plugin driver ships. No public root, seeds, or DHT are ever
configured for this cluster.

### 2. Timeseries layer

Same pattern — an owned, private swarm dedicated to the timeseries
workload, isolated from any other primitive's swarm by using a *different*
root secret per deployment (recommended) so a compromise or misconfiguration
in one workload's network cannot reach another's:

```
pillar node run --network-root '<timeseries-root-secret>' \
  --seed /ip4/192.0.2.30/tcp/4001/p2p/<seed-peer-id> ...
```

### 3. Key/secret distribution layer

Given this workload's sensitivity, treat the root secret with the same care
as any other credential it will distribute (separate secret-manager entry,
restricted access). Node configuration is otherwise identical:

```
pillar node run --network-root '<secret-distribution-root-secret>' \
  --seed /ip4/192.0.2.40/tcp/4001/p2p/<seed-peer-id> ...
```

### 4. Key/value store

```
pillar node run --network-root '<kv-root-secret>' \
  --seed /ip4/192.0.2.50/tcp/4001/p2p/<seed-peer-id> ...
```

### 5. Message bus

```
pillar node run --network-root '<bus-root-secret>' \
  --seed /ip4/192.0.2.60/tcp/4001/p2p/<seed-peer-id> ...
```

### 6. User-management system

```
pillar node run --network-root '<usermgmt-root-secret>' \
  --seed /ip4/192.0.2.70/tcp/4001/p2p/<seed-peer-id> ...
```

Note that this is still independent of WoT identity/authority
([identity.md](identity.md)) — a private root isolates the *network*, while
the user-management workload's own authorization model (however its plugin
defines it) is unaffected by which root the underlying pillar swarm uses.

### 7. Telemetry API + UI

Pillar's built-in observability signal stream ([observability.md](observability.md))
already runs over the same event-log transport as everything else, so a
telemetry-only deployment gets the identical isolation guarantee for free:

```
pillar node run --network-root '<telemetry-root-secret>' \
  --seed /ip4/192.0.2.80/tcp/4001/p2p/<seed-peer-id> \
  --web-bind 0.0.0.0 --web-port 8642 ...
```

`--web-bind`/`PILLAR_WEB_BIND` (and `--web-port`/`PILLAR_WEB_PORT`, default
`8642`) enable the node's web UI surface, which is otherwise off by default;
they are unrelated to the network-root/seed configuration and can be set on
any node regardless of public or private root.

## Summary checklist for an app-specific private deployment

- [ ] Generate one root secret per isolated deployment (do not reuse across
      unrelated workloads).
- [ ] Set `--network-root`/`PILLAR_NETWORK_ROOT` identically on every node
      in that deployment.
- [ ] Point every node but the first at one or more owned nodes via
      `--seed`/`PILLAR_SEED_MULTIADDR`.
- [ ] Never list a public-federation seed address.
- [ ] Confirm no node in the deployment has `--network-root` unset (an unset
      root falls back to the public default and that node will refuse to
      talk to the rest of your private swarm).
