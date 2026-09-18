# Peer discovery, bootstrap & the config anchor set

How a Pillar node finds the peers it talks to — the identity/reachability
model, the one-time bootstrap, the steady-state cell-scoped discovery, and the
small `config.yaml` anchor set an operator maintains for reconnect.

This document describes the operator- and user-facing surface. The transport
substrate itself (libp2p Swarm, Kademlia, gossipsub, identify, DCUtR/relay) is
covered in [architecture.md](architecture.md); the naming/authority split it
builds on is in the ROI's "Naming plane vs authority plane".

## The model: identity is not location

A peer's **identity** is its key — a stable libp2p `PeerId` derived from the
node keypair, persisted across restarts. Its **location** is a *set* of
[multiaddrs](https://docs.libp2p.io/concepts/fundamentals/addressing/), never a
single address. One peer can be reachable at several addresses at once —
multiple IPv4, multiple IPv6, over different transports — and a connection stays
keyed by `PeerId` regardless of which address won the dial. This is the standard
libp2p `PeerInfo` relationship (a `PeerId` plus the set of multiaddrs it listens
on); Pillar does not narrow it.

Two **kinds** of address travel through the system, and they must not be
conflated:

- **Reachability addresses** — where a node itself listens (its peer multiaddr
  set). Owned by the node, discovered or declared. Never handed out to a
  workload.
- **Allocatable addresses** — VIPs, service addresses, and pod pools that
  controllers hand to Deployments/StatefulSets/ResourceSets. These are *not*
  peer addresses; they are resources parented to a topology scope.

The rest of this document is about the first kind — how a node learns other
nodes' reachability addresses. Allocatable addresses are covered under the load
balancing / IPAM surface.

## Address forms: FQDN or raw IP, one multiaddr type

Every address the node consumes is a multiaddr, which encodes both DNS and
raw-IP forms in one syntax. You may use whichever suits your deployment:

```
/dnsaddr/ingest.example.net/p2p/<peer-id>            # FQDN, resolves _dnsaddr TXT (may carry the peer id)
/dns4/ingest.example.net/tcp/4001/p2p/<peer-id>      # FQDN, A record
/dns6/ingest.example.net/tcp/4001/p2p/<peer-id>      # FQDN, AAAA record
/ip4/192.0.2.7/tcp/4001/p2p/<peer-id>                # raw IPv4, TCP
/ip6/2001:db8::7/udp/4001/quic-v1/p2p/<peer-id>      # raw IPv6, QUIC
/ip4/192.0.2.8/udp/4001/p-pillar/p2p/<peer-id>       # raw IPv4, pillar-UDP transport
```

DNS forms are resolved at runtime by the libp2p DNS transport; a `/dnsaddr`
anchor can even carry the peer id in the `_dnsaddr.<host>` TXT record, so a seed
is rotated by editing a TXT record rather than shipping a new release.

> All examples use RFC 2606 / RFC 5737 placeholders (`example.net`,
> `192.0.2.0/24`, `2001:db8::/32`). Never commit a real deployment hostname or
> address into source; anchors live in an operator-owned `config.yaml`, not in
> the code.

## The bootstrap / reconnect ladder

A node needs to reach **one** live peer; once it has, cell-scoped discovery
(below) fills in the rest. On boot it tries, in order:

1. **Explicit CLI override** — `--dial <multiaddr>` (a raw dial) or
   `--seed-node <multiaddr>` (join via the public DHT). Highest precedence; see
   [private-pillar.md](private-pillar.md) and the swarm docs.
2. **The `config.yaml` anchor set** — a small, operator-maintained list of
   reachable ingest + backup peers (next section).
3. **Reseed** — the public/federation bootstrap over Kademlia (the baked
   `/dnsaddr` public anchor, or your private root's owned seeds). Last resort.

After reaching any live peer by any rung, the node repopulates its **in-memory**
peer address book from the cell's private pubsub. That live book is *not*
persisted — it is rebuilt each session — so the on-disk config never has to list
every node, and never churns.

## Steady-state discovery: cell-scoped, not a global DHT

Once a node is a cell member, it learns co-members' reachability addresses from
the cell itself, not from a global lookup:

- Each member publishes its current reachability address set as an
  **IPNS-format head** (`Visibility::Cell`): an owner-signed, monotone-sequence,
  TTL-bounded pointer. The newest valid sequence wins and stale/replayed records
  are rejected — last-write-wins by sequence, so a changed or dead address set
  is simply superseded, with no accumulation of dead entries.
- `Visibility::Cell` heads travel **only on the cell's private pubsub** and
  never touch any DHT. (`Visibility::Public` heads — used for public content and
  the public bootstrap anchor — are the only ones that ride the swarm-wide
  Kademlia.)

So within a cell, "find peer X" is a read of cell-scoped state gated by the
cell's own membership and forward-secret key epochs — no global keyspace walk.
**Kademlia is retained for public scope only**: the one-time public/federation
bootstrap (rung 3). It is not the steady-state discovery path.

Because bootstrap is normally a once-per-node event, the practical division is:

| Concern | Mechanism | Scope |
|---------|-----------|-------|
| First contact / cold reconnect | public Kademlia + seed/IPNS anchor | global, rare |
| Co-member reachability | `Visibility::Cell` IPNS heads on private pubsub | cell, steady-state |
| Explicit target | `--dial` / `--seed-node` | operator override |

## The `config.yaml` anchor set

`config.yaml` carries a short, static list of reachable **ingest + backup**
peers under `anchors:`. It is read-only to the daemon — Pillar never rewrites it
in normal operation — and it deliberately does **not** enumerate every node:
just enough to reach one live peer.

```yaml
# FQDN deployment — one anchor is enough (DNS fans out behind the name)
anchors:
  - /dnsaddr/ingest.example.net/p2p/<peer-id>
```

```yaml
# No-DNS deployment — a small list of raw-IP anchors (max 3: ingest + 2 backups)
anchors:
  - /ip4/192.0.2.7/tcp/4001/p2p/<peer-id>
  - /ip6/2001:db8::7/udp/4001/p-pillar/p2p/<peer-id>
  - /ip4/192.0.2.8/tcp/4001/p2p/<peer-id>
```

Count policy, enforced at load:

- **DNS anchor → 1 is sufficient.** A single `/dnsaddr` (or `/dns4`/`/dns6`)
  name already fans out to every A/AAAA record and every `_dnsaddr` TXT entry
  behind it, so one name is a complete redundancy set. The default is 1.
- **Raw-IP anchors → at most 3.** With no DNS indirection you want a little
  redundancy (a primary ingest plus up to two backups), but the file is meant to
  stay tiny — the cap is 3.
- **Mixed lists** are allowed: any DNS-form anchor satisfies the "you're
  covered" bar; the ≤3 cap applies to the raw-IP subset.

Why this stays static: with FQDN anchors, DNS indirection absorbs address
change — the name is stable while the A/AAAA/TXT records behind it move
operator-side, so `config.yaml` is edited rarely if ever. With raw-IP anchors an
address *can* go stale, but recovery is automatic as long as one anchor or the
reseed path still reaches a live peer, after which the in-memory book refills.

## Reachability warnings and regenerating anchors

At boot (and on the periodic health tick) the node probes each anchor and
reports the outcome on user-visible surfaces (log **and** the health/
observability UI), best-effort:

- An **unreachable anchor** raises a warning that names the anchor and the
  failure kind — DNS-resolution failure, dial failure, or `/p2p` peer-id
  mismatch — because each points to a different operator fix.
- Warnings fire **while the node is still degraded-but-alive** (e.g. "2 of 3
  anchors reachable — regenerate `config.yaml` before the rest go stale"),
  because regeneration must pull fresh anchors from the live cell, which is only
  possible while some connectivity remains. Warning early is what keeps manual
  regeneration possible.

Warnings stay warnings. Connectivity is a hard error **only** when *zero* anchors
are reachable **and** reseed is exhausted; any single reachable anchor, or a
successful reseed, keeps the node up with warnings.

To refresh the list, run — while still connected:

```
pillar node anchors regen
```

This queries the current co-member ingest addresses from the live cell and
writes a fresh `anchors:` block honoring the 1-DNS / ≤3-IP policy. It is the
only writer of the anchor set; the daemon never rewrites it on its own.

## How fanout uses real peer addresses

When Pillar disperses work across peers (redundant client connections, reply
dispersal), it targets the peer's **real, possibly multi-homed** reachability
set: a node is resolved through its `PeerId` to the multiaddr set it actually
advertised (via `identify` and its `Visibility::Cell` address head), so a peer
with two IPv6 and two IPv4 public addresses presents four dialable endpoints
under one identity. Dual-stack preference (IPv6-GUA first, then IPv4, with
hole-punching tiers) and topology diversity (spreading across distinct failure
domains) are applied over those real endpoints, not over synthetic per-site
addresses.

Allocatable addresses (VIPs, pod pools) are a separate plane, handed out by
controllers from operator-configured, topology-scoped pools — see the load
balancing / IPAM surface. The dividing line is the address-kind distinction from
the top of this document: reachability addresses identify *where a node is*;
allocatable addresses are *resources a workload gets*.

## Summary

- A peer is a stable `PeerId` with a *set* of multiaddrs (v4 and v6, several at
  once). Identity is decoupled from location.
- Bootstrap is once-per-node: CLI override → `config.yaml` anchors → reseed over
  public Kademlia. Reaching one peer is enough.
- Steady-state co-member discovery is cell-scoped: `Visibility::Cell` IPNS-format
  address heads on the cell's private pubsub, superseded last-write-wins by
  sequence. Kademlia is kept for public scope only.
- `config.yaml` holds a small static anchor set (1 DNS name, or ≤3 raw IPs),
  read-only to the daemon; unreachable anchors warn early and are refreshed with
  `pillar node anchors regen`.
- Fanout dials peers' real multi-homed addresses, not synthetic ones.
