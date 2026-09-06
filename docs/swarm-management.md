# Swarm management: which physical libp2p swarm a pillar node joins

**Status:** landed. Adds a shared `pillar-swarm` crate that owns the model of
*which physical libp2p swarm a node speaks on*, and surfaces management of it in
both the `pillar` CLI (`pillar swarm …`) and the web portal (the **Swarm**
panel). Answers the operator question "how does the swarm key work, and how do
users make their own swarm?"

## How the swarm key works

A pillar node's packets can only reach peers on the **same physical swarm**, and
membership is enforced at the **transport layer** by a libp2p private-network
(pnet) pre-shared key. Every transport byte is XORed with a per-connection
stream cipher keyed by that PSK, so a peer holding a different (or no) key can
never complete a handshake — it never gets far enough to send a DHT query, a
bitswap want, or an event-log message. This is completely distinct from a
*cell* (WoT / identity genesis *within* whichever swarm you joined); a private
swarm still has cells.

A swarm is named by a single **root secret**. Each transport crate derives its
own domain-separated 32-byte pnet key from it with a one-pass SHAKE256:

- `pillar_net::PrivateSwarmKey::from_root_secret` (label
  `pillar-network-root-psk-v1`) — the event-log / DHT swarm.
- `pillar_ipfs::PrivateSwarmKey::from_root_secret` (label
  `pillar-ipfs-network-root-psk-v1`) — the IPFS block swarm.

Same root on two nodes ⇒ same pnet key ⇒ one swarm. Two different roots derive
keys indistinguishable from independent random keys, so the two swarms are
mutually invisible at the transport. The derivation is a plain hash, not a slow
KDF: pnet is a **network-membership gate**, not a password store, and the root
is expected to be a generated high-entropy value, not a guessable password.

`pillar-swarm` deliberately owns only the **root secret and profile
bookkeeping** — it never re-derives the pnet key itself. That keeps the domain
separation inside each transport crate and avoids a dependency cycle
(`pillar-net`/`pillar-ipfs` do not depend on `pillar-swarm`; the node glue reads
the root from `pillar-swarm` and hands it to each transport).

## Public pillar swarm vs. your own swarm

There are two ways to be on a swarm:

- **The public pillar swarm** — one well-known root, `PUBLIC_PILLAR_ROOT`,
  **published in the source and baked into every binary**. Every node joins it
  by default, so the global pillar network is one swarm. Because the key is
  published it provides **namespace isolation, not secrecy**: it keeps pillar's
  public swarm from co-mingling with unrelated libp2p/IPFS peers on the open
  transport, but it is not a membership gate (anyone can read it). That is the
  correct model for a public network — joinable by all, still isolated from the
  rest of the libp2p world. (This *tightens* the earlier "public = open
  transport, no pnet" default: public is now a real, keyed pnet swarm.)
- **Your own swarm** — a fresh 256-bit root minted from the OS CSPRNG
  (`pillar swarm new <name>`). Distribute it out-of-band to the nodes you want
  in your private network (`pillar swarm import <name> <secret>` on each);
  nobody without it can complete a handshake. This IS a membership gate.

Each swarm also has a short, non-secret **fingerprint** (a one-way SHAKE256
digest of the root). Two nodes on the same swarm always show the same
fingerprint, so operators can confirm they are on the same network without
comparing or leaking the root secret.

## The registry

`SwarmRegistry` persists the swarms a node knows plus which one is **active**,
at `<data-dir>/swarm/registry.json` (written `0600` — it holds private join
credentials). It always contains the public swarm and always has a valid active
selection. The node's transport boots onto the active swarm.

## Resolving which swarm the node boots onto (`pillar node run`)

1. `--network-root <secret>` / `PILLAR_NETWORK_ROOT` — an explicit ad-hoc root,
   wins over everything.
2. else `--swarm <name>` / `PILLAR_SWARM` — a named swarm from the registry.
3. else the registry's **active** swarm.
4. the registry defaults to the **public** swarm.

So a node with nothing configured joins the one global public swarm on a real
pnet key. Standing up a private network is exactly: `pillar swarm new prod` on
one node, share the printed root, `pillar swarm import prod <secret>` +
`pillar swarm use prod` on each other node (or set `PILLAR_SWARM=prod`), then
seed them at each other with the existing `--seed` mechanism.

## CLI

`pillar swarm …` operates directly on the registry under the resolved data dir
(the same `--data-dir`/`PILLAR_DATA_DIR` the node uses), like the local-context
verbs:

| verb | effect |
|------|--------|
| `ls` / `list` | list known swarms, mark the active one, show kind + fingerprint |
| `current` | show the active swarm |
| `show [<name>] [--secret]` | show a swarm's details (`--secret` reveals a private root) |
| `new <name>` | mint a new PRIVATE swarm and print its root secret to distribute |
| `use <name>` | switch the active swarm the node boots onto |
| `import <name> <root-secret>` | adopt an existing private swarm from a shared secret |
| `export [<name>]` | print a swarm's root secret (the shareable join credential) |
| `forget <name>` | remove a known swarm (not the public or active one) |

## Web portal

The **Swarm** panel (`pillar_web_frontend::panels`) lists the known swarms
(active marked) and wires two acts, backed by real server routes in
`pillar-cli/src/web_serve.rs`:

- `GET  /portal/swarm` — list rows `SWARM <*|-> <name> <kind> <fingerprint>`. A
  private swarm's root secret is **never** in the list (only its fingerprint).
- `POST /portal/swarm/use`  (`<token>\n<name>`) — switch the active swarm.
- `POST /portal/swarm/new`  (`<token>\n<name>`) — mint a new private swarm;
  returns its row plus its `ROOT <secret>` line, once, to distribute.

All three require an admitted portal session; the two acts additionally pass the
shared non-loopback signing gate, so an unauthenticated caller cannot repoint
the node's transport. Portal edits persist to the same
`<data-dir>/swarm/registry.json` the transport boots from.

## Tests

- `pillar-swarm` — 9 unit tests (public baked root, generate/import/fingerprint,
  registry lifecycle, on-disk round trip + `0600`, repair).
- `pillar-cli` — `swarm_cli` dispatch (5), `run` swarm-flag resolution (3), the
  `web_serve` swarm-route test (list/switch/mint + the private-root-never-leaked
  invariant), and a `ui_confirms_swarm_panel` wasm-embed parity test.
- `pillar-web-frontend` — the Swarm `PanelSpec` wiring/parse test.
