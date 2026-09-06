# Swarm management: which physical libp2p swarm a pillar node joins

**Status:** landed. A shared `pillar-swarm` crate owns the model of *which
physical libp2p swarm a node speaks on*, surfaced in both the `pillar` CLI
(`pillar swarm …`) and the web portal (the **Swarm** panel). Answers the
operator question "how does the swarm key work, and how do users make their
own swarm?"

**Stateless by design.** Pillar keeps **no swarm registry, no active-swarm
selection, no on-disk swarm state**. A private swarm key lives only in an
operator-owned file. The tooling offers exactly two facilities — read-only
inspection (`show`) and keygen (`generate`) — and a node is told which swarm
to join at boot via `--swarm-key <path>`.

## How the swarm key works

A pillar node's packets can only reach peers on the **same physical swarm**,
and membership is enforced at the **transport layer** by a libp2p private-
network (pnet) pre-shared key. Every transport byte is XORed with a
per-connection stream cipher keyed by that PSK, so a peer holding a different
(or no) key can never complete a handshake — it never gets far enough to send
a DHT query, a bitswap want, or an event-log message. This is completely
distinct from a *cell* (WoT / identity genesis *within* whichever swarm you
joined); a private swarm still has cells.

A swarm is named by a single **key** (a root-secret string). Each transport
crate derives its own domain-separated 32-byte pnet key from it with a
one-pass SHAKE256:

- `pillar_net::PrivateSwarmKey::from_root_secret` (label
  `pillar-network-root-psk-v1`) — the event-log / DHT swarm.
- `pillar_ipfs::PrivateSwarmKey::from_root_secret` (label
  `pillar-ipfs-network-root-psk-v1`) — the IPFS block swarm.

Same key on two nodes ⇒ same pnet key ⇒ one swarm. Two different keys derive
pnet keys indistinguishable from independent random keys, so the two swarms
are mutually invisible at the transport. The derivation is a plain hash, not a
slow KDF: pnet is a **network-membership gate**, not a password store, and the
key is a generated high-entropy value.

`pillar-swarm` deliberately owns only the **key value and its fingerprint** —
it never re-derives the pnet key itself. That keeps the domain separation
inside each transport crate and avoids a dependency cycle
(`pillar-net`/`pillar-ipfs` do not depend on `pillar-swarm`; the node glue
reads the key from `pillar-swarm` and hands it to each transport).

## Public pillar swarm vs. your own swarm

- **The public pillar swarm** — one well-known key, `PUBLIC_PILLAR_ROOT`,
  **published in the source and baked into every binary**. A node joins it by
  default (no `--swarm-key`), so the global pillar network is one swarm.
  Because the key is published it provides **namespace isolation, not
  secrecy**: it keeps pillar's public swarm from co-mingling with unrelated
  libp2p/IPFS peers, but it is not a membership gate (anyone can read it).
- **Your own swarm** — a fresh 256-bit key minted from the OS CSPRNG
  (`pillar swarm generate`). Save it to a file, distribute it out-of-band to
  the nodes you want in your private network, and boot each with
  `--swarm-key <path>`. Nobody without it can complete a handshake. This IS a
  membership gate. Because a private swarm is transport-isolated from the
  public seeds, joining one also needs its own `--seed-node`(s).

Each key also has a short, non-secret **fingerprint** (a one-way SHAKE256
digest). Two nodes on the same swarm always show the same fingerprint, so
operators can confirm they are on the same network without comparing or
leaking the key.

## No state

There is no registry file and no "active swarm." The library exposes a single
immutable `SwarmKey` value:

- `SwarmKey::public()` — the baked-in public key.
- `SwarmKey::generate()` — a fresh private key from the OS CSPRNG.
- `SwarmKey::parse(str)` / `SwarmKey::from_file(path)` — load a key the
  operator wrote to a file (first non-empty, non-`#`-comment line).
- `.kind()` (public/private), `.fingerprint()`, `.root_secret()`.

Where a private key lives is entirely the operator's concern (a file, a
secret manager, a k8s Secret) — pillar never writes it.

## Which swarm the node boots onto (`pillar node run`)

- `--swarm-key <path>` / `PILLAR_SWARM_KEY` — read a private key from a file.
- else the **public** pillar swarm (baked-in key).

Plus `--seed-node <multiaddr>` (repeatable; also `--seed` /
`PILLAR_SEED_NODE` / legacy `PILLAR_SEED_MULTIADDR`) for the seed peers a
private swarm needs. Standing up a private network is: `pillar swarm generate
> prod.key` once, distribute the file, then boot each node with
`--swarm-key prod.key --seed-node <addr>`.

## CLI

`pillar swarm …` is stateless — it reads/writes no registry:

| verb | effect |
|------|--------|
| `generate` | mint a new PRIVATE swarm key; print ONLY the key to stdout (`pillar swarm generate > prod.key`). Guidance goes to stderr. |
| `show [--swarm-key <path>] [--secret]` | print a key's kind + fingerprint (the public swarm if no `--swarm-key`); `--secret` also reveals a private key's value |

## Web portal

The **Swarm** panel (`pillar_web_frontend::panels`) is read-only inspection
plus stateless keygen, backed by real server routes in
`pillar-cli/src/web_serve.rs`:

- `GET  /portal/swarm` — show which swarm the node is **running on**:
  `SWARM <kind> <fingerprint>` plus one `SEED <multiaddr>` line per configured
  seed. A private key is never exposed here (only its fingerprint).
- `POST /portal/swarm/generate` — mint a fresh private key statelessly:
  returns `KEY <key>` + `FINGERPRINT <fp>`, once, for the operator to save and
  distribute. Persists nothing and does NOT repoint the running node.

Both require an admitted portal session; `generate` additionally passes the
shared non-loopback signing gate. The panel never repoints a running node —
that only happens by rebooting it with `--swarm-key`. The node's running-swarm
info reaches the portal read-only via
`WebAuthContext::with_swarm_info(kind, fingerprint, seeds)`, set at boot.

## Tests

- `pillar-swarm` — 8 unit tests (public baked key, generate uniqueness,
  parse/round-trip, fingerprint stability + secret-hiding, `from_file` line
  selection + typed errors).
- `pillar-cli` — `swarm_cli` dispatch (5: generate-emits-only-a-key,
  public/file `show`, hidden-by-default secret, typed file error, unknown
  verb), `run` swarm-key + seed-node resolution (7), the `web_serve`
  swarm-route test (show reports the running swarm; generate is stateless and
  never repoints), and a `ui_confirms_swarm_panel` wasm-embed parity test.
- `pillar-web-frontend` — the Swarm `PanelSpec` show/generate wiring test.
