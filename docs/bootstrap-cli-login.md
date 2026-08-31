# Bootstrap library, CLI, and login

Status: implemented (operator-directed, 2026-08-31).

## Why

Bootstrapping a cell used to be a split web-UI flow: create the cell on one
screen, create the first user on another. Pressing **back** after creating the
cell could strand the operator in a state where the first user could no longer
be created. This change makes the whole sequence one atomic operation, factors
the bootstrap logic out of `pillar-web` into a shared crate both the web portal
and the CLI use, and adds a CLI surface (`pillar bootstrap …`, `pillar login`).

## Crate layout

The shared bootstrap logic lives in a dedicated crate, **`pillar-bootstrap`**,
depended on by both `pillar-web` and `pillar-cli`.

It is *not* in `pillar-core`: that crate is deliberately dependency-free (pure
value types that never touch the network or filesystem), and the bootstrap
sequence composes `pillar-identity`, `pillar-wot-authority`, and `pillar-rbac`.
Putting it in `pillar-core` would both violate that contract and create a
dependency cycle (`pillar-identity` already depends on `pillar-core`). The new
crate sits above the identity/authority crates and below the two front-ends, so
the CLI and the web portal can never diverge on the bootstrap contract.

Modules:

- `custody` — the per-key custody/encryption choice (`password` | `passkey` |
  `tpm` | `keyring`, the four `pillar_identity::CustodyKind` mechanisms) plus
  operator labels, applied uniformly to the cell, user, and node keys.
- `name` — the best-effort, peer-sourced cell-name uniqueness pre-check (moved
  verbatim from `pillar-web`).
- `keygen` — the identity bootstrap primitives (`Bootstrap`: user-primary
  keygen, node-subkey signing/admission) over `pillar_identity::Registry`.
- `cell` — the one-shot `cell_key_can_create_user` capability (`CellBootstrap`)
  and the **combined single-step** `bootstrap_cell_and_user`.
- `request` — the node/user bootstrap **request → approval** lifecycle.
- `token` — temporary login-token issuance and the `PILLAR_DOMAIN` /
  `PILLAR_TOKEN` env contract.

`pillar-web` re-exports the moved types (`Bootstrap`, `CellBootstrap`,
`BootstrapError`, the cell-name registry family) so existing
`pillar_web::…` / `pillar_web::node_custody::…` paths keep resolving unchanged.

## Combined single-step bootstrap

`bootstrap_cell_and_user(cell, user_handle, cell_custody, user_custody,
registry, trust_depth)` runs the whole sequence atomically:

1. **Name uniqueness** — refuse if a peer already serves the cell name, before
   any key is generated.
2. **Cell key genesis** — create the cell.
3. **Keygen + sign the user key** — anchor a `WotAuthority` at the cell and
   install a cell→user trust edge (the cell key signs the user key).
4. **Grant the user the add-users right** — an ALLOW `ExplicitGrant` of
   `identity/add-users` for the user.
5. **Revoke the cell's add-users right** — consume the one-shot capability AND
   install a DENY `ExplicitGrant` of `identity/add-users` for the cell key.

Because it is one call, there is no intermediate screen to abandon.

## Bootstrap requests (node + user)

A fresh node or a new user joins an existing cell by submitting a
`BootstrapRequest` carrying identifying information (a node advertises its peer
id, public/private addresses, version, OS, and public-key CID). An existing,
authorized member reviews the pending queue and approves or rejects it:

- **node approval** — an existing node seals (encrypts) the cell key to the
  newly-approved node and returns the CID of the sealed blob (`SealedCellKey`);
- **user approval** — the new user's operational-key offer is escrowed.

Key material is delivered ONLY to an approved request whose approver is an
authorized member; a rejected request never receives any (fail-closed). This is
proven in `specs/BootstrapRequest.tla` (TLC-green) BEFORE the Rust was written,
per the project's non-negotiable method. The node exposes it over HTTP
(`POST /bootstrap/request/node|user`, `GET /bootstrap/request/list`,
`POST /bootstrap/request/approve|reject`), gating approval on a valid login
session (an authenticated, WoT-authoritative user is an authorized member).

## Login token

`pillar login` performs the node-side custody login handshake against the
portal (`GET /nonce` → `POST /login`) and exports the resulting session bearer
as `PILLAR_DOMAIN` / `PILLAR_TOKEN`. Every later CLI command reads those env
vars (`TokenStore::from_env`) and presents the token — never the long-lived
key — for authn/authz. A web portal deployed separately from the
key-distribution server forwards the presented credentials to that server,
which is the sole minter of the token. The token lifecycle (mint only on a
forwarded valid credential, bound to one user+domain, fail-closed on
expiry/revocation) is proven in `specs/LoginToken.tla` (TLC-green).

## CLI

```
pillar bootstrap cell <name> --user <handle> [--domain D]
       [--cell-custody K] [--user-custody K] [--cell-label L]... [--user-label L]...
pillar bootstrap node --domain <D> [--key K] [--peer-id P] [--pubkey-cid C]
       [--node-custody K] [--listen A]... [--label L]...
pillar bootstrap user --domain <D> --user <id> [--user-custody K] [--label L]...
pillar bootstrap request list [--domain D]
pillar bootstrap request approve|reject <id> [--domain D]
pillar login --domain <D> --user <id> [--password P]   # eval "$(pillar login …)"
```

`custody K` is one of `password | passkey | tpm | keyring` and is available for
each key (cell, user, node), as are `--label`s.

## `onboard.rs`

`pillar onboard` (`crates/pillar-cli/src/onboard.rs`) was evaluated for the
"remove if fully redundant" instruction and **kept**: it is the non-networked
onboarding *integration invariant rig* (it asserts the keygen → node-subkey
signing → cross-user trust → depth/policy invariants end to end, driven by
`scripts/onboarding-rig-test.sh`), a different concern from the bootstrap
*mechanism* this change adds. Nothing in it belongs in `pillar-bootstrap`.

## Transport limitation (follow-up)

The CLI's HTTP client is plaintext HTTP/1.1 (std-only, no TLS): point
`--domain` at the node's HTTP listener directly (in-cluster Service or a
port-forward). A public HTTPS ingress terminates TLS in front of that listener;
a TLS-capable client (e.g. rustls) is a follow-up for hitting the public
`https://` URL directly.
