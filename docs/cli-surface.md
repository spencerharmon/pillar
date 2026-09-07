# CLI surface

> Status: reference design (operator, 2026-08-31). This document specifies the
> **complete, coherent surface of the `pillar` CLI**: one small verb vocabulary
> reused everywhere, a URI-like `kind/name` address scheme, and a hard split
> between **views** (read materialized state, sign nothing) and **acts** (emit a
> signed, WoT-authorized event). It is a *planning/reference* document: it does
> not implement any command. Each concrete command is filed as a separate
> `cli-*-impl` task, and this doc gates every one of them (the reviewer judges an
> impl against the classification, addressing, and mapping table defined here).
>
> No public-repo rule is bent: every example uses neutral placeholders
> (`example.com`, `192.0.2.0/24`, `cellA`, `nodeN`) and carries **zero** real
> infrastructure identifiers.

## 1. The two-fold rule: views vs. acts

Every `pillar` command is exactly one of two kinds, and the kind is a
platform-level property — not a per-command convention.

- **A view READS materialized state and SIGNS NOTHING.** It queries the
  local node's materialized views (the state each stateless peer derives from
  the shared event log; see [architecture.md](architecture.md) and
  [consistency-model.md](consistency-model.md)), renders the answer, and
  terminates. It never mints a signature, never appends to the event log, never
  acquires a coordination lease. A view is idempotent and side-effect-free by
  construction; running it twice changes nothing. `get`, `describe`, `explain`,
  `diff`, `logs`, `top`, `events`, `watch`, `whoami`, `status`, `caps`, and
  `audit` are views.
- **An act EMITS a signed, WoT-authorized event.** It constructs the intended
  change, runs it through the **identical non-network safety pipeline every
  plugin rides** (identity/capability authorization against the PGP Web-of-Trust
  authority + capability subkeys, target-node match, view-policy admission,
  coordination-lease exclusivity — see [plugin-surface.md](plugin-surface.md) §
  "Universal contract"), and — only if the decider ALLOWs — signs and appends
  the resulting event to the log. `apply`, `create`, `edit`, `delete`, `patch`,
  `label`, `annotate`, `scale`, `autoscale`, `rollout`, `trust`, `attest`,
  `grant`, `revoke`, `offer`, and every `bootstrap`/`login` mutation are acts.

**Why the split is load-bearing.** The signing key is the only source of
authority in pillar; a command that can sign is a command that can change the
cluster. Making "does this command sign?" a syntactic, up-front property (rather
than an implementation detail) means: (1) a view can be run with a **read-only
token** that holds no signing capability and still works; (2) an act ALWAYS
routes through the decider, so there is no back door that appends unsigned or
unauthorized events; (3) `--dry-run` on any act has one meaning — *run the
decider, emit nothing* — because the emit step is the single, well-known
boundary the flag suppresses.

### Classification of every command family

| Kind | Families |
|------|----------|
| **view** (reads state, signs nothing) | `get` `describe` `explain` `diff` `logs` `top` `events` `watch` `wait` `kinds` `apis` `whoami` `status` `ctx` (show) `caps` `audit` |
| **act** (emits a signed, authorized event) | `apply` `create` `edit` `delete` `patch` `label` `annotate` `scale` `autoscale` `rollout` `exec` `cp` `trust` `attest` `grant` `revoke` `offer` `key` (mint/rotate) `bootstrap` `login` `logout` |
| **local-only** (touches neither the node nor a signature; edits `~/.config/pillar` context) | `use` `ctx` (set/unset) |

`exec`, `cp`, `forward`, `attach` straddle: the *session-open* is an act (it is
authorized and audited like any other authority-bearing operation), while the
byte stream that follows is neither a view nor an emit. They are classified
**act** because the authority decision — "may this identity open a session to
this workload?" — is the security-relevant boundary and it goes through the
decider.

## 2. Addressing: URI-like `kind/name`

Every object is named by a **URI-like address** `kind/name`, reused by every
verb. This is the second unifying rule: `pillar get cell/cellA`,
`pillar describe node/nodeN`, `pillar delete stream/logs-app` all share one
grammar.

```
[<domain>::]<kind>/<name>[@<cell>]
```

- **`kind`** — the resource type, singular, lower-case (`cell`, `node`, `peer`,
  `space`, `lease`, `request`, `stream`, `user`, `key`, `grant`, `identity`,
  `domain`, plus every out-of-tree `ResourceSpec` kind from
  [plugin-surface.md](plugin-surface.md)). `pillar kinds` lists the kinds this
  node currently materializes; `pillar explain <kind>` documents one.
- **`name`** — the object's name within its kind. A bare `name` with no `kind/`
  prefix is only legal where a single kind is unambiguous from context (e.g.
  `pillar get -n cellA node nodeN` after a `kind` positional).
- **`@<cell>` (cell disambiguation)** — most kinds are namespaced by **cell**
  (the pillar analogue of a Kubernetes namespace; see
  [cells-confidentiality.md](cells-confidentiality.md)). The active cell comes
  from context (`pillar use cell/cellA`) or `-n/--cell <cell>`; the `@<cell>`
  suffix pins one object to a specific cell inline, overriding context. Cluster-
  scoped kinds (`node`, `peer`, `domain`, `identity`) take no `@<cell>`.
- **`<domain>:: ` (domain disambiguation)** — a **domain** is a naming root (see
  § "pillar domain"), and the same `kind/name` can exist under different
  domains in a federation. The `<domain>::` prefix selects which domain's view
  to read/act against; it defaults to `PILLAR_DOMAIN` (set by `pillar login`).
  It maps to *which node HTTP listener the client talks to*, not to a
  server-side lookup — see § "Transport".

Selectors and columns compose with addressing, exactly as kubectl:

- **`-l/--selector <sel>`** — filter a list view by label
  (`-l tier=edge,role!=seed`). Labels are the operator labels carried on cell,
  user, node, and every resource (see [bootstrap-cli-login.md](bootstrap-cli-login.md)).
- **`-L/--label-columns <k>[,<k>...]`** — add label values as output columns.

## 3. The one small verb vocabulary

The whole CLI is built from ~30 verbs, each reused across every kind. The
resource plane below is **kubectl-parity**: an operator who knows `kubectl`
knows pillar's resource verbs, with pillar semantics substituted underneath
(sign+append instead of API-server write; materialized view instead of etcd
read).

### 3.1 Session / context family

The entry points that establish *who you are* and *what you are pointed at*.

| Command | Kind | Effect |
|---------|------|--------|
| `pillar login --domain <D> --user <id> [--password P]` | act | Node-side custody login handshake (`GET /nonce` → `POST /login`); **mints a session token** and prints shell exports for `PILLAR_DOMAIN` / `PILLAR_TOKEN`. Use `eval "$(pillar login …)"`. Mint is proven fail-closed in [`specs/LoginToken.tla`](../specs/LoginToken.tla). |
| `pillar webauthn register --user <handle> [--domain D] [--token T]` | act | CLI parity with the browser WebAuthn path: drives `authenticatorMakeCredential` over ctap-hid against a locally attached hardware authenticator, then `POST`s `/webauthn/register/begin`+`/finish` — the SAME RP endpoints and COSE/CBOR credential-record shape a browser's `navigator.credentials.create()` produces. Requires the `passkey` build feature (folded into every deployed node's `hsm` feature set). |
| `pillar webauthn login --credential-id <id> [--domain D] [--token T]` | act | CLI parity with the browser WebAuthn login path: drives `authenticatorGetAssertion` (+ `hmac-secret`) over ctap-hid, then `POST`s `/webauthn/authenticate/begin`+`/finish`, deriving the operational-key-unlock secret via the same real RP verification path. Requires the `passkey` build feature. |
| `pillar logout` | act | Revoke the current session token (best-effort server call) and clear the local context's token. |
| `pillar whoami` | view | Print the authenticated identity (user handle, primary-key CID, cell membership, capability classes) resolved from the current token — signs nothing. |
| `pillar use <kind>/<name>` | local | Set the active cell/domain in `~/.config/pillar/context`. `pillar use cell/cellA`, `pillar use domain/example.com`. |
| `pillar ctx [get\|set\|unset] …` | view/local | Show or edit named contexts (a saved `{domain, token-ref, cell}` triple), like a kubeconfig context. `ctx get` is a view; `set`/`unset` are local. |
| `pillar status` | view | One-screen health of the pointed-at domain: reachable node, session validity/expiry, active cell, materialized-view freshness. Signs nothing. |

`login` is the ONLY command that mints `PILLAR_TOKEN`; every other command
reads it via `TokenStore::from_env` and presents the **token**, never the
long-lived key (see [bootstrap-cli-login.md](bootstrap-cli-login.md) § "Login
token").

### 3.2 Resource plane (kubectl-parity)

Every verb takes a `kind/name` address (or `kind` + `-l` selector for lists),
`-n/--cell`, `-o/--output`, and the standard `--dry-run` where it is an act.

| pillar verb | Kind | pillar semantics |
|-------------|------|------------------|
| `get` | view | List/read materialized objects of a kind. `-o wide\|yaml\|json`, `-l`, `-L`, `-w/--watch`. |
| `describe` | view | Full detail of one object **including provenance**: the **signer** (which subkey authorized the last change) and the **event CID** of the record in the log. This is the pillar-specific enrichment kubectl lacks. |
| `apply -f <file>` | act | Declarative upsert: decode the manifest, run the decider, sign+append the resulting create/patch event(s). Idempotent/convergent by manifest diff. |
| `create <kind>/<name> …` | act | Imperative create of one object; refuses if it already exists. |
| `edit <kind>/<name>` | act | Fetch → open `$EDITOR` → diff → apply the diff as a patch act. |
| `delete <kind>/<name>` | act | Emit a delete/tombstone event. Exclusive/CP-class kinds gate behind a coordination lease. |
| `patch <kind>/<name> -p <patch>` | act | Strategic/JSON-merge patch as a single signed event. |
| `label <kind>/<name> k=v` | act | Add/overwrite/remove (`k-`) operator labels. |
| `annotate <kind>/<name> k=v` | act | Same, for non-selecting annotations. |
| `explain <kind>` | view | Document a kind's schema/fields (from its `ResourceSpec`); signs nothing. |
| `diff -f <file>` | view | Show what `apply` WOULD change against materialized state — never emits. (`--dry-run` on `apply` is the emit-suppressing analogue; `diff` is the read-only presentation.) |
| `rollout {status\|history\|undo\|restart\|pause\|resume} <kind>/<name>` | view/act | `status`/`history` are views; `undo`/`restart`/`pause`/`resume` are acts (each emits a controller event). |
| `scale <kind>/<name> --replicas N` | act | Emit a scale event. |
| `autoscale <kind>/<name> --min --max --target` | act | Install an autoscaler resource (itself a `ResourceSpec`). |
| `wait <kind>/<name> --for <cond>` | view | Block until a materialized condition holds (or timeout); reads only. |
| `watch <kind>` | view | Stream materialized changes for a kind; reads only. |
| `logs <kind>/<name>` | view | Read the workload's `log`-kind observability signals from the event log (see [observability.md](observability.md)); signs nothing. |
| `exec <kind>/<name> -- <cmd>` | act | Open an authorized exec session to a workload; the session-open goes through the decider (audited). |
| `forward <kind>/<name> L:R` | act | Open an authorized port-forward session. |
| `attach <kind>/<name>` | act | Attach to a running workload's stdio (authorized session-open). |
| `cp <src> <kind>/<name>:<dst>` | act | Copy files over an authorized session. |
| `top <kind>` | view | Read `metric`-kind observability signals (cpu/mem) for a kind; signs nothing. |
| `events [<kind>/<name>]` | view | Read the raw event-log records (with signer + CID) for an object or the whole cell; signs nothing. |
| `kinds` | view | List the resource kinds this node materializes (the pillar analogue of `api-resources`). |
| `apis` | view | List the served API groups/versions (the `ResourceSpec` families this node hosts). |

**`--dry-run` contract.** `--dry-run=client` renders locally without contacting
the node; `--dry-run=server` (or bare `--dry-run`) **runs the full decider on
the node and emits NOTHING** — it returns the ALLOW/DENY the act would have got
plus the event that would have been appended, without signing or appending it.
This is the single, uniform "what would this act do, authorized?" probe across
every act verb.

#### kubectl → pillar mapping table

The complete substitution an operator carries over from kubectl:

| kubectl concept | pillar equivalent | Difference |
|-----------------|-------------------|-----------|
| `kubectl get/describe/...` | `pillar get/describe/...` | same verbs, same flags (`-o`, `-l`, `-L`, `-w`, `-n`) |
| API server write | sign + append a WoT-authorized event | authority is the PGP key, not an RBAC role on an API server |
| etcd read | read the local node's **materialized view** | no central store; each peer materializes from the event log |
| namespace (`-n`) | **cell** (`-n/--cell`, `@<cell>`) | cells are confidentiality boundaries, not just naming ([cells-confidentiality.md](cells-confidentiality.md)) |
| `kubeconfig` context | `pillar ctx` / `~/.config/pillar/context` | context holds `{domain, token-ref, cell}` |
| cluster endpoint (`--server`) | `--domain` → a node HTTP listener | see § Transport; no single API endpoint |
| ServiceAccount token | `PILLAR_TOKEN` (session token from `pillar login`) | minted by the key-distribution server, never the long-lived key |
| RBAC `Role`/`RoleBinding` | WoT trust edges + `ExplicitGrant` + capability subkeys | `pillar trust/grant/caps` |
| `api-resources` | `pillar kinds` | lists materialized `ResourceSpec` kinds |
| `explain` | `pillar explain <kind>` | schema from the `ResourceSpec` |
| `--dry-run=server` | `--dry-run` = run decider, emit nothing | the emit boundary is the signature append |
| CRD | out-of-tree `ResourceSpec` plugin | [plugin-surface.md](plugin-surface.md) |
| `kubectl auth can-i` | `pillar caps` (+ `--dry-run` on the act) | reads the decider's grant, or probes an act |
| audit log | `pillar audit` / `pillar events` | the event log itself is the audit trail |

### 3.3 Identity, trust, and authority families

These are the acts that shape *who may do what*. They are the CLI face of
[identity.md](identity.md), the WoT authority (`wot-authority-impl`), and the
`rbac-decider`.

| Command | Kind | Effect |
|---------|------|--------|
| `pillar identity {show\|register\|list}` | view/act | `show`/`list` read the registry; `register` is the out-of-band primary-key enrollment act ([identity.md](identity.md)). |
| `pillar user {list\|show\|add\|remove}` | view/act | Manage cell members. `add` requires the `identity/add-users` right (the one-shot cell capability, then the granted user right — [bootstrap-cli-login.md](bootstrap-cli-login.md)). |
| `pillar key {list\|mint\|rotate\|revoke}` | view/act | Manage the caller's node/operational subkeys with their capability class (`compute\|network\|storage\|all`). Minting/rotation/revocation are acts. |
| `pillar offer <user>` | act | Escrow an operational-key offer for a joining user (the user-approval half of a bootstrap request). |
| `pillar trust <user> [--depth N]` | act | Install a WoT trust edge (a signature) from the caller to `<user>`; `--depth` bounds delegation. |
| `pillar attest <kind>/<name>` | act | Sign an attestation about an object (a WoT statement that is not itself a trust edge). |
| `pillar grant <right> --to <user> [--allow\|--deny]` | act | Emit an `ExplicitGrant` (ALLOW/DENY) of a named right (`identity/add-users`, a capability class, a kind verb) for a user. |
| `pillar caps [<user>]` | view | Show the effective capability set the decider computes for the caller (or `<user>`): trust edges + grants + capability subkeys, with specific > group > all override resolved. Signs nothing — the pillar `auth can-i`. |
| `pillar revoke {trust\|grant\|key} <ref>` | act | Emit the revoking event (a DENY grant, a trust-edge revocation, or a key revocation). Authority-**reducing**, so fail-closed. |
| `pillar audit [<kind>/<name>]` | view | Read the authority-relevant event history (trusts, grants, revocations, admissions) with signer + CID for each; signs nothing. |

The decider is the single authority path: every act above appends an event that
the *same* `rbac-decider` used everywhere then evaluates; the CLI never has a
private authorization path (mirrors [plugin-surface.md](plugin-surface.md)
universal rule 2).

### 3.4 Naming: `pillar domain`

A **domain** is a naming root only — it disambiguates `kind/name` addresses
across a federation and maps a friendly name to the set of node listeners that
serve it. It carries **no** confidentiality or authority (that is the cell's
job). `pillar domain` is naming-only:

| Command | Kind | Effect |
|---------|------|--------|
| `pillar domain list` | view | List known domains and their serving listeners. |
| `pillar domain show <domain>` | view | Resolve a domain to its listeners / default cell. |
| `pillar domain set <domain> --listener <addr>...` | act | Register/update a domain → listener mapping. |

### 3.5 Topology: cell / space / node / peer / lease / request

The substrate objects. These cross-reference the topology docs
([architecture.md](architecture.md), [cells-confidentiality.md](cells-confidentiality.md),
[consistency-model.md](consistency-model.md)).

| Kind | View verbs | Act verbs | Notes |
|------|-----------|-----------|-------|
| `cell` | `get` `describe` `events` | `create` (`bootstrap cell`) `label` `annotate` `delete` | confidentiality + naming boundary; the `-n` namespace |
| `space` | `get` `describe` | `create` `label` `delete` | a sub-partition within a cell |
| `node` | `get` `describe` `top` `events` | `label` `annotate` `delete` (cordon) | cluster-scoped; admitted via the handshake ([identity.md](identity.md)) |
| `peer` | `get` `describe` | — | cluster-scoped; libp2p peer view (read-only; a peer becomes a `node` only via admission) |
| `lease` | `get` `describe` | `delete` (release) | the coordination-lease objects that gate CP-class exclusive effects ([consistency-model.md](consistency-model.md)) |
| `request` | `get`/`list` `describe` | `approve` `reject` | the node/user bootstrap request queue ([bootstrap-cli-login.md](bootstrap-cli-login.md)); `approve` seals the cell key / escrows the offer |

`pillar bootstrap …` (cell/node/user, request approve/reject, login) is the
already-implemented act sub-surface for standing a cell up
([bootstrap-cli-login.md](bootstrap-cli-login.md)); it is the imperative
front-door to `create cell`, node admission, and `request approve`.

### 3.6 Data plane: `pillar stream`

The streaming-DB / event-log surface (`streamdb-impl`,
[`specs/StreamingDB.tla`](../specs/StreamingDB.tla), and
[observability.md](observability.md), which rides it).

| Command | Kind | Effect |
|---------|------|--------|
| `pillar stream list` | view | List materialized streams (a `stream` is a named view over the append-only log). |
| `pillar stream describe <name>` | view | Stream detail: retention/compaction policy, head CID, signer. |
| `pillar stream read <name> [--from CID] [-f/--follow]` | view | Read/tail events from a stream; signs nothing. |
| `pillar stream append <name> -f <file>` | act | Sign + append one event to a stream (the raw act every higher verb composes). |
| `pillar stream create <name> --retention <dur>` | act | Create a stream view with its retention window. |

`logs`, `top`, `events`, and `audit` are all **views over streams** — thin,
pre-named projections of `stream read` for the observability and authority
signal kinds — so the data plane and the resource plane share one substrate.

## 4. Transport

Carried forward from [bootstrap-cli-login.md](bootstrap-cli-login.md) § "Transport
limitation":

- The CLI's HTTP client is **std-only, plaintext HTTP/1.1** (no TLS
  dependency).
- `--domain`/`PILLAR_DOMAIN` points at a **node HTTP listener** directly (an
  in-cluster Service or a port-forward). It is a client-side routing choice, not
  a server-side lookup — the `<domain>::` address prefix selects *which listener
  the client dials*.
- A public **HTTPS ingress terminates TLS in front of** that listener; a
  TLS-capable client (e.g. rustls) that hits the public `https://` URL directly
  is a **follow-up**, not part of this surface.

## 5. Cross-references

- [architecture.md](architecture.md) — layers, the materialized-state model,
  the `ResourceSpec` / `ResourceReconciler` pipeline every act rides.
- [consistency-model.md](consistency-model.md) — the CP/AP per-view split and
  coordination leases that `delete`/`scale`/exclusive acts gate behind.
- [identity.md](identity.md) — the OpenPGP key hierarchy and admission behind
  `identity`/`user`/`key`/`trust`/`node`.
- [plugin-surface.md](plugin-surface.md) — the out-of-tree `ResourceSpec` kinds
  the resource plane addresses uniformly and the universal safety pipeline every
  act obeys.
- [observability.md](observability.md) — the signal event schema behind `logs`,
  `top`, `events`, `stream`.
- [bootstrap-cli-login.md](bootstrap-cli-login.md) — the implemented
  `bootstrap`/`login` acts and the `PILLAR_DOMAIN`/`PILLAR_TOKEN` contract.

## 6. Scope

This document **specifies the surface**; it implements nothing. Each command
family is filed as its own `cli-*-impl` task (e.g. `cli-resource-plane-impl`,
`cli-identity-impl`, `cli-stream-impl`, `cli-session-impl`), and every such task
is gated on this doc — the reviewer measures the implementation against the
views-vs-acts classification (§1), the addressing grammar (§2), the verb
vocabulary and kubectl→pillar mapping (§3), and the transport note (§4).
`check=none`: this is a design/reference document with no machine-observable
effect (justified, matching the `docs-design` / `plugin-surface-catalog`
precedent); the reviewer judges completeness against the ROI command families.
