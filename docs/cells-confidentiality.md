# Cells & confidentiality (ROI P1)

Design doc for `specs/Cells.tla`. Model-checked by TLC (`cd specs && ./check.sh`).
Backs ROI P1 "Cells & confidentiality". Conceptually EXTENDS `WoTAuthority.tla`
(the revoke-before-act / owner-anchored-authority discipline) and
`KeyDistribution.tla` (the cell/offer/seal system) exactly the way
`IdentityLogin.tla` extends `Registration.tla`/`WoTAuthority.tla` and
`KeyDistribution.tla` conceptually extends `IdentityLogin.tla`: it re-uses their
already-proven ground truth (membership admitted via the offer system; a group
key sealed only to the current node allow-list) by SPECIALISING it, rather than
re-deriving those dynamics. This mirrors how `IPAM` re-uses `CoordinationCore`.

## What the spec models

A single cell is the unit of confidentiality. It owns a **group key** that is
rotated on membership change, a **node allow-list** (the recipient set — reached
via the offer system, so membership is `KeyDistribution`'s admitted-record set
specialised to "this node is a member of this cell"), a set of **cross-cell user
grants** (read-only / read-write, all-or-tags scoped), and an **IPNS-format
naming pointer** (a mutable name resolving to the current published root).

### Visibility classes (the confidentiality lattice)

Every object placed in the cell carries one of three visibility classes, and the
class fixes WHO can decrypt it:

- `Public` — plaintext; decryptable by anyone, member or not. No key.
- `CellEncrypted` — sealed under the cell **group key**; decryptable by exactly
  the current cell members (whoever holds the current group-key epoch). This is
  the ordinary "cell-private" class.
- `RecipientSealed` — sealed to a specific, explicitly named recipient set. The
  recipient GRANULARITY is one of three orthogonal scopes, modeled as the
  identity kind the seal targets:
  - `PerNode` — sealed to individual node keys (the `KeyDistribution` L0 default:
    every artifact sealed to specific recipient node keys).
  - `PerCell` — sealed to a whole peer cell (its group key), i.e. cell-to-cell.
  - `PerUser` — sealed to a user identity (across whatever nodes that user owns).

An object's decryptability is DERIVED from its class + the current world (group
key epoch, allow-list, grants), never stored as a separate mutable fact, so it
cannot drift. `VisibilitySound` is the single invariant proving no principal can
decrypt an object it is not entitled to under its class.

### Membership via the offer system

A node becomes a cell member only through `KeyDistribution`'s admitted-record
path (offer + accept, bi-directional consent, cross-owner-confirmed if foreign).
We hold that as ground truth: `members` grows only via `Admit` and shrinks only
via `Leave` (fail-closed offer revocation). This spec does not re-prove
`BiDirectionalConsent` — it consumes it.

### Group-key rotation & forward secrecy

The group key is an epoch counter `keyEpoch` plus, per epoch, the member set that
epoch was sealed to (`epochMembers`). Rotation rules:

- **On member-LEAVE the key MUST rotate** (`keyEpoch` increments and the new
  epoch is sealed to the reduced member set) BEFORE the leave is observable — so
  the departed member, who holds only the OLD epoch, can never decrypt any object
  authored under the NEW epoch. That is **forward secrecy on member-leave**, the
  invariant `ForwardSecrecyOnLeave`.
- **Atomic against concurrent writers**: a write "under the current epoch" and a
  rotation are the same-transition mutually-exclusive events guarded by a
  `rotating` fence — a write can never straddle a rotation and land partially
  under two epochs. `AtomicRotation` proves every object records exactly the
  single epoch that was current-and-not-rotating when it was authored, and no
  object is ever sealed to an epoch whose member set it was not part of.

### Cross-cell user-access grants

A user in another cell may be granted access into this cell without becoming a
node member: a grant is `<<user, mode, scope>>` where `mode \in {ReadOnly,
ReadWrite}` and `scope` is either `All` (every object) or `Tags(T)` (only objects
tagged within T). `GrantScopeRespected` proves a granted user can read exactly
the objects its scope admits and can write only under a `ReadWrite` grant — never
a `ReadOnly` grant escalating to write, never an out-of-scope object.

### IPNS-format naming pointer

`namePtr` is a mutable name→value pointer (IPNS shape: a single monotonically
re-published pointer resolving to the current root CID). It only ever advances to
a value the cell has actually published (`PublishRoot`), and resolution always
yields a published root — `NamePtrResolves` proves the pointer never dangles.

## Per-node vs per-cell cost/security posture (REQUIRED)

The `RecipientSealed` granularity choice is a real cost/security tradeoff the
implementation must make deliberately, so the spec models all three scopes and
this section spells out the posture:

- **Per-NODE sealing** (`PerNode`): each object is sealed to N individual node
  keys. COST: ciphertext/header size and re-seal work are O(N) in the recipient
  count, and every membership change forces a re-seal of the affected objects
  (this is `KeyDistribution`'s `AddNodeToAllowlist`/`RemoveNodeFromAllowlist`
  re-seal, O(records)). SECURITY: strongest — compromise of one node key exposes
  only that node's decryptions; there is no shared long-lived secret whose leak
  is catastrophic, and revocation is precise (drop the one node from the seal set,
  no rotation of a shared key needed). Use for small, high-sensitivity recipient
  sets and for the escrow/L0 transport path.
- **Per-CELL sealing** (`CellEncrypted` / `PerCell`): objects are sealed once
  under the shared group key. COST: O(1) per object regardless of member count —
  cheap authoring, cheap storage. SECURITY: weaker — the group key is a shared
  secret, so (a) any member can decrypt every cell object, and (b) removing a
  member REQUIRES a group-key rotation + re-seal of live objects to preserve
  forward secrecy (this spec's `ForwardSecrecyOnLeave`), which is the O(objects)
  cost that per-node sealing pays continuously and per-cell sealing pays only at
  membership-shrink time. Use for the common "everything in the cell is readable
  by all current members" case, accepting rotation cost on leave.
- **Per-USER sealing** (`PerUser`): sealed to a user identity spanning that user's
  nodes. COST: between the two — O(users) not O(nodes), amortising a user's many
  devices. SECURITY: revocation is per-user (drop the user), but a compromise of
  ANY of that user's nodes exposes that user's decryptions.

Posture summary: default cell content to **per-cell** (`CellEncrypted`) for
cost, rotating on leave for forward secrecy; escalate specific objects to
**per-node** (`RecipientSealed/PerNode`) when the blast-radius of the shared
group key is unacceptable; use **per-user** grants for cross-cell sharing where
device-set churn would make per-node sealing thrash.

## Proven properties (invariants in `Cells.cfg`)

- `TypeOK`
- `VisibilitySound` — no principal decrypts an object outside its visibility class.
- `ForwardSecrecyOnLeave` — a departed member cannot decrypt any object authored
  after it left (its old epoch was superseded before the leave was observable).
- `AtomicRotation` — every object is sealed to exactly one, current-at-author,
  non-straddling key epoch whose member set it belonged to.
- `GrantScopeRespected` — cross-cell grants confer read only within scope and
  write only when read-write; no escalation, no out-of-scope access.
- `NamePtrResolves` — the IPNS-format pointer always resolves to a published root
  (never dangles).

Safety-only (`-deadlock`): a quiesced cell (stable membership, no pending write
or rotation) is expected idle, not a fault.

## Verification

`cd specs && ./check.sh` runs TLC over `Cells.tla` (added to `check.sh`'s spec
list) with `Cells.cfg`; exit 0 = every invariant holds across all reachable
states of the finite instance (2 nodes, 1 user, 1 peer cell, 1 object, 1 tag,
1 root, `MaxEpoch=2`). The instance is kept small so the reachable state space
stays tractable while still exercising every property: a member join and leave
(forward secrecy), a stand-alone rotation under the write fence (atomicity), all
ReadOnly/ReadWrite x All/Tags grant combinations, every visibility class, and the
IPNS pointer. This is a spec-only task; no Rust code is changed.
The TLC gate is the automated regression check — it fails if any invariant above
is violated by a future edit and passes with the spec as written.
