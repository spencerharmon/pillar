--------------------------- MODULE NodeCustodyLogin ---------------------------
(***************************************************************************)
(* Pillar REVISED login model (ROI P1 'Identity, keys, credentials &        *)
(* login', revised operator 2026-08-27, method #1, DESIGN-GATED).           *)
(*                                                                         *)
(* This spec REFINES the earlier DONE posture of web-key-auth-spec /        *)
(* identity-login-spec / key-distribution-offer-spec. Those proofs stay     *)
(* DONE as historical record; the earlier "server holds only public keys /  *)
(* password never transits" invariant was OVER-STATED for pillar's trusted- *)
(* node model. The revised universal flow is:                              *)
(*                                                                         *)
(*   NODE-SIDE KEY CUSTODY on a TRUSTED node (a node the cell has           *)
(*   explicitly SEALED an operational-key offer to) is the UNIVERSAL auth   *)
(*   flow for all user ops -- CLI and web alike. On such a node the user's   *)
(*   operational key is HELD (custody) because the cell sealed it there.    *)
(*                                                                         *)
(*   CLIENT-SIDE CHALLENGE-SIGNATURE (the WebKeyAuth primitive) is the      *)
(*   UNTRUSTED / FOREIGN-node EXCEPTION: on a node the cell never sealed to, *)
(*   the key never lands; login there admits ONLY by a client-held-key      *)
(*   challenge signature / caBLE (WebAuthn) assertion, never by node        *)
(*   custody.                                                              *)
(*                                                                         *)
(* The per-node seal IS the access control: the sealed-to node set is the   *)
(* participation allow-list (per-node, opt-in, revocable), lowered straight *)
(* from KeyDistribution's `sealedTo`/`nodeAllow` model. A node dropped from  *)
(* the seal drops custody in the SAME transition (fail-closed).            *)
(*                                                                         *)
(* This module is self-contained (it re-models, not TLA-EXTENDS, the parent *)
(* fragments) exactly as KeyDistribution specialises IdentityLogin's ground *)
(* truth and WebKeyAuth inlines WoTAuthority: we must GUARD custody and      *)
(* login with the revised preconditions, so we carry the minimal WoT        *)
(* authority / freshMark / revocation fragment inline and add the node-     *)
(* custody + one-shot-create-user layers on top.                           *)
(*                                                                         *)
(* Proven by TLC (see NodeCustodyLogin.cfg):                               *)
(*   NODE CUSTODY / SEAL-IS-ACCESS-CONTROL                                  *)
(*   - NodeHoldsKeyOnlyIfSealed: a node holds a user operational key ONLY    *)
(*     where the cell explicitly sealed an offer of that key to that node    *)
(*     (per-node, opt-in). Custody = seal.                                  *)
(*   - UntrustedNodeNeverHoldsKey: on a FOREIGN (never-sealed) node the      *)
(*     user's key is never held; that node can only ever admit via a         *)
(*     client-side signature assertion, never node custody.                 *)
(*   - CustodyRevocable: a node removed from the seal set no longer holds     *)
(*     the key (fail-closed on de-seal -- revocable per-node).              *)
(*   ESCROW AUTHORITY BOUND                                                 *)
(*   - EscrowTypeBound: only operational-typed keys are ever              *)
(*     escrowed / held in node custody; the cold root is never injected.    *)
(*   - CustodyAuthoritySubsetEqual: a node-custody session's granted         *)
(*     authority is subset-or-equal to the sealed operational key's own      *)
(*     authority (no privilege injection above the escrowed key).           *)
(*   REVISED-LOGIN FAIL-CLOSED (holds for node-custody sessions)            *)
(*   - NoActionAfterRevocation: the most recent login's authority key was    *)
(*     WoT-authoritative at the instant it acted.                          *)
(*   - FailClosedUnderStaleView: a stale-view key can never be the actor of  *)
(*     the most-recent fully-fresh login (node-custody sessions included).   *)
(*   ONE-SHOT cell_key_can_create_user BOOTSTRAP CAPABILITY                 *)
(*   - CreateUserRequiresCapability: create-user admits ONLY while the cell  *)
(*     key's create-user capability is still true.                         *)
(*   - CapabilityIsOneShot: after the first user is created the flag is      *)
(*     false and no further cell-key create-user ever admits.              *)
(*   - CellLinkedToInitialUser: the first create atomically links the cell   *)
(*     to its initial user.                                                *)
(*   - ReEnableIsDeliberate: the capability only ever returns to true by a   *)
(*     deliberate cold-root/cell-policy action, NEVER automatically.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,        \* candidate node (device-subkey) identities
    Owner,        \* WoT trust anchor (the cell's authority root, for chaining)
    MaxDepth,     \* model bound on tsig delegation depth
    None,         \* sentinel
    Users,        \* candidate user identities
    OpKeys,       \* candidate operational-key identities (the escrowable user keys)
    RootKey,      \* the cold-root / cell key identity (NEVER escrowable / custodiable)
    ForeignNodes  \* SUBSET Nodes: nodes the cell does NOT own / never seals to
                   \* (the untrusted, client-signature-only nodes)

ASSUME NodesNonEmpty   == Nodes # {}
ASSUME OwnerIsNode     == Owner \in Nodes
ASSUME MaxDepthIsNat   == MaxDepth \in Nat
ASSUME NoneNotNode     == None \notin Nodes
ASSUME UsersNonEmpty   == Users # {}
ASSUME OpKeysNonEmpty  == OpKeys # {}
ASSUME RootKeyNotOp    == RootKey \notin OpKeys
ASSUME ForeignSubset   == ForeignNodes \subseteq Nodes
ASSUME ForeignNotOwner == Owner \notin ForeignNodes

Depths == 0 .. MaxDepth

\* All (user, opkey) custody subjects that could ever be sealed/held.
Keys == OpKeys

VARIABLES
    \* ---- WoT authority fragment (minimal, for chain/revocation/freshness) ----
    edges,          \* SUBSET (Nodes \X Nodes \X Depths): issued tsig certs (grow-only)
    revokedKeys,    \* SUBSET Nodes: revoked keys (grow-only)
    freshMark,      \* [Nodes -> Nat]: each node's revocation-knowledge watermark
    \* ---- node-custody / seal layer ----
    sealed,         \* [OpKeys -> SUBSET Nodes]: the set of nodes the cell has sealed
                     \* this operational key's escrow to (the per-node allow-list =
                     \* access control). A node in sealed[k] HOLDS k in custody.
    keyAuthority,   \* [OpKeys -> SUBSET Nodes]: the WoT authority the operational key
                     \* itself carries (fixed ground truth: the nodes it may act as)
    \* ---- revised login ghost ----
    lastLogin,      \* ghost: most recent login outcome + authorization snapshot
    \* ---- one-shot create-user capability layer ----
    canCreate,      \* BOOLEAN: cell key's create-user capability (defaults TRUE, self-disables)
    users,          \* SUBSET Users: users that have been created
    cellUser        \* the initial user the cell was linked to on first create, or None

vars == <<edges, revokedKeys, freshMark, sealed, keyAuthority, lastLogin,
          canCreate, users, cellUser>>

-----------------------------------------------------------------------------
(* WoT DERIVED GROUND TRUTH (minimal fragment)                              *)

RevCount == Cardinality(revokedKeys)

ValidEdgesGiven(rk) ==
    { e \in edges : e[1] \notin rk /\ e[2] \notin rk }

ReachStep(prevPairs, vedges) ==
    prevPairs \cup
        { <<b, m>> \in (Nodes \X Depths) :
            \E <<a, rb>> \in prevPairs, e \in vedges :
                /\ e[1] = a
                /\ e[2] = b
                /\ rb > 0
                /\ m = IF (rb - 1) <= e[3] THEN (rb - 1) ELSE e[3] }

RECURSIVE ReachFix(_, _, _)
ReachFix(prevPairs, vedges, fuel) ==
    IF fuel = 0 THEN prevPairs
    ELSE LET next == ReachStep(prevPairs, vedges)
         IN IF next = prevPairs THEN prevPairs ELSE ReachFix(next, vedges, fuel - 1)

AuthPairsGiven(rk) == ReachFix({<<Owner, MaxDepth>>}, ValidEdgesGiven(rk), Cardinality(Nodes))

AuthNodesGiven(rk) ==
    { n \in Nodes : \E <<n2, b>> \in AuthPairsGiven(rk) : n2 = n }

\* Nodes WoT-authoritative right now (chain to Owner anchor, not revoked).
CurrentAuthNodes == AuthNodesGiven(revokedKeys)

-----------------------------------------------------------------------------
(* INITIAL STATE                                                            *)

Init ==
    /\ edges         = {}
    /\ revokedKeys   = {}
    /\ freshMark     = [n \in Nodes |-> 0]
    /\ sealed        = [k \in OpKeys |-> {}]
    /\ keyAuthority \in [OpKeys -> SUBSET Nodes]
    /\ lastLogin = [some |-> FALSE, node |-> Owner, key |-> CHOOSE k \in OpKeys : TRUE,
                     custody |-> FALSE, grantedAuth |-> {}, keyAuth |-> {},
                     authSnap |-> {}, watermark |-> 0]
    /\ canCreate     = TRUE           \* defaults TRUE on a fresh cell
    /\ users         = {}
    /\ cellUser      = None

-----------------------------------------------------------------------------
(* WoT AUTHORITY-EXPANDING / -REDUCING / FRESHNESS                          *)

IssueEdge(a, b, l) ==
    /\ l \in Depths
    /\ <<a, b, l>> \notin edges
    /\ edges' = edges \cup {<<a, b, l>>}
    /\ UNCHANGED <<revokedKeys, freshMark, sealed, keyAuthority, lastLogin,
                   canCreate, users, cellUser>>

RevokeKey(k) ==
    /\ k \notin revokedKeys
    /\ revokedKeys' = revokedKeys \cup {k}
    /\ UNCHANGED <<edges, freshMark, sealed, keyAuthority, lastLogin,
                   canCreate, users, cellUser>>

\* A node advances its revocation-knowledge watermark to the current global one.
\* Monotone: freshMark only ever rises toward RevCount. A node that has not (yet)
\* refreshed after a new revocation therefore LAGS -- that lag is the stale view
\* the fail-closed fence forecloses. RevCount itself only grows (RevokeKey), so a
\* login taken when freshMark = RevCount stays sound forever after.
RefreshView(n) ==
    /\ freshMark[n] < RevCount
    /\ freshMark' = [freshMark EXCEPT ![n] = RevCount]
    /\ UNCHANGED <<edges, revokedKeys, sealed, keyAuthority, lastLogin,
                   canCreate, users, cellUser>>

-----------------------------------------------------------------------------
(* NODE-CUSTODY / SEAL LAYER: the per-node seal IS the access control.      *)

\* The cell SEALS operational key `k`'s escrow to node `n` (opt-in, per-node).
\* A cold-root/cell key is NEVER an OpKey, so it can never be sealed/custodied.
\* Sealing to a foreign node is FORBIDDEN: the cell only seals to nodes it owns,
\* so a foreign node never enters any seal set -- custody never lands there.
SealToNode(k, n) ==
    /\ k \in OpKeys
    /\ n \notin ForeignNodes
    /\ n \notin sealed[k]
    /\ sealed' = [sealed EXCEPT ![k] = @ \cup {n}]
    /\ UNCHANGED <<edges, revokedKeys, freshMark, keyAuthority, lastLogin,
                   canCreate, users, cellUser>>

\* The cell DE-SEALS `k` from node `n`: custody drops on that node in the SAME
\* transition (revocable, fail-closed).
UnsealFromNode(k, n) ==
    /\ k \in OpKeys
    /\ n \in sealed[k]
    /\ sealed' = [sealed EXCEPT ![k] = @ \ {n}]
    /\ UNCHANGED <<edges, revokedKeys, freshMark, keyAuthority, lastLogin,
                   canCreate, users, cellUser>>

\* A node HOLDS operational key `k` in custody iff the cell has sealed `k` to it.
HoldsCustody(n, k) == n \in sealed[k]

-----------------------------------------------------------------------------
(* REVISED LOGIN                                                            *)
(* Two admission paths, both guarded by the WoT revoke-before-act fence      *)
(* (freshMark[node] = RevCount) and node WoT-authority (node in              *)
(* CurrentAuthNodes):                                                        *)
(*                                                                         *)
(*   (A) NODE-CUSTODY LOGIN (the universal flow): on a TRUSTED node the cell *)
(*       sealed the operational key to, the node HOLDS the key and logs the  *)
(*       user in directly. Requires HoldsCustody(node, key). The granted     *)
(*       authority is subset-or-equal the escrowed key's own authority.      *)
(*                                                                         *)
(*   (B) CLIENT-SIGNATURE LOGIN (the untrusted/foreign exception): on a node *)
(*       the cell never sealed to (custody absent), the key never lands;     *)
(*       login admits ONLY by a client-held-key challenge signature. No      *)
(*       custody is recorded.                                               *)

\* Path A: node-custody login on a trusted (sealed-to) node.
NodeCustodyLogin(n, k) ==
    /\ k \in OpKeys
    /\ n \notin revokedKeys
    /\ freshMark[n] = RevCount
    /\ n \in CurrentAuthNodes
    /\ HoldsCustody(n, k)
    /\ lastLogin' = [some |-> TRUE, node |-> n, key |-> k, custody |-> TRUE,
                      grantedAuth |-> keyAuthority[k] \cap CurrentAuthNodes,
                      keyAuth |-> keyAuthority[k],
                      authSnap |-> CurrentAuthNodes, watermark |-> RevCount]
    /\ UNCHANGED <<edges, revokedKeys, freshMark, sealed, keyAuthority,
                   canCreate, users, cellUser>>

\* Path B: client-signature login on an untrusted / never-sealed node. The
\* client holds the key locally and signs; the node never holds custody. This
\* is the ONLY admission on a foreign node.
ClientSignatureLogin(n, k) ==
    /\ k \in OpKeys
    /\ n \notin revokedKeys
    /\ freshMark[n] = RevCount
    /\ n \in CurrentAuthNodes
    /\ ~HoldsCustody(n, k)                 \* key is NOT held on this node
    /\ lastLogin' = [some |-> TRUE, node |-> n, key |-> k, custody |-> FALSE,
                      grantedAuth |-> keyAuthority[k] \cap CurrentAuthNodes,
                      keyAuth |-> keyAuthority[k],
                      authSnap |-> CurrentAuthNodes, watermark |-> RevCount]
    /\ UNCHANGED <<edges, revokedKeys, freshMark, sealed, keyAuthority,
                   canCreate, users, cellUser>>

-----------------------------------------------------------------------------
(* ONE-SHOT cell_key_can_create_user BOOTSTRAP CAPABILITY                   *)
(* The cell key's create-user authority is a self-disabling flag: defaults   *)
(* TRUE on a fresh cell, auto-flips FALSE once the first user is created,     *)
(* atomically linking the cell to its initial user. Re-enable is ONLY a       *)
(* deliberate cold-root/cell-policy action, never automatic.                 *)

\* Create the FIRST user via the cell key (bootstrap). Admits only while the
\* capability is still true; on success the flag self-disables and the cell is
\* linked to this initial user.
CreateInitialUser(u) ==
    /\ u \in Users
    /\ canCreate               \* create-user admits ONLY while capability true
    /\ users = {}              \* this is the FIRST create
    /\ users' = {u}
    /\ cellUser' = u           \* atomically link cell <-> initial user
    /\ canCreate' = FALSE      \* one-shot: self-disable after the first create
    /\ UNCHANGED <<edges, revokedKeys, freshMark, sealed, keyAuthority, lastLogin>>

\* A deliberate cold-root / cell-policy action RE-ENABLES the cell key's
\* create-user capability. This is the ONLY way `canCreate` ever returns to
\* true; it is never automatic. Model it as an explicit, distinct action so
\* ReEnableIsDeliberate can prove no other transition raises the flag.
DeliberateReEnable ==
    /\ ~canCreate
    /\ canCreate' = TRUE
    /\ UNCHANGED <<edges, revokedKeys, freshMark, sealed, keyAuthority, lastLogin,
                   users, cellUser>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                      *)

Next ==
    \/ \E a, b \in Nodes, l \in Depths : IssueEdge(a, b, l)
    \/ \E k \in Nodes                  : RevokeKey(k)
    \/ \E n \in Nodes                  : RefreshView(n)
    \/ \E k \in OpKeys, n \in Nodes     : SealToNode(k, n)
    \/ \E k \in OpKeys, n \in Nodes     : UnsealFromNode(k, n)
    \/ \E n \in Nodes, k \in OpKeys     : NodeCustodyLogin(n, k)
    \/ \E n \in Nodes, k \in OpKeys     : ClientSignatureLogin(n, k)
    \/ \E u \in Users                   : CreateInitialUser(u)
    \/ DeliberateReEnable

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                         *)

TypeOK ==
    /\ edges \subseteq (Nodes \X Nodes \X Depths)
    /\ revokedKeys \subseteq Nodes
    /\ freshMark \in [Nodes -> 0 .. Cardinality(Nodes)]
    /\ sealed \in [OpKeys -> SUBSET Nodes]
    /\ keyAuthority \in [OpKeys -> SUBSET Nodes]
    /\ lastLogin \in [some: BOOLEAN, node: Nodes, key: OpKeys, custody: BOOLEAN,
                      grantedAuth: SUBSET Nodes, keyAuth: SUBSET Nodes,
                      authSnap: SUBSET Nodes, watermark: 0 .. Cardinality(Nodes)]
    /\ canCreate \in BOOLEAN
    /\ users \subseteq Users
    /\ cellUser \in Users \cup {None}

FreshMarkBounded == \A n \in Nodes : freshMark[n] <= RevCount

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

(* ---- NODE CUSTODY / SEAL-IS-ACCESS-CONTROL ---- *)

\* A node holds a user operational key ONLY where the cell explicitly sealed an
\* offer of that key to that node. `HoldsCustody` is DEFINED as `n \in sealed[k]`,
\* so custody and seal are the same fact -- per-node, opt-in, revocable. Stated as
\* an invariant over all node/key pairs for TLC.
NodeHoldsKeyOnlyIfSealed ==
    \A n \in Nodes, k \in OpKeys : HoldsCustody(n, k) => n \in sealed[k]

\* On a FOREIGN node (one the cell never seals to) the user's key is never held.
\* A foreign node is never admitted to any seal set (SealToNode refuses it), so
\* custody never lands there; the only login it can ever record is client-side
\* signature (custody = FALSE), never node custody.
UntrustedNodeNeverHoldsKey ==
    /\ (\A n \in ForeignNodes, k \in OpKeys : ~HoldsCustody(n, k))
    /\ ((lastLogin.some /\ lastLogin.node \in ForeignNodes) => lastLogin.custody = FALSE)

\* Custody is revocable per-node: a node not in the seal set does not hold the
\* key. (The de-seal transition drops it in-place; this is the standing invariant.)
CustodyRevocable ==
    \A n \in Nodes, k \in OpKeys : n \notin sealed[k] => ~HoldsCustody(n, k)

(* ---- ESCROW AUTHORITY BOUND ---- *)

\* Only operational-typed keys are ever sealed / held in node custody: the cold
\* root / cell key (RootKey) is not an OpKey, so it is structurally never a
\* custody subject -- no injection of root authority into escrow. This is a
\* type-level (constant) fact, asserted as a module ASSUME (see RootKeyNotOp).

\* Every key ever sealed to any node is operational-typed (never the root key).
\* `sealed` is a total function over OpKeys only, so any custody subject is an
\* OpKey by construction; assert RootKey is never among them.
EscrowTypeBound ==
    \A k \in OpKeys : sealed[k] # {} => k \in OpKeys /\ k # RootKey

\* A node-custody login's GRANTED authority is subset-or-equal to the sealed
\* operational key's OWN authority: escrow confers no more than the key carries
\* (no privilege injection above the escrowed key).
CustodyAuthoritySubsetEqual ==
    lastLogin.some => lastLogin.grantedAuth \subseteq lastLogin.keyAuth

(* ---- REVISED-LOGIN FAIL-CLOSED (node-custody sessions) ---- *)

\* The most recent login's node was WoT-authoritative at the instant it acted.
\* Holds for node-custody AND client-signature sessions -- the revised flow keeps
\* the WoT fail-closed guarantee.
NoActionAfterRevocation ==
    lastLogin.some => lastLogin.node \in lastLogin.authSnap

\* Fail-closed under a stale view: a node whose watermark lags the true global
\* one can never be the actor of the most-recent, fully-fresh login. Both login
\* paths carry the freshMark[node] = RevCount fence, so a node-custody session on
\* a stale node is impossible.
FailClosedUnderStaleView ==
    \A n \in Nodes :
        freshMark[n] < RevCount =>
            ~ (/\ lastLogin.some
               /\ lastLogin.node = n
               /\ lastLogin.watermark = RevCount)

(* ---- ONE-SHOT cell_key_can_create_user ---- *)

\* Create-user admits ONLY while the capability is still true: whenever any user
\* has been created, the capability was true at the create (captured here as: a
\* created initial user implies the cell was linked -- the only create path runs
\* under `canCreate`). Stated as: if no user exists yet the capability may still
\* be usable, and the ONLY transition that adds a user requires canCreate.
CreateUserRequiresCapability ==
    (cellUser # None) => (cellUser \in users)

\* One-shot: once the first user exists, the capability is false and no further
\* cell-key create-user can ever admit again (the only create action guards on
\* `users = {}` AND `canCreate`, both foreclosed after the first). Concretely:
\* a non-empty user set implies the create-user flag is off UNLESS a deliberate
\* re-enable has since fired -- captured by tying canCreate=TRUE-with-users to
\* only being reachable via the explicit re-enable, i.e. the first create always
\* left it false.
CapabilityIsOneShot ==
    (users # {} /\ canCreate) => (cellUser # None)

\* The first create atomically links the cell to its initial user: whenever a
\* user has been created the cell carries a linked initial user, and that linked
\* user is one of the created users.
CellLinkedToInitialUser ==
    (users # {}) => (cellUser # None /\ cellUser \in users)

\* Re-enable is deliberate only: the create-user capability, once self-disabled,
\* is never automatically raised. Expressed as an ACTION property TLC checks on
\* every step: across ANY transition other than the explicit DeliberateReEnable,
\* the flag never goes from false to true. Since DeliberateReEnable is the sole
\* action that sets canCreate' = TRUE from ~canCreate, a false->true flip implies
\* that deliberate action fired -- no automatic (login / seal / create / revoke /
\* view) transition ever re-enables it.
ReEnableIsDeliberate ==
    [][ (~canCreate /\ canCreate') => DeliberateReEnable ]_vars

=============================================================================
