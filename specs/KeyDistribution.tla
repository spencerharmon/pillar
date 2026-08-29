---------------------------- MODULE KeyDistribution ----------------------------
(***************************************************************************)
(* Pillar key distribution & the offer system (ROI P1, method #1 gate).    *)
(*                                                                         *)
(* Conceptually EXTENDS IdentityLogin.tla (same relationship IdentityLogin *)
(* itself has to Registration.tla/WoTAuthority.tla, per README.md's        *)
(* "Specs -> components" table): a NODE here is IdentityLogin's device     *)
(* subkey, and per identity-login-spec's cell-is-the-genesis-principal      *)
(* model, a node is OWNED by whichever cell its node subkey ultimately      *)
(* chains to (never a user) -- exactly IdentityLogin's                     *)
(* enrolledBy[deviceGrant[d]] chain. This spec treats that ownership as a   *)
(* fixed ground truth (`ForeignNodes`, below) rather than re-deriving the   *)
(* Certify/DelegationGrant/GrantDevice/Revoke dynamics IdentityLogin        *)
(* already proves elsewhere (`LoginRequiresValidChain`, `NoAmbientAuthority`)*)
(* -- matching how `IPAM` re-uses `CoordinationCore`'s theorem by            *)
(* specialising its ground truth rather than re-importing its module.       *)
(*                                                                         *)
(* THE CELL IS THE ABSTRACTION LAYER between users and nodes (operator,    *)
(* 2026-08-26 refinement): users and nodes are never wired directly. A     *)
(* cell owns (a) a USER SELECTOR (`userSel`, the set of users it currently *)
(* admits) and (b) a NODE ALLOW-LIST (`nodeAllow`, the authorized recipient*)
(* set). Key distribution is the cross product of the two.                *)
(*                                                                         *)
(* L0 -- ALWAYS RECIPIENT-(NODE-)SEALED. Every escrowed key artifact placed*)
(* into distribution is sealed to a specific set of recipient NODE keys,   *)
(* never broadcast in the clear and never sealed only to a user identity.  *)
(* `sealedTo[r]` models the current re-seal target for an admitted         *)
(* distribution record `r`; it is recomputed (never merely left stale)     *)
(* the instant a cell's node allow-list changes (`AddNodeToAllowlist` /    *)
(* `RemoveNodeFromAllowlist`), so `SealedMatchesAllowlist` below proves a   *)
(* node dropped from the allow-list can never remain a seal target -- the  *)
(* sealed-to node set IS the participation allow-list.                     *)
(*                                                                         *)
(* L1 -- BI-DIRECTIONAL OFFER/ACCEPT ADMISSION. A user OFFERS an escrowed  *)
(* operational key into a cell; the cell's policy ACCEPTS at offer time    *)
(* (modelled as a single `Accept` action per record, standing in for       *)
(* "each node's policy accepts"); only once BOTH exist may `Admit` fire,   *)
(* recording the event-sourced admitted-login entry. `BiDirectionalConsent`*)
(* proves neither alone ever admits. `RevokeOffer` withdraws the offer and *)
(* immediately clears both the admission and the seal (fail-closed);       *)
(* `FailClosedRevocation` proves an admitted record can never outlive its  *)
(* offer.                                                                  *)
(*                                                                         *)
(* L2 -- TAG-BASED POLICY AUTO-DISTRIBUTION. `userSel`/`nodeAllow` are the *)
(* cell's tag-driven policy surface (an operator external to this model    *)
(* recomputes them as membership/tags change); `AddNodeToAllowlist` /      *)
(* `RemoveNodeFromAllowlist` atomically re-seal every admitted record of   *)
(* that cell to the NEW allow-list in the SAME transition, so distribution *)
(* is always automatic and never a stale snapshot -- `SealedMatchesAllowlist`*)
(* is the single invariant proving both L0 (always sealed) and L2 (auto,   *)
(* current) simultaneously.                                                *)
(*                                                                         *)
(* ESCROW AUTHORITY BOUND. An artifact is a TYPE-LEVEL cold-root or        *)
(* operational key (`RootArtifacts`, fixed); `Offer`, `Admit`, and         *)
(* `EscrowStore` all guard `a \notin RootArtifacts`, so `EscrowTypeBound`   *)
(* and `NoRootEscrow` prove the cold root can NEVER be represented as an   *)
(* escrow artifact or reach admission -- escrow artifacts are only ever    *)
(* operational-key-typed.                                                  *)
(*                                                                         *)
(* ESCROW CONFIDENTIALITY (OPAQUE-SHAPED). Mirrors IdentityLogin's "no      *)
(* private-key variable" technique: the password-derived secret is never a *)
(* server-observable variable at all. `envelope[a]` is the server-held     *)
(* aPAKE envelope; `serverCompromised` models an attacker who has obtained *)
(* it; `clientCoop[a]` is set ONLY by the legitimate client actively        *)
(* supplying its password-derived value (`ClientParticipate`) and is       *)
(* completely independent of `serverCompromised`. `RecoverPlaintext` (the   *)
(* only action that ever sets `decrypted[a]`) requires `clientCoop[a]`      *)
(* regardless of `serverCompromised` -- there is no action anywhere in      *)
(* `Next` that derives `decrypted[a]` from `envelope`/`serverCompromised`   *)
(* alone, so `OpaqueConfidentiality` proves a compromised server-held       *)
(* envelope alone never admits the operational key's plaintext.            *)
(*                                                                         *)
(* CROSS-OWNER OFFER SURFACING. `ForeignNodes` is the fixed set of nodes   *)
(* NOT owned by our single modelled offering user's own cell (per          *)
(* identity-login-spec's ownership chain, held fixed here as noted above). *)
(* `CrossOwner(r)` holds when the target cell's CURRENT allow-list contains*)
(* `Admit` refuses to fire for a cross-owner record  *)
(* unless it has an explicit `ConfirmCrossOwner` confirmation on file        *)
(* (silent vs. explicit-confirmation-gated admission preconditions), and     *)
(* `CrossOwnerGate` additionally proves that gate cannot be bypassed by a    *)
(* LATER allow-list edit: an unconfirmed record's seal target may never      *)
(* include a foreign node, at any point in the behavior, not merely at the   *)
(* instant it was admitted.                                                  *)
(***************************************************************************)
EXTENDS FiniteSets, TLC

CONSTANTS
    Cells,          \* candidate cell identities
    Nodes,          \* candidate node (device-subkey) identities
    Users,          \* candidate user identities who may offer artifacts
    Artifacts,      \* candidate escrow artifact identities
    RootArtifacts,  \* SUBSET Artifacts: the cold-root-typed artifacts (never escrowable);
                     \* Artifacts \ RootArtifacts are the operational-typed ones
    ForeignNodes    \* SUBSET Nodes: nodes NOT owned by our modelled user's own cell
                     \* (ground truth fixed here; IdentityLogin proves how a node comes
                     \* to be owned by the cell its subkey chains to)

ASSUME CellsNonEmpty     == Cells # {}
ASSUME NodesNonEmpty     == Nodes # {}
ASSUME UsersNonEmpty     == Users # {}
ASSUME ArtifactsNonEmpty == Artifacts # {}
ASSUME RootArtifactsType == RootArtifacts \subseteq Artifacts
ASSUME ForeignNodesType  == ForeignNodes \subseteq Nodes

\* Every (user, cell, artifact) triple that could ever be offered/admitted.
AllRecords == [user: Users, cell: Cells, artifact: Artifacts]

VARIABLES
    userSel,        \* [Cells -> SUBSET Users]: each cell's user selector
    nodeAllow,      \* [Cells -> SUBSET Nodes]: each cell's node allow-list
    offered,        \* SUBSET AllRecords: pending user offers
    accepted,       \* SUBSET AllRecords: cell/node-side policy accept, recorded at offer time
    admitted,       \* SUBSET AllRecords: event-sourced admitted-login entries
    crossConfirmed, \* SUBSET AllRecords: explicit cross-owner confirmations on file
    sealedTo,       \* [AllRecords -> SUBSET Nodes]: current re-seal target of an admitted record
    envelope,       \* [Artifacts -> BOOLEAN]: server-held OPAQUE envelope exists for artifact
    serverCompromised, \* BOOLEAN: attacker has obtained every stored envelope
    clientCoop,     \* [Artifacts -> BOOLEAN]: the legitimate client actively supplied its
                     \* password-derived value for this artifact (the ONLY source of recovery)
    decrypted       \* [Artifacts -> BOOLEAN]: ghost -- artifact's operational key plaintext
                     \* actually recovered by anyone

vars == <<userSel, nodeAllow, offered, accepted, admitted, crossConfirmed,
           sealedTo, envelope, serverCompromised, clientCoop, decrypted>>

TypeOK ==
    /\ userSel \in [Cells -> SUBSET Users]
    /\ nodeAllow \in [Cells -> SUBSET Nodes]
    /\ offered \subseteq AllRecords
    /\ accepted \subseteq AllRecords
    /\ admitted \subseteq AllRecords
    /\ crossConfirmed \subseteq AllRecords
    /\ sealedTo \in [AllRecords -> SUBSET Nodes]
    /\ envelope \in [Artifacts -> BOOLEAN]
    /\ serverCompromised \in BOOLEAN
    /\ clientCoop \in [Artifacts -> BOOLEAN]
    /\ decrypted \in [Artifacts -> BOOLEAN]

Init ==
    /\ userSel = [c \in Cells |-> {}]
    /\ nodeAllow = [c \in Cells |-> {}]
    /\ offered = {}
    /\ accepted = {}
    /\ admitted = {}
    /\ crossConfirmed = {}
    /\ sealedTo = [r \in AllRecords |-> {}]
    /\ envelope = [a \in Artifacts |-> FALSE]
    /\ serverCompromised = FALSE
    /\ clientCoop = [a \in Artifacts |-> FALSE]
    /\ decrypted = [a \in Artifacts |-> FALSE]

-----------------------------------------------------------------------------
(* An offer/admission record is CROSS-OWNER iff the target cell's CURRENT   *)
(* node allow-list includes any node not owned by the offering user's own  *)
(* cell (`ForeignNodes`, fixed ground truth -- see module header).         *)
CrossOwner(r) == \E n \in nodeAllow[r.cell] : n \in ForeignNodes

\* The seal target an admitted record `r` is ENTITLED to right now, given a
\* node allow-list `na` (a `[Cells -> SUBSET Nodes]` function -- always
\* either the current `nodeAllow` or a proposed `nodeAllow'`): the cell's
\* full current allow-list once `r` is confirmed (or was never cross-owner
\* to begin with), but with UNCONFIRMED foreign nodes withheld otherwise --
\* L2's auto-distribution is real-time EXCEPT that it may never silently
\* re-seal an already-admitted record to a foreign node the explicit
\* cross-owner gate has not yet cleared (a later allow-list edit can never
\* retroactively bypass `CrossOwnerGate`).
DesiredSeal(r, na) ==
    IF r \in crossConfirmed \/ na[r.cell] \cap ForeignNodes = {}
    THEN na[r.cell]
    ELSE na[r.cell] \ ForeignNodes

-----------------------------------------------------------------------------
(* L2 POLICY SURFACE: cell user selector / node allow-list membership.     *)

AddUserToSelector(c, u) ==
    /\ u \notin userSel[c]
    /\ userSel' = [userSel EXCEPT ![c] = @ \cup {u}]
    /\ UNCHANGED <<nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, serverCompromised, clientCoop, decrypted>>

RemoveUserFromSelector(c, u) ==
    /\ u \in userSel[c]
    /\ userSel' = [userSel EXCEPT ![c] = @ \ {u}]
    /\ UNCHANGED <<nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, serverCompromised, clientCoop, decrypted>>

\* Adding a node to a cell's allow-list re-seals every ALREADY-ADMITTED
\* record of that cell to the new allow-list in the SAME transition -- L0
\* (always sealed) and L2 (auto, never stale) at once.
AddNodeToAllowlist(c, n) ==
    /\ n \notin nodeAllow[c]
    /\ nodeAllow' = [nodeAllow EXCEPT ![c] = @ \cup {n}]
    /\ sealedTo' = [r \in AllRecords |->
                      IF r \in admitted /\ r.cell = c
                      THEN DesiredSeal(r, nodeAllow')
                      ELSE sealedTo[r]]
    /\ UNCHANGED <<userSel, offered, accepted, admitted, crossConfirmed,
                    envelope, serverCompromised, clientCoop, decrypted>>

\* Dropping a node re-seals the same way, so a dropped node is NEVER left as
\* a stale seal target -- the crux of "distribution never reaches a node
\* outside the current allow-list".
RemoveNodeFromAllowlist(c, n) ==
    /\ n \in nodeAllow[c]
    /\ nodeAllow' = [nodeAllow EXCEPT ![c] = @ \ {n}]
    /\ sealedTo' = [r \in AllRecords |->
                      IF r \in admitted /\ r.cell = c
                      THEN DesiredSeal(r, nodeAllow')
                      ELSE sealedTo[r]]
    /\ UNCHANGED <<userSel, offered, accepted, admitted, crossConfirmed,
                    envelope, serverCompromised, clientCoop, decrypted>>

-----------------------------------------------------------------------------
(* L1: BI-DIRECTIONAL OFFER/ACCEPT ADMISSION.                              *)

\* A user offers an escrowed artifact into a cell. Type-bound at the point
\* of offering: a cold-root artifact can never even be offered.
Offer(u, c, a) ==
    /\ u \in userSel[c]
    /\ a \notin RootArtifacts
    /\ LET r == [user |-> u, cell |-> c, artifact |-> a] IN
         /\ r \notin offered
         /\ r \notin admitted
         /\ offered' = offered \cup {r}
    /\ UNCHANGED <<userSel, nodeAllow, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, serverCompromised, clientCoop, decrypted>>

\* The cell/node-side policy accept, recorded at offer time (standing in for
\* "each node's policy accepts").
Accept(u, c, a) ==
    LET r == [user |-> u, cell |-> c, artifact |-> a] IN
      /\ r \in offered
      /\ r \notin accepted
      /\ accepted' = accepted \cup {r}
      /\ UNCHANGED <<userSel, nodeAllow, offered, admitted, crossConfirmed,
                      sealedTo, envelope, serverCompromised, clientCoop, decrypted>>

\* Explicit confirmation required BEFORE a cross-owner offer may be admitted
\* -- and, once granted, immediately unblocks any foreign node the allow-list
\* already authorizes but confirmation had been withholding from the seal.
ConfirmCrossOwner(u, c, a) ==
    LET r == [user |-> u, cell |-> c, artifact |-> a] IN
      /\ r \in offered
      /\ CrossOwner(r)
      /\ r \notin crossConfirmed
      /\ crossConfirmed' = crossConfirmed \cup {r}
      /\ sealedTo' = [sealedTo EXCEPT ![r] =
                        IF r \in admitted THEN nodeAllow[c] ELSE sealedTo[r]]
      /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, admitted,
                      envelope, serverCompromised, clientCoop, decrypted>>

\* Admission fires only once BOTH offer and accept exist (bi-directional
\* consent) and, if cross-owner, only once explicitly confirmed.
Admit(u, c, a) ==
    LET r == [user |-> u, cell |-> c, artifact |-> a] IN
      /\ a \notin RootArtifacts
      /\ r \in offered
      /\ r \in accepted
      /\ r \notin admitted
      /\ (CrossOwner(r) => r \in crossConfirmed)
      /\ admitted' = admitted \cup {r}
      /\ sealedTo' = [sealedTo EXCEPT ![r] = DesiredSeal(r, nodeAllow)]
      /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, crossConfirmed,
                      envelope, serverCompromised, clientCoop, decrypted>>

\* Offer revocation is FAIL-CLOSED: it immediately removes the admitted-login
\* entry (if any) going forward and clears the seal target.
RevokeOffer(u, c, a) ==
    LET r == [user |-> u, cell |-> c, artifact |-> a] IN
      /\ r \in offered
      /\ offered' = offered \ {r}
      /\ admitted' = admitted \ {r}
      /\ sealedTo' = [sealedTo EXCEPT ![r] = {}]
      /\ UNCHANGED <<userSel, nodeAllow, accepted, crossConfirmed,
                      envelope, serverCompromised, clientCoop, decrypted>>

-----------------------------------------------------------------------------
(* ESCROW CONFIDENTIALITY (OPAQUE-SHAPED aPAKE ABSTRACTION).               *)

\* Store the server-held envelope for an operational-typed artifact.
EscrowStore(a) ==
    /\ a \notin RootArtifacts
    /\ ~envelope[a]
    /\ envelope' = [envelope EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, serverCompromised, clientCoop, decrypted>>

\* An attacker obtains every server-held envelope. Modelled as a single
\* irreversible global flip (idempotent) -- the strongest attacker the
\* confidentiality property must still withstand.
CompromiseServer ==
    /\ ~serverCompromised
    /\ serverCompromised' = TRUE
    /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, clientCoop, decrypted>>

\* ONLY the legitimate client, holding the password-derived value that never
\* leaves it, can supply this. Deliberately unguarded by `serverCompromised`
\* in either direction -- the client's ability to cooperate does not depend
\* on whether the server has been compromised.
ClientParticipate(a) ==
    /\ envelope[a]
    /\ ~clientCoop[a]
    /\ clientCoop' = [clientCoop EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, serverCompromised, decrypted>>

\* The ONLY action in Next that ever sets `decrypted` -- and it requires
\* `clientCoop[a]` regardless of `serverCompromised`, so a compromised
\* envelope alone (`envelope[a] /\ serverCompromised /\ ~clientCoop[a]`) can
\* never reach this action's guard.
RecoverPlaintext(a) ==
    /\ envelope[a]
    /\ clientCoop[a]
    /\ ~decrypted[a]
    /\ decrypted' = [decrypted EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<userSel, nodeAllow, offered, accepted, admitted, crossConfirmed,
                    sealedTo, envelope, serverCompromised, clientCoop>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                     *)

Next ==
    \/ \E c \in Cells, u \in Users            : AddUserToSelector(c, u)
    \/ \E c \in Cells, u \in Users            : RemoveUserFromSelector(c, u)
    \/ \E c \in Cells, n \in Nodes             : AddNodeToAllowlist(c, n)
    \/ \E c \in Cells, n \in Nodes             : RemoveNodeFromAllowlist(c, n)
    \/ \E u \in Users, c \in Cells, a \in Artifacts : Offer(u, c, a)
    \/ \E u \in Users, c \in Cells, a \in Artifacts : Accept(u, c, a)
    \/ \E u \in Users, c \in Cells, a \in Artifacts : ConfirmCrossOwner(u, c, a)
    \/ \E u \in Users, c \in Cells, a \in Artifacts : Admit(u, c, a)
    \/ \E u \in Users, c \in Cells, a \in Artifacts : RevokeOffer(u, c, a)
    \/ \E a \in Artifacts                      : EscrowStore(a)
    \/ CompromiseServer
    \/ \E a \in Artifacts                      : ClientParticipate(a)
    \/ \E a \in Artifacts                      : RecoverPlaintext(a)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* L0 (always sealed) + L2 (auto, current, never stale) in one invariant: an
\* admitted record's seal target is ALWAYS exactly what `DesiredSeal` says it
\* is entitled to right now (its cell's current allow-list, MINUS any
\* not-yet-confirmed foreign node); every non-admitted record's seal target
\* is empty. A node dropped from an allow-list can therefore never remain (or
\* become) a seal target, distribution never reaches a node outside the
\* current allow-list, and a later allow-list edit can never silently widen
\* an unconfirmed cross-owner record's seal past what `CrossOwnerGate` allows.
SealedMatchesAllowlist ==
    \A r \in AllRecords :
        IF r \in admitted THEN sealedTo[r] = DesiredSeal(r, nodeAllow)
        ELSE sealedTo[r] = {}

\* L1: admission requires BOTH the user's offer and the cell's accept.
BiDirectionalConsent ==
    \A r \in admitted : r \in offered /\ r \in accepted

\* L1: revoking an offer is fail-closed -- an admitted record can never
\* outlive (or exist without) its offer.
FailClosedRevocation ==
    \A r \in AllRecords : r \notin offered => r \notin admitted

\* Cross-owner offers follow a genuinely different admission precondition:
\* `Admit`'s own guard (`CrossOwner(r) => r \in crossConfirmed`, checked at
\* the moment admission fires) already proves an all-own-cell-nodes offer
\* silently admits while a cross-owner one cannot, structurally, without a
\* prior `ConfirmCrossOwner`. What TLC must additionally prove is that a
\* LATER allow-list edit can never bypass that gate by retroactively turning
\* an already-admitted record cross-owner and distributing to the new
\* foreign node anyway: an unconfirmed record's seal target may never
\* include a foreign node, at any point in the behavior.
CrossOwnerGate ==
    \A r \in admitted :
        r \notin crossConfirmed => sealedTo[r] \cap ForeignNodes = {}

\* Escrow authority bound: no cold-root artifact is ever stored in escrow.
EscrowTypeBound ==
    \A a \in Artifacts : envelope[a] => a \notin RootArtifacts

\* Escrow authority bound: no cold-root artifact ever reaches admission.
NoRootEscrow ==
    \A r \in admitted : r.artifact \notin RootArtifacts

\* OPAQUE-shaped confidentiality: a compromised server-held envelope alone
\* (without the client's password-derived cooperation) never yields the
\* operational key's plaintext.
OpaqueConfidentiality ==
    \A a \in Artifacts : decrypted[a] => clientCoop[a]

=============================================================================
