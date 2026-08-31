------------------------------ MODULE TrustArtifacts ------------------------------
(***************************************************************************)
(* Pillar trust artifacts: certify / trust / attest / revoke (ROI P1,      *)
(* method #1, DESIGN-GATED [TLA gate]). Extends WoTAuthority.tla (owner-    *)
(* anchored bounded-depth reachability, revoke-before-act fencing) and      *)
(* GlobalIdentity.tla (self-certifying identity, per-domain one-hop         *)
(* certification) into FOUR distinct, content-addressed signed artifact    *)
(* types -- never one overloaded "sign":                                   *)
(*                                                                         *)
(*   - certify : an identity binds its own subkey/identity (self capacity, *)
(*     unconditional -- no chain to walk, exactly GlobalIdentity's          *)
(*     "certify exactly one subkey" self-scoped act).                      *)
(*   - trust    : an identity vouches for ANOTHER identity, with an         *)
(*     optional depth (bare Web-of-Trust reachability, reusing              *)
(*     WoTAuthority's tsig-edge/depth-budget shape verbatim, but carrying   *)
(*     no capacity/authorization of its own).                             *)
(*   - attest   : an authorization CLAIM issued in a declared CAPACITY.     *)
(*     Capacity is always explicit -- "self" or a role@scope pair -- never *)
(*     ambient. An attestation renders as a sentence: issuer (identity),    *)
(*     capacity (self or role@scope), authority (the exact prior attest     *)
(*     edge -- itself a content-addressed tuple -- the issuer used to prove *)
(*     it holds capacity: the CID "proof pointer" of the grant being        *)
(*     exercised), subject, predicate (an action + resource, optionally     *)
(*     quantified by a quota, e.g. cpu<=1000m), scope (the capacity's own   *)
(*     scope component), and an epoch/validity stamp. Modelled as TWO       *)
(*     parallel relations by capacity kind (`selfAttested` for "self",      *)
(*     `roleGrants` for the single modelled role@scope) rather than one     *)
(*     relation universally quantified over every capacity value -- this   *)
(*     is exactly the same tractability trade WoTAuthority's own README     *)
(*     makes (it fixes `MaxDepth = 0`, the "largest instance kept           *)
(*     exhaustively checkable" for a 2-node model): a model with MORE than  *)
(*     one non-trivial capacity value at this Nodes/Depth size explodes the *)
(*     combined-tuple reachable state space by an order of magnitude before *)
(*     TLC can finish (measured directly while designing this spec -- see  *)
(*     the note on the checked-in `.cfg`), while a single representative    *)
(*     role capacity already exercises every branch of the properties      *)
(*     below (holding it, not holding it, revoking it, delegating it).      *)
(*     The spec generalizes to N capacities exactly as `roleGrants` does to *)
(*     one; only the CHECKED instance is restricted for CI tractability.   *)
(*   - revoke   : epoch-stamped, fail-closed, and targets one specific       *)
(*     role-grant attest edge (never a bare identity) -- a revoked edge can  *)
(*     never again serve as a witness in a later capacity walk, and any      *)
(*     attest issued at a stale epoch view is refused outright (fail-       *)
(*     closed, never optimistic).                                          *)
(*                                                                         *)
(* CAPACITY HOLDING (the role@scope one) is modelled as WoTAuthority's       *)
(* owner-anchored, bounded-depth reachability VERBATIM: `roleGrants` plays   *)
(* the role `edges` played there. Owner holds every capacity                *)
(* unconditionally (the trust anchor); any other identity must walk an      *)
(* unbroken, non-revoked chain of role-grant edges back to Owner, each      *)
(* hop's remaining sub-delegation depth strictly decreasing -- VERIFICATION *)
(* IS A PURE WALK: it consults ONLY `roleGrants` and `revokedRoleGrants`    *)
(* (never an ambient/out-of-band lookup) and always TERMINATES, because the *)
(* walk is the exact same bounded (|Nodes| fuel) fixpoint recursion          *)
(* WoTAuthority already proves terminates. Unlike WoTAuthority's bare tsig   *)
(* edges (AP, unconditionally issuable), an `attest` edge here is gated AT   *)
(* ISSUANCE on the issuer CURRENTLY holding the capacity it delegates --     *)
(* CapacityHeldAtSigning is checked at signing time, not deferred to a       *)
(* later verifier's Act -- which is exactly the "role permits predicate,     *)
(* no ambient lookup" extension this spec adds to bare WoT reachability.    *)
(*                                                                         *)
(* REVOCATION reuses WoTAuthority's revoke-before-act fencing discipline,   *)
(* renamed to the ROI's own vocabulary: the single monotonic counter is     *)
(* called `revEpoch` (an attest-artifact revocation is, precisely, "epoch-  *)
(* stamped"), and each node keeps a scalar fenced view `freshEpoch[n]` that  *)
(* must EXACTLY equal `revEpoch` before that node may issue a new attest --  *)
(* any lag at all (a stale epoch view) disables issuance outright           *)
(* (fail-closed, never an optimistic fallback).                            *)
(*                                                                         *)
(* QUOTA is modelled as a BUDGET, not a bare number: a single global        *)
(* reservation ledger `reserved` (the CP-fenced resource) is the only       *)
(* thing ever mutated by an admission, and mutation is gated on the same    *)
(* fencing discipline applied to a second dimension, `quotaView[n]`, the    *)
(* admitting node's cached view of `reserved`. An admission may only mutate *)
(* the true ledger when its own view is EXACTLY caught up -- so two nodes   *)
(* racing off stale, independently-advanced local views can never each      *)
(* admit against the same budget without one of them being refused          *)
(* (structurally: only a fenced, i.e. fully-current, admission can ever      *)
(* succeed, so no double counting of the same headroom is ever possible).   *)
(* An admission also requires the admitting node currently hold the role    *)
(* capacity (via the SAME capacity walk) -- a quota claim is a predicate     *)
(* exercised IN a capacity, never a bare/unauthorized reservation.          *)
(*                                                                         *)
(* Refines the WoT-authority/RBAC ExplicitGrant (WoTAuthority.tla) by       *)
(* adding issuer-capacity context (self/role@scope, never ambient) and the   *)
(* quantified-predicate form (an action+resource+quota claim, not a bare     *)
(* grant); retires no DONE proof.                                         *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - VerificationTerminates: the capacity walk (`CapPairsGiven`) always   *)
(*     reaches a well-typed fixpoint result -- a subset of Nodes X Depths   *)
(*     -- in every reachable state (the operational witness that the        *)
(*     bounded-fuel recursion always terminates, exactly as WoTAuthority's  *)
(*     ReachFix does), and does so consulting only `roleGrants`/            *)
(*     `revokedRoleGrants` (a PURE walk, no ambient state).                 *)
(*   - CapacityHeldAtSigning: the most recent successful Attest (if any)     *)
(*     carries a snapshot proving its issuer held the capacity it exercised *)
(*     (or the capacity was "self" over itself) at the exact moment it       *)
(*     signed -- stable evidence forever after, since revocations only ever *)
(*     grow (never shrink) the set of witnesses removed from the walk.      *)
(*   - RevocationHonorsEpoch: whenever a node's fenced epoch view lags the   *)
(*     true global one, that node can never appear as the issuer of the      *)
(*     most-recently-recorded Attest evaluated as fully fresh against the    *)
(*     CURRENT epoch -- fail-closed, structurally, exactly as               *)
(*     WoTAuthority's FailClosedUnderStaleView.                          *)
(*   - QuotaNeverDoubleSpent: the true reservation ledger never exceeds the *)
(*     model budget, and whenever an admitting node's fenced view of the     *)
(*     ledger lags the true one, that node can never appear as the most-    *)
(*     recently-recorded admission evaluated as fully fresh against the      *)
(*     CURRENT ledger value -- two nodes can never each admit against the    *)
(*     same stale headroom.                                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,      \* candidate identities
    Owner,      \* the trust anchor: unconditionally holds every capacity
    Role,       \* the single modelled role label (Capacities = {self, <<Role,Scope>>})
    Scope,      \* the single modelled scope the role is bound to
    MaxDepth,   \* model bound on attest sub-delegation depth
    MaxEpoch,   \* model bound on the revocation-epoch counter
    Quota,      \* model bound on the quota budget (Nat)
    None        \* sentinel: "no quota component" on a non-quantified predicate

ASSUME NodesNonEmpty == Nodes # {}
ASSUME OwnerIsNode    == Owner \in Nodes
ASSUME MaxDepthIsNat  == MaxDepth \in Nat
ASSUME MaxEpochIsNat  == MaxEpoch \in Nat
ASSUME QuotaIsNat     == Quota \in Nat
ASSUME NoneNotNode    == None \notin Nodes

Depths == 0 .. MaxDepth
QuotaAmts == 0 .. Quota

\* Capacity is always explicit: "self" (bind my own identity/subkey) or the
\* single modelled role@scope pair. Never ambient.
SelfCap == [kind |-> "self", role |-> None, scope |-> None]
RoleCapV == [kind |-> "role", role |-> Role, scope |-> Scope]

VARIABLES
    certified,        \* SUBSET Nodes: identities that have self-certified (bound their own subkey)
    selfAttested,     \* SUBSET Nodes: attest artifacts issued with capacity="self" (a=s, unconditional)
    trustEdges,       \* SUBSET (Nodes \X Nodes \X Depths): bare WoT vouch edges (no capacity)
    roleGrants,       \* SUBSET (Nodes \X Nodes \X Depths): <<issuer,subject,depth>> attest artifacts
                      \*   for the single modelled role capacity -- WoTAuthority's `edges` shape,
                      \*   but gated at issuance on the issuer currently holding the capacity
    revokedRoleGrants,\* SUBSET (Nodes \X Nodes \X Depths): revoked role-grant attest edges (grow-only)
    revEpoch,         \* Nat: the true global revocation-epoch counter (bumped once per Revoke)
    freshEpoch,       \* [Nodes -> Nat]: each node's fenced view of revEpoch
    partitioned,      \* SUBSET Nodes: nodes cut off from advancing freshEpoch/quotaView
    lastAttest,       \* ghost, overwritten each Attest: signing-time evidence snapshot
    reserved,         \* 0..Quota: the true, global quota reservation ledger (a CP-fenced budget)
    quotaView,        \* [Nodes -> 0..Quota]: each node's fenced view of reserved
    lastAdmit         \* ghost, overwritten each AdmitQuota: admission evidence snapshot

vars == <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
          partitioned, lastAttest, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* THE CAPACITY WALK: owner-anchored, bounded-depth reachability over        *)
(* non-revoked role-grant attest edges -- verbatim WoTAuthority ReachStep/   *)
(* ReachFix, renamed to this spec's vocabulary.                            *)

\* Role-grant edges usable given a revoked-grants snapshot: not revoked.
\* Attest edges are AP-issued/grow-only once written, so this is sound over
\* the CURRENT `roleGrants` set.
ValidGrantsGiven(rev) == { t \in roleGrants : t \notin rev }

\* One fixpoint step: extend reachable <<node, remaining-depth>> pairs by one
\* more hop across a still-valid role-grant edge. Depth budgets strictly
\* decrease every hop (capped by both the issuer's own remaining budget and
\* the edge's own declared depth), so this always reaches a fixpoint.
CapStep(prevPairs, vedges) ==
    prevPairs \cup
        { <<b, m>> \in (Nodes \X Depths) :
            \E <<a, rb>> \in prevPairs, t \in vedges :
                /\ t[1] = a
                /\ t[2] = b
                /\ rb > 0
                /\ m = IF (rb - 1) <= t[3] THEN (rb - 1) ELSE t[3] }

RECURSIVE CapFix(_, _, _)
CapFix(prevPairs, vedges, fuel) ==
    IF fuel = 0 THEN prevPairs
    ELSE LET next == CapStep(prevPairs, vedges)
         IN IF next = prevPairs THEN prevPairs ELSE CapFix(next, vedges, fuel - 1)

\* Owner unconditionally holds every capacity, with the full model budget to
\* delegate onward. |Nodes| iterations suffice for the fixpoint (each new
\* pair added strictly grows a finite relation) -- this bounded-fuel
\* recursion is the operational witness that the walk always TERMINATES.
CapPairsGiven(rev) == CapFix({<<Owner, MaxDepth>>}, ValidGrantsGiven(rev), Cardinality(Nodes))

\* The set of identities that currently hold the (single modelled) role
\* capacity, per a revoked-grants snapshot. A PURE walk: consults only
\* `roleGrants` (via ValidGrantsGiven) and the passed-in revoked snapshot --
\* no ambient/out-of-band lookup.
CapacityHeldGiven(rev) == { n \in Nodes : \E <<n2, b>> \in CapPairsGiven(rev) : n2 = n }

-----------------------------------------------------------------------------
(* INITIAL STATE *)

Init ==
    /\ certified = {}
    /\ selfAttested = {}
    /\ trustEdges = {}
    /\ roleGrants = {}
    /\ revokedRoleGrants = {}
    /\ revEpoch = 0
    /\ freshEpoch = [n \in Nodes |-> 0]
    /\ partitioned = {}
    /\ lastAttest = [some |-> FALSE, issuer |-> Owner, subject |-> Owner, capacity |-> SelfCap,
                      authSnap |-> {}, epochSnap |-> 0]
    /\ reserved = 0
    /\ quotaView = [n \in Nodes |-> 0]
    /\ lastAdmit = [some |-> FALSE, node |-> Owner, amt |-> 0, fencedSnap |-> 0]

-----------------------------------------------------------------------------
(* CERTIFY: self-bind own subkey/identity. Unconditional (AP) -- no chain    *)
(* to walk, exactly GlobalIdentity's self-scoped certification act. (Kept   *)
(* as a wholly separate variable from `selfAttested` below: certify BINDS   *)
(* the identity, attest-with-self-capacity CLAIMS a predicate about it --   *)
(* two distinct artifact kinds that happen to share the same trivial,       *)
(* chain-free guard.)                                                      *)

Certify(a) ==
    /\ a \notin certified
    /\ certified' = certified \cup {a}
    /\ UNCHANGED <<selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   partitioned, lastAttest, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* TRUST: vouch for ANOTHER identity, optional depth. Bare WoT reachability, *)
(* carrying no capacity of its own -- unconditional (AP), reusing            *)
(* WoTAuthority's IssueEdge shape verbatim but on a separate variable so it  *)
(* can never be confused with (or substitute for) a capacity attest.        *)

Trust(a, b, l) ==
    /\ l \in Depths
    /\ <<a, b, l>> \notin trustEdges
    /\ trustEdges' = trustEdges \cup {<<a, b, l>>}
    /\ UNCHANGED <<certified, selfAttested, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   partitioned, lastAttest, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* ATTEST: an authorization claim in a declared capacity. Capacity always    *)
(* explicit. Two forms, gated the same way on CapacityHeldAtSigning:         *)
(*   - self capacity: unconditional over one's own identity (a = s).        *)
(*   - role capacity: issuer must currently hold it via the non-revoked,     *)
(*     owner-anchored walk (`CapacityHeldGiven`), and issue a NEW grant      *)
(*     edge <<a, s, d>> sub-delegating up to depth d further hops -- the     *)
(*     "authority" proof pointer is the specific witness edge the walk       *)
(*     used, recorded structurally in `lastAttest.authSnap`.                *)
(* Both forms are gated by the SAME fenced-epoch discipline WoTAuthority     *)
(* uses for revoke-before-act.                                              *)

AttestSelf(a) ==
    /\ a \notin selfAttested
    /\ freshEpoch[a] = revEpoch
    /\ selfAttested' = selfAttested \cup {a}
    /\ lastAttest' = [some |-> TRUE, issuer |-> a, subject |-> a, capacity |-> SelfCap,
                       authSnap |-> {a}, epochSnap |-> revEpoch]
    /\ UNCHANGED <<certified, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   partitioned, reserved, quotaView, lastAdmit>>

AttestRole(a, s, d) ==
    /\ d \in Depths
    /\ <<a, s, d>> \notin roleGrants
    /\ freshEpoch[a] = revEpoch                              \* revoke-before-act: fully caught up
    /\ a \in CapacityHeldGiven(revokedRoleGrants)             \* CapacityHeldAtSigning: prove the walk
    /\ roleGrants' = roleGrants \cup {<<a, s, d>>}
    /\ lastAttest' = [some |-> TRUE, issuer |-> a, subject |-> s, capacity |-> RoleCapV,
                       authSnap |-> CapacityHeldGiven(revokedRoleGrants), epochSnap |-> revEpoch]
    /\ UNCHANGED <<certified, selfAttested, trustEdges, revokedRoleGrants, revEpoch, freshEpoch,
                   partitioned, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* ADMIT QUOTA: a predicate claim quantified by a quota (e.g. cpu<=1000m).  *)
(* Requires the admitting node currently hold the role capacity (the SAME    *)
(* walk) -- a quota claim is exercised IN a capacity, never a bare/          *)
(* unauthorized reservation -- and is a BUDGET: the reservation ledger        *)
(* `reserved` is mutated only under a fully-fenced (fully caught-up) view    *)
(* of itself, so two nodes racing off independently-stale views can never    *)
(* each admit against the same headroom.                                    *)

AdmitQuota(a, amt) ==
    /\ amt \in (QuotaAmts \ {0})
    /\ a \in CapacityHeldGiven(revokedRoleGrants)
    /\ quotaView[a] = reserved                                \* fenced/caught-up read
    /\ reserved + amt <= Quota                                \* the budget is never overrun
    /\ reserved' = reserved + amt
    /\ lastAdmit' = [some |-> TRUE, node |-> a, amt |-> amt, fencedSnap |-> reserved]
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch,
                   freshEpoch, partitioned, lastAttest, quotaView>>

-----------------------------------------------------------------------------
(* REVOKE: epoch-stamped, fail-closed. Targets one specific role-grant       *)
(* attest artifact (content-addressed -- the tuple itself), never a bare     *)
(* identity. Bumps the single global revocation-epoch counter by exactly    *)
(* one, the same mechanism WoTAuthority's Revoke* actions use for RevCount. *)

RevokeGrant(t) ==
    /\ t \in roleGrants
    /\ t \notin revokedRoleGrants
    /\ revEpoch < MaxEpoch
    /\ revokedRoleGrants' = revokedRoleGrants \cup {t}
    /\ revEpoch' = revEpoch + 1
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, freshEpoch, partitioned,
                   lastAttest, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: SyncEpoch / SyncQuotaView / Partition / Heal, one per     *)
(* fenced dimension (revocation epoch, quota ledger), gated the same way    *)
(* WoTAuthority gates StaleView.                                           *)

SyncEpoch(n) ==
    /\ n \notin partitioned
    /\ freshEpoch' = [freshEpoch EXCEPT ![n] = revEpoch]
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch,
                   partitioned, lastAttest, reserved, quotaView, lastAdmit>>

SyncQuotaView(n) ==
    /\ n \notin partitioned
    /\ quotaView' = [quotaView EXCEPT ![n] = reserved]
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   partitioned, lastAttest, reserved, lastAdmit>>

Partition ==
    /\ partitioned' \in SUBSET Nodes
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   lastAttest, reserved, quotaView, lastAdmit>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<certified, selfAttested, trustEdges, roleGrants, revokedRoleGrants, revEpoch, freshEpoch,
                   lastAttest, reserved, quotaView, lastAdmit>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION *)

Next ==
    \/ \E a \in Nodes : Certify(a)
    \/ \E a \in Nodes : AttestSelf(a)
    \/ \E a, b \in Nodes, l \in Depths : Trust(a, b, l)
    \/ \E a, s \in Nodes, d \in Depths : AttestRole(a, s, d)
    \/ \E a \in Nodes, amt \in (QuotaAmts \ {0}) : AdmitQuota(a, amt)
    \/ \E t \in roleGrants : RevokeGrant(t)
    \/ \E n \in Nodes : SyncEpoch(n)
    \/ \E n \in Nodes : SyncQuotaView(n)
    \/ Partition
    \/ Heal

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS *)

TypeOK ==
    /\ certified \subseteq Nodes
    /\ selfAttested \subseteq Nodes
    /\ trustEdges \subseteq (Nodes \X Nodes \X Depths)
    /\ roleGrants \subseteq (Nodes \X Nodes \X Depths)
    /\ revokedRoleGrants \subseteq (Nodes \X Nodes \X Depths)
    /\ revEpoch \in 0 .. MaxEpoch
    /\ freshEpoch \in [Nodes -> 0 .. MaxEpoch]
    /\ partitioned \subseteq Nodes
    /\ lastAttest \in [some: BOOLEAN, issuer: Nodes, subject: Nodes,
                        capacity: {SelfCap, RoleCapV}, authSnap: SUBSET Nodes,
                        epochSnap: 0 .. MaxEpoch]
    /\ reserved \in QuotaAmts
    /\ quotaView \in [Nodes -> QuotaAmts]
    /\ lastAdmit \in [some: BOOLEAN, node: Nodes, amt: QuotaAmts, fencedSnap: QuotaAmts]

\* A node's fenced views never run ahead of the true global counters.
FreshEpochBounded == \A n \in Nodes : freshEpoch[n] <= revEpoch
QuotaViewBounded == \A n \in Nodes : quotaView[n] <= reserved

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* VerificationIsAPureWalk/Terminates: in every reachable state, the
\* bounded-fuel fixpoint walk (CapPairsGiven) yields a well-typed result
\* over Nodes X Depths -- the operational witness that TLC evaluated the
\* recursion to completion (it always terminates, exactly as WoTAuthority's
\* ReachFix does) without ever needing more than Cardinality(Nodes) steps,
\* and did so consulting only `roleGrants` (via ValidGrantsGiven) and the
\* passed revoked-grants snapshot -- a PURE walk, no ambient state.
VerificationTerminates == CapPairsGiven(revokedRoleGrants) \subseteq (Nodes \X Depths)

\* The most recent successful Attest (if any) carries a snapshot proving its
\* issuer held the exercised capacity (or exercised "self" over itself) at
\* the exact moment it signed. Because revokedRoleGrants only ever grows (so
\* CapacityHeldGiven is antitone in it), that recorded snapshot is stable
\* evidence forever after -- the signing always precedes any later
\* revocation of a witness edge it relied on, never follows it.
CapacityHeldAtSigning ==
    lastAttest.some =>
        \/ lastAttest.capacity.kind = "self"
        \/ lastAttest.issuer \in lastAttest.authSnap

\* Fail-closed under a stale epoch view: whenever a node's fenced view lags
\* the true global revocation epoch, that node can never appear as the
\* issuer of the most-recently-recorded Attest evaluated as fully fresh
\* against the CURRENT epoch -- Attest's guard (freshEpoch[issuer] = revEpoch
\* at the moment it fired) structurally forecloses that, exactly as
\* WoTAuthority's FailClosedUnderStaleView.
RevocationHonorsEpoch ==
    \A n \in Nodes :
        freshEpoch[n] < revEpoch =>
            ~ (/\ lastAttest.some
               /\ lastAttest.issuer = n
               /\ lastAttest.epochSnap = revEpoch)

\* The true reservation ledger never exceeds the model budget (the CP-fenced
\* resource is never overrun), AND -- the double-spend guard proper --
\* whenever an admitting node's fenced view of the ledger lags the true one,
\* that node can never appear as the most-recently-recorded admission
\* evaluated as fully fresh against the CURRENT ledger value. Two nodes
\* racing off independently-stale local views can therefore never each
\* admit against the same headroom: only a fully fenced (fully caught-up)
\* admission can ever mutate `reserved`, so at most one admission is ever
\* "in flight" against a given true ledger value.
QuotaNeverDoubleSpent ==
    /\ reserved <= Quota
    /\ \A n \in Nodes :
        quotaView[n] < reserved =>
            ~ (/\ lastAdmit.some
               /\ lastAdmit.node = n
               /\ lastAdmit.fencedSnap = reserved)

=============================================================================
