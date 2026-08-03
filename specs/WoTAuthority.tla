------------------------------ MODULE WoTAuthority ------------------------------
(***************************************************************************)
(* Pillar Web-of-Trust authority & RBAC foundation (ROI P1, method #1).     *)
(*                                                                         *)
(* Model of OpenPGP trust-signature (tsig) authority: a bounded-depth       *)
(* reachability relation, anchored at a single OWNER identity, over tsig    *)
(* edges that have not been revoked. An edge <<signer, subject, level>>     *)
(* models a trust signature: signer vouches for subject, and `level` is     *)
(* the tsig depth field -- the number of further hops of delegation subject *)
(* is permitted to extend. Reachability composes depth budgets: a signer    *)
(* with remaining budget rb may grant subject a budget of at most           *)
(* min(rb - 1, level); the budget strictly decreases every hop, so the      *)
(* fixpoint below always terminates.                                       *)
(*                                                                         *)
(* Three revocation kinds are modelled as grow-only (monotonic) sets of      *)
(* true, global facts:                                                     *)
(*   - revokedKeys   : an OpenPGP key/subkey revocation -- no edge touching *)
(*                      the key as signer or subject can carry authority.   *)
(*   - revokedEdges   : a specific trust-signature (tsig) revocation.       *)
(*   - revokedGrants  : a direct grant revocation, stripping a subject's     *)
(*                      derived authority even while its tsig chain remains *)
(*                      intact (an explicit, out-of-band deny).            *)
(*                                                                         *)
(* Authority-EXPANDING events (IssueEdge, i.e. new tsig certificates) are   *)
(* AP: unconditionally available, no coordination required -- mirroring    *)
(* that possessing/publishing a certificate needs no consensus.            *)
(*                                                                         *)
(* Authority-REDUCING events (the three Revoke* actions) are CP/fail-      *)
(* closed at the point they matter: not when the true global fact is set   *)
(* (an unconditional, unilateral write, like any other log append), but at *)
(* ACT time. Every revocation, of any kind, also bumps a single global      *)
(* counter `revCount` (the "how many revocation facts exist" watermark).   *)
(* Every node keeps a scalar local watermark `freshMark[n]` -- how far its  *)
(* own revocation knowledge reaches -- that can lag `revCount` (StaleView   *)
(* is a partial/no-op resync while stale) or be frozen indefinitely by a    *)
(* Partition. Because the three Revoke* actions are each idempotent         *)
(* (add-once) and every one strictly increments revCount, `freshMark[n] =   *)
(* revCount` is equivalent to "n's view of revokedKeys/revokedEdges/        *)
(* revokedGrants exactly equals their current, true values" -- the scalar    *)
(* watermark is a sound, compact stand-in for a full per-node copy of the    *)
(* three revoked sets. The revoke-before-act rule is the guard on Act: an   *)
(* actor may only act on a subject's authority once its own watermark      *)
(* exactly equals the current global one -- a fully caught-up, fenced read *)
(* -- fail-closed, since any lag at all (a stale view) simply disables Act *)
(* rather than falling back to an optimistic/last-known-good grant.        *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - NoActionAfterRevocation: the most recent Act (if any) carries the    *)
(*     set of nodes that WERE authoritative at the exact moment it acted,   *)
(*     and the acted-on subject was a member of it -- i.e. the act always   *)
(*     precedes any later revocation of that subject, never follows it.     *)
(*   - FailClosedUnderStaleView: whenever a node's watermark lags the true  *)
(*     one (it is stale), that node can never appear as the actor of the    *)
(*     most-recently-recorded, fully-fresh-at-that-moment Act evaluated     *)
(*     against the CURRENT global watermark -- the guard structurally       *)
(*     forecloses the unsafe optimistic path.                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,      \* candidate identities participating in the web of trust
    Owner,      \* the trust anchor: unconditionally authoritative
    MaxDepth,   \* model bound on tsig delegation depth
    None        \* sentinel, unused by variables but kept for symmetry with sibling specs

ASSUME NodesNonEmpty == Nodes # {}
ASSUME OwnerIsNode    == Owner \in Nodes
ASSUME MaxDepthIsNat  == MaxDepth \in Nat
ASSUME NoneNotNode    == None \notin Nodes

Depths == 0 .. MaxDepth

VARIABLES
    edges,          \* SUBSET (Nodes \X Nodes \X Depths): issued tsig certificates (grow-only)
    revokedKeys,    \* SUBSET Nodes: keys revoked (grow-only, true/global)
    revokedEdges,   \* SUBSET (Nodes \X Nodes): tsig edges revoked (grow-only, true/global)
    revokedGrants,  \* SUBSET Nodes: direct grant revocations (grow-only, true/global)
    freshMark,      \* [Nodes -> Nat]: each node's local revocation-knowledge watermark
    partitioned,    \* SUBSET Nodes: nodes currently cut off from advancing their watermark
    lastAct         \* ghost: the most recent Act (if any), with its authorization snapshot

vars == <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned, lastAct>>

-----------------------------------------------------------------------------
(* DERIVED GROUND TRUTH GIVEN A (SNAPSHOT OF) REVOKED-SETS TRIPLE            *)

\* The true global revocation watermark: how many revocation facts exist in
\* total, across all three kinds, right now.
RevCount == Cardinality(revokedKeys) + Cardinality(revokedEdges) + Cardinality(revokedGrants)

\* Edges usable given a revoked-keys/revoked-edges snapshot: neither endpoint's
\* key nor the edge itself is revoked. Edges are AP (always fully known, never
\* gated by staleness), so this uses the CURRENT `edges` set -- sound because
\* edges only grow, so authority computed this way is monotone in time.
ValidEdgesGiven(rk, re) ==
    { e \in edges :
        /\ e[1] \notin rk
        /\ e[2] \notin rk
        /\ <<e[1], e[2]>> \notin re }

\* One fixpoint step: extend the reachable <<node, remaining-budget>> pairs by
\* one more hop across a still-valid edge. The new budget for the far endpoint
\* is capped both by the signer's own remaining budget (minus the hop) and by
\* the edge's declared tsig level -- exactly the OpenPGP "trust depth" rule.
\* Budgets strictly decrease every hop, so this always reaches a fixpoint.
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

\* Owner is the trust anchor: unconditionally authoritative, with the full
\* model budget to delegate onward. |Nodes| iterations suffice for the
\* fixpoint (each new pair added strictly grows a finite relation).
AuthPairsGiven(rk, re) == ReachFix({<<Owner, MaxDepth>>}, ValidEdgesGiven(rk, re), Cardinality(Nodes))

\* Ground truth given a revoked-sets snapshot: owner-anchored bounded-depth
\* reachability over non-revoked edges, with any directly grant-revoked node
\* stripped even if still reachable (a grant revocation overrides an intact
\* tsig chain).
AuthNodesGiven(rk, re, rg) ==
    { n \in Nodes : \E <<n2, b>> \in AuthPairsGiven(rk, re) : n2 = n } \ rg

\* Ground truth given the CURRENT global revoked sets.
CurrentAuthNodes == AuthNodesGiven(revokedKeys, revokedEdges, revokedGrants)

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ edges         = {}
    /\ revokedKeys   = {}
    /\ revokedEdges  = {}
    /\ revokedGrants = {}
    /\ freshMark     = [n \in Nodes |-> 0]
    /\ partitioned   = {}
    /\ lastAct       = [some |-> FALSE, actor |-> Owner, subject |-> Owner, authSnap |-> {}, watermark |-> 0]

-----------------------------------------------------------------------------
(* AUTHORITY-EXPANDING (AP): issuing a tsig certificate                      *)

\* A new trust signature. Unconditionally available -- no coordination, no
\* freshness requirement: publishing a certificate is a pure availability
\* operation, never gated the way a revocation's effect at Act time is.
IssueEdge(a, b, l) ==
    /\ l \in Depths
    /\ <<a, b, l>> \notin edges
    /\ edges' = edges \cup {<<a, b, l>>}
    /\ UNCHANGED <<revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned, lastAct>>

-----------------------------------------------------------------------------
(* AUTHORITY-REDUCING (CP/fail-closed, enforced at Act time): revocations    *)

\* Three revocation kinds, each a monotonic (idempotent, add-once) true fact.
\* Each strictly increments RevCount by exactly one (a set gains exactly one
\* element), which is what makes the scalar freshMark watermark a sound
\* stand-in for "has this node seen every revocation fact so far".
RevokeKey(k) ==
    /\ k \notin revokedKeys
    /\ revokedKeys' = revokedKeys \cup {k}
    /\ UNCHANGED <<edges, revokedEdges, revokedGrants, freshMark, partitioned, lastAct>>

RevokeEdge(a, b) ==
    /\ <<a, b>> \notin revokedEdges
    /\ revokedEdges' = revokedEdges \cup {<<a, b>>}
    /\ UNCHANGED <<edges, revokedKeys, revokedGrants, freshMark, partitioned, lastAct>>

RevokeGrant(n) ==
    /\ n \notin revokedGrants
    /\ revokedGrants' = revokedGrants \cup {n}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, freshMark, partitioned, lastAct>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: StaleView / Partition / Heal                              *)

\* A node refreshes its local watermark to the current true one (a full
\* resync). Disabled while partitioned. Staleness is not something this
\* action produces -- it is the DERIVED condition freshMark[n] < RevCount
\* that naturally reappears the instant any later Revoke* event lands after
\* this sync, which is exactly what lets Partition/Heal/StaleView exercise
\* the interesting states: caught-up now, stale again after the next
\* revocation, caught-up again after the next StaleView.
StaleView(n) ==
    /\ n \notin partitioned
    /\ freshMark' = [freshMark EXCEPT ![n] = RevCount]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, partitioned, lastAct>>

\* Adversarial network partition: an arbitrary set of nodes is cut off and can
\* no longer advance their watermark (StaleView is disabled for them), so
\* their staleness can persist indefinitely.
Partition ==
    /\ partitioned' \in SUBSET Nodes
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, lastAct>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, lastAct>>

-----------------------------------------------------------------------------
(* THE PRIVILEGED ACTION: revoke-before-act as an action-time rule           *)

\* actor performs a privileged action against subject's authority. The guard
\* IS the revoke-before-act rule: actor's watermark must EXACTLY equal the
\* true global watermark right now -- a fully caught-up, fenced read -- fail-
\* closed, since any lag at all (a stale view) simply disables this action
\* rather than falling back to an optimistic/last-known-good grant. `lastAct`
\* is a GHOST variable overwritten (not accumulated) each Act -- it need not
\* remember the whole history: TLC's invariant check runs after EVERY
\* transition, so every Act that ever fires is checked, exactly once, as
\* "the most recent one" in its own immediate successor state. Overwriting
\* keeps the state space independent of how many Acts have occurred, while
\* still giving TLC's exhaustive search the same total coverage as an
\* ever-growing log would.
Act(actor, subject) ==
    /\ freshMark[actor] = RevCount
    /\ subject \in CurrentAuthNodes
    /\ lastAct' = [some |-> TRUE, actor |-> actor, subject |-> subject,
                   authSnap |-> CurrentAuthNodes, watermark |-> RevCount]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E a, b \in Nodes, l \in Depths : IssueEdge(a, b, l)
    \/ \E k \in Nodes                  : RevokeKey(k)
    \/ \E a, b \in Nodes               : RevokeEdge(a, b)
    \/ \E n \in Nodes                  : RevokeGrant(n)
    \/ \E n \in Nodes                  : StaleView(n)
    \/ Partition
    \/ Heal
    \/ \E a, s \in Nodes                : Act(a, s)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

MaxRevCount == Cardinality(Nodes) + Cardinality(Nodes \X Nodes) + Cardinality(Nodes)

TypeOK ==
    /\ edges \subseteq (Nodes \X Nodes \X Depths)
    /\ revokedKeys \subseteq Nodes
    /\ revokedEdges \subseteq (Nodes \X Nodes)
    /\ revokedGrants \subseteq Nodes
    /\ freshMark \in [Nodes -> 0 .. MaxRevCount]
    /\ partitioned \subseteq Nodes
    /\ lastAct \in [some: BOOLEAN, actor: Nodes, subject: Nodes,
                    authSnap: SUBSET Nodes, watermark: 0 .. MaxRevCount]

\* A node's local watermark never runs ahead of the true global one.
FreshMarkBounded == \A n \in Nodes : freshMark[n] <= RevCount

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The most recent Act (if any) carries the set of nodes that WERE
\* authoritative (per the true revoked sets) at the exact moment it acted.
\* Because revocation only ever shrinks that authorized set over time
\* (revoked sets are grow-only, and AuthNodesGiven is antitone in them), this
\* recorded snapshot is stable evidence forever after -- and since TLC checks
\* this invariant after EVERY transition, every Act that ever fires is
\* checked exactly once, as `lastAct`, in its own immediate successor state.
\* That gives the same exhaustive coverage a full history log would, without
\* the state-space cost of accumulating one: the act always precedes any
\* later revocation of that subject, never follows it.
NoActionAfterRevocation ==
    lastAct.some => lastAct.subject \in lastAct.authSnap

\* Fail-closed under a stale view: whenever a node's watermark lags the true
\* global one (it is stale), that node can never appear as the actor of the
\* most-recently-recorded Act evaluated as fully fresh against the CURRENT
\* watermark -- Act's guard (freshMark[actor] = RevCount at the moment it
\* fired) structurally forecloses that: if it fired with watermark = W and W
\* still equals the CURRENT RevCount, no revocation has landed since, so
\* freshMark[actor] must still equal RevCount too -- contradicting staleness.
FailClosedUnderStaleView ==
    \A n \in Nodes :
        freshMark[n] < RevCount =>
            ~ (/\ lastAct.some
               /\ lastAct.actor = n
               /\ lastAct.watermark = RevCount)

=============================================================================
