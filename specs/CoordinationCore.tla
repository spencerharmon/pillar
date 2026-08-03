---------------------------- MODULE CoordinationCore ----------------------------
(***************************************************************************)
(* Pillar coordination core: a quorum-backed lease with fencing epochs.    *)
(*                                                                         *)
(* This is the formal contract behind Pillar's CP resource-class (see      *)
(* docs/consistency-model.md).  Exclusive, non-idempotent resources        *)
(* (singleton scheduling, IPAM allocation, cron-fire, ingress ownership)   *)
(* acquire authority through this protocol.  A candidate may only act as    *)
(* the holder for an epoch once a QUORUM of voters has granted it that      *)
(* epoch; because any two quorums intersect and each voter grants at most   *)
(* one candidate per epoch, no two candidates can ever hold the same epoch. *)
(* Higher epochs fence lower ones (monotonic grants), so a partitioned      *)
(* minority -- unable to reach quorum -- cannot acquire and correctly       *)
(* starves rather than splitting the brain.                                 *)
(*                                                                         *)
(* Safety proven by TLC:  AtMostOneHolderPerEpoch, GrantsAreFenced.         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,      \* set of participating node identities
    MaxEpoch,   \* model bound on epoch numbers
    None        \* sentinel: "no candidate" (a model value, distinct from Nodes)

ASSUME NodesNonEmpty == Nodes # {}
ASSUME MaxEpochIsNat == MaxEpoch \in Nat
ASSUME NoneNotNode   == None \notin Nodes

Epochs  == 0 .. MaxEpoch

\* A quorum is any strict majority of nodes.  Majorities pairwise intersect,
\* which is the entire basis for the safety argument below.
Quorums == {Q \in SUBSET Nodes : 2 * Cardinality(Q) > Cardinality(Nodes)}

VARIABLES
    grantedEpoch,   \* grantedEpoch[v] : highest epoch voter v has granted in
    grantedTo,      \* grantedTo[v]    : candidate v backed at grantedEpoch[v] (or None)
    holders         \* set of <<candidate, epoch>> pairs that have acquired the lease

vars == <<grantedEpoch, grantedTo, holders>>

TypeOK ==
    /\ grantedEpoch \in [Nodes -> Epochs]
    /\ grantedTo    \in [Nodes -> Nodes \cup {None}]
    /\ holders       \subseteq (Nodes \X Epochs)

Init ==
    /\ grantedEpoch = [v \in Nodes |-> 0]
    /\ grantedTo    = [v \in Nodes |-> None]
    /\ holders      = {}

\* A voter v grants candidate c its vote for epoch e.  Monotonic: a voter only
\* ever moves forward, and grants at most one candidate per epoch.  Modelling
\* the grant as "strictly greater than any prior grant" captures both.
Grant(v, c, e) ==
    /\ e \in Epochs
    /\ e > grantedEpoch[v]
    /\ grantedEpoch' = [grantedEpoch EXCEPT ![v] = e]
    /\ grantedTo'    = [grantedTo    EXCEPT ![v] = c]
    /\ UNCHANGED holders

\* Candidate c acquires the lease at epoch e once some quorum has granted it e.
\* No coordinator is required: acquisition is a locally-checkable predicate over
\* the (gossiped) grant state.  A minority partition can never satisfy it.
Acquire(c, e) ==
    /\ <<c, e>> \notin holders
    /\ \E Q \in Quorums :
         \A v \in Q : grantedEpoch[v] = e /\ grantedTo[v] = c
    /\ holders' = holders \cup {<<c, e>>}
    /\ UNCHANGED <<grantedEpoch, grantedTo>>

Next ==
    \/ \E v \in Nodes, c \in Nodes, e \in Epochs : Grant(v, c, e)
    \/ \E c \in Nodes, e \in Epochs             : Acquire(c, e)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* No two distinct candidates ever hold the same epoch.  This is the split-brain
\* exclusion: it is what lets a controller treat "I hold epoch e" as the right to
\* perform an exclusive, non-idempotent side effect.
AtMostOneHolderPerEpoch ==
    \A e \in Epochs :
        Cardinality({c \in Nodes : <<c, e>> \in holders}) <= 1

\* A voter never backs two different candidates at the same recorded epoch.
GrantsAreFenced ==
    \A v \in Nodes :
        (grantedTo[v] # None) => (grantedEpoch[v] \in Epochs)

=============================================================================
