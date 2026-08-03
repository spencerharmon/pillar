------------------------------ MODULE StreamingDB ------------------------------
(***************************************************************************)
(* Pillar streaming state substrate: an append-only, content-addressed     *)
(* Merkle-CRDT op-log (ROI P1, method #1).                                  *)
(*                                                                         *)
(* Model of the AP data plane.  Each op is identified by its CONTENT        *)
(* ADDRESS (a hash), so an op's identity is a pure function of its bytes:   *)
(* two nodes that hold the same op necessarily agree on its identity, and   *)
(* the log is a grow-only set of such ops -- a state-based CRDT (CvRDT)      *)
(* whose merge is set union (commutative, associative, idempotent).  Nodes  *)
(* anti-entropy (gossip) only with peers in the same network PARTITION;     *)
(* the network may PARTITION and HEAL arbitrarily.                          *)
(*                                                                         *)
(* Two things are proven by TLC here:                                       *)
(*                                                                         *)
(*  1. AP convergence.  Grow-only merge never loses or corrupts an op       *)
(*     (NoLostWrite, LogSubsetOfWritten, append-only via MonotonicLog), the *)
(*     content address is a deterministic function of content              *)
(*     (DeterministicMerkleRoot), and per-partition ordering is a           *)
(*     deterministic function of the delivered set (PerPartitionOrder).     *)
(*     Post Partition/Heal the system reconverges: with anti-entropy fair   *)
(*     and the network eventually healed, every node reaches the same       *)
(*     log -- the liveness property Convergence (<>[]AllConverged).         *)
(*                                                                         *)
(*  2. CP composition.  The CoordinationCore CP lease protocol runs         *)
(*     concurrently with the AP op-log (composed under a single Next).      *)
(*     Its safety invariant AtMostOneHolderPerEpoch is PRESERVED under the  *)
(*     composition -- the AP plane cannot violate the CP plane's mutual     *)
(*     exclusion, and vice versa, because they touch disjoint state.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,      \* set of participating node identities
    Ops,        \* finite set of content addresses (op ids); each a distinct Nat
    NumParts,   \* model bound: max number of concurrent network partitions
    MaxEpoch,   \* model bound on CoordinationCore epoch numbers
    None        \* CoordinationCore sentinel "no candidate" (a model value)

ASSUME NodesNonEmpty  == Nodes # {}
ASSUME OpsAreNats     == Ops \subseteq Nat
ASSUME NumPartsPos    == NumParts \in Nat \ {0}
ASSUME MaxEpochIsNat  == MaxEpoch \in Nat
ASSUME NoneNotNode    == None \notin Nodes

PartIds == 1 .. NumParts

VARIABLES
    log,          \* log[n]  : SUBSET Ops -- the grow-only op-log node n holds
    part,         \* part[n] : PartId     -- the network partition n is in
    written,      \* ghost: every op ever appended anywhere (for no-loss proof)
    \* --- CoordinationCore CP state (composed in; see CoordinationCore.tla) ---
    grantedEpoch,
    grantedTo,
    holders

apVars  == <<log, part, written>>
cpVars  == <<grantedEpoch, grantedTo, holders>>
vars    == <<log, part, written, grantedEpoch, grantedTo, holders>>

\* Instance of the CP lease protocol over the SAME nodes, sharing the CP
\* variables declared above.  This is the composition: the CP module's actions
\* and invariants are imported verbatim and interleaved with the AP actions.
CC == INSTANCE CoordinationCore

------------------------------------------------------------------------------
(* CONTENT ADDRESSING & PER-PARTITION ORDER                                  *)

\* Deterministic ascending sort of a finite set of Nats.  Because an op id IS
\* its content address, this order is a pure function of the delivered SET --
\* the basis for deterministic per-partition ordering and the Merkle root.
RECURSIVE SortSet(_)
SortSet(S) ==
    IF S = {} THEN << >>
    ELSE LET m == CHOOSE x \in S : \A y \in S : x <= y
         IN  <<m>> \o SortSet(S \ {m})

\* Per-partition materialised order of a node's log.
Order(n) == SortSet(log[n])

\* Merkle root: a hash-chain fold over the content-ordered ops.  Deterministic
\* in the SET alone (order is derived), modelling that identical delivered sets
\* yield identical roots regardless of the gossip path that delivered them.
RECURSIVE FoldRoot(_)
FoldRoot(seq) ==
    IF seq = << >> THEN 0
    ELSE (Head(seq) + 31 * FoldRoot(Tail(seq))) % 1000003
Root(n) == FoldRoot(Order(n))

------------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ log          = [n \in Nodes |-> {}]
    /\ part         = [n \in Nodes |-> 1]      \* start fully connected
    /\ written      = {}
    /\ grantedEpoch = [v \in Nodes |-> 0]
    /\ grantedTo    = [v \in Nodes |-> None]
    /\ holders      = {}

------------------------------------------------------------------------------
(* AP DATA-PLANE ACTIONS                                                     *)

\* Node n appends a fresh op (content it does not yet hold).  Append-only.
Write(n, op) ==
    /\ op \in Ops
    /\ op \notin log[n]
    /\ log'     = [log     EXCEPT ![n] = @ \cup {op}]
    /\ written' = written \cup {op}
    /\ UNCHANGED <<part>>
    /\ UNCHANGED cpVars

\* Anti-entropy: n ships its log to m.  Only within the SAME partition.  Merge
\* is set union -- commutative, associative, idempotent (a CvRDT join).
Gossip(n, m) ==
    /\ n # m
    /\ part[n] = part[m]
    /\ ~(log[n] \subseteq log[m])              \* enabled only when it delivers
    /\ log'     = [log EXCEPT ![m] = @ \cup log[n]]
    /\ UNCHANGED <<part, written>>
    /\ UNCHANGED cpVars

\* Network splits into an arbitrary partitioning (adversarial).
Partition ==
    /\ part' \in [Nodes -> PartIds]
    /\ UNCHANGED <<log, written>>
    /\ UNCHANGED cpVars

\* Network heals: everyone back in one partition.  Fair (see Spec).
Heal ==
    /\ part # [n \in Nodes |-> 1]
    /\ part' = [n \in Nodes |-> 1]
    /\ UNCHANGED <<log, written>>
    /\ UNCHANGED cpVars

------------------------------------------------------------------------------
(* CP CONTROL-PLANE ACTIONS (imported from CoordinationCore, AP state fixed) *)

CPStep ==
    /\ CC!Next
    /\ UNCHANGED apVars

------------------------------------------------------------------------------
(* COMPOSED NEXT-STATE RELATION                                              *)

Next ==
    \/ \E n \in Nodes, op \in Ops : Write(n, op)
    \/ \E n, m \in Nodes          : Gossip(n, m)
    \/ Partition
    \/ Heal
    \/ CPStep

\* Anti-entropy is STRONGLY fair per node pair, and healing is strongly fair
\* (the network is repaired infinitely often).  Strong fairness on each pair is
\* required, not weak: an adversary that partitions and heals forever leaves a
\* given deliverable gossip step enabled only intermittently (it is disabled
\* whenever the two nodes are split), and weak fairness makes no promise about a
\* step that is merely enabled infinitely often.  Strong fairness does: each
\* heal re-enables it, so it is eventually taken and the op is delivered.
\* Writes and CP steps need NO fairness: both are inherently finite (each op is
\* written at most once per node; the CP protocol is bounded by MaxEpoch), so
\* after the last one the fair gossip/heal pair drives the AP plane to a fixed
\* point.  That is what makes <>[]AllConverged provable.
Fairness ==
    /\ \A n, m \in Nodes : SF_vars(Gossip(n, m))
    /\ SF_vars(Heal)

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ log          \in [Nodes -> SUBSET Ops]
    /\ part         \in [Nodes -> PartIds]
    /\ written       \subseteq Ops
    /\ grantedEpoch \in [Nodes -> 0 .. MaxEpoch]
    /\ grantedTo    \in [Nodes -> Nodes \cup {None}]
    /\ holders       \subseteq (Nodes \X (0 .. MaxEpoch))

------------------------------------------------------------------------------
(* AP SAFETY INVARIANTS                                                      *)

\* Grow-only: a node's log is always a subset of everything ever written, and
\* every written op is still held somewhere (never lost or corrupted).
LogSubsetOfWritten == \A n \in Nodes : log[n] \subseteq written
NoLostWrite        == \A op \in written : \E n \in Nodes : op \in log[n]

\* Content addressing: two nodes holding the same delivered set have the same
\* Merkle root and the same materialised per-partition order.  This is the
\* CvRDT strong-eventual-consistency guarantee stated as reachable-state safety.
DeterministicMerkleRoot ==
    \A n, m \in Nodes : log[n] = log[m] => Root(n) = Root(m)
PerPartitionOrder ==
    \A n, m \in Nodes : (part[n] = part[m] /\ log[n] = log[m]) => Order(n) = Order(m)

------------------------------------------------------------------------------
(* APPEND-ONLY (MONOTONICITY) as an action property                          *)

\* A step never removes an op from any log.  Checked as a temporal safety
\* property over primed state.
MonotonicLog == [][ \A n \in Nodes : log[n] \subseteq log'[n] ]_vars

------------------------------------------------------------------------------
(* CP COMPOSITION SAFETY (imported unchanged from CoordinationCore)          *)

\* The whole point of the composition: CoordinationCore's mutual-exclusion
\* invariant still holds while the AP op-log runs alongside it.
AtMostOneHolderPerEpoch == CC!AtMostOneHolderPerEpoch
GrantsAreFenced         == CC!GrantsAreFenced

------------------------------------------------------------------------------
(* AP CONVERGENCE (LIVENESS)                                                 *)

\* All nodes hold identical logs.
AllConverged == \A n, m \in Nodes : log[n] = log[m]

\* Post Partition/Heal reconvergence: the system eventually reaches, and then
\* stays at, a fully-converged state.  Holds because writes/CP steps are finite
\* and, once they cease, fair gossip + fair healing merge every log to the
\* common union, an absorbing fixed point.
Convergence == <>[]AllConverged

===============================================================================
