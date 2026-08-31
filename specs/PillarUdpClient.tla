----------------------------- MODULE PillarUdpClient -----------------------------
(***************************************************************************)
(* pillar-UDP, ingress class 2: a NON-NODE client delivers one message to  *)
(* a cell by spraying REDUNDANT datagrams across a dispersed set of ingest  *)
(* nodes (ROI P2, "Load balancing, ingress & the pillar-UDP protocol").    *)
(* This is the ONE-TO-MANY case.                                            *)
(*                                                                          *)
(* The protocol's thesis, made formal: on a link where loss is the LINK's  *)
(* fault (jamming, radio, satellite) rather than congestion, TCP/QUIC back  *)
(* their single path off toward zero.  pillar-UDP instead keeps a BOUNDED   *)
(* per-round fan-out across topologically dispersed ingest nodes and lets   *)
(* the cell dedup by content-address (CID).  As long as the cell stays      *)
(* reachable by AT LEAST ONE dispersed path, the message is delivered --    *)
(* the protocol ROUTES AROUND the lossy paths instead of collapsing.        *)
(*                                                                          *)
(* Model (mirrors AntiEntropy.tla's lossy-channel + strong-fairness idiom,  *)
(* and in particular its discipline of making the pending work MONOTONE so  *)
(* the adversary cannot destroy it):                                        *)
(*   - up[n]     : whether the client<->node n path is currently good.      *)
(*   - targeted  : nodes the client has sprayed at least once.  Spraying    *)
(*                 is bounded per round (|S| <= Allowance) but coverage      *)
(*                 accumulates across rounds (retransmit) -- monotone.       *)
(*   - received  : nodes that got a copy (may be several: redundancy).      *)
(*   - injectCount: the cell accepts the message.  Redundant copies at      *)
(*                 several nodes dedup by CID: at most ONE injection.        *)
(*   - Scramble  : the adversary flips arbitrary paths lossy at any time    *)
(*                 (bursty loss / jamming) SUBJECT TO the standing premise   *)
(*                 that >= 1 dispersed path is always up -- i.e. the cell    *)
(*                 remains reachable by SOME route.  That premise is exactly *)
(*                 what "route around the lossy link" requires; the theorem  *)
(*                 is that pillar-UDP always finds it, with no window tuning.*)
(*                                                                          *)
(* Proven by TLC:                                                           *)
(*   - ExactlyOnce (safety)      : the message injects at most once despite *)
(*                 redundant copies landing on multiple dispersed nodes.    *)
(*   - SprayWidthBounded (safety): no spray round exceeds the redundancy    *)
(*                 allowance (no N*W fan-out explosion).                     *)
(*   - Delivered (liveness)      : <>(injected) -- despite arbitrarily many *)
(*                 adversarial loss bursts, the message is eventually        *)
(*                 delivered over whatever path stays good.  Route-around.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,      \* the cell's candidate ingest nodes (topologically dispersed)
    Allowance   \* max datagrams per spray round (the redundancy allowance)

ASSUME NodesNonEmpty == Nodes # {}
ASSUME AllowancePos  == Allowance \in Nat /\ Allowance > 0

VARIABLES
    up,          \* up[n] \in BOOLEAN : is the client<->n path currently good?
    targeted,    \* targeted \subseteq Nodes : nodes sprayed at least once
    received,    \* received \subseteq Nodes : nodes that got a copy (ghost)
    injectCount, \* {0,1} : times the cell accepted the message (CID dedup)
    lastWidth    \* ghost: fan-out of the most recent spray round

vars == <<up, targeted, received, injectCount, lastWidth>>

TypeOK ==
    /\ up          \in [Nodes -> BOOLEAN]
    /\ targeted    \subseteq Nodes
    /\ received    \subseteq Nodes
    /\ injectCount \in 0..1
    /\ lastWidth   \in 0..Cardinality(Nodes)

Init ==
    /\ up          = [n \in Nodes |-> TRUE]
    /\ targeted    = {}
    /\ received    = {}
    /\ injectCount = 0
    /\ lastWidth   = 0

------------------------------------------------------------------------------
(* ACTIONS *)

\* The client sprays one datagram to each node in a dispersed subset S,
\* bounded by the redundancy allowance. Coverage is monotone (targeted only
\* grows) -- unbounded in rounds (retransmit), bounded in width. The client
\* stops spraying once the message is delivered.
Spray(S) ==
    /\ injectCount = 0
    /\ S \subseteq Nodes
    /\ S # {}
    /\ Cardinality(S) <= Allowance
    /\ targeted'  = targeted \cup S
    /\ lastWidth' = Cardinality(S)
    /\ UNCHANGED <<up, received, injectCount>>

\* A copy reaches a node n whose path is currently good and that the client
\* has sprayed. n records the copy; the FIRST copy anywhere injects the
\* message into the cell, later copies dedup by CID (injectCount stays 1).
\* Redundant copies at several nodes are exactly what makes `received` able to
\* grow past a single node while injectCount never exceeds 1.
Receive(n) ==
    /\ up[n]
    /\ n \in targeted
    /\ n \notin received
    /\ received'    = received \cup {n}
    /\ injectCount' = IF injectCount = 0 THEN 1 ELSE injectCount
    /\ UNCHANGED <<up, targeted, lastWidth>>

\* Adversary: arbitrary paths go lossy (bursty loss / jamming), SUBJECT TO
\* the standing premise that the cell stays reachable by >= 1 dispersed path.
Scramble ==
    /\ up' \in [Nodes -> BOOLEAN]
    /\ \E n \in Nodes : up'[n]
    /\ UNCHANGED <<targeted, received, injectCount, lastWidth>>

Next ==
    \/ \E S \in SUBSET Nodes : Spray(S)
    \/ \E n \in Nodes : Receive(n)
    \/ Scramble

\* The client keeps re-spraying every dispersed subset until delivered
\* (strong fairness on each maximal-width spray -> coverage `targeted`
\* eventually reaches every node), and a copy over any currently-good path is
\* strongly fair. Because >= 1 path is always up and coverage is monotone,
\* some good, sprayed, not-yet-received node is enabled infinitely often, so
\* SF forces the delivery -- eventual delivery with no window control, purely
\* by redundant spray over whatever path stays good.
Fairness ==
    /\ \A S \in {T \in SUBSET Nodes : T # {} /\ Cardinality(T) = Allowance} :
           SF_vars(Spray(S))
    /\ \A n \in Nodes : SF_vars(Receive(n))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY *)

\* CID dedup: however many redundant copies land on however many dispersed
\* nodes, the cell accepts the message at most once.
ExactlyOnce == injectCount <= 1

\* No spray round ever exceeds the redundancy allowance -- the bound that
\* keeps redundancy from exploding to N*W while still spraying for diversity.
SprayWidthBounded == lastWidth <= Allowance

------------------------------------------------------------------------------
(* LIVENESS: ROUTE-AROUND-LOSS DELIVERY *)

\* Despite arbitrarily many adversarial loss bursts, the message is eventually
\* injected into the cell. No congestion window is ever tuned; delivery rides
\* bounded redundant spray plus whatever dispersed path stays good.
Delivered == <>(injectCount = 1)

=================================================================================
