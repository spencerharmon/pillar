----------------------------- MODULE PillarUdpMesh -----------------------------
(***************************************************************************)
(* pillar-UDP, ingress class 3: DIRECT node<->node messages in the         *)
(* INTER-CELL FULL-MESH case (ROI P2, "Load balancing, ingress & the        *)
(* pillar-UDP protocol").  This is the MANY-TO-MANY case.                   *)
(*                                                                          *)
(* Two cells, each present at several physical sites, form a full mesh of   *)
(* site-to-site links.  A flow of messages from cell A to cell B is spread  *)
(* across the mesh rather than pinned to one connection, so aggregate       *)
(* bandwidth is the SUM of the site links, not a single bottleneck -- and   *)
(* any lossy link is simply routed around by the other site pairs.  Trust   *)
(* is by WoT signature on each message (CID), not by origin address, so a   *)
(* copy of message m that arrives at cell B over ANY site pair counts, and  *)
(* redundant copies over other pairs dedup by CID.                          *)
(*                                                                          *)
(* Model (same monotone-work + lossy-channel + strong-fairness idiom as     *)
(* AntiEntropy.tla / PillarUdpClient.tla):                                  *)
(*   - up[l]      : whether mesh link l (an A-site<->B-site pair) is good.   *)
(*   - deliv[m]   : times cell B has accepted message m (CID dedup: <=1).    *)
(*   - carried[m] : the set of links that carried a copy of m (ghost) --     *)
(*                  shows a message's redundant copies AND that the flow as  *)
(*                  a whole is spread across multiple links (aggregation).   *)
(*   - Scramble   : the adversary flips arbitrary links lossy at any time    *)
(*                  SUBJECT TO the standing premise that >= 1 mesh link is    *)
(*                  always up (cell B stays reachable from cell A by SOME     *)
(*                  site pair) -- the premise "route around the lossy link"  *)
(*                  requires; the theorem is that the mesh always finds it.  *)
(*                                                                          *)
(* Proven by TLC:                                                           *)
(*   - ExactlyOnce (safety)  : every message is accepted by cell B at most  *)
(*                 once, though many sites may redundantly forward it.      *)
(*   - AllDelivered (liveness): <>(every message delivered) -- despite       *)
(*                 arbitrarily many lossy links, the full flow completes by  *)
(*                 routing around them over the remaining site pairs.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    SitesA,   \* the sites (nodes) where cell A is present
    SitesB,   \* the sites (nodes) where cell B is present
    Msgs      \* the flow: messages cell A must deliver to cell B

ASSUME SitesANonEmpty == SitesA # {}
ASSUME SitesBNonEmpty == SitesB # {}
ASSUME MsgsNonEmpty   == Msgs   # {}

\* Every site-to-site link of the full mesh.
Links == { [from |-> a, to |-> b] : a \in SitesA, b \in SitesB }

VARIABLES
    up,       \* up[l] \in BOOLEAN : is mesh link l currently good?
    deliv,    \* deliv[m] \in {0,1} : times cell B accepted m (CID dedup)
    carried   \* carried[m] \subseteq Links : links that carried a copy of m

vars == <<up, deliv, carried>>

TypeOK ==
    /\ up      \in [Links -> BOOLEAN]
    /\ deliv   \in [Msgs -> 0..1]
    /\ carried \in [Msgs -> SUBSET Links]

Init ==
    /\ up      = [l \in Links |-> TRUE]
    /\ deliv   = [m \in Msgs |-> 0]
    /\ carried = [m \in Msgs |-> {}]

------------------------------------------------------------------------------
(* ACTIONS *)

\* An A-site forwards message m to a B-site over a currently-good mesh link l
\* that has not already carried m. The FIRST copy to reach cell B (over any
\* site pair) injects m; later copies over other pairs dedup by CID (deliv
\* stays 1). `carried` records every link that moved a copy -- redundancy for
\* a single message, and, across messages, spread of the flow over the mesh.
Forward(m, l) ==
    /\ l \in Links
    /\ up[l]
    /\ l \notin carried[m]
    /\ carried' = [carried EXCEPT ![m] = @ \cup {l}]
    /\ deliv'   = [deliv   EXCEPT ![m] = IF @ = 0 THEN 1 ELSE @]
    /\ UNCHANGED up

\* Adversary: arbitrary mesh links go lossy (a site link degrades or a
\* transit path between two sites congests), SUBJECT TO the premise that
\* cell B stays reachable from cell A over >= 1 site pair.
Scramble ==
    /\ up' \in [Links -> BOOLEAN]
    /\ \E l \in Links : up'[l]
    /\ UNCHANGED <<deliv, carried>>

Next ==
    \/ \E m \in Msgs, l \in Links : Forward(m, l)
    \/ Scramble

\* Each forwarding opportunity is strongly fair, so an undelivered message --
\* whose deliverability persists (monotone: an undelivered m has carried no
\* copy, so ANY good link can move it) -- is eventually carried over whatever
\* site pair stays good. Because >= 1 link is always up, some Forward(m, l) is
\* enabled infinitely often for each still-undelivered m, so SF completes the
\* whole flow by routing around every lossy link. No window is ever tuned.
Fairness == \A m \in Msgs, l \in Links : SF_vars(Forward(m, l))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY *)

\* CID dedup across the mesh: every message is accepted by cell B at most
\* once, however many sites redundantly forward it over however many links.
ExactlyOnce == \A m \in Msgs : deliv[m] <= 1

------------------------------------------------------------------------------
(* LIVENESS: FULL-MESH ROUTE-AROUND *)

AllDelivered == \A m \in Msgs : deliv[m] = 1

\* Despite arbitrarily many lossy links, the entire A->B flow completes by
\* spreading across, and routing around bad links via, the remaining site
\* pairs -- aggregate mesh throughput, not a single pinned connection.
MeshCompletes == <>AllDelivered

=================================================================================
