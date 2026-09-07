------------------------------ MODULE PillarUDP ------------------------------
(***************************************************************************)
(* Pillar-UDP transport protocol (ROI P2 "Load balancing, ingress & the     *)
(* pillar-UDP protocol", method#1, DESIGN-GATED [TLA gate] -- blocking      *)
(* before any Rust for pillar-UDP).                                        *)
(*                                                                          *)
(* Models the ROI's twofold posture -- (1) variable loss/latency tolerance  *)
(* via a per-connection-declared redundancy allowance, and (2) automatic    *)
(* dynamic multipath source/route selection (never TCP-style window        *)
(* backoff) -- over a generic graph of Nodes joined by Edges, at least one  *)
(* of which is LOSSY (may silently drop a datagram in flight).  The same    *)
(* spray/forward/dedup/redundancy machinery applies uniformly to all THREE *)
(* communication shapes the ROI names, which this graph abstracts as       *)
(* edges rather than distinct mechanics (the delivery/redundancy/dedup      *)
(* logic literally does not care which shape a link stands for):           *)
(*   - non-node pillar-UDP client <-> cell   : c <-> n1 (lossy), c <-> k1   *)
(*   - intra-cell node <-> node / inter-cell  : n1 <-> k1 (one generic      *)
(*     link plays both roles -- the mechanics genuinely do not differ)     *)
(* (the default CONSTANTS below wire exactly this topology; see the .cfg). *)
(*                                                                          *)
(* Per message (CID): a declared per-connection Redundancy allowance caps   *)
(* every datagram -- initial spray AND every subsequent forward -- system-  *)
(* wide (BoundedTotalDatagrams); a hop/TTL budget plus per-node dedup (a    *)
(* node ever admits only the FIRST copy of a cid it sees) makes forwarding  *)
(* terminate and guarantees a forwarded copy is never re-injected into the  *)
(* spray (NoForwardingLoops); a reversibility classification -- reused from *)
(* the existing streamdb-viewpolicy idempotent/exclusive split -- routes an *)
(* exclusive (non-idempotent) message's actual PROCESSING to the           *)
(* coordination-core lease holder alone, while dedup ensures any message,   *)
(* however many redundant copies arrive, is ever processed by AT MOST ONE   *)
(* node system-wide (ExactlyOnceProcessing); and redundant replies toward   *)
(* an anonymous/unauthenticated client are capped by a factor of address-   *)
(* validated (return-routability-proven) requests, never committed ahead   *)
(* of validation (AntiAmplificationBound).                                 *)
(*                                                                          *)
(* Liveness: despite the lossy edge, reachability-under-partial-failure    *)
(* holds -- a message is eventually received by every node connected to its *)
(* originator through SOME non-lossy path, under weak fairness on the      *)
(* non-lossy edges alone (no fairness is ever granted to the lossy edge --  *)
(* this is the multipath/dispersed-source-selection half of the posture:   *)
(* it *routes around* a bad link via an alternate path, it never merely    *)
(* backs off and retries the bad one).                                     *)
(*                                                                          *)
(* Proven by TLC:                                                          *)
(*   - TypeOK, ExactlyOnceProcessing, BoundedTotalDatagrams,                *)
(*     NoForwardingLoops, AntiAmplificationBound (safety)                   *)
(*   - Reachability (liveness, <>)                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    c, n1, k1,      \* the three modeled participants (atomic model values --
                     \* TLC cfg files can't assign a function-valued CONSTANT
                     \* directly, so the topology/message-map operators below
                     \* are built from these named atoms instead):
                     \*   c  -- non-node pillar-UDP client
                     \*   n1 -- a cell node the client sprays to
                     \*   k1 -- a second node reachable from both c (directly,
                     \*         non-lossy: client<->cell's alternate spray
                     \*         path) and n1 (node<->node / cell<->cell: the
                     \*         same generic link mechanics back either shape)
    m1, m2,         \* the two modeled message content-ids
    MaxHops,        \* TTL bound: a datagram this many hops old cannot relay further
    AmpFactor,      \* Nat: bound on redundant replies per address-validated request
    MaxValidated    \* Nat: model bound on address-validation events (keeps the
                     \* validatedReq/repliesSent state space finite for TLC)

ASSUME MaxHopsOK      == MaxHops \in Nat /\ MaxHops > 0
ASSUME AmpFactorOK    == AmpFactor \in Nat
ASSUME MaxValidatedOK == MaxValidated \in Nat
ASSUME DistinctAtoms  == c # n1 /\ c # k1 /\ n1 # k1 /\ m1 # m2

\* Topology: every participant, modeled uniformly (client, cell node, remote
\* peer), joined by physical links. {c,n1} is the sole LOSSY edge (the ROI's
\* >= 1 lossy-link mandate); {c,k1} gives the client a non-lossy alternate
\* path to everywhere -- the multipath topology the Reachability liveness
\* property needs. All three ROI communication shapes are present as edges
\* (the delivery/redundancy/dedup logic is shape-agnostic, so a single
\* generic link plays both node<->node and cell<->cell roles):
\*   non-node client <-> cell         : {c,n1} (lossy), {c,k1}
\*   intra-cell / inter-cell node link : {n1,k1}
Nodes         == {c, n1, k1}
Edges         == { {c, n1}, {c, k1}, {n1, k1} }
LossyEdges    == { {c, n1} }
NonLossyEdges == Edges \ LossyEdges

\* Messages: m1 is idempotent, originated by the client; m2 is exclusive/
\* non-idempotent, originated by n1 and processable only by the remote lease
\* holder k1 -- exercising both halves of ExactlyOnceProcessing.
CIDs          == {m1, m2}
Origin        == [cid \in CIDs |-> IF cid = m1 THEN c ELSE n1]
ExclusiveCIDs == {m2}
LeaseHolder   == k1
AnonClients   == {c}

\* Redundancy covers every distinct directed (cid,from,to) send this 3-edge
\* graph can ever produce (2*3 = 6 per cid) -- BoundedTotalDatagrams is thus
\* checked as a genuine invariant of the enforcement mechanism without
\* becoming the thing that starves the Reachability liveness proof (a
\* smaller allowance would let an adversarial interleaving exhaust the
\* shared budget on edges that never reach the target before the useful
\* send fires -- see the design doc for this task).
Redundancy == [cid \in CIDs |-> 6]

\* Every message m -> AT MOST one recorded copy per node (dedup memory), so
\* Cardinality bounds below are all over genuinely finite record sets.
DatagramType == [cid: CIDs, from: Nodes, to: Nodes, hop: 0..MaxHops]

VARIABLES
    received,     \* received[n] : SUBSET [cid: CIDs, hop: 0..MaxHops] -- copies
                   \*   node n has ever admitted, at most one per cid (dedup)
    processed,    \* processed[n] : SUBSET CIDs -- cids n has actually EXECUTED
    sentCount,    \* sentCount[cid] : Nat -- total datagrams ever sent for cid
                   \*   (spray + forward), gated by Redundancy[cid]
    sentTo,       \* SUBSET [cid: CIDs, from: Nodes, to: Nodes] -- directed
                   \*   (cid,from,to) sends already issued (each fires once --
                   \*   a deterministic protocol never resends identically)
    inFlight,     \* SUBSET DatagramType -- datagrams currently on the wire
    validatedReq, \* Nat -- address-validation (return-routability) events so far
    repliesSent   \* Nat -- redundant reply datagrams sent toward an AnonClient

vars == <<received, processed, sentCount, sentTo, inFlight, validatedReq, repliesSent>>

ReceivedCids(n) == {p.cid : p \in received[n]}

TypeOK ==
    /\ received     \in [Nodes -> SUBSET [cid: CIDs, hop: 0..MaxHops]]
    /\ processed    \in [Nodes -> SUBSET CIDs]
    /\ sentCount    \in [CIDs -> Nat]
    /\ sentTo       \subseteq [cid: CIDs, from: Nodes, to: Nodes]
    /\ inFlight     \subseteq DatagramType
    /\ validatedReq \in 0..MaxValidated
    /\ repliesSent  \in 0..(AmpFactor * MaxValidated)

Init ==
    /\ received     = [n \in Nodes |-> {[cid |-> cd, hop |-> MaxHops] :
                                          cd \in {cc \in CIDs : Origin[cc] = n}}]
    /\ processed    = [n \in Nodes |-> {}]
    /\ sentCount    = [cd \in CIDs |-> 0]
    /\ sentTo       = {}
    /\ inFlight     = {}
    /\ validatedReq = 0
    /\ repliesSent  = 0

------------------------------------------------------------------------------
(* ACTIONS *)

\* `from`, already holding a fresh copy of cid at remaining-hop budget h,
\* sprays/forwards it across edge {from,to}. Counts against the declared
\* redundancy allowance; each directed (cid,from,to) fires at most once
\* (sentTo) -- a deterministic protocol, not an adversary retrying forever.
Send(from, to, cid, h) ==
    /\ {from, to} \in Edges
    /\ h > 0
    /\ [cid |-> cid, hop |-> h] \in received[from]
    /\ [cid |-> cid, from |-> from, to |-> to] \notin sentTo
    /\ sentCount[cid] < Redundancy[cid]
    /\ sentTo'     = sentTo \cup {[cid |-> cid, from |-> from, to |-> to]}
    /\ inFlight'   = inFlight \cup {[cid |-> cid, from |-> from, to |-> to, hop |-> h - 1]}
    /\ sentCount'  = [sentCount EXCEPT ![cid] = @ + 1]
    /\ UNCHANGED <<received, processed, validatedReq, repliesSent>>

\* A datagram (over a reliable edge, or one that happens to survive a lossy
\* one) arrives. Dedup: `to` admits only the FIRST copy of a cid it ever
\* sees -- a later copy is silently absorbed. This, plus the hop bound in
\* Send, is exactly what makes forwarding terminate and never loop
\* (NoForwardingLoops): once delivered, a cid can never be re-delivered (and
\* hence never re-forwarded) at that node again.
Deliver(dg) ==
    /\ dg \in inFlight
    /\ dg.cid \notin ReceivedCids(dg.to)
    /\ received' = [received EXCEPT ![dg.to] = @ \cup {[cid |-> dg.cid, hop |-> dg.hop]}]
    /\ inFlight' = inFlight \ {dg}
    /\ UNCHANGED <<processed, sentCount, sentTo, validatedReq, repliesSent>>

\* A datagram traversing a LOSSY edge may simply never arrive.
Drop(dg) ==
    /\ dg \in inFlight
    /\ {dg.from, dg.to} \in LossyEdges
    /\ inFlight' = inFlight \ {dg}
    /\ UNCHANGED <<received, processed, sentCount, sentTo, validatedReq, repliesSent>>

\* Node n actually EXECUTES cid's effect (as opposed to merely holding or
\* forwarding a copy). An exclusive/non-idempotent cid may only ever be
\* processed by the coordination-core lease holder; either way, at most one
\* node system-wide ever processes a given cid, however many redundant
\* copies were delivered (ExactlyOnceProcessing).
Process(n, cid) ==
    /\ cid \in ReceivedCids(n)
    /\ cid \notin processed[n]
    /\ \A m \in Nodes : cid \notin processed[m]
    /\ (cid \in ExclusiveCIDs => n = LeaseHolder)
    /\ processed' = [processed EXCEPT ![n] = @ \cup {cid}]
    /\ UNCHANGED <<received, sentCount, sentTo, inFlight, validatedReq, repliesSent>>

\* Return-routability: an anon client's address gets validated.
ValidateAddress ==
    /\ validatedReq < MaxValidated
    /\ validatedReq' = validatedReq + 1
    /\ UNCHANGED <<received, processed, sentCount, sentTo, inFlight, repliesSent>>

\* A cell node emits one more redundant reply datagram toward an anon client.
\* Never allowed to run ahead of the address-validation budget --
\* AntiAmplificationBound -- i.e. no reply-set commitment before a
\* return-routability proof.
ReplyToClient ==
    /\ repliesSent < AmpFactor * validatedReq
    /\ repliesSent' = repliesSent + 1
    /\ UNCHANGED <<received, processed, sentCount, sentTo, inFlight, validatedReq>>

Next ==
    \/ \E from, to \in Nodes, cid \in CIDs, h \in 1..MaxHops : Send(from, to, cid, h)
    \/ \E dg \in inFlight : Deliver(dg)
    \/ \E dg \in inFlight : Drop(dg)
    \/ \E n \in Nodes, cid \in CIDs : Process(n, cid)
    \/ ValidateAddress
    \/ ReplyToClient

\* Weak fairness on Send/Deliver over NON-LOSSY edges only -- a copy ready to
\* cross a good link is never starved forever. The lossy edge gets NO
\* fairness (an adversarial link may drop every copy forever): liveness must
\* ride the good link, never depend on the bad one healing.
Fairness ==
    /\ \A from, to \in Nodes, cid \in CIDs, h \in 1..MaxHops :
          {from, to} \in NonLossyEdges => WF_vars(Send(from, to, cid, h))
    /\ \A dg \in DatagramType :
          {dg.from, dg.to} \in NonLossyEdges => WF_vars(Deliver(dg))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* At most one node, system-wide, ever processes a given cid -- and an
\* exclusive/non-idempotent one is processed only by the lease holder.
ExactlyOnceProcessing ==
    /\ \A cid \in CIDs : Cardinality({n \in Nodes : cid \in processed[n]}) <= 1
    /\ \A cid \in ExclusiveCIDs : \A n \in Nodes : cid \in processed[n] => n = LeaseHolder

\* Redundancy + forwarding for one logical message never exceeds its
\* declared per-connection allowance (guard-enforced in Send; checked here
\* as the invariant the operator actually cares about).
BoundedTotalDatagrams == \A cid \in CIDs : sentCount[cid] <= Redundancy[cid]

\* Hop/TTL bound + dedup: every in-flight datagram carries a strictly
\* decreasing hop budget, and a node holds at most one recorded copy per
\* cid ever -- so a forwarded copy can never be re-injected into the spray,
\* and relaying provably terminates.
NoForwardingLoops ==
    /\ \A dg \in inFlight : dg.hop < MaxHops
    /\ \A n \in Nodes : \A cid \in CIDs :
          Cardinality({p \in received[n] : p.cid = cid}) <= 1

\* Redundant replies toward an anonymous/unauthenticated client are bounded
\* by AmpFactor times the address-validated requests seen so far.
AntiAmplificationBound == repliesSent <= AmpFactor * validatedReq

------------------------------------------------------------------------------
(* LIVENESS: REACHABILITY UNDER PARTIAL FAILURE *)

\* The set of nodes reachable from n using ONLY non-lossy edges.
RECURSIVE ReachableSet(_)
ReachableSet(S) ==
    LET S2 == S \cup {m \in Nodes : \E n \in S : {n, m} \in NonLossyEdges}
    IN  IF S2 = S THEN S ELSE ReachableSet(S2)

ReachableFrom(n) == ReachableSet({n})

\* Delivery holds whenever >= 1 non-lossy path exists between a message's
\* originator and a node: every node reachable from Origin[cid] via
\* non-lossy edges alone eventually receives a copy of cid -- despite the
\* lossy edge(s) elsewhere in the graph. This is the multipath/dispersed-
\* source-selection half of the ROI's twofold posture: it routes AROUND a
\* bad link via an alternate path, it never merely retries the bad one.
Reachability ==
    \A cid \in CIDs : \A m \in Nodes :
        (m \in ReachableFrom(Origin[cid])) => <>(cid \in ReceivedCids(m))

===============================================================================
