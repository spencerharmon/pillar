----------------------------- MODULE AntiEntropy -----------------------------
(***************************************************************************)
(* Pillar anti-entropy sync: fills gossipsub's best-effort gaps (ROI P1,    *)
(* "Event order & integrity", method #1).  Models a hypercore / SSB-EBT     *)
(* style replicator: range-based set reconciliation over a per-author      *)
(* linear log, delivered over a LOSSY channel (arbitrary, adversarial       *)
(* network partitions that may never heal within a bounded prefix of the    *)
(* run).  Every author is also a full replica node (as in Secure            *)
(* Scuttlebutt): it authors its own append-only chain locally and           *)
(* replicates every OTHER author's chain from peers.                        *)
(*                                                                          *)
(* The defining property of this replication discipline -- distinguishing  *)
(* it from a flat CRDT op-log union (already modeled in StreamingDB.tla) -- *)
(* is CAUSAL COMPLETENESS: a peer may only accept event (a, seq) once it    *)
(* already holds (a, seq-1).  Gossip therefore ships each author's range in *)
(* order (the "next missing item" of some author's prefix) rather than an  *)
(* arbitrary subset -- exactly the range-based reconciliation / hypercore   *)
(* replication contract.  This file proves that discipline never lets a    *)
(* peer hold an event without its causal predecessor (CausallyClosed), and *)
(* that despite the lossy channel dropping/delaying arbitrary deliveries    *)
(* (modeled as adversarial Partition), peers reach the SAME reachable event *)
(* set once the network heals and anti-entropy is retried fairly           *)
(* (Completeness, <>[]AllConverged) -- eventual completeness under a lossy  *)
(* channel, not merely under a reliable one.                                *)
(*                                                                          *)
(* Proven by TLC (exhaustive over every interleaving of authoring,          *)
(* gossiping, partitioning and healing):                                    *)
(*   - CausallyClosed   : a replica never holds (a, seq) without also       *)
(*                        holding (a, seq-1) -- the reachable event set is  *)
(*                        always causally closed (the hash-link "prev"      *)
(*                        completeness a range-sync/hypercore peer must     *)
(*                        maintain at every step, not just at quiescence).  *)
(*   - LogSubsetOfWritten / NoLostWrite : replication never invents or      *)
(*                        loses an event.                                   *)
(*   - Completeness (liveness) : <>[]AllConverged -- after arbitrarily many *)
(*                        Partition/Heal cycles, once authoring quiesces    *)
(*                        and anti-entropy + healing are fair, every peer   *)
(*                        converges to, and stays at, the identical         *)
(*                        reachable event set.                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Authors,   \* the set of peers; each peer is both an author and a full replica
    MaxSeq,    \* per-author chain length bound, to keep the model finite
    NumParts   \* model bound: max number of concurrent network partitions

ASSUME AuthorsNonEmpty == Authors # {}
ASSUME MaxSeqPos       == MaxSeq \in Nat /\ MaxSeq > 0
ASSUME NumPartsPos     == NumParts \in Nat \ {0}

PartIds == 1 .. NumParts

\* Content-address id of the event authored at (a, n).
Id(a, n) == [auth |-> a, seq |-> n]

\* Every id that can ever exist in a bounded run.
AllIds == { Id(a, n) : a \in Authors, n \in 0..(MaxSeq - 1) }

VARIABLES
    log,      \* log[n]    : SUBSET AllIds -- the reachable event set replica n holds
    height,   \* height[a] : the next unused seq for author a (its own chain length)
    part,     \* part[n]   : PartId -- the network partition replica n is currently in
    written   \* ghost: every id ever authored, anywhere

vars == <<log, height, part, written>>

TypeOK ==
    /\ log     \in [Authors -> SUBSET AllIds]
    /\ height  \in [Authors -> 0..MaxSeq]
    /\ part    \in [Authors -> PartIds]
    /\ written \subseteq AllIds

Init ==
    /\ log     = [n \in Authors |-> {}]
    /\ height  = [a \in Authors |-> 0]
    /\ part    = [n \in Authors |-> 1]   \* start fully connected
    /\ written = {}

------------------------------------------------------------------------------
(* ACTIONS *)

\* Author a originates its own next event locally. It always already holds
\* every one of its own prior events (its own log is updated directly here),
\* so an author's own chain is trivially causally complete at its origin.
Write(a) ==
    LET n == height[a]
    IN  /\ n < MaxSeq
        /\ log'     = [log EXCEPT ![a] = @ \cup {Id(a, n)}]
        /\ height'  = [height EXCEPT ![a] = n + 1]
        /\ written' = written \cup {Id(a, n)}
        /\ UNCHANGED part

\* Range-based anti-entropy: n ships ONE causally-ready id that m is missing.
\* "Causally ready" means m already holds that id's immediate predecessor (or
\* the id is a genesis event, seq = 0) -- exactly the hypercore / SSB-EBT
\* discipline of replicating a peer's range strictly in seq order, never a
\* gap. Only enabled within the same network partition -- the lossy channel.
Gossip(n, m) ==
    /\ n # m
    /\ part[n] = part[m]
    /\ \E id \in log[n] \ log[m] :
           /\ \/ id.seq = 0
              \/ Id(id.auth, id.seq - 1) \in log[m]
           /\ log' = [log EXCEPT ![m] = @ \cup {id}]
    /\ UNCHANGED <<height, part, written>>

\* Network splits into an arbitrary partitioning (adversarial, models drops).
Partition ==
    /\ part' \in [Authors -> PartIds]
    /\ UNCHANGED <<log, height, written>>

\* Network heals: everyone back in one partition. Fair (see Fairness below).
Heal ==
    /\ part # [n \in Authors |-> 1]
    /\ part' = [n \in Authors |-> 1]
    /\ UNCHANGED <<log, height, written>>

Next ==
    \/ \E a \in Authors    : Write(a)
    \/ \E n, m \in Authors : Gossip(n, m)
    \/ Partition
    \/ Heal

\* Anti-entropy is STRONGLY fair per replica pair, and healing is strongly
\* fair. Strong fairness is required, not weak: an adversarial partition
\* leaves a given deliverable Gossip(n, m) step enabled only intermittently
\* (disabled whenever n, m are split), and weak fairness makes no promise
\* about a step merely enabled infinitely often -- it does about one that is
\* CONTINUOUSLY enabled from some point on, which a perpetually re-splitting
\* adversary never grants. Strong fairness does: every Heal re-enables it, so
\* it is eventually taken and the event is delivered. Writes need no
\* fairness (finite: each author's chain saturates at MaxSeq); once writing
\* and partitioning cease to matter, fair Gossip/Heal drive every replica to
\* the same fixed point -- what makes Completeness provable below.
Fairness ==
    /\ \A n, m \in Authors : SF_vars(Gossip(n, m))
    /\ SF_vars(Heal)

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* CAUSAL COMPLETENESS: a replica never holds (a, seq) without also holding
\* (a, seq-1) -- the reachable event set is always causally closed. This is
\* the hallmark of hash-linked replication (hypercore/SSB-EBT range sync):
\* a peer can be BEHIND, but it can never be causally INCONSISTENT.
CausallyClosed ==
    \A n \in Authors : \A id \in log[n] :
        id.seq > 0 => Id(id.auth, id.seq - 1) \in log[n]

\* Grow-only replication: a replica's log is always a subset of everything
\* ever written, and every written event is still held somewhere.
LogSubsetOfWritten == \A n \in Authors : log[n] \subseteq written
NoLostWrite        == \A id \in written : \E n \in Authors : id \in log[n]

\* An author always fully holds its own authored chain (trivially, since
\* Write updates the author's own log directly) -- it never needs to sync
\* its own events in from a peer.
SelfComplete ==
    \A a \in Authors :
        { id \in log[a] : id.auth = a } = { Id(a, s) : s \in 0..(height[a] - 1) }

------------------------------------------------------------------------------
(* LIVENESS: EVENTUAL COMPLETENESS UNDER A LOSSY CHANNEL *)

\* All replicas hold identical reachable event sets.
AllConverged == \A n, m \in Authors : log[n] = log[m]

\* Despite arbitrarily many adversarial Partition/Heal cycles (arbitrarily
\* many dropped/delayed deliveries), once authoring quiesces and anti-entropy
\* + healing are fair, every replica converges to -- and stays at -- the same
\* reachable event set.
Completeness == <>[]AllConverged

===============================================================================
