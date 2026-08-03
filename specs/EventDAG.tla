------------------------------- MODULE EventDAG -------------------------------
(***************************************************************************)
(* Pillar event order & integrity: PGP-signed events in a hash-linked      *)
(* Merkle DAG (the git / Certificate-Transparency / Secure-Scuttlebutt /   *)
(* hypercore pattern). Pillar ADOPTS this convention rather than inventing  *)
(* a new one; this spec is the formal contract it must satisfy (ROI P1,     *)
(* "Event order & integrity", method #1). SPEC ONLY -- no CP total order is *)
(* modeled here (that is supplied by the coordination core, CoordinationCore*)
(* .tla); this file governs the AP integrity structure of the append log.   *)
(*                                                                          *)
(* An event is authored by exactly one author, carries a `prev` hash-link   *)
(* to that author's immediately preceding event (the per-author linear      *)
(* chain), and a set of `parents` hash-links to the current tips of OTHER   *)
(* authors it observed (the cross-author causal / happens-before edges).    *)
(* Every event is CONTENT-ADDRESSED: its identity is a pure function of its  *)
(* content. We model the content-address of an event by the pair            *)
(* (author, seq) -- which, GIVEN the per-author linear-chain invariant       *)
(* proven below (at most one event per (author, seq)), is a faithful stand-  *)
(* in for a collision-resistant hash of the full content: identical content  *)
(* has an identical id and therefore DEDUPLICATES (re-broadcasting an event  *)
(* is idempotent -- `ReBroadcast` never grows the log), and a fork (two      *)
(* distinct events sharing one id) is impossible.                            *)
(*                                                                          *)
(* Proven by TLC (exhaustive over every interleaving of authors appending    *)
(* and re-broadcasting):                                                     *)
(*   PER-AUTHOR LINEAR CHAIN                                                  *)
(*   - UniquePerAuthorSeq  : total order per author + content-address dedup   *)
(*                           (no fork: one event per (author, seq)).         *)
(*   - NoGaps              : gap detection -- an event at seq n>0 implies its  *)
(*                           n-1 predecessor is present (a contiguous prefix).*)
(*   - PrevLinkIntegrity   : tamper-evidence -- every non-genesis event's     *)
(*                           `prev` hash-link points at exactly its           *)
(*                           (author, seq-1) predecessor, which exists.       *)
(*   CROSS-AUTHOR PARTIAL ORDER                                              *)
(*   - ParentsCrossAuthorAndExist : every `parents` hash-link references an   *)
(*                           existing event of a DIFFERENT author (no         *)
(*                           dangling link; cross-author causal edge).       *)
(*   - CausalMonotone     : happens-before (via `prev` and `parents`) is a    *)
(*                           STRICT partial order -- every link points strictly*)
(*                           backward in the insertion clock, so the DAG is    *)
(*                           acyclic (no event is its own ancestor).          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Authors     \* the set of event authors (each a distinct PGP identity)
CONSTANTS MaxSeq      \* per-author chain length bound, to keep the model finite

ASSUME AuthorsNonEmpty == Authors # {}
ASSUME MaxSeqPos       == MaxSeq \in Nat /\ MaxSeq > 0

\* Content-address id of the event authored at (a, n). A pair here; the
\* UniquePerAuthorSeq theorem makes it a faithful surrogate for a content hash.
Id(a, n) == [auth |-> a, seq |-> n]

\* Sentinel "no predecessor" id for a genesis event (seq 0). Deliberately
\* outside AllIds (its auth is not an Author, its seq is negative).
NoId == [auth |-> "NONE", seq |-> -1]

\* Every id that can ever exist in a bounded run.
AllIds == { Id(a, n) : a \in Authors, n \in 0..(MaxSeq - 1) }

\* An event record: author, per-author sequence number, the prev hash-link,
\* and the set of cross-author parent hash-links.
EventType ==
    [ auth    : Authors,
      seq     : 0..(MaxSeq - 1),
      prev    : AllIds \cup {NoId},
      parents : SUBSET AllIds ]

VARIABLES
    log,     \* the set of events published so far (the content-addressed DAG)
    height,  \* height[a]: the next unused seq for author a (its chain length)
    ts,      \* ts[id]: insertion clock stamped when id was first published, else -1
    clock    \* monotone global counter minting the next insertion timestamp

vars == <<log, height, ts, clock>>

TypeOK ==
    /\ log    \subseteq EventType
    /\ height \in [Authors -> 0..MaxSeq]
    /\ ts     \in [AllIds -> Int]
    /\ clock  \in Nat

Init ==
    /\ log    = {}
    /\ height = [a \in Authors |-> 0]
    /\ ts     = [i \in AllIds |-> -1]
    /\ clock  = 0

\* The current tip id of author b (meaningful only when height[b] > 0).
Tip(b) == Id(b, height[b] - 1)

\* APPEND: author a publishes its next event. `prev` chains to a's own
\* previous event (genesis -> NoId); `parents` observes the current tip of
\* every OTHER author that has published at least once -- the cross-author
\* causal edges. The event's content-address id (a, n) is stamped into the
\* insertion clock. Guarded by n < MaxSeq purely for finiteness.
AddEvent(a) ==
    LET n       == height[a]
        others  == { b \in Authors \ {a} : height[b] > 0 }
        parents == { Tip(b) : b \in others }
        prev    == IF n = 0 THEN NoId ELSE Id(a, n - 1)
        e       == [auth |-> a, seq |-> n, prev |-> prev, parents |-> parents]
    IN  /\ n < MaxSeq
        /\ log'    = log \cup {e}
        /\ height' = [height EXCEPT ![a] = n + 1]
        /\ ts'     = [ts EXCEPT ![Id(a, n)] = clock]
        /\ clock'  = clock + 1

\* RE-BROADCAST: gossip an already-published event again. Because the event is
\* content-addressed, re-adding it to the set is idempotent -- the log never
\* grows and no timestamp is re-stamped. This is the dedup property in action,
\* and keeps the model deadlock-free after every chain saturates.
ReBroadcast ==
    /\ log # {}
    /\ \E e \in log : log' = log \cup {e}
    /\ UNCHANGED <<height, ts, clock>>

Next ==
    \/ \E a \in Authors : AddEvent(a)
    \/ ReBroadcast

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* PER-AUTHOR LINEAR CHAIN + CONTENT-ADDRESS DEDUP: at most one event per
\* (author, seq). Two events sharing a content-address id ARE the same event;
\* there is no fork and no id collision. This is what makes each author's chain
\* a total order and re-broadcast a no-op.
UniquePerAuthorSeq ==
    \A e1 \in log, e2 \in log :
        (e1.auth = e2.auth /\ e1.seq = e2.seq) => e1 = e2

\* GAP DETECTION: an author's published seqs form a contiguous prefix 0..k-1.
\* Any event at seq n>0 witnesses the presence of its n-1 predecessor, so a
\* missing middle event is detectable as a broken chain.
NoGaps ==
    \A e \in log :
        e.seq > 0 => \E f \in log : f.auth = e.auth /\ f.seq = e.seq - 1

\* TAMPER-EVIDENCE: the `prev` hash-link is exactly the (author, seq-1)
\* predecessor (NoId for genesis), and that predecessor is present. A rewritten
\* or reordered history breaks this link.
PrevLinkIntegrity ==
    \A e \in log :
        /\ (e.seq = 0 => e.prev = NoId)
        /\ (e.seq > 0 =>
              /\ e.prev = Id(e.auth, e.seq - 1)
              /\ \E f \in log : f.auth = e.auth /\ f.seq = e.seq - 1)

\* CROSS-AUTHOR CAUSAL EDGES: every parent hash-link references an existing
\* event authored by a DIFFERENT author (no dangling reference, and prev owns
\* the same-author edge so parents carry only cross-author happens-before).
ParentsCrossAuthorAndExist ==
    \A e \in log : \A p \in e.parents :
        /\ p.auth # e.auth
        /\ \E f \in log : f.auth = p.auth /\ f.seq = p.seq

\* ACYCLIC HAPPENS-BEFORE (STRICT PARTIAL ORDER): every hash-link -- the
\* per-author `prev` and every cross-author `parent` -- points to an event with
\* a STRICTLY smaller insertion clock than the referencing event. Since the
\* happens-before relation is thus contained in the strict total order on `ts`,
\* it is irreflexive and acyclic: no event can be its own ancestor.
CausalMonotone ==
    \A e \in log :
        LET myTs == ts[Id(e.auth, e.seq)]
        IN  /\ myTs >= 0
            /\ (e.prev # NoId => ts[e.prev] >= 0 /\ ts[e.prev] < myTs)
            /\ \A p \in e.parents : ts[p] >= 0 /\ ts[p] < myTs

=============================================================================
