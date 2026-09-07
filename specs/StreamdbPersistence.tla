------------------------- MODULE StreamdbPersistence -------------------------
(***************************************************************************)
(* Pillar IPFS-backed durable streaming-DB PERSISTENCE (ROI P1, method #1). *)
(*                                                                          *)
(* The 2026-08-31 audit ROI correction REVERSES the earlier "no TLA+       *)
(* change" folding recorded against streamdb-persistence-impl: IPFS-backed *)
(* persistence adds real authority-bearing behaviour that neither           *)
(* StreamingDB.tla (the AP op-log) nor StreamdbIpfsStore.tla (the abstract *)
(* content-object/IPNS-head store surface) covers on its own -- namely,     *)
(* WHAT is pinned, and how a node with an EMPTY local disk (a restart or a  *)
(* full replacement) rehydrates its materialized view PURELY from IPFS-    *)
(* pinned sealed segments plus its own custody-held private key, with no    *)
(* other durable input.  This spec models that rehydration contract on top *)
(* of the store surface StreamdbIpfsStore.tla already proves.               *)
(*                                                                          *)
(* Durable state, precisely:                                                *)
(*   - Sealed, content-addressed SEGMENTS, pinned to IPFS (durable,         *)
(*     grow-only -- once pinned, never unpinned in this model, matching     *)
(*     "durability" as a property that is never revoked by this protocol).  *)
(*   - A single IPNS-format mutable HEAD: a sequence-numbered pointer whose *)
(*     value at each sequence is the exact segment set that was durable     *)
(*     (pinned) at the moment that sequence was published -- an            *)
(*     append-only "durability watermark" chain.                            *)
(*   - Each node's own CUSTODY-HELD private key (modeled as a value drawn   *)
(*     from a universe DISJOINT from Segments) -- used locally to unseal    *)
(*     the sealed cell key and decrypt the log, but NEVER written to any    *)
(*     IPFS-facing variable (pinned segments or head contents).             *)
(*                                                                          *)
(* NOT durable / fully derived:                                             *)
(*   - Each node's local materialized VIEW (op-cache) -- rebuildable in     *)
(*     full from the pinned segments the current head resolves to.  Wiping *)
(*     it (a crash, a disk replacement) loses nothing durable.              *)
(*                                                                          *)
(* Proven by TLC:                                                          *)
(*   - RehydrateReconverges (<>[]): a node whose local disk is wiped        *)
(*     (bounded number of wipes, as in a real deployment) and that then     *)
(*     rehydrates PURELY from the IPFS-pinned segments its head resolves    *)
(*     to, plus its custody-held key, eventually reconverges to -- and      *)
(*     stays at -- the same view every continuously-live (never-wiped)      *)
(*     node reaches by tailing the durable pinned set.                     *)
(*   - NoLostWrite: every segment set ever published at any head sequence   *)
(*     remains a subset of the durable pinned set forever (an acknowledged  *)
(*     write -- pinned + referenced by a published head -- is never lost).  *)
(*   - HeadSequenceMonotonic: the head sequence a node has actually synced  *)
(*     to (via rehydrate or live tailing) never regresses -- a restarting   *)
(*     node never adopts a STALE head older than one it already saw.        *)
(*   - NodeKeyNeverOnIPFS: the custody-held node private-key universe never *)
(*     appears in the pinned set or in any published head contents -- ONLY *)
(*     sealed segments (which include the sealed, recipient-encrypted cell  *)
(*     key blob) are ever pinned/provided; the node's own private key is    *)
(*     custody-held only, never on IPFS.                                    *)
(*   - ViewIsDerived: a node's local materialized view is always a subset   *)
(*     of the durable pinned set -- it holds no state absent from IPFS, so  *)
(*     it is fully rebuildable and wiping it is always safe.                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,      \* participating node identities
    Segments,   \* finite universe of sealed, content-addressed segment ids
                \* (each a distinct Nat; includes ordinary sealed log segments
                \* AND the sealed, recipient-encrypted cell-key blob -- both
                \* are equally just "pinned content objects" at this layer)
    NodeKeys,   \* universe of custody-held node private keys -- DISJOINT
                \* from Segments; a value here must NEVER be written to any
                \* IPFS-facing variable (pinned / headSegs)
    MaxSeq,     \* model bound on IPNS-format head sequence numbers
    MaxWipes    \* model bound on the number of local-disk wipes per node
                \* (a real node crashes/replaces a bounded number of times
                \* per model run -- mirrors how Put()/AdvanceHead saturate)

ASSUME NodesNonEmpty     == Nodes # {}
ASSUME SegmentsAreNats   == Segments \subseteq Nat
ASSUME NodeKeysDisjoint  == NodeKeys \cap Segments = {}
ASSUME MaxSeqPos         == MaxSeq \in Nat /\ MaxSeq > 0
ASSUME MaxWipesNat       == MaxWipes \in Nat

Seqs == 0 .. MaxSeq

VARIABLES
    pinned,       \* SUBSET (Segments \cup NodeKeys) -- IPFS-durable pinned
                  \* content, grow-only.  Typed over the WIDER universe (not
                  \* just Segments) so NodeKeyNeverOnIPFS is a genuine,
                  \* TLC-checked fact about every action in Next -- never
                  \* vacuously true purely from a narrower declared type.
    headSeq,      \* Nat -- current published IPNS-format head sequence
    headSegs,      \* [Seqs -> SUBSET (Segments \cup NodeKeys)] -- the exact
                  \* durable (pinned) set the head referenced AT the moment
                  \* each sequence was published; an append-only watermark
                  \* chain (headSegs[s] for s <= headSeq is fixed forever)
    view,         \* [Nodes -> SUBSET (Segments \cup NodeKeys)] -- each
                  \* node's local materialized view (derived, rebuildable)
    wiped,        \* [Nodes -> BOOLEAN] -- TRUE while a node's local disk has
                  \* been wiped and it has not yet rehydrated
    wipeCount,    \* [Nodes -> 0..MaxWipes] -- wipes consumed so far per node
    lastSeqSeen,  \* [Nodes -> Seqs] -- the highest head sequence a node has
                  \* actually synced to (via rehydrate or live tailing)
    written       \* ghost: every segment ever sealed+pinned, anywhere

vars == <<pinned, headSeq, headSegs, view, wiped, wipeCount, lastSeqSeen, written>>

------------------------------------------------------------------------------
(* TYPE CORRECTNESS *)

TypeOK ==
    /\ pinned      \subseteq (Segments \cup NodeKeys)
    /\ headSeq     \in Seqs
    /\ headSegs    \in [Seqs -> SUBSET (Segments \cup NodeKeys)]
    /\ view        \in [Nodes -> SUBSET (Segments \cup NodeKeys)]
    /\ wiped       \in [Nodes -> BOOLEAN]
    /\ wipeCount   \in [Nodes -> 0..MaxWipes]
    /\ lastSeqSeen \in [Nodes -> Seqs]
    /\ written      \subseteq Segments

------------------------------------------------------------------------------
(* INITIAL STATE *)

Init ==
    /\ pinned      = {}
    /\ headSeq     = 0
    /\ headSegs    = [s \in Seqs |-> {}]
    /\ view        = [n \in Nodes |-> {}]
    /\ wiped       = [n \in Nodes |-> FALSE]
    /\ wipeCount   = [n \in Nodes |-> 0]
    /\ lastSeqSeen = [n \in Nodes |-> 0]
    /\ written     = {}

------------------------------------------------------------------------------
(* DURABLE-STORE-SIDE ACTIONS (the IPFS pin + IPNS-head watermark) *)

\* Seal(seg): a fresh sealed segment (or the sealed cell-key blob) is pinned
\* to IPFS.  Durable and grow-only -- once pinned it is never unpinned; this
\* is precisely what "durable" means for this protocol.
Seal(seg) ==
    /\ seg \in Segments
    /\ seg \notin pinned
    /\ pinned'  = pinned \cup {seg}
    /\ written' = written \cup {seg}
    /\ UNCHANGED <<headSeq, headSegs, view, wiped, wipeCount, lastSeqSeen>>

\* AdvanceHead: publish the next IPNS-format head sequence, watermarking it to
\* EXACTLY the durable (pinned) set at this moment.  Because pinned only
\* grows, headSegs[headSeq] (the previous watermark) is necessarily a subset
\* of the new watermark -- the chain is append-only by construction, which is
\* what makes HeadSegsMonotonic (folded into NoLostWrite below) provable.
AdvanceHead ==
    /\ headSeq < MaxSeq
    /\ headSegs' = [headSegs EXCEPT ![headSeq + 1] = pinned]
    /\ headSeq'  = headSeq + 1
    /\ UNCHANGED <<pinned, view, wiped, wipeCount, lastSeqSeen, written>>

------------------------------------------------------------------------------
(* NODE-SIDE ACTIONS: live tailing, crash/wipe, and pure-IPFS rehydration *)

\* IngestPinned(n): a live, never-wiped node continuously tails the durable
\* pinned set (its local view catches up to everything currently pinned --
\* the "continuously-gossiped view" RehydrateReconverges compares against),
\* and records that it has synced up to the current head sequence.
IngestPinned(n) ==
    /\ ~wiped[n]
    /\ (view[n] # pinned \/ lastSeqSeen[n] # headSeq)
    /\ view'        = [view        EXCEPT ![n] = pinned]
    /\ lastSeqSeen' = [lastSeqSeen EXCEPT ![n] = headSeq]
    /\ UNCHANGED <<pinned, headSeq, headSegs, wiped, wipeCount, written>>

\* Wipe(n): n's local disk is wiped (crash, replacement) -- its view is fully
\* discarded.  Bounded by MaxWipes per node, mirroring how Seal/AdvanceHead
\* are themselves finite; this is what lets fair rehydration eventually
\* dominate and RehydrateReconverges hold FOREVER, not merely infinitely often
\* (an unbounded, ever-recurring wipe could otherwise re-break convergence
\* after every reconvergence, exactly as an unbounded destructive action
\* would in any of the sibling specs' Partition/Heal-style liveness proofs).
Wipe(n) ==
    /\ ~wiped[n]
    /\ wipeCount[n] < MaxWipes
    /\ wiped'     = [wiped     EXCEPT ![n] = TRUE]
    /\ wipeCount' = [wipeCount EXCEPT ![n] = @ + 1]
    /\ view'      = [view      EXCEPT ![n] = {}]
    /\ UNCHANGED <<pinned, headSeq, headSegs, lastSeqSeen, written>>

\* Rehydrate(n): n rebuilds its ENTIRE materialized view purely from IPFS --
\* resolve the current IPNS-format head, fetch the pinned segments it
\* references, unseal the sealed cell key with n's OWN custody-held private
\* key (a purely local operation that never touches, and is never recorded
\* into, pinned/headSegs), then decrypt.  No other durable input is used.
Rehydrate(n) ==
    /\ wiped[n]
    /\ view'        = [view        EXCEPT ![n] = headSegs[headSeq]]
    /\ lastSeqSeen' = [lastSeqSeen EXCEPT ![n] = headSeq]
    /\ wiped'       = [wiped       EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<pinned, headSeq, headSegs, wipeCount, written>>

------------------------------------------------------------------------------
(* NEXT-STATE RELATION *)

Next ==
    \/ \E seg \in Segments : Seal(seg)
    \/ AdvanceHead
    \/ \E n \in Nodes : Wipe(n)
    \/ \E n \in Nodes : IngestPinned(n)
    \/ \E n \in Nodes : Rehydrate(n)

\* IngestPinned and Rehydrate are STRONGLY fair per node.  Seal, AdvanceHead
\* and Wipe are all finite (Segments is finite, MaxSeq and MaxWipes bound the
\* others), so once they cease, fair tailing + fair rehydration drive every
\* node's view to the same durable pinned set -- an absorbing fixed point,
\* since neither pinned nor headSegs ever shrinks and Wipe is exhausted.  This
\* is the same discipline StreamingDB.tla / StreamdbIpfsStore.tla use for
\* their own Gossip/Backfill + Heal liveness proofs.
Fairness ==
    /\ \A n \in Nodes : SF_vars(IngestPinned(n))
    /\ \A n \in Nodes : SF_vars(Rehydrate(n))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY INVARIANTS *)

\* NO LOST WRITE: every segment set ever published at any head sequence
\* remains a subset of the durable pinned set forever -- an acknowledged
\* write (pinned + referenced by a published head) is never lost.  Because
\* pinned is grow-only and headSegs[s] was set to a PAST value of pinned,
\* this also encodes the append-only watermark chain (each watermark is,
\* and remains, a subset of the current durable set).
NoLostWrite == \A s \in Seqs : headSegs[s] \subseteq pinned

\* NODE KEY NEVER ON IPFS: the custody-held node-key universe never appears
\* in the pinned set or in any published head watermark -- only sealed
\* segments (including the sealed cell-key blob, itself a Segment) are ever
\* pinned/provided.  Checked over the WIDER declared type (TypeOK allows
\* pinned/headSegs to range over Segments \cup NodeKeys), so this is a real,
\* non-vacuous fact about every action in Next, not an artifact of a narrow
\* declared type.
NodeKeyNeverOnIPFS ==
    /\ pinned \cap NodeKeys = {}
    /\ \A s \in Seqs : headSegs[s] \cap NodeKeys = {}

\* VIEW IS DERIVED: a node's local materialized view always holds state that
\* is a subset of the durable pinned set -- it is fully rebuildable from IPFS
\* alone, so wiping it (Wipe) is always safe and loses nothing durable.
ViewIsDerived == \A n \in Nodes : view[n] \subseteq pinned

------------------------------------------------------------------------------
(* HEAD SEQUENCE MONOTONICITY (action property) *)

\* A restarting/tailing node never adopts a STALE head: the head sequence a
\* node has actually synced to (via IngestPinned or Rehydrate) never
\* regresses across any step.
HeadSequenceMonotonic ==
    [][ \A n \in Nodes : lastSeqSeen'[n] >= lastSeqSeen[n] ]_vars

------------------------------------------------------------------------------
(* LIVENESS: REHYDRATION RECONVERGENCE *)

\* Every non-wiped node's view equals the (fully durable) pinned set.
AllConverged == \A n \in Nodes : ~wiped[n] /\ view[n] = pinned

\* Despite an arbitrary (but bounded, per MaxWipes) number of local-disk
\* wipes, once sealing/head-publishing/wiping quiesce and tailing +
\* rehydration are fair, every node -- including one that wiped its disk and
\* rehydrated PURELY from IPFS-pinned segments plus its custody-held key --
\* reconverges to, and stays at, the same view every continuously-live node
\* reaches: no divergence from the live/gossiped state.
RehydrateReconverges == <>[]AllConverged

===============================================================================
