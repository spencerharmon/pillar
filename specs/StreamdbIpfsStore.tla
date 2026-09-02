------------------------------ MODULE StreamdbIpfsStore ------------------------------
(***************************************************************************)
(* Pillar IPFS/libp2p content-object store surface (ROI P1, method #1).    *)
(*                                                                         *)
(* Per non-negotiable #5 (P2P-preferred), the IPFS/libp2p plugin OWNS       *)
(* content-addressing and durable object storage over pillar's OWN         *)
(* PRIVATE libp2p swarm -- OFF the public IPFS DHT.  This model is the      *)
(* plugin-owned surface the streaming DB (StreamingDB.tla) rides beneath   *)
(* it: put/get by CID, pin + provide anchors to the swarm's own Kademlia,  *)
(* and an IPNS-format mutable head (signed, sequence-numbered,             *)
(* visibility-scoped) a restarting node trusts to find the latest state.   *)
(* The streaming DB never re-implements content-addressing on local disk;  *)
(* this module is the durable content-object + head layer StreamingDB's    *)
(* op-log is built on top of.                                              *)
(*                                                                         *)
(* Four things are proven by TLC here:                                     *)
(*                                                                         *)
(*  1. Content addressing is correct and immutable.  A CID resolves only   *)
(*     to the exact bytes whose (injective, model-supplied) Hash it is     *)
(*     (ContentAddressCorrect), and once an object is written at a CID it  *)
(*     is never overwritten with different content (ObjectImmutable) --    *)
(*     no collision or mutation ever substitutes a segment.                *)
(*                                                                         *)
(*  2. The IPNS-format mutable head is safe.  A resolved head's sequence   *)
(*     number never regresses (HeadSequenceMonotonic: a stale/replayed     *)
(*     lower-sequence head can never be accepted because the publish       *)
(*     action itself is guarded on seq > last-accepted), and a head is     *)
(*     only ever recorded as signed by its own owning key -- never a       *)
(*     forged signer (HeadSignedByOwner).                                  *)
(*                                                                         *)
(*  3. The DHT boundary holds (AnchorsOnlyToDHT).  Only segment/anchor      *)
(*     roots (AnchorCids) are ever provided to the swarm's own Kademlia --  *)
(*     never every op -- and a cell/encrypted-visibility owner's head is   *)
(*     NEVER marked published to the DHT (it stays in the cell, modelled   *)
(*     here as the pubsub-only path by simply never touching the DHT       *)
(*     flag); only a public-visibility owner's head may be.                *)
(*                                                                         *)
(*  4. Backfill reconverges (BackfillReconverges).  A node missing a       *)
(*     reachable anchor (pinned + provided by some live peer) eventually   *)
(*     retrieves and pins it, despite arbitrarily many adversarial         *)
(*     network Partition/Heal cycles, so long as Backfill/Heal are fair --  *)
(*     liveness under a lossy private-swarm link.                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,        \* set of participating node identities (the private swarm)
    Segments,     \* finite set of possible segment contents, each ITS OWN
                  \* real multihash (Hash below is the identity function on
                  \* this set) -- a model value stands in for "the bytes",
                  \* so distinct model values are, by construction, distinct
                  \* content: exactly the property real content addressing
                  \* (sha2/blake3) gives for distinct byte strings.
    AnchorCids,   \* SUBSET Segments: segment/anchor roots eligible for DHT provide
    PublicOwners, \* SUBSET Nodes: owners whose IPNS head is public-visibility
                  \* (MAY reach the DHT); every other node is cell-visibility
                  \* (its head must never reach the DHT) -- a set constant,
                  \* not a function constant, because TLC's .cfg format has
                  \* no literal syntax for an arbitrary function value.
    NumParts,     \* model bound: max number of concurrent network partitions
    MaxSeq,       \* model bound on IPNS head sequence numbers
    Nil,          \* sentinel: "no content"/"no head published yet"
    None          \* sentinel: "no signer recorded"

\* Content ids ARE segments here: Hash is the identity function, so "CID" and
\* "segment" below are the same model value wearing two names. This is a
\* deliberate simplification (TLC cannot model-check an arbitrary function
\* CONSTANT in a .cfg file), not a weakening of ContentAddressCorrect: the
\* real property under test is that objects[cid] never holds a DIFFERENT
\* segment than the one written at that cid (see ObjectImmutable), which
\* holds regardless of whether Hash is the identity or a real multihash.
CIDs == Segments
Hash(s) == s

\* Owner o's IPNS visibility class: "public" (head MAY reach the DHT) or
\* "cell" (head must NEVER reach the DHT) -- see PublicOwners above.
Visibility(o) == IF o \in PublicOwners THEN "public" ELSE "cell"

ASSUME NodesNonEmpty      == Nodes # {}
ASSUME AnchorCidsSubset   == AnchorCids \subseteq CIDs
ASSUME PublicOwnersSubset == PublicOwners \subseteq Nodes
ASSUME NumPartsPos        == NumParts \in Nat \ {0}
ASSUME MaxSeqPos          == MaxSeq \in Nat /\ MaxSeq > 0
ASSUME NilNotSegment      == Nil \notin Segments
ASSUME NoneNotNode        == None \notin Nodes

PartIds == 1 .. NumParts

\* Every owning identity is itself a swarm node signing its own head.
Owners == Nodes

VARIABLES
    objects,      \* objects[cid]    : the segment stored at cid, or Nil if none
    pinned,       \* pinned[n]       : SUBSET CIDs -- n's local durable pin set
    providers,    \* providers[cid]  : SUBSET Nodes -- swarm-Kademlia provider records
    part,         \* part[n]         : PartId -- the network partition n is in
    headSeq,      \* headSeq[o]      : last accepted IPNS sequence number for owner o
    headCid,      \* headCid[o]      : CID the last accepted head points at, or Nil
    headSigner,   \* headSigner[o]   : key that signed the last accepted head, or None
    headOnDHT     \* headOnDHT[o]    : whether o's current head is published to the DHT

vars == <<objects, pinned, providers, part, headSeq, headCid, headSigner, headOnDHT>>

------------------------------------------------------------------------------
(* INITIAL STATE                                                            *)

Init ==
    /\ objects    = [cid \in CIDs |-> Nil]
    /\ pinned     = [n \in Nodes |-> {}]
    /\ providers  = [cid \in CIDs |-> {}]
    /\ part       = [n \in Nodes |-> 1]      \* start fully connected
    /\ headSeq    = [o \in Owners |-> 0]
    /\ headCid    = [o \in Owners |-> Nil]
    /\ headSigner = [o \in Owners |-> None]
    /\ headOnDHT  = [o \in Owners |-> FALSE]

------------------------------------------------------------------------------
(* CONTENT-OBJECT ACTIONS (put / pin / provide / backfill-get)              *)

\* put(segment) -> CID.  Content-addressed store: writes s at its real
\* multihash Hash(s), and durably pins it for n in the same step -- put
\* always retains what it stored (a node never has to re-fetch its own
\* write).  Guarded to never fire twice at the same cid, so an object,
\* once written, is never overwritten (see ObjectImmutable below): there is
\* no separate "get" action because reading is simply pinned-set/objects
\* membership, not a state transition (the same modelling choice StreamingDB
\* and AntiEntropy make for their own read paths).
Put(n, s) ==
    LET cid == Hash(s) IN
        /\ objects[cid] = Nil
        /\ objects'   = [objects EXCEPT ![cid] = s]
        /\ pinned'    = [pinned  EXCEPT ![n]   = @ \cup {cid}]
        /\ UNCHANGED <<providers, part, headSeq, headCid, headSigner, headOnDHT>>

\* provide(CID): n advertises an anchor/segment root it holds to the swarm's
\* OWN Kademlia so peers can backfill it.  Guarded to anchors only -- every
\* op is never individually provided to the DHT (AnchorsOnlyToDHT).
Provide(n, cid) ==
    /\ cid \in AnchorCids
    /\ cid \in pinned[n]
    /\ providers' = [providers EXCEPT ![cid] = @ \cup {n}]
    /\ UNCHANGED <<objects, pinned, part, headSeq, headCid, headSigner, headOnDHT>>

\* get(CID) backfill path: n is missing an anchor whose provider m holds it
\* pinned.  Only enabled within the same network partition (the private
\* swarm's own lossy link) and only for a peer m that actually advertised
\* (providers[cid]) -- exactly "backfill from a providing peer" per the
\* design doc.  n durably pins the retrieved content.
Backfill(n, m, cid) ==
    /\ n # m
    /\ part[n] = part[m]
    /\ cid \in AnchorCids
    /\ m \in providers[cid]
    /\ cid \in pinned[m]
    /\ cid \notin pinned[n]
    /\ pinned' = [pinned EXCEPT ![n] = @ \cup {cid}]
    /\ UNCHANGED <<objects, providers, part, headSeq, headCid, headSigner, headOnDHT>>

------------------------------------------------------------------------------
(* IPNS-FORMAT MUTABLE HEAD                                                 *)

\* ipns_publish(head): owner's signed, sequence-numbered, TTL-format head
\* (TTL modelled structurally by requiring strict advance, not wall-clock).
\* signer is a free choice so an adversary MAY attempt to forge a publish
\* under a different key -- the guard signer = owner is what makes a forged
\* publish simply never take effect (HeadSignedByOwner).  Likewise seq must
\* strictly exceed the last accepted sequence -- a stale/replayed lower-
\* sequence head is never enabled (HeadSequenceMonotonic).  A cell/encrypted
\* owner's onDht choice is guarded to FALSE: the cell head only ever
\* travels inside the cell over pubsub, never onto the public-reachable
\* DHT (AnchorsOnlyToDHT); a public owner's head MAY be marked onDht.
IpnsPublish(owner, cid, seq, signer, onDht) ==
    /\ signer = owner
    /\ seq > headSeq[owner]
    /\ objects[cid] # Nil
    /\ Visibility(owner) = "cell" => onDht = FALSE
    /\ headSeq'    = [headSeq    EXCEPT ![owner] = seq]
    /\ headCid'    = [headCid    EXCEPT ![owner] = cid]
    /\ headSigner' = [headSigner EXCEPT ![owner] = signer]
    /\ headOnDHT'  = [headOnDHT  EXCEPT ![owner] = onDht]
    /\ UNCHANGED <<objects, pinned, providers, part>>

------------------------------------------------------------------------------
(* NETWORK (adversarial partition/heal, as in StreamingDB / AntiEntropy)    *)

Partition ==
    /\ part' \in [Nodes -> PartIds]
    /\ UNCHANGED <<objects, pinned, providers, headSeq, headCid, headSigner, headOnDHT>>

Heal ==
    /\ part # [n \in Nodes |-> 1]
    /\ part' = [n \in Nodes |-> 1]
    /\ UNCHANGED <<objects, pinned, providers, headSeq, headCid, headSigner, headOnDHT>>

------------------------------------------------------------------------------
(* COMPOSED NEXT-STATE RELATION                                             *)

Next ==
    \/ \E n \in Nodes, s \in Segments                            : Put(n, s)
    \/ \E n \in Nodes, cid \in CIDs                                : Provide(n, cid)
    \/ \E n, m \in Nodes, cid \in CIDs                              : Backfill(n, m, cid)
    \/ Partition
    \/ Heal
    \/ \E o \in Owners, cid \in CIDs, seq \in 1 .. MaxSeq,
          signer \in Nodes, onDht \in BOOLEAN                       : IpnsPublish(o, cid, seq, signer, onDht)

\* Backfill and Heal are STRONGLY fair (same rationale as StreamingDB /
\* AntiEntropy): an adversary that partitions and heals forever leaves a
\* given deliverable Backfill enabled only intermittently, so weak fairness
\* promises nothing -- strong fairness does, since every Heal re-enables it.
\* Provide is also strongly fair so an anchor that is pinned but never
\* advertised does not stall Backfill's precondition forever. Put and
\* IpnsPublish need no fairness: both are inherently finite (each cid is
\* written at most once; sequence numbers are bounded by MaxSeq), so once
\* they cease, fair Provide/Backfill/Heal drive the reachable content to a
\* fixed point -- what makes BackfillReconverges provable.
Fairness ==
    /\ \A n, m \in Nodes, cid \in CIDs : SF_vars(Backfill(n, m, cid))
    /\ \A n \in Nodes, cid \in CIDs    : SF_vars(Provide(n, cid))
    /\ SF_vars(Heal)

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                         *)

TypeOK ==
    /\ objects    \in [CIDs -> Segments \cup {Nil}]
    /\ pinned     \in [Nodes -> SUBSET CIDs]
    /\ providers  \in [CIDs -> SUBSET Nodes]
    /\ part       \in [Nodes -> PartIds]
    /\ headSeq    \in [Owners -> 0 .. MaxSeq]
    /\ headCid    \in [Owners -> CIDs \cup {Nil}]
    /\ headSigner \in [Owners -> Nodes \cup {None}]
    /\ headOnDHT  \in [Owners -> BOOLEAN]

------------------------------------------------------------------------------
(* CONTENT-ADDRESSING SAFETY                                                *)

\* get(put(s)) = s: a stored cid's content is exactly the segment whose
\* real Hash it is -- no collision or substitution is ever reachable.
ContentAddressCorrect ==
    \A cid \in CIDs : objects[cid] # Nil => Hash(objects[cid]) = cid

\* Append-only / immutable-once-written: a step never changes an already
\* -written object's content (the content-addressed store never mutates a
\* CID's bytes underneath a holder).  Same style as StreamingDB's
\* MonotonicLog action property.
ObjectImmutable ==
    [][ \A cid \in CIDs : objects[cid] # Nil => objects'[cid] = objects[cid] ]_vars

------------------------------------------------------------------------------
(* IPNS HEAD SAFETY                                                         *)

\* A resolved head's sequence number never regresses across a step.
HeadSequenceMonotonic ==
    [][ \A o \in Owners : headSeq[o] <= headSeq'[o] ]_vars

\* Only the owner's own key is ever recorded as having signed the current
\* accepted head -- a forged signer can never make it into headSigner.
HeadSignedByOwner ==
    \A o \in Owners : headSeq[o] > 0 => headSigner[o] = o

------------------------------------------------------------------------------
(* DHT BOUNDARY SAFETY                                                      *)

\* Only anchor/segment roots are ever provided to the swarm's own DHT, and a
\* cell/encrypted owner's head is never marked as published to it.
AnchorsOnlyToDHT ==
    /\ \A cid \in CIDs : providers[cid] # {} => cid \in AnchorCids
    /\ \A o \in Owners  : Visibility(o) = "cell" => headOnDHT[o] = FALSE

------------------------------------------------------------------------------
(* BACKFILL LIVENESS                                                        *)

\* Every node holds every anchor that is reachable (pinned + advertised by
\* some live peer).
AllBackfilled ==
    \A n \in Nodes, cid \in AnchorCids : providers[cid] # {} => cid \in pinned[n]

\* Despite arbitrarily many adversarial Partition/Heal cycles, once writes/
\* provides/publishes quiesce and Backfill/Provide/Heal are fair, every node
\* eventually retrieves -- and keeps -- every reachable anchor.
BackfillReconverges == <>[]AllBackfilled

===============================================================================
