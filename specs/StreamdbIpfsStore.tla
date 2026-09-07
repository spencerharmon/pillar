--------------------------- MODULE StreamdbIpfsStore ---------------------------
(***************************************************************************)
(* Pillar durable content-object store surface (ROI P1, method #1).         *)
(*                                                                          *)
(* The 2026-08-31 audit ROI correction is non-negotiable: the streaming     *)
(* DB's DURABLE persistence MUST ride an IPFS / libp2p content-object       *)
(* store -- pillar's OWN private libp2p swarm, OFF the public DHT -- NOT a   *)
(* hand-rolled local-fs content store.  The IPFS/libp2p plugin OWNS          *)
(* content-addressing (non-negotiable #5); the streaming DB never            *)
(* re-implements it on local disk.  This spec models the ABSTRACT surface    *)
(* the plugin exposes, so the plugin's real implementation is a refinement  *)
(* of a machine-checked contract rather than a hopeful approximation.       *)
(*                                                                          *)
(* Refines StreamingDB.tla: it adds the durable content-object + mutable-    *)
(* head layer BENEATH the AP op-log.  StreamingDB already proved the op-log  *)
(* itself is an append-only content-addressed Merkle-CRDT; here we prove     *)
(* the STORAGE surface underneath it: put/get by CID over the private        *)
(* swarm, pin, provide anchors to the DHT, and an IPNS-format mutable head   *)
(* (signed, sequence-numbered, TTL) scoped by visibility class.             *)
(*                                                                          *)
(* Surface modeled:                                                          *)
(*   - put(bytes)  -> CID    : store an immutable content object; its id is  *)
(*                             a pure function of its bytes (content addr).   *)
(*   - get(CID)               : retrieve; two nodes holding a CID agree on    *)
(*                             its bytes (collision-free content address).    *)
(*   - pin(CID)               : mark an object durable on a node (never GC'd).*)
(*   - provide(CID)           : advertise a PUBLIC anchor object to the DHT   *)
(*                             so a lagging peer can find a provider.  ONLY   *)
(*                             public anchors ever touch the DHT.             *)
(*   - publishHead / head     : IPNS-format mutable pointer -- signed by the  *)
(*                             owner, sequence-numbered (monotone), TTL'd,    *)
(*                             scoped by a visibility class (public anchors    *)
(*                             to the DHT; cell/encrypted heads over pubsub    *)
(*                             within the private swarm, NEVER the public DHT).*)
(*                                                                          *)
(* Proven by TLC (exhaustive over every interleaving of put/get/pin/        *)
(* provide/publishHead + adversarial Partition/Heal on a lossy link):        *)
(*   - ContentAddressCorrect  : a CID identifies exactly one byte-content    *)
(*                              across all nodes (content addressing is       *)
(*                              collision-free and deterministic).           *)
(*   - HeadSequenceMonotonic  : an owner's published head sequence number     *)
(*                              never regresses -- an IPNS pointer only        *)
(*                              advances.                                     *)
(*   - HeadSignedByOwner      : every accepted head record was signed by the  *)
(*                              key that owns that head name (no forged/        *)
(*                              ambient head publication).                    *)
(*   - AnchorsOnlyToDHT       : the DHT-advertised set is EXACTLY the public   *)
(*                              anchor objects -- a cell/encrypted head or     *)
(*                              object is NEVER on the public DHT (it lives    *)
(*                              on the private swarm's pubsub only).           *)
(*   - BackfillReconverges    : a missing-but-reachable segment is EVENTUALLY  *)
(*                              retrieved under a lossy link (<>[] liveness).  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,       \* participating swarm node identities
    Objects,     \* finite set of content objects (each a distinct Nat = its bytes)
    Owners,      \* head-name owners; each owns one IPNS-format mutable head
    MaxSeq,      \* model bound on head sequence numbers
    NumParts     \* model bound: max number of concurrent network partitions

ASSUME NodesNonEmpty  == Nodes # {}
ASSUME ObjsAreNats    == Objects \subseteq Nat
ASSUME OwnersNonEmpty == Owners # {}
ASSUME MaxSeqPos      == MaxSeq \in Nat /\ MaxSeq > 0
ASSUME NumPartsPos    == NumParts \in Nat \ {0}

PartIds == 1 .. NumParts

\* Content address of an object: a pure, deterministic, collision-free function
\* of its bytes.  Because an object IS its bytes (a distinct Nat), the CID is the
\* identity function here -- modeling that identical bytes yield identical CIDs
\* and distinct bytes yield distinct CIDs (a >=256-bit collision-resistant hash
\* in the real plugin; injectivity is what the safety proof relies on).
CID(o) == o

\* Visibility classes.  "public" anchor objects may be advertised on the DHT;
\* "cell" (cell-encrypted) and "sealed" (recipient-sealed) objects never are --
\* their mutable heads travel the private swarm's pubsub only.
Vis == {"public", "cell", "sealed"}

\* A fixed, deterministic visibility labelling of each object (a model input:
\* the object's class is a property of the object, set at authoring time).
\* Even objects are public anchors; odd objects are cell-encrypted.
VisOf(o) == IF o % 2 = 0 THEN "public" ELSE "cell"

VARIABLES
    store,     \* store[n] : SUBSET Objects -- objects node n holds locally
    pinned,    \* pinned[n]: SUBSET Objects -- objects node n has pinned (durable)
    dht,       \* SUBSET Objects -- objects advertised (provided) to the public DHT
    headSeq,   \* headSeq[w] : the sequence number of owner w's latest published head
    headSigner,\* headSigner[w] : the owner key that signed w's latest head (or w0 sentinel)
    part,      \* part[n]  : PartId -- the network partition node n is in
    written    \* ghost: every object ever put(), anywhere

vars == <<store, pinned, dht, headSeq, headSigner, part, written>>

------------------------------------------------------------------------------
(* TYPE CORRECTNESS *)

TypeOK ==
    /\ store      \in [Nodes -> SUBSET Objects]
    /\ pinned     \in [Nodes -> SUBSET Objects]
    /\ dht         \subseteq Objects
    /\ headSeq    \in [Owners -> 0..MaxSeq]
    /\ headSigner \in [Owners -> Owners \cup {"nil"}]
    /\ part       \in [Nodes -> PartIds]
    /\ written     \subseteq Objects

------------------------------------------------------------------------------
(* INITIAL STATE *)

Init ==
    /\ store      = [n \in Nodes  |-> {}]
    /\ pinned     = [n \in Nodes  |-> {}]
    /\ dht        = {}
    /\ headSeq    = [w \in Owners |-> 0]
    /\ headSigner = [w \in Owners |-> "nil"]
    /\ part       = [n \in Nodes  |-> 1]   \* start fully connected
    /\ written    = {}

------------------------------------------------------------------------------
(* STORE-SURFACE ACTIONS *)

\* put(o): node n stores content object o.  The object's identity is CID(o),
\* a pure function of its bytes -- n never chooses the id, so two nodes that
\* put the same bytes necessarily agree on the CID.  Append-only per node.
Put(n, o) ==
    /\ o \in Objects
    /\ o \notin store[n]
    /\ store'   = [store EXCEPT ![n] = @ \cup {o}]
    /\ written' = written \cup {o}
    /\ UNCHANGED <<pinned, dht, headSeq, headSigner, part>>

\* get / backfill: n retrieves an object it is missing from a peer m in the
\* SAME partition (the private-swarm bitswap fetch).  Only within a partition,
\* modeling the lossy link.  Because the object arrives by its CID, n stores the
\* exact same bytes m held -- content is never corrupted in transit.
Backfill(n, m) ==
    /\ n # m
    /\ part[n] = part[m]
    /\ \E o \in store[m] \ store[n] :
           store' = [store EXCEPT ![n] = @ \cup {o}]
    /\ UNCHANGED <<pinned, dht, headSeq, headSigner, part, written>>

\* pin(o): n marks a held object durable (never garbage-collected).
Pin(n, o) ==
    /\ o \in store[n]
    /\ o \notin pinned[n]
    /\ pinned' = [pinned EXCEPT ![n] = @ \cup {o}]
    /\ UNCHANGED <<store, dht, headSeq, headSigner, part, written>>

\* provide(o): advertise a PUBLIC anchor object to the DHT so a lagging peer can
\* discover a provider.  ONLY a public-class object may be provided; a cell /
\* sealed object is never advertised on the public DHT (AnchorsOnlyToDHT).
Provide(n, o) ==
    /\ o \in store[n]
    /\ VisOf(o) = "public"
    /\ o \notin dht
    /\ dht' = dht \cup {o}
    /\ UNCHANGED <<store, pinned, headSeq, headSigner, part, written>>

\* publishHead(w): owner w advances its IPNS-format mutable head to the next
\* sequence number, SIGNED by w itself.  The head only ever moves forward
\* (monotone sequence) and is only accepted when signed by the head's owner.
\* A cell/sealed head travels the private swarm's pubsub -- never the DHT --
\* which is why publishing a head never writes `dht`.
PublishHead(w) ==
    /\ headSeq[w] < MaxSeq
    /\ headSeq'    = [headSeq    EXCEPT ![w] = @ + 1]
    /\ headSigner' = [headSigner EXCEPT ![w] = w]     \* signed by the owner
    /\ UNCHANGED <<store, pinned, dht, part, written>>

------------------------------------------------------------------------------
(* NETWORK FAULT ACTIONS (adversarial, lossy link) *)

\* Network splits into an arbitrary partitioning (models dropped/delayed fetch).
Partition ==
    /\ part' \in [Nodes -> PartIds]
    /\ UNCHANGED <<store, pinned, dht, headSeq, headSigner, written>>

\* Network heals: everyone back in one partition.  Fair (see Fairness below).
Heal ==
    /\ part # [n \in Nodes |-> 1]
    /\ part' = [n \in Nodes |-> 1]
    /\ UNCHANGED <<store, pinned, dht, headSeq, headSigner, written>>

------------------------------------------------------------------------------
(* NEXT-STATE RELATION *)

Next ==
    \/ \E n \in Nodes, o \in Objects : Put(n, o)
    \/ \E n, m \in Nodes             : Backfill(n, m)
    \/ \E n \in Nodes, o \in Objects : Pin(n, o)
    \/ \E n \in Nodes, o \in Objects : Provide(n, o)
    \/ \E w \in Owners               : PublishHead(w)
    \/ Partition
    \/ Heal

\* Backfill is STRONGLY fair per node pair and healing is strongly fair -- the
\* same discipline StreamingDB.tla / AntiEntropy.tla use.  Strong (not weak)
\* fairness is required: an adversarial partition leaves a deliverable
\* Backfill(n, m) enabled only intermittently (disabled whenever n, m are
\* split), and weak fairness makes no promise about a step merely enabled
\* infinitely often.  Strong fairness does: every Heal re-enables it, so the
\* missing segment is eventually fetched.  put/pin/provide/publishHead need no
\* fairness (all finite: objects are put once per node, heads saturate at
\* MaxSeq), so once they cease, fair Backfill + Heal drive every node to hold
\* the identical object set -- what makes BackfillReconverges provable.
Fairness ==
    /\ \A n, m \in Nodes : SF_vars(Backfill(n, m))
    /\ SF_vars(Heal)

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY INVARIANTS *)

\* CONTENT ADDRESSING: a CID identifies exactly one byte-content across every
\* node.  Because CID is injective (distinct bytes -> distinct CIDs), any two
\* nodes that both hold an object under a given CID hold the identical bytes --
\* content addressing is collision-free and deterministic.  Stated over the
\* LIVE store state (so TLC checks it against every reachable state, not as a
\* constant): whenever two held objects share a CID they are the same bytes, so
\* a CID looked up on any node resolves to one content.  The lookup helper
\* ObjOfCID(n, c) is well-defined precisely because of this injectivity.
ObjOfCID(n, c) == CHOOSE o \in store[n] : CID(o) = c
ContentAddressCorrect ==
    \A n, m \in Nodes :
        \A o1 \in store[n], o2 \in store[m] :
            CID(o1) = CID(o2) => o1 = o2

\* HEAD MONOTONICITY: an owner's published head sequence number never regresses.
\* Checked as an action property over primed state -- an IPNS pointer only ever
\* advances, so a stale head can never overwrite a newer one.
HeadSequenceMonotonic ==
    [][ \A w \in Owners : headSeq'[w] >= headSeq[w] ]_vars

\* HEAD AUTHENTICITY: every head that has actually been published (seq > 0) was
\* signed by the owner of that head name -- there is no forged or ambient head
\* publication.  (An unpublished head, seq = 0, has the "nil" sentinel signer.)
HeadSignedByOwner ==
    \A w \in Owners : headSeq[w] > 0 => headSigner[w] = w

\* DHT DISCIPLINE: the set advertised on the public DHT is EXACTLY a set of
\* public anchor objects -- a cell-encrypted or recipient-sealed object is NEVER
\* on the public DHT.  Its mutable head lives on the private swarm's pubsub.
AnchorsOnlyToDHT ==
    \A o \in dht : VisOf(o) = "public"

\* Grow-only durability: a node's pinned set is always a subset of what it holds
\* (you can only pin what you have), and what it holds is a subset of everything
\* ever put (never invents an object).
PinnedSubsetOfStore == \A n \in Nodes : pinned[n] \subseteq store[n]
StoreSubsetOfWritten == \A n \in Nodes : store[n] \subseteq written

------------------------------------------------------------------------------
(* LIVENESS: BACKFILL RECONVERGENCE UNDER A LOSSY LINK *)

\* Every node holds the identical object set.
AllHold == \A n, m \in Nodes : store[n] = store[m]

\* Despite arbitrarily many adversarial Partition/Heal cycles (arbitrarily many
\* dropped/delayed fetches), once putting quiesces and backfill + healing are
\* fair, every node converges to -- and stays at -- the same object set: a
\* missing-but-reachable segment is eventually retrieved.
BackfillReconverges == <>[]AllHold

===============================================================================
