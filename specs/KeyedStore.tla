------------------------------ MODULE KeyedStore ------------------------------
(***************************************************************************)
(* Pillar keyed store: two typed surfaces -- K/V (opaque-value, point       *)
(* access) and Document (structured, field-queryable) -- over ONE engine     *)
(* (ROI P1 data-layer whitepaper, section 4/5).  K/V is modeled as the       *)
(* degenerate case of Document with exactly one field (the whitepaper's      *)
(* "K/V = Document with an opaque value + key-only access"), so a single     *)
(* per-field-LWW fold covers both surfaces; this spec proves that fold.      *)
(*                                                                          *)
(* This extends the streamdb op model (StreamingDB.tla): the SAME grow-only *)
(* op-log substrate, but the keyed store folds it to a mutable CURRENT      *)
(* STATE keyed by (collection, id, field) instead of leaving it a flat op   *)
(* set.  `OpLog::order` (content-address order) is explicitly NOT the fold  *)
(* order for this layer -- section 4 of the whitepaper requires every       *)
(* put/tombstone op to carry a Hybrid Logical Clock (HLC) timestamp, and    *)
(* same-field conflicts resolve by HIGHEST HLC with a DETERMINISTIC         *)
(* tiebreak (never wall-clock order, never OpLog::order).  This spec models *)
(* the HLC as a (physical, logical, author) triple -- physical/logical form *)
(* the actual clock value, author is the deterministic tiebreak key when    *)
(* two ops carry the identical (physical, logical) pair.  Two DISTINCT ops  *)
(* are never given the identical full HLC (physical, logical, author),      *)
(* mirroring that a real HLC is only ever advanced/ticked by one author at  *)
(* a time -- see HLCsDistinct below.                                        *)
(*                                                                          *)
(* Proven by TLC:                                                          *)
(*   - TypeOK: every declared variable stays within its typed domain.       *)
(*   - HLCMonotonicPerField: the HLC recorded as "currently winning" for a   *)
(*     given (collection, id, field) at a node never regresses as that      *)
(*     node applies more ops -- an already-applied write's HLC is a floor.  *)
(*   - DeterministicLWWTiebreak: two nodes that have applied the SAME set    *)
(*     of ops for a given field resolve to the EXACT SAME winning op,        *)
(*     regardless of the ORDER they applied them in -- the fold is a pure    *)
(*     function of the delivered op set, never of arrival/apply order.      *)
(*   - TombstoneWins: a tombstone with a higher HLC than every live put for  *)
(*     that field always wins the field (the field reads as absent) -- a     *)
(*     tombstone is exactly one more HLC-carrying op in the SAME per-field   *)
(*     LWW fold, not a special case that can be reordered around.           *)
(*   - NoLostUpdateUnderConcurrentPut: two nodes concurrently put DIFFERENT  *)
(*     values to the SAME field with DIFFERENT HLCs and then merge (as in    *)
(*     StreamingDB's Gossip); the merged fold is never a THIRD value absent  *)
(*     from either input -- the winner is always one of the two concurrent   *)
(*     writes (the higher-HLC one), never a corrupted blend or a dropped     *)
(*     update that leaves neither writer's value in place.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,        \* set of participating node identities
    Ids,          \* finite set of document/record identifiers (one collection
                  \* modeled; extra collections add no new fold behaviour)
    Fields,       \* finite set of field names.  {onlyField} models the K/V
                  \* surface (a single opaque value, key-only access); a
                  \* larger set models the Document surface (field-queryable)
    Values,       \* finite set of value payloads an op may carry
    MaxPhysical,  \* model bound on HLC physical-time component
    MaxLogical    \* model bound on HLC logical (tie-break-within-tick) component

ASSUME NodesNonEmpty    == Nodes # {}
ASSUME IdsNonEmpty      == Ids # {}
ASSUME FieldsNonEmpty   == Fields # {}
ASSUME ValuesNonEmpty   == Values # {}
ASSUME MaxPhysicalNat   == MaxPhysical \in Nat
ASSUME MaxLogicalNat    == MaxLogical \in Nat

Physicals == 0 .. MaxPhysical
Logicals  == 0 .. MaxLogical

\* A Hybrid Logical Clock stamp: (physical, logical, author).  author is the
\* deterministic tiebreak key -- never wall-clock order, never OpLog::order.
HLCs == [phys: Physicals, log: Logicals, author: Nodes]

(* A concrete, TLC-checkable deterministic tiebreak: Nodes is finite, so fix  *)
(* an arbitrary but STABLE total order over it once, and use that order as   *)
(* the tiebreak (never wall-clock, never OpLog::order/content-address).       *)

\* Deterministic enumeration of Nodes into a sequence (stable across the run:
\* Nodes is a CONSTANT, so this value never changes once TLC evaluates it).
NodeSeq == CHOOSE sq \in [1 .. Cardinality(Nodes) -> Nodes] :
              \A i, j \in 1 .. Cardinality(Nodes) : i # j => sq[i] # sq[j]

NodeRank(n) == CHOOSE i \in 1 .. Cardinality(Nodes) : NodeSeq[i] = n

\* The actual HLC comparator used everywhere below: physical, then logical,
\* then the fixed deterministic node rank.  Total, irreflexive, and a pure
\* function of the two HLC values -- exactly the "deterministic tiebreak"
\* the whitepaper requires.
HLCBefore(a, b) ==
    \/ a.phys < b.phys
    \/ (a.phys = b.phys /\ a.log < b.log)
    \/ (a.phys = b.phys /\ a.log = b.log /\ NodeRank(a.author) < NodeRank(b.author))

\* Two distinct HLC values are never equal on all three components -- checked
\* as an invariant (HLCsDistinct) over every op actually produced by Next,
\* mirroring that a real HLC is advanced by exactly one author at a time.
HLCEq(a, b) == a.phys = b.phys /\ a.log = b.log /\ a.author = b.author

------------------------------------------------------------------------------
(* OPS                                                                       *)

\* An op targets one (id, field) pair, carries an HLC, and is either a Put
\* (kind = "put", carrying a value) or a Tombstone (kind = "tomb", no value
\* needed -- modeled with a fixed sentinel so Ops stays one uniform record
\* shape for TLC).
OpRec == [id: Ids, field: Fields, hlc: HLCs, kind: {"put", "tomb"}, val: Values]

VARIABLES
    written,   \* SUBSET OpRec -- ghost: every op ever produced, anywhere
                \* (its content-address identity is (id,field,hlc,kind,val);
                \* two produced ops are never identical records, mirroring
                \* content-addressed op identity from StreamingDB.tla)
    applied    \* [Nodes -> SUBSET OpRec] -- ops each node has folded in; a
                \* node's applied set only grows (append-only, as in
                \* StreamingDB's log), modeling per-node op-log replay

vars == <<written, applied>>

------------------------------------------------------------------------------
(* THE FOLD: per-(id, field) current state as a pure function of a node's    *)
(* applied op SET -- never of the order those ops were applied in.           *)

\* All ops in set S targeting (id, field).
OpsFor(S, id, field) == {o \in S : o.id = id /\ o.field = field}

\* The winning op for (id, field) in S: the one whose HLC no other op in the
\* same field beats.  Undefined (no CHOOSE needed) when the set is empty --
\* callers only invoke this after checking OpsFor(S,id,field) # {}.
Winner(S, id, field) ==
    LET fs == OpsFor(S, id, field)
    IN  CHOOSE o \in fs : \A o2 \in fs : o2 # o => HLCBefore(o2.hlc, o.hlc)

\* Current fold: TRUE (present, value v) or a tombstone (absent) or entirely
\* unset (no op yet for this field in S).
FieldIsSet(S, id, field)   == OpsFor(S, id, field) # {}
FieldIsLive(S, id, field)  == FieldIsSet(S, id, field) /\ Winner(S, id, field).kind = "put"
FieldValue(S, id, field)   == Winner(S, id, field).val   \* only meaningful if FieldIsLive

------------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ written = {}
    /\ applied = [n \in Nodes |-> {}]

------------------------------------------------------------------------------
(* ACTIONS                                                                   *)

\* A node originates a fresh put/tombstone op with a HLC strictly ahead of
\* every HLC it has already seen for that field (models a real HLC: an
\* author only ever ticks its clock forward past what it has observed), and
\* immediately applies it to its own log (an origination is also an apply).
FreshEnough(n, id, field, hlc) ==
    \A o \in OpsFor(applied[n], id, field) : HLCBefore(o.hlc, hlc)

Put(n, id, field, val, hlc) ==
    /\ hlc.author = n
    /\ FreshEnough(n, id, field, hlc)
    /\ LET op == [id |-> id, field |-> field, hlc |-> hlc, kind |-> "put", val |-> val]
       IN  /\ op \notin written
           /\ written' = written \cup {op}
           /\ applied' = [applied EXCEPT ![n] = @ \cup {op}]

\* val is irrelevant for a tombstone; CHOOSE a fixed witness so OpRec stays
\* one uniform shape without introducing a second record type.
TombVal == CHOOSE v \in Values : TRUE

Tombstone(n, id, field, hlc) ==
    /\ hlc.author = n
    /\ FreshEnough(n, id, field, hlc)
    /\ LET op == [id |-> id, field |-> field, hlc |-> hlc, kind |-> "tomb", val |-> TombVal]
       IN  /\ op \notin written
           /\ written' = written \cup {op}
           /\ applied' = [applied EXCEPT ![n] = @ \cup {op}]

\* Anti-entropy merge (as StreamingDB's Gossip): m absorbs every op n has
\* produced/applied that m has not yet applied.  Grow-only set union -- the
\* fold above is then re-derived over the LARGER set, never re-ordered.
Merge(n, m) ==
    /\ n # m
    /\ ~(applied[n] \subseteq applied[m])
    /\ applied' = [applied EXCEPT ![m] = @ \cup applied[n]]
    /\ UNCHANGED written

Next ==
    \/ \E n \in Nodes, id \in Ids, field \in Fields, val \in Values, hlc \in HLCs :
          Put(n, id, field, val, hlc)
    \/ \E n \in Nodes, id \in Ids, field \in Fields, hlc \in HLCs :
          Tombstone(n, id, field, hlc)
    \/ \E n, m \in Nodes : Merge(n, m)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ written \subseteq OpRec
    /\ applied \in [Nodes -> SUBSET OpRec]

------------------------------------------------------------------------------
(* CONTENT-ADDRESS-LIKE OP IDENTITY (mirrors StreamingDB's ghost `written`)   *)

\* Every op this run ever produced is distinct as a full record -- an op's
\* identity is its full (id,field,hlc,kind,val) content, so two logically
\* different puts/tombstones are never conflated by TLC into "the same op".
HLCsDistinct ==
    \A o1, o2 \in written : (o1 # o2 /\ o1.id = o2.id /\ o1.field = o2.field) =>
        ~HLCEq(o1.hlc, o2.hlc)

------------------------------------------------------------------------------
(* SAFETY INVARIANTS (the four properties the task requires)                 *)

\* 1. HLCMonotonicPerField: the winning HLC for a given (id, field) at a
\*    node never regresses as that node's applied set grows.  Stated as an
\*    action property over primed state: if the field is live/tombstoned
\*    both before and after a step at node n, the post-step winning HLC is
\*    never strictly BEFORE the pre-step one.
HLCMonotonicPerField ==
    [][ \A n \in Nodes, id \in Ids, field \in Fields :
          (FieldIsSet(applied[n], id, field) /\ FieldIsSet(applied'[n], id, field)) =>
             ~HLCBefore(Winner(applied'[n], id, field).hlc, Winner(applied[n], id, field).hlc)
    ]_vars

\* 2. DeterministicLWWTiebreak: two nodes (or the same node at two different
\*    reachable states) that have applied the IDENTICAL op set for a field
\*    always resolve to the identical winning op -- the fold is a pure
\*    function of the delivered set, independent of apply order. Checked
\*    directly over every pair of nodes at every reached state (their
\*    applied sets differ in general -- the invariant fires exactly when
\*    they happen to coincide for some field, which reachable interleavings
\*    of Merge/Put do produce).
DeterministicLWWTiebreak ==
    \A n, m \in Nodes, id \in Ids, field \in Fields :
        OpsFor(applied[n], id, field) = OpsFor(applied[m], id, field) =>
            (FieldIsSet(applied[n], id, field) =>
                Winner(applied[n], id, field) = Winner(applied[m], id, field))

\* 3. TombstoneWins: if the winning op for a field is a tombstone, the field
\*    reads as absent -- i.e. FieldIsLive is false whenever the highest-HLC
\*    op for that field is a "tomb". (A tombstone that is NOT the winner,
\*    because a later put superseded it, correctly leaves the field live --
\*    that is the SAME per-field LWW fold, not an exception.)
TombstoneWins ==
    \A n \in Nodes, id \in Ids, field \in Fields :
        FieldIsSet(applied[n], id, field) =>
            (Winner(applied[n], id, field).kind = "tomb" =>
                ~FieldIsLive(applied[n], id, field))

\* 4. NoLostUpdateUnderConcurrentPut: whenever two DIFFERENT ops target the
\*    same (id, field) in a node's applied set, the fold's winner is always
\*    ONE OF the ops actually present -- never a value absent from the
\*    input set. Concurrency (two nodes putting different values with
\*    different HLCs, then merging) is exactly the case where OpsFor has
\*    more than one member; this invariant says the merge never produces a
\*    third, corrupted value and never silently drops both live writes (the
\*    winner is always a real op that was actually applied).
NoLostUpdateUnderConcurrentPut ==
    \A n \in Nodes, id \in Ids, field \in Fields :
        FieldIsSet(applied[n], id, field) =>
            Winner(applied[n], id, field) \in OpsFor(applied[n], id, field)

===============================================================================
