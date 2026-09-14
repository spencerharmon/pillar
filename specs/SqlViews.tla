------------------------------- MODULE SqlViews -------------------------------
(***************************************************************************)
(* Pillar SQL views: SQL is a DERIVED-READ layer over the keyed Document    *)
(* store -- it owns NO storage of its own (ROI P1 data-layer whitepaper,    *)
(* section 2.2/3).  This spec proves the structural claims from section 3:  *)
(*   - DDL is not special: CREATE MATERIALIZED VIEW writes a document to a  *)
(*     `__catalog` system collection, exactly like any other collection     *)
(*     write (section 3.1) -- "the catalog is data".                        *)
(*   - A row's key IS (collection, id) -- no side index (section 3.2); this *)
(*     spec models both ordinary rows and catalog rows through the SAME     *)
(*     per-(collection,id,field) fold, catalog just being one more          *)
(*     collection name.                                                     *)
(*   - UPDATE never mutates a flat document in place -- it appends a        *)
(*     per-field delta op, and the "current row" is always DERIVED by       *)
(*     folding the op log (last-writer-wins per field) (section 3.3).       *)
(*   - A view is a catalog document naming its source collection + a query  *)
(*     (modeled as an equality filter over one field, the smallest faithful *)
(*     instance of "project/filter over a collection"); it is materialized  *)
(*     by FOLDING that source -- views subscribe to sources, sources stay   *)
(*     oblivious of views (section 3.4).                                    *)
(*   - Creating a new view over EXISTING data requires no migration: it is  *)
(*     folded from the unchanged, already-written log, and coexists with    *)
(*     every other view over the same source without disturbing it         *)
(*     (section 3.5).                                                       *)
(*                                                                          *)
(* Proven by TLC:                                                          *)
(*   - TypeOK: every op ever appended is a well-typed data or catalog op.   *)
(*   - ViewIsPureFoldOfSources: a view's materialized rows are a PURE       *)
(*     function of its catalog definition and the current folded state of  *)
(*     its source collection -- nothing else. Whenever a step leaves the    *)
(*     view's own definition AND every relevant field-fold of its source    *)
(*     collection unchanged, the view's materialized rows do not change     *)
(*     either (an unrelated write elsewhere in the log can never move a     *)
(*     view that does not depend on it).                                   *)
(*   - NoMigrationOnNewView: appending a NEW view's catalog definition       *)
(*     never changes the materialized rows of any OTHER, already-existing   *)
(*     view -- old and new views coexist, both folded independently from    *)
(*     the same unchanged content-addressed log, with no migration step     *)
(*     touching the older view.                                            *)
(*   - CatalogChangeNeverMutatesRow: appending a catalog op (CREATE VIEW)   *)
(*     never changes the folded value of any (collection, id, field) in an  *)
(*     ordinary data collection -- the catalog write and the rows it        *)
(*     describes are on separate keys of the SAME log, and touching one     *)
(*     never mutates the other in place.                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Collections,  \* finite set of ordinary (non-catalog) collection names
    ViewIds,      \* finite set of view identifiers (catalog row ids)
    Ids,          \* finite set of document ids in ordinary collections
    Fields,       \* finite set of field names for ordinary collection rows
    Values        \* finite set of field values

\* The system collection DDL writes into (section 3.1). A model value, kept
\* out of Collections so a data write and a catalog write are never confused.
CatalogColl == "__catalog"
ASSUME CatalogNotOrdinary == CatalogColl \notin Collections

ASSUME CollectionsNonEmpty == Collections # {}
ASSUME ViewIdsNonEmpty     == ViewIds # {}
ASSUME IdsNonEmpty         == Ids # {}
ASSUME FieldsNonEmpty      == Fields # {}
ASSUME ValuesNonEmpty      == Values # {}

\* A view definition: names its source collection and a single equality
\* filter (field = val) -- the smallest faithful instance of "project/filter
\* over one or more collections" (section 3.4). Extra predicate shapes would
\* not change the structural properties this spec proves.
ViewDefs == [source: Collections, filterField: Fields, filterVal: Values]

\* An ordinary row-field op: put carries a value, tombstone carries none
\* (uses a fixed sentinel so the record shape stays uniform, as KeyedStore.tla
\* does). Its key is (coll, id, field) -- the collection component IS the
\* table id, with no side index (section 3.2).
TombVal == CHOOSE v \in Values : TRUE
DataOp == [coll: Collections, id: Ids, field: Fields, kind: {"put", "tomb"}, val: Values]

\* A catalog op: CREATE MATERIALIZED VIEW writes ONE document to __catalog,
\* keyed by (viewId, "def"), carrying the whole ViewDef as its value (section
\* 3.1). Modeled create-only -- DROP VIEW is out of scope; creation alone
\* already exercises catalog-is-data + no-migration + non-mutation.
CatalogOp == [coll: {CatalogColl}, id: ViewIds, field: {"def"}, kind: {"put"}, val: ViewDefs]

Op == DataOp \cup CatalogOp

VARIABLES
    written   \* Seq(Op) -- the single append-only, content-addressed op log.
              \* (Concurrent-write conflict resolution via HLC is already
              \* proven in KeyedStore.tla; this spec's concern is catalog-
              \* as-data + view-fold purity, so append order alone suffices
              \* as the "last write wins" tiebreak -- no HLC needed here.)

vars == <<written>>

------------------------------------------------------------------------------
(* THE FOLD: per-(collection, id, field) current op, and a view's rows, as   *)
(* PURE functions of the log CONTENTS -- never of anything else.            *)

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

\* The winning (most-recently-appended) op for (coll, id, field) in log L, or
\* a "none" sentinel if no such op exists yet.
FieldOp(L, coll, id, field) ==
    LET idxs == {k \in 1..Len(L) : L[k].coll = coll /\ L[k].id = id /\ L[k].field = field}
    IN  IF idxs = {} THEN [kind |-> "none"] ELSE L[Max(idxs)]

FieldLive(L, coll, id, field)  == FieldOp(L, coll, id, field).kind = "put"
FieldValue(L, coll, id, field) == FieldOp(L, coll, id, field).val

\* A view's catalog definition folded from __catalog, or "undefined" if the
\* view has not (yet) been created.
CatalogDef(L, vid) ==
    LET idxs == {k \in 1..Len(L) : L[k].coll = CatalogColl /\ L[k].id = vid /\ L[k].field = "def"}
    IN  IF idxs = {} THEN [defined |-> FALSE]
        ELSE [defined |-> TRUE, def |-> L[Max(idxs)].val]

\* The view's materialized rows: every source-collection id whose filter
\* field currently equals the filter value -- computed by FOLDING the
\* source, never by consulting any per-document "which view?" pointer
\* (section 3.4: "views subscribe to sources; sources are oblivious of
\* views").
ViewRows(L, vid) ==
    LET cd == CatalogDef(L, vid)
    IN  IF ~cd.defined THEN {}
        ELSE { i \in Ids : FieldLive(L, cd.def.source, i, cd.def.filterField)
                           /\ FieldValue(L, cd.def.source, i, cd.def.filterField) = cd.def.filterVal }

------------------------------------------------------------------------------
(* INITIAL STATE / ACTIONS                                                  *)

Init == written = <<>>

\* INSERT / per-field UPDATE: append a put carrying only the changed field
\* (section 3.3) -- the row is never mutated in place, only derived by fold.
Put(c, i, f, v) == written' = Append(written, [coll |-> c, id |-> i, field |-> f, kind |-> "put", val |-> v])

\* DELETE: append a tombstone for one field (section 3.3).
Tombstone(c, i, f) == written' = Append(written, [coll |-> c, id |-> i, field |-> f, kind |-> "tomb", val |-> TombVal])

\* CREATE MATERIALIZED VIEW: append ONE document to __catalog naming the
\* source collection + query (section 3.1) -- an ordinary collection write,
\* nothing else; no data-collection op is touched.
CreateView(vid, def) == written' = Append(written, [coll |-> CatalogColl, id |-> vid, field |-> "def", kind |-> "put", val |-> def])

Next ==
    \/ \E c \in Collections, i \in Ids, f \in Fields, v \in Values : Put(c, i, f, v)
    \/ \E c \in Collections, i \in Ids, f \in Fields : Tombstone(c, i, f)
    \/ \E vid \in ViewIds, d \in ViewDefs : CreateView(vid, d)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK == written \in Seq(Op)

\* State-space bound for TLC (the append-only log is otherwise unbounded, as
\* a real content-addressed log is): stop exploring past a handful of ops --
\* enough to exercise a create-view-after-existing-data-and-view sequence.
LenConstraint == Len(written) <= 4

------------------------------------------------------------------------------
(* SAFETY PROPERTIES (the three properties the task requires)               *)

\* 1. ViewIsPureFoldOfSources: a view's materialized rows depend ONLY on its
\*    own catalog definition and the folded state of its source collection.
\*    Whenever a step leaves the view's definition unchanged AND leaves the
\*    per-(id,field) fold of its source collection unchanged for every id,
\*    the view's materialized rows do not change either -- an unrelated
\*    write anywhere else in the log can never move a view that does not
\*    depend on it, and the view is never anything other than the fold of
\*    its named sources.
ViewIsPureFoldOfSources ==
    [][ \A vid \in ViewIds :
          LET cd == CatalogDef(written, vid) IN
          ( cd.defined
            /\ CatalogDef(written', vid) = cd
            /\ \A i \in Ids : FieldOp(written', cd.def.source, i, cd.def.filterField)
                              = FieldOp(written, cd.def.source, i, cd.def.filterField)
          ) => ViewRows(written', vid) = ViewRows(written, vid)
      ]_vars

\* 2. NoMigrationOnNewView: creating a NEW view never changes the
\*    materialized rows of any OTHER, already-existing view. Old and new
\*    views coexist, each independently folded over the same unchanged,
\*    content-addressed log -- no migration step ever touches the older
\*    view (section 3.5).
NewCatalogOpFor(vid) ==
    /\ Len(written') = Len(written) + 1
    /\ written'[Len(written')].coll = CatalogColl
    /\ written'[Len(written')].id = vid

NoMigrationOnNewView ==
    [][ \A vid \in ViewIds :
          NewCatalogOpFor(vid) =>
             \A other \in ViewIds \ {vid} :
                CatalogDef(written, other).defined =>
                   ViewRows(written', other) = ViewRows(written, other)
      ]_vars

\* 3. CatalogChangeNeverMutatesRow: appending a catalog op (CREATE VIEW)
\*    never changes the folded value of any (collection, id, field) in an
\*    ordinary data collection -- DDL is data on its OWN key, and writing it
\*    never mutates a row's key elsewhere in the log (section 3.1/3.2).
CatalogChangeNeverMutatesRow ==
    [][ (Len(written') = Len(written) + 1 /\ written'[Len(written')].coll = CatalogColl) =>
           \A c \in Collections, i \in Ids, f \in Fields :
              FieldOp(written', c, i, f) = FieldOp(written, c, i, f)
      ]_vars

===============================================================================
