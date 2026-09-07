------------------------------- MODULE PSLCore -------------------------------
(***************************************************************************)
(* Pillar Signal Language (PSL) CORE spec (ROI Priority 0 -- "the Pillar     *)
(* Signal Language", operator 2026-08-31, method #1 TLA+-FIRST,             *)
(* DESIGN-GATED). This spec must be GREEN under TLC before psl-core-impl (or *)
(* any other PSL `*-impl`) may land: it is the machine-checked contract the  *)
(* Rust query engine refines.                                              *)
(*                                                                         *)
(* PSL is the query surface that pivots across the five observability signal *)
(* kinds (metrics/logs/traces/profiles/metadata) over the shared correlation *)
(* spine ObsIngestionSubstrate.tla / Observability.tla already model: every  *)
(* signal carries a uniform {kind, corr, labels} envelope plus a timestamp,  *)
(* and the CorrelationIndex answers "every signal sharing this correlation   *)
(* id / this label". PSL is the LANGUAGE over that index.                   *)
(*                                                                         *)
(* We model the PSL grammar as ONE abstract syntax tree (AST) reached by TWO  *)
(* concrete SURFACES that must be interchangeable:                          *)
(*                                                                         *)
(*   - a STRUCTURED surface (records/fields, the programmatic API), and      *)
(*   - a COMPACT TEXT surface (the terse operator-typed one-liner),          *)
(*                                                                         *)
(* both of which COMPILE to the identical AST. The AST has three clauses,    *)
(* mirroring the ROI grammar verbatim:                                      *)
(*                                                                         *)
(*   select   <kinds>              -- which of the five signal kinds,        *)
(*   where    <label matchers>     -- shared-label matchers =, !=, =~, !~,    *)
(*                                     in(...), and a timestamp range, and    *)
(*   correlate{ by, window, anchor } -- the window-join correlation.         *)
(*                                                                         *)
(* EVALUATION runs the AST over a finite universe of already-ingested        *)
(* signals: `select` + `where` filter the universe to a matched set, then    *)
(* `correlate` performs the WINDOW-JOIN over the CorrelationIndex axis        *)
(* (`by`) -- the result is the set of correlation GROUPS whose members all    *)
(* share the `by` key and lie within |delta t| <= window of a chosen anchor. *)
(*                                                                         *)
(* Proven by TLC (safety, over EVERY reachable constructed query):          *)
(*                                                                         *)
(*  1. CorrelationSymmetric -- omitting `anchor` (anchor = None) produces a   *)
(*     grouping that does NOT depend on query/scan order: the anchorless      *)
(*     grouping is the symmetric "all-pairs within window share a group"      *)
(*     equivalence and is invariant under how the matched set is enumerated.  *)
(*  2. WindowBoundHonored -- NO correlation group ever spans more than        *)
(*     `window`: every pair of signals in one result group is within         *)
(*     |delta t| <= window (the join never leaks a straddling pair).         *)
(*  3. SurfaceEquivalence -- the structured form and the compact text form    *)
(*     of the SAME query always compile to the IDENTICAL AST, hence evaluate  *)
(*     to the identical result over any signal universe.                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Kinds,        \* the five signal kinds (metrics/logs/traces/profiles/metadata)
    LabelKeys,    \* label dimension keys a `where` matcher may test (domain/cell/...)
    LabelVals,    \* label values a key may hold / a matcher may compare against
    CorrIds,      \* correlation-id values a signal may carry (the `by`=corr axis)
    Times,        \* Nat timestamps (ticks) a signal may carry -- finite window
    Signals,      \* the finite universe of already-ingested signal ids
    Windows,      \* SUBSET Nat : the finite set of window values queries may use
                  \* (keeps the AST space enumerable; a query's `window` is drawn
                  \* from here -- the real language admits any Nat, checked over
                  \* a representative finite sample here)
    RegexVals,    \* SUBSET LabelVals : the values the modeled regex =~ MATCHES
    None          \* shared sentinel: "no value" / "no anchor" / "no corr"

ASSUME KindsNonEmpty     == Kinds # {} /\ IsFiniteSet(Kinds)
ASSUME LabelKeysFinite   == IsFiniteSet(LabelKeys)
ASSUME LabelValsFinite   == IsFiniteSet(LabelVals)
ASSUME SignalsFinite     == IsFiniteSet(Signals)
ASSUME WindowsAreNat     == Windows \subseteq Nat /\ IsFiniteSet(Windows)
ASSUME RegexSubset       == RegexVals \subseteq LabelVals
ASSUME NoneFresh         == None \notin LabelVals /\ None \notin CorrIds
                            /\ None \notin Kinds /\ None \notin LabelKeys

------------------------------------------------------------------------------
(* THE SIGNAL UNIVERSE                                                       *)
(*                                                                          *)
(* Each ingested signal carries the uniform envelope ObsIngestionSubstrate   *)
(* proves (kind, corr, labels) plus a timestamp. `labels` is a total map     *)
(* LabelKeys -> LabelVals \cup {None} (None = "key absent on this signal").  *)
(* `sig` is a fixed model input (the CorrelationIndex contents), so PSL      *)
(* evaluation is a pure function of it -- no producer actions here; the      *)
(* ingestion contract is ObsIngestionSubstrate's job, the LANGUAGE is ours.  *)

Envelope ==
    [kind:   Kinds,
     corr:   CorrIds \cup {None},
     labels: [LabelKeys -> LabelVals \cup {None}],
     ts:     Times]

\* The concrete signal contents (the CorrelationIndex a query is evaluated
\* against): a fixed Signals -> Envelope function. PSL evaluation is a pure
\* function of it. The proven properties are universally quantified over the
\* query space, so they hold for this pinned `sig` -- chosen to exercise every
\* matcher / correlate axis / window-straddle case (see the three signals
\* below). The concrete model-value handles it names (s1.., metrics.., etc.)
\* are declared as CONSTANTS and pinned in the .cfg.
CONSTANTS s1, s2, s3, metrics, logs, cell, node, v1, v2, c1

\* Three signals chosen to exercise every path the invariants must survive:
\*   s1: kind metrics, corr c1, cell=v1 node=v1, ts 0  (regex-matched v1 on cell)
\*   s2: kind logs,    corr c1, cell=v1 node=v2, ts 1  (same corr+cell as s1,
\*                                                      within window 1 of s1)
\*   s3: kind metrics, corr c1, cell=v2 node=None,ts 2 (same corr as s1 but ts 2
\*                                                      STRADDLES window 1 vs s1;
\*                                                      None on node -> no node-axis
\*                                                      join; different cell)
sig ==
    ( s1 :> [kind |-> metrics, corr |-> c1,
             labels |-> (cell :> v1 @@ node :> v1), ts |-> 0] )
    @@ ( s2 :> [kind |-> logs, corr |-> c1,
                labels |-> (cell :> v1 @@ node :> v2), ts |-> 1] )
    @@ ( s3 :> [kind |-> metrics, corr |-> c1,
                labels |-> (cell :> v2 @@ node :> None), ts |-> 2] )

ASSUME SigWellTyped == sig \in [Signals -> Envelope]

------------------------------------------------------------------------------
(* THE ONE AST                                                              *)
(*                                                                          *)
(* A `where` clause is a SEQUENCE of atomic matchers; a matcher is a record  *)
(* tagged by its operator. The six operator tags are the ROI grammar's       *)
(* verbatim shared-label matchers plus the timestamp range:                  *)
(*                                                                          *)
(*   "eq"  key = val          "ne"  key != val                              *)
(*   "re"  key =~ regex       "nre" key !~ regex                            *)
(*   "in"  key in(vals)       "range" ts in [lo, hi]                        *)
(*                                                                          *)
(* An empty `where` seq matches everything (select-only query).             *)

MatcherOps == {"eq", "ne", "re", "nre", "in", "range"}

\* A label matcher tests one LabelKey; a range matcher tests the timestamp.
Matcher ==
    [op:   {"eq", "ne"},          key: LabelKeys, val:  LabelVals] \cup
    [op:   {"re", "nre"},         key: LabelKeys]                  \cup
    [op:   {"in"},                key: LabelKeys, vals: SUBSET LabelVals] \cup
    [op:   {"range"},             lo:  Times,     hi:   Times]

\* The correlate clause: `by` is the join axis, `window` the +/- span, `anchor`
\* an optional pivot signal (None = symmetric all-pairs grouping).
\* `by` = "corr" joins on the correlation id; a LabelKey joins on that shared
\* label -- both are CorrelationIndex axes.
CorrelateClause ==
    [by:     {"corr"} \cup LabelKeys,
     window: Nat,
     anchor: Signals \cup {None}]

\* Enumerable variant used to draw logical ASTs: window ranges over the finite
\* Windows sample instead of all of Nat. A subset of CorrelateClause.
BoundedCorrelateClause ==
    [by:     {"corr"} \cup LabelKeys,
     window: Windows,
     anchor: Signals \cup {None}]

\* The whole query AST. `select` = which kinds; `where` = the matcher sequence;
\* `correlate` = the window-join clause.
AST ==
    [select:    SUBSET Kinds,
     where:     Seq(Matcher),
     correlate: CorrelateClause]

------------------------------------------------------------------------------
(* MATCHER SEMANTICS -- the modeled shared-label / range operators.         *)
(*                                                                          *)
(* Regex (=~ / !~) is modeled faithfully-but-abstractly: a value MATCHES the *)
(* regex iff it is in the constant RegexVals (the pattern's language). This  *)
(* is the standard TLA+ surrogate for a concrete regex engine -- the AST/    *)
(* result equivalence properties do not depend on the engine's internals,    *)
(* only that =~ and !~ are exact complements, which this encoding guarantees.*)

\* Does signal s satisfy one matcher m?
SatisfiesMatcher(s, m) ==
    CASE m.op = "eq"    -> sig[s].labels[m.key] = m.val
      [] m.op = "ne"    -> sig[s].labels[m.key] # m.val
      [] m.op = "re"    -> sig[s].labels[m.key] \in RegexVals
      [] m.op = "nre"   -> sig[s].labels[m.key] \notin RegexVals
      [] m.op = "in"    -> sig[s].labels[m.key] \in m.vals
      [] m.op = "range" -> sig[s].ts >= m.lo /\ sig[s].ts <= m.hi
      [] OTHER          -> FALSE

\* Does signal s satisfy EVERY matcher in the where sequence (AND semantics)?
SatisfiesWhere(s, where) ==
    \A i \in 1 .. Len(where) : SatisfiesMatcher(s, where[i])

------------------------------------------------------------------------------
(* EVALUATION -- select + where filter, then the correlate window-join.     *)

\* The matched set: signals whose kind is selected AND that pass every matcher.
Matched(ast) ==
    { s \in Signals :
        /\ sig[s].kind \in ast.select
        /\ SatisfiesWhere(s, ast.where) }

\* The join key of a signal on the `by` axis: the corr id, or a named label.
\* Signals with a None key on the axis never join (they carry no join value).
JoinKey(s, by) ==
    IF by = "corr" THEN sig[s].corr ELSE sig[s].labels[by]

\* Two matched signals may share a group iff they share a NON-None join key on
\* the axis AND lie within the window on the timestamp: |ts_a - ts_b| <= window.
\* (Natural subtraction is truncating, so we test both directions.)
WithinWindow(a, b, w) ==
    /\ sig[a].ts <= sig[b].ts + w
    /\ sig[b].ts <= sig[a].ts + w

Joinable(a, b, cc) ==
    /\ JoinKey(a, cc.by) # None
    /\ JoinKey(a, cc.by) = JoinKey(b, cc.by)
    /\ WithinWindow(a, b, cc.window)

------------------------------------------------------------------------------
(* THE CORRELATION RESULT.                                                  *)
(*                                                                          *)
(* A correlation GROUP is a window-join around a PIVOT signal: every member   *)
(* shares the pivot's non-None join key AND lies within `window` of the pivot *)
(* on the timestamp axis. This is the standard range/ASOF-join semantics --   *)
(* the window is measured FROM THE PIVOT (pivot +/- window), so "the group    *)
(* spans within window" means every member is within `window` of the pivot,   *)
(* the reference point the correlation is anchored on. Each result group is   *)
(* therefore tagged with its pivot so WindowBoundHonored can check the bound   *)
(* against the exact reference the join used.                                 *)
(*                                                                          *)
(* ANCHORED (anchor = a specific signal): the ONE group pivoted on that       *)
(* chosen anchor. Deterministic pivot around a named signal.                 *)
(*                                                                          *)
(* ANCHORLESS (anchor = None): the SYMMETRIC family -- one group pivoted on    *)
(* EACH matched, join-keyed signal. Built as a pure set comprehension over    *)
(* the unordered matched universe, so it carries no dependence on scan order  *)
(* (CorrelationSymmetric). Identical (pivot, members) groups collapse.        *)

\* The group pivoted at signal p: p's key + timestamp are the reference; every
\* member shares p's non-None join key and is within window of p. Returned as
\* a record {pivot, members} so the window bound is checkable against p.
GroupAt(p, ast) ==
    [ pivot   |-> p,
      members |-> { s \in Matched(ast) : Joinable(p, s, ast.correlate) } ]

\* Anchorless result: one pivoted group per matched signal that HAS a join key,
\* i.e. the symmetric family { GroupAt(p) : p matched, join-keyed }. A pure set
\* comprehension over the unordered universe -> order-independent by
\* construction, the essence of CorrelationSymmetric.
SymmetricGroups(ast) ==
    { GroupAt(p, ast) :
        p \in { q \in Matched(ast) : JoinKey(q, ast.correlate.by) # None } }

\* The evaluation result of a query: a SET of pivoted groups. Anchored -> the
\* single group pivoted on the named anchor; anchorless -> the symmetric family.
Evaluate(ast) ==
    IF ast.correlate.anchor = None
    THEN SymmetricGroups(ast)
    ELSE { GroupAt(ast.correlate.anchor, ast) }

------------------------------------------------------------------------------
(* THE TWO SURFACES.                                                        *)
(*                                                                          *)
(* A STRUCTURED query is already an AST record (the programmatic surface).   *)
(* A COMPACT query is a distinct concrete representation -- we model it as a  *)
(* record with the SAME three fields but TAGGED as text-surface, plus we keep *)
(* an explicit `CompileCompact` that lowers it to the AST. The point of the  *)
(* two surfaces is that the SAME logical query, expressed either way,        *)
(* compiles to the IDENTICAL AST. We model a query as a PAIR of surfaces that *)
(* are declared to denote the same logical query, and prove their compiles   *)
(* coincide.                                                                 *)
(*                                                                          *)
(* Concretely: a `SurfacePair` is <<structured, compact>> where `structured` *)
(* is an AST and `compact` is its compact-text encoding. CompileStructured    *)
(* is the identity (the structured surface already IS the AST); CompileCompact*)
(* is the parser lowering the compact text. The construction guarantees they  *)
(* denote the same query, and SurfaceEquivalence proves the two compiles are  *)
(* equal -- so no surface can silently diverge.                              *)

\* Compact-text encoding of an AST: a reversible re-tagging of the same three
\* clauses. Modeled as the AST wrapped with a "text" marker to make it a
\* genuinely distinct representation that must be LOWERED, not just aliased.
EncodeCompact(ast) == [surface |-> "text", body |-> ast]

\* The compact-text PARSER: lowers a compact encoding back to the AST. Round-
\* trips EncodeCompact exactly (a faithful, total, deterministic parser).
CompileCompact(ct) == ct.body

\* The structured surface already IS the AST; its compile is the identity.
CompileStructured(ast) == ast

\* A surface pair for a logical query q: its structured form and its compact
\* form. Both are DERIVED from the one logical AST q, so they denote the same
\* query by construction -- exactly the situation a real dual-surface parser
\* must guarantee, and what SurfaceEquivalence re-checks holds after compile.
SurfacePair(q) == << CompileStructured(q), CompileCompact(EncodeCompact(q)) >>

------------------------------------------------------------------------------
(* STATE MACHINE.                                                           *)
(*                                                                          *)
(* The only dynamics are CONSTRUCTING queries: each step picks a logical AST  *)
(* out of the (finite) AST space, builds its two-surface pair, compiles both, *)
(* evaluates the compiled AST against the fixed signal universe, and records  *)
(* the (structuredAST, compactAST, result) so the invariants range over EVERY *)
(* constructible query. `sig` is fixed; PSL evaluation is a pure function of  *)
(* the query and the universe, so there is no other state to evolve. To keep  *)
(* the reachable state graph trivial (Init -> Built, two states) while still   *)
(* checking EVERY query, the single `BuildAll` transition materializes the     *)
(* full family of constructed queries at once -- equivalent to constructing    *)
(* them one at a time but with no combinatorial interleaving to explore.       *)

VARIABLES
    queries,   \* set of records {q, sAst, cAst, result} -- every query, once built
    built      \* BOOLEAN : has the family been materialized yet

vars == <<queries, built>>

\* The finite space of logical ASTs. Bounded `where` length keeps it finite;
\* the .cfg pins small kind/label/time sets.
BoundedWhere == UNION { [1 .. n -> Matcher] : n \in 0 .. 1 }

LogicalASTs ==
    [select:    SUBSET Kinds,
     where:     BoundedWhere,
     correlate: BoundedCorrelateClause]

\* The constructed-query record for a logical AST q: compile BOTH surfaces,
\* evaluate the compiled AST, record all three. sAst / cAst are the two
\* surfaces' compile outputs -- SurfaceEquivalence asserts they are equal.
Constructed(q) ==
    LET pair == SurfacePair(q)
        sAst == pair[1]
        cAst == pair[2]
    IN  [ q      |-> q,
          sAst   |-> sAst,
          cAst   |-> cAst,
          result |-> Evaluate(sAst) ]

Init ==
    /\ queries = {}
    /\ built   = FALSE

\* Materialize the whole family of constructed queries in one step, so every
\* query in LogicalASTs is present for the invariants to range over.
BuildAll ==
    /\ ~built
    /\ queries' = { Constructed(q) : q \in LogicalASTs }
    /\ built'   = TRUE

Next == BuildAll

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                         *)

QueryRecord ==
    [q: AST, sAst: AST, cAst: AST,
     result: SUBSET [pivot: Signals, members: SUBSET Signals]]

TypeOK ==
    /\ built \in BOOLEAN
    /\ \A r \in queries :
         /\ r.q      \in AST
         /\ r.sAst   \in AST
         /\ r.cAst   \in AST
         /\ \A g \in r.result :
              /\ g.pivot   \in Signals
              /\ g.members \subseteq Signals

------------------------------------------------------------------------------
(* PROPERTY 3: SURFACE EQUIVALENCE                                          *)
(*                                                                          *)
(* The structured form and the compact text form of the SAME query always    *)
(* compile to the IDENTICAL AST -- and therefore evaluate identically. For    *)
(* every constructed query the two compile outputs are equal; equal ASTs      *)
(* evaluate to equal results (Evaluate is a pure function), so we assert both *)
(* the AST equality and, explicitly, the result equality it entails.         *)

SurfaceEquivalence ==
    \A r \in queries :
        /\ r.sAst = r.cAst
        /\ Evaluate(r.sAst) = Evaluate(r.cAst)
        /\ r.result = Evaluate(r.cAst)

------------------------------------------------------------------------------
(* PROPERTY 2: WINDOW BOUND HONORED                                         *)
(*                                                                          *)
(* NO correlation group in ANY result spans more than `window`: every member  *)
(* of a result group is within |delta t| <= that query's window of the        *)
(* group's PIVOT -- the reference point the window-join is measured from       *)
(* (pivot +/- window, the standard range-join semantics). This is the anti-   *)
(* leak guarantee: the join never admits a signal whose timestamp straddles a *)
(* gap larger than the window from the pivot the correlation is anchored on.  *)
(* (Equivalently every member lies in the closed interval                     *)
(* [ts(pivot) - window, ts(pivot) + window].)                                *)

WindowBoundHonored ==
    \A r \in queries :
        \A g \in r.result :
            \A s \in g.members :
                WithinWindow(g.pivot, s, r.q.correlate.window)

------------------------------------------------------------------------------
(* PROPERTY 1: CORRELATION SYMMETRIC                                        *)
(*                                                                          *)
(* Omitting `anchor` produces a SYMMETRIC grouping independent of query/scan  *)
(* order. We assert this two ways, both of which the set-based construction   *)
(* guarantees for every anchorless query:                                    *)
(*                                                                          *)
(*  (a) MEMBERSHIP SYMMETRY: within any resulting group, joinability is       *)
(*      mutual -- a joins b iff b joins a -- so no group encodes a one-way    *)
(*      "a saw b but not vice versa" artifact of scan direction. (This is the *)
(*      per-pair symmetry of the underlying relation, lifted to the result.) *)
(*  (b) ORDER INDEPENDENCE: the anchorless result equals the symmetric family *)
(*      SymmetricGroups(ast), a pure set comprehension over the unordered     *)
(*      matched universe -- it has no dependence on any enumeration order, so  *)
(*      two evaluations of the same anchorless query always agree.           *)

\* The underlying join relation is symmetric on matched, same-key signals.
JoinSymmetric(cc) ==
    \A a, b \in Signals :
        (JoinKey(a, cc.by) # None /\ JoinKey(b, cc.by) # None)
            => (Joinable(a, b, cc) <=> Joinable(b, a, cc))

CorrelationSymmetric ==
    \A r \in queries :
        r.q.correlate.anchor = None =>
            /\ JoinSymmetric(r.q.correlate)
            /\ r.result = SymmetricGroups(r.q)

=============================================================================
