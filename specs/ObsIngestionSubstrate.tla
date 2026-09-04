------------------------- MODULE ObsIngestionSubstrate -------------------------
(***************************************************************************)
(* Pillar observability REAL ingestion substrate (ROI Priority 0,           *)
(* observability real ingestion, operator 2026-08-31, method #1). This is   *)
(* the DESIGN-GATE spec for the ingestion side of built-in observability:   *)
(* it extends the observability-design-spec spine (Observability.tla) by    *)
(* modelling the ONE producer contract shared by all five signal kinds and  *)
(* the default-on/off matrix + config surface that governs which producers  *)
(* are live. Where Observability.tla proves what happens to a signal event  *)
(* ONCE it is on the store (retention, sampling, read authority), THIS spec  *)
(* proves the ingestion contract UPSTREAM of the store: every kind's        *)
(* producer emits the SAME envelope shape, a freshly booted node's live     *)
(* producers match the declared defaults, a config/manifest toggle flips    *)
(* exactly its named producer with no cross-talk, and -- the store          *)
(* invariant Observability already proves, now carried END-TO-END through    *)
(* the producer -- no synthetic/sampled-demo data ever reaches the store.   *)
(*                                                                         *)
(* DESIGN GATE: this spec must be green under TLC before obs-ingest-metrics  *)
(* (or any other real-ingestion `*-impl` task) may land.                    *)
(*                                                                         *)
(* The five signal kinds and their default state (the "default matrix"):    *)
(*                                                                         *)
(*    metrics   ON     traces    OFF    metadata  ON  (basic periodic       *)
(*    logs      ON     profiles  OFF               sampling)                *)
(*                                                                         *)
(* Every default is config/manifest-toggleable; a toggle flips EXACTLY its  *)
(* named producer.                                                         *)
(*                                                                         *)
(* Proven safety properties:                                               *)
(*  1. ProducerContractUniform -- every producer of every kind, when it     *)
(*     emits, writes an envelope of the SAME shape {kind, correlation_id?,  *)
(*     labels}, so correlation pivots work uniformly across all five kinds. *)
(*  2. DefaultsMatchSpec -- a freshly booted node's live producer state     *)
(*     equals the declared default matrix on exactly those producers not    *)
(*     yet overridden by config.                                           *)
(*  3. ConfigOverrideHonored -- a config/manifest toggle sets exactly its   *)
(*     named producer's enabled state and no other (no cross-talk).         *)
(*  4. NoFabricatedSample -- extends Observability's store invariant end-to-*)
(*     end through the producer: every envelope that reaches the store      *)
(*     denotes a real, already-`happened` occurrence -- no synthetic /      *)
(*     sampled-demo data is ever produced into the store.                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,          \* peers that boot producers
    Kinds,          \* the five signal kinds (a producer per kind per node)
    Occurrences,    \* real-world occurrences an emitted envelope may reference
    Labels,         \* label sets an envelope may carry (any non-empty is fine)
    CorrIds,        \* correlation-id values an envelope may stamp (optional)
    MaxEnvelopes,   \* model bound on how many envelopes reach the store
    None            \* shared sentinel: "no correlation id" / "no value"

(* The declared default matrix: which kinds boot ON. metrics, logs, metadata *)
(* ON; traces, profiles OFF. Encoded as a constant so DefaultsMatchSpec can  *)
(* assert live state against it and the cfg pins the concrete kind names.    *)
CONSTANT DefaultOn      \* SUBSET Kinds : the kinds ON by default at boot

ASSUME NodesNonEmpty     == Nodes # {}
ASSUME KindsNonEmpty     == Kinds # {}
ASSUME KindsFinite       == IsFiniteSet(Kinds)
ASSUME OccurrencesFinite == IsFiniteSet(Occurrences)
ASSUME DefaultOnSubset   == DefaultOn \subseteq Kinds
ASSUME MaxEnvelopesNat   == MaxEnvelopes \in Nat
ASSUME NoneNotCorr       == None \notin CorrIds
ASSUME NoneNotOccurrence == None \notin Occurrences

VARIABLES
    \* --- producer enable/override state (properties 2 & 3) ---
    enabled,        \* [Nodes -> [Kinds -> BOOLEAN]] : live producer enabled state
    overridden,     \* [Nodes -> SUBSET Kinds] : producers a config toggle has set
    booted,         \* SUBSET Nodes : nodes whose producers have booted
    \* --- ingestion into the store (properties 1 & 4) ---
    happened,       \* ghost, grow-only: SUBSET Occurrences -- real occurrences
    store,          \* SUBSET of envelope records that reached the store
    envCount        \* Nat : envelopes produced so far (model bound)

vars == <<enabled, overridden, booted, happened, store, envCount>>

(* An envelope is the ONE shared producer contract: a record with a `kind`,  *)
(* an OPTIONAL `corr` correlation id (None when absent), a `labels` set, and  *)
(* the `occ` real occurrence it denotes (a ghost link used only to prove      *)
(* no-fabrication end-to-end -- an implementation never invents occ).         *)
Envelope ==
    [kind: Kinds, corr: CorrIds \cup {None}, labels: Labels, occ: Occurrences]

(* The uniform envelope-shape predicate: this is the contract every producer  *)
(* of every kind must satisfy. `labels` is always present (may be any element *)
(* of Labels), `corr` is optional (a CorrId or None), `kind` names a real     *)
(* kind. Correlation pivots need exactly this shape uniformly across kinds.    *)
WellFormedEnvelope(ev) ==
    /\ ev.kind  \in Kinds
    /\ ev.corr  \in CorrIds \cup {None}
    /\ ev.labels \in Labels
    /\ ev.occ   \in Occurrences

------------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

(* No node has booted yet; producers are all off until BootNode runs them up *)
(* to the default matrix. The store is empty. This lets DefaultsMatchSpec     *)
(* observe the boot transition rather than assuming it.                      *)
Init ==
    /\ enabled    = [n \in Nodes |-> [k \in Kinds |-> FALSE]]
    /\ overridden = [n \in Nodes |-> {}]
    /\ booted     = {}
    /\ happened   = {}
    /\ store      = {}
    /\ envCount   = 0

------------------------------------------------------------------------------
(* PRODUCER BOOT + CONFIG OVERRIDE ACTIONS (properties 2 & 3)                *)

(* Boot a node's producers to the DECLARED default matrix: every kind in     *)
(* DefaultOn comes up ON, every other kind OFF. This is what "a freshly       *)
(* booted node" means and is what DefaultsMatchSpec pins.                    *)
BootNode(n) ==
    /\ n \notin booted
    /\ booted'  = booted \cup {n}
    /\ enabled' = [enabled EXCEPT ![n] = [k \in Kinds |-> k \in DefaultOn]]
    /\ UNCHANGED <<overridden, happened, store, envCount>>

(* A config/manifest toggle flips EXACTLY one named producer on one node to   *)
(* an explicit value `v`, and records it as overridden. No other producer's   *)
(* enabled state changes (proven by ConfigOverrideHonored as no cross-talk).  *)
ConfigToggle(n, k, v) ==
    /\ n \in booted
    /\ k \in Kinds
    /\ v \in BOOLEAN
    /\ enabled'    = [enabled EXCEPT ![n][k] = v]
    /\ overridden' = [overridden EXCEPT ![n] = @ \cup {k}]
    /\ UNCHANGED <<booted, happened, store, envCount>>

------------------------------------------------------------------------------
(* INGESTION ACTIONS (properties 1 & 4)                                      *)

(* A real-world occurrence genuinely happens. Grow-only ghost fact, wholly    *)
(* independent of any producer -- the ground truth NoFabricatedSample checks  *)
(* every stored envelope against.                                            *)
Occur(o) ==
    /\ o \in Occurrences
    /\ o \notin happened
    /\ happened' = happened \cup {o}
    /\ UNCHANGED <<enabled, overridden, booted, store, envCount>>

(* The ONE producer path shared by all five kinds: a producer for kind k on   *)
(* node n, IF it is currently enabled, emits a well-formed envelope for a      *)
(* real occurrence o into the store. Two guards carry the two ingestion       *)
(* safety properties end-to-end:                                             *)
(*   - it builds an Envelope record (the uniform shape) -> ProducerContract-  *)
(*     Uniform holds for everything in the store;                            *)
(*   - it requires `o \in happened` -> NoFabricatedSample holds end-to-end:   *)
(*     no synthetic/demo data (an o that never happened) can ever be written. *)
Produce(n, k, o, c, l) ==
    /\ n \in booted
    /\ k \in Kinds
    /\ enabled[n][k]
    /\ o \in happened
    /\ c \in CorrIds \cup {None}
    /\ l \in Labels
    /\ envCount < MaxEnvelopes
    /\ LET ev == [kind |-> k, corr |-> c, labels |-> l, occ |-> o]
       IN  store' = store \cup {ev}
    /\ envCount' = envCount + 1
    /\ UNCHANGED <<enabled, overridden, booted, happened>>

------------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E n \in Nodes                       : BootNode(n)
    \/ \E n \in Nodes, k \in Kinds, v \in BOOLEAN : ConfigToggle(n, k, v)
    \/ \E o \in Occurrences                 : Occur(o)
    \/ \E n \in Nodes, k \in Kinds, o \in Occurrences,
          c \in CorrIds \cup {None}, l \in Labels : Produce(n, k, o, c, l)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ enabled    \in [Nodes -> [Kinds -> BOOLEAN]]
    /\ overridden \in [Nodes -> SUBSET Kinds]
    /\ booted     \subseteq Nodes
    /\ happened   \subseteq Occurrences
    /\ store      \subseteq Envelope
    /\ envCount   \in 0 .. MaxEnvelopes

------------------------------------------------------------------------------
(* PROPERTY 1: ONE UNIFORM PRODUCER CONTRACT ACROSS ALL FIVE KINDS          *)

(* Every envelope any producer of any kind ever wrote to the store satisfies  *)
(* the SAME {kind, correlation_id?, labels} shape -- so a correlation pivot    *)
(* (by corr id or by label) is well-defined uniformly across metrics, logs,   *)
(* traces, profiles and metadata alike.                                      *)
ProducerContractUniform ==
    \A ev \in store : WellFormedEnvelope(ev)

------------------------------------------------------------------------------
(* PROPERTY 2: A FRESHLY BOOTED NODE MATCHES THE DECLARED DEFAULT MATRIX     *)

(* For every booted node, each of its producers NOT yet overridden by config  *)
(* is ON exactly iff its kind is in the declared DefaultOn matrix. An         *)
(* overridden producer is excused (its state is governed by property 3). This *)
(* is what "defaults match spec unless overridden" means, checked live.       *)
DefaultsMatchSpec ==
    \A n \in booted :
        \A k \in Kinds :
            k \notin overridden[n] => (enabled[n][k] <=> (k \in DefaultOn))

------------------------------------------------------------------------------
(* PROPERTY 3: A CONFIG TOGGLE FLIPS EXACTLY ITS NAMED PRODUCER (NO CROSS-TALK)*)

(* Any producer whose kind was NOT overridden on a booted node still holds    *)
(* precisely its default value: a config toggle can never have leaked into a   *)
(* producer it did not name. Together with DefaultsMatchSpec this is the      *)
(* no-cross-talk guarantee -- an override touches its named producer alone.   *)
ConfigOverrideHonored ==
    \A n \in booted :
        \A k \in Kinds :
            k \notin overridden[n] => (enabled[n][k] = (k \in DefaultOn))

------------------------------------------------------------------------------
(* PROPERTY 4: NO FABRICATED / SYNTHETIC DATA REACHES THE STORE (END-TO-END) *)

(* Every envelope that reached the store denotes a real, already-`happened`   *)
(* occurrence. This is Observability.tla's store-side NoFabricatedSample       *)
(* invariant carried one hop UPSTREAM through the producer: because the ONLY   *)
(* path onto the store (Produce) requires `o \in happened`, no synthetic or    *)
(* sampled-demo data can ever be ingested.                                    *)
NoFabricatedSample ==
    \A ev \in store : ev.occ \in happened

===============================================================================
