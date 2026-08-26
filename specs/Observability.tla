------------------------------ MODULE Observability ------------------------------
(***************************************************************************)
(* Pillar built-in distributed observability (ROI new Priority 3,           *)
(* 2026-08-26): metrics/logging/tracing/profiling/metadata-sampling as      *)
(* core services riding the streaming DB. An observability signal is just   *)
(* another append-only, content-addressed event on the existing eventlog    *)
(* (StreamingDB.tla) -- this spec does NOT re-model the op-log itself; it   *)
(* models the THREE additional safety properties this feature layers on    *)
(* top of it, and composes (does not fork) the single WoT/RBAC authority    *)
(* decider (WoTAuthority.tla) for reads.  DESIGN GATE (ROI, 2026-08-26): no  *)
(* `*-impl` task may land until this spec is green.                        *)
(*                                                                         *)
(*  1. Retention/compaction is bounded and lossless within its retention    *)
(*     window: a signal event never silently vanishes from every node      *)
(*     before its declared per-write retention deadline (`expiry`), and     *)
(*     compaction (`Compact`) never fabricates an event -- every event any  *)
(*     node ever holds is one that was actually written (grow-only          *)
(*     `written`, exactly StreamingDB's `NoLostWrite`/`LogSubsetOfWritten`   *)
(*     pattern), and `Compact` is enabled only once the clock has passed    *)
(*     that event's own expiry (never early, never for another event).      *)
(*                                                                         *)
(*  2. Metadata sampling never double-counts or fabricates a sample: a      *)
(*     sample event (`EmitSample`) may only be recorded for an occurrence   *)
(*     that has genuinely `happened` (a ghost, grow-only, real-world fact   *)
(*     independent of any sampler's say-so) -- NoFabricatedSample -- and    *)
(*     each occurrence may be sampled at most `SampleCap` times, the        *)
(*     policy's configured rate -- NoDoubleCountSample.                     *)
(*                                                                         *)
(*  3. Read authority: a peer may materialize/read a signal's view only     *)
(*     under a currently-live, RBAC-decider-granted capability -- reusing   *)
(*     WoTAuthority's owner-anchored tsig reachability and revoke-before-   *)
(*     act fencing UNCHANGED (composed via INSTANCE, exactly the pattern    *)
(*     StreamingDB.tla uses to compose CoordinationCore) rather than        *)
(*     inventing a second, parallel authority path. ReadRequiresAuthority   *)
(*     and FailClosedReadUnderStaleView mirror WoTAuthority's own           *)
(*     NoActionAfterRevocation / FailClosedUnderStaleView for this new      *)
(*     action, and the imported invariants confirm the underlying decider   *)
(*     itself is untouched by composition.                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,          \* peers (shared with the composed WoTAuthority instance)
    EventIds,       \* finite set of content addresses for signal events (Nat)
    Occurrences,    \* finite set of real-world occurrences a sample may reference
    RetentionWindow,\* ticks a freshly-written event stays live before it may compact
    MaxTick,        \* model bound on the logical clock
    SampleCap,      \* policy's configured max samples per occurrence
    Owner,          \* WoTAuthority: trust anchor
    MaxDepth,       \* WoTAuthority: tsig delegation depth bound
    None            \* shared sentinel: "no candidate" / "not a sample event"

ASSUME NodesNonEmpty       == Nodes # {}
ASSUME EventIdsAreNats     == EventIds \subseteq Nat
ASSUME OccurrencesFinite   == IsFiniteSet(Occurrences)
ASSUME RetentionWindowNat  == RetentionWindow \in Nat
ASSUME MaxTickIsNat        == MaxTick \in Nat
ASSUME SampleCapIsNat      == SampleCap \in Nat
ASSUME NoneNotEvent        == None \notin EventIds
ASSUME NoneNotOccurrence   == None \notin Occurrences

VARIABLES
    \* --- signal event log: retention/compaction (property 1) ---
    tick,           \* Nat: global logical clock
    written,        \* ghost: SUBSET EventIds -- every signal event ever appended anywhere
    log,            \* log[n] : SUBSET EventIds -- events node n currently materializes
    expiry,         \* [EventIds -> Nat] -- retention deadline set at write time
    \* --- metadata sampling (property 2) ---
    happened,       \* ghost, grow-only: SUBSET Occurrences -- occurrences that really occurred
    sampled,        \* [Occurrences -> Nat] -- samples emitted so far per occurrence
    sampleOf,       \* [EventIds -> Occurrences \cup {None}] -- which occurrence a sample event denotes
    \* --- read authority (property 3) ---
    lastRead,       \* ghost: most recent ReadSignalView attempt + its authorization snapshot
    \* --- composed WoTAuthority state (the single RBAC decider, untouched) ---
    edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned, lastAct

ownVars == <<tick, written, log, expiry, happened, sampled, sampleOf, lastRead>>
wotVars == <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned, lastAct>>
vars    == <<tick, written, log, expiry, happened, sampled, sampleOf, lastRead,
             edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned, lastAct>>

\* Compose the SAME WoT/RBAC decider StreamingDB composes CoordinationCore with:
\* shared variables (declared above, matching WoTAuthority's own names), so this
\* is literally the one authority path, never a parallel/forked one.
WOT == INSTANCE WoTAuthority

------------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ tick      = 0
    /\ written   = {}
    /\ log       = [n \in Nodes |-> {}]
    /\ expiry    = [e \in EventIds |-> 0]
    /\ happened  = {}
    /\ sampled   = [o \in Occurrences |-> 0]
    /\ sampleOf  = [e \in EventIds |-> None]
    /\ lastRead  = [some |-> FALSE, reader |-> CHOOSE n \in Nodes : TRUE,
                    sig |-> CHOOSE e \in EventIds : TRUE, authSnap |-> {}, watermark |-> 0]
    /\ WOT!Init

------------------------------------------------------------------------------
(* RETENTION / COMPACTION ACTIONS (property 1)                              *)

AdvanceTick ==
    /\ tick < MaxTick
    /\ tick' = tick + 1
    /\ UNCHANGED <<written, log, expiry, happened, sampled, sampleOf, lastRead>>
    /\ UNCHANGED wotVars

\* A plain (non-sample) signal event: a metric/log/trace/profile point. Its
\* retention deadline is fixed the moment it is written and never changes.
WriteEvent(n, e) ==
    /\ e \in EventIds
    /\ e \notin written
    /\ written' = written \cup {e}
    /\ log'     = [log EXCEPT ![n] = @ \cup {e}]
    /\ expiry'  = [expiry EXCEPT ![e] = tick + RetentionWindow]
    /\ sampleOf' = [sampleOf EXCEPT ![e] = None]
    /\ UNCHANGED <<tick, happened, sampled, lastRead>>
    /\ UNCHANGED wotVars

\* Replicate held signal events between nodes (AP, mirrors StreamingDB Gossip).
Gossip(n, m) ==
    /\ n # m
    /\ ~(log[n] \subseteq log[m])
    /\ log' = [log EXCEPT ![m] = @ \cup log[n]]
    /\ UNCHANGED <<tick, written, expiry, happened, sampled, sampleOf, lastRead>>
    /\ UNCHANGED wotVars

\* Compaction may drop an event from ONE node's materialized view only once
\* the clock has passed that event's own declared retention deadline -- never
\* early, and it removes only an event that was genuinely written (log
\* stays a subset of `written`, so compaction can never fabricate an event).
Compact(n, e) ==
    /\ e \in log[n]
    /\ tick >= expiry[e]
    /\ log' = [log EXCEPT ![n] = @ \ {e}]
    /\ UNCHANGED <<tick, written, expiry, happened, sampled, sampleOf, lastRead>>
    /\ UNCHANGED wotVars

------------------------------------------------------------------------------
(* METADATA-SAMPLING ACTIONS (property 2)                                   *)

\* A real-world occurrence that CAN be sampled actually happens. Grow-only
\* ghost fact, independent of whether/how it is later sampled.
Occur(o) ==
    /\ o \in Occurrences
    /\ o \notin happened
    /\ happened' = happened \cup {o}
    /\ UNCHANGED <<tick, written, log, expiry, sampled, sampleOf, lastRead>>
    /\ UNCHANGED wotVars

\* Emit a metadata-sampling event for occurrence o. Guarded so it can never
\* fabricate (o must have genuinely `happened`) and never exceed the policy's
\* configured rate (`sampled[o] < SampleCap`) -- i.e. never double-count.
EmitSample(n, e, o) ==
    /\ e \in EventIds
    /\ e \notin written
    /\ o \in happened
    /\ sampled[o] < SampleCap
    /\ written'  = written \cup {e}
    /\ log'      = [log EXCEPT ![n] = @ \cup {e}]
    /\ expiry'   = [expiry EXCEPT ![e] = tick + RetentionWindow]
    /\ sampleOf' = [sampleOf EXCEPT ![e] = o]
    /\ sampled'  = [sampled EXCEPT ![o] = @ + 1]
    /\ UNCHANGED <<tick, happened, lastRead>>
    /\ UNCHANGED wotVars

------------------------------------------------------------------------------
(* READ-AUTHORITY ACTION (property 3): reuses WoTAuthority, never forks it  *)

\* A peer materializes/reads a signal's view. Gated EXACTLY like WoTAuthority's
\* own Act: the reader must be currently, freshly (fully caught-up watermark)
\* authoritative per the SAME owner-anchored tsig/RBAC decider -- composed,
\* not a second authority path. `lastRead` records the authorization snapshot
\* the same way WoTAuthority's `lastAct` does, giving the same exhaustive,
\* every-Act-checked-once coverage for this new action.
ReadSignalView(reader, e) ==
    /\ e \in written
    /\ freshMark[reader] = WOT!RevCount
    /\ reader \in WOT!CurrentAuthNodes
    /\ lastRead' = [some |-> TRUE, reader |-> reader, sig |-> e,
                    authSnap |-> WOT!CurrentAuthNodes, watermark |-> WOT!RevCount]
    /\ UNCHANGED <<tick, written, log, expiry, happened, sampled, sampleOf>>
    /\ UNCHANGED wotVars

------------------------------------------------------------------------------
(* COMPOSED WoT/RBAC STEP (the decider's own actions, imported verbatim)    *)

WoTStep ==
    /\ WOT!Next
    /\ UNCHANGED ownVars

------------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ AdvanceTick
    \/ \E o \in Occurrences                    : Occur(o)
    \/ \E n \in Nodes, e \in EventIds           : WriteEvent(n, e)
    \/ \E n \in Nodes, e \in EventIds, o \in Occurrences : EmitSample(n, e, o)
    \/ \E n, m \in Nodes                        : Gossip(n, m)
    \/ \E n \in Nodes, e \in EventIds           : Compact(n, e)
    \/ \E r \in Nodes, e \in EventIds           : ReadSignalView(r, e)
    \/ WoTStep

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ tick     \in 0 .. MaxTick
    /\ written  \subseteq EventIds
    /\ log      \in [Nodes -> SUBSET EventIds]
    /\ expiry   \in [EventIds -> 0 .. (MaxTick + RetentionWindow)]
    /\ happened \subseteq Occurrences
    /\ sampled  \in [Occurrences -> 0 .. SampleCap]
    /\ sampleOf \in [EventIds -> Occurrences \cup {None}]
    /\ lastRead \in [some: BOOLEAN, reader: Nodes, sig: EventIds,
                     authSnap: SUBSET Nodes, watermark: 0 .. WOT!MaxRevCount]
    /\ WOT!TypeOK

------------------------------------------------------------------------------
(* PROPERTY 1: RETENTION/COMPACTION BOUNDED AND LOSSLESS                     *)

\* Grow-only ledger, never fabricated: every node's materialized log is always
\* a subset of everything ever written (mirrors StreamingDB.LogSubsetOfWritten).
LogSubsetOfWritten == \A n \in Nodes : log[n] \subseteq written

\* No event silently vanishes from EVERY node before its own declared
\* retention deadline has passed.
NoLossBeforeExpiry ==
    \A e \in written : tick < expiry[e] => \E n \in Nodes : e \in log[n]

------------------------------------------------------------------------------
(* PROPERTY 2: SAMPLING NEVER DOUBLE-COUNTS OR FABRICATES                    *)

\* Every recorded sample event denotes a real, already-`happened` occurrence.
NoFabricatedSample ==
    \A e \in EventIds : sampleOf[e] # None => sampleOf[e] \in happened

\* No occurrence is ever sampled more than the policy's configured rate.
NoDoubleCountSample == \A o \in Occurrences : sampled[o] <= SampleCap

------------------------------------------------------------------------------
(* PROPERTY 3: READ AUTHORITY VIA THE SINGLE RBAC DECIDER                    *)

\* The most recent read (if any) was performed by a reader who WAS
\* RBAC-authoritative at the exact moment it read.
ReadRequiresAuthority == lastRead.some => lastRead.reader \in lastRead.authSnap

\* Fail-closed under a stale local view: a reader whose watermark lags the
\* true global one can never appear as the actor of a read most recently
\* recorded as fully fresh against the CURRENT watermark.
FailClosedReadUnderStaleView ==
    \A n \in Nodes :
        freshMark[n] < WOT!RevCount =>
            ~ (/\ lastRead.some
               /\ lastRead.reader = n
               /\ lastRead.watermark = WOT!RevCount)

\* The composed decider's OWN invariants still hold, untouched by composition
\* -- confirming this is the same single authority path, never a fork.
NoActionAfterRevocation == WOT!NoActionAfterRevocation
FailClosedUnderStaleView == WOT!FailClosedUnderStaleView
FreshMarkBounded         == WOT!FreshMarkBounded

===============================================================================
</content>
