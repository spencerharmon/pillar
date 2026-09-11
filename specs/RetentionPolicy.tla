----------------------------- MODULE RetentionPolicy -----------------------------
(***************************************************************************)
(* Manifest-driven PER-SERIES retention (ROI observability, obs slice 3).   *)
(*                                                                         *)
(* `Observability.tla` already proves retention is bounded and lossless    *)
(* under a SINGLE global `RetentionWindow` stamped at write. This spec      *)
(* models the NEW behavior slice 3 adds on top of that: an operator applies *)
(* `RetentionPolicy` manifests, each a (label-selector, window) pair, and   *)
(* the effective retention window for a signal series becomes the SHORTEST  *)
(* window among the policies whose selector matches it (falling back to the *)
(* default window when none match). The store installs the current policy   *)
(* set and stamps each freshly-written event's expiry from the effective    *)
(* window in force AT WRITE TIME; a later policy change never rewrites an    *)
(* already-written event's expiry (the Rust `TimeseriesStore::set_policies` *)
(* contract: "only affects future writes").                                *)
(*                                                                         *)
(* DESIGN GATE: no RetentionPolicy manifest/controller/web wiring may land  *)
(* until this spec is green (mirrors Observability.tla's own gate).         *)
(*                                                                         *)
(* Proven here:                                                            *)
(*                                                                         *)
(*  1. ShortestWindowWins  -- the effective window for a series is <= every *)
(*     matching policy's window (the selection really returns the minimum,  *)
(*     never a longer window a shorter policy should have overridden).      *)
(*                                                                         *)
(*  2. DefaultWhenUnmatched -- a series matched by NO installed policy       *)
(*     retains under exactly the default window (a policy set can never      *)
(*     silently drop a series' retention to zero or leave it undefined).     *)
(*                                                                         *)
(*  3. NoLossBeforeExpiry  -- exactly Observability.tla's core safety, now   *)
(*     under per-series expiries: no event vanishes from EVERY node before   *)
(*     its own stamped deadline, EVEN as the policy set changes underneath   *)
(*     it (compaction is gated on the write-time expiry, never the current   *)
(*     policy). This is what makes "changes affect future writes only" safe. *)
(*                                                                         *)
(*  4. ExpiryFrozenAtWrite -- an already-written event's expiry equals its   *)
(*     write tick plus the effective window in force when it was written     *)
(*     (a frozen ghost), so no InstallPolicies ever rewrote it. Directly the *)
(*     `set_policies` "future writes only" contract, checked.               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,          \* peers
    EventIds,       \* finite content addresses for signal events (Nat)
    Series,         \* finite set of signal-series identities a selector can match
    Windows,        \* finite set of Nat window sizes a policy may declare
    DefaultWindow,  \* the store's default retention window (used when unmatched)
    MaxTick         \* model bound on the logical clock

ASSUME NodesNonEmpty      == Nodes # {}
ASSUME EventIdsAreNats    == EventIds \subseteq Nat
ASSUME SeriesFinite       == IsFiniteSet(Series)
ASSUME WindowsArePos      == \A w \in Windows : w \in Nat /\ w > 0
ASSUME DefaultWindowPos   == DefaultWindow \in Nat /\ DefaultWindow > 0
ASSUME MaxTickIsNat       == MaxTick \in Nat

\* A policy is a (selector, window) pair. The universe of installable policies:
\* every non-empty subset of series paired with every declarable window. The
\* operator's applied RetentionPolicy set is any subset of this universe.
PolicyUniverse ==
    { [sel |-> S, window |-> w] : S \in (SUBSET Series \ {{}}), w \in Windows }

\* Minimum of a non-empty finite set of naturals.
MinOf(S) == CHOOSE x \in S : \A y \in S : x <= y

\* The largest declarable window (for the type bound).
MaxWindow == CHOOSE x \in Windows : \A y \in Windows : y <= x

\* The windows of the policies (in set P) whose selector matches series s.
MatchingWindows(s, P) == { p.window : p \in { q \in P : s \in q.sel } }

\* The effective retention window for series s under installed policy set P:
\* the shortest matching window, or the default when no policy matches.
\* (Mirrors RetentionPolicySet::effective + write_labeled's unwrap_or(default).)
EffectiveWindow(s, P) ==
    IF MatchingWindows(s, P) = {} THEN DefaultWindow
                                  ELSE MinOf(MatchingWindows(s, P))

VARIABLES
    tick,        \* Nat: global logical clock
    policySet,   \* SUBSET PolicyUniverse: currently installed RetentionPolicies
    written,     \* ghost, grow-only: SUBSET EventIds -- every event ever written
    log,         \* [Nodes -> SUBSET EventIds] -- events each node materializes
    seriesOf,    \* [EventIds -> Series] -- which series a written event belongs to
    writeTick,   \* [EventIds -> Nat] -- the tick an event was written
    writeWindow, \* [EventIds -> Nat] -- effective window in force at write (frozen)
    expiry       \* [EventIds -> Nat] -- retention deadline stamped at write

vars == <<tick, policySet, written, log, seriesOf, writeTick, writeWindow, expiry>>

------------------------------------------------------------------------------
(* INITIAL STATE: no policies installed, nothing written.                   *)

anySeries == CHOOSE s \in Series : TRUE

Init ==
    /\ tick        = 0
    /\ policySet   = {}
    /\ written     = {}
    /\ log         = [n \in Nodes |-> {}]
    /\ seriesOf    = [e \in EventIds |-> anySeries]
    /\ writeTick   = [e \in EventIds |-> 0]
    /\ writeWindow = [e \in EventIds |-> 0]
    /\ expiry      = [e \in EventIds |-> 0]

------------------------------------------------------------------------------
(* ACTIONS                                                                   *)

AdvanceTick ==
    /\ tick < MaxTick
    /\ tick' = tick + 1
    /\ UNCHANGED <<policySet, written, log, seriesOf, writeTick, writeWindow, expiry>>

\* The operator applies/removes RetentionPolicy manifests: the installed set
\* becomes ANY (different) subset of the universe. Crucially this touches ONLY
\* policySet -- never the expiry of an already-written event.
InstallPolicies(P) ==
    /\ P \in SUBSET PolicyUniverse
    /\ P # policySet
    /\ policySet' = P
    /\ UNCHANGED <<tick, written, log, seriesOf, writeTick, writeWindow, expiry>>

\* Write a signal event e for series s. Its expiry is stamped ONCE, from the
\* effective window in force right now, and never changes afterwards.
WriteEvent(n, e, s) ==
    /\ e \in EventIds
    /\ e \notin written
    /\ s \in Series
    /\ written'     = written \cup {e}
    /\ log'         = [log EXCEPT ![n] = @ \cup {e}]
    /\ seriesOf'    = [seriesOf EXCEPT ![e] = s]
    /\ writeTick'   = [writeTick EXCEPT ![e] = tick]
    /\ writeWindow' = [writeWindow EXCEPT ![e] = EffectiveWindow(s, policySet)]
    /\ expiry'      = [expiry EXCEPT ![e] = tick + EffectiveWindow(s, policySet)]
    /\ UNCHANGED <<tick, policySet>>

\* Replicate held events between nodes (AP gossip).
Gossip(n, m) ==
    /\ n # m
    /\ ~(log[n] \subseteq log[m])
    /\ log' = [log EXCEPT ![m] = @ \cup log[n]]
    /\ UNCHANGED <<tick, policySet, written, seriesOf, writeTick, writeWindow, expiry>>

\* Compaction may drop an event from ONE node only once the clock has passed
\* that event's OWN stamped deadline -- gated on the write-time expiry, not the
\* (possibly since-changed) current policy set.
Compact(n, e) ==
    /\ e \in log[n]
    /\ tick >= expiry[e]
    /\ log' = [log EXCEPT ![n] = @ \ {e}]
    /\ UNCHANGED <<tick, policySet, written, seriesOf, writeTick, writeWindow, expiry>>

Next ==
    \/ AdvanceTick
    \/ \E P \in SUBSET PolicyUniverse               : InstallPolicies(P)
    \/ \E n \in Nodes, e \in EventIds, s \in Series  : WriteEvent(n, e, s)
    \/ \E n, m \in Nodes                             : Gossip(n, m)
    \/ \E n \in Nodes, e \in EventIds                : Compact(n, e)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ tick        \in 0 .. MaxTick
    /\ policySet   \in SUBSET PolicyUniverse
    /\ written     \subseteq EventIds
    /\ log         \in [Nodes -> SUBSET EventIds]
    /\ seriesOf    \in [EventIds -> Series]
    /\ writeTick   \in [EventIds -> 0 .. MaxTick]
    /\ writeWindow \in [EventIds -> 0 .. MaxWindow]
    /\ expiry      \in [EventIds -> 0 .. (MaxTick + MaxWindow)]

------------------------------------------------------------------------------
(* PROPERTIES                                                                *)

\* (1) The effective window really is the minimum matching window: it is <=
\* every matching policy's window, so a shorter policy always wins.
ShortestWindowWins ==
    \A s \in Series :
        \A p \in policySet :
            s \in p.sel => EffectiveWindow(s, policySet) <= p.window

\* (2) A series no installed policy matches retains under exactly the default.
DefaultWhenUnmatched ==
    \A s \in Series :
        (\A p \in policySet : s \notin p.sel) =>
            EffectiveWindow(s, policySet) = DefaultWindow

\* (3) Grow-only, never fabricated.
LogSubsetOfWritten == \A n \in Nodes : log[n] \subseteq written

\* (3) No event silently vanishes from EVERY node before its own stamped
\* deadline -- holds across arbitrary interleaved InstallPolicies steps.
NoLossBeforeExpiry ==
    \A e \in written : tick < expiry[e] => \E n \in Nodes : e \in log[n]

\* (4) An already-written event's expiry is exactly its write tick plus the
\* effective window that was in force when it was written (the frozen ghost),
\* so no InstallPolicies ever rewrote it. If a later policy change had mutated
\* expiry, this stamped identity would break for some reachable state.
ExpiryFrozenAtWrite ==
    \A e \in written : expiry[e] = writeTick[e] + writeWindow[e]

===============================================================================
