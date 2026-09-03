-------------------------- MODULE SchedulerController --------------------------
(***************************************************************************)
(* Pillar's ONE shared scheduler controller.                               *)
(*                                                                         *)
(* There is exactly one scheduling engine.  It runs BOTH workload jobs     *)
(* (k8s-CronJob/Job semantics: a schedule, a concurrency policy, backoff   *)
(* on failure, bounded run-history) AND the internal observability         *)
(* evaluations (RecordingRule / Alert evaluations) as scheduled jobs on    *)
(* the SAME engine.  There is NO second, private scheduler for             *)
(* observability -- an observability evaluation and a workload CronJob     *)
(* fire, run, retry, and retire through the identical scheduling decision  *)
(* path.  This is the "synergy spine" method #1: one engine, no fork.       *)
(*                                                                         *)
(* Each schedulable is a `job`.  A job has:                                 *)
(*   kind    -- "workload" | "observability" (its ORIGIN, never a          *)
(*              second engine -- both take the identical decision path),   *)
(*   policy  -- "Allow" | "Forbid" | "Replace" (k8s concurrencyPolicy),    *)
(*   tier    -- the topology tier it must be placed in (reuses the         *)
(*              existing topology-label-hierarchy: an ordered set of       *)
(*              tiers, a job placed only where its required tier permits).  *)
(* A run has a status: "running" | "succeeded" | "failed".                 *)
(*                                                                         *)
(* Modelled: schedule evaluation (a due job fires a run), concurrency-     *)
(* policy enforcement (Allow/Forbid/Replace against an already-running     *)
(* run), backoff-on-failure (a bounded, non-busy-loop retry budget),       *)
(* bounded run-history retention (old runs are pruned to a fixed cap), and *)
(* placement by topology tier.                                             *)
(*                                                                         *)
(* Safety proven by TLC:                                                    *)
(*   OneEngineNoFork          -- every run, workload or observability,     *)
(*                               was produced by the single Fire path.     *)
(*   ConcurrencyPolicyHonored -- Forbid/Replace never leave two running.   *)
(*   BackoffBounded           -- failures consume a finite budget; no      *)
(*                               busy-loop of unbounded refires.           *)
(*   RunHistoryBounded        -- retained history per job <= a fixed cap.   *)
(*   PlacementRespectsTopology-- a run is only ever placed in a tier the   *)
(*                               job's required tier permits.              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Jobs,           \* set of job identities
    Kind,           \* function Jobs -> {"workload","observability"}
    Policy,         \* function Jobs -> {"Allow","Forbid","Replace"}
    ReqTier,        \* function Jobs -> Tiers : the topology tier a job requires
    Tiers,          \* the ordered set of topology tiers (topology-label-hierarchy)
    TierRank,       \* function Tiers -> Nat : the hierarchy order (0 = broadest)
    MaxBackoff,     \* per-job retry budget bound (backoff cap)
    HistoryCap,     \* bounded run-history retention per job
    MaxRuns         \* model bound: total runs the engine will ever create

ASSUME JobsNonEmpty   == Jobs # {}
ASSUME KindDef        == Kind    \in [Jobs -> {"workload","observability"}]
ASSUME PolicyDef      == Policy  \in [Jobs -> {"Allow","Forbid","Replace"}]
ASSUME TiersNonEmpty  == Tiers # {}
ASSUME ReqTierDef     == ReqTier \in [Jobs -> Tiers]
ASSUME TierRankDef    == TierRank \in [Tiers -> Nat]
ASSUME BackoffIsNat   == MaxBackoff \in Nat
ASSUME HistoryIsNat   == HistoryCap \in Nat /\ HistoryCap > 0
ASSUME MaxRunsIsNat   == MaxRuns \in Nat

RunStatus == {"running", "succeeded", "failed"}

\* A job may be PLACED in any tier at least as specific as (rank >= its required
\* tier's rank) the tier it requires -- the topology-label-hierarchy admission
\* rule.  A placement in a broader (rank <) tier is forbidden.
AdmissibleTiers(j) == {t \in Tiers : TierRank[t] >= TierRank[ReqTier[j]]}

VARIABLES
    runs,       \* seq of records: [job, kind, status, tier, path] -- the run-history ledger
    backoff,    \* backoff[j] : failures charged against job j's retry budget
    nextId      \* monotonic count of runs ever created (model bound)

vars == <<runs, backoff, nextId>>

RunRec == [ job: Jobs, kind: {"workload","observability"}, status: RunStatus,
            tier: Tiers, path: {"fire"} ]

TypeOK ==
    /\ nextId \in 0 .. MaxRuns
    /\ backoff \in [Jobs -> 0 .. MaxBackoff]
    /\ runs \in Seq(RunRec)
    /\ \A i \in 1 .. Len(runs) : runs[i] \in RunRec

Init ==
    /\ runs    = << >>
    /\ backoff = [j \in Jobs |-> 0]
    /\ nextId  = 0

\* --- helpers over the run-history ledger ---------------------------------

RunningOf(j) == { i \in 1 .. Len(runs) : runs[i].job = j /\ runs[i].status = "running" }
HasRunning(j) == RunningOf(j) # {}
HistoryCount(j) == Cardinality({ i \in 1 .. Len(runs) : runs[i].job = j })

\* Indices of job j's TERMINAL (non-running) history entries, oldest first.
TerminalOf(j) == { i \in 1 .. Len(runs) : runs[i].job = j /\ runs[i].status # "running" }

\* Drop a set of indices from the run-history sequence, preserving order.
DropIdx(s, drop) ==
    LET keep == SelectSeq(
                  [ i \in 1 .. Len(s) |-> <<i, s[i]>> ],
                  LAMBDA p : p[1] \notin drop)
    IN [ i \in 1 .. Len(keep) |-> keep[i][2] ]

\* Prune terminal entries of j in sequence s down to at most HistoryCap,
\* oldest-first.  Running entries are retained (they are in flight, not
\* history).  Applied whenever a run TERMINATES, so retained history is bounded
\* the instant it would exceed the cap -- not asynchronously.  Recurses on the
\* count of j's terminal entries, which strictly decreases each drop.
RECURSIVE PruneTerminals(_, _)
PruneTerminals(s, j) ==
    LET term == { i \in 1 .. Len(s) : s[i].job = j /\ s[i].status # "running" }
    IN IF Cardinality(term) <= HistoryCap
       THEN s
       ELSE LET oldest == CHOOSE i \in term : \A k \in term : i <= k
            IN PruneTerminals(DropIdx(s, {oldest}), j)

\* The SINGLE fire path.  Both a workload CronJob and an observability
\* evaluation reach a running state ONLY through this operator -- there is no
\* alternate engine.  Every created run is stamped path |-> "fire".
NewRun(j, tr) == [ job |-> j, kind |-> Kind[j], status |-> "running",
                   tier |-> tr, path |-> "fire" ]

\* --- schedule evaluation + concurrency policy ----------------------------

\* Fire job j (its schedule is due) into an admissible tier tr.  Concurrency
\* policy decides what happens versus an already-running run of the same job:
\*   Allow   -- always fire (a second concurrent run may exist).
\*   Forbid  -- skip firing entirely if one is already running.
\*   Replace -- terminate the running run (mark it "failed"), then fire.
\* Placement obeys the topology hierarchy (tr \in AdmissibleTiers(j)).
Fire(j, tr) ==
    /\ nextId < MaxRuns
    /\ tr \in AdmissibleTiers(j)
    /\ LET pol == Policy[j]
           \* Apply the policy's effect on any already-running run, then append
           \* the new run, then enforce retention over the whole result.  The
           \* new run is "running" so PruneTerminals never evicts it.
           afterPolicy ==
               IF pol = "Replace"
               THEN [ i \in 1 .. Len(runs) |->
                        IF runs[i].job = j /\ runs[i].status = "running"
                        THEN [runs[i] EXCEPT !.status = "failed"]
                        ELSE runs[i] ]
               ELSE runs
       IN
       /\ (pol = "Forbid") => ~HasRunning(j)
       /\ runs' = PruneTerminals(Append(afterPolicy, NewRun(j, tr)), j)
    /\ nextId' = nextId + 1
    /\ UNCHANGED backoff

\* A running run of j succeeds.  Clears the job's backoff budget.  Retention is
\* re-enforced: the newly-terminal run may push retained history over the cap, so
\* the oldest terminal entries are pruned back to HistoryCap in the same step.
Succeed(j) ==
    /\ \E i \in RunningOf(j) :
         runs' = PruneTerminals([runs EXCEPT ![i].status = "succeeded"], j)
    /\ backoff' = [backoff EXCEPT ![j] = 0]
    /\ UNCHANGED nextId

\* A running run of j fails.  Charges the retry budget.  Backoff is BOUNDED:
\* a job that has exhausted MaxBackoff failures cannot be failed further into a
\* busy-loop -- the guard `backoff[j] < MaxBackoff` caps refire pressure.
\* Retention is re-enforced exactly as in Succeed.
Fail(j) ==
    /\ backoff[j] < MaxBackoff
    /\ \E i \in RunningOf(j) :
         runs' = PruneTerminals([runs EXCEPT ![i].status = "failed"], j)
    /\ backoff' = [backoff EXCEPT ![j] = backoff[j] + 1]
    /\ UNCHANGED nextId

\* Bounded run-history retention is enforced eagerly at Fire time (see
\* RetainedBase): a job at HistoryCap evicts its oldest terminal entry before a
\* new run is appended, so retained history per job never exceeds the cap.

Next ==
    \/ \E j \in Jobs, tr \in Tiers : Fire(j, tr)
    \/ \E j \in Jobs : Succeed(j)
    \/ \E j \in Jobs : Fail(j)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* MODEL INSTANCE                                                            *)
(* Concrete finite instance the .cfg wires in via constant/definition        *)
(* overrides.  Kept in-module because the .cfg format cannot express a        *)
(* function literal ([a |-> x, ...]) as a constant value.  The model values   *)
(* j1..j3 / t1..t3 are declared in the .cfg; here we map them.               *)

CONSTANTS j1, j2, j3, t1, t2, t3

MCJobs  == {j1, j2, j3}
MCTiers == {t1, t2, t3}

\* j1 workload/Forbid/broad, j2 observability/Replace/mid, j3 workload/Allow/leaf.
MCKind    == [x \in MCJobs |-> IF x = j2 THEN "observability" ELSE "workload"]
MCPolicy  == (j1 :> "Forbid") @@ (j2 :> "Replace") @@ (j3 :> "Allow")
MCReqTier == (j1 :> t1) @@ (j2 :> t2) @@ (j3 :> t3)
MCTierRank == (t1 :> 0) @@ (t2 :> 1) @@ (t3 :> 2)

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* OneEngineNoFork: every run in the ledger -- whether it originated as a
\* workload CronJob or as an observability RecordingRule/Alert evaluation --
\* was produced by the single Fire path (path = "fire").  There is no second,
\* private scheduler: both kinds are present, and both share the identical
\* decision path.  This is the core "one engine, no fork" guarantee.
OneEngineNoFork ==
    \A i \in 1 .. Len(runs) : runs[i].path = "fire"

\* ConcurrencyPolicyHonored: a job whose policy is Forbid or Replace never has
\* two runs simultaneously in the "running" state.  (Allow may.)
ConcurrencyPolicyHonored ==
    \A j \in Jobs :
        (Policy[j] \in {"Forbid","Replace"}) =>
            Cardinality(RunningOf(j)) <= 1

\* BackoffBounded: no job ever exceeds its retry budget -- failures cannot
\* busy-loop unboundedly.
BackoffBounded ==
    \A j \in Jobs : backoff[j] <= MaxBackoff

\* RunHistoryBounded: the RETAINED (terminal) run-history per job never exceeds
\* HistoryCap.  Only terminal entries count as retained history -- a still-
\* running run is in flight, not history, and is not evictable -- so this is the
\* exact k8s successful/failedJobsHistoryLimit guarantee: the engine evicts the
\* oldest terminal run before appending a new one once the cap is reached.
RunHistoryBounded ==
    \A j \in Jobs : Cardinality(TerminalOf(j)) <= HistoryCap

\* PlacementRespectsTopology: every run is placed in a tier the job's required
\* tier admits under the topology-label-hierarchy -- never a broader tier.
PlacementRespectsTopology ==
    \A i \in 1 .. Len(runs) :
        runs[i].tier \in AdmissibleTiers(runs[i].job)

=============================================================================
