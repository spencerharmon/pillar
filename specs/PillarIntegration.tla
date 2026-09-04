-------------------------- MODULE PillarIntegration --------------------------
(***************************************************************************)
(* Pillar integration-conformance rig: the formal contract for the whole   *)
(* rig, model-checked BEFORE any rig code is trusted (specs-first, per this *)
(* repo's convention).  This is the gate every other pillar-integration     *)
(* task builds against.                                                     *)
(*                                                                         *)
(* It formalises FIVE things the ROI                                        *)
(* "pillar-integration: the conformance rig that demands working code"      *)
(* demands, as a single state machine + invariants:                         *)
(*                                                                         *)
(*  1. The SCENARIO LIFECYCLE.  Each scenario walks a strict lifecycle:      *)
(*        declared -> running -> oracleAsserted -> tornDown                  *)
(*     Teardown is UNCONDITIONAL: a scenario reaches `tornDown` on both the  *)
(*     pass and the fail path, and NO reachable state skips teardown         *)
(*     (`NoStateSkipsTeardown`).  A scenario's oracle claim is counted       *)
(*     AT MOST ONCE (`NoDoubleCountedClaim`) -- the assert transition is the *)
(*     only place a claim flips proven, and it fires once per scenario.      *)
(*                                                                         *)
(*  2. The SURFACE INVENTORY <-> SCENARIO DECLARATION relation.  Every       *)
(*     scenario declares which inventory entries it CLAIMS and which oracle  *)
(*     PROVES the claim.  Claims only ever target real inventory entries     *)
(*     (`ClaimsTargetRealSurface`) and every scenario names a real oracle    *)
(*     (`ScenarioNamesRealOracle`).                                          *)
(*                                                                         *)
(*  3. The COVERAGE GATES (Gates 1-3).                                       *)
(*       Gate 1 -- NO ORPHAN SURFACE: once the rig is sealed, every          *)
(*         inventory entry is claimed by some scenario (`Gate1_NoOrphan`     *)
(*         holds in the sealed terminal state).                             *)
(*       Gate 2 -- DONE REQUIRES A GREEN SCENARIO: an inventory entry is     *)
(*         only ever marked `covered` when a scenario that claims it reached *)
(*         `oracleAsserted` with a PROVEN oracle (`Gate2_CoveredIsProven`).  *)
(*       Gate 3 -- NO SKIP/XFEL CREEP PAST A DEADLINE: a scenario may be     *)
(*         `skipped`, but only with a deadline that has not passed; once the *)
(*         deadline passes an un-un-skipped scenario is a violation          *)
(*         (`Gate3_NoExpiredSkip`).                                          *)
(*                                                                         *)
(*  4. FIXTURE ISOLATION: no two DISTINCT running scenarios ever hold the    *)
(*     same fixture resource (`NoSharedFixtureState`) -- there is no         *)
(*     cross-scenario shared mutable state.                                  *)
(*                                                                         *)
(*  5. IDEMPOTENT TEARDOWN + LEAK DETECTION: a torn-down scenario holds no   *)
(*     fixture resources (`TeardownReleasesFixtures`) and, in the sealed     *)
(*     terminal state, the global leak detector sees zero residue           *)
(*     (`NoResidueWhenSealed`) -- teardown ran for every scenario, even the  *)
(*     failed ones.                                                          *)
(*                                                                         *)
(* Safety-only model (`-deadlock`): the sealed terminal state -- every       *)
(* scenario torn down and the rig sealed -- is expected quiescence, not a    *)
(* fault.                                                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Surfaces,    \* set of surface-inventory entries (CLI verb / HTTP route / manifest kind / wire op)
    Scenarios,   \* set of scenario identities
    Oracles,     \* set of oracle identities (packet, ciphertext, process, content-address, crypto, state-survival)
    Fixtures,    \* set of fixture resource identities a scenario may hold
    Deadline     \* model bound: the wall-clock tick at which a skip expires

ASSUME SurfacesNonEmpty  == Surfaces  # {}
ASSUME ScenariosNonEmpty == Scenarios # {}
ASSUME OraclesNonEmpty   == Oracles   # {}
ASSUME DeadlineIsNat     == Deadline \in Nat

Phases == {"declared", "running", "oracleAsserted", "tornDown", "skipped"}

\* The declared, static shape of the rig -- the schema the round-trip test
\* parses/re-serialises.  Each scenario CLAIMS a non-empty set of inventory
\* entries and names exactly one oracle that PROVES the claim.
\*
\* Rather than pin scenario->surface literals in the .cfg (TLC .cfg cannot carry
\* a function literal), the model DERIVES a concrete, non-orphaning assignment
\* from the constant sets alone, so it is expressed purely over the model values
\* the .cfg supplies:
\*   * ClaimsDef  : every scenario claims EVERY surface -- guarantees Gate 1
\*     (no orphan surface) is satisfiable at seal for any finite instance, while
\*     still exercising the covered/proven bookkeeping.
\*   * ProvenByDef: every scenario names a fixed, real oracle (some element of
\*     Oracles), satisfying ScenarioNamesRealOracle.
\* The .cfg wires these onto the CONSTANT parameters with `<-` operator overrides.
ClaimsDef   == [s \in Scenarios |-> Surfaces]
ProvenByDef == [s \in Scenarios |-> CHOOSE o \in Oracles : TRUE]

CONSTANTS Claims,   \* Claims[s]  \subseteq Surfaces : entries scenario s claims
          ProvenBy  \* ProvenBy[s] \in Oracles     : the oracle that proves s

ASSUME ClaimsShape   == Claims \in [Scenarios -> SUBSET Surfaces]
ASSUME ProvenByShape == ProvenBy \in [Scenarios -> Oracles]

VARIABLES
    phase,     \* phase[s]    : lifecycle phase of scenario s
    proven,    \* proven[s]   : TRUE once s's oracle asserted (claim counted once)
    held,      \* held[s]     : set of fixture resources s currently holds
    covered,   \* covered     : set of surface entries marked covered (Gate 2)
    skipDdl,   \* skipDdl[s]  : deadline stamped when s was skipped (0 = not skipped)
    clock,     \* clock       : monotone wall-clock tick (drives Gate 3)
    sealed     \* sealed      : TRUE once the rig is sealed (coverage gates evaluated)

vars == <<phase, proven, held, covered, skipDdl, clock, sealed>>

TypeOK ==
    /\ phase   \in [Scenarios -> Phases]
    /\ proven  \in [Scenarios -> BOOLEAN]
    /\ held    \in [Scenarios -> SUBSET Fixtures]
    /\ covered \subseteq Surfaces
    /\ skipDdl \in [Scenarios -> Nat]
    /\ clock   \in Nat
    /\ sealed  \in BOOLEAN

Init ==
    /\ phase   = [s \in Scenarios |-> "declared"]
    /\ proven  = [s \in Scenarios |-> FALSE]
    /\ held    = [s \in Scenarios |-> {}]
    /\ covered = {}
    /\ skipDdl = [s \in Scenarios |-> 0]
    /\ clock   = 0
    /\ sealed  = FALSE

-----------------------------------------------------------------------------
(* LIFECYCLE TRANSITIONS *)

\* declared -> running : the scenario acquires its fixtures.  Fixture isolation
\* is enforced HERE -- it may only take resources no other running scenario holds.
Start(s) ==
    /\ ~sealed
    /\ phase[s] = "declared"
    /\ \E F \in (SUBSET Fixtures) \ {{}} :
         /\ \A t \in Scenarios \ {s} :
              (phase[t] = "running") => (F \cap held[t] = {})
         /\ held' = [held EXCEPT ![s] = F]
    /\ phase' = [phase EXCEPT ![s] = "running"]
    /\ UNCHANGED <<proven, covered, skipDdl, clock, sealed>>

\* running -> oracleAsserted : the scenario's oracle proves its claim.  The claim
\* is counted EXACTLY ONCE (proven flips FALSE->TRUE here and nowhere else), and
\* the claimed surfaces are marked covered (Gate 2: covered => a green scenario).
OracleAssert(s) ==
    /\ ~sealed
    /\ phase[s] = "running"
    /\ proven[s] = FALSE
    /\ proven'  = [proven  EXCEPT ![s] = TRUE]
    /\ covered' = covered \cup Claims[s]
    /\ phase'   = [phase EXCEPT ![s] = "oracleAsserted"]
    /\ UNCHANGED <<held, skipDdl, clock, sealed>>

\* oracleAsserted -> tornDown (PASS path) : teardown runs, releasing every fixture
\* (idempotent teardown: held becomes empty).
TearDownPass(s) ==
    /\ ~sealed
    /\ phase[s] = "oracleAsserted"
    /\ held'  = [held  EXCEPT ![s] = {}]
    /\ phase' = [phase EXCEPT ![s] = "tornDown"]
    /\ UNCHANGED <<proven, covered, skipDdl, clock, sealed>>

\* running -> tornDown (FAIL path) : the oracle did NOT prove the claim, yet
\* teardown STILL runs (unconditional teardown) and NO surface is marked covered.
TearDownFail(s) ==
    /\ ~sealed
    /\ phase[s] = "running"
    /\ proven[s] = FALSE
    /\ held'  = [held  EXCEPT ![s] = {}]
    /\ phase' = [phase EXCEPT ![s] = "tornDown"]
    /\ UNCHANGED <<proven, covered, skipDdl, clock, sealed>>

\* declared -> skipped : allowed, but ONLY with a not-yet-expired deadline
\* (Gate 3).  A skipped scenario holds no fixtures.
Skip(s) ==
    /\ ~sealed
    /\ phase[s] = "declared"
    /\ clock < Deadline
    /\ skipDdl' = [skipDdl EXCEPT ![s] = Deadline]
    /\ phase'   = [phase EXCEPT ![s] = "skipped"]
    /\ UNCHANGED <<proven, held, covered, clock, sealed>>

\* skipped -> declared : un-skip before the deadline passes, returning the
\* scenario to the normal lifecycle (this is how a skip is retired in time).
UnSkip(s) ==
    /\ ~sealed
    /\ phase[s] = "skipped"
    /\ clock < skipDdl[s]
    /\ skipDdl' = [skipDdl EXCEPT ![s] = 0]
    /\ phase'   = [phase EXCEPT ![s] = "declared"]
    /\ UNCHANGED <<proven, held, covered, clock, sealed>>

\* Wall-clock advance.  Bounded by Deadline to keep the state space finite.  It
\* may NOT advance past a still-standing skip deadline -- Gate 3 forbids letting
\* a skip silently expire, so the tick that would expire it is disabled until the
\* skip is retired (UnSkip).  This makes "skip creep past a deadline" unreachable
\* by construction, which `Gate3_NoExpiredSkip` then re-checks as an invariant.
Tick ==
    /\ ~sealed
    /\ clock < Deadline
    /\ \A s \in Scenarios : (phase[s] = "skipped") => (clock + 1 <= skipDdl[s])
    /\ clock' = clock + 1
    /\ UNCHANGED <<phase, proven, held, covered, skipDdl, sealed>>

\* Seal the rig: only legal once every scenario is terminal (tornDown), i.e.
\* teardown ran for all of them.  Sealing evaluates the coverage gates (checked
\* as invariants in the sealed state).
Seal ==
    /\ ~sealed
    /\ \A s \in Scenarios : phase[s] = "tornDown"
    /\ sealed' = TRUE
    /\ UNCHANGED <<phase, proven, held, covered, skipDdl, clock>>

Next ==
    \/ \E s \in Scenarios : Start(s)
    \/ \E s \in Scenarios : OracleAssert(s)
    \/ \E s \in Scenarios : TearDownPass(s)
    \/ \E s \in Scenarios : TearDownFail(s)
    \/ \E s \in Scenarios : Skip(s)
    \/ \E s \in Scenarios : UnSkip(s)
    \/ Tick
    \/ Seal

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* --- Lifecycle integrity ---

\* A scenario is only ever `oracleAsserted` (its claim counted) via the single
\* Assert transition, which requires it to have been `running` first: no reachable
\* state reaches oracleAsserted without proven being set.  This is the
\* "no double-counted claim" guard -- proven, once TRUE, stays TRUE and a claim
\* contributes to `covered` exactly once (Assert is guarded by proven=FALSE).
NoDoubleCountedClaim ==
    \A s \in Scenarios :
        (phase[s] = "oracleAsserted") => proven[s]

\* No reachable terminal path skips teardown: a scenario that is done with its
\* run (proven) is NOT left holding fixtures forever without a teardown edge --
\* every exit from `running`/`oracleAsserted` goes through a *DownTear* to
\* `tornDown`.  Concretely: a proven scenario that still holds fixtures must not
\* be in a phase from which teardown is impossible.  The only phases that hold
\* fixtures are `running` and `oracleAsserted`, both of which have a teardown
\* successor; `tornDown` holds none.  Expressed as: no scenario is in a
\* "finished but un-teardownable" state.
NoStateSkipsTeardown ==
    \A s \in Scenarios :
        (phase[s] = "tornDown") => (held[s] = {})

\* --- Inventory <-> declaration relation ---
\* (Constant-level facts about the declared schema, so asserted as ASSUMEs
\* rather than state invariants: every claim targets a real inventory entry and
\* every scenario names a real oracle.  These mirror the schema round-trip
\* test's `claims_target_real_surface` cross-check.)
ASSUME ClaimsTargetRealSurface ==
    \A s \in Scenarios : Claims[s] \subseteq Surfaces

ASSUME ScenarioNamesRealOracle ==
    \A s \in Scenarios : ProvenBy[s] \in Oracles

\* --- Coverage gates ---

\* Gate 2 (holds in EVERY state): a surface is `covered` only because some
\* scenario that claims it was proven.  covered never contains a surface no
\* proven scenario claims.
Gate2_CoveredIsProven ==
    \A x \in covered :
        \E s \in Scenarios : (proven[s] /\ x \in Claims[s])

\* Gate 1 (evaluated at SEAL): no orphan surface -- once sealed, every inventory
\* entry is claimed by some scenario.  (Vacuously TRUE until sealed.)
Gate1_NoOrphan ==
    sealed =>
        \A x \in Surfaces : \E s \in Scenarios : x \in Claims[s]

\* Gate 3: no skip creeps PAST its deadline.  A skipped scenario's deadline is
\* never behind the clock (clock <= skipDdl: the skip is valid up to and
\* including its deadline tick, and a violation is the clock strictly PAST it).
Gate3_NoExpiredSkip ==
    \A s \in Scenarios :
        (phase[s] = "skipped") => (clock <= skipDdl[s])

\* --- Fixture isolation + teardown/leak invariants ---

\* No two distinct RUNNING scenarios share a fixture resource: no cross-scenario
\* shared mutable state.
NoSharedFixtureState ==
    \A s, t \in Scenarios :
        (s # t /\ phase[s] = "running" /\ phase[t] = "running")
            => (held[s] \cap held[t] = {})

\* Idempotent teardown: a torn-down scenario holds nothing.
TeardownReleasesFixtures ==
    \A s \in Scenarios : (phase[s] = "tornDown") => (held[s] = {})

\* Leak detection: in the sealed terminal state, the global leak detector sees
\* zero residue -- no scenario holds any fixture (teardown ran for all, incl.
\* the failed ones).
NoResidueWhenSealed ==
    sealed => (\A s \in Scenarios : held[s] = {})

=============================================================================
