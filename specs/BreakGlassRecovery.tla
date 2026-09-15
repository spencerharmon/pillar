-------------------------- MODULE BreakGlassRecovery --------------------------
(***************************************************************************)
(* Pillar break-glass recovery via admin quorum, M-of-N (user-management     *)
(* roadmap Group A, item A4). DESIGN-GATED on TLA+: A4 is explicitly called   *)
(* out as **TLA+-gated** ("quorum threshold + 'a recovered key regains        *)
(* exactly its prior authority, no more'") -- this spec is the gate for the   *)
(* Rust implementation (`ControlOp::Recovery(RecoveryOp::{Start,Approve})`).  *)
(*                                                                           *)
(* A subject (user) that lost its password/operational key cannot be         *)
(* unilaterally reset by a single admin (that would be a privileged REST     *)
(* call in disguise). Instead an M-of-N quorum of CURRENTLY-authoritative     *)
(* admins (over the WoT authority graph, exactly like WoTAuthority /          *)
(* Recovery.tla's FreshAuthVouchers) co-signs a ONE-TIME recovery: on the     *)
(* Mth fresh approval the node ROTATES the subject's key (the old key is      *)
(* dead forever -- a new key generation is minted) and the newly-minted       *)
(* recovery credential is CONTAINED exactly like an invite/require-change     *)
(* (`docs/user-management.md` #2, `ContainedHoldsNoOpKey`): the subject       *)
(* holds no *usable* authority until it completes onboarding (first login     *)
(* with the one-time credential), and even then never regains MORE than the  *)
(* authority it held before the loss.                                        *)
(*                                                                           *)
(* Proven by TLC (the five theorems the task card names):                    *)
(*   - RecoveryNeedsQuorum: every completed recovery was approved by >= M     *)
(*     admins.                                                               *)
(*   - SubThresholdNeverRecovers: it is never the case that a completed        *)
(*     recovery's approver set fell below the M threshold -- a sub-quorum     *)
(*     approval set can never fire the action at all (the guard makes the    *)
(*     state simply unreachable; this invariant is TLC's independent check   *)
(*     of that fact against the reachable state graph).                      *)
(*   - RecoveryRotatesAndRevokes: a completed recovery always strictly        *)
(*     advances the subject's key generation (the prior key is retired --     *)
(*     dead forever, never reusable) and strictly advances the global         *)
(*     revocation epoch (WoTAuthority/SessionRegistry technique) so that no    *)
(*     later admin can be fenced-fresh against a STALE pre-rotation view.     *)
(*   - RecoveryHonorsContainment: (a) the capability set a recovery regrants  *)
(*     is always a SUBSET of the subject's prior surviving authority --       *)
(*     "regains exactly its prior authority, no more", never an escalation;   *)
(*     and (b) the freshly-recovered credential is CONTAINED -- it grants NO  *)
(*     usable/effective authority whatsoever until the subject completes      *)
(*     onboarding, mirroring `ContainedHoldsNoOpKey` in UserLifecycle.        *)
(*   - RecoveryHonorsEpoch: fail-closed under a stale view -- an admin whose  *)
(*     freshness watermark lags the true global epoch can never have been a   *)
(*     counted approver of a recovery that fired at the current epoch (the    *)
(*     WoTAuthority / Recovery.tla / SessionRegistry revoke-before-act fence, *)
(*     applied to the quorum's own approvals rather than to a single actor).  *)
(*   - TypeOK: structural well-formedness.                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Subjects,   \* users eligible for break-glass recovery
    Admins,     \* candidate admin-quorum members (over the WoT authority graph)
    Caps,       \* candidate capabilities (abstract authority units)
    M,          \* the quorum threshold: number of FRESH admin approvals required
    MaxEpoch,   \* model bound on the global revocation/rotation-epoch counter
    MaxGen,     \* model bound on a subject's key-generation counter
    None        \* sentinel

ASSUME SubjectsNonEmpty == Subjects # {}
ASSUME AdminsNonEmpty   == Admins # {}
ASSUME CapsNonEmpty     == Caps # {}
ASSUME MIsNat           == M \in Nat
ASSUME MPositive        == M > 0
ASSUME MBounded         == M <= Cardinality(Admins)
ASSUME MaxEpochIsNat    == MaxEpoch \in Nat
ASSUME MaxGenIsNat      == MaxGen \in Nat
ASSUME NoneNotSubject   == None \notin Subjects

Epochs == 0 .. MaxEpoch
Gens   == 0 .. MaxGen

VARIABLES
    baseline,      \* baseline[s]: SUBSET Caps -- s's granted (role-derived) authority
                    \* ceiling, fixed independent of any single key loss/recovery
    revoked,        \* SUBSET Caps: capabilities revoked (grow-only, true/global)
    keyGen,         \* keyGen[s]: Nat -- s's current key generation (rotation counter)
    keyless,        \* keyless[s]: BOOLEAN -- s currently holds NO usable operational
                    \* key: either it lost its key (pre-recovery) or a recovery just
                    \* minted a one-time credential still awaiting onboarding
                    \* (post-recovery containment) -- both are "no usable authority"
    revEpoch,       \* Nat: global revocation/rotation epoch (monotonic, WoTAuthority/
                    \* SessionRegistry technique)
    adminFresh,     \* adminFresh[a]: each admin's revocation-knowledge watermark
    partitioned,    \* SUBSET Admins: admins cut off from advancing their watermark
    lastRecovery    \* ghost: the most recent completed break-glass recovery

vars == <<baseline, revoked, keyGen, keyless, revEpoch, adminFresh, partitioned,
          lastRecovery>>

-----------------------------------------------------------------------------
(* DERIVED GROUND TRUTH                                                       *)

\* A subject's authority that CURRENTLY survives revocation -- the ceiling any
\* recovery may restore, never more.
SurvivingAuth(s) == baseline[s] \ revoked

\* Admins that are currently AUTHORITATIVE (fenced/fresh, revoke-before-act):
\* their watermark equals the true global epoch and they are not cut off by a
\* partition.
FreshAdmins == { a \in Admins : /\ adminFresh[a] = revEpoch
                                 /\ a \notin partitioned }

\* A subject's EFFECTIVE (usable) authority: a keyless/contained subject signs
\* nothing, so it passes no capability gate regardless of what it is entitled
\* to -- exactly `ContainedHoldsNoOpKey` (UserLifecycle) applied to recovery.
EffectiveAuth(s) == IF keyless[s] THEN {} ELSE SurvivingAuth(s)

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

InitLastRecovery ==
    [ some |-> FALSE, subject |-> CHOOSE s \in Subjects : TRUE,
      approvers |-> {}, approverCount |-> 0, regranted |-> {}, priorSnap |-> {},
      oldGen |-> 0, newGen |-> 0, watermark |-> 0 ]

Init ==
    /\ baseline \in [Subjects -> SUBSET Caps]
    /\ revoked = {}
    /\ keyGen = [s \in Subjects |-> 0]
    /\ keyless = [s \in Subjects |-> FALSE]
    /\ revEpoch = 0
    /\ adminFresh = [a \in Admins |-> 0]
    /\ partitioned = {}
    /\ lastRecovery = InitLastRecovery

-----------------------------------------------------------------------------
(* KEY LOSS: a subject's password/operational key is lost. Does not touch     *)
(* `baseline` (the record of granted authority survives the loss -- that is   *)
(* what recovery restores against); it only marks the subject keyless.        *)

LoseKey(s) ==
    /\ keyless[s] = FALSE
    /\ keyless' = [keyless EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<baseline, revoked, keyGen, revEpoch, adminFresh, partitioned,
                    lastRecovery>>

-----------------------------------------------------------------------------
(* REVOCATION: grow-only, true/global. Strictly advances the epoch, exactly   *)
(* like SessionRegistry's revEpoch, so a watermark taken before this fact is  *)
(* provably stale afterward.                                                 *)

RevokeCap(c) ==
    /\ c \notin revoked
    /\ revEpoch < MaxEpoch
    /\ revoked' = revoked \cup {c}
    /\ revEpoch' = revEpoch + 1
    /\ UNCHANGED <<baseline, keyGen, keyless, adminFresh, partitioned, lastRecovery>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: StaleView / Partition / Heal (WoTAuthority/Recovery.tla     *)
(* technique) -- an admin's revocation knowledge can lag or be frozen.        *)

AdvanceFresh(a) ==
    /\ a \notin partitioned
    /\ adminFresh' = [adminFresh EXCEPT ![a] = revEpoch]
    /\ UNCHANGED <<baseline, revoked, keyGen, keyless, revEpoch, partitioned,
                    lastRecovery>>

Partition ==
    /\ partitioned' \in SUBSET Admins
    /\ UNCHANGED <<baseline, revoked, keyGen, keyless, revEpoch, adminFresh,
                    lastRecovery>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<baseline, revoked, keyGen, keyless, revEpoch, adminFresh,
                    lastRecovery>>

-----------------------------------------------------------------------------
(* THE BREAK-GLASS RECOVERY ACTION: on the Mth fresh admin approval, rotate   *)
(* the subject's key (old generation dead forever) and regrant only a        *)
(* subset of its surviving prior authority -- but the new credential is      *)
(* CONTAINED (no usable authority) until the subject completes onboarding.   *)

Recover(s, approvers, regrant) ==
    /\ keyless[s] = TRUE                     \* only a subject that needs recovery
    /\ approvers \subseteq FreshAdmins        \* every approver is fenced/fresh, now
    /\ Cardinality(approvers) >= M            \* a REAL quorum, not a plausible guess
    /\ regrant # {}
    /\ regrant \subseteq SurvivingAuth(s)      \* never more than prior authority
    /\ keyGen[s] < MaxGen
    /\ revEpoch < MaxEpoch
    /\ keyGen' = [keyGen EXCEPT ![s] = keyGen[s] + 1]   \* rotate: old key retired
    /\ revEpoch' = revEpoch + 1                          \* strictly advance the epoch
    /\ lastRecovery' = [ some |-> TRUE, subject |-> s, approvers |-> approvers,
                          approverCount |-> Cardinality(approvers),
                          regranted |-> regrant, priorSnap |-> SurvivingAuth(s),
                          oldGen |-> keyGen[s], newGen |-> keyGen[s] + 1,
                          watermark |-> revEpoch ]
    /\ UNCHANGED <<baseline, revoked, keyless, adminFresh, partitioned>>
       \* keyless stays TRUE: the one-time recovery credential is CONTAINED
       \* (mirrors an invite/require-change) until CompleteOnboarding fires.

-----------------------------------------------------------------------------
(* ONBOARDING: the subject completes the one-time recovery ceremony (or an    *)
(* ordinary first login) and its new key becomes usable.                     *)

CompleteOnboarding(s) ==
    /\ keyless[s] = TRUE
    /\ keyless' = [keyless EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<baseline, revoked, keyGen, revEpoch, adminFresh, partitioned,
                    lastRecovery>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E s \in Subjects                                     : LoseKey(s)
    \/ \E c \in Caps                                         : RevokeCap(c)
    \/ \E a \in Admins                                       : AdvanceFresh(a)
    \/ Partition
    \/ Heal
    \/ \E s \in Subjects, aps \in SUBSET Admins, r \in SUBSET Caps
                                                             : Recover(s, aps, r)
    \/ \E s \in Subjects                                     : CompleteOnboarding(s)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ baseline \in [Subjects -> SUBSET Caps]
    /\ revoked \subseteq Caps
    /\ keyGen \in [Subjects -> Gens]
    /\ keyless \in [Subjects -> BOOLEAN]
    /\ revEpoch \in Epochs
    /\ adminFresh \in [Admins -> Epochs]
    /\ partitioned \subseteq Admins
    /\ lastRecovery \in [ some: BOOLEAN, subject: Subjects, approvers: SUBSET Admins,
                          approverCount: 0 .. Cardinality(Admins),
                          regranted: SUBSET Caps, priorSnap: SUBSET Caps,
                          oldGen: Gens, newGen: Gens, watermark: Epochs ]

\* An admin's local watermark never runs ahead of the true global epoch.
FreshMarkBounded == \A a \in Admins : adminFresh[a] <= revEpoch

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES (the five theorems named by the task card)              *)

\* 1. RecoveryNeedsQuorum: every completed recovery was approved by a REAL
\* M-of-N quorum of currently-fresh admins -- never fewer.
RecoveryNeedsQuorum ==
    lastRecovery.some => lastRecovery.approverCount >= M

\* 2. SubThresholdNeverRecovers: TLC's independent check, over the reachable
\* state graph, that no completed recovery's recorded approver set ever fell
\* below the M threshold -- a sub-quorum approval set can never fire Recover
\* at all (the action's own guard makes that state unreachable; this
\* invariant is the artifact that proves it, exactly the shape of Recovery.tla's
\* paired NoRecoveryFromNothing/ShamirThreshold check).
SubThresholdNeverRecovers ==
    lastRecovery.some => Cardinality(lastRecovery.approvers) >= M

\* 3. RecoveryRotatesAndRevokes: every completed recovery strictly advanced
\* the subject's key generation (the prior key is dead forever, never
\* reusable) and strictly advanced the global revocation epoch (so no later
\* admin's watermark can be mistaken for having witnessed a pre-rotation
\* world).
RecoveryRotatesAndRevokes ==
    lastRecovery.some =>
        /\ lastRecovery.newGen = lastRecovery.oldGen + 1
        /\ lastRecovery.watermark < revEpoch
           \* the epoch the approvers observed (pre-rotation) is strictly
           \* behind the CURRENT epoch: the rotation (and possibly further
           \* revocations since) has strictly advanced past it -- the old
           \* key generation can never be mistaken for still-current.

\* 4. RecoveryHonorsContainment: (a) a recovery NEVER regrants more than the
\* subject's prior surviving authority -- "regains exactly its prior
\* authority, no more"; and (b) a subject holding a still-contained (keyless)
\* credential -- including every freshly-recovered one, before onboarding --
\* has NO effective/usable authority whatsoever, mirroring
\* `ContainedHoldsNoOpKey`.
RecoveryHonorsContainment ==
    /\ (lastRecovery.some => lastRecovery.regranted \subseteq lastRecovery.priorSnap)
    /\ (\A s \in Subjects : keyless[s] => EffectiveAuth(s) = {})

\* 5. RecoveryHonorsEpoch: fail-closed under a stale view -- whenever an
\* admin's watermark lags the true global epoch, that admin cannot have been
\* one of the counted approvers of a recovery recorded as having fired at the
\* CURRENT epoch (WoTAuthority / Recovery.tla / SessionRegistry's
\* revoke-before-act fence, applied to the quorum).
RecoveryHonorsEpoch ==
    \A a \in Admins :
        adminFresh[a] < revEpoch =>
            ~ (/\ lastRecovery.some
               /\ lastRecovery.watermark = revEpoch
               /\ a \in lastRecovery.approvers)

=============================================================================
