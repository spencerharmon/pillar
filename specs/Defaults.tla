------------------------------ MODULE Defaults ------------------------------
(***************************************************************************)
(* The DEFAULTS-MERGE protocol: how a cell absorbs the binary-shipped      *)
(* default manifests (e.g. the default RetentionPolicies) WITHOUT the       *)
(* shipped bundle being a reconcile target. The bundle is a SEED/OFFER, not *)
(* a desired state — operators freely add, edit, and delete members of the  *)
(* (Default) ResourceSet, and none of that is "drift" against the binary.   *)
(*                                                                         *)
(* This is the load-bearing distinction the operator called out: a node    *)
(* version bump ships a (possibly newer) bundle, but must never modify a    *)
(* cell's Default set. New defaults surface only as an ADDITIVE advisory    *)
(* ("N net-new available"), adopted per-operator-choice. The protocol is    *)
(* gated behind TLC before any Rust (pillar-method); the advisory count and *)
(* the graph rendering are pure derivations (Rust-tested, no TLA+).        *)
(*                                                                         *)
(* State (per cell):                                                        *)
(*   present     the default-provenance policies that EXIST as applied      *)
(*               resources (adopted from some bundle version).              *)
(*   edited      present policies the operator has diverged from ship.      *)
(*   tombstoned  defaults the operator DELETED — must never be resurrected  *)
(*               by a later seed / bundle bump.                             *)
(*   bundleNames the names in the currently-shipped binary bundle.          *)
(*   bundleVer   the shipped bundle's monotonic version.                    *)
(*                                                                         *)
(* Derived advisory:                                                        *)
(*   Available == (bundleNames \ present) \ tombstoned   (net-new, adoptable) *)
(*                                                                         *)
(* Proven safety:                                                           *)
(*   - NoResurrect          a tombstoned default is never present: neither  *)
(*                          Seed nor AdoptOne can re-add a deleted default.  *)
(*   - EditedSubsetPresent  an edit only exists for a present policy, and a *)
(*                          seed never drops it (edits survive seeding).     *)
(*   - SeedNoClobber (temporal) every Seed step preserves all present       *)
(*                          policies and all edits, and leaves tombstones   *)
(*                          untouched — seeding is create-if-absent.        *)
(*   - VersionMonotone (temporal) the bundle version never decreases.       *)
(* Proven liveness (under weak fairness of the controller Seed):            *)
(*   - Convergence          once operator edits settle (frozen), seeding    *)
(*                          drains Available to {} and it stays there —      *)
(*                          i.e. the seed is idempotent and terminating.     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Defaults,       \* the universe of shippable default ids
    InitialBundle   \* the names shipped at bundleVer = 1 (subset of Defaults)

VARIABLES
    present,      \* SUBSET Defaults : applied default-provenance policies
    edited,       \* SUBSET Defaults : present policies diverged from ship
    tombstoned,   \* SUBSET Defaults : operator-deleted, never resurrected
    bundleNames,  \* SUBSET Defaults : names in the current shipped bundle
    bundleVer,    \* Nat : monotonic shipped-bundle version
    frozen        \* BOOLEAN : once TRUE, operator edits stop (converge phase)

vars == <<present, edited, tombstoned, bundleNames, bundleVer, frozen>>

TypeOK ==
    /\ present \subseteq Defaults
    /\ edited \subseteq Defaults
    /\ tombstoned \subseteq Defaults
    /\ bundleNames \subseteq Defaults
    /\ bundleVer \in Nat
    /\ frozen \in BOOLEAN

Init ==
    /\ present = {}
    /\ edited = {}
    /\ tombstoned = {}
    /\ bundleNames = InitialBundle
    /\ bundleVer = 1
    /\ frozen = FALSE

----------------------------------------------------------------------------
(* Derived: the net-new adoptable defaults — the advisory the UI/CLI show.  *)
Available == (bundleNames \ present) \ tombstoned

----------------------------------------------------------------------------
(* CONTROLLER: seed = adopt EVERY currently-available default in one step.  *)
(* Create-if-absent by construction: present policies remain (present is a  *)
(* subset of present'), edits are UNCHANGED, and tombstoned names are        *)
(* excluded — so a seed never clobbers an edit and never resurrects a        *)
(* deletion. Definitionally idempotent (\cup): a second seed adds nothing.  *)
Seed ==
    /\ present' = present \cup (bundleNames \ tombstoned)
    /\ UNCHANGED <<edited, tombstoned, bundleNames, bundleVer, frozen>>

(* CONTROLLER: adopt a single available default (the per-item operator pick).*)
AdoptOne(d) ==
    /\ d \in bundleNames
    /\ d \notin present
    /\ d \notin tombstoned
    /\ present' = present \cup {d}
    /\ UNCHANGED <<edited, tombstoned, bundleNames, bundleVer, frozen>>

(* OPERATOR: diverge a present default from its shipped form.               *)
OperatorEdit(d) ==
    /\ ~frozen
    /\ d \in present
    /\ edited' = edited \cup {d}
    /\ UNCHANGED <<present, tombstoned, bundleNames, bundleVer, frozen>>

(* OPERATOR: delete a present default — drops it and records a tombstone so  *)
(* no later seed / bundle bump can bring it back.                           *)
OperatorDelete(d) ==
    /\ ~frozen
    /\ d \in present
    /\ present' = present \ {d}
    /\ edited' = edited \ {d}
    /\ tombstoned' = tombstoned \cup {d}
    /\ UNCHANGED <<bundleNames, bundleVer, frozen>>

(* NODE UPGRADE: ship a newer bundle version, possibly introducing new       *)
(* default names. Monotonic version; never removes shipped names; never      *)
(* touches present/edited/tombstoned — an upgrade cannot modify the cell.    *)
BumpBundle(newNames) ==
    /\ ~frozen
    /\ newNames \subseteq Defaults
    /\ bundleNames' = bundleNames \cup newNames
    /\ bundleVer' = bundleVer + 1
    /\ UNCHANGED <<present, edited, tombstoned, frozen>>

(* Stop accepting operator edits / bundle bumps — the "settled" phase in     *)
(* which the controller seed is expected to fully converge.                  *)
Freeze ==
    /\ ~frozen
    /\ frozen' = TRUE
    /\ UNCHANGED <<present, edited, tombstoned, bundleNames, bundleVer>>

Next ==
    \/ Seed
    \/ \E d \in Defaults : AdoptOne(d)
    \/ \E d \in Defaults : OperatorEdit(d)
    \/ \E d \in Defaults : OperatorDelete(d)
    \/ \E N \in SUBSET Defaults : BumpBundle(N)
    \/ Freeze

Fairness == WF_vars(Seed)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
(* Safety. *)

\* A deleted default is never present again: seeds/adopts exclude tombstoned,
\* and delete moves present -> tombstoned atomically.
NoResurrect == tombstoned \cap present = {}

\* An edit only ever exists for a present policy — a seed preserves present
\* policies (so their edits survive), and delete clears both together.
EditedSubsetPresent == edited \subseteq present

\* Every Seed step is create-if-absent: it preserves all present policies and
\* all edits and leaves tombstones untouched (no clobber, no resurrect).
SeedNoClobber ==
    [][ Seed => /\ present \subseteq present'
                /\ edited' = edited
                /\ tombstoned' = tombstoned ]_vars

\* The shipped bundle version never decreases.
VersionMonotone == [][ bundleVer' >= bundleVer ]_vars

\* State constraint: bound the version so TLC's state space is finite
\* (BumpBundle would otherwise increment bundleVer without bound).
VerBound == bundleVer =< 4

----------------------------------------------------------------------------
(* Liveness: once edits settle, seeding drains the advisory to empty and it  *)
(* stays there — the seed is terminating and idempotent (nothing to re-adopt *)
(* after it fires).                                                          *)
Convergence == frozen ~> (Available = {})

=============================================================================
