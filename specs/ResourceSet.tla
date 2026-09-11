---------------------------- MODULE ResourceSet ----------------------------
(***************************************************************************)
(* ResourceSet is pillar's ArgoCD-Application analog: a declarative        *)
(* grouping that OWNS a set of member resources and reconciles the live    *)
(* world toward its declared membership — creating (adopting) declared     *)
(* members that are missing and PRUNING owned members that are no longer   *)
(* declared. The Default ResourceSet owns the default RetentionPolicies.   *)
(*                                                                         *)
(* This spec proves the reconcile PROTOCOL, which is what pillar-method    *)
(* gates behind TLC before any Rust: the health ROLLUP and the graph       *)
(* rendering are pure derivations (Rust-tested, no TLA+). The load-bearing *)
(* safety of the protocol is:                                             *)
(*                                                                         *)
(*   - AdoptionSafe   a set only ever adopts an UNOWNED resource; it can   *)
(*                    never seize a resource another set owns (no hostile  *)
(*                    takeover, encoded in CreateMember's precondition).   *)
(*   - PruneOnlyOwnedUndeclared  a prune only ever removes a resource this *)
(*                    exact set owns AND no longer declares (encoded in    *)
(*                    PruneMember's precondition) — a declared resource is  *)
(*                    never pruned, and one set never prunes another's.    *)
(*   - OwnedIff       a resource is live IFF it has an owner, and ownership *)
(*                    is a function so it is exclusive by construction.     *)
(*   - Disjoint       declarations stay disjoint (a resource is declared by *)
(*                    at most one set), preserved by every user edit.       *)
(*                                                                         *)
(* And the liveness result under weak fairness of the controller actions:  *)
(*                                                                         *)
(*   - Convergence    once declarations stop changing (frozen), the live   *)
(*                    owned set of every ResourceSet reaches EXACTLY its    *)
(*                    declared set and stays there (Synced) — even across   *)
(*                    an ownership hand-off, where set B must wait for set  *)
(*                    A to prune a resource before B can adopt it.          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Resources,   \* the universe of member resource ids
    Sets,        \* the universe of ResourceSet ids
    NoOwner      \* a sentinel distinct from every real set id: "no owner" / not-live

VARIABLES
    declared,    \* declared[s] \in SUBSET Resources : set s's DESIRED members
    live,        \* SUBSET Resources : the resources that actually exist
    owner,       \* owner[r] \in Sets \cup {NoOwner} : the owning set of a live r
    frozen       \* BOOLEAN : once TRUE, user declarations stop (converge phase)

vars == <<declared, live, owner, frozen>>

TypeOK ==
    /\ declared \in [Sets -> SUBSET Resources]
    /\ live \subseteq Resources
    /\ owner \in [Resources -> (Sets \cup {NoOwner})]
    /\ frozen \in BOOLEAN

Init ==
    /\ declared = [s \in Sets |-> {}]
    /\ live = {}
    /\ owner = [r \in Resources |-> NoOwner]
    /\ frozen = FALSE

----------------------------------------------------------------------------
(* Derived: the live resources a given set currently owns, and whether the  *)
(* set's live-owned membership matches its declaration exactly.             *)
Owned(s) == { r \in live : owner[r] = s }
Synced(s) == Owned(s) = declared[s]
AllSynced == \A s \in Sets : Synced(s)

----------------------------------------------------------------------------
(* USER edit: retarget one set's declared membership to any subset that     *)
(* keeps declarations disjoint (a resource is declared by at most one set — *)
(* the manifest layer rejects a double-declaration).                        *)
ChangeDeclared(s, D) ==
    /\ ~frozen
    /\ \A s2 \in Sets : s2 # s => D \cap declared[s2] = {}
    /\ declared' = [declared EXCEPT ![s] = D]
    /\ UNCHANGED <<live, owner, frozen>>

(* CONTROLLER: create + adopt a declared-but-missing member. Adoption is    *)
(* safe: it fires ONLY when the resource is currently unowned, so a set can  *)
(* never seize a resource another set still owns.                           *)
CreateMember(s, r) ==
    /\ r \in declared[s]
    /\ r \notin live
    /\ owner[r] = NoOwner
    /\ live' = live \cup {r}
    /\ owner' = [owner EXCEPT ![r] = s]
    /\ UNCHANGED <<declared, frozen>>

(* CONTROLLER: prune an owned member that this set no longer declares. It    *)
(* fires ONLY on a resource this exact set owns AND does not declare — never *)
(* a declared resource, never another set's resource.                       *)
PruneMember(s, r) ==
    /\ owner[r] = s
    /\ r \notin declared[s]
    /\ r \in live
    /\ live' = live \ {r}
    /\ owner' = [owner EXCEPT ![r] = NoOwner]
    /\ UNCHANGED <<declared, frozen>>

(* Stop accepting user edits — model the "declarations have settled" phase   *)
(* in which the controller is expected to fully converge.                    *)
Freeze ==
    /\ ~frozen
    /\ frozen' = TRUE
    /\ UNCHANGED <<declared, live, owner>>

Next ==
    \/ \E s \in Sets, D \in SUBSET Resources : ChangeDeclared(s, D)
    \/ \E s \in Sets, r \in Resources : CreateMember(s, r)
    \/ \E s \in Sets, r \in Resources : PruneMember(s, r)
    \/ Freeze

Fairness ==
    /\ \A s \in Sets, r \in Resources : WF_vars(CreateMember(s, r))
    /\ \A s \in Sets, r \in Resources : WF_vars(PruneMember(s, r))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
(* Safety invariants. *)

\* A resource is live iff it has a real owner (and vice versa): no orphaned
\* ownership, no ownerless live resource. Ownership is a function, so a live
\* resource has exactly one owner — exclusivity by construction.
OwnedIff == \A r \in Resources : (r \in live) <=> (owner[r] # NoOwner)

\* Declarations never overlap: a resource is declared by at most one set.
Disjoint ==
    \A s1, s2 \in Sets : s1 # s2 => declared[s1] \cap declared[s2] = {}

\* A live resource's owner is a real set (never the sentinel) — the twin of
\* OwnedIff, stated directly for clarity.
NoSentinelOwnsLive == \A r \in live : owner[r] \in Sets

----------------------------------------------------------------------------
(* Liveness: once declarations settle, every set's live-owned membership     *)
(* reaches exactly its declared membership (Synced) — the reconcile          *)
(* converges, including across a resource hand-off from one set to another.  *)
Convergence == frozen ~> AllSynced

=============================================================================
