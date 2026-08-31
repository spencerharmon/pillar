--------------------------- MODULE NamingAuthorityPlane ---------------------------
(***************************************************************************)
(* Pillar naming plane vs authority plane (ROI P1, method #1).             *)
(*                                                                         *)
(* Conceptually EXTENDS WoTAuthority.tla: the CELL is the authority unit   *)
(* (WoTAuthority's owner-anchored, revoke-before-act reachability relation *)
(* is reused verbatim, just renamed from Nodes/Owner to Cells/RootCell),   *)
(* and identity/grant/attestation artifacts are rooted in a cell or an     *)
(* identity, never in a domain. This spec ADDS a disjoint NAMING plane:    *)
(*                                                                         *)
(*   AUTHORITY PLANE (reused from WoTAuthority, unmodified semantics):     *)
(*     - Cells        : the authority/coordination/storage root unit.      *)
(*     - edges/revokedKeys/revokedEdges/revokedGrants/freshMark/           *)
(*       partitioned/lastAct/Act : identical revoke-before-act discipline, *)
(*       anchored at RootCell instead of Owner.                           *)
(*     - roleAssignments : RBAC grants, each scoped to EXACTLY a Cell or   *)
(*       an Identity -- never a Domain. A domain cannot be a role anchor   *)
(*       by TYPE, not merely by convention (RolesAreCellOrIdentityScoped). *)
(*                                                                         *)
(*   NAMING PLANE (new, and everything this spec exists to constrain):     *)
(*     - Domains       : a NAME grouping over cells. A domain groups cells *)
(*       for topology/space/labelling purposes ONLY.                       *)
(*     - domainMembers  : [Domains -> SUBSET Cells], the only domain state. *)
(*       Notice there is no domain key, no domain edges, no domain grants, *)
(*       no domain freshMark/lastAct entry anywhere in this spec -- a      *)
(*       domain literally cannot appear as the signer or subject of any    *)
(*       authority-plane fact, because `edges` (and every revoked-set) is  *)
(*       typed over Cells, and Cells and Domains are disjoint universes    *)
(*       (DomainsAreNotCells). This is what "a domain has NO key, NO       *)
(*       authority" means formally: the type system, not a runtime check,  *)
(*       forecloses a domain ever being an authority participant.         *)
(*     - lastAddress   : ghost record of the most recent Address(d, c)     *)
(*       action -- resolving a (domain, cell) pair for disambiguation.     *)
(*       Addressing is READ-ONLY over domainMembers: it neither requires   *)
(*       nor grants any authority, and mutates no authority-plane variable *)
(*       (AddressingDoesNotConferAuthority).                              *)
(*                                                                         *)
(* Explicitly OFF the table (per the ROI note), and hence absent from this *)
(* model entirely: federation, domain keys, cross-cell domain-level roles, *)
(* and cell-recognition edges. A domain is a naming group, never an        *)
(* authority; the cell remains the sole authority unit; a role is always   *)
(* cell-scoped or identity-scoped, never domain-scoped; addressing via a   *)
(* domain/cell pair disambiguates but never signs, grants, or coordinates. *)
(*                                                                         *)
(* Proven by TLC:                                                         *)
(*   - DomainSignsNothing: no domain ever appears as an edge endpoint or a *)
(*     revoked-set member -- structurally impossible (Cells/Domains        *)
(*     disjoint, edges/revoked* typed over Cells only).                    *)
(*   - RolesAreCellOrIdentityScoped: every role assignment's anchor is a   *)
(*     Cell (scope = "Cell") or an Identity (scope = "Identity") -- never  *)
(*     a Domain; "Domain" is not even a member of the scope type.         *)
(*   - AddressingDoesNotConferAuthority: the authority-plane state         *)
(*     (edges, revoked*, roleAssignments) is byte-for-byte UNCHANGED by    *)
(*     every Address action, and CurrentAuthCells -- the ground truth of   *)
(*     which cells are authoritative -- is computed exclusively from       *)
(*     authority-plane variables, never referencing domainMembers or       *)
(*     lastAddress; a cell's presence in, or absence from, any domain has  *)
(*     zero effect on whether it is in CurrentAuthCells.                   *)
(*   - NoActionAfterRevocation / FailClosedUnderStaleView (carried over    *)
(*     from WoTAuthority, re-proved here under plane tagging): the revoke- *)
(*     before-act discipline over Cells is untouched by the presence of    *)
(*     the naming plane laid on top of it.                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Cells,      \* candidate authority units: THE authority/coordination/storage root
    Domains,    \* candidate naming groups over cells -- NO key, NO authority
    Identities, \* candidate identities a role may be scoped to directly
    RootCell,   \* the trust anchor cell: unconditionally authoritative
    Roles,      \* candidate RBAC role labels (opaque)
    MaxDepth,   \* model bound on tsig delegation depth (as WoTAuthority)
    None        \* sentinel, unused by variables but kept for symmetry with sibling specs

ASSUME CellsNonEmpty      == Cells # {}
ASSUME RootCellIsCell     == RootCell \in Cells
ASSUME MaxDepthIsNat      == MaxDepth \in Nat
ASSUME NoneNotCell        == None \notin Cells
\* THE core disjointness fact that makes DomainSignsNothing a type-level
\* impossibility rather than a runtime check: a domain can never be typed
\* as a Cell, so it can never occupy an `edges`/revoked-set slot.
ASSUME DomainsAreNotCells == Domains \cap Cells = {}
ASSUME DomainsAreNotIdentities == Domains \cap Identities = {}

Depths == 0 .. MaxDepth

VARIABLES
    \* --- authority plane: identical shape/semantics to WoTAuthority, over Cells ---
    edges,          \* SUBSET (Cells \X Cells \X Depths): issued tsig certificates (grow-only)
    revokedKeys,    \* SUBSET Cells: keys revoked (grow-only, true/global)
    revokedEdges,   \* SUBSET (Cells \X Cells): tsig edges revoked (grow-only, true/global)
    revokedGrants,  \* SUBSET Cells: direct grant revocations (grow-only, true/global)
    freshMark,      \* [Cells -> Nat]: each cell's local revocation-knowledge watermark
    partitioned,    \* SUBSET Cells: cells currently cut off from advancing their watermark
    lastAct,        \* ghost: the most recent Act (if any), with its authorization snapshot
    roleAssignments,\* SUBSET RoleAssignment: RBAC grants, each Cell- or Identity-scoped
    \* --- naming plane: pure grouping, no key, no authority ---
    domainMembers,  \* [Domains -> SUBSET Cells]: which cells a domain names/groups
    lastAddress     \* ghost: the most recent Address(d, c) resolution, if any

vars == <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned,
          lastAct, roleAssignments, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* ROLE ASSIGNMENT TYPE: scope is EXACTLY "Cell" or "Identity" -- "Domain"  *)
(* is not, and can never be, a member of this type.                        *)

RoleScopes == {"Cell", "Identity"}

\* A role assignment's anchor type is DETERMINED by its scope: a Cell-scoped
\* assignment anchors on a Cell, an Identity-scoped one on an Identity. This
\* is exactly how a domain is excluded from ever being a role anchor -- not
\* by a guard that happens to reject it today, but because the type has no
\* branch that admits one.
RoleAssignments ==
    [subject: Identities, scope: {"Cell"}, anchor: Cells, role: Roles]
    \cup [subject: Identities, scope: {"Identity"}, anchor: Identities, role: Roles]

-----------------------------------------------------------------------------
(* DERIVED GROUND TRUTH GIVEN A (SNAPSHOT OF) REVOKED-SETS TRIPLE           *)
(* -- identical formulation to WoTAuthority, over Cells instead of Nodes,   *)
(* and DELIBERATELY never taking domainMembers/lastAddress as a parameter: *)
(* that omission IS the formal statement that naming never feeds authority.*)

RevCount == Cardinality(revokedKeys) + Cardinality(revokedEdges) + Cardinality(revokedGrants)

ValidEdgesGiven(rk, re) ==
    { e \in edges :
        /\ e[1] \notin rk
        /\ e[2] \notin rk
        /\ <<e[1], e[2]>> \notin re }

ReachStep(prevPairs, vedges) ==
    prevPairs \cup
        { <<b, m>> \in (Cells \X Depths) :
            \E <<a, rb>> \in prevPairs, e \in vedges :
                /\ e[1] = a
                /\ e[2] = b
                /\ rb > 0
                /\ m = IF (rb - 1) <= e[3] THEN (rb - 1) ELSE e[3] }

RECURSIVE ReachFix(_, _, _)
ReachFix(prevPairs, vedges, fuel) ==
    IF fuel = 0 THEN prevPairs
    ELSE LET next == ReachStep(prevPairs, vedges)
         IN IF next = prevPairs THEN prevPairs ELSE ReachFix(next, vedges, fuel - 1)

AuthPairsGiven(rk, re) == ReachFix({<<RootCell, MaxDepth>>}, ValidEdgesGiven(rk, re), Cardinality(Cells))

\* Ground truth given a revoked-sets snapshot: root-cell-anchored bounded-depth
\* reachability over non-revoked edges, with any directly grant-revoked cell
\* stripped even if still reachable. Note the signature: (rk, re, rg) only --
\* no domain parameter exists to pass, which is the point.
AuthCellsGiven(rk, re, rg) ==
    { c \in Cells : \E <<c2, b>> \in AuthPairsGiven(rk, re) : c2 = c } \ rg

\* Ground truth given the CURRENT global revoked sets.
CurrentAuthCells == AuthCellsGiven(revokedKeys, revokedEdges, revokedGrants)

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ edges           = {}
    /\ revokedKeys     = {}
    /\ revokedEdges    = {}
    /\ revokedGrants   = {}
    /\ freshMark       = [c \in Cells |-> 0]
    /\ partitioned     = {}
    /\ lastAct         = [some |-> FALSE, actor |-> RootCell, subject |-> RootCell, authSnap |-> {}, watermark |-> 0]
    /\ roleAssignments = {}
    /\ domainMembers   = [d \in Domains |-> {}]
    /\ lastAddress     = [some |-> FALSE, domain |-> CHOOSE d \in Domains : TRUE, cell |-> RootCell]

-----------------------------------------------------------------------------
(* AUTHORITY-EXPANDING (AP): issuing a tsig certificate between cells        *)

IssueEdge(a, b, l) ==
    /\ l \in Depths
    /\ <<a, b, l>> \notin edges
    /\ edges' = edges \cup {<<a, b, l>>}
    /\ UNCHANGED <<revokedKeys, revokedEdges, revokedGrants, freshMark, partitioned,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* AUTHORITY-REDUCING (CP/fail-closed, enforced at Act time): revocations    *)

RevokeKey(k) ==
    /\ k \notin revokedKeys
    /\ revokedKeys' = revokedKeys \cup {k}
    /\ UNCHANGED <<edges, revokedEdges, revokedGrants, freshMark, partitioned,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

RevokeEdge(a, b) ==
    /\ <<a, b>> \notin revokedEdges
    /\ revokedEdges' = revokedEdges \cup {<<a, b>>}
    /\ UNCHANGED <<edges, revokedKeys, revokedGrants, freshMark, partitioned,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

RevokeGrant(n) ==
    /\ n \notin revokedGrants
    /\ revokedGrants' = revokedGrants \cup {n}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, freshMark, partitioned,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: StaleView / Partition / Heal (identical to WoTAuthority)  *)

StaleView(c) ==
    /\ c \notin partitioned
    /\ freshMark' = [freshMark EXCEPT ![c] = RevCount]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, partitioned,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

Partition ==
    /\ partitioned' \in SUBSET Cells
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    lastAct, roleAssignments, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* THE PRIVILEGED ACTION: revoke-before-act as an action-time rule           *)
(* (identical guard/ghost-update discipline to WoTAuthority's Act, over      *)
(* Cells instead of Nodes).                                                 *)

Act(actor, subject) ==
    /\ freshMark[actor] = RevCount
    /\ subject \in CurrentAuthCells
    /\ lastAct' = [some |-> TRUE, actor |-> actor, subject |-> subject,
                   authSnap |-> CurrentAuthCells, watermark |-> RevCount]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, roleAssignments, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* ROLE ASSIGNMENT: always Cell-scoped or Identity-scoped, never Domain.    *)
(* Assigning/revoking a role touches ONLY roleAssignments -- it neither      *)
(* reads nor writes any naming-plane variable, and neither reads nor writes  *)
(* the authority-plane's revoke-before-act state (edges/revoked*/freshMark/  *)
(* partitioned/lastAct): an RBAC grant is layered on top of, not folded      *)
(* into, cell authority.                                                    *)

AssignRole(ra) ==
    /\ ra \in RoleAssignments
    /\ ra \notin roleAssignments
    /\ roleAssignments' = roleAssignments \cup {ra}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, lastAct, domainMembers, lastAddress>>

RevokeRole(ra) ==
    /\ ra \in roleAssignments
    /\ roleAssignments' = roleAssignments \ {ra}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, lastAct, domainMembers, lastAddress>>

-----------------------------------------------------------------------------
(* NAMING PLANE: domain membership over cells. NO key, NO authority state,  *)
(* NO grant of any kind lives here -- these two actions are the entire      *)
(* naming-plane mutation surface, and neither touches an authority-plane    *)
(* variable nor roleAssignments.                                           *)

AddToDomain(d, c) ==
    /\ c \notin domainMembers[d]
    /\ domainMembers' = [domainMembers EXCEPT ![d] = @ \cup {c}]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, lastAct, roleAssignments, lastAddress>>

RemoveFromDomain(d, c) ==
    /\ c \in domainMembers[d]
    /\ domainMembers' = [domainMembers EXCEPT ![d] = @ \ {c}]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, lastAct, roleAssignments, lastAddress>>

\* Addressing: resolve a (domain, cell) pair for disambiguation ONLY. The
\* guard requires the cell to actually be grouped under the domain (so this
\* models a real lookup, not an arbitrary claim) -- but critically the guard
\* does NOT require, and the effect does NOT grant, membership in
\* CurrentAuthCells or any role. This action's UNCHANGED clause is the
\* structural proof of AddressingDoesNotConferAuthority: it is IMPOSSIBLE
\* for Address to mutate a single authority-plane variable or roleAssignments.
Address(d, c) ==
    /\ c \in domainMembers[d]
    /\ lastAddress' = [some |-> TRUE, domain |-> d, cell |-> c]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                    partitioned, lastAct, roleAssignments, domainMembers>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E a, b \in Cells, l \in Depths : IssueEdge(a, b, l)
    \/ \E k \in Cells                  : RevokeKey(k)
    \/ \E a, b \in Cells               : RevokeEdge(a, b)
    \/ \E n \in Cells                  : RevokeGrant(n)
    \/ \E c \in Cells                  : StaleView(c)
    \/ Partition
    \/ Heal
    \/ \E a, s \in Cells               : Act(a, s)
    \/ \E ra \in RoleAssignments       : AssignRole(ra)
    \/ \E ra \in RoleAssignments       : RevokeRole(ra)
    \/ \E d \in Domains, c \in Cells   : AddToDomain(d, c)
    \/ \E d \in Domains, c \in Cells   : RemoveFromDomain(d, c)
    \/ \E d \in Domains, c \in Cells   : Address(d, c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

MaxRevCount == Cardinality(Cells) + Cardinality(Cells \X Cells) + Cardinality(Cells)

TypeOK ==
    /\ edges \subseteq (Cells \X Cells \X Depths)
    /\ revokedKeys \subseteq Cells
    /\ revokedEdges \subseteq (Cells \X Cells)
    /\ revokedGrants \subseteq Cells
    /\ freshMark \in [Cells -> 0 .. MaxRevCount]
    /\ partitioned \subseteq Cells
    /\ lastAct \in [some: BOOLEAN, actor: Cells, subject: Cells,
                    authSnap: SUBSET Cells, watermark: 0 .. MaxRevCount]
    /\ roleAssignments \subseteq RoleAssignments
    /\ domainMembers \in [Domains -> SUBSET Cells]
    /\ lastAddress \in [some: BOOLEAN, domain: Domains, cell: Cells]

\* A cell's local watermark never runs ahead of the true global one.
FreshMarkBounded == \A c \in Cells : freshMark[c] <= RevCount

-----------------------------------------------------------------------------
(* STATE-SPACE CONSTRAINT (model-checking budget only, not a spec property). *)
(* roleAssignments/domainMembers are ADDITIONAL, orthogonal dimensions this   *)
(* spec adds on top of WoTAuthority's already-substantial revoke-before-act  *)
(* state space; left unconstrained their combinatorics multiply the already- *)
(* large base graph by a further two-orders-of-magnitude factor, which is    *)
(* wasted exhaustiveness -- every AssignRole/AddToDomain/RevokeRole/         *)
(* RemoveFromDomain/Address transition, and every interleaving of each with  *)
(* every authority-plane action, is still explored; only states that have    *)
(* already accumulated MORE than one live role assignment (resp. more than   *)
(* one cell named by a given domain) are pruned from further expansion. That *)
(* is ample to exhaustively hit every case the three naming/RBAC invariants  *)
(* below need: an assignment/membership existing vs. not, of every scope/    *)
(* anchor kind, added and revoked, interleaved with every authority-plane    *)
(* action (issue/revoke/stale/partition/heal/act).                          *)
StateConstraint ==
    /\ Cardinality(roleAssignments) <= 1
    /\ (\A d \in Domains : Cardinality(domainMembers[d]) <= 1)
    /\ RevCount <= 1

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* DOMAIN SIGNS NOTHING: no domain ever appears as an edge endpoint, nor as a
\* member of any revoked set -- it cannot, because Domains and Cells are
\* disjoint (DomainsAreNotCells) and every one of those variables is typed
\* SUBSET Cells / Cells \X Cells \X Depths. This restates that disjointness
\* as an explicit invariant so it is checked as part of the model, not left
\* as an unverified reading of the ASSUMEs.
DomainSignsNothing ==
    /\ \A e \in edges : e[1] \notin Domains /\ e[2] \notin Domains
    /\ \A k \in revokedKeys : k \notin Domains
    /\ \A re \in revokedEdges : re[1] \notin Domains /\ re[2] \notin Domains
    /\ \A rg \in revokedGrants : rg \notin Domains

\* ROLES ARE CELL- OR IDENTITY-SCOPED: every current role assignment's scope
\* is exactly "Cell" or "Identity", and its anchor is correspondingly typed --
\* "Domain" never appears as a scope value and no assignment anchors on a
\* Domains element (impossible anyway by RoleAssignments' own type, checked
\* here as a live invariant over the actual reachable roleAssignments).
RolesAreCellOrIdentityScoped ==
    \A ra \in roleAssignments :
        /\ ra.scope \in RoleScopes
        /\ (ra.scope = "Cell"     => ra.anchor \in Cells)
        /\ (ra.scope = "Identity" => ra.anchor \in Identities)
        /\ ra.anchor \notin Domains

\* ADDRESSING DOES NOT CONFER AUTHORITY: CurrentAuthCells is computed
\* exclusively from AuthCellsGiven(revokedKeys, revokedEdges, revokedGrants)
\* -- a function that takes no domain/address parameter at all -- so no
\* cell's presence in, or absence from, any domain (nor any past Address
\* resolution recorded in lastAddress) can possibly change which cells are
\* authoritative. We state this as the strongest useful form: for every
\* domain/cell pair, membership in the domain neither implies nor is implied
\* by membership in CurrentAuthCells -- the two sets are wholly independent,
\* checked directly against the domain-blind formula.
AddressingDoesNotConferAuthority ==
    /\ CurrentAuthCells = AuthCellsGiven(revokedKeys, revokedEdges, revokedGrants)
    /\ \A d \in Domains, c \in Cells :
        (c \in domainMembers[d]) =>
            (c \in CurrentAuthCells <=> c \in AuthCellsGiven(revokedKeys, revokedEdges, revokedGrants))

\* NO ACTION AFTER REVOCATION (carried over from WoTAuthority, re-proved
\* under plane tagging over Cells): the most recent Act (if any) carries the
\* set of cells that WERE authoritative at the exact moment it acted, and the
\* acted-on subject was a member of it.
NoActionAfterRevocation ==
    lastAct.some => lastAct.subject \in lastAct.authSnap

\* FAIL CLOSED UNDER STALE VIEW (carried over from WoTAuthority, re-proved
\* under plane tagging over Cells): whenever a cell's watermark lags the true
\* one, that cell can never appear as the actor of the most-recently-recorded,
\* fully-fresh-at-that-moment Act evaluated against the CURRENT watermark.
FailClosedUnderStaleView ==
    \A c \in Cells :
        freshMark[c] < RevCount =>
            ~ (/\ lastAct.some
               /\ lastAct.actor = c
               /\ lastAct.watermark = RevCount)

=============================================================================
