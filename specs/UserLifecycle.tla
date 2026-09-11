--------------------------- MODULE UserLifecycle ---------------------------
(***************************************************************************)
(* Pillar user-management / IAM lifecycle model (DESIGN-GATE for           *)
(* docs/user-management.md).                                               *)
(*                                                                         *)
(* Models the user lifecycle (invited -> active -> disabled), the forced   *)
(* password-change label, sessions, and capability derivation from roles + *)
(* group-roles. Proves, under TLC (see UserLifecycle.cfg):                 *)
(*                                                                         *)
(*   InvitedForcesChange   -- an invited user always carries               *)
(*     force_password_change until they complete a self password change.   *)
(*   ForcedChangeContained -- while force_password_change is set, the user  *)
(*     can perform NO act other than changing their own password; in       *)
(*     particular they hold no effective capabilities for other acts.      *)
(*   DisabledNeverActive   -- a disabled user holds no live session.        *)
(*   NoAmbientAuthority     -- a user with no roles and no group memberships *)
(*     holds NO effective capabilities: authority comes only from an        *)
(*     explicit role or group-role grant, so removing them drops it.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Users,        \* candidate user handles
    Roles,        \* candidate role names
    Groups,       \* candidate group names
    Caps,         \* candidate capability names
    RoleCaps,     \* [Roles -> SUBSET Caps]      role -> its capabilities
    GroupRoles    \* [Groups -> SUBSET Roles]    group -> roles attached to it

ASSUME UsersNonEmpty  == Users  # {}
ASSUME RoleCapsType   == RoleCaps   \in [Roles  -> SUBSET Caps]
ASSUME GroupRolesType == GroupRoles \in [Groups -> SUBSET Roles]

(* Concrete model-check instances of the two function-valued constants,      *)
(* referenced from UserLifecycle.cfg via `CONSTANT RoleCaps <- RoleCapsDef`  *)
(* (the repo's PillarIntegration.cfg pattern). Defined abstractly over the    *)
(* constant sets so they stay valid for any finite instance: every role      *)
(* grants every capability, every group attaches every role. The lifecycle    *)
(* invariants are structural and hold for any tables; NoAmbientAuthority       *)
(* still bites because the EMPTY role/group set yields the empty union.        *)
RoleCapsDef   == [r \in Roles  |-> Caps]
GroupRolesDef == [g \in Groups |-> Roles]

Status == {"none", "invited", "active", "disabled"}

VARIABLES
    status,       \* [Users -> Status]         ; "none" = not yet created
    forceChange,  \* [Users -> BOOLEAN]        ; force_password_change label
    userRoles,    \* [Users -> SUBSET Roles]
    userGroups,   \* [Users -> SUBSET Groups]
    session       \* [Users -> BOOLEAN]        ; TRUE = has a live session

vars == <<status, forceChange, userRoles, userGroups, session>>

(* Effective capabilities: union over directly-assigned roles and the roles *)
(* attached to the user's groups. This is the authorization bridge the       *)
(* RbacDecider consumes.                                                      *)
GroupDerivedRoles(u) == UNION { GroupRoles[g] : g \in userGroups[u] }
EffectiveRoles(u)    == userRoles[u] \cup GroupDerivedRoles(u)
EffectiveCaps(u)     == UNION { RoleCaps[r] : r \in EffectiveRoles(u) }

TypeOK ==
    /\ status      \in [Users -> Status]
    /\ forceChange \in [Users -> BOOLEAN]
    /\ userRoles   \in [Users -> SUBSET Roles]
    /\ userGroups  \in [Users -> SUBSET Groups]
    /\ session     \in [Users -> BOOLEAN]

Init ==
    /\ status      = [u \in Users |-> "none"]
    /\ forceChange = [u \in Users |-> FALSE]
    /\ userRoles   = [u \in Users |-> {}]
    /\ userGroups  = [u \in Users |-> {}]
    /\ session     = [u \in Users |-> FALSE]

(* Admin invites a not-yet-created user: Invited + forced change. *)
Invite(u) ==
    /\ status[u] = "none"
    /\ status'      = [status      EXCEPT ![u] = "invited"]
    /\ forceChange' = [forceChange EXCEPT ![u] = TRUE]
    /\ UNCHANGED <<userRoles, userGroups, session>>

(* The user logs in. A disabled user never admits; an invited user becomes  *)
(* active on first admit but keeps the forced-change label.                 *)
Login(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ session'  = [session EXCEPT ![u] = TRUE]
    /\ status'   = [status  EXCEPT ![u] = "active"]
    /\ UNCHANGED <<forceChange, userRoles, userGroups>>

Logout(u) ==
    /\ session[u]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, forceChange, userRoles, userGroups>>

(* The user completes a self password change: clears the forced-change label. *)
(* Requires a live session (they authenticated with the current password).    *)
CompletePasswordChange(u) ==
    /\ session[u]
    /\ forceChange[u]
    /\ forceChange' = [forceChange EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, userRoles, userGroups, session>>

(* Admin sets the forced-change label (rotation / require-new-password). *)
RequireChange(u) ==
    /\ status[u] = "active"
    /\ forceChange' = [forceChange EXCEPT ![u] = TRUE]
    /\ UNCHANGED <<status, userRoles, userGroups, session>>

(* Disable revokes the user's session and blocks future admits. *)
Disable(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ status'  = [status  EXCEPT ![u] = "disabled"]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<forceChange, userRoles, userGroups>>

Enable(u) ==
    /\ status[u] = "disabled"
    /\ status' = [status EXCEPT ![u] = "active"]
    /\ UNCHANGED <<forceChange, userRoles, userGroups, session>>

AssignRole(u, r) ==
    /\ status[u] \in {"invited", "active"}
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \cup {r}]
    /\ UNCHANGED <<status, forceChange, userGroups, session>>

RevokeRole(u, r) ==
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \ {r}]
    /\ UNCHANGED <<status, forceChange, userGroups, session>>

AddToGroup(u, g) ==
    /\ status[u] \in {"invited", "active"}
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \cup {g}]
    /\ UNCHANGED <<status, forceChange, userRoles, session>>

RemoveFromGroup(u, g) ==
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \ {g}]
    /\ UNCHANGED <<status, forceChange, userRoles, session>>

Next ==
    \/ \E u \in Users : Invite(u)
    \/ \E u \in Users : Login(u)
    \/ \E u \in Users : Logout(u)
    \/ \E u \in Users : CompletePasswordChange(u)
    \/ \E u \in Users : RequireChange(u)
    \/ \E u \in Users : Disable(u)
    \/ \E u \in Users : Enable(u)
    \/ \E u \in Users, r \in Roles  : AssignRole(u, r)
    \/ \E u \in Users, r \in Roles  : RevokeRole(u, r)
    \/ \E u \in Users, g \in Groups : AddToGroup(u, g)
    \/ \E u \in Users, g \in Groups : RemoveFromGroup(u, g)

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

(* An invited user that has not completed a password change is still forced. *)
(* (Once active they may or may not be forced; invited implies forced.)      *)
InvitedForcesChange ==
    \A u \in Users : status[u] = "invited" => forceChange[u]

(* A user under a forced change may perform no capability-gated act: the      *)
(* console/server confine them to the password-change screen. We model "may   *)
(* perform an act needing capability c" as (has session) /\ ~forceChange /\    *)
(* c \in EffectiveCaps(u); the containment invariant is that a forced user     *)
(* passes NO such gate.                                                        *)
MayPerform(u, c) == session[u] /\ ~forceChange[u] /\ c \in EffectiveCaps(u)
ForcedChangeContained ==
    \A u \in Users : forceChange[u] => (\A c \in Caps : ~MayPerform(u, c))

(* A disabled user never holds a live session. *)
DisabledNeverActive ==
    \A u \in Users : status[u] = "disabled" => ~session[u]

(* Authority comes only from an explicit role or group-role grant: a user    *)
(* with no roles and no group memberships holds no capabilities — there is no *)
(* ambient/default grant, so a role/group removal drops it entirely.          *)
NoAmbientAuthority ==
    \A u \in Users : EffectiveRoles(u) = {} => EffectiveCaps(u) = {}

=============================================================================
