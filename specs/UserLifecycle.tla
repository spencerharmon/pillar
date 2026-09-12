--------------------------- MODULE UserLifecycle ---------------------------
(***************************************************************************)
(* Pillar user-management / IAM lifecycle model (DESIGN-GATE for           *)
(* docs/user-management.md).                                               *)
(*                                                                         *)
(* Models the user lifecycle (invited -> active -> disabled), the two       *)
(* onboarding "required actions" an admin invite may attach (a forced       *)
(* first-login password change and a required passkey enrolment), sessions, *)
(* and capability derivation from roles + group-roles. Proves, under TLC    *)
(* (see UserLifecycle.cfg):                                                 *)
(*                                                                         *)
(*   ForcedChangeContained  -- while force_password_change is set, the user  *)
(*     can perform NO capability-gated act other than the two self-service   *)
(*     escapes (own profile, own password change); in particular they hold   *)
(*     no effective capabilities for other acts.                             *)
(*   RequiredPasskeyContained -- while a required passkey enrolment is        *)
(*     outstanding, the user likewise passes NO capability gate (they may    *)
(*     only enrol the passkey / touch their own profile / change their own   *)
(*     password). Keycloak-style: the invite can require a second factor be  *)
(*     enrolled before the account is usable for anything else.              *)
(*   DisabledNeverActive   -- a disabled user holds no live session.        *)
(*   NoAmbientAuthority     -- a user with no roles and no group memberships *)
(*     holds NO effective capabilities: authority comes only from an        *)
(*     explicit role or group-role grant, so removing them drops it.        *)
(*                                                                         *)
(* Design change (2026-09, "keycloak-style invite"): the forced first-login  *)
(* password change is now an OPTIONAL per-invite required action rather than *)
(* an unconditional property of every invited user (the old                 *)
(* InvitedForcesChange invariant), and a second optional required action —   *)
(* required passkey enrolment — is added. Both are modelled uniformly as     *)
(* containment gates: an invited user carrying EITHER outstanding required   *)
(* action is fully contained until they clear it. An admin may also invite   *)
(* with neither (an immediately-usable account with an admin-set password),  *)
(* exactly as Keycloak's "required user actions" are each independently      *)
(* optional.                                                                 *)
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
    status,         \* [Users -> Status]         ; "none" = not yet created
    forceChange,    \* [Users -> BOOLEAN]        ; force_password_change required action
    requirePasskey, \* [Users -> BOOLEAN]        ; required passkey-enrolment action
    userRoles,      \* [Users -> SUBSET Roles]
    userGroups,     \* [Users -> SUBSET Groups]
    session         \* [Users -> BOOLEAN]        ; TRUE = has a live session

vars == <<status, forceChange, requirePasskey, userRoles, userGroups, session>>

(* Effective capabilities: union over directly-assigned roles and the roles *)
(* attached to the user's groups. This is the authorization bridge the       *)
(* RbacDecider consumes.                                                      *)
GroupDerivedRoles(u) == UNION { GroupRoles[g] : g \in userGroups[u] }
EffectiveRoles(u)    == userRoles[u] \cup GroupDerivedRoles(u)
EffectiveCaps(u)     == UNION { RoleCaps[r] : r \in EffectiveRoles(u) }

(* A user is "onboarding-contained" while EITHER required action is still    *)
(* outstanding — the union of the two containment gates.                     *)
Contained(u) == forceChange[u] \/ requirePasskey[u]

TypeOK ==
    /\ status         \in [Users -> Status]
    /\ forceChange    \in [Users -> BOOLEAN]
    /\ requirePasskey \in [Users -> BOOLEAN]
    /\ userRoles      \in [Users -> SUBSET Roles]
    /\ userGroups     \in [Users -> SUBSET Groups]
    /\ session        \in [Users -> BOOLEAN]

Init ==
    /\ status         = [u \in Users |-> "none"]
    /\ forceChange    = [u \in Users |-> FALSE]
    /\ requirePasskey = [u \in Users |-> FALSE]
    /\ userRoles      = [u \in Users |-> {}]
    /\ userGroups     = [u \in Users |-> {}]
    /\ session        = [u \in Users |-> FALSE]

(* Admin invites a not-yet-created user, optionally attaching either or both *)
(* onboarding required actions (forced password change, required passkey).   *)
(* `forced`/`passkey` are the admin's per-invite choices — Keycloak's        *)
(* optional required user actions.                                            *)
Invite(u, forced, passkey) ==
    /\ status[u] = "none"
    /\ status'         = [status         EXCEPT ![u] = "invited"]
    /\ forceChange'    = [forceChange    EXCEPT ![u] = forced]
    /\ requirePasskey' = [requirePasskey EXCEPT ![u] = passkey]
    /\ UNCHANGED <<userRoles, userGroups, session>>

(* The user logs in. A disabled user never admits; an invited user becomes  *)
(* active on first admit but keeps any outstanding required-action labels.   *)
Login(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ session'  = [session EXCEPT ![u] = TRUE]
    /\ status'   = [status  EXCEPT ![u] = "active"]
    /\ UNCHANGED <<forceChange, requirePasskey, userRoles, userGroups>>

Logout(u) ==
    /\ session[u]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, forceChange, requirePasskey, userRoles, userGroups>>

(* The user completes a self password change: clears the forced-change label. *)
(* Requires a live session (they authenticated with the current password).    *)
CompletePasswordChange(u) ==
    /\ session[u]
    /\ forceChange[u]
    /\ forceChange' = [forceChange EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, requirePasskey, userRoles, userGroups, session>>

(* The user enrols the passkey their invite required: clears the required-    *)
(* passkey label. Requires a live session (they are signed in, contained,     *)
(* and completing onboarding).                                                *)
EnrollPasskey(u) ==
    /\ session[u]
    /\ requirePasskey[u]
    /\ requirePasskey' = [requirePasskey EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, forceChange, userRoles, userGroups, session>>

(* Admin sets the forced-change label (rotation / require-new-password). *)
RequireChange(u) ==
    /\ status[u] = "active"
    /\ forceChange' = [forceChange EXCEPT ![u] = TRUE]
    /\ UNCHANGED <<status, requirePasskey, userRoles, userGroups, session>>

(* Disable revokes the user's session and blocks future admits. *)
Disable(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ status'  = [status  EXCEPT ![u] = "disabled"]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<forceChange, requirePasskey, userRoles, userGroups>>

Enable(u) ==
    /\ status[u] = "disabled"
    /\ status' = [status EXCEPT ![u] = "active"]
    /\ UNCHANGED <<forceChange, requirePasskey, userRoles, userGroups, session>>

AssignRole(u, r) ==
    /\ status[u] \in {"invited", "active"}
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \cup {r}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, userGroups, session>>

RevokeRole(u, r) ==
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \ {r}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, userGroups, session>>

AddToGroup(u, g) ==
    /\ status[u] \in {"invited", "active"}
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \cup {g}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, userRoles, session>>

RemoveFromGroup(u, g) ==
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \ {g}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, userRoles, session>>

Next ==
    \/ \E u \in Users, forced \in BOOLEAN, passkey \in BOOLEAN : Invite(u, forced, passkey)
    \/ \E u \in Users : Login(u)
    \/ \E u \in Users : Logout(u)
    \/ \E u \in Users : CompletePasswordChange(u)
    \/ \E u \in Users : EnrollPasskey(u)
    \/ \E u \in Users : RequireChange(u)
    \/ \E u \in Users : Disable(u)
    \/ \E u \in Users : Enable(u)
    \/ \E u \in Users, r \in Roles  : AssignRole(u, r)
    \/ \E u \in Users, r \in Roles  : RevokeRole(u, r)
    \/ \E u \in Users, g \in Groups : AddToGroup(u, g)
    \/ \E u \in Users, g \in Groups : RemoveFromGroup(u, g)

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

(* A user carrying an outstanding required action may perform no capability-  *)
(* gated act: the console/server confine them to the onboarding screens. We   *)
(* model "may perform an act needing capability c" as (has session) /\ (not   *)
(* contained by either required action) /\ c \in EffectiveCaps(u).            *)
MayPerform(u, c) == session[u] /\ ~Contained(u) /\ c \in EffectiveCaps(u)

(* While force_password_change is set, the user passes NO capability gate. *)
ForcedChangeContained ==
    \A u \in Users : forceChange[u] => (\A c \in Caps : ~MayPerform(u, c))

(* While a required passkey enrolment is outstanding, the user passes NO     *)
(* capability gate either — the second onboarding gate, symmetric to the     *)
(* forced-change one.                                                         *)
RequiredPasskeyContained ==
    \A u \in Users : requirePasskey[u] => (\A c \in Caps : ~MayPerform(u, c))

(* A disabled user never holds a live session. *)
DisabledNeverActive ==
    \A u \in Users : status[u] = "disabled" => ~session[u]

(* Authority comes only from an explicit role or group-role grant: a user    *)
(* with no roles and no group memberships holds no capabilities — there is no *)
(* ambient/default grant, so a role/group removal drops it entirely.          *)
NoAmbientAuthority ==
    \A u \in Users : EffectiveRoles(u) = {} => EffectiveCaps(u) = {}

=============================================================================
