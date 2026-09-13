--------------------------- MODULE UserLifecycle ---------------------------
(***************************************************************************)
(* Pillar user-management / IAM lifecycle model (DESIGN-GATE for           *)
(* docs/user-management.md).                                               *)
(*                                                                         *)
(* Models the user lifecycle (invited -> active -> disabled), the two       *)
(* onboarding "required actions" an admin invite may attach (a forced       *)
(* first-login password change and a required passkey enrolment), sessions, *)
(* capability derivation from roles + group-roles, and -- the load-bearing   *)
(* CRYPTOGRAPHIC foundation of this revision -- an `opKey` variable: TRUE     *)
(* iff an OPERATIONAL signing key is currently minted AND its node-seal is    *)
(* admitted for the user, i.e. iff the key-distribution node can delegate-    *)
(* sign an authority-bearing op ON BEHALF of that user.                       *)
(*                                                                           *)
(* Design change (2026-09, "cryptographic containment via delegated          *)
(* signing"): authority to perform a cell op is no longer a POLICY gate       *)
(* (an `if force_password_change { deny }` around signing). It is the ability *)
(* to PRODUCE AN ACCEPTED SIGNATURE, and in pillar's delegated-signing model  *)
(* the client never holds the key -- the KD node signs on the user's behalf,  *)
(* and only if it holds an UNLOCKED operational key for that user. Therefore   *)
(* "contained" == "no operational key exists to sign with" (`~opKey`), not a  *)
(* boolean the app consults. An onboarding user's operational offer is simply *)
(* NOT MINTED; a must-change / admin-reset REVOKES it; a disable revokes its   *)
(* node-seal admission. The change-password dialog then FALLS OUT: the only    *)
(* server-side-signable actions for a keyless credential are the self-service  *)
(* onboarding ceremonies, so the UI can render nothing else.                   *)
(*                                                                           *)
(* Proves, under TLC (see UserLifecycle.cfg):                                *)
(*                                                                         *)
(*   ContainedHoldsNoOpKey   -- CRYPTO FOUNDATION: while EITHER required       *)
(*     action is outstanding, the user holds NO operational key. No mint       *)
(*     transition ever fires while a required action is owed; every            *)
(*     require-change/admin-reset revokes the key. This is the theorem the     *)
(*     old boolean gate only pretended to enforce.                             *)
(*   DisabledHoldsNoOpKey    -- a disabled user's operational node-seal        *)
(*     admission is revoked: a disabled account can sign nothing.              *)
(*   OnboardingCannotSign    -- authority flows ONLY through the operational   *)
(*     key: a user without one (`~opKey`) passes NO capability gate,           *)
(*     regardless of roles/groups/session. The signing-layer realization of    *)
(*     NoAmbientAuthority.                                                      *)
(*   ForcedChangeContained / RequiredPasskeyContained -- the old guarantees,   *)
(*     now DERIVED consequences of key absence rather than policy checks:      *)
(*     a forced-change / required-passkey user passes no capability gate.      *)
(*   DisabledNeverActive     -- a disabled user holds no live session.         *)
(*   NoAmbientAuthority       -- a user with no roles and no group memberships  *)
(*     holds NO effective capabilities.                                        *)
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
    opKey,          \* [Users -> BOOLEAN]        ; TRUE = operational key minted+admitted
                    \*                             (KD node can delegate-sign for the user)
    userRoles,      \* [Users -> SUBSET Roles]
    userGroups,     \* [Users -> SUBSET Groups]
    session         \* [Users -> BOOLEAN]        ; TRUE = has a live session

vars == <<status, forceChange, requirePasskey, opKey, userRoles, userGroups, session>>

(* Effective capabilities: union over directly-assigned roles and the roles *)
(* attached to the user's groups. This is the authorization bridge the       *)
(* RbacDecider consumes.                                                      *)
GroupDerivedRoles(u) == UNION { GroupRoles[g] : g \in userGroups[u] }
EffectiveRoles(u)    == userRoles[u] \cup GroupDerivedRoles(u)
EffectiveCaps(u)     == UNION { RoleCaps[r] : r \in EffectiveRoles(u) }

(* A user is "onboarding-contained" while EITHER required action is still    *)
(* outstanding. In this revision containment is realised cryptographically:   *)
(* the invariant ContainedHoldsNoOpKey ties `Contained(u)` to `~opKey[u]`.    *)
Contained(u) == forceChange[u] \/ requirePasskey[u]

TypeOK ==
    /\ status         \in [Users -> Status]
    /\ forceChange    \in [Users -> BOOLEAN]
    /\ requirePasskey \in [Users -> BOOLEAN]
    /\ opKey          \in [Users -> BOOLEAN]
    /\ userRoles      \in [Users -> SUBSET Roles]
    /\ userGroups     \in [Users -> SUBSET Groups]
    /\ session        \in [Users -> BOOLEAN]

Init ==
    /\ status         = [u \in Users |-> "none"]
    /\ forceChange    = [u \in Users |-> FALSE]
    /\ requirePasskey = [u \in Users |-> FALSE]
    /\ opKey          = [u \in Users |-> FALSE]
    /\ userRoles      = [u \in Users |-> {}]
    /\ userGroups     = [u \in Users |-> {}]
    /\ session        = [u \in Users |-> FALSE]

(* Admin invites a not-yet-created user, optionally attaching either or both *)
(* onboarding required actions (forced password change, required passkey).   *)
(* The operational key is MINTED at invite time ONLY for an immediately-      *)
(* usable account (neither required action attached, an admin-set password    *)
(* seals the operational offer straight away). If either action is owed the   *)
(* offer is left UNMINTED -- the temp password unlocks only an onboarding      *)
(* credential -- so ContainedHoldsNoOpKey holds from creation.                *)
Invite(u, forced, passkey) ==
    /\ status[u] = "none"
    /\ status'         = [status         EXCEPT ![u] = "invited"]
    /\ forceChange'    = [forceChange    EXCEPT ![u] = forced]
    /\ requirePasskey' = [requirePasskey EXCEPT ![u] = passkey]
    /\ opKey'          = [opKey          EXCEPT ![u] = ~(forced \/ passkey)]
    /\ UNCHANGED <<userRoles, userGroups, session>>

(* The user logs in. A disabled user never admits; an invited user becomes  *)
(* active on first admit but keeps any outstanding required-action labels    *)
(* and its opKey state (an onboarding user gets a session but no op key).     *)
Login(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ session'  = [session EXCEPT ![u] = TRUE]
    /\ status'   = [status  EXCEPT ![u] = "active"]
    /\ UNCHANGED <<forceChange, requirePasskey, opKey, userRoles, userGroups>>

Logout(u) ==
    /\ session[u]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, forceChange, requirePasskey, opKey, userRoles, userGroups>>

(* The user completes a self password change: clears the forced-change label  *)
(* and, if no other required action remains, MINTS the operational key (the   *)
(* KD node re-seals the operational offer under the newly chosen password and *)
(* admits its node-seal). Requires a live active session.                     *)
CompletePasswordChange(u) ==
    /\ status[u] = "active"
    /\ session[u]
    /\ forceChange[u]
    /\ forceChange' = [forceChange EXCEPT ![u] = FALSE]
    /\ opKey'       = [opKey       EXCEPT ![u] = ~requirePasskey[u]]
    /\ UNCHANGED <<status, requirePasskey, userRoles, userGroups, session>>

(* The user enrols the passkey their invite required: clears the required-    *)
(* passkey label and, if no forced change remains, MINTS the operational key. *)
EnrollPasskey(u) ==
    /\ status[u] = "active"
    /\ session[u]
    /\ requirePasskey[u]
    /\ requirePasskey' = [requirePasskey EXCEPT ![u] = FALSE]
    /\ opKey'          = [opKey          EXCEPT ![u] = ~forceChange[u]]
    /\ UNCHANGED <<status, forceChange, userRoles, userGroups, session>>

(* Admin requires a password change of an active user: sets the forced-change *)
(* label and REVOKES the operational key (the operational offer's node-seal   *)
(* admission is stripped -- the current credential can sign nothing until the *)
(* user completes an ownership-proved rotation). The node needs no knowledge  *)
(* of the password to revoke.                                                  *)
RequireChange(u) ==
    /\ status[u] = "active"
    /\ forceChange' = [forceChange EXCEPT ![u] = TRUE]
    /\ opKey'       = [opKey       EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, requirePasskey, userRoles, userGroups, session>>

(* Admin reset: like RequireChange but also revokes every live session and    *)
(* re-issues onboarding under a fresh admin-set temp password (still keyless   *)
(* until the user rotates).                                                    *)
AdminReset(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ forceChange' = [forceChange EXCEPT ![u] = TRUE]
    /\ opKey'       = [opKey       EXCEPT ![u] = FALSE]
    /\ session'     = [session     EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<status, requirePasskey, userRoles, userGroups>>

(* Disable revokes the user's session AND the operational key's node-seal      *)
(* admission (a disabled account signs nothing), and blocks future admits.     *)
Disable(u) ==
    /\ status[u] \in {"invited", "active"}
    /\ status'  = [status  EXCEPT ![u] = "disabled"]
    /\ session' = [session EXCEPT ![u] = FALSE]
    /\ opKey'   = [opKey   EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<forceChange, requirePasskey, userRoles, userGroups>>

(* Enable re-admits the operational node-seal (no password needed -- only the  *)
(* outer node-seal is re-wrapped around the untouched inner offer) IFF the     *)
(* user owes no onboarding action; a user disabled mid-onboarding stays        *)
(* keyless. Requires a fresh login (session stays FALSE).                      *)
Enable(u) ==
    /\ status[u] = "disabled"
    /\ status' = [status EXCEPT ![u] = "active"]
    /\ opKey'  = [opKey  EXCEPT ![u] = ~Contained(u)]
    /\ UNCHANGED <<forceChange, requirePasskey, userRoles, userGroups, session>>

AssignRole(u, r) ==
    /\ status[u] \in {"invited", "active"}
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \cup {r}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, opKey, userGroups, session>>

RevokeRole(u, r) ==
    /\ userRoles' = [userRoles EXCEPT ![u] = @ \ {r}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, opKey, userGroups, session>>

AddToGroup(u, g) ==
    /\ status[u] \in {"invited", "active"}
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \cup {g}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, opKey, userRoles, session>>

RemoveFromGroup(u, g) ==
    /\ userGroups' = [userGroups EXCEPT ![u] = @ \ {g}]
    /\ UNCHANGED <<status, forceChange, requirePasskey, opKey, userRoles, session>>

Next ==
    \/ \E u \in Users, forced \in BOOLEAN, passkey \in BOOLEAN : Invite(u, forced, passkey)
    \/ \E u \in Users : Login(u)
    \/ \E u \in Users : Logout(u)
    \/ \E u \in Users : CompletePasswordChange(u)
    \/ \E u \in Users : EnrollPasskey(u)
    \/ \E u \in Users : RequireChange(u)
    \/ \E u \in Users : AdminReset(u)
    \/ \E u \in Users : Disable(u)
    \/ \E u \in Users : Enable(u)
    \/ \E u \in Users, r \in Roles  : AssignRole(u, r)
    \/ \E u \in Users, r \in Roles  : RevokeRole(u, r)
    \/ \E u \in Users, g \in Groups : AddToGroup(u, g)
    \/ \E u \in Users, g \in Groups : RemoveFromGroup(u, g)

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

(* "May perform an act needing capability c" is the ability to produce an     *)
(* ACCEPTED signature for it: a live session, an operational key the KD node   *)
(* can delegate-sign with (`opKey`), and the capability in the effective set.  *)
(* opKey is load-bearing -- without it there is no signature, hence no act,    *)
(* independent of any policy check.                                            *)
MayPerform(u, c) == session[u] /\ opKey[u] /\ c \in EffectiveCaps(u)

(* CRYPTO FOUNDATION: an outstanding required action means no operational key  *)
(* exists to sign with. TLC proves no reachable state mints a key while a      *)
(* required action is owed.                                                    *)
ContainedHoldsNoOpKey ==
    \A u \in Users : Contained(u) => ~opKey[u]

(* A disabled account's operational node-seal admission is revoked. *)
DisabledHoldsNoOpKey ==
    \A u \in Users : status[u] = "disabled" => ~opKey[u]

(* Authority flows ONLY through the operational key: no key => no act. The     *)
(* signing-layer realization of NoAmbientAuthority.                            *)
OnboardingCannotSign ==
    \A u \in Users : ~opKey[u] => (\A c \in Caps : ~MayPerform(u, c))

(* The old guarantees, now DERIVED consequences of key absence: a forced-      *)
(* change / required-passkey user passes no capability gate (because           *)
(* ContainedHoldsNoOpKey denies them the key MayPerform requires).             *)
ForcedChangeContained ==
    \A u \in Users : forceChange[u] => (\A c \in Caps : ~MayPerform(u, c))

RequiredPasskeyContained ==
    \A u \in Users : requirePasskey[u] => (\A c \in Caps : ~MayPerform(u, c))

(* A disabled user never holds a live session. *)
DisabledNeverActive ==
    \A u \in Users : status[u] = "disabled" => ~session[u]

(* Authority comes only from an explicit role or group-role grant. *)
NoAmbientAuthority ==
    \A u \in Users : EffectiveRoles(u) = {} => EffectiveCaps(u) = {}

=============================================================================
