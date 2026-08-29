------------------------------ MODULE IdentityLogin ------------------------------
(***************************************************************************)
(* Pillar identity, keys, credentials & login (ROI P1, method #1).         *)
(*                                                                         *)
(* Extends Registration.tla (USER_PRIMARY -> NODE_SUBKEY admission) and    *)
(* WoTAuthority.tla (owner-anchored tsig reachability + revocation) into   *)
(* the full cold-root/operational-key/device-subkey/node-subkey hierarchy: *)
(*                                                                         *)
(*   COLD_ROOT (genesis identity, canonical CID)                          *)
(*        |  Certify   (cold key signs directly -- rare, high-value use)  *)
(*        v                                                                *)
(*   OPERATIONAL_KEY                                                       *)
(*        |  DelegationGrant (an already-enrolled op key vouches for a     *)
(*        |  new op key -- day-to-day enrollment that never touches the    *)
(*        v   cold key)                                                    *)
(*   OPERATIONAL_KEY (further op keys, transitively enrolled)              *)
(*        |  GrantDevice (an op key grants a device/node subkey)          *)
(*        v                                                                *)
(*   DEVICE_SUBKEY (per-device/per-node identity actually presented at    *)
(*                   login)                                                *)
(*                                                                         *)
(* A ROOT's identity IS its genesis CID: the model treats `Roots` as the   *)
(* set of canonical genesis identities directly (no separate CID variable  *)
(* is needed -- a root constant already stands for "the canonical CID that *)
(* anchors this identity's whole key hierarchy").                          *)
(*                                                                         *)
(* Enrollment (CertifyOp / DelegationGrantOp / GrantDevice) is AP and      *)
(* deliberately UNGUARDED by validity of the signer -- exactly like        *)
(* Registration's IssueSubkey and WoTAuthority's IssueEdge: a rogue or     *)
(* not-yet-valid key can still mint a certificate. Validity is checked     *)
(* only at the point that matters -- Login -- mirroring both parent specs' *)
(* "guard admission, not issuance" discipline.                            *)
(*                                                                         *)
(* Revocation (RevokeRoot / RevokeOp / RevokeDevice) is modelled, as in    *)
(* WoTAuthority, as three independent grow-only (monotonic) sets. Crucially*)
(* RevokeOp and RevokeDevice carry NO precondition referencing any root:   *)
(* an operational key can revoke itself (or a device it granted) with no  *)
(* cold-key action whatsoever -- this is "self-revocation without the      *)
(* cold key". Only a root's OWN revocation (RevokeRoot) touches the root   *)
(* level, and even that needs no other root's involvement.                *)
(*                                                                         *)
(* Login is the client-side-signature primitive: the server holds only    *)
(* public identities (Roots/OpKeys/Devices) and the public                *)
(* certify/grant/revoke facts modelled below -- there is no private-key    *)
(* variable in this model at all, which IS the "server holds public keys  *)
(* only" property: nothing in the server-observable state (`vars`) could   *)
(* ever let the server itself produce a login, only verify one presented   *)
(* to it. Login's guard is the admission policy: the presented device      *)
(* must chain, through a non-revoked op key, to a non-revoked root, and    *)
(* the device itself must not be revoked.                                  *)
(*                                                                         *)
(* Following WoTAuthority's technique, the login OUTCOME is recorded in a  *)
(* single OVERWRITTEN ghost variable `lastLogin` (not an ever-growing      *)
(* "admitted" set) together with a snapshot of the revoked sets at the     *)
(* moment it fired. TLC checks invariants after EVERY transition, so every *)
(* Login that ever fires is checked, exactly once, as "the most recent     *)
(* one", in its own immediate successor state -- giving the same total     *)
(* coverage as an ever-growing admitted-log while keeping the state space  *)
(* independent of how many logins have occurred, and sidestepping the      *)
(* unsound alternative of a permanent "admitted" set that a LATER          *)
(* revocation could silently invalidate without ever being re-checked.     *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - LoginRequiresValidChain: the most recent successful login's device, *)
(*     op key, and root were ALL simultaneously non-revoked, at the exact  *)
(*     moment of login, and the device was genuinely granted by that op    *)
(*     key which was genuinely (transitively) enrolled under that root.    *)
(*   - NoAmbientAuthority: an ungranted device (never the subject of any    *)
(*     GrantDevice) is never the subject of a successful login.           *)
(*   - TypeOK: structural well-formedness of the model's state.           *)
(***************************************************************************)
EXTENDS FiniteSets, TLC

CONSTANTS
    Roots,      \* candidate cold-root (genesis-CID) identities
    OpKeys,     \* candidate operational-key identities
    Devices,    \* candidate device/node-subkey identities
    None        \* sentinel: "not (yet) enrolled/granted"

ASSUME RootsNonEmpty   == Roots # {}
ASSUME OpKeysNonEmpty  == OpKeys # {}
ASSUME DevicesNonEmpty == Devices # {}
ASSUME NoneNotRoot     == None \notin Roots
ASSUME NoneNotOp       == None \notin OpKeys
ASSUME NoneNotDevice   == None \notin Devices

VARIABLES
    enrolledBy,     \* enrolledBy[op]: the Root this OpKey ultimately chains to (via Certify or
                     \* transitive DelegationGrant), or None if not (yet) enrolled
    deviceGrant,    \* deviceGrant[d]: the OpKey that granted device d, or None
    revokedRoots,   \* SUBSET Roots: self-revoked cold roots (grow-only, true/global)
    revokedOps,     \* SUBSET OpKeys: self-revoked operational keys (grow-only, true/global)
    revokedDevices, \* SUBSET Devices: self-revoked device subkeys (grow-only, true/global)
    lastLogin       \* ghost: the most recent Login attempt's outcome + a SNAPSHOT of the
                     \* revoked sets at the exact moment it fired (overwritten, not accumulated
                     \* -- mirrors WoTAuthority's lastAct.authSnap technique so a LATER
                     \* revocation of the same device/op/root can never retroactively falsify
                     \* a login that was genuinely valid when it happened)

vars == <<enrolledBy, deviceGrant, revokedRoots, revokedOps, revokedDevices, lastLogin>>

TypeOK ==
    /\ enrolledBy \in [OpKeys -> Roots \cup {None}]
    /\ deviceGrant \in [Devices -> OpKeys \cup {None}]
    /\ revokedRoots \subseteq Roots
    /\ revokedOps \subseteq OpKeys
    /\ revokedDevices \subseteq Devices
    /\ lastLogin \in [some: BOOLEAN, device: Devices, op: OpKeys \cup {None},
                       root: Roots \cup {None}, devRevokedSnap: SUBSET Devices,
                       opRevokedSnap: SUBSET OpKeys, rootRevokedSnap: SUBSET Roots]

Init ==
    /\ enrolledBy = [op \in OpKeys |-> None]
    /\ deviceGrant = [d \in Devices |-> None]
    /\ revokedRoots = {}
    /\ revokedOps = {}
    /\ revokedDevices = {}
    /\ lastLogin = [some |-> FALSE, device |-> CHOOSE d \in Devices : TRUE,
                     op |-> None, root |-> None, devRevokedSnap |-> {},
                     opRevokedSnap |-> {}, rootRevokedSnap |-> {}]

-----------------------------------------------------------------------------
(* ENROLLMENT (AP): unguarded by validity of the signer, exactly like       *)
(* Registration's IssueSubkey / WoTAuthority's IssueEdge.                  *)

\* Cold-root certification: root directly signs/certifies op key `op`.
CertifyOp(root, op) ==
    /\ enrolledBy[op] = None
    /\ enrolledBy' = [enrolledBy EXCEPT ![op] = root]
    /\ UNCHANGED <<deviceGrant, revokedRoots, revokedOps, revokedDevices, lastLogin>>

\* Delegation-grant enrollment: an already-enrolled op key `signer` vouches
\* for a new op key `op`, WITHOUT ever touching the cold root key. `op`
\* inherits `signer`'s root binding (whatever it is -- even None, mirroring
\* Registration's IssueSubkey allowing a rogue/unenrolled signer to still
\* mint a certificate; Login is what actually checks validity).
DelegationGrantOp(signer, op) ==
    /\ signer \in OpKeys
    /\ enrolledBy[op] = None
    /\ enrolledBy' = [enrolledBy EXCEPT ![op] = enrolledBy[signer]]
    /\ UNCHANGED <<deviceGrant, revokedRoots, revokedOps, revokedDevices, lastLogin>>

\* An op key grants a device/node subkey. Unguarded by the op key's own
\* validity -- a rogue or not-yet-enrolled op key can still mint a device
\* grant; Login is the sole checkpoint.
GrantDevice(op, d) ==
    /\ deviceGrant[d] = None
    /\ deviceGrant' = [deviceGrant EXCEPT ![d] = op]
    /\ UNCHANGED <<enrolledBy, revokedRoots, revokedOps, revokedDevices, lastLogin>>

-----------------------------------------------------------------------------
(* REVOCATION: three independent grow-only (idempotent, add-once) sets.    *)
(* RevokeOp / RevokeDevice reference NO root at all -- self-revocation     *)
(* without the cold key. RevokeRoot needs no other root's involvement      *)
(* either.                                                                 *)

RevokeRoot(root) ==
    /\ root \notin revokedRoots
    /\ revokedRoots' = revokedRoots \cup {root}
    /\ UNCHANGED <<enrolledBy, deviceGrant, revokedOps, revokedDevices, lastLogin>>

RevokeOp(op) ==
    /\ op \notin revokedOps
    /\ revokedOps' = revokedOps \cup {op}
    /\ UNCHANGED <<enrolledBy, deviceGrant, revokedRoots, revokedDevices, lastLogin>>

RevokeDevice(d) ==
    /\ d \notin revokedDevices
    /\ revokedDevices' = revokedDevices \cup {d}
    /\ UNCHANGED <<enrolledBy, deviceGrant, revokedRoots, revokedOps, lastLogin>>

-----------------------------------------------------------------------------
(* LOGIN: the client-side-signature primitive. The server-observable state *)
(* (`vars`) holds only public identities and public certify/grant/revoke   *)
(* facts -- no private key is ever a variable here, so nothing in this      *)
(* model lets the server itself manufacture a login; it can only verify    *)
(* one against the chain below.                                           *)

Login(d) ==
    /\ d \notin revokedDevices
    /\ deviceGrant[d] # None
    /\ LET op == deviceGrant[d] IN
         /\ op \notin revokedOps
         /\ enrolledBy[op] # None
         /\ LET root == enrolledBy[op] IN
              /\ root \notin revokedRoots
              /\ lastLogin' = [some |-> TRUE, device |-> d, op |-> op, root |-> root,
                                devRevokedSnap |-> revokedDevices,
                                opRevokedSnap |-> revokedOps,
                                rootRevokedSnap |-> revokedRoots]
    /\ UNCHANGED <<enrolledBy, deviceGrant, revokedRoots, revokedOps, revokedDevices>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                     *)

Next ==
    \/ \E root \in Roots, op \in OpKeys       : CertifyOp(root, op)
    \/ \E signer, op \in OpKeys               : DelegationGrantOp(signer, op)
    \/ \E op \in OpKeys, d \in Devices         : GrantDevice(op, d)
    \/ \E root \in Roots                       : RevokeRoot(root)
    \/ \E op \in OpKeys                        : RevokeOp(op)
    \/ \E d \in Devices                        : RevokeDevice(d)
    \/ \E d \in Devices                        : Login(d)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The core admission theorem: whenever the most recent Login succeeded, the
\* device it recorded really was granted by the recorded op key, which
\* really was (transitively) enrolled under the recorded root, and NONE of
\* device/op/root were revoked (per the SNAPSHOT taken at the exact moment
\* the login fired) -- so a login that was genuinely valid when it happened
\* stays provably valid-at-that-time forever after, even once a later
\* revocation makes the same device/op/root revoked going forward.
LoginRequiresValidChain ==
    lastLogin.some =>
        /\ deviceGrant[lastLogin.device] = lastLogin.op
        /\ lastLogin.op # None
        /\ enrolledBy[lastLogin.op] = lastLogin.root
        /\ lastLogin.root # None
        /\ lastLogin.device \notin lastLogin.devRevokedSnap
        /\ lastLogin.op \notin lastLogin.opRevokedSnap
        /\ lastLogin.root \notin lastLogin.rootRevokedSnap

\* No ambient authority: a device that was never granted by any op key
\* (deviceGrant[d] = None) can never be the subject of a successful login.
NoAmbientAuthority ==
    lastLogin.some => deviceGrant[lastLogin.device] # None

=============================================================================
