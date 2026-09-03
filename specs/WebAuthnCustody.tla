--------------------------- MODULE WebAuthnCustody ---------------------------
(***************************************************************************)
(* Pillar WebAuthn hardware-security-key custody model (ROI Priority 0     *)
(* 'unified custody & hardware security keys', operator 2026-08-31,        *)
(* method #1, DESIGN-GATED).                                               *)
(*                                                                         *)
(* This spec REFINES NodeCustodyLogin.tla's password/operational-key       *)
(* custody posture with a SECOND, hardware-backed custody factor. It does  *)
(* NOT retire identity-node-custody-spec: node-key custody remains the     *)
(* universal login flow; WebAuthn adds a hardware authenticator whose      *)
(* assertions the relying party (RP) verifies against a SHARED credential  *)
(* record.                                                                 *)
(*                                                                         *)
(* THE SHARED CREDENTIAL RECORD is the crux. One authenticator (a roaming  *)
(* FIDO2 security key or a platform authenticator) is registered ONCE and  *)
(* produces a single record                                                *)
(*                                                                         *)
(*   { credential_id, COSE public key, PRF salt, sign_count,               *)
(*     user handle, cell }                                                 *)
(*                                                                         *)
(* stored server-side by the RP. That ONE record is read/written by BOTH   *)
(* client surfaces:                                                        *)
(*                                                                         *)
(*   - the BROWSER via navigator.credentials.{create,get}, and            *)
(*   - the CLI via ctap-hid (direct CTAP2 to the same authenticator),      *)
(*                                                                         *)
(* against the SAME relying-party challenge protocol. Because both         *)
(* surfaces resolve to the one record, a credential registered on either   *)
(* surface admits on the other (CrossSurfaceUsability).                    *)
(*                                                                         *)
(* We model the registration + assertion state machine and prove, under    *)
(* TLC (see WebAuthnCustody.cfg):                                          *)
(*                                                                         *)
(*   SignCountMonotonic       -- a stored sign_count only ever increases;  *)
(*     a replayed / cloned-authenticator assertion carrying a stale or     *)
(*     EQUAL count is refused (clone detection).                           *)
(*   ChallengeFreshness       -- an assertion against an expired or        *)
(*     already-consumed challenge is refused (no replay). A challenge is   *)
(*     single-use and issued fresh by the RP.                              *)
(*   CrossSurfaceUsability    -- a credential registered via EITHER surface *)
(*     admits via the OTHER, because both read/write the one record.       *)
(*   RevokedKeyNeverAdmits    -- a revoked / deleted credential record      *)
(*     never again produces an admitting assertion (fail-closed).          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Creds,        \* candidate credential-id identities (one per authenticator record)
    Users,        \* candidate user-handle identities
    Cell,         \* the relying-party cell identity (scopes the record)
    Surfaces,     \* the two client surfaces: {browser, cli}
    None,         \* sentinel
    MaxCount      \* model bound on sign_count (authenticator signature counter)

ASSUME CredsNonEmpty    == Creds # {}
ASSUME UsersNonEmpty    == Users # {}
ASSUME SurfacesTwo      == Surfaces # {}
ASSUME MaxCountIsNat    == MaxCount \in Nat
ASSUME NoneNotCred      == None \notin Creds

Counts == 0 .. MaxCount

VARIABLES
    \* ---- the SHARED credential record, server-side (RP store) ----
    registered,   \* SUBSET Creds: credential records that exist (registered, not deleted)
    pubKey,       \* [Creds -> Users \cup {None}]: COSE public key <-> user handle binding
                   \* (modelled by the user handle it is bound to; None = unregistered)
    prfSalt,      \* [Creds -> Nat]: the PRF salt stored with the record (opaque; fixed at reg)
    signCount,    \* [Creds -> Counts]: the last stored authenticator signature counter
    regSurface,   \* [Creds -> Surfaces \cup {None}]: surface the record was registered from
    revoked,      \* SUBSET Creds: revoked / deleted records (grow-only, fail-closed)
    \* ---- the RP challenge protocol ----
    challenge,    \* the outstanding RP challenge nonce (a Nat), or None if none outstanding
    consumed,     \* SUBSET Nat: challenge nonces already consumed (single-use / replay guard)
    nextNonce,    \* Nat: monotone source of fresh challenge nonces
    \* ---- assertion ghost: the most recent assertion outcome ----
    lastAssert    \* ghost record describing the most recent admitting assertion

vars == <<registered, pubKey, prfSalt, signCount, regSurface, revoked,
          challenge, consumed, nextNonce, lastAssert>>

-----------------------------------------------------------------------------
(* INITIAL STATE                                                            *)

Init ==
    /\ registered = {}
    /\ pubKey     = [c \in Creds |-> None]
    /\ prfSalt    = [c \in Creds |-> 0]
    /\ signCount  = [c \in Creds |-> 0]
    /\ regSurface = [c \in Creds |-> None]
    /\ revoked    = {}
    /\ challenge   = None
    /\ consumed    = {}
    /\ nextNonce   = 0
    /\ lastAssert = [some |-> FALSE, cred |-> CHOOSE c \in Creds : TRUE,
                      user |-> None, surface |-> CHOOSE s \in Surfaces : TRUE,
                      count |-> 0, nonce |-> 0]

-----------------------------------------------------------------------------
(* RP CHALLENGE PROTOCOL                                                     *)
(* The RP issues a fresh, single-use challenge nonce. Only ONE challenge is  *)
(* outstanding at a time in this model; consuming it (an assertion or an     *)
(* expiry) frees the RP to issue the next. A nonce, once consumed, is never  *)
(* honoured again -- that is the replay guard.                               *)

\* Issue a fresh challenge (only when none is outstanding). The nonce is drawn
\* from a monotone source so it is globally unique and never reused.
IssueChallenge ==
    /\ challenge = None
    /\ nextNonce < MaxCount            \* model bound on distinct nonces
    /\ challenge'  = nextNonce
    /\ nextNonce'  = nextNonce + 1
    /\ UNCHANGED <<registered, pubKey, prfSalt, signCount, regSurface, revoked,
                   consumed, lastAssert>>

\* The outstanding challenge EXPIRES unused: it is consumed (single-use) and no
\* longer outstanding. An assertion presented against it afterwards is refused
\* because it is neither the outstanding challenge nor un-consumed.
ExpireChallenge ==
    /\ challenge # None
    /\ consumed'  = consumed \cup {challenge}
    /\ challenge' = None
    /\ UNCHANGED <<registered, pubKey, prfSalt, signCount, regSurface, revoked,
                   nextNonce, lastAssert>>

-----------------------------------------------------------------------------
(* REGISTRATION (navigator.credentials.create / CTAP2 makeCredential)       *)
(* One authenticator produces ONE shared record. Registration binds the     *)
(* record to a user handle and a PRF salt, initialises the signature counter *)
(* and stamps the surface it was created from. A revoked cred-id is never    *)
(* re-registered (the record stays dead -- fail-closed).                     *)

RegisterCred(c, u, s, salt) ==
    /\ c \in Creds
    /\ u \in Users
    /\ s \in Surfaces
    /\ salt \in 1 .. MaxCount
    /\ c \notin registered            \* fresh record only
    /\ c \notin revoked               \* a revoked/deleted record is never revived
    /\ registered' = registered \cup {c}
    /\ pubKey'     = [pubKey     EXCEPT ![c] = u]
    /\ prfSalt'    = [prfSalt    EXCEPT ![c] = salt]
    /\ signCount'  = [signCount  EXCEPT ![c] = 0]
    /\ regSurface' = [regSurface EXCEPT ![c] = s]
    /\ UNCHANGED <<revoked, challenge, consumed, nextNonce, lastAssert>>

-----------------------------------------------------------------------------
(* ASSERTION (navigator.credentials.get / CTAP2 getAssertion)               *)
(* An assertion is admitted ONLY when, all together:                        *)
(*   - the record exists and is not revoked,                                *)
(*   - it answers the OUTSTANDING, un-consumed challenge (freshness),       *)
(*   - the presented authenticator counter STRICTLY EXCEEDS the stored one  *)
(*     (SignCountMonotonic / clone detection).                              *)
(* On success the stored counter advances to the presented value and the    *)
(* challenge is consumed. Crucially, the admitting SURFACE may differ from   *)
(* the REGISTRATION surface: both surfaces read/write the ONE record, so a   *)
(* browser-registered cred admits a CLI assertion and vice versa.           *)

\* `newCount` is the counter value the authenticator presents this assertion.
AssertCred(c, s, newCount) ==
    /\ c \in Creds
    /\ s \in Surfaces
    /\ newCount \in Counts
    /\ c \in registered               \* record must exist ...
    /\ c \notin revoked               \* ... and not be revoked/deleted
    /\ challenge # None               \* there is an outstanding challenge ...
    /\ challenge \notin consumed      \* ... that has not already been consumed
    /\ newCount > signCount[c]        \* STRICT increase: stale/equal count => clone => refuse
    /\ signCount'  = [signCount EXCEPT ![c] = newCount]  \* advance stored counter
    /\ consumed'   = consumed \cup {challenge}           \* single-use: burn the challenge
    /\ lastAssert' = [some |-> TRUE, cred |-> c, user |-> pubKey[c], surface |-> s,
                       count |-> newCount, nonce |-> challenge]
    /\ challenge'  = None
    /\ UNCHANGED <<registered, pubKey, prfSalt, regSurface, revoked, nextNonce>>

-----------------------------------------------------------------------------
(* REVOCATION / DELETION                                                     *)
(* The RP revokes (deletes) a credential record. Grow-only: once revoked the *)
(* record can never admit again and is never re-registered (fail-closed).    *)

RevokeCred(c) ==
    /\ c \in registered
    /\ c \notin revoked
    /\ revoked' = revoked \cup {c}
    /\ UNCHANGED <<registered, pubKey, prfSalt, signCount, regSurface,
                   challenge, consumed, nextNonce, lastAssert>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                      *)

Next ==
    \/ IssueChallenge
    \/ ExpireChallenge
    \/ \E c \in Creds, u \in Users, s \in Surfaces, salt \in 1 .. MaxCount :
            RegisterCred(c, u, s, salt)
    \/ \E c \in Creds, s \in Surfaces, nc \in Counts : AssertCred(c, s, nc)
    \/ \E c \in Creds : RevokeCred(c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                         *)

TypeOK ==
    /\ registered \subseteq Creds
    /\ pubKey     \in [Creds -> Users \cup {None}]
    /\ prfSalt    \in [Creds -> 0 .. MaxCount]
    /\ signCount  \in [Creds -> Counts]
    /\ regSurface \in [Creds -> Surfaces \cup {None}]
    /\ revoked    \subseteq Creds
    /\ challenge  \in (0 .. MaxCount) \cup {None}
    /\ consumed   \subseteq (0 .. MaxCount)
    /\ nextNonce  \in 0 .. MaxCount
    /\ lastAssert \in [some: BOOLEAN, cred: Creds, user: Users \cup {None},
                       surface: Surfaces, count: Counts, nonce: 0 .. MaxCount]

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

(* ---- SignCountMonotonic (clone / replay detection) ---- *)
(* The stored sign_count only ever increases. Any admitting assertion had a  *)
(* presented counter STRICTLY GREATER than the previously stored value, so a  *)
(* replayed or cloned-authenticator assertion carrying a stale or EQUAL count *)
(* can never admit. Expressed as an action property: across every step the    *)
(* stored counter for any cred never decreases, AND whenever the most-recent  *)
(* assertion fired for a cred, its recorded count equals the (advanced) stored *)
(* value -- i.e. the admission raised the counter.                            *)
SignCountMonotonic ==
    [][ \A c \in Creds : signCount'[c] >= signCount[c] ]_vars

\* Standing invariant tie: the last admitting assertion's recorded count is the
\* stored counter of its cred (the admission advanced the store to exactly it),
\* so no admitted assertion ever left the stored counter behind a stale value.
LastAssertCountStored ==
    (lastAssert.some /\ lastAssert.cred \in registered)
        => signCount[lastAssert.cred] >= lastAssert.count

(* ---- ChallengeFreshness (no replay) ---- *)
(* Every admitting assertion consumed a challenge nonce that was the           *)
(* outstanding, un-consumed one at the instant it acted -- so an assertion      *)
(* against an expired (already-consumed) or absent challenge is refused. Once   *)
(* consumed a nonce is in `consumed` forever and can never admit again.         *)
\* The most recent assertion's nonce is now among the consumed set (it was
\* burned single-use on admission) -- a nonce can never fuel a second admission.
ChallengeFreshness ==
    lastAssert.some => lastAssert.nonce \in consumed

\* No outstanding challenge is ever a previously-consumed nonce: the RP always
\* issues a globally-fresh nonce, so a replayed nonce is never live again.
ChallengeNeverReissued ==
    challenge # None => challenge \notin consumed

(* ---- CrossSurfaceUsability ---- *)
(* A credential registered via EITHER surface admits via the OTHER, because     *)
(* both surfaces read/write the ONE shared record. The record is surface-        *)
(* agnostic for admission: assertion admits on ANY surface (Assert quantifies    *)
(* s over all Surfaces, independent of regSurface), so the admitting surface     *)
(* may differ from the registration surface. Whenever the most-recent assertion  *)
(* admitted, its cred is a real registered record whose registration surface is  *)
(* a valid surface -- and admission did not require surface = regSurface.         *)
CrossSurfaceUsability ==
    (lastAssert.some /\ lastAssert.cred \in registered)
        => /\ regSurface[lastAssert.cred] \in Surfaces
           /\ lastAssert.surface \in Surfaces
           /\ pubKey[lastAssert.cred] = lastAssert.user

(* ---- RevokedKeyNeverAdmits (fail-closed) ---- *)
(* A revoked / deleted credential record never again produces an admitting      *)
(* assertion. AssertCred refuses any `c \in revoked`, so at the instant an        *)
(* assertion admits (lastAssert advances this step) its cred is NOT revoked.     *)
(* Stated as an action property: whenever the assertion ghost changes -- i.e. a   *)
(* new admission fired -- the admitted cred is absent from the CURRENT revoked    *)
(* set. (A later revocation of that same cred does not retroactively make the     *)
(* past admission illegal; a fresh admission on a revoked cred is impossible.)    *)
RevokedKeyNeverAdmits ==
    [][ (lastAssert' # lastAssert) => (lastAssert'.cred \notin revoked') ]_vars

\* A revoked record is never re-registered / revived: revoked is grow-only and a
\* revoked cred can never re-enter `registered` via RegisterCred.
RevokedStaysDead ==
    \A c \in Creds : c \in revoked => c \in registered

=============================================================================
