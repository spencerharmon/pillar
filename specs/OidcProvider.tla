------------------------------ MODULE OidcProvider ------------------------------
(***************************************************************************)
(* Pillar OIDC provider authority seam (ROI Priority 0 IAM epic, method     *)
(* #1) -- an ORIGINAL-DESIGN model, own TLA+ gate before any Rust           *)
(* implementation. Extends UserLifecycle's user-state model (status \in     *)
(* {"active","disabled"}, Disable/Enable) with:                            *)
(*                                                                         *)
(*   - the authorization-code + PKCE grant: IssueCode binds a code to a     *)
(*     (user, client, pkce-challenge) triple only once consent is granted;  *)
(*     ConsumeCode redeems it exactly once and only when the presented       *)
(*     verifier matches the bound challenge, minting one access token and    *)
(*     one refresh token;                                                  *)
(*   - refresh-token rotation: RefreshRotate redeems a still-valid refresh   *)
(*     token for a fresh access+refresh pair and immediately invalidates     *)
(*     the redeemed one (single-use rotation, never reusable);              *)
(*   - consent as its own small state machine: "none" -> "granted" ->       *)
(*     "revoked", terminal once revoked (no re-grant modelled: a revoked     *)
(*     consent is a hard stop, matching the OIDC "revoke access" UX);        *)
(*   - introspection as a LIVE, dynamically-gated read: IntrospectValid     *)
(*     never trusts a token's stored valid bit alone -- it re-checks the     *)
(*     owning user's current status and the current consent state at the    *)
(*     moment of introspection, every time, so a user disabled or a         *)
(*     consent revoked AFTER a token was minted is caught immediately        *)
(*     without needing a synchronous fan-out to invalidate every            *)
(*     outstanding token record.                                           *)
(*                                                                         *)
(* Implicit and Resource-Owner-Password-Credentials grants are refused      *)
(* entirely by omission: no action in Next models them, so TLC's Next        *)
(* enumerates only the authorization-code+PKCE and refresh-rotation paths.   *)
(* The client-credentials grant is a separate, machine-to-machine authority  *)
(* seam with no user/consent dimension at all; it is out of scope here and   *)
(* is proved by its own spec.                                              *)
(*                                                                         *)
(* Proven by TLC (see OidcProvider.cfg):                                    *)
(*                                                                         *)
(*   NoTokenWithoutConsumedCode -- every issued access or refresh token,     *)
(*     however far down a refresh-rotation chain, traces its origin (via a   *)
(*     ghost provenance field propagated through every rotation) to a code   *)
(*     that was actually consumed. No token is ever minted from thin air.    *)
(*                                                                         *)
(*   RevokedConsentNeverIntrospectsValid -- once a (user, client) consent    *)
(*     pair is revoked, IntrospectValid is FALSE for every token minted       *)
(*     under that pair, in every reachable state thereafter -- regardless    *)
(*     of the token's own stored valid bit, because introspection re-reads   *)
(*     consent live rather than trusting a point-in-time snapshot.           *)
(*                                                                         *)
(*   DisabledUserNeverIntrospectsValid -- once a user is disabled,           *)
(*     IntrospectValid is FALSE for every token they own, in every           *)
(*     reachable state thereafter, for the same live-read reason.           *)
(*                                                                         *)
(*   RefreshRotationSingleUse -- no refresh token is ever redeemed by        *)
(*     RefreshRotate more than once: a ghost per-token rotation counter      *)
(*     never exceeds 1 in any reachable state, so the "single-use rotation"  *)
(*     property holds structurally, not merely by the action's own guard.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Users,          \* candidate user handles
    Clients,        \* candidate OIDC client ids
    CodeIds,        \* candidate authorization-code identifiers
    AccessIds,      \* candidate access-token identifiers
    RefreshIds,     \* candidate refresh-token identifiers
    PKCEVerifiers,  \* candidate PKCE code_verifier / code_challenge values
    None            \* sentinel: "not issued" / "no such user or client"

ASSUME UsersNonEmpty     == Users # {}
ASSUME ClientsNonEmpty   == Clients # {}
ASSUME CodeIdsNonEmpty   == CodeIds # {}
ASSUME AccessIdsNonEmpty == AccessIds # {}
ASSUME RefreshIdsNonEmpty == RefreshIds # {}
ASSUME NoneNotUser    == None \notin Users
ASSUME NoneNotClient  == None \notin Clients
ASSUME NoneNotCode    == None \notin CodeIds
ASSUME NoneNotPKCE    == None \notin PKCEVerifiers

Status == {"active", "disabled"}         \* UserLifecycle's status model, narrowed to
                                          \* the two states this seam cares about
ConsentState == {"none", "granted", "revoked"}

VARIABLES
    userStatus,       \* [Users -> Status]
    consent,          \* [Users \X Clients -> ConsentState]

    codeUser,         \* [CodeIds -> Users \cup {None}]     ; None = not issued
    codeClient,       \* [CodeIds -> Clients \cup {None}]
    codeVerifier,     \* [CodeIds -> PKCEVerifiers \cup {None}] ; the bound challenge
    codeConsumed,     \* [CodeIds -> BOOLEAN]

    accessOwner,      \* [AccessIds -> Users \cup {None}]   ; None = not issued
    accessClient,      \* [AccessIds -> Clients \cup {None}]
    accessValid,       \* [AccessIds -> BOOLEAN]
    accessOrigin,      \* [AccessIds -> CodeIds \cup {None}] ; provenance, propagated
                        \*   through every refresh rotation back to the original code

    refreshOwner,      \* [RefreshIds -> Users \cup {None}]
    refreshClient,      \* [RefreshIds -> Clients \cup {None}]
    refreshValid,       \* [RefreshIds -> BOOLEAN]
    refreshOrigin,      \* [RefreshIds -> CodeIds \cup {None}]
    refreshRotatedCount \* [RefreshIds -> Nat] ; ghost: how many times this id was
                        \*   ever redeemed by RefreshRotate (must never exceed 1)

vars == <<userStatus, consent,
          codeUser, codeClient, codeVerifier, codeConsumed,
          accessOwner, accessClient, accessValid, accessOrigin,
          refreshOwner, refreshClient, refreshValid, refreshOrigin,
          refreshRotatedCount>>

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS *)

TypeOK ==
    /\ userStatus \in [Users -> Status]
    /\ consent \in [Users \X Clients -> ConsentState]
    /\ codeUser     \in [CodeIds -> Users \cup {None}]
    /\ codeClient   \in [CodeIds -> Clients \cup {None}]
    /\ codeVerifier \in [CodeIds -> PKCEVerifiers \cup {None}]
    /\ codeConsumed \in [CodeIds -> BOOLEAN]
    /\ accessOwner  \in [AccessIds -> Users \cup {None}]
    /\ accessClient \in [AccessIds -> Clients \cup {None}]
    /\ accessValid  \in [AccessIds -> BOOLEAN]
    /\ accessOrigin \in [AccessIds -> CodeIds \cup {None}]
    /\ refreshOwner  \in [RefreshIds -> Users \cup {None}]
    /\ refreshClient \in [RefreshIds -> Clients \cup {None}]
    /\ refreshValid  \in [RefreshIds -> BOOLEAN]
    /\ refreshOrigin \in [RefreshIds -> CodeIds \cup {None}]
    /\ refreshRotatedCount \in [RefreshIds -> Nat]

-----------------------------------------------------------------------------
(* INITIAL STATE *)

Init ==
    /\ userStatus = [u \in Users |-> "active"]
    /\ consent    = [p \in (Users \X Clients) |-> "none"]
    /\ codeUser     = [c \in CodeIds |-> None]
    /\ codeClient   = [c \in CodeIds |-> None]
    /\ codeVerifier = [c \in CodeIds |-> None]
    /\ codeConsumed = [c \in CodeIds |-> FALSE]
    /\ accessOwner  = [a \in AccessIds |-> None]
    /\ accessClient = [a \in AccessIds |-> None]
    /\ accessValid  = [a \in AccessIds |-> FALSE]
    /\ accessOrigin = [a \in AccessIds |-> None]
    /\ refreshOwner  = [r \in RefreshIds |-> None]
    /\ refreshClient = [r \in RefreshIds |-> None]
    /\ refreshValid  = [r \in RefreshIds |-> FALSE]
    /\ refreshOrigin = [r \in RefreshIds |-> None]
    /\ refreshRotatedCount = [r \in RefreshIds |-> 0]

-----------------------------------------------------------------------------
(* USER LIFECYCLE (borrowed from UserLifecycle: the minimum needed here) *)

Disable(u) ==
    /\ userStatus[u] = "active"
    /\ userStatus' = [userStatus EXCEPT ![u] = "disabled"]
    /\ UNCHANGED <<consent, codeUser, codeClient, codeVerifier, codeConsumed,
                   accessOwner, accessClient, accessValid, accessOrigin,
                   refreshOwner, refreshClient, refreshValid, refreshOrigin,
                   refreshRotatedCount>>

Enable(u) ==
    /\ userStatus[u] = "disabled"
    /\ userStatus' = [userStatus EXCEPT ![u] = "active"]
    /\ UNCHANGED <<consent, codeUser, codeClient, codeVerifier, codeConsumed,
                   accessOwner, accessClient, accessValid, accessOrigin,
                   refreshOwner, refreshClient, refreshValid, refreshOrigin,
                   refreshRotatedCount>>

-----------------------------------------------------------------------------
(* CONSENT STATE MACHINE: none -> granted -> revoked (terminal) *)

Consent(u, c) ==
    /\ consent[<<u, c>>] = "none"
    /\ consent' = [consent EXCEPT ![<<u, c>>] = "granted"]
    /\ UNCHANGED <<userStatus, codeUser, codeClient, codeVerifier, codeConsumed,
                   accessOwner, accessClient, accessValid, accessOrigin,
                   refreshOwner, refreshClient, refreshValid, refreshOrigin,
                   refreshRotatedCount>>

RevokeConsent(u, c) ==
    /\ consent[<<u, c>>] = "granted"
    /\ consent' = [consent EXCEPT ![<<u, c>>] = "revoked"]
    /\ UNCHANGED <<userStatus, codeUser, codeClient, codeVerifier, codeConsumed,
                   accessOwner, accessClient, accessValid, accessOrigin,
                   refreshOwner, refreshClient, refreshValid, refreshOrigin,
                   refreshRotatedCount>>

-----------------------------------------------------------------------------
(* AUTHORIZATION-CODE + PKCE GRANT *)

\* The authorization endpoint issues a code only for an active user who has
\* already granted consent to the client, binding a PKCE challenge to it.
IssueCode(codeId, u, c, pkce) ==
    /\ codeUser[codeId] = None
    /\ userStatus[u] = "active"
    /\ consent[<<u, c>>] = "granted"
    /\ codeUser'     = [codeUser     EXCEPT ![codeId] = u]
    /\ codeClient'   = [codeClient   EXCEPT ![codeId] = c]
    /\ codeVerifier' = [codeVerifier EXCEPT ![codeId] = pkce]
    /\ UNCHANGED <<userStatus, consent, codeConsumed,
                   accessOwner, accessClient, accessValid, accessOrigin,
                   refreshOwner, refreshClient, refreshValid, refreshOrigin,
                   refreshRotatedCount>>

\* The token endpoint redeems an unconsumed code exactly once, and only when
\* the presented verifier matches the bound challenge (PKCE). Mints exactly
\* one access token and one refresh token, both tagged with this code as
\* their provenance.
ConsumeCode(codeId, presentedVerifier, accessId, refreshId) ==
    /\ codeUser[codeId] # None
    /\ ~codeConsumed[codeId]
    /\ presentedVerifier = codeVerifier[codeId]
    /\ accessOwner[accessId] = None
    /\ refreshOwner[refreshId] = None
    /\ codeConsumed' = [codeConsumed EXCEPT ![codeId] = TRUE]
    /\ accessOwner'  = [accessOwner  EXCEPT ![accessId] = codeUser[codeId]]
    /\ accessClient' = [accessClient EXCEPT ![accessId] = codeClient[codeId]]
    /\ accessValid'  = [accessValid  EXCEPT ![accessId] = TRUE]
    /\ accessOrigin' = [accessOrigin EXCEPT ![accessId] = codeId]
    /\ refreshOwner'  = [refreshOwner  EXCEPT ![refreshId] = codeUser[codeId]]
    /\ refreshClient' = [refreshClient EXCEPT ![refreshId] = codeClient[codeId]]
    /\ refreshValid'  = [refreshValid  EXCEPT ![refreshId] = TRUE]
    /\ refreshOrigin' = [refreshOrigin EXCEPT ![refreshId] = codeId]
    /\ UNCHANGED <<userStatus, consent, codeUser, codeClient, codeVerifier,
                   refreshRotatedCount>>

-----------------------------------------------------------------------------
(* REFRESH-TOKEN ROTATION: single-use *)

\* Redeems a still-valid refresh token for a fresh access+refresh pair,
\* immediately invalidating the redeemed one (rotation is single-use: the
\* guard `refreshValid[oldRefreshId]` can never be TRUE again for this id
\* once it fires, and refreshRotatedCount records that fact for TLC to
\* check as a state invariant rather than trusting the guard alone).
RefreshRotate(oldRefreshId, newAccessId, newRefreshId) ==
    /\ refreshOwner[oldRefreshId] # None
    /\ refreshValid[oldRefreshId]
    /\ accessOwner[newAccessId] = None
    /\ refreshOwner[newRefreshId] = None
    /\ oldRefreshId # newRefreshId
    /\ refreshValid' = [refreshValid EXCEPT ![oldRefreshId] = FALSE,
                                             ![newRefreshId] = TRUE]
    /\ refreshRotatedCount' = [refreshRotatedCount EXCEPT ![oldRefreshId] = @ + 1]
    /\ accessOwner'  = [accessOwner  EXCEPT ![newAccessId] = refreshOwner[oldRefreshId]]
    /\ accessClient' = [accessClient EXCEPT ![newAccessId] = refreshClient[oldRefreshId]]
    /\ accessValid'  = [accessValid  EXCEPT ![newAccessId] = TRUE]
    /\ accessOrigin' = [accessOrigin EXCEPT ![newAccessId] = refreshOrigin[oldRefreshId]]
    /\ refreshOwner'  = [refreshOwner  EXCEPT ![newRefreshId] = refreshOwner[oldRefreshId]]
    /\ refreshClient' = [refreshClient EXCEPT ![newRefreshId] = refreshClient[oldRefreshId]]
    /\ refreshOrigin' = [refreshOrigin EXCEPT ![newRefreshId] = refreshOrigin[oldRefreshId]]
    /\ UNCHANGED <<userStatus, consent, codeUser, codeClient, codeVerifier, codeConsumed>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION -- implicit and password grants are refused by       *)
(* omission: no action here models them. Client-credentials is a separate    *)
(* seam, proved by its own spec, and has no place in this Next either.       *)

Next ==
    \/ \E u \in Users : Disable(u)
    \/ \E u \in Users : Enable(u)
    \/ \E u \in Users, c \in Clients : Consent(u, c)
    \/ \E u \in Users, c \in Clients : RevokeConsent(u, c)
    \/ \E codeId \in CodeIds, u \in Users, c \in Clients, pkce \in PKCEVerifiers :
          IssueCode(codeId, u, c, pkce)
    \/ \E codeId \in CodeIds, pkce \in PKCEVerifiers,
          accessId \in AccessIds, refreshId \in RefreshIds :
          ConsumeCode(codeId, pkce, accessId, refreshId)
    \/ \E oldR \in RefreshIds, newA \in AccessIds, newR \in RefreshIds :
          RefreshRotate(oldR, newA, newR)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* LIVE, DYNAMICALLY-GATED INTROSPECTION *)

\* Never trusts a token's stored valid bit alone: re-reads the owning user's
\* CURRENT status and the CURRENT consent state at the moment of
\* introspection, so a disable or a consent revocation that happened after
\* the token was minted is caught immediately.
AccessIntrospectValid(id) ==
    /\ accessOwner[id] # None
    /\ accessValid[id]
    /\ userStatus[accessOwner[id]] = "active"
    /\ consent[<<accessOwner[id], accessClient[id]>>] # "revoked"

RefreshIntrospectValid(id) ==
    /\ refreshOwner[id] # None
    /\ refreshValid[id]
    /\ userStatus[refreshOwner[id]] = "active"
    /\ consent[<<refreshOwner[id], refreshClient[id]>>] # "revoked"

-----------------------------------------------------------------------------
(* INVARIANTS *)

\* Every issued access or refresh token, however far down a rotation chain,
\* traces its provenance back to a code that was actually consumed.
NoTokenWithoutConsumedCode ==
    /\ \A id \in AccessIds :
        accessOwner[id] # None =>
            /\ accessOrigin[id] # None
            /\ codeConsumed[accessOrigin[id]]
    /\ \A id \in RefreshIds :
        refreshOwner[id] # None =>
            /\ refreshOrigin[id] # None
            /\ codeConsumed[refreshOrigin[id]]

\* Once a (user, client) consent is revoked, no token minted under that pair
\* ever introspects valid again, in any reachable state.
RevokedConsentNeverIntrospectsValid ==
    /\ \A id \in AccessIds :
        (accessOwner[id] # None /\ consent[<<accessOwner[id], accessClient[id]>>] = "revoked")
            => ~AccessIntrospectValid(id)
    /\ \A id \in RefreshIds :
        (refreshOwner[id] # None /\ consent[<<refreshOwner[id], refreshClient[id]>>] = "revoked")
            => ~RefreshIntrospectValid(id)

\* Once a user is disabled, none of their tokens ever introspect valid again.
DisabledUserNeverIntrospectsValid ==
    /\ \A id \in AccessIds :
        (accessOwner[id] # None /\ userStatus[accessOwner[id]] = "disabled")
            => ~AccessIntrospectValid(id)
    /\ \A id \in RefreshIds :
        (refreshOwner[id] # None /\ userStatus[refreshOwner[id]] = "disabled")
            => ~RefreshIntrospectValid(id)

\* No refresh token is ever redeemed by RefreshRotate more than once.
RefreshRotationSingleUse ==
    \A id \in RefreshIds : refreshRotatedCount[id] <= 1

=============================================================================
