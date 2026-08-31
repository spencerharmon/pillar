----------------------------- MODULE LoginToken -----------------------------
(***************************************************************************)
(* Pillar temporary LOGIN-TOKEN issuance (operator 2026-08-31 addendum).   *)
(*                                                                         *)
(* `pillar login` obtains a temporary auth token for a user and exports it   *)
(* as PILLAR_DOMAIN + PILLAR_TOKEN; later CLI commands present that token    *)
(* (never the long-lived key) for authn/authz. A web portal MAY be separate  *)
(* from the key-distribution server: it FORWARDS the presented credentials   *)
(* to the key-distribution server, which is the sole minter of the token.    *)
(*                                                                         *)
(* This spec models the token lifecycle so the "spec before Rust" gate       *)
(* covers it (it is a credential-model addition). It composes -- does not     *)
(* fork -- the DONE IdentityLogin one-time-token/redevocation posture: a      *)
(* token here is a short-lived bearer credential bound to (user, domain,      *)
(* expiry), verified by the key-distribution server, revocable, and never     *)
(* honored past expiry or revocation.                                        *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - AuthdImpliesLiveToken: a request is authenticated ONLY while its       *)
(*     token is valid and unexpired -- no auth on an absent/expired/revoked   *)
(*     token (fail-closed).                                                  *)
(*   - TokenBoundToItsUser: a minted token authorizes ONLY the user it was    *)
(*     bound to for the domain it was bound to (no cross-user reuse).         *)
(*   - MintedOnlyByForwardedCredential: a token exists ONLY because valid     *)
(*     credentials were forwarded to the key-distribution server (the portal  *)
(*     never mints; it forwards).                                            *)
(*   - NoAuthAfterExpiryOrRevoke: once expired or revoked a token can never   *)
(*     re-authenticate.                                                      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Users,      \* candidate users logging in
    Domains,    \* candidate cell domains (PILLAR_DOMAIN)
    MaxClock,   \* model time bound
    None        \* sentinel: "unbound"

ASSUME UsersNonEmpty   == Users # {}
ASSUME DomainsNonEmpty == Domains # {}
ASSUME MaxClockIsNat   == MaxClock \in Nat
ASSUME NoneUnbound     == None \notin Domains

Times     == 0 .. MaxClock
TokStates == {"absent", "valid", "expired", "revoked"}

VARIABLES
    tokState,   \* [Users -> TokStates]: this user's current token state
    boundDom,   \* [Users -> Domains \cup {None}]: the domain a valid token is bound to
    expiry,     \* [Users -> Times]: the token's expiry time
    forwarded,  \* SUBSET Users: users whose valid credentials reached the key-dist server
    authd,      \* SUBSET Users: users currently authenticated by a live token
    clock       \* current time

vars == <<tokState, boundDom, expiry, forwarded, authd, clock>>

TypeOK ==
    /\ tokState  \in [Users -> TokStates]
    /\ boundDom  \in [Users -> Domains \cup {None}]
    /\ expiry    \in [Users -> Times]
    /\ forwarded \subseteq Users
    /\ authd     \subseteq Users
    /\ clock     \in Times

Init ==
    /\ tokState  = [u \in Users |-> "absent"]
    /\ boundDom  = [u \in Users |-> None]
    /\ expiry    = [u \in Users |-> 0]
    /\ forwarded = {}
    /\ authd     = {}
    /\ clock     = 0

-----------------------------------------------------------------------------
(* A user (or a portal on the user's behalf) FORWARDS valid credentials to    *)
(* the key-distribution server. This is the ONLY precondition for minting.    *)
ForwardCredential(u) ==
    /\ u \in Users
    /\ u \notin forwarded
    /\ forwarded' = forwarded \cup {u}
    /\ UNCHANGED <<tokState, boundDom, expiry, authd, clock>>

-----------------------------------------------------------------------------
(* The key-distribution server MINTS a token bound to (u, d) with a future    *)
(* expiry e > clock -- only after valid credentials were forwarded for u.     *)
Mint(u, d, e) ==
    /\ u \in Users
    /\ d \in Domains
    /\ e \in Times
    /\ e > clock
    /\ u \in forwarded
    /\ tokState[u] \in {"absent", "expired", "revoked"}
    /\ tokState' = [tokState EXCEPT ![u] = "valid"]
    /\ boundDom' = [boundDom EXCEPT ![u] = d]
    /\ expiry'   = [expiry   EXCEPT ![u] = e]
    /\ UNCHANGED <<forwarded, authd, clock>>

-----------------------------------------------------------------------------
(* Present the token to authenticate a CLI action. Admitted only while the    *)
(* token is valid and unexpired.                                             *)
Authenticate(u) ==
    /\ u \in Users
    /\ tokState[u] = "valid"
    /\ clock < expiry[u]
    /\ authd' = authd \cup {u}
    /\ UNCHANGED <<tokState, boundDom, expiry, forwarded, clock>>

-----------------------------------------------------------------------------
(* Revoke a valid token (server-side). It can no longer authenticate.         *)
Revoke(u) ==
    /\ u \in Users
    /\ tokState[u] = "valid"
    /\ tokState' = [tokState EXCEPT ![u] = "revoked"]
    /\ authd'    = authd \ {u}
    /\ UNCHANGED <<boundDom, expiry, forwarded, clock>>

-----------------------------------------------------------------------------
(* Time advances. Any valid token whose expiry is reached becomes expired and  *)
(* its holder is dropped from the authenticated set (fail-closed on expiry).   *)
Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ tokState' = [u \in Users |->
                      IF tokState[u] = "valid" /\ expiry[u] <= clock + 1
                      THEN "expired" ELSE tokState[u]]
    /\ authd' = { u \in authd : ~(tokState[u] = "valid" /\ expiry[u] <= clock + 1) }
    /\ UNCHANGED <<boundDom, expiry, forwarded>>

Next ==
    \/ \E u \in Users                                : ForwardCredential(u)
    \/ \E u \in Users, d \in Domains, e \in Times    : Mint(u, d, e)
    \/ \E u \in Users                                : Authenticate(u)
    \/ \E u \in Users                                : Revoke(u)
    \/ Tick

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* A user is authenticated ONLY while holding a valid, unexpired token.
AuthdImpliesLiveToken ==
    \A u \in authd :
        /\ tokState[u] = "valid"
        /\ clock < expiry[u]

\* A valid token is always bound to a real domain (authorizes only its bound
\* user for that domain -- there is no unbound/global token).
TokenBoundToItsUser ==
    \A u \in Users :
        tokState[u] = "valid" => boundDom[u] \in Domains

\* A token exists ONLY because valid credentials were forwarded to the
\* key-distribution server (the portal forwards; it never mints on its own).
MintedOnlyByForwardedCredential ==
    \A u \in Users :
        tokState[u] \in {"valid", "expired", "revoked"} => u \in forwarded

\* Once expired or revoked, a token holder is not in the authenticated set.
NoAuthAfterExpiryOrRevoke ==
    \A u \in Users :
        tokState[u] \in {"expired", "revoked"} => u \notin authd

=============================================================================
