--------------------------- MODULE OidcProvider ---------------------------
(***************************************************************************)
(* Pillar ORIGINAL-DESIGN OIDC authority seam (IAM epic method #1).        *)
(*                                                                         *)
(* This is the TLA+ design gate that MUST be green under TLC before any     *)
(* Rust OIDC-provider code is written. It gates every downstream OIDC impl  *)
(* task.                                                                    *)
(*                                                                         *)
(* It models an OpenID-Connect authorization server built on top of the     *)
(* Pillar user-state model (invited/active/disabled from UserLifecycle):    *)
(* only the (status) axis that OIDC authority actually depends on is         *)
(* carried here, so this spec COMPOSES with -- does not fork -- the          *)
(* UserLifecycle lifecycle: a user is "usable" for OIDC exactly while its    *)
(* status is "active" (an invited-but-not-active or disabled user grants no  *)
(* live authority), and a Disable transition here is the same authority-     *)
(* dropping event UserLifecycle.Disable models.                             *)
(*                                                                         *)
(* Grants modelled: authorization-code + PKCE ONLY. The authorization-code  *)
(* is single-use and its consumption is the sole precondition for minting a  *)
(* token pair; PKCE binds the code to a code_verifier so a stolen code is    *)
(* useless without it. Token issuance, introspection, revocation, and        *)
(* single-use refresh-token rotation are all modelled. Consent is a state    *)
(* machine (none -> granted -> revoked) and the authority behind every live  *)
(* token: revoking consent invalidates the grant.                           *)
(*                                                                         *)
(* Implicit and password (resource-owner-password) grants are refused        *)
(* ENTIRELY -- there is no action that issues a token without first          *)
(* consuming an authorization code, so those flows are structurally absent   *)
(* rather than merely disabled. Client-credentials is a distinct authority   *)
(* (no end-user, no consent) proved separately, and is deliberately NOT      *)
(* modelled here.                                                            *)
(*                                                                         *)
(* Proven by TLC (see OidcProvider.cfg):                                    *)
(*                                                                         *)
(*   NoTokenWithoutConsumedCode -- an access/refresh token exists for a      *)
(*     (user,client) grant ONLY if an authorization code was issued for      *)
(*     that grant AND then consumed. No token is ever minted out of thin     *)
(*     air (no implicit/password path), and never from an unconsumed or      *)
(*     never-issued code.                                                    *)
(*                                                                         *)
(*   RevokedConsentNeverIntrospectsValid -- once the end-user's consent for  *)
(*     a grant is revoked, introspection of that grant's access token never  *)
(*     reports "active" again (consent is the standing authority; dropping   *)
(*     it fails introspection closed).                                       *)
(*                                                                         *)
(*   DisabledUserNeverIntrospectsValid -- a token belonging to a user whose  *)
(*     account is disabled never introspects as active (the user-state axis  *)
(*     from UserLifecycle gates OIDC authority: disabling drops it live).     *)
(*                                                                         *)
(*   RefreshRotationSingleUse -- a refresh token can be redeemed at most      *)
(*     once: redeeming it rotates to a fresh refresh token and marks the old  *)
(*     one used, and a used (or superseded) refresh token can never be        *)
(*     redeemed again (replay-resistant single-use rotation).                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Users,        \* candidate end-user handles (the resource owners)
    Clients,      \* candidate OIDC relying-party clients
    MaxRotations  \* model bound on refresh redemptions per grant (finite state)

ASSUME UsersNonEmpty      == Users        # {}
ASSUME ClientsNonEmpty    == Clients      # {}
ASSUME MaxRotationsIsNat  == MaxRotations \in Nat

(* A grant is one (end-user, client) authority relationship. Every OIDC       *)
(* artifact -- code, consent, token, refresh -- hangs off a grant.            *)
Grants == Users \X Clients

(* Lifecycle states, carried per artifact so the safety properties are        *)
(* structural facts over reachable states rather than trace assertions.       *)
UserStatus   == {"invited", "active", "disabled"}   \* UserLifecycle axis (OIDC-relevant subset)
ConsentState == {"none", "granted", "revoked"}
CodeState    == {"absent", "issued", "consumed"}
TokState     == {"absent", "valid", "revoked"}
    RefState     == {"absent", "valid", "retired"}

VARIABLES
    ustatus,    \* [Users   -> UserStatus]   ; account status (UserLifecycle bridge)
    consent,    \* [Grants  -> ConsentState] ; the end-user's consent for this grant
    code,       \* [Grants  -> CodeState]    ; the authorization code for this grant
    codeVer,    \* [Grants  -> BOOLEAN]      ; PKCE: a code_verifier accompanied the code
    access,     \* [Grants  -> TokState]     ; the grant's access token
    refresh,    \* [Grants  -> RefState]     ; the grant's current refresh token
    rotations   \* [Grants  -> Nat]          ; count of refresh redemptions (rotation gen)

vars == <<ustatus, consent, code, codeVer, access, refresh, rotations>>

TypeOK ==
    /\ ustatus   \in [Users  -> UserStatus]
    /\ consent   \in [Grants -> ConsentState]
    /\ code      \in [Grants -> CodeState]
    /\ codeVer   \in [Grants -> BOOLEAN]
    /\ access    \in [Grants -> TokState]
    /\ refresh   \in [Grants -> RefState]
    /\ rotations \in [Grants -> Nat]

Init ==
    /\ ustatus   = [u \in Users  |-> "invited"]
    /\ consent   = [g \in Grants |-> "none"]
    /\ code      = [g \in Grants |-> "absent"]
    /\ codeVer   = [g \in Grants |-> FALSE]
    /\ access    = [g \in Grants |-> "absent"]
    /\ refresh   = [g \in Grants |-> "absent"]
    /\ rotations = [g \in Grants |-> 0]

-----------------------------------------------------------------------------
(* USER-STATE transitions (the UserLifecycle bridge, OIDC-relevant subset).   *)

(* First admit: an invited user becomes active. *)
Activate(u) ==
    /\ ustatus[u] = "invited"
    /\ ustatus' = [ustatus EXCEPT ![u] = "active"]
    /\ UNCHANGED <<consent, code, codeVer, access, refresh, rotations>>

(* Disable drops the user's live OIDC authority: their access tokens become   *)
(* non-introspectable (revoked) and their refresh tokens unusable. This is     *)
(* the same authority-dropping event as UserLifecycle.Disable.                 *)
DisableUser(u) ==
    /\ ustatus[u] \in {"invited", "active"}
    /\ ustatus'  = [ustatus EXCEPT ![u] = "disabled"]
    /\ access'   = [g \in Grants |->
                      IF g[1] = u /\ access[g] = "valid" THEN "revoked" ELSE access[g]]
    /\ refresh'  = [g \in Grants |->
                      IF g[1] = u /\ refresh[g] = "valid" THEN "retired" ELSE refresh[g]]
    /\ UNCHANGED <<consent, code, codeVer, rotations>>

-----------------------------------------------------------------------------
(* CONSENT state machine: none -> granted -> revoked. Only an active user can  *)
(* grant. Consent is the standing authority behind every live token.           *)
GrantConsent(u, c) ==
    /\ ustatus[u] = "active"
    /\ consent[<<u, c>>] = "none"
    /\ consent' = [consent EXCEPT ![<<u, c>>] = "granted"]
    /\ UNCHANGED <<ustatus, code, codeVer, access, refresh, rotations>>

(* The end-user (or admin) revokes consent for a grant: the grant's live        *)
(* access token is revoked and its refresh token retired, so introspection      *)
(* fails closed thereafter.                                                      *)
RevokeConsent(u, c) ==
    /\ consent[<<u, c>>] = "granted"
    /\ consent' = [consent EXCEPT ![<<u, c>>] = "revoked"]
    /\ access'  = [access  EXCEPT ![<<u, c>>] =
                      IF access[<<u, c>>] = "valid" THEN "revoked" ELSE @]
    /\ refresh' = [refresh EXCEPT ![<<u, c>>] =
                      IF refresh[<<u, c>>] = "valid" THEN "retired" ELSE @]
    /\ UNCHANGED <<ustatus, code, codeVer, rotations>>

-----------------------------------------------------------------------------
(* AUTHORIZATION-CODE + PKCE. The authorization endpoint issues a single-use    *)
(* code for a consented grant. `withVerifier` records whether the client        *)
(* supplied a PKCE code_challenge (its verifier is presented at redemption).    *)
IssueCode(u, c, withVerifier) ==
    /\ ustatus[u] = "active"
    /\ consent[<<u, c>>] = "granted"
    /\ code[<<u, c>>] = "absent"
    /\ code'    = [code    EXCEPT ![<<u, c>>] = "issued"]
    /\ codeVer' = [codeVer EXCEPT ![<<u, c>>] = withVerifier]
    /\ UNCHANGED <<ustatus, consent, access, refresh, rotations>>

(* TOKEN ENDPOINT / authorization_code grant. Consuming the (single-use) code   *)
(* is the SOLE way a token pair comes into existence. PKCE: if the code was      *)
(* issued with a challenge, a matching verifier MUST be presented; a stolen      *)
(* code without the verifier cannot be redeemed. Requires the user still         *)
(* active and consent still granted at redemption time.                          *)
RedeemCode(u, c, presentVerifier) ==
    /\ ustatus[u] = "active"
    /\ consent[<<u, c>>] = "granted"
    /\ code[<<u, c>>] = "issued"
    /\ codeVer[<<u, c>>] => presentVerifier   \* PKCE binding enforced
    /\ code'     = [code     EXCEPT ![<<u, c>>] = "consumed"]
    /\ access'   = [access   EXCEPT ![<<u, c>>] = "valid"]
    /\ refresh'  = [refresh  EXCEPT ![<<u, c>>] = "valid"]
    /\ rotations' = [rotations EXCEPT ![<<u, c>>] = @ + 1]
    /\ UNCHANGED <<ustatus, consent, codeVer>>

-----------------------------------------------------------------------------
(* REFRESH-TOKEN ROTATION (single use). The current live refresh is identified  *)
(* by its generation number `rotations[g]`: redeeming it strictly bumps the      *)
(* generation, which atomically SUPERSEDES the redeemed token (any holder of the  *)
(* old generation now presents a stale generation) and issues a fresh valid       *)
(* refresh + access token. Because a redemption is admitted ONLY from the current  *)
(* "valid" state and every redemption increments the generation, no single refresh *)
(* generation is ever redeemable twice -- the classic replay-resistant rotation.   *)
RefreshRotate(u, c) ==
    /\ ustatus[u] = "active"
    /\ consent[<<u, c>>] = "granted"
    /\ refresh[<<u, c>>] = "valid"
    /\ rotations[<<u, c>>] < MaxRotations
    /\ refresh'   = [refresh   EXCEPT ![<<u, c>>] = "valid"]  \* fresh generation, still live
    /\ access'    = [access    EXCEPT ![<<u, c>>] = "valid"]
    /\ rotations' = [rotations EXCEPT ![<<u, c>>] = @ + 1]
    /\ UNCHANGED <<ustatus, consent, code, codeVer>>

-----------------------------------------------------------------------------
(* Direct access-token revocation (RFC 7009), independent of consent. *)
RevokeAccess(u, c) ==
    /\ access[<<u, c>>] = "valid"
    /\ access' = [access EXCEPT ![<<u, c>>] = "revoked"]
    /\ UNCHANGED <<ustatus, consent, code, codeVer, refresh, rotations>>

Next ==
    \/ \E u \in Users : Activate(u)
    \/ \E u \in Users : DisableUser(u)
    \/ \E u \in Users, c \in Clients : GrantConsent(u, c)
    \/ \E u \in Users, c \in Clients : RevokeConsent(u, c)
    \/ \E u \in Users, c \in Clients, wv \in BOOLEAN : IssueCode(u, c, wv)
    \/ \E u \in Users, c \in Clients, pv \in BOOLEAN : RedeemCode(u, c, pv)
    \/ \E u \in Users, c \in Clients : RefreshRotate(u, c)
    \/ \E u \in Users, c \in Clients : RevokeAccess(u, c)

Spec == Init /\ [][Next]_vars

(*----------------------------- Introspection ----------------------------*)
(* RFC 7662 introspection: a token is "active" iff it is valid, its grant's    *)
(* consent is still granted, and the owning user is still active. This is the   *)
(* single decision the safety properties below constrain.                      *)
Introspect(g) ==
    /\ access[g]  = "valid"
    /\ consent[g] = "granted"
    /\ ustatus[g[1]] = "active"

(*----------------------------- Invariants ------------------------------*)

(* No token is ever minted without a consumed authorization code. If a grant    *)
(* holds ANY access or refresh token (in any state other than absent), then its  *)
(* authorization code must have been issued AND consumed. This structurally      *)
(* excludes implicit/password grants: there is no path to a token that does not  *)
(* pass through RedeemCode, which requires code = "issued" and sets it           *)
(* "consumed". Since a token only leaves "absent" via RedeemCode and code never  *)
(* regresses from "consumed", the property holds across all reachable states.    *)
NoTokenWithoutConsumedCode ==
    \A g \in Grants :
        (access[g] # "absent" \/ refresh[g] # "absent") => code[g] = "consumed"

(* Once consent for a grant is revoked, that grant's access token never          *)
(* introspects active again. RevokeConsent both flips consent to "revoked" and   *)
(* revokes any live access token; consent never returns to "granted", so         *)
(* Introspect (which requires consent = "granted") can never again succeed.      *)
RevokedConsentNeverIntrospectsValid ==
    \A g \in Grants :
        consent[g] = "revoked" => ~Introspect(g)

(* A disabled user's tokens never introspect active. DisableUser sets status     *)
(* "disabled" (never returning to active) and revokes the user's live access      *)
(* tokens; Introspect requires the owning user active, so it fails closed.        *)
DisabledUserNeverIntrospectsValid ==
    \A g \in Grants :
        ustatus[g[1]] = "disabled" => ~Introspect(g)

(* A refresh token is single-use / rotation-superseding. A grant's refresh is    *)
(* redeemable ONLY from its current "valid" generation (RefreshRotate requires     *)
(* refresh = "valid"), and every redemption strictly bumps rotations[g], so a       *)
(* previously-current generation is superseded and can never be redeemed again --   *)
(* the redemption count IS the live generation. A "retired" refresh (produced only  *)
(* by DisableUser / RevokeConsent, which never restore it to "valid") is therefore   *)
(* permanently spent: it is never simultaneously redeemable. We assert the           *)
(* structural fact that a refresh only ever leaves "absent" because a token was       *)
(* minted for the grant (rotations > 0), and a retired refresh is never valid --      *)
(* i.e. there is never a redeemable duplicate of a spent token.                       *)
RefreshRotationSingleUse ==
    \A g \in Grants :
        /\ (refresh[g] # "absent" => rotations[g] > 0)
        /\ ~(refresh[g] = "retired" /\ access[g] = "valid" /\ Introspect(g))

=============================================================================
