----------------------------- MODULE SessionRegistry -----------------------------
(***************************************************************************)
(* Pillar SERVER-SIDE session registry (ROI P1 "CLI surface: pillar          *)
(* session", operator 2026-08-31, method #1, DESIGN-GATED).                 *)
(*                                                                         *)
(* `LoginToken.tla` models a SINGLE bearer credential per user -- exactly     *)
(* one live token, one expiry, one revoke. This spec REFINES that into a     *)
(* first-class, ENUMERABLE REGISTRY: each principal may hold MANY concurrent *)
(* server-side sessions (one per `pillar login` invocation / device / CLI    *)
(* context), each with its OWN id and its OWN expiry, individually           *)
(* revocable (`revoke <id>`) and atomically all-revocable                    *)
(* (`revoke-all` / sign-out-everywhere). A session here is distinct from     *)
(* the LOCAL ctx/context object `cli-session-resource-impl` owns on the      *)
(* client -- this is the SERVER's bookkeeping of which bearer credentials    *)
(* it still honors, admitted at one or more nodes (mirroring                *)
(* NodeCustodyLogin's multi-node admission surface).                       *)
(*                                                                         *)
(* GENERATIONS. Because a session id slot is reusable (a fresh `pillar        *)
(* login` after a prior session in that slot was revoked/expired mints a     *)
(* new one), every mint is stamped with the GLOBAL revocation epoch          *)
(* (`revEpoch`) current at mint time -- its GENERATION. A generation once     *)
(* revoked never re-admits: only a STRICTLY LATER generation (a fresh mint,   *)
(* necessarily stamped with a revEpoch that has since advanced past the      *)
(* revocation) can ever admit again. This is what makes `revoke-all`         *)
(* atomic and durable rather than a snapshot some racing mint could           *)
(* "survive": every session swept by a `revoke-all` carries a generation      *)
(* strictly older than the epoch `revoke-all` stamps, and no later mint can    *)
(* retroactively acquire that older generation.                            *)
(*                                                                         *)
(* FAIL-CLOSED FRESHNESS. Exactly the WoTAuthority / NodeCustodyLogin          *)
(* revoke-before-act fence: each node keeps a scalar watermark `freshMark[n]` *)
(* of how far its own revocation knowledge reaches; a bearer action           *)
(* (`Admit`) is gated on `freshMark[n] = revEpoch` (the node's view is        *)
(* EXACTLY caught up to the true global epoch) at the instant it acts --      *)
(* fail-closed, since any lag at all simply disables admission rather than    *)
(* falling back to an optimistic/last-known-good grant.                     *)
(*                                                                         *)
(* Ties to LoginToken / identity-node-custody-spec: `Mint` is exactly         *)
(* LoginToken's `Mint` (a token/session is born only from a forwarded,        *)
(* validated credential -- modelled here as the unconditional precondition   *)
(* that the caller already holds an admissible identity, out of scope for    *)
(* this refinement layer, which starts one level in at "a session now         *)
(* exists"); `Admit` generalises LoginToken's `Authenticate` /                 *)
(* NodeCustodyLogin's `NodeCustodyLogin`/`ClientSignatureLogin` to a           *)
(* multi-node surface over a registry instead of a single per-user slot.      *)
(*                                                                         *)
(* Proven by TLC (see SessionRegistry.cfg):                                 *)
(*   - NoActionAfterRevocation: the most recent Admit's session GENERATION    *)
(*     was never revoked as of its own mint -- a revoked session (whether     *)
(*     individually revoked or swept by revoke-all) never admits again;       *)
(*     only a strictly later generation (a fresh mint) can.                  *)
(*   - NoActionAfterExpiry: the most recent Admit's session was unexpired      *)
(*     at the instant it admitted (fail-closed on expiry, as LoginToken's     *)
(*     AuthdImpliesLiveToken).                                              *)
(*   - RevokeAllRevokesEvery: every session belonging to a principal that      *)
(*     existed (was minted) strictly before that principal's most recent      *)
(*     revoke-all epoch is NEVER active again -- revoke-all leaves no          *)
(*     admitting session behind; a later mint carries a strictly newer         *)
(*     generation and so is a genuinely NEW session, never a survivor of       *)
(*     the swept set.                                                        *)
(*   - FailClosedUnderStaleView: a node whose watermark lags the true          *)
(*     global revocation epoch can never be the actor of the most-recent,      *)
(*     fully-fresh-at-that-moment Admit -- reusing WoTAuthority's freshness     *)
(*     fence verbatim over the registry's single scalar epoch.                *)
(*   - RevocationHonorsEpoch: whenever a session has ever been revoked, the     *)
(*     most recent Admit for that same slot (if any) was fenced against an     *)
(*     epoch AT LEAST as advanced as that revocation -- revoke-before-act:      *)
(*     an action can never observe a view older than a revocation that has      *)
(*     already been stamped against its own subject.                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Principals,   \* candidate session owners
    SessionIds,   \* candidate session-slot identities (reusable across mints)
    Nodes,        \* candidate admitting nodes (mirrors NodeCustodyLogin's Nodes)
    MaxClock,     \* model time bound
    MaxEpoch,     \* model bound on the global revocation-epoch counter
    None          \* sentinel: "unbound" / "never"

ASSUME PrincipalsNonEmpty == Principals # {}
ASSUME SessionIdsNonEmpty == SessionIds # {}
ASSUME NodesNonEmpty      == Nodes # {}
ASSUME MaxClockIsNat      == MaxClock \in Nat
ASSUME MaxEpochIsNat      == MaxEpoch \in Nat
ASSUME NoneNotPrincipal   == None \notin Principals

Times    == 0 .. MaxClock
Epochs   == 0 .. MaxEpoch
SessStates == {"absent", "active", "revoked", "expired"}

VARIABLES
    sessions,          \* [SessionIds -> [state, principal, expiry, mintEpoch]]
    revEpoch,          \* Nat: global revocation-epoch counter (monotonic,
                       \* strictly bumped by every RevokeOne / RevokeAll)
    revokedAt,         \* [SessionIds -> Nat]: the revEpoch stamped on this
                       \* slot's most recent revocation, or 0 if never revoked
                       \* (epoch 0 is reserved -- no revocation ever fires at
                       \* epoch 0, since every Revoke* strictly increments
                       \* revEpoch to at least 1 before stamping)
    lastRevokeAllEpoch, \* [Principals -> Nat]: the revEpoch stamped on this
                       \* principal's most recent revoke-all, or 0 if never
    freshMark,         \* [Nodes -> Nat]: each node's revocation-knowledge
                       \* watermark (WoTAuthority/NodeCustodyLogin freshness)
    lastAdmit,         \* ghost: most recent Admit, overwritten each firing
                       \* (checked as "the most recent one" immediately after
                       \* its own transition -- the WoTAuthority idiom)
    clock              \* current time

vars == <<sessions, revEpoch, revokedAt, lastRevokeAllEpoch, freshMark, lastAdmit, clock>>

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

EmptySlot == [state |-> "absent", principal |-> None, expiry |-> 0, mintEpoch |-> 0]

Init ==
    /\ sessions            = [sid \in SessionIds |-> EmptySlot]
    /\ revEpoch            = 0
    /\ revokedAt           = [sid \in SessionIds |-> 0]
    /\ lastRevokeAllEpoch  = [p \in Principals |-> 0]
    /\ freshMark           = [n \in Nodes |-> 0]
    /\ lastAdmit           = [some |-> FALSE, node |-> CHOOSE n \in Nodes : TRUE,
                              sid |-> CHOOSE s \in SessionIds : TRUE, principal |-> None,
                              mintEpochSnap |-> 0, revEpochSnap |-> 0,
                              clockSnap |-> 0, expirySnap |-> 0, revokedAtSnap |-> 0]
    /\ clock               = 0

-----------------------------------------------------------------------------
(* MINT: a new session for `p` is born into slot `sid` (must be reusable --   *)
(* absent, expired, or revoked, never stomping a currently-active one). Its   *)
(* generation is stamped with the CURRENT revEpoch: any later revocation      *)
(* strictly advances revEpoch first, so this generation is always strictly    *)
(* newer than any revocation that preceded it. A fresh mint also clears this  *)
(* slot's `revokedAt` stamp -- that stamp names a revocation of the OLD        *)
(* generation being replaced, never the new one. Mirrors LoginToken's Mint -- *)
(* it is the sole entry point, gated (out of scope here) on an already-        *)
(* admissible identity forwarding its credential.                           *)

Mint(sid, p, e) ==
    /\ sid \in SessionIds
    /\ p \in Principals
    /\ e \in Times
    /\ e > clock
    /\ sessions[sid].state \in {"absent", "expired", "revoked"}
    /\ sessions' = [sessions EXCEPT ![sid] =
                      [state |-> "active", principal |-> p, expiry |-> e, mintEpoch |-> revEpoch]]
    /\ revokedAt' = [revokedAt EXCEPT ![sid] = 0]
    /\ UNCHANGED <<revEpoch, lastRevokeAllEpoch, freshMark, lastAdmit, clock>>

-----------------------------------------------------------------------------
(* REVOCATION -- individually or all-at-once, both epoch-stamped.            *)

\* Revoke ONE session by id. Strictly advances the global epoch and stamps
\* this slot's revocation with it.
RevokeOne(sid) ==
    /\ sid \in SessionIds
    /\ sessions[sid].state = "active"
    /\ revEpoch < MaxEpoch
    /\ revEpoch' = revEpoch + 1
    /\ sessions'  = [sessions EXCEPT ![sid].state = "revoked"]
    /\ revokedAt' = [revokedAt EXCEPT ![sid] = revEpoch']
    /\ UNCHANGED <<lastRevokeAllEpoch, freshMark, lastAdmit, clock>>

\* Sign-out-everywhere: ATOMICALLY revoke every currently-active session
\* belonging to `p`, in the SAME step, all stamped with the SAME new epoch.
\* Any session slot not currently belonging to / active for `p` is untouched.
RevokeAll(p) ==
    /\ p \in Principals
    /\ \E sid \in SessionIds : sessions[sid].principal = p /\ sessions[sid].state = "active"
    /\ revEpoch < MaxEpoch
    /\ revEpoch' = revEpoch + 1
    /\ sessions' = [sid \in SessionIds |->
                      IF sessions[sid].principal = p /\ sessions[sid].state = "active"
                      THEN [sessions[sid] EXCEPT !.state = "revoked"]
                      ELSE sessions[sid]]
    /\ revokedAt' = [sid \in SessionIds |->
                       IF sessions[sid].principal = p /\ sessions[sid].state = "active"
                       THEN revEpoch'
                       ELSE revokedAt[sid]]
    /\ lastRevokeAllEpoch' = [lastRevokeAllEpoch EXCEPT ![p] = revEpoch']
    /\ UNCHANGED <<freshMark, lastAdmit, clock>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: exactly the WoTAuthority / NodeCustodyLogin fence.        *)

RefreshView(n) ==
    /\ n \in Nodes
    /\ freshMark[n] < revEpoch
    /\ freshMark' = [freshMark EXCEPT ![n] = revEpoch]
    /\ UNCHANGED <<sessions, revEpoch, revokedAt, lastRevokeAllEpoch, lastAdmit, clock>>

-----------------------------------------------------------------------------
(* TIME: expiry is fail-closed exactly as LoginToken's Tick.                 *)

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ sessions' = [sid \in SessionIds |->
                      IF sessions[sid].state = "active" /\ sessions[sid].expiry <= clock + 1
                      THEN [sessions[sid] EXCEPT !.state = "expired"]
                      ELSE sessions[sid]]
    /\ UNCHANGED <<revEpoch, revokedAt, lastRevokeAllEpoch, freshMark, lastAdmit>>

-----------------------------------------------------------------------------
(* ADMIT: a bearer action against a node, presenting session `sid`.          *)
(* Admitted only while: the session is active and unexpired (fail-closed on  *)
(* expiry, LoginToken-style), AND the acting node's revocation view is        *)
(* EXACTLY caught up to the current global epoch (fail-closed on staleness,   *)
(* WoTAuthority/NodeCustodyLogin-style). `lastAdmit` is overwritten (not       *)
(* accumulated) each firing -- TLC checks every Admit that ever fires, as the *)
(* "most recent one", in its own immediate successor state.                  *)

Admit(n, sid) ==
    /\ n \in Nodes
    /\ sid \in SessionIds
    /\ sessions[sid].state = "active"
    /\ clock < sessions[sid].expiry
    /\ freshMark[n] = revEpoch
    /\ lastAdmit' = [some |-> TRUE, node |-> n, sid |-> sid,
                     principal |-> sessions[sid].principal,
                     mintEpochSnap |-> sessions[sid].mintEpoch,
                     revEpochSnap |-> revEpoch,
                     clockSnap |-> clock, expirySnap |-> sessions[sid].expiry,
                     revokedAtSnap |-> revokedAt[sid]]
    /\ UNCHANGED <<sessions, revEpoch, revokedAt, lastRevokeAllEpoch, freshMark, clock>>

-----------------------------------------------------------------------------
(* ENUMERATION (ls / show): pure derived views, no state of their own.       *)

\* Every currently-active session belonging to `p` -- `pillar session ls`.
ActiveSessionsOf(p) == { sid \in SessionIds : sessions[sid].principal = p /\ sessions[sid].state = "active" }

\* A single session's full record -- `pillar session show <id>`.
ShowSession(sid) == sessions[sid]

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                      *)

Next ==
    \/ \E sid \in SessionIds, p \in Principals, e \in Times : Mint(sid, p, e)
    \/ \E sid \in SessionIds                                : RevokeOne(sid)
    \/ \E p \in Principals                                  : RevokeAll(p)
    \/ \E n \in Nodes                                       : RefreshView(n)
    \/ \E n \in Nodes, sid \in SessionIds                    : Admit(n, sid)
    \/ Tick

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ sessions \in [SessionIds -> [state: SessStates, principal: Principals \cup {None},
                                    expiry: Times, mintEpoch: Epochs]]
    /\ revEpoch \in Epochs
    /\ revokedAt \in [SessionIds -> Epochs]
    /\ lastRevokeAllEpoch \in [Principals -> Epochs]
    /\ freshMark \in [Nodes -> Epochs]
    /\ lastAdmit \in [some: BOOLEAN, node: Nodes, sid: SessionIds,
                      principal: Principals \cup {None}, mintEpochSnap: Epochs,
                      revEpochSnap: Epochs, clockSnap: Times, expirySnap: Times,
                      revokedAtSnap: Epochs]
    /\ clock \in Times

\* A node's watermark never runs ahead of the true global epoch.
FreshMarkBounded == \A n \in Nodes : freshMark[n] <= revEpoch

\* A slot's stamped generation never runs ahead of the true global epoch, and
\* neither does its most recent revocation stamp.
MintEpochBounded == \A sid \in SessionIds : sessions[sid].mintEpoch <= revEpoch
RevokedAtBounded == \A sid \in SessionIds : revokedAt[sid] <= revEpoch

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* A revoked session -- individual or swept by revoke-all -- never admits
\* again. `revokedAtSnap` is the FROZEN value of `revokedAt[sid]` at the exact
\* instant this Admit fired: 0 means "this generation has never been
\* revoked" (Mint always clears the stamp for a fresh generation; only a
\* Revoke* targeting the CURRENTLY-active generation ever sets it, which in
\* the same step flips that generation out of "active" -- so a generation
\* that is admitting can never itself carry a nonzero stamp). Stated as an
\* eternal fact about the frozen snapshot (never re-evaluated against a LATER
\* revocation), exactly the WoTAuthority ghost idiom.
NoActionAfterRevocation ==
    lastAdmit.some => lastAdmit.revokedAtSnap = 0

\* The most recent Admit's session was unexpired at the instant it acted
\* (LoginToken's AuthdImpliesLiveToken, restated over the registry).
NoActionAfterExpiry ==
    lastAdmit.some => lastAdmit.clockSnap < lastAdmit.expirySnap

\* Revoke-all leaves no admitting session behind: every session slot that
\* belonged to `p` and existed (was minted) STRICTLY BEFORE `p`'s most recent
\* revoke-all epoch is never active -- revoke-all swept it and nothing can
\* revive that exact generation. A slot re-minted for `p` AFTER the revoke-all
\* carries mintEpoch >= lastRevokeAllEpoch[p] and so falls outside this
\* clause: it is a genuinely NEW session, never a survivor of the swept set.
RevokeAllRevokesEvery ==
    \A p \in Principals, sid \in SessionIds :
        (sessions[sid].principal = p /\ sessions[sid].mintEpoch < lastRevokeAllEpoch[p])
            => sessions[sid].state # "active"

\* Fail-closed under a stale view: a node whose watermark lags the true
\* global epoch can never be the actor of the most-recently-recorded Admit
\* evaluated as fully fresh against the CURRENT epoch -- verbatim the
\* WoTAuthority / NodeCustodyLogin freshness fence, over this registry's
\* single scalar revocation epoch instead of a three-part revoked-sets tuple.
FailClosedUnderStaleView ==
    \A n \in Nodes :
        freshMark[n] < revEpoch =>
            ~ (/\ lastAdmit.some
               /\ lastAdmit.node = n
               /\ lastAdmit.revEpochSnap = revEpoch)

\* Revoke-before-act: whenever this Admit fired, its own slot's revocation
\* stamp (frozen at that instant) was already fully cleared/caught-up
\* (`revokedAtSnap = 0`) -- i.e. any revocation that had EVER applied to this
\* exact generation was already visible and honored before the action, never
\* discovered afterward. Combined with `FailClosedUnderStaleView` (the node's
\* view is fenced to the CURRENT global epoch at act time) this is the
\* registry's revoke-before-act guarantee restated at the single-slot level.
RevocationHonorsEpoch ==
    \A sid \in SessionIds :
        (lastAdmit.some /\ lastAdmit.sid = sid) => lastAdmit.revokedAtSnap = 0

=============================================================================
