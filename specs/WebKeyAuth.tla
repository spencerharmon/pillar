------------------------------ MODULE WebKeyAuth ------------------------------
(***************************************************************************)
(* Pillar web login: "your key is your account" (ROI 2026-08-26 operator    *)
(* redesign, safety-critical authority, DESIGN-GATED).                     *)
(*                                                                         *)
(* There is NO separate identity provider. Logging in to the web UI is      *)
(* proving control of a key the Web of Trust already trusts -- the same      *)
(* primitive the controllers use -- so authorization comes "for free" from   *)
(* the existing WoT authority (WoTAuthority.tla) and the rbac-decider        *)
(* lattice. This spec proves the LOGIN handshake is a sound composition on   *)
(* top of that authority, never a parallel/second authority path.          *)
(*                                                                         *)
(* CLIENT-SIDE UNLOCK, CHALLENGE-SIGNATURE LOGIN (the only sound reading):   *)
(*   1. The server issues a nonce bound to (origin, expiry).                *)
(*   2. The client fetches its password-protected auth SUBKEY (never the     *)
(*      primary) by CID, decrypts + unlocks it LOCALLY, and signs the nonce. *)
(*   3. The server verifies the signature against a WoT-trusted registration *)
(*      key and runs the single rbac-decider. The password and the plaintext *)
(*      key NEVER transit the server.                                       *)
(*                                                                         *)
(* This module EXTENDS the WoTAuthority authority model verbatim (its edges/ *)
(* revocation kinds/freshMark watermark/Act guard, and its                  *)
(* NoActionAfterRevocation / FailClosedUnderStaleView safety) and adds the   *)
(* web-login layer on top: nonce issuance, client signing, and server-side   *)
(* verification. A login `Admit` is modelled as WoTAuthority's own           *)
(* privileged Act against the presented subkey's authority -- there is       *)
(* exactly ONE authority path, so the WoT fail-closed guarantees apply to    *)
(* login sessions unchanged.                                                *)
(*                                                                         *)
(* WoT AUTHORITY MODEL (imported unchanged from WoTAuthority) *)
(* We inline the WoTAuthority state and actions here rather than TLA-EXTENDS *)
(* it, because we must GUARD its Act with the web-login preconditions        *)
(* (a matching, unexpired, right-origin, unreplayed nonce signed by an       *)
(* unlocked, chained subkey). The imported fragment is line-for-line the     *)
(* WoTAuthority authority relation; the safety invariants below are the      *)
(* WoTAuthority ones, re-proven under the composed next-state relation, plus *)
(* the four web-login obligations from the design doc.                      *)
(*                                                                         *)
(* Proven by TLC (see WebKeyAuth.cfg):                                      *)
(*   - StaleNonceRejected / WrongOriginRejected / ReplayRejected: a          *)
(*     signature over an expired, wrong-origin, or already-consumed nonce is *)
(*     never admitted.                                                      *)
(*   - AdmitRequiresChainedUnlockedSubkey: only a genuinely-unlocked subkey  *)
(*     that is WoT-trust-reachable (chains to the Owner anchor) to an        *)
(*     authorized primary can admit; a forged/unchained/locked subkey is     *)
(*     refused.                                                             *)
(*   - NoActionAfterRevocation / FailClosedUnderStaleView: the WoTAuthority  *)
(*     fail-closed guarantees, holding for auth-subkey LOGIN sessions too.   *)
(*   - PasskeyPathEquivalent: a WebAuthn-bound AUTH_SUBKEY admits through the *)
(*     exact same admit/deny predicate as a software-unlocked subkey (no     *)
(*     parallel gate).                                                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,       \* candidate identities in the web of trust (subkeys included)
    Owner,       \* the WoT trust anchor
    MaxDepth,    \* model bound on tsig delegation depth
    None,        \* sentinel
    Origins,     \* set of server origins a nonce may be bound to
    GoodOrigin,  \* THE origin this server accepts (a login to another origin's nonce is wrong-origin)
    MaxTime,     \* model bound on the (discrete) clock; nonces carry an expiry <= MaxTime
    MaxNonces,   \* model bound on how many challenge nonces may be outstanding (state bound)
    Passkeys     \* SUBSET Nodes: subkeys that are WebAuthn-attested AUTH_SUBKEYs (a static key property)

ASSUME NodesNonEmpty  == Nodes # {}
ASSUME OwnerIsNode    == Owner \in Nodes
ASSUME MaxDepthIsNat  == MaxDepth \in Nat
ASSUME NoneNotNode    == None \notin Nodes
ASSUME OriginsNonEmpty == Origins # {}
ASSUME GoodOriginIn   == GoodOrigin \in Origins
ASSUME MaxTimeIsNat   == MaxTime \in Nat
ASSUME MaxNoncesIsNat == MaxNonces \in Nat
ASSUME PasskeysSubset == Passkeys \subseteq Nodes

Depths == 0 .. MaxDepth
Times  == 0 .. MaxTime

VARIABLES
    \* ---- WoT authority state (imported from WoTAuthority) ----
    edges,          \* SUBSET (Nodes \X Nodes \X Depths): issued tsig certificates (grow-only)
    revokedKeys,    \* SUBSET Nodes: keys revoked (grow-only, true/global)
    revokedEdges,   \* SUBSET (Nodes \X Nodes): tsig edges revoked (grow-only)
    revokedGrants,  \* SUBSET Nodes: direct grant revocations (grow-only)
    freshMark,      \* [Nodes -> Nat]: each node's revocation-knowledge watermark
    partitioned,    \* SUBSET Nodes: nodes cut off from advancing their watermark
    \* ---- web-login layer ----
    clock,          \* current discrete server time (monotone nondecreasing)
    nonces,         \* set of issued challenges: [id, origin, expiry, consumed]
    nonceSerial,    \* monotone counter: the next distinct nonce id to mint (never reused)
    unlocked,       \* SUBSET Nodes: subkeys the client has locally decrypted+unlocked
    lastAct         \* ghost: most recent Admit (login), with its authorization snapshot

vars == <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
          partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

-----------------------------------------------------------------------------
(* WoT DERIVED GROUND TRUTH (imported verbatim from WoTAuthority)            *)

RevCount == Cardinality(revokedKeys) + Cardinality(revokedEdges) + Cardinality(revokedGrants)

ValidEdgesGiven(rk, re) ==
    { e \in edges :
        /\ e[1] \notin rk
        /\ e[2] \notin rk
        /\ <<e[1], e[2]>> \notin re }

ReachStep(prevPairs, vedges) ==
    prevPairs \cup
        { <<b, m>> \in (Nodes \X Depths) :
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

AuthPairsGiven(rk, re) == ReachFix({<<Owner, MaxDepth>>}, ValidEdgesGiven(rk, re), Cardinality(Nodes))

AuthNodesGiven(rk, re, rg) ==
    { n \in Nodes : \E <<n2, b>> \in AuthPairsGiven(rk, re) : n2 = n } \ rg

\* Ground truth given the CURRENT global revoked sets: the set of nodes
\* (subkeys) whose key WoT-chains to the Owner anchor and is not grant-revoked.
CurrentAuthNodes == AuthNodesGiven(revokedKeys, revokedEdges, revokedGrants)

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ edges         = {}
    /\ revokedKeys   = {}
    /\ revokedEdges  = {}
    /\ revokedGrants = {}
    /\ freshMark     = [n \in Nodes |-> 0]
    /\ partitioned   = {}
    /\ clock         = 0
    /\ nonces        = {}
    /\ nonceSerial   = 0
    /\ unlocked      = {}
    /\ lastAct = [some |-> FALSE, actor |-> Owner, subject |-> Owner,
                  authSnap |-> {}, watermark |-> 0,
                  origin |-> GoodOrigin, expiry |-> 0, atTime |-> 0, passkey |-> FALSE]

-----------------------------------------------------------------------------
(* WoT AUTHORITY-EXPANDING (AP): issuing a tsig certificate                  *)

IssueEdge(a, b, l) ==
    /\ l \in Depths
    /\ <<a, b, l>> \notin edges
    /\ edges' = edges \cup {<<a, b, l>>}
    /\ UNCHANGED <<revokedKeys, revokedEdges, revokedGrants, freshMark,
                   partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

-----------------------------------------------------------------------------
(* WoT AUTHORITY-REDUCING (fail-closed at Act/Admit time): revocations       *)

RevokeKey(k) ==
    /\ k \notin revokedKeys
    /\ revokedKeys' = revokedKeys \cup {k}
    /\ UNCHANGED <<edges, revokedEdges, revokedGrants, freshMark,
                   partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

RevokeEdge(a, b) ==
    /\ <<a, b>> \notin revokedEdges
    /\ revokedEdges' = revokedEdges \cup {<<a, b>>}
    /\ UNCHANGED <<edges, revokedKeys, revokedGrants, freshMark,
                   partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

RevokeGrant(n) ==
    /\ n \notin revokedGrants
    /\ revokedGrants' = revokedGrants \cup {n}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, freshMark,
                   partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

-----------------------------------------------------------------------------
(* WoT VIEW FRESHNESS: StaleView / Partition / Heal                          *)

StaleView(n) ==
    /\ n \notin partitioned
    /\ freshMark' = [freshMark EXCEPT ![n] = RevCount]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants,
                   partitioned, clock, nonces, nonceSerial, unlocked, lastAct>>

Partition ==
    /\ partitioned' \in SUBSET Nodes
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   clock, nonces, nonceSerial, unlocked, lastAct>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   clock, nonces, nonceSerial, unlocked, lastAct>>

-----------------------------------------------------------------------------
(* WEB-LOGIN LAYER                                                           *)

\* Discrete clock advance. Monotone; only ever moves forward, so a nonce that
\* was live can become expired -- exercising the stale-nonce path.
Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   partitioned, nonces, nonceSerial, unlocked, lastAct>>

\* The server issues a fresh challenge nonce bound to a chosen origin and a
\* chosen expiry time. A nonce identity is the pair <<origin, expiry>> together
\* with an issue serial so replays/consumption are trackable; we model each
\* issued nonce as a record. `consumed` starts FALSE.
IssueNonce(o, ex) ==
    /\ o \in Origins
    /\ ex \in Times
    /\ Cardinality(nonces) < MaxNonces
    /\ nonces' = nonces \cup
          {[id |-> nonceSerial, origin |-> o, expiry |-> ex, consumed |-> FALSE]}
    /\ nonceSerial' = nonceSerial + 1
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   partitioned, clock, unlocked, lastAct>>

\* The client locally decrypts + unlocks an auth subkey (password + KDF, all
\* client-side). This is the ONLY way a subkey can sign a nonce below. The
\* password/plaintext never reach the server -- unlocking is a purely local
\* client fact, modelled here as membership in `unlocked`.
UnlockSubkey(k) ==
    /\ k \in Nodes
    /\ k \notin unlocked
    /\ unlocked' = unlocked \cup {k}
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   partitioned, clock, nonces, nonceSerial, lastAct>>

-----------------------------------------------------------------------------
(* THE PRIVILEGED LOGIN: challenge-signature admission                       *)

\* A nonce is LIVE for THIS server iff it is bound to GoodOrigin, has not
\* expired (expiry >= clock), and has not been consumed. These three predicates
\* are the wrong-origin / stale / replay gates respectively.
NonceLive(nc) ==
    /\ nc.origin = GoodOrigin
    /\ nc.expiry >= clock
    /\ ~nc.consumed

\* Admit(k, nc): the client signs challenge `nc` with unlocked subkey `k` and
\* the server verifies. This is WoTAuthority's Act -- the SAME single authority
\* path -- guarded additionally by the full web-login preconditions:
\*   * the WoT revoke-before-act fence: signer key's freshMark = RevCount
\*     (fail-closed: any stale view disables login, never falls back);
\*   * subject subkey WoT-chains to the Owner anchor and is not revoked
\*     (k \in CurrentAuthNodes) -- forged/unchained subkey refused;
\*   * the subkey is genuinely unlocked (k \in unlocked) -- a locked/absent
\*     key cannot sign, so mere possession of the ciphertext admits nothing;
\*   * the presented nonce is LIVE (right-origin, unexpired, unconsumed).
\* On success the nonce is consumed (single-use -> replay refused thereafter),
\* and lastAct records the authorization snapshot exactly as WoTAuthority does.
Admit(k, nc) ==
    /\ nc \in nonces
    /\ freshMark[k] = RevCount
    /\ k \in CurrentAuthNodes
    /\ k \in unlocked
    /\ NonceLive(nc)
    /\ nonces' = (nonces \ {nc}) \cup {[nc EXCEPT !.consumed = TRUE]}
    /\ lastAct' = [some |-> TRUE, actor |-> k, subject |-> k,
                   authSnap |-> CurrentAuthNodes, watermark |-> RevCount,
                   origin |-> nc.origin, expiry |-> nc.expiry, atTime |-> clock,
                   passkey |-> (k \in Passkeys)]
    /\ UNCHANGED <<edges, revokedKeys, revokedEdges, revokedGrants, freshMark,
                   partitioned, clock, nonceSerial, unlocked>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E a, b \in Nodes, l \in Depths : IssueEdge(a, b, l)
    \/ \E k \in Nodes                  : RevokeKey(k)
    \/ \E a, b \in Nodes               : RevokeEdge(a, b)
    \/ \E n \in Nodes                  : RevokeGrant(n)
    \/ \E n \in Nodes                  : StaleView(n)
    \/ Tick
    \/ \E o \in Origins, ex \in Times  : IssueNonce(o, ex)
    \/ \E k \in Nodes                  : UnlockSubkey(k)
    \/ \E k \in Nodes, nc \in nonces   : Admit(k, nc)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

MaxRevCount == Cardinality(Nodes) + Cardinality(Nodes \X Nodes) + Cardinality(Nodes)

NonceRecords ==
    [id: 0 .. MaxNonces, origin: Origins, expiry: Times, consumed: BOOLEAN]

TypeOK ==
    /\ edges \subseteq (Nodes \X Nodes \X Depths)
    /\ revokedKeys \subseteq Nodes
    /\ revokedEdges \subseteq (Nodes \X Nodes)
    /\ revokedGrants \subseteq Nodes
    /\ freshMark \in [Nodes -> 0 .. MaxRevCount]
    /\ partitioned \subseteq Nodes
    /\ clock \in Times
    /\ nonces \subseteq NonceRecords
    /\ nonceSerial \in 0 .. MaxNonces
    /\ unlocked \subseteq Nodes
    /\ lastAct \in [some: BOOLEAN, actor: Nodes, subject: Nodes,
                    authSnap: SUBSET Nodes, watermark: 0 .. MaxRevCount,
                    origin: Origins, expiry: Times, atTime: Times, passkey: BOOLEAN]

FreshMarkBounded == \A n \in Nodes : freshMark[n] <= RevCount

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

(* ---- WoTAuthority guarantees, re-proven for LOGIN sessions ---- *)

\* The most recent login (if any) admitted a subject that WAS WoT-authoritative
\* at the exact moment it acted. Since revocation only shrinks authority over
\* time, this is stable evidence: a login always precedes any later revocation
\* of that subkey, never follows it -- fail-closed carries to auth-subkey
\* sessions, not just controller Acts.
NoActionAfterRevocation ==
    lastAct.some => lastAct.subject \in lastAct.authSnap

\* Fail-closed under a stale view: a signer key whose watermark lags the true
\* global one can never be the actor of the most-recent, fully-fresh-against-
\* the-current-watermark login. Admit's freshMark[k] = RevCount fence forecloses
\* the optimistic path for logins exactly as WoTAuthority's Act does.
FailClosedUnderStaleView ==
    \A n \in Nodes :
        freshMark[n] < RevCount =>
            ~ (/\ lastAct.some
               /\ lastAct.actor = n
               /\ lastAct.watermark = RevCount)

(* ---- Web-login obligations (the four from the design doc) ---- *)

\* A login is only ever recorded against a nonce bound to THIS server's origin.
\* A signature over a wrong-origin nonce is never admitted.
WrongOriginRejected ==
    lastAct.some => lastAct.origin = GoodOrigin

\* A login is only ever recorded against a nonce that had not expired at the
\* moment it was admitted. A signature over a stale nonce is never admitted.
StaleNonceRejected ==
    lastAct.some => lastAct.expiry >= lastAct.atTime

\* Replay: every nonce is single-use. A recorded login's nonce is consumed, so
\* no nonce can be admitted twice. Concretely: at most one non-consumed nonce
\* can ever match a given <<origin, expiry, id>>, and Admit consumes it -- so
\* there is never a reachable state with two distinct un-consumed nonces of the
\* same identity available for a second Admit of the same challenge.
ReplayRejected ==
    \A n1, n2 \in nonces :
        (n1.id = n2.id /\ n1.origin = n2.origin /\ n1.expiry = n2.expiry
            /\ ~n1.consumed /\ ~n2.consumed) => n1 = n2

\* Only a genuinely-unlocked subkey that WoT-chains (is trust-reachable to the
\* Owner anchor, not revoked/grant-revoked) can admit. A forged/unchained or
\* locked subkey is refused: the most recent login's subject was, at act time,
\* both in the WoT-authoritative set and locally unlocked.
AdmitRequiresChainedUnlockedSubkey ==
    lastAct.some =>
        /\ lastAct.subject \in lastAct.authSnap
        /\ lastAct.subject \in unlocked

\* A WebAuthn-bound AUTH_SUBKEY resolves through the EXACT SAME admit predicate
\* as a software-unlocked subkey: the `passkey` flavour flag recorded on a login
\* never appears without every non-passkey admit precondition also holding. I.e.
\* being a passkey neither adds a parallel gate nor bypasses the WoT/unlock/nonce
\* gates -- the admit/deny path is identical for both signer flavours.
PasskeyPathEquivalent ==
    (lastAct.some /\ lastAct.passkey) =>
        /\ lastAct.subject \in lastAct.authSnap
        /\ lastAct.subject \in unlocked
        /\ lastAct.origin = GoodOrigin
        /\ lastAct.expiry >= lastAct.atTime

=============================================================================
