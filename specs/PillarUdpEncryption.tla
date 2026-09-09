-------------------------- MODULE PillarUdpEncryption --------------------------
(***************************************************************************)
(* ROI P1 "The unified Pillar Message Format" / pillar-udp transport crypto  *)
(* (operator-directed, 2026-09-09). Method #1 TLA+-FIRST, DESIGN-GATED: this   *)
(* MUST be green under TLC before any Rust for the pillar-udp session-key      *)
(* cutover. Design of record: docs/papers/pillar-udp-encryption.md.           *)
(*                                                                          *)
(* SCOPE. How a pillar-udp DATAGRAM is encrypted on the wire -- the portable, *)
(* cell-minted transport SESSION KEY. (QUIC/TCP fallbacks use their own TLS   *)
(* and are out of scope; the transport-agnostic PillarMessage content seal is *)
(* in PillarMessageFormat.tla.)                                               *)
(*                                                                          *)
(* THE SCHEME (cell as KDC over streamdb).                                    *)
(* A client (node / non-node / anonymous) opens a session by choosing a fresh *)
(* EPHEMERAL key. An ingress cell node authorizes it, applies WoT/RBAC policy, *)
(* and derives the session key K_s = HKDF(ECDH(client_eph, cell_static), ...). *)
(* Because derivation is DETERMINISTIC in (cell key, eph), every cell node and *)
(* the client compute the byte-IDENTICAL K_s -- no race, no reconcile, and the *)
(* session is PORTABLE across every cell node (ingress failover / relay / LB). *)
(* The authorization is a CELL-SIGNED record on streamdb; K_s itself is never  *)
(* stored (only its derivation inputs are), and any node recomputes it.        *)
(*                                                                          *)
(* ANONYMITY is a POLICY state, not a separate crypto scheme: an anonymous key *)
(* runs the identical flow but, lacking role attestations, the cell grants it  *)
(* only the restricted set (default-deny) -- no sensitive data, no privileged  *)
(* ops. REPLAY defense is the content-addressed dedup pillar already has.      *)
(* FORWARD SECRECY is deliberately bounded to cell-key security + erase-on-    *)
(* revoke (documented in the paper, not a state invariant); GC of a revoked    *)
(* session is therefore SECURITY-critical, modelled as RevokedKeyEventually-   *)
(* Erased.                                                                     *)
(*                                                                          *)
(* Proven by TLC:                                                            *)
(*   Safety   : TypeOK, SessionKeyCellSigned, SessionConvergesOnOneKey,      *)
(*              SessionAuthorizedBeforeServe, AnonIsUnattestedPrincipal,     *)
(*              SharedKeyReplayViaDedup                                       *)
(*   Liveness : RevokedKeyEventuallyErased                                    *)
(*   Constant : NonceCollisionFree (per-frame nonce injective in plaintext)  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,               \* the cell's member nodes (each holds the cell static key,
                         \*   so each can derive K_s and serve a session -- portability)
    Principals,          \* client signing identities (node / user / anonymous keys)
    AttestedPrincipals,  \* subset of Principals carrying WoT role attestations;
                         \*   the complement are anonymous/unattested principals
    Eph,                 \* the finite set of client ephemeral keys; a session's id is
                         \*   its ephemeral (content_address(eph || nonce), abstracted)
    Frames               \* distinct application frames (distinct content addresses)

ASSUME NodesOK   == Nodes # {}
ASSUME PrincOK   == Principals # {} /\ AttestedPrincipals \subseteq Principals
ASSUME EphOK     == Eph # {}
ASSUME FramesOK  == Frames # {}

CellSig == "cA"                       \* the single cell / genesis principal signature
Grant(p) == IF p \in AttestedPrincipals THEN "full" ELSE "restricted"
MkRec(p, e) == [sid |-> e, principal |-> p, eph |-> e, grant |-> Grant(p), signed |-> CellSig]

\* Deterministic session key: HKDF(ECDH(client_eph, cell_static), nonce). Both the
\* client (ECDH(eph_sk, cell_pk)) and ANY cell node (ECDH(cell_sk, eph_pk)) compute
\* the identical value from the same inputs -- so it is portable and race-free.
Ks(sid)          == <<"Ks", sid>>
NodeKs(n, sid)   == Ks(sid)           \* what any cell node derives
ClientKs(p, sid) == Ks(sid)           \* what the client derives (must equal NodeKs)

\* Per-frame AEAD nonce under K_s: convergent (content-derived), injective in the
\* plaintext, so the many cell nodes sharing K_s never reuse a nonce (AEAD safety).
FrameCAs == Eph \X Frames
FrameNonce(sid, ca) == <<sid, ca>>
ASSUME NonceCollisionFree ==
    \A sid \in Eph : \A c1, c2 \in FrameCAs :
        FrameNonce(sid, c1) = FrameNonce(sid, c2) => c1 = c2

VARIABLES
    inits,        \* SUBSET [principal, eph] : sprayed session-initiation requests in flight
    sdb,          \* SUBSET SessionRec : the cell-signed authorizations on streamdb (converged
                  \*   set; K_s is NOT here -- only its derivation inputs + the cell signature)
    views,        \* [Nodes -> SUBSET Eph] : which session-ids each node has converged (can serve)
    revoked,      \* SUBSET Eph : sessions whose revocation record has been written
    everRevoked,  \* SUBSET Eph : monotone memory of revocations (sids are one-shot)
    appliedCAs,   \* SUBSET FrameCAs : frame content-addresses that have taken effect (dedup key)
    effectCount   \* Nat : number of frame effects applied (must equal |appliedCAs| -- no replay)

vars == <<inits, sdb, views, revoked, everRevoked, appliedCAs, effectCount>>

SessionRec == [sid: Eph, principal: Principals, eph: Eph,
               grant: {"full", "restricted"}, signed: {CellSig}]
ActiveSids == {r.sid : r \in sdb}
MaxEffects == Cardinality(Eph) * Cardinality(Frames)

Init ==
    /\ inits       = {}
    /\ sdb         = {}
    /\ views       = [n \in Nodes |-> {}]
    /\ revoked     = {}
    /\ everRevoked = {}
    /\ appliedCAs  = {}
    /\ effectCount = 0

------------------------------------------------------------------------------
(* ACTIONS *)

\* Client sprays a session-initiation request (sealed to the cell key) with a FRESH
\* ephemeral -- fresh: never previously used or retired (sids are one-shot).
OpenSession(p, e) ==
    /\ e \notin everRevoked
    /\ \A i \in inits : i.eph # e
    /\ \A r \in sdb   : r.eph # e
    /\ inits' = inits \cup {[principal |-> p, eph |-> e]}
    /\ UNCHANGED <<sdb, views, revoked, everRevoked, appliedCAs, effectCount>>

\* An ingress cell node authorizes the init: verify, apply RBAC policy (grant), derive
\* K_s (deterministic), write the cell-signed record to streamdb. The request stays in
\* flight so a REDUNDANT copy may be authorized by ANOTHER ingress node -- and because
\* the record is a deterministic function of (principal, eph), the two are byte-
\* identical and the set dedups to one (no race, nothing for the client to reject).
Accept(n, i) ==
    /\ i \in inits
    /\ sdb'   = sdb \cup {MkRec(i.principal, i.eph)}
    /\ views' = [views EXCEPT ![n] = @ \cup {i.eph}]
    /\ UNCHANGED <<inits, revoked, everRevoked, appliedCAs, effectCount>>

\* streamdb convergence: another cell node learns an authorized session and can now
\* derive K_s and serve it -- this is what makes the session portable / failover-safe.
ConvergeView(n, sid) ==
    /\ \E r \in sdb : r.sid = sid
    /\ sid \notin views[n]
    /\ sid \notin revoked
    /\ views' = [views EXCEPT ![n] = @ \cup {sid}]
    /\ UNCHANGED <<inits, sdb, revoked, everRevoked, appliedCAs, effectCount>>

\* A cell node serves a K_s-encrypted frame for a converged, non-revoked session.
\* Delivery is CONTENT-ADDRESSED and idempotent: a replayed frame (same content
\* address) takes NO second effect -- replay defense without a per-session window.
Deliver(n, sid, f) ==
    /\ sid \in views[n]
    /\ sid \notin revoked
    /\ LET ca == <<sid, f>> IN
         IF ca \in appliedCAs
            THEN UNCHANGED <<appliedCAs, effectCount>>
            ELSE /\ appliedCAs'  = appliedCAs \cup {ca}
                 /\ effectCount' = effectCount + 1
    /\ UNCHANGED <<inits, sdb, views, revoked, everRevoked>>

\* Close / timeout: a cell node writes a cell-signed revocation; convergence stops
\* every node from honoring K_s.
Revoke(n, sid) ==
    /\ \E r \in sdb : r.sid = sid
    /\ sid \notin revoked
    /\ revoked'     = revoked \cup {sid}
    /\ everRevoked' = everRevoked \cup {sid}
    /\ UNCHANGED <<inits, sdb, views, appliedCAs, effectCount>>

\* GC erases the revoked authorization from streamdb and every node's view. This is a
\* SECURITY operation: while the record survives, K_s stays derivable (a live oracle).
CollectGC(sid) ==
    /\ sid \in revoked
    /\ sdb'     = {r \in sdb : r.sid # sid}
    /\ views'   = [n \in Nodes |-> views[n] \ {sid}]
    /\ revoked' = revoked \ {sid}
    /\ UNCHANGED <<inits, everRevoked, appliedCAs, effectCount>>

Next ==
    \/ \E p \in Principals, e \in Eph : OpenSession(p, e)
    \/ \E n \in Nodes, i \in inits : Accept(n, i)
    \/ \E n \in Nodes, sid \in Eph : ConvergeView(n, sid)
    \/ \E n \in Nodes, sid \in Eph, f \in Frames : Deliver(n, sid, f)
    \/ \E n \in Nodes, sid \in Eph : Revoke(n, sid)
    \/ \E sid \in Eph : CollectGC(sid)

\* Fairness: EACH revoked session's GC eventually fires (needed for the security-
\* critical erase liveness). Per-sid weak fairness -- fairness on the existential
\* alone would let GC starve one revoked sid by forever collecting another.
Fairness == \A sid \in Eph : WF_vars(CollectGC(sid))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY *)

TypeOK ==
    /\ inits       \in SUBSET [principal: Principals, eph: Eph]
    /\ sdb         \in SUBSET SessionRec
    /\ views       \in [Nodes -> SUBSET Eph]
    /\ revoked     \in SUBSET Eph
    /\ everRevoked \in SUBSET Eph
    /\ appliedCAs  \in SUBSET FrameCAs
    /\ effectCount \in 0..MaxEffects

\* Every honored session is backed by a CELL-signed authorization -- provenance any
\* node verifies against the genesis principal before deriving/serving K_s.
SessionKeyCellSigned == \A r \in sdb : r.signed = CellSig

\* The cell converges on ONE session key per session: at most one active record per
\* session-id (deterministic derivation makes even a race byte-identical, so it dedups),
\* AND every cell node derives exactly the key the client derived (portable agreement).
SessionConvergesOnOneKey ==
    /\ \A r1, r2 \in sdb : r1.sid = r2.sid => r1 = r2
    /\ \A r \in sdb : \A n \in Nodes : NodeKs(n, r.sid) = ClientKs(r.principal, r.sid)

\* A node only ever serves a session it has an authorized, still-present record for --
\* no fabricated or post-erasure sessions (a node's view is always backed by streamdb).
SessionAuthorizedBeforeServe ==
    \A n \in Nodes : \A sid \in views[n] : \E r \in sdb : r.sid = sid

\* Anonymity is enforced by POLICY: an unattested principal only ever holds the
\* restricted grant, and no privileged ("full") grant is ever attached to one.
AnonIsUnattestedPrincipal ==
    /\ \A r \in sdb : (r.principal \notin AttestedPrincipals) => r.grant = "restricted"
    /\ \A r \in sdb : r.grant = "full" => r.principal \in AttestedPrincipals

\* Replay defense via content-addressed dedup: the number of frame EFFECTS equals the
\* number of DISTINCT frame content addresses -- a replay never causes a second effect.
SharedKeyReplayViaDedup == effectCount = Cardinality(appliedCAs)

------------------------------------------------------------------------------
(* LIVENESS *)

\* A revoked session's authorization is EVENTUALLY erased from streamdb (bounded-time
\* GC). Until then K_s stays derivable, so this erasure is a security guarantee.
RevokedKeyEventuallyErased ==
    \A sid \in Eph : [](sid \in revoked => <>(sid \notin ActiveSids))

===============================================================================
