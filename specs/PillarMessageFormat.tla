-------------------------- MODULE PillarMessageFormat --------------------------
(***************************************************************************)
(* ROI P1 "The unified Pillar Message Format" (operator-directed, 2026-09-09), *)
(* method #1 TLA+-FIRST, DESIGN-GATED. This spec is step (a): it MUST be     *)
(* green under TLC before ANY Rust lands for the envelope or the convergent   *)
(* content seal (pillar-wire-crate-impl, cell-seal-convergent-impl,           *)
(* streamdb-pillarmsg-migration, obs-signal-pillarmsg-ipfs all depend on it).  *)
(* Design of record: docs/papers/pillar-message-format.md.                    *)
(*                                                                          *)
(* SCOPE: this spec is TRANSPORT-AGNOSTIC -- envelope + convergent CONTENT     *)
(* seal (holds on pillar-udp, QUIC, TCP alike) + format/protocol version      *)
(* negotiation. The pillar-udp TRANSPORT-FRAME encryption (the portable       *)
(* cell-minted session key) is proven separately in PillarUdpEncryption.tla / *)
(* docs/papers/pillar-udp-encryption.md -- NOT modelled here.                  *)
(*                                                                          *)
(* It extends the version-negotiation discipline of VersioningCompat.tla     *)
(* (the pillar-UDP protocol version is one of that spec's abstract           *)
(* Surfaces) and the one-substrate ingestion model of                        *)
(* ObsIngestionSubstrate.tla (a Signal is now a PillarMessage body, so it     *)
(* is content-addressed and persisted on the SAME store as a streamdb op).   *)
(*                                                                          *)
(* WHAT IS MODELLED                                                          *)
(*                                                                          *)
(* Every byte Pillar persists or transmits is ONE record: a PillarMessage    *)
(* envelope carrying a body sealed CONVERGENTLY to a cell. Nodes are          *)
(* partitioned into cells (CellA, CellB); a node holds ONLY its own cell's    *)
(* group key. A body sealed to cell c yields a DETERMINISTIC ciphertext       *)
(* (a pure function of (c, plaintext)) whose content address (Cid) is         *)
(* therefore identical on every node -- that is what keeps dedup + IPFS       *)
(* convergence intact DESPITE encryption. The convergent nonce is a pure      *)
(* injective function of (cell key, content-address(plaintext)), so two       *)
(* DISTINCT plaintexts never share a nonce (AEAD-safe) while two IDENTICAL    *)
(* plaintexts collapse to one Cid (the intended dedup).                       *)
(*                                                                          *)
(* SEAL-TREATMENT SCOPE: this spec models the CONVERGENT cell seal -- the     *)
(* treatment of a StreamOp / Signal body and of the cell WRAPPER of a direct- *)
(* message Op, i.e. the multi-node-unseal layer where identical content MUST  *)
(* dedupe. The OTHER two body treatments an Op may carry inside this envelope *)
(* -- a RANDOM seal to one recipient principal (a UserMessage / KeyOffer Op's *)
(* contents, unique per message, NOT content-deduped) and an UNENCRYPTED body *)
(* (a libp2p control message) -- are modelled in PillarBodySeals.tla.         *)
(*                                                                          *)
(* The legacy libp2p Noise upgrade is gone: the message-format/pillar-UDP     *)
(* version bumps and a mixed-version swarm negotiates or is cleanly refused.  *)
(*                                                                          *)
(* Proven by TLC:                                                            *)
(*   Safety   : TypeOK, OneRecordFormat, ContentAddressStable,               *)
(*              DedupUnderEncryption, CellConfidential,                       *)
(*              NoNonceReuseAcrossDistinctPlaintext,                          *)
(*              NegotiationRefusesIncompatible                               *)
(*   Liveness : RollingCoexistence (mixed Noise/session-key era reachable)   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    CellA, CellB,  \* disjoint, non-empty node sets -- the swarm's two cells;
                   \* Nodes == CellA \cup CellB. A node holds ONLY its cell key.
    Bodies,        \* the finite set of logical plaintext record contents (a
                   \* streamdb op payload or an observability signal payload --
                   \* both are just "a body" to the envelope)
    N,             \* Nat >= 1 : the pillar-UDP/message-format compat window
    MaxV           \* Nat >= N : finite ceiling on the protocol version

ASSUME CellsOK  == /\ CellA \cap CellB = {} /\ CellA # {} /\ CellB # {}
ASSUME BodiesOK == Bodies # {}
ASSUME NOK      == N \in Nat /\ N >= 1
ASSUME MaxVOK   == MaxV \in Nat /\ MaxV >= N

Nodes == CellA \cup CellB
Cells == {"cA", "cB"}
CellOf(n) == IF n \in CellA THEN "cA" ELSE "cB"
Holds(n, c) == c = CellOf(n)          \* n can decrypt a c-sealed body iff it holds c
Diff(a, b) == IF a >= b THEN a - b ELSE b - a

\* ---- the sealed, content-addressed record (all pure, deterministic) --------

Env == [cell: Cells, body: Bodies]
MkEnv(c, b) == [cell |-> c, body |-> b]

\* Convergent nonce: derived from the cell group key and the content address of
\* the plaintext. Injective in the plaintext for a fixed cell key => distinct
\* plaintexts never collide (AEAD nonce-reuse safety); identical plaintext under
\* the same cell key reproduces the SAME nonce (the mechanism of dedup).
ConvergentNonce(c, b) == <<c, b>>

\* The convergent ciphertext: a deterministic function of (cell key, plaintext).
\* A random-nonce seal would make this vary per call, breaking the two dedup /
\* stable-Cid invariants below -- this determinism is exactly the design claim.
Ciphertext(c, b) == <<"ct", c, ConvergentNonce(c, b)>>

\* The content address of the canonical sealed envelope bytes. Injective on Env
\* because Ciphertext is; equal for two envelopes iff they are the same record.
Cid(e) == <<e.cell, Ciphertext(e.cell, e.body)>>

VARIABLES
    stored,    \* [Nodes -> SUBSET Env] : each node's content-addressed store
               \*   (a SET, so identical Cids collapse -- dedup by construction)
    opened,    \* [Nodes -> SUBSET (Cells \X Bodies)] : the <<cell, body>> pairs a
               \*   node has actually DECRYPTED (only ever for a cell it holds)
    protoVer,  \* [Nodes -> 0..MaxV] : each node's running pillar-UDP/message
               \*   version (0 = legacy Noise era, >=1 = sealed-envelope era)
    released,  \* 0..MaxV : swarm-wide released pillar-UDP/message version
    neg        \* last negotiation outcome: [kind: {"none","linked","refused"}, p, q]

vars == <<stored, opened, protoVer, released, neg>>

NoNode == CHOOSE n \in Nodes : TRUE

Init ==
    /\ stored   = [n \in Nodes |-> {}]
    /\ opened   = [n \in Nodes |-> {}]
    /\ protoVer = [n \in Nodes |-> 0]
    /\ released = 0
    /\ neg      = [kind |-> "none", p |-> NoNode, q |-> NoNode]

------------------------------------------------------------------------------
(* ACTIONS *)

\* A node authors a record: seals `b` to its OWN cell and stores the envelope.
\* The author holds its cell key, so it also holds the plaintext (opened).
Produce(n, b) ==
    LET c == CellOf(n) IN
    /\ stored' = [stored EXCEPT ![n] = @ \cup {MkEnv(c, b)}]
    /\ opened' = [opened EXCEPT ![n] = @ \cup {<<c, b>>}]
    /\ UNCHANGED <<protoVer, released, neg>>

\* Content-addressed backfill: m fetches an envelope from n's store (bitswap).
\* m stores the (sealed) block unconditionally; it recovers the PLAINTEXT only
\* if it holds the sealing cell's key -- a non-member keeps ciphertext only.
\* Transport-agnostic: same whether the block arrives over pillar-udp/QUIC/TCP.
Replicate(n, m) ==
    /\ n # m
    /\ \E e \in stored[n] :
         /\ stored' = [stored EXCEPT ![m] = @ \cup {e}]
         /\ opened' = [opened EXCEPT ![m] =
                          IF Holds(m, e.cell) THEN @ \cup {<<e.cell, e.body>>} ELSE @]
    /\ UNCHANGED <<protoVer, released, neg>>

\* A new pillar-UDP/message version is released; guarded to never strand a peer
\* beyond the window (the N-1 discipline inherited from VersioningCompat).
Release ==
    /\ released < MaxV
    /\ \A n \in Nodes : released - protoVer[n] < N
    /\ released' = released + 1
    /\ UNCHANGED <<stored, opened, protoVer, neg>>

\* A node rolls forward one version at a time (never a stop-the-world jump), so
\* a mixed Noise/session-key swarm is the reachable norm during cutover.
Upgrade(n) ==
    /\ protoVer[n] < released
    /\ protoVer' = [protoVer EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<stored, opened, released, neg>>

\* Two peers exchange + compare versions: within the window => linked; else
\* cleanly REFUSED (never silently mis-framed across the Noise/session boundary).
Negotiate(p, q) ==
    /\ p # q
    /\ neg' = [kind |-> IF Diff(protoVer[p], protoVer[q]) <= N THEN "linked" ELSE "refused",
               p |-> p, q |-> q]
    /\ UNCHANGED <<stored, opened, protoVer, released>>

Next ==
    \/ \E n \in Nodes, b \in Bodies : Produce(n, b)
    \/ \E n, m \in Nodes : Replicate(n, m)
    \/ Release
    \/ \E n \in Nodes : Upgrade(n)
    \/ \E p, q \in Nodes : Negotiate(p, q)

\* Fairness only needs to drive the version machine forward for the one liveness
\* property (RollingCoexistence): a release eventually happens and a lagging
\* node eventually rolls forward, so a mixed-version state is unavoidable.
Fairness ==
    /\ WF_vars(Release)
    /\ \A n \in Nodes : WF_vars(Upgrade(n))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY *)

TypeOK ==
    /\ stored   \in [Nodes -> SUBSET Env]
    /\ opened   \in [Nodes -> SUBSET (Cells \X Bodies)]
    /\ protoVer \in [Nodes -> 0..MaxV]
    /\ released \in 0..MaxV
    /\ neg      \in [kind: {"none", "linked", "refused"}, p: Nodes, q: Nodes]

\* Every persisted item is a PillarMessage envelope -- there is NO non-envelope
\* byte path anywhere in the system (the whole point of the unification: one
\* record format for streamdb ops, obs signals, and control).
OneRecordFormat ==
    \A n \in Nodes : \A e \in stored[n] : e \in Env

\* The content address of a record is identical on every node that holds it,
\* DESPITE the body being encrypted -- convergent sealing preserves the stable,
\* node-independent Cid that dedup, IPFS convergence, and Merkle roots need.
ContentAddressStable ==
    \A n, m \in Nodes :
      \A e1 \in stored[n], e2 \in stored[m] :
        (e1.cell = e2.cell /\ e1.body = e2.body) => Cid(e1) = Cid(e2)

\* A node's content-addressed store never holds two DISTINCT blocks under one
\* Cid: the sealed record is a function of its Cid, so encryption never forks a
\* single logical record into multiple stored copies (dedup under encryption).
DedupUnderEncryption ==
    \A n \in Nodes :
      \A e1, e2 \in stored[n] : Cid(e1) = Cid(e2) => e1 = e2

\* Only a cell-key holder ever recovers a body sealed to that cell: a node's
\* set of decrypted <<cell, body>> pairs contains only cells it holds. A peer
\* outside the cell may STORE the ciphertext (backfill over any transport) but
\* never obtains the plaintext.
CellConfidential ==
    \A n \in Nodes : \A pair \in opened[n] : Holds(n, pair[1])

\* The convergent nonce never repeats for two DISTINCT plaintexts under the same
\* cell key -- the AEAD nonce-reuse safety condition the convergent scheme must
\* meet (equality of nonces implies equality of plaintext).
NoNonceReuseAcrossDistinctPlaintext ==
    \A c \in Cells : \A b1, b2 \in Bodies :
        ConvergentNonce(c, b1) = ConvergentNonce(c, b2) => b1 = b2

\* Discharged as a constant assumption (it is a property of the pure convergent-
\* nonce derivation, independent of state): TLC verifies it at startup and aborts
\* if it is ever false. This is the AEAD nonce-reuse safety obligation.
ASSUME NonceInjective == NoNonceReuseAcrossDistinctPlaintext

\* A negotiation's recorded outcome is always correct w.r.t. the window: a
\* "linked" pair truly is within N (never a silent link across an incompatible
\* Noise/session-key boundary); a "refused" pair truly is beyond N.
NegotiationRefusesIncompatible ==
    /\ (neg.kind = "linked"  => Diff(protoVer[neg.p], protoVer[neg.q]) <= N)
    /\ (neg.kind = "refused" => Diff(protoVer[neg.p], protoVer[neg.q]) > N)

------------------------------------------------------------------------------
(* LIVENESS *)

\* A mixed-version swarm (some nodes on the legacy Noise era, some on the
\* session-key era) is REACHABLE, not merely tolerated -- the rolling cutover
\* passes through a state where two nodes run different versions.
RollingCoexistence == <>(\E p, q \in Nodes : protoVer[p] # protoVer[q])

===============================================================================
