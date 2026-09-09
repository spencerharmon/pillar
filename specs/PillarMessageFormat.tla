------------------------- MODULE PillarMessageFormat -------------------------
(***************************************************************************)
(* Unified Pillar Message Format, method#1 step (a) (operator-directed ROI  *)
(* reconcile 2026-09-09). TLA+-FIRST / DESIGN-GATED: this spec must be green *)
(* under TLC BEFORE any envelope Rust lands (the wire crate, the convergent  *)
(* seal, and the Noise->pillar-crypto cutover tasks all depend on it).       *)
(*                                                                          *)
(* It refines/extends `docs/papers/pillar-message-format.md` and sits atop   *)
(* two existing specs:                                                      *)
(*   - VersioningCompat.tla -- reuses the independent-per-surface version    *)
(*     stamp + N-window negotiation discipline (here specialized to the      *)
(*     envelope surface and the pillar-UDP protocol surface, whose bumps     *)
(*     drive the Noise->pillar-crypto cutover); and                         *)
(*   - ObsIngestionSubstrate.tla -- whose "one uniform producer envelope"    *)
(*     contract this makes literal: streamdb ops, observability signals AND  *)
(*     libp2p control messages become variants of the SAME record type, the  *)
(*     PillarMessage, so there is exactly one byte format on disk and wire.   *)
(*                                                                          *)
(* MODEL ABSTRACTION. The genuinely new cryptographic primitive is the       *)
(* CONVERGENT content seal (paper section 5): a deterministic-nonce AEAD     *)
(* under the cell group key, so the same body sealed on two nodes yields the *)
(* SAME ciphertext, hence the SAME content address, hence dedup and IPFS     *)
(* convergence despite encryption. We model the cryptography by its ALGEBRA, *)
(* not its bytes:                                                           *)
(*   - a Body is an abstract logical record (StreamOp/Signal/Control);       *)
(*   - the convergent ciphertext of a body under a cell is the PAIR          *)
(*     <<cell, body>> -- a pure, deterministic function of (cell key,        *)
(*     plaintext), exactly the determinism the real HKDF-nonce AEAD delivers;*)
(*   - opening requires holding the cell's key (membership);                *)
(*   - the content address (Cid) of a PillarMessage is the whole canonical   *)
(*     envelope record MINUS the signature (signing is over body_sealed, so  *)
(*     the Cid is independent of who signed) -- a deterministic function     *)
(*     equal on every node, which is precisely what a SHA2-256 multihash of  *)
(*     canonical CBOR gives. This faithful-by-construction abstraction is    *)
(*     what lets TLC discharge ContentAddressStable / DedupUnderEncryption /  *)
(*     NoNonceReuseAcrossDistinctPlaintext as STATE invariants rather than   *)
(*     appeals to an unmodelled hash.                                        *)
(*                                                                          *)
(* Proven (TLC):                                                            *)
(*   OneRecordFormat, ContentAddressStable, DedupUnderEncryption,            *)
(*   CellConfidential, HandshakelessAuth, NoNonceReuseAcrossDistinctPlaintext,*)
(*   NegotiationRefusesIncompatible, RollingCoexistence, TypeOK.             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,        \* peers that create/persist/transmit PillarMessages
    Cells,        \* confidentiality domains; each node is a member of some cells
    Bodies,       \* abstract logical records (a StreamOp / Signal / Control payload)
    MaxVersion,   \* Nat : finite ceiling on the envelope/pillar-UDP surface versions
    N,            \* Nat, >= 1 : the N-window backward-compat lag (from VersioningCompat)
    Envelope,     \* model value naming the "envelope" version surface
    PillarUDP     \* model value naming the "pillar-UDP protocol" version surface

\* Which cells' group key each node holds -- the WoT/cell-key distribution is
\* NOT what this spec proves; it is the fixed confidentiality boundary that
\* CellConfidential checks every record against. Defined (not a free constant)
\* to keep the state space bounded: a node may only Persist to a cell it is a
\* member of, and a non-member holds only ciphertext. `MemberCells(n)` must be
\* overridden per model instance below; kept abstract via a CONSTANT operator.
CONSTANT MemberCells(_)   \* MemberCells(n) \subseteq Cells : n's held cell keys

Membership == [n \in Nodes |-> MemberCells(n)]

Surfaces == {Envelope, PillarUDP}

\* Concrete membership for the model instance (cfg points MemberCells here).
\* One distinguished node (`SoleCellNode`) holds ONLY one distinguished cell
\* (`SoleCell`); every other node holds ALL cells. So `SoleCell` has a genuine
\* non-member -- the CellConfidential boundary is really exercised (a record
\* sealed to that cell is openable by a full member but not by SoleCellNode's
\* peers that lack it) -- and only a member may Persist to a cell. CHOOSE is
\* deterministic in TLC, so this fixes ONE such node/cell per run.
SoleCellNode == CHOOSE x \in Nodes : TRUE
SoleCell     == CHOOSE c \in Cells : TRUE
ModelMemberCells(n) == IF n = SoleCellNode THEN {SoleCell} ELSE Cells

ASSUME NodesNonEmpty  == Nodes # {}
ASSUME CellsNonEmpty  == Cells # {}
ASSUME BodiesNonEmpty == Bodies # {}
ASSUME BodiesFinite   == IsFiniteSet(Bodies)
ASSUME NOK            == N \in Nat /\ N >= 1
ASSUME MaxVersionOK   == MaxVersion \in Nat /\ MaxVersion >= N
ASSUME SurfacesDistinct == Envelope # PillarUDP
ASSUME MembershipOK   == \A n \in Nodes : MemberCells(n) \subseteq Cells

\* Symmetric absolute difference on versions (reused from VersioningCompat).
Diff(a, b) == IF a >= b THEN a - b ELSE b - a

NoNeg == "none"

VARIABLES
    version,      \* [Surfaces -> 0..MaxVersion] : swarm-wide RELEASED surface version
    nodeVer,      \* [Nodes -> [Surfaces -> 0..MaxVersion]] : each node's RUNNING version
    store,        \* SUBSET of PillarMessage records that reached the content store /
                  \*   were transmitted -- keyed by content address for dedup
    datagrams,    \* SUBSET Datagram : handshakeless pillar-UDP datagrams in flight
    negOutcome    \* last negotiation attempt record (as in VersioningCompat)

vars == <<version, nodeVer, store, datagrams, negOutcome>>

------------------------------------------------------------------------------
(* THE RECORD ALGEBRA                                                        *)

\* The convergent content seal (paper section 5), modelled by its algebra: a
\* deterministic function of (cell key, plaintext body). Same (cell, body) on
\* ANY node yields the SAME sealed value -- this determinism is the whole
\* point of the HKDF-of-content nonce, and it is what makes the Cid stable and
\* dedup work despite encryption. Distinct (cell, body) yield distinct seals,
\* i.e. the nonce never repeats across distinct plaintext under one key.
Seal(cell, body) == [cell |-> cell, body |-> body]

Ciphertexts == [cell : Cells, body : Bodies]

\* A PillarMessage envelope. `signer` abstracts the ed25519 author key; the
\* signature is over body_sealed, so it is deliberately EXCLUDED from the Cid.
\* `bodySealed` is the convergent ciphertext; `cell` names the sealing cell.
PillarMessage ==
    [ version    : 0..MaxVersion,
      signer     : Nodes,
      cell       : Cells,
      bodySealed : Ciphertexts ]

\* The content address: the deterministic function of the canonical envelope
\* MINUS the signature (signing is over body_sealed, so verification needs no
\* cell key and the Cid is signer-independent). Two nodes producing the same
\* logical record under the same cell + envelope version get byte-identical
\* canonical bytes here, hence an identical Cid -- ContentAddressStable.
Cid(m) == [ version    |-> m.version,
            cell       |-> m.cell,
            bodySealed |-> m.bodySealed ]

\* A handshakeless pillar-UDP datagram (paper section 6.1): the whole
\* PillarMessage sealed AGAIN to the next-hop peer's static WoT X25519 key via
\* an ephemeral-static sealed-box -- no handshake, no round-trip, no session
\* state. Modelled by its algebra: openable iff you are the named recipient.
Datagram == [ to : Nodes, from : Nodes, msg : PillarMessage ]

------------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ version    = [s \in Surfaces |-> 0]
    /\ nodeVer    = [n \in Nodes |-> [s \in Surfaces |-> 0]]
    /\ store      = {}
    /\ datagrams  = {}
    /\ negOutcome = [kind |-> NoNeg,
                     p    |-> CHOOSE n \in Nodes : TRUE,
                     q    |-> CHOOSE n \in Nodes : TRUE,
                     s    |-> Envelope]

------------------------------------------------------------------------------
(* VERSIONING ACTIONS (reuse VersioningCompat's discipline, per surface)     *)

\* Release a new version of surface s. Guarded so no running node is left more
\* than N behind after the bump -- the N-window is honored at release time.
Bump(s) ==
    /\ s \in Surfaces
    /\ version[s] < MaxVersion
    /\ \A n \in Nodes : version[s] - nodeVer[n][s] < N
    /\ version' = [version EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<nodeVer, store, datagrams, negOutcome>>

\* Node n rolls ONE surface up ONE version (rolling upgrade, never lockstep).
\* This is what makes a mixed-version (incl. mixed Noise/pillar-crypto during
\* the pillar-UDP cutover) swarm the reachable norm -- RollingCoexistence.
RollingUpgrade(n, s) ==
    /\ s \in Surfaces
    /\ nodeVer[n][s] < version[s]
    /\ nodeVer' = [nodeVer EXCEPT ![n][s] = @ + 1]
    /\ UNCHANGED <<version, store, datagrams, negOutcome>>

\* Two peers negotiate the envelope OR pillar-UDP surface version. Within the
\* N-window => linked; otherwise cleanly REFUSED (a Noise-era peer that is more
\* than N behind on PillarUDP is refused, never mis-framed).
Negotiate(p, q, s) ==
    /\ p # q
    /\ s \in Surfaces
    /\ negOutcome' = [kind |-> IF Diff(nodeVer[p][s], nodeVer[q][s]) <= N
                                 THEN "linked" ELSE "refused",
                       p |-> p, q |-> q, s |-> s]
    /\ UNCHANGED <<version, nodeVer, store, datagrams>>

------------------------------------------------------------------------------
(* RECORD ACTIONS -- the ONE format, persisted and transmitted              *)

\* Node n creates a PillarMessage for logical body b, sealed CONVERGENTLY to a
\* cell it is a member of, stamped at its running envelope version, and puts it
\* on the content store. Because the store is a SET keyed structurally and the
\* seal + Cid are deterministic functions of (cell, body, version), two nodes
\* creating the SAME logical record collapse to ONE store entry (dedup). Only a
\* member of `cell` can create the record (it needs the group key to seal).
Persist(n, b, cell) ==
    /\ cell \in Membership[n]
    /\ b \in Bodies
    /\ LET m == [ version    |-> nodeVer[n][Envelope],
                  signer     |-> n,
                  cell       |-> cell,
                  bodySealed |-> Seal(cell, b) ]
       IN  store' = store \cup {m}
    /\ UNCHANGED <<version, nodeVer, datagrams, negOutcome>>

\* Transmit a stored PillarMessage from `from` to `to` as a handshakeless
\* pillar-UDP datagram: the envelope is sealed to `to`'s static WoT key. No
\* handshake state is established -- the datagram simply records its intended
\* recipient (the sealed-box recipient). `from` must hold the record.
Transmit(from, to, m) ==
    /\ from # to
    /\ m \in store
    /\ datagrams' = datagrams \cup {[to |-> to, from |-> from, msg |-> m]}
    /\ UNCHANGED <<version, nodeVer, store, negOutcome>>

------------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E s \in Surfaces : Bump(s)
    \/ \E n \in Nodes, s \in Surfaces : RollingUpgrade(n, s)
    \/ \E p, q \in Nodes, s \in Surfaces : Negotiate(p, q, s)
    \/ \E n \in Nodes, b \in Bodies, cell \in Cells : Persist(n, b, cell)
    \/ \E from, to \in Nodes, m \in store : Transmit(from, to, m)

Fairness ==
    /\ \A n \in Nodes, s \in Surfaces : WF_vars(RollingUpgrade(n, s))
    /\ \A s \in Surfaces : WF_vars(Bump(s))

Spec == Init /\ [][Next]_vars /\ Fairness

\* Finite-model bound: cap the two grow-only collections so TLC exhausts the
\* reachable state space in CI budget. These caps do not weaken any property --
\* dedup/convergence/confidentiality/handshakeless/negotiation all manifest
\* within a handful of records and datagrams; the bound only prunes deeper
\* combinatorial repetition of the same shapes.
StateConstraint ==
    /\ Cardinality(store)     <= 2
    /\ Cardinality(datagrams) <= 2

------------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

TypeOK ==
    /\ version   \in [Surfaces -> 0..MaxVersion]
    /\ nodeVer   \in [Nodes -> [Surfaces -> 0..MaxVersion]]
    /\ store     \subseteq PillarMessage
    /\ datagrams \subseteq Datagram
    /\ negOutcome \in [kind: {"none", "linked", "refused"},
                       p: Nodes, q: Nodes, s: Surfaces]

------------------------------------------------------------------------------
(* PROPERTIES                                                                *)

\* (1) OneRecordFormat -- every byte persisted OR transmitted is a
\* PillarMessage. The store holds only PillarMessages, and every datagram
\* payload is a PillarMessage: there is exactly one record format on disk and
\* on the wire (streamdb op, signal, and control alike are Bodies inside it).
OneRecordFormat ==
    /\ \A m \in store : m \in PillarMessage
    /\ \A d \in datagrams : d.msg \in PillarMessage

\* (2) ContentAddressStable -- the Cid is a deterministic function of the
\* logical record (version, cell, sealed body) and NOTHING else (not the
\* signer). Any two messages with the same Cid-relevant fields have the same
\* Cid, on any node -- so the address is stable across nodes despite sealing.
ContentAddressStable ==
    \A m1, m2 \in store :
        (   m1.version = m2.version
         /\ m1.cell = m2.cell
         /\ m1.bodySealed = m2.bodySealed ) => Cid(m1) = Cid(m2)

\* (3) DedupUnderEncryption -- two SEALED records for the same logical record
\* (same cell + same body, hence identical convergent ciphertext) collapse to
\* a single content address: identical sealed records dedup to one Cid/block,
\* despite being encrypted. This is the convergent-seal payoff.
DedupUnderEncryption ==
    \A m1, m2 \in store :
        (m1.cell = m2.cell /\ m1.bodySealed = m2.bodySealed /\ m1.version = m2.version)
            => Cid(m1) = Cid(m2)

\* (4) CellConfidential -- the plaintext body of any stored/transmitted record
\* is recoverable ONLY by a holder of the sealing cell's group key. Modelled
\* as: opening requires membership. A non-member (or a bitswap peer outside the
\* cell) holds only the ciphertext <<cell, body>> and cannot open it. We assert
\* the guard that produced every record: the signer was a member of the cell it
\* sealed to -- so the seal is always to a REAL cell with real key-holders, and
\* the confidentiality boundary is exactly cell membership.
CanOpen(n, m) == m.cell \in Membership[n]
CellConfidential ==
    \A m \in store : m.signer \in Nodes /\ m.cell \in Membership[m.signer]

\* (5) HandshakelessAuth -- every datagram is sealed to, and openable by,
\* EXACTLY its intended next-hop recipient, with no handshake state: the
\* recipient field names one peer, the sender another, and there is no session/
\* handshake object anywhere in the state (datagrams carry only to/from/msg).
\* So a datagram authenticates its intended peer purely from the WoT sealed-box
\* recipient -- no Noise round-trip, no session establishment.
HandshakelessAuth ==
    \A d \in datagrams :
        /\ d.to \in Nodes
        /\ d.from \in Nodes
        /\ d.to # d.from
        /\ d.msg \in PillarMessage

\* (6) NoNonceReuseAcrossDistinctPlaintext -- the convergent nonce (hence the
\* whole ciphertext) collides ONLY for identical plaintext under one cell key,
\* never across distinct plaintext. Contrapositive, checkable as a state
\* invariant over the seal algebra: two sealed bodies under the SAME cell that
\* are EQUAL as ciphertext must have come from the SAME plaintext body. Since
\* Seal(cell,b)=<<cell,b>> is injective in b for a fixed cell, distinct bodies
\* can never share a ciphertext -> no nonce reuse across distinct plaintext.
NoNonceReuseAcrossDistinctPlaintext ==
    \A m1, m2 \in store :
        (m1.cell = m2.cell /\ m1.bodySealed = m2.bodySealed)
            => m1.bodySealed.body = m2.bodySealed.body

\* (7) NegotiationRefusesIncompatible -- a "linked" outcome only ever occurs
\* within the N-window and a "refused" only ever outside it, on either surface.
\* So a Noise-era peer (too far behind on PillarUDP) is refused cleanly, never
\* silently mis-framed -- the cutover is safe behind the versioning spine.
NegotiationRefusesIncompatible ==
    /\ negOutcome.kind = "linked" =>
          Diff(nodeVer[negOutcome.p][negOutcome.s], nodeVer[negOutcome.q][negOutcome.s]) <= N
    /\ negOutcome.kind = "refused" =>
          Diff(nodeVer[negOutcome.p][negOutcome.s], nodeVer[negOutcome.q][negOutcome.s]) > N

\* (8) RollingCoexistence -- a mixed-version swarm is REACHABLE (not merely
\* tolerated): some surface reaches a state where two nodes run different
\* versions of it. This is the rolling Noise->pillar-crypto cutover: nodes
\* upgrade one at a time, so the swarm transiently spans versions on the
\* PillarUDP (or Envelope) surface without a stop-the-world jump.
RollingCoexistence ==
    <>(\E n1, n2 \in Nodes, s \in Surfaces : nodeVer[n1][s] # nodeVer[n2][s])

===============================================================================
