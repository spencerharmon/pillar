---------------------------- MODULE PillarBodySeals ----------------------------
(***************************************************************************)
(* ROI P1 "The unified Pillar Message Format" (operator-directed, 2026-09-09), *)
(* method #1 TLA+-FIRST, DESIGN-GATED. Companion to PillarMessageFormat.tla:  *)
(* that spec proves the CONVERGENT cell-sealed envelope (the multi-node       *)
(* unseal layer) + version negotiation; THIS spec proves the per-BODY seal    *)
(* treatments an Op may carry INSIDE that envelope. Green under TLC before    *)
(* any Rust for pillar-wire / the seal primitives.                            *)
(*                                                                          *)
(* THE THREE SEAL TREATMENTS (operator-directed, 2026-09-09)                  *)
(*                                                                          *)
(* The transport-frame seal (PillarUdpEncryption.tla) and the PillarMessage   *)
(* content seal (PillarMessageFormat.tla) are BOTH convergent: a datagram and *)
(* a PillarMessage each fan out to MULTIPLE nodes that must ALL unseal, so     *)
(* their key is portable/convergent and identical content is byte-identical   *)
(* (redundant-datagram / duplicate dedup). This spec models what a body may    *)
(* be once a cell node opens the PillarMessage:                               *)
(*                                                                          *)
(*   (1) CELL  -- a StreamOp / Signal, or the cell WRAPPER of a direct-message *)
(*       Op: convergently cell-sealed. Cid is a pure function of              *)
(*       (cell, content) -- NO per-message entropy -- so identical (cell,      *)
(*       content) records DEDUPE across the many cell nodes that hold them.    *)
(*   (2) RCPT  -- the CONTENTS of a UserMessage / NodeMessage / KeyOffer Op,   *)
(*       random-sealed to ONE recipient principal and referenced by Cid from a *)
(*       cell wrapper. Only the recipient unseals (not a fan-out) and the      *)
(*       message is unique/canonical, so the seal binds per-message ENTROPY:   *)
(*       same (prin, content) under a different draw is a DIFFERENT record and  *)
(*       is NOT deduped -- identical-text messages at different times are       *)
(*       distinct messages. Exactly-once coordination is an APPLICATION-layer   *)
(*       concern (a CP streamdb / other primitive), NOT the wire format.       *)
(*   (3) PLAIN -- an UNENCRYPTED body (e.g. a libp2p control message): sealed   *)
(*       once by the transport, not content-addressed for confidentiality;     *)
(*       anyone holding the bytes reads it, no cell/principal key required.     *)
(*                                                                          *)
(* Proven by TLC:                                                            *)
(*   Safety   : TypeOK, OneRecordFormat, DedupByCid, ConvergentCellDedup,     *)
(*              RcptRandomDistinctByEntropy, CellConfidential,               *)
(*              RcptOpaqueToNonHolder                                        *)
(*   Assumed  : RcptSealInjective (AEAD nonce-reuse safety for the random seal)*)
(*   Liveness : PlainReadableWithoutKey (an unencrypted body is readable by a  *)
(*              party holding NO cell or principal key)                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

\* Model values (declared individually so holder sets can name them; the cfg
\* format admits sets of model values but NOT <<tuple>> literals, so key-holding
\* is expressed as one agent-set per key rather than a relation of pairs).
CONSTANTS
    a1, a2, a3,    \* agents: a1 holds cell cA, a2 holds cell cB + principal pn,
                   \*         a3 holds NOTHING (no-key witness)
    cA, cB,        \* cell ids (each has a convergent group key)
    pu, pn,        \* recipient principals: pu external (held by nobody), pn held by a2
    Contents,      \* logical plaintext contents
    Entropies,     \* per-message random-seal draws (a UserMessage Op's nonce)
    holdersCA,     \* SUBSET Agents : who holds cell cA's group key
    holdersCB,     \* SUBSET Agents : who holds cell cB's group key
    holdersPU,     \* SUBSET Agents : who holds principal pu's key
    holdersPN      \* SUBSET Agents : who holds principal pn's key

Agents == {a1, a2, a3}
Cells  == {cA, cB}
Prins  == {pu, pn}

HoldsCell(a, c) == \/ (c = cA /\ a \in holdersCA)
                   \/ (c = cB /\ a \in holdersCB)
HoldsPrin(a, p) == \/ (p = pu /\ a \in holdersPU)
                   \/ (p = pn /\ a \in holdersPN)

ASSUME NonEmpty == Contents # {} /\ Entropies # {}
\* the liveness witness needs a party holding NO key at all
ASSUME HasNoKeyAgent ==
    \E a \in Agents : /\ \A c \in Cells : ~HoldsCell(a, c)
                      /\ \A p \in Prins : ~HoldsPrin(a, p)

\* ---- the three body treatments as content-addressed records ----------------
CellRec(c, m)    == [kind |-> "cell",  cell |-> c, content |-> m]
RcptRec(p, m, e) == [kind |-> "rcpt",  prin |-> p, content |-> m, ent |-> e]
PlainRec(m)      == [kind |-> "plain", content |-> m]

Env == [kind: {"cell"},  cell: Cells, content: Contents]
     \cup [kind: {"rcpt"},  prin: Prins, content: Contents, ent: Entropies]
     \cup [kind: {"plain"}, content: Contents]

\* Ciphertext identity (an opaque AEAD output). CONVERGENT for cell (a pure
\* function of (cell, content), no entropy); RANDOM for rcpt (binds the per-
\* message entropy draw); ABSENT for plain (the plaintext bytes themselves).
Ct(r) == CASE r.kind = "cell"  -> <<"ct-cell", r.cell, r.content>>
           [] r.kind = "rcpt"  -> <<"ct-rcpt", r.prin, r.content, r.ent>>
           [] r.kind = "plain" -> <<"pt", r.content>>
Cid(r) == <<"cid", Ct(r)>>

VARIABLES
    store,       \* SUBSET Env : the shared content-addressed store / wire (a SET,
                 \*   so identical Cids collapse -- redundant / duplicate dedup)
    openedCell,  \* [Agents -> SUBSET (Cells \X Contents)] : cell bodies decrypted
    openedRcpt,  \* [Agents -> SUBSET (Prins \X Contents \X Entropies)] : rcpt opened
    readPlain    \* [Agents -> SUBSET Contents] : unencrypted bodies read

vars == <<store, openedCell, openedRcpt, readPlain>>

Init ==
    /\ store      = {}
    /\ openedCell = [a \in Agents |-> {}]
    /\ openedRcpt = [a \in Agents |-> {}]
    /\ readPlain  = [a \in Agents |-> {}]

------------------------------------------------------------------------------
(* ACTIONS *)

\* Authoring: a producer puts a sealed / plain record on the shared store. Guarded
\* to be non-stuttering (the record is not already present).
SealCell(c, m) ==
    /\ CellRec(c, m) \notin store
    /\ store' = store \cup {CellRec(c, m)}
    /\ UNCHANGED <<openedCell, openedRcpt, readPlain>>

SealRcpt(p, m, e) ==
    /\ RcptRec(p, m, e) \notin store
    /\ store' = store \cup {RcptRec(p, m, e)}
    /\ UNCHANGED <<openedCell, openedRcpt, readPlain>>

EmitPlain(m) ==
    /\ PlainRec(m) \notin store
    /\ store' = store \cup {PlainRec(m)}
    /\ UNCHANGED <<openedCell, openedRcpt, readPlain>>

\* Opening: the ONLY way to recover a sealed plaintext is a KEYED decrypt.
OpenCell(a) ==
    \E r \in store :
        /\ r.kind = "cell" /\ HoldsCell(a, r.cell)
        /\ <<r.cell, r.content>> \notin openedCell[a]
        /\ openedCell' = [openedCell EXCEPT ![a] = @ \cup {<<r.cell, r.content>>}]
        /\ UNCHANGED <<store, openedRcpt, readPlain>>

OpenRcpt(a) ==
    \E r \in store :
        /\ r.kind = "rcpt" /\ HoldsPrin(a, r.prin)
        /\ <<r.prin, r.content, r.ent>> \notin openedRcpt[a]
        /\ openedRcpt' = [openedRcpt EXCEPT ![a] = @ \cup {<<r.prin, r.content, r.ent>>}]
        /\ UNCHANGED <<store, openedCell, readPlain>>

\* An unencrypted body is readable by ANY agent -- NO key precondition.
ReadPlain(a) ==
    \E r \in store :
        /\ r.kind = "plain"
        /\ r.content \notin readPlain[a]
        /\ readPlain' = [readPlain EXCEPT ![a] = @ \cup {r.content}]
        /\ UNCHANGED <<store, openedCell, openedRcpt>>

Next ==
    \/ \E c \in Cells, m \in Contents : SealCell(c, m)
    \/ \E p \in Prins, m \in Contents, e \in Entropies : SealRcpt(p, m, e)
    \/ \E m \in Contents : EmitPlain(m)
    \/ \E a \in Agents : OpenCell(a)
    \/ \E a \in Agents : OpenRcpt(a)
    \/ \E a \in Agents : ReadPlain(a)

\* Fairness only drives the one liveness witness: a plain body eventually exists
\* and a no-key agent eventually reads it.
Fairness ==
    /\ \A m \in Contents : WF_vars(EmitPlain(m))
    /\ \A a \in Agents : WF_vars(ReadPlain(a))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY *)

TypeOK ==
    /\ store      \in SUBSET Env
    /\ openedCell \in [Agents -> SUBSET (Cells \X Contents)]
    /\ openedRcpt \in [Agents -> SUBSET (Prins \X Contents \X Entropies)]
    /\ readPlain  \in [Agents -> SUBSET Contents]

\* Every record on the store is one of the three envelope-body treatments.
OneRecordFormat == \A r \in store : r \in Env

\* Content-addressed: no two DISTINCT records share a Cid, so redundant copies
\* (sprayed datagrams, forwarded duplicates) collapse to one block by construction.
DedupByCid == \A r1, r2 \in store : Cid(r1) = Cid(r2) => r1 = r2

\* CONVERGENT cell seal: a cell record's Cid is a pure function of (cell, content)
\* -- identical (cell, content) always collapses to ONE Cid (dedup across the many
\* cell nodes that receive it), distinct (cell, content) never collides. This is
\* exactly what a random per-message nonce would BREAK, and why the multi-node
\* unseal layers are convergent.
ConvergentCellDedup ==
    \A c1, c2 \in Cells, m1, m2 \in Contents :
        Cid(CellRec(c1, m1)) = Cid(CellRec(c2, m2)) <=> (c1 = c2 /\ m1 = m2)
ASSUME ConvergentCellDedupHolds == ConvergentCellDedup

\* RANDOM recipient seal: a UserMessage Op's contents with the SAME (prin, content)
\* but a DIFFERENT per-message entropy draw are DISTINCT records with DISTINCT Cids
\* -- identical-text direct messages at different times are separate messages, NOT
\* deduped. (Exactly-once is an application-layer concern, not the wire format.)
RcptRandomDistinctByEntropy ==
    \A p \in Prins, m \in Contents, e1, e2 \in Entropies :
        e1 # e2 => Cid(RcptRec(p, m, e1)) # Cid(RcptRec(p, m, e2))
ASSUME RcptRandomDistinctHolds == RcptRandomDistinctByEntropy

\* Only a cell-key holder ever recovers a cell-sealed body.
CellConfidential ==
    \A a \in Agents : \A pr \in openedCell[a] : HoldsCell(a, pr[1])

\* Only the recipient principal's key-holder ever recovers a recipient-sealed body:
\* a cell member WITHOUT that principal's key (and any external party) holds only
\* the referenced ciphertext. This is the whole point of nesting a random recipient
\* seal inside a cell-sealed Op -- the cell coordinates delivery without reading it.
RcptOpaqueToNonHolder ==
    \A a \in Agents : \A t \in openedRcpt[a] : HoldsPrin(a, t[1])

\* AEAD nonce-reuse safety for the random seal: the ciphertext identity is injective
\* in (prin, content, entropy), so one draw never seals two distinct plaintexts to
\* one recipient under one identity. A pure property of the derivation -> ASSUME.
RcptSealInjective ==
    \A p \in Prins, m1, m2 \in Contents, e1, e2 \in Entropies :
        Ct(RcptRec(p, m1, e1)) = Ct(RcptRec(p, m2, e2)) => (m1 = m2 /\ e1 = e2)
ASSUME RcptNonceSafe == RcptSealInjective

------------------------------------------------------------------------------
(* LIVENESS *)

NoKeyAgent ==
    CHOOSE a \in Agents : /\ \A c \in Cells : ~HoldsCell(a, c)
                          /\ \A p \in Prins : ~HoldsPrin(a, p)

\* An UNENCRYPTED body is eventually readable by a party holding NO cell or
\* principal key -- confirming a plain control message carries no confidentiality
\* obligation (it is protected, if at all, only by the one-shot transport seal).
PlainReadableWithoutKey == <>(\E m \in Contents : m \in readPlain[NoKeyAgent])

===============================================================================
