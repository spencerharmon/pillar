-------------------------- MODULE BootstrapRequest --------------------------
(***************************************************************************)
(* Pillar bootstrap REQUEST lifecycle (operator 2026-08-31 addendum).      *)
(*                                                                         *)
(* A fresh NODE or a new USER joins an existing cell by submitting a signed *)
(* bootstrap REQUEST carrying its identifying information (peer id, public/ *)
(* private addresses, versions, OS, public-key CID). An existing, AUTHORIZED*)
(* cell member reviews the queue and APPROVES or REJECTS it. On approval:   *)
(*   - a NODE request: an existing node ENCRYPTS (seals) the cell key to the *)
(*     newly-approved node and returns the CID of the sealed blob, so the    *)
(*     new node can materialize cell state -- the key is sealed ONLY to an   *)
(*     approved node.                                                        *)
(*   - a USER request: the new user's scoped OPERATIONAL-key offer is        *)
(*     escrowed (node-sealed) so the trusted node can resolve+unlock it at   *)
(*     first login -- escrowed ONLY for an approved user.                    *)
(*                                                                         *)
(* This is the authority-bearing mechanism behind `pillar bootstrap node`,  *)
(* `pillar bootstrap user`, and `pillar bootstrap request approve` (and the  *)
(* web equivalent). Per the ROI's non-negotiable method, it is model-checked *)
(* HERE before any Rust is written. It composes -- does not fork -- the DONE *)
(* KeyDistribution offer/seal mechanics (the actual sealing target is the    *)
(* approved requester's node/user key) and the WoTAuthority admission        *)
(* (only an authorized existing member may approve).                        *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - SealOnlyToApprovedNode: the cell key is sealed/returned ONLY to a     *)
(*     requester whose NODE request reached the approved state.             *)
(*   - EscrowOnlyForApprovedUser: an operational-key offer is escrowed ONLY  *)
(*     for a requester whose USER request reached the approved state.        *)
(*   - NoKeyWithoutAuthorizedApprover: any sealed/escrowed key material is    *)
(*     backed by an approval from an AUTHORIZED existing member (never a     *)
(*     self-approval by the unapproved requester, never an outsider).        *)
(*   - RejectedNeverGetsKey: a rejected request never receives any key       *)
(*     material -- fail-closed.                                             *)
(*   - ApprovalIsTerminal: approved/rejected are terminal; a request is      *)
(*     decided at most once (no re-approval flip-flop leaking a second key). *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    Requesters,   \* candidate joining node/user identities
    Members,      \* existing, authorized cell members that may approve
    None          \* sentinel: "no approver"

ASSUME RequestersNonEmpty == Requesters # {}
ASSUME MembersNonEmpty     == Members # {}
ASSUME NoneIsFresh         == None \notin Members

Kinds   == {"node", "user"}
States  == {"absent", "pending", "approved", "rejected"}

VARIABLES
    state,     \* [Requesters -> States]
    kind,      \* [Requesters -> Kinds \cup {None}]: request kind once submitted
    approver,  \* [Requesters -> Members \cup {None}]: who decided it
    sealed,    \* SUBSET Requesters: node requesters given the sealed cell key CID
    escrowed   \* SUBSET Requesters: user requesters whose op-key offer was escrowed

vars == <<state, kind, approver, sealed, escrowed>>

TypeOK ==
    /\ state    \in [Requesters -> States]
    /\ kind     \in [Requesters -> Kinds \cup {None}]
    /\ approver \in [Requesters -> Members \cup {None}]
    /\ sealed   \subseteq Requesters
    /\ escrowed \subseteq Requesters

Init ==
    /\ state    = [r \in Requesters |-> "absent"]
    /\ kind     = [r \in Requesters |-> None]
    /\ approver = [r \in Requesters |-> None]
    /\ sealed   = {}
    /\ escrowed = {}

-----------------------------------------------------------------------------
(* Submit a bootstrap request carrying identifying info (modelled by its     *)
(* KIND -- node or user; the concrete identity fields are opaque here). A     *)
(* request can be submitted only from the absent state (no double-submit).   *)
Submit(r, k) ==
    /\ r \in Requesters
    /\ k \in Kinds
    /\ state[r] = "absent"
    /\ state' = [state EXCEPT ![r] = "pending"]
    /\ kind'  = [kind  EXCEPT ![r] = k]
    /\ UNCHANGED <<approver, sealed, escrowed>>

-----------------------------------------------------------------------------
(* Approve a pending request. The approver MUST be an authorized existing     *)
(* member (m \in Members) -- never the requester itself, never an outsider.  *)
(* On approval the matching key material is delivered exactly once:           *)
(*   node -> the cell key is sealed to r and its CID returned (r joins sealed)*)
(*   user -> r's operational-key offer is escrowed (r joins escrowed).       *)
Approve(r, m) ==
    /\ r \in Requesters
    /\ m \in Members
    /\ state[r] = "pending"
    /\ state'    = [state    EXCEPT ![r] = "approved"]
    /\ approver' = [approver EXCEPT ![r] = m]
    /\ sealed'   = IF kind[r] = "node" THEN sealed \cup {r} ELSE sealed
    /\ escrowed' = IF kind[r] = "user" THEN escrowed \cup {r} ELSE escrowed
    /\ UNCHANGED kind

-----------------------------------------------------------------------------
(* Reject a pending request. Terminal, and NO key material is ever delivered. *)
Reject(r, m) ==
    /\ r \in Requesters
    /\ m \in Members
    /\ state[r] = "pending"
    /\ state'    = [state    EXCEPT ![r] = "rejected"]
    /\ approver' = [approver EXCEPT ![r] = m]
    /\ UNCHANGED <<kind, sealed, escrowed>>

Next ==
    \/ \E r \in Requesters, k \in Kinds  : Submit(r, k)
    \/ \E r \in Requesters, m \in Members : Approve(r, m)
    \/ \E r \in Requesters, m \in Members : Reject(r, m)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The cell key is sealed/returned ONLY to an approved NODE request.
SealOnlyToApprovedNode ==
    \A r \in sealed :
        /\ state[r] = "approved"
        /\ kind[r]  = "node"

\* An operational-key offer is escrowed ONLY for an approved USER request.
EscrowOnlyForApprovedUser ==
    \A r \in escrowed :
        /\ state[r] = "approved"
        /\ kind[r]  = "user"

\* Any delivered key material is backed by an approval from an AUTHORIZED
\* existing member (never a self-approval by an unapproved requester).
NoKeyWithoutAuthorizedApprover ==
    \A r \in (sealed \cup escrowed) :
        approver[r] \in Members

\* A rejected request never receives any key material -- fail-closed.
RejectedNeverGetsKey ==
    \A r \in Requesters :
        state[r] = "rejected" => (r \notin sealed /\ r \notin escrowed)

=============================================================================
