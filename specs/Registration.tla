------------------------------ MODULE Registration ------------------------------
(***************************************************************************)
(* Pillar identity: PGP key hierarchy and node admission.                  *)
(*                                                                         *)
(* Key hierarchy: USER_PRIMARY -> NODE_SUBKEY, with REGISTRATION marking a *)
(* user primary as authorized (an enrolled Pillar user). A node joins the  *)
(* cluster via a handshake that presents a NODE_SUBKEY; admission is       *)
(* granted iff that subkey carries a genuine signature chaining to a      *)
(* currently REGISTERED user primary.                                     *)
(*                                                                         *)
(* This is the formal contract behind Pillar's identity/PGP admission      *)
(* control (crates/pillar-identity, ROI P1, method #1). Two properties are *)
(* proven by TLC:                                                          *)
(*   - AdmissionRequiresAuthorizedChain: admitted => signed by a           *)
(*     registered primary (no forged/unauthorized-primary admission).      *)
(*   - NoAmbientAuthority: an unsigned subkey can never be admitted (mere  *)
(*     possession of a subkey identity confers no authority).              *)
(* Because `admitted` changes ONLY through the guarded Handshake action,   *)
(* TLC's exhaustive state-space search confirms there is no reachable path *)
(* -- via any interleaving of registration, subkey issuance (including by  *)
(* unregistered/rogue primaries), and handshakes -- that ever admits a     *)
(* subkey without a genuine, currently-authorized signature chain.        *)
(***************************************************************************)
EXTENDS FiniteSets, TLC

CONSTANTS
    Users,      \* candidate user-primary identities (some registered, some not)
    Subkeys,    \* candidate node-subkey identities presented at handshake
    None        \* sentinel: "subkey not (yet) signed by anyone"

ASSUME UsersNonEmpty   == Users # {}
ASSUME SubkeysNonEmpty == Subkeys # {}
ASSUME NoneNotUser     == None \notin Users

VARIABLES
    registered, \* set of Users holding a REGISTRATION record (authorized primaries)
    signedBy,   \* signedBy[k]: the User whose primary key actually signed subkey k, or None
    admitted    \* set of Subkeys admitted as node identities via handshake

vars == <<registered, signedBy, admitted>>

TypeOK ==
    /\ registered \subseteq Users
    /\ signedBy \in [Subkeys -> Users \cup {None}]
    /\ admitted \subseteq Subkeys

Init ==
    /\ registered = {}
    /\ signedBy   = [k \in Subkeys |-> None]
    /\ admitted   = {}

\* REGISTRATION: user primary u becomes authorized. Models the out-of-band
\* enrollment of a user primary key with Pillar. Any user may register --
\* the point of the model is that admission depends on THIS having happened,
\* not on any prerequisite for registration itself.
Register(u) ==
    /\ u \in Users
    /\ u \notin registered
    /\ registered' = registered \cup {u}
    /\ UNCHANGED <<signedBy, admitted>>

\* NODE_SUBKEY issuance: user primary u signs node subkey k, minting a
\* certificate. Deliberately unguarded by `registered`: an UNREGISTERED
\* (rogue/forged) primary can still mint a signature over a subkey. That
\* signature alone must never be sufficient for admission -- proving that is
\* exactly the point of AdmissionRequiresAuthorizedChain below.
IssueSubkey(u, k) ==
    /\ u \in Users
    /\ k \in Subkeys
    /\ signedBy[k] = None
    /\ signedBy' = [signedBy EXCEPT ![k] = u]
    /\ UNCHANGED <<registered, admitted>>

\* Handshake: a node presents subkey k for admission. This is the ONLY
\* action that can ever grow `admitted`, and its guard IS the admission
\* policy: k must carry a genuine signature (signedBy[k] # None -- no
\* ambient authority from bare possession) from a primary that is currently
\* registered (signedBy[k] \in registered -- no forged/unauthorized-primary
\* admission).
Handshake(k) ==
    /\ k \in Subkeys
    /\ k \notin admitted
    /\ signedBy[k] # None
    /\ signedBy[k] \in registered
    /\ admitted' = admitted \cup {k}
    /\ UNCHANGED <<registered, signedBy>>

Next ==
    \/ \E u \in Users : Register(u)
    \/ \E u \in Users, k \in Subkeys : IssueSubkey(u, k)
    \/ \E k \in Subkeys : Handshake(k)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The core admission theorem: a subkey is ever admitted only if it carries
\* a genuine signature chaining to a user primary that is registered
\* (authorized) at the time of admission. No other path to `admitted`
\* exists in this model, so TLC's exhaustive search over every interleaving
\* -- including rogue/unregistered primaries issuing subkey signatures --
\* certifies this holds in every reachable state.
AdmissionRequiresAuthorizedChain ==
    \A k \in Subkeys :
        k \in admitted => (signedBy[k] # None /\ signedBy[k] \in registered)

\* No ambient authority: mere existence/possession of a subkey identity is
\* never sufficient on its own -- an unsigned subkey can never be admitted.
NoAmbientAuthority ==
    \A k \in Subkeys : (signedBy[k] = None) => (k \notin admitted)

=============================================================================
