------------------------------ MODULE IPAM ------------------------------
(***************************************************************************)
(* Pillar IPAM: allocation of addresses from a delegated pool (ROI P3,      *)
(* distributed-authority, method #1).                                      *)
(*                                                                         *)
(* An address must never be handed to two actors at once -- that is a       *)
(* duplicate-IP outage, not a benign race.  Rather than invent a bespoke     *)
(* allocation protocol, IPAM allocation is modelled as a DIRECT INSTANCE of  *)
(* the ONE coordination core (CoordinationCore.tla): each address in the     *)
(* delegated pool plays the role of an "epoch" slot, and "acquiring epoch e" *)
(* is exactly "allocating address e" -- a candidate/actor may only become    *)
(* the allocator of an address once a QUORUM of voters has granted it that   *)
(* address, and any two quorums intersect, so no two actors can ever be       *)
(* granted the same address by a majority simultaneously.                    *)
(*                                                                         *)
(* This is the same technique StreamingDB.tla uses to compose the CP lease   *)
(* protocol with the AP op-log: instantiate CoordinationCore over the         *)
(* concrete resource (there, a lease epoch guarding an exclusive side        *)
(* effect; here, one address per pool slot) and re-export its invariant       *)
(* under IPAM's own vocabulary.  Safety proven by TLC:                        *)
(* NoDoubleAllocation (renamed AtMostOneHolderPerEpoch), GrantsAreFenced.     *)
(*                                                                         *)
(* Out of scope here (spec-only, allocation guard): address release/         *)
(* re-allocation, and the pool-delegation handshake itself (which subdivides *)
(* a parent pool to a child authority) -- both are left to the Rust           *)
(* refinement (ipam-impl) and, if warranted, a follow-up spec.               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Actors,     \* set of participating actor identities (allocators)
    MaxAddr,    \* model bound: the delegated pool is addresses 0 .. MaxAddr
    None        \* sentinel: "no actor" (a model value, distinct from Actors)

ASSUME ActorsNonEmpty == Actors # {}
ASSUME MaxAddrIsNat   == MaxAddr \in Nat
ASSUME NoneNotActor   == None \notin Actors

\* The delegated pool: every address this authority may hand out.
Addrs == 0 .. MaxAddr

VARIABLES
    grantedAddr,  \* grantedAddr[v] : highest address voter v has granted in
    grantedTo,    \* grantedTo[v]   : actor v backed for grantedAddr[v] (or None)
    allocations   \* set of <<actor, addr>> pairs that have been allocated

vars == <<grantedAddr, grantedTo, allocations>>

\* Instance of the coordination core with "epoch" specialised to "address":
\* granting/acquiring an epoch e is granting/acquiring address e from the pool.
CC == INSTANCE CoordinationCore WITH
    Nodes        <- Actors,
    MaxEpoch     <- MaxAddr,
    None         <- None,
    grantedEpoch <- grantedAddr,
    grantedTo    <- grantedTo,
    holders      <- allocations

Init == CC!Init
Next == CC!Next
Spec == CC!Spec

------------------------------------------------------------------------------
(* TYPE CORRECTNESS *)

TypeOK == CC!TypeOK

------------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* No two distinct actors ever hold (are allocated) the same address from the
\* delegated pool.  This is the direct duplicate-IP exclusion, re-exported
\* verbatim from CoordinationCore's AtMostOneHolderPerEpoch.
NoDoubleAllocation == CC!AtMostOneHolderPerEpoch

\* A voter never backs two different actors for the same address.
GrantsAreFenced == CC!GrantsAreFenced

=============================================================================
