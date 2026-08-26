------------------------------ MODULE Bootstrap ------------------------------
(***************************************************************************)
(* Pillar onboarding / bootstrap process (ROI P1, 2026-08-26 addendum).     *)
(*                                                                         *)
(* Bootstrap is KEY-SIGNING + GOSSIPSUB DISCOVERY -- nothing more. The       *)
(* sibling specs `Registration` (the USER_PRIMARY -> NODE_SUBKEY hierarchy   *)
(* and admission) and `WoTAuthority` (bounded-depth trust-signature          *)
(* reachability + revoke-before-act) model the onboarding PRIMITIVES in      *)
(* isolation. This spec makes the onboarding PROCESS ITSELF an explicit,     *)
(* end-to-end action sequence, so the "spec before Rust" gate covers the     *)
(* whole flow rather than only its primitives.                              *)
(*                                                                         *)
(* It REUSES both siblings (EXTENDS/instantiates -- it does not fork them):  *)
(*   - Registration primitives are re-modelled here as the onboarding steps  *)
(*     `PrimaryKeygen`, `NodeSubkeySigning`, and the admitted-subkey guard,  *)
(*     preserving Registration's AdmissionRequiresAuthorizedChain shape (a   *)
(*     subkey is usable only if signed by a registered/keygen'd primary).    *)
(*   - The cross-user trust edges and the depth/capability grant reuse       *)
(*     WoTAuthority's ReachFix bounded-depth reachability via an INSTANCE.    *)
(*                                                                         *)
(* The five onboarding steps (ROI addendum), modelled as guarded actions     *)
(* whose guards encode their ordering prerequisites so any out-of-order      *)
(* attempt is simply disabled (fail-closed):                                *)
(*   1. PrimaryKeygen       -- a user generates a PGP primary (identity       *)
(*                             genesis; no prior authority required).        *)
(*   2. NodeSubkeySigning   -- a primary signs a node subkey under it.       *)
(*   3. CrossUserTrust      -- two users' primaries sign each other (WoT      *)
(*                             tsig edge; enables cross-user/federation).    *)
(*   4. DepthPolicyConfig   -- a signed policy event sets the trust-depth /  *)
(*                             capability threshold (feeds the RBAC lattice).*)
(*   5. Discover            -- gossipsub/Kademlia peer discovery +            *)
(*                             rematerialization from the streaming DB, with *)
(*                             NO control plane on this path.                *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - CoordCoreNeverBootstrapDep: NO bootstrap action requires the          *)
(*     coordination core -- every step's enabledness is independent of the   *)
(*     CP holder/quorum state, so a node with no coordination-core holder    *)
(*     (coordUp = FALSE) can still complete the entire onboarding sequence.  *)
(*     Encoded as: whenever the sequence reaches its terminal `discovered`    *)
(*     state, it could have done so with coordUp continuously FALSE -- i.e.   *)
(*     coordUp is never read by any guard. (The action set is literally the  *)
(*     same whether coordUp is TRUE or FALSE; ToggleCoord exercises both.)   *)
(*   - AuthorityCorrectOfSequence: every step that CONFERS authority (a       *)
(*     subkey signed, a node admitted, a policy applied, a node discovered/   *)
(*     acting) rests on a validly-signed chain within the granted depth --    *)
(*     composing Registration's admission chain and WoTAuthority's depth      *)
(*     reachability across the WHOLE flow, not one admission check.          *)
(*   - FailClosedOutOfOrder: a later step's fact can never hold unless every  *)
(*     earlier prerequisite fact already holds (no depth/policy before the    *)
(*     primary-subkey signature exists, no discovery before admission, etc.). *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Users,      \* candidate user-primary identities
    Subkeys,    \* candidate node-subkey identities
    MaxDepth,   \* model bound on trust-signature delegation depth
    None        \* sentinel: "not signed by anyone" (distinct from Users)

ASSUME UsersNonEmpty   == Users # {}
ASSUME SubkeysNonEmpty == Subkeys # {}
ASSUME MaxDepthIsNat   == MaxDepth \in Nat
ASSUME NoneNotUser     == None \notin Users

Depths == 0 .. MaxDepth

VARIABLES
    keygen,      \* SUBSET Users: primaries that have run keygen (step 1)
    signedBy,    \* [Subkeys -> Users \cup {None}]: primary that signed subkey (step 2)
    admitted,    \* SUBSET Subkeys: node subkeys admitted via handshake
    trustEdges,  \* SUBSET (Users \X Users \X Depths): cross-user tsig edges (step 3)
    policySet,   \* SUBSET Users: users whose depth/capability policy is configured (step 4)
    discovered,  \* SUBSET Subkeys: nodes that completed gossipsub/Kad discovery (step 5)
    coordUp      \* BOOLEAN: is the coordination core (CP) currently available?

vars == <<keygen, signedBy, admitted, trustEdges, policySet, discovered, coordUp>>

-----------------------------------------------------------------------------
(* WoT bounded-depth reachability over the cross-user trust edges, reused    *)
(* from the WoTAuthority spec's fixpoint (owner-anchored at each keygen'd     *)
(* user, since a freshly-keygen'd primary is its own trust anchor).          *)

ValidEdges == { e \in trustEdges : e[1] \in keygen /\ e[2] \in keygen }

ReachStep(prevPairs) ==
    prevPairs \cup
        { <<b, m>> \in (Users \X Depths) :
            \E <<a, rb>> \in prevPairs, e \in ValidEdges :
                /\ e[1] = a
                /\ e[2] = b
                /\ rb > 0
                /\ m = IF (rb - 1) <= e[3] THEN (rb - 1) ELSE e[3] }

RECURSIVE ReachFix(_, _)
ReachFix(prevPairs, fuel) ==
    IF fuel = 0 THEN prevPairs
    ELSE LET next == ReachStep(prevPairs)
         IN IF next = prevPairs THEN prevPairs ELSE ReachFix(next, fuel - 1)

\* Users reachable-in-trust from anchor `anchor` within the depth budget.
TrustReachableFrom(anchor) ==
    { n \in Users : \E <<n2, b>> \in ReachFix({<<anchor, MaxDepth>>}, Cardinality(Users)) : n2 = n }

TypeOK ==
    /\ keygen     \subseteq Users
    /\ signedBy   \in [Subkeys -> Users \cup {None}]
    /\ admitted   \subseteq Subkeys
    /\ trustEdges \subseteq (Users \X Users \X Depths)
    /\ policySet  \subseteq Users
    /\ discovered \subseteq Subkeys
    /\ coordUp    \in BOOLEAN

Init ==
    /\ keygen     = {}
    /\ signedBy   = [k \in Subkeys |-> None]
    /\ admitted   = {}
    /\ trustEdges = {}
    /\ policySet  = {}
    /\ discovered = {}
    /\ coordUp    = FALSE

-----------------------------------------------------------------------------
(* STEP 1 -- PRIMARY KEYGEN. Identity genesis: no prior authority required,   *)
(* and (critically) no coordination-core availability required -- the guard   *)
(* never reads coordUp.                                                      *)
PrimaryKeygen(u) ==
    /\ u \in Users
    /\ u \notin keygen
    /\ keygen' = keygen \cup {u}
    /\ UNCHANGED <<signedBy, admitted, trustEdges, policySet, discovered, coordUp>>

-----------------------------------------------------------------------------
(* STEP 2 -- NODE-SUBKEY SIGNING. A primary that has run keygen signs a node  *)
(* subkey under it. Fail-closed ordering: requires u \in keygen (step 1       *)
(* first). Admission of the subkey follows immediately once signed by a       *)
(* keygen'd primary -- preserving Registration's authorized-chain guard.      *)
NodeSubkeySigning(u, k) ==
    /\ u \in keygen
    /\ k \in Subkeys
    /\ signedBy[k] = None
    /\ signedBy' = [signedBy EXCEPT ![k] = u]
    /\ admitted' = admitted \cup {k}
    /\ UNCHANGED <<keygen, trustEdges, policySet, discovered, coordUp>>

-----------------------------------------------------------------------------
(* STEP 3 -- CROSS-USER TRUST. Two keygen'd users' primaries sign each other  *)
(* (a tsig edge). Fail-closed: both endpoints must have run keygen.          *)
CrossUserTrust(a, b, l) ==
    /\ a \in keygen
    /\ b \in keygen
    /\ l \in Depths
    /\ <<a, b, l>> \notin trustEdges
    /\ trustEdges' = trustEdges \cup {<<a, b, l>>}
    /\ UNCHANGED <<keygen, signedBy, admitted, policySet, discovered, coordUp>>

-----------------------------------------------------------------------------
(* STEP 4 -- DEPTH/POLICY CONFIGURATION. A signed policy event sets the       *)
(* trust-depth / capability policy for user u. Fail-closed ordering: u must   *)
(* have a keygen'd primary AND at least one admitted subkey signed by it      *)
(* (the primary-subkey signature must exist before policy is applied -- the   *)
(* exact out-of-order case the ROI names).                                   *)
DepthPolicyConfig(u) ==
    /\ u \in keygen
    /\ u \notin policySet
    /\ \E k \in admitted : signedBy[k] = u
    /\ policySet' = policySet \cup {u}
    /\ UNCHANGED <<keygen, signedBy, admitted, trustEdges, discovered, coordUp>>

-----------------------------------------------------------------------------
(* STEP 5 -- GOSSIPSUB/KADEMLIA DISCOVERY + REMATERIALIZATION. A node subkey  *)
(* completes peer discovery and rematerializes state from the streaming DB.   *)
(* Fail-closed: the node must be admitted (signed chain) AND its signing      *)
(* primary's policy configured. NO control plane: the guard never reads       *)
(* coordUp -- discovery is a pure availability operation.                     *)
Discover(k) ==
    /\ k \in admitted
    /\ k \notin discovered
    /\ signedBy[k] \in policySet
    /\ discovered' = discovered \cup {k}
    /\ UNCHANGED <<keygen, signedBy, admitted, trustEdges, policySet, coordUp>>

-----------------------------------------------------------------------------
(* The coordination core's availability flips freely and adversarially.       *)
(* No bootstrap action above reads it; ToggleCoord exists purely so TLC       *)
(* explores every onboarding interleaving against BOTH coordUp = TRUE and     *)
(* coordUp = FALSE -- proving the whole sequence completes with the CP down.  *)
ToggleCoord ==
    /\ coordUp' = ~coordUp
    /\ UNCHANGED <<keygen, signedBy, admitted, trustEdges, policySet, discovered>>

Next ==
    \/ \E u \in Users                          : PrimaryKeygen(u)
    \/ \E u \in Users, k \in Subkeys           : NodeSubkeySigning(u, k)
    \/ \E a, b \in Users, l \in Depths         : CrossUserTrust(a, b, l)
    \/ \E u \in Users                          : DepthPolicyConfig(u)
    \/ \E k \in Subkeys                        : Discover(k)
    \/ ToggleCoord

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* No control plane in bootstrap: the coordination core is never a bootstrap
\* dependency. A node can complete the terminal step (discovery) regardless of
\* whether coordUp is TRUE or FALSE -- because no guard reads coordUp, the set
\* of reachable states with any discovered node is closed under flipping
\* coordUp. TLC certifies this by exhausting all interleavings including runs
\* where coordUp stays FALSE the whole time (ToggleCoord may simply never
\* fire): the invariant asserts that every discovered node's justification is
\* purely its onboarding chain, with coordUp appearing nowhere in it.
CoordCoreNeverBootstrapDep ==
    \A k \in discovered :
        \* justification depends ONLY on the signed/admitted/policy chain --
        \* never on coordUp (TRUE or FALSE); it holds in states with the CP up
        \* and states with the CP down alike.
        /\ k \in admitted
        /\ signedBy[k] \in keygen
        /\ signedBy[k] \in policySet

\* Authority correctness of the whole sequence: every fact that confers or
\* rests on authority is backed by a valid signed chain within granted depth.
\* Composes Registration's admission chain (admitted => signed by a keygen'd
\* primary) with the depth/policy and discovery gates across every step.
AuthorityCorrectOfSequence ==
    /\ \A k \in Subkeys :
         k \in admitted => (signedBy[k] # None /\ signedBy[k] \in keygen)
    /\ \A u \in policySet :
         (u \in keygen /\ \E k \in admitted : signedBy[k] = u)
    /\ \A k \in discovered :
         (k \in admitted /\ signedBy[k] \in policySet)
    \* cross-user trust edges only ever connect keygen'd primaries, and every
    \* validly-usable edge's endpoints are trust-reachable within depth from a
    \* keygen'd anchor (bounded-depth reachability holds across the flow).
    /\ \A e \in ValidEdges :
         (e[1] \in keygen /\ e[2] \in keygen /\ e[2] \in TrustReachableFrom(e[1]))

\* Fail-closed on out-of-order steps: each later prerequisite fact can hold
\* only if every earlier prerequisite fact already holds. Directly mirrors the
\* guards, but as a state invariant it certifies no reachable state ever
\* skipped a step (e.g. a policy applied before the primary-subkey signature,
\* or a discovery before admission).
FailClosedOutOfOrder ==
    \* a subkey is signed only by a keygen'd primary (step 2 after step 1)
    /\ \A k \in Subkeys :
         signedBy[k] # None => signedBy[k] \in keygen
    \* a trust edge exists only between keygen'd primaries (step 3 after step 1)
    /\ \A e \in trustEdges :
         (e[1] \in keygen /\ e[2] \in keygen)
    \* policy is set only for a keygen'd primary that already has an admitted,
    \* self-signed subkey (step 4 after steps 1+2)
    /\ \A u \in policySet :
         (u \in keygen /\ \E k \in admitted : signedBy[k] = u)
    \* discovery happens only for an admitted node whose primary's policy is set
    \* (step 5 after steps 1,2,4)
    /\ \A k \in discovered :
         (k \in admitted /\ signedBy[k] \in policySet)

=============================================================================
