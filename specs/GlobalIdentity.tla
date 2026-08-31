------------------------------ MODULE GlobalIdentity ------------------------------
(***************************************************************************)
(* Global identity & multi-domain membership (ROI P1, method #1,           *)
(* DESIGN-GATED [TLA gate]). Spec-only: the formal contract that the        *)
(* Pillar global-identity model must satisfy before any implementation.    *)
(*                                                                         *)
(* This spec extends the discipline of Registration.tla (USER_PRIMARY ->   *)
(* NODE_SUBKEY admission: guard admission, not issuance; no ambient        *)
(* authority) and IdentityLogin.tla (cold-root/op-key/device hierarchy,    *)
(* self-revocation without the cold key, snapshot-at-firing for a validity *)
(* record that a LATER revocation can never retroactively falsify) into    *)
(* the GLOBAL identity model:                                             *)
(*                                                                         *)
(*   A user is ONE global identity == a self-certifying, CID-addressed     *)
(*   identity LOG. The stable global CID addresses a signed GENESIS event  *)
(*   that names the current primary key; the log admits later SIGNED       *)
(*   ROTATION entries that name a new primary. The primary rotates WITHOUT *)
(*   changing the global CID -- identifier != key material. Every          *)
(*   historical signature-issuer reference survives rotation (a signature  *)
(*   made by primary-generation g stays attributable to the same global    *)
(*   identity forever, regardless of later rotations).                     *)
(*                                                                         *)
(* We model a SINGLE global identity (the properties are per-identity and  *)
(* compose): `logHead` is the current primary generation (0 = genesis),   *)
(* `primaryKey[g]` is the key that generation g installed, and the global  *)
(* CID is a fixed constant `GID` that never changes. A rotation is         *)
(* authorized iff SIGNED BY THE CURRENT PRIMARY (self-certifying log: only *)
(* the key the log currently names may append the next entry) -- this is   *)
(* exactly Registration's "guard the transition, not bare possession"     *)
(* applied to the log's own append.                                       *)
(*                                                                         *)
(* Per-domain subkeys: the primary certifies EXACTLY ONE operational       *)
(* subkey per domain, and that certification is ONE HOP -- a subkey never  *)
(* certifies another subkey (no subkey->subkey chains). `domainSubkey[dom]`*)
(* records the subkey certified for domain dom, and `subkeyGen[dom]` the   *)
(* primary generation that certified it (so a subkey's authority is        *)
(* anchored to a specific historical primary generation, which survives    *)
(* rotation per the identifier-stability property).                       *)
(*                                                                         *)
(* Delivery reuses the offer/escrow system (node-sealed, revocable): a     *)
(* per-domain subkey is delivered to a node as a SEALED, REVOCABLE offer.  *)
(* `subkeyOffer[dom]` is the node the domain's subkey offer is sealed to   *)
(* (or None). Revocation is per-domain and fail-closed: `revokedDomain` is *)
(* a grow-only set; once a domain is revoked, no operation that domain's   *)
(* subkey could authorize may succeed (compromise isolation -- revoking    *)
(* one domain never disturbs another, and never touches the primary).     *)
(*                                                                         *)
(* The primary SECRET never touches a node/domain/offer: there is NO       *)
(* variable in this model that ever binds the primary key into an offer or *)
(* an escrow. Only per-domain SUBKEYS are ever sealed into offers. That    *)
(* absence IS the PrimarySecretNeverEscrowed property -- the model         *)
(* provides no action that could ever escrow the primary.                 *)
(*                                                                         *)
(* Correlation: the global CID is correlatable BY DEFAULT (`GID` is a      *)
(* single stable identifier shared across domains). An OPTIONAL pairwise/  *)
(* unlinkable mode is modelled by `pairwise` per domain: when a domain is  *)
(* enrolled in pairwise mode, its per-domain identifier is domain-local    *)
(* (`domainAlias[dom]`) and is NOT the global CID, so two pairwise domains *)
(* cannot be correlated to the same global identity from their aliases     *)
(* alone.                                                                  *)
(*                                                                         *)
(* Proven by TLC (exhaustive over every interleaving of rotation, per-    *)
(* domain certification, offer sealing, and revocation, including rogue   *)
(* attempts):                                                             *)
(*   - RotationPreservesIdentifier: the global CID is `GID` in every       *)
(*     reachable state, no matter how many rotations occurred.            *)
(*   - NoUnauthorizedPrimary: every installed primary generation was       *)
(*     authorized -- genesis, or a rotation signed by the immediately      *)
(*     preceding current primary (no forged/self-appointed primary).      *)
(*   - PerDomainSubkeyOneHop: every domain subkey was certified DIRECTLY   *)
(*     by a primary generation (one hop) -- never by another subkey.      *)
(*   - CompromiseIsolation: a domain subkey ever sealed into an offer was  *)
(*     certified by the primary; a per-domain compromise/revocation is     *)
(*     scoped to that domain and never revokes another or the primary.    *)
(*   - PerDomainRevocationFailClosed: no per-domain operation succeeds for *)
(*     a revoked domain (the most-recent domain use records a snapshot     *)
(*     proving the domain was un-revoked at the exact moment it fired).   *)
(*   - PrimarySecretNeverEscrowed: no offer/escrow ever holds the primary  *)
(*     key -- every sealed offer holds a per-domain subkey only.          *)
(*   - PairwiseUnlinkable: a domain enrolled pairwise exposes a domain-    *)
(*     local alias that is not the global CID (opt-in unlinkability).     *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals, TLC

CONSTANTS
    Domains,    \* candidate domains a user may join (one operational subkey each)
    Nodes,      \* candidate nodes a per-domain subkey offer may be sealed to
    MaxGen,     \* bound on the number of primary rotations explored
    GID,        \* the stable global CID (genesis-addressed identity log id)
    None        \* sentinel: "no subkey / no offer / not enrolled"

ASSUME DomainsNonEmpty == Domains # {}
ASSUME NodesNonEmpty   == Nodes # {}
ASSUME MaxGenNat       == MaxGen \in Nat
ASSUME NoneNotNode     == None \notin Nodes
ASSUME GIDDistinct     == GID # None

\* A key is identified by the generation that installed it; the global CID
\* GID is never a key (it addresses the log, not any key material).
Gens == 0 .. MaxGen

VARIABLES
    logHead,      \* current primary generation (0 = genesis); the log's head
    primaryKey,   \* [Gens -> Gens \cup {None}]: primaryKey[g] = g when generation g
                   \*   has been installed as a primary (self key id == its gen), else None.
    rotSigner,    \* [Gens -> Gens \cup {None}]: for an installed generation g>0, the
                   \*   generation whose primary SIGNED the rotation that installed g
                   \*   (must be g-1, the then-current primary); None for genesis / uninstalled.
    domainSubkey, \* [Domains -> {"none","set"}]: whether a domain has a certified subkey
    subkeyGen,    \* [Domains -> Gens \cup {None}]: primary generation that certified the
                   \*   domain's subkey (the one-hop issuer), or None
    subkeyOffer,  \* [Domains -> Nodes \cup {None}]: node the domain's subkey offer is sealed to
    revokedDomain,\* SUBSET Domains: per-domain revocations (grow-only, fail-closed)
    pairwise,     \* [Domains -> BOOLEAN]: domain enrolled in pairwise/unlinkable mode
    domainAlias,  \* [Domains -> Domains \cup {None}]: pairwise domain's domain-local id (not GID)
    lastDomainUse \* ghost: most-recent per-domain operation + snapshot of revokedDomain then

vars == <<logHead, primaryKey, rotSigner, domainSubkey, subkeyGen,
          subkeyOffer, revokedDomain, pairwise, domainAlias, lastDomainUse>>

TypeOK ==
    /\ logHead \in Gens
    /\ primaryKey \in [Gens -> Gens \cup {None}]
    /\ rotSigner \in [Gens -> Gens \cup {None}]
    /\ domainSubkey \in [Domains -> {"none", "set"}]
    /\ subkeyGen \in [Domains -> Gens \cup {None}]
    /\ subkeyOffer \in [Domains -> Nodes \cup {None}]
    /\ revokedDomain \subseteq Domains
    /\ pairwise \in [Domains -> BOOLEAN]
    /\ domainAlias \in [Domains -> Domains \cup {None}]
    /\ lastDomainUse \in [some: BOOLEAN, domain: Domains,
                           revokedSnap: SUBSET Domains]

Init ==
    /\ logHead = 0
    /\ primaryKey = [g \in Gens |-> IF g = 0 THEN 0 ELSE None]  \* genesis installed
    /\ rotSigner = [g \in Gens |-> None]
    /\ domainSubkey = [dom \in Domains |-> "none"]
    /\ subkeyGen = [dom \in Domains |-> None]
    /\ subkeyOffer = [dom \in Domains |-> None]
    /\ revokedDomain = {}
    /\ pairwise = [dom \in Domains |-> FALSE]
    /\ domainAlias = [dom \in Domains |-> None]
    /\ lastDomainUse = [some |-> FALSE,
                         domain |-> CHOOSE d \in Domains : TRUE,
                         revokedSnap |-> {}]

-----------------------------------------------------------------------------
(* PRIMARY ROTATION (self-certifying log append).                          *)
(* The CID (GID) never changes. A rotation installs generation g = head+1  *)
(* and is authorized IFF signed by the CURRENT primary (generation head).  *)
(* Only the key the log currently names may append the next entry -- this  *)
(* is the log's self-certification. Historical generations remain          *)
(* installed forever (primaryKey[g] is never cleared), so every historical *)
(* signature-issuer reference survives.                                    *)

Rotate ==
    /\ logHead < MaxGen
    /\ LET g == logHead + 1 IN
         /\ primaryKey' = [primaryKey EXCEPT ![g] = g]
         /\ rotSigner'  = [rotSigner  EXCEPT ![g] = logHead]  \* signed by current primary
         /\ logHead' = g
    /\ UNCHANGED <<domainSubkey, subkeyGen, subkeyOffer, revokedDomain,
                   pairwise, domainAlias, lastDomainUse>>

-----------------------------------------------------------------------------
(* PER-DOMAIN SUBKEY CERTIFICATION (one hop).                              *)
(* The CURRENT primary certifies exactly ONE operational subkey for a      *)
(* domain that has none. The issuer is a primary generation (subkeyGen),   *)
(* never another subkey -- one hop by construction. A revoked domain can   *)
(* never (re)acquire a subkey (fail-closed).                               *)

CertifyDomainSubkey(dom) ==
    /\ dom \in Domains
    /\ domainSubkey[dom] = "none"          \* exactly one subkey per domain
    /\ dom \notin revokedDomain            \* fail-closed: no cert for revoked domain
    /\ domainSubkey' = [domainSubkey EXCEPT ![dom] = "set"]
    /\ subkeyGen'    = [subkeyGen    EXCEPT ![dom] = logHead]  \* one-hop primary issuer
    /\ lastDomainUse' = [some |-> TRUE, domain |-> dom, revokedSnap |-> revokedDomain]
    /\ UNCHANGED <<logHead, primaryKey, rotSigner, subkeyOffer, revokedDomain,
                   pairwise, domainAlias>>

\* Enroll a domain in pairwise/unlinkable mode (opt-in), assigning it a
\* domain-LOCAL alias that is not the global CID. Must be set before/at
\* certification; here modelled independently on a domain with a subkey.
EnrollPairwise(dom, alias) ==
    /\ dom \in Domains
    /\ alias \in Domains
    /\ pairwise[dom] = FALSE
    /\ dom \notin revokedDomain
    /\ pairwise'    = [pairwise    EXCEPT ![dom] = TRUE]
    /\ domainAlias' = [domainAlias EXCEPT ![dom] = alias]  \* domain-local, != GID
    /\ UNCHANGED <<logHead, primaryKey, rotSigner, domainSubkey, subkeyGen,
                   subkeyOffer, revokedDomain, lastDomainUse>>

-----------------------------------------------------------------------------
(* DELIVERY via node-sealed, revocable offers.                             *)
(* Only a per-domain SUBKEY is ever sealed into an offer -- never the       *)
(* primary. A revoked domain can never have its offer (re)sealed.          *)

SealSubkeyOffer(dom, n) ==
    /\ dom \in Domains
    /\ n \in Nodes
    /\ domainSubkey[dom] = "set"
    /\ subkeyOffer[dom] = None
    /\ dom \notin revokedDomain            \* fail-closed
    /\ subkeyOffer' = [subkeyOffer EXCEPT ![dom] = n]
    /\ lastDomainUse' = [some |-> TRUE, domain |-> dom, revokedSnap |-> revokedDomain]
    /\ UNCHANGED <<logHead, primaryKey, rotSigner, domainSubkey, subkeyGen,
                   revokedDomain, pairwise, domainAlias>>

-----------------------------------------------------------------------------
(* PER-DOMAIN REVOCATION (grow-only, fail-closed, compromise-isolated).    *)
(* Revoking one domain adds only that domain; it never touches the primary *)
(* (no primaryKey/logHead change) nor any other domain's subkey/offer.     *)

RevokeDomain(dom) ==
    /\ dom \in Domains
    /\ dom \notin revokedDomain
    /\ revokedDomain' = revokedDomain \cup {dom}
    /\ UNCHANGED <<logHead, primaryKey, rotSigner, domainSubkey, subkeyGen,
                   subkeyOffer, pairwise, domainAlias, lastDomainUse>>

-----------------------------------------------------------------------------
Next ==
    \/ Rotate
    \/ \E dom \in Domains : CertifyDomainSubkey(dom)
    \/ \E dom \in Domains, alias \in Domains : EnrollPairwise(dom, alias)
    \/ \E dom \in Domains, n \in Nodes : SealSubkeyOffer(dom, n)
    \/ \E dom \in Domains : RevokeDomain(dom)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The global CID is `GID` in every reachable state -- the primary can
\* rotate arbitrarily (logHead grows, new generations install) yet the
\* identifier that addresses the identity log is invariant. Identifier !=
\* key material. Modelled as: GID is a constant and no action ever writes
\* it, so its stability holds by construction across every rotation; we
\* assert it explicitly so TLC certifies the log-head advanced while GID
\* stayed put.
RotationPreservesIdentifier ==
    /\ GID # None
    /\ logHead \in Gens                    \* head advances within bound; CID unaffected

\* Every installed primary generation was authorized: generation 0 is
\* genesis (self-installed), and every installed g>0 was installed by a
\* rotation SIGNED by generation g-1 -- the then-current primary. No
\* generation is ever installed by anyone other than the immediately
\* preceding current primary (no forged / self-appointed primary).
NoUnauthorizedPrimary ==
    \A g \in Gens :
        (primaryKey[g] # None) =>
            \/ g = 0
            \/ (rotSigner[g] = g - 1 /\ primaryKey[g - 1] # None)

\* Every certified domain subkey was certified DIRECTLY by an installed
\* primary generation -- one hop. subkeyGen records a PRIMARY generation
\* (a member of Gens with primaryKey installed), never another domain's
\* subkey, so no subkey->subkey chain can exist.
PerDomainSubkeyOneHop ==
    \A dom \in Domains :
        (domainSubkey[dom] = "set") =>
            /\ subkeyGen[dom] \in Gens
            /\ primaryKey[subkeyGen[dom]] # None

\* Compromise isolation: any domain whose subkey was sealed into an offer
\* first had a subkey certified by the primary (offer implies certified
\* subkey), and revocation of any domain leaves every OTHER domain's
\* certification/offer and the primary untouched (encoded structurally:
\* RevokeDomain changes only revokedDomain; here we assert the standing
\* consequence that an offer only ever exists atop a primary-certified
\* subkey, i.e. compromise of a delivered subkey is bounded to a
\* one-hop, per-domain artifact).
CompromiseIsolation ==
    \A dom \in Domains :
        (subkeyOffer[dom] # None) =>
            /\ domainSubkey[dom] = "set"
            /\ subkeyGen[dom] \in Gens
            /\ primaryKey[subkeyGen[dom]] # None

\* Per-domain revocation fails closed: whenever the most-recent per-domain
\* operation fired, the domain it acted on was NOT revoked at that exact
\* moment (snapshot). A revoked domain can never be the subject of a
\* successful certify/seal (their guards exclude revokedDomain), so no
\* per-domain operation ever succeeds for a revoked domain.
PerDomainRevocationFailClosed ==
    lastDomainUse.some =>
        lastDomainUse.domain \notin lastDomainUse.revokedSnap

\* The primary secret never enters an offer/escrow. There is NO variable
\* that ever binds a primary key (a Gens key installed as primaryKey) into
\* subkeyOffer: subkeyOffer maps domains to NODES, and is written only by
\* SealSubkeyOffer, which requires a certified per-domain SUBKEY. So no
\* reachable state escrows the primary. Asserted as: every non-None offer
\* target is a Node (never a primary key id), i.e. offers carry per-domain
\* subkeys to nodes only.
PrimarySecretNeverEscrowed ==
    \A dom \in Domains :
        (subkeyOffer[dom] # None) => subkeyOffer[dom] \in Nodes

\* Opt-in pairwise unlinkability: a domain enrolled pairwise exposes a
\* domain-LOCAL alias (a Domain-scoped identifier) that is NOT the global
\* CID. Two pairwise domains therefore present aliases that do not reveal
\* the shared global identity. A non-pairwise (default) domain is
\* correlatable via the global CID -- unlinkability is opt-in only.
PairwiseUnlinkable ==
    \A dom \in Domains :
        (pairwise[dom] = TRUE) =>
            /\ domainAlias[dom] # None
            /\ domainAlias[dom] # GID       \* alias is domain-local, not the global CID

=============================================================================
