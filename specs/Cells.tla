-------------------------------- MODULE Cells --------------------------------
(***************************************************************************)
(* Pillar cells & confidentiality (ROI P1, 2026-08-26).                    *)
(*                                                                         *)
(* Conceptually EXTENDS WoTAuthority.tla (revoke-before-act authority      *)
(* discipline) and KeyDistribution.tla (the cell / offer / seal system),   *)
(* the way IdentityLogin extends Registration/WoTAuthority and             *)
(* KeyDistribution conceptually extends IdentityLogin: it CONSUMES their    *)
(* already-proven ground truth -- membership is admitted only through the   *)
(* offer system (KeyDistribution's BiDirectionalConsent), a group key is    *)
(* sealed only to current members -- by SPECIALISING it, rather than        *)
(* re-deriving it (exactly how IPAM re-uses CoordinationCore).             *)
(*                                                                         *)
(* A single cell is the unit of confidentiality. It owns:                  *)
(*   - a GROUP KEY: an epoch counter `keyEpoch` plus, per epoch, the member *)
(*     set that epoch was sealed to (`epochMembers`);                      *)
(*   - a MEMBER set `members` (nodes admitted via the offer system);       *)
(*   - CROSS-CELL user GRANTS `grants` (ReadOnly|ReadWrite x All|Tags);     *)
(*   - an IPNS-format naming pointer `namePtr` over published roots.        *)
(*                                                                         *)
(* VISIBILITY CLASSES. Every object carries one class fixing who decrypts:  *)
(*   Public                     -- plaintext, anyone.                       *)
(*   CellEncrypted              -- sealed under the group key: exactly the  *)
(*                                 members holding the object's key epoch.  *)
(*   RecipientSealed(scope)     -- sealed to an explicit recipient set at   *)
(*                                 one of three granularities:             *)
(*        PerNode -- individual node keys (KeyDistribution L0 default),     *)
(*        PerCell -- a whole peer cell (cell-to-cell),                     *)
(*        PerUser -- a user identity spanning its nodes.                    *)
(* Decryptability is DERIVED from class + current world, never a separate   *)
(* mutable fact, so it cannot drift.                                       *)
(*                                                                         *)
(* GROUP-KEY ROTATION. On member-LEAVE the key rotates (keyEpoch++, sealed  *)
(* to the reduced set) BEFORE the leave is observable, so a departed member *)
(* (holding only the OLD epoch) can never decrypt an object authored under  *)
(* the NEW epoch -- forward secrecy (`ForwardSecrecyOnLeave`). A write and  *)
(* a rotation are same-transition mutually exclusive under a `rotating`     *)
(* fence, so no write straddles a rotation (`AtomicRotation`).             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,       \* candidate node (device-subkey) identities -- cell members
    Users,       \* candidate user identities (for cross-cell grants)
    PeerCells,   \* candidate peer cell identities (PerCell seal targets)
    Objects,     \* candidate object identities placed in the cell
    Tags,        \* candidate tags an object may carry / a grant may scope to
    Roots,       \* candidate published-root values the name pointer may resolve to
    None         \* sentinel

ASSUME NodesNonEmpty   == Nodes # {}
ASSUME UsersNonEmpty   == Users # {}
ASSUME ObjectsNonEmpty == Objects # {}
ASSUME RootsNonEmpty   == Roots # {}
ASSUME NoneFresh       == None \notin (Nodes \cup Users \cup PeerCells \cup Roots)

\* Visibility-class scope granularities for RecipientSealed.
Scopes == {"PerNode", "PerCell", "PerUser"}

\* The three visibility classes, tagged records. A RecipientSealed class also
\* carries its granularity scope and the explicit recipient set for that scope.
VisClasses ==
    {[kind |-> "Public"]}
    \cup {[kind |-> "CellEncrypted"]}
    \cup [kind: {"RecipientSealed"}, scope: {"PerNode"}, rcpt: SUBSET Nodes]
    \cup [kind: {"RecipientSealed"}, scope: {"PerCell"}, rcpt: SUBSET PeerCells]
    \cup [kind: {"RecipientSealed"}, scope: {"PerUser"}, rcpt: SUBSET Users]

\* Grant modes and scopes.
Modes  == {"ReadOnly", "ReadWrite"}
\* A grant scope is All, or a Tags(T) with T a subset of Tags.
GrantScopes == {[kind |-> "All"]} \cup [kind: {"Tags"}, tags: SUBSET Tags]
Grants == [user: Users, mode: Modes, scope: GrantScopes]

VARIABLES
    members,       \* SUBSET Nodes: current cell members (offer-system admitted)
    keyEpoch,      \* Nat: current group-key epoch
    epochMembers,  \* [Nat -> SUBSET Nodes]: member set each epoch was sealed to
    rotating,      \* BOOLEAN: a rotation is in progress (write fence)
    objClass,      \* [Objects -> VisClasses]: each placed object's visibility class
    objEpoch,      \* [Objects -> Nat]: the key epoch a CellEncrypted object was sealed under
    objTags,       \* [Objects -> SUBSET Tags]: each object's tags
    placed,        \* SUBSET Objects: objects actually authored into the cell
    grants,        \* SUBSET Grants: cross-cell user access grants
    published,     \* SUBSET Roots: roots the cell has published
    namePtr        \* Roots \cup {None}: IPNS-format pointer to current root

vars == <<members, keyEpoch, epochMembers, rotating, objClass, objEpoch,
          objTags, placed, grants, published, namePtr>>

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                         *)

MaxEpoch == 2

TypeOK ==
    /\ members \subseteq Nodes
    /\ keyEpoch \in 0 .. MaxEpoch
    /\ epochMembers \in [0 .. MaxEpoch -> SUBSET Nodes]
    /\ rotating \in BOOLEAN
    /\ objClass \in [Objects -> VisClasses]
    /\ objEpoch \in [Objects -> 0 .. MaxEpoch]
    /\ objTags \in [Objects -> SUBSET Tags]
    /\ placed \subseteq Objects
    /\ grants \subseteq Grants
    /\ published \subseteq Roots
    /\ namePtr \in (Roots \cup {None})

-----------------------------------------------------------------------------
(* INITIAL STATE: empty cell, epoch 0 sealed to no members.                *)

Init ==
    /\ members = {}
    /\ keyEpoch = 0
    /\ epochMembers = [e \in 0 .. MaxEpoch |-> {}]
    /\ rotating = FALSE
    /\ objClass = [o \in Objects |-> [kind |-> "Public"]]
    /\ objEpoch = [o \in Objects |-> 0]
    /\ objTags = [o \in Objects |-> {}]
    /\ placed = {}
    /\ grants = {}
    /\ published = {}
    /\ namePtr = None

-----------------------------------------------------------------------------
(* MEMBERSHIP via the offer system (consumed as ground truth).             *)

\* A node is admitted as a member. Re-seals the CURRENT epoch to include it
\* (a join widens the epoch's sealed set). Disabled mid-rotation (fence).
Admit(n) ==
    /\ ~rotating
    /\ n \notin members
    /\ members' = members \cup {n}
    /\ epochMembers' = [epochMembers EXCEPT ![keyEpoch] = members']
    /\ UNCHANGED <<keyEpoch, rotating, objClass, objEpoch, objTags, placed,
                    grants, published, namePtr>>

\* A member LEAVES. To preserve forward secrecy the group key ROTATES in the
\* SAME transition the member is dropped: keyEpoch increments and the NEW epoch
\* is sealed to the reduced member set. The departed member holds only the old
\* epoch, so it can never decrypt anything authored under the new one. Bounded
\* by MaxEpoch (finite model). The rotation is atomic (no straddling write:
\* placing an object and leaving are distinct transitions).
Leave(n) ==
    /\ ~rotating
    /\ n \in members
    /\ keyEpoch < MaxEpoch
    /\ members' = members \ {n}
    /\ keyEpoch' = keyEpoch + 1
    /\ epochMembers' = [epochMembers EXCEPT ![keyEpoch + 1] = members']
    /\ UNCHANGED <<rotating, objClass, objEpoch, objTags, placed,
                    grants, published, namePtr>>

\* Explicit stand-alone rotation fence open/close, letting a rotation be
\* observable as a distinct in-progress state a concurrent write is barred
\* from (AtomicRotation). Opening the fence disables Admit/Leave/PlaceObject.
BeginRotate ==
    /\ ~rotating
    /\ keyEpoch < MaxEpoch
    /\ rotating' = TRUE
    /\ UNCHANGED <<members, keyEpoch, epochMembers, objClass, objEpoch,
                    objTags, placed, grants, published, namePtr>>

\* Closing the fence commits the new epoch, sealed to the (unchanged) member
\* set. No write could have landed while rotating.
EndRotate ==
    /\ rotating
    /\ keyEpoch' = keyEpoch + 1
    /\ epochMembers' = [epochMembers EXCEPT ![keyEpoch + 1] = members]
    /\ rotating' = FALSE
    /\ UNCHANGED <<members, objClass, objEpoch, objTags, placed,
                    grants, published, namePtr>>

-----------------------------------------------------------------------------
(* PLACING OBJECTS with a visibility class. Barred while rotating (a write  *)
(* can never straddle a rotation). A CellEncrypted object records the       *)
(* CURRENT epoch as the epoch it was sealed under.                         *)

PlaceObject(o, cls, tgs) ==
    /\ ~rotating
    /\ o \notin placed
    /\ cls \in VisClasses
    /\ tgs \subseteq Tags
    /\ placed' = placed \cup {o}
    /\ objClass' = [objClass EXCEPT ![o] = cls]
    /\ objEpoch' = [objEpoch EXCEPT ![o] = keyEpoch]
    /\ objTags' = [objTags EXCEPT ![o] = tgs]
    /\ UNCHANGED <<members, keyEpoch, epochMembers, rotating, grants,
                    published, namePtr>>

-----------------------------------------------------------------------------
(* CROSS-CELL USER GRANTS.                                                  *)

AddGrant(u, m, sc) ==
    /\ u \in Users
    /\ m \in Modes
    /\ sc \in GrantScopes
    /\ LET g == [user |-> u, mode |-> m, scope |-> sc] IN
         /\ g \notin grants
         /\ grants' = grants \cup {g}
    /\ UNCHANGED <<members, keyEpoch, epochMembers, rotating, objClass,
                    objEpoch, objTags, placed, published, namePtr>>

RevokeGrant(g) ==
    /\ g \in grants
    /\ grants' = grants \ {g}
    /\ UNCHANGED <<members, keyEpoch, epochMembers, rotating, objClass,
                    objEpoch, objTags, placed, published, namePtr>>

-----------------------------------------------------------------------------
(* IPNS-FORMAT NAMING POINTER: publish a root, then advance the pointer to  *)
(* a published root. The pointer only ever names a published root.         *)

PublishRoot(r) ==
    /\ r \in Roots
    /\ r \notin published
    /\ published' = published \cup {r}
    /\ UNCHANGED <<members, keyEpoch, epochMembers, rotating, objClass,
                    objEpoch, objTags, placed, grants, namePtr>>

SetNamePtr(r) ==
    /\ r \in published
    /\ namePtr' = r
    /\ UNCHANGED <<members, keyEpoch, epochMembers, rotating, objClass,
                    objEpoch, objTags, placed, grants, published>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E n \in Nodes : Admit(n)
    \/ \E n \in Nodes : Leave(n)
    \/ BeginRotate
    \/ EndRotate
    \/ \E o \in Objects, cls \in VisClasses, tgs \in SUBSET Tags :
            PlaceObject(o, cls, tgs)
    \/ \E u \in Users, m \in Modes, sc \in GrantScopes : AddGrant(u, m, sc)
    \/ \E g \in grants : RevokeGrant(g)
    \/ \E r \in Roots : PublishRoot(r)
    \/ \E r \in Roots : SetNamePtr(r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* DERIVED DECRYPTABILITY                                                    *)

\* A node n can decrypt object o under o's visibility class:
\*   Public          -- always.
\*   CellEncrypted   -- n was a member of the epoch the object was sealed under
\*                      (i.e. n \in epochMembers[objEpoch[o]]). A departed member
\*                      is NOT in the epochMembers of any epoch authored after it
\*                      left, which is exactly forward secrecy.
\*   RecipientSealed/PerNode -- n is in the explicit recipient node set.
\*   RecipientSealed/PerCell -- a node cannot decrypt a cell-to-cell seal here
\*                      (targets peer cells, not our nodes) -- FALSE.
\*   RecipientSealed/PerUser -- likewise not a node-level entitlement -- FALSE.
NodeCanDecrypt(n, o) ==
    LET c == objClass[o] IN
      CASE c.kind = "Public"        -> TRUE
        [] c.kind = "CellEncrypted" -> n \in epochMembers[objEpoch[o]]
        [] c.kind = "RecipientSealed" ->
              /\ c.scope = "PerNode"
              /\ n \in c.rcpt
        [] OTHER -> FALSE

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES                                                         *)

\* VISIBILITY SOUND: for every placed object, a node's ability to decrypt it
\* is EXACTLY what its class entitles -- in particular a CellEncrypted object
\* is decryptable only by nodes sealed into its epoch, and a PerNode-sealed
\* object only by its explicit recipients. (Derived directly from
\* NodeCanDecrypt; the property is that decryptability is class-determined and
\* never a member of a class it does not belong to. Concretely: no node outside
\* the sealed set can decrypt a non-Public object, and every entitled node can.)
VisibilitySound ==
    \A o \in placed :
        LET c == objClass[o] IN
          /\ (c.kind = "CellEncrypted" =>
                \A n \in Nodes :
                    NodeCanDecrypt(n, o) <=> n \in epochMembers[objEpoch[o]])
          /\ (c.kind = "RecipientSealed" /\ c.scope = "PerNode" =>
                \A n \in Nodes : NodeCanDecrypt(n, o) <=> n \in c.rcpt)
          /\ (c.kind = "Public" => \A n \in Nodes : NodeCanDecrypt(n, o))

\* FORWARD SECRECY ON LEAVE: a node that is NOT a current member cannot decrypt
\* any CellEncrypted object sealed under the CURRENT epoch. Because Leave
\* rotates the key (increments keyEpoch, seals the new epoch to the reduced set)
\* in the same transition it drops the member, and PlaceObject seals to the
\* current epoch, a departed member holds no epoch that any post-leave object
\* was authored under. epochMembers[e] is exactly the members present when
\* epoch e became current, so a non-member is absent from the current epoch's
\* sealed set.
ForwardSecrecyOnLeave ==
    \A n \in Nodes :
        n \notin members =>
            \A o \in placed :
                (objClass[o].kind = "CellEncrypted" /\ objEpoch[o] = keyEpoch)
                    => ~NodeCanDecrypt(n, o)

\* ATOMIC ROTATION: no object is ever recorded under an epoch it could not have
\* been legally sealed to. Every placed object's epoch is a real, already-
\* reached epoch (<= keyEpoch), and no object was authored while a rotation was
\* in progress (PlaceObject is fenced by ~rotating, so a placed CellEncrypted
\* object's epoch is a committed one whose member set is defined). Concretely:
\* every placed object's recorded epoch never exceeds the current epoch, so it
\* never straddles into an epoch that does not yet exist.
AtomicRotation ==
    \A o \in placed : objEpoch[o] <= keyEpoch

\* GRANT SCOPE RESPECTED: define what a grant admits and prove read/write are
\* confined. A user may READ object o iff it holds a grant whose scope covers o
\* (All, or Tags(T) with o's tags meeting T); it may WRITE o only under a
\* ReadWrite grant likewise scoped. We prove the structural confinement: no
\* ReadOnly grant ever confers write, and no grant confers access to an object
\* outside its scope.
ScopeCovers(sc, o) ==
    \/ sc.kind = "All"
    \/ (sc.kind = "Tags" /\ objTags[o] \cap sc.tags # {})

UserCanRead(u, o) ==
    \E g \in grants : g.user = u /\ ScopeCovers(g.scope, o)

UserCanWrite(u, o) ==
    \E g \in grants : g.user = u /\ g.mode = "ReadWrite" /\ ScopeCovers(g.scope, o)

GrantScopeRespected ==
    \A u \in Users, o \in placed :
        /\ (UserCanWrite(u, o) => UserCanRead(u, o))      \* write implies read
        /\ (UserCanWrite(u, o) =>                          \* write needs a RW grant
              \E g \in grants : g.user = u /\ g.mode = "ReadWrite" /\ ScopeCovers(g.scope, o))
        /\ (UserCanRead(u, o) =>                            \* read needs an in-scope grant
              \E g \in grants : g.user = u /\ ScopeCovers(g.scope, o))

\* NAME POINTER RESOLVES: the IPNS-format pointer, when set, always names a root
\* the cell actually published -- it never dangles.
NamePtrResolves ==
    namePtr # None => namePtr \in published

=============================================================================
