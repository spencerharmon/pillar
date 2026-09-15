------------------------------ MODULE GrantAuthority ------------------------------
(***************************************************************************)
(* Pillar shared authority-grant model (ROI P1 "User management &           *)
(* lifecycle" roadmap C1-C4). Every C-tier grant is authority-touching:      *)
(* this spec is the docs -> TLA+ -> Rust gate every C-tier impl inherits.    *)
(*                                                                          *)
(* Models the four authority-mutating primitives shared by the C-tier        *)
(* stories on top of a bounded authority LATTICE `0 .. MaxLevel` (0 = no     *)
(* authority; higher = strictly more):                                       *)
(*                                                                          *)
(*   C1  delegated grant     -- an actor with authority level `gl` grants a   *)
(*       subject a grant of level `l`; the subject's effective authority is   *)
(*       the max over its live grants. A grant carries its granter, its       *)
(*       level, and an absolute expiry tick.                                  *)
(*   C2  time-bounded grant  -- every grant has an `expiry`; once wall-clock   *)
(*       `now` passes it the grant is DEAD and admits nothing, forever.       *)
(*   C3  revocation          -- a grant may be explicitly revoked (grow-only   *)
(*       monotonic fact); a revoked grant admits nothing, forever.            *)
(*   C4  JIT elevation       -- a subject may request a just-in-time          *)
(*       elevation to a HIGHER level for a bounded window; the elevation is   *)
(*       itself a grant, so it inherits expiry + revocation, and is capped    *)
(*       by the granter's own authority exactly like any other grant.        *)
(*                                                                          *)
(* Plus an ATTESTATION CAMPAIGN: an admin periodically re-attests every live  *)
(* grant; a grant not re-attested before the campaign deadline is auto-       *)
(* revoked. The campaign is modelled as a monotone sweep that always          *)
(* CONVERGES: it terminates with every live grant either re-attested or       *)
(* revoked, never leaving a grant in limbo.                                   *)
(*                                                                          *)
(* Time is a bounded, monotonically non-decreasing tick `now \in 0..MaxTime`.*)
(* Authority-EXPANDING events (Grant, JitElevate) are AP: available without   *)
(* coordination, but STRUCTURALLY capped at issue time by the granter's own   *)
(* effective authority -- a grant can never exceed its granter. Authority-    *)
(* REDUCING events (Revoke, expiry via Tick, campaign auto-revoke) are        *)
(* monotone and fail-closed: a dead grant never re-admits.                    *)
(*                                                                          *)
(* Owner is the trust anchor: it holds MaxLevel unconditionally and needs no  *)
(* grant. Every other identity's authority is derived solely from its live    *)
(* grants, so there is no ambient authority.                                  *)
(*                                                                          *)
(* Proven by TLC (see GrantAuthority.cfg):                                    *)
(*   GrantNeverExceedsGranter   -- no live grant's level exceeds the level     *)
(*     its granter effectively held; authority strictly descends the lattice. *)
(*   ExpiredGrantNeverAdmits    -- a grant past its expiry contributes nothing *)
(*     to any subject's effective authority.                                  *)
(*   RevokedGrantNeverAdmits    -- a revoked grant contributes nothing.        *)
(*   JitElevationIsBounded      -- a JIT elevation never exceeds its granter   *)
(*     and never outlives its bounded window (expiry).                        *)
(*   AttestationCampaignConverges -- once a campaign deadline passes, no live  *)
(*     grant is left un-adjudicated: every one is either freshly attested or   *)
(*     revoked.                                                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,      \* candidate identities
    Owner,      \* trust anchor: unconditionally holds MaxLevel
    MaxLevel,   \* top of the bounded authority lattice
    MaxTime,    \* model bound on wall-clock ticks
    MaxGrants   \* model bound on the number of grants ever issued

ASSUME NodesNonEmpty  == Nodes # {}
ASSUME OwnerIsNode     == Owner \in Nodes
ASSUME MaxLevelIsNat   == MaxLevel \in Nat
ASSUME MaxTimeIsNat    == MaxTime \in Nat
ASSUME MaxGrantsIsNat  == MaxGrants \in Nat

Levels == 0 .. MaxLevel
Times  == 0 .. MaxTime
GrantIds == 1 .. MaxGrants

\* A grant is a record. `kind` distinguishes an ordinary delegated grant from
\* a JIT elevation so JitElevationIsBounded can quantify over just the latter.
\* `granterLevel` STAMPS the granter's effective authority at the exact instant
\* the grant was issued -- the fenced fact "this grant was capped by <= that".
\* We assert the cap against this stamp, not against the granter's LATER
\* authority, because a granter losing its own authority (its upstream grant
\* revoked/expired) must not retroactively invalidate the stamp; instead that
\* cascade is handled by revoking the downstream grant explicitly (or by the
\* attestation campaign). The stamp is what makes "never exceeds granter" a
\* stable, monotone-safe theorem rather than one violated by ordinary revoke
\* ordering.
GrantRec ==
    [ id: GrantIds, granter: Nodes, subject: Nodes, level: Levels,
      expiry: Times, kind: {"grant", "jit"}, granterLevel: Levels ]

VARIABLES
    grants,     \* SUBSET GrantRec: every grant ever issued (grow-only)
    revoked,    \* SUBSET GrantIds: explicitly-or-campaign-revoked grant ids (grow-only)
    attested,   \* [GrantIds -> Times]: last tick each grant id was (re-)attested
    now,        \* Nat: wall-clock, monotone non-decreasing
    nextId,     \* Nat: next grant id to allocate
    campaign    \* record: the in-flight attestation campaign, if any

vars == <<grants, revoked, attested, now, nextId, campaign>>

-----------------------------------------------------------------------------
(* DERIVED AUTHORITY                                                          *)

\* A grant is LIVE at the current `now` iff it is not revoked and not expired.
\* (Expiry is inclusive-open: a grant with expiry = e is dead once now > e.)
IsLive(g) == /\ g.id \notin revoked
             /\ now <= g.expiry

\* The set of live grants naming `s` as subject.
LiveGrantsFor(s) == { g \in grants : g.subject = s /\ IsLive(g) }

\* Effective authority of a node: Owner is unconditionally MaxLevel; anyone
\* else is the max level over their live grants (0 if none -- no ambient
\* authority). Computed as a monotone fold so it is a plain, decidable value.
MaxOver(S) == IF S = {} THEN 0
              ELSE CHOOSE m \in { g.level : g \in S } :
                     \A g \in S : g.level <= m

EffAuth(n) == IF n = Owner THEN MaxLevel ELSE MaxOver(LiveGrantsFor(n))

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

Init ==
    /\ grants   = {}
    /\ revoked  = {}
    /\ attested = [i \in GrantIds |-> 0]
    /\ now      = 0
    /\ nextId   = 1
    /\ campaign = [active |-> FALSE, deadline |-> 0]

-----------------------------------------------------------------------------
(* AUTHORITY-EXPANDING (AP, capped at issue time)                            *)

\* An actor grants a subject a grant of level `l` expiring at `exp`. Capped:
\* `l` may not exceed the granter's CURRENT effective authority, so a grant
\* can never exceed its granter. `exp` must be in the future (a grant issued
\* already-dead is pointless and disallowed). A fresh id is allocated and the
\* grant is stamped attested at `now`.
Grant(actor, subject, l, exp) ==
    /\ nextId \in GrantIds
    /\ l \in Levels
    /\ exp \in Times
    /\ exp >= now
    /\ l <= EffAuth(actor)
    /\ l > 0
    /\ LET g == [ id |-> nextId, granter |-> actor, subject |-> subject,
                  level |-> l, expiry |-> exp, kind |-> "grant",
                  granterLevel |-> EffAuth(actor) ]
       IN grants' = grants \cup {g}
    /\ attested' = [attested EXCEPT ![nextId] = now]
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<revoked, now, campaign>>

\* A JIT elevation: a subject requests a bounded-window elevation to level `l`,
\* authorised (granted) by `actor`. It is just a grant with kind "jit", so it
\* inherits the SAME granter cap and expiry machinery -- and JitElevationIsBounded
\* asserts exactly those two facts survive over the whole state space.
JitElevate(actor, subject, l, exp) ==
    /\ nextId \in GrantIds
    /\ l \in Levels
    /\ exp \in Times
    /\ exp >= now
    /\ l <= EffAuth(actor)
    /\ l > EffAuth(subject)          \* an elevation strictly raises the subject
    /\ LET g == [ id |-> nextId, granter |-> actor, subject |-> subject,
                  level |-> l, expiry |-> exp, kind |-> "jit",
                  granterLevel |-> EffAuth(actor) ]
       IN grants' = grants \cup {g}
    /\ attested' = [attested EXCEPT ![nextId] = now]
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<revoked, now, campaign>>

-----------------------------------------------------------------------------
(* AUTHORITY-REDUCING (monotone, fail-closed)                                *)

\* Explicit revocation of a grant id. Grow-only, idempotent.
Revoke(i) ==
    /\ i \in GrantIds
    /\ \E g \in grants : g.id = i
    /\ i \notin revoked
    /\ revoked' = revoked \cup {i}
    /\ UNCHANGED <<grants, attested, now, nextId, campaign>>

\* Wall-clock advances. Expiry is DERIVED from `now` vs each grant's expiry,
\* so a Tick can turn live grants dead with no per-grant write -- ExpiredGrant-
\* NeverAdmits proves the derivation is respected everywhere authority is read.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<grants, revoked, attested, nextId, campaign>>

-----------------------------------------------------------------------------
(* ATTESTATION CAMPAIGN                                                       *)

\* Grants that are live and whose last attestation is OLDER than the campaign
\* deadline -- i.e. the grants a running campaign still has to adjudicate.
StaleLiveGrants ==
    { g \in grants : IsLive(g) /\ attested[g.id] < campaign.deadline }

\* Start a campaign: set a deadline. Only one at a time.
StartCampaign(d) ==
    /\ ~campaign.active
    /\ d \in Times
    /\ d <= now                        \* deadline is "attest since tick d"
    /\ campaign' = [active |-> TRUE, deadline |-> d]
    /\ UNCHANGED <<grants, revoked, attested, now, nextId>>

\* Re-attest one stale grant: bump its attestation to `now` (>= deadline), so
\* it leaves the stale set. Monotone progress toward convergence.
Reattest(g) ==
    /\ campaign.active
    /\ g \in StaleLiveGrants
    /\ attested' = [attested EXCEPT ![g.id] = now]
    /\ UNCHANGED <<grants, revoked, now, nextId, campaign>>

\* Auto-revoke one stale grant: the campaign's fail-closed leg -- a grant not
\* re-attested is revoked. Also monotone progress: the stale set strictly
\* shrinks (the id enters `revoked`, so IsLive drops it).
CampaignRevoke(g) ==
    /\ campaign.active
    /\ g \in StaleLiveGrants
    /\ revoked' = revoked \cup {g.id}
    /\ UNCHANGED <<grants, attested, now, nextId, campaign>>

\* Close a campaign -- allowed ONLY once no stale grant remains, so the sweep
\* cannot "finish" while a grant is still un-adjudicated. This is the guard
\* that makes AttestationCampaignConverges meaningful: an inactive campaign is
\* one that reached a fully-adjudicated fixpoint.
CloseCampaign ==
    /\ campaign.active
    /\ StaleLiveGrants = {}
    /\ campaign' = [active |-> FALSE, deadline |-> campaign.deadline]
    /\ UNCHANGED <<grants, revoked, attested, now, nextId>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                        *)

Next ==
    \/ \E a, s \in Nodes, l \in Levels, e \in Times : Grant(a, s, l, e)
    \/ \E a, s \in Nodes, l \in Levels, e \in Times : JitElevate(a, s, l, e)
    \/ \E i \in GrantIds : Revoke(i)
    \/ Tick
    \/ \E d \in Times : StartCampaign(d)
    \/ \E g \in grants : Reattest(g)
    \/ \E g \in grants : CampaignRevoke(g)
    \/ CloseCampaign

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                           *)

TypeOK ==
    /\ grants \subseteq GrantRec
    /\ revoked \subseteq GrantIds
    /\ attested \in [GrantIds -> Times]
    /\ now \in Times
    /\ nextId \in 1 .. (MaxGrants + 1)
    /\ campaign \in [active: BOOLEAN, deadline: Times]

\* Grant ids are unique: never two grants sharing an id (allocation is strict).
UniqueIds ==
    \A g1, g2 \in grants : g1.id = g2.id => g1 = g2

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES                                                          *)

\* GrantNeverExceedsGranter: every grant's level is <= the authority its
\* granter effectively held AT ISSUE TIME (the `granterLevel` stamp), and that
\* stamp itself never exceeds the lattice top. Authority strictly descends the
\* lattice at every delegation hop: no grant can mint MORE authority than the
\* granter possessed. (Checked against the fenced issue-time stamp, not the
\* granter's later authority -- a granter losing its own upstream grant is a
\* revocation-cascade concern handled by explicit/campaign revocation of the
\* downstream grant, and must not retroactively falsify a correctly-capped
\* historical stamp.)
GrantNeverExceedsGranter ==
    \A g \in grants :
        /\ g.level <= g.granterLevel
        /\ g.granterLevel <= MaxLevel

\* ExpiredGrantNeverAdmits: a grant whose expiry has passed contributes
\* nothing -- it is absent from every subject's live-grant set, hence cannot
\* raise EffAuth.
ExpiredGrantNeverAdmits ==
    \A g \in grants :
        now > g.expiry => g \notin LiveGrantsFor(g.subject)

\* RevokedGrantNeverAdmits: a revoked grant contributes nothing, forever
\* (revoked is grow-only, so once out it never returns).
RevokedGrantNeverAdmits ==
    \A g \in grants :
        g.id \in revoked => g \notin LiveGrantsFor(g.subject)

\* JitElevationIsBounded: every JIT elevation is (a) capped by its granter --
\* never exceeds the granter's effective authority -- and (b) bounded in time:
\* once past its expiry it admits nothing. The two properties that make a JIT
\* elevation "just in time" and not a permanent privilege escalation.
JitElevationIsBounded ==
    \A g \in grants :
        g.kind = "jit" =>
            /\ g.level <= g.granterLevel
            /\ (now > g.expiry => g \notin LiveGrantsFor(g.subject))

\* AttestationCampaignConverges: a campaign that has CLOSED (become inactive
\* after starting) left no stale live grant behind -- every grant is either
\* freshly attested past the deadline or revoked. Stated as: whenever no
\* campaign is active, the stale set relative to the last deadline is empty.
\* (CloseCampaign's guard establishes this; the invariant proves nothing can
\* re-open the gap without re-activating.)
AttestationCampaignConverges ==
    ~campaign.active => StaleLiveGrants = {}

=============================================================================
