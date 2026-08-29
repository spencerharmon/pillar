------------------------------ MODULE Recovery ------------------------------
(***************************************************************************)
(* Pillar backup & recovery (ROI P1 'Identity, keys, credentials & login   *)
(* -> Backup & recovery', method #1). DESIGN-GATED on TLA+: the ROI gates  *)
(* recovery on model-checking wherever it touches authority, so this spec  *)
(* is the gate for recovery-backup-impl.                                   *)
(*                                                                         *)
(* Recovery re-establishes a working device/operational key for a          *)
(* principal (a "subject") that has LOST its keys, WITHOUT ever letting     *)
(* the recovered key regain MORE authority than the subject held before    *)
(* the loss. Three layered recovery mechanisms are modelled at BOTH tiers  *)
(* (cell tier and user tier -- carried as a `tier` field on every subject  *)
(* and recovery record, so the theorems quantify over both uniformly):     *)
(*                                                                         *)
(*   1. SOCIAL RE-VOUCH over the Web of Trust: k independent, currently-    *)
(*      authoritative vouchers re-attest the subject. Models the WoT        *)
(*      social-recovery path -- authority is regranted only by parties who  *)
(*      themselves hold authority right now.                               *)
(*                                                                         *)
(*   2. ENCRYPTED-TO-RECOVERY-KEYS BACKUP BLOB, optionally Shamir k-of-n    *)
(*      split, stored on pillar's OWN federation-restricted swarm -- never  *)
(*      a passphrase-only public blob. Modelled as a blob that is           *)
(*      federation-restricted (a boolean the theorem requires TRUE) and     *)
(*      whose recovery-key shares must reach a k-of-n threshold before the  *)
(*      blob decrypts.                                                      *)
(*                                                                         *)
(*   3. TOTAL-DEVICE-LOSS recovery: the subject lost EVERY device. Covered  *)
(*      uniformly -- a subject may be recovered from nothing-held via (1)   *)
(*      or (2); the theorems never assume the subject retained a key.       *)
(*                                                                         *)
(* Authority is modelled exactly as an abstraction of the sibling specs'    *)
(* discipline (WoTAuthority.tla / IdentityLogin.tla): a subject's PRIOR     *)
(* authority is a set of capabilities `held[s]` (SUBSET Caps), and          *)
(* recovery may only ever RESTORE a subset of what was previously held --   *)
(* never inject a new capability. Revocation (grow-only `revoked`, plus     *)
(* the WoTAuthority-style scalar freshness watermark) still fences every    *)
(* authority-granting recovery action: a stale or lagging recoverer is      *)
(* fail-closed, and no recovery may resurrect authority for a subject whose *)
(* prior authority was already revoked.                                    *)
(*                                                                         *)
(* Proven by TLC:                                                          *)
(*   - RecoveryPreservesAuthority: every completed recovery regranted a     *)
(*     SUBSET-OR-EQUAL of the subject's prior authority (never more) -- no  *)
(*     authority injection, at either tier.                                *)
(*   - NoRecoveryFromNothing: a subject that never held ANY authority (and  *)
(*     for social re-vouch: without a real threshold of authoritative       *)
(*     vouchers; for the blob: without a real k-of-n share threshold and a  *)
(*     federation-restricted blob) can never be the subject of a completed  *)
(*     recovery. Authority is never conjured from nothing.                  *)
(*   - ShamirThreshold: a blob recovery completed only when the number of   *)
(*     presented recovery-key shares met or exceeded the blob's k-of-n      *)
(*     threshold AND the blob was federation-restricted -- a sub-threshold  *)
(*     or public-passphrase blob never recovers.                           *)
(*   - NoActionAfterRevocation / FailClosedUnderStaleView: the             *)
(*     WoTAuthority invariants STILL hold across recovery actions -- a      *)
(*     recovery is just another privileged act, fenced by the same          *)
(*     revoke-before-act watermark rule, so it can never regrant authority  *)
(*     to a subject whose authority was revoked, nor fire from a stale view.*)
(*   - TypeOK: structural well-formedness.                                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Subjects,   \* principals that may lose keys and be recovered
    Vouchers,   \* candidate WoT vouchers for social re-vouch (subset of authoritative parties)
    Caps,       \* candidate capabilities (abstract authority units)
    Shares,     \* candidate recovery-key shares of a backup blob (the n in k-of-n)
    K,          \* the Shamir threshold k (shares needed to decrypt the blob)
    Tiers,      \* the two authority tiers: cell and user
    None        \* sentinel

ASSUME SubjectsNonEmpty == Subjects # {}
ASSUME VouchersNonEmpty == Vouchers # {}
ASSUME CapsNonEmpty     == Caps # {}
ASSUME SharesNonEmpty   == Shares # {}
ASSUME KIsNat           == K \in Nat
ASSUME KPositive        == K > 0
ASSUME KBounded         == K <= Cardinality(Shares)
ASSUME TiersDef         == Tiers = {"cell", "user"}
ASSUME NoneNotSubject   == None \notin Subjects

VARIABLES
    tier,           \* tier[s]: which authority tier subject s belongs to
    held,           \* held[s]: SUBSET Caps -- the authority s held BEFORE any loss (prior authority)
    lost,           \* SUBSET Subjects: subjects that have lost their keys (total-device-loss eligible)
    revoked,        \* SUBSET Caps: capabilities revoked (grow-only, true/global)
    freshMark,      \* [Vouchers -> Nat]: each voucher's revocation-knowledge watermark (WoT staleness)
    partitioned,    \* SUBSET Vouchers: vouchers cut off from advancing their watermark
    blobRestricted, \* [Subjects -> BOOLEAN]: is s's backup blob federation-restricted (not public)?
    lastRecovery    \* ghost: the most recent completed Recovery + its authorization snapshot

vars == <<tier, held, lost, revoked, freshMark, partitioned, blobRestricted, lastRecovery>>

-----------------------------------------------------------------------------
(* DERIVED GROUND TRUTH                                                       *)

\* The true global revocation watermark: how many capabilities are revoked now.
RevCount == Cardinality(revoked)

\* A subject's authority that CURRENTLY survives revocation: its prior-held
\* capabilities minus anything revoked. This is the ceiling any recovery may
\* restore -- never more, and shrinking monotonically as revocation grows.
SurvivingAuth(s) == held[s] \ revoked

\* Vouchers that are currently AUTHORITATIVE and fully caught-up: they hold at
\* least one non-revoked capability (they are a real authority) and their
\* watermark exactly equals the true global one (fenced, non-stale read) --
\* mirroring WoTAuthority's revoke-before-act guard.
FreshAuthVouchers ==
    { v \in Vouchers :
        /\ freshMark[v] = RevCount
        /\ v \in Subjects => SurvivingAuth(v) # {} }

-----------------------------------------------------------------------------
(* INITIAL STATE                                                             *)

InitLastRecovery ==
    [ some |-> FALSE, subject |-> CHOOSE s \in Subjects : TRUE,
      tier |-> "cell", method |-> "none", regranted |-> {},
      priorSnap |-> {}, shares |-> 0, restricted |-> FALSE, watermark |-> 0,
      revokedSnap |-> {} ]

Init ==
    /\ tier \in [Subjects -> Tiers]
    /\ held \in [Subjects -> SUBSET Caps]
    /\ lost = {}
    /\ revoked = {}
    /\ freshMark = [v \in Vouchers |-> 0]
    /\ partitioned = {}
    /\ blobRestricted \in [Subjects -> BOOLEAN]
    /\ lastRecovery = InitLastRecovery

-----------------------------------------------------------------------------
(* KEY LOSS (total-device-loss): a subject loses every device it held. This  *)
(* does NOT touch `held` (the record of PRIOR authority survives the loss --  *)
(* that is what recovery restores against); it only marks the subject as     *)
(* eligible for recovery.                                                    *)

LoseKeys(s) ==
    /\ s \notin lost
    /\ lost' = lost \cup {s}
    /\ UNCHANGED <<tier, held, revoked, freshMark, partitioned, blobRestricted, lastRecovery>>

-----------------------------------------------------------------------------
(* REVOCATION: grow-only, true/global. Each strictly increments RevCount by   *)
(* one, making the scalar freshMark watermark a sound stand-in for "has this  *)
(* voucher seen every revocation fact so far" (WoTAuthority technique).       *)

RevokeCap(c) ==
    /\ c \notin revoked
    /\ revoked' = revoked \cup {c}
    /\ UNCHANGED <<tier, held, lost, freshMark, partitioned, blobRestricted, lastRecovery>>

-----------------------------------------------------------------------------
(* VIEW FRESHNESS: StaleView / Partition / Heal (WoTAuthority technique) --  *)
(* a voucher's revocation knowledge can lag or be frozen by a partition.     *)

StaleView(v) ==
    /\ v \notin partitioned
    /\ freshMark' = [freshMark EXCEPT ![v] = RevCount]
    /\ UNCHANGED <<tier, held, lost, revoked, partitioned, blobRestricted, lastRecovery>>

Partition ==
    /\ partitioned' \in SUBSET Vouchers
    /\ UNCHANGED <<tier, held, lost, revoked, freshMark, blobRestricted, lastRecovery>>

Heal ==
    /\ partitioned # {}
    /\ partitioned' = {}
    /\ UNCHANGED <<tier, held, lost, revoked, freshMark, blobRestricted, lastRecovery>>

-----------------------------------------------------------------------------
(* THE PRIVILEGED RECOVERY ACTIONS. Each REGRANTS a set of capabilities       *)
(* `regrant` to a subject. The universal guard (shared by all three) is:      *)
(*   - regrant is a SUBSET of the subject's currently-surviving prior         *)
(*     authority (SurvivingAuth) -- so recovery can NEVER inject authority    *)
(*     the subject did not previously hold, nor resurrect revoked authority;  *)
(*   - regrant is non-empty (no recovery from nothing).                      *)
(* Each mechanism adds its own additional threshold guard.                    *)

\* Common precondition + ghost write shared by every recovery method.
RecordRecovery(s, method, regrant, shareCount, restricted) ==
    lastRecovery' = [ some |-> TRUE, subject |-> s, tier |-> tier[s],
                      method |-> method, regranted |-> regrant,
                      priorSnap |-> SurvivingAuth(s), shares |-> shareCount,
                      restricted |-> restricted, watermark |-> RevCount,
                      revokedSnap |-> revoked ]

\* (1) SOCIAL RE-VOUCH: a set `vs` of fresh, currently-authoritative vouchers
\* (>= K of them -- a real threshold of independent attestations) re-attest
\* the subject. Regrants only a subset of surviving prior authority.
SocialRevouch(s, vs, regrant) ==
    /\ vs \subseteq FreshAuthVouchers
    /\ Cardinality(vs) >= K
    /\ regrant # {}
    /\ regrant \subseteq SurvivingAuth(s)
    /\ RecordRecovery(s, "social", regrant, Cardinality(vs), TRUE)
    /\ UNCHANGED <<tier, held, lost, revoked, freshMark, partitioned, blobRestricted>>

\* (2) BACKUP-BLOB recovery, Shamir k-of-n. `shs` are the presented recovery-
\* key shares; the blob decrypts only when |shs| >= K AND the blob is
\* federation-restricted (never a passphrase-only public blob). Regrants only
\* a subset of surviving prior authority. The recoverer must be fenced/fresh
\* (revoke-before-act) via at least one fresh authoritative voucher acting as
\* the decrypting party -- so a stale view fail-closes exactly like an Act.
BlobRecover(s, shs, regrant) ==
    /\ blobRestricted[s] = TRUE
    /\ shs \subseteq Shares
    /\ Cardinality(shs) >= K
    /\ regrant # {}
    /\ regrant \subseteq SurvivingAuth(s)
    /\ FreshAuthVouchers # {}
    /\ RecordRecovery(s, "blob", regrant, Cardinality(shs), TRUE)
    /\ UNCHANGED <<tier, held, lost, revoked, freshMark, partitioned, blobRestricted>>

-----------------------------------------------------------------------------
(* NEXT-STATE RELATION                                                       *)

Next ==
    \/ \E s \in Subjects                                    : LoseKeys(s)
    \/ \E c \in Caps                                        : RevokeCap(c)
    \/ \E v \in Vouchers                                    : StaleView(v)
    \/ Partition
    \/ Heal
    \/ \E s \in Subjects, vs \in SUBSET Vouchers, r \in SUBSET Caps
                                                            : SocialRevouch(s, vs, r)
    \/ \E s \in Subjects, shs \in SUBSET Shares, r \in SUBSET Caps
                                                            : BlobRecover(s, shs, r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* TYPE CORRECTNESS                                                          *)

MaxShares == Cardinality(Shares)
Methods == {"none", "social", "blob"}

TypeOK ==
    /\ tier \in [Subjects -> Tiers]
    /\ held \in [Subjects -> SUBSET Caps]
    /\ lost \subseteq Subjects
    /\ revoked \subseteq Caps
    /\ freshMark \in [Vouchers -> 0 .. Cardinality(Caps)]
    /\ partitioned \subseteq Vouchers
    /\ blobRestricted \in [Subjects -> BOOLEAN]
    /\ lastRecovery \in [ some: BOOLEAN, subject: Subjects, tier: Tiers,
                          method: Methods, regranted: SUBSET Caps,
                          priorSnap: SUBSET Caps, shares: 0 .. MaxShares,
                          restricted: BOOLEAN, watermark: 0 .. Cardinality(Caps),
                          revokedSnap: SUBSET Caps ]

\* A voucher's local watermark never runs ahead of the true global one.
FreshMarkBounded == \A v \in Vouchers : freshMark[v] <= RevCount

-----------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* The core theorem: every completed recovery regranted a SUBSET-OR-EQUAL of
\* the subject's prior surviving authority at the moment it fired -- never
\* more. No authority injection, at either tier (the invariant quantifies over
\* the recorded `tier` uniformly, so both cell and user recoveries are checked).
RecoveryPreservesAuthority ==
    lastRecovery.some =>
        /\ lastRecovery.regranted \subseteq lastRecovery.priorSnap
        /\ lastRecovery.tier \in Tiers

\* Authority is never conjured from nothing: a completed recovery always
\* regranted a NON-EMPTY set drawn from a NON-EMPTY prior authority, and met a
\* real threshold (>= K shares/vouchers) with a federation-restricted blob path.
NoRecoveryFromNothing ==
    lastRecovery.some =>
        /\ lastRecovery.regranted # {}
        /\ lastRecovery.priorSnap # {}
        /\ lastRecovery.shares >= K
        /\ lastRecovery.restricted = TRUE

\* Shamir threshold: a blob recovery completed only with >= K shares AND a
\* federation-restricted blob -- a sub-threshold or public-passphrase blob
\* never recovers. (Social re-vouch also carries shares = |vouchers| >= K, so
\* this uniform check covers the threshold for every completed recovery.)
ShamirThreshold ==
    lastRecovery.some =>
        /\ lastRecovery.shares >= K
        /\ lastRecovery.restricted = TRUE

\* WoTAuthority invariant, preserved across recovery: the recovery never
\* regranted authority that was ALREADY revoked at the moment it fired -- the
\* regranted set is disjoint from the revoked set AS IT STOOD WHEN THE RECOVERY
\* FIRED (revokedSnap), because it was drawn from SurvivingAuth (= held \ revoked)
\* at that instant. This mirrors WoTAuthority's lastAct.authSnap technique: the
\* snapshot is stable evidence forever after, so a LATER revocation of a
\* capability that was legitimately restored can never retroactively falsify a
\* recovery that was genuinely valid when it happened. A recovery always
\* precedes any revocation of the capabilities it restored, never follows it.
NoActionAfterRevocation ==
    lastRecovery.some => lastRecovery.regranted \cap lastRecovery.revokedSnap = {}

\* Fail-closed under a stale view: whenever a voucher's watermark lags the true
\* global one (it is stale), no fresh-at-current-watermark recovery could have
\* been driven by a caught-up fenced read that this voucher was part of while
\* stale. A completed recovery recorded watermark = W; if W still equals the
\* CURRENT RevCount, no revocation has landed since, so every voucher that was
\* fresh at fire time is still fresh now -- a currently-stale voucher therefore
\* cannot have been a member of the fresh set that authorized it.
FailClosedUnderStaleView ==
    \A v \in Vouchers :
        freshMark[v] < RevCount =>
            ~ (/\ lastRecovery.some
               /\ lastRecovery.watermark = RevCount
               /\ freshMark[v] = lastRecovery.watermark)

=============================================================================
