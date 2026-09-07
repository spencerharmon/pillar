------------------------------ MODULE VersioningCompat ------------------------------
(***************************************************************************)
(* ROI P1 "Versioning, compatibility & safe rollout" (operator, 2026-08-31), *)
(* method#1 TLA+-FIRST, DESIGN-GATED -- blocking before any Rust lands for   *)
(* this line (version-stamps-impl, sealed-artifact-self-describing-impl,    *)
(* compat-negotiation-impl, cell-aware-migration-impl, and the swarm-aware  *)
(* follow-on all depend on this spec).                                     *)
(*                                                                          *)
(* Models the three things the ROI asks be proven BEFORE any surface gets a *)
(* version stamp:                                                          *)
(*   1. INDEPENDENT per-surface versioning. The real system stamps eight    *)
(*      seams independently (event-envelope, materialized-view, pillar      *)
(*      message, HTTP ingest API, pillar-UDP protocol, trust-artifact/      *)
(*      attestation, sealed-artifact envelope, manifest/declared-object     *)
(*      schema); this spec abstracts that as a generic set `Surfaces` of    *)
(*      >= 2 independently-versioned seams so the abstraction is faithful   *)
(*      to "many seams, no forced lockstep" without hard-wiring eight       *)
(*      near-identical copies of the same state machine.                    *)
(*   2. COMPATIBILITY NEGOTIATION with an N-1+ backward-compat window.      *)
(*      Every peer runs its OWN version per surface; two peers attempting   *)
(*      to interoperate declare/compare that version and either link        *)
(*      (compatible) or are cleanly refused (incompatible) -- modeled       *)
(*      generically over pillar-UDP peers / HTTP-QUIC clients / cell        *)
(*      members alike (the ROI's "peers/HTTP-QUIC clients/cell members      *)
(*      exchange + check versions" clause).                                *)
(*   3. CELL-AWARE + SWARM-AWARE MIGRATION. Peers are partitioned into       *)
(*      cells (CellA, CellB); an upgrade rolls out ONE peer at a time       *)
(*      (never a stop-the-world jump), so a cell transiently holds          *)
(*      members at different versions (mixed-version coexistence) while    *)
(*      remaining internally negotiable; cross-cell (federation) pairs      *)
(*      negotiate across the SAME window discipline, so the swarm never     *)
(*      permanently splits along cell lines as versions drift and          *)
(*      re-converge.                                                        *)
(*                                                                          *)
(* A materialized view built by replay at a given surface version is        *)
(* represented implicitly by peerVer[p][ViewSurface] -- "coexisting views"  *)
(* is exactly a state where cellmates' recorded ViewSurface versions        *)
(* differ (RollingCoexistence), which this spec proves is REACHABLE (not    *)
(* merely tolerated) rather than a forced synchronous cutover.              *)
(*                                                                          *)
(* Proven by TLC:                                                          *)
(*   - N1WindowHonored, NoOrphanedMember, NegotiationRefusesIncompatible,   *)
(*     TypeOK (safety)                                                     *)
(*   - IndependentVersioning, RollingCoexistence, SwarmNeverPartitioned     *)
(*     (liveness, <>)                                                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Surfaces,     \* >= 2 independently-versioned seams (abstracts the 8 real ones)
    CellA, CellB, \* CellA, CellB : disjoint, non-empty sets of peers -- the swarm's
                  \* two cells; Peers == CellA \cup CellB
    N,            \* Nat, >= 1 : the compat window -- max tolerated version lag
                  \* ("N-1+": a peer up to N versions behind the released version
                  \* is still supported/negotiable; N+1 behind is orphaned)
    MaxVersion    \* Nat : finite bound on version growth, keeps TLC's state space
                  \* finite (release/upgrade both stop at this ceiling)

ASSUME NOK          == N \in Nat /\ N >= 1
ASSUME MaxVersionOK == MaxVersion \in Nat /\ MaxVersion >= N
ASSUME CellsOK      == /\ CellA \cap CellB = {}
                       /\ CellA # {} /\ CellB # {}
ASSUME SurfacesOK   == Cardinality(Surfaces) >= 2

Peers == CellA \cup CellB

CellOf(p) == IF p \in CellA THEN CellA ELSE CellB

\* Symmetric absolute difference -- reused everywhere two versions are compared.
Diff(a, b) == IF a >= b THEN a - b ELSE b - a

NoNeg == "none"

VARIABLES
    version,     \* [Surfaces -> 0..MaxVersion] : swarm-wide RELEASED version per
                 \*   surface, independent per surface, monotonically non-decreasing
    peerVer,     \* [Peers -> [Surfaces -> 0..MaxVersion]] : each peer's currently
                 \*   RUNNING version per surface (<= version[s]); a peer catches up
                 \*   one surface, one version, at a time -- never a stop-the-world
                 \*   simultaneous jump (that is exactly what makes rolling/mixed-
                 \*   version coexistence the reachable norm, not an edge case)
    negOutcome   \* record of the MOST RECENT negotiation attempt -- [kind: {"none",
                 \*   "linked", "refused"}, p, q \in Peers, s \in Surfaces]. A scalar
                 \*   "last attempt" record (not a growing history ledger) keeps the
                 \*   state space finite while still exercising the safety invariant
                 \*   below at the exact moment EVERY negotiation attempt occurs --
                 \*   TLC checks invariants after every step, so no attempt escapes
                 \*   the check merely because a later one overwrote this record.

vars == <<version, peerVer, negOutcome>>

AnyP == CHOOSE p \in Peers : TRUE
AnyS == CHOOSE s \in Surfaces : TRUE

TypeOK ==
    /\ version   \in [Surfaces -> 0..MaxVersion]
    /\ peerVer   \in [Peers -> [Surfaces -> 0..MaxVersion]]
    /\ negOutcome \in [kind: {"none", "linked", "refused"}, p: Peers, q: Peers, s: Surfaces]

Init ==
    /\ version    = [s \in Surfaces |-> 0]
    /\ peerVer    = [p \in Peers |-> [s \in Surfaces |-> 0]]
    /\ negOutcome = [kind |-> NoNeg, p |-> AnyP, q |-> AnyP, s |-> AnyS]

------------------------------------------------------------------------------
(* ACTIONS *)

\* A new version of surface s is RELEASED (independent per surface -- bumping
\* s never touches any other surface's version or any peer's running version).
\* Guarded so the release itself never orphans a peer: every peer must
\* ALREADY be within N-1 versions of the current release, so after the bump
\* it is within N (the invariant N1WindowHonored this maintains). This is the
\* "release cadence honors the backward-compat window" half of the contract --
\* an operator cannot ship a release that strands an unupgraded peer.
Bump(s) ==
    /\ version[s] < MaxVersion
    /\ \A p \in Peers : version[s] - peerVer[p][s] < N
    /\ version' = [version EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<peerVer, negOutcome>>

\* Peer p catches up ONE version of ONE surface at a time (rolling upgrade,
\* never a batch/global jump). Independent per (peer, surface) pair -- this
\* is what lets cellmates transiently diverge (RollingCoexistence) rather
\* than requiring lockstep.
RollingUpgrade(p, s) ==
    /\ peerVer[p][s] < version[s]
    /\ peerVer' = [peerVer EXCEPT ![p][s] = @ + 1]
    /\ UNCHANGED <<version, negOutcome>>

\* p and q attempt to interoperate over surface s (a pillar-UDP peer pair, an
\* HTTP-QUIC client/server pair, or two cell members -- the mechanics are the
\* same generic version-exchange-and-check regardless of which). Compatible
\* (within the N-window) => linked; otherwise cleanly REFUSED -- recorded,
\* never a silent mis-negotiation. Always enabled (may be re-attempted after
\* either side upgrades further), so the model never deadlocks on this action
\* and re-negotiation after convergence is always eventually observed.
Negotiate(p, q, s) ==
    /\ p # q
    /\ negOutcome' = [kind |-> IF Diff(peerVer[p][s], peerVer[q][s]) <= N THEN "linked" ELSE "refused",
                       p |-> p, q |-> q, s |-> s]
    /\ UNCHANGED <<version, peerVer>>

Next ==
    \/ \E s \in Surfaces : Bump(s)
    \/ \E p \in Peers, s \in Surfaces : RollingUpgrade(p, s)
    \/ \E p, q \in Peers, s \in Surfaces : Negotiate(p, q, s)

\* Fairness: every peer eventually catches up on every surface if it keeps
\* lagging (WF on RollingUpgrade), every surface eventually releases if it
\* keeps being enabled (WF on Bump), and every ordered pair eventually
\* attempts negotiation on every surface (WF on Negotiate). Nothing here
\* forces two DISTINCT surfaces, or two DISTINCT peers, to move in lockstep
\* -- that absence of coupling is exactly IndependentVersioning /
\* RollingCoexistence's content, not an artifact of under-specified fairness.
Fairness ==
    /\ \A s \in Surfaces : WF_vars(Bump(s))
    /\ \A p \in Peers, s \in Surfaces : WF_vars(RollingUpgrade(p, s))
    /\ \A p, q \in Peers, s \in Surfaces : WF_vars(Negotiate(p, q, s))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
(* SAFETY PROPERTIES *)

\* No peer is EVER more than N versions behind a surface's released version --
\* the backward-compat window ("N-1+") is honored at every reachable state,
\* not merely at release time. Maintained by Bump's guard above.
N1WindowHonored == \A p \in Peers, s \in Surfaces : version[s] - peerVer[p][s] <= N

\* A same-cell member is never permanently unreachable/unnegotiable from its
\* cellmates: since EVERY peer individually stays within N of the release
\* (N1WindowHonored), two cellmates are always within 2N of each other --
\* the direct corollary that formalizes "no cell member is orphaned by a
\* rolling upgrade in progress".
NoOrphanedMember ==
    \A p, q \in Peers, s \in Surfaces :
        CellOf(p) = CellOf(q) => Diff(peerVer[p][s], peerVer[q][s]) <= 2 * N

\* Negotiate's outcome is always correct w.r.t. the window: a "linked" result
\* only ever occurs when the pair truly is within N of each other, and a
\* "refused" result only ever occurs when it truly is not -- so an
\* incompatible pair is REFUSED cleanly (never silently linked) and a
\* compatible pair is never spuriously refused. Checked at the exact moment
\* of every negotiation attempt (see the negOutcome comment above).
NegotiationRefusesIncompatible ==
    /\ negOutcome.kind = "linked"  => Diff(peerVer[negOutcome.p][negOutcome.s], peerVer[negOutcome.q][negOutcome.s]) <= N
    /\ negOutcome.kind = "refused" => Diff(peerVer[negOutcome.p][negOutcome.s], peerVer[negOutcome.q][negOutcome.s]) > N

------------------------------------------------------------------------------
(* LIVENESS PROPERTIES *)

\* Two distinct surfaces are NOT forced to move in lockstep: the model
\* reaches a state where they sit at different released versions. Since
\* Bump(s) touches only version[s] (independent per surface) and WF_vars
\* guarantees the first enabled Bump anywhere eventually fires while both
\* start equal at 0, any single release immediately breaks the tie.
IndependentVersioning == <>(\E s1, s2 \in Surfaces : s1 # s2 /\ version[s1] # version[s2])

\* A cell transiently holds members running DIFFERENT versions of the same
\* surface -- rolling, mixed-version coexistence is reachable, not merely a
\* stop-the-world global cutover collapsed to a single instant. Guaranteed
\* because RollingUpgrade advances exactly one (peer, surface) pair per
\* step: once a release creates a gap, cellmates cannot all close it in the
\* same atomic step, so an intermediate divergent state is unavoidable.
RollingCoexistence ==
    <>(\E p, q \in Peers, s \in Surfaces :
         p # q /\ CellOf(p) = CellOf(q) /\ peerVer[p][s] # peerVer[q][s])

\* The swarm never permanently partitions along cell lines: a cross-cell
\* (federation) pair eventually negotiates successfully. Fairness drives
\* every peer to eventually fully catch up to each surface's released
\* ceiling (RollingUpgrade under WF, bounded by MaxVersion) and every pair
\* to eventually re-attempt negotiation (Negotiate under WF); once both
\* sides of a cross-cell pair are caught up, Diff drops to 0 <= N and the
\* next attempt links -- proving the earlier "refused" state (if any) was a
\* temporary negotiation outcome, never a permanent swarm split.
SwarmNeverPartitioned ==
    <>(\E p, q \in Peers, s \in Surfaces :
         p # q /\ CellOf(p) # CellOf(q) /\ negOutcome.kind = "linked" /\ negOutcome.p = p /\ negOutcome.q = q /\ negOutcome.s = s)

===============================================================================
