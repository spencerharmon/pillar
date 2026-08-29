# Pillar formal specifications (TLA+)

Every core component of Pillar ships with a TLA+ specification whose safety
(and, where applicable, liveness) properties are exhaustively model-checked by
TLC **before** the corresponding Rust implementation is trusted. The Rust unit
and property tests encode the same invariants, so the code is a refinement of a
machine-checked contract rather than a hopeful approximation.

This follows the methodology in
<https://blog.graysonhead.net/posts/tla-plus/>: model the protocol, state the
invariants, model failures as actions, let TLC explore every reachable state.

## Specs → components

| Spec | Proven properties | Backs component | Design doc |
|------|-------------------|-----------------|------------|
| `CoordinationCore.tla` | `AtMostOneHolderPerEpoch`, `GrantsAreFenced`, `TypeOK` | `crates/pillar-coordination` (CP resource class) | `docs/consistency-model.md` |
| `Registration.tla` | `AdmissionRequiresAuthorizedChain`, `NoAmbientAuthority`, `TypeOK` | `crates/pillar-identity` (PGP key hierarchy: USER_PRIMARY -> NODE_SUBKEY + REGISTRATION; node-join handshake) | ROI P1 identity/PGP |
| `StreamingDB.tla` | `NoLostWrite`, `LogSubsetOfWritten`, `DeterministicMerkleRoot`, `PerPartitionOrder`, `MonotonicLog`, `Convergence` (`<>[]`), + composed `AtMostOneHolderPerEpoch` | AP state substrate (append-only content-addressed Merkle-CRDT op-log) | `docs/consistency-model.md` |
| `EventDAG.tla` | `UniquePerAuthorSeq`, `NoGaps`, `PrevLinkIntegrity`, `ParentsCrossAuthorAndExist`, `CausalMonotone`, `TypeOK` | event order & integrity substrate (PGP-signed events in a hash-linked Merkle DAG: per-author linear chain + cross-author causal partial order + content-addressed dedup) | ROI P1 event order & integrity |
| `IPAM.tla` | `NoDoubleAllocation`, `GrantsAreFenced`, `TypeOK` | `crates/pillar-ipam` (IPv4/IPv6 allocation from a delegated pool) | ROI P3 distributed-authority |
| `WoTAuthority.tla` | `NoActionAfterRevocation`, `FailClosedUnderStaleView`, `TypeOK`, `CaughtUpBounded` | Web-of-Trust authority & RBAC (`wot-authority-impl`, `rbac-decider`): owner-anchored bounded-depth tsig reachability, 3 revocation kinds, revoke-before-act | ROI P1 WoT authority |
| `AntiEntropy.tla` | `CausallyClosed`, `LogSubsetOfWritten`, `NoLostWrite`, `SelfComplete`, `TypeOK`, + liveness `Completeness` (`<>[]`) | anti-entropy sync (fills gossipsub's best-effort gaps): hypercore / SSB-EBT style range-based set reconciliation over a lossy channel | ROI P1 event order & integrity |
| `IdentityLogin.tla` | `LoginRequiresValidChain`, `NoAmbientAuthority`, `TypeOK` | identity/keys/credentials/login (extends `Registration.tla` + `WoTAuthority.tla`): cold-root/operational-key/device-subkey hierarchy, certification + delegation-grant enrollment, self-revocation without the cold key, client-side-signature login primitive | ROI P1 identity, keys, credentials & login |
| `Recovery.tla` | `RecoveryPreservesAuthority`, `NoRecoveryFromNothing`, `ShamirThreshold`, `NoActionAfterRevocation`, `FailClosedUnderStaleView`, `FreshMarkBounded`, `TypeOK` | backup & recovery (extends the `Registration.tla`/`WoTAuthority.tla`/`IdentityLogin.tla` authority discipline): three layered recovery mechanisms — WoT social re-vouch, encrypted-to-recovery-keys backup blob with optional Shamir k-of-n split on the federation-restricted swarm, total-device-loss — at both the cell and user tiers; a recovered key regains a subset-or-equal of prior authority, never more | ROI P1 identity, keys, credentials & login -> backup & recovery |
| `KeyDistribution.tla` | `TypeOK`, `SealedMatchesAllowlist`, `BiDirectionalConsent`, `FailClosedRevocation`, `CrossOwnerGate`, `EscrowTypeBound`, `NoRootEscrow`, `OpaqueConfidentiality` | key distribution & the offer system (conceptually extends `IdentityLogin.tla`'s device-subkey model): L0 sealed-artifact transport, L1 bi-directional offer/accept admission, L2 tag-based policy auto-distribution, escrow type-bound to operational keys only + OPAQUE-shaped confidentiality, cross-owner(-cell) offer explicit-confirmation gate | ROI P1 key distribution & the offer system |
| `Cells.tla` | `TypeOK`, `VisibilitySound`, `ForwardSecrecyOnLeave`, `AtomicRotation`, `GrantScopeRespected`, `NamePtrResolves` | cells & confidentiality (conceptually extends `WoTAuthority.tla` + `KeyDistribution.tla`): public/cell-encrypted/recipient-sealed (per-node/per-cell/per-user) visibility classes, offer-system cell membership, cross-cell user-access grants (read-only/read-write, all-or-tags), group-key rotation with forward secrecy on member-leave atomic against writers, IPNS-format cell naming pointer | ROI P1 cells & confidentiality |

## Running the checker

```sh
./check.sh            # model-check every spec; non-zero exit on any violation
```

Requires a JVM (17+) and `tla2tools.jar`. `check.sh` locates the jar via, in
order: `$TLA_TOOLS_JAR`, `~/.local/lib/tla/tla2tools.jar`, or downloads the
pinned release into `./.tools/` (the path CI uses).

## Notes

- `CoordinationCore` is currently a **safety-only** model; TLC is run with
  `-deadlock` because terminal quiescence (every voter has granted its final
  epoch) is an expected idle state, not a fault. Deadlock-freedom and liveness
  (`Declared ~> Held`) are tracked as a follow-up spec, not yet asserted here.
- `Registration` is likewise **safety-only** (`-deadlock`): a state where every
  candidate subkey has been admitted (or every remaining action is disabled)
  is expected quiescence, not a fault. It models the ground-truth signature
  relation directly (`signedBy`) rather than cryptographic verification, and
  admission of an already-registered-then-revoked primary's earlier grants is
  out of scope here (no `Revoke` action) -- that is left to a follow-up spec
  alongside the Rust refinement (`identity-impl`).
- `StreamingDB` composes the AP op-log with the CP `CoordinationCore` lease
  protocol under a single `Next` and re-checks `AtMostOneHolderPerEpoch`, proving
  the CP mutual-exclusion invariant is preserved under the composition (the two
  planes touch disjoint state). Its `Convergence` liveness property
  (`<>[]AllConverged`) proves that after arbitrary `Partition`/`Heal` the op-log
  reconverges, under **strong** per-pair fairness of anti-entropy and of healing
  — weak fairness is insufficient because an adversarial partition leaves a
  deliverable gossip step enabled only intermittently. TLC is run with
  `-deadlock` (quiescence at the semilattice top is an expected idle state).
- `EventDAG` is **safety-only** (`-deadlock`): a state where every author's
  chain has saturated is expected quiescence, not a fault (the `ReBroadcast`
  self-loop also keeps the model deadlock-free). It ADOPTS the git / CT / SSB /
  hypercore hash-linked-DAG convention rather than inventing one, and models an
  event's content-address by its `(author, seq)` id -- a faithful surrogate for
  a collision-resistant content hash GIVEN the `UniquePerAuthorSeq` (no-fork)
  theorem it proves. The CP total order is deliberately NOT modeled here
  (`CoordinationCore` supplies it); PGP signing is modeled at the ground-truth
  authorship level (each event carries its author) rather than as cryptographic
  verification, matching how `Registration` models `signedBy`.
- `IPAM` allocates addresses from a delegated pool by DIRECTLY INSTANTIATING
  `CoordinationCore` with "epoch" specialised to "address": granting/acquiring
  epoch `e` is granting/acquiring address `e` from the pool, so
  `AtMostOneHolderPerEpoch` re-exported as `NoDoubleAllocation` is exactly the
  duplicate-IP exclusion this spec exists to prove. It is spec-only and
  safety-only (`-deadlock`): address release/re-allocation and the
  pool-delegation handshake itself are out of scope, left to the Rust
  refinement (`ipam-impl`).
- `WoTAuthority` models tsig authority as owner-anchored bounded-depth
  reachability over non-revoked edges, with edge issuance (AP, unconditional)
  separated from the three revocation kinds (key/edge/grant). Revocations are
  CP/fail-closed at the point they matter -- not when appended to the log
  (an unconditional write), but at `Act` time: `Act`'s guard is the
  revoke-before-act rule, requiring the actor's local view (`caughtUpTo`) to
  be a fully caught-up, fenced read of the current revocation log before it
  may treat a subject as authoritative. `Partition`/`StaleView` let a node's
  view lag arbitrarily (and `Heal` restore it), and `FailClosedUnderStaleView`
  proves the unsafe optimistic path -- acting on a subject that only looks
  authoritative under a stale view -- is structurally unreachable. Safety-only
  (`-deadlock`): full convergence to a caught-up, unrevoked-everywhere
  quiescent state is expected, not a fault.
- `AntiEntropy` proves the replication discipline that fills gossipsub's
  best-effort delivery gaps: a hypercore / SSB-EBT style range-based set
  reconciliation, where every author is also a full replica that syncs
  missing ranges from peers strictly in causal (per-author `seq`) order --
  never a gap. Unlike `StreamingDB`'s flat CRDT op-log union, a peer here may
  never accept `(a, seq)` without already holding `(a, seq-1)`
  (`CausallyClosed`), matching the hash-linked chain `EventDAG` defines. The
  lossy channel is modeled the same way as `StreamingDB`'s `Partition`/`Heal`
  (adversarial, arbitrarily repeated splits); its liveness property
  `Completeness` (`<>[]AllConverged`) proves that despite arbitrarily many
  dropped/delayed deliveries, once authoring quiesces and anti-entropy +
  healing are **strongly** fair per replica pair, every peer converges to,
  and stays at, the identical reachable event set -- weak fairness is
  insufficient for the same reason as in `StreamingDB` (an adversarial
  partition leaves a given deliverable step enabled only intermittently). TLC
  is run with `-deadlock` (full agreement, or a fully-saturated set of
  author chains, is expected quiescence, not a fault). Cross-author `parents`
  hash-links (the DAG shape `EventDAG` proves) are out of scope here -- this
  spec is scoped to the per-author linear-chain range-sync contract that
  hypercore/SSB-EBT replicate; a follow-up spec composing the two would prove
  full-DAG anti-entropy.
- `Cells` models a single cell as the unit of confidentiality: three visibility
  classes (`Public` / `CellEncrypted` / `RecipientSealed`, the last at
  per-node/per-cell/per-user granularity) whose decryptability is DERIVED from
  the class + current world, never a separate mutable fact. Membership is
  consumed as `KeyDistribution` ground truth (offer-system admitted). The group
  key is an epoch counter re-sealed per epoch to its member set; a member-leave
  rotates the key in the SAME transition it drops the member
  (`ForwardSecrecyOnLeave`), and a `rotating` fence bars a write from straddling
  a rotation (`AtomicRotation`). Cross-cell grants are `<<user, mode, scope>>`
  (read-only/read-write x all-or-tags), proven to confine read/write to scope
  (`GrantScopeRespected`). The IPNS-format `namePtr` only ever resolves to a
  published root (`NamePtrResolves`). Safety-only (`-deadlock`): a quiesced cell
  (stable membership, no pending write/rotation) is expected idle, not a fault.
  The per-node-vs-per-cell cost/security posture is spelled out in
  `docs/cells-confidentiality.md`.
