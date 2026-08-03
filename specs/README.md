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
| `WoTAuthority.tla` | `NoActionAfterRevocation`, `FailClosedUnderStaleView`, `TypeOK`, `CaughtUpBounded` | Web-of-Trust authority & RBAC (`wot-authority-impl`, `rbac-decider`): owner-anchored bounded-depth tsig reachability, 3 revocation kinds, revoke-before-act | ROI P1 WoT authority |

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
