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
