# Pillar design documentation

Pillar is a **control-plane-less orchestrator for a federation of
PGP-trusted peers**. It runs application workloads (OCI images, cronjobs,
autoscalers, ingress, and pluggable resource types) across a set of nodes with
no central control plane and no single owner. libp2p is the messaging and
storage layer, OpenPGP is the identity and authorization layer, and every node
is a stateless peer that materializes cluster state from a shared event stream.

Every core component is specified in TLA+ and model-checked before it is
trusted. Each document below links to the specification that proves its claims.

## Contents

| Document | What it covers |
|----------|----------------|
| [architecture.md](architecture.md) | System layers, the state model, how components fit together |
| [consistency-model.md](consistency-model.md) | The CP/AP per-view split and the coordination core (`specs/CoordinationCore.tla`) |
| [identity.md](identity.md) | The OpenPGP key hierarchy and node-admission handshake (`specs/Registration.tla`) |
| [plugin-surface.md](plugin-surface.md) | The complete out-of-tree plugin surface and each plugin's interface contract |
| [cli-surface.md](cli-surface.md) | The single coherent `pillar` CLI: views-vs-acts split, `kind/name` addressing, and the kubectl-parity resource plane |
| [observability.md](observability.md) | Built-in distributed observability: signal event schema, retention/sampling policy, and RBAC-decider read authority (`specs/Observability.tla`) |
| [query-languages/psl.md](query-languages/psl.md) | PSL — the compact-text/structured query surface over observability signals: grammar, correlation semantics, worked example (`specs/PSLCore.tla`) |
| [readiness-probe.md](readiness-probe.md) | The node readiness/liveness health surface (`GET /readyz` + `/healthz`) — real readiness (identity + views + WoT root), not a bound port, and how the deployment manifest wires it |
| [private-pillar.md](private-pillar.md) | Configuring a private network root + owned seeds to run an isolated, app-specific pillar deployment |

## Design principles

1. **Specify, then build.** No core protocol is implemented before its safety
   invariants are model-checked in TLA+ (`specs/`). The Rust tests encode the
   same invariants, so the code refines a machine-checked contract.
2. **P2P-preferred, legacy-capable.** Distributed-native backends (IPFS,
   Pillar's streaming DB, Tor hidden services) are the default; traditional
   backends are reachable through plugins.
3. **Defer policy, never mechanism.** The platform builds and verifies the
   strong coordination primitive once; individual views *opt into* it. The hard
   problem is never pushed onto controller authors.
4. **Safe-by-default.** An unspecified consistency policy resolves to the
   stronger posture; exclusive side effects are refused under relaxed views.
