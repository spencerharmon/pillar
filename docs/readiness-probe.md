# Node readiness & liveness probes

Pillar's `pillar node run` process exposes a **real** health surface so a
Kubernetes (or any orchestrator's) `readinessProbe`/`livenessProbe` gates
traffic on the node's *substantive* readiness — never on a merely bound port.

A node that answers a bound TCP/QUIC port is NOT yet ready to serve: its
identity may be unloaded, its materialized views un-rehydrated, or its
Web-of-Trust root unable to self-verify. A readiness probe that only checks the
port lets such a node into the Service and, worse, passes a rolling upgrade's
acceptance gate — so a broken build rolls out silently. The probe below makes
"Ready" mean the node can actually serve correct, authoritative answers.

## The HTTP surface

The health server runs unconditionally on every `node run` boot (it does NOT
depend on the optional `--web-bind` UI). It binds, by default, `0.0.0.0` on
port **8643** (so the kubelet, off-loopback, can reach it), overridable with:

| flag | env | default |
|------|-----|---------|
| `--health-bind` | `PILLAR_HEALTH_BIND` | `0.0.0.0` |
| `--health-port` | `PILLAR_HEALTH_PORT` | `8643` |

Two routes:

- **`GET /readyz`** — substantive readiness (the `readinessProbe` target).
  `200 OK` body `ready` iff ALL THREE conditions below hold; otherwise
  `503 Service Unavailable` with body `not-ready: <condition>` naming the FIRST
  unmet condition (checked in ROI order: identity → views → WoT root).
- **`GET /healthz`** — liveness (the `livenessProbe` target). Always `200 OK`
  body `alive` while the process is up, so a still-warming pod (not yet ready)
  is not killed by liveness.

## The three readiness conditions

A node reports `Ready` ONLY when every one of these holds — a bound port is
explicitly not sufficient:

1. **Identity loaded** — the node's long-lived ed25519 keypair is loaded and
   its stable `PeerId` is known.
2. **Views rehydrated** — the durable streaming DB opened and its materialized
   view was rehydrated from the persisted op store. An empty store on a first
   boot counts: zero ops IS the correct rehydrated state; the condition asserts
   the rehydrate STEP completed, not that ops exist.
3. **WoT root self-verifies** — the node's Web-of-Trust authority root (its
   trust anchor) verifies against itself: the anchor's own key is not revoked
   and it is reachable at full delegation depth. A root that cannot self-verify
   can vouch for nobody, so the node can make no authoritative decision.

The readiness DECISION is a pure, unit-tested function
(`pillar_cli::health::NodeReadiness::evaluate`); the definition-of-done check
`cargo test --all` exercises the real accept/reject logic, including the
`503`-with-failing-condition path and an end-to-end socket round-trip.

## Wiring it into the deployment manifest (infra side)

The Pillar SOURCE repo exposes the probe; the concrete Deployment manifest that
consumes it lives on the **infrastructure/GitOps side** (per the repo's rule
that deployment-specific manifests and identifiers stay infra-side, never in
this source tree). A Pillar node container spec wires the probe like:

```yaml
readinessProbe:
  httpGet:
    path: /readyz
    port: 8643
  initialDelaySeconds: 2
  periodSeconds: 5
  failureThreshold: 3
livenessProbe:
  httpGet:
    path: /healthz
    port: 8643
  periodSeconds: 10
```

Because a not-ready node answers `/readyz` with `503`, the pod is kept OUT of
the Service endpoints and a `maxUnavailable`-bounded rolling upgrade HALTS
visibly on the un-ready pod instead of continuing over a broken replica.
