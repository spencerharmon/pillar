# pillar-udp Encryption — the portable cell-minted session key

*Design of record for how a **pillar-udp** datagram is encrypted on the wire.*
TLA+-gated (method #1): `specs/PillarUdpEncryption.tla` must be green under TLC before
any Rust. Companion to `pillar-message-format.md` (the transport-agnostic envelope and
content seal); this paper covers **only** the pillar-udp transport-frame seal.

> Scope. This scheme applies **only to pillar-udp**, a bare datagram substrate with no
> built-in cryptography. When a connection instead uses **QUIC or TCP**, that
> transport's own **TLS 1.3** supplies session-level encryption and *none* of this
> applies. The `PillarMessage` content seal (`pillar-message-format.md` §5) is
> end-to-end and transport-agnostic; it holds regardless of which transport carries the
> datagram. So there are two, and only two, transport-frame crypto providers:
> **pillar-udp session key (this paper)** and **transport-native TLS (QUIC/TCP)**.

---

## 1. Why not Noise, and why not a per-pair session

pillar-udp's posture (see `pillar-udp-congestion.tex`) is **redundant datagrams sprayed
across multiple paths, deduplicated by content address, processed once**, with ingress
nodes that fail over and load-balance. Two candidate transport-crypto designs were
rejected against that posture:

- **libp2p Noise upgrade** — a *session/connection* protocol. Its handshake is a strict
  ordered multi-message exchange that needs a reliability sublayer just to land over
  lossy/unordered UDP, and it binds a session to **one pair** of endpoints. That fights
  the connectionless, multipath, any-ingress model.
- **A per-pair Noise/WireGuard session** (an earlier proposal) — gives forward secrecy
  and replay protection, but a session bound to a pair is **not portable**: if the
  first ingress node dies, or a redundant copy arrives at a different node, the session
  cannot be served without re-handshaking.

The blocker to portability is precise and cryptographic: an AEAD session is *shared key
+ a per-direction monotonic nonce counter*. The **key** is portable; the **counter** is
not — two nodes incrementing one counter would reuse a nonce, and AEAD nonce reuse is a
total break (keystream reuse → plaintext recovery; auth-key leak → forgery). Remove the
shared counter and derive the nonce collision-free instead (convergent, or
sender-partitioned `node_id‖counter`), and the key becomes portable across every node
that holds it. That is the whole idea.

## 2. The scheme: the cell is a KDC, the session key rides streamdb

pillar already has a shared trust boundary (the **cell**, the genesis principal with a
static key), a converging cell-internal state substrate (**streamdb**), per-message
**ed25519 signatures**, and **content-addressed dedup**. Those are exactly the
ingredients a portable session needs, so the transport session key is built from them:

- **The session key is portable and cell-scoped.** Every node in the cell can derive
  and serve it — no per-pair binding.
- **It is deterministically derived, not minted-and-reconciled.** No race: two ingress
  nodes handling the same sprayed init derive the *byte-identical* key.
- **It is authorized by a cell-signed streamdb record**, which converges to every cell
  node, so ingress failover / relay / load-balancing all serve the same session.
- **Anonymity is a policy state, not a separate scheme** (§6).

### 2.1 Key derivation (deterministic, portable)

A client (a node, a non-node client, or an anonymous client) opens a session by
choosing a fresh **ephemeral X25519 keypair** `(eph_pk, eph_sk)` and a random
`client_nonce`. The transport session key is a **static-ephemeral ECDH against the cell
static key**, run through an HKDF with a domain separator distinct from the content
seal:

```
shared   = X25519( eph_sk,        cell_static_pk )        # client side
         = X25519( cell_static_sk, eph_pk        )        # any cell node side  (equal)
K_s      = HKDF( shared, salt = client_nonce,
                 info = "pillar-udp/session/v1" )
session_id = content_address( eph_pk ‖ client_nonce )
```

Both endpoints compute the **same** `K_s` with no key transmitted on the wire and no
round-trip required: the client derives it the instant it picks `eph_pk` (it knows the
published `cell_static_pk`); **every** cell node derives the identical `K_s` from
`(cell_static_sk, eph_pk, client_nonce)` carried in the session record. Because it is a
pure function of those inputs, two racing ingress nodes cannot diverge — the "collision"
is byte-identical, so there is nothing for the client to reject. `K_s` is **never at
rest**: streamdb stores only the derivation inputs plus the cell authorization, and any
node recomputes `K_s` on demand.

Per-datagram AEAD nonces under `K_s` are **collision-free without coordination** —
convergent (`HKDF(K_s, content_address(frame_plaintext))`) or sender-partitioned
(`node_id ‖ counter`) — so the many cell nodes sharing `K_s` never reuse a nonce.

### 2.2 The session record (cell-signed, on streamdb)

```
SessionRecord {
  session_id        : Cid            // content_address(eph_pk ‖ client_nonce)
  principal_pk      : PublicKey      // client's signing key (node / user / anonymous)
  eph_pk            : X25519PublicKey
  client_nonce      : bytes
  grants            : PolicySet      // from WoT/RBAC on principal_pk (§6)
  not_after         : Timestamp      // session lifetime
  cell_sig          : Signature      // signed by the CELL key  → provenance
}
```

Any node verifies `cell_sig` against the cell key before honoring the session; streamdb
convergence makes the record available cell-wide. It carries no key material — only the
inputs from which `K_s` is derivable by a cell-secret holder.

---

## 3. Packet flow

```
 CLIENT (node / non-node / anonymous)                 CELL  (genesis principal, static key;
   knows cell_static_pk                                     members n1,n2,… hold cell_static_sk;
                                                            streamdb converges cell-wide)
   ┌──────────────────────────────────────┐
   │ pick eph_pk,eph_sk ; client_nonce     │
   │ shared = X25519(eph_sk, cell_static_pk)│
   │ K_s    = HKDF(shared, client_nonce,…) │   ← client derives K_s locally, 0-RTT
   └───────────────┬──────────────────────┘
                   │  ❶ INIT  (sprayed, redundant, multipath)
                   │     sealed-box → cell_static_pk of:
                   │       { principal_pk, eph_pk, client_nonce,
                   │         sig_principal }                       [+ optional first
                   │                                                 K_s-encrypted frame]
        ┌──────────┴───────────┬───────────────────────────────┐
        ▼ (path A)             ▼ (path B, redundant)            │
 ┌─────────────────┐    ┌─────────────────┐                    │  (ingress chosen by
 │ ingress n1      │    │ ingress n2      │                    │   path/LB; either or
 │ unseal(cell_sk) │    │ unseal(cell_sk) │                    │   both may process —
 │ verify sig_pr.  │    │ verify sig_pr.  │                    │   result is identical)
 │ RBAC(principal) │    │ RBAC(principal) │                    │
 │ shared=X25519(  │    │ shared=X25519(  │                    │
 │  cell_sk,eph_pk)│    │  cell_sk,eph_pk)│                    │
 │ K_s=HKDF(…)   ⟵─┼────┼─⟶ identical K_s │  ← deterministic: no race, no reconcile
 │ grants=policy(…)│    │ grants=policy(…)│                    │
 │ write Session-  │    │ write Session-  │                    │
 │  Record(cell_sig)   │  Record(cell_sig)                    │
 └───────┬─────────┘    └───────┬─────────┘                    │
         │  ❷ append (same session_id ⇒ same Cid ⇒ DEDUP to one record)
         ▼                                                      │
   ┌───────────────────────────────────────────┐               │
   │ streamdb  (cell-internal, converges)       │  ❸ replicate │
   │  SessionRecord{session_id, …, cell_sig}    │ ────────────▶ │  n3,n4,… now can
   └───────────────────────────────────────────┘               │  derive K_s & serve
                   ▲                                            │
                   │  ❹ DATA  ⇄  K_s-encrypted pillar-udp frames (convergent nonce)
                   │     inner PillarMessage signed by principal_pk (sender identity)
                   │     served by ANY cell node holding the record  → portable / failover
                   │     replayed frame = same Cid ⇒ deduped, not re-applied
                   │
                   │  ❺ CLOSE / TIMEOUT
                   │     cell node writes Revocation{session_id, cell_sig} → streamdb
                   │     converges → all nodes stop honoring K_s
                   │  ❻ GC erases the SessionRecord after a bounded grace  (SECURITY-
                   │     critical: a revoked-but-uncollected record is a live oracle)
```

Legend: ❶ init, ❷ authorize+append, ❸ converge, ❹ data, ❺ revoke, ❻ collect. A
non-node client and an anonymous client run the **identical** flow; only the RBAC policy
outcome at each ingress differs (§6).

---

## 4. What each layer provides (and what it deliberately does not)

- **Confidentiality of framing** — `K_s`-AEAD on every pillar-udp datagram. (Application
  content is *additionally* cell-sealed end-to-end, `pillar-message-format.md` §5.)
- **Sender identity** — *not* from `K_s` (which only proves cell membership, since every
  cell node holds it) but from the **ed25519 signature inside the `PillarMessage`**. The
  transport key gives group-level confidentiality; identity is a content-layer property.
- **Replay protection** — from **content-addressed dedup**: a replayed datagram has the
  same `Cid` and is dropped by the store pillar already runs. No per-session replay
  window is needed.
- **Portability / failover / load-balancing** — any cell node that has the (converged)
  session record derives the same `K_s` and serves the session.
- **Forward secrecy** — **bounded to cell-key security + erase-on-revoke**, *by design*.
  `K_s` is derivable under the cell static key, so a cell-key compromise exposes past
  sessions; this is the identical tradeoff the content cell-seal already accepts. FS
  *independent* of the cell key would require a discarded ephemeral DH secret, which
  directly contradicts a portable, cell-derivable key — so it is deliberately traded
  away for cross-node portability. Mitigations: periodic cell rekey, and **erase on
  revoke** (see below).

## 5. Revocation and GC are security-critical

On close or timeout a cell node writes a cell-signed **revocation** for `session_id` to
streamdb; convergence stops every node from honoring `K_s`. **GC of the revoked session
record is a security operation, not hygiene**: a revoked-but-uncollected record keeps
`K_s` derivable, i.e. it is a live decryption oracle for any captured ciphertext, so GC
must erase within a bounded deadline. Ciphertext captured *before* revocation stays
readable by anyone who held `K_s` — inherent to shared-key transport and accepted.

## 6. Anonymous sessions = the same scheme + policy

An anonymous client generates an anonymous signing key and runs the **exact scheme of
§2–§3**. The anonymous key is **cryptographically equivalent** to a user or node key and
is subject to the **same WoT/RBAC checks** as any other principal. The only difference
is the *policy outcome*: absent signed role attestations for the key, the cell's
default-deny RBAC **withholds sensitive data and privileged operations** — the anonymous
session can communicate, but only within an unattested principal's grant set. Nothing
else about key derivation, portability, revocation, or nonce discipline changes.

Two consequences worth stating:
- **Anonymous ⇒ pseudonymous, not automatically unlinkable.** A stable anonymous key
  lets the cell link a client across its sessions. Unlinkability is a *client* choice:
  use a fresh anonymous key (hence a fresh `session_id`) per session.
- **The policy gate is the whole security boundary for anonymity.** It rests on the ROI
  invariant that every controller enforces WoT/RBAC default-deny; an unattested
  principal must never acquire a privileged grant.

---

## 7. Compatibility & rollout

Dropping the libp2p Noise upgrade is a **breaking** pillar-udp change, gated by the
versioning spine: the pillar-UDP protocol version bumps, and compatibility negotiation
refuses a legacy-Noise peer cleanly rather than mis-framing. A mixed
legacy-Noise / session-key swarm must coexist through the rollout window
(`RollingCoexistence`, `NegotiationRefusesIncompatible` in the message-format spec).
QUIC/TCP peers are unaffected — they never used this path.

## 8. Invariants (TLA+ obligations, `specs/PillarUdpEncryption.tla`)

- `SessionKeyCellSigned` — every honored session is backed by a cell-signed record.
- `SessionConvergesOnOneKey` — at most one active authorization per `session_id`, and
  every cell node derives the identical `K_s` the client derived (deterministic
  derivation ⇒ portable, race-free convergence).
- `SessionAuthorizedBeforeServe` — a node serves a session only for a record it has
  actually converged (no fabricated/unauthorized sessions).
- `AnonIsUnattestedPrincipal` — a session whose principal carries no attestations holds
  only the restricted grant set; an unattested principal never holds a privileged grant.
- `SharedKeyReplayViaDedup` — applying a frame is content-addressed and idempotent; a
  replay causes no second effect (replay defense without a session replay window).
- `RevokedKeyEventuallyErased` *(liveness)* — a revoked session's record is eventually
  erased from streamdb and every node's view.
- `NonceCollisionFree` — the per-frame nonce under `K_s` is injective in the plaintext
  (convergent), so distinct plaintexts never reuse a nonce (AEAD safety), discharged as
  a constant assumption.

Forward secrecy is a *documented, accepted* property (§4), not a state invariant: it is
a statement about a hypothetical cell-key compromise, deliberately bounded rather than
proven absent.

## 9. Relationship to the content seal

Independent layers, composed. The **content seal** (`pillar-message-format.md` §5) is
end-to-end to the cell, convergent, transport-agnostic, and gives the stable `Cid`. The
**transport frame seal** (this paper) is pillar-udp-specific, keyed by the portable
session key, and protects on-wire framing. A pillar-udp datagram carries a cell-sealed
body inside a session-key-sealed frame; on QUIC/TCP the outer frame seal is the
transport's TLS instead, and the content seal is unchanged.
