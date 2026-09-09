# The Pillar Message Format

*A single sealed, content-addressed, version-stamped envelope for every byte
Pillar persists or transmits.*

Status: design of record (operator-directed, 2026-09-09). Implementation is
TLA+-gated per ROI non-negotiable method #1 — this paper is the design the spec
refines and the `pillar-wire` crate implements.

---

## 1. Motivation

Today Pillar has three unrelated byte formats for what is fundamentally the same
thing — a signed, content-addressed record:

- **streamdb ops** — `SignedSegment { bytes, signer, signature, visibility }`,
  hand-rolled length-prefixed wire form, addressed by `Cid = content_address(to_wire())`,
  persisted through `ContentStore`/`IpfsBackend` onto Pillar's embedded IPFS node.
- **observability signals** — `Signal { id, kind, payload, labels, expiry }`, held
  only in an in-memory `TimeseriesStore`, never persisted to IPFS, never on the wire.
- **libp2p control traffic** — per-protocol CBOR request/response types
  (`OpSyncRequest/Response`, `SyncRequest/Response`, `BlobRequest/Response`) plus
  gossipsub event-log messages, each its own struct, encrypted only by the libp2p
  Noise session at the transport layer.

Three formats mean three serializers, three version stories, three security
postures, and — critically — observability signals get *none* of the durability,
content-addressing, or replication that streamdb ops already have. The five signal
kinds (metric/log/trace/profile/metadata) are already specified to ride "IPFS
(durable signed segments/backfill) + streaming-DB tip … no parallel store, no
second authority" (ROI Priority 3, Observability rework). This paper makes that
literal by giving signals the *same* record type streamdb ops use.

**Thesis.** There is exactly one Pillar record on the wire and on disk: the
**`PillarMessage`** — a version-stamped envelope carrying a sealed, content-addressed
payload. streamdb ops, observability signals, and every libp2p control message are
variants of it. It is:

1. **content-addressed** — its `Cid` is the SHA2-256 multihash of its canonical
   encoding, identical on every node (dedup, IPFS convergence, Merkle roots);
2. **sealed to the cell** — the payload is AEAD-encrypted under the cell group key
   so any cell node (and only a cell node) can decrypt, *convergently* so the `Cid`
   is stable across nodes despite encryption;
3. **version-stamped** — an independently-incrementable surface version, per the
   ROI versioning spine;
4. **the payload of a pillar-udp datagram** (fallback QUIC, then TCP+TLS). On
   pillar-udp the datagram is encrypted under a **portable, cell-minted session key**
   (not a libp2p Noise handshake, and not a per-pair session); the full scheme is its
   own design-of-record — see the companion paper **`pillar-udp-encryption.md`**. On
   QUIC/TCP the transport's own TLS supplies session encryption and this scheme does
   not apply. The content seal (point 2) is transport-agnostic and applies either way.

---

## 2. Layering

```
┌──────────────────────────────────────────────────────────────────────┐
│ application records                                                    │
│   streamdb Op │ obs Signal │ libp2p control (opsync/antientropy/blob/  │
│               │            │   gossip)                                 │
└───────────────┬───────────────────────────────────────────────────────┘
                │  each becomes a PillarMessage.body variant
┌───────────────▼───────────────────────────────────────────────────────┐
│ PillarMessage  (pillar-wire crate)                                     │
│   version-stamped, canonical CBOR, body sealed-to-cell (convergent)    │
│   Cid = content_address(canonical bytes)                               │
└───────────────┬───────────────────────────────┬───────────────────────┘
        persist │                         transmit│
┌───────────────▼──────────────┐  ┌───────────────▼───────────────────────┐
│ ContentStore → IpfsBackend   │  │ pillar-net: one PillarMessage per       │
│  (embedded IPFS, pin/provide)│  │  request/response/gossip payload        │
│  Cid ⇔ IPFS CIDv1 raw block  │  └───────────────┬───────────────────────┘
└──────────────────────────────┘   transport │ frame seal (pillar-udp ONLY)
                                   ┌───────────────▼───────────────────────┐
                                   │ pillar-udp datagram — sealed under a   │
                                   │   portable cell-minted SESSION KEY     │
                                   │   (see pillar-udp-encryption.md).      │
                                   │ fallback QUIC / TCP+TLS: transport TLS │
                                   │   supplies the frame seal instead.     │
                                   └────────────────────────────────────────┘
```

Two distinct seals, deliberately, because they protect different things:

| Seal | Layer | Recipient | Key | Nonce | Purpose |
|------|-------|-----------|-----|-------|---------|
| **content seal** | `PillarMessage.body` | the **cell** | cell group key (symmetric) | **deterministic** (convergent) | confidentiality at rest + stable `Cid` + dedup |
| **transport frame seal** | pillar-udp datagram | the **cell** (any member) | portable cell-minted **session key** `K_s` | **collision-free** (convergent / sender-partitioned) | confidentiality of transport framing on the wire |

The content seal travels *with* the record — an IPFS block on disk is already sealed;
a peer that backfills it over bitswap still cannot read it without the cell key. The
transport frame seal is **pillar-udp-specific** and protects the on-wire framing; it
is keyed by a session key that is *portable across every cell node* (established via
the cell-as-KDC scheme in **`pillar-udp-encryption.md`**), so any ingress/relay node
can carry the session. On QUIC/TCP the transport's native TLS plays this role instead.
A pillar-udp datagram to a cell therefore carries a cell-sealed body inside a
session-key-sealed datagram — double-sealed, each layer independent.

---

## 3. `pillar-wire`: the shared substrate crate

Decision (operator): both streamdb and observability **depend down** onto one shared
crate rather than sideways onto each other. That crate is **`pillar-wire`** — the
common home for the wire/persistence primitives that are currently trapped inside
`pillar-streamdb`. (Named for the fact that the *same* bytes go on the wire and to
disk; it is the deliberately-broad "widely used substrate" crate the operator prefers
over a scatter of opaquely-named micro-crates.)

`pillar-wire` owns:

- `PillarMessage` — the envelope enum + its canonical CBOR codec + `Cid` derivation.
- The content seal (`cell_seal_convergent` / `cell_open`, wrapping `pillar-crypto`).
- `SignedSegment`, `Cid`, `HeadRecord`, `Visibility` — **moved down** from
  `pillar-streamdb::store`.
- `ContentStore` and the `IpfsBackend` trait + `NativeIpfsBackend` — **moved down**
  from `pillar-streamdb`.

Dependency direction (all downward, no cycles):

```
pillar-streamdb ─┐
pillar-observability ─┤→ pillar-wire → pillar-crypto, pillar-core, pillar-ipfs
pillar-net ──────┘
```

`pillar-wire` must **not** depend on `pillar-net` (net uses the envelope, not the
reverse) nor on `pillar-streamdb`/`pillar-observability` (they depend on it).

---

## 4. The envelope

```rust
/// The one Pillar record — persisted and transmitted.
pub struct PillarMessage {
    /// Independently-incrementable envelope surface version (ROI versioning spine).
    pub version: SurfaceVersion,
    /// Author identity + signature over `body_sealed` (ed25519, pillar-crypto).
    pub signer: SigningPublicKey,
    pub signature: Signature,
    /// DHT/propagation reach (unchanged semantics from streamdb `Visibility`).
    pub visibility: Visibility,
    /// The cell this record's body is sealed to (which group key opens it).
    pub cell: CellId,
    /// AEAD ciphertext of the canonical-CBOR-encoded `Body`, sealed CONVERGENTLY
    /// under the cell group key (see §5). Never plaintext on disk or wire.
    pub body_sealed: Ciphertext,
}

/// What the sealed body decodes to once a cell node opens it.
pub enum Body {
    /// A streamdb operation (the CRDT op-log payload).
    StreamOp(StreamOpBody),
    /// An observability signal — one of the five kinds.
    Signal(SignalBody),          // { kind, payload, labels, expiry, correlation }
    /// A libp2p control message, wrapped so it too rides the envelope.
    Control(ControlBody),        // { protocol, bytes }  — opsync/antientropy/blob/gossip
}
```

### 4.1 Canonical encoding

The envelope and `Body` are encoded with **deterministic CBOR** (RFC 8949 §4.2.1
canonical form: sorted map keys, definite lengths, shortest-int encoding). CBOR
because pillar-net already uses `request_response::cbor`, and determinism because the
`Cid` is a hash of these bytes — two nodes MUST produce byte-identical encodings for
the same logical record or content-addressing breaks. This replaces streamdb's
hand-rolled length-prefixed `to_wire`; `SignedSegment::to_wire`/`from_wire` become the
`version=1` compatibility path (see §7).

### 4.2 Content address

```
Cid = content_address( canonical_cbor(PillarMessage) )
```

`content_address` is the existing `pillar-crypto` SHA2-256 multihash — the same
function streamdb and observability already share, and the same multihash inside an
IPFS CIDv1 `raw` block. Signing is over `body_sealed` (the ciphertext), so signature
verification needs no cell key; decryption needs the cell key; both are independent of
the `Cid`.

---

## 5. Convergent content seal (the crux)

Decision #2: **encryption recipient is the cell; any cell node can decrypt; the `Cid`
is the same across nodes; we promise BOTH dedup AND encryption.**

Naïve AEAD breaks this: `pillar-crypto::seal_symmetric` draws a **random** nonce
(`OsRng`), so the same signal sealed on two nodes yields different ciphertext →
different `Cid` → no dedup, no IPFS convergence. We therefore add a **convergent**
seal to `pillar-crypto`:

```
nonce = HKDF(key = cell_group_key,
             info = "pillar-wire/convergent-nonce/v1" || domain,
             ikm  = content_address(plaintext_body))[..nonce_len]
ciphertext = AEAD_seal(cell_group_key, nonce, plaintext_body, aad = envelope_header)
```

Properties:

- **Deterministic** — nonce is a pure function of (cell key, plaintext). Same body +
  same cell key ⇒ identical ciphertext ⇒ identical `Cid` on every cell node ⇒ dedup and
  IPFS convergence preserved (exactly the streamdb CRDT idempotence guarantee, now for
  sealed content).
- **Confidential** — recovered only with the cell group key, which is sealed to each
  member via the existing `distribute_group_key` (X25519 sealed-box). A non-member,
  or a bitswap peer outside the cell, holds only ciphertext.
- **Nonce-safe** — nonce reuse across *distinct* plaintexts under one key would break
  AEAD; here reuse happens **only** for identical plaintext (which produces identical
  ciphertext anyway — the intended dedup), never for distinct plaintext, because the
  nonce binds `content_address(plaintext)`. The HKDF salt with the cell key keeps
  nonces unpredictable to a non-member.
- **Equality leak (accepted, documented):** convergent encryption reveals that two
  sealed records are byte-identical (that is *how* dedup works). Within a single cell
  this is the desired property; the cell boundary is the confidentiality boundary. The
  `domain` input separates record classes (op vs signal-kind) so equality never leaks
  across classes.

This is the single genuinely new cryptographic primitive the refactor introduces; it
gets its own TLA+ obligations (`ConvergentDeterministic`, `ConvergentConfidential`,
`NoNonceReuseAcrossDistinctPlaintext`) and `pillar-crypto` contract tests.

---

## 6. Transport: how the envelope is encrypted on the wire

The envelope's on-wire encryption depends on the transport, and there are exactly two
cases:

- **pillar-udp** (a bare datagram substrate) supplies its **own** frame encryption,
  keyed by a **portable, cell-minted session key** — established by a *cell-as-KDC*
  scheme distributed over streamdb, with a deterministic session key derived from the
  client's ephemeral key against the cell static key. This replaces the libp2p Noise
  upgrade. It is **not** handshakeless-per-peer and it is **not** a per-pair Noise
  session: the session key is portable across every cell node so any ingress/relay can
  carry it. The complete scheme — packet flow, key derivation, anonymous handling,
  revocation/GC, and the forward-secrecy tradeoff — is its **own design-of-record**,
  the companion paper **`pillar-udp-encryption.md`**, TLA+-gated by
  `specs/PillarUdpEncryption.tla`.

- **QUIC / TCP** (the fallback transports) bring their **own TLS 1.3 session
  encryption**; the pillar-udp session-key scheme does **not** apply there. pillar-udp
  → QUIC → TCP+TLS is the selection order; the *payload of every one of them* is a
  `PillarMessage`, and because the body is *already* cell-sealed (§5), even the
  fallback transports never see plaintext application content.

**All libp2p control messages ride inside the `PillarMessage` envelope**, exactly like
streamdb ops and observability signals; pillar-udp sits **beneath** IPFS in the stack.

Removing the libp2p Noise upgrade from pillar-udp is a deliberate, **breaking**
transport-protocol change, safe only behind the versioning spine: the pillar-UDP
protocol version bumps and compatibility negotiation refuses a Noise-era peer cleanly
rather than mis-framing. `NegotiationRefusesIncompatible` and `RollingCoexistence`
(§9) cover a mixed legacy-Noise / session-key swarm during rollout.

---

## 7. Compatibility & versioning

Per the ROI versioning spine (independent per-surface version stamps, N-1 window):

- **envelope version** — `PillarMessage.version`. `v1` = the legacy streamdb
  `SignedSegment` length-prefixed form (read-compat); `v2` = this canonical-CBOR,
  cell-sealed, convergent envelope.
- **pillar-UDP protocol version** — bumped for the Noise→session-key cutover
  (see `pillar-udp-encryption.md`).
- **sealed-artifact/key envelope version** — the convergent-seal algorithm tag
  (reuses `pillar-crypto`'s self-describing AEAD tag; the convergent KDF gets its own
  `"…/v1"` info string so a future scheme coexists).

A stamped-but-unknown-future version is rejected *distinctly* from a parse error, so a
node one version ahead is refused cleanly, not silently mis-read. Migration of already
-persisted streamdb `v1` segments is read-through: a `v1` `Cid` stays valid; new writes
are `v2`; no rewrite of history is forced (the content-addressed store makes both
coexist by construction).

---

## 8. What changes, concretely

- **New crate `pillar-wire`** — envelope + codec + convergent content seal +
  `SignedSegment`/`Cid`/`HeadRecord`/`Visibility`/`ContentStore`/`IpfsBackend` moved
  down from `pillar-streamdb`.
- **`pillar-crypto`** — add `cell_seal_convergent` / `cell_open_convergent`
  (deterministic-nonce AEAD, §5) alongside the existing random-nonce `seal_symmetric`.
- **`pillar-streamdb`** — `Op`/`OpLog` payloads become `PillarMessage::StreamOp`
  bodies; persistence re-exports `pillar-wire`'s `ContentStore` (no behavior change to
  the CRDT model or Merkle root).
- **`pillar-observability`** — `Signal` becomes `PillarMessage::Signal`; the
  `TimeseriesStore` hot tip persists each signal as a sealed, content-addressed IPFS
  block via `ContentStore`; cross-node backfill rides the same substrate as streamdb.
- **`pillar-net`** — every request/response/gossip payload is a `PillarMessage`; the
  pillar-udp transport drops the Noise upgrade and seals datagrams under the portable
  cell-minted session key (§6, `pillar-udp-encryption.md`). The per-protocol CBOR
  types become `ControlBody` variants.

## 9. Invariants (TLA+ obligations, before any Rust)

Refines/extends the existing `versioning-compat-migration-spec` and
`ObsIngestionSubstrate.tla`:

- `OneRecordFormat` — every persisted/transmitted byte is a `PillarMessage`.
- `ContentAddressStable` — `Cid` is a deterministic function of the logical record,
  equal across nodes despite sealing (the convergent-seal property).
- `DedupUnderEncryption` — identical sealed records collapse to one `Cid`/one block.
- `CellConfidential` — only a cell-key holder recovers `Body`; a non-member/bitswap
  peer gets ciphertext only.
- `NoNonceReuseAcrossDistinctPlaintext` — convergent content nonces collide only for
  identical plaintext.

The transport-frame encryption obligations (portable session-key convergence,
cell-signed session records, anonymous-as-unattested-principal policy gating, replay
via dedup, revoked-key erasure) are proven separately in
`specs/PillarUdpEncryption.tla` — see `pillar-udp-encryption.md` §Invariants.
- `IndependentVersioning` / `NegotiationRefusesIncompatible` / `RollingCoexistence` —
  the envelope, pillar-UDP, and seal versions bump independently and a mixed-version
  (incl. Noise-era) swarm never mis-frames or partitions.

## 10. Resolved design points

1. **Anonymous-session transport crypto** — *resolved.* Anonymous clients use the
   *exact same* pillar-udp session-key scheme; anonymity is a **policy** property, not
   a crypto scheme. An anonymous key is cryptographically equivalent to a user/node
   key and is subject to the same WoT/RBAC checks; lacking role attestations, the cell
   withholds sensitive data and privileged operations by default-deny. See
   `pillar-udp-encryption.md` §Anonymous.
2. **Transport forward secrecy** — *accepted tradeoff.* The portable session key is
   derivable under the cell static key, so transport forward secrecy bounds to
   cell-key security plus erase-on-revoke — the same price the content seal already
   pays. Per-session ephemeral FS is deliberately traded for cross-node portability.
   Detailed in `pillar-udp-encryption.md`.
3. **Convergent-encryption equality leak (§5)** — accepted as the mechanism of dedup,
   scoped to the cell boundary. Flagged so it is an explicit, reviewed acceptance, not
   an accident.
