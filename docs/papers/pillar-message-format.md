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
4. **the payload of a pillar-udp datagram** (fallback QUIC, then TCP+TLS), where
   pillar-udp — *not* a libp2p Noise handshake — supplies the transport encryption.

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
└──────────────────────────────┘          per-hop │ seal to peer (handshakeless)
                                   ┌───────────────▼───────────────────────┐
                                   │ pillar-udp datagram  (fallback QUIC,   │
                                   │   then TCP+TLS)  — pillar-crypto seals, │
                                   │   NOT libp2p Noise                      │
                                   └────────────────────────────────────────┘
```

Two distinct seals, deliberately, because they protect different things:

| Seal | Layer | Recipient | Key | Nonce | Purpose |
|------|-------|-----------|-----|-------|---------|
| **content seal** | `PillarMessage.body` | the **cell** | cell group key (symmetric) | **deterministic** (convergent) | confidentiality at rest + stable `Cid` + dedup |
| **hop seal** | pillar-udp datagram | the **peer** (next hop) | peer X25519 sealing key (WoT) | random (ephemeral) | confidentiality on the wire, handshakeless |

The content seal travels *with* the record — an IPFS block on disk is already sealed;
a peer that backfills it over bitswap still cannot read it without the cell key. The
hop seal is per-datagram and protects the transport metadata/framing to the specific
next hop. A datagram to a cell member therefore carries a cell-sealed body inside a
peer-sealed datagram — double-sealed, each layer independent.

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

## 6. Transport: pillar-udp supplies the cryptography

Decision #1: pillar-udp itself supplies transport cryptography **via pillar-crypto**,
because non-anonymous sessions are **handshakeless** — the distributed Web of Trust
already yields each peer's static X25519 `SealingPublicKey`, so there is no need for a
Noise DH handshake round-trip to establish a session key. **All libp2p messages ride
inside the `PillarMessage` envelope**, exactly like streamdb ops and tsdb signals.
pillar-udp sits **beneath** IPFS in the stack.

### 6.1 Non-anonymous datagram (handshakeless)

```
datagram_payload = seal_to_recipients( canonical_cbor(PillarMessage),
                                        [ peer_sealing_pubkey ] )     // X25519 sealed-box
```

`seal_to_recipients` (`pillar-crypto::seal`) is an ephemeral-static ECDH sealed-box:
the sender mints an ephemeral X25519 key per datagram, derives a shared secret against
the peer's WoT-published static key, and AEAD-seals — **no handshake, no round-trip,
no session state.** The peer opens with `unseal(secret)`. This is what "handshakeless
due to the distributed WoT" means concretely: the WoT *is* the key-distribution that a
handshake would otherwise perform.

### 6.2 Anonymous sessions

An anonymous session has no WoT identity for the peer, so §6.1 has no recipient key.
Anonymous datagrams are therefore **out of scope for per-hop confidentiality** and are
specified separately (candidate: ephemeral-ephemeral with an out-of-band-verified
short-auth-string, or cleartext-authenticated-only for public gossip). The TLA+ spec
resolves the anonymous path; the non-anonymous path above is the default and the one
the initial implementation lands. *(Open design point flagged to the operator.)*

### 6.3 Fallback chain

Transport selection is unchanged in ordering — pillar-udp → QUIC → TCP+TLS — but the
**payload of every one of them is a `PillarMessage`**. QUIC and TCP+TLS retain their
own transport-native encryption (QUIC-TLS, TLS); pillar-udp is the case that needed an
explicit cryptographic story because it is a bare datagram substrate. Because the
envelope body is *already* cell-sealed (§5), even the fallback transports never see
plaintext application content.

### 6.4 Relationship to Noise

Removing the libp2p Noise upgrade from the pillar-udp transport is a deliberate,
**breaking** transport-protocol change. It is safe only behind the versioning spine:
the pillar-UDP protocol version and the pillar-message version both bump, and
compatibility negotiation (ROI versioning section) refuses a Noise-era peer cleanly
rather than mis-framing. Non-negotiable method #1 (TLA+ first) governs the cutover —
`NegotiationRefusesIncompatible` and `RollingCoexistence` must cover a mixed
Noise/pillar-crypto swarm during rollout.

---

## 7. Compatibility & versioning

Per the ROI versioning spine (independent per-surface version stamps, N-1 window):

- **envelope version** — `PillarMessage.version`. `v1` = the legacy streamdb
  `SignedSegment` length-prefixed form (read-compat); `v2` = this canonical-CBOR,
  cell-sealed, convergent envelope.
- **pillar-UDP protocol version** — bumped for the Noise→pillar-crypto cutover.
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
  pillar-udp transport drops the Noise upgrade and seals datagrams with
  `seal_to_recipients` (§6). The per-protocol CBOR types become `ControlBody` variants.

## 9. Invariants (TLA+ obligations, before any Rust)

Refines/extends the existing `versioning-compat-migration-spec` and
`ObsIngestionSubstrate.tla`:

- `OneRecordFormat` — every persisted/transmitted byte is a `PillarMessage`.
- `ContentAddressStable` — `Cid` is a deterministic function of the logical record,
  equal across nodes despite sealing (the convergent-seal property).
- `DedupUnderEncryption` — identical sealed records collapse to one `Cid`/one block.
- `CellConfidential` — only a cell-key holder recovers `Body`; a non-member/bitswap
  peer gets ciphertext only.
- `HandshakelessAuth` — a non-anonymous datagram is sealed to and openable by exactly
  the intended WoT peer, with no handshake state.
- `NoNonceReuseAcrossDistinctPlaintext` — convergent nonces collide only for identical
  plaintext.
- `IndependentVersioning` / `NegotiationRefusesIncompatible` / `RollingCoexistence` —
  the envelope, pillar-UDP, and seal versions bump independently and a mixed-version
  (incl. Noise-era) swarm never mis-frames or partitions.

## 10. Open points for the operator

1. **Anonymous-session transport crypto (§6.2)** — no WoT key exists; needs an
   explicit scheme (ephemeral-ephemeral + SAS, or authenticated-cleartext for public
   gossip). Default proposed: non-anonymous handshakeless first; anonymous resolved in
   the spec.
2. **Convergent-encryption equality leak (§5)** — accepted as the mechanism of dedup,
   scoped to the cell boundary. Flagged so it is an explicit, reviewed acceptance, not
   an accident.
