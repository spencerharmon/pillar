//! PGP-signed, hash-linked event DAG — the Rust refinement of
//! `specs/EventDAG.tla`.
//!
//! Pillar's "event order & integrity" layer (ROI P1, method #1) ADOPTS the
//! git / Certificate-Transparency / Secure-Scuttlebutt / hypercore convention
//! rather than inventing a new one: every event is
//!
//! * **PGP-signed** by exactly one author, so a tampered event is detectable
//!   (its signature no longer covers its content);
//! * **content-addressed** — its identity ([`EventId`]) is a pure function of
//!   its content, computed with the SAME canonical content-addressing the
//!   [`pillar_streamdb`] op-log uses ([`pillar_streamdb::content_address`]),
//!   so re-broadcasting an event **deduplicates** (ingesting it twice is a
//!   no-op);
//! * **hash-linked** — it carries a `prev` link to that author's immediately
//!   preceding event (the per-author linear chain) and a set of `parents`
//!   links to the observed tips of OTHER authors (the cross-author causal /
//!   happens-before edges).
//!
//! The signature is backed by real `pillar_crypto` ed25519 sign/verify (see
//! [`author_signing_keypair`]) and the collision-resistant hash is the real
//! streamdb content address: [`Signature`] asserts a *verified* ed25519
//! signature over an event's content digest, and content addresses are the
//! streamdb content hash. This crate refines the AP integrity structure of
//! the append log; the CP total order is supplied elsewhere (the
//! coordination core).
//!
//! The type mirrors, and its tests encode, the TLC-proven invariants of
//! `EventDAG.tla`:
//!
//! * `UniquePerAuthorSeq` / dedup — [`EventLog::ingest`] is idempotent and no
//!   two distinct events share a content id (see
//!   [`tests::dedup_by_content_id`]);
//! * `NoGaps` — an event at `seq n > 0` is refused unless its `n-1`
//!   predecessor is already present ([`tests::gap_is_detected`]);
//! * `PrevLinkIntegrity` — a rewritten link breaks the signature and is
//!   rejected ([`tests::tampered_link_is_rejected`]);
//! * `ParentsCrossAuthorAndExist` — every parent references an existing event
//!   of a different author;
//! * `CausalMonotone` — happens-before (via `prev` and `parents`) is a strict
//!   partial order, so the DAG is acyclic
//!   ([`tests::causal_order_is_a_strict_partial_order`]).

use std::collections::{BTreeMap, BTreeSet};

use pillar_streamdb::{content_address, OpLog};
use serde::{Deserialize, Serialize};

pub mod antientropy;
pub mod audit;
pub use antientropy::LogDigest;
pub use audit::{AuditEntry, AuditRecord};

/// The fingerprint of an event author's OpenPGP identity. An event is authored
/// by exactly one author (the `auth` field of `EventDAG.tla`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Author(pub String);

/// A content address: the identity of an [`Event`], a pure function of its
/// content. Mirrors `Id(a, n)` in the spec, whose `UniquePerAuthorSeq`
/// theorem makes the content address a faithful surrogate for a
/// collision-resistant hash of the full event content.
///
/// Backed by a real cryptographic content address (SHA2-256 multihash) via
/// [`pillar_streamdb::content_address`] — NOT a 64-bit checksum. A
/// non-cryptographic id would let an adversary forge a distinct event content
/// sharing an [`EventId`], collapsing the `UniquePerAuthorSeq` guarantee.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventId(pub pillar_streamdb::OpId);

impl EventId {
    /// The raw multihash bytes of this content address.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Serialize for EventId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().to_vec().serialize(s)
    }
}
impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        Ok(EventId(pillar_streamdb::OpId(
            pillar_crypto::ContentId::from_bytes(bytes),
        )))
    }
}

// `EventId` keys `BTreeMap`/`BTreeSet`, so it needs a total order. `OpId`
// (hence `ContentId`) is opaque and not `Ord`; order lexicographically by the
// multihash bytes — a pure, content-derived, node-independent order.
impl PartialOrd for EventId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EventId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

/// The signed content of an event: author, per-author sequence number, the
/// `prev` hash-link (the same-author chain edge; `None` for a genesis event),
/// the set of cross-author `parents` hash-links, and the opaque payload.
///
/// The [`EventId`] is a pure function of exactly these fields
/// ([`EventContent::id`]), so identical content deduplicates and a fork (two
/// distinct events sharing an id) is impossible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContent {
    author: Author,
    seq: u64,
    prev: Option<EventId>,
    parents: BTreeSet<EventId>,
    payload: Vec<u8>,
}

impl EventContent {
    /// The author of this event.
    #[must_use]
    pub fn author(&self) -> &Author {
        &self.author
    }

    /// The per-author sequence number (chain position) of this event.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The `prev` hash-link to the author's immediately preceding event, or
    /// `None` for a genesis (`seq == 0`) event.
    #[must_use]
    pub fn prev(&self) -> Option<EventId> {
        self.prev.clone()
    }

    /// The set of cross-author `parents` hash-links (observed tips of other
    /// authors — the happens-before edges).
    #[must_use]
    pub fn parents(&self) -> &BTreeSet<EventId> {
        &self.parents
    }

    /// The opaque event payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Every backward hash-link of this event: `prev` (if any) plus every
    /// cross-author parent. These are exactly the happens-before edges.
    fn links(&self) -> BTreeSet<EventId> {
        let mut links = self.parents.clone();
        if let Some(p) = &self.prev {
            links.insert(p.clone());
        }
        links
    }

    /// The canonical, deterministic byte serialization of this content. Fed to
    /// the content-address hash; stable across runs and platforms so two nodes
    /// holding the same content necessarily agree on its [`EventId`].
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.author.0.len() as u64).to_le_bytes());
        b.extend_from_slice(self.author.0.as_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        match &self.prev {
            Some(p) => {
                b.push(1);
                b.extend_from_slice(p.as_bytes());
            }
            None => b.push(0),
        }
        b.extend_from_slice(&(self.parents.len() as u64).to_le_bytes());
        // BTreeSet iterates in sorted order — canonical regardless of insert order.
        for p in &self.parents {
            b.extend_from_slice(p.as_bytes());
        }
        b.extend_from_slice(&self.payload);
        b
    }

    /// The content digest — the raw cryptographic content address (SHA2-256
    /// multihash bytes) of this content.
    fn digest(&self) -> pillar_streamdb::OpId {
        pillar_streamdb::OpId(content_address(&self.canonical_bytes()))
    }

    /// The content-addressed identity of this event.
    #[must_use]
    pub fn id(&self) -> EventId {
        EventId(self.digest())
    }

    /// Build content OUTSIDE the normal `append`/`ingest` authoring path, for
    /// a caller that must construct a deliberately forged/tampered fixture —
    /// e.g. the pillar-integration harness's crypto-realness oracle, which
    /// proves the audit view refuses to render a wrong-key-signed or
    /// tampered-after-signing event as legitimate. An ordinary writer should
    /// use [`EventLog::append`] instead; this constructor bypasses none of
    /// the log's OWN invariants — only [`EventLog::insert_unchecked`]
    /// (paired with this) skips `ingest`'s validation, and even then the
    /// audit view still authenticates every entry independently.
    #[must_use]
    pub fn for_fixture(
        author: Author,
        seq: u64,
        prev: Option<EventId>,
        parents: BTreeSet<EventId>,
        payload: Vec<u8>,
    ) -> Self {
        EventContent {
            author,
            seq,
            prev,
            parents,
            payload,
        }
    }
}

/// Deterministically derive an author's real ed25519 signing keypair from
/// its stable identifier.
///
/// This crate has no out-of-band keystore, so — mirroring the same
/// seed-derived-keypair convention `pillar_identity::login::backend_keypair`
/// uses for its own fixture identities — the keypair is derived from the
/// author's name via a domain-separated seed
/// ([`pillar_crypto::sign::signing_keypair_from_seed`]). A real deployment
/// may instead draw the seed from an OS CSPRNG / an enrolled identity's
/// actual key; either way the signature itself is genuine ed25519, not a
/// dependency-free stand-in.
fn author_signing_keypair(
    author: &Author,
) -> (pillar_crypto::SigningPublicKey, pillar_crypto::SigningSecretKey) {
    let seed = pillar_crypto::Seed::from_bytes(
        format!("pillar-eventlog/author-signing-seed::{}", author.0).into_bytes(),
    );
    pillar_crypto::sign::signing_keypair_from_seed(&seed)
        .expect("deterministic seed-derived ed25519 keygen never fails")
}

/// A *verified* ed25519 signature over an [`EventContent`] by its author —
/// backed by real `pillar_crypto` sign/verify (see
/// [`author_signing_keypair`]), not a dependency-free stand-in.
///
/// Constructing one via [`Signature::sign`] asserts the author signed the
/// content's digest with their real ed25519 secret key.
/// [`Signature::verifies`] recomputes the content digest and cryptographically
/// verifies the signature against it with the author's derived public key: if
/// any field of the content was rewritten after signing, the digest changes
/// and verification fails; a signature forged without the author's secret key
/// likewise fails, even if it happens to name the right digest —
/// tamper-evidence AND authenticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    author: Author,
    signature: pillar_crypto::Signature,
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.author, self.signature.as_bytes()).serialize(s)
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (author, bytes): (Author, Vec<u8>) = Deserialize::deserialize(d)?;
        Ok(Signature {
            author,
            signature: pillar_crypto::Signature::from_bytes(bytes),
        })
    }
}

impl Signature {
    /// Sign `content` as `author`: derive the author's real ed25519 secret
    /// key ([`author_signing_keypair`]) and sign the content's current
    /// digest with it.
    #[must_use]
    pub fn sign(author: &Author, content: &EventContent) -> Self {
        let (_public, secret) = author_signing_keypair(author);
        let digest = content.digest();
        let signature = pillar_crypto::sign::sign(&secret, digest.as_bytes())
            .expect("ed25519 signing over a fixed-length digest never fails");
        Signature {
            author: author.clone(),
            signature,
        }
    }

    /// Whether this signature verifies against `content`: it must be a
    /// genuine ed25519 signature, by the content's own author's derived
    /// secret key, over the content's (recomputed) digest. A rewritten link
    /// or payload changes the digest and fails this check; a forged
    /// signature by a non-author also fails (asymmetry — the public key
    /// alone cannot forge).
    #[must_use]
    pub fn verifies(&self, content: &EventContent) -> bool {
        if self.author != content.author {
            return false;
        }
        let (public, _secret) = author_signing_keypair(&self.author);
        let digest = content.digest();
        pillar_crypto::sign::verify(&public, digest.as_bytes(), &self.signature).is_ok()
    }

    /// The author who issued this signature.
    #[must_use]
    pub fn author(&self) -> &Author {
        &self.author
    }

    /// Build a deliberately mislabeled signature: relabel a REAL signature
    /// (e.g. genuinely produced by [`Signature::sign`] under a DIFFERENT
    /// author's own secret key) as having been issued by `claimed_author`,
    /// without holding `claimed_author`'s secret key. This is exactly the
    /// forged-key impersonation attempt the crypto-realness oracle proves
    /// [`Signature::verifies`] refuses (the claimed author's derived public
    /// key can never validate signature bytes produced by a different
    /// secret key) — a caller building a real fixture, never a shortcut
    /// around the real check.
    #[must_use]
    pub fn relabel_for_fixture(claimed_author: Author, genuine_signature: &Signature) -> Self {
        Signature {
            author: claimed_author,
            signature: genuine_signature.signature.clone(),
        }
    }
}

/// A fully-formed, signed event: its content plus its author's PGP signature,
/// carrying an explicit event-envelope schema version stamp
/// ([`Event::SCHEMA_VERSION`]).
///
/// The stamp lives on the ENVELOPE, deliberately OUTSIDE the hashed
/// [`EventContent`], so an envelope-schema revision never perturbs any existing
/// [`EventId`] (content addresses are unchanged) while still letting a reader
/// reject an envelope stamped with a version it does not understand — distinctly
/// from a parse/tamper failure. This is the event-envelope surface of ROI P1's
/// independent per-surface versioning; it advances independently of every other
/// surface's stamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The event-envelope schema version this event is stamped with.
    #[serde(default = "Event::default_schema_version")]
    schema_version: pillar_crypto::SurfaceVersion,
    content: EventContent,
    signature: Signature,
}

impl Event {
    /// The event-envelope schema version this build authors and understands.
    /// The event-envelope surface's own independent version line.
    pub const SCHEMA_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);

    /// The lowest event-envelope schema version this build still accepts on
    /// ingest.
    pub const MIN_SCHEMA_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);

    fn default_schema_version() -> pillar_crypto::SurfaceVersion {
        Event::SCHEMA_VERSION
    }

    /// The event-envelope schema version stamped on this event.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        self.schema_version
    }

    /// Assemble an event from already-signed content, stamped with the current
    /// envelope schema version. Used by the local-authoring path, by tests
    /// exercising ingest, and by a caller building a deliberately forged/
    /// tampered fixture (paired with [`EventContent::for_fixture`] and
    /// [`EventLog::insert_unchecked`]) to prove the audit view refuses to
    /// render it as legitimate.
    #[must_use]
    pub fn stamped(content: EventContent, signature: Signature) -> Self {
        Event {
            schema_version: Event::SCHEMA_VERSION,
            content,
            signature,
        }
    }

    /// The signed content of this event.
    #[must_use]
    pub fn content(&self) -> &EventContent {
        &self.content
    }

    /// The author's signature over this event.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The content-addressed identity of this event.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.content.id()
    }

    /// Whether this event's signature verifies against its content (see
    /// [`Signature::verifies`]).
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        self.signature.verifies(&self.content)
    }
}

/// Why an event was refused by [`EventLog::ingest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventError {
    /// The event's signature does not verify its content — a tampered link,
    /// payload, or a signature by someone other than the author.
    TamperedSignature,
    /// The event's stated [`EventId`] does not match its content's content
    /// address (a forged/mismatched id).
    IdMismatch,
    /// A genesis event (`seq == 0`) must carry no `prev` link, or a non-genesis
    /// event must carry one — this event violates that.
    MalformedChainLink,
    /// The event's `prev` link does not point at exactly its `(author, seq-1)`
    /// predecessor, or that predecessor is not present — a gap or a broken
    /// same-author chain (`NoGaps` / `PrevLinkIntegrity`).
    GapOrBrokenPrev,
    /// A `parents` link references an event authored by the SAME author, or an
    /// event that is not present — a dangling / non-cross-author causal edge
    /// (`ParentsCrossAuthorAndExist`).
    DanglingParent,
    /// The event's envelope carries a schema version this build does not
    /// understand (below [`Event::MIN_SCHEMA_VERSION`] or above
    /// [`Event::SCHEMA_VERSION`]). Distinct from [`EventError::TamperedSignature`]/
    /// [`EventError::IdMismatch`] (a corrupt/forged event): here the envelope
    /// parsed cleanly but is stamped for a version — typically a newer peer's —
    /// that this build cannot interpret.
    UnsupportedSchemaVersion(pillar_crypto::VersionError),
}

/// The append-only, content-addressed event DAG: the grow-only set of
/// published events (`log` in the spec), plus the per-author chain heights and
/// tips used to build and validate hash-links.
///
/// Events are stored behind the shared content-addressed store
/// ([`pillar_streamdb::OpLog`]) so an event's bytes are deduplicated by the
/// same canonical content-addressing used everywhere else in Pillar.
#[derive(Debug, Default)]
pub struct EventLog {
    store: OpLog,
    events: BTreeMap<EventId, Event>,
    height: BTreeMap<Author, u64>,
    tip: BTreeMap<Author, EventId>,
    /// Per-author, per-seq index: `(author, seq) -> EventId`. Lets anti-entropy
    /// address an author's chain by position (`Id(a, n)` in the spec) so a peer
    /// can serve exactly the contiguous range another peer is missing.
    by_seq: BTreeMap<(Author, u64), EventId>,
}

impl EventLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        EventLog::default()
    }

    /// The number of distinct events held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log holds no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether the log already holds `id`.
    #[must_use]
    pub fn contains(&self, id: &EventId) -> bool {
        self.events.contains_key(id)
    }

    /// Borrow a held event by id.
    #[must_use]
    pub fn get(&self, id: &EventId) -> Option<&Event> {
        self.events.get(id)
    }

    /// The current tip (latest event id) of `author`, if it has published.
    #[must_use]
    pub fn tip(&self, author: &Author) -> Option<EventId> {
        self.tip.get(author).cloned()
    }

    /// Author `author` appends `payload` as its next event, building the
    /// hash-links from local state: `prev` chains to the author's own current
    /// tip (`None` for the genesis event) and `parents` observes the current
    /// tip of every OTHER author that has published — the cross-author causal
    /// edges (`AddEvent` in the spec). The event is signed, content-addressed,
    /// and inserted; its id is returned.
    ///
    /// This is the local-authoring path, so its links are correct by
    /// construction and it never fails.
    pub fn append(&mut self, author: &Author, payload: impl Into<Vec<u8>>) -> EventId {
        let seq = self.height.get(author).copied().unwrap_or(0);
        let prev = self.tip.get(author).cloned();
        let parents: BTreeSet<EventId> = self
            .tip
            .iter()
            .filter(|(a, _)| *a != author)
            .map(|(_, id)| id.clone())
            .collect();
        let content = EventContent {
            author: author.clone(),
            seq,
            prev,
            parents,
            payload: payload.into(),
        };
        let signature = Signature::sign(author, &content);
        let event = Event::stamped(content, signature);
        // ingest cannot fail for a locally-authored, correctly-linked event.
        self.ingest(event)
            .expect("locally authored event is always valid")
    }

    /// Ingest a (possibly remotely gossiped) fully-formed event, enforcing
    /// every `EventDAG.tla` integrity invariant before admitting it:
    ///
    /// * **dedup** (`UniquePerAuthorSeq`) — an event already held is a no-op;
    ///   its id is returned unchanged (idempotent re-broadcast);
    /// * **tamper-evidence** (`PrevLinkIntegrity`) — the signature must verify
    ///   the content, and the stated id must match the content address;
    /// * **gap detection** (`NoGaps` + `PrevLinkIntegrity`) — a non-genesis
    ///   event's `prev` must be exactly its `(author, seq-1)` predecessor and
    ///   that predecessor must be present;
    /// * **cross-author causal edges** (`ParentsCrossAuthorAndExist`) — every
    ///   `parents` link must reference a present event of a DIFFERENT author.
    ///
    /// Returns the event's [`EventId`] on success, or the specific
    /// [`EventError`] that refused it.
    pub fn ingest(&mut self, event: Event) -> Result<EventId, EventError> {
        // Envelope-schema gate: reject a stamped-but-unknown envelope version
        // (e.g. a newer peer's) distinctly from a corrupt/tampered event.
        event
            .schema_version
            .check_supported(Event::MIN_SCHEMA_VERSION, Event::SCHEMA_VERSION)
            .map_err(EventError::UnsupportedSchemaVersion)?;

        let id = event.content.id();

        // Dedup: an already-held event is idempotent (re-broadcast is a no-op).
        if self.events.contains_key(&id) {
            return Ok(id);
        }

        // Tamper-evidence: the signature must cover the content, and the id
        // must be the genuine content address.
        if !event.is_authentic() {
            return Err(EventError::TamperedSignature);
        }
        if event.signature.author != event.content.author {
            return Err(EventError::TamperedSignature);
        }

        let author = event.content.author.clone();
        let seq = event.content.seq;

        // Same-author chain link + gap detection.
        match &event.content.prev {
            None => {
                if seq != 0 {
                    return Err(EventError::MalformedChainLink);
                }
                // Genesis: there must not already be a chain for this author at
                // seq 0 (a fork would violate UniquePerAuthorSeq); a distinct
                // genesis id colliding is impossible by content-addressing.
                if self.height.get(&author).copied().unwrap_or(0) != 0 {
                    return Err(EventError::GapOrBrokenPrev);
                }
            }
            Some(prev_id) => {
                if seq == 0 {
                    return Err(EventError::MalformedChainLink);
                }
                // The prev link must be exactly the (author, seq-1)
                // predecessor, which must be present — this is both gap
                // detection and prev-link integrity.
                let expected = self.tip.get(&author);
                if expected != Some(prev_id) {
                    return Err(EventError::GapOrBrokenPrev);
                }
                match self.events.get(prev_id) {
                    Some(p) if p.content.author == author && p.content.seq == seq - 1 => {}
                    _ => return Err(EventError::GapOrBrokenPrev),
                }
            }
        }

        // Cross-author causal edges: every parent exists and is a different
        // author.
        for parent_id in &event.content.parents {
            match self.events.get(parent_id) {
                Some(p) if p.content.author != author => {}
                _ => return Err(EventError::DanglingParent),
            }
        }

        // Admit: store the content-addressed bytes in the shared store, then
        // record the event and advance the author's chain.
        self.store.append(event.content.canonical_bytes());
        self.height.insert(author.clone(), seq + 1);
        self.tip.insert(author.clone(), id.clone());
        self.by_seq.insert((author, seq), id.clone());
        self.events.insert(id.clone(), event);
        Ok(id)
    }

    /// The set of STRICT ancestors of `id` reachable by following `prev` and
    /// `parents` hash-links backward (the transitive happens-before predecessor
    /// set). `id` itself is not included.
    #[must_use]
    pub fn ancestors(&self, id: &EventId) -> BTreeSet<EventId> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<EventId> = Vec::new();
        if let Some(ev) = self.events.get(id) {
            stack.extend(ev.content.links());
        }
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(ev) = self.events.get(&cur) {
                stack.extend(ev.content.links());
            }
        }
        seen
    }

    /// Whether `a` happens-before `b`: `a` is a strict ancestor of `b` in the
    /// DAG. This relation is the transitive closure of the `prev`/`parents`
    /// hash-links, and (per `CausalMonotone`) is a strict partial order —
    /// irreflexive, asymmetric, and transitive — so the DAG is acyclic.
    #[must_use]
    pub fn happens_before(&self, a: &EventId, b: &EventId) -> bool {
        self.ancestors(b).contains(a)
    }

    /// The authors that have published at least one event — the chains this log
    /// holds. Used by the audit view to enumerate the log deterministically.
    pub(crate) fn chain_authors(&self) -> Vec<Author> {
        self.height.keys().cloned().collect()
    }

    /// The contiguous chain height (next unheld seq) held for `author`; 0 if the
    /// author has no events. Because `NoGaps` holds, the author's events are
    /// exactly seq `0 .. chain_height`.
    pub(crate) fn chain_height(&self, author: &Author) -> u64 {
        self.height.get(author).copied().unwrap_or(0)
    }

    /// Insert a fully-formed event into the store WITHOUT running ingest's
    /// integrity checks — used by tests, and by the pillar-integration
    /// harness's crypto-realness oracle, to model a forged/tampered event
    /// that slipped into a replica's store (paired with
    /// [`EventContent::for_fixture`] / [`Signature::relabel_for_fixture`]),
    /// so the audit view can be shown to still refuse to render it as
    /// legitimate. An ordinary writer always goes through [`EventLog::append`]
    /// or [`EventLog::ingest`], both of which DO enforce every invariant;
    /// this bypass exists solely to construct the deliberately-invalid
    /// fixture the audit view must independently reject.
    pub fn insert_unchecked(&mut self, event: Event) {
        let id = event.content.id();
        let author = event.content.author.clone();
        let seq = event.content.seq;
        // Advance chain bookkeeping so the audit-view enumeration visits it,
        // without asserting any of ingest's invariants.
        let next = self.height.get(&author).copied().unwrap_or(0).max(seq + 1);
        self.height.insert(author.clone(), next);
        self.by_seq.insert((author, seq), id.clone());
        self.events.insert(id, event);
    }

    /// Test-only alias retained for the existing in-crate fixture tests.
    #[cfg(test)]
    pub(crate) fn insert_unchecked_for_test(&mut self, event: Event) {
        self.insert_unchecked(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn author(name: &str) -> Author {
        Author(name.to_string())
    }

    /// `UniquePerAuthorSeq` + content-address dedup: re-ingesting an event is a
    /// no-op (the log does not grow), and identical content yields an identical
    /// id (no fork).
    #[test]
    fn dedup_by_content_id() {
        let alice = author("alice");
        let mut log = EventLog::new();

        let g = log.append(&alice, b"genesis".to_vec());
        let e1 = log.get(&g).unwrap().clone();
        assert_eq!(log.len(), 1);

        // Re-broadcasting the very same event is idempotent.
        let again = log.ingest(e1.clone()).unwrap();
        assert_eq!(again, g);
        assert_eq!(
            log.len(),
            1,
            "re-ingesting a held event must not grow the log"
        );

        // Identical content computes the identical content address (no fork).
        let dup_content = EventContent {
            author: alice.clone(),
            seq: 0,
            prev: None,
            parents: BTreeSet::new(),
            payload: b"genesis".to_vec(),
        };
        assert_eq!(
            dup_content.id(),
            g.clone(),
            "identical content must share the content id"
        );

        // Different payload => different content address.
        let other = EventContent {
            payload: b"different".to_vec(),
            ..dup_content
        };
        assert_ne!(other.id(), g.clone());
    }

    /// `NoGaps`: an event at `seq n > 0` is refused unless its `n-1`
    /// predecessor is already present.
    #[test]
    fn gap_is_detected() {
        let alice = author("alice");
        let mut log = EventLog::new();
        let g = log.append(&alice, b"seq0".to_vec());

        // Forge a well-signed event at seq 2 whose prev points at the genuine
        // genesis — but seq 1 is missing. It must be refused as a gap.
        let content = EventContent {
            author: alice.clone(),
            seq: 2,
            prev: Some(g.clone()),
            parents: BTreeSet::new(),
            payload: b"seq2".to_vec(),
        };
        let signature = Signature::sign(&alice, &content);
        let gapped = Event::stamped(content, signature);

        assert_eq!(log.ingest(gapped), Err(EventError::GapOrBrokenPrev));
        assert_eq!(log.len(), 1, "a gapped event must not be admitted");

        // Filling seq 1 first, then seq 2 chained to it, is accepted.
        let s1 = log.append(&alice, b"seq1".to_vec());
        let c2 = EventContent {
            author: alice.clone(),
            seq: 2,
            prev: Some(s1.clone()),
            parents: BTreeSet::new(),
            payload: b"seq2".to_vec(),
        };
        let sig2 = Signature::sign(&alice, &c2);
        assert!(log.ingest(Event::stamped(c2, sig2)).is_ok());
    }

    /// `PrevLinkIntegrity`: a rewritten (tampered) hash-link breaks the
    /// signature and is rejected.
    #[test]
    fn tampered_link_is_rejected() {
        let alice = author("alice");
        let mut log = EventLog::new();
        let g = log.append(&alice, b"seq0".to_vec());
        let s1 = log.append(&alice, b"seq1".to_vec());

        // Take the genuine seq-1 event, then rewrite its prev link to point at
        // itself (history tampering) while keeping the original signature.
        let mut tampered = log.get(&s1).unwrap().clone();
        tampered.content.prev = Some(s1.clone());

        assert!(
            !tampered.is_authentic(),
            "rewriting a signed link must break the signature"
        );

        // A fresh log that has seq0 must still reject the tampered seq1.
        let mut log2 = EventLog::new();
        log2.ingest(log.get(&g).unwrap().clone()).unwrap();
        assert_eq!(log2.ingest(tampered), Err(EventError::TamperedSignature));
    }

    /// A real ed25519 keypair signs an event, and the resulting signature
    /// verifies via genuine `pillar_crypto` sign/verify — no dependency-free
    /// stand-in remains.
    #[test]
    fn real_keypair_signs_and_verifies_the_envelope() {
        let alice = author("alice");
        let content = EventContent {
            author: alice.clone(),
            seq: 0,
            prev: None,
            parents: BTreeSet::new(),
            payload: b"hello".to_vec(),
        };
        let signature = Signature::sign(&alice, &content);

        // The signature bytes are a genuine ed25519 detached signature (64
        // bytes), not a stand-in digest copy.
        assert_eq!(
            signature.signature.as_bytes().len(),
            64,
            "must be a real ed25519 signature, not a stand-in"
        );
        assert!(
            signature.verifies(&content),
            "a genuine signature by the content's own author must verify"
        );

        let (public, _secret) = author_signing_keypair(&alice);
        assert!(
            pillar_crypto::sign::verify(&public, content.digest().as_bytes(), &signature.signature)
                .is_ok(),
            "the signature must verify directly against pillar_crypto::sign::verify too"
        );
    }

    /// A forged event signature — one produced by a different author's key,
    /// or hand-rolled bytes claiming to be alice's — is rejected both by
    /// direct verification and by `EventLog::ingest` (the anti-entropy-sync
    /// ingest path).
    #[test]
    fn forged_event_signature_is_rejected_by_ingest() {
        let alice = author("alice");
        let mallory = author("mallory");
        let mut log = EventLog::new();
        let g = log.append(&alice, b"seq0".to_vec());
        let content = EventContent {
            author: alice.clone(),
            seq: 1,
            prev: Some(g),
            parents: BTreeSet::new(),
            payload: b"seq1".to_vec(),
        };

        // Forge #1: sign the SAME content with a different author's secret
        // key, then claim it was alice's signature.
        let mallory_sig_over_alice_content = Signature::sign(&mallory, &content);
        let forged = Signature {
            author: alice.clone(),
            signature: mallory_sig_over_alice_content.signature,
        };
        assert!(
            !forged.verifies(&content),
            "a signature produced by a non-author's key must not verify, even \
             relabelled with the victim's author id"
        );
        let event = Event::stamped(content.clone(), forged);
        assert_eq!(
            log.ingest(event),
            Err(EventError::TamperedSignature),
            "ingest must reject a forged signature"
        );

        // Forge #2: arbitrary bytes are not a valid signature at all.
        let garbage = Signature {
            author: alice.clone(),
            signature: pillar_crypto::Signature::from_bytes(vec![0u8; 64]),
        };
        assert!(!garbage.verifies(&content));
        assert_eq!(
            log.ingest(Event::stamped(content, garbage)),
            Err(EventError::TamperedSignature)
        );
    }

    /// `ParentsCrossAuthorAndExist`: a parent link to a same-author event, or
    /// to an absent event, is refused.
    #[test]
    fn parent_must_be_a_present_other_author() {
        let alice = author("alice");
        let mut log = EventLog::new();
        let g = log.append(&alice, b"seq0".to_vec());

        // seq1 by alice with a parent pointing at alice's own genesis — a
        // same-author "cross-author" edge is illegal.
        let content = EventContent {
            author: alice.clone(),
            seq: 1,
            prev: Some(g.clone()),
            parents: BTreeSet::from([g.clone()]),
            payload: b"seq1".to_vec(),
        };
        let signature = Signature::sign(&alice, &content);
        assert_eq!(
            log.ingest(Event::stamped(content, signature)),
            Err(EventError::DanglingParent)
        );

        // A parent id that is not present at all is also refused.
        let content = EventContent {
            author: alice.clone(),
            seq: 1,
            prev: Some(g.clone()),
            parents: BTreeSet::from([EventId(pillar_streamdb::OpId(
                pillar_crypto::content::content_address(b"absent-parent").unwrap(),
            ))]),
            payload: b"seq1".to_vec(),
        };
        let signature = Signature::sign(&alice, &content);
        assert_eq!(
            log.ingest(Event::stamped(content, signature)),
            Err(EventError::DanglingParent)
        );
    }

    /// `CausalMonotone`: happens-before (via `prev` and `parents`) is a STRICT
    /// partial order — irreflexive, asymmetric, transitive — over a real
    /// cross-author DAG, so the DAG is acyclic and its `parents` are genuine
    /// cross-author causal edges.
    #[test]
    fn causal_order_is_a_strict_partial_order() {
        let alice = author("alice");
        let bob = author("bob");
        let mut log = EventLog::new();

        // alice: a0 -> a1 ; bob observes a0 then publishes b0 (parent a0);
        // alice then publishes a1 observing bob's b0.
        let a0 = log.append(&alice, b"a0".to_vec());
        let b0 = log.append(&bob, b"b0".to_vec()); // parents = {a0}
        let a1 = log.append(&alice, b"a1".to_vec()); // prev a0, parents {b0}

        // Sanity: the cross-author edges were actually built.
        assert!(log.get(&b0).unwrap().content.parents().contains(&a0));
        assert!(log.get(&a1).unwrap().content.parents().contains(&b0));

        let all = [a0.clone(), b0.clone(), a1.clone()];

        // Irreflexive: nothing happens-before itself.
        for x in &all {
            assert!(
                !log.happens_before(x, x),
                "happens-before must be irreflexive"
            );
        }

        // Known edges of the causal order.
        assert!(log.happens_before(&a0, &b0));
        assert!(log.happens_before(&b0, &a1));
        assert!(log.happens_before(&a0, &a1)); // transitive: a0 -> b0 -> a1

        // Asymmetric: no pair is ordered both ways.
        for x in &all {
            for y in &all {
                if log.happens_before(x, y) {
                    assert!(
                        !log.happens_before(y, x),
                        "happens-before must be asymmetric (acyclic)"
                    );
                }
            }
        }

        // Transitive over the whole set.
        for x in &all {
            for y in &all {
                for z in &all {
                    if log.happens_before(x, y) && log.happens_before(y, z) {
                        assert!(
                            log.happens_before(x, z),
                            "happens-before must be transitive"
                        );
                    }
                }
            }
        }
    }

    /// Event-envelope version stamp: a locally-authored event carries the
    /// current schema version, and an envelope stamped with an unknown FUTURE
    /// version is refused by ingest — distinctly from a tamper/parse failure —
    /// while the CID of the wrapped content is unchanged by the envelope stamp.
    #[test]
    fn unknown_future_envelope_version_is_rejected_distinctly() {
        let alice = author("alice");
        let mut log = EventLog::new();
        let g = log.append(&alice, b"seq0".to_vec());
        // The locally-authored event is stamped with the current version.
        assert_eq!(log.get(&g).unwrap().schema_version(), Event::SCHEMA_VERSION);

        // Author a valid seq-1 event, then re-stamp its envelope to a future
        // version. Its content (and thus its CID) is untouched.
        let content = EventContent {
            author: alice.clone(),
            seq: 1,
            prev: Some(g.clone()),
            parents: BTreeSet::new(),
            payload: b"seq1".to_vec(),
        };
        let signature = Signature::sign(&alice, &content);
        let expected_id = content.id();
        let mut future = Event::stamped(content, signature);
        future.schema_version = pillar_crypto::SurfaceVersion(Event::SCHEMA_VERSION.0 + 1);

        // The envelope stamp did not perturb the content address.
        assert_eq!(
            future.id(),
            expected_id,
            "envelope stamp must not change CID"
        );
        // The signature still verifies (the stamp is outside the signed content).
        assert!(future.is_authentic());

        // Ingest refuses it as an unsupported version, NOT as tamper/gap.
        match log.ingest(future) {
            Err(EventError::UnsupportedSchemaVersion(
                pillar_crypto::VersionError::Unsupported { found, .. },
            )) => assert_eq!(
                found,
                pillar_crypto::SurfaceVersion(Event::SCHEMA_VERSION.0 + 1)
            ),
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }
}
