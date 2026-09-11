//! Portable, cell-minted **pillar-UDP session key** — the transport-frame
//! crypto that supersedes the seal-to-recipients handshakeless scheme
//! ([`crate::pillarmsg_udp`]) for pillar-UDP.
//!
//! Design of record: `docs/papers/pillar-udp-encryption.md`; formally gated by
//! `specs/PillarUdpEncryption.tla` (green under TLC — see the spec change doc).
//! This module is the executable refinement of that spec's obligations, one
//! for one:
//!
//! - **Deterministic, portable `K_s`** ([`derive_session_key`]) — a
//!   static-ephemeral X25519 ECDH against the **cell static key**, run through
//!   HKDF-SHA256 with a domain separator distinct from the content seal. The
//!   client derives it as `X25519(eph_sk, cell_static_pk)`; **every** cell node
//!   derives the byte-identical key as `X25519(cell_static_sk, eph_pk)` from the
//!   session record's inputs. No key rides the wire, `K_s` is **never stored**,
//!   and two racing ingress nodes cannot diverge (the "collision" is
//!   byte-identical). Refines `SessionConvergesOnOneKey`.
//! - **Cell-signed streamdb authorization record** ([`SessionRecord`],
//!   [`SessionStore`]) — an ingress node verifies the client's principal
//!   signature over the init, decides RBAC grants, and appends a
//!   **cell-signed** record carrying only the derivation inputs (never `K_s`).
//!   The record converges cell-wide; any node verifies `cell_sig` before it
//!   serves. Refines `SessionKeyCellSigned` + `SessionAuthorizedBeforeServe`.
//! - **Authorize-before-serve** ([`SessionStore::serve_key`]) — a node derives
//!   and serves `K_s` for a session **only** if it holds a converged,
//!   cell-signed, non-revoked record for it. A fabricated / unauthorized
//!   session id yields no key.
//! - **Anonymous-as-policy** ([`PolicySet`], [`grants_for`]) — an anonymous
//!   principal runs the identical scheme; only the default-deny RBAC outcome
//!   differs (an unattested principal never acquires a privileged grant).
//!   Refines `AnonIsUnattestedPrincipal`.
//! - **CID-dedup replay defense** ([`crate::pillar_udp::DedupProcessor`]) — a
//!   replayed frame has the same [`crate::pillar_udp::Cid`] and is dropped;
//!   no per-session replay window. Refines `SharedKeyReplayViaDedup`.
//! - **ed25519 `PillarMessage` sender identity** — `K_s` only proves cell
//!   membership (every cell node holds it), so sender identity is the
//!   ed25519 signature INSIDE the [`PillarMessage`], verified on open. Content
//!   is additionally cell-sealed end-to-end, unchanged.
//! - **Cell-signed revocation whose GC erases the record**
//!   ([`SessionStore::revoke`] / [`SessionStore::gc_erase`]) — a cell-signed
//!   revocation stops every node from honoring `K_s`; GC then **erases** the
//!   record within a bounded deadline (a revoked-but-uncollected record is a
//!   live decryption oracle). Refines `RevokedKeyEventuallyErased`.
//! - **Version-gated cutover** ([`negotiate_session_key_peer`]) — dropping the
//!   legacy Noise/seal path is a breaking pillar-UDP change; a legacy-era peer
//!   is refused cleanly, and a mixed rolling swarm coexists. Fallback ordering
//!   (pillar-udp → QUIC → TCP+TLS) is unchanged.
//!
//! Forward secrecy is **bounded to cell-key security + erase-on-revoke** by
//! design (paper §4) — an accepted tradeoff for cross-node portability, not a
//! gap.

use std::collections::HashMap;

use pillar_crypto::seal::x25519_shared_secret;
use pillar_crypto::{
    cell::group_key_from_seed, CellId, NegotiationRefused, SealingPublicKey, SealingSecretKey,
    Seed, Signature, SigningPublicKey, SigningSecretKey, SurfaceVersion, SymmetricKey,
};
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::store::Visibility;
use pillar_wire::{Body, PillarMessage};

use crate::pillar_udp::{
    Cid, MIN_PROTOCOL_VERSION as UDP_MIN_PROTOCOL_VERSION,
    PROTOCOL_COMPAT_WINDOW as UDP_COMPAT_WINDOW, PROTOCOL_SURFACE as UDP_SURFACE,
    PROTOCOL_VERSION as UDP_PROTOCOL_VERSION,
};

/// HKDF `info` domain separator for the pillar-UDP session key — distinct from
/// the content-seal derivation so a session key can never collide with a
/// content key.
const SESSION_KEY_INFO: &[u8] = b"pillar-udp/session/v1";
/// AEAD `info`/nonce domain for a session-key transport frame, separating it
/// from the content-seal's convergent nonce class.
const SESSION_FRAME_DOMAIN: &[u8] = b"pillar-udp/session-frame/v1";
/// The signed-init domain the client's principal signature covers, binding the
/// principal to exactly `(eph_pk, client_nonce, principal_pk)`.
const SESSION_INIT_SIG_DOMAIN: &[u8] = b"pillar-udp/session-init/v1";
/// The domain the CELL signature over a [`SessionRecord`] covers.
const SESSION_RECORD_SIG_DOMAIN: &[u8] = b"pillar-udp/session-record/v1";
/// The domain the CELL signature over a revocation covers.
const SESSION_REVOKE_SIG_DOMAIN: &[u8] = b"pillar-udp/session-revoke/v1";

/// A fault in the session-key transport crypto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The wrapped [`PillarMessage`] envelope/body could not be
    /// (de)serialized, or its version stamp was out of window.
    Envelope(pillar_wire::envelope::EnvelopeError),
    /// An AEAD / key-derivation fault (bad key, tampered frame, wrong aad).
    Crypto(pillar_crypto::CryptoError),
    /// The client's principal signature over the init did not verify.
    BadPrincipalSignature,
    /// The cell signature over the session record / revocation did not verify.
    BadCellSignature,
    /// No converged, cell-signed, non-revoked authorization exists for the
    /// session — a node MUST NOT derive or serve `K_s` (authorize-before-serve).
    NotAuthorized,
    /// The session was revoked; its key is no longer honored.
    Revoked,
    /// The inner envelope signature (transport-frame sender identity) failed.
    BadSenderSignature,
    /// The decoded body was not the expected [`Body::Control`] frame.
    NotAControlBody,
    /// A privileged operation was attempted by a principal whose grants do not
    /// permit it (default-deny; the anonymous / unattested case).
    Denied,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Envelope(e) => write!(f, "pillar-message envelope error: {e}"),
            SessionError::Crypto(e) => write!(f, "session-key crypto error: {e}"),
            SessionError::BadPrincipalSignature => {
                f.write_str("client principal signature invalid")
            }
            SessionError::BadCellSignature => {
                f.write_str("cell signature on session record invalid")
            }
            SessionError::NotAuthorized => {
                f.write_str("no converged cell-signed authorization for this session")
            }
            SessionError::Revoked => f.write_str("session revoked; key no longer honored"),
            SessionError::BadSenderSignature => {
                f.write_str("transport-frame sender signature invalid")
            }
            SessionError::NotAControlBody => f.write_str("expected a Control body frame"),
            SessionError::Denied => f.write_str("operation denied by default-deny policy"),
        }
    }
}

impl std::error::Error for SessionError {}

/// The grant set a principal holds in a session — the RBAC outcome the paper
/// (§6) calls `grants: PolicySet`. Anonymity is a *policy state* of this set,
/// not a separate scheme: an unattested principal gets [`PolicySet::restricted`]
/// (default-deny of sensitive/privileged ops), an attested one gets a grant
/// that includes [`Grant::Privileged`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PolicySet {
    grants: Vec<Grant>,
}

/// A single grant a session's principal may hold. The distinction the anonymity
/// boundary turns on is [`Grant::Privileged`]: an unattested (anonymous)
/// principal must never hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// Baseline: the session may communicate at all (every principal, including
    /// anonymous, holds this).
    Communicate,
    /// Access to sensitive data / privileged operations. An unattested
    /// principal must NEVER hold this (default-deny).
    Privileged,
}

impl PolicySet {
    /// The restricted (default-deny) grant set an **unattested** principal
    /// holds: it may communicate, but holds NO privileged grant. This is the
    /// anonymous case — same scheme, restricted policy.
    #[must_use]
    pub fn restricted() -> Self {
        Self {
            grants: vec![Grant::Communicate],
        }
    }

    /// The grant set an **attested** principal holds: communicate plus
    /// privileged access.
    #[must_use]
    pub fn attested() -> Self {
        Self {
            grants: vec![Grant::Communicate, Grant::Privileged],
        }
    }

    /// Whether this policy holds `grant`.
    #[must_use]
    pub fn allows(&self, grant: Grant) -> bool {
        self.grants.contains(&grant)
    }

    /// Whether this policy permits a **privileged** operation. Default-deny: an
    /// unattested principal's [`PolicySet::restricted`] returns `false`.
    #[must_use]
    pub fn is_privileged(&self) -> bool {
        self.allows(Grant::Privileged)
    }

    fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.grants.len());
        for g in &self.grants {
            v.push(match g {
                Grant::Communicate => 1u8,
                Grant::Privileged => 2u8,
            });
        }
        v
    }
}

/// Decide the grants for a principal, given whether the cell's WoT/RBAC holds a
/// signed role attestation for it. Anonymity is **not** a special code path:
/// an anonymous key with no attestation and a named user with no attestation
/// get the identical restricted set; only a principal with an attestation gets
/// the privileged set. This is exactly the paper's "anonymous = same scheme +
/// policy" (§6), reduced to the one bit the transport layer cares about.
#[must_use]
pub fn grants_for(is_attested: bool) -> PolicySet {
    if is_attested {
        PolicySet::attested()
    } else {
        PolicySet::restricted()
    }
}

/// The client-minted **session init**: everything an ingress node needs to
/// authorize the session and derive `K_s`, with the client's principal
/// signature binding the principal to the ephemeral inputs. Sprayed, redundant,
/// multipath — any ingress node processes it and the result is identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInit {
    /// The client's signing (identity) key — a node, a user, or an anonymous
    /// principal (cryptographically indistinguishable; §6).
    pub principal_pk: SigningPublicKey,
    /// The client's fresh ephemeral X25519 public key.
    pub eph_pk: SealingPublicKey,
    /// The client's random per-session nonce (HKDF salt + session-id input).
    pub client_nonce: Vec<u8>,
    /// The client principal's signature over `(eph_pk ‖ client_nonce)`.
    pub principal_sig: Signature,
}

impl SessionInit {
    /// The exact bytes the client principal signs (and an ingress node
    /// verifies): the init-sig domain, the ephemeral public key, and the nonce.
    fn signing_material(eph_pk: &SealingPublicKey, client_nonce: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(SESSION_INIT_SIG_DOMAIN);
        m.extend_from_slice(eph_pk.as_bytes());
        m.extend_from_slice(client_nonce);
        m
    }

    /// Mint a signed session init from a client principal's keypair, a fresh
    /// ephemeral X25519 keypair, and a random nonce. (Callers draw `eph`/`nonce`
    /// randomly per session; the acceptance test derives them from seeds.)
    ///
    /// # Errors
    /// [`SessionError::Crypto`] on a signing fault.
    pub fn mint(
        principal_pk: &SigningPublicKey,
        principal_sk: &SigningSecretKey,
        eph_pk: &SealingPublicKey,
        client_nonce: Vec<u8>,
    ) -> Result<Self, SessionError> {
        let material = Self::signing_material(eph_pk, &client_nonce);
        let principal_sig =
            pillar_crypto::sign::sign(principal_sk, &material).map_err(SessionError::Crypto)?;
        Ok(Self {
            principal_pk: principal_pk.clone(),
            eph_pk: eph_pk.clone(),
            client_nonce,
            principal_sig,
        })
    }

    /// Verify the client principal's signature over the ephemeral inputs.
    ///
    /// # Errors
    /// [`SessionError::BadPrincipalSignature`] if it does not verify.
    pub fn verify(&self) -> Result<(), SessionError> {
        let material = Self::signing_material(&self.eph_pk, &self.client_nonce);
        pillar_crypto::sign::verify(&self.principal_pk, &material, &self.principal_sig)
            .map_err(|_| SessionError::BadPrincipalSignature)
    }

    /// The session id: `content_address(eph_pk ‖ client_nonce)`. Canonical
    /// across every layer (same [`Cid`] the store / dedup use), so two racing
    /// ingress nodes and the client all agree on it.
    #[must_use]
    pub fn session_id(&self) -> Cid {
        let mut m = Vec::with_capacity(self.eph_pk.as_bytes().len() + self.client_nonce.len());
        m.extend_from_slice(self.eph_pk.as_bytes());
        m.extend_from_slice(&self.client_nonce);
        Cid::of(&m)
    }
}

/// Derive the portable session key `K_s` from a raw X25519 shared secret and
/// the client nonce (the HKDF salt), with the session-key domain separator.
///
/// Both endpoints call this with the byte-identical shared secret they each
/// computed via [`x25519_shared_secret`] (`X25519(eph_sk, cell_static_pk)` on
/// the client; `X25519(cell_static_sk, eph_pk)` on every cell node), so both
/// derive the byte-identical `K_s` with no key on the wire. `K_s` is returned
/// as a [`SymmetricKey`] and is **never stored** — every node recomputes it on
/// demand from the record's inputs.
#[must_use]
pub fn derive_session_key(shared_secret: &[u8; 32], client_nonce: &[u8]) -> SymmetricKey {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(client_nonce), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(SESSION_KEY_INFO, &mut okm)
        .expect("32-byte HKDF-SHA256 expansion is infallible");
    SymmetricKey::from_bytes(okm.to_vec())
}

/// The client side of `K_s` derivation: ECDH the client's ephemeral secret
/// against the published cell static public key, then HKDF. 0-RTT — the client
/// derives `K_s` the instant it picks its ephemeral key, before any round-trip.
///
/// # Errors
/// [`SessionError::Crypto`] on a malformed key.
pub fn client_session_key(
    eph_sk: &SealingSecretKey,
    cell_static_pk: &SealingPublicKey,
    client_nonce: &[u8],
) -> Result<SymmetricKey, SessionError> {
    let shared = x25519_shared_secret(eph_sk, cell_static_pk).map_err(SessionError::Crypto)?;
    Ok(derive_session_key(&shared, client_nonce))
}

/// The cell-node side of `K_s` derivation: ECDH the cell static secret against
/// the client's ephemeral public key (carried in the session record), then
/// HKDF. Byte-identical to [`client_session_key`] — that equality is the whole
/// portability guarantee.
///
/// # Errors
/// [`SessionError::Crypto`] on a malformed key.
pub fn cell_node_session_key(
    cell_static_sk: &SealingSecretKey,
    eph_pk: &SealingPublicKey,
    client_nonce: &[u8],
) -> Result<SymmetricKey, SessionError> {
    let shared = x25519_shared_secret(cell_static_sk, eph_pk).map_err(SessionError::Crypto)?;
    Ok(derive_session_key(&shared, client_nonce))
}

/// The cell-signed **session record** on streamdb: it carries only the
/// derivation inputs plus the cell authorization — **never** `K_s`. Any node
/// verifies `cell_sig` against the cell key, then may derive `K_s` and serve.
/// Converges cell-wide, so ingress failover / relay / load-balancing all serve
/// the same session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// `content_address(eph_pk ‖ client_nonce)` — the session id / dedup Cid.
    pub session_id: Cid,
    /// The client's signing (identity) key.
    pub principal_pk: SigningPublicKey,
    /// The client's ephemeral X25519 public key (a cell node ECDHs against it).
    pub eph_pk: SealingPublicKey,
    /// The client's per-session nonce (HKDF salt).
    pub client_nonce: Vec<u8>,
    /// The RBAC grant set decided for `principal_pk` at authorization time.
    pub grants: PolicySet,
    /// The CELL signature over this record — its provenance.
    pub cell_sig: Signature,
}

impl SessionRecord {
    /// The bytes the CELL signs over (everything but the signature itself).
    fn signing_material(
        session_id: &Cid,
        principal_pk: &SigningPublicKey,
        eph_pk: &SealingPublicKey,
        client_nonce: &[u8],
        grants: &PolicySet,
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(SESSION_RECORD_SIG_DOMAIN);
        m.extend_from_slice(session_id.as_bytes());
        m.extend_from_slice(principal_pk.as_bytes());
        m.extend_from_slice(eph_pk.as_bytes());
        m.extend_from_slice(client_nonce);
        m.extend_from_slice(&grants.to_wire());
        m
    }

    /// Verify this record's cell signature against the cell's signing key.
    ///
    /// # Errors
    /// [`SessionError::BadCellSignature`] if it does not verify.
    pub fn verify_cell_sig(&self, cell_signing_pk: &SigningPublicKey) -> Result<(), SessionError> {
        let material = Self::signing_material(
            &self.session_id,
            &self.principal_pk,
            &self.eph_pk,
            &self.client_nonce,
            &self.grants,
        );
        pillar_crypto::sign::verify(cell_signing_pk, &material, &self.cell_sig)
            .map_err(|_| SessionError::BadCellSignature)
    }
}

/// The **cell key material** every cell node holds: the cell's static X25519
/// sealing secret (for the ECDH that derives `K_s`) and the cell's ed25519
/// signing keypair (to sign / verify records + revocations). A client only
/// needs the public halves.
#[derive(Clone)]
pub struct CellKeys {
    /// Cell static X25519 secret — ECDH'd against a client ephemeral to derive
    /// `K_s`. Held by every cell node; never leaves the cell.
    pub static_sk: SealingSecretKey,
    /// Cell static X25519 public — published; a client ECDHs against it.
    pub static_pk: SealingPublicKey,
    /// Cell ed25519 signing secret — signs session records + revocations.
    pub signing_sk: SigningSecretKey,
    /// Cell ed25519 signing public — verifies records + revocations.
    pub signing_pk: SigningPublicKey,
}

impl CellKeys {
    /// Derive the cell key material deterministically from a cell seed. In a
    /// live deployment the cell's genesis principal holds these; here the
    /// derivation is exposed so a caller (and the acceptance test) obtains the
    /// exact keys a cell would hold.
    ///
    /// # Errors
    /// [`SessionError::Crypto`] on a key-derivation fault.
    pub fn from_seed(cell_seed: &str) -> Result<Self, SessionError> {
        let seed = Seed::from_bytes(format!("cell-static::{cell_seed}").into_bytes());
        let (static_pk, static_sk) =
            pillar_crypto::seal::sealing_keypair_from_seed(&seed).map_err(SessionError::Crypto)?;
        let sign_seed = Seed::from_bytes(format!("cell-signing::{cell_seed}").into_bytes());
        let (signing_pk, signing_sk) = pillar_crypto::sign::signing_keypair_from_seed(&sign_seed)
            .map_err(SessionError::Crypto)?;
        Ok(Self {
            static_sk,
            static_pk,
            signing_sk,
            signing_pk,
        })
    }
}

/// A converging, cell-internal view of session authorizations — the streamdb
/// slice this scheme rides. Every cell node has one; in a live deployment
/// streamdb convergence makes an authorization appended at one ingress visible
/// at every node. Modeled here as the per-node materialized view: records that
/// have converged, minus those that have been revoked, minus those GC has
/// erased.
#[derive(Debug, Default, Clone)]
pub struct SessionStore {
    /// Converged, cell-signed authorizations, keyed by session id.
    records: HashMap<Cid, SessionRecord>,
    /// Sessions with a converged, cell-signed revocation (key no longer
    /// honored). A revoked id is kept here until GC erases BOTH the record and
    /// this marker.
    revoked: HashMap<Cid, Signature>,
}

impl SessionStore {
    /// A fresh empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// **Authorize** a session at an ingress node: verify the client's
    /// principal signature, decide RBAC grants (`is_attested` gates the
    /// privileged set — anonymous ⇒ restricted), then mint and append a
    /// **cell-signed** record. Deterministic in its inputs: two racing ingress
    /// nodes append the byte-identical record (same `session_id` ⇒ same record;
    /// idempotent). Returns the cell-signed record (which then converges
    /// cell-wide).
    ///
    /// # Errors
    /// [`SessionError::BadPrincipalSignature`] if the init does not verify;
    /// [`SessionError::Crypto`] on a signing fault.
    pub fn authorize(
        &mut self,
        init: &SessionInit,
        is_attested: bool,
        cell: &CellKeys,
    ) -> Result<SessionRecord, SessionError> {
        init.verify()?;
        let session_id = init.session_id();
        let grants = grants_for(is_attested);
        let material = SessionRecord::signing_material(
            &session_id,
            &init.principal_pk,
            &init.eph_pk,
            &init.client_nonce,
            &grants,
        );
        let cell_sig =
            pillar_crypto::sign::sign(&cell.signing_sk, &material).map_err(SessionError::Crypto)?;
        let record = SessionRecord {
            session_id: session_id.clone(),
            principal_pk: init.principal_pk.clone(),
            eph_pk: init.eph_pk.clone(),
            client_nonce: init.client_nonce.clone(),
            grants,
            cell_sig,
        };
        // Append/converge (dedup: same session_id ⇒ one record).
        self.records
            .entry(session_id)
            .or_insert_with(|| record.clone());
        Ok(record)
    }

    /// Converge a cell-signed record replicated from another node into this
    /// node's view — the streamdb replication step (❸). Verifies the cell
    /// signature before admitting it (a node never honors an unsigned /
    /// forged record).
    ///
    /// # Errors
    /// [`SessionError::BadCellSignature`] if `cell_sig` does not verify.
    pub fn converge(
        &mut self,
        record: &SessionRecord,
        cell_signing_pk: &SigningPublicKey,
    ) -> Result<(), SessionError> {
        record.verify_cell_sig(cell_signing_pk)?;
        self.records
            .entry(record.session_id.clone())
            .or_insert_with(|| record.clone());
        Ok(())
    }

    /// The authorization record for a session, if this node holds a converged
    /// one that has not been revoked/erased.
    #[must_use]
    pub fn authorization(&self, session_id: &Cid) -> Option<&SessionRecord> {
        if self.revoked.contains_key(session_id) {
            return None;
        }
        self.records.get(session_id)
    }

    /// **Authorize-before-serve**: derive and return `K_s` for a session ONLY
    /// if this node holds a converged, cell-signed, non-revoked authorization
    /// for it. A fabricated / unauthorized / revoked / GC-erased session id
    /// yields [`SessionError::NotAuthorized`] (or [`SessionError::Revoked`]) and
    /// NO key — the node never derives a key it is not authorized to serve.
    ///
    /// # Errors
    /// [`SessionError::Revoked`] if a revocation converged; otherwise
    /// [`SessionError::NotAuthorized`] if there is no converged record;
    /// [`SessionError::Crypto`] on a key-derivation fault.
    pub fn serve_key(
        &self,
        session_id: &Cid,
        cell: &CellKeys,
    ) -> Result<SymmetricKey, SessionError> {
        if self.revoked.contains_key(session_id) {
            return Err(SessionError::Revoked);
        }
        let record = self
            .records
            .get(session_id)
            .ok_or(SessionError::NotAuthorized)?;
        cell_node_session_key(&cell.static_sk, &record.eph_pk, &record.client_nonce)
    }

    /// The grant set (policy) for a served session — the anonymity boundary.
    #[must_use]
    pub fn grants(&self, session_id: &Cid) -> Option<&PolicySet> {
        self.authorization(session_id).map(|r| &r.grants)
    }

    /// Sign a cell **revocation** for a session (on close / timeout). The
    /// returned signature is what converges to every node.
    ///
    /// # Errors
    /// [`SessionError::Crypto`] on a signing fault.
    pub fn sign_revocation(session_id: &Cid, cell: &CellKeys) -> Result<Signature, SessionError> {
        let mut m = Vec::new();
        m.extend_from_slice(SESSION_REVOKE_SIG_DOMAIN);
        m.extend_from_slice(session_id.as_bytes());
        pillar_crypto::sign::sign(&cell.signing_sk, &m).map_err(SessionError::Crypto)
    }

    /// **Revoke** a session in this node's view: verify the cell-signed
    /// revocation, then stop honoring `K_s` for it. Convergence carries the
    /// revocation to every node (each calls this). The record is NOT yet erased
    /// — that is [`gc_erase`](Self::gc_erase), a separate, security-critical
    /// step.
    ///
    /// # Errors
    /// [`SessionError::BadCellSignature`] if the revocation signature is invalid.
    pub fn revoke(
        &mut self,
        session_id: &Cid,
        revocation_sig: &Signature,
        cell_signing_pk: &SigningPublicKey,
    ) -> Result<(), SessionError> {
        let mut m = Vec::new();
        m.extend_from_slice(SESSION_REVOKE_SIG_DOMAIN);
        m.extend_from_slice(session_id.as_bytes());
        pillar_crypto::sign::verify(cell_signing_pk, &m, revocation_sig)
            .map_err(|_| SessionError::BadCellSignature)?;
        self.revoked
            .insert(session_id.clone(), revocation_sig.clone());
        Ok(())
    }

    /// **GC-erase** a revoked session's record — the security-critical
    /// collection (❻). A revoked-but-uncollected record keeps `K_s`
    /// **derivable** (its `eph_pk`/`client_nonce` are still present), i.e. it is
    /// a live decryption oracle, so GC must erase the record within a bounded
    /// deadline. After this, the derivation inputs are gone: no node can
    /// recompute `K_s`, even one holding the cell static key.
    ///
    /// Returns `true` if a revoked record was erased. Only a session that has
    /// actually been [`revoke`](Self::revoke)d is eligible — GC never erases a
    /// live authorization.
    pub fn gc_erase(&mut self, session_id: &Cid) -> bool {
        if self.revoked.contains_key(session_id) {
            let had_record = self.records.remove(session_id).is_some();
            self.revoked.remove(session_id);
            return had_record;
        }
        false
    }

    /// Whether the derivation inputs for `session_id` are still present in this
    /// node's view (i.e. `K_s` is still recomputable here). Used to assert the
    /// erase-on-revoke security property: after [`gc_erase`](Self::gc_erase)
    /// this is `false`.
    #[must_use]
    pub fn key_material_present(&self, session_id: &Cid) -> bool {
        self.records.contains_key(session_id)
    }
}

/// A sealed pillar-UDP **session frame**: a [`PillarMessage`] (signed by the
/// sender's ed25519 principal key — the sender identity) sealed under the
/// portable session key `K_s`, with a convergent nonce (collision-free without
/// coordination) so the many cell nodes sharing `K_s` never reuse a nonce.
///
/// `wrap` produces the inner cell-sealed, ed25519-signed [`PillarMessage`]
/// (content confidentiality + sender identity, unchanged from the content
/// seal), then this function seals it under `K_s` for the transport frame.
///
/// # Errors
/// [`SessionError::Envelope`] on an encoding fault, [`SessionError::Crypto`]
/// on a seal fault.
pub fn seal_frame(
    msg: &PillarMessage,
    session_key: &SymmetricKey,
) -> Result<(Cid, pillar_crypto::Ciphertext), SessionError> {
    use pillar_crypto::aead::{nonce_len, seal_symmetric_with_nonce};
    use pillar_crypto::AeadAlgorithm;

    let cbor = msg.to_canonical_cbor().map_err(SessionError::Envelope)?;
    // Replay-defense Cid: the content address of the frame plaintext. A
    // replayed frame has the same Cid ⇒ DedupProcessor drops it.
    let cid = Cid::of(&cbor);

    // Convergent nonce, HKDF'd from K_s over the frame content address, with a
    // session-frame domain separator — injective in the plaintext, so distinct
    // frames never reuse a nonce (NonceCollisionFree).
    let algorithm = AeadAlgorithm::current_default();
    let nonce = convergent_frame_nonce(session_key, &cbor, algorithm);
    let sealed =
        seal_symmetric_with_nonce(algorithm, session_key, &nonce, &cbor, SESSION_FRAME_DOMAIN)
            .map_err(SessionError::Crypto)?;
    let _ = nonce_len(algorithm);
    Ok((cid, sealed))
}

/// Open a session frame sealed by [`seal_frame`] with the served `K_s`,
/// recovering the [`PillarMessage`] and verifying its ed25519 sender identity.
///
/// # Errors
/// [`SessionError::Crypto`] if `session_key` is wrong / the frame is tampered;
/// [`SessionError::Envelope`] on a decode fault; [`SessionError::BadSenderSignature`]
/// if the inner sender signature is invalid.
pub fn open_frame(
    sealed: &pillar_crypto::Ciphertext,
    session_key: &SymmetricKey,
) -> Result<PillarMessage, SessionError> {
    let cbor = pillar_crypto::aead::open_symmetric(session_key, sealed, SESSION_FRAME_DOMAIN)
        .map_err(SessionError::Crypto)?;
    let msg = PillarMessage::from_canonical_cbor(&cbor).map_err(SessionError::Envelope)?;
    // Sender identity is the ed25519 signature INSIDE the envelope, NOT K_s
    // (which only proves cell membership).
    msg.verify_signature()
        .map_err(|_| SessionError::BadSenderSignature)?;
    Ok(msg)
}

/// Derive the convergent transport-frame nonce from `K_s` over the frame
/// content address, sized for `algorithm`, with the session-frame domain.
fn convergent_frame_nonce(
    session_key: &SymmetricKey,
    frame_plaintext: &[u8],
    algorithm: pillar_crypto::AeadAlgorithm,
) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    let ikm = Sha256::digest(frame_plaintext);
    let hk = Hkdf::<Sha256>::new(Some(session_key.as_bytes()), &ikm);
    let mut info = Vec::new();
    info.extend_from_slice(b"pillar-udp/session-frame-nonce/v1");
    let nonce_len = pillar_crypto::aead::nonce_len(algorithm);
    let mut nonce = vec![0u8; nonce_len];
    hk.expand(&info, &mut nonce)
        .expect("session-frame nonce HKDF expansion is infallible");
    nonce
}

/// Wrap a raw control payload as a signed, cell-sealed [`PillarMessage`] — the
/// content layer, identical in spirit to [`crate::pillarmsg_udp::wrap_control`]:
/// the inner ed25519 signature is the sender identity, and the body is
/// cell-sealed end-to-end (unchanged by the transport-frame session key). The
/// result is what [`seal_frame`] then seals under `K_s`.
///
/// # Errors
/// [`SessionError::Envelope`] on an encoding fault, [`SessionError::Crypto`]
/// on a seal/sign fault.
pub fn wrap_frame_body(
    raw: &[u8],
    cell_seed: &str,
    signer_pk: &SigningPublicKey,
    signer_sk: &SigningSecretKey,
) -> Result<PillarMessage, SessionError> {
    let body = Body::Control(raw.to_vec());
    let plaintext = body.to_canonical_cbor().map_err(SessionError::Envelope)?;

    let cell = CellId::from_bytes(format!("cell::{cell_seed}").into_bytes());
    let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
        .map_err(SessionError::Crypto)?;
    let aad = PillarMessage::header_aad(Visibility::Cell, &cell);
    let body_sealed = CellSeal
        .seal(
            &group,
            &plaintext,
            pillar_wire::seal::CONTROL_BODY_SEAL_DOMAIN,
            &aad,
        )
        .map_err(SessionError::Crypto)?;

    let signature =
        pillar_crypto::sign::sign(signer_sk, &PillarMessage::signing_material(&body_sealed))
            .map_err(SessionError::Crypto)?;

    Ok(PillarMessage::new(
        signer_pk.clone(),
        signature,
        Visibility::Cell,
        cell,
        body_sealed,
    ))
}

/// Recover the raw control bytes from a [`PillarMessage`] produced by
/// [`wrap_frame_body`] (the content layer): verify the sender signature, open
/// the cell-sealed body.
///
/// # Errors
/// [`SessionError::BadSenderSignature`], [`SessionError::Crypto`], or
/// [`SessionError::Envelope`] / [`SessionError::NotAControlBody`] on a fault.
pub fn unwrap_frame_body(msg: &PillarMessage, cell_seed: &str) -> Result<Vec<u8>, SessionError> {
    msg.verify_signature()
        .map_err(|_| SessionError::BadSenderSignature)?;
    let group = group_key_from_seed(&Seed::from_bytes(cell_seed.as_bytes().to_vec()))
        .map_err(SessionError::Crypto)?;
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext = CellSeal
        .open(&group, &msg.body_sealed, &aad)
        .map_err(SessionError::Crypto)?;
    let body = Body::from_canonical_cbor(&plaintext).map_err(SessionError::Envelope)?;
    match body {
        Body::Control(bytes) => Ok(bytes),
        _ => Err(SessionError::NotAControlBody),
    }
}

/// The ed25519 sender identity a frame's [`PillarMessage`] carries — the signer
/// public key. `K_s` proves only cell membership (every cell node holds it);
/// THIS is who sent the frame.
#[must_use]
pub fn frame_sender(msg: &PillarMessage) -> &SigningPublicKey {
    &msg.signer
}

/// Negotiate the session-key pillar-UDP cutover with a peer that declared
/// `remote_udp_version`. Dropping the legacy Noise/seal-to-recipients path is a
/// breaking pillar-UDP change ([`crate::pillar_udp::PROTOCOL_VERSION`] is
/// bumped): a legacy-era peer that never bumped past this build's window is
/// refused CLEANLY here rather than mis-framed, and a compatible peer inside
/// [`crate::pillar_udp::PROTOCOL_COMPAT_WINDOW`] links — a mixed
/// legacy/session-key swarm coexists through the rollout window. The
/// pillar-udp → QUIC → TCP+TLS fallback is unchanged (this only gates the
/// pillar-UDP transport-frame crypto).
///
/// # Errors
/// [`NegotiationRefused`] when the declared versions differ by more than the
/// compat window, or the remote is below the minimum this build understands.
pub fn negotiate_session_key_peer(
    remote_udp_version: SurfaceVersion,
) -> Result<(), NegotiationRefused> {
    if remote_udp_version.0 < UDP_MIN_PROTOCOL_VERSION.0 {
        return Err(NegotiationRefused {
            surface: UDP_SURFACE,
            local: UDP_PROTOCOL_VERSION,
            remote: remote_udp_version,
            window: UDP_COMPAT_WINDOW,
        });
    }
    pillar_crypto::negotiate_surface(
        UDP_SURFACE,
        UDP_PROTOCOL_VERSION,
        remote_udp_version,
        UDP_COMPAT_WINDOW,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_keys(
        seed: &str,
    ) -> (
        SigningPublicKey,
        SigningSecretKey,
        SealingPublicKey,
        SealingSecretKey,
    ) {
        let s = Seed::from_bytes(format!("client-sign::{seed}").into_bytes());
        let (spk, ssk) = pillar_crypto::sign::signing_keypair_from_seed(&s).unwrap();
        let e = Seed::from_bytes(format!("client-eph::{seed}").into_bytes());
        let (epk, esk) = pillar_crypto::seal::sealing_keypair_from_seed(&e).unwrap();
        (spk, ssk, epk, esk)
    }

    fn init_for(seed: &str) -> (SessionInit, SealingSecretKey) {
        let (spk, ssk, epk, esk) = client_keys(seed);
        let nonce = format!("nonce::{seed}").into_bytes();
        let init = SessionInit::mint(&spk, &ssk, &epk, nonce).unwrap();
        (init, esk)
    }

    #[test]
    fn ks_is_portable_client_equals_every_cell_node() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (init, esk) = init_for("alice");

        // Client derives K_s locally (0-RTT).
        let k_client = client_session_key(&esk, &cell.static_pk, &init.client_nonce).unwrap();
        // Any cell node derives the IDENTICAL K_s from the record inputs.
        let k_node =
            cell_node_session_key(&cell.static_sk, &init.eph_pk, &init.client_nonce).unwrap();
        assert_eq!(
            k_client.as_bytes(),
            k_node.as_bytes(),
            "client and every cell node MUST derive the byte-identical portable K_s"
        );
    }

    #[test]
    fn racing_ingress_nodes_derive_identical_key_and_authorize_identically() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (init, _esk) = init_for("alice");

        let mut n1 = SessionStore::new();
        let mut n2 = SessionStore::new();
        let r1 = n1.authorize(&init, true, &cell).unwrap();
        let r2 = n2.authorize(&init, true, &cell).unwrap();
        assert_eq!(
            r1, r2,
            "two racing ingress nodes append the byte-identical record"
        );
        assert_eq!(r1.session_id, init.session_id());

        let k1 = n1.serve_key(&init.session_id(), &cell).unwrap();
        let k2 = n2.serve_key(&init.session_id(), &cell).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn authorize_before_serve_refuses_unauthorized_session() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (init, _esk) = init_for("alice");
        let store = SessionStore::new();
        // No authorization converged → no key served.
        assert_eq!(
            store.serve_key(&init.session_id(), &cell),
            Err(SessionError::NotAuthorized)
        );
    }

    #[test]
    fn tampered_init_signature_is_refused() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (mut init, _esk) = init_for("alice");
        // Corrupt the nonce so the principal signature no longer matches.
        init.client_nonce.push(0xFF);
        let mut store = SessionStore::new();
        assert_eq!(
            store.authorize(&init, true, &cell),
            Err(SessionError::BadPrincipalSignature)
        );
    }

    #[test]
    fn record_requires_a_valid_cell_signature_to_converge() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let other = CellKeys::from_seed("cell-B").unwrap();
        let (init, _esk) = init_for("alice");
        let mut n1 = SessionStore::new();
        let record = n1.authorize(&init, true, &cell).unwrap();

        // Converging under the RIGHT cell key works.
        let mut n2 = SessionStore::new();
        assert!(n2.converge(&record, &cell.signing_pk).is_ok());
        // Under a DIFFERENT cell's key it is refused (forged provenance).
        let mut n3 = SessionStore::new();
        assert_eq!(
            n3.converge(&record, &other.signing_pk),
            Err(SessionError::BadCellSignature)
        );
    }

    #[test]
    fn anonymous_is_policy_not_a_separate_scheme() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (anon_init, _e) = init_for("anon");
        let (user_init, _e2) = init_for("attested-user");

        let mut store = SessionStore::new();
        // Anonymous / unattested: restricted grants, NO privileged.
        store.authorize(&anon_init, false, &cell).unwrap();
        let anon_grants = store.grants(&anon_init.session_id()).unwrap();
        assert!(anon_grants.allows(Grant::Communicate));
        assert!(
            !anon_grants.is_privileged(),
            "unattested principal must never be privileged"
        );

        // Attested: same scheme, privileged grant.
        store.authorize(&user_init, true, &cell).unwrap();
        let user_grants = store.grants(&user_init.session_id()).unwrap();
        assert!(user_grants.is_privileged());

        // The anonymous session still derives and serves K_s identically —
        // only the policy differs, not the crypto path.
        assert!(store.serve_key(&anon_init.session_id(), &cell).is_ok());
    }

    #[test]
    fn revocation_stops_service_and_gc_erases_key_material() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (init, _esk) = init_for("alice");
        let mut store = SessionStore::new();
        store.authorize(&init, true, &cell).unwrap();
        let sid = init.session_id();

        // Served before revocation.
        assert!(store.serve_key(&sid, &cell).is_ok());
        assert!(store.key_material_present(&sid));

        // Cell-signed revocation → no longer honored (but material still present).
        let rev = SessionStore::sign_revocation(&sid, &cell).unwrap();
        store.revoke(&sid, &rev, &cell.signing_pk).unwrap();
        assert_eq!(store.serve_key(&sid, &cell), Err(SessionError::Revoked));
        assert!(
            store.key_material_present(&sid),
            "before GC the derivation inputs are still present (the oracle window)"
        );

        // GC erases the record: K_s is no longer recomputable, even with the
        // cell static key.
        assert!(store.gc_erase(&sid));
        assert!(!store.key_material_present(&sid));
        // A fully-erased session is indistinguishable from one that never
        // existed — the derivation inputs are gone, so no key can be served.
        assert_eq!(
            store.serve_key(&sid, &cell),
            Err(SessionError::NotAuthorized)
        );

        // A forged revocation (wrong cell key) is refused.
        let (other_init, _o) = init_for("bob");
        let mut s2 = SessionStore::new();
        s2.authorize(&other_init, true, &cell).unwrap();
        let bad = SessionStore::sign_revocation(
            &other_init.session_id(),
            &CellKeys::from_seed("cell-B").unwrap(),
        )
        .unwrap();
        assert_eq!(
            s2.revoke(&other_init.session_id(), &bad, &cell.signing_pk),
            Err(SessionError::BadCellSignature)
        );
    }

    #[test]
    fn frame_seals_under_ks_and_carries_ed25519_sender_identity() {
        let cell = CellKeys::from_seed("cell-A").unwrap();
        let (spk, ssk, epk, esk) = client_keys("alice");
        let nonce = b"nonce-alice".to_vec();
        let init = SessionInit::mint(&spk, &ssk, &epk, nonce.clone()).unwrap();

        let mut store = SessionStore::new();
        store.authorize(&init, true, &cell).unwrap();
        let k_client = client_session_key(&esk, &cell.static_pk, &nonce).unwrap();
        let k_node = store.serve_key(&init.session_id(), &cell).unwrap();
        assert_eq!(k_client.as_bytes(), k_node.as_bytes());

        // Wrap + seal on the client side.
        let msg = wrap_frame_body(b"opsync-request", "cell-A", &spk, &ssk).unwrap();
        let (cid, sealed) = seal_frame(&msg, &k_client).unwrap();

        // Any cell node with the served K_s opens it and verifies sender identity.
        let opened = open_frame(&sealed, &k_node).unwrap();
        assert_eq!(
            frame_sender(&opened),
            &spk,
            "sender identity is the ed25519 signer, not K_s"
        );
        assert_eq!(
            unwrap_frame_body(&opened, "cell-A").unwrap(),
            b"opsync-request"
        );

        // A wrong K_s cannot open the frame.
        let wrong = client_session_key(&esk, &cell.static_pk, b"different-nonce").unwrap();
        assert!(matches!(
            open_frame(&sealed, &wrong),
            Err(SessionError::Crypto(_))
        ));

        // Replay defense: the same frame has the same Cid ⇒ dedup drops it.
        use crate::pillar_udp::DedupProcessor;
        let mut dedup = DedupProcessor::new();
        assert!(dedup.process(&cid), "first copy admitted");
        let (cid2, _sealed2) = seal_frame(&msg, &k_client).unwrap();
        assert_eq!(cid, cid2, "the frame is content-addressed convergently");
        assert!(
            !dedup.process(&cid2),
            "a replayed frame is deduped, not re-applied"
        );
    }

    #[test]
    fn negotiation_admits_matching_peer_and_refuses_legacy() {
        assert!(negotiate_session_key_peer(UDP_PROTOCOL_VERSION).is_ok());
        let legacy = SurfaceVersion(UDP_MIN_PROTOCOL_VERSION.0.saturating_sub(1));
        if legacy.0 < UDP_MIN_PROTOCOL_VERSION.0 {
            assert!(negotiate_session_key_peer(legacy).is_err());
        }
        let future = SurfaceVersion(UDP_PROTOCOL_VERSION.0 + UDP_COMPAT_WINDOW.0 + 1);
        assert!(negotiate_session_key_peer(future).is_err());
    }
}
