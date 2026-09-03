//! Four distinct, content-addressed signed trust artifact types — never one
//! overloaded "sign" — the Rust refinement of `specs/TrustArtifacts.tla`,
//! wired into `pillar_rbac`'s single decider.
//!
//! # Model
//!
//! - [`Certify`] — an identity self-binds its own subkey/identity.
//!   Unconditional, no chain to walk.
//! - [`Trust`] — an identity vouches for ANOTHER identity (an optional-depth
//!   WoT introduction edge), carrying no capacity/authorization of its own.
//! - [`Attest`] — an authorization CLAIM issued in a declared [`Capacity`]
//!   (`self` or `<role>@<scope>`, never ambient), carrying: `issuer`,
//!   `capacity`, `authority` (the [`Cid`] proof pointer of the prior grant
//!   the issuer is exercising — `None` only for the trust anchor / `self`
//!   capacity), `subject`, [`Predicate`] (action + resource + optional
//!   quantified quota), `scope`, and `epoch`. Capacity is checked AT SIGNING
//!   TIME ([`TrustStore::issue_attest`]) via [`TrustStore::holds_capacity`] —
//!   never deferred to a later verifier.
//! - [`Revoke`] — signed, epoch-stamped, fail-closed: targets one specific
//!   attest artifact by its content address, never a bare identity.
//!
//! [`TrustStore::verify`] is a PURE walk from an attest artifact's `authority`
//! proof pointer back to a genesis/self anchor: it consults only the stored
//! attest artifacts and the revoked set (no ambient lookup), always
//! terminates (bounded chain length, cycle-detected), rejects a broken or
//! cyclic chain, and renders the full [`Proof`] chain + natural-language
//! sentence. A revoked artifact anywhere on the path fails verification
//! closed at the epoch it was revoked.
//!
//! Quota attestations ([`Predicate::quota`]) are BUDGETS admitted via
//! [`TrustStore::admit_quota`] against a per-artifact ledger — never a bare
//! boolean allow; a non-quantified predicate is refused for quota admission.
//!
//! [`as_explicit_grants`] projects the store's currently-valid, non-revoked
//! role attestations into `pillar_rbac::ExplicitGrant`s, so the single
//! `RbacDecider` consumes attest artifacts through the SAME explicit-grant
//! rung it already exposes — no second, divergent enforcement path.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;
use pillar_crypto::sign::{sign, signing_keypair_from_seed, verify};
use pillar_crypto::{Seed, Signature as CryptoSignature, SigningPublicKey, SigningSecretKey};
use pillar_rbac::{Capability, ExplicitGrant, GrantEffect};

/// The content address of a stored artifact (a [`Attest`], keyed by its
/// [`Attest::cid`]). Distinct artifact instances with identical fields
/// address the SAME [`Cid`] — this is what makes an `authority` field a
/// genuine content-addressed "proof pointer" rather than an opaque handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub String);

/// The reproducible ed25519 keypair that *is* a named identity. As in
/// `pillar_identity::global_identity::PrimaryKeypair`, the string-modelled
/// identity name (`NodeId`) is treated as secret seed material via a
/// domain-separated derivation, so only a party that knows the name can
/// produce a signature that verifies under that identity. Distinct names
/// yield distinct keypairs, so a signer named `"mallory"` can never forge a
/// signature that verifies as `"owner"`.
#[derive(Clone)]
pub struct IdentityKeypair {
    name: NodeId,
    public: SigningPublicKey,
    secret: SigningSecretKey,
}

impl IdentityKeypair {
    /// Derive the reproducible keypair a `NodeId` name maps to. The name is
    /// domain-separated secret seed material — knowing the name is what lets
    /// you sign as that identity.
    #[must_use]
    pub fn for_name(name: impl Into<NodeId>) -> Self {
        let name = name.into();
        let (public, secret) = signing_keypair_from_seed(&name_seed(&name))
            .expect("a signing seed always yields an ed25519 keypair");
        IdentityKeypair {
            name,
            public,
            secret,
        }
    }

    /// This identity's ed25519 public (verifying) key.
    #[must_use]
    pub fn public(&self) -> &SigningPublicKey {
        &self.public
    }

    /// The identity name this keypair belongs to.
    #[must_use]
    pub fn name(&self) -> &NodeId {
        &self.name
    }

    /// Produce a genuine detached ed25519 [`Sig`] over `message`, embedding
    /// the claimed signer name and the verifying key so a verifier can both
    /// re-check the signature AND confirm the key is exactly the one the name
    /// derives to.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Sig {
        let sig = sign(&self.secret, message).expect("signing always succeeds");
        Sig {
            signer: self.name.clone(),
            issuer_public: self.public.clone(),
            sig,
        }
    }
}

/// The public verifying key an identity name derives to — the same key
/// [`IdentityKeypair::for_name`] would produce, without holding the secret.
#[must_use]
pub fn public_key_for(name: &NodeId) -> SigningPublicKey {
    let (public, _secret) = signing_keypair_from_seed(&name_seed(name))
        .expect("a signing seed always yields an ed25519 keypair");
    public
}

/// Domain-separated seed derivation binding an identity name to its keypair.
fn name_seed(name: &NodeId) -> Seed {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pillar-trust-artifacts/identity-keyname-seed-v1");
    h.update(name.0.as_bytes());
    Seed::from_bytes(h.finalize().to_vec())
}

/// A **genuine detached ed25519 signature** over an artifact's canonical
/// message: it carries the claimed signer name, the issuer's verifying key,
/// and the signature bytes. [`Sig::verifies_as`] confirms (a) the claimed
/// name matches, (b) the carried key is exactly the one that name derives to,
/// and (c) the ed25519 signature validates over the canonical message — so
/// producing a `Sig` that verifies as a given identity requires that
/// identity's secret seed. A forged assertion never verifies; the store no
/// longer trusts an unchecked `signer` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sig {
    /// The claimed signer (the string-modelled identity name).
    pub signer: NodeId,
    /// The issuer's ed25519 verifying key (must equal the key `signer`
    /// derives to).
    issuer_public: SigningPublicKey,
    /// The detached ed25519 signature bytes over the artifact's canonical
    /// message.
    sig: CryptoSignature,
}

impl Sig {
    /// Sign `message` as identity `signer` — deriving that identity's keypair
    /// from its name and producing a real ed25519 signature. Convenience over
    /// [`IdentityKeypair::for_name`] + [`IdentityKeypair::sign`].
    #[must_use]
    pub fn sign_as(signer: impl Into<NodeId>, message: &[u8]) -> Self {
        IdentityKeypair::for_name(signer).sign(message)
    }

    /// The verifying key this signature carries.
    #[must_use]
    pub fn issuer_public(&self) -> &SigningPublicKey {
        &self.issuer_public
    }

    /// Verify this signature over `message` for claimed signer `expected`:
    /// the claimed name must equal [`signer`](Sig::signer), the carried
    /// public key must be exactly the key that name derives to, AND the
    /// ed25519 signature must validate. Returns `false` for any forgery,
    /// name spoof, or tampered message.
    #[must_use]
    pub fn verifies_as(&self, expected: &NodeId, message: &[u8]) -> bool {
        if &self.signer != expected {
            return false;
        }
        if public_key_for(&self.signer) != self.issuer_public {
            return false;
        }
        verify(&self.issuer_public, message, &self.sig).is_ok()
    }
}

/// Compute a real, collision-resistant content address (a sha2-256 multihash
/// via [`pillar_crypto::content::content_address`]) over a canonical,
/// length-prefixed encoding of `parts` — never a non-cryptographic checksum.
/// The length prefixes make the encoding unambiguous, so distinct field
/// tuples can never collide by concatenation.
fn content_address(parts: &[&str]) -> Cid {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"pillar-trust-artifact-v1");
    for p in parts {
        let bytes = p.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    let addr = pillar_crypto::content::content_address(&buf)
        .expect("content_address is infallible for in-memory bytes");
    Cid(format!("trust:{}", hex(addr.as_bytes())))
}

/// The current, explicit schema version of the trust-artifact / attestation
/// surface — the one wire/storage shape all four artifact types
/// ([`Certify`]/[`Trust`]/[`Attest`]/[`Revoke`]) share. Per ROI P1
/// "Versioning, compatibility & safe rollout", this stamp is
/// independently-incrementable from every other surface's version and is
/// folded into each artifact's content address (and therefore its signed
/// material), so a version bump changes every affected [`Cid`] and is covered
/// by the signature. Bump this (and, when a floor retires, [`MIN_ARTIFACT_SCHEMA_VERSION`])
/// when the artifact field layout changes.
pub const ARTIFACT_SCHEMA_VERSION: pillar_crypto::SurfaceVersion = pillar_crypto::SurfaceVersion(1);

/// The lowest trust-artifact schema version THIS build still interprets. A
/// stamp below this floor (a retired version) or above [`ARTIFACT_SCHEMA_VERSION`]
/// (a stamped-but-unknown FUTURE version) is rejected distinctly via
/// [`check_artifact_schema_version`] — a [`pillar_crypto::VersionError::Unsupported`],
/// never a [`pillar_crypto::VersionError::Malformed`].
pub const MIN_ARTIFACT_SCHEMA_VERSION: pillar_crypto::SurfaceVersion =
    pillar_crypto::SurfaceVersion(1);

/// Validate an ARBITRARY claimed trust-artifact schema version against the
/// range `[MIN_ARTIFACT_SCHEMA_VERSION, ARTIFACT_SCHEMA_VERSION]` this build
/// supports. A version outside the window — most importantly one NEWER than
/// [`ARTIFACT_SCHEMA_VERSION`] — is a [`pillar_crypto::VersionError::Unsupported`],
/// reported distinctly from a parse error so the later compatibility layer can
/// treat a newer peer as negotiable rather than as corruption.
///
/// # Errors
/// [`pillar_crypto::VersionError::Unsupported`] if `v` is below the floor or
/// above the current version.
pub fn check_artifact_schema_version(
    v: pillar_crypto::SurfaceVersion,
) -> Result<(), pillar_crypto::VersionError> {
    v.check_supported(MIN_ARTIFACT_SCHEMA_VERSION, ARTIFACT_SCHEMA_VERSION)
}

/// Lowercase hex rendering of raw bytes (for a stable, readable [`Cid`]).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The declared capacity an [`Attest`] is issued in: `self` (unconditional,
/// over one's own identity) or `<role>@<scope>` (must be held, checked at
/// signing time). Always explicit — never ambient.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capacity {
    /// Unconditional capacity over the issuer's own identity.
    SelfCap,
    /// A named role scoped to a specific resource/domain — must be HELD
    /// (proven by a non-revoked, terminating walk to a genesis/self anchor)
    /// at the moment the attest carrying it is signed.
    Role {
        /// The role label (e.g. `"operator"`).
        role: String,
        /// The scope the role is bound to (e.g. `"cell-b"`).
        scope: String,
    },
}

impl Capacity {
    fn tag(&self) -> String {
        match self {
            Capacity::SelfCap => "self".to_owned(),
            Capacity::Role { role, scope } => format!("role:{role}@{scope}"),
        }
    }
}

/// An authorization predicate: an `action` over a `resource`, optionally
/// quantified by a `quota` — a budget (see [`TrustStore::admit_quota`]), not
/// a bare boolean allow. `quota = None` is a plain boolean-shaped predicate;
/// a `quota = Some(_)` predicate REQUIRES admission through the ledger and
/// is refused if treated as a bare boolean.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Predicate {
    /// The action this predicate authorizes (e.g. `"stream:append"`).
    pub action: String,
    /// The resource the action targets (e.g. `"cell-b/streams/*"`).
    pub resource: String,
    /// An optional quota budget quantifying the predicate (e.g. `cpu<=1000m`
    /// encoded as a raw milli-unit amount). `None` = unquantified.
    pub quota: Option<u64>,
}

impl Predicate {
    /// A plain, unquantified predicate.
    #[must_use]
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Predicate {
            action: action.into(),
            resource: resource.into(),
            quota: None,
        }
    }

    /// The same predicate, quantified by a quota budget.
    #[must_use]
    pub fn with_quota(mut self, quota: u64) -> Self {
        self.quota = Some(quota);
        self
    }
}

/// **certify** — an identity self-binds its own subkey/identity.
/// Unconditional: no chain to walk, exactly `GlobalIdentity`'s "certify
/// exactly one subkey" self-scoped act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certify {
    /// The identity performing the self-bind.
    pub identity: NodeId,
    /// The subkey/identity material being bound.
    pub subkey: NodeId,
    /// The signature over this artifact (must name `identity` as signer).
    pub sig: Sig,
}

impl Certify {
    /// This artifact's content address.
    #[must_use]
    pub fn cid(&self) -> Cid {
        content_address(&[
            "certify",
            ARTIFACT_SCHEMA_VERSION.0.to_string().as_str(),
            self.identity.0.as_str(),
            self.subkey.0.as_str(),
        ])
    }

    /// The canonical bytes this artifact's signature covers — its content
    /// address, so a valid signature is bound to exactly these fields (a
    /// tampered field changes the cid and invalidates the signature).
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        self.cid().0.into_bytes()
    }

    /// The trust-artifact schema version this artifact is stamped at.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        ARTIFACT_SCHEMA_VERSION
    }

    /// Validate this artifact's [`schema_version`](Certify::schema_version)
    /// against the range this build supports.
    ///
    /// # Errors
    /// [`pillar_crypto::VersionError::Unsupported`] if the stamp is out of range.
    pub fn check_schema_version(&self) -> Result<(), pillar_crypto::VersionError> {
        check_artifact_schema_version(self.schema_version())
    }

    /// Produce a real, signed `Certify` from `identity` over its own fields.
    #[must_use]
    pub fn signed(identity: impl Into<NodeId>, subkey: impl Into<NodeId>) -> Self {
        let identity = identity.into();
        let subkey = subkey.into();
        let msg = content_address(&[
            "certify",
            ARTIFACT_SCHEMA_VERSION.0.to_string().as_str(),
            identity.0.as_str(),
            subkey.0.as_str(),
        ])
            .0
            .into_bytes();
        Certify {
            sig: Sig::sign_as(identity.clone(), &msg),
            identity,
            subkey,
        }
    }
}

/// **trust** — an identity vouches for ANOTHER identity, with an optional
/// depth. Bare WoT reachability; carries no capacity of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    /// The identity vouching.
    pub truster: NodeId,
    /// The identity being vouched for.
    pub trustee: NodeId,
    /// The delegation depth this vouch permits onward.
    pub depth: u8,
    /// The signature over this artifact (must name `truster` as signer).
    pub sig: Sig,
}

impl Trust {
    /// This artifact's content address.
    #[must_use]
    pub fn cid(&self) -> Cid {
        content_address(&[
            "trust",
            ARTIFACT_SCHEMA_VERSION.0.to_string().as_str(),
            self.truster.0.as_str(),
            self.trustee.0.as_str(),
            self.depth.to_string().as_str(),
        ])
    }

    /// The canonical bytes this artifact's signature covers (its content
    /// address).
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        self.cid().0.into_bytes()
    }

    /// The trust-artifact schema version this artifact is stamped at.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        ARTIFACT_SCHEMA_VERSION
    }

    /// Validate this artifact's [`schema_version`](Trust::schema_version)
    /// against the range this build supports.
    ///
    /// # Errors
    /// [`pillar_crypto::VersionError::Unsupported`] if the stamp is out of range.
    pub fn check_schema_version(&self) -> Result<(), pillar_crypto::VersionError> {
        check_artifact_schema_version(self.schema_version())
    }

    /// Produce a real, signed `Trust` from `truster` over its own fields.
    #[must_use]
    pub fn signed(
        truster: impl Into<NodeId>,
        trustee: impl Into<NodeId>,
        depth: u8,
    ) -> Self {
        let truster = truster.into();
        let trustee = trustee.into();
        let msg = content_address(&[
            "trust",
            ARTIFACT_SCHEMA_VERSION.0.to_string().as_str(),
            truster.0.as_str(),
            trustee.0.as_str(),
            depth.to_string().as_str(),
        ])
        .0
        .into_bytes();
        Trust {
            sig: Sig::sign_as(truster.clone(), &msg),
            truster,
            trustee,
            depth,
        }
    }
}

/// **attest** — an authorization claim issued in a declared [`Capacity`].
/// See module docs for the full field semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attest {
    /// The identity issuing this attestation.
    pub issuer: NodeId,
    /// The capacity the issuer claims to be acting in (`self` or
    /// `<role>@<scope>`), checked at signing time.
    pub capacity: Capacity,
    /// The [`Cid`] proof pointer of the prior attest artifact the issuer is
    /// exercising to prove it holds `capacity` — `None` only for the trust
    /// anchor (genesis) or a `self`-capacity attest, which needs no prior
    /// grant to walk to.
    pub authority: Option<Cid>,
    /// The subject this attestation is about.
    pub subject: NodeId,
    /// The action/resource/optional-quota predicate this attestation
    /// authorizes.
    pub predicate: Predicate,
    /// The scope this attestation is valid within (e.g. a cell name).
    pub scope: String,
    /// The revocation-epoch stamp this attest was signed at (fenced: must
    /// equal the store's current epoch, or issuance is refused fail-closed).
    pub epoch: u64,
    /// The signature over this artifact (must name `issuer` as signer).
    pub sig: Sig,
}

impl Attest {
    /// This artifact's content address — a stable identity referenced by
    /// [`Attest::authority`] proof pointers and by [`Revoke::target`].
    #[must_use]
    pub fn cid(&self) -> Cid {
        content_address(&[
            "attest",
            ARTIFACT_SCHEMA_VERSION.0.to_string().as_str(),
            self.issuer.0.as_str(),
            self.capacity.tag().as_str(),
            self.authority.as_ref().map(|c| c.0.as_str()).unwrap_or(""),
            self.subject.0.as_str(),
            self.predicate.action.as_str(),
            self.predicate.resource.as_str(),
            self.predicate
                .quota
                .map(|q| q.to_string())
                .unwrap_or_default()
                .as_str(),
            self.scope.as_str(),
            self.epoch.to_string().as_str(),
        ])
    }

    /// The canonical bytes this attest's signature covers (its content
    /// address) — every authorization-bearing field is folded into the cid,
    /// so a tampered capacity/subject/predicate/epoch invalidates the
    /// signature.
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        self.cid().0.into_bytes()
    }

    /// The trust-artifact schema version this artifact is stamped at.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        ARTIFACT_SCHEMA_VERSION
    }

    /// Validate this artifact's [`schema_version`](Attest::schema_version)
    /// against the range this build supports.
    ///
    /// # Errors
    /// [`pillar_crypto::VersionError::Unsupported`] if the stamp is out of range.
    pub fn check_schema_version(&self) -> Result<(), pillar_crypto::VersionError> {
        check_artifact_schema_version(self.schema_version())
    }

    /// Re-sign this attest as its declared `issuer`, producing a real ed25519
    /// signature over its canonical message. Consumes and returns `self` so
    /// callers build the fields then sign in one expression.
    #[must_use]
    pub fn signed_by_issuer(mut self) -> Self {
        let msg = self.signed_message();
        self.sig = Sig::sign_as(self.issuer.clone(), &msg);
        self
    }
}

/// **revoke** — signed, epoch-stamped, fail-closed revocation of one
/// specific attest artifact (content-addressed: the [`Cid`] itself), never a
/// bare identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoke {
    /// The attest artifact this revocation targets.
    pub target: Cid,
    /// The signer of this revocation.
    pub sig: Sig,
}

impl Revoke {
    /// The canonical bytes this revocation's signature covers: a
    /// domain-separated encoding of the target content address, so a
    /// revocation signature is bound to exactly the artifact it revokes.
    #[must_use]
    pub fn signed_message(target: &Cid) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"pillar-trust-artifact-revoke-v1:");
        m.extend_from_slice(ARTIFACT_SCHEMA_VERSION.0.to_string().as_bytes());
        m.push(b':');
        m.extend_from_slice(target.0.as_bytes());
        m
    }

    /// The trust-artifact schema version this revocation is stamped at.
    #[must_use]
    pub fn schema_version(&self) -> pillar_crypto::SurfaceVersion {
        ARTIFACT_SCHEMA_VERSION
    }

    /// Validate this revocation's [`schema_version`](Revoke::schema_version)
    /// against the range this build supports.
    ///
    /// # Errors
    /// [`pillar_crypto::VersionError::Unsupported`] if the stamp is out of range.
    pub fn check_schema_version(&self) -> Result<(), pillar_crypto::VersionError> {
        check_artifact_schema_version(self.schema_version())
    }

    /// Produce a real, signed `Revoke` of `target` by `signer`.
    #[must_use]
    pub fn signed(target: Cid, signer: impl Into<NodeId>) -> Self {
        let msg = Revoke::signed_message(&target);
        Revoke {
            sig: Sig::sign_as(signer, &msg),
            target,
        }
    }
}

/// Why an operation on the [`TrustStore`] was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// A signature's `signer` does not match the artifact's claimed actor
    /// (e.g. a `Certify` whose `sig.signer != identity`) — an ambiguous /
    /// mismatched sign is never accepted where a typed artifact is required.
    SignerMismatch,
    /// A `<role>@<scope>` [`Attest`] whose issuer does NOT currently hold
    /// that capacity (per the pure walk) at signing time.
    CapacityNotHeld {
        /// The issuer that does not currently hold the claimed capacity.
        issuer: NodeId,
    },
    /// An [`Attest`] signed at a stale epoch view (`epoch != current`) —
    /// fail-closed, never optimistic.
    StaleEpoch {
        /// The epoch the attest was signed at.
        attempted: u64,
        /// The store's current epoch.
        current: u64,
    },
    /// A [`Revoke`] naming a [`Cid`] this store has never seen.
    UnknownTarget(Cid),
    /// [`TrustStore::admit_quota`] called against a predicate with no quota
    /// component — a boolean-only path is refused for quota admission.
    NotAQuotaPredicate,
    /// A quota admission that would exceed the attest's declared budget.
    QuotaExceeded {
        /// The amount that was requested.
        requested: u64,
        /// The amount actually remaining in the budget.
        remaining: u64,
    },
}

/// Why [`TrustStore::verify`] refused to certify a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The chain references a [`Cid`] this store has never stored — a
    /// broken chain.
    Broken(Cid),
    /// The chain revisits a [`Cid`] already on the walk — a cyclic chain.
    Cycle(Cid),
    /// A [`Cid`] on the chain has been revoked — fails closed at the epoch
    /// it was revoked, regardless of anything else on the chain.
    Revoked(Cid),
}

/// A rendered, successful verification: the full proof chain (subject-most
/// artifact first, genesis-most last) plus a natural-language sentence
/// `describe`/audit can show directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The full chain of [`Cid`]s walked, subject-most first.
    pub chain: Vec<Cid>,
    /// A natural-language rendering of the chain for `describe`/audit.
    pub sentence: String,
}

/// A bound on chain length the pure walk will traverse before concluding the
/// chain must be cyclic (never reached on an honest, acyclic chain shorter
/// than this, since every stored [`Cid`] is distinct).
const MAX_CHAIN_LEN: usize = 4096;

/// The trust-artifact store: holds every issued [`Attest`] (keyed by its
/// [`Cid`]), the grow-only revoked set, the current global revocation
/// epoch, and the per-attest quota admission ledger.
///
/// `genesis` is the trust anchor: it unconditionally holds every capacity
/// (mirrors `Owner` in `specs/TrustArtifacts.tla`), so an `Attest` whose
/// `issuer == genesis` needs no `authority` proof pointer at all.
#[derive(Clone, Debug)]
pub struct TrustStore {
    genesis: NodeId,
    attests: HashMap<Cid, Attest>,
    revoked: HashSet<Cid>,
    epoch: u64,
    /// Per-quota-attest cumulative admitted amount (never exceeds the
    /// attest's declared `predicate.quota`).
    admitted: HashMap<Cid, u64>,
}

impl TrustStore {
    /// A fresh store anchored at `genesis` (the trust anchor, which
    /// unconditionally holds every capacity), starting at epoch 0.
    #[must_use]
    pub fn new(genesis: NodeId) -> Self {
        TrustStore {
            genesis,
            attests: HashMap::new(),
            revoked: HashSet::new(),
            epoch: 0,
            admitted: HashMap::new(),
        }
    }

    /// The trust anchor this store is rooted at.
    #[must_use]
    pub fn genesis(&self) -> &NodeId {
        &self.genesis
    }

    /// The current global revocation epoch. An [`Attest`] must be signed at
    /// exactly this epoch to be accepted (fenced, fail-closed on lag).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Record a **certify** artifact: unconditional (AP), rejecting only a
    /// signer mismatch — no typed replacement for a bare/ambiguous sign is
    /// accepted here.
    pub fn certify(&self, c: &Certify) -> Result<Cid, TrustError> {
        if !c.sig.verifies_as(&c.identity, &c.signed_message()) {
            return Err(TrustError::SignerMismatch);
        }
        Ok(c.cid())
    }

    /// Record a **trust** artifact: unconditional (AP), rejecting only a
    /// signer mismatch.
    pub fn trust(&self, t: &Trust) -> Result<Cid, TrustError> {
        if !t.sig.verifies_as(&t.truster, &t.signed_message()) {
            return Err(TrustError::SignerMismatch);
        }
        Ok(t.cid())
    }

    /// Whether `subject` currently holds `capacity` — a PURE walk consulting
    /// only stored attests and the revoked set. The genesis anchor holds
    /// every capacity unconditionally; any other identity must own a
    /// non-revoked `Attest` issued to it under this exact capacity whose own
    /// chain verifies back to genesis.
    #[must_use]
    pub fn holds_capacity(&self, subject: &NodeId, capacity: &Capacity) -> bool {
        if subject == &self.genesis {
            return true;
        }
        self.attests.values().any(|a| {
            &a.subject == subject
                && &a.capacity == capacity
                && !self.revoked.contains(&a.cid())
                && self.verify(&a.cid()).is_ok()
        })
    }

    /// Issue an **attest** artifact: the single gated entry point enforcing
    /// `CapacityHeldAtSigning` (a `Role` capacity must be held by `issuer`,
    /// proven by the pure walk, RIGHT NOW — never deferred) and the fenced
    /// epoch discipline (`epoch` must equal [`TrustStore::epoch`] exactly).
    /// `self` capacity is unconditional over the issuer's own identity.
    pub fn issue_attest(&mut self, a: Attest) -> Result<Cid, TrustError> {
        let cid = self.decide_attest(&a)?;
        self.attests.insert(cid.clone(), a);
        Ok(cid)
    }

    /// The PURE decision [`TrustStore::issue_attest`] would enforce for `a`
    /// — signer match, the fenced epoch check, and (for a `Role` capacity)
    /// that `issuer` currently holds it — WITHOUT recording anything. This
    /// is the single decider both the real issuance and a `--dry-run`
    /// preview call: `issue_attest` computes its `Cid` by calling this
    /// function first, so `dry_run_attest(a) == Ok(cid)` iff a subsequent
    /// `issue_attest(a)` would ALSO succeed and mint that same `cid` —
    /// predicted == enforced, structurally, not merely by test coverage.
    /// On success returns the [`Cid`] the artifact WOULD be stored under;
    /// the store is left completely unchanged either way.
    ///
    /// # Errors
    /// The same [`TrustError`] variants `issue_attest` returns.
    pub fn decide_attest(&self, a: &Attest) -> Result<Cid, TrustError> {
        if !a.sig.verifies_as(&a.issuer, &a.signed_message()) {
            return Err(TrustError::SignerMismatch);
        }
        if a.epoch != self.epoch {
            return Err(TrustError::StaleEpoch {
                attempted: a.epoch,
                current: self.epoch,
            });
        }
        match &a.capacity {
            Capacity::SelfCap => {}
            Capacity::Role { .. } => {
                if a.issuer != self.genesis && !self.holds_capacity(&a.issuer, &a.capacity) {
                    return Err(TrustError::CapacityNotHeld {
                        issuer: a.issuer.clone(),
                    });
                }
            }
        }
        Ok(a.cid())
    }

    /// `describe <attest cid>` (VIEW): a human-readable rendering of a
    /// stored [`Attest`] INCLUDING its provenance — the signer, and the
    /// **exercised authority**: the `authority` [`Cid`] proof pointer walked
    /// all the way back to the genesis/self anchor (the same [`Proof`]
    /// [`TrustStore::verify`] computes), rendered as its natural-language
    /// sentence. An artifact that needs no prior grant to walk (a `self`
    /// capacity, or one issued directly by genesis with no `authority`
    /// pointer) describes cleanly as `"(self-issued; no authority to
    /// walk)"` — it never FABRICATES a chain where none was exercised.
    /// Returns `None` if `cid` names no stored artifact. Signs/mutates
    /// nothing.
    #[must_use]
    pub fn describe(&self, cid: &Cid) -> Option<String> {
        let a = self.attests.get(cid)?;
        let mut out = String::new();
        out.push_str(&format!("Cid:         {}\n", cid.0));
        out.push_str(&format!("Signer:      {}\n", a.sig.signer.0));
        out.push_str(&format!("Issuer:      {}\n", a.issuer.0));
        out.push_str(&format!("Capacity:    {}\n", a.capacity.tag()));
        out.push_str(&format!("Subject:     {}\n", a.subject.0));
        out.push_str(&format!(
            "Predicate:   {} {}\n",
            a.predicate.action, a.predicate.resource
        ));
        out.push_str(&format!("Scope:       {}\n", a.scope));
        out.push_str(&format!("Epoch:       {}\n", a.epoch));
        out.push_str("Exercised-Authority: ");
        if a.authority.is_none() {
            // Nothing was exercised to sign this artifact — never invent a
            // chain the artifact never walked.
            out.push_str("(self-issued; no authority to walk)\n");
        } else {
            match self.verify(cid) {
                Ok(proof) => out.push_str(&format!("{}\n", proof.sentence)),
                Err(e) => out.push_str(&format!("(unverifiable: {e:?})\n")),
            }
        }
        out.push_str(&format!(
            "Revoked:     {}\n",
            if self.revoked.contains(cid) {
                "yes"
            } else {
                "no"
            }
        ));
        Some(out)
    }

    /// **revoke** — epoch-stamped, fail-closed: marks `target` revoked (a
    /// specific attest artifact, content-addressed) and bumps the global
    /// epoch by exactly one, so any attest signed at the prior epoch is
    /// immediately stale for future issuance and `target`'s own chain (and
    /// anything walking through it) fails verification closed from this
    /// point on.
    pub fn revoke(&mut self, r: &Revoke) -> Result<(), TrustError> {
        if !r
            .sig
            .verifies_as(&r.sig.signer.clone(), &Revoke::signed_message(&r.target))
        {
            return Err(TrustError::SignerMismatch);
        }
        if !self.attests.contains_key(&r.target) {
            return Err(TrustError::UnknownTarget(r.target.clone()));
        }
        self.revoked.insert(r.target.clone());
        self.epoch += 1;
        Ok(())
    }

    /// A PURE walk from `cid` back to a genesis/self anchor: consults ONLY
    /// stored attests and the revoked set (no ambient lookup), always
    /// terminates ([`MAX_CHAIN_LEN`]-bounded, cycle-detected), rejects a
    /// broken (missing target) or cyclic chain, and — on success — renders
    /// the full [`Proof`] chain plus a natural-language sentence.
    pub fn verify(&self, cid: &Cid) -> Result<Proof, VerifyError> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = cid.clone();
        loop {
            if !seen.insert(cur.clone()) {
                return Err(VerifyError::Cycle(cur));
            }
            if chain.len() >= MAX_CHAIN_LEN {
                return Err(VerifyError::Cycle(cur));
            }
            if self.revoked.contains(&cur) {
                return Err(VerifyError::Revoked(cur));
            }
            let Some(a) = self.attests.get(&cur) else {
                return Err(VerifyError::Broken(cur));
            };
            chain.push(cur.clone());
            match &a.authority {
                None => break,
                Some(parent) => cur = parent.clone(),
            }
        }
        let sentence = render_sentence(&chain, self);
        Ok(Proof { chain, sentence })
    }

    /// Admit a quota-quantified predicate: requires `cid` to name an attest
    /// whose predicate carries a quota (a boolean-only predicate is refused
    /// — [`TrustError::NotAQuotaPredicate`]), that its chain currently
    /// verifies (subject holds the capacity, chain not revoked), and that
    /// cumulative admissions against it never exceed its declared budget.
    /// The reservation is per-artifact: a BUDGET ledger, not a bare boolean
    /// allow.
    pub fn admit_quota(&mut self, cid: &Cid, amt: u64) -> Result<(), TrustError> {
        let a = self
            .attests
            .get(cid)
            .ok_or_else(|| VerifyError::Broken(cid.clone()));
        let a = match a {
            Ok(a) => a,
            Err(_) => return Err(TrustError::UnknownTarget(cid.clone())),
        };
        let quota = a.predicate.quota.ok_or(TrustError::NotAQuotaPredicate)?;
        self.verify(cid).map_err(|_| TrustError::CapacityNotHeld {
            issuer: a.issuer.clone(),
        })?;
        let used = *self.admitted.get(cid).unwrap_or(&0);
        if used + amt > quota {
            return Err(TrustError::QuotaExceeded {
                requested: amt,
                remaining: quota - used,
            });
        }
        self.admitted.insert(cid.clone(), used + amt);
        Ok(())
    }

    /// The cumulative amount admitted so far against a quota attest's
    /// budget.
    #[must_use]
    pub fn admitted_amount(&self, cid: &Cid) -> u64 {
        *self.admitted.get(cid).unwrap_or(&0)
    }

    /// Every currently-live (non-revoked, chain-verified) `Attest` in this
    /// store — used by [`as_explicit_grants`] and by `describe`/audit
    /// rendering.
    fn live_attests(&self) -> impl Iterator<Item = (&Cid, &Attest)> {
        self.attests
            .iter()
            .filter(move |(cid, _)| !self.revoked.contains(*cid) && self.verify(cid).is_ok())
    }

    /// A PURE view of the trust graph: one [`GraphEdge`] per currently-live
    /// (non-revoked, chain-verified) attest, `issuer -> subject` labeled
    /// with the capacity/predicate it authorizes. Reads only — signs and
    /// stores nothing, exactly the trust-graph visualization tile needs.
    #[must_use]
    pub fn graph_edges(&self) -> Vec<GraphEdge> {
        let mut edges: Vec<GraphEdge> = self
            .live_attests()
            .map(|(cid, a)| GraphEdge {
                cid: cid.clone(),
                from: a.issuer.clone(),
                to: a.subject.clone(),
                label: format!(
                    "{}:{}({})",
                    a.capacity.tag(),
                    a.predicate.action,
                    a.predicate.resource
                ),
            })
            .collect();
        edges.sort_by(|a, b| a.cid.cmp(&b.cid));
        edges
    }
}

/// One edge in the pure trust-graph view: `from` (the issuer) `-> to` (the
/// subject), carrying the capacity/predicate `label` the underlying attest
/// authorizes and the attest's own [`Cid`] (so a viewer can cross-reference
/// the full [`Proof`] chain via [`TrustStore::verify`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphEdge {
    /// The underlying attest's content address.
    pub cid: Cid,
    /// The issuing identity.
    pub from: NodeId,
    /// The subject the attest is about.
    pub to: NodeId,
    /// A short rendering of the capacity + predicate this edge authorizes.
    pub label: String,
}

/// Parse a `--quota <resource>=<amount>[m]` budget form (e.g. `cpu=1000m`)
/// into a raw milli-unit amount, matching [`Predicate::with_quota`]'s unit.
/// A bare integer amount (no trailing `m`) is treated as WHOLE units and
/// scaled by 1000 (`cpu=2` == `cpu=2000m`). Returns `None` for anything not
/// shaped `<key>=<amount>[m]` with a parseable non-negative integer amount.
#[must_use]
pub fn parse_quota(spec: &str) -> Option<(String, u64)> {
    let (key, amount) = spec.split_once('=')?;
    let key = key.trim();
    let amount = amount.trim();
    if key.is_empty() || amount.is_empty() {
        return None;
    }
    if let Some(milli) = amount.strip_suffix('m') {
        let milli: u64 = milli.parse().ok()?;
        Some((key.to_owned(), milli))
    } else {
        let whole: u64 = amount.parse().ok()?;
        Some((key.to_owned(), whole.checked_mul(1000)?))
    }
}

fn render_sentence(chain: &[Cid], store: &TrustStore) -> String {
    if chain.is_empty() {
        return "genesis".to_owned();
    }
    let mut parts = Vec::new();
    for cid in chain {
        if let Some(a) = store.attests.get(cid) {
            parts.push(format!(
                "{} attests {} may {} {} as {} (scope {}, epoch {})",
                a.issuer.0,
                a.subject.0,
                a.predicate.action,
                a.predicate.resource,
                a.capacity.tag(),
                a.scope,
                a.epoch
            ));
        }
    }
    parts.push(format!("rooted at genesis {}", store.genesis.0));
    parts.join(" <- ")
}

/// Project every currently-live (non-revoked, chain-verified) `Role`
/// [`Attest`] in `store` into a `pillar_rbac::ExplicitGrant`, so the single
/// `RbacDecider` consumes attest artifacts through the SAME explicit-grant
/// rung it already exposes for controller enforcement / UI prediction —
/// never a second, divergent trust-artifact-aware decision path. A `self`
/// capacity attest never projects a grant here (it authorizes only over the
/// issuer's own identity, not a third-party capability decision).
#[must_use]
pub fn as_explicit_grants(store: &TrustStore) -> Vec<ExplicitGrant> {
    store
        .live_attests()
        .filter(|(_, a)| matches!(a.capacity, Capacity::Role { .. }))
        .map(|(_, a)| ExplicitGrant {
            subject: a.subject.clone(),
            capability: Capability::from(a.predicate.action.as_str()),
            effect: GrantEffect::Allow,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn role(r: &str, s: &str) -> Capacity {
        Capacity::Role {
            role: r.to_owned(),
            scope: s.to_owned(),
        }
    }

    /// A test placeholder used only to fill the `sig` field of a struct
    /// literal before it is re-signed with a REAL signature. It never verifies
    /// as anyone (it is signed by a reserved name over empty bytes), so a test
    /// that forgets to re-sign fails closed rather than passing spuriously.
    fn placeholder_sig() -> Sig {
        Sig::sign_as(n("\u{0}unsigned-placeholder"), b"")
    }

    /// Re-sign a struct-literal `Certify` as its declared `identity`.
    fn signed_certify(mut c: Certify) -> Certify {
        c.sig = Sig::sign_as(c.identity.clone(), &c.signed_message());
        c
    }

    /// Re-sign a struct-literal `Trust` as its declared `truster`.
    fn signed_trust(mut t: Trust) -> Trust {
        t.sig = Sig::sign_as(t.truster.clone(), &t.signed_message());
        t
    }

    /// Re-sign a struct-literal `Revoke` as an explicit signer over its target.
    fn signed_revoke(target: Cid, signer: NodeId) -> Revoke {
        Revoke::signed(target, signer)
    }
    // --- four types round-trip ------------------------------------------

    #[test]
    fn certify_round_trips_sign_content_address_verify() {
        let store = TrustStore::new(n("owner"));
        let c = signed_certify(Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: placeholder_sig(),
        });
        let cid = store.certify(&c).expect("certify accepted");
        // Content-addressed: identical fields address the same Cid.
        let c2 = signed_certify(Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: placeholder_sig(),
        });
        assert_eq!(cid, c2.cid());
    }

    #[test]
    fn certify_rejects_a_signer_mismatch() {
        let store = TrustStore::new(n("owner"));
        // mallory forges: she claims alice's identity but signs with her OWN
        // real key. The carried key is not the one "alice" derives to, so the
        // signature never verifies as alice.
        let mut c = Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: placeholder_sig(),
        };
        c.sig = Sig::sign_as(n("mallory"), &c.signed_message());
        assert_eq!(store.certify(&c), Err(TrustError::SignerMismatch));
    }

    #[test]
    fn trust_round_trips_sign_content_address_verify() {
        let store = TrustStore::new(n("owner"));
        let t = signed_trust(Trust {
            truster: n("alice"),
            trustee: n("bob"),
            depth: 2,
            sig: placeholder_sig(),
        });
        let cid = store.trust(&t).expect("trust accepted");
        assert_eq!(cid, t.cid());
    }

    #[test]
    fn trust_rejects_a_signer_mismatch() {
        let store = TrustStore::new(n("owner"));
        // mallory forges alice's vouch with her own real key: rejected.
        let mut t = Trust {
            truster: n("alice"),
            trustee: n("bob"),
            depth: 2,
            sig: placeholder_sig(),
        };
        t.sig = Sig::sign_as(n("mallory"), &t.signed_message());
        assert_eq!(store.trust(&t), Err(TrustError::SignerMismatch));
    }

    #[test]
    fn attest_round_trips_sign_content_address_verify() {
        let mut store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let expected_cid = a.cid();
        let cid = store.issue_attest(a).expect("attest accepted");
        assert_eq!(cid, expected_cid);
        let proof = store.verify(&cid).expect("verifies");
        assert_eq!(proof.chain, vec![cid]);
    }

    #[test]
    fn revoke_round_trips_and_targets_a_specific_cid() {
        let mut store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(a).unwrap();
        let r = signed_revoke(cid.clone(), n("owner"));
        store.revoke(&r).expect("revoke accepted");
        assert!(matches!(store.verify(&cid), Err(VerifyError::Revoked(_))));
    }

    #[test]
    fn revoke_rejects_an_unknown_target() {
        let mut store = TrustStore::new(n("owner"));
        let r = signed_revoke(Cid("trust:doesnotexist".to_owned()), n("owner"));
        assert!(matches!(
            store.revoke(&r),
            Err(TrustError::UnknownTarget(_))
        ));
    }

    // --- capacity checked at signing time --------------------------------

    #[test]
    fn role_not_held_at_signing_is_rejected() {
        let mut store = TrustStore::new(n("owner"));
        // alice never received any role-grant attest, so she cannot issue one.
        let a = (Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        assert_eq!(
            store.issue_attest(a),
            Err(TrustError::CapacityNotHeld { issuer: n("alice") })
        );
    }

    #[test]
    fn role_held_at_signing_is_admitted_and_can_sub_delegate() {
        let mut store = TrustStore::new(n("owner"));
        let grant_to_alice = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let alice_cid = store.issue_attest(grant_to_alice).unwrap();

        // alice now holds the role capacity and can sub-delegate, pointing
        // her authority proof pointer at the exact grant edge she used.
        let sub_grant = (Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: Some(alice_cid.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let bob_cid = store.issue_attest(sub_grant).expect("alice holds capacity");
        let proof = store.verify(&bob_cid).expect("verifies to genesis");
        assert_eq!(proof.chain, vec![bob_cid, alice_cid]);
    }

    #[test]
    fn self_capacity_is_unconditional_and_needs_no_authority_pointer() {
        let mut store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("alice"),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("identity:describe", "self"),
            scope: "global".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store
            .issue_attest(a)
            .expect("self capacity is unconditional");
        assert!(store.verify(&cid).is_ok());
    }

    // --- pure walk: terminates, rejects broken/cyclic, renders proof -----

    #[test]
    fn verify_rejects_a_broken_chain() {
        let store = TrustStore::new(n("owner"));
        let dangling = Cid("trust:nope".to_owned());
        assert_eq!(store.verify(&dangling), Err(VerifyError::Broken(dangling)));
    }

    #[test]
    fn verify_rejects_a_cyclic_chain() {
        let mut store = TrustStore::new(n("owner"));
        // Construct two attests whose authority pointers reference each
        // other, forming a cycle, by inserting directly (issue_attest's own
        // capacity gate would refuse this pair honestly - this test proves
        // verify() itself is robust to an already-cyclic stored chain).
        let a = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: Some(Cid("trust:self-cycle-b".to_owned())),
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid_a = a.cid();
        let b = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: Some(cid_a.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        // Force b's cid to equal the authority pointer a expects, by
        // directly inserting into the map under that fabricated cid.
        let fabricated_cid = Cid("trust:self-cycle-b".to_owned());
        store.attests.insert(cid_a.clone(), a);
        store.attests.insert(fabricated_cid.clone(), b);

        assert!(matches!(store.verify(&cid_a), Err(VerifyError::Cycle(_))));
    }

    #[test]
    fn verify_renders_the_full_chain_and_a_sentence() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();
        let proof = store.verify(&cid).unwrap();
        assert_eq!(proof.chain.len(), 1);
        assert!(proof.sentence.contains("owner"));
        assert!(proof.sentence.contains("alice"));
        assert!(proof.sentence.contains("stream:append"));
        assert!(proof.sentence.contains("genesis"));
    }

    // --- revocation fails closed at the required epoch --------------------

    #[test]
    fn revoked_path_fails_closed_even_partway_through_the_chain() {
        let mut store = TrustStore::new(n("owner"));
        let grant_to_alice = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let alice_cid = store.issue_attest(grant_to_alice).unwrap();
        let sub_grant = (Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: Some(alice_cid.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let bob_cid = store.issue_attest(sub_grant).unwrap();
        assert!(store.verify(&bob_cid).is_ok());

        // Revoke alice's own grant edge: bob's chain must now fail closed,
        // even though bob's own attest was never directly touched.
        store
            .revoke(&signed_revoke(alice_cid.clone(), n("owner")))
            .unwrap();

        assert_eq!(store.verify(&bob_cid), Err(VerifyError::Revoked(alice_cid)));
    }

    #[test]
    fn a_stale_epoch_view_refuses_new_attest_issuance_fail_closed() {
        let mut store = TrustStore::new(n("owner"));
        // Bump epoch by revoking something first.
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();
        store
            .revoke(&signed_revoke(cid, n("owner")))
            .unwrap();
        assert_eq!(store.epoch(), 1);

        // Attempt to issue at the now-stale epoch 0.
        let stale = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        assert_eq!(
            store.issue_attest(stale),
            Err(TrustError::StaleEpoch {
                attempted: 0,
                current: 1
            })
        );
    }

    // --- quota attestations are budgets, not booleans ---------------------

    #[test]
    fn quota_predicate_produces_a_budget_admitted_incrementally() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(1000),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();

        store.admit_quota(&cid, 400).expect("within budget");
        assert_eq!(store.admitted_amount(&cid), 400);
        store.admit_quota(&cid, 400).expect("still within budget");
        assert_eq!(store.admitted_amount(&cid), 800);
        assert_eq!(
            store.admit_quota(&cid, 400),
            Err(TrustError::QuotaExceeded {
                requested: 400,
                remaining: 200
            })
        );
    }

    #[test]
    fn boolean_only_predicate_refuses_quota_admission() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"), // no quota
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();
        assert_eq!(
            store.admit_quota(&cid, 1),
            Err(TrustError::NotAQuotaPredicate)
        );
    }

    #[test]
    fn revoked_quota_grant_refuses_further_admission() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(1000),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();
        store.admit_quota(&cid, 100).unwrap();
        store
            .revoke(&signed_revoke(cid.clone(), n("owner")))
            .unwrap();
        assert!(matches!(
            store.admit_quota(&cid, 100),
            Err(TrustError::CapacityNotHeld { .. })
        ));
    }

    // --- rbac-decider integration: single decision path -------------------

    #[test]
    fn live_role_attests_project_into_rbac_explicit_grants() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        store.issue_attest(grant).unwrap();

        let grants = as_explicit_grants(&store);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].subject, n("alice"));
        assert_eq!(grants[0].capability, Capability::from("stream:append"));
        assert_eq!(grants[0].effect, GrantEffect::Allow);
    }

    #[test]
    fn revoked_attest_never_projects_a_grant() {
        let mut store = TrustStore::new(n("owner"));
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(grant).unwrap();
        store
            .revoke(&signed_revoke(cid, n("owner")))
            .unwrap();
        assert!(as_explicit_grants(&store).is_empty());
    }

    #[test]
    fn self_capacity_attests_never_project_a_third_party_grant() {
        let mut store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("alice"),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("identity:describe", "self"),
            scope: "global".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        store.issue_attest(a).unwrap();
        assert!(as_explicit_grants(&store).is_empty());
    }

    // --- dry-run: decide_attest previews the SAME decision issue_attest enforces

    #[test]
    fn decide_attest_previews_an_allowed_issuance_without_recording_it() {
        let store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let previewed = store.decide_attest(&a).expect("owner may issue");
        assert_eq!(previewed, a.cid());
        // Nothing was recorded by the preview.
        assert!(store.verify(&previewed).is_err());

        // The SAME artifact, actually issued: identical decision (the same
        // Cid), and only NOW does it verify.
        let mut store = store;
        let enforced = store.issue_attest(a.clone()).expect("matches the preview");
        assert_eq!(enforced, previewed, "predicted == enforced");
        assert!(store.verify(&enforced).is_ok());
    }

    #[test]
    fn decide_attest_previews_a_denied_issuance_and_the_real_issuance_agrees() {
        let mut store = TrustStore::new(n("owner"));
        // mallory has never been granted the `operator@cell-b` capacity.
        let a = (Attest {
            issuer: n("mallory"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("mallory"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        assert_eq!(
            store.decide_attest(&a),
            Err(TrustError::CapacityNotHeld {
                issuer: n("mallory")
            })
        );
        // The real issuance refuses IDENTICALLY, and records nothing.
        assert_eq!(
            store.issue_attest(a),
            Err(TrustError::CapacityNotHeld {
                issuer: n("mallory")
            })
        );
        assert!(store.attests.is_empty());
    }

    // --- describe: signer + exercised authority + no fabricated provenance --

    #[test]
    fn describe_renders_signer_and_the_exercised_authority_chain_for_an_attestation() {
        let mut store = TrustStore::new(n("owner"));
        // owner (genesis) grants alice the operator@cell-b capacity...
        let grant = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("hold", "operator@cell-b"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let grant_cid = store.issue_attest(grant).unwrap();
        // ...which alice then EXERCISES to attest bob may stream:append.
        let exercised = (Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: Some(grant_cid.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(exercised).unwrap();
        let doc = store.describe(&cid).expect("stored artifact describes");
        assert!(doc.contains("Signer:      alice"));
        // The exercised authority's sentence walks the grant_cid's own
        // attestation all the way back to the genesis anchor.
        let _ = &grant_cid;
        assert!(
            doc.contains("Exercised-Authority:")
                && doc.contains("owner attests alice may hold operator@cell-b")
                && doc.contains("rooted at genesis owner"),
            "describe must show the authority chain walked back to genesis:\n{doc}"
        );
        assert!(!doc.contains("self-issued"));
    }

    #[test]
    fn describe_never_fabricates_a_chain_for_a_self_issued_artifact() {
        let mut store = TrustStore::new(n("owner"));
        let a = (Attest {
            issuer: n("alice"),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("identity:describe", "self"),
            scope: "global".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        }).signed_by_issuer();
        let cid = store.issue_attest(a).unwrap();
        let doc = store.describe(&cid).unwrap();
        assert!(doc.contains("Signer:      alice"));
        // No authority pointer was exercised — describe says so plainly,
        // rather than inventing a genesis walk that never happened.
        assert!(doc.contains("Exercised-Authority: (self-issued; no authority to walk)"));
    }

    #[test]
    fn describe_returns_none_for_an_unknown_cid() {
        let store = TrustStore::new(n("owner"));
        assert_eq!(store.describe(&Cid("nope".to_owned())), None);
    }

    // --- real cryptography: signatures unforgeable, addresses collision-resistant

    #[test]
    fn forged_attest_signature_is_rejected_signer_cannot_be_spoofed() {
        // mallory builds an attest CLAIMING owner is the issuer, but signs it
        // with her own real ed25519 key. Because the carried verifying key is
        // not the one "owner" derives to, the signature never verifies as
        // owner and issuance is refused.
        let mut store = TrustStore::new(n("owner"));
        let mut a = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("mallory"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        };
        a.sig = Sig::sign_as(n("mallory"), &a.signed_message());
        assert_eq!(store.decide_attest(&a), Err(TrustError::SignerMismatch));
        assert_eq!(store.issue_attest(a), Err(TrustError::SignerMismatch));
        assert!(store.attests.is_empty());
    }

    #[test]
    fn tampering_a_signed_field_invalidates_the_signature() {
        // Owner honestly signs an attest; flipping the subject afterwards
        // changes the canonical message (via the cid), so the retained
        // signature no longer verifies — a store consumer cannot mutate a
        // signed artifact and keep it accepted.
        let store = TrustStore::new(n("owner"));
        let honest = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        })
        .signed_by_issuer();
        assert!(honest.sig.verifies_as(&n("owner"), &honest.signed_message()));

        let mut tampered = honest.clone();
        tampered.subject = n("mallory");
        // The signature was over the ORIGINAL subject; against the tampered
        // message it fails.
        assert!(!tampered.sig.verifies_as(&n("owner"), &tampered.signed_message()));
        let _ = &store;
    }

    #[test]
    fn revoke_rejects_a_forged_signature() {
        let mut store = TrustStore::new(n("owner"));
        let cid = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        })
        .signed_by_issuer();
        let cid = store.issue_attest(cid).unwrap();
        // A revoke whose carried key does not match its claimed signer name.
        let mut r = signed_revoke(cid.clone(), n("owner"));
        // Corrupt the signature bytes -> verification fails closed.
        r.sig = Sig::sign_as(n("mallory"), b"unrelated message");
        assert_eq!(store.revoke(&r), Err(TrustError::SignerMismatch));
    }

    #[test]
    fn content_address_is_a_real_cryptographic_multihash_not_a_checksum() {
        // Distinct fields -> distinct addresses; a one-character change flips
        // the whole address; the digest is at least 256 bits (64 hex chars),
        // far wider than the old 64-bit SipHash checksum.
        let a = content_address(&["attest", "owner", "alice", "cell-b"]);
        let a_again = content_address(&["attest", "owner", "alice", "cell-b"]);
        let b = content_address(&["attest", "owner", "alicf", "cell-b"]);
        assert_eq!(a, a_again, "content addressing must be deterministic");
        assert_ne!(a, b, "a one-character change must change the address");
        // "trust:" prefix + >= 64 hex chars of digest.
        let hex_len = a.0.trim_start_matches("trust:").len();
        assert!(
            hex_len >= 64,
            "a real content address is >= 256 bits (>= 64 hex chars), got {hex_len}"
        );
    }

    #[test]
    fn length_prefixing_prevents_field_concatenation_collisions() {
        // Without length prefixes, ("ab","c") and ("a","bc") would collide.
                let x = content_address(&["ab", "c"]);
        let y = content_address(&["a", "bc"]);
        assert_ne!(x, y, "ambiguous concatenation must not collide");
    }

    // --- explicit schema-version stamp: content-addressed & signature-covered

    #[test]
    fn the_current_artifact_schema_version_is_supported() {
        // The stamp this build bakes into every artifact is, by construction,
        // in the supported window.
        assert_eq!(check_artifact_schema_version(ARTIFACT_SCHEMA_VERSION), Ok(()));
    }

    #[test]
    fn a_stamped_but_unknown_future_schema_version_is_rejected_distinctly() {
        // A cleanly-parsed but FUTURE version is Unsupported — never Malformed —
        // so the later compatibility layer can treat a newer peer as negotiable
        // rather than as corruption.
        let future = pillar_crypto::SurfaceVersion(ARTIFACT_SCHEMA_VERSION.0 + 1);
        let err = check_artifact_schema_version(future).unwrap_err();
        assert_eq!(
            err,
            pillar_crypto::VersionError::Unsupported {
                found: future,
                min: MIN_ARTIFACT_SCHEMA_VERSION,
                max: ARTIFACT_SCHEMA_VERSION,
            }
        );
        assert_ne!(err, pillar_crypto::VersionError::Malformed);
    }

    #[test]
    fn every_artifact_still_verifies_after_the_version_was_folded_into_signed_material() {
        // The schema version is now part of each artifact's content address and
        // therefore its signed message; a genuinely-signed artifact must still
        // verify against its own signed_message()/cid.
        let certify = signed_certify(Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: placeholder_sig(),
        });
        assert!(certify
            .sig
            .verifies_as(&certify.identity, &certify.signed_message()));
        assert_eq!(certify.schema_version(), ARTIFACT_SCHEMA_VERSION);
        assert_eq!(certify.check_schema_version(), Ok(()));

        let trust = signed_trust(Trust {
            truster: n("alice"),
            trustee: n("bob"),
            depth: 2,
            sig: placeholder_sig(),
        });
        assert!(trust.sig.verifies_as(&trust.truster, &trust.signed_message()));
        assert_eq!(trust.schema_version(), ARTIFACT_SCHEMA_VERSION);
        assert_eq!(trust.check_schema_version(), Ok(()));

        let attest = (Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: placeholder_sig(),
        })
        .signed_by_issuer();
        assert!(attest.sig.verifies_as(&attest.issuer, &attest.signed_message()));
        assert_eq!(attest.schema_version(), ARTIFACT_SCHEMA_VERSION);
        assert_eq!(attest.check_schema_version(), Ok(()));

        let revoke = signed_revoke(attest.cid(), n("owner"));
        assert!(revoke.sig.verifies_as(
            &n("owner"),
            &Revoke::signed_message(&attest.cid())
        ));
        assert_eq!(revoke.schema_version(), ARTIFACT_SCHEMA_VERSION);
        assert_eq!(revoke.check_schema_version(), Ok(()));
    }
}