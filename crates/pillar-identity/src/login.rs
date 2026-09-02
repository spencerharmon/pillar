//! Cold-root / operational-key / device-subkey identity, enrollment,
//! self-revocation, login, and pluggable key custody — the Rust refinement
//! of `specs/IdentityLogin.tla` (ROI P1 "Identity, keys, credentials &
//! login").
//!
//! # Model
//!
//! Where [`crate::Registry`] models the flat `USER_PRIMARY -> NODE_SUBKEY`
//! admission of `Registration.tla`, this module refines the full
//! genesis-anchored hierarchy of `IdentityLogin.tla`:
//!
//! ```text
//!   COLD_ROOT (the cell key: genesis principal, identity IS its canonical CID)
//!        |  Certify        (cold key signs an op key directly — rare, high-value)
//!        v
//!   OPERATIONAL_KEY
//!        |  DelegationGrant (an enrolled op key vouches for a new op key,
//!        |                   day-to-day enrollment that NEVER touches the cold key;
//!        |                   the new op key inherits the signer's root binding)
//!        v
//!   OPERATIONAL_KEY (further op keys, transitively enrolled)
//!        |  GrantDevice    (an op key grants a device/node subkey)
//!        v
//!   DEVICE_SUBKEY (the per-device/node identity actually presented at Login)
//! ```
//!
//! The **cell key IS the cold root**: bootstrap creates it as the genesis
//! principal, node subkeys chain to the cell (as op keys enrolled under it),
//! and users are created within the cell (op keys certified/delegated under
//! the same root). An "org-as-cell" is just a cold root whose op keys are the
//! org's members.
//!
//! ## Enrollment is unguarded; validity is checked only at Login
//!
//! [`certify_op`](IdentityStore::certify_op),
//! [`delegation_grant_op`](IdentityStore::delegation_grant_op) and
//! [`grant_device`](IdentityStore::grant_device) are **AP and deliberately
//! unguarded** by the signer's own validity — exactly like
//! [`Registry::issue_subkey`] and `pillar_wot_authority`'s edge issuance: a
//! rogue or not-yet-enrolled key can still mint a certificate. Validity is
//! checked at the sole checkpoint that matters — [`login`](IdentityStore::login).
//!
//! ## One-time-token enrollment
//!
//! [`OneTimeToken`] models a delegation-grant pre-authorized by an enrolled
//! op key and redeemable **exactly once** to enroll a brand-new op key
//! without an interactive signer present. Redeeming it is delegation-grant
//! with the token standing in for the signer's live participation; a consumed
//! token can never enroll a second key ([`TokenError::AlreadyConsumed`]).
//!
//! ## Self-revocation without the cold key
//!
//! [`revoke_op`](IdentityStore::revoke_op) and
//! [`revoke_device`](IdentityStore::revoke_device) reference **no root at
//! all** — an operational key can revoke itself (or a device it granted) with
//! no cold-key action, mirroring the spec's `RevokeOp`/`RevokeDevice`. The
//! cold key's OWN revocation ([`revoke_root`](IdentityStore::revoke_root),
//! the spec's `RevokeRoot`) likewise needs no other root. Pre-staged
//! revocation certificates and a designated revoker are modelled by
//! [`RevocationCert`]: a detached, pre-signed authority to revoke a specific
//! key that anyone holding it may later fire, so custody of the private key
//! is not required to revoke it.
//!
//! ## Login: the client-side-signature primitive
//!
//! The server-observable [`IdentityStore`] holds only **public** identities
//! and public certify/grant/revoke facts — there is NO private-key field in
//! this type, which IS the "server holds public keys only" property: nothing
//! in the store could ever let the server itself manufacture a login, only
//! verify one presented to it. [`login`](IdentityStore::login)'s guard is the
//! admission policy of `IdentityLogin.tla`'s `Login`: the presented device
//! must not be revoked, must be granted by a non-revoked op key, which must
//! be enrolled under a non-revoked root.
//!
//! ## Proven properties (re-asserted by this crate's tests)
//!
//! * `LoginRequiresValidChain` — a successful login's device, op key, and
//!   root were all simultaneously non-revoked at the moment of login, and the
//!   device was genuinely granted by that op key which was genuinely enrolled
//!   under that root.
//! * `NoAmbientAuthority` — an ungranted device is never the subject of a
//!   successful login.
//!
//! ## Encryption subkey `E`
//!
//! [`KeyMaterialSet`] models the OpenPGP subkey capabilities a user or cell
//! key may carry: a **sign** subkey, a **certify** subkey, and — the piece
//! this task adds — an **optional dedicated encryption subkey `E`** for
//! *receiving* encrypted material, distinct from the sign/certify subkeys. It
//! is optional (a key may exist with none) and, when present, is the only
//! capability that may be an encryption recipient.
//!
//! ## Pluggable key custody ([`SignerBackend`])
//!
//! Where a private key actually LIVES is a per-key configuration choice, not
//! a protocol fact. [`SignerBackend`] is the single trait every custody
//! option implements — for **node keys and cell keys as well as user keys**:
//! [`FileKeyringBackend`] (the default), [`TpmBackend`] (recommended for node
//! keys, since the private key never leaves the host), [`PasskeyBackend`]
//! (WebAuthn), and [`PasswordBackend`] (supported but NOT recommended). The
//! backend produces a challenge signature; the identity model above verifies
//! the resulting public-key chain, so custody is orthogonal to admission.
//!
//! As with the rest of this crate, no real OpenPGP/crypto primitive is
//! involved: signatures and ciphertext stand in for verified packets so the
//! identity, enrollment, revocation and login *policy* is auditable in
//! isolation from the crypto library that will later produce the real
//! material.

use std::collections::{HashMap, HashSet};

/// A cold-root (cell-key) genesis identity. Its string IS its canonical
/// genesis CID — the anchor of an entire key hierarchy. Refines a `Roots`
/// element of `IdentityLogin.tla`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ColdRoot(pub String);

impl From<&str> for ColdRoot {
    fn from(s: &str) -> Self {
        ColdRoot(s.to_owned())
    }
}

/// An operational key: a user or node key enrolled (transitively) under a
/// cold root. Refines an `OpKeys` element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpKey(pub String);

impl From<&str> for OpKey {
    fn from(s: &str) -> Self {
        OpKey(s.to_owned())
    }
}

/// A device/node subkey — the per-device identity actually presented at
/// [`login`](IdentityStore::login). Refines a `Devices` element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceSubkey(pub String);

impl From<&str> for DeviceSubkey {
    fn from(s: &str) -> Self {
        DeviceSubkey(s.to_owned())
    }
}

/// The subkey capabilities an OpenPGP user or cell key may carry.
///
/// The **encryption subkey `E`** is optional and dedicated to *receiving*
/// encrypted material — distinct from the `sign` and `certify` capabilities.
/// A key with `encryption == None` can sign/certify but can never be an
/// encryption recipient ([`can_receive_encrypted`](Self::can_receive_encrypted)
/// is then `false`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyMaterialSet {
    /// Fingerprint of the dedicated **signing** subkey, if any.
    pub sign: Option<String>,
    /// Fingerprint of the dedicated **certification** subkey, if any.
    pub certify: Option<String>,
    /// Fingerprint of the optional dedicated **encryption subkey `E`**, used
    /// only to *receive* encrypted material. Absent by default.
    pub encryption: Option<String>,
}

impl KeyMaterialSet {
    /// A key with none of the optional subkeys present.
    #[must_use]
    pub fn bare() -> Self {
        KeyMaterialSet::default()
    }

    /// Attach a dedicated encryption subkey `E` (builder-style).
    #[must_use]
    pub fn with_encryption_subkey(mut self, fingerprint: impl Into<String>) -> Self {
        self.encryption = Some(fingerprint.into());
        self
    }

    /// Whether this key may be an encryption recipient — true **iff** it
    /// carries a dedicated encryption subkey `E`.
    #[must_use]
    pub fn can_receive_encrypted(&self) -> bool {
        self.encryption.is_some()
    }
}

/// Which key-custody backend holds a private key. A per-key configuration
/// choice, applicable to node keys and cell keys as well as user keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyKind {
    /// On-disk keyring file. The default.
    FileKeyring,
    /// A TPM: the private key never leaves the host. Recommended for node
    /// keys.
    Tpm,
    /// A passkey / WebAuthn authenticator.
    Passkey,
    /// A password-derived key. Supported but NOT recommended.
    Password,
}

/// A backend that produces a challenge signature on behalf of a private key
/// it holds. The single trait every custody option implements, for node,
/// cell and user keys alike.
///
/// The backend NEVER exposes the private key: it only answers "sign this
/// challenge". The identity model verifies the resulting public-key chain, so
/// custody choice is orthogonal to the admission policy.
pub trait SignerBackend {
    /// Which custody mechanism this backend implements.
    fn kind(&self) -> CustodyKind;

    /// Whether this custody choice is operator-recommended. TPM is
    /// recommended for node keys (the key never leaves the host); password is
    /// explicitly not.
    fn is_recommended(&self) -> bool {
        !matches!(self.kind(), CustodyKind::Password)
    }

    /// Produce a signature over `challenge` using the held private key,
    /// yielding an opaque signature token. Returns `None` if this backend
    /// cannot currently sign (e.g. locked/absent hardware).
    fn sign_challenge(&self, challenge: &str) -> Option<String>;
}

/// File-keyring custody: the default backend.
#[derive(Clone, Debug)]
pub struct FileKeyringBackend {
    key_id: String,
    unlocked: bool,
}

impl FileKeyringBackend {
    /// A file-keyring backend for `key_id`, initially locked.
    #[must_use]
    pub fn new(key_id: impl Into<String>) -> Self {
        FileKeyringBackend {
            key_id: key_id.into(),
            unlocked: false,
        }
    }

    /// Unlock the keyring (builder-style), enabling signing.
    #[must_use]
    pub fn unlocked(mut self) -> Self {
        self.unlocked = true;
        self
    }
}

impl SignerBackend for FileKeyringBackend {
    fn kind(&self) -> CustodyKind {
        CustodyKind::FileKeyring
    }

    fn sign_challenge(&self, challenge: &str) -> Option<String> {
        self.unlocked
            .then(|| format!("file-keyring:{}:{challenge}", self.key_id))
    }
}

/// TPM custody: the private key never leaves the host. Recommended for node
/// keys.
#[derive(Clone, Debug)]
pub struct TpmBackend {
    handle: String,
}

impl TpmBackend {
    /// A TPM-backed signer bound to `handle` (a TPM key handle).
    #[must_use]
    pub fn new(handle: impl Into<String>) -> Self {
        TpmBackend {
            handle: handle.into(),
        }
    }
}

impl SignerBackend for TpmBackend {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Tpm
    }

    fn sign_challenge(&self, challenge: &str) -> Option<String> {
        Some(format!("tpm:{}:{challenge}", self.handle))
    }
}

/// Passkey / WebAuthn custody.
#[derive(Clone, Debug)]
pub struct PasskeyBackend {
    credential_id: String,
    present: bool,
}

impl PasskeyBackend {
    /// A passkey backend for `credential_id`. `present` models whether the
    /// authenticator is currently connected/available for a user gesture.
    #[must_use]
    pub fn new(credential_id: impl Into<String>, present: bool) -> Self {
        PasskeyBackend {
            credential_id: credential_id.into(),
            present,
        }
    }
}

impl SignerBackend for PasskeyBackend {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Passkey
    }

    fn sign_challenge(&self, challenge: &str) -> Option<String> {
        self.present
            .then(|| format!("passkey:{}:{challenge}", self.credential_id))
    }
}

/// Password-derived custody. Supported but NOT recommended.
#[derive(Clone, Debug)]
pub struct PasswordBackend {
    key_id: String,
}

impl PasswordBackend {
    /// A password-derived signer for `key_id`.
    #[must_use]
    pub fn new(key_id: impl Into<String>) -> Self {
        PasswordBackend {
            key_id: key_id.into(),
        }
    }
}

impl SignerBackend for PasswordBackend {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Password
    }

    fn sign_challenge(&self, challenge: &str) -> Option<String> {
        Some(format!("password:{}:{challenge}", self.key_id))
    }
}

/// Per-key custody assignment: which [`CustodyKind`] backend a given key id
/// is LABELED to use. This is the real per-key wiring point — a principal
/// (cell, user, or node) may have several keys, each labeled to a different
/// custody backend (e.g. a TPM-sealed node key alongside a
/// password-unlocked user operational key), and [`sign_with_backend`]
/// enforces that a key can only ever be signed by the backend it is labeled
/// for, refusing any other.
#[derive(Clone, Debug, Default)]
pub struct CustodyRegistry {
    assignments: HashMap<String, CustodyKind>,
}

impl CustodyRegistry {
    /// An empty registry: no key has an assigned custody backend yet.
    #[must_use]
    pub fn new() -> Self {
        CustodyRegistry::default()
    }

    /// Label `key_id` to be signed ONLY by the `kind` backend. Re-labeling an
    /// already-assigned key overwrites its prior label (a deliberate
    /// custody-migration action, not silently ignored).
    pub fn assign(&mut self, key_id: impl Into<String>, kind: CustodyKind) {
        self.assignments.insert(key_id.into(), kind);
    }

    /// The custody backend `key_id` is labeled for, if any.
    #[must_use]
    pub fn kind_of(&self, key_id: &str) -> Option<CustodyKind> {
        self.assignments.get(key_id).copied()
    }
}

/// Why signing through a labeled backend was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodySignError {
    /// `key_id` has no custody label recorded in the registry.
    NoBackendAssigned,
    /// `key_id` is labeled for a DIFFERENT backend than the one presented —
    /// e.g. a key labeled `Tpm` cannot be signed by a `PasswordBackend`. This
    /// is the enforcement point for "a key labeled backend X uses X".
    KindMismatch {
        /// The backend kind `key_id` is actually labeled for.
        expected: CustodyKind,
        /// The backend kind the caller presented.
        presented: CustodyKind,
    },
    /// The presented backend matched the label but declined to sign (e.g. a
    /// locked keyring or absent passkey authenticator).
    SigningDeclined,
}

/// Sign `challenge` for `key_id` through `backend`, but ONLY if `backend`'s
/// kind matches `key_id`'s label in `registry` — the real per-key custody
/// enforcement: a mismatched backend is refused before it is ever asked to
/// sign, so custody labels are a hard requirement, not a cosmetic hint.
///
/// The backend NEVER exposes private key material here or anywhere else —
/// only the opaque signature token [`SignerBackend::sign_challenge`]
/// produces crosses this boundary, so this function structurally cannot leak
/// key material even on success.
///
/// # Errors
///
/// [`CustodySignError::NoBackendAssigned`] if `key_id` carries no label;
/// [`CustodySignError::KindMismatch`] if `backend`'s kind differs from the
/// label; [`CustodySignError::SigningDeclined`] if the (correctly labeled)
/// backend itself declines to sign.
pub fn sign_with_backend(
    registry: &CustodyRegistry,
    key_id: &str,
    backend: &dyn SignerBackend,
    challenge: &str,
) -> Result<String, CustodySignError> {
    let expected = registry
        .kind_of(key_id)
        .ok_or(CustodySignError::NoBackendAssigned)?;
    if expected != backend.kind() {
        return Err(CustodySignError::KindMismatch {
            expected,
            presented: backend.kind(),
        });
    }
    backend
        .sign_challenge(challenge)
        .ok_or(CustodySignError::SigningDeclined)
}

/// A pre-authorized, single-use delegation grant redeemable to enroll one new
/// op key without an interactive signer present (one-time-token enrollment).
///
/// The token records the enrolled `issuer` op key that authorized it; on
/// redemption the new op key inherits the issuer's root binding, exactly as a
/// live [`delegation_grant_op`](IdentityStore::delegation_grant_op) would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimeToken {
    id: String,
    issuer: OpKey,
}

impl OneTimeToken {
    /// Mint a token authorized by enrolled op key `issuer`.
    #[must_use]
    pub fn new(id: impl Into<String>, issuer: OpKey) -> Self {
        OneTimeToken {
            id: id.into(),
            issuer,
        }
    }

    /// The op key that authorized this token.
    #[must_use]
    pub fn issuer(&self) -> &OpKey {
        &self.issuer
    }
}

/// Why a one-time-token redemption failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// The token was already redeemed — it can enroll at most one op key.
    AlreadyConsumed,
    /// The op key the redemption would enroll is already enrolled.
    AlreadyEnrolled,
}

/// The subject a pre-staged revocation certificate authorizes revoking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationSubject {
    /// Revoke a cold root (cell key).
    Root(ColdRoot),
    /// Revoke an operational key.
    Op(OpKey),
    /// Revoke a device subkey.
    Device(DeviceSubkey),
}

/// A detached, pre-signed authority to revoke a specific key — a *pre-staged
/// revocation certificate* held by a designated revoker.
///
/// Holding one lets its bearer fire the revocation later WITHOUT possessing
/// the target's private key, which is the point: a key can be pre-authorized
/// for revocation (and that authority handed to a trusted revoker) at
/// creation time, so it can be revoked even if its own private key is lost or
/// compromised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationCert {
    subject: RevocationSubject,
    designated_revoker: String,
}

impl RevocationCert {
    /// Pre-stage a revocation certificate for `subject`, redeemable by the
    /// named `designated_revoker`.
    #[must_use]
    pub fn stage(subject: RevocationSubject, designated_revoker: impl Into<String>) -> Self {
        RevocationCert {
            subject,
            designated_revoker: designated_revoker.into(),
        }
    }

    /// What this certificate authorizes revoking.
    #[must_use]
    pub fn subject(&self) -> &RevocationSubject {
        &self.subject
    }

    /// The designated revoker permitted to fire this certificate.
    #[must_use]
    pub fn designated_revoker(&self) -> &str {
        &self.designated_revoker
    }
}

/// Why firing a pre-staged revocation certificate was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationCertError {
    /// The caller is not the certificate's designated revoker.
    NotDesignatedRevoker,
}

/// Why a login attempt was refused. Mirrors the negation of each conjunct of
/// `IdentityLogin.tla`'s `Login` guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginError {
    /// The presented device subkey has been revoked.
    DeviceRevoked,
    /// The device was never granted by any op key — no ambient authority.
    DeviceUngranted,
    /// The op key that granted the device has been revoked.
    OpRevoked,
    /// The op key that granted the device is not enrolled under any root.
    OpUnenrolled,
    /// The root the op key chains to has been revoked.
    RootRevoked,
}

/// A successful login's recorded chain: the device, the op key that granted
/// it, and the cold root that op key is enrolled under. The Rust counterpart
/// of `IdentityLogin.tla`'s `lastLogin` outcome fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginOutcome {
    /// The device that logged in.
    pub device: DeviceSubkey,
    /// The op key that granted `device`.
    pub op: OpKey,
    /// The cold root `op` is enrolled under.
    pub root: ColdRoot,
}

/// The server-observable identity store: public identities and the public
/// certify / grant / revoke facts, with **no private-key field** — the "server
/// holds public keys only" property, structurally.
///
/// Refines the `enrolledBy` / `deviceGrant` / `revokedRoots` / `revokedOps` /
/// `revokedDevices` state of `specs/IdentityLogin.tla`.
#[derive(Clone, Debug, Default)]
pub struct IdentityStore {
    /// op -> the cold root it ultimately chains to (via certify or transitive
    /// delegation-grant). Absent = not yet enrolled.
    enrolled_by: HashMap<OpKey, ColdRoot>,
    /// device -> the op key that granted it. Absent = ungranted.
    device_grant: HashMap<DeviceSubkey, OpKey>,
    revoked_roots: HashSet<ColdRoot>,
    revoked_ops: HashSet<OpKey>,
    revoked_devices: HashSet<DeviceSubkey>,
    /// consumed one-time tokens (by id) — grow-only, so a token redeems once.
    consumed_tokens: HashSet<String>,
}

impl IdentityStore {
    /// An empty store: no enrollment, grant, or revocation.
    #[must_use]
    pub fn new() -> Self {
        IdentityStore::default()
    }

    // --- Enrollment (AP, unguarded by signer validity) ---

    /// Cold-root certification (`CertifyOp`): the cold root (cell key) signs
    /// op key `op` directly — the rare, high-value path. Idempotent-guarded:
    /// only enrolls an op key that is not already enrolled.
    pub fn certify_op(&mut self, root: ColdRoot, op: OpKey) {
        self.enrolled_by.entry(op).or_insert(root);
    }

    /// Delegation-grant enrollment (`DelegationGrantOp`): an already-enrolled
    /// op key `signer` vouches for a new op key `op` WITHOUT touching the cold
    /// key. `op` inherits `signer`'s root binding.
    ///
    /// Unguarded by `signer`'s own validity — if `signer` is not enrolled,
    /// nothing happens (there is no root to inherit); if `op` is already
    /// enrolled, it is left unchanged. Login is the sole validity checkpoint.
    pub fn delegation_grant_op(&mut self, signer: &OpKey, op: OpKey) {
        if self.enrolled_by.contains_key(&op) {
            return;
        }
        if let Some(root) = self.enrolled_by.get(signer).cloned() {
            self.enrolled_by.insert(op, root);
        }
    }

    /// Redeem a [`OneTimeToken`] to enroll `op` — delegation-grant with the
    /// token standing in for the issuer's live participation. The token is
    /// consumed and can never enroll a second key.
    ///
    /// # Errors
    ///
    /// [`TokenError::AlreadyConsumed`] if the token was already redeemed;
    /// [`TokenError::AlreadyEnrolled`] if `op` is already enrolled.
    pub fn redeem_token(&mut self, token: &OneTimeToken, op: OpKey) -> Result<(), TokenError> {
        if self.consumed_tokens.contains(&token.id) {
            return Err(TokenError::AlreadyConsumed);
        }
        if self.enrolled_by.contains_key(&op) {
            return Err(TokenError::AlreadyEnrolled);
        }
        self.consumed_tokens.insert(token.id.clone());
        // Inherit the issuer's root binding, exactly as a live delegation
        // grant would. If the issuer is not enrolled, the op is left
        // unenrolled — Login rejects it, same as the unguarded spec action.
        if let Some(root) = self.enrolled_by.get(&token.issuer).cloned() {
            self.enrolled_by.insert(op, root);
        }
        Ok(())
    }

    /// An op key grants a device/node subkey (`GrantDevice`). Unguarded by the
    /// op key's own validity; idempotent-guarded on the device.
    pub fn grant_device(&mut self, op: OpKey, device: DeviceSubkey) {
        self.device_grant.entry(device).or_insert(op);
    }

    // --- Revocation (grow-only; op/device revocation touches no root) ---

    /// Self-revoke a cold root / cell key (`RevokeRoot`). Needs no other
    /// root's involvement.
    pub fn revoke_root(&mut self, root: ColdRoot) {
        self.revoked_roots.insert(root);
    }

    /// Self-revoke an operational key (`RevokeOp`) — references NO root:
    /// an op key can revoke itself with no cold-key action whatsoever.
    pub fn revoke_op(&mut self, op: OpKey) {
        self.revoked_ops.insert(op);
    }

    /// Self-revoke a device subkey (`RevokeDevice`) — references NO root.
    pub fn revoke_device(&mut self, device: DeviceSubkey) {
        self.revoked_devices.insert(device);
    }

    /// Fire a pre-staged [`RevocationCert`] as its designated revoker.
    ///
    /// The certificate authorizes revoking its subject WITHOUT the subject's
    /// private key — pre-staged revocation with a designated revoker. The
    /// caller must be the named designated revoker.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationCertError::NotDesignatedRevoker`] if `as_revoker`
    /// is not the certificate's designated revoker.
    pub fn fire_revocation_cert(
        &mut self,
        cert: &RevocationCert,
        as_revoker: &str,
    ) -> Result<(), RevocationCertError> {
        if cert.designated_revoker != as_revoker {
            return Err(RevocationCertError::NotDesignatedRevoker);
        }
        match &cert.subject {
            RevocationSubject::Root(r) => self.revoke_root(r.clone()),
            RevocationSubject::Op(o) => self.revoke_op(o.clone()),
            RevocationSubject::Device(d) => self.revoke_device(d.clone()),
        }
        Ok(())
    }

    // --- Queries ---

    /// The cold root `op` is enrolled under, if any.
    #[must_use]
    pub fn enrolled_root(&self, op: &OpKey) -> Option<&ColdRoot> {
        self.enrolled_by.get(op)
    }

    /// The op key that granted `device`, if any.
    #[must_use]
    pub fn granting_op(&self, device: &DeviceSubkey) -> Option<&OpKey> {
        self.device_grant.get(device)
    }

    /// Whether `root` has been revoked.
    #[must_use]
    pub fn is_root_revoked(&self, root: &ColdRoot) -> bool {
        self.revoked_roots.contains(root)
    }

    /// Whether `op` has been revoked.
    #[must_use]
    pub fn is_op_revoked(&self, op: &OpKey) -> bool {
        self.revoked_ops.contains(op)
    }

    /// Whether `device` has been revoked.
    #[must_use]
    pub fn is_device_revoked(&self, device: &DeviceSubkey) -> bool {
        self.revoked_devices.contains(device)
    }

    // --- Login (the sole validity checkpoint) ---

    /// Present `device` for login (`Login`): verify the full admission chain.
    ///
    /// Succeeds **iff** the device is not revoked, was granted by a non-revoked
    /// op key, which is enrolled under a non-revoked root — the exact
    /// conjunction of `IdentityLogin.tla`'s `Login` guard. The store is a
    /// public-key-only view, so this only *verifies* a login; it can never
    /// manufacture one.
    ///
    /// # Errors
    ///
    /// See [`LoginError`] — one variant per failing conjunct.
    pub fn login(&self, device: &DeviceSubkey) -> Result<LoginOutcome, LoginError> {
        if self.revoked_devices.contains(device) {
            return Err(LoginError::DeviceRevoked);
        }
        let op = self
            .device_grant
            .get(device)
            .ok_or(LoginError::DeviceUngranted)?;
        if self.revoked_ops.contains(op) {
            return Err(LoginError::OpRevoked);
        }
        let root = self.enrolled_by.get(op).ok_or(LoginError::OpUnenrolled)?;
        if self.revoked_roots.contains(root) {
            return Err(LoginError::RootRevoked);
        }
        Ok(LoginOutcome {
            device: device.clone(),
            op: op.clone(),
            root: root.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(s: &str) -> ColdRoot {
        ColdRoot::from(s)
    }
    fn op(s: &str) -> OpKey {
        OpKey::from(s)
    }
    fn dev(s: &str) -> DeviceSubkey {
        DeviceSubkey::from(s)
    }

    /// A cell key (cold root) certifies an op key, which grants a device;
    /// login over the intact chain succeeds and records device/op/root.
    #[test]
    fn login_over_intact_chain_records_full_chain() {
        let mut store = IdentityStore::new();
        let cell = root("cell-genesis-cid");
        let user_op = op("alice-op");
        let laptop = dev("alice-laptop");

        store.certify_op(cell.clone(), user_op.clone());
        store.grant_device(user_op.clone(), laptop.clone());

        assert_eq!(
            store.login(&laptop),
            Ok(LoginOutcome {
                device: laptop,
                op: user_op,
                root: cell,
            })
        );
    }

    /// `NoAmbientAuthority`: a device never granted by any op key can never
    /// log in.
    #[test]
    fn ungranted_device_never_logs_in() {
        let store = IdentityStore::new();
        assert_eq!(
            store.login(&dev("orphan")),
            Err(LoginError::DeviceUngranted)
        );
    }

    /// Delegation-grant enrolls a new op key WITHOUT the cold key, inheriting
    /// the signer's root binding; a device it grants can then log in.
    #[test]
    fn delegation_grant_enrolls_without_cold_key_and_chains_to_root() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let admin_op = op("admin-op");
        let member_op = op("member-op");
        let member_device = dev("member-phone");

        store.certify_op(cell.clone(), admin_op.clone());
        // The cold key is NOT used here — an op key vouches for another op key.
        store.delegation_grant_op(&admin_op, member_op.clone());
        store.grant_device(member_op.clone(), member_device.clone());

        let outcome = store.login(&member_device).expect("chain is intact");
        assert_eq!(outcome.op, member_op);
        assert_eq!(outcome.root, cell, "inherited signer's root binding");
    }

    /// Self-revoking the op key (no cold-key action) refuses login of a device
    /// it granted.
    #[test]
    fn op_self_revocation_without_cold_key_blocks_login() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let user_op = op("op");
        let device = dev("device");
        store.certify_op(cell, user_op.clone());
        store.grant_device(user_op.clone(), device.clone());
        assert!(store.login(&device).is_ok());

        store.revoke_op(user_op); // no root referenced
        assert_eq!(store.login(&device), Err(LoginError::OpRevoked));
    }

    /// Self-revoking the device refuses its login.
    #[test]
    fn device_self_revocation_blocks_login() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let user_op = op("op");
        let device = dev("device");
        store.certify_op(cell, user_op.clone());
        store.grant_device(user_op, device.clone());

        store.revoke_device(device.clone());
        assert_eq!(store.login(&device), Err(LoginError::DeviceRevoked));
    }

    /// Cell-key (cold-root) revocation invalidates the whole hierarchy under
    /// it, even with op/device intact.
    #[test]
    fn cell_key_revocation_blocks_login_through_it() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let user_op = op("op");
        let device = dev("device");
        store.certify_op(cell.clone(), user_op.clone());
        store.grant_device(user_op, device.clone());
        assert!(store.login(&device).is_ok());

        store.revoke_root(cell);
        assert_eq!(store.login(&device), Err(LoginError::RootRevoked));
    }

    /// A device granted by an op key that was never enrolled under any root
    /// cannot log in — enrollment is unguarded, but Login checks it.
    #[test]
    fn device_of_unenrolled_op_is_refused() {
        let mut store = IdentityStore::new();
        let rogue_op = op("rogue-op"); // never certified/delegated
        let device = dev("device");
        store.grant_device(rogue_op, device.clone());
        assert_eq!(store.login(&device), Err(LoginError::OpUnenrolled));
    }

    /// A one-time token enrolls exactly one op key, inheriting the issuer's
    /// root; a second redemption is refused.
    #[test]
    fn one_time_token_enrolls_once_then_is_consumed() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let issuer_op = op("issuer-op");
        store.certify_op(cell.clone(), issuer_op.clone());

        let token = OneTimeToken::new("enroll-token-1", issuer_op);
        let new_op = op("enrolled-via-token");
        assert_eq!(store.redeem_token(&token, new_op.clone()), Ok(()));
        assert_eq!(store.enrolled_root(&new_op), Some(&cell));

        // A second redemption of the same token can never enroll anything.
        assert_eq!(
            store.redeem_token(&token, op("another-op")),
            Err(TokenError::AlreadyConsumed)
        );
    }

    /// A pre-staged revocation cert lets a designated revoker revoke a key
    /// WITHOUT its private key; a non-designated caller is refused.
    #[test]
    fn pre_staged_revocation_cert_only_designated_revoker_fires() {
        let mut store = IdentityStore::new();
        let cell = root("cell");
        let user_op = op("op");
        let device = dev("device");
        store.certify_op(cell, user_op.clone());
        store.grant_device(user_op.clone(), device.clone());

        let cert =
            RevocationCert::stage(RevocationSubject::Op(user_op.clone()), "designated-revoker");

        // A non-designated caller cannot fire it.
        assert_eq!(
            store.fire_revocation_cert(&cert, "stranger"),
            Err(RevocationCertError::NotDesignatedRevoker)
        );
        assert!(store.login(&device).is_ok());

        // The designated revoker can — without the op key's private key.
        assert_eq!(
            store.fire_revocation_cert(&cert, "designated-revoker"),
            Ok(())
        );
        assert_eq!(store.login(&device), Err(LoginError::OpRevoked));
    }

    /// The optional encryption subkey `E` gates encryption-recipient status
    /// and is distinct from sign/certify.
    #[test]
    fn encryption_subkey_e_gates_receiving_encrypted_material() {
        let sign_only = KeyMaterialSet {
            sign: Some("sign-fpr".into()),
            certify: Some("certify-fpr".into()),
            encryption: None,
        };
        assert!(!sign_only.can_receive_encrypted());

        let with_e = sign_only.with_encryption_subkey("enc-fpr");
        assert!(with_e.can_receive_encrypted());
        assert_eq!(with_e.encryption.as_deref(), Some("enc-fpr"));
        // `E` is distinct from sign/certify.
        assert_ne!(with_e.encryption, with_e.sign);
        assert_ne!(with_e.encryption, with_e.certify);
    }

    /// Every custody backend implements the SAME `SignerBackend` trait, for
    /// node, cell and user keys alike; TPM is recommended, password is not.
    #[test]
    fn all_custody_backends_share_one_trait() {
        let backends: Vec<Box<dyn SignerBackend>> = vec![
            Box::new(FileKeyringBackend::new("cell-key").unlocked()),
            Box::new(TpmBackend::new("0x81000001")), // node-key custody
            Box::new(PasskeyBackend::new("cred-1", true)),
            Box::new(PasswordBackend::new("user-key")),
        ];

        // The trait signs a challenge regardless of which key it fronts.
        for b in &backends {
            assert!(
                b.sign_challenge("nonce-abc").is_some(),
                "unlocked/present backend {:?} must sign",
                b.kind()
            );
        }

        assert!(
            TpmBackend::new("h").is_recommended(),
            "TPM recommended for node keys"
        );
        assert!(
            !PasswordBackend::new("k").is_recommended(),
            "password supported but not recommended"
        );
    }

    /// A locked file keyring / absent passkey cannot sign — custody state is
    /// enforced by the backend, not the identity model.
    #[test]
    fn unavailable_backend_declines_to_sign() {
        assert!(FileKeyringBackend::new("k").sign_challenge("c").is_none());
        assert!(PasskeyBackend::new("c", false)
            .sign_challenge("c")
            .is_none());
    }

    // ---- per-key custody registry wiring ----

    /// A key labeled backend X actually uses X: the matching backend signs
    /// successfully through the registry.
    #[test]
    fn key_labeled_backend_x_uses_x() {
        let mut registry = CustodyRegistry::new();
        registry.assign("node-key-1", CustodyKind::Tpm);
        let tpm = TpmBackend::new("0x81000001");
        let sig = sign_with_backend(&registry, "node-key-1", &tpm, "nonce")
            .expect("labeled backend signs");
        assert!(sig.starts_with("tpm:"));
    }

    /// Presenting a DIFFERENT backend than the key's label is refused before
    /// it is ever asked to sign — the mismatch case.
    #[test]
    fn mismatched_backend_is_refused() {
        let mut registry = CustodyRegistry::new();
        registry.assign("node-key-1", CustodyKind::Tpm);
        let password = PasswordBackend::new("node-key-1");
        assert_eq!(
            sign_with_backend(&registry, "node-key-1", &password, "nonce"),
            Err(CustodySignError::KindMismatch {
                expected: CustodyKind::Tpm,
                presented: CustodyKind::Password,
            })
        );
    }

    /// An unlabeled key refuses signing through any backend.
    #[test]
    fn unlabeled_key_has_no_backend_assigned() {
        let registry = CustodyRegistry::new();
        let tpm = TpmBackend::new("h");
        assert_eq!(
            sign_with_backend(&registry, "unknown-key", &tpm, "nonce"),
            Err(CustodySignError::NoBackendAssigned)
        );
    }

    /// Two keys on the SAME principal may carry different labels (e.g. a
    /// TPM-sealed node key and a password-unlocked user operational key) and
    /// both sign successfully through their own labeled backend.
    #[test]
    fn two_keys_with_different_labels_both_sign() {
        let mut registry = CustodyRegistry::new();
        registry.assign("node-key", CustodyKind::Tpm);
        registry.assign("user-op-key", CustodyKind::Password);

        let tpm = TpmBackend::new("node-handle");
        let password = PasswordBackend::new("user-op-key");

        let node_sig =
            sign_with_backend(&registry, "node-key", &tpm, "chal").expect("node key signs");
        let user_sig =
            sign_with_backend(&registry, "user-op-key", &password, "chal").expect("user key signs");

        assert!(node_sig.starts_with("tpm:"));
        assert!(user_sig.starts_with("password:"));
        assert_ne!(node_sig, user_sig);

        // Cross-wiring is refused: the node key cannot sign via the user's
        // password backend and vice versa.
        assert_eq!(
            sign_with_backend(&registry, "node-key", &password, "chal"),
            Err(CustodySignError::KindMismatch {
                expected: CustodyKind::Tpm,
                presented: CustodyKind::Password,
            })
        );
        assert_eq!(
            sign_with_backend(&registry, "user-op-key", &tpm, "chal"),
            Err(CustodySignError::KindMismatch {
                expected: CustodyKind::Password,
                presented: CustodyKind::Tpm,
            })
        );
    }

    /// A correctly-labeled backend that is currently unavailable (locked
    /// keyring / absent passkey) declines rather than falsely succeeding.
    #[test]
    fn labeled_but_unavailable_backend_declines() {
        let mut registry = CustodyRegistry::new();
        registry.assign("k", CustodyKind::FileKeyring);
        let locked = FileKeyringBackend::new("k"); // not unlocked
        assert_eq!(
            sign_with_backend(&registry, "k", &locked, "c"),
            Err(CustodySignError::SigningDeclined)
        );
    }

    /// Property: no key material (private key bytes / secrets) ever crosses
    /// the signing boundary — only the opaque signature token returned by
    /// [`SignerBackend::sign_challenge`] does. Backends here carry no
    /// private-key field at all, so `sign_with_backend`'s output can only
    /// ever be composed from the backend's own public id/handle and the
    /// challenge, never a secret.
    #[test]
    fn no_key_material_crosses_the_signing_boundary() {
        for kind in [
            CustodyKind::FileKeyring,
            CustodyKind::Tpm,
            CustodyKind::Passkey,
            CustodyKind::Password,
        ] {
            let mut registry = CustodyRegistry::new();
            registry.assign("k", kind);
            let backend: Box<dyn SignerBackend> = match kind {
                CustodyKind::FileKeyring => Box::new(FileKeyringBackend::new("k").unlocked()),
                CustodyKind::Tpm => Box::new(TpmBackend::new("h")),
                CustodyKind::Passkey => Box::new(PasskeyBackend::new("c", true)),
                CustodyKind::Password => Box::new(PasswordBackend::new("k")),
            };
            let sig = sign_with_backend(&registry, "k", backend.as_ref(), "chal-xyz")
                .expect("labeled + available backend signs");
            // The signature is a formatted string over (backend-id, challenge)
            // only — never a secret/private-key field, since none exists on
            // any `SignerBackend` impl in this module.
            assert!(sig.ends_with(":chal-xyz"));
        }
    }
}
