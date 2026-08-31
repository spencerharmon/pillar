//! `pillar identity`/`user`/`key`/`offer` and `pillar trust`/`attest`/
//! `grant`/`caps`/`revoke`/`audit`: the CLI-side identity & trust-authority
//! command families of [`docs/cli-surface.md`](../../../docs/cli-surface.md)
//! § "Identity, trust, and authority families" (`cli-identity-trust-impl`).
//!
//! Built directly over the proven engines this task is filed against — never
//! a second, divergent implementation:
//!
//! - [`pillar_identity::global_identity::IdentityLog`]
//!   (`global-identity-log-impl`) backs [`IdentityCli`]: `new`/`show`/
//!   `enroll --domain`/`rotate-primary`/`link`/`unlink`/`backup`/`recover`.
//! - [`pillar_trust_artifacts::TrustStore`] (`trust-artifacts-impl`) backs
//!   [`AttestCli`], [`GrantCli`], [`CapsCli`], [`RevokeCli`] (the `attest`
//!   half), and [`AuditCli`] — typed artifacts, capacity checked explicitly
//!   at issuance, and a full proof-chain + natural-language sentence per
//!   audit.
//! - [`pillar_wot_authority::WotAuthority`] backs [`TrustCli`] (`trust`/
//!   `path`/`graph`) and the `trust`/`key` half of [`RevokeCli`].
//! - [`pillar_rbac::RbacDecider`] + [`pillar_rbac::ExplicitGrant`] are the
//!   SAME single decider every other command family routes through — `grant
//!   check`/`who-can` are pure views over it, never a private auth path.
//! - [`pillar_key_distribution`] (`key-distribution-offer-impl`) backs
//!   [`OfferCli`] (`seal`/`escrow`/`resolve`/`revoke`/`status`) and the
//!   escrow half of [`KeyCli`] (`escrow`/`recover`).
//!
//! # Views vs. acts (docs/cli-surface.md §1), enforced by construction
//!
//! Every method below is exactly one kind, and the kind is visible in its
//! receiver: a **view** takes `&self` and can never mutate anything it
//! reads (`show`, `path`, `graph`, `caps`, `check`/`who_can`, `audit`,
//! `status`, `fingerprint`, `attestations`); an **act** takes `&mut self`
//! and is the only place a signed artifact/event is ever recorded (`enroll`,
//! `rotate_primary`, `link`/`unlink`, `trust`, `attest`, `grant`
//! `add`/`rm`, `revoke`, `offer`'s `seal`/`escrow`/`resolve`/`revoke`, `key`'s
//! `gen`/`rotate`/`revoke`).

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_identity::global_identity::{
    Cid as IdentityCid, Domain, Genesis, IdentityLog, IdentityLogError, KeyId as IdentityKeyId,
    Rotation, Sig as IdentitySig,
};
use pillar_key_distribution::{
    Artifact, ArtifactId, ArtifactKind, CellId, Escrow, KeyDistributionError,
    KeyDistributionLedger, RecordKey, UserId as KdUserId,
};
use pillar_rbac::{Capability, Decision, ExplicitGrant, GrantEffect, RbacDecider, Request};
use pillar_trust_artifacts::{
    as_explicit_grants, Attest, Capacity, Cid as TrustCid, Predicate, Proof, Revoke,
    Sig as TrustSig, TrustError, TrustStore, VerifyError,
};
use pillar_wot_authority::WotAuthority;

// ---------------------------------------------------------------------
// pillar identity {new|show|enroll|rotate-primary|link|unlink|backup|recover}
// ---------------------------------------------------------------------

/// A read-only summary of an [`IdentityLog`] for `pillar identity show` —
/// the VIEW rendering, never mutates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySummary {
    /// The stable global CID (invariant across every rotation).
    pub cid: IdentityCid,
    /// The current primary generation number.
    pub head_generation: u64,
    /// The current primary key.
    pub current_primary: IdentityKeyId,
    /// Whether this identity has an authorized recovery key.
    pub has_recovery: bool,
    /// Every domain currently certified, with its subkey.
    pub domains: Vec<(Domain, IdentityKeyId)>,
}

/// Why an `identity`/`link`/`unlink` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityCliError {
    /// The underlying [`IdentityLog`] refused the operation.
    Log(IdentityLogError),
}

impl From<IdentityLogError> for IdentityCliError {
    fn from(e: IdentityLogError) -> Self {
        IdentityCliError::Log(e)
    }
}

/// `pillar identity …`: the per-identity CLI surface over one
/// [`IdentityLog`]. `new` constructs it; every other verb is a thin,
/// views-vs-acts-honoring wrapper.
pub struct IdentityCli {
    log: IdentityLog,
}

impl IdentityCli {
    /// `pillar identity new --primary <key> [--recovery <key>]` — an ACT:
    /// opens a fresh identity log from its signed genesis. The CID is fixed
    /// here and never changes.
    #[must_use]
    pub fn new(primary: IdentityKeyId, recovery: Option<IdentityKeyId>) -> Self {
        IdentityCli {
            log: IdentityLog::genesis(Genesis {
                initial_primary: primary,
                recovery,
            }),
        }
    }

    /// `pillar identity show` — a VIEW: renders the current identity state.
    #[must_use]
    pub fn show(&self) -> IdentitySummary {
        IdentitySummary {
            cid: self.log.cid().clone(),
            head_generation: self.log.head_generation(),
            current_primary: self.log.current_primary().clone(),
            has_recovery: self.log.recovery_key().is_some(),
            domains: self
                .log
                .domains()
                .map(|(d, k)| (d.clone(), k.clone()))
                .collect(),
        }
    }

    /// `pillar identity enroll --domain <domain> --subkey <key>` — an ACT:
    /// certify exactly one per-domain operational subkey, one hop, issued by
    /// the CURRENT primary (the CLI never lets a caller present any other
    /// issuer, so "enroll certifies one per-domain subkey (one hop)" is a
    /// structural guarantee, not a convention).
    pub fn enroll(
        &mut self,
        domain: Domain,
        subkey: IdentityKeyId,
    ) -> Result<(), IdentityCliError> {
        let issuer = self.log.current_primary().clone();
        self.log
            .certify_domain_subkey(domain, subkey, &issuer)
            .map_err(IdentityCliError::from)
    }

    /// `pillar identity rotate-primary --new <key> --as <signer>` — an ACT:
    /// installs a new primary, authorized iff signed by the current primary
    /// or the genesis-committed recovery key. The identity's CID is
    /// UNCHANGED by rotation (asserted by the caller via [`Self::show`]
    /// before/after).
    pub fn rotate_primary(
        &mut self,
        new_primary: IdentityKeyId,
        signer: IdentityKeyId,
    ) -> Result<u64, IdentityCliError> {
        self.log
            .rotate(Rotation {
                new_primary,
                sig: IdentitySig::by(signer),
            })
            .map_err(IdentityCliError::from)
    }

    /// `pillar identity link --domain <domain> --alias <alias>` — an ACT:
    /// opt-in pairwise/unlinkable mode for `domain`, binding a domain-local
    /// alias distinct from the global CID.
    pub fn link(&mut self, domain: &Domain, alias: impl Into<String>) -> Result<(), IdentityCliError> {
        self.log
            .enroll_pairwise(domain, alias)
            .map_err(IdentityCliError::from)
    }

    /// `pillar identity unlink --domain <domain>` — an ACT: revokes `domain`
    /// entirely (clears its outstanding offer and any pairwise linkage,
    /// fail-closed for all future per-domain operations on it) — the CLI's
    /// detach-a-domain counterpart to [`Self::link`].
    pub fn unlink(&mut self, domain: &Domain) {
        self.log.revoke_domain(domain);
    }

    /// `pillar identity backup` — a VIEW: a portable, human-legible snapshot
    /// of every field an operator needs to recognize this identity later
    /// (never the private key material this crate never models).
    #[must_use]
    pub fn backup(&self) -> String {
        let summary = self.show();
        let domains = summary
            .domains
            .iter()
            .map(|(d, k)| format!("{}={}", d.0, k.0))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "identity-backup-v1 cid={} generation={} primary={} recovery={} domains=[{}]",
            summary.cid.0,
            summary.head_generation,
            summary.current_primary.0,
            summary.has_recovery,
            domains
        )
    }

    /// `pillar identity recover --new <key>` — an ACT: rotate to `new`
    /// signed by the genesis-committed recovery key (refused if this
    /// identity has none). The one path to install a new primary WITHOUT
    /// the current primary's cooperation.
    pub fn recover(&mut self, new_primary: IdentityKeyId) -> Result<u64, IdentityCliError> {
        let recovery = self
            .log
            .recovery_key()
            .cloned()
            .ok_or(IdentityCliError::Log(IdentityLogError::UnauthorizedRotation {
                signer: new_primary.clone(),
            }))?;
        self.rotate_primary(new_primary, recovery)
    }
}

// ---------------------------------------------------------------------
// pillar user {add|invite|rm|rename|suspend|resume|passwd|roles|attestations}
// ---------------------------------------------------------------------

/// One cell member record — the CLI-layer model `pillar user` operates
/// over, deliberately thin: identity/authority live in [`IdentityLog`] and
/// [`TrustStore`]; this is just the membership roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    /// The user's handle (unique within the roster).
    pub handle: String,
    /// The global identity this user handle is bound to.
    pub identity: NodeId,
    /// The domain this user was added `--in`.
    pub domain: String,
    /// Named roles this user has been assigned (view-only labels; actual
    /// authority is `pillar attest`/`grant`, never this set alone).
    pub roles: BTreeSet<String>,
    /// Whether this user is currently suspended (suspended users are
    /// refused every act by [`UserCli::require_active`]).
    pub suspended: bool,
    /// An opaque password hash placeholder (never the plaintext).
    pub passwd_hash: Option<String>,
}

/// Why a `pillar user` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserCliError {
    /// The acting caller lacks the `identity/add-users` right (or whatever
    /// right the act requires) per the shared [`RbacDecider`] — an
    /// unauthorized act is refused with NOTHING mutated.
    Unauthorized {
        /// The caller that attempted the act.
        caller: NodeId,
        /// The right the act required.
        right: Capability,
    },
    /// No such user handle in the roster.
    NoSuchUser(String),
    /// A handle already exists in the roster.
    AlreadyExists(String),
    /// The user is suspended and cannot be acted upon until resumed.
    Suspended(String),
}

/// `pillar user …`: cell-member management gated on the SAME
/// [`RbacDecider`] every other act routes through — `add` requires the
/// caller hold `identity/add-users`.
pub struct UserCli {
    users: BTreeMap<String, UserRecord>,
}

impl UserCli {
    /// An empty roster.
    #[must_use]
    pub fn new() -> Self {
        UserCli {
            users: BTreeMap::new(),
        }
    }

    fn require_grant(
        &self,
        decider: &RbacDecider<'_>,
        caller: &NodeId,
        right: &str,
    ) -> Result<(), UserCliError> {
        let capability = Capability::from(right);
        let request = Request::new(caller.clone(), capability.clone());
        match decider.decide(&request) {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(UserCliError::Unauthorized {
                caller: caller.clone(),
                right: capability,
            }),
        }
    }

    /// `pillar user add --identity <id> --in <domain>` — an ACT: refused
    /// (nothing mutated) unless `caller` holds `identity/add-users` per the
    /// decider.
    pub fn add(
        &mut self,
        decider: &RbacDecider<'_>,
        caller: &NodeId,
        handle: impl Into<String>,
        identity: NodeId,
        domain: impl Into<String>,
    ) -> Result<(), UserCliError> {
        self.require_grant(decider, caller, "identity/add-users")?;
        let handle = handle.into();
        if self.users.contains_key(&handle) {
            return Err(UserCliError::AlreadyExists(handle));
        }
        self.users.insert(
            handle.clone(),
            UserRecord {
                handle,
                identity,
                domain: domain.into(),
                roles: BTreeSet::new(),
                suspended: false,
                passwd_hash: None,
            },
        );
        Ok(())
    }

    /// `pillar user invite --in <domain>` — an ACT: same admission path as
    /// [`Self::add`], modeling an out-of-band accepted invite (the CLI does
    /// not model the invite token itself).
    pub fn invite(
        &mut self,
        decider: &RbacDecider<'_>,
        caller: &NodeId,
        handle: impl Into<String>,
        identity: NodeId,
        domain: impl Into<String>,
    ) -> Result<(), UserCliError> {
        self.add(decider, caller, handle, identity, domain)
    }

    /// `pillar user rm <handle>` — an ACT.
    pub fn rm(&mut self, handle: &str) -> Result<(), UserCliError> {
        self.users
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| UserCliError::NoSuchUser(handle.to_owned()))
    }

    /// `pillar user rename <old> <new>` — an ACT.
    pub fn rename(&mut self, old: &str, new: impl Into<String>) -> Result<(), UserCliError> {
        let mut record = self
            .users
            .remove(old)
            .ok_or_else(|| UserCliError::NoSuchUser(old.to_owned()))?;
        let new = new.into();
        record.handle = new.clone();
        self.users.insert(new, record);
        Ok(())
    }

    /// `pillar user suspend <handle>` — an ACT.
    pub fn suspend(&mut self, handle: &str) -> Result<(), UserCliError> {
        self.record_mut(handle)?.suspended = true;
        Ok(())
    }

    /// `pillar user resume <handle>` — an ACT.
    pub fn resume(&mut self, handle: &str) -> Result<(), UserCliError> {
        self.record_mut(handle)?.suspended = false;
        Ok(())
    }

    /// `pillar user passwd <handle>` — an ACT: refused while suspended.
    pub fn passwd(&mut self, handle: &str, hash: impl Into<String>) -> Result<(), UserCliError> {
        let record = self.record_mut(handle)?;
        if record.suspended {
            return Err(UserCliError::Suspended(handle.to_owned()));
        }
        record.passwd_hash = Some(hash.into());
        Ok(())
    }

    /// `pillar user roles <handle>` — a VIEW: the labels attached by prior
    /// `pillar attest --as <role>@<scope>` acts against this user (see
    /// [`Self::note_role`]).
    #[must_use]
    pub fn roles(&self, handle: &str) -> BTreeSet<String> {
        self.users
            .get(handle)
            .map(|u| u.roles.clone())
            .unwrap_or_default()
    }

    /// Record a role label locally (called after a successful `pillar
    /// attest --as <role>@<scope>` names this user as subject) — an ACT.
    pub fn note_role(&mut self, handle: &str, role: impl Into<String>) -> Result<(), UserCliError> {
        self.record_mut(handle)?.roles.insert(role.into());
        Ok(())
    }

    /// `pillar user attestations <handle>` — a VIEW: every live attest
    /// artifact naming this user's identity as subject, rendered from the
    /// shared [`TrustStore`] (no separate bookkeeping — one source of
    /// truth).
    #[must_use]
    pub fn attestations(&self, handle: &str, store: &TrustStore) -> Vec<TrustCid> {
        let Some(record) = self.users.get(handle) else {
            return Vec::new();
        };
        as_explicit_grants(store)
            .into_iter()
            .filter(|g| &g.subject == &record.identity)
            .map(|g| TrustCid(format!("grant:{}:{}", g.subject.0, g.capability.0)))
            .collect()
    }

    fn record_mut(&mut self, handle: &str) -> Result<&mut UserRecord, UserCliError> {
        self.users
            .get_mut(handle)
            .ok_or_else(|| UserCliError::NoSuchUser(handle.to_owned()))
    }

    /// `pillar user show <handle>` / `pillar user list` — VIEWS.
    #[must_use]
    pub fn show(&self, handle: &str) -> Option<&UserRecord> {
        self.users.get(handle)
    }

    /// `pillar user list` — a VIEW.
    #[must_use]
    pub fn list(&self) -> Vec<&UserRecord> {
        self.users.values().collect()
    }
}

impl Default for UserCli {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------
// pillar key {gen|fingerprint|label|custody|rotate|revoke|verify|export|import|escrow|recover}
// ---------------------------------------------------------------------

/// One managed operational key record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    /// The key's stable id.
    pub id: IdentityKeyId,
    /// An operator-facing label (e.g. "laptop-2026").
    pub label: Option<String>,
    /// The node currently holding custody of this key.
    pub custody: Option<NodeId>,
    /// Whether this key has been revoked.
    pub revoked: bool,
    /// The generation this key was rotated FROM, if it is a rotation
    /// successor.
    pub rotated_from: Option<IdentityKeyId>,
}

/// Why a `pillar key` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyCliError {
    /// No such key id is managed here.
    NoSuchKey(IdentityKeyId),
    /// The key is revoked and cannot be acted upon.
    Revoked(IdentityKeyId),
    /// The underlying key-distribution escrow refused the operation.
    Distribution(KeyDistributionError),
}

impl From<KeyDistributionError> for KeyCliError {
    fn from(e: KeyDistributionError) -> Self {
        KeyCliError::Distribution(e)
    }
}

/// `pillar key …`: the caller's operational-subkey lifecycle, plus the
/// escrow/recover pair delegated to [`Escrow`] (`key-distribution-offer-impl`).
#[derive(Default)]
pub struct KeyCli {
    keys: BTreeMap<IdentityKeyId, KeyRecord>,
    escrow: Escrow,
}

impl KeyCli {
    /// A fresh, empty key manager.
    #[must_use]
    pub fn new() -> Self {
        KeyCli::default()
    }

    /// `pillar key gen` — an ACT: mint a new managed key record.
    pub fn gen(&mut self, id: IdentityKeyId) {
        self.keys.insert(
            id.clone(),
            KeyRecord {
                id,
                label: None,
                custody: None,
                revoked: false,
                rotated_from: None,
            },
        );
    }

    /// `pillar key fingerprint <id>` — a VIEW: a stable, deterministic
    /// fingerprint string derived from the key id (never real crypto — this
    /// crate models no key material).
    #[must_use]
    pub fn fingerprint(&self, id: &IdentityKeyId) -> Option<String> {
        self.keys.get(id).map(|_| format!("fp:{:x}", crc32(id.0.as_bytes())))
    }

    /// `pillar key label <id> <label>` — an ACT.
    pub fn label(&mut self, id: &IdentityKeyId, label: impl Into<String>) -> Result<(), KeyCliError> {
        self.record_mut(id)?.label = Some(label.into());
        Ok(())
    }

    /// `pillar key custody <id> <node>` — an ACT: assign holding custody.
    pub fn custody(&mut self, id: &IdentityKeyId, node: NodeId) -> Result<(), KeyCliError> {
        self.record_mut(id)?.custody = Some(node);
        Ok(())
    }

    /// `pillar key rotate <id> --to <new-id>` — an ACT: mint `new_id` as a
    /// rotation successor, carrying forward label/custody, and revoke the
    /// old id.
    pub fn rotate(&mut self, id: &IdentityKeyId, new_id: IdentityKeyId) -> Result<(), KeyCliError> {
        let old = self.record_mut(id)?.clone();
        if old.revoked {
            return Err(KeyCliError::Revoked(id.clone()));
        }
        self.keys.insert(
            new_id.clone(),
            KeyRecord {
                id: new_id,
                label: old.label,
                custody: old.custody,
                revoked: false,
                rotated_from: Some(id.clone()),
            },
        );
        self.keys.get_mut(id).expect("checked above").revoked = true;
        Ok(())
    }

    /// `pillar key revoke <id>` — an ACT: authority-reducing, fail-closed —
    /// idempotent (revoking twice is a no-op, never an error).
    pub fn revoke(&mut self, id: &IdentityKeyId) -> Result<(), KeyCliError> {
        self.record_mut(id)?.revoked = true;
        Ok(())
    }

    /// `pillar key verify <id>` — a VIEW: whether this key is currently
    /// managed and not revoked.
    #[must_use]
    pub fn verify(&self, id: &IdentityKeyId) -> bool {
        self.keys.get(id).is_some_and(|k| !k.revoked)
    }

    /// `pillar key export <id>` — a VIEW: a portable text form (never the
    /// private key material this crate does not model).
    #[must_use]
    pub fn export(&self, id: &IdentityKeyId) -> Option<String> {
        let k = self.keys.get(id)?;
        Some(format!(
            "key-export-v1 id={} label={} custody={} revoked={}",
            k.id.0,
            k.label.as_deref().unwrap_or(""),
            k.custody.as_ref().map(|n| n.0.as_str()).unwrap_or(""),
            k.revoked
        ))
    }

    /// `pillar key import <text>` — an ACT: the inverse of [`Self::export`].
    /// Refused (parse error) on malformed input rather than silently
    /// dropping fields.
    pub fn import(&mut self, text: &str) -> Result<IdentityKeyId, String> {
        let rest = text
            .strip_prefix("key-export-v1 id=")
            .ok_or_else(|| format!("not a key-export-v1 record: {text}"))?;
        let id_str = rest.split(' ').next().unwrap_or_default();
        if id_str.is_empty() {
            return Err(format!("missing id in: {text}"));
        }
        let id = IdentityKeyId(id_str.to_owned());
        self.keys.entry(id.clone()).or_insert(KeyRecord {
            id: id.clone(),
            label: None,
            custody: None,
            revoked: false,
            rotated_from: None,
        });
        Ok(id)
    }

    /// `pillar key escrow <id> --artifact <artifact-id>` — an ACT: store
    /// this key's operational artifact into the shared escrow (refused for
    /// a root artifact — the escrow authority bound).
    pub fn escrow(&mut self, artifact: ArtifactId) -> Result<(), KeyCliError> {
        let artifact = Artifact::new(artifact, ArtifactKind::Operational);
        self.escrow.store(&artifact).map_err(KeyCliError::from)
    }

    /// `pillar key recover <artifact-id>` — an ACT: client-cooperated
    /// plaintext recovery over the shared [`Escrow`].
    pub fn recover(&mut self, artifact: &ArtifactId) -> Result<(), KeyCliError> {
        self.escrow.client_participate(artifact)?;
        self.escrow.recover_plaintext(artifact)?;
        Ok(())
    }

    fn record_mut(&mut self, id: &IdentityKeyId) -> Result<&mut KeyRecord, KeyCliError> {
        self.keys
            .get_mut(id)
            .ok_or_else(|| KeyCliError::NoSuchKey(id.clone()))
    }
}

/// A tiny deterministic checksum (NOT a cryptographic fingerprint — this
/// crate never models real key material) used to give `pillar key
/// fingerprint` a stable, distinct-per-id string.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------
// pillar offer {seal|escrow|resolve|revoke|status}
// ---------------------------------------------------------------------

/// Why a `pillar offer` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferCliError {
    /// The underlying [`KeyDistributionLedger`] refused the transition.
    Ledger(KeyDistributionError),
}

impl From<KeyDistributionError> for OfferCliError {
    fn from(e: KeyDistributionError) -> Self {
        OfferCliError::Ledger(e)
    }
}

/// The resolved status of one offer record — `pillar offer status`'s VIEW
/// rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferStatus {
    /// Whether the record is currently offered.
    pub offered: bool,
    /// Whether the record has been admitted.
    pub admitted: bool,
    /// The current seal target (empty for any non-admitted record).
    pub sealed_to: BTreeSet<NodeId>,
}

/// `pillar offer …`: the operational-key offer/escrow lifecycle over
/// [`KeyDistributionLedger`] (`key-distribution-offer-impl`).
pub struct OfferCli {
    ledger: KeyDistributionLedger,
    escrow: Escrow,
}

impl OfferCli {
    /// A fresh ledger with no foreign nodes recorded.
    #[must_use]
    pub fn new(foreign_nodes: BTreeSet<NodeId>) -> Self {
        OfferCli {
            ledger: KeyDistributionLedger::new(foreign_nodes),
            escrow: Escrow::new(),
        }
    }

    /// Direct access to the underlying ledger, for cell-policy setup
    /// (`cell_mut`, `add_node_to_allowlist`, …) the offer family builds on.
    pub fn ledger_mut(&mut self) -> &mut KeyDistributionLedger {
        &mut self.ledger
    }

    /// `pillar offer seal --to <user> <cell> <artifact>` — an ACT: offer an
    /// escrowed artifact into a cell (the user-approval half of the
    /// bootstrap request).
    pub fn seal(
        &mut self,
        user: KdUserId,
        cell: CellId,
        artifact: ArtifactId,
    ) -> Result<(), OfferCliError> {
        self.ledger.offer(user, cell, artifact).map_err(OfferCliError::from)
    }

    /// `pillar offer escrow <artifact-kind> <artifact-id>` — an ACT: store
    /// the server-held envelope for an operational artifact.
    pub fn escrow(&mut self, artifact: ArtifactId, kind: ArtifactKind) -> Result<(), OfferCliError> {
        let artifact = Artifact::new(artifact, kind);
        self.escrow.store(&artifact).map_err(OfferCliError::from)
    }

    /// `pillar offer resolve <record>` — an ACT: the cell/node-side accept
    /// PLUS admission in one step, once both offer and accept exist (fires
    /// only under bi-directional consent — the ledger's own invariant).
    pub fn resolve(&mut self, record: &RecordKey) -> Result<(), OfferCliError> {
        self.ledger.accept(record)?;
        self.ledger.admit(record)?;
        Ok(())
    }

    /// `pillar offer revoke <record>` — an ACT: withdraw the offer,
    /// fail-closed (clears admission and seal immediately).
    pub fn revoke(&mut self, record: &RecordKey) -> Result<(), OfferCliError> {
        self.ledger.revoke_offer(record).map_err(OfferCliError::from)
    }

    /// `pillar offer status <record>` — a VIEW.
    #[must_use]
    pub fn status(&self, record: &RecordKey) -> OfferStatus {
        OfferStatus {
            offered: self.ledger.is_offered(record),
            admitted: self.ledger.is_admitted(record),
            sealed_to: self.ledger.seal_of(record),
        }
    }
}

// ---------------------------------------------------------------------
// pillar trust <id> [--depth N] [--in domain] / path / graph
// ---------------------------------------------------------------------

/// `pillar trust …`: the WoT trust-edge family over [`WotAuthority`].
pub struct TrustCli {
    authority: WotAuthority,
}

impl TrustCli {
    /// A fresh authority rooted at `owner`, bounded at `max_depth`.
    #[must_use]
    pub fn new(owner: NodeId, max_depth: u8) -> Self {
        TrustCli {
            authority: WotAuthority::new(owner, max_depth),
        }
    }

    /// `pillar trust <id> [--depth N]` — an ACT: install a trust edge from
    /// `signer` to `subject` bounding onward delegation at `depth`.
    pub fn trust(&mut self, signer: NodeId, subject: NodeId, depth: u8) {
        self.authority.issue_edge(signer, subject, depth);
    }

    /// `pillar trust path <id>` — a VIEW: the reachable depth from the
    /// authority's owner to `id`, if any.
    #[must_use]
    pub fn path(&self, id: &NodeId) -> Option<u8> {
        self.authority.reachable_depth(id)
    }

    /// `pillar trust graph [--group <id>]` — a VIEW: the members of a trust
    /// group rooted at `group`.
    #[must_use]
    pub fn graph(&self, group: &NodeId) -> BTreeSet<NodeId> {
        self.authority.group_members(group).into_iter().collect()
    }

    /// Shared read access to the underlying authority, for `revoke
    /// trust`/`key` and RBAC decisions built on the same graph.
    #[must_use]
    pub fn authority(&self) -> &WotAuthority {
        &self.authority
    }

    /// Mutable access to the underlying authority, for `revoke trust`/`key`.
    pub fn authority_mut(&mut self) -> &mut WotAuthority {
        &mut self.authority
    }
}

// ---------------------------------------------------------------------
// pillar attest --as <role>@<scope> --subject --allow --quota cpu=1000m --in cell
// ---------------------------------------------------------------------

/// `pillar attest …`: issue a capacity-checked authorization claim over the
/// shared [`TrustStore`].
pub struct AttestCli;

impl AttestCli {
    /// `pillar attest --as self --subject <id> --allow <action> <resource>
    /// [--quota N] --in <scope>` — an ACT: capacity is checked AT SIGNING
    /// TIME by [`TrustStore::issue_attest`] — the issuer must currently HOLD
    /// the declared capacity (never deferred). Returns the artifact's
    /// content address on success.
    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        store: &mut TrustStore,
        issuer: NodeId,
        capacity: Capacity,
        authority: Option<TrustCid>,
        subject: NodeId,
        predicate: Predicate,
        scope: impl Into<String>,
    ) -> Result<TrustCid, TrustError> {
        let epoch = store.epoch();
        store.issue_attest(Attest {
            issuer: issuer.clone(),
            capacity,
            authority,
            subject,
            predicate,
            scope: scope.into(),
            epoch,
            sig: TrustSig::by(issuer),
        })
    }

    /// The `--quota N` path: admit `amount` against a JUST-issued quota
    /// attest's budget — a BUDGET LEDGER charge, never a bare boolean allow.
    /// Refused if the predicate carries no quota, or the budget would be
    /// exceeded.
    pub fn admit_quota(
        store: &mut TrustStore,
        cid: &TrustCid,
        amount: u64,
    ) -> Result<(), TrustError> {
        store.admit_quota(cid, amount)
    }
}

// ---------------------------------------------------------------------
// pillar grant {add|rm|check(can-i)|who-can}
// ---------------------------------------------------------------------

/// `pillar grant …`: explicit ALLOW/DENY grants over the shared decider
/// state — `check`/`who-can` are PURE VIEWS (`&self`, never mutate).
#[derive(Default)]
pub struct GrantCli {
    grants: Vec<ExplicitGrant>,
}

impl GrantCli {
    /// A fresh, empty grant set.
    #[must_use]
    pub fn new() -> Self {
        GrantCli::default()
    }

    /// `pillar grant add <right> --to <user> [--allow|--deny]` — an ACT.
    pub fn add(&mut self, subject: NodeId, capability: Capability, effect: GrantEffect) {
        self.grants.retain(|g| !(g.subject == subject && g.capability == capability));
        self.grants.push(ExplicitGrant {
            subject,
            capability,
            effect,
        });
    }

    /// `pillar grant rm <right> --to <user>` — an ACT: removes any grant
    /// for that `(subject, capability)` pair (allow or deny). Idempotent.
    pub fn rm(&mut self, subject: &NodeId, capability: &Capability) {
        self.grants
            .retain(|g| !(&g.subject == subject && &g.capability == capability));
    }

    /// `pillar grant check <right> --as <user>` (`can-i`) — a PURE VIEW:
    /// asks the SAME [`RbacDecider`] every act routes through — never a
    /// private/duplicated auth path.
    #[must_use]
    pub fn check(&self, authority: &WotAuthority, subject: &NodeId, capability: &Capability) -> Decision {
        let decider = RbacDecider::new(authority, &[], &self.grants);
        decider.decide(&Request::new(subject.clone(), capability.clone()))
    }

    /// `pillar grant who-can <right>` — a PURE VIEW: every subject with an
    /// explicit ALLOW of `capability` (deny-effect grants are never
    /// positive authority and are excluded).
    #[must_use]
    pub fn who_can(&self, capability: &Capability) -> BTreeSet<NodeId> {
        self.grants
            .iter()
            .filter(|g| &g.capability == capability && g.effect == GrantEffect::Allow)
            .map(|g| g.subject.clone())
            .collect()
    }

    /// The current explicit grant set — used by `pillar caps` and by
    /// `pillar revoke grant`.
    #[must_use]
    pub fn grants(&self) -> &[ExplicitGrant] {
        &self.grants
    }
}

// ---------------------------------------------------------------------
// pillar caps [<user>]
// ---------------------------------------------------------------------

/// `pillar caps [<user>]` — a VIEW (signs nothing): the effective
/// capability set the decider computes for `subject` — the pillar `auth
/// can-i`, generalized to "every capability this store knows about".
pub struct CapsCli;

impl CapsCli {
    /// Render the effective ALLOW set for `subject` across `candidates`
    /// (the capability universe to probe — the decider has no
    /// "list all capabilities" primitive, so the caller names what it cares
    /// about, exactly like `kubectl auth can-i --list` enumerates a known
    /// verb set).
    #[must_use]
    pub fn effective(
        authority: &WotAuthority,
        grants: &[ExplicitGrant],
        subject: &NodeId,
        candidates: &[Capability],
    ) -> BTreeSet<Capability> {
        let decider = RbacDecider::new(authority, &[], grants);
        candidates
            .iter()
            .filter(|c| decider.decide(&Request::new(subject.clone(), (*c).clone())) == Decision::Allow)
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------
// pillar revoke {trust|grant|key} <ref>
// ---------------------------------------------------------------------

/// `pillar revoke {trust|grant|key} <ref>` — ACTS: authority-REDUCING,
/// fail-closed. Each targets exactly one authority source and never
/// touches the others.
pub struct RevokeCli;

impl RevokeCli {
    /// `pillar revoke trust <signer> <subject>` — removes one specific
    /// trust edge only (never the whole node).
    pub fn trust(authority: &mut WotAuthority, signer: NodeId, subject: NodeId) {
        authority.revoke_edge(signer, subject);
    }

    /// `pillar revoke grant <right> --to <user>` — removes one explicit
    /// grant.
    pub fn grant(grants: &mut GrantCli, subject: &NodeId, capability: &Capability) {
        grants.rm(subject, capability);
    }

    /// `pillar revoke key <id>` — removes ALL authority reachable through
    /// `key` in the WoT graph (a strictly stronger act than [`Self::trust`],
    /// mirroring [`WotAuthority::revoke_key`]).
    pub fn key(authority: &mut WotAuthority, key: NodeId) {
        authority.revoke_key(key);
    }

    /// `pillar revoke attest <cid>` — an ACT over [`TrustStore`]: revoke one
    /// specific attest artifact by content address, bumping the store's
    /// epoch by one so any attest signed at the prior epoch is immediately
    /// stale for future issuance.
    pub fn attest(store: &mut TrustStore, target: TrustCid, signer: NodeId) -> Result<(), TrustError> {
        store.revoke(&Revoke {
            target,
            sig: TrustSig::by(signer),
        })
    }
}

// ---------------------------------------------------------------------
// pillar audit <cid>
// ---------------------------------------------------------------------

/// `pillar audit <cid>` — a VIEW: renders the full proof chain plus the
/// natural-language sentence for one attest artifact, or the reason
/// verification failed.
pub struct AuditCli;

impl AuditCli {
    /// Render the audit result for `cid`.
    #[must_use]
    pub fn audit(store: &TrustStore, cid: &TrustCid) -> Result<Proof, VerifyError> {
        store.verify(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn kid(s: &str) -> IdentityKeyId {
        IdentityKeyId::from(s)
    }

    fn domain(s: &str) -> Domain {
        Domain::from(s)
    }

    // -- identity --------------------------------------------------------

    #[test]
    fn enroll_certifies_one_per_domain_subkey_one_hop() {
        let mut cli = IdentityCli::new(kid("primary-0"), None);
        cli.enroll(domain("example.com"), kid("subkey-a")).unwrap();

        let summary = cli.show();
        assert_eq!(summary.domains, vec![(domain("example.com"), kid("subkey-a"))]);

        // A second enroll on the SAME domain is refused (exactly one subkey
        // per domain) — one hop, never a chain.
        let err = cli.enroll(domain("example.com"), kid("subkey-b")).unwrap_err();
        assert_eq!(
            err,
            IdentityCliError::Log(IdentityLogError::DomainAlreadyCertified(domain("example.com")))
        );
    }

    #[test]
    fn rotate_primary_preserves_the_identity_cid() {
        let mut cli = IdentityCli::new(kid("primary-0"), None);
        let cid_before = cli.show().cid;

        cli.rotate_primary(kid("primary-1"), kid("primary-0")).unwrap();

        let after = cli.show();
        assert_eq!(after.cid, cid_before, "identity CID must survive rotation");
        assert_eq!(after.current_primary, kid("primary-1"));
        assert_eq!(after.head_generation, 1);
    }

    #[test]
    fn rotate_primary_refuses_an_unauthorized_signer() {
        let mut cli = IdentityCli::new(kid("primary-0"), None);
        let err = cli.rotate_primary(kid("primary-1"), kid("attacker")).unwrap_err();
        assert_eq!(
            err,
            IdentityCliError::Log(IdentityLogError::UnauthorizedRotation {
                signer: kid("attacker")
            })
        );
    }

    #[test]
    fn recover_rotates_via_the_recovery_key_without_the_primary() {
        let mut cli = IdentityCli::new(kid("primary-0"), Some(kid("recovery-0")));
        cli.recover(kid("primary-1")).unwrap();
        assert_eq!(cli.show().current_primary, kid("primary-1"));
    }

    #[test]
    fn recover_refused_with_no_recovery_key_configured() {
        let mut cli = IdentityCli::new(kid("primary-0"), None);
        assert!(cli.recover(kid("primary-1")).is_err());
    }

    #[test]
    fn link_unlink_round_trip() {
        let mut cli = IdentityCli::new(kid("primary-0"), None);
        cli.enroll(domain("example.com"), kid("subkey-a")).unwrap();
        cli.link(&domain("example.com"), "alias-1").unwrap();
        assert_eq!(cli.log.pairwise_alias(&domain("example.com")), Some("alias-1"));

        cli.unlink(&domain("example.com"));
        assert!(cli.log.is_revoked(&domain("example.com")));
    }

    #[test]
    fn backup_renders_a_stable_snapshot() {
        let cli = IdentityCli::new(kid("primary-0"), Some(kid("recovery-0")));
        let text = cli.backup();
        assert!(text.contains("primary=primary-0"));
        assert!(text.contains("recovery=true"));
    }

    // -- user --------------------------------------------------------

    #[test]
    fn user_add_requires_the_add_users_grant() {
        let authority = WotAuthority::new(nid("root"), 4);
        let allowed = vec![ExplicitGrant {
            subject: nid("op"),
            capability: Capability::from("identity/add-users"),
            effect: GrantEffect::Allow,
        }];
        let decider_allow = RbacDecider::new(&authority, &[], &allowed);
        let decider_deny = RbacDecider::new(&authority, &[], &[]);

        let mut cli = UserCli::new();
        let err = cli
            .add(&decider_deny, &nid("stranger"), "alice", nid("id-alice"), "example.com")
            .unwrap_err();
        assert!(matches!(err, UserCliError::Unauthorized { .. }));
        assert!(cli.show("alice").is_none());

        cli.add(&decider_allow, &nid("op"), "alice", nid("id-alice"), "example.com")
            .unwrap();
        assert!(cli.show("alice").is_some());
    }

    #[test]
    fn user_suspend_blocks_passwd() {
        let authority = WotAuthority::new(nid("root"), 4);
        let grants = vec![ExplicitGrant {
            subject: nid("op"),
            capability: Capability::from("identity/add-users"),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&authority, &[], &grants);
        let mut cli = UserCli::new();
        cli.add(&decider, &nid("op"), "alice", nid("id-alice"), "example.com")
            .unwrap();
        cli.suspend("alice").unwrap();
        assert!(matches!(
            cli.passwd("alice", "hash"),
            Err(UserCliError::Suspended(_))
        ));
        cli.resume("alice").unwrap();
        cli.passwd("alice", "hash").unwrap();
    }

    // -- key -----------------------------------------------------------

    #[test]
    fn key_rotate_revokes_the_predecessor() {
        let mut cli = KeyCli::new();
        cli.gen(kid("k1"));
        cli.rotate(&kid("k1"), kid("k2")).unwrap();
        assert!(!cli.verify(&kid("k1")));
        assert!(cli.verify(&kid("k2")));
    }

    #[test]
    fn key_export_import_round_trip() {
        let mut cli = KeyCli::new();
        cli.gen(kid("k1"));
        cli.label(&kid("k1"), "laptop").unwrap();
        let text = cli.export(&kid("k1")).unwrap();

        let mut other = KeyCli::new();
        let id = other.import(&text).unwrap();
        assert_eq!(id, kid("k1"));
        assert!(other.verify(&kid("k1")));
    }

    #[test]
    fn key_fingerprint_is_stable_and_distinct() {
        let mut cli = KeyCli::new();
        cli.gen(kid("k1"));
        cli.gen(kid("k2"));
        let fp1a = cli.fingerprint(&kid("k1")).unwrap();
        let fp1b = cli.fingerprint(&kid("k1")).unwrap();
        let fp2 = cli.fingerprint(&kid("k2")).unwrap();
        assert_eq!(fp1a, fp1b);
        assert_ne!(fp1a, fp2);
    }

    // -- offer -----------------------------------------------------------

    #[test]
    fn offer_seal_resolve_status_round_trip() {
        let mut cli = OfferCli::new(BTreeSet::new());
        cli.ledger_mut().cell_mut(CellId::from("cellA")).add_user(KdUserId::from("alice"));
        cli.ledger_mut()
            .register_artifact(Artifact::new(ArtifactId::from("art-1"), ArtifactKind::Operational));

        let record = RecordKey {
            user: KdUserId::from("alice"),
            cell: CellId::from("cellA"),
            artifact: ArtifactId::from("art-1"),
        };

        cli.seal(KdUserId::from("alice"), CellId::from("cellA"), ArtifactId::from("art-1"))
            .unwrap();
        assert!(cli.status(&record).offered);
        assert!(!cli.status(&record).admitted);

        cli.resolve(&record).unwrap();
        assert!(cli.status(&record).admitted);

        cli.revoke(&record).unwrap();
        let status = cli.status(&record);
        assert!(!status.offered);
        assert!(!status.admitted);
    }

    #[test]
    fn offer_seal_refuses_a_root_artifact() {
        let mut cli = OfferCli::new(BTreeSet::new());
        cli.ledger_mut().cell_mut(CellId::from("cellA")).add_user(KdUserId::from("alice"));
        cli.ledger_mut()
            .register_artifact(Artifact::new(ArtifactId::from("root-1"), ArtifactKind::Root));

        let err = cli
            .seal(KdUserId::from("alice"), CellId::from("cellA"), ArtifactId::from("root-1"))
            .unwrap_err();
        assert!(matches!(
            err,
            OfferCliError::Ledger(KeyDistributionError::RootArtifactNotDistributable(_))
        ));
    }

    // -- trust / attest / grant / caps / revoke / audit ------------------

    #[test]
    fn attest_as_checks_signer_held_capacity_and_audit_renders_the_chain() {
        let genesis = nid("genesis");
        let mut store = TrustStore::new(genesis.clone());

        // genesis attests operator@cellA to alice.
        let cid_alice = AttestCli::attest(
            &mut store,
            genesis.clone(),
            Capacity::Role {
                role: "operator".to_owned(),
                scope: "cellA".to_owned(),
            },
            None,
            nid("alice"),
            Predicate::new("stream:append", "cellA/streams/*"),
            "cellA",
        )
        .unwrap();

        // alice, HOLDING operator@cellA, attests bob may act too — checked
        // AT SIGNING TIME against alice's held capacity.
        let cid_bob = AttestCli::attest(
            &mut store,
            nid("alice"),
            Capacity::Role {
                role: "operator".to_owned(),
                scope: "cellA".to_owned(),
            },
            Some(cid_alice.clone()),
            nid("bob"),
            Predicate::new("stream:append", "cellA/streams/*"),
            "cellA",
        )
        .unwrap();

        let proof = AuditCli::audit(&store, &cid_bob).unwrap();
        assert_eq!(proof.chain, vec![cid_bob.clone(), cid_alice.clone()]);
        assert!(proof.sentence.contains("rooted at genesis genesis"));

        // eve never held the capacity: refused, nothing recorded.
        let err = AttestCli::attest(
            &mut store,
            nid("eve"),
            Capacity::Role {
                role: "operator".to_owned(),
                scope: "cellA".to_owned(),
            },
            None,
            nid("mallory"),
            Predicate::new("stream:append", "cellA/streams/*"),
            "cellA",
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::CapacityNotHeld { .. }));
    }

    #[test]
    fn quota_attest_produces_a_budget_form_not_boolean() {
        let genesis = nid("genesis");
        let mut store = TrustStore::new(genesis.clone());

        let cid = AttestCli::attest(
            &mut store,
            genesis,
            Capacity::SelfCap,
            None,
            nid("bob"),
            Predicate::new("compute:cpu", "cellA/*").with_quota(1000),
            "cellA",
        )
        .unwrap();

        // A boolean-only predicate is refused for quota admission.
        AttestCli::admit_quota(&mut store, &cid, 400).unwrap();
        assert_eq!(store.admitted_amount(&cid), 400);
        AttestCli::admit_quota(&mut store, &cid, 400).unwrap();
        assert_eq!(store.admitted_amount(&cid), 800);

        // Exceeding the declared budget is refused (a bare boolean allow
        // would never enforce this).
        let err = AttestCli::admit_quota(&mut store, &cid, 400).unwrap_err();
        assert_eq!(
            err,
            TrustError::QuotaExceeded {
                requested: 400,
                remaining: 200
            }
        );

        // A non-quota predicate is refused for quota admission.
        let cid2 = AttestCli::attest(
            &mut store,
            NodeId::from("genesis"),
            Capacity::SelfCap,
            None,
            nid("carol"),
            Predicate::new("stream:append", "cellA/*"),
            "cellA",
        )
        .unwrap();
        assert_eq!(
            AttestCli::admit_quota(&mut store, &cid2, 1).unwrap_err(),
            TrustError::NotAQuotaPredicate
        );
    }

    #[test]
    fn grant_check_and_who_can_are_pure_views() {
        let authority = WotAuthority::new(nid("root"), 4);
        let mut grants = GrantCli::new();
        grants.add(nid("alice"), Capability::from("stream:append"), GrantEffect::Allow);
        grants.add(nid("eve"), Capability::from("stream:append"), GrantEffect::Deny);

        let before = grants.grants().to_vec();

        assert_eq!(
            grants.check(&authority, &nid("alice"), &Capability::from("stream:append")),
            Decision::Allow
        );
        assert_eq!(
            grants.check(&authority, &nid("eve"), &Capability::from("stream:append")),
            Decision::Deny
        );
        assert_eq!(
            grants.check(&authority, &nid("stranger"), &Capability::from("stream:append")),
            Decision::Deny
        );

        let who = grants.who_can(&Capability::from("stream:append"));
        assert_eq!(who, BTreeSet::from([nid("alice")]));

        // Views never mutate.
        assert_eq!(grants.grants(), before.as_slice());
    }

    #[test]
    fn an_unauthorized_act_is_refused() {
        let authority = WotAuthority::new(nid("root"), 4);
        let decider = RbacDecider::new(&authority, &[], &[]);
        let mut users = UserCli::new();
        let err = users
            .add(&decider, &nid("stranger"), "mallory", nid("id-mallory"), "example.com")
            .unwrap_err();
        assert!(matches!(err, UserCliError::Unauthorized { .. }));
        assert!(users.list().is_empty());
    }

    #[test]
    fn revoke_key_removes_all_authority_and_revoke_trust_removes_one_edge() {
        let mut authority = WotAuthority::new(nid("root"), 4);
        authority.issue_edge(nid("root"), nid("alice"), 3);
        authority.issue_edge(nid("alice"), nid("bob"), 2);
        assert!(authority.reachable_depth(&nid("bob")).is_some());

        RevokeCli::trust(&mut authority, nid("alice"), nid("bob"));
        assert!(authority.reachable_depth(&nid("bob")).is_none());
        // alice's own edge from root is untouched.
        assert!(authority.reachable_depth(&nid("alice")).is_some());

        authority.issue_edge(nid("alice"), nid("bob"), 2);
        RevokeCli::key(&mut authority, nid("alice"));
        assert!(authority.reachable_depth(&nid("bob")).is_none());
        assert!(authority.reachable_depth(&nid("alice")).is_none());
    }

    #[test]
    fn trust_cli_path_and_graph() {
        let mut cli = TrustCli::new(nid("root"), 4);
        cli.trust(nid("root"), nid("alice"), 3);
        cli.trust(nid("alice"), nid("bob"), 2);

        assert!(cli.path(&nid("bob")).is_some());
        assert!(cli.path(&nid("carol")).is_none());

        let group = cli.graph(&nid("alice"));
        assert!(group.contains(&nid("bob")));
    }

    #[test]
    fn caps_effective_reflects_deny_over_allow() {
        let authority = WotAuthority::new(nid("root"), 4);
        let grants = vec![
            ExplicitGrant {
                subject: nid("alice"),
                capability: Capability::from("a"),
                effect: GrantEffect::Allow,
            },
            ExplicitGrant {
                subject: nid("alice"),
                capability: Capability::from("b"),
                effect: GrantEffect::Deny,
            },
        ];
        let caps = CapsCli::effective(
            &authority,
            &grants,
            &nid("alice"),
            &[Capability::from("a"), Capability::from("b"), Capability::from("c")],
        );
        assert_eq!(caps, BTreeSet::from([Capability::from("a")]));
    }
}
