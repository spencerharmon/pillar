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

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use pillar_core::NodeId;
use pillar_rbac::{Capability, ExplicitGrant, GrantEffect};

/// The content address of a stored artifact (a [`Attest`], keyed by its
/// [`Attest::cid`]). Distinct artifact instances with identical fields
/// address the SAME [`Cid`] — this is what makes an `authority` field a
/// genuine content-addressed "proof pointer" rather than an opaque handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub String);

/// A stand-in for a verified signature: the identity that produced it. As in
/// `pillar_identity::global_identity`, the model trusts a `Sig` to be
/// authentic; the store's job is to check the signer is AUTHORIZED (capacity
/// held at signing time), not to verify crypto.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sig {
    /// The identity that signed the artifact.
    pub signer: NodeId,
}

impl Sig {
    /// A signature produced by `signer`.
    #[must_use]
    pub fn by(signer: impl Into<NodeId>) -> Self {
        Sig { signer: signer.into() }
    }
}

fn content_address(parts: &[&str]) -> Cid {
    let mut h = DefaultHasher::new();
    "pillar-trust-artifact-v1".hash(&mut h);
    for p in parts {
        p.hash(&mut h);
    }
    Cid(format!("trust:{:016x}", h.finish()))
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
        content_address(&["certify", self.identity.0.as_str(), self.subkey.0.as_str()])
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
            self.truster.0.as_str(),
            self.trustee.0.as_str(),
            self.depth.to_string().as_str(),
        ])
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
        if c.sig.signer != c.identity {
            return Err(TrustError::SignerMismatch);
        }
        Ok(c.cid())
    }

    /// Record a **trust** artifact: unconditional (AP), rejecting only a
    /// signer mismatch.
    pub fn trust(&self, t: &Trust) -> Result<Cid, TrustError> {
        if t.sig.signer != t.truster {
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
        if a.sig.signer != a.issuer {
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
        let cid = a.cid();
        self.attests.insert(cid.clone(), a);
        Ok(cid)
    }

    /// **revoke** — epoch-stamped, fail-closed: marks `target` revoked (a
    /// specific attest artifact, content-addressed) and bumps the global
    /// epoch by exactly one, so any attest signed at the prior epoch is
    /// immediately stale for future issuance and `target`'s own chain (and
    /// anything walking through it) fails verification closed from this
    /// point on.
    pub fn revoke(&mut self, r: &Revoke) -> Result<(), TrustError> {
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
        let a = self.attests.get(cid).ok_or_else(|| VerifyError::Broken(cid.clone()));
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

    // --- four types round-trip ------------------------------------------

    #[test]
    fn certify_round_trips_sign_content_address_verify() {
        let store = TrustStore::new(n("owner"));
        let c = Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: Sig::by(n("alice")),
        };
        let cid = store.certify(&c).expect("certify accepted");
        // Content-addressed: identical fields address the same Cid.
        let c2 = Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: Sig::by(n("alice")),
        };
        assert_eq!(cid, c2.cid());
    }

    #[test]
    fn certify_rejects_a_signer_mismatch() {
        let store = TrustStore::new(n("owner"));
        let c = Certify {
            identity: n("alice"),
            subkey: n("alice-sub"),
            sig: Sig::by(n("mallory")),
        };
        assert_eq!(store.certify(&c), Err(TrustError::SignerMismatch));
    }

    #[test]
    fn trust_round_trips_sign_content_address_verify() {
        let store = TrustStore::new(n("owner"));
        let t = Trust {
            truster: n("alice"),
            trustee: n("bob"),
            depth: 2,
            sig: Sig::by(n("alice")),
        };
        let cid = store.trust(&t).expect("trust accepted");
        assert_eq!(cid, t.cid());
    }

    #[test]
    fn trust_rejects_a_signer_mismatch() {
        let store = TrustStore::new(n("owner"));
        let t = Trust {
            truster: n("alice"),
            trustee: n("bob"),
            depth: 2,
            sig: Sig::by(n("mallory")),
        };
        assert_eq!(store.trust(&t), Err(TrustError::SignerMismatch));
    }

    #[test]
    fn attest_round_trips_sign_content_address_verify() {
        let mut store = TrustStore::new(n("owner"));
        let a = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let expected_cid = a.cid();
        let cid = store.issue_attest(a).expect("attest accepted");
        assert_eq!(cid, expected_cid);
        let proof = store.verify(&cid).expect("verifies");
        assert_eq!(proof.chain, vec![cid]);
    }

    #[test]
    fn revoke_round_trips_and_targets_a_specific_cid() {
        let mut store = TrustStore::new(n("owner"));
        let a = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid = store.issue_attest(a).unwrap();
        let r = Revoke {
            target: cid.clone(),
            sig: Sig::by(n("owner")),
        };
        store.revoke(&r).expect("revoke accepted");
        assert!(matches!(store.verify(&cid), Err(VerifyError::Revoked(_))));
    }

    #[test]
    fn revoke_rejects_an_unknown_target() {
        let mut store = TrustStore::new(n("owner"));
        let r = Revoke {
            target: Cid("trust:doesnotexist".to_owned()),
            sig: Sig::by(n("owner")),
        };
        assert!(matches!(store.revoke(&r), Err(TrustError::UnknownTarget(_))));
    }

    // --- capacity checked at signing time --------------------------------

    #[test]
    fn role_not_held_at_signing_is_rejected() {
        let mut store = TrustStore::new(n("owner"));
        // alice never received any role-grant attest, so she cannot issue one.
        let a = Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("alice")),
        };
        assert_eq!(
            store.issue_attest(a),
            Err(TrustError::CapacityNotHeld { issuer: n("alice") })
        );
    }

    #[test]
    fn role_held_at_signing_is_admitted_and_can_sub_delegate() {
        let mut store = TrustStore::new(n("owner"));
        let grant_to_alice = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let alice_cid = store.issue_attest(grant_to_alice).unwrap();

        // alice now holds the role capacity and can sub-delegate, pointing
        // her authority proof pointer at the exact grant edge she used.
        let sub_grant = Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: Some(alice_cid.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("alice")),
        };
        let bob_cid = store.issue_attest(sub_grant).expect("alice holds capacity");
        let proof = store.verify(&bob_cid).expect("verifies to genesis");
        assert_eq!(proof.chain, vec![bob_cid, alice_cid]);
    }

    #[test]
    fn self_capacity_is_unconditional_and_needs_no_authority_pointer() {
        let mut store = TrustStore::new(n("owner"));
        let a = Attest {
            issuer: n("alice"),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("identity:describe", "self"),
            scope: "global".to_owned(),
            epoch: 0,
            sig: Sig::by(n("alice")),
        };
        let cid = store.issue_attest(a).expect("self capacity is unconditional");
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
        let a = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: Some(Cid("trust:self-cycle-b".to_owned())),
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid_a = a.cid();
        let b = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: Some(cid_a.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
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
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
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
        let grant_to_alice = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let alice_cid = store.issue_attest(grant_to_alice).unwrap();
        let sub_grant = Attest {
            issuer: n("alice"),
            capacity: role("operator", "cell-b"),
            authority: Some(alice_cid.clone()),
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("alice")),
        };
        let bob_cid = store.issue_attest(sub_grant).unwrap();
        assert!(store.verify(&bob_cid).is_ok());

        // Revoke alice's own grant edge: bob's chain must now fail closed,
        // even though bob's own attest was never directly touched.
        store
            .revoke(&Revoke {
                target: alice_cid.clone(),
                sig: Sig::by(n("owner")),
            })
            .unwrap();

        assert_eq!(store.verify(&bob_cid), Err(VerifyError::Revoked(alice_cid)));
    }

    #[test]
    fn a_stale_epoch_view_refuses_new_attest_issuance_fail_closed() {
        let mut store = TrustStore::new(n("owner"));
        // Bump epoch by revoking something first.
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid = store.issue_attest(grant).unwrap();
        store
            .revoke(&Revoke {
                target: cid,
                sig: Sig::by(n("owner")),
            })
            .unwrap();
        assert_eq!(store.epoch(), 1);

        // Attempt to issue at the now-stale epoch 0.
        let stale = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("bob"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
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
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(1000),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
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
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"), // no quota
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid = store.issue_attest(grant).unwrap();
        assert_eq!(store.admit_quota(&cid, 1), Err(TrustError::NotAQuotaPredicate));
    }

    #[test]
    fn revoked_quota_grant_refuses_further_admission() {
        let mut store = TrustStore::new(n("owner"));
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(1000),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid = store.issue_attest(grant).unwrap();
        store.admit_quota(&cid, 100).unwrap();
        store
            .revoke(&Revoke {
                target: cid.clone(),
                sig: Sig::by(n("owner")),
            })
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
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
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
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("operator", "cell-b"),
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("stream:append", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::by(n("owner")),
        };
        let cid = store.issue_attest(grant).unwrap();
        store
            .revoke(&Revoke {
                target: cid,
                sig: Sig::by(n("owner")),
            })
            .unwrap();
        assert!(as_explicit_grants(&store).is_empty());
    }

    #[test]
    fn self_capacity_attests_never_project_a_third_party_grant() {
        let mut store = TrustStore::new(n("owner"));
        let a = Attest {
            issuer: n("alice"),
            capacity: Capacity::SelfCap,
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("identity:describe", "self"),
            scope: "global".to_owned(),
            epoch: 0,
            sig: Sig::by(n("alice")),
        };
        store.issue_attest(a).unwrap();
        assert!(as_explicit_grants(&store).is_empty());
    }
}
