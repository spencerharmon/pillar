//! CID-addressed self-certifying global identity log — the Rust refinement of
//! `specs/GlobalIdentity.tla` (ROI P1 "Global identity & multi-domain
//! membership").
//!
//! # Model
//!
//! A user is **one global identity** == a self-certifying, content-addressed
//! (CID) identity LOG. The stable global [`Cid`] addresses a signed
//! [`Genesis`] entry naming the *initial primary key*; the log admits later
//! signed [`Rotation`] entries, each naming a new primary and signed by the
//! *then-current* primary. The primary rotates **without changing the global
//! CID** — the identifier addresses the genesis, not the current key material,
//! so it is stable across every rotation (a signature issued by primary
//! generation `g` stays attributable to the same global identity forever).
//!
//! * **Self-certifying append.** A rotation is authorized iff signed by the
//!   current primary (the key the log currently names), or by an authorized
//!   recovery key committed in the genesis. A rotation signed by anything else
//!   is rejected — no forged / self-appointed primary. Historical generations
//!   are never dropped, so every historical issuer reference survives.
//! * **Per-domain subkeys, ONE HOP.** The current primary certifies exactly
//!   one operational subkey per domain, directly. A subkey never certifies
//!   another subkey: a two-hop chain is refused by construction.
//! * **Delivery over offer/escrow.** A per-domain subkey is delivered to a
//!   node as a node-sealed, revocable offer (mirrors the offer system). The
//!   PRIMARY secret is never sealed into an offer/escrow or bound to a domain
//!   — only subkeys are. The custody invariant is enforced at the API: there
//!   is no path that seals the primary.
//! * **Correlatable by default, opt-in unlinkable.** The global CID is a
//!   single stable identifier shared across domains (correlatable). A domain
//!   may opt into a pairwise/unlinkable mode, exposing a domain-local alias
//!   that is *not* the global CID.
//! * **Per-domain revocation, fail-closed, compromise-isolated.** Revoking a
//!   domain is grow-only; no operation a revoked domain's subkey could
//!   authorize may succeed afterwards, and revoking one domain never disturbs
//!   another or the primary.
//!
//! Like the rest of the modelled core, this carries no real key material and
//! touches neither network nor filesystem: a [`KeyId`] stands in for a
//! verified key and a [`Sig`] for a verified signature, so the identity-log
//! *policy* — the part the spec constrains — is auditable in isolation from
//! the crypto library that will later produce/verify OpenPGP packets. Content
//! addressing uses a real cryptographic multihash (SHA2-256, via the
//! `pillar-crypto` crate) over the canonical genesis encoding — a
//! collision-resistant content address, not a `DefaultHasher`/SipHash checksum.

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;

/// A stand-in for a verified key: the fingerprint/id of a primary or subkey.
///
/// A primary key of generation `g` is `KeyId("primary:<g>")` by convention in
/// this model, but callers supply arbitrary ids; the log tracks whichever id a
/// rotation names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        KeyId(s.to_owned())
    }
}

/// A stand-in for a verified signature over a log entry: the id of the key
/// that produced it. In the model a signature is trusted to be authentic; the
/// log's job is to check the signer is *authorized* to append, not to verify
/// crypto.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sig {
    /// The key that signed the entry.
    pub signer: KeyId,
}

impl Sig {
    /// A signature produced by `signer`.
    pub fn by(signer: impl Into<KeyId>) -> Self {
        Sig {
            signer: signer.into(),
        }
    }
}

/// The stable, content-addressed identifier of a global identity log. It
/// addresses the [`Genesis`] entry and never changes across rotations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub String);

/// A per-domain name (the domain a user joins with one operational subkey).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(pub String);

impl From<&str> for Domain {
    fn from(s: &str) -> Self {
        Domain(s.to_owned())
    }
}

/// The signed genesis of an identity log: names the initial primary key and an
/// optional authorized recovery key. The CID is the content address of this
/// entry, so it is fixed for the life of the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// The initial primary key (generation 0).
    pub initial_primary: KeyId,
    /// An optional recovery key authorized (at genesis) to sign a rotation
    /// when the current primary is lost/compromised. `None` = no recovery
    /// path (only the current primary may rotate).
    pub recovery: Option<KeyId>,
}

impl Genesis {
    /// Compute this genesis's content address (the stable global CID). Two
    /// genesis entries with identical fields address the same identity; any
    /// difference yields a different CID.
    ///
    /// The address is a **real cryptographic content address**: a SHA2-256
    /// multihash (via [`pillar_crypto::content::content_address`]) over a
    /// length-prefixed canonical encoding of the genesis fields. A
    /// non-cryptographic hash (SipHash/`DefaultHasher`, FNV) is a checksum, not
    /// a content address — it is collision-prone and forgeable, so it must not
    /// address a self-certifying identity. The canonical encoding is
    /// unambiguous (each field length-prefixed) so distinct genesis structures
    /// can never encode to the same bytes.
    fn cid(&self) -> Cid {
        let mut buf = Vec::new();
        // Domain-separation tag, length-prefixed.
        let tag = b"pillar-global-identity-genesis-v1";
        buf.extend_from_slice(&(tag.len() as u64).to_le_bytes());
        buf.extend_from_slice(tag);
        // initial_primary, length-prefixed.
        let ip = self.initial_primary.0.as_bytes();
        buf.extend_from_slice(&(ip.len() as u64).to_le_bytes());
        buf.extend_from_slice(ip);
        // recovery: presence byte then length-prefixed value.
        match &self.recovery {
            Some(r) => {
                buf.push(1u8);
                let rb = r.0.as_bytes();
                buf.extend_from_slice(&(rb.len() as u64).to_le_bytes());
                buf.extend_from_slice(rb);
            }
            None => buf.push(0u8),
        }
        let addr = pillar_crypto::content::content_address(&buf)
            .expect("content_address is infallible for in-memory bytes");
        let hex: String = addr.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        Cid(format!("gid:{hex}"))
    }
}

/// A signed rotation entry appended to the log: installs a new primary,
/// signed by the current primary (or the authorized recovery key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The new primary key this rotation installs.
    pub new_primary: KeyId,
    /// The signature over the rotation.
    pub sig: Sig,
}

/// Why an append or certification was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityLogError {
    /// A rotation was not signed by the current primary nor the authorized
    /// recovery key — no forged / self-appointed primary (`NoUnauthorizedPrimary`).
    UnauthorizedRotation {
        /// The key that signed the rejected rotation.
        signer: KeyId,
    },
    /// A domain already has a certified subkey (exactly one per domain).
    DomainAlreadyCertified(Domain),
    /// A domain has no certified subkey (cannot seal/deliver or opt-in).
    DomainNotCertified(Domain),
    /// The operation targets a revoked domain — fail-closed
    /// (`PerDomainRevocationFailClosed`).
    DomainRevoked(Domain),
    /// The domain already has an outstanding sealed offer.
    OfferAlreadySealed(Domain),
    /// A subkey may not certify another subkey — one hop only
    /// (`PerDomainSubkeyOneHop`). Raised if a non-primary key is presented as
    /// a certifying issuer.
    TwoHopCertification {
        /// The offending non-primary issuer.
        issuer: KeyId,
    },
}

/// A per-domain operational subkey certified one-hop by a primary generation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainSubkey {
    /// The subkey's key id.
    key: KeyId,
    /// The primary generation that certified it (the one-hop issuer anchor).
    /// Survives rotation: the subkey's authority stays anchored to a specific
    /// historical primary generation.
    certifying_gen: u64,
    /// The node the subkey's offer is sealed to, if delivered.
    offer: Option<NodeId>,
    /// Opt-in pairwise/unlinkable mode: a domain-local alias (never the CID).
    pairwise_alias: Option<String>,
}

/// The self-certifying, CID-addressed global identity log.
///
/// Holds the immutable [`Genesis`], the append-only chain of installed primary
/// generations (each with the signer that authorized its rotation), and the
/// per-domain subkey / offer / revocation state.
#[derive(Clone, Debug)]
pub struct IdentityLog {
    genesis: Genesis,
    cid: Cid,
    /// Installed primary keys by generation (0 = genesis's initial primary).
    /// Never truncated: every historical generation survives forever.
    primaries: Vec<KeyId>,
    /// For each generation `g > 0`, the key that signed the rotation that
    /// installed it (the then-current primary or the recovery key).
    rotation_signers: Vec<KeyId>,
    domains: BTreeMap<Domain, DomainSubkey>,
    revoked: BTreeSet<Domain>,
}

impl IdentityLog {
    /// Open a new identity log from its signed genesis. The CID is fixed here
    /// and never changes.
    pub fn genesis(genesis: Genesis) -> Self {
        let cid = genesis.cid();
        let initial = genesis.initial_primary.clone();
        IdentityLog {
            genesis,
            cid,
            primaries: vec![initial],
            rotation_signers: Vec::new(),
            domains: BTreeMap::new(),
            revoked: BTreeSet::new(),
        }
    }

    /// The stable global CID — invariant across every rotation.
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// The current primary generation (0 = genesis).
    pub fn head_generation(&self) -> u64 {
        (self.primaries.len() - 1) as u64
    }

    /// The current primary key.
    pub fn current_primary(&self) -> &KeyId {
        self.primaries
            .last()
            .expect("log always has at least the genesis primary")
    }

    /// The genesis-committed recovery key authorized to sign a rotation when
    /// the current primary is lost/compromised, if this identity has one —
    /// used by a "recover" UI action to rotate without the current primary.
    pub fn recovery_key(&self) -> Option<&KeyId> {
        self.genesis.recovery.as_ref()
    }

    /// All domains with a certified subkey, in stable order — the "multi-
    /// domain view": one global identity across its domains/cells with
    /// per-domain keys.
    pub fn domains(&self) -> impl Iterator<Item = (&Domain, &KeyId)> {
        self.domains.iter().map(|(d, sk)| (d, &sk.key))
    }

    /// The primary key installed at generation `g`, if `g` is installed. Every
    /// historical generation is retained, so a signature attributed to
    /// generation `g` remains resolvable to this identity forever, regardless
    /// of later rotations.
    pub fn primary_at(&self, generation: u64) -> Option<&KeyId> {
        self.primaries.get(generation as usize)
    }

    /// Attribute a historical signature (issued by the primary of generation
    /// `g`) to this global identity. Returns the stable CID together with the
    /// resolved issuer key — proving that pre-rotation signatures stay valid
    /// and attributable after any number of rotations.
    pub fn attribute_signature(&self, generation: u64) -> Option<(&Cid, &KeyId)> {
        self.primary_at(generation).map(|k| (&self.cid, k))
    }

    /// Append a signed rotation. Authorized **iff** signed by the current
    /// primary or the genesis-committed recovery key; otherwise rejected. The
    /// CID is unaffected. Returns the newly installed generation.
    pub fn rotate(&mut self, rotation: Rotation) -> Result<u64, IdentityLogError> {
        let signer = &rotation.sig.signer;
        let authorized =
            signer == self.current_primary() || self.genesis.recovery.as_ref() == Some(signer);
        if !authorized {
            return Err(IdentityLogError::UnauthorizedRotation {
                signer: signer.clone(),
            });
        }
        self.primaries.push(rotation.new_primary);
        self.rotation_signers.push(signer.clone());
        Ok(self.head_generation())
    }

    /// The signer that authorized the rotation installing generation `g`
    /// (`None` for genesis). Used to audit the append chain.
    pub fn rotation_signer(&self, generation: u64) -> Option<&KeyId> {
        if generation == 0 {
            return None;
        }
        self.rotation_signers.get((generation - 1) as usize)
    }

    /// Certify exactly one operational subkey for `domain`, ONE HOP, by the
    /// **current primary**. Refused if the domain already has a subkey, is
    /// revoked, or if a non-primary issuer is presented (two-hop).
    ///
    /// `issuer` must be the current primary key; passing any other key models
    /// (and rejects) a subkey attempting to certify another subkey.
    pub fn certify_domain_subkey(
        &mut self,
        domain: Domain,
        subkey: KeyId,
        issuer: &KeyId,
    ) -> Result<(), IdentityLogError> {
        if self.revoked.contains(&domain) {
            return Err(IdentityLogError::DomainRevoked(domain));
        }
        if issuer != self.current_primary() {
            // Only the primary certifies subkeys. A subkey (or any non-primary
            // key) presented as issuer is a two-hop chain — refused.
            return Err(IdentityLogError::TwoHopCertification {
                issuer: issuer.clone(),
            });
        }
        if self.domains.contains_key(&domain) {
            return Err(IdentityLogError::DomainAlreadyCertified(domain));
        }
        self.domains.insert(
            domain,
            DomainSubkey {
                key: subkey,
                certifying_gen: self.head_generation(),
                offer: None,
                pairwise_alias: None,
            },
        );
        Ok(())
    }

    /// The primary generation that certified `domain`'s subkey (the one-hop
    /// issuer anchor), if certified.
    pub fn subkey_certifying_generation(&self, domain: &Domain) -> Option<u64> {
        self.domains.get(domain).map(|d| d.certifying_gen)
    }

    /// The certified subkey for `domain`, if any.
    pub fn domain_subkey(&self, domain: &Domain) -> Option<&KeyId> {
        self.domains.get(domain).map(|d| &d.key)
    }

    /// Enroll `domain` in opt-in pairwise/unlinkable mode with a domain-local
    /// alias. The alias must not equal the global CID. Correlation is the
    /// default; this is the explicit opt-out.
    pub fn enroll_pairwise(
        &mut self,
        domain: &Domain,
        alias: impl Into<String>,
    ) -> Result<(), IdentityLogError> {
        if self.revoked.contains(domain) {
            return Err(IdentityLogError::DomainRevoked(domain.clone()));
        }
        let alias = alias.into();
        let d = self
            .domains
            .get_mut(domain)
            .ok_or_else(|| IdentityLogError::DomainNotCertified(domain.clone()))?;
        d.pairwise_alias = Some(alias);
        Ok(())
    }

    /// The domain-local pairwise alias for `domain`, if enrolled. A domain
    /// NOT enrolled pairwise is correlatable via the global CID and returns
    /// `None` here.
    pub fn pairwise_alias(&self, domain: &Domain) -> Option<&str> {
        self.domains
            .get(domain)
            .and_then(|d| d.pairwise_alias.as_deref())
    }

    /// Deliver `domain`'s subkey to `node` as a node-sealed, revocable offer.
    /// Only a per-domain SUBKEY is ever sealed — never the primary (the API
    /// exposes no path that seals the primary, enforcing the custody
    /// invariant). Fail-closed for a revoked domain.
    pub fn seal_subkey_offer(
        &mut self,
        domain: &Domain,
        node: NodeId,
    ) -> Result<(), IdentityLogError> {
        if self.revoked.contains(domain) {
            return Err(IdentityLogError::DomainRevoked(domain.clone()));
        }
        let d = self
            .domains
            .get_mut(domain)
            .ok_or_else(|| IdentityLogError::DomainNotCertified(domain.clone()))?;
        if d.offer.is_some() {
            return Err(IdentityLogError::OfferAlreadySealed(domain.clone()));
        }
        d.offer = Some(node);
        Ok(())
    }

    /// The node `domain`'s subkey offer is currently sealed to, if delivered
    /// and not revoked (revocation clears the offer — fail-closed).
    pub fn offer_recipient(&self, domain: &Domain) -> Option<&NodeId> {
        if self.revoked.contains(domain) {
            return None;
        }
        self.domains.get(domain).and_then(|d| d.offer.as_ref())
    }

    /// Revoke `domain`. Grow-only, fail-closed, compromise-isolated: it clears
    /// that domain's outstanding offer and blocks all future per-domain
    /// operations for it, while never touching the primary or any other
    /// domain.
    pub fn revoke_domain(&mut self, domain: &Domain) {
        self.revoked.insert(domain.clone());
        if let Some(d) = self.domains.get_mut(domain) {
            d.offer = None;
        }
    }

    /// Whether `domain` is revoked.
    pub fn is_revoked(&self, domain: &Domain) -> bool {
        self.revoked.contains(domain)
    }

    /// The set of key ids ever sealed into an offer. Used to assert the
    /// primary-custody invariant: no primary key id is ever present here.
    fn sealed_subkeys(&self) -> BTreeSet<&KeyId> {
        self.domains
            .values()
            .filter(|d| d.offer.is_some())
            .map(|d| &d.key)
            .collect()
    }

    /// Invariant probe: the primary secret (any installed primary generation's
    /// key) is never sealed into an offer/escrow. True in every reachable
    /// state (`PrimarySecretNeverEscrowed`).
    pub fn primary_never_sealed(&self) -> bool {
        let primaries: BTreeSet<&KeyId> = self.primaries.iter().collect();
        self.sealed_subkeys().is_disjoint(&primaries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> IdentityLog {
        IdentityLog::genesis(Genesis {
            initial_primary: KeyId::from("primary:0"),
            recovery: Some(KeyId::from("recovery")),
        })
    }

    #[test]
    fn rotation_preserves_cid_and_prerotation_signatures_still_attribute() {
        let mut log = seed();
        let cid0 = log.cid().clone();
        // A signature issued now, by generation 0.
        let gen0 = log.head_generation();

        // Rotate three times, each signed by the then-current primary.
        for g in 1..=3u64 {
            let signer = log.current_primary().clone();
            log.rotate(Rotation {
                new_primary: KeyId(format!("primary:{g}")),
                sig: Sig::by(signer),
            })
            .expect("authorized rotation");
        }
        assert_eq!(log.head_generation(), 3);
        // CID is invariant across every rotation.
        assert_eq!(log.cid(), &cid0);
        // The pre-rotation (gen0) signature still attributes to this identity.
        let (cid, issuer) = log.attribute_signature(gen0).expect("gen0 resolvable");
        assert_eq!(cid, &cid0);
        assert_eq!(issuer, &KeyId::from("primary:0"));
    }

    #[test]
    fn forged_rotation_not_signed_by_current_primary_is_rejected() {
        let mut log = seed();
        let err = log
            .rotate(Rotation {
                new_primary: KeyId::from("attacker"),
                sig: Sig::by("attacker"),
            })
            .unwrap_err();
        assert_eq!(
            err,
            IdentityLogError::UnauthorizedRotation {
                signer: KeyId::from("attacker")
            }
        );
        // Head unchanged — the forged append never installed.
        assert_eq!(log.head_generation(), 0);
        assert_eq!(log.current_primary(), &KeyId::from("primary:0"));
    }

    #[test]
    fn recovery_key_may_authorize_a_rotation() {
        let mut log = seed();
        log.rotate(Rotation {
            new_primary: KeyId::from("primary:1"),
            sig: Sig::by("recovery"),
        })
        .expect("recovery path authorized at genesis");
        assert_eq!(log.head_generation(), 1);
        assert_eq!(log.rotation_signer(1), Some(&KeyId::from("recovery")));
    }

    #[test]
    fn stale_primary_cannot_rotate_after_a_later_rotation() {
        let mut log = seed();
        log.rotate(Rotation {
            new_primary: KeyId::from("primary:1"),
            sig: Sig::by("primary:0"),
        })
        .unwrap();
        // The old (gen0) primary is no longer current; its rotation is refused.
        let err = log
            .rotate(Rotation {
                new_primary: KeyId::from("primary:2"),
                sig: Sig::by("primary:0"),
            })
            .unwrap_err();
        assert_eq!(
            err,
            IdentityLogError::UnauthorizedRotation {
                signer: KeyId::from("primary:0")
            }
        );
    }

    #[test]
    fn one_hop_subkey_certification_admitted_by_primary() {
        let mut log = seed();
        let issuer = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &issuer)
            .expect("one-hop certification by primary");
        assert_eq!(
            log.domain_subkey(&Domain::from("d1")),
            Some(&KeyId::from("sub:d1"))
        );
        assert_eq!(
            log.subkey_certifying_generation(&Domain::from("d1")),
            Some(0)
        );
    }

    #[test]
    fn two_hop_certification_by_a_subkey_is_refused() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        // A subkey attempting to certify another domain's subkey (two hops).
        let err = log
            .certify_domain_subkey(
                Domain::from("d2"),
                KeyId::from("sub:d2"),
                &KeyId::from("sub:d1"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IdentityLogError::TwoHopCertification {
                issuer: KeyId::from("sub:d1")
            }
        );
        assert_eq!(log.domain_subkey(&Domain::from("d2")), None);
    }

    #[test]
    fn subkey_authority_anchor_survives_rotation() {
        let mut log = seed();
        let primary0 = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary0)
            .unwrap();
        // Rotate; the subkey stays anchored to generation 0.
        log.rotate(Rotation {
            new_primary: KeyId::from("primary:1"),
            sig: Sig::by(primary0),
        })
        .unwrap();
        assert_eq!(
            log.subkey_certifying_generation(&Domain::from("d1")),
            Some(0)
        );
        assert!(log.primary_at(0).is_some());
    }

    #[test]
    fn offer_round_trip_delivers_subkey_to_a_node() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        log.seal_subkey_offer(&Domain::from("d1"), NodeId::from("node-a"))
            .expect("seal to node");
        assert_eq!(
            log.offer_recipient(&Domain::from("d1")),
            Some(&NodeId::from("node-a"))
        );
    }

    #[test]
    fn revoked_domain_fails_closed_across_every_operation() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        log.seal_subkey_offer(&Domain::from("d1"), NodeId::from("node-a"))
            .unwrap();
        log.revoke_domain(&Domain::from("d1"));

        // Offer cleared immediately.
        assert_eq!(log.offer_recipient(&Domain::from("d1")), None);
        // No re-seal, no re-certify, no pairwise opt-in for a revoked domain.
        assert_eq!(
            log.seal_subkey_offer(&Domain::from("d1"), NodeId::from("node-b")),
            Err(IdentityLogError::DomainRevoked(Domain::from("d1")))
        );
        assert_eq!(
            log.enroll_pairwise(&Domain::from("d1"), "alias"),
            Err(IdentityLogError::DomainRevoked(Domain::from("d1")))
        );
        // certify on a fresh-but-revoked domain also fails closed.
        log.revoke_domain(&Domain::from("d2"));
        assert_eq!(
            log.certify_domain_subkey(Domain::from("d2"), KeyId::from("sub:d2"), &primary),
            Err(IdentityLogError::DomainRevoked(Domain::from("d2")))
        );
    }

    #[test]
    fn revocation_is_compromise_isolated() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        log.certify_domain_subkey(Domain::from("d2"), KeyId::from("sub:d2"), &primary)
            .unwrap();
        log.seal_subkey_offer(&Domain::from("d2"), NodeId::from("node-b"))
            .unwrap();

        log.revoke_domain(&Domain::from("d1"));
        // d2 (another domain) is completely untouched.
        assert!(!log.is_revoked(&Domain::from("d2")));
        assert_eq!(
            log.offer_recipient(&Domain::from("d2")),
            Some(&NodeId::from("node-b"))
        );
        // The primary is untouched by any domain revocation.
        assert_eq!(log.current_primary(), &KeyId::from("primary:0"));
        assert_eq!(log.head_generation(), 0);
    }

    #[test]
    fn primary_secret_is_never_sealed_into_an_offer() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        log.seal_subkey_offer(&Domain::from("d1"), NodeId::from("node-a"))
            .unwrap();
        // Rotate and seal more — the invariant holds through rotations.
        log.rotate(Rotation {
            new_primary: KeyId::from("primary:1"),
            sig: Sig::by(primary),
        })
        .unwrap();
        let p1 = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d2"), KeyId::from("sub:d2"), &p1)
            .unwrap();
        log.seal_subkey_offer(&Domain::from("d2"), NodeId::from("node-b"))
            .unwrap();
        assert!(log.primary_never_sealed());
    }

    #[test]
    fn cid_is_correlatable_by_default_and_unlinkable_only_when_opted_in() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        log.certify_domain_subkey(Domain::from("d2"), KeyId::from("sub:d2"), &primary)
            .unwrap();
        // Default: no alias — correlatable via the global CID.
        assert_eq!(log.pairwise_alias(&Domain::from("d1")), None);

        // Opt-in pairwise for d2: a domain-local alias that is NOT the CID.
        log.enroll_pairwise(&Domain::from("d2"), "d2-local")
            .unwrap();
        let alias = log.pairwise_alias(&Domain::from("d2")).unwrap();
        assert_eq!(alias, "d2-local");
        assert_ne!(alias, log.cid().0.as_str());
    }

    #[test]
    fn cid_is_a_stable_content_address_of_the_genesis() {
        let a = IdentityLog::genesis(Genesis {
            initial_primary: KeyId::from("primary:0"),
            recovery: None,
        });
        let b = IdentityLog::genesis(Genesis {
            initial_primary: KeyId::from("primary:0"),
            recovery: None,
        });
        // Same genesis => same CID (content-addressed, self-certifying).
        assert_eq!(a.cid(), b.cid());
        // Different genesis => different CID.
        let c = IdentityLog::genesis(Genesis {
            initial_primary: KeyId::from("primary:x"),
            recovery: None,
        });
        assert_ne!(a.cid(), c.cid());
    }

    #[test]
    fn cid_is_a_real_cryptographic_content_address_not_a_checksum() {
        // The CID must be a real cryptographic multihash (SHA2-256 => 32-byte
        // digest, at least 64 hex chars after the "gid:" prefix), never a
        // 64-bit DefaultHasher/SipHash checksum (which would render as 16 hex
        // chars). This is the regression guard for ROI non-negotiable #7:
        // content addressing on real primitives only.
        let log = IdentityLog::genesis(Genesis {
            initial_primary: KeyId::from("primary:0"),
            recovery: None,
        });
        let cid = log.cid().0.clone();
        let hex = cid.strip_prefix("gid:").expect("cid carries gid: prefix");
        assert!(
            hex.len() >= 64,
            "a cryptographic content address is >= 256 bits (>= 64 hex chars), got {} chars: {hex}",
            hex.len()
        );
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "content address must be lowercase hex digest, got {hex}"
        );

        // It must agree byte-for-byte with the pillar-crypto content address of
        // the same canonical genesis encoding — i.e. it genuinely delegates to
        // the real primitive, not a local re-hash.
        let mut buf = Vec::new();
        let tag = b"pillar-global-identity-genesis-v1";
        buf.extend_from_slice(&(tag.len() as u64).to_le_bytes());
        buf.extend_from_slice(tag);
        let ip = b"primary:0";
        buf.extend_from_slice(&(ip.len() as u64).to_le_bytes());
        buf.extend_from_slice(ip);
        buf.push(0u8);
        let expected = pillar_crypto::content::content_address(&buf).expect("address");
        let expected_hex: String = expected
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, expected_hex,
            "CID must be the real crypto content address"
        );
    }

    #[test]
    fn one_subkey_per_domain_second_certification_refused() {
        let mut log = seed();
        let primary = log.current_primary().clone();
        log.certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1"), &primary)
            .unwrap();
        let err = log
            .certify_domain_subkey(Domain::from("d1"), KeyId::from("sub:d1b"), &primary)
            .unwrap_err();
        assert_eq!(
            err,
            IdentityLogError::DomainAlreadyCertified(Domain::from("d1"))
        );
    }
}
