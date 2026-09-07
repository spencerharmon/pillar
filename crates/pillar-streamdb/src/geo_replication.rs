//! Cross-cell geo-replication — an OPTIONAL live-HA path built entirely from
//! existing pillar primitives (cells trust + IPFS content-addressing + cell
//! sealing), with NO bespoke backup/restore feature.
//!
//! Per the ROI's explicit design note, "backup" is a filesystem-layer concern,
//! not a pillar feature. This module instead lets a cell obtain LIVE, offsite,
//! geo-replicated high availability WITHOUT running its own second node: a cell
//! (the *owner*) establishes a TRUST relationship with another cell (the
//! *remote*) and AUTHORIZES that remote to PIN the owner's still-encrypted
//! database segments in the shared IPFS/libp2p content store
//! ([`crate::store::ContentStore`]). The remote becomes a live geo-replicated
//! HA datastore for the owner: it can hold and SERVE the owner's content by CID
//! (content-addressing already guarantees byte-integrity on serve — see
//! [`ContentStore::get`]), but because the segments are cell-encrypted
//! ([`Visibility::Cell`], sealed under the owner cell's group key which the
//! remote never holds) the remote CANNOT read the plaintext.
//!
//! Nothing here re-implements IPFS, encryption, or trust:
//!
//! * **Content-addressing / pin / serve** is the existing
//!   [`ContentStore`] surface — a remote replica is just another `ContentStore`
//!   that pins the owner's CIDs and answers backfill fetches for them.
//! * **Encryption at rest** is the existing cell group-key sealing
//!   (`pillar_crypto::cell` / `pillar_crypto::seal`): the owner's DB segments
//!   are ciphertext; the remote holds no key, so replication is zero-knowledge.
//! * **Trust** is an owner-signed authorization ([`ReplicationGrant`]),
//!   verified under the owner cell's signing key exactly like every other
//!   pillar signed record — reusing `pillar_crypto::sign`.
//!
//! The two protocol properties the ROI names:
//!
//! 1. An AUTHORIZED remote can pin+serve the encrypted CIDs of a trusting cell's
//!    database ([`RemoteReplica::authorize_and_pin`] + [`RemoteReplica::serve`]).
//! 2. The remote CANNOT decrypt the plaintext — it holds only ciphertext and no
//!    group key; sealing is the real barrier ([`RemoteReplica::try_decrypt`]).
//! 3. Revoking the trust relationship stops FUTURE pin authorization
//!    ([`ReplicationTrust::revoke`]): a grant is scoped to a trust epoch, and a
//!    revoked/superseded epoch's grant no longer authorizes a new pin. Existing
//!    pins persist (IPFS semantics — you cannot un-give bytes already served),
//!    but no NEW pin is authorized after revocation.

use std::collections::{HashMap, HashSet};

use pillar_crypto::cell::{cell_decrypt, CellGroupKey};
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{Ciphertext, Signature, SigningPublicKey, SigningSecretKey};

use crate::store::{Cid, ContentStore, SignedSegment, StoreError, Visibility};

/// Domain-separation tag for an owner-signed replication grant, so a grant's
/// signature can never be confused with any other pillar signature.
const GRANT_SIG_DOMAIN: &[u8] = b"pillar-streamdb/geo-replication/grant-v1";

fn grant_signing_material(
    owner: &SigningPublicKey,
    remote: &SigningPublicKey,
    epoch: u64,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(GRANT_SIG_DOMAIN);
    m.extend_from_slice(owner.as_bytes());
    m.extend_from_slice(remote.as_bytes());
    m.extend_from_slice(&epoch.to_be_bytes());
    m
}

/// An owner cell's signed authorization for a specific remote cell to pin the
/// owner's (still-encrypted) database segments.
///
/// The grant names the owner cell (`owner`), the authorized remote cell
/// (`remote`), and the trust `epoch` it belongs to. It is signed by the owner
/// cell's signing secret, so a remote — or the shared content store — can prove,
/// from the grant alone, that THIS owner authorized THIS remote for THIS epoch.
/// A forged grant (signed by anyone but the owner) fails [`Self::verify`].
///
/// The grant deliberately does NOT convey any decryption key: it authorizes
/// PINNING of ciphertext, nothing more. This is what keeps replication
/// zero-knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationGrant {
    owner: SigningPublicKey,
    remote: SigningPublicKey,
    epoch: u64,
    signature: Signature,
}

impl ReplicationGrant {
    /// Author a grant authorizing `remote` to pin `owner`'s encrypted database
    /// for trust `epoch`, signed by the owner cell's `secret`.
    ///
    /// # Errors
    ///
    /// Propagates any signing failure from `pillar_crypto::sign`.
    pub fn author(
        owner: SigningPublicKey,
        remote: SigningPublicKey,
        epoch: u64,
        secret: &SigningSecretKey,
    ) -> pillar_crypto::Result<Self> {
        let signature = sign(secret, &grant_signing_material(&owner, &remote, epoch))?;
        Ok(ReplicationGrant {
            owner,
            remote,
            epoch,
            signature,
        })
    }

    /// The owner cell that issued this grant.
    #[must_use]
    pub fn owner(&self) -> &SigningPublicKey {
        &self.owner
    }

    /// The remote cell this grant authorizes.
    #[must_use]
    pub fn remote(&self) -> &SigningPublicKey {
        &self.remote
    }

    /// The trust epoch this grant belongs to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Verify the owner's signature over this grant.
    ///
    /// `Ok(())` only when signed by `owner`'s secret over exactly this
    /// `(owner, remote, epoch)` tuple; a forged grant yields
    /// [`ReplicationError::BadGrant`].
    pub fn verify(&self) -> Result<(), ReplicationError> {
        verify(
            &self.owner,
            &grant_signing_material(&self.owner, &self.remote, self.epoch),
            &self.signature,
        )
        .map_err(|_| ReplicationError::BadGrant)
    }
}

/// The OWNER-side view of a cross-cell trust relationship: which remote cells
/// this cell trusts to geo-replicate its encrypted database, and at what trust
/// epoch.
///
/// Trust is epoch-scoped so it can be REVOKED without a bespoke revocation
/// list: [`Self::grant`] mints a grant at the current epoch for a remote;
/// [`Self::revoke`] advances the epoch, immediately invalidating every grant a
/// remote holds for the OLD epoch (so no NEW pin can be authorized), while
/// leaving already-served/pinned bytes untouched (IPFS semantics). Re-granting
/// after a revoke issues a fresh grant at the new epoch.
#[derive(Debug)]
pub struct ReplicationTrust {
    owner: SigningPublicKey,
    secret: SigningSecretKey,
    /// The current trust epoch for each remote we have ever trusted. A remote
    /// is "currently trusted" iff it is present here AND not revoked.
    epochs: HashMap<Vec<u8>, u64>,
    /// Remotes whose trust has been revoked at their recorded epoch.
    revoked: HashSet<Vec<u8>>,
}

impl ReplicationTrust {
    /// Create the owner-side trust registry for a cell identified by
    /// `owner`/`secret` (its signing keypair).
    #[must_use]
    pub fn new(owner: SigningPublicKey, secret: SigningSecretKey) -> Self {
        ReplicationTrust {
            owner,
            secret,
            epochs: HashMap::new(),
            revoked: HashSet::new(),
        }
    }

    /// This cell's owning signing public key.
    #[must_use]
    pub fn owner(&self) -> &SigningPublicKey {
        &self.owner
    }

    /// Whether `remote` is currently trusted to geo-replicate this cell's DB.
    #[must_use]
    pub fn trusts(&self, remote: &SigningPublicKey) -> bool {
        let key = remote.as_bytes().to_vec();
        self.epochs.contains_key(&key) && !self.revoked.contains(&key)
    }

    /// The current trust epoch for `remote`, if it has ever been trusted.
    #[must_use]
    pub fn epoch_of(&self, remote: &SigningPublicKey) -> Option<u64> {
        self.epochs.get(remote.as_bytes()).copied()
    }

    /// Establish (or refresh) trust in `remote` and mint a signed grant
    /// authorizing it to pin this cell's encrypted database at the CURRENT
    /// epoch.
    ///
    /// If `remote` was previously revoked, this re-grants at a fresh (advanced)
    /// epoch, clearing the revocation — the old grant remains invalid.
    ///
    /// # Errors
    ///
    /// Propagates any signing failure from `pillar_crypto::sign`.
    pub fn grant(
        &mut self,
        remote: &SigningPublicKey,
    ) -> pillar_crypto::Result<ReplicationGrant> {
        let key = remote.as_bytes().to_vec();
        // On a re-grant after revoke, advance past the revoked epoch so the old
        // grant can never be replayed as valid.
        let epoch = if self.revoked.remove(&key) {
            self.epochs.get(&key).copied().unwrap_or(0) + 1
        } else {
            *self.epochs.entry(key.clone()).or_insert(0)
        };
        self.epochs.insert(key, epoch);
        ReplicationGrant::author(self.owner.clone(), remote.clone(), epoch, &self.secret)
    }

    /// Revoke `remote`'s trust: every grant it holds for the current epoch stops
    /// authorizing NEW pins. Existing pins persist (IPFS semantics).
    ///
    /// Idempotent, and a no-op for a remote never trusted. After revocation
    /// [`Self::authorizes`] rejects the remote's outstanding grant.
    pub fn revoke(&mut self, remote: &SigningPublicKey) {
        let key = remote.as_bytes().to_vec();
        if self.epochs.contains_key(&key) {
            self.revoked.insert(key);
        }
    }

    /// Whether `grant` currently authorizes a NEW pin under this cell's trust
    /// state: the grant must verify, name THIS cell as owner, name a remote
    /// that is currently trusted, and carry the remote's CURRENT epoch.
    ///
    /// This is the single decision the shared store consults before honoring a
    /// remote's pin request — so a revoked (or stale-epoch, or forged) grant is
    /// refused authorization for any new pin.
    #[must_use]
    pub fn authorizes(&self, grant: &ReplicationGrant) -> bool {
        if grant.verify().is_err() {
            return false;
        }
        if grant.owner().as_bytes() != self.owner.as_bytes() {
            return false;
        }
        let key = grant.remote().as_bytes().to_vec();
        if self.revoked.contains(&key) {
            return false;
        }
        match self.epochs.get(&key) {
            Some(current) => *current == grant.epoch(),
            None => false,
        }
    }
}

/// The REMOTE-side replica: a plain content store the remote cell uses to hold
/// and serve a trusting owner cell's encrypted database segments.
///
/// It is a thin wrapper over [`ContentStore`] that enforces the replication
/// PROTOCOL: it only pins an owner's segment when the owner's trust registry
/// [authorizes](ReplicationTrust::authorizes) the presented grant, and it can
/// prove — by construction — that it holds no decryption key (holding a
/// [`Ciphertext`] and being unable to produce plaintext without the owner's
/// group key).
#[derive(Debug, Default)]
pub struct RemoteReplica {
    store: ContentStore,
    /// The set of owner CIDs this replica has been authorized to pin.
    replicated: HashSet<Cid>,
}

impl RemoteReplica {
    /// A new, empty remote replica.
    #[must_use]
    pub fn new() -> Self {
        RemoteReplica::default()
    }

    /// Accept an owner's encrypted `segment` for replication and pin it — but
    /// ONLY when `trust` currently authorizes `grant` (owner-signed, current
    /// epoch, not revoked) AND the segment is genuinely cell-encrypted
    /// (`Visibility::Cell`, never public plaintext).
    ///
    /// On success the segment's CID is pinned (durable, served on backfill) and
    /// returned. This is the ROI's property (1): an authorized remote pins+serves
    /// the encrypted CIDs of a trusting cell's database.
    ///
    /// # Errors
    ///
    /// * [`ReplicationError::NotAuthorized`] if `trust` does not authorize
    ///   `grant` (revoked, stale epoch, wrong owner, or forged) — the segment is
    ///   NOT pinned, satisfying the ROI's property (3) that revocation stops
    ///   future pin authorization.
    /// * [`ReplicationError::NotEncrypted`] if the segment is not cell-encrypted
    ///   (a replica must never accept plaintext).
    /// * [`ReplicationError::Store`] for an underlying store fault (e.g. a bad
    ///   segment signature).
    pub fn authorize_and_pin(
        &mut self,
        trust: &ReplicationTrust,
        grant: &ReplicationGrant,
        segment: SignedSegment,
    ) -> Result<Cid, ReplicationError> {
        if !trust.authorizes(grant) {
            return Err(ReplicationError::NotAuthorized);
        }
        if segment.visibility() != Visibility::Cell {
            return Err(ReplicationError::NotEncrypted);
        }
        let cid = self.store.put(segment).map_err(ReplicationError::Store)?;
        self.store.pin(&cid).map_err(ReplicationError::Store)?;
        self.replicated.insert(cid.clone());
        Ok(cid)
    }

    /// Serve a replicated segment by CID from the local pin set — the read path
    /// a peer (the owner cell recovering, or a reader the owner points at) uses
    /// to fetch the owner's content back off this HA replica.
    ///
    /// Content-addressing guarantees byte-integrity: the returned segment's CID
    /// equals the requested one. Serving reveals only ciphertext.
    ///
    /// # Errors
    ///
    /// [`ReplicationError::NotReplicated`] if this replica does not hold `cid`.
    pub fn serve(&self, cid: &Cid) -> Result<SignedSegment, ReplicationError> {
        self.store
            .get_local(cid)
            .ok_or(ReplicationError::NotReplicated)
    }

    /// Whether this replica currently pins `cid`.
    #[must_use]
    pub fn replicates(&self, cid: &Cid) -> bool {
        self.replicated.contains(cid) && self.store.is_pinned(cid)
    }

    /// The number of owner segments this replica currently pins.
    #[must_use]
    pub fn replicated_count(&self) -> usize {
        self.replicated.len()
    }

    /// Attempt to decrypt a replicated segment's ciphertext with a candidate
    /// group key — the honest read path IF one held the owner's key.
    ///
    /// A replica holds NO owner group key, so it can never call this with the
    /// real key; it exists to make the zero-knowledge property testable and
    /// explicit: only a holder of the owner cell's true group key recovers the
    /// plaintext, and any other key fails.
    ///
    /// # Errors
    ///
    /// [`ReplicationError::CannotDecrypt`] if `candidate_key` is not the group
    /// key the segment was sealed under.
    pub fn try_decrypt(
        candidate_key: &CellGroupKey,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, ReplicationError> {
        cell_decrypt(candidate_key, ciphertext, aad).map_err(|_| ReplicationError::CannotDecrypt)
    }
}

/// A fault in a cross-cell geo-replication operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicationError {
    /// The presented grant does not authorize a new pin (revoked, stale epoch,
    /// wrong owner, or forged).
    NotAuthorized,
    /// A segment offered for replication was not cell-encrypted.
    NotEncrypted,
    /// The requested CID is not held by this replica.
    NotReplicated,
    /// A grant's owner signature did not verify.
    BadGrant,
    /// Decryption failed — the candidate key is not the sealing group key.
    CannotDecrypt,
    /// An underlying content-store fault.
    Store(StoreError),
}

impl std::fmt::Display for ReplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationError::NotAuthorized => {
                f.write_str("no current grant authorizes this remote to pin the owner's database")
            }
            ReplicationError::NotEncrypted => {
                f.write_str("a geo-replica accepts only cell-encrypted segments, never plaintext")
            }
            ReplicationError::NotReplicated => {
                f.write_str("the requested content id is not held by this replica")
            }
            ReplicationError::BadGrant => f.write_str("replication grant signature did not verify"),
            ReplicationError::CannotDecrypt => {
                f.write_str("the candidate key cannot decrypt this segment (no owner group key)")
            }
            ReplicationError::Store(e) => write!(f, "content store fault: {e}"),
        }
    }
}

impl std::error::Error for ReplicationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::{cell_encrypt, group_key_from_seed};
    use pillar_crypto::sign::signing_keypair_from_seed;
    use pillar_crypto::Seed;

    fn cell_keys(label: &str) -> (SigningPublicKey, SigningSecretKey) {
        let seed = Seed::from_bytes(format!("pillar-geo-repl-test::cell::{label}").into_bytes());
        signing_keypair_from_seed(&seed).expect("keygen")
    }

    fn group_key(label: &str) -> CellGroupKey {
        let seed = Seed::from_bytes(format!("pillar-geo-repl-test::group::{label}").into_bytes());
        group_key_from_seed(&seed).expect("group key")
    }

    /// Encrypt `plaintext` under `owner_group` and author it as a signed,
    /// cell-visibility segment (as the owner's DB persistence would), returning
    /// the segment plus the aad used so a decryptor can reproduce it.
    fn encrypted_db_segment(
        plaintext: &[u8],
        owner_group: &CellGroupKey,
        signer: &SigningPublicKey,
        signer_sk: &SigningSecretKey,
    ) -> (SignedSegment, Ciphertext, Vec<u8>) {
        let aad = b"pillar-streamdb/geo-repl-test/record".to_vec();
        let ct = cell_encrypt(owner_group, plaintext, &aad).expect("encrypt");
        // The segment's on-store bytes ARE the ciphertext bytes — the store is
        // content-addressing over ciphertext, zero-knowledge to the replica.
        let seg = SignedSegment::author(
            ct.as_bytes().to_vec(),
            signer.clone(),
            signer_sk,
            Visibility::Cell,
        )
        .expect("author segment");
        (seg, ct, aad)
    }

    /// DoD part 1: an AUTHORIZED remote cell can pin+serve the encrypted CIDs of
    /// a trusting cell's database.
    #[test]
    fn authorized_remote_pins_and_serves_encrypted_cids() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");
        let owner_group = group_key("owner-A");

        // Owner trusts remote B and mints a grant.
        let mut trust = ReplicationTrust::new(owner_pk.clone(), owner_sk.clone());
        let grant = trust.grant(&remote_pk).expect("grant");
        assert!(trust.trusts(&remote_pk));

        // Owner's encrypted DB segment.
        let (seg, _ct, _aad) =
            encrypted_db_segment(b"secret database record", &owner_group, &owner_pk, &owner_sk);
        let expected_cid = seg.cid();

        // Remote B pins it under the authorization.
        let mut replica = RemoteReplica::new();
        let cid = replica
            .authorize_and_pin(&trust, &grant, seg.clone())
            .expect("authorized pin");
        assert_eq!(cid, expected_cid);
        assert!(replica.replicates(&cid), "authorized segment is pinned");
        assert_eq!(replica.replicated_count(), 1);

        // Remote B serves the encrypted CID back, byte-identical.
        let served = replica.serve(&cid).expect("serve");
        assert_eq!(served.cid(), expected_cid, "content-addressed integrity");
        assert_eq!(served.bytes(), seg.bytes());
    }

    /// A forged grant (signed by anyone but the owner) never authorizes a pin.
    #[test]
    fn forged_grant_is_not_authorized() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");
        let (_forger_pk, forger_sk) = cell_keys("forger");
        let owner_group = group_key("owner-A");

        let mut trust = ReplicationTrust::new(owner_pk.clone(), owner_sk.clone());
        let _real = trust.grant(&remote_pk).expect("grant");

        // Forge a grant claiming the owner but signed with the forger's key.
        let forged =
            ReplicationGrant::author(owner_pk.clone(), remote_pk.clone(), 0, &forger_sk)
                .expect("author forged");
        assert!(!trust.authorizes(&forged));

        let (seg, _ct, _aad) =
            encrypted_db_segment(b"record", &owner_group, &owner_pk, &owner_sk);
        let mut replica = RemoteReplica::new();
        assert_eq!(
            replica
                .authorize_and_pin(&trust, &forged, seg)
                .unwrap_err(),
            ReplicationError::NotAuthorized
        );
    }

    /// DoD part 2 (property): the remote CANNOT decrypt/read the plaintext — it
    /// holds only ciphertext and no owner group key. Exercises the REAL seal:
    /// only the owner's true group key recovers the plaintext; every other key
    /// (including a plausible attacker-derived one) fails.
    #[test]
    fn remote_cannot_decrypt_plaintext_but_owner_key_can() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let owner_group = group_key("owner-A");

        let plaintext = b"the plaintext the remote must never read";
        let (seg, ct, aad) =
            encrypted_db_segment(plaintext, &owner_group, &owner_pk, &owner_sk);

        // The replica stores/serves only the ciphertext bytes.
        assert_ne!(
            seg.bytes(),
            plaintext.as_slice(),
            "stored bytes must be ciphertext, never plaintext"
        );

        // The remote holds NO owner group key. A wrong/attacker key fails.
        let attacker_key = group_key("attacker-guess");
        assert_eq!(
            RemoteReplica::try_decrypt(&attacker_key, &ct, &aad).unwrap_err(),
            ReplicationError::CannotDecrypt,
            "a non-owner key must never recover the plaintext"
        );
        // A different cell's real group key also fails (no shared key).
        let other_cell_key = group_key("remote-B");
        assert_eq!(
            RemoteReplica::try_decrypt(&other_cell_key, &ct, &aad).unwrap_err(),
            ReplicationError::CannotDecrypt
        );

        // Only the owner's true group key recovers it — proving the ciphertext
        // is real, not a trivially-empty "sealed" blob.
        let recovered =
            RemoteReplica::try_decrypt(&owner_group, &ct, &aad).expect("owner decrypts");
        assert_eq!(recovered, plaintext, "owner key recovers exact plaintext");
    }

    /// A replica refuses a non-encrypted (public/plaintext) segment outright — a
    /// geo-replica must never hold owner plaintext.
    #[test]
    fn replica_refuses_plaintext_segment() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");

        let mut trust = ReplicationTrust::new(owner_pk.clone(), owner_sk.clone());
        let grant = trust.grant(&remote_pk).expect("grant");

        let plain = SignedSegment::author(
            b"PLAINTEXT that must never be replicated".to_vec(),
            owner_pk.clone(),
            &owner_sk,
            Visibility::Public,
        )
        .expect("author");
        let mut replica = RemoteReplica::new();
        assert_eq!(
            replica.authorize_and_pin(&trust, &grant, plain).unwrap_err(),
            ReplicationError::NotEncrypted
        );
        assert_eq!(replica.replicated_count(), 0);
    }

    /// DoD part 3: revoking the trust relationship stops FUTURE pin
    /// authorization. Existing pins persist (IPFS semantics), but no NEW pin is
    /// authorized after revocation — and the previously-issued grant is dead.
    #[test]
    fn revocation_stops_future_pin_authorization_but_keeps_existing() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");
        let owner_group = group_key("owner-A");

        let mut trust = ReplicationTrust::new(owner_pk.clone(), owner_sk.clone());
        let grant = trust.grant(&remote_pk).expect("grant");

        // Before revoke: an authorized pin succeeds and persists.
        let (seg1, _ct, _aad) =
            encrypted_db_segment(b"record one", &owner_group, &owner_pk, &owner_sk);
        let mut replica = RemoteReplica::new();
        let cid1 = replica
            .authorize_and_pin(&trust, &grant, seg1)
            .expect("authorized before revoke");
        assert!(replica.replicates(&cid1));

        // Revoke the trust relationship.
        trust.revoke(&remote_pk);
        assert!(!trust.trusts(&remote_pk));
        // The grant it holds no longer authorizes.
        assert!(!trust.authorizes(&grant));

        // A NEW pin under the SAME (now-stale) grant is refused.
        let (seg2, _ct2, _aad2) =
            encrypted_db_segment(b"record two", &owner_group, &owner_pk, &owner_sk);
        assert_eq!(
            replica
                .authorize_and_pin(&trust, &grant, seg2)
                .unwrap_err(),
            ReplicationError::NotAuthorized,
            "no new pin is authorized after revocation"
        );

        // Existing pin persists (IPFS semantics — bytes already served stay).
        assert!(
            replica.replicates(&cid1),
            "already-pinned segment persists across revocation"
        );
        assert_eq!(replica.replicated_count(), 1);
    }

    /// Re-granting after a revoke issues a FRESH grant at an advanced epoch; the
    /// OLD grant stays dead while the new one authorizes.
    #[test]
    fn regrant_after_revoke_advances_epoch_and_kills_old_grant() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");
        let owner_group = group_key("owner-A");

        let mut trust = ReplicationTrust::new(owner_pk.clone(), owner_sk.clone());
        let old_grant = trust.grant(&remote_pk).expect("grant");
        let old_epoch = old_grant.epoch();

        trust.revoke(&remote_pk);
        let new_grant = trust.grant(&remote_pk).expect("re-grant");
        assert!(new_grant.epoch() > old_epoch, "epoch advances on re-grant");
        assert!(trust.trusts(&remote_pk));

        // Old grant is permanently dead; new grant authorizes.
        assert!(!trust.authorizes(&old_grant));
        assert!(trust.authorizes(&new_grant));

        let (seg, _ct, _aad) =
            encrypted_db_segment(b"post re-grant record", &owner_group, &owner_pk, &owner_sk);
        let mut replica = RemoteReplica::new();
        assert!(
            replica
                .authorize_and_pin(&trust, &old_grant, seg.clone())
                .is_err(),
            "old grant rejected after re-grant"
        );
        replica
            .authorize_and_pin(&trust, &new_grant, seg)
            .expect("new grant authorizes");
    }

    /// A grant naming a DIFFERENT owner never authorizes against this cell's
    /// trust registry.
    #[test]
    fn grant_for_a_different_owner_is_not_authorized() {
        let (owner_pk, owner_sk) = cell_keys("owner-A");
        let (other_owner_pk, other_owner_sk) = cell_keys("owner-Z");
        let (remote_pk, _remote_sk) = cell_keys("remote-B");

        let mut trust = ReplicationTrust::new(owner_pk, owner_sk);
        let _ = trust.grant(&remote_pk).expect("grant");

        // A validly-signed grant, but from a different owner cell.
        let foreign = ReplicationGrant::author(
            other_owner_pk,
            remote_pk,
            0,
            &other_owner_sk,
        )
        .expect("author foreign");
        assert!(foreign.verify().is_ok(), "foreign grant is self-consistent");
        assert!(
            !trust.authorizes(&foreign),
            "a grant for another owner cell must not authorize here"
        );
    }
}
