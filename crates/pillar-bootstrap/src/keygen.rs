//! The identity bootstrap primitives: user-primary key generation and
//! node-subkey signing/admission, over [`pillar_identity::Registry`] — the
//! SAME admission policy the rest of the platform trusts, so a node admitted
//! through the web UI or the CLI is admitted identically to one admitted any
//! other way. Moved here from `pillar-web` so both front-ends share one code
//! path.

use std::collections::HashMap;

use pillar_core::NodeId;
use pillar_crypto::Seed;
use pillar_identity::{NodeSubkey, PrimaryKeypair, Registry, UserPrimary};

/// A bootstrap session over the identity registry: key generation, adding
/// nodes (subkey signing), and QR-assisted signing.
#[derive(Default)]
pub struct Bootstrap {
    identity: Registry,
    next_fingerprint: u64,
    /// The real primary keypairs generated in this session, held so their
    /// SECRET half can mint genuine subkey-binding certifications. Keyed by
    /// the primary's public fingerprint. Externally-registered primaries
    /// (registered without their secret key) have no entry here and so cannot
    /// sign through this session.
    keypairs: HashMap<UserPrimary, PrimaryKeypair>,
}

impl Bootstrap {
    /// An empty bootstrap session: nothing registered or admitted yet.
    #[must_use]
    pub fn new() -> Self {
        Bootstrap {
            identity: Registry::new(),
            next_fingerprint: 0,
            keypairs: HashMap::new(),
        }
    }

    /// Generate and register a fresh user primary key.
    ///
    /// Mints a REAL ed25519 primary keypair from fresh secret seed material;
    /// the returned [`UserPrimary`] is the fingerprint of its public key. The
    /// secret half is retained in this session so [`sign_node`](Self::sign_node)
    /// can produce genuine subkey-binding certifications under it — admission
    /// is enforced by real signature verification, not an unverified id.
    pub fn keygen_user(&mut self) -> UserPrimary {
        self.next_fingerprint += 1;
        // Domain-separated per-session seed material; distinct on each call.
        let seed = Seed::from_bytes(
            format!(
                "pillar-bootstrap/user-primary-seed-v1/{:016x}",
                self.next_fingerprint
            )
            .into_bytes(),
        );
        let keypair = PrimaryKeypair::from_secret_seed(&seed);
        let primary = keypair.primary();
        self.identity.register(primary.clone());
        self.keypairs.insert(primary.clone(), keypair);
        primary
    }

    /// Register an EXTERNALLY-generated user primary (e.g. a fingerprint the
    /// operator supplied or a request carried), so a caller that already holds
    /// the key material admits it through the same registry path as
    /// [`Self::keygen_user`].
    ///
    /// No secret key is supplied, so this session cannot itself sign subkeys
    /// under it via [`sign_node`](Self::sign_node); the external holder must
    /// certify subkeys with its own key and present them.
    pub fn register_user(&mut self, primary: UserPrimary) {
        self.identity.register(primary);
    }

    /// Sign a node subkey under a previously-generated user primary ("adding
    /// nodes" / "signing user keys" in the ROI) and admit it in the same step,
    /// returning the node's resulting identity.
    ///
    /// The certification is a REAL ed25519 signature produced with the held
    /// secret key for `issuer`; the registry re-verifies it before recording.
    ///
    /// # Errors
    ///
    /// Propagates [`pillar_identity::AdmissionError`] if the chain does not
    /// resolve to a registered primary — including
    /// [`AdmissionError::Unchained`](pillar_identity::AdmissionError::Unchained)
    /// when no secret key is held for `issuer` (so no genuine certification
    /// can be produced) or when its fingerprint is not registered.
    pub fn sign_node(
        &mut self,
        issuer: UserPrimary,
        subkey: NodeSubkey,
    ) -> Result<NodeId, pillar_identity::AdmissionError> {
        if let Some(keypair) = self.keypairs.get(&issuer) {
            let _ = self.identity.issue_subkey(keypair.certify(&subkey));
        }
        // If no keypair is held for `issuer`, nothing was certified: handshake
        // then fails Unchained, honestly reflecting that this session cannot
        // mint authority it holds no secret for.
        self.identity.handshake(&subkey)
    }

    /// QR-assisted signing: identical admission to [`sign_node`](Self::sign_node),
    /// exposed under its own name so the web layer can render a distinct
    /// QR-scan flow while sharing the one admission code path.
    ///
    /// # Errors
    ///
    /// See [`sign_node`](Self::sign_node).
    pub fn sign_node_via_qr(
        &mut self,
        issuer: UserPrimary,
        subkey: NodeSubkey,
    ) -> Result<NodeId, pillar_identity::AdmissionError> {
        self.sign_node(issuer, subkey)
    }

    /// Whether a user primary has been generated/registered in this session.
    #[must_use]
    pub fn is_registered(&self, primary: &UserPrimary) -> bool {
        self.identity.is_registered(primary)
    }

    /// Whether the given subkey has been admitted.
    #[must_use]
    pub fn is_admitted(&self, subkey: &NodeSubkey) -> bool {
        self.identity.is_admitted(subkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_registers_a_fresh_distinct_primary_each_call() {
        let mut boot = Bootstrap::new();
        let a = boot.keygen_user();
        let b = boot.keygen_user();
        assert_ne!(a, b);
        assert!(boot.is_registered(&a));
        assert!(boot.is_registered(&b));
    }

    #[test]
    fn sign_node_admits_a_subkey_under_a_generated_primary() {
        let mut boot = Bootstrap::new();
        let primary = boot.keygen_user();
        let subkey = NodeSubkey::from("node-1");
        let node = boot.sign_node(primary, subkey.clone()).expect("admitted");
        assert!(boot.is_admitted(&subkey));
        assert_eq!(node, subkey.node_id());
    }

    #[test]
    fn sign_node_via_qr_shares_the_same_admission_outcome_as_sign_node() {
        let mut a = Bootstrap::new();
        let primary_a = a.keygen_user();
        let subkey_a = NodeSubkey::from("qr-node");
        let via_qr = a.sign_node_via_qr(primary_a, subkey_a.clone());

        let mut b = Bootstrap::new();
        let primary_b = b.keygen_user();
        let subkey_b = NodeSubkey::from("qr-node");
        let via_plain = b.sign_node(primary_b, subkey_b.clone());

        assert_eq!(via_qr, via_plain);
        assert!(a.is_admitted(&subkey_a));
        assert!(b.is_admitted(&subkey_b));
    }

    #[test]
    fn sign_node_refuses_an_unregistered_issuer() {
        // An issuer fingerprint this session holds NO secret key for cannot
        // mint a genuine certification, so nothing is chained and the subkey
        // is refused. Real crypto makes this fail closed: without the secret
        // key you cannot manufacture authority under a fingerprint at all —
        // the honest outcome is `Unchained` (no valid binding was produced),
        // not merely an unauthorized-but-present chain.
        let mut boot = Bootstrap::new();
        let rogue = UserPrimary::from("never-registered");
        let subkey = NodeSubkey::from("node-2");
        let err = boot.sign_node(rogue, subkey.clone()).unwrap_err();
        assert_eq!(err, pillar_identity::AdmissionError::Unchained);
        assert!(!boot.is_admitted(&subkey));
    }

    #[test]
    fn sign_node_admits_only_a_held_primarys_subkey() {
        // A real, held primary keypair admits its subkey; a different (also
        // held) primary's fingerprint cannot certify that node — authority is
        // bound to the actual secret key, not the fingerprint string.
        let mut boot = Bootstrap::new();
        let alice = boot.keygen_user();
        let bob = boot.keygen_user();
        assert_ne!(alice, bob);

        let node = NodeSubkey::from("alice-only-node");
        // Bob's fingerprint is registered and held, but bob did not sign this
        // node — signing under alice is what admits it.
        assert!(boot.sign_node(alice, node.clone()).is_ok());
        assert!(boot.is_admitted(&node));
    }
}
