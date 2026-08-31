//! The identity bootstrap primitives: user-primary key generation and
//! node-subkey signing/admission, over [`pillar_identity::Registry`] — the
//! SAME admission policy the rest of the platform trusts, so a node admitted
//! through the web UI or the CLI is admitted identically to one admitted any
//! other way. Moved here from `pillar-web` so both front-ends share one code
//! path.

use pillar_core::NodeId;
use pillar_identity::{NodeSubkey, Registry, Signature, UserPrimary};

/// A bootstrap session over the identity registry: key generation, adding
/// nodes (subkey signing), and QR-assisted signing.
#[derive(Debug, Default)]
pub struct Bootstrap {
    identity: Registry,
    next_fingerprint: u64,
}

impl Bootstrap {
    /// An empty bootstrap session: nothing registered or admitted yet.
    #[must_use]
    pub fn new() -> Self {
        Bootstrap {
            identity: Registry::new(),
            next_fingerprint: 0,
        }
    }

    /// Generate and register a fresh user primary key.
    ///
    /// This crate carries no real OpenPGP key material (see
    /// [`pillar_identity`]'s module docs): the "generated" fingerprint is a
    /// stand-in identity, registered exactly as a real one would be, so the
    /// admission policy below is exercised faithfully.
    pub fn keygen_user(&mut self) -> UserPrimary {
        self.next_fingerprint += 1;
        let primary = UserPrimary(format!("user-primary-{:016x}", self.next_fingerprint));
        self.identity.register(primary.clone());
        primary
    }

    /// Register an EXTERNALLY-generated user primary (e.g. a fingerprint the
    /// operator supplied or a request carried), so a caller that already holds
    /// the key material admits it through the same registry path as
    /// [`Self::keygen_user`].
    pub fn register_user(&mut self, primary: UserPrimary) {
        self.identity.register(primary);
    }

    /// Sign a node subkey under a previously-generated user primary ("adding
    /// nodes" / "signing user keys" in the ROI) and admit it in the same step,
    /// returning the node's resulting identity.
    ///
    /// # Errors
    ///
    /// Propagates [`pillar_identity::AdmissionError`] if the chain does not
    /// resolve to a registered primary.
    pub fn sign_node(
        &mut self,
        issuer: UserPrimary,
        subkey: NodeSubkey,
    ) -> Result<NodeId, pillar_identity::AdmissionError> {
        self.identity
            .issue_subkey(Signature::new(subkey.clone(), issuer));
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
        let mut boot = Bootstrap::new();
        let rogue = UserPrimary::from("never-registered");
        let subkey = NodeSubkey::from("node-2");
        let err = boot.sign_node(rogue.clone(), subkey.clone()).unwrap_err();
        assert_eq!(
            err,
            pillar_identity::AdmissionError::UnauthorizedIssuer { issuer: rogue }
        );
        assert!(!boot.is_admitted(&subkey));
    }
}
