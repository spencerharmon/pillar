//! The Pillar web interface: the SAME binary exposes it behind a `--web`
//! (localhost-only) flag rather than shipping a separate daemon.
//!
//! Two phases, per the ROI:
//!
//! - **Bootstrap** ([`Bootstrap`]): key generation, adding nodes, signing
//!   user keys, and QR-assisted signing — reachable only from localhost,
//!   with no credential required (there is nothing to authenticate against
//!   yet).
//! - **Post-bootstrap**: viewing the WoT/resource materialized views and
//!   editing depth/grants/manifests with a predicted effect
//!   ([`predicted_effect`]) computed by the exact same decider
//!   ([`pillar_rbac::RbacDecider`]) the controllers enforce with — never a
//!   second, divergent code path. An edit is authorized like any other write
//!   and lands as one signed event; this crate does not seal manifests or
//!   append events itself (that is [`pillar_cli::Platform::apply`]'s job),
//!   it only supplies the auth gate and the predicted-effect preview the web
//!   layer sits in front of that call.
//!
//! [`AuthMode`] is the auth gate: localhost-only during bootstrap, localhost
//! **plus** a second factor (passkey/WebAuthn assertion or a
//! user-configured code) once bootstrap has completed.
//!
//! This crate deliberately does not hand-roll HTTP parsing or bind a socket
//! by default: [`bind_localhost`] is the one place a real listener is
//! opened, kept separate from every other function here so the auth
//! gate, bootstrap flow, and predicted-effect preview are all exercised by
//! plain unit tests with no socket I/O.

#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener};

use pillar_core::NodeId;
use pillar_identity::{NodeSubkey, Registry, Signature, UserPrimary};
use pillar_rbac::{Decision, ExplicitGrant, PolicyEvent, RbacDecider, Request};
use pillar_wot_authority::WotAuthority;

/// The web interface's auth gate.
///
/// Bootstrap is reachable from localhost alone (there is no registered
/// identity yet to authenticate against); once bootstrap has produced a
/// second factor, every later request must additionally present it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMode {
    /// No credential configured yet: localhost is sufficient. This is the
    /// bootstrap surface — keygen, node admission, user-key signing.
    LocalhostBootstrap,
    /// Post-bootstrap: localhost AND a second factor (a WebAuthn/passkey
    /// assertion, or a user-configured 2FA code) are both required.
    SecondFactor {
        /// The expected second-factor assertion/code for this install.
        expected: String,
    },
}

/// Why [`AuthMode::authorize`] refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The request did not originate from the loopback interface.
    NotLocalhost,
    /// A second factor was required but missing or did not match.
    SecondFactorRequired,
}

impl AuthMode {
    /// Authorize one request, given the peer's socket address and an
    /// optional second-factor token it presented.
    ///
    /// Localhost is required unconditionally, in every mode: the bootstrap
    /// surface never becomes reachable from the network merely because a
    /// second factor was later configured for it.
    ///
    /// # Errors
    ///
    /// [`AuthError::NotLocalhost`] if the peer is not loopback;
    /// [`AuthError::SecondFactorRequired`] in [`AuthMode::SecondFactor`] mode
    /// when `second_factor` is absent or does not match.
    pub fn authorize(&self, peer: &SocketAddr, second_factor: Option<&str>) -> Result<(), AuthError> {
        if !peer.ip().is_loopback() {
            return Err(AuthError::NotLocalhost);
        }
        match self {
            AuthMode::LocalhostBootstrap => Ok(()),
            AuthMode::SecondFactor { expected } => match second_factor {
                Some(token) if token == expected => Ok(()),
                _ => Err(AuthError::SecondFactorRequired),
            },
        }
    }
}

/// The bootstrap flow: key generation, adding nodes (subkey signing), and
/// QR-assisted signing, all over [`pillar_identity::Registry`] — the same
/// admission policy the rest of the platform trusts, so a node admitted
/// through the web UI is admitted identically to one admitted any other way.
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

    /// Sign a node subkey under a previously-generated user primary ("adding
    /// nodes" / "signing user keys" in the ROI) and admit it in the same
    /// step, returning the node's resulting identity.
    ///
    /// # Errors
    ///
    /// Propagates [`pillar_identity::AdmissionError`] if the chain does not
    /// resolve to a registered primary (e.g. the caller never called
    /// [`keygen_user`](Self::keygen_user) for `issuer`, or it was never
    /// registered).
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
    /// QR-scan flow (a mobile device scanning a bootstrap QR code to submit
    /// its subkey) while sharing the one admission code path — a QR-signed
    /// node is never admitted on different terms than a manually-entered one.
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

/// Compute the predicted effect of a capability request against the current
/// WoT authority/policy/grant state.
///
/// Deliberately a thin wrapper over [`RbacDecider::predict`] — which itself
/// is a direct call to the same [`RbacDecider::decide`] a controller
/// enforces with — so a web-rendered "predicted effect" preview can never
/// diverge from what actually happens when the edit is applied.
#[must_use]
pub fn predicted_effect(
    authority: &WotAuthority,
    policies: &[PolicyEvent],
    grants: &[ExplicitGrant],
    request: &Request,
) -> Decision {
    RbacDecider::new(authority, policies, grants).predict(request)
}

/// Bind a localhost-only TCP listener for the web interface on `port`.
///
/// Binds explicitly to the loopback address (`127.0.0.1`), never
/// `0.0.0.0`/`::`, so the listener itself is unreachable off-host regardless
/// of firewalling — the same "bootstrap surface never leaves localhost"
/// invariant [`AuthMode`] enforces per-request is also true at the socket
/// layer. Kept as the single function in this crate that touches the
/// network so every other behavior here is unit-testable without a socket.
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the port cannot be bound (e.g. already
/// in use).
pub fn bind_localhost(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_rbac::{Capability, Request};
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn remote(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), port)
    }

    #[test]
    fn bootstrap_mode_admits_localhost_with_no_credential() {
        let mode = AuthMode::LocalhostBootstrap;
        assert_eq!(mode.authorize(&loopback(8080), None), Ok(()));
    }

    #[test]
    fn bootstrap_mode_refuses_non_localhost_regardless_of_credential() {
        let mode = AuthMode::LocalhostBootstrap;
        assert_eq!(
            mode.authorize(&remote(8080), Some("anything")),
            Err(AuthError::NotLocalhost)
        );
    }

    #[test]
    fn second_factor_mode_requires_matching_token_from_localhost() {
        let mode = AuthMode::SecondFactor {
            expected: "correct-horse-battery-staple".to_owned(),
        };
        assert_eq!(
            mode.authorize(&loopback(8080), Some("correct-horse-battery-staple")),
            Ok(())
        );
        assert_eq!(
            mode.authorize(&loopback(8080), Some("wrong")),
            Err(AuthError::SecondFactorRequired)
        );
        assert_eq!(
            mode.authorize(&loopback(8080), None),
            Err(AuthError::SecondFactorRequired)
        );
    }

    #[test]
    fn second_factor_mode_still_refuses_non_localhost_even_with_correct_token() {
        let mode = AuthMode::SecondFactor {
            expected: "secret".to_owned(),
        };
        assert_eq!(
            mode.authorize(&remote(8080), Some("secret")),
            Err(AuthError::NotLocalhost)
        );
    }

    #[test]
    fn bootstrap_keygen_registers_a_fresh_distinct_primary_each_call() {
        let mut boot = Bootstrap::new();
        let a = boot.keygen_user();
        let b = boot.keygen_user();
        assert_ne!(a, b);
        assert!(boot.is_registered(&a));
        assert!(boot.is_registered(&b));
    }

    #[test]
    fn bootstrap_sign_node_admits_a_subkey_under_a_generated_primary() {
        let mut boot = Bootstrap::new();
        let primary = boot.keygen_user();
        let subkey = NodeSubkey::from("node-1");
        let node = boot.sign_node(primary, subkey.clone()).expect("admitted");
        assert!(boot.is_admitted(&subkey));
        assert_eq!(node, subkey.node_id());
    }

    #[test]
    fn bootstrap_sign_node_via_qr_shares_the_same_admission_outcome_as_sign_node() {
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
    fn bootstrap_sign_node_refuses_an_unregistered_issuer() {
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

    #[test]
    fn predicted_effect_matches_the_controller_decider_directly() {
        let root = NodeId::from("root");
        let authority = WotAuthority::new(root.clone(), 4);
        let policies = pillar_rbac::default_resource_class_policies(&Capability("deploy".into()));
        let grants: Vec<ExplicitGrant> = Vec::new();
        let request = Request::new(root.clone(), Capability("deploy".into()));

        let predicted = predicted_effect(&authority, &policies, &grants, &request);
        let decided = RbacDecider::new(&authority, &policies, &grants).decide(&request);
        assert_eq!(predicted, decided);
    }

    #[test]
    fn bind_localhost_succeeds_on_an_ephemeral_port_and_reports_loopback_address() {
        let listener = bind_localhost(0).expect("bind an ephemeral localhost port");
        let addr = listener.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback());
    }
}
