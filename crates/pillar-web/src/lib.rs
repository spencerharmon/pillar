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

pub mod key_login;
pub mod node_custody;

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{SocketAddr, TcpListener};

use pillar_manifest::{Crd, Value};
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
    /// The request reached a non-loopback bind with no admitted WoT-key
    /// login session — see [`authorize_nonloopback_signing_action`].
    NotAuthenticated,
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

/// A registered WebAuthn/passkey credential: an opaque, server-visible
/// credential id. This crate carries no real WebAuthn/CBOR/COSE stack (see
/// the module docs on why: same reason [`pillar_identity::Signature`] stands
/// in for a verified OpenPGP certification rather than shipping real key
/// material) — [`PasskeyAuthenticator`] models the registration+assertion
/// *protocol* precisely: the server never learns the authenticator's secret,
/// only a challenge-bound proof of possession it can verify.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PasskeyCredential(pub String);

impl From<&str> for PasskeyCredential {
    fn from(s: &str) -> Self {
        PasskeyCredential(s.to_owned())
    }
}

fn deterministic_digest(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// A passkey/WebAuthn authenticator relying party: registers credentials and
/// verifies assertions.
///
/// Registration binds a credential id to a secret that never leaves the
/// (simulated) authenticator; assertion presents a response the server
/// verifies by recomputing the challenge-bound proof from the credential's
/// stored public half — an authenticator without the matching secret cannot
/// produce a response that verifies, exactly like a real WebAuthn assertion
/// signature. Distinct challenges (and thus distinct signing-action
/// requests) never share a valid response, so a captured assertion cannot be
/// replayed against a different challenge.
#[derive(Clone, Debug, Default)]
pub struct PasskeyAuthenticator {
    // credential id -> the public verifier derived at registration time.
    credentials: HashMap<PasskeyCredential, u64>,
}

impl PasskeyAuthenticator {
    /// A relying party with no credentials registered yet.
    #[must_use]
    pub fn new() -> Self {
        PasskeyAuthenticator::default()
    }

    /// Register a new passkey credential (`navigator.credentials.create`),
    /// given the authenticator's private secret. Only the resulting
    /// [`PasskeyCredential`] and its derived public verifier are retained;
    /// the secret itself is never stored server-side.
    pub fn register(&mut self, credential: impl Into<PasskeyCredential>, secret: &str) -> PasskeyCredential {
        let credential = credential.into();
        let verifier = deterministic_digest(&["pillar-passkey-register", &credential.0, secret]);
        self.credentials.insert(credential.clone(), verifier);
        credential
    }

    /// Whether a credential has been registered.
    #[must_use]
    pub fn is_registered(&self, credential: &PasskeyCredential) -> bool {
        self.credentials.contains_key(credential)
    }

    /// Verify an assertion (`navigator.credentials.get`) for `credential`
    /// over `challenge`, given the authenticator's `response` and the
    /// (never-transmitted) `secret` it was produced with.
    ///
    /// A caller who does not hold the authenticator's secret cannot compute
    /// a `response` that verifies; an unregistered credential never
    /// verifies regardless of secret.
    #[must_use]
    pub fn assert(&self, credential: &PasskeyCredential, challenge: &str, response: &str) -> bool {
        let Some(&verifier) = self.credentials.get(credential) else {
            return false;
        };
        let expected = deterministic_digest(&["pillar-passkey-assert", challenge, &verifier.to_string()]);
        response == expected.to_string()
    }

    /// Compute the response an authenticator holding `secret` for
    /// `credential` would produce over `challenge` — a test/client-side
    /// helper mirroring what a real authenticator computes internally.
    #[must_use]
    pub fn sign_challenge(credential: &PasskeyCredential, secret: &str, challenge: &str) -> String {
        let verifier = deterministic_digest(&["pillar-passkey-register", &credential.0, secret]);
        deterministic_digest(&["pillar-passkey-assert", challenge, &verifier.to_string()]).to_string()
    }
}

/// A pluggable external second-factor provider — the plugin surface this
/// crate's open-standard passkey/WebAuthn core rides. A user's manifest
/// declares which provider gates their signing actions (see
/// [`declared_second_factor_provider`]); anything implementing this trait —
/// a TOTP app, a push-approval service, a hardware-key bridge — can be
/// registered under that name and honored identically to the built-in
/// [`PasskeyAuthenticator`].
pub trait SecondFactorProvider {
    /// The manifest-declared provider name this instance answers to.
    fn name(&self) -> &str;
    /// Verify a presented second-factor token/response for `user`.
    fn verify(&self, user: &str, presented: &str) -> bool;
}

/// A registry of pluggable external [`SecondFactorProvider`]s, keyed by the
/// name a user's manifest declares in `secondFactorProvider`.
#[derive(Default)]
pub struct SecondFactorProviders {
    providers: HashMap<String, Box<dyn SecondFactorProvider>>,
}

impl SecondFactorProviders {
    /// A registry with no providers registered yet.
    #[must_use]
    pub fn new() -> Self {
        SecondFactorProviders::default()
    }

    /// Register an external provider under its own declared name.
    pub fn register(&mut self, provider: Box<dyn SecondFactorProvider>) {
        self.providers.insert(provider.name().to_owned(), provider);
    }

    /// Verify `presented` for `user` against the named provider. `false` if
    /// no provider is registered under `name`.
    #[must_use]
    pub fn verify(&self, name: &str, user: &str, presented: &str) -> bool {
        self.providers
            .get(name)
            .is_some_and(|provider| provider.verify(user, presented))
    }
}

/// The manifest field name a user declares their external 2FA provider
/// under: `spec.secondFactorProvider`.
pub const SECOND_FACTOR_PROVIDER_FIELD: &str = "secondFactorProvider";

/// Read the manifest-declared external second-factor provider name from a
/// user's manifest (`spec.secondFactorProvider`) — the plugin-surface toggle
/// [`SecondFactorProviders::verify`] looks the provider up by.
#[must_use]
pub fn declared_second_factor_provider(manifest: &Crd) -> Option<&str> {
    match manifest.spec.get(SECOND_FACTOR_PROVIDER_FIELD) {
        Some(Value::String(name)) => Some(name.as_str()),
        _ => None,
    }
}

/// Honor a user's manifest-declared external second-factor provider: looks
/// up the provider `manifest` names in [`SECOND_FACTOR_PROVIDER_FIELD`] and
/// verifies `presented` against it. `false` if the manifest declares no
/// provider, or names one that is not registered.
#[must_use]
pub fn second_factor_honored(providers: &SecondFactorProviders, manifest: &Crd, user: &str, presented: &str) -> bool {
    match declared_second_factor_provider(manifest) {
        Some(name) => providers.verify(name, user, presented),
        None => false,
    }
}

/// Which second factor gates a signing action: the built-in
/// passkey/WebAuthn core, or a manifest-declared external
/// [`SecondFactorProvider`].
pub enum SigningGate<'a> {
    /// Gate by a WebAuthn/passkey assertion against a registered credential.
    Passkey {
        /// The relying party holding registered credentials.
        authenticator: &'a PasskeyAuthenticator,
        /// The credential the caller is asserting.
        credential: &'a PasskeyCredential,
    },
    /// Gate by the external provider the signing user's manifest declares.
    ExternalProvider {
        /// The registry of pluggable external providers.
        providers: &'a SecondFactorProviders,
        /// The signing user's manifest (names the provider to honor).
        manifest: &'a Crd,
        /// The signing user's identity, passed through to the provider.
        user: &'a str,
    },
}

/// Gate a web-UI signing action after bootstrap: localhost is required
/// unconditionally (as in [`AuthMode::authorize`]), and in addition the
/// caller must present a valid second factor — either a passkey/WebAuthn
/// assertion over `challenge`, or (for [`SigningGate::ExternalProvider`]) a
/// token honored by the user's manifest-declared provider. An unauthenticated
/// signing attempt (no valid assertion/token) is always refused.
///
/// # Errors
///
/// [`AuthError::NotLocalhost`] if `peer` is not loopback;
/// [`AuthError::SecondFactorRequired`] if the presented second factor does
/// not verify.
pub fn authorize_signing_action(
    peer: &SocketAddr,
    gate: &SigningGate<'_>,
    challenge: &str,
    presented: &str,
) -> Result<(), AuthError> {
    if !peer.ip().is_loopback() {
        return Err(AuthError::NotLocalhost);
    }
    let verified = match gate {
        SigningGate::Passkey { authenticator, credential } => authenticator.assert(credential, challenge, presented),
        SigningGate::ExternalProvider { providers, manifest, user } => {
            second_factor_honored(providers, manifest, user, presented)
        }
    };
    if verified {
        Ok(())
    } else {
        Err(AuthError::SecondFactorRequired)
    }
}

/// The identity bootstrap primitives (user-primary keygen, node-subkey
/// signing/admission) were factored out into the shared `pillar-bootstrap`
/// crate so the CLI and the web portal share one code path. Re-exported here
/// so existing `pillar_web::Bootstrap` paths keep resolving unchanged.
pub use pillar_bootstrap::Bootstrap;

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

/// Bind a TCP listener for the web interface on a caller-chosen — including
/// **non-loopback** (e.g. `0.0.0.0`) — address, so a k8s Service can reach
/// it (flux's `pillar-web-ingress-tls` gate on this task).
///
/// Unlike [`bind_localhost`], this makes NO reachability claim by itself:
/// every accepted connection MUST be gated through
/// [`authorize_nonloopback_signing_action`] before a signing action is
/// honored — binding non-loopback never implies the bootstrap exemption.
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the address/port cannot be bound.
pub fn bind_web(addr: std::net::IpAddr, port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((addr, port))
}

/// Gate a signing action reaching the web UI when the listening socket may
/// be non-loopback (see [`bind_web`]).
///
/// A **loopback** peer keeps the existing bootstrap exemption unchanged
/// (same invariant [`AuthMode::authorize`] enforces): `Ok(())` regardless of
/// `session`.
///
/// A **non-loopback** peer never gets that exemption — reachability off
/// localhost REQUIRES an already-admitted WoT-key login `session`
/// ([`key_login::KeyLoginVerifier::admit`]), the ROI's default gate for the
/// exposed surface. Passkey/WebAuthn remains available as an OPTIONAL
/// signer feeding the very same [`key_login`] decider
/// ([`key_login::is_passkey_attested`]) rather than a parallel gate — so a
/// passkey-attested login admits through here identically to a
/// software-unlocked one, and an unauthenticated request (`session: None`)
/// is always refused.
///
/// # Errors
///
/// [`AuthError::NotAuthenticated`] if `peer` is not loopback and no
/// `session` is presented.
pub fn authorize_nonloopback_signing_action(
    peer: &SocketAddr,
    session: Option<&key_login::LoginSession>,
) -> Result<(), AuthError> {
    if peer.ip().is_loopback() {
        return Ok(());
    }
    match session {
        Some(_) => Ok(()),
        None => Err(AuthError::NotAuthenticated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::NodeId;
    use pillar_manifest::Metadata;
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

    #[test]
    fn bind_web_binds_a_non_loopback_address_on_an_ephemeral_port() {
        let listener =
            bind_web(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind an ephemeral non-loopback port");
        let addr = listener.local_addr().expect("local_addr");
        assert!(!addr.ip().is_loopback());
    }

    #[test]
    fn nonloopback_signing_action_with_no_session_is_refused() {
        assert_eq!(
            authorize_nonloopback_signing_action(&remote(8080), None),
            Err(AuthError::NotAuthenticated)
        );
    }

    #[test]
    fn loopback_signing_action_keeps_the_bootstrap_exemption_even_without_a_session() {
        assert_eq!(authorize_nonloopback_signing_action(&loopback(8080), None), Ok(()));
    }

    #[test]
    fn nonloopback_signing_action_with_an_admitted_wot_key_session_is_allowed() {
        use key_login::{EncryptedAuthSubkey, KeyLoginVerifier, NonceIssuer, RegisteredAuthKey};
        use pillar_identity::NodeSubkey;
        use pillar_wot_authority::{FencedActor, WotAuthority};

        const PASSWORD: &str = "correct horse battery staple";
        const SECRET: &str = "plaintext-auth-subkey-secret";

        let subkey = NodeSubkey::from("auth-subkey-nonloopback");
        let encrypted = EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);

        let mut verifier = KeyLoginVerifier::new();
        verifier.register_auth_key(RegisteredAuthKey::register(&encrypted, PASSWORD, SECRET));

        let mut issuer = NonceIssuer::new("https://pillar.example.com");
        let nonce = issuer.issue(10);
        verifier.track_issued(nonce.clone());

        let unlocked = key_login::unlock_auth_subkey(&encrypted, PASSWORD, SECRET).expect("unlock");
        let signature = unlocked.sign_nonce(&nonce);

        let owner = NodeId::from("owner");
        let mut authority = WotAuthority::new(owner.clone(), 4);
        authority.issue_edge(owner, subkey.node_id(), 4);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        let session = verifier
            .admit(&nonce, &signature, &subkey, issuer.origin(), 0, &authority, &actor)
            .expect("admitted");

        assert_eq!(
            authorize_nonloopback_signing_action(&remote(8080), Some(&session)),
            Ok(())
        );
    }

    #[test]
    fn passkey_registration_and_assertion_gates_a_signing_action() {
        let mut authenticator = PasskeyAuthenticator::new();
        let credential = authenticator.register(PasskeyCredential::from("cred-1"), "authenticator-secret");
        assert!(authenticator.is_registered(&credential));

        let challenge = "sign-node-42";
        let response = PasskeyAuthenticator::sign_challenge(&credential, "authenticator-secret", challenge);

        let gate = SigningGate::Passkey {
            authenticator: &authenticator,
            credential: &credential,
        };
        assert_eq!(authorize_signing_action(&loopback(8080), &gate, challenge, &response), Ok(()));
    }

    #[test]
    fn unauthenticated_signing_action_is_refused_without_a_valid_passkey_assertion() {
        let mut authenticator = PasskeyAuthenticator::new();
        let credential = authenticator.register(PasskeyCredential::from("cred-2"), "real-secret");
        let challenge = "sign-node-99";

        let gate = SigningGate::Passkey {
            authenticator: &authenticator,
            credential: &credential,
        };

        // No response at all (empty string never matches a real assertion).
        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, challenge, ""),
            Err(AuthError::SecondFactorRequired)
        );
        // A forged response computed without the authenticator's secret.
        let forged = PasskeyAuthenticator::sign_challenge(&credential, "guessed-secret", challenge);
        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, challenge, &forged),
            Err(AuthError::SecondFactorRequired)
        );
        // A genuine response replayed against a different challenge.
        let response = PasskeyAuthenticator::sign_challenge(&credential, "real-secret", challenge);
        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, "a-different-challenge", &response),
            Err(AuthError::SecondFactorRequired)
        );
    }

    #[test]
    fn passkey_signing_action_still_refuses_non_localhost_even_with_a_valid_assertion() {
        let mut authenticator = PasskeyAuthenticator::new();
        let credential = authenticator.register(PasskeyCredential::from("cred-3"), "secret");
        let challenge = "sign-node-1";
        let response = PasskeyAuthenticator::sign_challenge(&credential, "secret", challenge);

        let gate = SigningGate::Passkey {
            authenticator: &authenticator,
            credential: &credential,
        };
        assert_eq!(
            authorize_signing_action(&remote(8080), &gate, challenge, &response),
            Err(AuthError::NotLocalhost)
        );
    }

    struct StubTotpProvider {
        expected_code: String,
    }

    impl SecondFactorProvider for StubTotpProvider {
        fn name(&self) -> &str {
            "stub-totp"
        }

        fn verify(&self, _user: &str, presented: &str) -> bool {
            presented == self.expected_code
        }
    }

    #[test]
    fn manifest_declared_second_factor_provider_is_honored() {
        let manifest = Crd::new("pillar.dev/v1", "User", Metadata::new("alice")).with_spec(
            SECOND_FACTOR_PROVIDER_FIELD,
            Value::String("stub-totp".to_owned()),
        );
        assert_eq!(declared_second_factor_provider(&manifest), Some("stub-totp"));

        let mut providers = SecondFactorProviders::new();
        providers.register(Box::new(StubTotpProvider {
            expected_code: "654321".to_owned(),
        }));

        let gate = SigningGate::ExternalProvider {
            providers: &providers,
            manifest: &manifest,
            user: "alice",
        };

        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, "unused-challenge", "654321"),
            Ok(())
        );
        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, "unused-challenge", "000000"),
            Err(AuthError::SecondFactorRequired)
        );
    }

    #[test]
    fn manifest_with_no_declared_provider_never_honors_a_second_factor() {
        let manifest = Crd::new("pillar.dev/v1", "User", Metadata::new("bob"));
        assert_eq!(declared_second_factor_provider(&manifest), None);

        let mut providers = SecondFactorProviders::new();
        providers.register(Box::new(StubTotpProvider {
            expected_code: "111111".to_owned(),
        }));

        let gate = SigningGate::ExternalProvider {
            providers: &providers,
            manifest: &manifest,
            user: "bob",
        };

        assert_eq!(
            authorize_signing_action(&loopback(8080), &gate, "unused-challenge", "111111"),
            Err(AuthError::SecondFactorRequired)
        );
    }
}
