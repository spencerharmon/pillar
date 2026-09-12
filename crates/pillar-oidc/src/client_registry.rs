//! OAuth client registry, consent records, and consent-gated introspection.
//!
//! # Design
//!
//! An OAuth client is a **managed `pillar-oidc` resource**, rebuilt ONLY by
//! folding signed, journaled [`ClientOp`]s through [`apply_op`]/[`replay`] —
//! exactly the `PortalOp`/`UserOp` pattern the rest of the portal already uses
//! (`pillar_iam::apply_op`). This module holds no I/O and no HTTP types: the
//! host signs each op's serialized payload and appends it to its durable
//! journal, and this crate is the deterministic state machine those ops drive,
//! so live and replayed state can never diverge.
//!
//! Each [`OAuthClient`] carries a redirect-URI **allow-list**, its
//! confidential-vs-public [`ClientType`], and the sets of scopes and
//! [`GrantType`]s it is permitted. Two invariants are enforced at mutation
//! time rather than trusted later:
//!
//! * **A public client can never hold a confidential-only grant.** Registering
//!   (or updating) a [`ClientType::Public`] client with a grant whose
//!   [`GrantType::requires_confidential`] is true (today: the
//!   client-credentials grant) is refused with
//!   [`ClientRegistryError::PublicClientConfidentialGrant`]. This mirrors
//!   RFC 6749 §2.1 / §4.4 — a public client has no way to authenticate, so it
//!   must never be allowed the client-credentials grant.
//! * **A redirect URI presented at authorize-time must be in the allow-list.**
//!   [`authorize_redirect`] refuses any redirect URI the client did not
//!   pre-register with [`ClientRegistryError::UnregisteredRedirectUri`], so an
//!   attacker-supplied `redirect_uri` can never be honored.
//!
//! # Consent and introspection
//!
//! A [`Consent`] record is keyed by `(user, client_id)` and carries the set of
//! scopes the user granted the client. Consents are **listable**
//! ([`list_consents`]) and **revocable** ([`ClientOp::RevokeConsent`]).
//! Revocation is immediate and total: [`introspect`] treats a token as active
//! ONLY when a live (non-revoked) consent exists for its `(user, client_id)`
//! and covers the token's scopes, so revoking a consent **immediately fails
//! introspection for every token ever issued under it**
//! (`RevokedConsentNeverIntrospectsValid`) — with no per-token bookkeeping and
//! no revocation-list TTL.
//!
//! # Capability gating
//!
//! Every client-registry and consent mutation is administered behind the
//! dedicated [`OAUTH_WRITE_CAPABILITY`] (`iam:oauth:write`), decided by the
//! SAME [`pillar_rbac::RbacDecider`] every other Pillar capability check uses
//! (see [`authorize_oauth_write`]) — never a parallel authorization mechanism.

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_rbac::{Capability, Decision, RbacDecider, Request, ResourceClass};
use serde::{Deserialize, Serialize};

/// The capability string gating every administrative write to the OAuth
/// client registry and consent store (register/update/delete a client, and
/// grant/revoke a consent on behalf of the surface). A three-segment
/// `namespace:resource:verb` capability, the same convention
/// `iam:users:write` / `iam:roles:write` already use.
pub const OAUTH_WRITE_CAPABILITY: &str = "iam:oauth:write";

/// The [`Capability`] value for [`OAUTH_WRITE_CAPABILITY`].
#[must_use]
pub fn oauth_write_capability() -> Capability {
    Capability::from(OAUTH_WRITE_CAPABILITY)
}

/// Decide whether `subject` may perform an OAuth client-registry / consent
/// mutation right now. A single call so the CLI, the web console, and any
/// future admin surface can never diverge on who is allowed — exactly
/// [`pillar_iam::authorize_users_write`]'s pattern applied to the OAuth
/// surface.
#[must_use]
pub fn authorize_oauth_write(
    decider: &RbacDecider<'_>,
    subject: NodeId,
    now_secs: u64,
) -> Decision {
    let request = Request::new(subject, oauth_write_capability())
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    decider.decide(&request)
}

/// Confidential vs public client (RFC 6749 §2.1). A confidential client can
/// authenticate itself (it holds a secret / private key); a public client
/// cannot, so it is barred from any [`GrantType::requires_confidential`] grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClientType {
    /// Can authenticate with a secret — eligible for confidential-only grants.
    Confidential,
    /// Cannot authenticate (a browser SPA, a native app) — must use PKCE and
    /// may never hold a confidential-only grant.
    Public,
}

/// An OAuth 2.0 / OIDC grant type this OP understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GrantType {
    /// The authorization-code grant (with PKCE) — the default for both client
    /// types.
    AuthorizationCode,
    /// The refresh-token grant.
    RefreshToken,
    /// The client-credentials grant (RFC 6749 §4.4) — machine-to-machine, no
    /// user. **Confidential-only**: it authenticates purely by the client's
    /// own credentials, which a public client does not have.
    ClientCredentials,
}

impl GrantType {
    /// Whether only a [`ClientType::Confidential`] client may hold this grant.
    #[must_use]
    pub fn requires_confidential(self) -> bool {
        matches!(self, GrantType::ClientCredentials)
    }
}

/// A registered OAuth client — the crate's central resource, rebuilt ONLY by
/// replaying [`ClientOp`]s through [`apply_op`]. Never mutated directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClient {
    /// The stable public client identifier.
    pub client_id: String,
    /// Confidential or public (bounds which grants are legal).
    pub client_type: ClientType,
    /// The redirect-URI allow-list. A `redirect_uri` presented at
    /// authorize-time MUST be a member (exact match) or the request is
    /// refused.
    pub redirect_uris: BTreeSet<String>,
    /// The scopes this client is permitted to request.
    pub allowed_scopes: BTreeSet<String>,
    /// The grant types this client is permitted to use. Enforced never to
    /// contain a [`GrantType::requires_confidential`] grant for a
    /// [`ClientType::Public`] client.
    pub allowed_grants: BTreeSet<GrantType>,
    /// Wall-clock (Unix seconds) of registration.
    pub created_at: u64,
    /// Wall-clock (Unix seconds) of the last mutation.
    pub updated_at: u64,
}

/// A per-`(user, client)` consent record: the set of scopes `user` granted
/// `client`, and whether that consent has been revoked. Keyed in the registry
/// by [`ConsentKey`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    /// The consenting user's handle.
    pub user: String,
    /// The client the consent is for.
    pub client_id: String,
    /// The scopes granted.
    pub scopes: BTreeSet<String>,
    /// Wall-clock (Unix seconds) the consent was first granted.
    pub granted_at: u64,
    /// Wall-clock (Unix seconds) of the last mutation.
    pub updated_at: u64,
    /// `true` once revoked — a revoked consent authorizes NO token
    /// (`RevokedConsentNeverIntrospectsValid`). Retained (not deleted) so the
    /// revocation itself is auditable and replay-deterministic.
    pub revoked: bool,
}

/// The `(user, client_id)` key a [`Consent`] is stored under.
pub type ConsentKey = (String, String);

/// The materialized OAuth state: the client registry and the consent store,
/// both rebuilt ONLY by folding [`ClientOp`]s. Construct with [`replay`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRegistry {
    /// Registered clients by `client_id`.
    pub clients: BTreeMap<String, OAuthClient>,
    /// Consent records by `(user, client_id)`.
    pub consents: BTreeMap<ConsentKey, Consent>,
}

/// An access/refresh token as far as introspection is concerned: the minimal
/// binding the OP records for every token it issues. Introspection needs only
/// the token's subject, the client it was issued to, and its scopes — the
/// consent gate is evaluated purely against those, so no per-token revocation
/// state is required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// Opaque token identifier (jti).
    pub token_id: String,
    /// The resource-owner handle the token acts for.
    pub user: String,
    /// The client the token was issued to.
    pub client_id: String,
    /// The scopes the token carries.
    pub scopes: BTreeSet<String>,
}

/// Why a client-registry mutation or an authorize-time check was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientRegistryError {
    /// A [`ClientType::Public`] client was registered/updated with a
    /// confidential-only grant (e.g. client-credentials).
    PublicClientConfidentialGrant(GrantType),
    /// A redirect URI presented at authorize-time is not in the client's
    /// pre-registered allow-list.
    UnregisteredRedirectUri,
    /// No client is registered under the given `client_id`.
    UnknownClient,
    /// A client-registry write was attempted without `iam:oauth:write`.
    Unauthorized,
    /// A registration named no redirect URI (an authorization-code client
    /// with an empty allow-list can never complete a flow).
    NoRedirectUris,
}

impl std::fmt::Display for ClientRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientRegistryError::PublicClientConfidentialGrant(g) => {
                write!(
                    f,
                    "public client may not hold confidential-only grant {g:?}"
                )
            }
            ClientRegistryError::UnregisteredRedirectUri => {
                write!(
                    f,
                    "redirect_uri is not in the client's registered allow-list"
                )
            }
            ClientRegistryError::UnknownClient => write!(f, "no such client"),
            ClientRegistryError::Unauthorized => {
                write!(f, "iam:oauth:write is required for this mutation")
            }
            ClientRegistryError::NoRedirectUris => {
                write!(f, "a client must register at least one redirect URI")
            }
        }
    }
}

impl std::error::Error for ClientRegistryError {}

/// One durable OAuth mutation. Journaled by the host exactly like a `PortalOp`
/// (signed, content-addressed, appended, replayed on boot) and folded through
/// [`apply_op`]. Every variant carries exactly the material a deterministic
/// replay needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOp {
    /// Register a NEW client. Rejected by [`validate_registration`] (call it
    /// before signing) if the type/grant/redirect invariants do not hold.
    RegisterClient {
        /// The new client's stable public identifier.
        client_id: String,
        /// Confidential or public.
        client_type: ClientType,
        /// The initial redirect-URI allow-list.
        redirect_uris: BTreeSet<String>,
        /// The scopes the client may request.
        allowed_scopes: BTreeSet<String>,
        /// The grants the client may use.
        allowed_grants: BTreeSet<GrantType>,
        /// Wall-clock (Unix seconds) of registration.
        at: u64,
    },
    /// Replace an existing client's redirect-URI allow-list.
    SetRedirectUris {
        /// The client being edited.
        client_id: String,
        /// The replacement allow-list.
        redirect_uris: BTreeSet<String>,
        /// Wall-clock (Unix seconds) of the edit.
        at: u64,
    },
    /// Replace an existing client's allowed-grant set.
    SetGrants {
        /// The client being edited.
        client_id: String,
        /// The replacement grant set.
        allowed_grants: BTreeSet<GrantType>,
        /// Wall-clock (Unix seconds) of the edit.
        at: u64,
    },
    /// Grant (or extend) a user's consent to a client for a scope set.
    GrantConsent {
        /// The consenting user's handle.
        user: String,
        /// The client the consent is for.
        client_id: String,
        /// The scopes granted (unioned into any existing consent).
        scopes: BTreeSet<String>,
        /// Wall-clock (Unix seconds) of the grant.
        at: u64,
    },
    /// Revoke a user's consent to a client. Immediately invalidates every
    /// token issued under it (introspection fails).
    RevokeConsent {
        /// The user whose consent is revoked.
        user: String,
        /// The client the consent was for.
        client_id: String,
        /// Wall-clock (Unix seconds) of the revocation.
        at: u64,
    },
}

/// Validate a would-be registration BEFORE it is signed and journaled, so an
/// invalid client is refused at the source. The SAME invariants
/// [`apply_op`] preserves are checked here up-front (a public client may hold
/// no confidential-only grant; an authorization-code client must name at
/// least one redirect URI).
pub fn validate_registration(
    client_type: ClientType,
    redirect_uris: &BTreeSet<String>,
    allowed_grants: &BTreeSet<GrantType>,
) -> Result<(), ClientRegistryError> {
    if client_type == ClientType::Public {
        for &grant in allowed_grants {
            if grant.requires_confidential() {
                return Err(ClientRegistryError::PublicClientConfidentialGrant(grant));
            }
        }
    }
    // An authorization-code client with no redirect URI can never complete a
    // flow; the pure client-credentials machine-to-machine case (no redirect)
    // is only reachable for a confidential client.
    if allowed_grants.contains(&GrantType::AuthorizationCode) && redirect_uris.is_empty() {
        return Err(ClientRegistryError::NoRedirectUris);
    }
    Ok(())
}

/// Build the signed op for a client registration, gating it on
/// `iam:oauth:write` and validating the invariants. Returns the op the host
/// then signs + journals + folds through [`apply_op`]; the SAME op replays
/// deterministically on boot.
#[allow(clippy::too_many_arguments)]
pub fn register_client(
    decider: &RbacDecider<'_>,
    subject: NodeId,
    client_id: String,
    client_type: ClientType,
    redirect_uris: BTreeSet<String>,
    allowed_scopes: BTreeSet<String>,
    allowed_grants: BTreeSet<GrantType>,
    now_secs: u64,
) -> Result<ClientOp, ClientRegistryError> {
    if authorize_oauth_write(decider, subject, now_secs) != Decision::Allow {
        return Err(ClientRegistryError::Unauthorized);
    }
    validate_registration(client_type, &redirect_uris, &allowed_grants)?;
    Ok(ClientOp::RegisterClient {
        client_id,
        client_type,
        redirect_uris,
        allowed_scopes,
        allowed_grants,
        at: now_secs,
    })
}

/// Check a `redirect_uri` presented at authorize-time against the named
/// client's registered allow-list. This is the security gate that makes the
/// allow-list meaningful: an unregistered redirect URI is refused, so an
/// attacker-supplied value can never be honored.
pub fn authorize_redirect(
    registry: &ClientRegistry,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), ClientRegistryError> {
    let client = registry
        .clients
        .get(client_id)
        .ok_or(ClientRegistryError::UnknownClient)?;
    if client.redirect_uris.contains(redirect_uri) {
        Ok(())
    } else {
        Err(ClientRegistryError::UnregisteredRedirectUri)
    }
}

/// Introspect a token: RFC 7662 `active`. A token is active ONLY when a live
/// (non-revoked) consent exists for its `(user, client_id)` AND that consent
/// still covers every scope the token carries. Because the gate is evaluated
/// against the consent store rather than a per-token flag, revoking a consent
/// **immediately** flips every token issued under it to inactive
/// (`RevokedConsentNeverIntrospectsValid`).
#[must_use]
pub fn introspect(registry: &ClientRegistry, token: &Token) -> bool {
    // The client must still exist.
    if !registry.clients.contains_key(&token.client_id) {
        return false;
    }
    let key: ConsentKey = (token.user.clone(), token.client_id.clone());
    match registry.consents.get(&key) {
        Some(consent) if !consent.revoked => token.scopes.is_subset(&consent.scopes),
        _ => false,
    }
}

/// List every consent for a user (both live and revoked), for the
/// listable/revocable consent surface.
#[must_use]
pub fn list_consents<'a>(registry: &'a ClientRegistry, user: &str) -> Vec<&'a Consent> {
    registry
        .consents
        .values()
        .filter(|c| c.user == user)
        .collect()
}

/// Fold ONE [`ClientOp`] into `registry` — the SAME mutator live (right after
/// a successful signed act) and during replay (folding the persisted journal
/// on boot), so live and replayed state can never diverge. The public-client /
/// confidential-grant invariant is preserved here too: a confidential-only
/// grant is silently dropped for a public client (the signed path already
/// refused it in [`validate_registration`], so this only hardens replay).
pub fn apply_op(registry: &mut ClientRegistry, op: ClientOp) {
    match op {
        ClientOp::RegisterClient {
            client_id,
            client_type,
            redirect_uris,
            allowed_scopes,
            allowed_grants,
            at,
        } => {
            let allowed_grants = sanitize_grants(client_type, allowed_grants);
            registry
                .clients
                .entry(client_id.clone())
                .or_insert(OAuthClient {
                    client_id,
                    client_type,
                    redirect_uris,
                    allowed_scopes,
                    allowed_grants,
                    created_at: at,
                    updated_at: at,
                });
        }
        ClientOp::SetRedirectUris {
            client_id,
            redirect_uris,
            at,
        } => {
            if let Some(client) = registry.clients.get_mut(&client_id) {
                client.redirect_uris = redirect_uris;
                client.updated_at = at;
            }
        }
        ClientOp::SetGrants {
            client_id,
            allowed_grants,
            at,
        } => {
            if let Some(client) = registry.clients.get_mut(&client_id) {
                let client_type = client.client_type;
                client.allowed_grants = sanitize_grants(client_type, allowed_grants);
                client.updated_at = at;
            }
        }
        ClientOp::GrantConsent {
            user,
            client_id,
            scopes,
            at,
        } => {
            let key: ConsentKey = (user.clone(), client_id.clone());
            registry
                .consents
                .entry(key)
                .and_modify(|c| {
                    // Re-granting revives a revoked consent and unions scopes.
                    c.scopes.extend(scopes.iter().cloned());
                    c.revoked = false;
                    c.updated_at = at;
                })
                .or_insert(Consent {
                    user,
                    client_id,
                    scopes,
                    granted_at: at,
                    updated_at: at,
                    revoked: false,
                });
        }
        ClientOp::RevokeConsent {
            user,
            client_id,
            at,
        } => {
            let key: ConsentKey = (user, client_id);
            if let Some(consent) = registry.consents.get_mut(&key) {
                consent.revoked = true;
                consent.updated_at = at;
            }
        }
    }
}

/// Drop any confidential-only grant from a public client's grant set — the
/// replay-side hardening of [`validate_registration`].
fn sanitize_grants(client_type: ClientType, grants: BTreeSet<GrantType>) -> BTreeSet<GrantType> {
    if client_type == ClientType::Public {
        grants
            .into_iter()
            .filter(|g| !g.requires_confidential())
            .collect()
    } else {
        grants
    }
}

/// Replay a journal of [`ClientOp`]s into a fresh [`ClientRegistry`].
#[must_use]
pub fn replay(ops: impl IntoIterator<Item = ClientOp>) -> ClientRegistry {
    let mut registry = ClientRegistry::default();
    for op in ops {
        apply_op(&mut registry, op);
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_rbac::{ExplicitGrant, GrantEffect};
    use pillar_wot_authority::WotAuthority;

    fn scopes(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn uris(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn grants(items: &[GrantType]) -> BTreeSet<GrantType> {
        items.iter().copied().collect()
    }

    /// A decider that allows `iam:oauth:write` only for `admin`.
    fn admin_decider<'a>(
        authority: &'a WotAuthority,
        policies: &'a [pillar_rbac::PolicyEvent],
        grants: &'a [ExplicitGrant],
    ) -> RbacDecider<'a> {
        RbacDecider::new(authority, policies, grants)
    }

    #[test]
    fn oauth_write_capability_is_required_and_gated_by_the_shared_rbac_decider() {
        let authority = WotAuthority::new(NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let grant_list = [ExplicitGrant {
            subject: NodeId::from("admin"),
            capability: oauth_write_capability(),
            effect: GrantEffect::Allow,
        }];
        let decider = admin_decider(&authority, &policies, &grant_list);

        // Authorized admin: registration succeeds.
        let ok = register_client(
            &decider,
            NodeId::from("admin"),
            "web".to_owned(),
            ClientType::Confidential,
            uris(&["https://app.example.com/cb"]),
            scopes(&["openid"]),
            grants(&[GrantType::AuthorizationCode]),
            10,
        );
        assert!(ok.is_ok());

        // Unauthorized stranger: refused.
        let denied = register_client(
            &decider,
            NodeId::from("stranger"),
            "web".to_owned(),
            ClientType::Confidential,
            uris(&["https://app.example.com/cb"]),
            scopes(&["openid"]),
            grants(&[GrantType::AuthorizationCode]),
            10,
        );
        assert_eq!(denied, Err(ClientRegistryError::Unauthorized));
    }

    #[test]
    fn client_registry_refuses_unregistered_redirect_uri_at_authorize_time() {
        let registry = replay([ClientOp::RegisterClient {
            client_id: "web".to_owned(),
            client_type: ClientType::Confidential,
            redirect_uris: uris(&["https://app.example.com/cb"]),
            allowed_scopes: scopes(&["openid"]),
            allowed_grants: grants(&[GrantType::AuthorizationCode]),
            at: 1,
        }]);

        // The pre-registered URI is honored.
        assert_eq!(
            authorize_redirect(&registry, "web", "https://app.example.com/cb"),
            Ok(())
        );
        // An attacker-supplied URI NOT on the allow-list is refused. Without
        // the allow-list gate this would erroneously succeed.
        assert_eq!(
            authorize_redirect(&registry, "web", "https://evil.example.net/cb"),
            Err(ClientRegistryError::UnregisteredRedirectUri)
        );
        // Unknown client.
        assert_eq!(
            authorize_redirect(&registry, "ghost", "https://app.example.com/cb"),
            Err(ClientRegistryError::UnknownClient)
        );
    }

    #[test]
    fn client_registry_public_client_cannot_register_client_credentials_grant() {
        // Direct validation: a public client + client-credentials is refused.
        assert_eq!(
            validate_registration(
                ClientType::Public,
                &uris(&["https://spa.example.com/cb"]),
                &grants(&[GrantType::AuthorizationCode, GrantType::ClientCredentials]),
            ),
            Err(ClientRegistryError::PublicClientConfidentialGrant(
                GrantType::ClientCredentials
            ))
        );
        // The same restriction holds through the capability-gated builder.
        let authority = WotAuthority::new(NodeId::from("root"), 5);
        let policies: [pillar_rbac::PolicyEvent; 0] = [];
        let grant_list = [ExplicitGrant {
            subject: NodeId::from("admin"),
            capability: oauth_write_capability(),
            effect: GrantEffect::Allow,
        }];
        let decider = admin_decider(&authority, &policies, &grant_list);
        let refused = register_client(
            &decider,
            NodeId::from("admin"),
            "spa".to_owned(),
            ClientType::Public,
            uris(&["https://spa.example.com/cb"]),
            scopes(&["openid"]),
            grants(&[GrantType::ClientCredentials]),
            10,
        );
        assert_eq!(
            refused,
            Err(ClientRegistryError::PublicClientConfidentialGrant(
                GrantType::ClientCredentials
            ))
        );
        // A confidential client CAN hold the client-credentials grant.
        assert!(validate_registration(
            ClientType::Confidential,
            &uris(&[]),
            &grants(&[GrantType::ClientCredentials]),
        )
        .is_ok());
        // Replay hardening: even a forged op carrying the illegal grant has it
        // dropped for the public client.
        let registry = replay([ClientOp::RegisterClient {
            client_id: "spa".to_owned(),
            client_type: ClientType::Public,
            redirect_uris: uris(&["https://spa.example.com/cb"]),
            allowed_scopes: scopes(&["openid"]),
            allowed_grants: grants(&[GrantType::AuthorizationCode, GrantType::ClientCredentials]),
            at: 1,
        }]);
        assert!(
            !registry.clients["spa"]
                .allowed_grants
                .contains(&GrantType::ClientCredentials),
            "a public client must never end up holding a confidential-only grant"
        );
    }

    #[test]
    fn client_registry_revoking_consent_immediately_invalidates_all_its_tokens() {
        let mut registry = replay([
            ClientOp::RegisterClient {
                client_id: "web".to_owned(),
                client_type: ClientType::Confidential,
                redirect_uris: uris(&["https://app.example.com/cb"]),
                allowed_scopes: scopes(&["openid", "profile"]),
                allowed_grants: grants(&[GrantType::AuthorizationCode]),
                at: 1,
            },
            ClientOp::GrantConsent {
                user: "alice".to_owned(),
                client_id: "web".to_owned(),
                scopes: scopes(&["openid", "profile"]),
                at: 2,
            },
        ]);

        // Two distinct tokens issued under the SAME consent.
        let t1 = Token {
            token_id: "tok-1".to_owned(),
            user: "alice".to_owned(),
            client_id: "web".to_owned(),
            scopes: scopes(&["openid"]),
        };
        let t2 = Token {
            token_id: "tok-2".to_owned(),
            user: "alice".to_owned(),
            client_id: "web".to_owned(),
            scopes: scopes(&["openid", "profile"]),
        };
        // Before revocation both introspect as active.
        assert!(introspect(&registry, &t1));
        assert!(introspect(&registry, &t2));
        assert_eq!(list_consents(&registry, "alice").len(), 1);

        // Revoke the consent.
        apply_op(
            &mut registry,
            ClientOp::RevokeConsent {
                user: "alice".to_owned(),
                client_id: "web".to_owned(),
                at: 3,
            },
        );

        // EVERY token issued under it is immediately inactive — no per-token
        // bookkeeping was needed.
        assert!(!introspect(&registry, &t1));
        assert!(!introspect(&registry, &t2));
        // The consent is still listable (retained, marked revoked).
        let consents = list_consents(&registry, "alice");
        assert_eq!(consents.len(), 1);
        assert!(consents[0].revoked);
    }

    #[test]
    fn client_registry_introspection_requires_scopes_within_consent() {
        let registry = replay([
            ClientOp::RegisterClient {
                client_id: "web".to_owned(),
                client_type: ClientType::Confidential,
                redirect_uris: uris(&["https://app.example.com/cb"]),
                allowed_scopes: scopes(&["openid", "profile", "email"]),
                allowed_grants: grants(&[GrantType::AuthorizationCode]),
                at: 1,
            },
            ClientOp::GrantConsent {
                user: "alice".to_owned(),
                client_id: "web".to_owned(),
                scopes: scopes(&["openid"]),
                at: 2,
            },
        ]);
        // A token whose scopes exceed the consent is NOT active.
        let over = Token {
            token_id: "tok".to_owned(),
            user: "alice".to_owned(),
            client_id: "web".to_owned(),
            scopes: scopes(&["openid", "email"]),
        };
        assert!(!introspect(&registry, &over));
        // A token with no consent at all (different user) is not active.
        let no_consent = Token {
            token_id: "tok".to_owned(),
            user: "bob".to_owned(),
            client_id: "web".to_owned(),
            scopes: scopes(&["openid"]),
        };
        assert!(!introspect(&registry, &no_consent));
    }

    #[test]
    fn client_registry_replay_is_deterministic() {
        let ops = [
            ClientOp::RegisterClient {
                client_id: "web".to_owned(),
                client_type: ClientType::Confidential,
                redirect_uris: uris(&["https://app.example.com/cb"]),
                allowed_scopes: scopes(&["openid"]),
                allowed_grants: grants(&[GrantType::AuthorizationCode]),
                at: 1,
            },
            ClientOp::SetRedirectUris {
                client_id: "web".to_owned(),
                redirect_uris: uris(&["https://app.example.com/cb", "https://app.example.com/cb2"]),
                at: 2,
            },
            ClientOp::GrantConsent {
                user: "alice".to_owned(),
                client_id: "web".to_owned(),
                scopes: scopes(&["openid"]),
                at: 3,
            },
        ];
        let a = replay(ops.iter().cloned());
        let b = replay(ops.iter().cloned());
        assert_eq!(a, b);
        assert_eq!(a.clients["web"].redirect_uris.len(), 2);
    }
}
