//! Pillar OIDC provider (`pillar-oidc`).
//!
//! Refines `specs/OidcProvider.tla` (see `docs/tasks/oidc-provider-spec.md` in
//! the beehive layer). This crate currently ships the OP's **custodied ID-token
//! signing-key** machinery ([`custodied_keys`]): the signing key rides the
//! SAME pluggable [`pillar_identity::login::SignerBackend`] custody trait node
//! and cell keys already use (`file-keyring` / `tpm` / `passkey` / `password`),
//! never a bare on-disk secret, and JWKS publishes the current key plus any
//! still-in-grace prior key so a rotation never breaks in-flight verifiers.
//! The authorize/token/userinfo/discovery HTTP surface and claims mapping
//! land in later tasks (`oidc-provider-endpoints`, `oidc-claims-from-user-record`).

#![forbid(unsafe_code)]

pub mod client_registry;
pub mod custodied_keys;

pub use client_registry::{
    apply_op, authorize_oauth_write, authorize_redirect, introspect, list_consents,
    oauth_write_capability, register_client, replay, validate_registration, ClientOp,
    ClientRegistry, ClientRegistryError, ClientType, Consent, ConsentKey, GrantType, OAuthClient,
    Token, OAUTH_WRITE_CAPABILITY,
};
pub use custodied_keys::{
    IdTokenClaims, JwksDocument, KeyRotationError, SigningKeySet, VerifyIdTokenError,
};
