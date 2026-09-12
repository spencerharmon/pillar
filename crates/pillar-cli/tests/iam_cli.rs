//! Acceptance test — `iam-cli-management` (2026-09-11 ROI Priority 0 IAM
//! epic).
//!
//! Proves CLI parity with the console for the IAM surface: `pillar
//! user`/`role`/`group`/`oauth` verbs plus `pillar login --oidc`, driven
//! directly over `pillar_cli::iam_cli` — the exact library the CLI verb
//! dispatch table (`pillar_cli::cli_surface::VERBS`) calls into. Every
//! mutation is a signed pillar-message op gated on the shared
//! `pillar_rbac::RbacDecider` (never a private auth path); every mutating
//! call has a `--dry-run`-shaped pure decider preview
//! ([`RoleCli::dry_run`]/[`GroupCli::dry_run`]/[`OauthCli::dry_run`]); every
//! mutated resource's `describe` renders its signer, authority, and
//! content-addressed event CID.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test iam_cli --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::BTreeSet;

use pillar_cli::iam_cli::{oidc_login, GroupCli, OauthCli, RoleCli};
use pillar_core::NodeId;
use pillar_oidc::client_registry::{ClientRegistryError, ClientType, GrantType};
use pillar_rbac::{Capability, Decision, ExplicitGrant, GrantEffect, RbacDecider};
use pillar_wot_authority::WotAuthority;

fn nid(s: &str) -> NodeId {
    NodeId::from(s)
}

/// End-to-end: an operator with NO grants is refused every IAM mutation
/// (`--dry-run` agrees, nothing is mutated), then — once granted the three
/// IAM write capabilities — successfully creates a role, a group with that
/// role and a member, and an OAuth client, each producing a describable
/// signed event (signer + authority + CID).
#[test]
fn role_group_oauth_cli_parity_gated_signed_and_describable() {
    let authority = WotAuthority::new(nid("root"), 4);
    let op = nid("operator");

    let no_grants: Vec<ExplicitGrant> = Vec::new();
    let decider_deny = RbacDecider::new(&authority, &[], &no_grants);

    let grants = vec![
        ExplicitGrant {
            subject: op.clone(),
            capability: Capability::from("iam:roles:write"),
            effect: GrantEffect::Allow,
        },
        ExplicitGrant {
            subject: op.clone(),
            capability: Capability::from("iam:groups:write"),
            effect: GrantEffect::Allow,
        },
        ExplicitGrant {
            subject: op.clone(),
            capability: Capability::from("iam:oauth:write"),
            effect: GrantEffect::Allow,
        },
    ];
    let decider_allow = RbacDecider::new(&authority, &[], &grants);

    // -- role -----------------------------------------------------------
    let mut roles = RoleCli::new();
    assert_eq!(
        roles.dry_run(&decider_deny, &op),
        Decision::Deny,
        "dry-run must preview the SAME refusal the real call would hit"
    );
    assert!(roles
        .add(&decider_deny, &op, "support-role", ["iam:users:write"])
        .is_err());
    assert!(roles.show("support-role").is_none(), "refused act must mutate nothing");

    assert_eq!(roles.dry_run(&decider_allow, &op), Decision::Allow);
    let role_cid = roles
        .add(&decider_allow, &op, "support-role", ["iam:users:write"])
        .expect("granted operator may create a role");
    let role_event = roles.describe("support-role").expect("describe renders the event");
    assert_eq!(role_event.signer, op);
    assert_eq!(role_event.authority, Capability::from("iam:roles:write"));
    assert_eq!(role_event.cid, role_cid);
    assert!(
        roles
            .show("support-role")
            .unwrap()
            .capabilities
            .contains("iam:users:write")
    );

    // -- group ------------------------------------------------------------
    let mut groups = GroupCli::new();
    assert!(groups
        .add(&decider_deny, &op, "support-team", ["support-role"])
        .is_err());
    assert!(groups.show("support-team").is_none());

    let group_cid = groups
        .add(&decider_allow, &op, "support-team", ["support-role"])
        .expect("granted operator may create a group");
    let member_cid = groups
        .add_member(&decider_allow, &op, "support-team", "bob")
        .expect("granted operator may add a member");
    assert_ne!(group_cid, member_cid, "distinct ops mint distinct CIDs");
    let group = groups.show("support-team").expect("group exists");
    assert_eq!(group.roles, BTreeSet::from(["support-role".to_owned()]));
    assert_eq!(group.members, BTreeSet::from(["bob".to_owned()]));
    let group_event = groups.describe("support-team").expect("describe renders the event");
    assert_eq!(group_event.cid, member_cid, "describe shows the MOST RECENT mutation");
    assert_eq!(group_event.authority, Capability::from("iam:groups:write"));

    // -- oauth --------------------------------------------------------------
    let mut oauth = OauthCli::new();
    assert_eq!(oauth.dry_run(&decider_deny, &op), Decision::Deny);
    let denied = oauth
        .register(
            &decider_deny,
            &op,
            "console-app",
            ClientType::Public,
            BTreeSet::from(["https://console.example.com/callback".to_owned()]),
            BTreeSet::from(["openid".to_owned(), "profile".to_owned()]),
            BTreeSet::from([GrantType::AuthorizationCode]),
            100,
        )
        .unwrap_err();
    assert_eq!(
        denied,
        pillar_cli::iam_cli::OauthCliError::Registry(ClientRegistryError::Unauthorized)
    );
    assert!(oauth.show("console-app").is_none());

    let oauth_cid = oauth
        .register(
            &decider_allow,
            &op,
            "console-app",
            ClientType::Public,
            BTreeSet::from(["https://console.example.com/callback".to_owned()]),
            BTreeSet::from(["openid".to_owned(), "profile".to_owned()]),
            BTreeSet::from([GrantType::AuthorizationCode]),
            100,
        )
        .expect("granted operator may register an oauth client");
    let client = oauth.show("console-app").expect("client registered");
    assert_eq!(client.client_type, ClientType::Public);
    let oauth_event = oauth.describe("console-app").expect("describe renders the event");
    assert_eq!(oauth_event.cid, oauth_cid);
    assert_eq!(oauth_event.authority, Capability::from("iam:oauth:write"));

    // A public client registering a confidential-only grant is refused by
    // the SAME registry invariant the console's registration path enforces
    // (never a CLI-only, weaker check).
    let invalid = oauth
        .register(
            &decider_allow,
            &op,
            "bad-public-client",
            ClientType::Public,
            BTreeSet::from(["https://x.example.com/cb".to_owned()]),
            BTreeSet::from(["openid".to_owned()]),
            BTreeSet::from([GrantType::ClientCredentials]),
            100,
        )
        .unwrap_err();
    assert!(matches!(
        invalid,
        pillar_cli::iam_cli::OauthCliError::Registry(
            ClientRegistryError::PublicClientConfidentialGrant(GrantType::ClientCredentials)
        )
    ));
}

/// `pillar login --oidc`: a real authorization-code + PKCE round trip
/// against the SAME `pillar_oidc::endpoints::Provider` engine a deployed
/// node's HTTP surface serves, minting a real `EdDSA`-signed ID token — not
/// a mock.
#[test]
fn login_oidc_mints_a_real_token_over_a_pkce_verified_code_exchange() {
    let result = oidc_login::run(
        "https://pillar.local",
        "cli-login-client",
        "https://cli.local/callback",
        "alice",
        BTreeSet::from(["openid".to_owned()]),
        "a-real-random-code-verifier-at-least-43-characters",
        1,
    )
    .expect("real in-process authorize + token exchange");
    assert!(!result.access_token.is_empty());
    assert!(
        result.id_token.is_some(),
        "an end-user grant must mint a real signed ID token"
    );

    // The PKCE transform itself is real, deterministic, and distinct per
    // verifier — the property `token_authorization_code` relies on to refuse
    // a mismatched verifier.
    let challenge_a = oidc_login::pkce_challenge_s256("verifier-a-at-least-43-characters-long");
    let challenge_b = oidc_login::pkce_challenge_s256("verifier-b-at-least-43-characters-long");
    assert_ne!(challenge_a, challenge_b);
}
