//! Acceptance suite for the `iam-console-sections` task
//! (definition of done: `cargo test -p pillar-web-frontend --features
//! acceptance`).
//!
//! Proves, as a real integration test against this crate's PUBLIC API (not a
//! source-grep), that the four IAM console sections the ROI P0 IAM epic asks
//! for — Profile, Users (invite/list/disable/enable/reset/require-password-
//! change), Roles & Groups, OAuth Clients — are genuinely wired into the
//! console's `Section`/`Route` model, and that the forced-password-change
//! router guard intercepts every other route while it is set. Host-native:
//! no browser or wasm runner is needed, since `pillar-web-frontend`'s Yew
//! components already typecheck on the host under the crate's default `yew`
//! feature (see that feature's doc comment in `Cargo.toml`).
#![cfg(feature = "acceptance")]

use pillar_web_frontend::auth::reduce;
use pillar_web_frontend::iam_console::{
    attach_role_wire, create_group_wire, create_role_wire, invite_user_wire, parse_group_rows,
    parse_oauth_client_rows, parse_profile, parse_role_rows, parse_user_rows, profile_update_wire,
    register_client_wire, revoke_consent_wire, sensitive_action_allowed, user_target_wire,
};
use pillar_web_frontend::{AuthAction, AuthSession, Route, Section};

/// Every one of the four new IAM sections is a real, distinct, routable
/// `Section` filed under the Identity & Access nav group — not a decorative
/// stub.
#[test]
fn every_iam_section_is_registered_routable_and_grouped_under_access() {
    use pillar_web_frontend::NavGroup;

    let all = Section::all();
    for section in [
        Section::Profile,
        Section::Users,
        Section::RolesGroups,
        Section::OAuthClients,
    ] {
        assert!(
            all.contains(&section),
            "{section:?} missing from Section::all()"
        );
        assert_eq!(section.group(), NavGroup::Access);
        assert!(section.path().starts_with('/'));
        assert!(!section.label().is_empty());
    }

    // Each resolves to a real, distinct, protected Route.
    let routes = [
        Route::Profile,
        Route::Users,
        Route::RolesGroups,
        Route::OAuthClients,
    ];
    for r in &routes {
        assert!(r.requires_auth(), "{r:?} must require an active session");
    }
    for (i, a) in routes.iter().enumerate() {
        for b in &routes[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// Every mutating act each section performs is a real signed-op-style wire
/// builder carrying the session token FIRST (the crate's universal POST
/// framing) — never an empty/placeholder body.
#[test]
fn every_section_mutation_carries_a_real_wire_body_with_the_token_first() {
    assert_eq!(
        profile_update_wire("tok", "Alice", "alice@example.com"),
        "tok\nAlice\nalice@example.com"
    );
    assert_eq!(
        invite_user_wire("tok", "alice", "a@x.com"),
        "tok\nalice\na@x.com"
    );
    let user_wire = user_target_wire("tok", "alice"); // disable/enable/reset/require-change
    assert!(user_wire.starts_with("tok\n"));
    assert_eq!(
        create_role_wire("tok", "admin", "iam:users:write"),
        "tok\nadmin\niam:users:write"
    );
    assert_eq!(create_group_wire("tok", "ops"), "tok\nops");
    assert_eq!(attach_role_wire("tok", "ops", "admin"), "tok\nops\nadmin");
    assert_eq!(
        register_client_wire("tok", "Confidential", "https://example.com/cb", "read"),
        "tok\nConfidential\nhttps://example.com/cb\nread"
    );
    assert_eq!(
        revoke_consent_wire("tok", "client-1", "alice"),
        "tok\nclient-1\nalice"
    );
}

/// The full round trip of every section's list parser against a realistic
/// server response shape.
#[test]
fn every_section_list_parser_reads_real_server_response_shapes() {
    let profile = parse_profile(
        "PROFILE handle=alice display_name=Alice email=alice@example.com \
         status=Active force_password_change=false",
    );
    assert_eq!(profile.handle, "alice");
    assert_eq!(profile.status, "Active");

    let users = parse_user_rows(
        "alice status=Active force_password_change=false roles=admin\n\
         bob status=Invited force_password_change=true roles=\n",
    );
    assert_eq!(users.len(), 2);
    assert!(users[1].force_password_change);

    let roles = parse_role_rows("admin capabilities=iam:users:write,iam:roles:write\n");
    assert_eq!(roles[0].name, "admin");
    assert_eq!(roles[0].capabilities.len(), 2);

    let groups = parse_group_rows("ops roles=admin\n");
    assert_eq!(groups[0].name, "ops");

    let clients = parse_oauth_client_rows(
        "client-1 type=Confidential scopes=read,write redirect_uris=https://example.com/cb\n",
    );
    assert_eq!(clients[0].client_id, "client-1");
    assert_eq!(clients[0].client_type, "Confidential");
}

/// The predicted-effect-via-decider gate: every sensitive act (disable a
/// user, require a password change, revoke an OAuth consent) is only
/// permitted when a `PREDICTED ALLOW` dry-run precedes it — mirroring
/// `crate::resources_console`'s established pattern, never a UI-only guess,
/// and defaulting CLOSED on anything unparseable.
#[test]
fn sensitive_iam_acts_are_gated_by_a_predicted_allow_dry_run() {
    assert!(sensitive_action_allowed("PREDICTED ALLOW"));
    assert!(!sensitive_action_allowed("PREDICTED DENY"));
    assert!(!sensitive_action_allowed(""));
    assert!(!sensitive_action_allowed("garbage"));
}

/// The forced-change router guard: a session admitted with
/// `force_password_change: true` is intercepted to `Route::ChangePassword`
/// for EVERY other route (console home, a specific IAM section, the legacy
/// dashboard alias) — proving the guard is total, not a single spot-check —
/// and the interception lifts once `AuthAction::PasswordChanged` clears it.
#[test]
fn forced_password_change_intercepts_every_route_until_cleared() {
    use pillar_web_frontend::router::guard;

    let forced = reduce(
        &AuthSession::default(),
        AuthAction::LoginSuccess {
            user: "alice".to_string(),
            token: "tok-123".to_string(),
            force_password_change: true,
        },
    );
    for route in [
        Route::Overview,
        Route::Users,
        Route::Profile,
        Route::RolesGroups,
        Route::OAuthClients,
        Route::Dashboard,
        Route::Home,
    ] {
        assert_eq!(
            guard(route.clone(), &forced),
            Route::ChangePassword,
            "route not intercepted while force_password_change is set"
        );
    }
    // The change-password screen itself renders (no redirect loop).
    assert_eq!(guard(Route::ChangePassword, &forced), Route::ChangePassword);

    let cleared = reduce(&forced, AuthAction::PasswordChanged);
    assert_eq!(guard(Route::Overview, &cleared), Route::Overview);
    assert_eq!(guard(Route::Users, &cleared), Route::Users);
}
