//! Acceptance test — `um-session-device-inventory-revoke` (ROI P1 "User
//! management & lifecycle" roadmap A3).
//!
//! Proves the session/device inventory + selective revoke surface over the
//! proven `session-registry-impl` engine: a principal (or an admin-granted
//! caller, `um-delegated-signed-user-admin`'s decider shape) can enumerate
//! their active sessions/devices — each row carrying its origin (device/user
//! agent) and last-seen watermark, not just an opaque id/expiry — and revoke
//! either ONE named session or every OTHER session but the caller's current
//! one (`revoke --all-but-current`), in a single atomic, epoch-fenced,
//! signed act. Rides `specs/SessionRegistry.tla`'s proven
//! `NoActionAfterRevocation`/`RevokeAllRevokesEvery` invariants — restated
//! here over the selective (all-but-current) sweep the console's
//! "log out other devices" affordance needs.
//!
//! Driven directly over `pillar_cli::session_cli` — the exact engine the
//! `pillar session …` CLI verb dispatch and the delegated-signed console
//! surface (`iam-console-sections`) both call into.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test session_device_inventory_revoke --features acceptance`.

#![cfg(feature = "acceptance")]

use pillar_cli::session_cli::{SessionCli, SessionCliError};
use pillar_identity::session_registry::{AdmitError, SessionView};

/// End-to-end device inventory: mint three sessions from distinct
/// devices/origins, `ls` renders id/origin/issued-at/last-seen/expiry
/// countdown/current-marker for each, `show` renders the same for one named
/// slot, and a view over any of them admits until revoked.
#[test]
fn ls_and_show_render_the_device_inventory() {
    let mut cli = SessionCli::new();
    cli.mint_with_origin("alice", "laptop", 0, 1000, "chrome/macos/198.51.100.9");
    cli.mint_with_origin("alice", "phone", 5, 1000, "safari/ios/198.51.100.10");
    cli.mint_with_origin("alice", "tablet", 8, 1000, "safari/ipados/198.51.100.11");

    // Observe some activity on the laptop session before enumerating.
    cli.registry_mut().touch("alice", "laptop", 50);

    let rows = cli.ls("alice", "alice", 60, Some("phone")).unwrap();
    assert_eq!(rows.len(), 3, "every minted device session is listed");

    let laptop = rows.iter().find(|r| r.id == "laptop").unwrap();
    assert_eq!(laptop.origin, "chrome/macos/198.51.100.9");
    assert_eq!(laptop.issued_at, 0);
    assert_eq!(laptop.last_seen, 50, "touch advanced last_seen");
    assert_eq!(laptop.expires_in, 940);
    assert!(!laptop.is_current);

    let phone = rows.iter().find(|r| r.id == "phone").unwrap();
    assert_eq!(phone.origin, "safari/ios/198.51.100.10");
    assert_eq!(phone.last_seen, 5, "never touched: last_seen == issued_at");
    assert!(phone.is_current, "phone is the caller's current session");

    let tablet = rows.iter().find(|r| r.id == "tablet").unwrap();
    assert_eq!(tablet.origin, "safari/ipados/198.51.100.11");
    assert!(!tablet.is_current);

    // `show` on one named slot renders the identical projection.
    let shown = cli
        .show("alice", "alice", "tablet", 60, Some("phone"))
        .unwrap();
    assert_eq!(shown, *tablet);

    // All three currently admit.
    let mut view = SessionView::new();
    view.refresh(cli.registry());
    for id in ["laptop", "phone", "tablet"] {
        assert!(view.admit(cli.registry(), "alice", id, 60).is_ok());
    }
}

/// `revoke <id>` selectively kills exactly the named device/session and
/// leaves every other device of the same principal admitting — proves the
/// inventory's single-session revoke is truly selective, not a hidden sweep.
#[test]
fn revoke_one_device_leaves_the_others_admitting() {
    let mut cli = SessionCli::new();
    cli.mint_with_origin("alice", "laptop", 0, 1000, "chrome/macos");
    cli.mint_with_origin("alice", "phone", 0, 1000, "safari/ios");

    let event = cli.revoke("alice", "alice", "phone").unwrap();
    assert_eq!(cli.log().len(), 1);
    assert!(cli.log().get(&event).unwrap().is_authentic());

    let mut view = SessionView::new();
    view.refresh(cli.registry());
    assert!(
        view.admit(cli.registry(), "alice", "laptop", 10).is_ok(),
        "the untouched device must still admit"
    );
    assert_eq!(
        view.admit(cli.registry(), "alice", "phone", 10),
        Err(AdmitError::Revoked)
    );

    let active: Vec<String> = cli
        .ls("alice", "alice", 10, None)
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(active, vec!["laptop".to_string()]);
}

/// `revoke --all-but-current`: the core deliverable of this task. Minting
/// three devices then selectively revoking every one but the caller's
/// current session emits exactly ONE signed event, bumps the epoch exactly
/// once, leaves the current device admitting, revokes every other device of
/// the SAME principal, and leaves an unrelated principal entirely untouched
/// — restating `SessionRegistry.tla`'s `RevokeAllRevokesEvery` over the
/// selective sweep.
#[test]
fn revoke_all_but_current_sweeps_every_other_device_atomically() {
    let mut cli = SessionCli::new();
    cli.mint_with_origin("alice", "laptop", 0, 1000, "chrome/macos");
    cli.mint_with_origin("alice", "phone", 0, 1000, "safari/ios");
    cli.mint_with_origin("alice", "tablet", 0, 1000, "safari/ipados");
    cli.mint_with_origin("bob", "desktop", 0, 1000, "firefox/linux");

    let epoch_before = cli.registry().rev_epoch();
    let event = cli
        .revoke_all_but_current("alice", "alice", "laptop")
        .unwrap();

    // Exactly one signed event, one atomic epoch bump.
    assert_eq!(
        cli.log().len(),
        1,
        "revoke-all-but-current signs exactly one event"
    );
    let signed = cli.log().get(&event).unwrap();
    assert!(signed.is_authentic());
    assert_eq!(
        cli.registry().rev_epoch(),
        epoch_before + 1,
        "a single atomic epoch bump for the whole selective sweep"
    );

    let mut view = SessionView::new();
    view.refresh(cli.registry());
    assert!(
        view.admit(cli.registry(), "alice", "laptop", 10).is_ok(),
        "the current device is exempted from the sweep"
    );
    assert_eq!(
        view.admit(cli.registry(), "alice", "phone", 10),
        Err(AdmitError::Revoked)
    );
    assert_eq!(
        view.admit(cli.registry(), "alice", "tablet", 10),
        Err(AdmitError::Revoked)
    );
    // bob is an unrelated principal — entirely untouched by alice's sweep.
    assert!(view.admit(cli.registry(), "bob", "desktop", 10).is_ok());

    let active: Vec<String> = cli
        .ls("alice", "alice", 10, Some("laptop"))
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        active,
        vec!["laptop".to_string()],
        "only the current device remains active after the selective sweep"
    );

    // NoActionAfterRevocation: any later bearer action against a swept
    // device is refused, even with a view refreshed AFTER the sweep.
    assert_eq!(
        view.admit(cli.registry(), "alice", "phone", 999),
        Err(AdmitError::Revoked),
        "a revoked generation never re-admits, at any later logical time"
    );
}

/// Neither `revoke <id>` nor `revoke --all-but-current` may be aimed at
/// another principal's device inventory without an explicit admin grant —
/// the SAME decider `um-delegated-signed-user-admin`'s cross-principal rule
/// enforces. An unauthorized attempt signs/appends NOTHING and mutates
/// nothing; granting admin then permits it.
#[test]
fn cross_principal_device_revoke_requires_admin_grant() {
    let mut cli = SessionCli::new();
    cli.mint_with_origin("bob", "desktop", 0, 1000, "firefox/linux");
    cli.mint_with_origin("bob", "phone", 0, 1000, "safari/ios");

    // mallory has no grant: both the selective single-device revoke and the
    // all-but-current sweep are refused, and nothing is signed/mutated.
    let err_one = cli.revoke("mallory", "bob", "phone").unwrap_err();
    assert_eq!(
        err_one,
        SessionCliError::Unauthorized {
            caller: "mallory".into(),
            target: "bob".into(),
        }
    );
    let err_sweep = cli
        .revoke_all_but_current("mallory", "bob", "desktop")
        .unwrap_err();
    assert_eq!(
        err_sweep,
        SessionCliError::Unauthorized {
            caller: "mallory".into(),
            target: "bob".into(),
        }
    );
    assert_eq!(cli.log().len(), 0, "every unauthorized act emits nothing");
    assert!(
        matches!(
            cli.ls("mallory", "bob", 10, None),
            Err(SessionCliError::Unauthorized { .. })
        ),
        "an un-granted caller may not even VIEW another principal's inventory"
    );

    let mut view = SessionView::new();
    view.refresh(cli.registry());
    assert!(view.admit(cli.registry(), "bob", "desktop", 10).is_ok());
    assert!(view.admit(cli.registry(), "bob", "phone", 10).is_ok());

    // Once granted admin, mallory may enumerate and selectively revoke bob's
    // OTHER devices, keeping bob's own current one alive.
    cli.decider_mut().grant_admin("mallory").unwrap();
    let event = cli
        .revoke_all_but_current("mallory", "bob", "desktop")
        .unwrap();
    assert_eq!(cli.log().len(), 1);
    assert_eq!(
        cli.log().get(&event).unwrap().content().author(),
        &pillar_eventlog::Author("mallory".into())
    );

    view.refresh(cli.registry());
    assert!(
        view.admit(cli.registry(), "bob", "desktop", 10).is_ok(),
        "the exempted device is untouched even under an admin-driven sweep"
    );
    assert_eq!(
        view.admit(cli.registry(), "bob", "phone", 10),
        Err(AdmitError::Revoked)
    );
}
