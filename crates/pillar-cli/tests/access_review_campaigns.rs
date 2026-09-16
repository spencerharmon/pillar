//! Acceptance test — `um-access-review-campaigns` (ROI P1 "User management &
//! lifecycle" roadmap C4: access-review / attestation campaigns).
//!
//! Proves the C4 story end to end over the REAL `pillar_iam::access_review`
//! engine (`AttestationCampaign` / `CampaignOp` driving the same
//! `pillar_iam::expiring_grants` `GrantSet`/`GrantOp` journal every capability
//! check reads) — not a mock:
//!
//! - Opening a campaign makes every un-attested LIVE grant STALE.
//! - Re-attesting a grant past the deadline clears its staleness.
//! - A stale grant AUTO-LAPSES fail-closed when the campaign closes: the
//!   `close_fail_closed` sweep revokes it through the shared grant journal, so
//!   it contributes NOTHING to the subject's effective capabilities afterward —
//!   exactly like an expired or explicitly-revoked grant, via the SAME
//!   `effective_capabilities_at` path.
//! - `AttestationCampaignConverges`: once no campaign is active, no live grant
//!   is stale — every grant was adjudicated (re-attested or revoked).
//!
//! This is the Rust refinement of `specs/GrantAuthority.tla`'s
//! `AttestationCampaignConverges` invariant the C4 story is gated on.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test access_review_campaigns --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::{BTreeMap, BTreeSet};

use pillar_iam::access_review::{AttestationCampaign, GrantKey};
use pillar_iam::expiring_grants::{effective_capabilities_at, GrantOp, GrantSet};
use pillar_iam::rbac_bridge::{ManagedGroup, Role};
use pillar_iam::{replay, UserOp, UserRecord};

const CRED_MANAGE: &str = "iam:credentials:manage";
const USERS_WRITE: &str = "iam:users:write";

fn roles() -> BTreeMap<String, Role> {
    let mut roles = BTreeMap::new();
    roles.insert(
        "billing-admin".to_owned(),
        Role::new("billing-admin", [CRED_MANAGE]),
    );
    roles.insert(
        "support-role".to_owned(),
        Role::new("support-role", [USERS_WRITE]),
    );
    roles
}

fn groups() -> BTreeMap<String, ManagedGroup> {
    BTreeMap::new()
}

fn users(handles: &[&str]) -> BTreeMap<String, UserRecord> {
    let ops: Vec<UserOp> = handles
        .iter()
        .map(|h| UserOp::Invite {
            handle: (*h).to_owned(),
            display_name: (*h).to_owned(),
            email: format!("{h}@example.com"),
            force_password_change: true,
            require_passkey_enrollment: false,
            at: 1,
        })
        .collect();
    replay(ops)
}

fn base_grants() -> GrantSet {
    // Two permanent role grants — the exact class a periodic access review
    // exists to re-attest.
    GrantSet::replay([
        GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: None,
        },
        GrantOp::GrantRole {
            handle: "bob".to_owned(),
            name: "support-role".to_owned(),
            expires_at: None,
        },
    ])
}

/// Opening a campaign marks every un-attested LIVE grant stale, and both
/// subjects still hold their capability while the campaign is merely open (the
/// grant is not revoked until it is adjudicated).
#[test]
fn opening_a_campaign_marks_live_grants_stale_without_revoking_them() {
    let records = users(&["alice", "bob"]);
    let roles = roles();
    let groups = groups();
    let grants = base_grants();

    let mut campaign = AttestationCampaign::new();
    assert!(campaign.open(50), "a fresh campaign opens");

    let stale = campaign.stale_live_grants(&grants, 60);
    assert_eq!(
        stale,
        BTreeSet::from([
            GrantKey::role("alice", "billing-admin"),
            GrantKey::role("bob", "support-role"),
        ]),
        "every un-attested live grant is stale under the campaign deadline"
    );

    // Merely opening the campaign never touches authority.
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 60),
        BTreeSet::from([CRED_MANAGE.to_owned()]),
        "an un-adjudicated grant still admits while the campaign is open"
    );
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "bob", 60),
        BTreeSet::from([USERS_WRITE.to_owned()]),
    );
}

/// The central C4 guarantee: a grant re-attested past the deadline SURVIVES the
/// campaign, and a grant left un-attested is AUTO-LAPSED fail-closed by the
/// campaign's close sweep — proven through the shared `effective_capabilities_at`
/// path, and `AttestationCampaignConverges` holds after close.
#[test]
fn unattested_grants_auto_lapse_fail_closed_on_close() {
    let records = users(&["alice", "bob"]);
    let roles = roles();
    let groups = groups();
    let mut grants = base_grants();

    let mut campaign = AttestationCampaign::new();
    campaign.open(50);

    // alice re-attests past the deadline; bob does not.
    assert!(campaign.reattest(GrantKey::role("alice", "billing-admin"), 60));

    // alice is no longer stale; bob still is.
    assert_eq!(
        campaign.stale_live_grants(&grants, 60),
        BTreeSet::from([GrantKey::role("bob", "support-role")]),
    );

    // Close the campaign fail-closed: bob's un-attested grant is auto-revoked.
    let revoked = campaign.close_fail_closed(&mut grants, 60);
    assert_eq!(
        revoked,
        BTreeSet::from([GrantKey::role("bob", "support-role")]),
        "the close sweep auto-revokes exactly the un-attested grant"
    );
    assert!(!campaign.is_active(), "the campaign closed");

    // The effect through the SHARED capability path: alice keeps her
    // capability, bob's has lapsed to nothing (fail-closed).
    assert_eq!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "alice", 60),
        BTreeSet::from([CRED_MANAGE.to_owned()]),
        "a re-attested grant survives the campaign"
    );
    assert!(
        effective_capabilities_at(&records, &grants, &roles, &groups, "bob", 60).is_empty(),
        "an un-attested grant admits NOTHING after the campaign closes (fail-closed)"
    );

    // AttestationCampaignConverges: no campaign active => no stale live grant.
    assert!(
        campaign.stale_live_grants(&grants, 60).is_empty(),
        "AttestationCampaignConverges — a closed campaign leaves no stale grant"
    );
}

/// A campaign CANNOT close while any stale grant remains un-adjudicated (the
/// `CloseCampaign` guard); once every grant is either re-attested or revoked,
/// the close succeeds and convergence holds. This is the invariant's teeth: the
/// gap can never be left open behind an inactive campaign.
#[test]
fn close_is_guarded_until_every_grant_is_adjudicated() {
    let mut grants = base_grants();
    let mut campaign = AttestationCampaign::new();
    campaign.open(50);

    // A guarded close is refused while stale grants remain, and leaves the
    // campaign active.
    let refused = campaign.close(&grants, 60).unwrap_err();
    assert_eq!(refused.len(), 2, "both un-attested grants block the close");
    assert!(
        campaign.is_active(),
        "a refused close leaves the campaign running"
    );

    // Adjudicate both: re-attest one, revoke the other.
    campaign.reattest(GrantKey::role("alice", "billing-admin"), 60);
    assert!(campaign.revoke_stale(&GrantKey::role("bob", "support-role"), &mut grants));

    // Now the guard is satisfied and the close succeeds.
    campaign
        .close(&grants, 60)
        .expect("close succeeds once every grant is adjudicated");
    assert!(!campaign.is_active());
    assert!(
        campaign.stale_live_grants(&grants, 60).is_empty(),
        "AttestationCampaignConverges holds after a guarded close"
    );
}

/// An ALREADY-EXPIRED grant is not the campaign's concern — it is dead through
/// the expiry engine already, so it is never in the stale set and the campaign
/// converges over the live grants alone.
#[test]
fn already_expired_grants_are_not_swept_by_the_campaign() {
    let mut grants = GrantSet::replay([
        GrantOp::GrantRole {
            handle: "alice".to_owned(),
            name: "billing-admin".to_owned(),
            expires_at: Some(100),
        },
        GrantOp::GrantRole {
            handle: "bob".to_owned(),
            name: "support-role".to_owned(),
            expires_at: None,
        },
    ]);
    let mut campaign = AttestationCampaign::new();
    campaign.open(50);

    // At tick 200 alice's grant has already lapsed via expiry — only bob's
    // permanent grant is a live, un-attested, stale grant.
    let stale = campaign.stale_live_grants(&grants, 200);
    assert_eq!(
        stale,
        BTreeSet::from([GrantKey::role("bob", "support-role")]),
        "an already-expired grant is not stale — it is already dead"
    );

    let revoked = campaign.close_fail_closed(&mut grants, 200);
    assert_eq!(
        revoked,
        BTreeSet::from([GrantKey::role("bob", "support-role")])
    );
    assert!(campaign.stale_live_grants(&grants, 200).is_empty());
}
