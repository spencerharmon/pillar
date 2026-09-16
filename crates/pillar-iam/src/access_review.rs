//! Access-review / attestation campaigns — `um-access-review-campaigns` (ROI
//! P1 "User management & lifecycle" roadmap C4).
//!
//! A grant that lives forever until someone remembers to revoke it is a
//! standing liability. C4 layers a PERIODIC RE-ATTESTATION discipline on top
//! of the [`expiring_grants`](crate::expiring_grants) authority engine: an
//! admin opens a CAMPAIGN with a deadline, every live grant must be
//! RE-ATTESTED (an admin affirms "yes, this grant is still warranted") after
//! that deadline, and any grant NOT re-attested by the time the campaign
//! closes is AUTO-REVOKED — fail-closed. Nobody has to hand-revoke a stale
//! grant; the campaign sweep does it.
//!
//! This is the Rust refinement of `specs/GrantAuthority.tla`'s
//! `AttestationCampaignConverges` invariant (the story is gated on it):
//!
//! ```text
//! AttestationCampaignConverges ==
//!     ~campaign.active => StaleLiveGrants = {}
//! ```
//!
//! i.e. whenever no campaign is active, NO live grant is stale relative to the
//! last deadline — a closed campaign has adjudicated (re-attested OR revoked)
//! every live grant it was responsible for. The refinement:
//!
//! - `StaleLiveGrants` is [`AttestationCampaign::stale_live_grants`]: the LIVE
//!   role/group grants (unexpired, per [`ExpiringGrant::is_live`]) whose last
//!   attestation tick is OLDER than the campaign deadline.
//! - `Reattest` is [`AttestationCampaign::reattest`]: bump one stale grant's
//!   attestation to `now` (`>= deadline`), so it leaves the stale set —
//!   monotone progress toward convergence.
//! - `CampaignRevoke` is [`AttestationCampaign::revoke_stale`]: revoke one
//!   stale grant (emit a [`GrantOp::RevokeRole`]/[`GrantOp::RevokeGroup`] into
//!   the underlying [`GrantSet`]), so it is no longer live and leaves the stale
//!   set — the campaign's fail-closed leg.
//! - `CloseCampaign`'s guard (`StaleLiveGrants = {}`) is [`AttestationCampaign::close`]:
//!   a campaign can only close once every stale grant has been adjudicated. The
//!   fail-closed convenience [`AttestationCampaign::close_fail_closed`] first
//!   AUTO-REVOKES every remaining stale grant, then closes — so a campaign
//!   driven to its deadline can never leave an un-adjudicated live grant
//!   standing, exactly what `AttestationCampaignConverges` promises.
//!
//! The campaign never invents a bespoke authority path: it drives the SAME
//! [`GrantSet`]/[`GrantOp`] journal the [`expiring_grants`](crate::expiring_grants)
//! engine reads, so a campaign-revoked grant is dead through every capability
//! check exactly like an expired or explicitly-revoked one. Attestation state
//! is itself journaled ([`CampaignOp`] folded through
//! [`AttestationCampaign::apply`]/[`AttestationCampaign::replay`]), the same
//! replay discipline [`UserOp`](crate::UserOp) and [`GrantOp`] follow, so live
//! and replayed campaign state can never diverge.

use std::collections::{BTreeMap, BTreeSet};

use crate::expiring_grants::{GrantOp, GrantSet};

/// Identifies one grant a campaign adjudicates: a subject handle plus the kind
/// and name of the role/group binding it re-attests or revokes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct GrantKey {
    /// The subject handle the grant binds.
    pub handle: String,
    /// Whether this key names a role grant or a group grant.
    pub kind: GrantKind,
    /// The role or group name.
    pub name: String,
}

impl GrantKey {
    /// A role-grant key.
    #[must_use]
    pub fn role(handle: impl Into<String>, name: impl Into<String>) -> Self {
        GrantKey {
            handle: handle.into(),
            kind: GrantKind::Role,
            name: name.into(),
        }
    }

    /// A group-grant key.
    #[must_use]
    pub fn group(handle: impl Into<String>, name: impl Into<String>) -> Self {
        GrantKey {
            handle: handle.into(),
            kind: GrantKind::Group,
            name: name.into(),
        }
    }
}

/// Whether a [`GrantKey`] names a role or a group binding.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum GrantKind {
    /// A role binding (`GrantSet::role_grants`).
    Role,
    /// A group binding (`GrantSet::group_grants`).
    Group,
}

/// One journaled mutation of attestation/campaign state. Folded through
/// [`AttestationCampaign::apply`] both live and on replay — the SAME mutator
/// either way, so state can never diverge.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CampaignOp {
    /// Open a campaign with `deadline` — every live grant must be re-attested
    /// at or after `deadline` or it is stale. Only one campaign at a time
    /// (opening while active is a no-op).
    Open {
        /// The attestation deadline: a grant last attested BEFORE this tick is
        /// stale.
        deadline: u64,
    },
    /// Re-attest a grant at `at`: records that an admin affirmed it is still
    /// warranted as of tick `at`.
    Attest {
        /// The grant re-attested.
        key: GrantKey,
        /// The tick at which the attestation was made.
        at: u64,
    },
    /// Close the active campaign (a no-op if none is active). The caller is
    /// responsible for having adjudicated (attested or revoked) every stale
    /// grant first; [`AttestationCampaign::close`] enforces that guard.
    Close,
}

/// The durable access-review state: the in-flight campaign (if any) plus the
/// per-grant last-attestation ledger. Rebuilt ONLY by replaying [`CampaignOp`]s
/// (never mutated directly), exactly the [`GrantSet::replay`] discipline.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationCampaign {
    /// The active campaign's deadline, or `None` when no campaign is running.
    active_deadline: Option<u64>,
    /// Per-grant last-attestation tick. A grant absent here has never been
    /// attested (last attestation `0`, older than any positive deadline).
    attested: BTreeMap<GrantKey, u64>,
}

impl AttestationCampaign {
    /// An empty campaign state — no campaign active, nothing attested.
    #[must_use]
    pub fn new() -> Self {
        AttestationCampaign::default()
    }

    /// Whether a campaign is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active_deadline.is_some()
    }

    /// The active campaign's deadline, if any.
    #[must_use]
    pub fn deadline(&self) -> Option<u64> {
        self.active_deadline
    }

    /// The last-attestation tick recorded for `key` (`0` if never attested).
    #[must_use]
    pub fn attested_at(&self, key: &GrantKey) -> u64 {
        self.attested.get(key).copied().unwrap_or(0)
    }

    /// Fold ONE [`CampaignOp`] into the state — idempotent-safe live and on
    /// replay. Note this is the pure ledger mutation; the guarded, grant-set-
    /// mutating operations ([`Self::open`], [`Self::reattest`],
    /// [`Self::revoke_stale`], [`Self::close`]) build on it.
    pub fn apply(&mut self, op: CampaignOp) {
        match op {
            CampaignOp::Open { deadline } => {
                if self.active_deadline.is_none() {
                    self.active_deadline = Some(deadline);
                }
            }
            CampaignOp::Attest { key, at } => {
                let slot = self.attested.entry(key).or_insert(0);
                // Attestation only moves forward — a later attest never
                // rewinds the ledger.
                if at > *slot {
                    *slot = at;
                }
            }
            CampaignOp::Close => {
                self.active_deadline = None;
            }
        }
    }

    /// Rebuild campaign state from an ordered [`CampaignOp`] sequence.
    #[must_use]
    pub fn replay(ops: impl IntoIterator<Item = CampaignOp>) -> Self {
        let mut state = AttestationCampaign::new();
        for op in ops {
            state.apply(op);
        }
        state
    }

    /// Open a campaign with `deadline`. A no-op if one is already active
    /// (only one campaign at a time, matching the spec's `~campaign.active`
    /// guard). Returns whether a new campaign was opened.
    pub fn open(&mut self, deadline: u64) -> bool {
        if self.active_deadline.is_some() {
            return false;
        }
        self.apply(CampaignOp::Open { deadline });
        true
    }

    /// The LIVE grants that are STALE relative to the active campaign's
    /// deadline: every unexpired role/group binding in `grants` at `now` whose
    /// last attestation is OLDER than the deadline. This is the Rust
    /// `StaleLiveGrants`. Empty when no campaign is active.
    #[must_use]
    pub fn stale_live_grants(&self, grants: &GrantSet, now: u64) -> BTreeSet<GrantKey> {
        let Some(deadline) = self.active_deadline else {
            return BTreeSet::new();
        };
        let mut stale = BTreeSet::new();
        for (handle, name) in live_grant_pairs(grants, now, GrantKind::Role) {
            let key = GrantKey::role(handle, name);
            if self.attested_at(&key) < deadline {
                stale.insert(key);
            }
        }
        for (handle, name) in live_grant_pairs(grants, now, GrantKind::Group) {
            let key = GrantKey::group(handle, name);
            if self.attested_at(&key) < deadline {
                stale.insert(key);
            }
        }
        stale
    }

    /// Re-attest one grant at `now` (the `Reattest` action). Only meaningful
    /// while a campaign is active and only advances the ledger; `now` should
    /// be `>=` the deadline so the grant leaves the stale set. Returns whether
    /// an attestation was recorded (false if no campaign is active).
    pub fn reattest(&mut self, key: GrantKey, now: u64) -> bool {
        if self.active_deadline.is_none() {
            return false;
        }
        self.apply(CampaignOp::Attest { key, at: now });
        true
    }

    /// Auto-revoke one stale grant (the `CampaignRevoke` fail-closed leg):
    /// emit the matching [`GrantOp`] into `grants` so the binding is dead
    /// through every capability check, exactly like an explicit revoke. Returns
    /// whether a revoke was applied (false if no campaign is active).
    pub fn revoke_stale(&self, key: &GrantKey, grants: &mut GrantSet) -> bool {
        if self.active_deadline.is_none() {
            return false;
        }
        let op = match key.kind {
            GrantKind::Role => GrantOp::RevokeRole {
                handle: key.handle.clone(),
                name: key.name.clone(),
            },
            GrantKind::Group => GrantOp::RevokeGroup {
                handle: key.handle.clone(),
                name: key.name.clone(),
            },
        };
        grants.apply(op);
        true
    }

    /// Close the active campaign, but ONLY if every stale live grant has been
    /// adjudicated (`stale_live_grants` is empty) — the `CloseCampaign` guard
    /// that makes `AttestationCampaignConverges` meaningful. Returns `Err` with
    /// the still-stale grants if the guard is unmet, leaving the campaign
    /// active.
    pub fn close(&mut self, grants: &GrantSet, now: u64) -> Result<(), BTreeSet<GrantKey>> {
        let stale = self.stale_live_grants(grants, now);
        if !stale.is_empty() {
            return Err(stale);
        }
        self.apply(CampaignOp::Close);
        Ok(())
    }

    /// Fail-closed close: AUTO-REVOKE every remaining stale live grant, then
    /// close the campaign. This is the whole point of C4 — a campaign driven to
    /// its deadline revokes anything left un-attested rather than leaving it
    /// standing. Returns the set of grants it auto-revoked (empty if all were
    /// re-attested). After it returns, `stale_live_grants` is empty and the
    /// campaign is closed, so `AttestationCampaignConverges` holds.
    pub fn close_fail_closed(&mut self, grants: &mut GrantSet, now: u64) -> BTreeSet<GrantKey> {
        let stale = self.stale_live_grants(grants, now);
        for key in &stale {
            self.revoke_stale(key, grants);
        }
        self.apply(CampaignOp::Close);
        stale
    }
}

/// The `(handle, name)` pairs of every LIVE (unexpired at `now`) role or group
/// binding in `grants`. Reuses [`GrantSet::live_role_names`]/
/// [`GrantSet::live_group_names`] so "live" means exactly what the
/// [`expiring_grants`](crate::expiring_grants) engine means by it — a
/// campaign never re-derives liveness.
fn live_grant_pairs(grants: &GrantSet, now: u64, kind: GrantKind) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for handle in grants.granted_handles() {
        let names = match kind {
            GrantKind::Role => grants.live_role_names(&handle, now),
            GrantKind::Group => grants.live_group_names(&handle, now),
        };
        for name in names {
            pairs.push((handle.clone(), name));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants_with_two_roles() -> GrantSet {
        GrantSet::replay([
            GrantOp::GrantRole {
                handle: "alice".to_owned(),
                name: "billing-admin".to_owned(),
                expires_at: None,
            },
            GrantOp::GrantRole {
                handle: "bob".to_owned(),
                name: "support-role".to_owned(),
                expires_at: Some(1_000),
            },
        ])
    }

    #[test]
    fn no_active_campaign_has_no_stale_grants() {
        let campaign = AttestationCampaign::new();
        let grants = grants_with_two_roles();
        assert!(!campaign.is_active());
        assert!(campaign.stale_live_grants(&grants, 10).is_empty());
    }

    #[test]
    fn opening_a_campaign_makes_every_unattested_live_grant_stale() {
        let mut campaign = AttestationCampaign::new();
        let grants = grants_with_two_roles();
        assert!(campaign.open(50));
        // Second open is a no-op (one campaign at a time).
        assert!(!campaign.open(999));
        assert_eq!(campaign.deadline(), Some(50));

        let stale = campaign.stale_live_grants(&grants, 10);
        assert_eq!(
            stale,
            BTreeSet::from([
                GrantKey::role("alice", "billing-admin"),
                GrantKey::role("bob", "support-role"),
            ])
        );
    }

    #[test]
    fn reattest_removes_a_grant_from_the_stale_set() {
        let mut campaign = AttestationCampaign::new();
        let grants = grants_with_two_roles();
        campaign.open(50);
        // Re-attest alice's grant AT the deadline.
        assert!(campaign.reattest(GrantKey::role("alice", "billing-admin"), 60));
        let stale = campaign.stale_live_grants(&grants, 10);
        assert_eq!(
            stale,
            BTreeSet::from([GrantKey::role("bob", "support-role")])
        );
    }

    #[test]
    fn a_stale_grant_below_the_deadline_stays_stale() {
        let mut campaign = AttestationCampaign::new();
        let grants = grants_with_two_roles();
        campaign.open(50);
        // An attestation OLDER than the deadline does not clear staleness.
        campaign.reattest(GrantKey::role("alice", "billing-admin"), 60);
        // A prior (pre-deadline) attest for bob is too old.
        let mut c2 = AttestationCampaign::replay([
            CampaignOp::Attest {
                key: GrantKey::role("bob", "support-role"),
                at: 40,
            },
            CampaignOp::Open { deadline: 50 },
        ]);
        assert_eq!(c2.attested_at(&GrantKey::role("bob", "support-role")), 40);
        let stale = c2.stale_live_grants(&grants, 10);
        assert!(stale.contains(&GrantKey::role("bob", "support-role")));
        // sanity: alice still attested fresh above.
        assert!(!campaign
            .stale_live_grants(&grants, 10)
            .contains(&GrantKey::role("alice", "billing-admin")));
        c2.apply(CampaignOp::Close);
    }

    #[test]
    fn revoke_stale_kills_the_grant_through_the_grant_set() {
        let mut campaign = AttestationCampaign::new();
        let mut grants = grants_with_two_roles();
        campaign.open(50);
        assert!(campaign.revoke_stale(&GrantKey::role("bob", "support-role"), &mut grants));
        // bob's role is now dead in the underlying grant set at every tick.
        assert!(grants.live_role_names("bob", 10).is_empty());
        // ...and hence no longer stale.
        assert!(!campaign
            .stale_live_grants(&grants, 10)
            .contains(&GrantKey::role("bob", "support-role")));
    }

    #[test]
    fn close_is_refused_while_a_stale_grant_remains() {
        let mut campaign = AttestationCampaign::new();
        let grants = grants_with_two_roles();
        campaign.open(50);
        let err = campaign.close(&grants, 10).unwrap_err();
        assert_eq!(err.len(), 2, "both unattested grants block the close");
        assert!(
            campaign.is_active(),
            "a refused close leaves the campaign active"
        );
    }

    #[test]
    fn close_succeeds_once_every_grant_is_adjudicated() {
        let mut campaign = AttestationCampaign::new();
        let mut grants = grants_with_two_roles();
        campaign.open(50);
        campaign.reattest(GrantKey::role("alice", "billing-admin"), 60);
        campaign.revoke_stale(&GrantKey::role("bob", "support-role"), &mut grants);
        assert!(campaign.close(&grants, 10).is_ok());
        assert!(!campaign.is_active());
        // AttestationCampaignConverges: no campaign active => no stale grant.
        assert!(campaign.stale_live_grants(&grants, 10).is_empty());
    }

    #[test]
    fn close_fail_closed_auto_revokes_the_leftovers() {
        let mut campaign = AttestationCampaign::new();
        let mut grants = grants_with_two_roles();
        campaign.open(50);
        // Only alice re-attests; bob is left un-attested.
        campaign.reattest(GrantKey::role("alice", "billing-admin"), 60);
        let revoked = campaign.close_fail_closed(&mut grants, 10);
        assert_eq!(
            revoked,
            BTreeSet::from([GrantKey::role("bob", "support-role")])
        );
        assert!(!campaign.is_active());
        // bob's grant is dead; alice's survives.
        assert!(grants.live_role_names("bob", 10).is_empty());
        assert_eq!(
            grants.live_role_names("alice", 10),
            BTreeSet::from(["billing-admin".to_owned()])
        );
        // Convergence holds.
        assert!(campaign.stale_live_grants(&grants, 10).is_empty());
    }

    #[test]
    fn replay_is_deterministic() {
        let ops = [
            CampaignOp::Open { deadline: 50 },
            CampaignOp::Attest {
                key: GrantKey::role("alice", "billing-admin"),
                at: 60,
            },
        ];
        let a = AttestationCampaign::replay(ops.iter().cloned());
        let b = AttestationCampaign::replay(ops.iter().cloned());
        assert_eq!(a, b);
        assert_eq!(a.deadline(), Some(50));
        assert_eq!(a.attested_at(&GrantKey::role("alice", "billing-admin")), 60);
    }
}
