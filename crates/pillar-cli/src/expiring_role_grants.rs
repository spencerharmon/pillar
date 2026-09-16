//! Expiring role/group grants — bounded-lifetime RBAC bindings that
//! auto-lapse fail-closed, never standing past their window.
//!
//! ROI Priority 1 "User management & lifecycle" roadmap C1
//! (`um-expiring-role-grants`): a role or group binding may carry an
//! ABSOLUTE expiry; once wall-clock passes it the binding is DEAD and
//! contributes NOTHING to the subject's effective roles/capabilities —
//! forever, with no revoke and no sweeper required. This is the
//! roles/groups-and-capability-derivation analogue of
//! [`crate::jit_elevation::AuthorityLedger`] and is gated on the SAME
//! model-checked invariant `specs/GrantAuthority.tla` proves exhaustively:
//!
//! ```text
//! ExpiredGrantNeverAdmits ==
//!     \A g \in grants :
//!         now > g.expiry => g \notin LiveGrantsFor(g.subject)
//! ```
//!
//! An [`ExpiringRoleGrantLedger`] is a grow-only ledger of
//! [`RoleGrant`]s — each binds a `subject` to a `role` name through an
//! inclusive `expiry` tick. [`ExpiringRoleGrantLedger::effective_roles`]
//! folds ONLY the LIVE grants (not revoked, not expired) into a subject's
//! current role set — a pure, decidable, read-time fold exactly like
//! `AuthorityLedger::eff_auth`, so an expired grant needs no daemon to stop
//! admitting: it simply drops out of the fold the instant `now` passes its
//! expiry. [`ExpiringRoleGrantLedger::expired_grant_never_admits`] is the
//! executable image of `ExpiredGrantNeverAdmits`, asserted over the WHOLE
//! ledger at any wall-clock tick.
//!
//! This module composes with `pillar_iam::rbac_bridge`'s
//! [`crate::expiring_role_grants::ExpiringRoleGrantLedger::effective_roles`]
//! standing in for [`pillar_iam::UserRecord::roles`]/`::groups`'s
//! non-expiring set: a deployment that wants bounded-lifetime role/group
//! bindings computes `effective_roles`/`effective_groups` here FIRST, then
//! feeds that (fail-closed-empty-once-expired) set into
//! `pillar_iam::rbac_bridge::effective_capabilities` exactly as it would a
//! `UserRecord`'s standing set — an expired binding can never resurrect a
//! capability the standing derivation would otherwise grant.

use std::collections::BTreeSet;

/// Whether an [`ExpiringRoleGrantLedger`] binding attaches a `Role` name
/// directly to a subject, or attaches a `ManagedGroup` name to a subject
/// (mirroring `pillar_iam::rbac_bridge`'s two attachment paths — direct role
/// vs. group membership — each independently expirable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleGrantKind {
    /// A direct role-name binding (`UserRecord::roles`'s expiring analogue).
    Role,
    /// A group-membership binding (`UserRecord::groups`'s expiring
    /// analogue) — the subject's membership in the named group itself
    /// lapses, which in turn drops every role the group attaches.
    Group,
}

/// A single issued role/group binding. Grow-only: once issued it is never
/// mutated; it leaves the live set only by explicit revocation or by `now`
/// passing its `expiry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleGrant {
    /// Monotone grant id (1-based, allocation order).
    pub id: u64,
    /// The admin (or automated actor) that issued this binding.
    pub granter: String,
    /// The handle this binding names.
    pub subject: String,
    /// The role or group NAME this binding attaches (resolved elsewhere,
    /// e.g. against `pillar_iam::rbac_bridge`'s `roles`/`groups` maps).
    pub name: String,
    /// Whether `name` is a role or a group (see [`RoleGrantKind`]).
    pub kind: RoleGrantKind,
    /// Inclusive expiry tick: the binding is dead once `now > expiry`.
    pub expiry: u64,
}

impl RoleGrant {
    /// A binding is LIVE at `now` iff it is neither revoked nor past its
    /// expiry. Expiry is inclusive: `expiry = e` is live through `now == e`,
    /// dead at `now == e + 1` — identical semantics to
    /// `jit_elevation::Grant::is_live`.
    fn is_live(&self, now: u64, revoked: &BTreeSet<u64>) -> bool {
        !revoked.contains(&self.id) && now <= self.expiry
    }
}

/// Error building a [`RoleGrant`] via [`ExpiringRoleGrantLedger::assign`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleGrantError {
    /// The expiry is not in the future (`< now`): a binding issued
    /// already-dead is pointless and refused, mirroring
    /// `jit_elevation::ElevationError::ExpiryInPast`.
    ExpiryInPast {
        /// The rejected expiry.
        expiry: u64,
        /// The current wall-clock tick.
        now: u64,
    },
    /// The role/group name is empty — a binding must name something.
    EmptyName,
}

/// The grow-only ledger of expiring role/group bindings: every binding ever
/// issued plus the set of revoked ids and the current wall-clock `now`.
/// Effective role/group membership is a PURE fold over the LIVE bindings, so
/// expiry needs no sweeper — an expiring grant auto-lapses the instant `now`
/// passes its window, exactly like [`crate::jit_elevation::AuthorityLedger`].
#[derive(Clone, Debug, Default)]
pub struct ExpiringRoleGrantLedger {
    grants: Vec<RoleGrant>,
    revoked: BTreeSet<u64>,
    now: u64,
    next_id: u64,
}

impl ExpiringRoleGrantLedger {
    /// A fresh ledger at `now = 0` with no bindings.
    #[must_use]
    pub fn new() -> Self {
        ExpiringRoleGrantLedger {
            grants: Vec::new(),
            revoked: BTreeSet::new(),
            now: 0,
            next_id: 1,
        }
    }

    /// The current wall-clock tick.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Advance wall-clock to `t`. Monotone non-decreasing: a request to move
    /// backwards is ignored (time never rewinds), so an expired binding can
    /// never be revived by winding the clock back.
    pub fn tick_to(&mut self, t: u64) {
        if t > self.now {
            self.now = t;
        }
    }

    /// Bind `subject` to role `name` through `expiry`. Returns the new
    /// grant id, or [`RoleGrantError`] if the expiry is already past or the
    /// name is empty.
    pub fn assign_role(
        &mut self,
        granter: &str,
        subject: &str,
        name: &str,
        expiry: u64,
    ) -> Result<u64, RoleGrantError> {
        self.push(granter, subject, name, RoleGrantKind::Role, expiry)
    }

    /// Bind `subject` into group `name` through `expiry`. Returns the new
    /// grant id, or [`RoleGrantError`] if the expiry is already past or the
    /// name is empty.
    pub fn assign_group(
        &mut self,
        granter: &str,
        subject: &str,
        name: &str,
        expiry: u64,
    ) -> Result<u64, RoleGrantError> {
        self.push(granter, subject, name, RoleGrantKind::Group, expiry)
    }

    fn push(
        &mut self,
        granter: &str,
        subject: &str,
        name: &str,
        kind: RoleGrantKind,
        expiry: u64,
    ) -> Result<u64, RoleGrantError> {
        if name.is_empty() {
            return Err(RoleGrantError::EmptyName);
        }
        if expiry < self.now {
            return Err(RoleGrantError::ExpiryInPast {
                expiry,
                now: self.now,
            });
        }
        let id = self.next_id;
        self.next_id += 1;
        self.grants.push(RoleGrant {
            id,
            granter: granter.to_owned(),
            subject: subject.to_owned(),
            name: name.to_owned(),
            kind,
            expiry,
        });
        Ok(id)
    }

    /// Explicitly revoke a binding by id. Grow-only and idempotent: a
    /// revoked binding contributes nothing forever, same as an expired one.
    pub fn revoke(&mut self, id: u64) {
        self.revoked.insert(id);
    }

    /// Whether the binding `id` currently admits (is live and contributes to
    /// its subject's effective role/group set). `false` for an unknown,
    /// revoked, or expired id.
    #[must_use]
    pub fn admits(&self, id: u64) -> bool {
        self.grants
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.is_live(self.now, &self.revoked))
            .unwrap_or(false)
    }

    /// The live bindings naming `subject` at the current `now`, of `kind`.
    fn live_grants_for<'a>(
        &'a self,
        subject: &'a str,
        kind: RoleGrantKind,
    ) -> impl Iterator<Item = &'a RoleGrant> {
        self.grants
            .iter()
            .filter(move |g| g.subject == subject && g.kind == kind && g.is_live(self.now, &self.revoked))
    }

    /// `subject`'s currently LIVE direct role names — a fail-closed-empty
    /// fold: an unknown subject, or one whose every role binding is expired
    /// or revoked, yields the empty set, never a stale name.
    #[must_use]
    pub fn effective_roles(&self, subject: &str) -> BTreeSet<String> {
        self.live_grants_for(subject, RoleGrantKind::Role)
            .map(|g| g.name.clone())
            .collect()
    }

    /// `subject`'s currently LIVE group memberships — same fail-closed-empty
    /// fold as [`Self::effective_roles`], over [`RoleGrantKind::Group`]
    /// bindings.
    #[must_use]
    pub fn effective_groups(&self, subject: &str) -> BTreeSet<String> {
        self.live_grants_for(subject, RoleGrantKind::Group)
            .map(|g| g.name.clone())
            .collect()
    }

    /// The executable image of the TLA+ `ExpiredGrantNeverAdmits` invariant:
    /// EVERY binding past its expiry must be ABSENT from its subject's live
    /// set (of its own kind) at the current `now`. Returns `true` iff this
    /// holds for every binding in the ledger. A binding that ever violated
    /// it would be a standing grant that outlived its window — precisely
    /// the "never fail-closed" defect this roadmap item exists to prevent.
    #[must_use]
    pub fn expired_grant_never_admits(&self) -> bool {
        self.grants.iter().all(|g| {
            if self.now > g.expiry {
                !self.live_grants_for(&g.subject, g.kind).any(|live| live.id == g.id)
            } else {
                true
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_binding_is_live_through_inclusive_expiry_then_lapses() {
        let mut l = ExpiringRoleGrantLedger::new();
        let g = l.assign_role("owner", "alice", "billing-admin", 10).unwrap();
        assert!(l.admits(g));
        assert_eq!(
            l.effective_roles("alice"),
            BTreeSet::from(["billing-admin".to_owned()])
        );

        l.tick_to(10);
        assert!(l.admits(g), "inclusive expiry: still live at now == expiry");
        assert_eq!(
            l.effective_roles("alice"),
            BTreeSet::from(["billing-admin".to_owned()])
        );

        l.tick_to(11);
        assert!(!l.admits(g), "one tick past expiry it auto-lapses");
        assert!(
            l.effective_roles("alice").is_empty(),
            "an expired role grant contributes nothing, fail-closed"
        );
        assert!(l.expired_grant_never_admits());
    }

    #[test]
    fn group_membership_expiry_drops_the_whole_membership() {
        let mut l = ExpiringRoleGrantLedger::new();
        let g = l.assign_group("owner", "bob", "support-team", 5).unwrap();
        assert_eq!(
            l.effective_groups("bob"),
            BTreeSet::from(["support-team".to_owned()])
        );
        l.tick_to(6);
        assert!(!l.admits(g));
        assert!(l.effective_groups("bob").is_empty());
    }

    #[test]
    fn explicit_revoke_also_fail_closes_immediately_without_waiting_for_expiry() {
        let mut l = ExpiringRoleGrantLedger::new();
        let g = l.assign_role("owner", "carol", "support-role", 1_000).unwrap();
        assert!(l.admits(g));
        l.revoke(g);
        assert!(!l.admits(g), "revocation fail-closes immediately");
        assert!(l.effective_roles("carol").is_empty());
        assert!(l.expired_grant_never_admits());
    }

    #[test]
    fn expiry_in_past_is_refused() {
        let mut l = ExpiringRoleGrantLedger::new();
        l.tick_to(20);
        assert!(matches!(
            l.assign_role("owner", "dave", "role-x", 19),
            Err(RoleGrantError::ExpiryInPast { expiry: 19, now: 20 })
        ));
    }

    #[test]
    fn empty_name_is_refused() {
        let mut l = ExpiringRoleGrantLedger::new();
        assert!(matches!(
            l.assign_role("owner", "erin", "", 100),
            Err(RoleGrantError::EmptyName)
        ));
    }

    #[test]
    fn invariant_holds_across_the_ledger_at_every_tick() {
        let mut l = ExpiringRoleGrantLedger::new();
        l.assign_role("owner", "a", "role-a", 5).unwrap();
        l.assign_group("owner", "b", "group-b", 8).unwrap();
        l.assign_role("owner", "c", "role-c", 1_000).unwrap();
        for t in 0..=12 {
            l.tick_to(t);
            assert!(l.expired_grant_never_admits(), "invariant holds at now={t}");
        }
        // The long-lived one is still admitting; the short ones have lapsed.
        assert_eq!(l.effective_roles("c"), BTreeSet::from(["role-c".to_owned()]));
        assert!(l.effective_roles("a").is_empty());
        assert!(l.effective_groups("b").is_empty());
    }

    #[test]
    fn monotone_clock_never_revives_a_lapsed_binding() {
        let mut l = ExpiringRoleGrantLedger::new();
        let g = l.assign_role("owner", "f", "role-f", 3).unwrap();
        l.tick_to(4);
        assert!(!l.admits(g));
        l.tick_to(1);
        assert!(!l.admits(g), "clock never rewinds; lapsed binding stays dead");
    }
}
