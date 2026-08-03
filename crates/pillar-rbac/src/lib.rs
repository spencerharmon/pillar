//! The single, pure RBAC decider: one precedence-lattice computation used
//! identically for both controller *enforcement* and UI *predicted*
//! outcome — never two implementations that could diverge.
//!
//! # Model
//!
//! The tsig web-of-trust graph ([`pillar_wot_authority::WotAuthority`]) is a
//! *trust metric only* — it never grants a capability by itself. Two other,
//! independent inputs layer on top of it:
//!
//! - **Signed policy events** ([`PolicyEvent`]) map a [`PolicyTarget`] —
//!   either a bare [`Capability`] or a [`Group`] — to a minimum WoT
//!   `depth_threshold`. A subject satisfies a policy when its
//!   [`WotAuthority::reachable_depth`] is at least that threshold (deeper
//!   trust chains have a *smaller* remaining budget number, per
//!   `pillar-wot-authority`'s budget model, so "at least as deep" reads
//!   "budget >= threshold").
//! - **Explicit signed grants** ([`ExplicitGrant`]) directly allow or deny
//!   one `(subject, capability)` pair, overriding the depth default in
//!   either direction.
//!
//! [`RbacDecider::decide`] composes all three into ONE precedence lattice,
//! evaluated top to bottom, fail-closed at the bottom:
//!
//! 1. **explicit-deny** — an [`ExplicitGrant`] naming `(subject, capability)`
//!    with [`GrantEffect::Deny`] always wins over everything below it.
//! 2. **explicit-allow** — absent an explicit deny, an [`ExplicitGrant`] with
//!    [`GrantEffect::Allow`] wins over the WoT-depth default.
//! 3. **WoT-depth-default** — absent any explicit grant, the subject is
//!    allowed if it is reachable (see [`pillar_wot_authority::WotAuthority`])
//!    at a depth satisfying ANY [`PolicyEvent`] that applies to this
//!    capability, whether that policy targets the capability directly or a
//!    [`Group`] the subject belongs to.
//! 4. **deny-all** — with no explicit grant and no satisfied depth policy,
//!    the decision is [`Decision::Deny`]: fail-closed default.
//!
//! [`RbacDecider::decide`] is the ONLY place this logic is computed. The
//! controller calls it to enforce; the UI calls the identical function to
//! predict — so "predicted == enforced" is true by construction, not by
//! coincidence of two independently-written codepaths staying in sync.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use pillar_core::NodeId;
use pillar_wot_authority::WotAuthority;

/// One specific, named action the decider may allow or deny.
///
/// Opaque from this crate's point of view, matching
/// `pillar_identity::capability::Capability`'s shape without adding a
/// dependency edge on that crate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability(pub String);

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_owned())
    }
}

/// A named group of subjects, used only as a [`PolicyEvent`] target — never
/// itself a source of authority.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Group(pub String);

impl From<&str> for Group {
    fn from(s: &str) -> Self {
        Group(s.to_owned())
    }
}

/// What a [`PolicyEvent`]'s depth threshold applies to: a capability
/// directly, or every member of a group.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PolicyTarget {
    /// The threshold applies to any subject requesting this capability,
    /// regardless of group membership.
    Capability(Capability),
    /// The threshold applies to members of this group requesting the
    /// [`PolicyEvent`]'s capability.
    Group(Group),
}

/// A signed policy event: `target` (capability|group) requires WoT
/// reachable-depth at least `depth_threshold` to satisfy `capability` under
/// the WoT-depth-default rung of the lattice.
///
/// Remaining budget from [`WotAuthority::reachable_depth`] must be `>=
/// depth_threshold` — a shallower (larger remaining-budget) trust position
/// satisfies a lower threshold; the deepest position (budget `0`) satisfies
/// only a threshold of `0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvent {
    /// What this threshold applies to (a capability directly, or a group).
    pub target: PolicyTarget,
    /// The capability this policy event grants under the depth default.
    pub capability: Capability,
    /// The minimum WoT reachable-depth budget required to satisfy this
    /// policy.
    pub depth_threshold: u8,
}

/// Whether an [`ExplicitGrant`] allows or denies its `(subject, capability)`
/// pair — both override the WoT-depth-default rung; deny always wins over
/// allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantEffect {
    /// Explicit allow: wins over the depth default, loses to explicit deny.
    Allow,
    /// Explicit deny: wins over every other rung, unconditionally.
    Deny,
}

/// An explicit signed grant (or denial) of one capability to one subject —
/// the two topmost, override rungs of the lattice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitGrant {
    /// The subject this grant names.
    pub subject: NodeId,
    /// The capability this grant covers.
    pub capability: Capability,
    /// Allow or deny.
    pub effect: GrantEffect,
}

/// The decider's verdict for one `(subject, capability)` query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The action is permitted.
    Allow,
    /// The action is refused — the fail-closed default, or an explicit
    /// deny.
    Deny,
}

/// A subject's group memberships — the sole input [`PolicyTarget::Group`]
/// consults. Membership is asserted here, not derived from the WoT graph:
/// the tsig graph is a trust metric only.
#[derive(Clone, Debug, Default)]
pub struct GroupMemberships {
    memberships: HashMap<NodeId, HashSet<Group>>,
}

impl GroupMemberships {
    /// An empty membership table: no subject belongs to any group.
    #[must_use]
    pub fn new() -> Self {
        GroupMemberships::default()
    }

    /// Add `subject` to `group` (additive; idempotent).
    pub fn add(&mut self, subject: NodeId, group: Group) {
        self.memberships.entry(subject).or_default().insert(group);
    }

    /// Whether `subject` belongs to `group`.
    #[must_use]
    pub fn is_member(&self, subject: &NodeId, group: &Group) -> bool {
        self.memberships
            .get(subject)
            .is_some_and(|gs| gs.contains(group))
    }
}

/// The single, pure RBAC decider over a local materialized view: one
/// `decide` computation, called identically for controller enforcement and
/// UI prediction (see module docs).
#[derive(Clone, Debug)]
pub struct RbacDecider<'a> {
    authority: &'a WotAuthority,
    policies: &'a [PolicyEvent],
    grants: &'a [ExplicitGrant],
    memberships: &'a GroupMemberships,
}

impl<'a> RbacDecider<'a> {
    /// Build a decider over this pass's materialized view: the WoT
    /// authority, the currently-live signed policy events, the currently-
    /// live explicit grants, and group memberships.
    #[must_use]
    pub fn new(
        authority: &'a WotAuthority,
        policies: &'a [PolicyEvent],
        grants: &'a [ExplicitGrant],
        memberships: &'a GroupMemberships,
    ) -> Self {
        RbacDecider {
            authority,
            policies,
            grants,
            memberships,
        }
    }

    /// Find this subject's explicit grant for `capability`, if any.
    fn explicit_grant(&self, subject: &NodeId, capability: &Capability) -> Option<GrantEffect> {
        // Explicit-deny outranks explicit-allow even if both are present
        // (e.g. a later deny narrowing an earlier allow): scan for a deny
        // first, unconditionally.
        let mut allow = None;
        for g in self.grants {
            if &g.subject == subject && &g.capability == capability {
                match g.effect {
                    GrantEffect::Deny => return Some(GrantEffect::Deny),
                    GrantEffect::Allow => allow = Some(GrantEffect::Allow),
                }
            }
        }
        allow
    }

    /// Whether `subject` satisfies ANY [`PolicyEvent`] granting
    /// `capability` under the WoT-depth-default rung: either a
    /// [`PolicyTarget::Capability`] policy for this capability, or a
    /// [`PolicyTarget::Group`] policy for a group `subject` belongs to,
    /// whose `depth_threshold` the subject's [`WotAuthority::reachable_depth`]
    /// satisfies.
    fn satisfies_depth_default(&self, subject: &NodeId, capability: &Capability) -> bool {
        let Some(depth) = self.authority.reachable_depth(subject) else {
            return false;
        };
        self.policies.iter().any(|p| {
            if &p.capability != capability {
                return false;
            }
            let target_matches = match &p.target {
                PolicyTarget::Capability(c) => c == capability,
                PolicyTarget::Group(g) => self.memberships.is_member(subject, g),
            };
            target_matches && depth >= p.depth_threshold
        })
    }

    /// Decide whether `subject` may perform `capability`, per the four-rung
    /// precedence lattice in the module docs: explicit-deny >
    /// explicit-allow > WoT-depth-default > deny-all.
    ///
    /// This is the ONLY decision function in the crate: call it for
    /// controller enforcement AND for UI prediction so the two can never
    /// diverge.
    #[must_use]
    pub fn decide(&self, subject: &NodeId, capability: &Capability) -> Decision {
        match self.explicit_grant(subject, capability) {
            Some(GrantEffect::Deny) => return Decision::Deny,
            Some(GrantEffect::Allow) => return Decision::Allow,
            None => {}
        }
        if self.satisfies_depth_default(subject, capability) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// UI-predicted outcome for `subject`/`capability`. Deliberately
    /// implemented as a direct call to [`decide`](Self::decide) — the
    /// SAME function the controller uses to enforce — so
    /// `predict(..) == decide(..)` holds structurally, not merely by test
    /// coverage.
    #[must_use]
    pub fn predict(&self, subject: &NodeId, capability: &Capability) -> Decision {
        self.decide(subject, capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn cap(s: &str) -> Capability {
        Capability::from(s)
    }

    fn owner_authority_with_alice(max_depth: u8, alice_level: u8) -> WotAuthority {
        let mut a = WotAuthority::new(n("owner"), max_depth);
        a.issue_edge(n("owner"), n("alice"), alice_level);
        a
    }

    #[test]
    fn deny_all_is_the_default_with_no_grants_or_policies() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![];
        let grants = vec![];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Deny
        );
    }

    #[test]
    fn wot_depth_default_allows_when_threshold_is_met() {
        let a = owner_authority_with_alice(3, 2);
        // owner budget 3 -> alice gets min(3-1,2) = 2
        assert_eq!(a.reachable_depth(&n("alice")), Some(2));

        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(cap("stream:append")),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Allow
        );
    }

    #[test]
    fn wot_depth_default_denies_when_threshold_is_not_met() {
        let a = owner_authority_with_alice(3, 2);
        assert_eq!(a.reachable_depth(&n("alice")), Some(2));

        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(cap("stream:append")),
            capability: cap("stream:append"),
            depth_threshold: 3,
        }];
        let grants = vec![];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Deny
        );
    }

    #[test]
    fn group_targeted_policy_allows_members_meeting_threshold() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Group(Group::from("operators")),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let mut memberships = GroupMemberships::new();
        memberships.add(n("alice"), Group::from("operators"));
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Allow
        );
        // bob is not a member of "operators", so the same policy does not
        // apply to him even if he were reachable.
        assert_eq!(
            decider.decide(&n("bob"), &cap("stream:append")),
            Decision::Deny
        );
    }

    #[test]
    fn explicit_allow_overrides_a_failing_depth_default() {
        let a = owner_authority_with_alice(3, 2);
        // Threshold is impossible to meet (deeper than owner's own budget).
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(cap("stream:append")),
            capability: cap("stream:append"),
            depth_threshold: 200,
        }];
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Allow,
        }];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        // Depth default alone would deny (threshold unreachable), but the
        // explicit allow rung wins.
        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Allow
        );
    }

    #[test]
    fn explicit_deny_overrides_a_satisfied_depth_default() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(cap("stream:append")),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Deny,
        }];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        // Depth default alone would allow, but explicit deny wins.
        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Deny
        );
    }

    #[test]
    fn explicit_deny_overrides_explicit_allow() {
        // Both explicit rungs present for the same subject/capability: deny
        // must win, regardless of insertion order.
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![];
        let grants = vec![
            ExplicitGrant {
                subject: n("alice"),
                capability: cap("stream:append"),
                effect: GrantEffect::Allow,
            },
            ExplicitGrant {
                subject: n("alice"),
                capability: cap("stream:append"),
                effect: GrantEffect::Deny,
            },
        ];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        assert_eq!(
            decider.decide(&n("alice"), &cap("stream:append")),
            Decision::Deny
        );

        // Order reversed: still deny.
        let grants_reversed: Vec<ExplicitGrant> = grants.into_iter().rev().collect();
        let decider2 = RbacDecider::new(&a, &policies, &grants_reversed, &memberships);
        assert_eq!(
            decider2.decide(&n("alice"), &cap("stream:append")),
            Decision::Deny
        );
    }

    #[test]
    fn each_lattice_rung_wins_over_the_one_below_it() {
        // Full descent through all four rungs on the SAME subject/capability,
        // proving strict precedence order: deny > allow > depth-default >
        // deny-all.
        let a = owner_authority_with_alice(3, 2);
        let c = cap("stream:append");
        let memberships = GroupMemberships::new();

        // Rung 4: deny-all (no policy, no grant).
        let no_policies = vec![];
        let no_grants = vec![];
        let d = RbacDecider::new(&a, &no_policies, &no_grants, &memberships);
        assert_eq!(d.decide(&n("alice"), &c), Decision::Deny);

        // Rung 3: WoT-depth-default now satisfied -> Allow.
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(c.clone()),
            capability: c.clone(),
            depth_threshold: 2,
        }];
        let d = RbacDecider::new(&a, &policies, &no_grants, &memberships);
        assert_eq!(d.decide(&n("alice"), &c), Decision::Allow);

        // Rung 2: explicit-allow added on top -- still Allow (no visible
        // change), but now let the depth default fail while the explicit
        // allow keeps it Allow, proving allow beats a failing default.
        let failing_policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(c.clone()),
            capability: c.clone(),
            depth_threshold: 200,
        }];
        let allow_grant = vec![ExplicitGrant {
            subject: n("alice"),
            capability: c.clone(),
            effect: GrantEffect::Allow,
        }];
        let d = RbacDecider::new(&a, &failing_policies, &allow_grant, &memberships);
        assert_eq!(d.decide(&n("alice"), &c), Decision::Allow);

        // Rung 1: explicit-deny added alongside -- wins over everything,
        // including a satisfied depth default and an explicit allow.
        let deny_and_allow = vec![
            ExplicitGrant {
                subject: n("alice"),
                capability: c.clone(),
                effect: GrantEffect::Allow,
            },
            ExplicitGrant {
                subject: n("alice"),
                capability: c.clone(),
                effect: GrantEffect::Deny,
            },
        ];
        let d = RbacDecider::new(&a, &policies, &deny_and_allow, &memberships);
        assert_eq!(d.decide(&n("alice"), &c), Decision::Deny);
    }

    #[test]
    fn predicted_always_equals_enforced_across_every_rung() {
        // predict() and decide() must never diverge, across every rung of
        // the lattice and both outcomes.
        let a = owner_authority_with_alice(3, 2);
        let c = cap("stream:append");
        let memberships = GroupMemberships::new();

        let cases: Vec<(Vec<PolicyEvent>, Vec<ExplicitGrant>)> = vec![
            (vec![], vec![]),
            (
                vec![PolicyEvent {
                    target: PolicyTarget::Capability(c.clone()),
                    capability: c.clone(),
                    depth_threshold: 2,
                }],
                vec![],
            ),
            (
                vec![],
                vec![ExplicitGrant {
                    subject: n("alice"),
                    capability: c.clone(),
                    effect: GrantEffect::Allow,
                }],
            ),
            (
                vec![PolicyEvent {
                    target: PolicyTarget::Capability(c.clone()),
                    capability: c.clone(),
                    depth_threshold: 2,
                }],
                vec![ExplicitGrant {
                    subject: n("alice"),
                    capability: c.clone(),
                    effect: GrantEffect::Deny,
                }],
            ),
        ];

        for (policies, grants) in &cases {
            let decider = RbacDecider::new(&a, policies, grants, &memberships);
            assert_eq!(
                decider.decide(&n("alice"), &c),
                decider.predict(&n("alice"), &c),
                "predicted must equal enforced for policies={policies:?} grants={grants:?}"
            );
        }
    }

    #[test]
    fn unreachable_subject_never_satisfies_depth_default() {
        let a = WotAuthority::new(n("owner"), 3);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Capability(cap("stream:append")),
            capability: cap("stream:append"),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let memberships = GroupMemberships::new();
        let decider = RbacDecider::new(&a, &policies, &grants, &memberships);

        // "nobody" is not reachable from the owner at all, so even a
        // threshold of 0 cannot be satisfied -- deny-all wins.
        assert_eq!(
            decider.decide(&n("nobody"), &cap("stream:append")),
            Decision::Deny
        );
    }
}
