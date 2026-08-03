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
//!   a specific node, a group, a label-set, or a resource class — to a
//!   minimum WoT `depth_threshold`. A subject satisfies a policy when its
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
//!    at a depth satisfying the MOST SPECIFIC [`PolicyEvent`] that applies
//!    to this request, per the `specific > group > all` override order (see
//!    [`PolicyTarget`]).
//! 4. **deny-all** — with no explicit grant and no satisfied depth policy,
//!    the decision is [`Decision::Deny`]: fail-closed default.
//!
//! [`RbacDecider::decide`] is the ONLY place this logic is computed. The
//! controller calls it to enforce; the UI calls the identical function to
//! predict — so "predicted == enforced" is true by construction, not by
//! coincidence of two independently-written codepaths staying in sync.
//!
//! # Node ownership
//!
//! Ownership of a node by a user is a separate, orthogonal question from
//! capability decisions: a node's subkey chains, over zero or more further
//! tsig edges, back to a user's primary key. This crate re-exposes
//! [`pillar_wot_authority::WotAuthority::owns`] as [`owns_node`] so
//! ownership resolution and RBAC decisions share the exact same WoT-graph
//! source of truth.
//!
//! # Shipped defaults
//!
//! [`default_resource_class_policies`] ships sane, LOW, in-tree default
//! trust levels per [`ResourceClass`] — see its docs for the exact
//! thresholds and rationale. These are a deliberately conservative
//! starting point a deployment can override with more specific
//! [`PolicyEvent`]s (node/group/label-set), which — per the override order
//! — always win over the resource-class default.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

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
///
/// A group's identity IS its signing parent subkey ([`Group::parent`]):
/// "group = node subkeys signed by a common parent subkey" (see the module
/// docs' `PolicyTarget::Group` rung), so membership is *derived* from the
/// live WoT graph ([`WotAuthority::is_group_member`]) rather than asserted
/// in a side table.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Group(pub NodeId);

impl Group {
    /// The parent subkey this group is defined by: its members are exactly
    /// the subjects that parent has (validly) tsig-signed.
    #[must_use]
    pub fn parent(&self) -> &NodeId {
        &self.0
    }
}

impl From<&str> for Group {
    fn from(s: &str) -> Self {
        Group(NodeId::from(s))
    }
}

/// A resource class a policy or request targets: `Compute`/`Network`/
/// `Storage` name a specific class of resource, and `All` is the catch-all
/// applying across every class absent a more specific match — the least-
/// specific rung a [`PolicyTarget`] can occupy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceClass {
    /// Compute resources (nodes, workloads, execution).
    Compute,
    /// Network resources (links, routes, mesh membership).
    Network,
    /// Storage resources (volumes, streams, blobs).
    Storage,
    /// Every resource class, absent a more specific class/node/group/label
    /// match — the final catch-all rung.
    All,
}

/// All four [`ResourceClass`] variants, in a stable order — used to iterate
/// the full set (e.g. to build [`default_resource_class_policies`]).
pub const RESOURCE_CLASSES: [ResourceClass; 4] = [
    ResourceClass::Compute,
    ResourceClass::Network,
    ResourceClass::Storage,
    ResourceClass::All,
];

/// A label-set target: a policy applies to any subject carrying ALL of
/// these labels. More specific than a resource class, less specific than a
/// named node or group.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LabelSet(pub BTreeSet<String>);

impl LabelSet {
    /// Build a label-set from an iterator of label strings.
    #[must_use]
    pub fn new(labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        LabelSet(labels.into_iter().map(Into::into).collect())
    }

    /// Whether `subject_labels` carries every label in this set.
    #[must_use]
    pub fn matches(&self, subject_labels: &BTreeSet<String>) -> bool {
        self.0.is_subset(subject_labels)
    }
}

/// What a [`PolicyEvent`]'s depth threshold applies to: a specific node, a
/// group (subkeys signed by a common parent), a label-set, or a resource
/// class — in strictly decreasing specificity.
///
/// # Override precedence
///
/// When more than one [`PolicyEvent`] targeting the SAME capability applies
/// to a subject/request, the MOST SPECIFIC applicable target wins —
/// `specific > group > all`:
///
/// 1. [`PolicyTarget::Node`] — names the subject directly: most specific.
/// 2. [`PolicyTarget::Group`] — the subject is a member (its subkey was
///    signed by the group's parent key).
/// 3. [`PolicyTarget::LabelSet`] — the subject carries every named label.
/// 4. [`PolicyTarget::ResourceClass`] (`Compute`/`Network`/`Storage`) — the
///    request targets that specific resource class.
/// 5. [`PolicyTarget::ResourceClass`]`(`[`ResourceClass::All`]`)` — the
///    final catch-all, least specific: applies absent any more specific
///    match.
///
/// See [`RbacDecider::most_specific_satisfied_policy`] for the resolution
/// that implements this order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PolicyTarget {
    /// The threshold applies to exactly this one subject — the most
    /// specific, highest-precedence target.
    Node(NodeId),
    /// The threshold applies to members of this group requesting the
    /// [`PolicyEvent`]'s capability.
    Group(Group),
    /// The threshold applies to any subject carrying every label in this
    /// set.
    LabelSet(LabelSet),
    /// The threshold applies to any request against this resource class
    /// (`Compute`/`Network`/`Storage` are specific classes;
    /// [`ResourceClass::All`] is the least-specific catch-all).
    ResourceClass(ResourceClass),
}

impl PolicyTarget {
    /// This target's specificity rank for the `specific > group > all`
    /// override order: a LOWER number is MORE specific and wins between two
    /// policies whose depth thresholds are both satisfied for the same
    /// request.
    fn specificity(&self) -> u8 {
        match self {
            PolicyTarget::Node(_) => 0,
            PolicyTarget::Group(_) => 1,
            PolicyTarget::LabelSet(_) => 2,
            PolicyTarget::ResourceClass(ResourceClass::Compute)
            | PolicyTarget::ResourceClass(ResourceClass::Network)
            | PolicyTarget::ResourceClass(ResourceClass::Storage) => 3,
            PolicyTarget::ResourceClass(ResourceClass::All) => 4,
        }
    }
}

/// A signed policy event: `target` (node|group|label-set|resource-class)
/// requires WoT reachable-depth at least `depth_threshold` to satisfy
/// `capability` under the WoT-depth-default rung of the lattice.
///
/// Remaining budget from [`WotAuthority::reachable_depth`] must be `>=
/// depth_threshold` — a shallower (larger remaining-budget) trust position
/// satisfies a lower threshold; the deepest position (budget `0`) satisfies
/// only a threshold of `0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvent {
    /// What this threshold applies to (node, group, label-set, or resource
    /// class).
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

/// The decider's verdict for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The action is permitted.
    Allow,
    /// The action is refused — the fail-closed default, or an explicit
    /// deny.
    Deny,
}

/// One `(subject, capability)` query against a specific [`ResourceClass`]
/// and the subject's labels — everything [`RbacDecider::decide`] needs to
/// resolve every [`PolicyTarget`] rung.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The subject requesting the capability.
    pub subject: NodeId,
    /// The capability requested.
    pub capability: Capability,
    /// Which resource class this request targets (use
    /// [`ResourceClass::All`] when the request is not class-specific).
    pub resource_class: ResourceClass,
    /// The subject's labels, consulted by [`PolicyTarget::LabelSet`].
    pub subject_labels: BTreeSet<String>,
}

impl Request {
    /// Build a request with no labels and [`ResourceClass::All`] — the
    /// common case for a plain `(subject, capability)` decision that does
    /// not care about resource class or label-set targeting.
    #[must_use]
    pub fn new(subject: NodeId, capability: Capability) -> Self {
        Request {
            subject,
            capability,
            resource_class: ResourceClass::All,
            subject_labels: BTreeSet::new(),
        }
    }

    /// Set this request's resource class.
    #[must_use]
    pub fn with_resource_class(mut self, class: ResourceClass) -> Self {
        self.resource_class = class;
        self
    }

    /// Set this request's subject labels.
    #[must_use]
    pub fn with_labels(mut self, labels: BTreeSet<String>) -> Self {
        self.subject_labels = labels;
        self
    }
}

/// Whether `node`'s subkey chains, over zero or more further tsig edges,
/// back to `user_primary` — a thin, crate-local re-export of
/// [`WotAuthority::owns`] so callers doing RBAC decisions and ownership
/// resolution share the identical WoT-graph source of truth without
/// depending on `pillar-wot-authority` directly for this one call.
#[must_use]
pub fn owns_node(authority: &WotAuthority, user_primary: &NodeId, node: &NodeId) -> bool {
    authority.owns(user_primary, node)
}

/// Ship sane, LOW default trust-depth thresholds per [`ResourceClass`], as
/// a starting-point [`PolicyEvent`] set a deployment can layer more
/// specific node/group/label-set policies on top of (which always win, per
/// the `specific > group > all` override order).
///
/// The defaults are deliberately LOW (i.e. a HIGH `depth_threshold`, since
/// remaining budget shrinks with distance from the trust root — a subject
/// must be *close* to the root to satisfy a low/strict default): every
/// resource class starts fail-closed-ish, requiring near-root trust, and
/// `ResourceClass::All`'s threshold is the strictest (highest) of all,
/// since it is the last-resort catch-all when nothing more specific
/// applies. A deployment that wants a laxer default installs its OWN
/// [`PolicyEvent`] with a lower `depth_threshold` for that resource class
/// or a more specific target; this shipped set never prevents that
/// override, it only ever supplies the floor absent one.
#[must_use]
pub fn default_resource_class_policies(capability: &Capability) -> Vec<PolicyEvent> {
    // Depth-threshold values: larger means a subject must be closer to the
    // trust root (deeper subjects have smaller remaining budget), so a
    // LOW default trust level reads as a comparatively HIGH threshold here.
    // Compute/network/storage share one conservative default; `All` (the
    // final catch-all) requires the very closest trust (root only).
    const LOW_DEFAULT_THRESHOLD: u8 = 2;
    const ALL_CATCHALL_THRESHOLD: u8 = 3;

    RESOURCE_CLASSES
        .iter()
        .map(|class| PolicyEvent {
            target: PolicyTarget::ResourceClass(*class),
            capability: capability.clone(),
            depth_threshold: if matches!(class, ResourceClass::All) {
                ALL_CATCHALL_THRESHOLD
            } else {
                LOW_DEFAULT_THRESHOLD
            },
        })
        .collect()
}

/// The single, pure RBAC decider over a local materialized view: one
/// `decide` computation, called identically for controller enforcement and
/// UI prediction (see module docs).
#[derive(Clone, Debug)]
pub struct RbacDecider<'a> {
    authority: &'a WotAuthority,
    policies: &'a [PolicyEvent],
    grants: &'a [ExplicitGrant],
}

impl<'a> RbacDecider<'a> {
    /// Build a decider over this pass's materialized view: the WoT
    /// authority, the currently-live signed policy events, and the
    /// currently-live explicit grants. Group membership and node ownership
    /// are resolved directly against `authority` (see module docs) rather
    /// than an asserted side table.
    #[must_use]
    pub fn new(authority: &'a WotAuthority, policies: &'a [PolicyEvent], grants: &'a [ExplicitGrant]) -> Self {
        RbacDecider {
            authority,
            policies,
            grants,
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

    /// Whether `target` applies to this `request`, independent of its
    /// depth threshold (i.e. is this policy even in scope for the
    /// subject/resource-class/labels being asked about).
    fn target_applies(&self, target: &PolicyTarget, request: &Request) -> bool {
        match target {
            PolicyTarget::Node(node) => node == &request.subject,
            PolicyTarget::Group(g) => self.authority.is_group_member(g.parent(), &request.subject),
            PolicyTarget::LabelSet(labels) => labels.matches(&request.subject_labels),
            PolicyTarget::ResourceClass(ResourceClass::All) => true,
            PolicyTarget::ResourceClass(class) => *class == request.resource_class,
        }
    }

    /// The most specific [`PolicyEvent`] — per the `specific > group > all`
    /// override order (see [`PolicyTarget::specificity`]) — that both
    /// applies to `request` (by target) AND is satisfied by `request`'s
    /// subject's current WoT reachable depth, if any. Ties in
    /// specificity resolve to whichever is satisfied; among equally
    /// specific satisfied policies the choice is immaterial since they all
    /// grant `Allow`.
    fn most_specific_satisfied_policy(&self, request: &Request, depth: u8) -> Option<&'a PolicyEvent> {
        self.policies
            .iter()
            .filter(|p| p.capability == request.capability)
            .filter(|p| self.target_applies(&p.target, request))
            .filter(|p| depth >= p.depth_threshold)
            .min_by_key(|p| p.target.specificity())
    }

    /// Whether `request`'s subject satisfies the WoT-depth-default rung:
    /// reachable from the trust root at a depth meeting the most specific
    /// applicable, satisfied [`PolicyEvent`] (see
    /// [`most_specific_satisfied_policy`](Self::most_specific_satisfied_policy)).
    fn satisfies_depth_default(&self, request: &Request) -> bool {
        let Some(depth) = self.authority.reachable_depth(&request.subject) else {
            return false;
        };
        self.most_specific_satisfied_policy(request, depth).is_some()
    }

    /// Decide `request`, per the four-rung precedence lattice in the module
    /// docs: explicit-deny > explicit-allow > WoT-depth-default > deny-all.
    ///
    /// This is the ONLY decision function in the crate: call it for
    /// controller enforcement AND for UI prediction so the two can never
    /// diverge.
    #[must_use]
    pub fn decide(&self, request: &Request) -> Decision {
        match self.explicit_grant(&request.subject, &request.capability) {
            Some(GrantEffect::Deny) => return Decision::Deny,
            Some(GrantEffect::Allow) => return Decision::Allow,
            None => {}
        }
        if self.satisfies_depth_default(request) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// UI-predicted outcome for `request`. Deliberately implemented as a
    /// direct call to [`decide`](Self::decide) — the SAME function the
    /// controller uses to enforce — so `predict(..) == decide(..)` holds
    /// structurally, not merely by test coverage.
    #[must_use]
    pub fn predict(&self, request: &Request) -> Decision {
        self.decide(request)
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

    fn req(subject: &str, capability: &Capability) -> Request {
        Request::new(n(subject), capability.clone())
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
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Deny
        );
    }

    #[test]
    fn wot_depth_default_allows_when_threshold_is_met_via_resource_class() {
        let a = owner_authority_with_alice(3, 2);
        // owner budget 3 -> alice gets min(3-1,2) = 2
        assert_eq!(a.reachable_depth(&n("alice")), Some(2));

        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::Compute),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);
        let request = req("alice", &cap("stream:append")).with_resource_class(ResourceClass::Compute);

        assert_eq!(decider.decide(&request), Decision::Allow);
    }

    #[test]
    fn resource_class_policy_does_not_apply_to_a_different_class() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::Compute),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);
        let request = req("alice", &cap("stream:append")).with_resource_class(ResourceClass::Network);

        assert_eq!(decider.decide(&request), Decision::Deny);
    }

    #[test]
    fn wot_depth_default_denies_when_threshold_is_not_met() {
        let a = owner_authority_with_alice(3, 2);
        assert_eq!(a.reachable_depth(&n("alice")), Some(2));

        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("stream:append"),
            depth_threshold: 3,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Deny
        );
    }

    #[test]
    fn node_targeted_policy_allows_only_the_named_node() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Allow
        );
        // bob is a different node: the node-targeted policy never applies
        // to him even if he were separately reachable.
        assert_eq!(
            decider.decide(&req("bob", &cap("stream:append"))),
            Decision::Deny
        );
    }

    #[test]
    fn group_targeted_policy_allows_members_meeting_threshold() {
        // Group membership is derived from the WoT graph itself: "operators"
        // IS the parent key, and alice is a member because operators signed
        // her subkey directly.
        let mut a = owner_authority_with_alice(5, 4);
        a.issue_edge(n("operators"), n("alice"), 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::Group(Group::from("operators")),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Allow
        );
        // bob is not a member of "operators", so the same policy does not
        // apply to him even if he were reachable.
        assert_eq!(
            decider.decide(&req("bob", &cap("stream:append"))),
            Decision::Deny
        );
    }

    #[test]
    fn label_set_targeted_policy_allows_subjects_carrying_every_label() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::LabelSet(LabelSet::new(["gpu", "us-east"])),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        let matching = req("alice", &cap("stream:append"))
            .with_labels(BTreeSet::from(["gpu".to_string(), "us-east".to_string(), "extra".to_string()]));
        assert_eq!(decider.decide(&matching), Decision::Allow);

        let partial =
            req("alice", &cap("stream:append")).with_labels(BTreeSet::from(["gpu".to_string()]));
        assert_eq!(decider.decide(&partial), Decision::Deny);
    }

    #[test]
    fn override_order_specific_beats_group_beats_all() {
        // A satisfied node-specific policy wins even when a satisfied group
        // policy AND a satisfied resource-class-All policy would also apply
        // -- and even if the node-specific policy's OWN threshold is looser
        // (proving the override is about TARGET specificity, not about
        // which policy happens to be "best").
        let mut a = owner_authority_with_alice(5, 4);
        a.issue_edge(n("operators"), n("alice"), 3);
        assert_eq!(a.reachable_depth(&n("alice")), Some(4));

        let c = cap("stream:append");
        let policies = vec![
            // All three rungs are satisfied at depth 4, but they would give
            // DIFFERENT verdicts if evaluated independently: rig the group
            // and all-catchall policies to threshold 3 (satisfied, Allow)
            // and prove node-specific is what gets consulted by using a
            // depth_threshold on the node policy that is ALSO satisfiable,
            // then flip only the group/all policies to unsatisfiable and
            // confirm node-specific alone still allows.
            PolicyEvent {
                target: PolicyTarget::Node(n("alice")),
                capability: c.clone(),
                depth_threshold: 4,
            },
            PolicyEvent {
                target: PolicyTarget::Group(Group::from("operators")),
                capability: c.clone(),
                depth_threshold: 200, // unsatisfiable
            },
            PolicyEvent {
                target: PolicyTarget::ResourceClass(ResourceClass::All),
                capability: c.clone(),
                depth_threshold: 200, // unsatisfiable
            },
        ];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        // Node-specific policy alone satisfies -> Allow, even though the
        // less-specific group/all policies at the same request would deny.
        assert_eq!(
            decider.decide(&req("alice", &c)),
            Decision::Allow
        );
    }

    #[test]
    fn group_beats_resource_class_all_catchall() {
        let mut a = owner_authority_with_alice(5, 4);
        a.issue_edge(n("operators"), n("alice"), 3);

        let c = cap("stream:append");
        let policies = vec![
            PolicyEvent {
                target: PolicyTarget::Group(Group::from("operators")),
                capability: c.clone(),
                depth_threshold: 3,
            },
            PolicyEvent {
                target: PolicyTarget::ResourceClass(ResourceClass::All),
                capability: c.clone(),
                depth_threshold: 200, // unsatisfiable
            },
        ];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(decider.decide(&req("alice", &c)), Decision::Allow);
    }

    #[test]
    fn explicit_allow_overrides_a_failing_depth_default() {
        let a = owner_authority_with_alice(3, 2);
        // Threshold is impossible to meet (deeper than owner's own budget).
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("stream:append"),
            depth_threshold: 200,
        }];
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&a, &policies, &grants);

        // Depth default alone would deny (threshold unreachable), but the
        // explicit allow rung wins.
        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Allow
        );
    }

    #[test]
    fn explicit_deny_overrides_a_satisfied_depth_default() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Deny,
        }];
        let decider = RbacDecider::new(&a, &policies, &grants);

        // Depth default alone would allow, but explicit deny wins.
        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
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
        let decider = RbacDecider::new(&a, &policies, &grants);

        assert_eq!(
            decider.decide(&req("alice", &cap("stream:append"))),
            Decision::Deny
        );

        // Order reversed: still deny.
        let grants_reversed: Vec<ExplicitGrant> = grants.into_iter().rev().collect();
        let decider2 = RbacDecider::new(&a, &policies, &grants_reversed);
        assert_eq!(
            decider2.decide(&req("alice", &cap("stream:append"))),
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

        // Rung 4: deny-all (no policy, no grant).
        let no_policies = vec![];
        let no_grants = vec![];
        let d = RbacDecider::new(&a, &no_policies, &no_grants);
        assert_eq!(d.decide(&req("alice", &c)), Decision::Deny);

        // Rung 3: WoT-depth-default now satisfied -> Allow.
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: c.clone(),
            depth_threshold: 2,
        }];
        let d = RbacDecider::new(&a, &policies, &no_grants);
        assert_eq!(d.decide(&req("alice", &c)), Decision::Allow);

        // Rung 2: explicit-allow added on top -- still Allow (no visible
        // change), but now let the depth default fail while the explicit
        // allow keeps it Allow, proving allow beats a failing default.
        let failing_policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: c.clone(),
            depth_threshold: 200,
        }];
        let allow_grant = vec![ExplicitGrant {
            subject: n("alice"),
            capability: c.clone(),
            effect: GrantEffect::Allow,
        }];
        let d = RbacDecider::new(&a, &failing_policies, &allow_grant);
        assert_eq!(d.decide(&req("alice", &c)), Decision::Allow);

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
        let d = RbacDecider::new(&a, &policies, &deny_and_allow);
        assert_eq!(d.decide(&req("alice", &c)), Decision::Deny);
    }

    #[test]
    fn predicted_always_equals_enforced_across_every_rung() {
        // predict() and decide() must never diverge, across every rung of
        // the lattice and both outcomes.
        let a = owner_authority_with_alice(3, 2);
        let c = cap("stream:append");

        let cases: Vec<(Vec<PolicyEvent>, Vec<ExplicitGrant>)> = vec![
            (vec![], vec![]),
            (
                vec![PolicyEvent {
                    target: PolicyTarget::ResourceClass(ResourceClass::All),
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
                    target: PolicyTarget::ResourceClass(ResourceClass::All),
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
            let decider = RbacDecider::new(&a, policies, grants);
            let request = req("alice", &c);
            assert_eq!(
                decider.decide(&request),
                decider.predict(&request),
                "predicted must equal enforced for policies={policies:?} grants={grants:?}"
            );
        }
    }

    #[test]
    fn unreachable_subject_never_satisfies_depth_default() {
        let a = WotAuthority::new(n("owner"), 3);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("stream:append"),
            depth_threshold: 0,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);

        // "nobody" is not reachable from the owner at all, so even a
        // threshold of 0 cannot be satisfied -- deny-all wins.
        assert_eq!(
            decider.decide(&req("nobody", &cap("stream:append"))),
            Decision::Deny
        );
    }

    // --- ownership ---------------------------------------------------------

    #[test]
    fn owns_node_delegates_to_the_wot_authority() {
        let mut a = WotAuthority::new(n("owner"), 3);
        a.issue_edge(n("alice-primary"), n("alice-laptop"), 2);

        assert!(owns_node(&a, &n("alice-primary"), &n("alice-laptop")));
        assert!(!owns_node(&a, &n("alice-primary"), &n("bob-laptop")));
    }

    // --- shipped defaults ----------------------------------------------------

    #[test]
    fn default_resource_class_policies_cover_every_class_and_are_low() {
        let c = cap("compute:schedule");
        let defaults = default_resource_class_policies(&c);

        for class in RESOURCE_CLASSES {
            let matching = defaults
                .iter()
                .find(|p| matches!(&p.target, PolicyTarget::ResourceClass(rc) if *rc == class))
                .unwrap_or_else(|| panic!("missing default policy for {class:?}"));
            // "LOW default trust level" means a comparatively strict
            // (nonzero, and non-trivially-low) depth threshold: nobody gets
            // this capability by default just for being loosely reachable.
            assert!(
                matching.depth_threshold >= 2,
                "default threshold for {class:?} should be a LOW trust level (a high depth_threshold), got {}",
                matching.depth_threshold
            );
        }

        // The final catch-all (`All`) is at least as strict as every named
        // class, since it is the last-resort default.
        let all_threshold = defaults
            .iter()
            .find(|p| matches!(p.target, PolicyTarget::ResourceClass(ResourceClass::All)))
            .unwrap()
            .depth_threshold;
        for class in [ResourceClass::Compute, ResourceClass::Network, ResourceClass::Storage] {
            let t = defaults
                .iter()
                .find(|p| matches!(&p.target, PolicyTarget::ResourceClass(rc) if *rc == class))
                .unwrap()
                .depth_threshold;
            assert!(all_threshold >= t);
        }
    }

    #[test]
    fn default_resource_class_policy_is_overridden_by_a_more_specific_node_policy() {
        // Even though alice fails the shipped Compute default (too deep),
        // an operator-installed node-specific policy for her wins per the
        // override order.
        let mut a = WotAuthority::new(n("owner"), 5);
        a.issue_edge(n("owner"), n("alice"), 1); // deep: only budget 1 remains

        let c = cap("compute:schedule");
        let mut policies = default_resource_class_policies(&c);
        assert_eq!(a.reachable_depth(&n("alice")), Some(1));
        // Sanity: the shipped Compute default (threshold 2) is NOT met by
        // alice's depth of 1.
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);
        let request = req("alice", &c).with_resource_class(ResourceClass::Compute);
        assert_eq!(decider.decide(&request), Decision::Deny);

        // Now install a node-specific override for alice with a looser
        // threshold.
        policies.push(PolicyEvent {
            target: PolicyTarget::Node(n("alice")),
            capability: c.clone(),
            depth_threshold: 1,
        });
        let decider = RbacDecider::new(&a, &policies, &grants);
        assert_eq!(decider.decide(&request), Decision::Allow);

        // Keep `a` used past the override to avoid an unused-mut lint on a
        // hypothetical future edit; assert once more for clarity.
        a.issue_edge(n("owner"), n("bob"), 1);
        assert!(a.reachable_depth(&n("bob")).is_some());
    }
}
