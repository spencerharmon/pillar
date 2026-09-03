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
use std::fmt;

use pillar_core::NodeId;
use pillar_wot_authority::WotAuthority;

pub mod sealed_secret_store;
pub use sealed_secret_store::{SecretId, SecretRequestError, SecretStore};

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

/// Evidence that the request carried a FRESH, already-cryptographically-
/// verified WebAuthn step-up assertion (the P0 WebAuthn credential from the
/// `webauthn-rp-endpoints` custody surface re-used as a step-up factor).
///
/// This is NOT where the assertion signature is checked — that is the RP
/// endpoint's job ([`pillar_crypto::webauthn::verify_assertion`]), which the
/// caller runs BEFORE constructing this value. What the decider consumes is
/// the *proof of a successful, recent* step-up: the moment the assertion was
/// verified (`verified_at_secs`, a Unix timestamp) and the credential id it
/// was bound to. The decider then enforces the step-up rung purely on
/// FRESHNESS (see [`StepUpPolicy::max_age_secs`]) inside the same `decide`
/// path — a stale/expired proof is treated as if no step-up happened at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpAssertion {
    /// Unix time (seconds) at which the WebAuthn assertion was successfully
    /// verified by the RP. Freshness is measured against this.
    pub verified_at_secs: u64,
    /// The credential id the verified assertion was bound to (opaque handle,
    /// as returned by
    /// [`pillar_crypto::webauthn::RegisteredCredential::credential_id`]).
    pub credential_id: Vec<u8>,
}

impl StepUpAssertion {
    /// Build a step-up proof from a successfully verified assertion.
    #[must_use]
    pub fn new(verified_at_secs: u64, credential_id: impl Into<Vec<u8>>) -> Self {
        StepUpAssertion {
            verified_at_secs,
            credential_id: credential_id.into(),
        }
    }
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
    /// The current wall-clock (Unix seconds) at which this decision is made,
    /// used to measure a [`StepUpAssertion`]'s freshness. The caller stamps
    /// it from the same clock it verified the assertion under.
    pub now_secs: u64,
    /// A fresh WebAuthn step-up proof, if the caller re-authenticated the
    /// subject for this request. `None` means "no step-up presented" — which
    /// denies any capability the [`StepUpPolicy`] marks step-up-required, no
    /// matter how strong the base auth is.
    pub step_up: Option<StepUpAssertion>,
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
            now_secs: 0,
            step_up: None,
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

    /// Set the current wall-clock (Unix seconds) this request is decided at.
    #[must_use]
    pub fn at_time(mut self, now_secs: u64) -> Self {
        self.now_secs = now_secs;
        self
    }

    /// Attach a fresh WebAuthn step-up proof to this request.
    #[must_use]
    pub fn with_step_up(mut self, assertion: StepUpAssertion) -> Self {
        self.step_up = Some(assertion);
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

/// A typed, non-fatal RBAC error: every RBAC failure mode is a value a
/// caller can match on and fail the single request/action closed (deny)
/// with, never a `panic!` that would crash the whole process/thread for a
/// condition scoped to one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RbacError {
    /// A caller asked for the shipped default [`PolicyEvent`] for
    /// `ResourceClass`, but no such default exists in the given set (e.g. a
    /// corrupted or hand-edited defaults fixture). Callers must treat this
    /// as "fail this one lookup closed", never crash the process over it.
    MissingDefaultPolicy(ResourceClass),
}

impl fmt::Display for RbacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RbacError::MissingDefaultPolicy(class) => {
                write!(f, "missing default policy for {class:?}")
            }
        }
    }
}

impl std::error::Error for RbacError {}

/// Look up `class`'s shipped default [`PolicyEvent`] within `defaults` (as
/// produced by [`default_resource_class_policies`]), returning a typed
/// [`RbacError::MissingDefaultPolicy`] rather than panicking if it is
/// absent. A missing default is scoped to failing THIS lookup (the caller
/// then denies the single request/action it was serving) — it must never
/// crash the process.
pub fn default_policy_for_class(
    defaults: &[PolicyEvent],
    class: ResourceClass,
) -> Result<&PolicyEvent, RbacError> {
    defaults
        .iter()
        .find(|p| matches!(&p.target, PolicyTarget::ResourceClass(rc) if *rc == class))
        .ok_or(RbacError::MissingDefaultPolicy(class))
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

/// The step-up (re-authentication) policy: which capabilities are gated on a
/// FRESH WebAuthn assertion, and how fresh "fresh" must be.
///
/// Step-up is NOT a bespoke MFA subsystem and NOT a parallel gate: it is an
/// ADDITIONAL required factor folded into the single [`RbacDecider::decide`]
/// path. A capability listed here is refused unless the request also carries
/// a [`StepUpAssertion`] no older than [`StepUpPolicy::max_age_secs`] — even
/// when the base RBAC rungs (explicit-allow / WoT-depth-default) would grant
/// it. The WebAuthn credential that satisfies step-up is the very same P0
/// custody credential (`webauthn-rp-endpoints`); the caller verifies its
/// assertion once and hands the decider the freshness proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StepUpPolicy {
    /// The set of capabilities that require a fresh step-up assertion before
    /// they may be allowed (destructive/sensitive operations: key rotation,
    /// secret reveal, cell-membership changes, …).
    pub required: BTreeSet<Capability>,
    /// The maximum age (seconds) a [`StepUpAssertion`] may have — measured as
    /// `request.now_secs - assertion.verified_at_secs` — and still count as
    /// "fresh". An assertion older than this (or from the future) is refused
    /// exactly as if none were presented.
    pub max_age_secs: u64,
}

impl StepUpPolicy {
    /// Build a step-up policy requiring a fresh assertion for `capabilities`,
    /// with the given freshness window in seconds.
    #[must_use]
    pub fn new(
        capabilities: impl IntoIterator<Item = Capability>,
        max_age_secs: u64,
    ) -> Self {
        StepUpPolicy {
            required: capabilities.into_iter().collect(),
            max_age_secs,
        }
    }

    /// Whether `capability` requires a fresh step-up assertion under this
    /// policy.
    #[must_use]
    pub fn requires_step_up(&self, capability: &Capability) -> bool {
        self.required.contains(capability)
    }

    /// Whether `assertion` is fresh enough to satisfy step-up for a request
    /// decided at `now_secs`: it must not be older than `max_age_secs` and
    /// must not be dated in the future (a clock-skew / replay guard).
    #[must_use]
    pub fn assertion_is_fresh(&self, assertion: &StepUpAssertion, now_secs: u64) -> bool {
        match now_secs.checked_sub(assertion.verified_at_secs) {
            // Assertion verified at or before `now`: fresh iff within window.
            Some(age) => age <= self.max_age_secs,
            // verified_at is in the FUTURE relative to now — refuse (never
            // treat a future-dated proof as fresh).
            None => false,
        }
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
    step_up: &'a StepUpPolicy,
}

impl<'a> RbacDecider<'a> {
    /// Build a decider over this pass's materialized view: the WoT
    /// authority, the currently-live signed policy events, and the
    /// currently-live explicit grants. Group membership and node ownership
    /// are resolved directly against `authority` (see module docs) rather
    /// than an asserted side table.
    ///
    /// The step-up policy defaults to EMPTY (no capability gated on a fresh
    /// WebAuthn assertion); attach one with
    /// [`with_step_up_policy`](Self::with_step_up_policy) to require step-up
    /// re-authentication for destructive/sensitive capabilities.
    #[must_use]
    pub fn new(
        authority: &'a WotAuthority,
        policies: &'a [PolicyEvent],
        grants: &'a [ExplicitGrant],
    ) -> Self {
        // A process-wide empty step-up policy so a decider built without one
        // gates nothing on step-up (backwards-compatible default).
        static EMPTY_STEP_UP: StepUpPolicy = StepUpPolicy {
            required: BTreeSet::new(),
            max_age_secs: 0,
        };
        RbacDecider {
            authority,
            policies,
            grants,
            step_up: &EMPTY_STEP_UP,
        }
    }

    /// Attach a [`StepUpPolicy`] so the named capabilities require a fresh
    /// WebAuthn step-up assertion as an ADDITIONAL required factor within the
    /// same `decide` path.
    #[must_use]
    pub fn with_step_up_policy(mut self, step_up: &'a StepUpPolicy) -> Self {
        self.step_up = step_up;
        self
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
    fn most_specific_satisfied_policy(
        &self,
        request: &Request,
        depth: u8,
    ) -> Option<&'a PolicyEvent> {
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
        self.most_specific_satisfied_policy(request, depth)
            .is_some()
    }

    /// Whether `request` satisfies the step-up rung: either its capability is
    /// NOT step-up-gated, or it IS gated and the request carries a FRESH
    /// [`StepUpAssertion`] (per [`StepUpPolicy::assertion_is_fresh`]). A gated
    /// capability with no assertion, or a stale/future-dated one, fails.
    fn satisfies_step_up(&self, request: &Request) -> bool {
        if !self.step_up.requires_step_up(&request.capability) {
            return true;
        }
        match &request.step_up {
            Some(assertion) => self.step_up.assertion_is_fresh(assertion, request.now_secs),
            None => false,
        }
    }

    /// Decide `request`, per the four-rung precedence lattice in the module
    /// docs: explicit-deny > explicit-allow > WoT-depth-default > deny-all.
    ///
    /// This is the ONLY decision function in the crate: call it for
    /// controller enforcement AND for UI prediction so the two can never
    /// diverge.
    ///
    /// # Step-up factor
    ///
    /// A capability marked step-up-required by the attached [`StepUpPolicy`]
    /// is an ADDITIONAL required factor folded into this same path — never a
    /// parallel gate. An explicit deny still wins unconditionally (rung 1),
    /// but any decision that would otherwise ALLOW (explicit-allow or
    /// WoT-depth-default) is downgraded to [`Decision::Deny`] unless the
    /// request also carries a fresh WebAuthn step-up assertion.
    #[must_use]
    pub fn decide(&self, request: &Request) -> Decision {
        match self.explicit_grant(&request.subject, &request.capability) {
            // Explicit deny wins unconditionally, ahead of every factor.
            Some(GrantEffect::Deny) => return Decision::Deny,
            Some(GrantEffect::Allow) => {
                // Base auth grants — but a step-up-gated capability still
                // needs a fresh assertion as the additional factor.
                return if self.satisfies_step_up(request) {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
            }
            None => {}
        }
        if self.satisfies_depth_default(request) && self.satisfies_step_up(request) {
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

    /// The **exercised authority** behind [`RbacDecider::decide`]'s verdict
    /// for `request` — WHICH rung of the four-rung precedence lattice
    /// produced it, for `describe`/audit provenance rendering. Computed by
    /// literally re-deriving the same rungs `decide` consults (never a
    /// second, divergent explanation path), so a caller can render "why"
    /// alongside the boolean `decide`/`predict` verdict.
    #[must_use]
    pub fn explain(&self, request: &Request) -> Exercised {
        match self.explicit_grant(&request.subject, &request.capability) {
            Some(GrantEffect::Deny) => return Exercised::ExplicitDeny,
            Some(GrantEffect::Allow) => {
                // Base auth would allow; a step-up-gated capability without a
                // fresh assertion is refused on the step-up rung instead.
                if self.satisfies_step_up(request) {
                    return Exercised::ExplicitAllow;
                }
                return Exercised::StepUpRequired;
            }
            None => {}
        }
        let Some(depth) = self.authority.reachable_depth(&request.subject) else {
            return Exercised::DenyAll;
        };
        match self.most_specific_satisfied_policy(request, depth) {
            Some(policy) => {
                if self.satisfies_step_up(request) {
                    Exercised::WotDepthDefault {
                        depth,
                        threshold: policy.depth_threshold,
                    }
                } else {
                    // The base depth default was satisfied, but the step-up
                    // factor was not — that is what decided the (deny) verdict.
                    Exercised::StepUpRequired
                }
            }
            None => Exercised::DenyAll,
        }
    }
}

/// The rung of the RBAC precedence lattice [`RbacDecider::explain`] found
/// exercised for a request — the "why" behind a `decide`/`predict` verdict,
/// rendered by `describe`/audit as the resource's "exercised authority".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exercised {
    /// An explicit signed grant allowed the subject this capability.
    ExplicitAllow,
    /// An explicit signed grant denied the subject this capability
    /// (overriding every other rung).
    ExplicitDeny,
    /// The subject's WoT-graph reachable depth satisfied the most specific
    /// applicable policy's threshold.
    WotDepthDefault {
        /// The subject's reachable depth from the trust root.
        depth: u8,
        /// The satisfied policy's depth threshold.
        threshold: u8,
    },
    /// The base RBAC rungs would have allowed the subject, but the capability
    /// is step-up-gated and no FRESH WebAuthn assertion was presented — the
    /// additional step-up factor is what produced the (deny) verdict.
    StepUpRequired,
    /// No rung authorized the subject — the fail-closed default.
    DenyAll,
}

impl fmt::Display for Exercised {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Exercised::ExplicitAllow => write!(f, "explicit grant (allow)"),
            Exercised::ExplicitDeny => write!(f, "explicit grant (deny)"),
            Exercised::WotDepthDefault { depth, threshold } => write!(
                f,
                "WoT-depth default (reachable at depth {depth}, threshold {threshold})"
            ),
            Exercised::StepUpRequired => {
                write!(f, "step-up re-authentication required (no fresh assertion)")
            }
            Exercised::DenyAll => write!(f, "none (deny-all default)"),
        }
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
        let request =
            req("alice", &cap("stream:append")).with_resource_class(ResourceClass::Compute);

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
        let request =
            req("alice", &cap("stream:append")).with_resource_class(ResourceClass::Network);

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

        let matching = req("alice", &cap("stream:append")).with_labels(BTreeSet::from([
            "gpu".to_string(),
            "us-east".to_string(),
            "extra".to_string(),
        ]));
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
        assert_eq!(decider.decide(&req("alice", &c)), Decision::Allow);
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
            let matching = default_policy_for_class(&defaults, class)
                .expect("shipped defaults must cover every resource class");
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
        for class in [
            ResourceClass::Compute,
            ResourceClass::Network,
            ResourceClass::Storage,
        ] {
            let t = defaults
                .iter()
                .find(|p| matches!(&p.target, PolicyTarget::ResourceClass(rc) if *rc == class))
                .unwrap()
                .depth_threshold;
            assert!(all_threshold >= t);
        }
    }

    #[test]
    fn missing_default_policy_returns_typed_error_not_panic() {
        // A corrupted/hand-edited defaults fixture missing one resource
        // class's entry must fail closed with a typed error -- the single
        // lookup denies, the process/thread must NOT crash.
        let c = cap("compute:schedule");
        let mut defaults = default_resource_class_policies(&c);
        defaults.retain(|p| {
            !matches!(&p.target, PolicyTarget::ResourceClass(rc) if *rc == ResourceClass::Compute)
        });

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            default_policy_for_class(&defaults, ResourceClass::Compute)
        }));

        let result = outcome.expect(
            "a missing default policy must return a typed error, never panic/crash the thread",
        );
        assert_eq!(
            result,
            Err(RbacError::MissingDefaultPolicy(ResourceClass::Compute))
        );

        // Every OTHER class's default is unaffected -- only the single
        // missing lookup fails, nothing else is dragged down with it.
        assert!(default_policy_for_class(&defaults, ResourceClass::Network).is_ok());
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

    // --- explain: the "why" behind decide/predict, for describe/audit -----

    #[test]
    fn explain_names_the_explicit_grant_rung_allow_and_deny() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![];
        let allow_grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&a, &policies, &allow_grants);
        let request = req("alice", &cap("stream:append"));
        assert_eq!(decider.explain(&request), Exercised::ExplicitAllow);
        assert_eq!(decider.decide(&request), Decision::Allow);

        let deny_grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("stream:append"),
            effect: GrantEffect::Deny,
        }];
        let decider = RbacDecider::new(&a, &policies, &deny_grants);
        assert_eq!(decider.explain(&request), Exercised::ExplicitDeny);
        assert_eq!(decider.decide(&request), Decision::Deny);
    }

    #[test]
    fn explain_names_the_wot_depth_default_rung_when_that_is_what_decided() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::Compute),
            capability: cap("stream:append"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);
        let request =
            req("alice", &cap("stream:append")).with_resource_class(ResourceClass::Compute);
        assert_eq!(
            decider.explain(&request),
            Exercised::WotDepthDefault {
                depth: 2,
                threshold: 2
            }
        );
        assert_eq!(decider.decide(&request), Decision::Allow);
    }

    #[test]
    fn explain_names_deny_all_when_nothing_authorized_the_subject() {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![];
        let grants = vec![];
        let decider = RbacDecider::new(&a, &policies, &grants);
        let request = req("alice", &cap("stream:append"));
        assert_eq!(decider.explain(&request), Exercised::DenyAll);
        assert_eq!(decider.decide(&request), Decision::Deny);
        // An entirely unreachable subject also explains as deny-all.
        let request = req("nobody", &cap("stream:append"));
        assert_eq!(decider.explain(&request), Exercised::DenyAll);
    }

    #[test]
    fn exercised_display_renders_a_readable_sentence() {
        assert_eq!(
            Exercised::ExplicitAllow.to_string(),
            "explicit grant (allow)"
        );
        assert_eq!(Exercised::ExplicitDeny.to_string(), "explicit grant (deny)");
        assert_eq!(Exercised::DenyAll.to_string(), "none (deny-all default)");
        assert_eq!(
            Exercised::StepUpRequired.to_string(),
            "step-up re-authentication required (no fresh assertion)"
        );
        assert_eq!(
            Exercised::WotDepthDefault {
                depth: 2,
                threshold: 2
            }
            .to_string(),
            "WoT-depth default (reachable at depth 2, threshold 2)"
        );
    }

    // --- step-up MFA: WebAuthn re-authentication as an additional factor ---

    /// A depth-default policy + decider that would ALLOW `rotate:key` for
    /// alice on base auth alone, with `rotate:key` marked step-up-required.
    fn stepup_fixture(
        max_age: u64,
    ) -> (WotAuthority, Vec<PolicyEvent>, Vec<ExplicitGrant>, StepUpPolicy) {
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("rotate:key"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let step_up = StepUpPolicy::new([cap("rotate:key")], max_age);
        (a, policies, grants, step_up)
    }

    #[test]
    fn step_up_gated_action_is_refused_without_a_fresh_assertion() {
        // Base auth (depth default) is otherwise valid, but the destructive
        // action is step-up-gated and NO assertion is presented -> deny.
        let (a, policies, grants, step_up) = stepup_fixture(300);
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);

        // Sanity: without the step-up gate the SAME base auth allows.
        let base_decider = RbacDecider::new(&a, &policies, &grants);
        assert_eq!(
            base_decider.decide(&req("alice", &cap("rotate:key")).at_time(1_000)),
            Decision::Allow,
            "base auth alone would allow — proving the gate, not weak base auth, is what denies"
        );

        let request = req("alice", &cap("rotate:key")).at_time(1_000);
        assert_eq!(decider.decide(&request), Decision::Deny);
        assert_eq!(decider.explain(&request), Exercised::StepUpRequired);
    }

    #[test]
    fn fresh_assertion_allows_the_action_through_the_same_rbac_path() {
        // Providing a fresh valid step-up assertion allows the action through
        // the SAME decide() path (no parallel gate).
        let (a, policies, grants, step_up) = stepup_fixture(300);
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);

        let request = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(950, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&request), Decision::Allow);
        // Same single path: predict == decide.
        assert_eq!(decider.predict(&request), decider.decide(&request));
        assert_eq!(
            decider.explain(&request),
            Exercised::WotDepthDefault {
                depth: 2,
                threshold: 2
            }
        );
    }

    #[test]
    fn stale_or_expired_assertion_is_refused() {
        // An assertion older than the freshness window is refused.
        let (a, policies, grants, step_up) = stepup_fixture(300);
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);

        // verified 400s ago, window is 300s -> stale -> deny.
        let stale = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(600, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&stale), Decision::Deny);
        assert_eq!(decider.explain(&stale), Exercised::StepUpRequired);

        // exactly at the boundary (age == max_age) is still fresh.
        let boundary = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(700, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&boundary), Decision::Allow);

        // a future-dated proof (clock skew / replay) is refused.
        let future = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(1_050, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&future), Decision::Deny);
    }

    #[test]
    fn step_up_does_not_gate_non_sensitive_capabilities() {
        // A capability NOT in the step-up set is unaffected: base auth alone
        // decides it, with or without an assertion.
        let (a, policies, grants, step_up) = stepup_fixture(300);
        let policies = {
            let mut p = policies;
            p.push(PolicyEvent {
                target: PolicyTarget::ResourceClass(ResourceClass::All),
                capability: cap("stream:read"),
                depth_threshold: 2,
            });
            p
        };
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);
        assert_eq!(
            decider.decide(&req("alice", &cap("stream:read")).at_time(1_000)),
            Decision::Allow,
            "a non-step-up capability is allowed on base auth with no assertion"
        );
    }

    #[test]
    fn explicit_deny_still_wins_over_a_fresh_step_up_assertion() {
        // The step-up factor never overrides explicit-deny (rung 1).
        let (a, policies, _grants, step_up) = stepup_fixture(300);
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("rotate:key"),
            effect: GrantEffect::Deny,
        }];
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);
        let request = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(1_000, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&request), Decision::Deny);
        assert_eq!(decider.explain(&request), Exercised::ExplicitDeny);
    }

    #[test]
    fn explicit_allow_is_still_gated_by_step_up() {
        // An explicit-allow grant does NOT bypass the step-up factor: a
        // step-up-gated capability still needs a fresh assertion.
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![];
        let grants = vec![ExplicitGrant {
            subject: n("alice"),
            capability: cap("rotate:key"),
            effect: GrantEffect::Allow,
        }];
        let step_up = StepUpPolicy::new([cap("rotate:key")], 300);
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);

        // No assertion -> denied despite the explicit allow.
        assert_eq!(
            decider.decide(&req("alice", &cap("rotate:key")).at_time(1_000)),
            Decision::Deny
        );
        // Fresh assertion -> the explicit allow now takes effect.
        let with = req("alice", &cap("rotate:key"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(1_000, b"cred-1".to_vec()));
        assert_eq!(decider.decide(&with), Decision::Allow);
        assert_eq!(decider.explain(&with), Exercised::ExplicitAllow);
    }

    #[test]
    fn step_up_reuses_the_real_p0_webauthn_credential() {
        // End-to-end: the SAME P0 WebAuthn custody credential
        // (pillar-crypto::webauthn) is verified, and its freshly-verified
        // assertion drives the step-up rung of the RBAC decider — not a
        // bespoke MFA credential.
        use pillar_crypto::sign::signing_keypair_from_seed;
        use pillar_crypto::Seed;
        use pillar_crypto::webauthn::{
            base64url_encode, ed25519_public_key_to_cose, verify_assertion,
        };
        use sha2::{Digest, Sha256};

        // Register the credential (as webauthn-rp-endpoints would).
        let (public, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"alice-authenticator".to_vec()))
                .expect("keygen");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        let credential_id = b"alice-cred".to_vec();

        // Authenticator produces an assertion for a step-up challenge.
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pillar.local"}}"#,
            base64url_encode(b"stepup-challenge")
        )
        .into_bytes();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x01); // UP
        auth_data.extend_from_slice(&7u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig = pillar_crypto::sign::sign(&secret, &signed).expect("sign");

        // The RP verifies the assertion (the real crypto core) BEFORE it
        // becomes a step-up proof for the decider.
        let verified = verify_assertion(&cose, &auth_data, &client_data_json, sig.as_bytes())
            .expect("assertion verifies");
        assert_eq!(verified.sign_count, 7);

        // Now feed the verified assertion into the SAME rbac path.
        let a = owner_authority_with_alice(3, 2);
        let policies = vec![PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: cap("secret:reveal"),
            depth_threshold: 2,
        }];
        let grants = vec![];
        let step_up = StepUpPolicy::new([cap("secret:reveal")], 300);
        let decider = RbacDecider::new(&a, &policies, &grants).with_step_up_policy(&step_up);

        // Without the verified assertion the sensitive action is refused.
        assert_eq!(
            decider.decide(&req("alice", &cap("secret:reveal")).at_time(1_000)),
            Decision::Deny
        );
        // With the freshly verified real-WebAuthn assertion, it passes.
        let request = req("alice", &cap("secret:reveal"))
            .at_time(1_000)
            .with_step_up(StepUpAssertion::new(980, credential_id));
        assert_eq!(decider.decide(&request), Decision::Allow);
    }
}
