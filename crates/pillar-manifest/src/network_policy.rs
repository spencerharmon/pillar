//! Network policy controller (ROI Priority 0, Tier 3, OPTIONAL).
//!
//! Allow/deny network policy between cells/workloads, WoT + RBAC gated,
//! riding the SAME controller interface [`crate::builtin`] gives every
//! built-in kind: a `NetworkPolicy`-shaped [`Crd`] is validated against an
//! ordinary [`Schema`] registered into a [`crate::SchemaRegistry`] and
//! reconciled through an ordinary [`ControllerHook`] registered into a
//! [`ControllerRegistry`] — no special-cased dispatch path. Exactly like
//! [`crate::tls_cert`], `NetworkPolicy` is deliberately NOT part of
//! [`crate::builtin::BuiltinKind::ALL`]: it is Tier 3 and OPTIONAL, so a
//! cell that never registers its hook must boot and operate normally —
//! **unrestricted by default** — the [`ControllerRegistry::dispatch`]
//! absence-returns-`None` contract already guarantees that.
//!
//! # The gate
//!
//! An allow/deny connection decision between two workloads/cells is gated
//! on TWO independent, already-existing authorities — never a parallel
//! authorization path:
//!
//! - **RBAC** ([`pillar_rbac::RbacDecider`]) — the connecting subject must
//!   be decided [`pillar_rbac::Decision::Allow`] for the `net:connect`
//!   capability under [`pillar_rbac::ResourceClass::Network`]. This reuses
//!   the SAME decider (and therefore the same WoT-depth-default /
//!   explicit-grant precedence lattice) every other controller enforces
//!   with — the WoT check is folded into this single RBAC computation
//!   rather than a second, separate trust-graph walk.
//! - **The declared [`NetworkPolicyRule`] set** — a fixed table of
//!   allow/deny rules between named selectors (`from` -> `to`), evaluated
//!   fail-open (unrestricted) absent any matching rule, deny-wins when
//!   multiple rules match the same pair.
//!
//! A connection is authorized only when BOTH the RBAC gate and the policy
//! rule set agree — see [`is_connection_authorized`].

use std::collections::BTreeMap;
use std::sync::Mutex;

use pillar_core::NodeId;
use pillar_rbac::{Capability, Decision as RbacDecision, RbacDecider, Request as RbacRequest, ResourceClass};

use crate::builtin::{ControllerHook, ReconcileOutcome};
use crate::{Crd, FieldType, Schema, Value};

/// The `apiVersion` a `NetworkPolicy` manifest is declared under — the same
/// namespace [`crate::builtin::BUILTIN_API_VERSION`] uses, since a
/// `NetworkPolicy` is a first-class pillar resource kind even though its
/// controller is optional.
pub const NETPOLICY_API_VERSION: &str = "pillar.dev/v1";

/// The `kind` string a network-policy manifest declares.
pub const NETPOLICY_KIND: &str = "NetworkPolicy";

/// The RBAC capability a connection attempt is decided against — the
/// `net:connect` capability under [`ResourceClass::Network`], enforced
/// identically for controller enforcement and (were a UI to predict it)
/// prediction, per [`pillar_rbac::RbacDecider`]'s single-decision-path
/// contract.
#[must_use]
pub fn connect_capability() -> Capability {
    Capability::from("net:connect")
}

/// The OpenAPI-style schema a `NetworkPolicy` manifest validates against,
/// registered into a [`crate::SchemaRegistry`] exactly like any other kind:
/// `from` / `to` (the selector names this rule applies between) and
/// `action` (`allow` or `deny`).
#[must_use]
pub fn network_policy_schema() -> Schema {
    Schema::new(NETPOLICY_API_VERSION, NETPOLICY_KIND)
        .required("from", FieldType::String)
        .required("to", FieldType::String)
        .required("action", FieldType::String)
}

/// Whether a [`NetworkPolicyRule`] allows or denies the matched `from` ->
/// `to` connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyAction {
    /// The matched connection is permitted (subject to the RBAC gate, see
    /// module docs).
    Allow,
    /// The matched connection is refused unconditionally — deny always
    /// wins over an allow rule matching the same pair.
    Deny,
}

/// Why a rule could not be extracted from a `NetworkPolicy` [`Crd`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// A required spec field was missing or the wrong type — should not
    /// happen for a body that already passed [`network_policy_schema`]
    /// validation, but this hook re-derives the rule defensively rather
    /// than trusting the caller ran the schema check.
    MalformedSpec(String),
    /// `spec.action` was present and string-typed but not `allow`/`deny`.
    UnknownAction(String),
}

/// One allow/deny network-policy rule between two named selectors
/// (`from`/`to` name cells/workloads by their resource name — opaque to
/// this model, resolved by whatever names workloads elsewhere).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkPolicyRule {
    /// The source selector this rule matches.
    pub from: String,
    /// The destination selector this rule matches.
    pub to: String,
    /// Whether a matching connection is allowed or denied.
    pub action: PolicyAction,
}

impl NetworkPolicyRule {
    /// Extract a [`NetworkPolicyRule`] from a `NetworkPolicy`-kind [`Crd`].
    ///
    /// # Errors
    /// [`RuleError::MalformedSpec`] if a required field is absent or is not
    /// a string; [`RuleError::UnknownAction`] if `action` is neither
    /// `allow` nor `deny`.
    pub fn from_crd(crd: &Crd) -> Result<Self, RuleError> {
        let field = |name: &str| -> Result<String, RuleError> {
            match crd.spec.get(name) {
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(RuleError::MalformedSpec(name.to_owned())),
            }
        };
        let from = field("from")?;
        let to = field("to")?;
        let action_str = field("action")?;
        let action = match action_str.as_str() {
            "allow" => PolicyAction::Allow,
            "deny" => PolicyAction::Deny,
            other => return Err(RuleError::UnknownAction(other.to_owned())),
        };
        Ok(NetworkPolicyRule { from, to, action })
    }
}

/// The live, reconciled set of [`NetworkPolicyRule`]s this controller has
/// installed, keyed by `(from, to)` so a later manifest for the same pair
/// replaces (rather than accumulates behind) an earlier one — exactly the
/// "declared state wins" reconcile semantics every other builtin kind
/// applies.
#[derive(Default)]
pub struct NetworkPolicySet {
    rules: Mutex<BTreeMap<(String, String), PolicyAction>>,
}

impl NetworkPolicySet {
    /// An empty policy set — with no rules installed, [`Self::rule_permits`]
    /// is unrestricted (fail-open) for every pair, per the "controller
    /// absent boots normally" property this module guarantees.
    #[must_use]
    pub fn new() -> Self {
        NetworkPolicySet {
            rules: Mutex::new(BTreeMap::new()),
        }
    }

    fn install(&self, rule: NetworkPolicyRule) {
        self.rules
            .lock()
            .expect("NetworkPolicySet mutex poisoned")
            .insert((rule.from, rule.to), rule.action);
    }

    /// Whether the declared rule set permits a connection from `from` to
    /// `to`. Absent any rule naming this exact pair: **unrestricted**
    /// (permitted) — the fail-open default this controller's absence (or an
    /// as-yet-undeclared pair) must preserve. A rule naming the pair with
    /// [`PolicyAction::Deny`] refuses it; [`PolicyAction::Allow`] confirms
    /// it (still subject to the separate RBAC gate — see
    /// [`is_connection_authorized`]).
    #[must_use]
    pub fn rule_permits(&self, from: &str, to: &str) -> bool {
        match self
            .rules
            .lock()
            .expect("NetworkPolicySet mutex poisoned")
            .get(&(from.to_owned(), to.to_owned()))
        {
            Some(PolicyAction::Deny) => false,
            Some(PolicyAction::Allow) | None => true,
        }
    }
}

/// A [`ControllerHook`] that reconciles `NetworkPolicy` manifests into a
/// shared [`NetworkPolicySet`] — the same [`ControllerHook`] shape (and the
/// same [`crate::builtin::ControllerRegistry::register`] call) a built-in
/// kind's hook or a third-party CRD's hook uses. Registering this hook is
/// entirely optional: a cell/node that never calls
/// [`register_network_policy_controller`] simply has no entry for
/// `pillar.dev/v1/NetworkPolicy` in its registry, so
/// [`crate::builtin::ControllerRegistry::dispatch`] returns `None` for it —
/// booting and operating normally, unrestricted, with the controller
/// absent.
#[derive(Default)]
pub struct NetworkPolicyControllerHook {
    policies: NetworkPolicySet,
}

impl NetworkPolicyControllerHook {
    /// A hook with no rules installed yet.
    #[must_use]
    pub fn new() -> Self {
        NetworkPolicyControllerHook {
            policies: NetworkPolicySet::new(),
        }
    }

    /// Whether the rules this hook has reconciled so far permit a
    /// connection from `from` to `to` (the rule-set half of the gate; see
    /// [`is_connection_authorized`] for the full RBAC + rule-set gate).
    #[must_use]
    pub fn rule_permits(&self, from: &str, to: &str) -> bool {
        self.policies.rule_permits(from, to)
    }
}

impl ControllerHook for NetworkPolicyControllerHook {
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
        match NetworkPolicyRule::from_crd(crd) {
            Ok(rule) => {
                self.policies.install(rule);
                ReconcileOutcome::Reconciled
            }
            Err(RuleError::MalformedSpec(field)) => {
                ReconcileOutcome::Failed(format!("malformed spec field: {field}"))
            }
            Err(RuleError::UnknownAction(action)) => {
                ReconcileOutcome::Failed(format!("unknown action: {action}"))
            }
        }
    }
}

/// Register `hook`'s schema and controller into `schemas`/`controllers` —
/// the identical two calls a caller makes to wire up any third-party CRD,
/// with no special-cased "builtin-but-optional" registration path.
pub fn register_network_policy_controller(
    schemas: &mut crate::SchemaRegistry,
    controllers: &mut crate::builtin::ControllerRegistry,
    hook: NetworkPolicyControllerHook,
) {
    schemas.register(network_policy_schema());
    controllers.register(NETPOLICY_API_VERSION, NETPOLICY_KIND, Box::new(hook));
}

/// **The full allow/deny gate**: whether `subject` may open a connection
/// from `from` to `to`, consistent with BOTH the declared
/// [`NetworkPolicySet`] rule (fail-open/unrestricted absent a matching
/// rule; deny always wins when a rule matches) AND the RBAC/WoT gate
/// (`decider.decide` must return [`RbacDecision::Allow`] for
/// [`connect_capability`] under [`ResourceClass::Network`]). A connection
/// is authorized only when both agree — either gate refusing it refuses
/// the connection.
#[must_use]
pub fn is_connection_authorized(
    policies: &NetworkPolicySet,
    decider: &RbacDecider<'_>,
    subject: &NodeId,
    from: &str,
    to: &str,
) -> bool {
    if !policies.rule_permits(from, to) {
        return false;
    }
    let request = RbacRequest::new(subject.clone(), connect_capability())
        .with_resource_class(ResourceClass::Network);
    matches!(decider.decide(&request), RbacDecision::Allow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::ControllerRegistry;
    use crate::{Metadata, SchemaRegistry};
    use pillar_rbac::{default_resource_class_policies, ExplicitGrant};
    use pillar_wot_authority::WotAuthority;

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn policy_crd(name: &str, from: &str, to: &str, action: &str) -> Crd {
        Crd::new(NETPOLICY_API_VERSION, NETPOLICY_KIND, Metadata::new(name))
            .with_spec("from", Value::String(from.into()))
            .with_spec("to", Value::String(to.into()))
            .with_spec("action", Value::String(action.into()))
    }

    #[test]
    fn a_network_policy_manifest_validates_against_its_schema() {
        let mut registry = SchemaRegistry::new();
        registry.register(network_policy_schema());
        let crd = policy_crd("deny-db", "web", "db", "deny");
        assert_eq!(registry.validate(&crd), Ok(()));
    }

    #[test]
    fn a_network_policy_manifest_missing_a_required_field_is_rejected() {
        let mut registry = SchemaRegistry::new();
        registry.register(network_policy_schema());
        let crd = Crd::new(NETPOLICY_API_VERSION, NETPOLICY_KIND, Metadata::new("bad"))
            .with_spec("from", Value::String("web".into()));
        assert!(registry.validate(&crd).is_err());
    }

    #[test]
    fn an_unknown_action_is_rejected_at_reconcile() {
        let hook = NetworkPolicyControllerHook::new();
        let crd = policy_crd("bad-action", "web", "db", "sometimes");
        match hook.reconcile(&crd) {
            ReconcileOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn a_declared_deny_rule_refuses_the_connection_even_with_full_rbac_allow() {
        let mut schemas = SchemaRegistry::new();
        let mut controllers = ControllerRegistry::new();
        register_network_policy_controller(
            &mut schemas,
            &mut controllers,
            NetworkPolicyControllerHook::new(),
        );

        let crd = policy_crd("deny-db", "web", "db", "deny");
        assert_eq!(schemas.validate(&crd), Ok(()));
        assert_eq!(
            controllers.dispatch(&crd),
            Some(ReconcileOutcome::Reconciled)
        );

        // Root-of-trust subject: satisfies every RBAC depth default there
        // is, so the ONLY thing standing between it and the connection is
        // the declared policy rule.
        let root = n("root");
        let authority = WotAuthority::new(root.clone(), 4);
        let policies = default_resource_class_policies(&connect_capability());
        let grants: Vec<ExplicitGrant> = Vec::new();
        let decider = RbacDecider::new(&authority, &policies, &grants);

        let network_policy_set = NetworkPolicySet::new();
        network_policy_set.install(NetworkPolicyRule {
            from: "web".into(),
            to: "db".into(),
            action: PolicyAction::Deny,
        });

        assert!(!is_connection_authorized(
            &network_policy_set,
            &decider,
            &root,
            "web",
            "db",
        ));
    }

    #[test]
    fn an_allow_rule_with_a_satisfied_rbac_gate_permits_the_connection() {
        let root = n("root");
        let authority = WotAuthority::new(root.clone(), 4);
        let policies = default_resource_class_policies(&connect_capability());
        let grants: Vec<ExplicitGrant> = Vec::new();
        let decider = RbacDecider::new(&authority, &policies, &grants);

        let network_policy_set = NetworkPolicySet::new();
        network_policy_set.install(NetworkPolicyRule {
            from: "web".into(),
            to: "cache".into(),
            action: PolicyAction::Allow,
        });

        assert!(is_connection_authorized(
            &network_policy_set,
            &decider,
            &root,
            "web",
            "cache",
        ));
    }

    #[test]
    fn an_untrusted_subject_is_refused_by_the_rbac_gate_even_with_an_allow_rule() {
        // A subject with no reachable trust path (never declared/tsig-linked
        // into the authority at all) satisfies no depth-default policy, so
        // the RBAC gate refuses it regardless of what the declared network
        // policy rule says.
        let root = n("root");
        let authority = WotAuthority::new(root, 4);
        let policies = default_resource_class_policies(&connect_capability());
        let grants: Vec<ExplicitGrant> = Vec::new();
        let decider = RbacDecider::new(&authority, &policies, &grants);

        let stranger = n("stranger");
        let network_policy_set = NetworkPolicySet::new();
        network_policy_set.install(NetworkPolicyRule {
            from: "web".into(),
            to: "cache".into(),
            action: PolicyAction::Allow,
        });

        assert!(!is_connection_authorized(
            &network_policy_set,
            &decider,
            &stranger,
            "web",
            "cache",
        ));
    }

    #[test]
    fn an_undeclared_pair_is_unrestricted_by_default() {
        // No rule at all for this (from, to) pair: fail-open per the
        // "controller absent/undeclared boots normally, unrestricted"
        // property, so a satisfied RBAC gate is enough on its own.
        let root = n("root");
        let authority = WotAuthority::new(root.clone(), 4);
        let policies = default_resource_class_policies(&connect_capability());
        let grants: Vec<ExplicitGrant> = Vec::new();
        let decider = RbacDecider::new(&authority, &policies, &grants);

        let network_policy_set = NetworkPolicySet::new();
        assert!(is_connection_authorized(
            &network_policy_set,
            &decider,
            &root,
            "unrelated-a",
            "unrelated-b",
        ));
    }

    #[test]
    fn a_cell_with_this_controller_absent_still_boots_and_operates_normally() {
        // No `register_network_policy_controller` call at all — the
        // controller is genuinely absent, exactly as a Tier-3 OPTIONAL
        // integration a cell chose not to enable would be. Schema
        // registration and dispatch for every OTHER kind still work; a
        // NetworkPolicy manifest simply has no registered hook, dispatched
        // through the identical absence-returns-None path any unregistered
        // kind takes, and connections remain unrestricted absent the
        // controller (fail-open, never fail-closed on a missing OPTIONAL
        // integration).
        let schemas = SchemaRegistry::new();
        let controllers = ControllerRegistry::new();

        let crd = policy_crd("deny-db", "web", "db", "deny");
        assert!(!controllers.contains(&crd));
        assert_eq!(controllers.dispatch(&crd), None);
        assert!(schemas.validate(&crd).is_err());

        // And the fail-open property holds structurally too: an empty
        // NetworkPolicySet (as a cell without this controller would have)
        // permits every pair.
        let network_policy_set = NetworkPolicySet::new();
        assert!(network_policy_set.rule_permits("anything", "anything-else"));
    }
}
