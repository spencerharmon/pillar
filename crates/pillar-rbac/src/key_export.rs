//! The **cell-level key-export role** — an RBAC capability, independently
//! grantable, that authorizes exporting private key material (cell or user) in
//! the gpg-auditable OpenPGP form produced by
//! [`pillar_crypto::openpgp`](../../pillar_crypto/openpgp/index.html).
//!
//! ## Why a distinct capability
//!
//! Exporting a private identity key is strictly more dangerous than ordinary
//! admin actions (user administration, membership edits): it removes the key
//! from its custody boundary. So it is gated by its OWN capability
//! [`CELL_KEY_EXPORT_CAPABILITY`], never folded into a broad "admin" grant. A
//! deployment grants it to exactly the subjects that should hold it via a single
//! [`ExplicitGrant`] naming this capability and NOTHING else — the capability
//! model already makes each `(subject, capability)` grant independent, so a
//! key-export holder gains no other authority, and an admin without this grant
//! cannot export even though they administer users.
//!
//! ## Always step-up gated
//!
//! Because the blast radius is a private key, export is ALWAYS an additional-
//! factor action: [`key_export_step_up_policy`] marks the capability step-up-
//! required, so [`RbacDecider::decide`] refuses it unless the request also
//! carries a FRESH WebAuthn assertion — the same P0 custody credential re-used
//! as the step-up factor. There is no non-step-up export path.

use crate::{
    Capability, Decision, RbacDecider, Request, ResourceClass, StepUpAssertion, StepUpPolicy,
};
use pillar_core::NodeId;

/// The well-known capability string for the cell-level key-export role.
pub const CELL_KEY_EXPORT_CAPABILITY: &str = "cell:key-export";

/// The default freshness window (seconds) a step-up WebAuthn assertion may have
/// and still authorize an export. Deliberately tight — an export is a deliberate,
/// just-authenticated act, not a background one.
pub const KEY_EXPORT_STEP_UP_MAX_AGE_SECS: u64 = 120;

/// The [`Capability`] value for the key-export role.
#[must_use]
pub fn cell_key_export_capability() -> Capability {
    Capability::from(CELL_KEY_EXPORT_CAPABILITY)
}

/// A [`StepUpPolicy`] that marks the key-export capability step-up-required with
/// the default freshness window, so every export path demands a fresh WebAuthn
/// assertion. Compose with any other step-up-gated capabilities a deployment
/// already requires (this only adds the export capability).
#[must_use]
pub fn key_export_step_up_policy() -> StepUpPolicy {
    StepUpPolicy::new(
        [cell_key_export_capability()],
        KEY_EXPORT_STEP_UP_MAX_AGE_SECS,
    )
}

/// Decide whether `subject` may export private key material right now: a single
/// call both the CLI (`pillar key export --private`) and the web-api export
/// endpoint use, so the two can never diverge on who is allowed. `decider` MUST
/// have [`key_export_step_up_policy`] (or a superset) attached via
/// [`RbacDecider::with_step_up_policy`]; `step_up` is the freshly verified
/// WebAuthn proof (the RP verified its signature before this call).
///
/// Returns [`Decision::Allow`] only when the subject holds the key-export
/// capability (by explicit grant or a satisfied WoT-depth policy for it) AND the
/// step-up proof is fresh; otherwise [`Decision::Deny`], fail-closed.
#[must_use]
pub fn authorize_key_export(
    decider: &RbacDecider<'_>,
    subject: NodeId,
    now_secs: u64,
    step_up: Option<StepUpAssertion>,
) -> Decision {
    let mut req = Request::new(subject, cell_key_export_capability())
        .with_resource_class(ResourceClass::All)
        .at_time(now_secs);
    if let Some(assertion) = step_up {
        req = req.with_step_up(assertion);
    }
    decider.decide(&req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExplicitGrant, GrantEffect};
    use pillar_wot_authority::WotAuthority;

    fn node(s: &str) -> NodeId {
        NodeId::from(s)
    }

    #[test]
    fn export_requires_the_capability_and_fresh_step_up() {
        let authority = WotAuthority::new(node("root"), 5);
        let policies: [crate::PolicyEvent; 0] = [];
        let step_up = key_export_step_up_policy();

        // Holder of the key-export grant.
        let grants = [ExplicitGrant {
            subject: node("alice"),
            capability: cell_key_export_capability(),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&authority, &policies, &grants).with_step_up_policy(&step_up);

        // With a fresh step-up: allowed.
        let fresh = StepUpAssertion::new(1_000, b"cred");
        assert_eq!(
            authorize_key_export(&decider, node("alice"), 1_010, Some(fresh)),
            Decision::Allow
        );
        // Without step-up: denied even though the grant exists.
        assert_eq!(
            authorize_key_export(&decider, node("alice"), 1_010, None),
            Decision::Deny
        );
        // Stale step-up: denied.
        let stale = StepUpAssertion::new(1, b"cred");
        assert_eq!(
            authorize_key_export(&decider, node("alice"), 10_000, Some(stale)),
            Decision::Deny
        );
    }

    #[test]
    fn admin_without_the_grant_cannot_export() {
        let authority = WotAuthority::new(node("root"), 5);
        let policies: [crate::PolicyEvent; 0] = [];
        let step_up = key_export_step_up_policy();
        // Bob has a DIFFERENT admin grant but not key-export — independence.
        let grants = [ExplicitGrant {
            subject: node("bob"),
            capability: Capability::from("user:admin"),
            effect: GrantEffect::Allow,
        }];
        let decider = RbacDecider::new(&authority, &policies, &grants).with_step_up_policy(&step_up);
        let fresh = StepUpAssertion::new(1_000, b"cred");
        assert_eq!(
            authorize_key_export(&decider, node("bob"), 1_010, Some(fresh)),
            Decision::Deny
        );
    }

    #[test]
    fn explicit_deny_overrides_the_grant() {
        let authority = WotAuthority::new(node("root"), 5);
        let policies: [crate::PolicyEvent; 0] = [];
        let step_up = key_export_step_up_policy();
        let grants = [
            ExplicitGrant {
                subject: node("carol"),
                capability: cell_key_export_capability(),
                effect: GrantEffect::Allow,
            },
            ExplicitGrant {
                subject: node("carol"),
                capability: cell_key_export_capability(),
                effect: GrantEffect::Deny,
            },
        ];
        let decider = RbacDecider::new(&authority, &policies, &grants).with_step_up_policy(&step_up);
        let fresh = StepUpAssertion::new(1_000, b"cred");
        assert_eq!(
            authorize_key_export(&decider, node("carol"), 1_010, Some(fresh)),
            Decision::Deny
        );
    }
}
