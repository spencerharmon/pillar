//! `pillar onboard`: drives the explicit onboarding sequence
//! `specs/bootstrap-onboarding-spec` models — primary keygen, node-subkey
//! signing, cross-user trust, depth/policy config — as one real,
//! cross-crate CLI invocation, asserting every safety invariant the spec
//! proves holds end to end (not merely re-running each crate's own unit
//! tests in isolation).
//!
//! This is the non-networked half of the onboarding integration rig: the
//! `onboarding-rig-test.sh` script runs this FIRST (fast, in-process, no
//! sockets) to prove the identity/trust/policy sequence, then drives the
//! separate real multi-process libp2p mesh (`pillar node run`) for the
//! gossipsub-discovery/state-convergence half.
//!
//! Every step prints one `ok: <step>` line on success; any step failing an
//! invariant prints `FAIL: <step>: <why>` and the whole command exits
//! non-zero — so the rig script can fail loud on the first broken step
//! rather than a generic non-zero with no diagnosis.

use pillar_core::NodeId;
use pillar_identity::{AdmissionError, NodeSubkey, Registry, Signature, UserPrimary};
use pillar_rbac::{
    Capability, Decision, ExplicitGrant, PolicyEvent, PolicyTarget, RbacDecider, Request,
    ResourceClass,
};
use pillar_wot_authority::WotAuthority;

/// Runs the full onboarding sequence. Returns `Ok(())` if every step's
/// invariant holds, `Err(<diagnostic>)` naming the first violated one.
pub fn run() -> Result<(), String> {
    step_keygen_and_registration()?;
    step_node_key_signing_admits_only_chained()?;
    step_cross_user_trust_and_depth()?;
    step_policy_config_gates_by_depth()?;
    step_out_of_order_admission_fails_closed()?;
    Ok(())
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

/// Step 1 — primary keygen: a fresh [`UserPrimary`] is unregistered until
/// explicitly registered; registering it is the only path to authority.
fn step_keygen_and_registration() -> Result<(), String> {
    const STEP: &str = "keygen-and-registration";
    let mut registry = Registry::new();
    let alice = UserPrimary::from("alice-primary");

    if registry.is_registered(&alice) {
        return Err(fail(
            STEP,
            "freshly keygen'd primary reads as already registered",
        ));
    }
    registry.register(alice.clone());
    if !registry.is_registered(&alice) {
        return Err(fail(STEP, "register() did not persist the primary"));
    }
    ok(STEP);
    Ok(())
}

/// Step 2 — node-key signing: a subkey signed by a registered primary is
/// admitted; the SAME subkey signed only by a rogue, never-registered
/// primary must be refused (`AdmissionRequiresAuthorizedChain`).
fn step_node_key_signing_admits_only_chained() -> Result<(), String> {
    const STEP: &str = "node-key-signing";
    let mut registry = Registry::new();
    let alice = UserPrimary::from("alice-primary");
    let rogue = UserPrimary::from("rogue-primary");
    let good_node = NodeSubkey::from("alice-node-1");
    let bad_node = NodeSubkey::from("rogue-node-1");

    registry.register(alice.clone());
    registry.issue_subkey(Signature::new(good_node.clone(), alice));
    registry.issue_subkey(Signature::new(bad_node.clone(), rogue));

    let admitted = registry
        .handshake(&good_node)
        .map_err(|e| fail(STEP, format!("chained node subkey refused: {e:?}")))?;
    if admitted != good_node.node_id() {
        return Err(fail(STEP, "handshake returned the wrong NodeId"));
    }
    if !registry.is_admitted(&good_node) {
        return Err(fail(STEP, "admitted subkey not recorded as admitted"));
    }

    match registry.handshake(&bad_node) {
        Err(AdmissionError::UnauthorizedIssuer { .. }) => {}
        Err(other) => return Err(fail(STEP, format!("wrong refusal reason: {other:?}"))),
        Ok(_) => return Err(fail(STEP, "rogue-signed node subkey was WRONGLY admitted")),
    }
    if registry.is_admitted(&bad_node) {
        return Err(fail(STEP, "refused subkey ended up marked admitted"));
    }
    ok(STEP);
    Ok(())
}

/// Step 3 — cross-user trust: alice (the owning root) issues a tsig edge to
/// bob, extending WoT reachability. Depth accounting must reflect the real
/// edge (a stranger with no edge stays unreachable).
fn step_cross_user_trust_and_depth() -> Result<(), String> {
    const STEP: &str = "cross-user-trust-and-depth";
    let alice = NodeId::from("alice-primary");
    let bob = NodeId::from("bob-primary");
    let stranger = NodeId::from("stranger-primary");

    let mut authority = WotAuthority::new(alice.clone(), 5);
    // Owner is always reachable at full budget.
    if authority.reachable_depth(&alice).is_none() {
        return Err(fail(STEP, "trust root itself is not reachable"));
    }
    if authority.reachable_depth(&bob).is_some() {
        return Err(fail(STEP, "bob reachable before any trust edge was issued"));
    }

    // Cross-user trust: alice tsigs bob at level 3 (an ordinary cross-user
    // certification, not the owner's implicit root authority).
    authority.issue_edge(alice.clone(), bob.clone(), 3);
    let bob_depth = authority
        .reachable_depth(&bob)
        .ok_or_else(|| fail(STEP, "bob still unreachable after alice's trust edge"))?;
    if bob_depth >= authority.max_depth() {
        return Err(fail(
            STEP,
            "bob's reachable depth did not shrink from the root budget",
        ));
    }
    if authority.reachable_depth(&stranger).is_some() {
        return Err(fail(STEP, "an untrusted stranger is reachable"));
    }
    ok(STEP);
    Ok(())
}

/// Step 4 — depth/policy config: a signed [`PolicyEvent`] requiring a WoT
/// depth threshold correctly gates the RBAC decision — bob (within
/// threshold) is allowed, the stranger (no trust edge at all) is refused,
/// fail-closed.
fn step_policy_config_gates_by_depth() -> Result<(), String> {
    const STEP: &str = "policy-config-gates-by-depth";
    let alice = NodeId::from("alice-primary");
    let bob = NodeId::from("bob-primary");
    let stranger = NodeId::from("stranger-primary");
    let cap = Capability::from("compute/deploy");

    let mut authority = WotAuthority::new(alice.clone(), 5);
    authority.issue_edge(alice, bob.clone(), 3);

    let policy = PolicyEvent {
        target: PolicyTarget::ResourceClass(ResourceClass::Compute),
        capability: cap.clone(),
        depth_threshold: 1,
    };
    let policies = vec![policy];
    let grants: Vec<ExplicitGrant> = Vec::new();
    let decider = RbacDecider::new(&authority, &policies, &grants);

    let bob_req = Request::new(bob, cap.clone()).with_resource_class(ResourceClass::Compute);
    if decider.decide(&bob_req) != Decision::Allow {
        return Err(fail(
            STEP,
            "trusted bob was refused a capability his depth satisfies",
        ));
    }

    let stranger_req = Request::new(stranger, cap).with_resource_class(ResourceClass::Compute);
    if decider.decide(&stranger_req) != Decision::Deny {
        return Err(fail(
            STEP,
            "unreachable stranger was WRONGLY granted a capability (fail-closed violated)",
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 5 — fail-closed on out-of-order steps: presenting a node subkey
/// BEFORE its primary is registered must never admit it, even once the
/// primary registers later (a stale, already-refused handshake attempt does
/// not retroactively succeed just because the state caught up).
fn step_out_of_order_admission_fails_closed() -> Result<(), String> {
    const STEP: &str = "out-of-order-fails-closed";
    let mut registry = Registry::new();
    let alice = UserPrimary::from("alice-primary");
    let node = NodeSubkey::from("alice-node-early");

    // Subkey signed and handshake attempted BEFORE alice ever registers.
    registry.issue_subkey(Signature::new(node.clone(), alice.clone()));
    match registry.handshake(&node) {
        Err(AdmissionError::UnauthorizedIssuer { .. }) => {}
        other => {
            return Err(fail(
                STEP,
                format!("pre-registration handshake was not refused as unauthorized: {other:?}"),
            ))
        }
    }
    if registry.is_admitted(&node) {
        return Err(fail(
            STEP,
            "out-of-order handshake left the subkey admitted",
        ));
    }

    // Registering the primary afterwards does not retroactively admit the
    // earlier failed attempt; a FRESH handshake is required and now
    // succeeds because the chain is checked live, not memoized as a
    // permanent refusal.
    registry.register(alice);
    let admitted = registry.handshake(&node).map_err(|e| {
        fail(
            STEP,
            format!("fresh handshake after registration refused: {e:?}"),
        )
    })?;
    if admitted != node.node_id() {
        return Err(fail(
            STEP,
            "post-registration handshake returned the wrong NodeId",
        ));
    }
    ok(STEP);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sequence_passes() {
        run().expect("onboarding sequence holds every invariant");
    }

    #[test]
    fn each_step_passes_individually() {
        step_keygen_and_registration().unwrap();
        step_node_key_signing_admits_only_chained().unwrap();
        step_cross_user_trust_and_depth().unwrap();
        step_policy_config_gates_by_depth().unwrap();
        step_out_of_order_admission_fails_closed().unwrap();
    }
}
