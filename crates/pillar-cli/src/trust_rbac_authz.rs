//! `pillar apply-authz`: drive the REAL certify -> trust -> attest -> revoke
//! trust-artifact pipeline and the REAL `pillar_rbac::RbacDecider` over the
//! REAL `pillar_wot_authority::WotAuthority`, then decide a manifest `apply`
//! request as the decider actually would — proving an UNAUTHORIZED apply is
//! REJECTED with a real fail-closed 403-style denial (not a mocked check),
//! and a revoked grant flips a previously-allowed apply back to denied.
//!
//! This is the CLI surface the `pillar-integration` trust/RBAC scenario
//! family drives black-box (`run-scenario.sh trust-rbac`): the scenario
//! execs this verb against the REAL published image and asserts, from the
//! transcript alone, that the real decider denied the unauthorized apply.
//! Nothing here is a stub — every allow/deny is `RbacDecider::decide`'s real
//! verdict over a `TrustStore` built from real, signed trust artifacts and
//! projected through the SAME `as_explicit_grants` rung the controller uses.
//!
//! Every step prints one `ok: <step>` line on success and a
//! `denied: <what>` line for each observed real denial; any violated
//! invariant prints `FAIL: <step>: <why>` and the command exits non-zero, so
//! the harness fails loud on the first broken step. The command's exit code
//! is 0 iff every invariant held INCLUDING that the unauthorized apply was
//! denied — an unauthorized apply silently admitted is a non-zero FAIL.

use std::process::ExitCode;

use pillar_core::NodeId;
use pillar_rbac::{Capability, Decision, RbacDecider, Request, ResourceClass};
use pillar_trust_artifacts::{
    as_explicit_grants, Attest, Capacity, Certify, Predicate, Revoke, Trust, TrustStore,
};
use pillar_wot_authority::WotAuthority;

/// The manifest action an `apply` exercises, expressed as the RBAC
/// capability the decider gates on.
const APPLY_CAP: &str = "compute/apply";

/// `pillar apply-authz`: run the whole sequence; `ExitCode::SUCCESS` iff
/// every invariant (including "unauthorized apply denied") held.
pub fn run() -> ExitCode {
    match sequence() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn denied(what: &str) {
    println!("denied: {what}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

/// Build a real, signed grant chain over a `TrustStore` and decide real
/// `apply` requests through the real `RbacDecider`.
fn sequence() -> Result<(), String> {
    // Genesis owner: the trust root. `operator` is an authorized principal we
    // will grant; `stranger` is never granted anything.
    let owner = NodeId::from("owner-primary");
    let operator = NodeId::from("operator-primary");
    let stranger = NodeId::from("stranger-primary");

    let mut store = TrustStore::new(owner.clone());

    // --- certify: the operator self-binds a subkey (real signed artifact,
    // verified by the store). A signer mismatch is refused.
    step_certify(&store, &operator)?;

    // --- trust: the owner vouches for the operator (real signed Trust).
    step_trust(&store, &owner, &operator)?;

    // --- attest: the owner (genesis) issues a Role grant to the operator
    // authorizing the apply capability. This is the ONLY authorization path
    // to an allowed apply; it is recorded into the real store and gated on
    // the fenced epoch + capacity-held-at-signing invariants.
    let grant_cid = step_attest(&mut store, &owner, &operator)?;

    // --- decide (pre-revoke): the REAL decider over the REAL authority.
    // The operator (granted) is allowed; the stranger (never granted) is
    // DENIED — a real fail-closed 403 from the real decider, not a mock.
    step_decide_before_revoke(&store, &owner, &operator, &stranger)?;

    // --- revoke: the owner revokes the operator's grant (real signed,
    // epoch-stamped, fail-closed revocation). The operator's apply must now
    // ALSO be denied — revocation is real, not cosmetic.
    step_revoke_then_decide(&mut store, &owner, &operator, grant_cid)?;

    Ok(())
}

/// certify — a real signed self-bind, accepted; a forged (wrong-signer) one
/// is refused fail-closed.
fn step_certify(store: &TrustStore, operator: &NodeId) -> Result<(), String> {
    const STEP: &str = "certify";
    let good = Certify::signed(operator.clone(), NodeId::from("operator-subkey"));
    store
        .certify(&good)
        .map_err(|e| fail(STEP, format!("a real signed certify was refused: {e:?}")))?;

    // A certify claiming to be the operator but signed by someone else must
    // be rejected — the real signature check, fail-closed.
    let mut forged = Certify::signed(NodeId::from("impostor"), NodeId::from("operator-subkey"));
    forged.identity = operator.clone();
    if store.certify(&forged).is_ok() {
        return Err(fail(
            STEP,
            "a certify signed by an impostor was WRONGLY accepted for the operator",
        ));
    }
    ok(STEP);
    Ok(())
}

/// trust — a real signed vouch, accepted; a forged one refused fail-closed.
fn step_trust(store: &TrustStore, owner: &NodeId, operator: &NodeId) -> Result<(), String> {
    const STEP: &str = "trust";
    let t = Trust::signed(owner.clone(), operator.clone(), 3);
    store
        .trust(&t)
        .map_err(|e| fail(STEP, format!("a real signed trust was refused: {e:?}")))?;

    let mut forged = Trust::signed(NodeId::from("impostor"), operator.clone(), 3);
    forged.truster = owner.clone();
    if store.trust(&forged).is_ok() {
        return Err(fail(
            STEP,
            "a trust signed by an impostor was WRONGLY accepted as the owner's vouch",
        ));
    }
    ok(STEP);
    Ok(())
}

/// attest — the genesis owner issues a Role grant authorizing the apply
/// capability to the operator, recorded into the real store. A grant forged
/// by a non-holder must be refused (`CapacityNotHeld`), fail-closed.
fn step_attest(
    store: &mut TrustStore,
    owner: &NodeId,
    operator: &NodeId,
) -> Result<pillar_trust_artifacts::Cid, String> {
    const STEP: &str = "attest";

    // A stranger who holds no capacity cannot forge the grant into existence.
    let stranger = NodeId::from("stranger-primary");
    let forged = Attest {
        issuer: stranger.clone(),
        capacity: Capacity::Role {
            role: "operator".to_owned(),
            scope: "cell-a".to_owned(),
        },
        authority: None,
        subject: operator.clone(),
        predicate: Predicate::new(APPLY_CAP, "cell-a/*"),
        scope: "cell-a".to_owned(),
        epoch: store.epoch(),
        sig: pillar_trust_artifacts::Sig::sign_as(stranger, b""),
    }
    .signed_by_issuer();
    if store.issue_attest(forged).is_ok() {
        return Err(fail(
            STEP,
            "an attest issued by a non-holding stranger was WRONGLY recorded",
        ));
    }

    // The genesis owner holds every capacity unconditionally, so its grant to
    // the operator is admitted — the single authorized path to an allowed
    // apply.
    let grant = Attest {
        issuer: owner.clone(),
        capacity: Capacity::Role {
            role: "operator".to_owned(),
            scope: "cell-a".to_owned(),
        },
        authority: None,
        subject: operator.clone(),
        predicate: Predicate::new(APPLY_CAP, "cell-a/*"),
        scope: "cell-a".to_owned(),
        epoch: store.epoch(),
        sig: pillar_trust_artifacts::Sig::sign_as(owner.clone(), b""),
    }
    .signed_by_issuer();
    let cid = store
        .issue_attest(grant)
        .map_err(|e| fail(STEP, format!("the owner's real grant was refused: {e:?}")))?;
    ok(STEP);
    Ok(cid)
}

/// Build the real decider from the store's live grants and decide an apply
/// request for `subject`. Returns the real verdict.
fn decide_apply(store: &TrustStore, owner: &NodeId, subject: &NodeId) -> Decision {
    // The single WoT authority + the grants projected from the SAME live
    // trust store the controller consumes (`as_explicit_grants`).
    let mut authority = WotAuthority::new(owner.clone(), 5);
    authority.issue_edge(owner.clone(), subject.clone(), 3);
    let grants = as_explicit_grants(store);
    // No depth-default policies: authorization for apply comes ONLY from an
    // explicit grant, so a subject with no grant fails closed to Deny.
    let policies = Vec::new();
    let decider = RbacDecider::new(&authority, &policies, &grants);
    let req = Request::new(subject.clone(), Capability::from(APPLY_CAP))
        .with_resource_class(ResourceClass::Compute);
    decider.decide(&req)
}

/// decide (pre-revoke): operator allowed, stranger DENIED — the real 403.
fn step_decide_before_revoke(
    store: &TrustStore,
    owner: &NodeId,
    operator: &NodeId,
    stranger: &NodeId,
) -> Result<(), String> {
    const STEP: &str = "authorized-apply-allowed";
    if decide_apply(store, owner, operator) != Decision::Allow {
        return Err(fail(
            STEP,
            "the granted operator's apply was refused despite a valid grant",
        ));
    }
    ok(STEP);

    const STEP2: &str = "unauthorized-apply-denied";
    if decide_apply(store, owner, stranger) != Decision::Deny {
        return Err(fail(
            STEP2,
            "an UNGRANTED stranger's apply was WRONGLY admitted (fail-closed 403 violated)",
        ));
    }
    denied(&format!(
        "apply subject={} capability={} verdict=403 (real decider, fail-closed)",
        stranger.0, APPLY_CAP
    ));
    ok(STEP2);
    Ok(())
}

/// revoke then re-decide: after the owner revokes the operator's grant, the
/// operator's apply must ALSO be denied — revocation is real.
fn step_revoke_then_decide(
    store: &mut TrustStore,
    owner: &NodeId,
    operator: &NodeId,
    grant_cid: pillar_trust_artifacts::Cid,
) -> Result<(), String> {
    const STEP: &str = "revoke";
    let r = Revoke::signed(grant_cid, owner.clone());
    store
        .revoke(&r)
        .map_err(|e| fail(STEP, format!("the owner's real revoke was refused: {e:?}")))?;
    ok(STEP);

    const STEP2: &str = "revoked-apply-denied";
    if decide_apply(store, owner, operator) != Decision::Deny {
        return Err(fail(
            STEP2,
            "the operator's apply was still admitted AFTER its grant was revoked (revocation ignored)",
        ));
    }
    denied(&format!(
        "apply subject={} capability={} verdict=403 (grant revoked)",
        operator.0, APPLY_CAP
    ));
    ok(STEP2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole sequence holds every invariant end to end — the same path
    /// the `apply-authz` CLI verb runs. Proves an unauthorized apply is denied
    /// and a granted one allowed, through the real decider.
    #[test]
    fn full_sequence_denies_unauthorized_apply() {
        sequence().expect("trust/RBAC sequence holds every invariant");
    }

    /// The DECISIVE property, asserted directly against the real decider (not
    /// via the string transcript): an UNGRANTED subject's apply is DENIED and
    /// a GRANTED subject's apply is ALLOWED — a real fail-closed 403 from the
    /// real `RbacDecider`, and the RED condition (silent admit) cannot hold.
    #[test]
    fn unauthorized_apply_is_denied_and_authorized_allowed() {
        let owner = NodeId::from("owner-primary");
        let operator = NodeId::from("operator-primary");
        let stranger = NodeId::from("stranger-primary");
        let mut store = TrustStore::new(owner.clone());

        // No grant yet: BOTH subjects are denied (fail-closed default).
        assert_eq!(
            decide_apply(&store, &owner, &operator),
            Decision::Deny,
            "operator allowed before any grant (fail-closed default violated)"
        );
        assert_eq!(
            decide_apply(&store, &owner, &stranger),
            Decision::Deny,
            "stranger allowed before any grant (fail-closed default violated)"
        );

        // Grant the operator (genesis owner issues the Role attest).
        let grant_cid = step_attest(&mut store, &owner, &operator).expect("owner grant admitted");

        // Now the operator is ALLOWED, the ungranted stranger still DENIED.
        assert_eq!(
            decide_apply(&store, &owner, &operator),
            Decision::Allow,
            "granted operator's apply was refused"
        );
        assert_eq!(
            decide_apply(&store, &owner, &stranger),
            Decision::Deny,
            "UNGRANTED stranger's apply was admitted (the RED failure this scenario forbids)"
        );

        // Revoke the operator's grant: the operator's apply flips to DENIED.
        let r = Revoke::signed(grant_cid, owner.clone());
        store.revoke(&r).expect("owner revoke accepted");
        assert_eq!(
            decide_apply(&store, &owner, &operator),
            Decision::Deny,
            "operator's apply still admitted after its grant was revoked"
        );
    }

    /// A grant forged by a non-holding stranger is refused by the real store,
    /// so a stranger cannot mint its own authorization into existence.
    #[test]
    fn stranger_cannot_forge_its_own_grant() {
        let owner = NodeId::from("owner-primary");
        let stranger = NodeId::from("stranger-primary");
        let mut store = TrustStore::new(owner.clone());
        // step_attest tries (and must fail) to record a stranger-issued grant
        // before recording the owner's; a panic-free Ok here means the forged
        // grant was rejected as required.
        step_attest(&mut store, &owner, &NodeId::from("operator-primary"))
            .expect("owner grant path holds while forged stranger grant is refused");
        // The stranger holds no live grant, so it is denied.
        assert_eq!(
            decide_apply(&store, &owner, &stranger),
            Decision::Deny,
            "stranger somehow authorized despite no valid grant"
        );
    }
}
