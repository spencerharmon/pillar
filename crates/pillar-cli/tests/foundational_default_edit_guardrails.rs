//! Acceptance test — `foundational-default-edit-guardrails` (ROI Priority 1
//! deliverable #3, 2026-09-14).
//!
//! Proves the five HARD-DoD guardrails that gate an edit to a
//! `default-resourceset-bootstrap` floor object (a system collection, the
//! seed-admin role binding, a `CollectionPolicy`, a `RetentionPolicy`) — one
//! edit can never lock a cell out of itself:
//!
//! 1. DRY-RUN CONFIRMATION is required before any access-reducing edit
//!    commits.
//! 2. NO-LOCKOUT ADMISSION refuses an edit leaving zero administrators or
//!    stripping the editor's own catalog-reconcile ability.
//! 3. STRICT (CP) REVOCATION rides the real `cp-viewpolicy-strict-cofold`
//!    primitive — fenced and exactly-once.
//! 4. HIGHER AUTHORITY: a foundational edit needs a stricter WoT trust
//!    threshold than an ordinary resource of the same capability, reusing
//!    the real `rbac-decider` / `wot-authority-impl` policy machinery.
//! 5. IMMUTABLE IDENTITY: a system collection's kind/identity fields and the
//!    cell genesis identity are read-only.
//!
//! Plus BREAK-GLASS (the genesis-key holder can always restore the seed
//! administrator binding) and retention-window-shortening's own strong
//! confirmation + data-removal contract.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test foundational_default_edit_guardrails --features acceptance`.

#![cfg(feature = "acceptance")]

use std::collections::BTreeSet;

use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};
use pillar_rbac::{Capability, PolicyEvent, PolicyTarget, ResourceClass};
use pillar_streamdb::cofold::CoFoldError;
use pillar_wot_authority::WotAuthority;

use pillar_cli::foundational_guardrails::{
    admits_no_lockout, apply_retention_shortening, break_glass_restore_seed_admin,
    foundational_policy, guard_higher_authority, guard_identity_edit, meets_higher_authority,
    preview_foundational_edit, retention_shortening_requires_confirmation, EditEffect,
    GuardrailError, StrictRevocation, IMMUTABLE_IDENTITY_FIELDS,
};

fn nid(s: &str) -> NodeId {
    NodeId::from(s)
}

/// Guardrail 1: an edit to the seed-admin role binding that would strip an
/// operator's access is REFUSED until its dry-run effect is confirmed — and
/// a purely additive edit never needs confirmation at all.
#[test]
fn guardrail_1_dry_run_confirmation_gates_access_reducing_edits() {
    let stripped_operator = nid("operator-losing-access");
    let effect = EditEffect {
        losing_access: vec![stripped_operator.clone()],
        becomes_unreachable: vec!["RoleBinding/seed-admin".to_owned()],
    };

    // Unconfirmed: refused, carrying exactly the computed effect.
    let refused = preview_foundational_edit(&effect, false).unwrap_err();
    match refused {
        GuardrailError::ConfirmationRequired {
            losing_access,
            becomes_unreachable,
        } => {
            assert_eq!(losing_access, vec![stripped_operator]);
            assert_eq!(
                becomes_unreachable,
                vec!["RoleBinding/seed-admin".to_owned()]
            );
        }
        other => panic!("expected ConfirmationRequired, got {other:?}"),
    }

    // Confirmed: admitted.
    preview_foundational_edit(&effect, true).expect("confirmed reducing edit is admitted");

    // A purely additive edit never needs confirmation.
    preview_foundational_edit(&EditEffect::none(), false)
        .expect("an additive edit never requires confirmation");
}

/// Guardrail 2: an edit leaving zero administrators, or stripping the
/// editor's own catalog-reconcile ability, is refused before it is written.
#[test]
fn guardrail_2_no_lockout_admission() {
    let empty: BTreeSet<NodeId> = BTreeSet::new();
    assert!(matches!(
        admits_no_lockout(&empty, true),
        Err(GuardrailError::LockoutRefused { .. })
    ));

    let mut one_admin = BTreeSet::new();
    one_admin.insert(nid("remaining-admin"));
    assert!(matches!(
        admits_no_lockout(&one_admin, false),
        Err(GuardrailError::LockoutRefused { .. })
    ));

    admits_no_lockout(&one_admin, true)
        .expect("at least one admin and an editor keeping catalog-reconcile is admitted");
}

/// Guardrail 3: revocation of a foundational grant rides the REAL
/// `StrictCofold` (`cp-viewpolicy-strict-cofold`) primitive — a stale/
/// unfenced writer is refused outright (never half-applied) and a duplicate
/// revoke of the same key is refused (never lost / silently re-admitted).
#[test]
fn guardrail_3_strict_cp_revocation_is_fenced_and_exactly_once() {
    let mut revocation = StrictRevocation::new();
    let mut lease = LeaseRegister::new(3);
    let candidate = nid("revoking-node");
    let key = b"RoleBinding/seed-admin";

    // Sub-quorum: not fenced yet, revoke refused outright (never half-applied).
    lease
        .grant(nid("voter-1"), candidate.clone(), Epoch(1))
        .unwrap();
    let unfenced = revocation.revoke(&mut lease, &candidate, key, Epoch(1), b"revoke".to_vec());
    assert!(
        matches!(
            unfenced,
            Err(GuardrailError::RevocationNotStrict(
                CoFoldError::NotFenced { .. }
            ))
        ),
        "an unfenced revoke must be refused outright, got {unfenced:?}"
    );
    assert!(!revocation.already_revoked(key));

    // Quorum reached: the fenced candidate's revoke is admitted.
    lease
        .grant(nid("voter-2"), candidate.clone(), Epoch(1))
        .unwrap();
    revocation
        .revoke(&mut lease, &candidate, key, Epoch(1), b"revoke".to_vec())
        .expect("a fenced, quorum-backed revoke is admitted");
    assert!(revocation.already_revoked(key));

    // A second revoke of the SAME key is refused — never lost, never
    // silently re-admitted.
    let dup = revocation.revoke(
        &mut lease,
        &candidate,
        key,
        Epoch(1),
        b"revoke-again".to_vec(),
    );
    assert!(
        matches!(
            dup,
            Err(GuardrailError::RevocationNotStrict(
                CoFoldError::DuplicateKey { .. }
            ))
        ),
        "a duplicate revoke must be refused, got {dup:?}"
    );
}

/// Guardrail 4: a foundational-default edit requires a STRICTLY higher WoT
/// trust threshold than an ordinary resource of the same capability, reusing
/// the real `rbac-decider`/`wot-authority-impl` per-scope threshold policy.
#[test]
fn guardrail_4_foundational_edit_requires_higher_authority() {
    let owner = nid("cell-owner");
    let mut authority = WotAuthority::new(owner.clone(), 6);
    let genesis_adjacent = nid("genesis-adjacent-admin");
    let ordinary_operator = nid("ordinary-operator");
    authority.issue_edge(owner.clone(), genesis_adjacent.clone(), 5);
    authority.issue_edge(owner.clone(), ordinary_operator.clone(), 2);

    let ordinary = PolicyEvent {
        target: PolicyTarget::ResourceClass(ResourceClass::All),
        capability: Capability::from("resourceset/write"),
        depth_threshold: 2,
    };
    let foundational = foundational_policy(&ordinary);
    assert!(
        foundational.depth_threshold > ordinary.depth_threshold,
        "the foundational policy must be strictly stricter than the ordinary one"
    );

    // The ordinary operator clears the ORDINARY threshold...
    assert!(ordinary_operator_meets_ordinary(
        &authority,
        &ordinary_operator,
        ordinary.depth_threshold
    ));
    // ...but NOT the foundational one.
    assert!(!meets_higher_authority(
        &authority,
        &ordinary_operator,
        ordinary.depth_threshold
    ));
    assert!(matches!(
        guard_higher_authority(&authority, &ordinary_operator, ordinary.depth_threshold),
        Err(GuardrailError::InsufficientAuthority { .. })
    ));

    // A subject close enough to the trust anchor clears the foundational bar.
    guard_higher_authority(&authority, &genesis_adjacent, ordinary.depth_threshold)
        .expect("a subject with enough remaining WoT budget clears the foundational threshold");
}

fn ordinary_operator_meets_ordinary(
    authority: &WotAuthority,
    subject: &NodeId,
    threshold: u8,
) -> bool {
    authority
        .reachable_depth(subject)
        .is_some_and(|d| d >= threshold)
}

/// Guardrail 5: a system collection's kind/identity fields and the cell
/// genesis identity are read-only even while the rest of the object stays
/// viewable/tunable.
#[test]
fn guardrail_5_immutable_identity_fields_stay_read_only() {
    for field in IMMUTABLE_IDENTITY_FIELDS {
        assert!(matches!(
            guard_identity_edit(field),
            Err(GuardrailError::ImmutableField { .. })
        ));
    }
    guard_identity_edit("spec.matchLabels").expect("non-identity fields remain freely editable");
}

/// BREAK-GLASS: the cell genesis-key holder can always restore the seed
/// administrator binding, so authority is recoverable; anyone else's attempt
/// is refused.
#[test]
fn break_glass_restores_seed_admin_for_genesis_key_holder_only() {
    let genesis_identity = nid("cell-genesis-identity");
    let mut admins: BTreeSet<NodeId> = BTreeSet::new();
    let seed_admin = nid("seed-admin");

    let refused = break_glass_restore_seed_admin(
        &nid("not-the-genesis-key"),
        &genesis_identity,
        &mut admins,
        seed_admin.clone(),
    );
    assert_eq!(refused, Err(GuardrailError::BreakGlassUnauthorized));
    assert!(
        admins.is_empty(),
        "an unauthorized restore must not mutate anything"
    );

    break_glass_restore_seed_admin(
        &genesis_identity,
        &genesis_identity,
        &mut admins,
        seed_admin.clone(),
    )
    .expect("the genesis-key holder can always restore the seed administrator binding");
    assert!(admins.contains(&seed_admin));
}

/// Retention-window shortening removes out-of-window data on apply and
/// requires a strong confirmation before doing so; widening never does.
#[test]
fn retention_window_shortening_requires_strong_confirmation_and_removes_data() {
    let old_window = 30 * 86_400;
    let new_window = 7 * 86_400;
    assert!(retention_shortening_requires_confirmation(
        old_window, new_window
    ));

    let refused = apply_retention_shortening(old_window, new_window, 12_345, false);
    assert!(matches!(
        refused,
        Err(GuardrailError::RetentionConfirmationRequired { .. })
    ));

    let removed = apply_retention_shortening(old_window, new_window, 12_345, true)
        .expect("a confirmed shortening applies");
    assert_eq!(
        removed, 12_345,
        "the confirmed shortening reports the removed count"
    );

    // Widening never requires confirmation and never removes anything.
    assert!(!retention_shortening_requires_confirmation(
        new_window, old_window
    ));
    assert_eq!(
        apply_retention_shortening(new_window, old_window, 999, false).unwrap(),
        0
    );
}
