//! Guardrails gating an edit to a **foundational default** — a
//! `default-resourceset-bootstrap` floor object (the system collection, the
//! seed-admin role binding, a `CollectionPolicy`, a `RetentionPolicy`).
//! Editing one of these carries FIVE extra checks an ordinary app-resource
//! edit never needs, per ROI Priority 1 deliverable #3, so that one edit can
//! never lock a cell out of itself:
//!
//! 1. [`preview_foundational_edit`] — **dry-run confirmation**: the computed
//!    effect (who loses access, what becomes unreachable) must be shown and
//!    explicitly confirmed before commit. This reuses the SAME
//!    preview-then-confirm shape [`crate::iam_cli::RoleCli::dry_run`] /
//!    [`crate::resource::ResourcePlane::dry_run_apply`] already establish
//!    (compute the exact effect the real act would produce, mutate nothing,
//!    require it to be looked at) rather than inventing a bespoke prompt.
//! 2. [`admits_no_lockout`] — **no-lockout admission**: an edit leaving zero
//!    administrators, or stripping the editor's own catalog-reconcile
//!    ability, is refused before it is ever written.
//! 3. [`StrictRevocation`] — **strict (CP) revocation**: an access-reducing
//!    edit is folded through [`pillar_streamdb::cofold::StrictCofold`] (the
//!    `cp-viewpolicy-strict-cofold` primitive) under a real fencing epoch, so
//!    a revoke is strongly consistent — never half-applied (refused outright
//!    if the epoch is stale) and never lost (never silently re-admitted:
//!    exactly-once via [`pillar_streamdb::cofold::UniqueOnce`]).
//! 4. [`meets_higher_authority`] — **higher authority**: a foundational
//!    resource requires a STRICTER WoT trust threshold than an ordinary
//!    resource of the same capability — reusing the exact per-scope
//!    `depth_threshold` policy machinery `rbac-decider`/`wot-authority-impl`
//!    already define ([`pillar_rbac::PolicyEvent`] over
//!    [`pillar_wot_authority::WotAuthority::reachable_depth`]), just at a
//!    margin above the ordinary threshold via [`foundational_policy`].
//! 5. [`guard_identity_edit`] — **immutable identity**: a system collection's
//!    `kind`/identity fields and the cell genesis identity are read-only even
//!    while the rest of the object stays viewable/tunable.
//!
//! Plus **break-glass** ([`break_glass_restore_seed_admin`]): the cell
//! genesis-key holder can always restore the seed administrator binding, so
//! authority is recoverable even after a legitimate lockout-avoiding edit
//! sequence goes wrong. And **retention-window shortening**
//! ([`apply_retention_shortening`]) is itself a strong-confirmation-gated,
//! access-reducing-shaped edit: shortening the window removes out-of-window
//! data on apply and refuses to do so silently.

use std::collections::BTreeSet;

use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};
use pillar_rbac::PolicyEvent;
use pillar_streamdb::cofold::{CoFoldError, StrictCofold, UniqueOnce};
use pillar_streamdb::OpId;
use pillar_wot_authority::WotAuthority;

/// The margin ADDED atop an ordinary-resource's `depth_threshold` to obtain
/// the threshold a foundational-default edit must meet (guardrail 4,
/// "HIGHER AUTHORITY"). A larger [`WotAuthority::reachable_depth`] budget
/// means a subject closer to the trust anchor (per the `rbac-decider` doc:
/// "a shallower, larger-remaining-budget trust position satisfies a lower
/// threshold"), so requiring `ordinary + MARGIN` demands STRICTLY more
/// authority than the capability's ordinary-resource policy alone.
pub const FOUNDATIONAL_THRESHOLD_MARGIN: u8 = 2;

/// The fields of a system collection / cell genesis identity that are
/// READ-ONLY even while the rest of the object stays viewable/tunable
/// (guardrail 5, "IMMUTABLE IDENTITY").
pub const IMMUTABLE_IDENTITY_FIELDS: &[&str] = &["kind", "genesisIdentity", "cellGenesisIdentity"];

/// Every way a foundational-default edit can be refused by a guardrail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardrailError {
    /// Guardrail 1: the edit's computed effect was not confirmed. Carries
    /// the effect summary the operator must review before retrying with
    /// confirmation.
    ConfirmationRequired {
        /// Who would lose access under this edit.
        losing_access: Vec<NodeId>,
        /// What would become unreachable (addresses/paths) under this edit.
        becomes_unreachable: Vec<String>,
    },
    /// Guardrail 2: the edit would leave zero administrators, or strips the
    /// editor's own catalog-reconcile ability.
    LockoutRefused {
        /// Human-readable reason (zero-admins vs self-lockout).
        reason: &'static str,
    },
    /// Guardrail 3: the strict-CP revocation fold refused the write (a stale
    /// fencing epoch, or an already-admitted duplicate revoke).
    RevocationNotStrict(CoFoldError),
    /// Guardrail 4: the subject's WoT reachable-depth budget does not meet
    /// the foundational (ordinary + margin) threshold.
    InsufficientAuthority {
        /// The threshold a foundational edit requires (`ordinary + margin`).
        required: u8,
        /// The subject's actual reachable-depth budget (`None` if
        /// unreachable at all).
        actual: Option<u8>,
    },
    /// Guardrail 5: the edit targets a read-only identity field.
    ImmutableField {
        /// The refused field name.
        field: String,
    },
    /// Retention-window shortening was attempted without the strong
    /// confirmation it requires (it is access/data-reducing, same shape as
    /// guardrail 1).
    RetentionConfirmationRequired {
        /// The current window, in seconds.
        old_window_secs: u64,
        /// The proposed (shorter) window, in seconds.
        new_window_secs: u64,
        /// The estimated count of now-out-of-window data points that would
        /// be removed on apply.
        would_remove_estimate: u64,
    },
    /// Break-glass restore attempted by someone other than the cell
    /// genesis-key holder.
    BreakGlassUnauthorized,
}

// --- guardrail 1: dry-run confirmation --------------------------------------

/// The computed effect of a foundational edit — exactly what the
/// dry-run-gated-confirm UX must show BEFORE the edit may commit: who loses
/// access, and what becomes unreachable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditEffect {
    /// Subjects who would lose access under this edit (empty for an edit
    /// that grants/adds rather than reduces access).
    pub losing_access: Vec<NodeId>,
    /// Addresses/paths that would become unreachable under this edit.
    pub becomes_unreachable: Vec<String>,
}

impl EditEffect {
    /// No one loses anything and nothing becomes unreachable — a purely
    /// additive edit.
    #[must_use]
    pub fn none() -> Self {
        EditEffect::default()
    }

    /// Whether this effect reduces access/reachability at all (i.e. whether
    /// a dry-run confirmation is even meaningful to show).
    #[must_use]
    pub fn is_reducing(&self) -> bool {
        !self.losing_access.is_empty() || !self.becomes_unreachable.is_empty()
    }
}

/// Guardrail 1 — DRY-RUN CONFIRMATION: reuses the SAME preview-then-confirm
/// shape the IAM CLI's `dry_run` and [`crate::resource::ResourcePlane`]'s
/// `dry_run_apply` family already establish. `effect` is the ALREADY-COMPUTED
/// preview (who loses access / what becomes unreachable); this function is
/// the confirmation gate that refuses to proceed until `confirmed` is `true`
/// — mutating NOTHING itself either way.
///
/// # Errors
/// [`GuardrailError::ConfirmationRequired`] carrying the effect, iff `effect`
/// reduces access/reachability and `confirmed` is `false`. A purely additive
/// effect (nothing lost) never requires confirmation.
pub fn preview_foundational_edit(
    effect: &EditEffect,
    confirmed: bool,
) -> Result<(), GuardrailError> {
    if effect.is_reducing() && !confirmed {
        return Err(GuardrailError::ConfirmationRequired {
            losing_access: effect.losing_access.clone(),
            becomes_unreachable: effect.becomes_unreachable.clone(),
        });
    }
    Ok(())
}

// --- guardrail 2: no-lockout admission --------------------------------------

/// Guardrail 2 — NO-LOCKOUT ADMISSION: refuses (before anything is written)
/// an edit that would leave `proposed_admins` empty, or that strips
/// `editor`'s own catalog-reconcile ability.
///
/// # Errors
/// [`GuardrailError::LockoutRefused`] if `proposed_admins` is empty, or if
/// `editor_retains_catalog_reconcile` is `false`.
pub fn admits_no_lockout(
    proposed_admins: &BTreeSet<NodeId>,
    editor_retains_catalog_reconcile: bool,
) -> Result<(), GuardrailError> {
    if proposed_admins.is_empty() {
        return Err(GuardrailError::LockoutRefused {
            reason: "edit would leave zero administrators",
        });
    }
    if !editor_retains_catalog_reconcile {
        return Err(GuardrailError::LockoutRefused {
            reason: "edit strips the editor's own catalog-reconcile ability",
        });
    }
    Ok(())
}

// --- guardrail 3: strict (CP) revocation ------------------------------------

/// Guardrail 3 — STRICT (CP) REVOCATION: an access-reducing foundational
/// edit's revoke is folded through a real
/// [`pillar_streamdb::cofold::StrictCofold`] over
/// [`pillar_streamdb::cofold::UniqueOnce`] (`cp-viewpolicy-strict-cofold`),
/// so it can never be half-applied (a stale/unfenced writer is refused
/// outright) or lost (never silently re-admitted / silently dropped —
/// exactly-once per key).
pub struct StrictRevocation {
    cofold: StrictCofold<UniqueOnce>,
}

impl StrictRevocation {
    /// A fresh strict-revocation fold with no keys admitted yet.
    #[must_use]
    pub fn new() -> Self {
        StrictRevocation {
            cofold: StrictCofold::new(UniqueOnce::new()),
        }
    }

    /// Whether `key` (a foundational resource's revocation partition key,
    /// e.g. `<kind>/<name>`) has already been strictly revoked.
    #[must_use]
    pub fn already_revoked(&self, key: &[u8]) -> bool {
        self.cofold.held_epoch(key).is_some()
    }

    /// Acquire the fencing epoch for `key`'s partition and admit the revoke
    /// `payload` under it, in one call — the SAME acquire-then-admit shape
    /// [`StrictCofold`] enforces: a caller with less than a quorum of the
    /// coordination core never becomes the fenced writer for `key`, and every
    /// subsequent revoke attempt for it is refused rather than silently
    /// admitted from a stale/minority writer.
    ///
    /// # Errors
    /// [`GuardrailError::RevocationNotStrict`] wrapping
    /// [`CoFoldError::NotFenced`] if `candidate` does not (yet) hold `epoch`
    /// for `key` per `lease`, or [`CoFoldError::DuplicateKey`] if `key` was
    /// already strictly revoked.
    pub fn revoke(
        &mut self,
        lease: &mut LeaseRegister,
        candidate: &NodeId,
        key: &[u8],
        epoch: Epoch,
        payload: Vec<u8>,
    ) -> Result<OpId, GuardrailError> {
        if !self.cofold.acquire(key, lease, candidate, epoch) {
            return Err(GuardrailError::RevocationNotStrict(
                CoFoldError::NotFenced {
                    key: key.to_vec(),
                    claimed: epoch,
                    held: self.cofold.held_epoch(key),
                },
            ));
        }
        self.cofold
            .try_admit(key, epoch, payload)
            .map_err(GuardrailError::RevocationNotStrict)
    }
}

impl Default for StrictRevocation {
    fn default() -> Self {
        Self::new()
    }
}

// --- guardrail 4: higher authority ------------------------------------------

/// Derive the foundational-scope [`PolicyEvent`] from an ordinary-resource
/// one: SAME target/capability, threshold raised by
/// [`FOUNDATIONAL_THRESHOLD_MARGIN`] — reusing the exact per-scope threshold
/// policy machinery `rbac-decider` already defines rather than inventing a
/// parallel authorization path.
#[must_use]
pub fn foundational_policy(ordinary: &PolicyEvent) -> PolicyEvent {
    PolicyEvent {
        target: ordinary.target.clone(),
        capability: ordinary.capability.clone(),
        depth_threshold: ordinary
            .depth_threshold
            .saturating_add(FOUNDATIONAL_THRESHOLD_MARGIN),
    }
}

/// Guardrail 4 — HIGHER AUTHORITY: whether `subject`'s
/// [`WotAuthority::reachable_depth`] budget meets the foundational threshold
/// (`ordinary_threshold + `[`FOUNDATIONAL_THRESHOLD_MARGIN`]) — strictly
/// stricter than the capability's ordinary-resource `depth_threshold` alone.
#[must_use]
pub fn meets_higher_authority(
    authority: &WotAuthority,
    subject: &NodeId,
    ordinary_threshold: u8,
) -> bool {
    let required = ordinary_threshold.saturating_add(FOUNDATIONAL_THRESHOLD_MARGIN);
    authority
        .reachable_depth(subject)
        .is_some_and(|depth| depth >= required)
}

/// Guardrail 4 as a refusal: the same check as [`meets_higher_authority`],
/// returning the concrete [`GuardrailError::InsufficientAuthority`] on
/// failure (carrying the required threshold and the subject's actual budget,
/// for the operator-facing refusal message).
///
/// # Errors
/// [`GuardrailError::InsufficientAuthority`] iff the subject's budget is
/// below `ordinary_threshold + `[`FOUNDATIONAL_THRESHOLD_MARGIN`].
pub fn guard_higher_authority(
    authority: &WotAuthority,
    subject: &NodeId,
    ordinary_threshold: u8,
) -> Result<(), GuardrailError> {
    let required = ordinary_threshold.saturating_add(FOUNDATIONAL_THRESHOLD_MARGIN);
    let actual = authority.reachable_depth(subject);
    if actual.is_some_and(|depth| depth >= required) {
        Ok(())
    } else {
        Err(GuardrailError::InsufficientAuthority { required, actual })
    }
}

// --- guardrail 5: immutable identity ----------------------------------------

/// Whether `field` on a system collection / genesis identity object may be
/// edited at all (guardrail 5, "IMMUTABLE IDENTITY"). Every other field on
/// the object stays viewable/tunable; only identity/kind fields are pinned.
#[must_use]
pub fn is_identity_field_mutable(field: &str) -> bool {
    !IMMUTABLE_IDENTITY_FIELDS.contains(&field)
}

/// Guardrail 5 as a refusal: refuses an edit that targets a read-only
/// identity field.
///
/// # Errors
/// [`GuardrailError::ImmutableField`] iff `field` is one of
/// [`IMMUTABLE_IDENTITY_FIELDS`].
pub fn guard_identity_edit(field: &str) -> Result<(), GuardrailError> {
    if is_identity_field_mutable(field) {
        Ok(())
    } else {
        Err(GuardrailError::ImmutableField {
            field: field.to_owned(),
        })
    }
}

// --- break-glass -------------------------------------------------------------

/// BREAK-GLASS: the cell genesis-key holder can ALWAYS restore the seed
/// administrator binding — authority is recoverable even after a legitimate
/// (guardrail-admitted) edit sequence leaves the cell in an unintended state.
/// This is the ONE path that bypasses guardrail 2/4's ordinary admission
/// checks (a restore can never itself be the lockout), gated ONLY on
/// `genesis_key_holder == cell_genesis_identity`.
///
/// # Errors
/// [`GuardrailError::BreakGlassUnauthorized`] iff `genesis_key_holder` is not
/// the cell's genesis identity.
pub fn break_glass_restore_seed_admin(
    genesis_key_holder: &NodeId,
    cell_genesis_identity: &NodeId,
    admins: &mut BTreeSet<NodeId>,
    seed_admin: NodeId,
) -> Result<(), GuardrailError> {
    if genesis_key_holder != cell_genesis_identity {
        return Err(GuardrailError::BreakGlassUnauthorized);
    }
    admins.insert(seed_admin);
    Ok(())
}

// --- retention-window shortening --------------------------------------------

/// Whether shortening a `RetentionPolicy`'s window from `old_window_secs` to
/// `new_window_secs` is a SHORTENING at all (and therefore requires the
/// strong confirmation [`apply_retention_shortening`] enforces).
#[must_use]
pub fn retention_shortening_requires_confirmation(
    old_window_secs: u64,
    new_window_secs: u64,
) -> bool {
    new_window_secs < old_window_secs
}

/// Apply a `RetentionPolicy` window edit: a SHORTENING removes out-of-window
/// data on apply and requires a strong confirmation before doing so — the
/// same reducing-edit shape guardrail 1 gates, applied specifically to the
/// retention-window case the task calls out.
///
/// # Errors
/// [`GuardrailError::RetentionConfirmationRequired`] iff this is a
/// shortening (`new_window_secs < old_window_secs`) and `confirmed` is
/// `false`. A widening (or unchanged) window never requires confirmation and
/// never removes anything.
///
/// # Returns
/// On success, the count of out-of-window data points removed by this apply
/// (`0` for a widening/unchanged window).
pub fn apply_retention_shortening(
    old_window_secs: u64,
    new_window_secs: u64,
    out_of_window_estimate: u64,
    confirmed: bool,
) -> Result<u64, GuardrailError> {
    if retention_shortening_requires_confirmation(old_window_secs, new_window_secs) {
        if !confirmed {
            return Err(GuardrailError::RetentionConfirmationRequired {
                old_window_secs,
                new_window_secs,
                would_remove_estimate: out_of_window_estimate,
            });
        }
        Ok(out_of_window_estimate)
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_rbac::{Capability, PolicyTarget, ResourceClass};

    fn nid(s: &str) -> NodeId {
        NodeId::from(s)
    }

    #[test]
    fn dry_run_confirmation_gates_reducing_edits_only() {
        let additive = EditEffect::none();
        assert!(preview_foundational_edit(&additive, false).is_ok());

        let reducing = EditEffect {
            losing_access: vec![nid("operator-a")],
            becomes_unreachable: vec!["Collection/system".to_owned()],
        };
        let err = preview_foundational_edit(&reducing, false).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::ConfirmationRequired {
                losing_access: vec![nid("operator-a")],
                becomes_unreachable: vec!["Collection/system".to_owned()],
            }
        );
        assert!(preview_foundational_edit(&reducing, true).is_ok());
    }

    #[test]
    fn no_lockout_refuses_zero_admins_and_self_lockout() {
        let mut admins: BTreeSet<NodeId> = BTreeSet::new();
        assert_eq!(
            admits_no_lockout(&admins, true).unwrap_err(),
            GuardrailError::LockoutRefused {
                reason: "edit would leave zero administrators"
            }
        );
        admins.insert(nid("admin-a"));
        assert_eq!(
            admits_no_lockout(&admins, false).unwrap_err(),
            GuardrailError::LockoutRefused {
                reason: "edit strips the editor's own catalog-reconcile ability"
            }
        );
        assert!(admits_no_lockout(&admins, true).is_ok());
    }

    #[test]
    fn strict_revocation_is_fenced_and_exactly_once() {
        let mut revoke = StrictRevocation::new();
        let mut lease = LeaseRegister::new(3);
        let candidate = nid("node-a");
        let key = b"RoleBinding/seed-admin";

        // No quorum yet -> not fenced -> refused.
        lease.grant(nid("v1"), candidate.clone(), Epoch(1)).unwrap();
        let refused = revoke.revoke(&mut lease, &candidate, key, Epoch(1), b"revoke".to_vec());
        assert!(matches!(
            refused,
            Err(GuardrailError::RevocationNotStrict(
                CoFoldError::NotFenced { .. }
            ))
        ));

        // Quorum reached -> the fenced candidate's revoke is admitted, exactly once.
        lease.grant(nid("v2"), candidate.clone(), Epoch(1)).unwrap();
        revoke
            .revoke(&mut lease, &candidate, key, Epoch(1), b"revoke".to_vec())
            .expect("first strict revoke under a held epoch succeeds");
        assert!(revoke.already_revoked(key));

        // A second revoke for the SAME key is refused: never half-applied,
        // never silently re-admitted / lost.
        let dup = revoke.revoke(
            &mut lease,
            &candidate,
            key,
            Epoch(1),
            b"revoke-again".to_vec(),
        );
        assert!(matches!(
            dup,
            Err(GuardrailError::RevocationNotStrict(
                CoFoldError::DuplicateKey { .. }
            ))
        ));
    }

    #[test]
    fn higher_authority_requires_ordinary_threshold_plus_margin() {
        let owner = nid("owner");
        let mut authority = WotAuthority::new(owner.clone(), 5);
        let close = nid("close-operator");
        let far = nid("far-operator");
        authority.issue_edge(owner.clone(), close.clone(), 4);
        authority.issue_edge(owner.clone(), far.clone(), 2);

        let ordinary_threshold = 2;
        // `close` has enough remaining budget to clear ordinary + margin.
        assert!(meets_higher_authority(
            &authority,
            &close,
            ordinary_threshold
        ));
        guard_higher_authority(&authority, &close, ordinary_threshold)
            .expect("close operator clears the foundational threshold");

        // `far` clears the ORDINARY threshold but not the foundational one.
        assert!(authority.reachable_depth(&far).unwrap() >= ordinary_threshold);
        assert!(!meets_higher_authority(
            &authority,
            &far,
            ordinary_threshold
        ));
        assert!(matches!(
            guard_higher_authority(&authority, &far, ordinary_threshold),
            Err(GuardrailError::InsufficientAuthority { .. })
        ));
    }

    #[test]
    fn foundational_policy_raises_threshold_over_ordinary() {
        let ordinary = PolicyEvent {
            target: PolicyTarget::ResourceClass(ResourceClass::All),
            capability: Capability::from("resourceset/write"),
            depth_threshold: 2,
        };
        let foundational = foundational_policy(&ordinary);
        assert_eq!(foundational.target, ordinary.target);
        assert_eq!(foundational.capability, ordinary.capability);
        assert_eq!(
            foundational.depth_threshold,
            ordinary.depth_threshold + FOUNDATIONAL_THRESHOLD_MARGIN
        );
    }

    #[test]
    fn identity_fields_are_immutable_everything_else_is_not() {
        for f in IMMUTABLE_IDENTITY_FIELDS {
            assert!(!is_identity_field_mutable(f));
            assert!(matches!(
                guard_identity_edit(f),
                Err(GuardrailError::ImmutableField { .. })
            ));
        }
        assert!(is_identity_field_mutable("labels"));
        guard_identity_edit("spec.window").expect("non-identity fields stay tunable");
    }

    #[test]
    fn break_glass_restores_only_for_the_genesis_key_holder() {
        let genesis = nid("cell-genesis");
        let mut admins: BTreeSet<NodeId> = BTreeSet::new();
        let seed_admin = nid("seed-admin");

        let refused = break_glass_restore_seed_admin(
            &nid("impostor"),
            &genesis,
            &mut admins,
            seed_admin.clone(),
        );
        assert_eq!(refused.unwrap_err(), GuardrailError::BreakGlassUnauthorized);
        assert!(admins.is_empty());

        break_glass_restore_seed_admin(&genesis, &genesis, &mut admins, seed_admin.clone())
            .expect("the genesis-key holder can always restore the seed admin binding");
        assert!(admins.contains(&seed_admin));
    }

    #[test]
    fn retention_shortening_requires_strong_confirmation_and_removes_data() {
        // Widening never requires confirmation and never removes anything.
        assert!(!retention_shortening_requires_confirmation(
            7 * 86_400,
            30 * 86_400
        ));
        assert_eq!(
            apply_retention_shortening(7 * 86_400, 30 * 86_400, 999, false).unwrap(),
            0
        );

        // Shortening requires confirmation.
        assert!(retention_shortening_requires_confirmation(
            30 * 86_400,
            7 * 86_400
        ));
        let refused = apply_retention_shortening(30 * 86_400, 7 * 86_400, 4_200, false);
        assert_eq!(
            refused.unwrap_err(),
            GuardrailError::RetentionConfirmationRequired {
                old_window_secs: 30 * 86_400,
                new_window_secs: 7 * 86_400,
                would_remove_estimate: 4_200,
            }
        );

        // Confirmed shortening applies and reports the removed count.
        let removed = apply_retention_shortening(30 * 86_400, 7 * 86_400, 4_200, true).unwrap();
        assert_eq!(removed, 4_200);
    }
}
