//! The cell-wide **credential policy** — an editable `CredentialPolicy`
//! resource seeded into the Default ResourceSet floor at bootstrap and READ by
//! the password change/reset ceremonies.
//!
//! ROI Priority 1 "User management & lifecycle" roadmap B2: credential policy
//! (minimum strength, maximum age, reuse history, breach-list) expressed as a
//! first-class, operator-editable resource rather than a hardcoded constant or
//! a bare `Option<u64>` threaded through call sites. It rides the SAME Default
//! ResourceSet floor machinery the shipped `RetentionPolicy` defaults use
//! ([`crate::defaults::bootstrap_default_manifests`]): a
//! [`crate::resource::FLOOR_LABEL`] object whose EXISTENCE is bootstrap-
//! guaranteed (a `delete` is refused) but whose spec the operator freely EDITS
//! via an ordinary `pillar apply`. No new TLA+ gate — it reuses the proven
//! floor-edit guardrails + containment ceremony.
//!
//! Two halves:
//! * The **resource** — [`CredentialPolicy`], its shipped default
//!   [`shipped_default_credential_policy`], the floor-labeled manifest
//!   [`bootstrap_credential_policy_manifest`], and the round-tripping
//!   [`CredentialPolicy::to_crd`] / [`CredentialPolicy::from_crd`].
//! * The **enforcement** the change/reset ceremonies call — a proposed
//!   password is admitted only if it meets minimum strength, is not in the
//!   reuse-history set, and (when the policy enables the breach check) is NOT
//!   present in the **runtime-supplied** breach list. The breach list is NEVER
//!   baked into the resource — it is infrastructure-supplied at runtime (a
//!   `BreachList` the caller injects), keeping site secrets out of the tracked
//!   resource per the credential-policy design.
//!
//! `max_password_age_secs` is the SAME field
//! `pillar_iam::password_lifecycle::{evaluate_login_password_age,
//! admit_gated_action}` already consume — this module makes it an editable
//! resource read rather than a bare parameter, so a single edited resource,
//! not a redeploy, changes the cell's max age.

use std::collections::BTreeSet;

use pillar_manifest::{Crd, Metadata, Value};

use crate::defaults::{
    DEFAULTS_MANAGED_BY_LABEL, DEFAULTS_MANAGED_BY_VALUE, DEFAULT_BUNDLE_LABEL,
    DEFAULT_BUNDLE_VERSION,
};

/// `apiVersion` the credential policy resource carries (the shared resource API).
pub const CREDENTIAL_POLICY_API_VERSION: &str = "pillar.dev/v1";
/// `kind` of the credential policy resource.
pub const CREDENTIAL_POLICY_KIND: &str = "CredentialPolicy";
/// The single, well-known name of the cell-wide credential policy floor object.
pub const CREDENTIAL_POLICY_NAME: &str = "credential-policy-default";

// spec field names (stable wire keys the operator edits in YAML).
const F_MIN_STRENGTH: &str = "minPasswordStrength";
const F_MAX_AGE: &str = "maxPasswordAgeSecs";
const F_REUSE_HISTORY: &str = "reuseHistory";
const F_BREACH_CHECK: &str = "breachCheck";

/// The cell-wide credential policy — the typed image of the editable
/// `CredentialPolicy` resource the change/reset ceremonies read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialPolicy {
    /// Minimum acceptable password strength (a monotonic strength score; a
    /// proposed password scoring below this is refused). `0` = no floor.
    pub min_password_strength: u32,
    /// Optional maximum password age, in seconds. `None` = passwords never go
    /// stale (the SAME semantics
    /// `pillar_iam::password_lifecycle::evaluate_login_password_age` gives a
    /// `None` age). A login past this age is forced-change on next admit.
    pub max_password_age_secs: Option<u64>,
    /// How many previous passwords a new password may not reuse. `0` = no
    /// reuse restriction. The caller supplies the actual history set.
    pub reuse_history: u32,
    /// Whether to reject a proposed password that appears in the
    /// infrastructure-supplied breach list. The breach list itself is NEVER
    /// part of the resource — it is injected at runtime (see [`BreachList`]).
    pub breach_check: bool,
}

impl Default for CredentialPolicy {
    fn default() -> Self {
        // The shipped floor: a sensible baseline, not a placeholder — a
        // moderate strength floor, 90-day max age, refuse the last 5 passwords,
        // and screen against the runtime breach list.
        CredentialPolicy {
            min_password_strength: 3,
            max_password_age_secs: Some(90 * 24 * 60 * 60),
            reuse_history: 5,
            breach_check: true,
        }
    }
}

/// The binary-shipped default credential policy — the floor a fresh cell
/// bootstraps. Distinct from [`Default`] only in intent: this is the value
/// [`bootstrap_credential_policy_manifest`] renders as the seeded resource.
#[must_use]
pub fn shipped_default_credential_policy() -> CredentialPolicy {
    CredentialPolicy::default()
}

impl CredentialPolicy {
    /// Render this policy as a provenance-labeled `CredentialPolicy` [`Crd`]
    /// (the applyable resource `pillar apply -f` consumes and `pillar get`
    /// shows). `version` is the shipped-bundle version stamped into the
    /// provenance label, matching the `RetentionPolicy` defaults' convention.
    #[must_use]
    pub fn to_crd(&self, version: u32) -> Crd {
        let meta = Metadata::new(CREDENTIAL_POLICY_NAME)
            .with_label(DEFAULTS_MANAGED_BY_LABEL, DEFAULTS_MANAGED_BY_VALUE)
            .with_label(DEFAULT_BUNDLE_LABEL, version.to_string());
        let mut crd = Crd::new(CREDENTIAL_POLICY_API_VERSION, CREDENTIAL_POLICY_KIND, meta)
            .with_spec(
                F_MIN_STRENGTH,
                Value::Integer(i64::from(self.min_password_strength)),
            )
            .with_spec(
                F_REUSE_HISTORY,
                Value::Integer(i64::from(self.reuse_history)),
            )
            .with_spec(F_BREACH_CHECK, Value::Boolean(self.breach_check));
        if let Some(age) = self.max_password_age_secs {
            crd = crd.with_spec(F_MAX_AGE, Value::Integer(age as i64));
        }
        crd
    }

    /// Read a `CredentialPolicy` back from a live resource [`Crd`] (the value a
    /// ceremony reads off the resource plane, after an operator may have edited
    /// it). A malformed/negative field falls back to the shipped default for
    /// that field rather than failing closed — a partially-edited resource
    /// still yields a usable policy. A missing `maxPasswordAgeSecs` (or a
    /// non-positive one) means "no max age", so an operator can DISABLE aging
    /// by removing the field.
    #[must_use]
    pub fn from_crd(crd: &Crd) -> CredentialPolicy {
        let shipped = shipped_default_credential_policy();
        let min_password_strength = match crd.spec.get(F_MIN_STRENGTH) {
            Some(Value::Integer(i)) if *i >= 0 => *i as u32,
            _ => shipped.min_password_strength,
        };
        let reuse_history = match crd.spec.get(F_REUSE_HISTORY) {
            Some(Value::Integer(i)) if *i >= 0 => *i as u32,
            _ => shipped.reuse_history,
        };
        let breach_check = match crd.spec.get(F_BREACH_CHECK) {
            Some(Value::Boolean(b)) => *b,
            _ => shipped.breach_check,
        };
        let max_password_age_secs = match crd.spec.get(F_MAX_AGE) {
            Some(Value::Integer(i)) if *i > 0 => Some(*i as u64),
            // Present-but-non-positive or absent both mean "no max age".
            Some(Value::Integer(_)) => None,
            _ if crd.spec.contains_key(F_MAX_AGE) => shipped.max_password_age_secs,
            _ => None,
        };
        CredentialPolicy {
            min_password_strength,
            max_password_age_secs,
            reuse_history,
            breach_check,
        }
    }
}

/// The bootstrap-guaranteed credential policy manifest a fresh cell
/// materializes at cell-creation time — the [`crate::resource::FLOOR_LABEL`]
/// object seeded alongside the default `RetentionPolicy` set. Its EXISTENCE is
/// pinned (delete is refused) while its spec stays freely editable, exactly
/// like the `RetentionPolicy` floor.
#[must_use]
pub fn bootstrap_credential_policy_manifest() -> Crd {
    let mut crd = shipped_default_credential_policy().to_crd(DEFAULT_BUNDLE_VERSION);
    crd.metadata
        .labels
        .insert(crate::resource::FLOOR_LABEL.to_owned(), "true".to_owned());
    crd
}

/// An infrastructure-supplied breach list, injected at RUNTIME. The known-
/// breached password material is NEVER part of the tracked `CredentialPolicy`
/// resource (site data stays out of source/resources) — the deployment supplies
/// it and the ceremony consults it only when the policy enables the breach
/// check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BreachList {
    breached: BTreeSet<Vec<u8>>,
}

impl BreachList {
    /// An empty breach list (no password is considered breached).
    #[must_use]
    pub fn new() -> Self {
        BreachList {
            breached: BTreeSet::new(),
        }
    }

    /// Build a breach list from raw breached-password entries.
    #[must_use]
    pub fn from_entries<I, E>(entries: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Vec<u8>>,
    {
        BreachList {
            breached: entries.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `password` appears in the breach list.
    #[must_use]
    pub fn contains(&self, password: &[u8]) -> bool {
        self.breached.contains(password)
    }
}

/// A minimal, dependency-free password strength score: one point each for
/// length ≥ 8, ≥ 12, and for containing a lowercase, an uppercase, a digit, and
/// a symbol — capped so the shipped floor (`3`) is meaningful. This is the
/// scoring the policy's `min_password_strength` compares against; a deployment
/// may swap a richer estimator, but the ceremony's contract is a monotonic
/// score vs. the policy floor.
#[must_use]
pub fn password_strength(password: &[u8]) -> u32 {
    let mut score = 0u32;
    if password.len() >= 8 {
        score += 1;
    }
    if password.len() >= 12 {
        score += 1;
    }
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    for &b in password {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            _ => symbol = true,
        }
    }
    score += u32::from(lower) + u32::from(upper) + u32::from(digit) + u32::from(symbol);
    score
}

/// Why a proposed new password was refused by the credential policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialPolicyViolation {
    /// The password scores below the policy's minimum strength.
    TooWeak {
        /// The password's computed strength.
        strength: u32,
        /// The policy's required minimum.
        required: u32,
    },
    /// The password matches one of the last `reuse_history` passwords.
    Reused,
    /// The policy enables the breach check and the password is in the
    /// runtime-supplied breach list.
    Breached,
}

/// Enforce the credential policy against a PROPOSED new password — the check
/// the password change/reset ceremonies run BEFORE sealing the new password.
///
/// `history` is the set of the user's recent prior passwords (opaque byte
/// material the caller already holds); a new password matching any of them is
/// refused when the policy's `reuse_history` is non-zero. `breach_list` is the
/// runtime-supplied breach list consulted only when `breach_check` is set.
///
/// Returns `Ok(())` when the password satisfies EVERY enabled rule, else the
/// FIRST violation (checked strength → reuse → breach, a stable order for a
/// deterministic message).
pub fn evaluate_new_password(
    policy: &CredentialPolicy,
    new_password: &[u8],
    history: &[Vec<u8>],
    breach_list: &BreachList,
) -> Result<(), CredentialPolicyViolation> {
    let strength = password_strength(new_password);
    if strength < policy.min_password_strength {
        return Err(CredentialPolicyViolation::TooWeak {
            strength,
            required: policy.min_password_strength,
        });
    }
    if policy.reuse_history > 0 {
        let window = policy.reuse_history as usize;
        let recent = if history.len() > window {
            &history[history.len() - window..]
        } else {
            history
        };
        if recent.iter().any(|p| p.as_slice() == new_password) {
            return Err(CredentialPolicyViolation::Reused);
        }
    }
    if policy.breach_check && breach_list.contains(new_password) {
        return Err(CredentialPolicyViolation::Breached);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_default_round_trips_through_the_crd() {
        let policy = shipped_default_credential_policy();
        let crd = policy.to_crd(DEFAULT_BUNDLE_VERSION);
        assert_eq!(crd.kind, CREDENTIAL_POLICY_KIND);
        assert_eq!(crd.metadata.name, CREDENTIAL_POLICY_NAME);
        assert_eq!(
            crd.metadata
                .labels
                .get(DEFAULTS_MANAGED_BY_LABEL)
                .map(String::as_str),
            Some(DEFAULTS_MANAGED_BY_VALUE)
        );
        let read_back = CredentialPolicy::from_crd(&crd);
        assert_eq!(read_back, policy);
    }

    #[test]
    fn bootstrap_manifest_is_floor_labeled() {
        let crd = bootstrap_credential_policy_manifest();
        assert!(crate::resource::is_floor(&crd));
        // And still parses back to the shipped policy.
        assert_eq!(
            CredentialPolicy::from_crd(&crd),
            shipped_default_credential_policy()
        );
    }

    #[test]
    fn edited_resource_is_read_back_faithfully() {
        // Operator edits: strength 4, no max age (field removed), reuse 10, no
        // breach check.
        let crd = Crd::new(
            CREDENTIAL_POLICY_API_VERSION,
            CREDENTIAL_POLICY_KIND,
            Metadata::new(CREDENTIAL_POLICY_NAME),
        )
        .with_spec(F_MIN_STRENGTH, Value::Integer(4))
        .with_spec(F_REUSE_HISTORY, Value::Integer(10))
        .with_spec(F_BREACH_CHECK, Value::Boolean(false));
        let policy = CredentialPolicy::from_crd(&crd);
        assert_eq!(policy.min_password_strength, 4);
        assert_eq!(policy.max_password_age_secs, None);
        assert_eq!(policy.reuse_history, 10);
        assert!(!policy.breach_check);
    }

    #[test]
    fn weak_password_is_refused() {
        let policy = CredentialPolicy {
            min_password_strength: 3,
            max_password_age_secs: None,
            reuse_history: 0,
            breach_check: false,
        };
        let err = evaluate_new_password(&policy, b"abc", &[], &BreachList::new()).unwrap_err();
        assert!(matches!(err, CredentialPolicyViolation::TooWeak { .. }));
        // A strong password passes.
        assert_eq!(
            evaluate_new_password(&policy, b"Str0ng-Passw0rd!", &[], &BreachList::new()),
            Ok(())
        );
    }

    #[test]
    fn reused_password_is_refused_within_the_history_window() {
        let policy = CredentialPolicy {
            min_password_strength: 0,
            max_password_age_secs: None,
            reuse_history: 2,
            breach_check: false,
        };
        let history = vec![
            b"old-one".to_vec(),
            b"old-two".to_vec(),
            b"old-three".to_vec(),
        ];
        // Within the last-2 window: refused.
        assert_eq!(
            evaluate_new_password(&policy, b"old-three", &history, &BreachList::new()),
            Err(CredentialPolicyViolation::Reused)
        );
        // Outside the window (older than the last 2): allowed again.
        assert_eq!(
            evaluate_new_password(&policy, b"old-one", &history, &BreachList::new()),
            Ok(())
        );
    }

    #[test]
    fn breached_password_is_refused_only_when_the_check_is_enabled() {
        let breach = BreachList::from_entries([b"hunter2".to_vec()]);
        let with_check = CredentialPolicy {
            min_password_strength: 0,
            max_password_age_secs: None,
            reuse_history: 0,
            breach_check: true,
        };
        assert_eq!(
            evaluate_new_password(&with_check, b"hunter2", &[], &breach),
            Err(CredentialPolicyViolation::Breached)
        );
        let without_check = CredentialPolicy {
            breach_check: false,
            ..with_check
        };
        assert_eq!(
            evaluate_new_password(&without_check, b"hunter2", &[], &breach),
            Ok(())
        );
    }
}
