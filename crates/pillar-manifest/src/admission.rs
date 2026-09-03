//! Quota admission — enforce the built `pillar-quota-ledger` at ADMISSION
//! time, riding the SAME built-in-resource controller interface every kind
//! uses ([`crate::builtin::ControllerRegistry`] / [`crate::builtin::ControllerHook`]).
//!
//! # Why this module exists
//!
//! The [`pillar_quota_ledger::QuotaLedger`] is a fully built, quorum-fenced
//! enforcement layer: `admit` refuses an over-budget reservation with
//! [`pillar_quota_ledger::LedgerError::WouldExceedBudget`] and consumes no
//! slot. But nothing WIRED that refusal into the manifest admission path — a
//! workload manifest was validated for schema and reconciled, never CHARGED
//! against its quota. This module surfaces the ledger where it belongs:
//!
//! - **Enforced at admission, not after the fact.** A manifest declaring a
//!   `quota` amount is admitted only if it fits the remaining budget. An
//!   over-budget request is REFUSED at admission ([`AdmissionOutcome::Refused`])
//!   and never recorded — exactly the ledger's `WouldExceedBudget` gate, now
//!   reached from the controller interface a CRD flows through.
//! - **Same interface as any built-in kind.** [`QuotaAdmissionHook`] implements
//!   the ordinary [`ControllerHook`] and registers with the ordinary
//!   [`ControllerRegistry::register`] under a `(apiVersion, kind)` key — there
//!   is NO special-cased admission fork. A cell whose registry has no such hook
//!   for a kind simply dispatches `None` and admits the workload normally
//!   (the "controller absent still boots and admits" property): admission
//!   enforcement is OPTIONAL and never a bootstrap dependency.
//! - **Usage is surfaced from real ledger state.** [`QuotaUsage::of`] snapshots
//!   the LIVE ledger (`budget`/`reserved`/`available`), producing a
//!   portal-consumable view derived from the actual op-log-backed reservations,
//!   not a recomputed guess.

use std::cell::RefCell;

use pillar_core::NodeId;
use pillar_quota_ledger::{LedgerError, QuotaLedger, ReservationId};

use crate::builtin::{ControllerHook, ReconcileOutcome};
use crate::{Crd, Value};

/// The spec field a workload manifest declares its requested quota amount in.
/// A CRD carrying this integer field is charged that many budget units at
/// admission; a CRD without it requests nothing and is admitted freely.
pub const QUOTA_REQUEST_FIELD: &str = "quota";

/// The outcome of a quota admission decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// The workload was admitted; the reservation charged against the budget is
    /// returned so the caller can release it when the workload terminates.
    Admitted(ReservationId),
    /// The workload declared no quota request — nothing was charged, it is a
    /// plain admit.
    NoRequest,
    /// The workload was refused at admission because it would exceed the
    /// remaining budget (or the ledger refused it for another reason). No slot
    /// is consumed and nothing is recorded.
    Refused(LedgerError),
}

impl AdmissionOutcome {
    /// Whether the workload was admitted (either charged or request-free).
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(
            self,
            AdmissionOutcome::Admitted(_) | AdmissionOutcome::NoRequest
        )
    }
}

/// The quota amount a CRD's spec requests, if any (`spec.quota`, a
/// non-negative integer). A missing field, or a non-integer/negative value,
/// yields `None` — the manifest requests nothing to charge.
#[must_use]
pub fn requested_quota(crd: &Crd) -> Option<u64> {
    match crd.spec.get(QUOTA_REQUEST_FIELD) {
        Some(Value::Integer(n)) if *n >= 0 => Some(*n as u64),
        _ => None,
    }
}

/// A read-only, portal-consumable snapshot of a budget's usage, derived from
/// the LIVE [`QuotaLedger`] state — the real op-log-backed reservations, not a
/// recomputed estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaUsage {
    /// The total declared budget (the quota attestation's amount).
    pub budget: u64,
    /// The amount currently reserved by outstanding admissions.
    pub reserved: u64,
    /// The amount still available to admit against.
    pub available: u64,
}

impl QuotaUsage {
    /// Snapshot `ledger`'s current usage.
    #[must_use]
    pub fn of(ledger: &QuotaLedger) -> Self {
        QuotaUsage {
            budget: ledger.budget(),
            reserved: ledger.reserved(),
            available: ledger.available(),
        }
    }

    /// The reserved fraction of the budget in the range `0.0..=1.0` (a portal
    /// gauge). A zero budget reports fully utilized.
    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.budget == 0 {
            return 1.0;
        }
        self.reserved as f64 / self.budget as f64
    }
}

/// An admission controller enforcing ONE quota budget, wired behind the
/// ordinary built-in controller interface. It holds the enforcement
/// [`QuotaLedger`] and, on each reconcile, CHARGES the CRD's requested quota —
/// refusing (via [`ReconcileOutcome::Failed`]) any manifest that would exceed
/// the budget. Because it is an ordinary [`ControllerHook`], a registry without
/// it dispatches `None` and admits the workload unenforced; enforcement is
/// strictly additive and optional.
///
/// The ledger is `RefCell`-wrapped so the `&self` [`ControllerHook::reconcile`]
/// contract can mutate the running balance; each admitted CRD advances the real
/// op-log-backed ledger.
pub struct QuotaAdmissionHook {
    ledger: RefCell<QuotaLedger>,
    /// The candidate node reservations are fenced for (this cell's identity).
    candidate: NodeId,
    /// The quorum grants to replay for each admission's pending slot. In a
    /// real cell these arrive over coordination gossip; the hook records the
    /// voters it should collect a grant from before admitting.
    voters: Vec<NodeId>,
}

impl QuotaAdmissionHook {
    /// Wire a hook enforcing `ledger`, admitting reservations for `candidate`
    /// fenced by a quorum of `voters`.
    #[must_use]
    pub fn new(ledger: QuotaLedger, candidate: NodeId, voters: Vec<NodeId>) -> Self {
        QuotaAdmissionHook {
            ledger: RefCell::new(ledger),
            candidate,
            voters,
        }
    }

    /// The live usage of the enforced budget — a portal-consumable snapshot of
    /// the REAL ledger state.
    #[must_use]
    pub fn usage(&self) -> QuotaUsage {
        QuotaUsage::of(&self.ledger.borrow())
    }

    /// Attempt to admit `crd` against the budget, charging its `spec.quota`
    /// request. This is the enforcement decision the [`ControllerHook`] runs on
    /// every reconcile, exposed directly so a caller can inspect the reservation.
    pub fn admit(&self, crd: &Crd) -> AdmissionOutcome {
        let Some(amount) = requested_quota(crd) else {
            return AdmissionOutcome::NoRequest;
        };
        let mut ledger = self.ledger.borrow_mut();
        // Collect the pending slot's quorum before charging. Grants are
        // monotonic; a fresh slot is contended each admission.
        for v in &self.voters {
            if let Err(e) = ledger.grant(v.clone(), self.candidate.clone()) {
                return AdmissionOutcome::Refused(e);
            }
        }
        match ledger.admit(&self.candidate, amount) {
            Ok(id) => AdmissionOutcome::Admitted(id),
            Err(e) => AdmissionOutcome::Refused(e),
        }
    }

    /// Release a reservation this hook previously admitted, returning its
    /// amount to the budget.
    pub fn release(&self, id: &ReservationId) -> Result<u64, LedgerError> {
        self.ledger.borrow_mut().release(id)
    }
}

impl ControllerHook for QuotaAdmissionHook {
    /// Enforce the quota at admission: charge the CRD's request and reconcile
    /// only if it fits the budget; an over-budget manifest is REFUSED here (a
    /// `Failed` outcome), never reconciled and never recorded.
    fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
        match self.admit(crd) {
            AdmissionOutcome::Admitted(_) | AdmissionOutcome::NoRequest => {
                ReconcileOutcome::Reconciled
            }
            AdmissionOutcome::Refused(LedgerError::WouldExceedBudget {
                requested,
                available,
            }) => ReconcileOutcome::Failed(format!(
                "quota admission refused: requested {requested} exceeds available {available}"
            )),
            AdmissionOutcome::Refused(e) => {
                ReconcileOutcome::Failed(format!("quota admission refused: {e:?}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::ControllerRegistry;
    use crate::Metadata;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig};

    const API: &str = "pillar.dev/v1";
    const KIND: &str = "Job";

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn quota_attest(amount: u64) -> Attest {
        Attest {
            issuer: n("owner"),
            capacity: Capacity::Role {
                role: "operator".to_owned(),
                scope: "cell-b".to_owned(),
            },
            authority: None,
            subject: n("alice"),
            predicate: Predicate::new("compute:schedule", "cell-b/*").with_quota(amount),
            scope: "cell-b".to_owned(),
            epoch: 0,
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer()
    }

    fn ledger(amount: u64) -> QuotaLedger {
        QuotaLedger::for_budget(&quota_attest(amount), 3).unwrap()
    }

    fn hook(amount: u64) -> QuotaAdmissionHook {
        QuotaAdmissionHook::new(ledger(amount), n("alice"), vec![n("v1"), n("v2")])
    }

    /// A workload manifest requesting `amount` quota units.
    fn workload(amount: i64) -> Crd {
        Crd::new(API, KIND, Metadata::new("wl")).with_spec(QUOTA_REQUEST_FIELD, Value::Integer(amount))
    }

    // --- Test 1: over-budget is REFUSED AT ADMISSION, not recorded after ----

    #[test]
    fn an_admission_over_the_ledger_quota_is_refused_at_admission_not_recorded() {
        let h = hook(1000);
        // Fill 600 of the 1000 budget.
        assert!(matches!(
            h.admit(&workload(600)),
            AdmissionOutcome::Admitted(_)
        ));
        assert_eq!(h.usage().reserved, 600);

        // A request for 500 (only 400 left) is REFUSED at admission — the
        // controller-interface reconcile returns Failed, and the ledger records
        // NOTHING (reserved stays 600, not 1100).
        let outcome = h.reconcile(&workload(500));
        assert!(
            matches!(outcome, ReconcileOutcome::Failed(_)),
            "over-budget admission must be refused, got {outcome:?}"
        );
        assert_eq!(
            h.usage().reserved,
            600,
            "a refused admission must not be charged after the fact"
        );

        // The direct admit path agrees: WouldExceedBudget with the real numbers.
        assert_eq!(
            h.admit(&workload(500)),
            AdmissionOutcome::Refused(LedgerError::WouldExceedBudget {
                requested: 500,
                available: 400,
            })
        );
    }

    // --- Test 2: usage is queryable/surfaced from REAL ledger state ---------

    #[test]
    fn usage_is_surfaced_from_the_real_ledger_state() {
        let h = hook(1000);
        assert_eq!(
            h.usage(),
            QuotaUsage {
                budget: 1000,
                reserved: 0,
                available: 1000
            }
        );

        let id = match h.admit(&workload(750)) {
            AdmissionOutcome::Admitted(id) => id,
            other => panic!("expected admit, got {other:?}"),
        };
        // The snapshot reflects the real op-log-backed reservation.
        let u = h.usage();
        assert_eq!(u.budget, 1000);
        assert_eq!(u.reserved, 750);
        assert_eq!(u.available, 250);
        assert!((u.utilization() - 0.75).abs() < 1e-9);

        // Releasing returns budget — surfaced usage tracks it live.
        assert_eq!(h.release(&id).unwrap(), 750);
        assert_eq!(h.usage().available, 1000);
        assert_eq!(h.usage().reserved, 0);
    }

    // --- Test 3 (property): controller ABSENT still admits normally ---------

    #[test]
    fn a_cell_without_the_quota_controller_still_admits_workloads_normally() {
        // A registry with NO quota admission hook for this kind: dispatch falls
        // through to `None`, exactly as for any unregistered kind — the cell
        // boots and admits the workload unenforced. No bootstrap dependency.
        let registry = ControllerRegistry::new();
        let wl = workload(10_000); // would blow ANY budget, if one existed
        assert_eq!(
            registry.dispatch(&wl),
            None,
            "absent the controller, admission is not gated — the workload falls through"
        );

        // And WITH the hook registered on the SAME interface, the identical
        // dispatch path now enforces — proving enforcement is purely additive.
        let mut enforced = ControllerRegistry::new();
        enforced.register(API, KIND, Box::new(hook(1000)));
        assert_eq!(
            enforced.dispatch(&workload(500)),
            Some(ReconcileOutcome::Reconciled),
            "within budget admits through the ordinary dispatch"
        );
        match enforced.dispatch(&wl) {
            Some(ReconcileOutcome::Failed(_)) => {}
            other => panic!("over-budget must be refused through dispatch, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_without_a_quota_request_is_admitted_free() {
        let h = hook(1000);
        let no_request = Crd::new(API, KIND, Metadata::new("free"));
        assert_eq!(h.admit(&no_request), AdmissionOutcome::NoRequest);
        assert_eq!(h.reconcile(&no_request), ReconcileOutcome::Reconciled);
        assert_eq!(h.usage().reserved, 0);
    }
}
