//! # pillar-realness-gate
//!
//! The merge-blocking **feature-realness gate** (ROI Priority 0, "The workload
//! reckoning — the hard gate: feature-realness, enforced at merge",
//! 2026-08-31). It is the forcing function that stops the corpus of *model-DONE*
//! tasks (`controller-vertical-proof`, `scheduler-controller-impl`,
//! `service-route-dns-controller`, `builtin-resource-definitions`) from growing:
//! a task may not claim a running feature and land a diff that only *models* it.
//!
//! It generalises the crypto realness gate ([`pillar-crypto`]'s
//! `realness_gate.rs`) beyond crypto, and adds two plan-level teeth. Three teeth
//! total:
//!
//! 1. **Static realness scan** ([`scan`]) — scans every shipping (non-`#[cfg(test)]`)
//!    source path and FAILS when it finds a no-op reconcile/handler that reports
//!    success without a side effect, a stand-in / placeholder payload used as
//!    real data, or a modeled `run`/`fetch`/`bind`/`resolve`/`forward` verb with
//!    no corresponding real syscall in the same delivered path. The annotated LB
//!    `consistent_hash` and `#[cfg(test)]` fixtures are the only exemptions.
//! 2. **Verb-claim => acceptance-Check lint** ([`plan_lint::verb_claim_offenses`]) —
//!    a plan where a task BODY verb-claims execution but its `Check:` is a unit
//!    test over a model rather than an acceptance-tier integration/e2e test.
//! 3. **No attempts=0 feature-DONE** ([`plan_lint::same_reconcile_feature_done`],
//!    [`plan_lint::feature_done_without_real_io`]) — a feature-tier task may not
//!    be flipped DONE in the same reconcile that files it, nor reach DONE with a
//!    Check whose output shows no real socket/process I/O.
//!
//! The crate is a library so the same logic backs both the merge gate (its own
//! `cargo test -p pillar-realness-gate`, wired into CI as a REQUIRED status
//! check) and `beehive plan lint` (which calls the plan-level teeth).

#![allow(clippy::needless_doctest_main)]

pub mod plan_lint;
pub mod scan;

pub use plan_lint::{
    feature_done_without_real_io, same_reconcile_feature_done, verb_claim_offenses, PlanOffense,
    Task,
};
pub use scan::{scan_source, scan_workspace, Offense};
