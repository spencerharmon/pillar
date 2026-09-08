//! # pillar-integration-coverage
//!
//! The `pillar-integration` coverage ledger (ROI "pillar-integration",
//! operator-directed, 2026-08-31) — the anti-false-done spine that closes the
//! gap between "a surface exists" and "a scenario actually proves it real".
//!
//! Three gates, of which this crate implements two directly and wires the
//! third's plan-level enforcement into [`pillar_realness_gate`]:
//!
//! 1. **Gate 1 — no orphan surface** ([`orphan_surface_offenses`]). Every
//!    entry in the real [`pillar_surface_inventory`] must be claimed by at
//!    least one registered [`ScenarioClaim`], and every claim must name a
//!    "realness oracle" — the concrete, non-model evidence (a live socket, a
//!    spawned process, a digest-verified fetch, …) the scenario asserts on.
//!    A surface with zero claiming scenarios, or a claim with no oracle,
//!    FAILS the build.
//! 2. **Gate 2 — feature-tier DONE requires a green scenario.** A PLAN
//!    feature-tier task cannot reach `DONE` unless its named
//!    `pillar-integration` scenario is green on the Gitea Actions runner.
//!    This is enforced by wiring [`ScenarioClaim`] lookups into
//!    `pillar-realness-gate`'s plan-level tooth #2, delivered by the
//!    follow-on `feature-realness-gate-integration-scenario-gate` task — this
//!    crate exposes [`ScenarioClaim`] and the ledger precisely so that task
//!    has something concrete to call.
//! 3. **Gate 3 — a skip cannot be quiet forever** ([`skip_deadline_offenses`]).
//!    A scenario marked `skip`/`xfail` carries a declared deadline; before the
//!    deadline it is only a WARNING (tracked, not blocking), but past the
//!    deadline it becomes an ERROR — a skipped proof cannot be silently
//!    disabled indefinitely.
//!
//! The ledger itself (which scenarios exist and what they claim) is supplied
//! by the caller — this crate is the enforcement machinery, not a hardcoded
//! catalog of scenarios, exactly as `pillar-surface-inventory` reads the real
//! served registries rather than hand-maintaining a list.

use pillar_surface_inventory::SurfaceEntry;

/// A registered integration scenario's claim over the surface inventory: which
/// surface ids it exercises, and the realness oracle it asserts on to prove
/// the exercise was real (not merely modeled).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioClaim {
    /// A stable identifier for the scenario (e.g. a `#[test]` name or a
    /// `pillar-integration` scenario id from the ROI's scenario-family list).
    pub scenario_id: String,
    /// The surface-inventory entry ids ([`SurfaceEntry::id`]) this scenario
    /// claims to exercise.
    pub claims: Vec<String>,
    /// The realness oracle this scenario asserts on to prove its claim is
    /// real — e.g. `"listening-port"`, `"spawned-pid"`,
    /// `"digest-verified-fetch"`. `None` means the scenario claims a surface
    /// but names no concrete proof mechanism — itself an offense.
    pub realness_oracle: Option<String>,
    /// If this scenario is currently skipped/xfail'd, the skip record naming
    /// why and by when it must be un-skipped.
    pub skip: Option<ScenarioSkip>,
}

/// A scenario's skip/xfail record: a deliberate, tracked, TIME-BOUNDED
/// exemption — never a silent, permanent disable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSkip {
    /// Human-readable reason the scenario is currently skipped.
    pub reason: String,
    /// The deadline (an ISO-8601 `YYYY-MM-DD` date) by which the scenario
    /// must be un-skipped and green again. Compared lexicographically against
    /// `today` (`YYYY-MM-DD` sorts identically to date order), so no date
    /// dependency is required.
    pub deadline: String,
}

/// One coverage-ledger offense.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageOffense {
    /// A short machine tag naming which gate/tooth fired.
    pub kind: String,
    /// Human-readable detail (the surface id or scenario id involved).
    pub detail: String,
}

impl core::fmt::Display for CoverageOffense {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "coverage-gate: [{}] {}", self.kind, self.detail)
    }
}

/// Gate 1. For every entry in `inventory`, at least one scenario in
/// `scenarios` must name it in [`ScenarioClaim::claims`] — otherwise it is an
/// ORPHAN SURFACE (present in the inventory, claimed by zero scenarios).
/// Additionally, every claim naming at least one surface must carry a
/// `realness_oracle`; a claim with none is a REALNESS-LESS CLAIM offense (the
/// claim exists but proves nothing concrete).
#[must_use]
pub fn orphan_surface_offenses(
    inventory: &[SurfaceEntry],
    scenarios: &[ScenarioClaim],
) -> Vec<CoverageOffense> {
    let mut out = Vec::new();

    for entry in inventory {
        let claimed = scenarios.iter().any(|s| s.claims.iter().any(|c| c == &entry.id));
        if !claimed {
            out.push(CoverageOffense {
                kind: "orphan-surface".to_string(),
                detail: format!(
                    "surface `{}` ({:?}) has zero claiming scenarios",
                    entry.id, entry.kind
                ),
            });
        }
    }

    for s in scenarios {
        if !s.claims.is_empty() && s.realness_oracle.is_none() {
            out.push(CoverageOffense {
                kind: "claim-without-oracle".to_string(),
                detail: format!(
                    "scenario `{}` claims {} surface(s) but names no realness oracle",
                    s.scenario_id,
                    s.claims.len()
                ),
            });
        }
    }

    out
}

/// `true` iff [`orphan_surface_offenses`] is empty — the GREEN condition for
/// Gate 1.
#[must_use]
pub fn gate1_holds(inventory: &[SurfaceEntry], scenarios: &[ScenarioClaim]) -> bool {
    orphan_surface_offenses(inventory, scenarios).is_empty()
}

/// Gate 3. For every scenario in `scenarios` carrying a [`ScenarioSkip`], if
/// `today >= skip.deadline` (lexicographic `YYYY-MM-DD` comparison) the skip
/// is a hard ERROR offense; a skip whose deadline has not yet passed produces
/// NO offense here (it is a tracked warning, surfaced separately by a caller
/// that wants to list `[(scenario_id, skip)]` pairs rather than fail the
/// build — see [`pending_skips`]).
#[must_use]
pub fn skip_deadline_offenses(scenarios: &[ScenarioClaim], today: &str) -> Vec<CoverageOffense> {
    let mut out = Vec::new();
    for s in scenarios {
        if let Some(skip) = &s.skip {
            if today >= skip.deadline.as_str() {
                out.push(CoverageOffense {
                    kind: "skip-past-deadline".to_string(),
                    detail: format!(
                        "scenario `{}` is skipped (\"{}\") past its declared deadline {} \
                         (today={today}); the proof cannot be quietly disabled",
                        s.scenario_id, skip.reason, skip.deadline
                    ),
                });
            }
        }
    }
    out
}

/// Every currently-skipped scenario whose deadline has NOT yet passed — the
/// WARNING-tier view of Gate 3 (tracked, non-blocking) a caller can print
/// alongside a passing gate to keep the pending skips visible.
#[must_use]
pub fn pending_skips<'a>(
    scenarios: &'a [ScenarioClaim],
    today: &str,
) -> Vec<(&'a str, &'a ScenarioSkip)> {
    scenarios
        .iter()
        .filter_map(|s| s.skip.as_ref().map(|skip| (s.scenario_id.as_str(), skip)))
        .filter(|(_, skip)| today < skip.deadline.as_str())
        .collect()
}

/// `true` iff [`skip_deadline_offenses`] is empty — the GREEN condition for
/// Gate 3.
#[must_use]
pub fn gate3_holds(scenarios: &[ScenarioClaim], today: &str) -> bool {
    skip_deadline_offenses(scenarios, today).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_surface_inventory::SurfaceKind;

    fn entry(id: &str) -> SurfaceEntry {
        SurfaceEntry {
            id: id.to_string(),
            kind: SurfaceKind::HttpRoute,
            signature: format!("GET {id}"),
        }
    }

    fn claim(scenario_id: &str, claims: &[&str], oracle: Option<&str>) -> ScenarioClaim {
        ScenarioClaim {
            scenario_id: scenario_id.to_string(),
            claims: claims.iter().map(|s| s.to_string()).collect(),
            realness_oracle: oracle.map(|s| s.to_string()),
            skip: None,
        }
    }

    #[test]
    fn orphaned_surface_is_flagged() {
        let inventory = vec![entry("http:GET /a"), entry("http:GET /b-orphan")];
        let scenarios = vec![claim("scenario-a", &["http:GET /a"], Some("listening-port"))];
        let offenses = orphan_surface_offenses(&inventory, &scenarios);
        assert!(
            offenses
                .iter()
                .any(|o| o.kind == "orphan-surface" && o.detail.contains("b-orphan")),
            "{offenses:?}"
        );
    }

    #[test]
    fn claimed_surface_with_oracle_is_clean() {
        let inventory = vec![entry("http:GET /a")];
        let scenarios = vec![claim("scenario-a", &["http:GET /a"], Some("listening-port"))];
        assert!(gate1_holds(&inventory, &scenarios));
    }

    #[test]
    fn claim_without_oracle_is_flagged_even_if_surface_covered() {
        let inventory = vec![entry("http:GET /a")];
        let scenarios = vec![claim("scenario-a", &["http:GET /a"], None)];
        let offenses = orphan_surface_offenses(&inventory, &scenarios);
        assert!(
            offenses
                .iter()
                .any(|o| o.kind == "claim-without-oracle" && o.detail.contains("scenario-a")),
            "{offenses:?}"
        );
        assert!(!gate1_holds(&inventory, &scenarios));
    }

    #[test]
    fn skip_before_deadline_is_a_warning_only() {
        let scenarios = vec![ScenarioClaim {
            scenario_id: "scenario-a".to_string(),
            claims: vec!["http:GET /a".to_string()],
            realness_oracle: Some("listening-port".to_string()),
            skip: Some(ScenarioSkip {
                reason: "flaky upstream".to_string(),
                deadline: "2099-01-01".to_string(),
            }),
        }];
        assert!(gate3_holds(&scenarios, "2026-09-07"));
        assert_eq!(pending_skips(&scenarios, "2026-09-07").len(), 1);
    }

    #[test]
    fn skip_past_deadline_is_an_error() {
        let scenarios = vec![ScenarioClaim {
            scenario_id: "scenario-a".to_string(),
            claims: vec!["http:GET /a".to_string()],
            realness_oracle: Some("listening-port".to_string()),
            skip: Some(ScenarioSkip {
                reason: "flaky upstream".to_string(),
                deadline: "2026-01-01".to_string(),
            }),
        }];
        let offenses = skip_deadline_offenses(&scenarios, "2026-09-07");
        assert_eq!(offenses.len(), 1, "{offenses:?}");
        assert_eq!(offenses[0].kind, "skip-past-deadline");
        assert!(!gate3_holds(&scenarios, "2026-09-07"));
    }

    #[test]
    fn skip_exactly_on_deadline_is_an_error() {
        let scenarios = vec![ScenarioClaim {
            scenario_id: "scenario-a".to_string(),
            claims: vec![],
            realness_oracle: None,
            skip: Some(ScenarioSkip {
                reason: "flaky".to_string(),
                deadline: "2026-09-07".to_string(),
            }),
        }];
        assert!(!gate3_holds(&scenarios, "2026-09-07"));
    }
}
