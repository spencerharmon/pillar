//! Teeth 2 & 3 — the plan-level realness lints, called by `beehive plan lint`.
//!
//! These operate on a parsed `PLAN.md`: each task is a `## <id> [STATUS] <!--
//! attempts=N deps=... weight=N ... -->` header followed by a free-text body
//! that may carry `Check:` / `Verify-After-Merge:` / `check=none` fields.
//!
//! * **Tooth 2 — verb-claim => acceptance-Check.** A task whose BODY verb-claims
//!   execution ("run", "runs", "bind", "binds", "resolve", "forward", "fetch
//!   over libp2p", "pulled over libp2p", "executes") must carry an
//!   acceptance-tier `Check:` (an integration/e2e `cargo test` with `--test`,
//!   `-p pillar-e2e`, or `--features …acceptance` — the `acceptance-e2e` stub),
//!   NOT a plain unit-test `Check:` over a model. A verb-claimer with a unit
//!   Check is an offense.
//!
//! * **Tooth 3 — no attempts=0 feature-DONE.** A FEATURE-tier task (its Check is
//!   an acceptance/e2e gate, or the ROI names it a feature) may not be flipped
//!   `DONE` in the SAME reconcile that files it — i.e. it may not be `DONE` with
//!   `attempts=0`. A separate helper checks a feature-tier DONE whose recorded
//!   Check output shows no real socket/process I/O.

/// A parsed PLAN task, carrying only the fields the realness lints need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// Task id (the `## <id>` heading token).
    pub id: String,
    /// Status inside the `[...]` on the header line (e.g. `TODO`, `DONE`).
    pub status: String,
    /// `attempts=N` from the header comment (0 if absent/unparsable).
    pub attempts: u32,
    /// The free-text body (everything between this header and the next).
    pub body: String,
    /// The `Check:` command, if the body declares one.
    pub check: Option<String>,
    /// True if the body declares `check=none`.
    pub check_none: bool,
    /// The `integration-scenario:` field — the `pillar-integration` scenario
    /// family that PROVES this feature-tier task, if the body declares one.
    pub integration_scenario: Option<String>,
}

/// A plan-level offense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOffense {
    /// The offending task id.
    pub task: String,
    /// A short machine tag naming which tooth fired.
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Whole-word (identifier/word-boundary) match of `word` in `hay`, case-
/// insensitively, treating `[A-Za-z0-9_]` as word chars. Lets "run" match "run"
/// and "runs" (a separate entry) without matching "overrun" or "prerun".
fn contains_word(hay: &str, word: &str) -> bool {
    let hay = hay.to_ascii_lowercase();
    let word = word.to_ascii_lowercase();
    let hb = hay.as_bytes();
    let mut start = 0;
    while let Some(pos) = hay[start..].find(&word) {
        let abs = start + pos;
        let before_ok = abs == 0 || !is_word_char(hb[abs - 1]);
        let after = abs + word.len();
        let after_ok = after >= hay.len() || !is_word_char(hb[after]);
        if before_ok && after_ok {
            return true;
        }
        start = abs + word.len();
    }
    false
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Single-word verb claims (matched on a word boundary).
const VERB_WORDS: &[&str] = &[
    "run", "runs", "bind", "binds", "resolve", "forward", "executes",
];
/// Multi-word verb-claim phrases (matched as case-insensitive substrings).
const VERB_PHRASES: &[&str] = &["fetch over libp2p", "pulled over libp2p"];

/// Does this body verb-claim execution of a running feature?
fn body_verb_claims(body: &str) -> bool {
    for &w in VERB_WORDS {
        if contains_word(body, w) {
            return true;
        }
    }
    let lower = body.to_ascii_lowercase();
    VERB_PHRASES.iter().any(|p| lower.contains(p))
}

/// Is this `Check:` command an ACCEPTANCE-tier check (the `acceptance-e2e`
/// stub): a `cargo test` carrying `--test <name>`, `-p pillar-e2e`, or
/// `--features …acceptance`? Anything else (a plain `cargo test` / `-p <unit>`)
/// is a unit-tier check for the purposes of this lint.
pub fn is_acceptance_check(check: &str) -> bool {
    let c = check;
    if !c.contains("cargo") || !contains_word(c, "test") {
        return false;
    }
    // --test <name>
    if c.contains("--test ") {
        return true;
    }
    // -p pillar-e2e
    if c.contains("-p pillar-e2e") || c.contains("--package pillar-e2e") {
        return true;
    }
    // --features <...acceptance...>
    if let Some(rest) = c.split("--features").nth(1) {
        // the token(s) following --features, up to the next flag/end
        let feats = rest.trim_start();
        let token = feats.split_whitespace().next().unwrap_or("");
        if token.contains("acceptance") {
            return true;
        }
    }
    false
}

/// Tooth 2. A task whose body verb-claims execution but whose `Check:` is NOT an
/// acceptance-tier check (or is missing / `check=none`) is an offense.
pub fn verb_claim_offenses(tasks: &[Task]) -> Vec<PlanOffense> {
    let mut out = Vec::new();
    for t in tasks {
        if !body_verb_claims(&t.body) {
            continue;
        }
        let ok = match &t.check {
            Some(cmd) => is_acceptance_check(cmd),
            None => false,
        };
        if t.check_none {
            out.push(PlanOffense {
                task: t.id.clone(),
                kind: "verb-claim-check-none".to_string(),
                detail: "body verb-claims execution but declares check=none; \
                         it needs an acceptance-tier Check (acceptance-e2e stub)"
                    .to_string(),
            });
            continue;
        }
        if !ok {
            out.push(PlanOffense {
                task: t.id.clone(),
                kind: "verb-claim-unit-check".to_string(),
                detail: format!(
                    "body verb-claims execution but Check is not acceptance-tier \
                     (needs --test/-p pillar-e2e/--features acceptance): {:?}",
                    t.check
                ),
            });
        }
    }
    out
}

/// Is this task FEATURE-tier? Its `Check:` is an acceptance/e2e gate, or its body
/// (verb-claiming) marks it a feature.
pub fn is_feature_tier(t: &Task) -> bool {
    if let Some(cmd) = &t.check {
        if is_acceptance_check(cmd) {
            return true;
        }
    }
    body_verb_claims(&t.body)
}

/// Tooth 3a. A feature-tier task flipped `DONE` with `attempts=0` was marked DONE
/// in the same reconcile that filed it — forbidden.
pub fn same_reconcile_feature_done(tasks: &[Task]) -> Vec<PlanOffense> {
    let mut out = Vec::new();
    for t in tasks {
        if t.status == "DONE" && t.attempts == 0 && is_feature_tier(t) {
            out.push(PlanOffense {
                task: t.id.clone(),
                kind: "attempts0-feature-done".to_string(),
                detail: "feature-tier task flipped DONE at attempts=0 (marked DONE in \
                         the same reconcile that filed it)"
                    .to_string(),
            });
        }
    }
    out
}

/// Tooth 3b. Given a feature-tier task's recorded Check OUTPUT, does it show real
/// socket/process I/O? A feature-tier DONE whose check output has no such
/// evidence is a failed invariant (the runner handoff gate treats it so).
///
/// Real-I/O evidence: a bound/listening port, a spawned pid/child, an echoed
/// datagram, a libp2p/swarm event, or a digest-verified fetched blob.
pub fn check_output_shows_real_io(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    const EVIDENCE: &[&str] = &[
        "listening on",
        "bound to",
        "udpsocket",
        "tcplistener",
        "spawned pid",
        "child pid",
        "pid=",
        "echoed datagram",
        "swarm event",
        "libp2p",
        "digest verified",
        "127.0.0.1:",
        "0.0.0.0:",
    ];
    EVIDENCE.iter().any(|e| lower.contains(e))
}

/// Tooth 3b (plan-level). For each feature-tier DONE task whose recorded check
/// output is supplied in `check_outputs` (id -> output), flag it if the output
/// shows no real I/O.
pub fn feature_done_without_real_io(
    tasks: &[Task],
    check_outputs: &[(String, String)],
) -> Vec<PlanOffense> {
    let mut out = Vec::new();
    for t in tasks {
        if t.status != "DONE" || !is_feature_tier(t) {
            continue;
        }
        if let Some((_, output)) = check_outputs.iter().find(|(id, _)| id == &t.id) {
            if !check_output_shows_real_io(output) {
                out.push(PlanOffense {
                    task: t.id.clone(),
                    kind: "feature-done-no-real-io".to_string(),
                    detail: "feature-tier task is DONE but its Check output shows no real \
                             socket/process I/O"
                        .to_string(),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tooth 4 — feature-tier tasks MUST name a pillar-integration scenario, and a
// feature-tier DONE is only legal when its named scenario is GREEN on the
// Gitea Actions runner (queried the same way the
// pillar-integration-gitea-actions-workflow Check queries a run's status).
// ---------------------------------------------------------------------------

/// The runner-observed status of a named `pillar-integration` scenario family.
/// Mirrors the `verify-actions-run.sh` exit-code contract: a scenario is either
/// green (its Actions run concluded `success`), not-yet-green (queued/in
/// progress/failed/absent), so a feature-DONE gated on a non-green scenario is
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioStatus {
    /// The scenario's latest Gitea Actions run concluded `success`.
    Green,
    /// The scenario is queued/in-progress/failed, or no run exists yet.
    NotGreen,
    /// The scenario name is not a known `pillar-integration` scenario family.
    Unknown,
}

/// A resolver from a scenario-family name to its runner-observed status. The
/// production implementation queries the Gitea Actions REST API exactly as
/// `scripts/verify-actions-run.sh` does (the `pillar-integration` workflow's
/// per-scenario job conclusion); tests inject a deterministic map so the lint's
/// decision logic is proven offline without live reachability or a token.
pub trait ScenarioOracle {
    /// Return the runner-observed status of scenario family `name`.
    fn status(&self, name: &str) -> ScenarioStatus;
}

impl<F: Fn(&str) -> ScenarioStatus> ScenarioOracle for F {
    fn status(&self, name: &str) -> ScenarioStatus {
        (self)(name)
    }
}

/// Tooth 4a. Every FEATURE-tier task MUST carry an `integration-scenario:` field
/// naming the `pillar-integration` scenario family that proves it. A feature-tier
/// task lacking the field is an offense — the gate cannot know which real
/// integration scenario would demonstrate the claimed running effect.
pub fn feature_missing_integration_scenario(tasks: &[Task]) -> Vec<PlanOffense> {
    let mut out = Vec::new();
    for t in tasks {
        if !is_feature_tier(t) {
            continue;
        }
        if t.integration_scenario.is_none() {
            out.push(PlanOffense {
                task: t.id.clone(),
                kind: "feature-missing-integration-scenario".to_string(),
                detail: "feature-tier task lacks a mandatory `integration-scenario:` field \
                         naming the pillar-integration scenario family that proves it"
                    .to_string(),
            });
        }
    }
    out
}

/// Tooth 4b. A feature-tier task may not be `DONE` unless the scenario named by
/// its `integration-scenario:` field is GREEN on the Gitea Actions runner. A
/// DONE whose named scenario is missing, unknown, or not-green is refused. A
/// feature-tier DONE with NO `integration-scenario:` field is likewise refused
/// (tooth 4a flags it separately, but a DONE without the field can never be
/// proven green here, so it is an offense at this gate too).
pub fn feature_done_scenario_not_green<O: ScenarioOracle>(
    tasks: &[Task],
    oracle: &O,
) -> Vec<PlanOffense> {
    let mut out = Vec::new();
    for t in tasks {
        if t.status != "DONE" || !is_feature_tier(t) {
            continue;
        }
        match &t.integration_scenario {
            None => out.push(PlanOffense {
                task: t.id.clone(),
                kind: "feature-done-no-integration-scenario".to_string(),
                detail: "feature-tier task is DONE but names no `integration-scenario:` \
                         to prove it green on the runner"
                    .to_string(),
            }),
            Some(name) => match oracle.status(name) {
                ScenarioStatus::Green => {}
                ScenarioStatus::NotGreen => out.push(PlanOffense {
                    task: t.id.clone(),
                    kind: "feature-done-scenario-not-green".to_string(),
                    detail: format!(
                        "feature-tier task is DONE but its integration-scenario {name:?} \
                         is not green on the Gitea Actions runner"
                    ),
                }),
                ScenarioStatus::Unknown => out.push(PlanOffense {
                    task: t.id.clone(),
                    kind: "feature-done-scenario-unknown".to_string(),
                    detail: format!(
                        "feature-tier task is DONE but its integration-scenario {name:?} \
                         is not a known pillar-integration scenario family"
                    ),
                }),
            },
        }
    }
    out
}

/// Parse a `PLAN.md` into the tasks the lints need. A task begins at a line
/// `## <id> [<STATUS>] <!-- ... -->` and its body runs to the next `## ` header
/// (or a top-level `# ` heading / EOF).
pub fn parse_plan(text: &str) -> Vec<Task> {
    let mut tasks = Vec::new();
    let mut cur: Option<Task> = None;
    let mut body_lines: Vec<String> = Vec::new();

    for line in text.lines() {
        if let Some(header) = parse_header(line) {
            if let Some(mut t) = cur.take() {
                finish_body(&mut t, &body_lines);
                tasks.push(t);
            }
            cur = Some(header);
            body_lines.clear();
        } else if cur.is_some() {
            // A new top-level section ends the current task's body.
            if line.starts_with("# ") {
                if let Some(mut t) = cur.take() {
                    finish_body(&mut t, &body_lines);
                    tasks.push(t);
                }
                body_lines.clear();
            } else {
                body_lines.push(line.to_string());
            }
        }
    }
    if let Some(mut t) = cur.take() {
        finish_body(&mut t, &body_lines);
        tasks.push(t);
    }
    tasks
}

fn finish_body(t: &mut Task, lines: &[String]) {
    t.body = lines.join("\n");
    // Extract the LAST `Check:` line (a task may cite the stub in prose then
    // give the real command; the machine field is the final `Check:` line).
    for l in lines {
        let trimmed = l.trim();
        if let Some(rest) = trimmed.strip_prefix("Check:") {
            t.check = Some(rest.trim().to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("integration-scenario:") {
            let v = rest.trim();
            if !v.is_empty() {
                t.integration_scenario = Some(v.to_string());
            }
        }
    }
    if t.body.contains("check=none") || t.body.contains("check-none") {
        t.check_none = true;
    }
}

/// Parse a `## <id> [<STATUS>] <!-- ... attempts=N ... -->` header line.
fn parse_header(line: &str) -> Option<Task> {
    let rest = line.strip_prefix("## ")?;
    // id is the first whitespace-delimited token.
    let id = rest.split_whitespace().next()?.to_string();
    // status is inside the first `[...]`.
    let status = {
        let lb = rest.find('[')?;
        let rb = rest[lb..].find(']')? + lb;
        rest[lb + 1..rb].trim().to_string()
    };
    // attempts=N from the header comment.
    let attempts = rest
        .find("attempts=")
        .and_then(|p| {
            let tail = &rest[p + "attempts=".len()..];
            let num: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            num.parse::<u32>().ok()
        })
        .unwrap_or(0);
    Some(Task {
        id,
        status,
        attempts,
        body: String::new(),
        check: None,
        check_none: false,
        integration_scenario: None,
    })
}

#[cfg(test)]
mod unit {
    use super::*;

    fn t(id: &str, status: &str, attempts: u32, body: &str) -> Task {
        let mut task = Task {
            id: id.to_string(),
            status: status.to_string(),
            attempts,
            body: body.to_string(),
            check: None,
            check_none: false,
            integration_scenario: None,
        };
        for l in body.lines() {
            if let Some(rest) = l.trim().strip_prefix("Check:") {
                task.check = Some(rest.trim().to_string());
            }
            if let Some(rest) = l.trim().strip_prefix("integration-scenario:") {
                let v = rest.trim();
                if !v.is_empty() {
                    task.integration_scenario = Some(v.to_string());
                }
            }
        }
        if body.contains("check=none") {
            task.check_none = true;
        }
        task
    }

    #[test]
    fn acceptance_check_detection() {
        assert!(is_acceptance_check("cargo test -p pillar-e2e --test real"));
        assert!(is_acceptance_check("cargo test --test workload_run"));
        assert!(is_acceptance_check(
            "cargo test -p pillar-net --features acceptance"
        ));
        assert!(!is_acceptance_check("cargo test -p pillar-controller"));
        assert!(!is_acceptance_check("cargo test --all"));
    }

    #[test]
    fn verb_claim_with_unit_check_is_flagged() {
        let tasks = vec![t(
            "workload-run",
            "TODO",
            0,
            "The controller runs the workload as a real process.\nCheck: cargo test -p pillar-controller",
        )];
        let o = verb_claim_offenses(&tasks);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].kind, "verb-claim-unit-check");
    }

    #[test]
    fn verb_claim_with_acceptance_check_passes() {
        let tasks = vec![t(
            "workload-run",
            "TODO",
            0,
            "The controller runs the workload as a real process.\nCheck: cargo test -p pillar-e2e --test workload",
        )];
        assert!(verb_claim_offenses(&tasks).is_empty());
    }

    #[test]
    fn attempts0_feature_done_is_flagged() {
        let tasks = vec![t(
            "workload-run",
            "DONE",
            0,
            "runs the workload.\nCheck: cargo test -p pillar-e2e --test x",
        )];
        let o = same_reconcile_feature_done(&tasks);
        assert_eq!(o.len(), 1, "{o:?}");
    }

    #[test]
    fn parse_header_extracts_fields() {
        let tasks = parse_plan(
            "## foo-task [DONE] <!-- attempts=3 deps=bar weight=64 commits=abc -->\nbody line\nCheck: cargo test --all\nintegration-scenario: pillar-integration-scenarios-workload-runtime\n## next-task [TODO] <!-- attempts=0 -->\nx",
        );
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].id, "foo-task");
        assert_eq!(tasks[0].status, "DONE");
        assert_eq!(tasks[0].attempts, 3);
        assert_eq!(tasks[0].check.as_deref(), Some("cargo test --all"));
        assert_eq!(
            tasks[0].integration_scenario.as_deref(),
            Some("pillar-integration-scenarios-workload-runtime")
        );
    }

    #[test]
    fn feature_tier_without_scenario_is_flagged() {
        let tasks = vec![t(
            "workload-run",
            "TODO",
            1,
            "The controller runs the workload as a real process.\nCheck: cargo test -p pillar-e2e --test workload_run",
        )];
        let o = feature_missing_integration_scenario(&tasks);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].kind, "feature-missing-integration-scenario");
    }

    #[test]
    fn feature_tier_with_scenario_is_accepted() {
        let tasks = vec![t(
            "workload-run",
            "TODO",
            1,
            "The controller runs the workload as a real process.\nCheck: cargo test -p pillar-e2e --test workload_run\nintegration-scenario: pillar-integration-scenarios-workload-runtime",
        )];
        assert!(feature_missing_integration_scenario(&tasks).is_empty());
    }

    #[test]
    fn feature_done_gated_on_scenario_greenness() {
        let tasks = vec![t(
            "workload-run",
            "DONE",
            2,
            "runs the workload.\nCheck: cargo test -p pillar-e2e --test workload_run\nintegration-scenario: pillar-integration-scenarios-workload-runtime",
        )];
        let green = |name: &str| {
            if name == "pillar-integration-scenarios-workload-runtime" {
                ScenarioStatus::Green
            } else {
                ScenarioStatus::Unknown
            }
        };
        assert!(feature_done_scenario_not_green(&tasks, &green).is_empty());

        let red = |_: &str| ScenarioStatus::NotGreen;
        let o = feature_done_scenario_not_green(&tasks, &red);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].kind, "feature-done-scenario-not-green");

        let unknown = |_: &str| ScenarioStatus::Unknown;
        let o = feature_done_scenario_not_green(&tasks, &unknown);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].kind, "feature-done-scenario-unknown");
    }

    #[test]
    fn feature_done_without_scenario_field_is_flagged() {
        let tasks = vec![t(
            "workload-run",
            "DONE",
            2,
            "runs the workload.\nCheck: cargo test -p pillar-e2e --test workload_run",
        )];
        let any = |_: &str| ScenarioStatus::Green;
        let o = feature_done_scenario_not_green(&tasks, &any);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].kind, "feature-done-no-integration-scenario");
    }
}
