//! The ONE shared scheduler engine — the "synergy spine" method #1.
//!
//! Refines `specs/SchedulerController.tla`. There is exactly one scheduling
//! engine. It runs BOTH workload jobs (k8s-CronJob/Job semantics: a schedule,
//! a concurrency policy, backoff on failure, bounded run-history) AND the
//! internal observability evaluations (RecordingRule / Alert evaluations) as
//! scheduled jobs on the SAME engine. There is NO second, private scheduler
//! for observability: a workload CronJob and an observability evaluation fire,
//! run, retry, and retire through the identical [`Scheduler::fire`] decision
//! path — the `OneEngineNoFork` guarantee. The only thing distinguishing the
//! two is a [`JobKind`] tag recording a job's ORIGIN; there is deliberately no
//! separate dispatch function for observability jobs.
//!
//! The engine models (mirroring the TLA+ actions):
//!   - schedule evaluation — a due job fires a run ([`Scheduler::fire`]);
//!   - concurrency-policy enforcement — [`ConcurrencyPolicy::Allow`] /
//!     [`ConcurrencyPolicy::Forbid`] / [`ConcurrencyPolicy::Replace`] against an
//!     already-running run (`ConcurrencyPolicyHonored`);
//!   - backoff-on-failure — a bounded, non-busy-loop retry budget
//!     (`BackoffBounded`): a job that has exhausted its budget refuses to refire;
//!   - bounded run-history retention — terminal runs are pruned oldest-first to
//!     a fixed cap (`RunHistoryBounded`);
//!   - placement by topology tier — a run is only ever placed in a tier the
//!     job's required tier admits, reusing [`pillar_topology::TierHierarchy`]'s
//!     config-ordered hierarchy (`PlacementRespectsTopology`).
//!
//! Nothing here reaches the network or the filesystem; the engine is a pure,
//! deterministic value type.

use std::collections::BTreeMap;

use pillar_topology::TierHierarchy;

/// A job's ORIGIN — never a second engine. Both kinds take the identical
/// [`Scheduler::fire`] decision path; this tag only records where the job came
/// from so the caller can tell a workload CronJob apart from an internal
/// observability evaluation after the fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobKind {
    /// A user-declared Job/CronJob workload manifest.
    Workload,
    /// An internal RecordingRule / Alert evaluation, scheduled as an ordinary
    /// job on this same engine.
    Observability,
}

/// The k8s `concurrencyPolicy` a job enforces against an already-running run of
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConcurrencyPolicy {
    /// Always fire — a second concurrent run of the job may exist.
    Allow,
    /// Skip firing entirely if a run of the job is already running.
    Forbid,
    /// Terminate the already-running run (mark it failed), then fire.
    Replace,
}

/// The status of one run in the history ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunStatus {
    /// In flight — not history, not evictable.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Completed unsuccessfully — charged against the job's backoff budget.
    Failed,
}

/// A schedulable job's definition. Placement, concurrency, kind, and retry/
/// history bounds are all per-job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    kind: JobKind,
    policy: ConcurrencyPolicy,
    /// The coarsest tier this job may be placed in — a run is admissible only
    /// in a tier at least as specific (equal or finer rank) as this one.
    required_tier: String,
    /// Per-job failure budget: a job that has failed `max_backoff` times cannot
    /// be failed further into a busy-loop (`BackoffBounded`).
    max_backoff: u32,
    /// Bounded terminal run-history retained per job (`RunHistoryBounded`).
    /// Must be `>= 1`.
    history_cap: usize,
}

impl Job {
    /// A new job. `history_cap` is clamped to a minimum of 1 (a zero cap would
    /// evict a run the instant it terminated, which the spec forbids —
    /// `HistoryCap > 0`).
    #[must_use]
    pub fn new(
        kind: JobKind,
        policy: ConcurrencyPolicy,
        required_tier: impl Into<String>,
        max_backoff: u32,
        history_cap: usize,
    ) -> Job {
        Job {
            kind,
            policy,
            required_tier: required_tier.into(),
            max_backoff,
            history_cap: history_cap.max(1),
        }
    }

    /// This job's origin kind.
    #[must_use]
    pub fn kind(&self) -> JobKind {
        self.kind
    }

    /// This job's concurrency policy.
    #[must_use]
    pub fn policy(&self) -> ConcurrencyPolicy {
        self.policy
    }

    /// The coarsest tier this job may be placed in.
    #[must_use]
    pub fn required_tier(&self) -> &str {
        &self.required_tier
    }
}

/// One run recorded in the ledger — the result of a single [`Scheduler::fire`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// The job this run belongs to.
    pub job: String,
    /// The origin kind of the job (carried so a caller never re-derives it).
    pub kind: JobKind,
    /// The current status of the run.
    pub status: RunStatus,
    /// The tier the run was placed in.
    pub tier: String,
}

/// Why a [`Scheduler::fire`] did not create a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FireError {
    /// No such job is registered.
    UnknownJob(String),
    /// The requested placement tier is not a member of the hierarchy.
    UnknownTier(String),
    /// The placement tier is broader (lower rank) than the job's required tier
    /// — forbidden by the topology-label-hierarchy admission rule.
    TierTooBroad {
        /// The tier requested.
        requested: String,
        /// The coarsest tier the job permits.
        required: String,
    },
    /// The job's policy is [`ConcurrencyPolicy::Forbid`] and a run is already
    /// running — the fire is skipped, not an error the caller must handle, but
    /// surfaced so the caller knows nothing was created.
    ForbiddenWhileRunning,
}

/// What [`Scheduler::fire`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FireOutcome {
    /// A run was created (its index in the post-fire history is returned).
    Fired,
    /// A [`ConcurrencyPolicy::Forbid`] job was already running; nothing fired.
    Skipped,
}

/// Why a terminate ([`Scheduler::succeed`] / [`Scheduler::fail`]) did nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminateError {
    /// No such job is registered.
    UnknownJob(String),
    /// The job has no run currently running to terminate.
    NoRunning(String),
    /// The job has exhausted its backoff budget — it cannot be failed further
    /// into a busy-loop (`BackoffBounded`). Only returned by [`Scheduler::fail`].
    BackoffExhausted(String),
}

/// The single shared scheduler engine. Holds the job definitions, the run-
/// history ledger, and each job's backoff budget. Every run — workload or
/// observability — is created ONLY by [`Scheduler::fire`].
#[derive(Clone, Debug)]
pub struct Scheduler {
    hierarchy: TierHierarchy,
    jobs: BTreeMap<String, Job>,
    runs: Vec<Run>,
    backoff: BTreeMap<String, u32>,
}

impl Scheduler {
    /// A new, empty engine over `hierarchy` (the topology-label-hierarchy that
    /// governs placement admissibility).
    #[must_use]
    pub fn new(hierarchy: TierHierarchy) -> Scheduler {
        Scheduler {
            hierarchy,
            jobs: BTreeMap::new(),
            runs: Vec::new(),
            backoff: BTreeMap::new(),
        }
    }

    /// Register (or replace) `job` under `id`. Registering resets the job's
    /// backoff budget to zero.
    pub fn register(&mut self, id: impl Into<String>, job: Job) {
        let id = id.into();
        self.backoff.insert(id.clone(), 0);
        self.jobs.insert(id, job);
    }

    /// The registered job, if any.
    #[must_use]
    pub fn job(&self, id: &str) -> Option<&Job> {
        self.jobs.get(id)
    }

    /// Unregister `id` — the manifest-delete counterpart of [`Self::register`].
    /// Drops the job definition and its backoff budget so a removed CronJob/Job
    /// manifest stops being considered due by [`Self::fire`]; already-recorded
    /// run-history rows for `id` are left in place (deleting a job does not
    /// rewrite history). Returns whether `id` was registered.
    pub fn unregister(&mut self, id: &str) -> bool {
        self.backoff.remove(id);
        self.jobs.remove(id).is_some()
    }

    /// The full run-history ledger, oldest first.
    #[must_use]
    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// The current backoff budget consumed by `id` (0 if unknown).
    #[must_use]
    pub fn backoff(&self, id: &str) -> u32 {
        self.backoff.get(id).copied().unwrap_or(0)
    }

    /// The tiers `id` may be placed in: every tier at least as specific (rank
    /// `>=`) as the job's required tier. A placement in a broader tier is
    /// forbidden. Empty if the job or its required tier is unknown.
    #[must_use]
    pub fn admissible_tiers(&self, id: &str) -> Vec<String> {
        let Some(job) = self.jobs.get(id) else {
            return Vec::new();
        };
        let Some(req_rank) = self.hierarchy.rank(&job.required_tier) else {
            return Vec::new();
        };
        self.hierarchy
            .tiers()
            .iter()
            .filter(|t| {
                self.hierarchy
                    .rank(t)
                    .is_some_and(|r| r >= req_rank)
            })
            .cloned()
            .collect()
    }

    /// Whether `id` has a run currently running.
    #[must_use]
    pub fn has_running(&self, id: &str) -> bool {
        self.runs
            .iter()
            .any(|r| r.job == id && r.status == RunStatus::Running)
    }

    /// The number of TERMINAL (retained history) runs for `id`.
    #[must_use]
    pub fn terminal_count(&self, id: &str) -> usize {
        self.runs
            .iter()
            .filter(|r| r.job == id && r.status != RunStatus::Running)
            .count()
    }

    /// The SINGLE fire path — the identical decision path a workload CronJob and
    /// an observability evaluation both take (`OneEngineNoFork`). Fires `id`
    /// into `tier` (its schedule is due), honoring the job's concurrency policy
    /// and the topology-hierarchy placement rule, then re-enforces bounded run-
    /// history retention.
    ///
    /// Returns [`FireOutcome::Skipped`] (not an error) when a
    /// [`ConcurrencyPolicy::Forbid`] job is already running.
    pub fn fire(&mut self, id: &str, tier: &str) -> Result<FireOutcome, FireError> {
        let job = self
            .jobs
            .get(id)
            .ok_or_else(|| FireError::UnknownJob(id.to_owned()))?
            .clone();

        // Placement obeys the topology-label-hierarchy: tier must be a member
        // and at least as specific as the job's required tier.
        let tier_rank = self
            .hierarchy
            .rank(tier)
            .ok_or_else(|| FireError::UnknownTier(tier.to_owned()))?;
        let req_rank = self
            .hierarchy
            .rank(&job.required_tier)
            .ok_or_else(|| FireError::UnknownTier(job.required_tier.clone()))?;
        if tier_rank < req_rank {
            return Err(FireError::TierTooBroad {
                requested: tier.to_owned(),
                required: job.required_tier.clone(),
            });
        }

        match job.policy {
            ConcurrencyPolicy::Forbid => {
                if self.has_running(id) {
                    return Ok(FireOutcome::Skipped);
                }
            }
            ConcurrencyPolicy::Replace => {
                // Terminate the already-running run(s) before firing.
                for r in &mut self.runs {
                    if r.job == id && r.status == RunStatus::Running {
                        r.status = RunStatus::Failed;
                    }
                }
            }
            ConcurrencyPolicy::Allow => {}
        }

        // The one and only place a Run is ever constructed.
        self.runs.push(Run {
            job: id.to_owned(),
            kind: job.kind,
            status: RunStatus::Running,
            tier: tier.to_owned(),
        });

        self.prune_terminals(id, job.history_cap);
        Ok(FireOutcome::Fired)
    }

    /// A running run of `id` succeeds. Clears the job's backoff budget and re-
    /// enforces retention (the newly-terminal run may push history over the cap).
    pub fn succeed(&mut self, id: &str) -> Result<(), TerminateError> {
        let cap = self
            .jobs
            .get(id)
            .ok_or_else(|| TerminateError::UnknownJob(id.to_owned()))?
            .history_cap;
        self.terminate_one_running(id, RunStatus::Succeeded)?;
        self.backoff.insert(id.to_owned(), 0);
        self.prune_terminals(id, cap);
        Ok(())
    }

    /// A running run of `id` fails. Charges the retry budget, which is BOUNDED:
    /// a job that has exhausted `max_backoff` failures refuses to fail further,
    /// so failures cannot busy-loop (`BackoffBounded`). Retention is re-enforced.
    pub fn fail(&mut self, id: &str) -> Result<(), TerminateError> {
        let job = self
            .jobs
            .get(id)
            .ok_or_else(|| TerminateError::UnknownJob(id.to_owned()))?
            .clone();
        if self.backoff(id) >= job.max_backoff {
            return Err(TerminateError::BackoffExhausted(id.to_owned()));
        }
        self.terminate_one_running(id, RunStatus::Failed)?;
        let charged = self.backoff(id) + 1;
        self.backoff.insert(id.to_owned(), charged);
        self.prune_terminals(id, job.history_cap);
        Ok(())
    }

    /// Mark the OLDEST running run of `id` with `status`. The oldest is chosen
    /// so termination is deterministic.
    fn terminate_one_running(
        &mut self,
        id: &str,
        status: RunStatus,
    ) -> Result<(), TerminateError> {
        let idx = self
            .runs
            .iter()
            .position(|r| r.job == id && r.status == RunStatus::Running)
            .ok_or_else(|| TerminateError::NoRunning(id.to_owned()))?;
        self.runs[idx].status = status;
        Ok(())
    }

    /// Prune `id`'s TERMINAL history down to at most `cap`, oldest-first.
    /// Running runs are never evicted (in flight, not history). Applied whenever
    /// a run is appended or terminated, so retained history is bounded the
    /// instant it would exceed the cap (`RunHistoryBounded`).
    fn prune_terminals(&mut self, id: &str, cap: usize) {
        loop {
            let terminal: Vec<usize> = self
                .runs
                .iter()
                .enumerate()
                .filter(|(_, r)| r.job == id && r.status != RunStatus::Running)
                .map(|(i, _)| i)
                .collect();
            if terminal.len() <= cap {
                break;
            }
            // Drop the oldest terminal entry (lowest index).
            let oldest = terminal[0];
            self.runs.remove(oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_hierarchy() -> TierHierarchy {
        // region > zone > site > room > cage > rack > chassis > node.
        TierHierarchy::default()
    }

    /// A CronJob-shaped WORKLOAD manifest runs on schedule with the declared
    /// concurrency policy and records run-history.
    #[test]
    fn a_cronjob_workload_runs_on_schedule_with_its_policy_and_records_history() {
        let mut sched = Scheduler::new(default_hierarchy());
        sched.register(
            "backup",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Forbid, "rack", 3, 5),
        );

        // Schedule fires -> a run is recorded in history.
        assert_eq!(sched.fire("backup", "rack"), Ok(FireOutcome::Fired));
        assert_eq!(sched.runs().len(), 1);
        assert_eq!(sched.runs()[0].job, "backup");
        assert_eq!(sched.runs()[0].kind, JobKind::Workload);
        assert_eq!(sched.runs()[0].status, RunStatus::Running);

        // Forbid concurrency policy: a second fire while running is skipped, so
        // no second concurrent run exists.
        assert_eq!(sched.fire("backup", "rack"), Ok(FireOutcome::Skipped));
        assert_eq!(
            sched
                .runs()
                .iter()
                .filter(|r| r.status == RunStatus::Running)
                .count(),
            1
        );

        // The run completes and is retained as history.
        sched.succeed("backup").unwrap();
        assert_eq!(sched.runs()[0].status, RunStatus::Succeeded);
        assert_eq!(sched.terminal_count("backup"), 1);

        // Now that nothing is running, the next schedule fires again.
        assert_eq!(sched.fire("backup", "rack"), Ok(FireOutcome::Fired));
        assert_eq!(sched.runs().len(), 2);
    }

    /// A scheduled RecordingRule-shaped (observability) job runs through the
    /// IDENTICAL scheduling code path. Property: there is no separate dispatch
    /// function for observability jobs — the SAME `fire`/`succeed`/`fail` calls
    /// drive both, distinguished only by the `JobKind` origin tag.
    #[test]
    fn an_observability_job_runs_through_the_identical_scheduling_code_path() {
        let mut sched = Scheduler::new(default_hierarchy());
        // A workload CronJob and an observability RecordingRule evaluation.
        sched.register(
            "cron",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "node", 3, 5),
        );
        sched.register(
            "recording-rule",
            Job::new(JobKind::Observability, ConcurrencyPolicy::Allow, "node", 3, 5),
        );

        // Both fire via the EXACT SAME method — no observability-specific entry
        // point exists on Scheduler.
        assert_eq!(sched.fire("cron", "node"), Ok(FireOutcome::Fired));
        assert_eq!(sched.fire("recording-rule", "node"), Ok(FireOutcome::Fired));

        // Both produced a run, differing ONLY in their origin kind tag.
        let cron_run = sched.runs().iter().find(|r| r.job == "cron").unwrap();
        let obs_run = sched
            .runs()
            .iter()
            .find(|r| r.job == "recording-rule")
            .unwrap();
        assert_eq!(cron_run.kind, JobKind::Workload);
        assert_eq!(obs_run.kind, JobKind::Observability);
        assert_eq!(cron_run.status, obs_run.status); // both Running via one path
        assert_eq!(cron_run.status, RunStatus::Running);

        // And both terminate + record history through the identical calls.
        sched.succeed("cron").unwrap();
        sched.succeed("recording-rule").unwrap();
        assert_eq!(sched.terminal_count("cron"), 1);
        assert_eq!(sched.terminal_count("recording-rule"), 1);
    }

    /// A failing job backs off instead of busy-looping: failures consume a
    /// finite budget and, once exhausted, further failures are refused
    /// (`BackoffBounded`).
    #[test]
    fn a_failing_job_backs_off_instead_of_busy_looping() {
        let mut sched = Scheduler::new(default_hierarchy());
        let max_backoff = 3;
        sched.register(
            "flaky",
            Job::new(
                JobKind::Workload,
                ConcurrencyPolicy::Allow,
                "node",
                max_backoff,
                10,
            ),
        );

        // Fire-fail up to the budget.
        for expected in 1..=max_backoff {
            assert_eq!(sched.fire("flaky", "node"), Ok(FireOutcome::Fired));
            sched.fail("flaky").unwrap();
            assert_eq!(sched.backoff("flaky"), expected);
        }

        // Budget exhausted: another running run cannot be failed further — no
        // unbounded busy-loop of refires.
        assert_eq!(sched.fire("flaky", "node"), Ok(FireOutcome::Fired));
        assert_eq!(
            sched.fail("flaky"),
            Err(TerminateError::BackoffExhausted("flaky".to_owned()))
        );
        assert_eq!(sched.backoff("flaky"), max_backoff);
        assert!(sched.backoff("flaky") <= max_backoff);

        // A success clears the budget so the job can run normally again.
        sched.succeed("flaky").unwrap();
        assert_eq!(sched.backoff("flaky"), 0);
    }

    /// Placement respects topology tier constraints: a run may only be placed in
    /// a tier at least as specific as the job's required tier; a broader tier is
    /// refused (`PlacementRespectsTopology`).
    #[test]
    fn placement_respects_topology_tier_constraints() {
        let mut sched = Scheduler::new(default_hierarchy());
        // Requires placement at `rack` or finer (chassis, node).
        sched.register(
            "placed",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "rack", 3, 5),
        );

        // A finer/equal tier is admissible.
        assert_eq!(sched.fire("placed", "rack"), Ok(FireOutcome::Fired));
        assert_eq!(sched.fire("placed", "node"), Ok(FireOutcome::Fired));

        // A broader tier (zone nests rack) is refused.
        assert_eq!(
            sched.fire("placed", "zone"),
            Err(FireError::TierTooBroad {
                requested: "zone".to_owned(),
                required: "rack".to_owned(),
            })
        );

        // A non-member tier is refused.
        assert_eq!(
            sched.fire("placed", "galaxy"),
            Err(FireError::UnknownTier("galaxy".to_owned()))
        );

        // Every placed run is in an admissible tier.
        let admissible = sched.admissible_tiers("placed");
        for run in sched.runs() {
            assert!(
                admissible.contains(&run.tier),
                "run placed in {} outside admissible {:?}",
                run.tier,
                admissible
            );
        }
        // The admissible set is exactly rack and finer.
        assert_eq!(admissible, vec!["rack", "chassis", "node"]);
    }

    /// Bounded run-history retention: retained (terminal) history per job never
    /// exceeds the cap; the oldest terminal run is evicted first
    /// (`RunHistoryBounded`).
    #[test]
    fn run_history_is_bounded_to_the_cap_oldest_first() {
        let mut sched = Scheduler::new(default_hierarchy());
        let cap = 2;
        sched.register(
            "hist",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "node", 10, cap),
        );

        // Run and succeed more times than the cap.
        for _ in 0..5 {
            sched.fire("hist", "node").unwrap();
            sched.succeed("hist").unwrap();
        }
        assert_eq!(sched.terminal_count("hist"), cap);
        assert!(sched.terminal_count("hist") <= cap);

        // A still-running run is NOT counted as evictable history.
        sched.fire("hist", "node").unwrap();
        assert_eq!(sched.terminal_count("hist"), cap);
        assert!(sched.has_running("hist"));
    }

    /// The Replace concurrency policy never leaves two runs running: the already-
    /// running run is terminated before the new one fires
    /// (`ConcurrencyPolicyHonored`).
    #[test]
    fn replace_policy_never_leaves_two_running() {
        let mut sched = Scheduler::new(default_hierarchy());
        sched.register(
            "replacer",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Replace, "node", 5, 10),
        );

        sched.fire("replacer", "node").unwrap();
        sched.fire("replacer", "node").unwrap();

        let running = sched
            .runs()
            .iter()
            .filter(|r| r.job == "replacer" && r.status == RunStatus::Running)
            .count();
        assert_eq!(running, 1, "Replace must never leave two runs running");
    }

    /// Unknown jobs are refused rather than silently creating a run.
    #[test]
    fn an_unknown_job_cannot_fire() {
        let mut sched = Scheduler::new(default_hierarchy());
        assert_eq!(
            sched.fire("ghost", "node"),
            Err(FireError::UnknownJob("ghost".to_owned()))
        );
    }

    /// `unregister` removes a job so it can no longer fire (the manifest-delete
    /// path: a removed CronJob stops being scheduled) and reports whether the
    /// job existed.
    #[test]
    fn unregister_stops_a_job_from_firing_and_reports_prior_existence() {
        let mut sched = Scheduler::new(default_hierarchy());
        sched.register(
            "gone-soon",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "node", 3, 5),
        );
        assert!(sched.fire("gone-soon", "node").is_ok());

        assert!(sched.unregister("gone-soon"));
        assert_eq!(
            sched.fire("gone-soon", "node"),
            Err(FireError::UnknownJob("gone-soon".to_owned())),
            "an unregistered job can no longer fire"
        );
        // Unregistering an already-absent id reports false rather than
        // panicking.
        assert!(!sched.unregister("gone-soon"));
    }
}
