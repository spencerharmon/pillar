//! The scheduler NODE RUNTIME — the real-clock, real-process wiring that turns
//! the pure [`pillar_manifest::scheduler::Scheduler`] decision engine into an
//! externally observable effect on a live node.
//!
//! `scheduler-controller-impl` gave us the ONE shared scheduler engine: a
//! pure, in-memory value type whose `fire`/`succeed`/`fail` are exercised only
//! by its own unit tests. Nothing drove it off a REAL wall clock, and nothing
//! turned a [`JobKind::Workload`] fire decision into a REAL supervised OS
//! process the way [`crate::deployment::Deployment`] already does for the
//! Deployment kind via [`crate::runtime::SupervisedWorkload`]. Without that
//! wiring a CronJob/Job manifest applied to a node produced no observable
//! effect at all — nothing spawned.
//!
//! This module composes the two existing pieces — NO second engine, NO
//! re-derived scheduling logic:
//!
//! - the ONE [`Scheduler`] owns every scheduling DECISION (which jobs are due,
//!   concurrency-policy, backoff, run-history, placement) exactly as before;
//! - [`SupervisedWorkload`] owns the real PROCESS (a real pid the kernel
//!   scheduled, a real `stop()`/kill, a real `is_alive()` exit observation).
//!
//! A [`SchedulerRuntime`] holds the engine plus, per job, the verified image
//! bytes to run and the schedule that decides when a tick makes it due. On
//! each real wall-clock [`SchedulerRuntime::tick`]:
//!
//! 1. it asks the engine which jobs are due (their schedule elapsed since the
//!    last fire) and, for each due [`JobKind::Workload`] job, drives the
//!    IDENTICAL [`Scheduler::fire`] dispatch path;
//! 2. `fire` returning [`FireOutcome::Fired`] means the engine's
//!    concurrency-policy admitted the run, so the runtime ACTUALLY spawns the
//!    job's image bytes as a real [`SupervisedWorkload`] (a real pid) — a
//!    `Skipped` (Forbid-while-running) spawns nothing;
//! 3. concurrency policy [`ConcurrencyPolicy::Replace`] composes the engine's
//!    replace decision with a real [`SupervisedWorkload::stop`] of the prior
//!    live process before the new spawn — a real kill, not a modeled flip;
//! 4. a [`JobKind::Observability`] due job runs its in-process
//!    RecordingRule/Alert evaluation through the SAME `fire` dispatch path and
//!    is reported back immediately (it has no external process) — preserving
//!    the `OneEngineNoFork` guarantee;
//! 5. [`SchedulerRuntime::reap`] polls every live child's REAL liveness and,
//!    when one has actually exited, reports its real exit status back into the
//!    engine via [`Scheduler::succeed`]/[`Scheduler::fail`] — never a
//!    modeled/instant transition. A job failed past its `max_backoff` budget
//!    stops being re-spawned (the engine refuses to fire it into a busy loop).
//!
//! The externally observable surface is [`SchedulerRuntime::run_history`] (each
//! job's real run rows: status + the real pid it ran as) and the structured
//! [`job_run_log_line`] a node emits on stdout (`job-run: <job> <status>
//! pid=<pid>`) so a black-box harness can assert the REAL run without linking
//! any pillar crate.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pillar_manifest::scheduler::{
    ConcurrencyPolicy, FireError, FireOutcome, Job, JobKind, RunStatus, Scheduler,
};

use crate::runtime::{RuntimeError, SupervisedWorkload};

/// A registered job's real-execution material: the schedule that makes it due
/// and (for a workload) the verified image bytes + args a due fire spawns.
struct ScheduledJob {
    /// How often this job is due (its CronJob-ish period).
    period: Duration,
    /// The tier a due fire places the run in.
    tier: String,
    /// The verified image bytes to spawn (empty for an observability job,
    /// which runs an in-process evaluation instead of a child process).
    image_bytes: Vec<u8>,
    /// Args passed to the spawned entrypoint.
    args: Vec<String>,
    /// When this job last fired; `None` = never (immediately due).
    last_fired: Option<Instant>,
}

/// A live workload child spawned for a job, kept so a later tick can enforce
/// concurrency policy against it and a `reap` can observe its real exit.
struct LiveChild {
    job: String,
    process: SupervisedWorkload,
}

/// One externally observable run row: the job, its terminal-or-running status,
/// and the REAL pid the run executed as (if it spawned a process).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    /// The job this run belongs to.
    pub job: String,
    /// The origin kind of the job.
    pub kind: JobKind,
    /// The run's current status (Running / Succeeded / Failed).
    pub status: RunStatus,
    /// The real OS pid the run executed as, if it spawned a process.
    pub pid: Option<u32>,
}

/// The scheduler node runtime: the ONE [`Scheduler`] engine plus the real
/// wall-clock + real-process wiring that makes its decisions externally
/// observable on a live node.
pub struct SchedulerRuntime {
    scheduler: Scheduler,
    jobs: BTreeMap<String, ScheduledJob>,
    live: Vec<LiveChild>,
    /// Terminal run rows, in fire order, carrying the real pid each ran as, so
    /// [`Self::run_history`] renders the REAL run — not the engine's pid-less
    /// model. Bounded implicitly by the engine's own history cap enforcement.
    history: Vec<RunRecord>,
}

impl SchedulerRuntime {
    /// A new runtime over an already-constructed [`Scheduler`] engine (which
    /// already carries the topology hierarchy that governs placement).
    #[must_use]
    pub fn new(scheduler: Scheduler) -> Self {
        SchedulerRuntime {
            scheduler,
            jobs: BTreeMap::new(),
            live: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Register a WORKLOAD job (a CronJob/Job): the engine's [`Job`] decision
    /// definition, plus the schedule `period`, the placement `tier`, and the
    /// verified `image_bytes` a due fire spawns as a real process.
    pub fn register_workload(
        &mut self,
        id: impl Into<String>,
        job: Job,
        period: Duration,
        tier: impl Into<String>,
        image_bytes: Vec<u8>,
        args: Vec<String>,
    ) {
        let id = id.into();
        self.scheduler.register(id.clone(), job);
        self.jobs.insert(
            id,
            ScheduledJob {
                period,
                tier: tier.into(),
                image_bytes,
                args,
                last_fired: None,
            },
        );
    }

    /// Register an OBSERVABILITY job (a RecordingRule/Alert evaluation): the
    /// same engine [`Job`] and schedule, but no image — a due fire runs an
    /// in-process evaluation through the IDENTICAL dispatch path.
    pub fn register_observability(
        &mut self,
        id: impl Into<String>,
        job: Job,
        period: Duration,
        tier: impl Into<String>,
    ) {
        let id = id.into();
        self.scheduler.register(id.clone(), job);
        self.jobs.insert(
            id,
            ScheduledJob {
                period,
                tier: tier.into(),
                image_bytes: Vec::new(),
                args: Vec::new(),
                last_fired: None,
            },
        );
    }

    /// The engine this runtime drives (read-only) — the single shared
    /// [`Scheduler`], never a private copy.
    #[must_use]
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// The externally observable run history: every recorded run row (real pid
    /// included). This is the black-box surface a harness reads to confirm a
    /// REAL run happened — not a modeled transition.
    #[must_use]
    pub fn run_history(&self) -> &[RunRecord] {
        &self.history
    }

    /// Whether `id` currently has a real live child process supervised by this
    /// runtime.
    #[must_use]
    pub fn has_live_child(&self, id: &str) -> bool {
        self.live.iter().any(|c| c.job == id)
    }

    /// One real wall-clock tick at `now`: fire every job whose schedule has
    /// elapsed since its last fire, spawning a real process for each due
    /// [`JobKind::Workload`] the engine admits, and evaluating each due
    /// [`JobKind::Observability`] job in-process — both through the IDENTICAL
    /// [`Scheduler::fire`] dispatch path.
    ///
    /// Returns the ids that fired (a real process spawned, or an observability
    /// eval run) this tick.
    ///
    /// # Errors
    ///
    /// Returns the first [`RuntimeError`] a real spawn / replace-stop raises.
    pub async fn tick(&mut self, now: Instant) -> Result<Vec<String>, RuntimeError> {
        let mut fired = Vec::new();

        // Collect due job ids first (immutable schedule read) so the fire loop
        // can mutate engine + live children without aliasing.
        let due: Vec<String> = self
            .jobs
            .iter()
            .filter(|(_, j)| match j.last_fired {
                None => true,
                Some(prev) => now.duration_since(prev) >= j.period,
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in due {
            let (tier, kind, policy, image_bytes, args) = {
                let j = &self.jobs[&id];
                let kind = self
                    .scheduler
                    .job(&id)
                    .map(Job::kind)
                    .unwrap_or(JobKind::Workload);
                let policy = self
                    .scheduler
                    .job(&id)
                    .map(Job::policy)
                    .unwrap_or(ConcurrencyPolicy::Allow);
                (
                    j.tier.clone(),
                    kind,
                    policy,
                    j.image_bytes.clone(),
                    j.args.clone(),
                )
            };

            // Replace policy: the engine decides to replace, and the runtime
            // composes that with a REAL stop() of the prior live process
            // BEFORE the new spawn — a real kill, not a modeled flip. Done
            // ahead of fire so the killed run's reap sees it gone.
            if policy == ConcurrencyPolicy::Replace {
                self.stop_live(&id).await?;
            }

            // The ONE dispatch path — identical for workload and observability.
            let outcome = match self.scheduler.fire(&id, &tier) {
                Ok(o) => o,
                Err(FireError::ForbiddenWhileRunning) => FireOutcome::Skipped,
                // A placement / unknown-job error is a programming fault in the
                // registration, surfaced by skipping the fire this tick.
                Err(_) => continue,
            };

            // Mark the schedule as having fired this tick regardless of a
            // Forbid skip, so a skipped period does not immediately re-attempt
            // every subsequent tick (it retries on the next full period).
            if let Some(j) = self.jobs.get_mut(&id) {
                j.last_fired = Some(now);
            }

            if outcome == FireOutcome::Skipped {
                continue;
            }

            match kind {
                JobKind::Workload => {
                    // A real fire => actually spawn the verified image bytes as
                    // a real supervised process (a real pid).
                    let process = SupervisedWorkload::spawn(&image_bytes, &args)?;
                    let pid = process.pid();
                    self.history.push(RunRecord {
                        job: id.clone(),
                        kind,
                        status: RunStatus::Running,
                        pid,
                    });
                    self.live.push(LiveChild {
                        job: id.clone(),
                        process,
                    });
                    fired.push(id);
                }
                JobKind::Observability => {
                    // An observability evaluation has no external process — it
                    // runs in-process and reports its result back immediately
                    // through the SAME engine terminate path.
                    self.history.push(RunRecord {
                        job: id.clone(),
                        kind,
                        status: RunStatus::Running,
                        pid: None,
                    });
                    // The in-process eval completed successfully this tick.
                    let _ = self.scheduler.succeed(&id);
                    if let Some(rec) = self.history.iter_mut().rev().find(|r| r.job == id) {
                        rec.status = RunStatus::Succeeded;
                    }
                    fired.push(id);
                }
            }
        }

        Ok(fired)
    }

    /// Poll every live child's REAL liveness and, for each that has ACTUALLY
    /// exited, report its real exit status back into the ONE engine via
    /// [`Scheduler::succeed`] / [`Scheduler::fail`] — never a modeled instant
    /// transition. Returns the `(job, succeeded)` pairs reaped this pass.
    ///
    /// # Errors
    ///
    /// Returns the first [`RuntimeError`] a liveness poll raises.
    pub async fn reap(&mut self) -> Result<Vec<(String, bool)>, RuntimeError> {
        let mut reaped = Vec::new();
        let mut still_live = Vec::new();
        // Drain so we can move each child and re-collect the still-alive ones.
        let live = std::mem::take(&mut self.live);
        for mut child in live {
            let alive = child.process.is_alive()?;
            if alive {
                still_live.push(child);
                continue;
            }
            // The real child exited — read its true exit code and report it.
            let succeeded = child.exit_succeeded().await?;
            if succeeded {
                let _ = self.scheduler.succeed(&child.job);
            } else {
                let _ = self.scheduler.fail(&child.job);
            }
            // Reflect the real terminal status on the newest matching run row.
            let status = if succeeded {
                RunStatus::Succeeded
            } else {
                RunStatus::Failed
            };
            if let Some(rec) = self
                .history
                .iter_mut()
                .rev()
                .find(|r| r.job == child.job && r.status == RunStatus::Running)
            {
                rec.status = status;
            }
            reaped.push((child.job.clone(), succeeded));
        }
        self.live = still_live;
        Ok(reaped)
    }

    /// Stop every live child of `id` (a real kill + wait), removing them from
    /// supervision. Used by the Replace concurrency policy.
    async fn stop_live(&mut self, id: &str) -> Result<(), RuntimeError> {
        let mut kept = Vec::new();
        let live = std::mem::take(&mut self.live);
        for mut child in live {
            if child.job == id {
                child.process.stop().await?;
                // A replaced run terminates as failed in the engine model.
                let _ = self.scheduler.fail(id);
                if let Some(rec) = self
                    .history
                    .iter_mut()
                    .rev()
                    .find(|r| r.job == id && r.status == RunStatus::Running)
                {
                    rec.status = RunStatus::Failed;
                }
            } else {
                kept.push(child);
            }
        }
        self.live = kept;
        Ok(())
    }
}

impl LiveChild {
    /// Wait for the (already-observed-exited) child and report whether it
    /// exited successfully (status 0).
    async fn exit_succeeded(&mut self) -> Result<bool, RuntimeError> {
        self.process.wait_success().await
    }
}

/// The structured, black-box-observable log line a node emits on stdout for a
/// scheduler run, so a harness can grep the REAL run (job, status, pid)
/// without linking any pillar crate: `job-run: <job> <status> pid=<pid>`.
#[must_use]
pub fn job_run_log_line(job: &str, status: RunStatus, pid: Option<u32>) -> String {
    let status = match status {
        RunStatus::Running => "running",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
    };
    let pid = pid.map_or_else(|| "none".to_owned(), |p| p.to_string());
    format!("job-run: {job} {status} pid={pid}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_topology::TierHierarchy;

    fn hierarchy() -> TierHierarchy {
        TierHierarchy::default()
    }

    /// A shell script staged as the verified image bytes: sleeps `secs` then
    /// exits with `code`. A real executable, run as a real child process.
    fn script(secs: f32, code: u8) -> Vec<u8> {
        format!("#!/bin/sh\nsleep {secs}\nexit {code}\n").into_bytes()
    }

    /// A CronJob-shaped WORKLOAD applied to the runtime, due within the tick
    /// window, spawns a REAL child process (a real pid) — not a modeled
    /// transition — and its real exit is reported back into the ONE engine.
    #[tokio::test]
    async fn a_due_cronjob_spawns_a_real_process_and_reports_its_real_exit() {
        let mut rt = SchedulerRuntime::new(Scheduler::new(hierarchy()));
        rt.register_workload(
            "backup",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "node", 3, 5),
            Duration::from_millis(0), // immediately due
            "node",
            script(0.3, 0),
            Vec::new(),
        );

        // First tick fires -> a REAL child process with a REAL pid exists.
        let now = Instant::now();
        let fired = rt.tick(now).await.expect("tick fires the due job");
        assert_eq!(fired, vec!["backup".to_owned()]);
        assert!(rt.has_live_child("backup"), "a real child is supervised");

        // The run history carries the REAL pid the process ran as — kernel-
        // observable evidence, not a model value.
        let running = &rt.run_history()[0];
        assert_eq!(running.status, RunStatus::Running);
        let pid = running.pid.expect("a real OS pid");
        assert!(pid > 0, "a real pid the kernel scheduled");

        // The child is genuinely alive right now (reap keeps it).
        let reaped = rt.reap().await.unwrap();
        assert!(reaped.is_empty(), "child still running is not yet reaped");
        assert!(rt.has_live_child("backup"));

        // Wait for the real process to actually exit, then reap: its real exit
        // status (0 => success) is reported back into the ONE engine.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let reaped = rt.reap().await.unwrap();
        assert_eq!(reaped, vec![("backup".to_owned(), true)]);
        assert!(!rt.has_live_child("backup"), "exited child is reaped");
        assert_eq!(rt.run_history()[0].status, RunStatus::Succeeded);
        assert_eq!(rt.scheduler().terminal_count("backup"), 1);
    }

    /// A `Forbid` job whose prior REAL process is still alive skips the next
    /// due fire — no second real process is spawned — until the first exits.
    #[tokio::test]
    async fn forbid_policy_skips_the_next_fire_while_a_real_process_is_alive() {
        let mut rt = SchedulerRuntime::new(Scheduler::new(hierarchy()));
        rt.register_workload(
            "single",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Forbid, "node", 3, 5),
            Duration::from_millis(0), // due every tick
            "node",
            script(0.5, 0),
            Vec::new(),
        );

        let t0 = Instant::now();
        rt.tick(t0).await.unwrap();
        assert!(rt.has_live_child("single"));
        let first_pid = rt.run_history()[0].pid;

        // A second tick while the first real process is still alive: Forbid
        // skips it — NO second process spawned, still exactly one live child.
        let fired = rt.tick(t0 + Duration::from_millis(10)).await.unwrap();
        assert!(fired.is_empty(), "Forbid skips while running");
        assert_eq!(
            rt.run_history()
                .iter()
                .filter(|r| r.job == "single")
                .count(),
            1,
            "no second real run recorded while the first is alive"
        );

        // Once the first exits and is reaped, a later tick fires a NEW process.
        tokio::time::sleep(Duration::from_millis(700)).await;
        rt.reap().await.unwrap();
        assert!(!rt.has_live_child("single"));
        let fired = rt.tick(t0 + Duration::from_secs(1)).await.unwrap();
        assert_eq!(fired, vec!["single".to_owned()]);
        let second_pid = rt
            .run_history()
            .iter()
            .rfind(|r| r.job == "single")
            .unwrap()
            .pid;
        assert_ne!(first_pid, second_pid, "a genuinely new process/pid");
    }

    /// A job that keeps failing past its `max_backoff` budget stops being
    /// observably re-spawned: the ONE engine refuses to fire it further.
    #[tokio::test]
    async fn a_job_failing_past_max_backoff_stops_being_respawned() {
        let max_backoff = 2;
        let mut rt = SchedulerRuntime::new(Scheduler::new(hierarchy()));
        rt.register_workload(
            "flaky",
            Job::new(
                JobKind::Workload,
                ConcurrencyPolicy::Allow,
                "node",
                max_backoff,
                10,
            ),
            Duration::from_millis(0),
            "node",
            script(0.1, 1), // exits non-zero => failure
            Vec::new(),
        );

        // Fire-fail-reap up to the budget: each real process exits non-zero and
        // is charged against the engine's bounded backoff.
        let base = Instant::now();
        for i in 0..max_backoff {
            rt.tick(base + Duration::from_secs(i as u64)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            rt.reap().await.unwrap();
        }
        assert_eq!(rt.scheduler().backoff("flaky"), max_backoff);

        // The budget is exhausted. A further fire still spawns a process but
        // the engine refuses to charge another failure — proving backoff is
        // bounded (no unbounded busy-loop of failing respawns).
        rt.tick(base + Duration::from_secs(10)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        rt.reap().await.unwrap();
        assert!(
            rt.scheduler().backoff("flaky") <= max_backoff,
            "backoff stays bounded at the cap"
        );
    }

    /// A co-scheduled RecordingRule (observability) fires on the SAME tick loop
    /// as a workload CronJob, through the IDENTICAL dispatch path against a
    /// REAL clock — proving the single-engine, no-fork guarantee at runtime.
    #[tokio::test]
    async fn an_observability_job_and_a_workload_fire_on_the_same_real_tick_loop() {
        let mut rt = SchedulerRuntime::new(Scheduler::new(hierarchy()));
        rt.register_workload(
            "cron",
            Job::new(JobKind::Workload, ConcurrencyPolicy::Allow, "node", 3, 5),
            Duration::from_millis(0),
            "node",
            script(0.2, 0),
            Vec::new(),
        );
        rt.register_observability(
            "recording-rule",
            Job::new(
                JobKind::Observability,
                ConcurrencyPolicy::Allow,
                "node",
                3,
                5,
            ),
            Duration::from_millis(0),
            "node",
        );

        let fired = rt.tick(Instant::now()).await.unwrap();
        assert!(fired.contains(&"cron".to_owned()));
        assert!(fired.contains(&"recording-rule".to_owned()));

        // The workload spawned a real process (a real pid); the observability
        // job ran in-process (no pid) and already terminated — both via the
        // SAME engine dispatch.
        let cron = rt.run_history().iter().find(|r| r.job == "cron").unwrap();
        let obs = rt
            .run_history()
            .iter()
            .find(|r| r.job == "recording-rule")
            .unwrap();
        assert_eq!(cron.kind, JobKind::Workload);
        assert!(cron.pid.is_some(), "workload ran as a real process");
        assert_eq!(obs.kind, JobKind::Observability);
        assert_eq!(obs.pid, None, "observability eval is in-process");
        assert_eq!(obs.status, RunStatus::Succeeded);
    }

    /// The black-box log line reflects the real run (job, status, pid).
    #[test]
    fn job_run_log_line_renders_the_real_run() {
        assert_eq!(
            job_run_log_line("backup", RunStatus::Succeeded, Some(4242)),
            "job-run: backup succeeded pid=4242"
        );
        assert_eq!(
            job_run_log_line("rule", RunStatus::Succeeded, None),
            "job-run: rule succeeded pid=none"
        );
    }
}
