//! GitOps manifest reconciler — declare pillar objects from a git repo and
//! converge a running cell to them (ROI Priority 0 "synergy everywhere").
//!
//! This is the USER-authored-manifest analogue of how Flux drives pillar's own
//! deployment: a [`ManifestSource`] (a git repo checkout, addressed by a commit
//! revision) holds a set of manifests at named paths; a [`Reconciler`] polls
//! that source on a trigger and drives the target cell — the ordinary
//! [`ControllerRegistry`] — to match it. Crucially it rides the manifest
//! system's EXISTING apply path: every desired manifest is validated against
//! the [`SchemaRegistry`] and applied through [`ControllerRegistry::dispatch`],
//! the SAME `(apiVersion, kind)` dispatch a built-in or third-party CRD uses.
//! There is no bespoke per-kind reconcile loop here — the reconciler is a thin
//! diff-and-drive over that one apply path.
//!
//! **Prune semantics.** The reconciler tracks what it applied last pass. A
//! manifest removed from the source repo is not silently orphaned in-cell: on
//! the next reconcile it is PRUNED (retired) from the cell, via the same
//! controller path (a [`ControllerHook`]'s [`ControllerHook::delete`]), unless
//! pruning is explicitly disabled (`prune=false`), in which case the object is
//! retained and reported as orphaned rather than deleted.

use std::collections::{BTreeMap, BTreeSet};

use crate::builtin::{ControllerRegistry, ReconcileOutcome};
use crate::{Crd, SchemaError, SchemaRegistry};

/// A logical path within the source repo (e.g. `apps/route.yaml`) — the stable
/// identity of a declared manifest across reconciles. Two revisions of the repo
/// that carry the same path declare the "same" object; a path that disappears
/// between revisions is a removal the reconciler must prune.
pub type ManifestPath = String;

/// A snapshot of the desired state declared in a git repo at one revision: the
/// set of manifests, keyed by their path. This models a git checkout at a
/// commit — the reconciler never itself talks to git; a caller (a poll loop or
/// a webhook handler) produces this snapshot from a real clone/checkout and
/// hands it to [`Reconciler::reconcile`]. Keeping the git I/O outside the pure
/// reconcile core is exactly what makes the whole converge/prune contract unit-
/// testable without a network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestSource {
    /// The commit revision this snapshot was taken at — an opaque string (a
    /// git sha, a tag). Carried for reporting/idempotence; the reconcile diff
    /// is by path+content, not by revision.
    pub revision: String,
    /// The desired manifests, keyed by their in-repo path.
    manifests: BTreeMap<ManifestPath, Crd>,
}

impl ManifestSource {
    /// An empty source at the given revision.
    #[must_use]
    pub fn new(revision: impl Into<String>) -> Self {
        ManifestSource {
            revision: revision.into(),
            manifests: BTreeMap::new(),
        }
    }

    /// Declare (or replace) the manifest at `path`, builder-style.
    #[must_use]
    pub fn with(mut self, path: impl Into<ManifestPath>, crd: Crd) -> Self {
        self.manifests.insert(path.into(), crd);
        self
    }

    /// Declare (or replace) the manifest at `path`.
    pub fn insert(&mut self, path: impl Into<ManifestPath>, crd: Crd) {
        self.manifests.insert(path.into(), crd);
    }

    /// Remove the manifest at `path` (models a file deleted from the repo).
    pub fn remove(&mut self, path: &str) -> Option<Crd> {
        self.manifests.remove(path)
    }

    /// The declared manifests, keyed by path.
    #[must_use]
    pub fn manifests(&self) -> &BTreeMap<ManifestPath, Crd> {
        &self.manifests
    }
}

/// What happened to one manifest path during a reconcile pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// The path is new in the source and was applied into the cell.
    Applied,
    /// The path existed before with different content and was re-applied.
    Updated,
    /// The path was unchanged since the last pass; re-applied idempotently
    /// (declarative convergence re-asserts desired state every pass).
    Unchanged,
    /// The path was removed from the source and PRUNED (retired) from the cell.
    Pruned,
    /// The path was removed from the source but pruning is disabled, so the
    /// in-cell object was RETAINED and is reported as orphaned, not deleted.
    OrphanRetained,
}

/// One path's outcome in a reconcile pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathOutcome {
    /// The manifest path.
    pub path: ManifestPath,
    /// What the reconciler did with it.
    pub change: ChangeKind,
    /// The controller outcome, when the path was driven through the apply/prune
    /// path (`None` for an orphan that was retained without a controller call).
    pub outcome: Option<ReconcileOutcome>,
}

/// The full result of a reconcile pass — every path's outcome plus the pruned
/// set, so a caller can report exactly what converged and what was retired.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Per-path outcomes, in path order.
    pub outcomes: Vec<PathOutcome>,
}

impl ReconcileReport {
    /// The paths applied (new) this pass.
    #[must_use]
    pub fn applied(&self) -> Vec<&str> {
        self.of_kind(&ChangeKind::Applied)
    }

    /// The paths pruned (removed from repo → retired in-cell) this pass.
    #[must_use]
    pub fn pruned(&self) -> Vec<&str> {
        self.of_kind(&ChangeKind::Pruned)
    }

    /// The paths retained as orphans (removed from repo, pruning disabled).
    #[must_use]
    pub fn orphaned(&self) -> Vec<&str> {
        self.of_kind(&ChangeKind::OrphanRetained)
    }

    fn of_kind(&self, kind: &ChangeKind) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|o| &o.change == kind)
            .map(|o| o.path.as_str())
            .collect()
    }

    /// Whether every controller invocation in the pass reconciled successfully
    /// (no [`ReconcileOutcome::Failed`]).
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.outcomes.iter().all(|o| {
            !matches!(o.outcome, Some(ReconcileOutcome::Failed(_)))
        })
    }
}

/// Why a reconcile pass could not proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileError {
    /// A desired manifest failed schema validation — the pass is refused whole
    /// (a declarative apply is all-or-nothing at the validation gate) rather
    /// than partially applying an invalid set.
    Invalid {
        /// The offending manifest's path.
        path: ManifestPath,
        /// The schema error.
        error: SchemaError,
    },
    /// A desired manifest names a kind with no registered controller hook, so
    /// the reconciler cannot drive it. Refused rather than silently skipped.
    NoController {
        /// The offending manifest's path.
        path: ManifestPath,
        /// The `apiVersion/kind` with no hook.
        kind: String,
    },
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::Invalid { path, error } => {
                write!(f, "manifest `{path}` is invalid: {error}")
            }
            ReconcileError::NoController { path, kind } => {
                write!(f, "manifest `{path}` declares kind {kind} with no registered controller")
            }
        }
    }
}

impl std::error::Error for ReconcileError {}

/// Drives a target cell (a [`ControllerRegistry`]) to match a
/// [`ManifestSource`], riding the manifest system's existing validate+dispatch
/// apply path and tracking applied state so removals prune.
///
/// The reconciler is deliberately NOT a per-kind loop: it diffs the desired
/// source against what it applied last pass and, for every desired manifest,
/// validates it against `schemas` then applies it through
/// [`ControllerRegistry::dispatch`] — the exact one apply path a built-in or
/// third-party CRD reconciles through. A path that vanished from the source is
/// pruned through the same controller (via [`ControllerHook::delete`]).
pub struct Reconciler {
    /// The schema registry every desired manifest is validated against before
    /// apply — the same registry that gates any manifest.
    schemas: SchemaRegistry,
    /// Whether a manifest removed from the source is pruned (retired) from the
    /// cell. Default `true`; `false` retains orphans (Flux's `prune: false`).
    prune: bool,
    /// The paths applied on the previous pass, and the body applied — so the
    /// next pass can tell Applied vs Updated vs Unchanged, and can prune what
    /// disappeared.
    applied: BTreeMap<ManifestPath, Crd>,
}

impl Reconciler {
    /// A reconciler validating against `schemas`, pruning enabled.
    #[must_use]
    pub fn new(schemas: SchemaRegistry) -> Self {
        Reconciler {
            schemas,
            prune: true,
            applied: BTreeMap::new(),
        }
    }

    /// Disable pruning: a manifest removed from the source is retained in-cell
    /// and reported as an orphan rather than retired. Builder-style.
    #[must_use]
    pub fn without_prune(mut self) -> Self {
        self.prune = false;
        self
    }

    /// Whether pruning is enabled.
    #[must_use]
    pub fn prunes(&self) -> bool {
        self.prune
    }

    /// The set of manifest paths currently applied (managed) in the cell.
    #[must_use]
    pub fn applied_paths(&self) -> BTreeSet<&str> {
        self.applied.keys().map(String::as_str).collect()
    }

    /// Reconcile the target cell (`controllers`) to `source`: validate every
    /// desired manifest, apply it through the controller registry's dispatch
    /// path, and prune every previously-applied path that vanished from the
    /// source (unless pruning is disabled).
    ///
    /// The whole pass is refused BEFORE any mutation if any desired manifest
    /// fails validation or names a kind with no controller — a declarative
    /// apply must not leave the cell half-converged over an invalid set.
    ///
    /// # Errors
    /// [`ReconcileError`] if any desired manifest is invalid or uncontrollable;
    /// the cell and the reconciler's applied-state are left untouched.
    pub fn reconcile(
        &mut self,
        source: &ManifestSource,
        controllers: &ControllerRegistry,
    ) -> Result<ReconcileReport, ReconcileError> {
        // --- Validation gate: refuse the whole pass before mutating. ---
        for (path, crd) in source.manifests() {
            self.schemas
                .validate(crd)
                .map_err(|error| ReconcileError::Invalid {
                    path: path.clone(),
                    error,
                })?;
            if !controllers.contains(crd) {
                return Err(ReconcileError::NoController {
                    path: path.clone(),
                    kind: format!("{}/{}", crd.api_version, crd.kind),
                });
            }
        }

        let mut report = ReconcileReport::default();

        // --- Apply/update every desired manifest through the dispatch path. ---
        for (path, crd) in source.manifests() {
            let change = match self.applied.get(path) {
                None => ChangeKind::Applied,
                Some(prev) if prev == crd => ChangeKind::Unchanged,
                Some(_) => ChangeKind::Updated,
            };
            // Ride the EXISTING apply path: the same dispatch a built-in or
            // third-party CRD reconciles through. `contains` was checked above,
            // so dispatch is Some.
            let outcome = controllers
                .dispatch(crd)
                .expect("controller presence was validated above");
            report.outcomes.push(PathOutcome {
                path: path.clone(),
                change,
                outcome: Some(outcome),
            });
        }

        // --- Prune every previously-applied path that vanished. ---
        let removed: Vec<(ManifestPath, Crd)> = self
            .applied
            .iter()
            .filter(|(path, _)| !source.manifests().contains_key(*path))
            .map(|(p, c)| (p.clone(), c.clone()))
            .collect();
        for (path, crd) in removed {
            if self.prune {
                let outcome = controllers.delete(&crd);
                report.outcomes.push(PathOutcome {
                    path,
                    change: ChangeKind::Pruned,
                    outcome: Some(outcome),
                });
            } else {
                report.outcomes.push(PathOutcome {
                    path,
                    change: ChangeKind::OrphanRetained,
                    outcome: None,
                });
            }
        }

        // --- Commit the new applied-state. ---
        // Managed set becomes exactly the source; pruned paths drop out, and a
        // retained orphan STOPS being managed (we no longer track it, matching
        // Flux: once pruning is off and the file is gone, it is unmanaged).
        report.outcomes.sort_by(|a, b| a.path.cmp(&b.path));
        self.applied = source.manifests().clone();

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::{
        register_builtin_controllers, register_builtin_schemas, ControllerHook, ReconcileOutcome,
    };
    use crate::builtin::{BuiltinKind, BUILTIN_API_VERSION};
    use crate::{Metadata, Value};
    use std::cell::RefCell;
    use std::rc::Rc;

    fn schemas() -> SchemaRegistry {
        let mut reg = SchemaRegistry::new();
        register_builtin_schemas(&mut reg);
        reg
    }

    fn controllers() -> ControllerRegistry {
        let mut reg = ControllerRegistry::new();
        register_builtin_controllers(&mut reg);
        reg
    }

    fn dashboard(name: &str, title: &str) -> Crd {
        Crd::new(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Metadata::new(name),
        )
        .with_spec("title", Value::String(title.into()))
    }

    fn job(name: &str, command: &str) -> Crd {
        Crd::new(
            BUILTIN_API_VERSION,
            BuiltinKind::Job.kind_str(),
            Metadata::new(name),
        )
        .with_spec("command", Value::String(command.into()))
    }

    #[test]
    fn a_manifest_in_the_repo_is_reconciled_into_the_cell_via_the_apply_path() {
        let mut r = Reconciler::new(schemas());
        let ctl = controllers();
        let source = ManifestSource::new("rev-1").with("apps/dash.yaml", dashboard("d", "Overview"));

        let report = r.reconcile(&source, &ctl).expect("reconcile");

        assert_eq!(report.applied(), vec!["apps/dash.yaml"]);
        assert!(report.all_ok());
        assert_eq!(
            report.outcomes[0].outcome,
            Some(ReconcileOutcome::Reconciled)
        );
        assert!(r.applied_paths().contains("apps/dash.yaml"));
    }

    /// The load-bearing failing-without-the-change test: a hook that records the
    /// exact (apiVersion, kind) it was dispatched on proves the reconciler rides
    /// the SAME ControllerRegistry::dispatch path — not a bespoke per-kind loop.
    struct RecordingHook {
        applied: Rc<RefCell<Vec<(String, String)>>>,
        deleted: Rc<RefCell<Vec<(String, String)>>>,
    }

    impl ControllerHook for RecordingHook {
        fn reconcile(&self, crd: &Crd) -> ReconcileOutcome {
            self.applied
                .borrow_mut()
                .push((crd.api_version.clone(), crd.kind.clone()));
            ReconcileOutcome::Reconciled
        }
        fn delete(&self, crd: &Crd) -> ReconcileOutcome {
            self.deleted
                .borrow_mut()
                .push((crd.api_version.clone(), crd.kind.clone()));
            ReconcileOutcome::Reconciled
        }
    }

    #[test]
    fn reconcile_drives_the_manifest_through_the_registered_controller_hook() {
        let applied = Rc::new(RefCell::new(Vec::new()));
        let deleted = Rc::new(RefCell::new(Vec::new()));
        let mut ctl = ControllerRegistry::new();
        ctl.register(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Box::new(RecordingHook {
                applied: Rc::clone(&applied),
                deleted: Rc::clone(&deleted),
            }),
        );

        let mut r = Reconciler::new(schemas());
        let source = ManifestSource::new("rev-1").with("d.yaml", dashboard("d", "Overview"));
        r.reconcile(&source, &ctl).expect("reconcile");

        assert_eq!(
            *applied.borrow(),
            vec![(BUILTIN_API_VERSION.to_owned(), "Dashboard".to_owned())]
        );
        assert!(deleted.borrow().is_empty());
    }

    #[test]
    fn a_manifest_removed_from_the_repo_is_pruned_from_the_cell() {
        let applied = Rc::new(RefCell::new(Vec::new()));
        let deleted = Rc::new(RefCell::new(Vec::new()));
        let mut ctl = ControllerRegistry::new();
        ctl.register(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Box::new(RecordingHook {
                applied: Rc::clone(&applied),
                deleted: Rc::clone(&deleted),
            }),
        );

        let mut r = Reconciler::new(schemas());

        // Pass 1: repo has the dashboard.
        let source1 = ManifestSource::new("rev-1").with("d.yaml", dashboard("d", "Overview"));
        r.reconcile(&source1, &ctl).expect("reconcile 1");
        assert!(r.applied_paths().contains("d.yaml"));

        // Pass 2: the file is gone from the repo.
        let source2 = ManifestSource::new("rev-2");
        let report = r.reconcile(&source2, &ctl).expect("reconcile 2");

        assert_eq!(report.pruned(), vec!["d.yaml"]);
        assert!(report.orphaned().is_empty());
        // The prune went through the controller's delete path.
        assert_eq!(
            *deleted.borrow(),
            vec![(BUILTIN_API_VERSION.to_owned(), "Dashboard".to_owned())]
        );
        // It is no longer managed.
        assert!(!r.applied_paths().contains("d.yaml"));
    }

    #[test]
    fn a_removed_manifest_is_retained_when_pruning_is_disabled() {
        let applied = Rc::new(RefCell::new(Vec::new()));
        let deleted = Rc::new(RefCell::new(Vec::new()));
        let mut ctl = ControllerRegistry::new();
        ctl.register(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Box::new(RecordingHook {
                applied: Rc::clone(&applied),
                deleted: Rc::clone(&deleted),
            }),
        );

        let mut r = Reconciler::new(schemas()).without_prune();
        assert!(!r.prunes());

        let source1 = ManifestSource::new("rev-1").with("d.yaml", dashboard("d", "Overview"));
        r.reconcile(&source1, &ctl).expect("reconcile 1");

        let source2 = ManifestSource::new("rev-2");
        let report = r.reconcile(&source2, &ctl).expect("reconcile 2");

        assert_eq!(report.orphaned(), vec!["d.yaml"]);
        assert!(report.pruned().is_empty());
        // NO delete was dispatched — the object was retained, not retired.
        assert!(deleted.borrow().is_empty());
    }

    #[test]
    fn a_changed_manifest_reports_updated_and_an_unchanged_one_reports_unchanged() {
        let mut r = Reconciler::new(schemas());
        let ctl = controllers();

        let source1 = ManifestSource::new("rev-1").with("d.yaml", dashboard("d", "Overview"));
        r.reconcile(&source1, &ctl).expect("reconcile 1");

        // Same path, changed body.
        let source2 = ManifestSource::new("rev-2").with("d.yaml", dashboard("d", "Fleet"));
        let report = r.reconcile(&source2, &ctl).expect("reconcile 2");
        assert_eq!(report.outcomes[0].change, ChangeKind::Updated);

        // Same path, identical body → Unchanged (still re-applied idempotently).
        let source3 = ManifestSource::new("rev-3").with("d.yaml", dashboard("d", "Fleet"));
        let report = r.reconcile(&source3, &ctl).expect("reconcile 3");
        assert_eq!(report.outcomes[0].change, ChangeKind::Unchanged);
        assert_eq!(
            report.outcomes[0].outcome,
            Some(ReconcileOutcome::Reconciled)
        );
    }

    #[test]
    fn multiple_manifests_across_kinds_all_ride_the_one_dispatch_path() {
        let mut r = Reconciler::new(schemas());
        let ctl = controllers();
        let source = ManifestSource::new("rev-1")
            .with("a/dash.yaml", dashboard("d", "Overview"))
            .with("b/job.yaml", job("j", "echo hi"));

        let report = r.reconcile(&source, &ctl).expect("reconcile");
        assert_eq!(report.applied(), vec!["a/dash.yaml", "b/job.yaml"]);
        assert!(report.all_ok());
    }

    #[test]
    fn an_invalid_manifest_refuses_the_whole_pass_without_mutating() {
        let mut r = Reconciler::new(schemas());
        let ctl = controllers();
        // Dashboard missing its required `title`.
        let bad = Crd::new(
            BUILTIN_API_VERSION,
            BuiltinKind::Dashboard.kind_str(),
            Metadata::new("d"),
        );
        let source = ManifestSource::new("rev-1")
            .with("good.yaml", dashboard("g", "OK"))
            .with("bad.yaml", bad);

        let err = r.reconcile(&source, &ctl).unwrap_err();
        assert!(matches!(err, ReconcileError::Invalid { .. }));
        // Nothing was applied — the good manifest did not sneak in.
        assert!(r.applied_paths().is_empty());
    }

    #[test]
    fn a_kind_with_no_registered_controller_refuses_the_pass() {
        let mut r = Reconciler::new({
            // Register a third-party schema so validation passes but no hook.
            let mut reg = schemas();
            reg.register(
                crate::Schema::new("acme.example/v1", "Widget")
                    .required("size", crate::FieldType::Integer),
            );
            reg
        });
        let ctl = controllers(); // no Widget hook
        let widget = Crd::new("acme.example/v1", "Widget", Metadata::new("w"))
            .with_spec("size", Value::Integer(3));
        let source = ManifestSource::new("rev-1").with("w.yaml", widget);

        let err = r.reconcile(&source, &ctl).unwrap_err();
        assert!(matches!(err, ReconcileError::NoController { .. }));
    }

    #[test]
    fn re_applying_the_same_revision_is_idempotent() {
        let mut r = Reconciler::new(schemas());
        let ctl = controllers();
        let source = ManifestSource::new("rev-1").with("d.yaml", dashboard("d", "Overview"));

        let r1 = r.reconcile(&source, &ctl).expect("reconcile 1");
        assert_eq!(r1.outcomes[0].change, ChangeKind::Applied);
        let r2 = r.reconcile(&source, &ctl).expect("reconcile 2");
        assert_eq!(r2.outcomes[0].change, ChangeKind::Unchanged);
        assert!(r2.pruned().is_empty());
        assert!(r2.orphaned().is_empty());
    }
}
