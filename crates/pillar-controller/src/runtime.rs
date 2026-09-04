//! The OCI runtime layer — executes a digest-verified [`RunningWorkload`]'s
//! image bytes as a REAL supervised OS process, replacing the modeled
//! `admitted.run(bytes)` result (a `RunningWorkload` *state value* with no
//! process, no pid, no socket) with an actual `tokio::process::Child`: a real
//! pid the kernel scheduled, capable of binding a real listening socket.
//!
//! This is the execute half of the workload vertical (the fetch half —
//! pulling and content-verifying the image bytes — is
//! [`crate::AdmittedFetch::run`]). [`SupervisedWorkload::spawn`] takes the
//! verified image bytes, writes them to an executable file, and runs them as
//! the workload's entrypoint under [`tokio::process::Child`] supervision:
//! [`SupervisedWorkload::pid`] exposes the real OS pid, [`stop`](SupervisedWorkload::stop)
//! terminates the child and waits for it to actually exit,
//! [`restart`](SupervisedWorkload::restart) stops and re-spawns the same
//! image, and [`is_alive`](SupervisedWorkload::is_alive) is the liveness
//! health check — a non-blocking `try_wait` on the real child, not a modeled
//! flag.
//!
//! No namespace/cgroup isolation is implemented yet (the workspace forbids
//! `unsafe_code`, and `tokio::process::Command` already gives us the
//! at-minimum-required "real child process running the image's entrypoint");
//! namespaces/cgroups are a follow-up hardening step, not a gate on this
//! task's acceptance criteria.

use std::io;
use std::path::PathBuf;
use std::process::Stdio;

use tempfile::TempDir;
use tokio::process::{Child, Command};

/// Errors raised while spawning or supervising a workload's OCI process.
#[derive(Debug)]
pub enum RuntimeError {
    /// The verified image bytes could not be staged to disk as an
    /// executable file.
    Stage(io::Error),
    /// The staged executable could not be spawned as a child process.
    Spawn(io::Error),
    /// Waiting on / signaling the child process failed.
    Supervise(io::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Stage(e) => write!(f, "failed to stage workload image as executable: {e}"),
            RuntimeError::Spawn(e) => write!(f, "failed to spawn workload process: {e}"),
            RuntimeError::Supervise(e) => write!(f, "failed to supervise workload process: {e}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// A real, supervised OS process running a workload's digest-verified image
/// bytes as its entrypoint — the "execute" half of the workload vertical.
///
/// Holds the staged executable (kept alive in a [`TempDir`] for the
/// process's lifetime so `restart` can re-exec the exact same verified
/// bytes) and the live [`tokio::process::Child`]. Every lifecycle operation
/// (`stop`, `restart`, `is_alive`) acts on that real child — never a modeled
/// state value.
pub struct SupervisedWorkload {
    // Kept alive so the staged executable file is not removed out from under
    // a running (or restarting) child.
    _staging_dir: TempDir,
    exec_path: PathBuf,
    args: Vec<String>,
    child: Child,
}

impl SupervisedWorkload {
    /// Stage `image_bytes` to an executable file and spawn it as a real
    /// child process with `args`, returning once the process has actually
    /// been scheduled by the kernel (a real pid is available).
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Stage`] if the image bytes cannot be written
    /// to disk as an executable, or [`RuntimeError::Spawn`] if the OS
    /// refuses to schedule the process.
    pub fn spawn(image_bytes: &[u8], args: &[String]) -> Result<Self, RuntimeError> {
        let staging_dir = tempfile::tempdir().map_err(RuntimeError::Stage)?;
        let exec_path = staging_dir.path().join("workload-entrypoint");
        std::fs::write(&exec_path, image_bytes).map_err(RuntimeError::Stage)?;
        make_executable(&exec_path).map_err(RuntimeError::Stage)?;

        let child = spawn_child(&exec_path, args)?;

        Ok(SupervisedWorkload {
            _staging_dir: staging_dir,
            exec_path,
            args: args.to_vec(),
            child,
        })
    }

    /// The real OS pid of the supervised child process.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Liveness health check: a non-blocking poll of the REAL child process
    /// (`try_wait`), true iff the kernel still schedules it and it has not
    /// exited.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Supervise`] if the OS refuses to report the
    /// child's status.
    pub fn is_alive(&mut self) -> Result<bool, RuntimeError> {
        match self.child.try_wait().map_err(RuntimeError::Supervise)? {
            Some(_exit_status) => Ok(false),
            None => Ok(true),
        }
    }

    /// Terminate the supervised child and wait for it to actually exit —
    /// after this returns, the pid is gone and any socket it held is
    /// closed by the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Supervise`] if the child cannot be signaled
    /// or its exit cannot be awaited.
    pub async fn stop(&mut self) -> Result<(), RuntimeError> {
        // start_kill is a no-op (Ok) if the child already exited.
        self.child.start_kill().map_err(RuntimeError::Supervise)?;
        self.child.wait().await.map_err(RuntimeError::Supervise)?;
        Ok(())
    }

    /// Stop the current process (if still running) and spawn a fresh child
    /// running the SAME staged image/entrypoint — a real restart, not a
    /// modeled state flip: the pid changes and the socket is rebound by the
    /// new process.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Supervise`] if the old process cannot be
    /// stopped, or [`RuntimeError::Spawn`] if the new one cannot be started.
    pub async fn restart(&mut self) -> Result<(), RuntimeError> {
        self.stop().await?;
        self.child = spawn_child(&self.exec_path, &self.args)?;
        Ok(())
    }
}

fn spawn_child(exec_path: &PathBuf, args: &[String]) -> Result<Child, RuntimeError> {
    Command::new(exec_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(RuntimeError::Spawn)
}

#[cfg(unix)]
fn make_executable(path: &PathBuf) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &PathBuf) -> io::Result<()> {
    Ok(())
}
