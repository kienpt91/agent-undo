//! Runs the wrapped command with inherited stdio.

use agent_undo_app::error::Result;
use agent_undo_app::ports::{CommandRunner, RunOutcome, RunRequest};
use agent_undo_domain::journal::ExitInfo;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct ProcessRunner {
    /// Working directory of the wrapped command (the project root).
    cwd: PathBuf,
    /// Directory `agent-undo` was started in; relative program names and relative
    /// `PATH` entries mean this directory, as they would for any other command.
    caller_dir: PathBuf,
}

impl ProcessRunner {
    /// Runs commands in `cwd`; relative programs are resolved against the current
    /// directory of this process.
    pub fn new(cwd: PathBuf) -> ProcessRunner {
        let caller_dir = std::env::current_dir().unwrap_or_else(|_| cwd.clone());
        ProcessRunner { cwd, caller_dir }
    }

    pub fn with_caller_dir(cwd: PathBuf, caller_dir: PathBuf) -> ProcessRunner {
        ProcessRunner { cwd, caller_dir }
    }
}

/// Resolves `program` like a shell would and returns an **absolute** path: names
/// with a `/` are taken relative to `caller_dir`, others are searched in `path_var`
/// (the parent's `PATH`, even when the child environment does not contain it),
/// where relative and empty entries also mean `caller_dir`. The command then runs
/// in a different directory (the project root), so a relative path must never be
/// handed to `exec`: it would name another file.
pub fn resolve_program(
    program: &[u8],
    path_var: Option<&OsStr>,
    caller_dir: &Path,
) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let is_exec = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains(&b'/') {
        let p = PathBuf::from(OsString::from_vec(program.to_vec()));
        let p = if p.is_absolute() {
            p
        } else {
            caller_dir.join(p)
        };
        return std::fs::metadata(&p).is_ok().then_some(p);
    }
    for dir in std::env::split_paths(path_var?) {
        let dir = if dir.as_os_str().is_empty() {
            caller_dir.to_path_buf()
        } else if dir.is_absolute() {
            dir
        } else {
            caller_dir.join(dir)
        };
        let cand = dir.join(OsStr::from_bytes(program));
        if is_exec(&cand) {
            return Some(cand);
        }
    }
    None
}

impl CommandRunner for ProcessRunner {
    fn run(&self, request: &RunRequest) -> Result<RunOutcome> {
        let Some((program, args)) = request.args.split_first() else {
            return Ok(RunOutcome::NotFound);
        };
        let path_var = std::env::var_os("PATH");
        let Some(resolved) = resolve_program(program, path_var.as_deref(), &self.caller_dir) else {
            return Ok(RunOutcome::NotFound);
        };
        let parent: Vec<(Vec<u8>, Vec<u8>)> = std::env::vars_os()
            .map(|(k, v)| (k.into_vec(), v.into_vec()))
            .collect();
        let extra: Vec<(&str, Vec<u8>)> = request
            .extra_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let env = request.env.child_env(&parent, &extra);
        let mut cmd = Command::new(&resolved);
        cmd.args(args.iter().map(|a| OsStr::from_bytes(a)))
            .env_clear()
            .envs(
                env.iter()
                    .map(|(k, v)| (OsStr::from_bytes(k), OsStr::from_bytes(v))),
            )
            .current_dir(&self.cwd)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RunOutcome::NotFound),
            Err(e) => return Ok(RunOutcome::CannotExecute(e.to_string())),
        };
        let status = child
            .wait()
            .map_err(|e| agent_undo_app::error::Error::io("waiting for the command", e))?;
        Ok(RunOutcome::Exited(match (status.code(), status.signal()) {
            (Some(c), _) => ExitInfo::Code(c),
            (None, Some(s)) => ExitInfo::Signal(s),
            (None, None) => ExitInfo::Code(1),
        }))
    }
}

#[cfg(test)]
mod tests;
