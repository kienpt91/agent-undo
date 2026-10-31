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
    cwd: PathBuf,
}

impl ProcessRunner {
    pub fn new(cwd: PathBuf) -> ProcessRunner {
        ProcessRunner { cwd }
    }
}

/// Resolves `program` like a shell would: names with a `/` are used as given,
/// others are searched in `path_var` (the parent's `PATH`, even when the child
/// environment does not contain it).
pub fn resolve_program(program: &[u8], path_var: Option<&OsStr>) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let is_exec = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains(&b'/') {
        let p = PathBuf::from(OsString::from_vec(program.to_vec()));
        return std::fs::metadata(&p).is_ok().then_some(p);
    }
    for dir in std::env::split_paths(path_var?) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
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
        let Some(resolved) = resolve_program(program, path_var.as_deref()) else {
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
mod tests {
    use super::*;
    use agent_undo_domain::env::EnvPolicy;

    #[test]
    fn resolves_programs_on_path_and_by_path() {
        let sh = resolve_program(b"sh", std::env::var_os("PATH").as_deref());
        assert!(sh.is_some());
        assert!(resolve_program(b"/bin/sh", None).is_some());
        assert!(
            resolve_program(
                b"definitely-not-a-real-program-xyz",
                std::env::var_os("PATH").as_deref()
            )
            .is_none()
        );
        assert!(resolve_program(b"sh", None).is_none());
        assert!(resolve_program(b"", std::env::var_os("PATH").as_deref()).is_none());
        assert!(resolve_program(b"/nonexistent/prog", None).is_none());
    }

    fn req(args: &[&str], env: EnvPolicy) -> RunRequest {
        RunRequest {
            args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
            env,
            extra_env: vec![("AGENT_UNDO_ACTIVE".into(), b"1".to_vec())],
        }
    }

    #[test]
    fn exit_codes_and_signals_are_reported() {
        let r = ProcessRunner::new(std::env::temp_dir());
        assert_eq!(
            r.run(&req(&["sh", "-c", "exit 7"], EnvPolicy::Inherit))
                .unwrap(),
            RunOutcome::Exited(ExitInfo::Code(7))
        );
        assert_eq!(
            r.run(&req(&["sh", "-c", "kill -9 $$"], EnvPolicy::Inherit))
                .unwrap(),
            RunOutcome::Exited(ExitInfo::Signal(9))
        );
    }

    #[test]
    fn missing_and_non_executable_commands() {
        let r = ProcessRunner::new(std::env::temp_dir());
        assert_eq!(
            r.run(&req(
                &["definitely-not-a-real-program-xyz"],
                EnvPolicy::Inherit
            ))
            .unwrap(),
            RunOutcome::NotFound
        );
        assert_eq!(
            r.run(&RunRequest {
                args: vec![],
                env: EnvPolicy::Inherit,
                extra_env: vec![]
            })
            .unwrap(),
            RunOutcome::NotFound
        );
        let dir = std::env::temp_dir().join(format!("au-proc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("notexec");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let out = r
            .run(&req(&[f.to_str().unwrap()], EnvPolicy::Inherit))
            .unwrap();
        assert!(matches!(out, RunOutcome::CannotExecute(_)), "{out:?}");
    }

    #[test]
    fn allow_list_hides_other_variables_and_extras_are_passed() {
        let r = ProcessRunner::new(std::env::temp_dir());
        let ok = r
            .run(&req(
                &["sh", "-c", "[ \"$AGENT_UNDO_ACTIVE\" = 1 ] && [ -z \"${HOME+x}\" ] && [ -z \"${USER+x}\" ]"],
                EnvPolicy::allow(&["PATH_NOT_NEEDED".into()]).unwrap(),
            ))
            .unwrap();
        assert_eq!(ok, RunOutcome::Exited(ExitInfo::Code(0)));
    }

    #[test]
    fn runs_in_the_given_directory() {
        let dir = std::env::temp_dir().join(format!("au-proc-cwd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let canon = std::fs::canonicalize(&dir).unwrap();
        let r = ProcessRunner::new(canon.clone());
        let script = format!("[ \"$(pwd -P)\" = '{}' ]", canon.display());
        assert_eq!(
            r.run(&req(&["sh", "-c", &script], EnvPolicy::Inherit))
                .unwrap(),
            RunOutcome::Exited(ExitInfo::Code(0))
        );
    }
}
