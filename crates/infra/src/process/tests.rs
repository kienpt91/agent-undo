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
            &[
                "sh",
                "-c",
                "[ \"$AGENT_UNDO_ACTIVE\" = 1 ] && [ -z \"${HOME+x}\" ] && [ -z \"${USER+x}\" ]",
            ],
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
