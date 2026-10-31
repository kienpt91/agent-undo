use super::*;
use agent_undo_domain::env::EnvPolicy;

#[test]
fn resolves_programs_on_path_and_by_path() {
    let here = std::env::temp_dir();
    let path = std::env::var_os("PATH");
    assert!(resolve_program(b"sh", path.as_deref(), &here).is_some());
    assert!(resolve_program(b"/bin/sh", None, &here).is_some());
    assert!(
        resolve_program(b"definitely-not-a-real-program-xyz", path.as_deref(), &here).is_none()
    );
    assert!(resolve_program(b"sh", None, &here).is_none());
    assert!(resolve_program(b"", path.as_deref(), &here).is_none());
    assert!(resolve_program(b"/nonexistent/prog", None, &here).is_none());
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

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("au-proc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

fn script(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_relative_program_is_resolved_against_the_callers_directory_not_the_project_root() {
    // `agent-undo run -- ./tool` from root/sub: the file that was checked is root/sub/tool,
    // but the command runs with the project root as its working directory, where
    // `./tool` would be a different (possibly attacker-placed) file.
    let root = tmpdir("rel");
    let sub = root.join("sub");
    script(&root, "tool", "printf root > who.txt");
    script(&sub, "tool", "printf sub > who.txt");
    let r = ProcessRunner::with_caller_dir(root.clone(), sub.clone());
    let out = r.run(&req(&["./tool"], EnvPolicy::Inherit)).unwrap();
    assert_eq!(out, RunOutcome::Exited(ExitInfo::Code(0)));
    assert_eq!(std::fs::read(root.join("who.txt")).unwrap(), b"sub");
}

#[test]
fn relative_and_empty_path_entries_are_resolved_against_the_callers_directory() {
    let root = tmpdir("relpath");
    let sub = root.join("sub");
    script(&root.join("bin"), "mytool", "printf rootbin > who.txt");
    script(&sub.join("bin"), "mytool", "printf subbin > who.txt");
    let got = resolve_program(b"mytool", Some(OsStr::new("bin")), &sub).unwrap();
    assert_eq!(got, sub.join("bin").join("mytool"));
    assert!(got.is_absolute());
    // an empty PATH entry means the current directory: the caller's, not the project root
    script(&sub, "here", "true");
    assert_eq!(
        resolve_program(b"here", Some(OsStr::new("")), &sub),
        Some(sub.join("here"))
    );
    assert_eq!(
        resolve_program(b"here", Some(OsStr::new("/nonexistent:")), &sub),
        Some(sub.join("here"))
    );
}

#[test]
fn resolved_programs_are_always_absolute() {
    let dir = tmpdir("abs");
    script(&dir, "t", "true");
    let r = resolve_program(b"./t", None, &dir).unwrap();
    assert!(r.is_absolute());
    assert_eq!(r, dir.join("./t"));
    let abs = dir.join("t");
    assert_eq!(
        resolve_program(abs.as_os_str().as_bytes(), None, Path::new("/elsewhere")),
        Some(abs)
    );
    assert!(
        resolve_program(b"sub/t", None, &dir).is_none(),
        "a relative path with a slash is not searched in PATH"
    );
}
