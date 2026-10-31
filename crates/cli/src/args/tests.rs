use super::*;

fn p(args: &[&str]) -> Result<Cli> {
    parse(args.iter().map(OsString::from).collect())
}

fn cmd(args: &[&str]) -> Command {
    p(args).unwrap().command
}

#[test]
fn no_args_and_help_flags() {
    assert_eq!(cmd(&[]), Command::Help(None));
    assert_eq!(cmd(&["--help"]), Command::Help(None));
    assert_eq!(cmd(&["undo", "--help"]), Command::Help(Some("undo".into())));
    assert_eq!(cmd(&["help", "gc"]), Command::Help(Some("gc".into())));
    assert_eq!(cmd(&["--version"]), Command::Version);
}

#[test]
fn global_options_before_and_after_command() {
    let c = p(&["-C", "/proj", "--json", "status"]).unwrap();
    assert_eq!(
        (c.project.as_deref(), c.json),
        (Some(std::path::Path::new("/proj")), true)
    );
    let c = p(&["status", "--json", "--project", "/p"]).unwrap();
    assert!(c.json && c.project.is_some());
    assert!(p(&["-C"]).is_err());
}

#[test]
fn unknown_command_and_option() {
    assert!(matches!(p(&["frobnicate"]), Err(Error::Usage(_))));
    assert!(matches!(p(&["--frobnicate"]), Err(Error::Usage(_))));
    assert!(p(&["status", "extra"]).is_err());
}

#[test]
fn init_options() {
    assert_eq!(
        cmd(&[
            "init",
            "--in-project",
            "--max-file-size",
            "1MiB",
            "--allow-broad-root"
        ]),
        Command::Init {
            in_project: true,
            max_file_size: Some(1 << 20),
            allow_broad_root: true
        }
    );
    assert!(p(&["init", "--max-file-size", "lots"]).is_err());
    assert!(p(&["init", "--bogus"]).is_err());
    assert!(p(&["init", "--max-file-size"]).is_err());
}

#[test]
fn run_collects_command_after_double_dash() {
    let c = cmd(&[
        "run",
        "--label",
        "fix",
        "--new-session",
        "--env-allow",
        "A,B",
        "--",
        "sh",
        "-c",
        "echo hi",
        "--json",
    ]);
    assert_eq!(
        c,
        Command::Run {
            label: Some(b"fix".to_vec()),
            new_session: true,
            env_allow: vec!["A,B".into()],
            args: vec![
                b"sh".to_vec(),
                b"-c".to_vec(),
                b"echo hi".to_vec(),
                b"--json".to_vec()
            ],
        }
    );
}

#[test]
fn run_requires_a_command() {
    assert!(p(&["run"]).is_err());
    assert!(p(&["run", "--"]).is_err());
    assert!(p(&["run", "sh"]).is_err(), "command must follow --");
    assert!(p(&["run", "--label"]).is_err());
}

#[test]
fn global_flags_after_double_dash_belong_to_the_command() {
    let c = p(&["run", "--", "echo", "--json", "-C", "x"]).unwrap();
    assert!(!c.json);
    assert!(c.project.is_none());
}

#[test]
fn checkpoint_and_log() {
    assert_eq!(
        cmd(&["checkpoint", "--label", "x", "--new-session"]),
        Command::Checkpoint {
            label: Some(b"x".to_vec()),
            new_session: true
        }
    );
    assert_eq!(cmd(&["log"]), Command::Log { session: None });
    assert_eq!(
        cmd(&["log", "--session", "2"]),
        Command::Log { session: Some(2) }
    );
    assert!(p(&["log", "--session", "zero"]).is_err());
    assert!(p(&["checkpoint", "x"]).is_err());
}

#[test]
fn diff_needs_a_valid_checkpoint() {
    assert_eq!(cmd(&["diff", "3"]), Command::Diff { checkpoint: 3 });
    assert_eq!(cmd(&["diff", "#7"]), Command::Diff { checkpoint: 7 });
    assert!(p(&["diff"]).is_err());
    assert!(p(&["diff", "0"]).is_err());
    assert!(p(&["diff", "x"]).is_err());
    assert!(p(&["diff", "1", "2"]).is_err());
}

#[test]
fn undo_targets_and_flags() {
    assert_eq!(
        cmd(&["undo", "4"]),
        Command::Undo {
            target: UndoTarget::Checkpoint(4),
            apply: false,
            force: false
        }
    );
    assert_eq!(
        cmd(&["undo", "--last", "--apply", "--force"]),
        Command::Undo {
            target: UndoTarget::Last,
            apply: true,
            force: true
        }
    );
    assert!(matches!(
        cmd(&["undo", "--session"]),
        Command::Undo {
            target: UndoTarget::Session(None),
            ..
        }
    ));
    assert!(matches!(
        cmd(&["undo", "--session", "3"]),
        Command::Undo {
            target: UndoTarget::Session(Some(3)),
            ..
        }
    ));
    assert!(matches!(
        cmd(&["undo", "--session", "--apply"]),
        Command::Undo {
            target: UndoTarget::Session(None),
            apply: true,
            ..
        }
    ));
}

#[test]
fn undo_rejects_bad_combinations() {
    assert!(p(&["undo"]).is_err());
    assert!(p(&["undo", "1", "--last"]).is_err());
    assert!(p(&["undo", "--last", "--session"]).is_err());
    assert!(p(&["undo", "--last", "--apply", "--dry-run"]).is_err());
    assert!(p(&["undo", "--bogus"]).is_err());
    assert!(p(&["undo", "abc"]).is_err());
}

#[test]
fn restore_parsing() {
    assert_eq!(
        cmd(&["restore", "src/a.rs", "--from", "#2", "--apply"]),
        Command::Restore {
            path: "src/a.rs".into(),
            from: 2,
            apply: true,
            force: false
        }
    );
    assert!(p(&["restore", "a"]).is_err(), "needs --from");
    assert!(p(&["restore", "--from", "1"]).is_err(), "needs a path");
    assert!(p(&["restore", "a", "b", "--from", "1"]).is_err());
    assert!(p(&["restore", "a", "--from", "1", "--apply", "--dry-run"]).is_err());
    assert!(p(&["restore", "a", "--from", "1", "--weird"]).is_err());
}

#[test]
fn gc_parsing() {
    assert_eq!(
        cmd(&["gc", "--keep", "5"]),
        Command::Gc {
            policy: GcPolicy::Keep(5),
            apply: false
        }
    );
    assert_eq!(
        cmd(&["gc", "--older-than", "7d", "--apply"]),
        Command::Gc {
            policy: GcPolicy::OlderThan(Duration::from_secs(7 * 86_400)),
            apply: true
        }
    );
    assert!(p(&["gc"]).is_err());
    assert!(p(&["gc", "--keep", "0"]).is_err());
    assert!(p(&["gc", "--keep", "x"]).is_err());
    assert!(p(&["gc", "--keep", "1", "--older-than", "1d"]).is_err());
    assert!(p(&["gc", "--keep", "1", "--apply", "--dry-run"]).is_err());
    assert!(p(&["gc", "--older-than", "soon"]).is_err());
}

#[test]
fn watch_parsing() {
    let c = cmd(&[
        "watch",
        "--interval",
        "250ms",
        "--quiet",
        "1s",
        "--label",
        "w",
        "--exit-after",
        "2",
        "--timeout",
        "1m",
    ]);
    assert_eq!(
        c,
        Command::Watch(WatchOpts {
            interval: Duration::from_millis(250),
            quiet: Duration::from_secs(1),
            label: Some(b"w".to_vec()),
            exit_after: Some(2),
            timeout: Some(Duration::from_secs(60)),
        })
    );
    assert!(matches!(cmd(&["watch"]), Command::Watch(_)));
    assert!(p(&["watch", "--interval", "0"]).is_err());
    assert!(p(&["watch", "--exit-after", "x"]).is_err());
    assert!(p(&["watch", "--bogus"]).is_err());
}

#[test]
fn simple_commands_reject_extras() {
    assert_eq!(cmd(&["status"]), Command::Status);
    assert_eq!(cmd(&["verify"]), Command::Verify);
    assert_eq!(cmd(&["doctor"]), Command::Doctor);
    assert!(p(&["verify", "x"]).is_err());
    assert!(p(&["doctor", "--fix"]).is_err());
}

#[test]
fn non_utf8_paths_and_labels_are_accepted() {
    let weird = OsString::from_vec(vec![b'a', 0xff, b'b']);
    let c = parse(vec![
        "restore".into(),
        weird.clone(),
        "--from".into(),
        "1".into(),
    ])
    .unwrap();
    assert!(matches!(c.command, Command::Restore { ref path, .. } if *path == weird));
    let c = parse(vec!["checkpoint".into(), "--label".into(), weird]).unwrap();
    assert!(
        matches!(c.command, Command::Checkpoint { label: Some(ref l), .. } if l == &[b'a', 0xff, b'b'])
    );
}

#[test]
fn error_messages_escape_hostile_arguments() {
    let hostile = OsString::from_vec(b"\x1b[31mbad".to_vec());
    let e = parse(vec!["status".into(), hostile]).unwrap_err();
    assert!(!e.to_string().contains('\x1b'));
}

#[test]
fn is_helper() {
    assert!(is(OsStr::new("x"), "x"));
    assert!(!is(OsStr::new("x"), "y"));
}
