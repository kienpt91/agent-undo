//! End-to-end tests of the real `agent-undo` binary: init, run, checkpoint, log,
//! diff, undo, restore, status, verify, gc, watch, doctor, usage errors, locking
//! and the `--json` contract. Safety scenarios live in `e2e_safety.rs`.

mod common;

use common::*;
use std::fs;
use std::time::Duration;

// ---------------------------------------------------------- the JSON reader

#[test]
fn json_reader_parses_nested_documents() {
    let j = parse_json(r#" {"a":[1,2,{"b":null}],"c":true,"d":"x","e":-12.5e1} "#).unwrap();
    assert_eq!(j.p("a.0").u64(), 1);
    assert!(j.p("a.2.b").is_null());
    assert!(j.p("c").bool());
    assert_eq!(j.p("d").str(), "x");
    assert_eq!(j.p("e"), &J::Num("-12.5e1".into()));
    assert_eq!(j.keys(), vec!["a", "c", "d", "e"]);
    assert!(j.try_p("a.9").is_none() && j.try_p("zzz").is_none());
    assert_eq!(parse_json("[]").unwrap(), J::Arr(vec![]));
    assert_eq!(parse_json("{}").unwrap(), J::Obj(vec![]));
}

#[test]
fn json_reader_decodes_escapes_and_surrogate_pairs() {
    let j = parse_json(r#""a\"b\\c\/d\n\t\u0041\u00e9\ud83d\ude00""#).unwrap();
    assert_eq!(j.str(), "a\"b\\c/d\n\tA\u{e9}\u{1F600}");
}

#[test]
fn json_reader_rejects_malformed_input() {
    for bad in [
        "",
        "{",
        "[1,]",
        "{\"a\" 1}",
        "\"abc",
        "tru",
        "1 2",
        "\"a\nb\"",
        "\"\\x\"",
        "\"\\ud83d\"",
        "{\"a\":}",
        "-",
    ] {
        assert!(parse_json(bad).is_err(), "should reject {bad:?}");
    }
}

// --------------------------------------------------------------------- init

#[test]
fn init_creates_external_store_with_private_permissions() {
    let p = Proj::new("init-perms");
    p.write("a.txt", "hello");
    let o = p.run(&["init"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("initialized agent-undo for"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("baseline: checkpoint #1"), "{}", o.stdout);

    let store = p.store();
    assert!(store.starts_with(p.state.join("agent-undo")));
    let id = store.file_name().unwrap().to_str().unwrap();
    assert_eq!(id.len(), 16);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
    assert_eq!(mode_of(&store), 0o700);
    for d in ["blobs", "checkpoints", "tmp"] {
        assert_eq!(mode_of(&store.join(d)), 0o700, "{d}");
    }
    for f in ["meta", "key", "log"] {
        assert_eq!(mode_of(&store.join(f)), 0o600, "{f}");
    }
    // Every file the baseline wrote (blobs, manifests) is private too.
    for f in files_below(&store) {
        assert_eq!(
            mode_of(&f) & 0o077,
            0,
            "{} is accessible to others",
            f.display()
        );
    }
}

#[test]
fn init_never_puts_the_store_in_the_project_by_default() {
    let p = Proj::inited("init-outside");
    p.agent("echo data > f.txt");
    p.run(&["checkpoint"]);
    assert!(!p.exists(".agent-undo"));
    let names: Vec<String> = fs::read_dir(&p.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["f.txt".to_string()]);
}

#[test]
fn init_json_describes_the_store() {
    let p = Proj::new("init-json");
    let j = p.json(&["init"]);
    assert_eq!(j.p("command").str(), "init");
    assert_eq!(j.p("project").str(), p.root.to_str().unwrap());
    assert_eq!(j.p("store").str(), p.store().to_str().unwrap());
    assert!(!j.p("in_project").bool());
    assert_eq!(j.p("max_file_size").u64(), 25 * 1024 * 1024);
    assert_eq!(j.p("baseline.id").u64(), 1);
    assert_eq!(j.p("baseline.kind").str(), "baseline");
    assert!(j.p("note").is_null());
}

#[test]
fn init_twice_fails_with_already_initialized() {
    let p = Proj::inited("init-twice");
    let j = p.json_err(&["init"], 1, "already_initialized");
    assert!(j.p("error.message").str().contains("already initialized"));
    // The first store is untouched.
    assert_eq!(p.count(), 1);
}

#[test]
fn init_in_project_creates_store_and_git_exclude() {
    let p = Proj::new("init-inproj");
    fs::create_dir_all(p.path(".git")).unwrap();
    let j = p.json(&["init", "--in-project"]);
    assert!(j.p("in_project").bool());
    assert_eq!(j.p("store").str(), p.path(".agent-undo").to_str().unwrap());
    assert!(j.p("note").is_null());
    assert!(p.path(".agent-undo/meta").is_file());
    assert_eq!(mode_of(&p.path(".agent-undo")), 0o700);
    assert_eq!(mode_of(&p.path(".agent-undo/key")), 0o600);
    let exclude = p.read(".git/info/exclude");
    assert_eq!(exclude.lines().filter(|l| *l == ".agent-undo").count(), 1);
    // No external store was created.
    assert!(!p.state.join("agent-undo").exists());
}

#[test]
fn init_in_project_does_not_duplicate_an_existing_exclude_line() {
    let p = Proj::new("init-excl-idem");
    fs::create_dir_all(p.path(".git/info")).unwrap();
    p.write(".git/info/exclude", "# comment\n.agent-undo\n");
    let o = p.run(&["init", "--in-project"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read(".git/info/exclude"), "# comment\n.agent-undo\n");
}

#[test]
fn init_in_project_appends_to_exclude_without_trailing_newline() {
    let p = Proj::new("init-excl-nonl");
    fs::create_dir_all(p.path(".git/info")).unwrap();
    p.write(".git/info/exclude", "*.tmp");
    assert_eq!(p.run(&["init", "--in-project"]).code, 0);
    assert_eq!(p.read(".git/info/exclude"), "*.tmp\n.agent-undo\n");
}

#[test]
fn init_in_project_twice_is_refused_and_exclude_stays_single() {
    let p = Proj::new("init-excl-twice");
    fs::create_dir_all(p.path(".git")).unwrap();
    assert_eq!(p.run(&["init", "--in-project"]).code, 0);
    p.json_err(&["init", "--in-project"], 1, "already_initialized");
    let exclude = p.read(".git/info/exclude");
    assert_eq!(exclude.matches(".agent-undo").count(), 1, "{exclude}");
}

#[test]
fn init_in_project_without_git_prints_a_note() {
    let p = Proj::new("init-nogit");
    let o = p.run(&["init", "--in-project"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stderr.contains("note: no .git directory found"),
        "{}",
        o.stderr
    );
    assert!(p.path(".agent-undo/meta").is_file());

    let q = Proj::new("init-nogit-json");
    let j = q.json(&["init", "--in-project"]);
    assert!(j.p("note").str().contains("no .git directory"));
}

#[test]
fn init_in_project_with_git_file_notes_that_git_is_not_a_directory() {
    let p = Proj::new("init-gitfile");
    p.write(".git", "gitdir: /somewhere/else\n");
    let j = p.json(&["init", "--in-project"]);
    assert!(j.p("note").str().contains("not a directory"));
    assert_eq!(p.read(".git"), "gitdir: /somewhere/else\n");
}

#[test]
fn in_project_store_is_never_recorded_as_a_change() {
    let p = Proj::new("inproj-ignored");
    p.write("a.txt", "x");
    assert_eq!(p.run(&["init", "--in-project"]).code, 0);
    let st = p.json(&["status"]);
    assert_eq!(st.p("pending.counts.total").u64(), 0);
    let c = p.json(&["checkpoint"]);
    assert_eq!(c.p("checkpoint.changes.total").u64(), 0);
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn init_refuses_the_home_directory() {
    let p = Proj::at_home("init-home");
    p.write("notes.txt", "private");
    let j = p.json_err(&["init"], 2, "usage");
    assert!(j.p("error.message").str().contains("home directory"));
    assert!(
        !p.state.join("agent-undo").exists(),
        "nothing may be created"
    );
    assert!(!p.exists(".agent-undo"));
}

#[test]
fn init_allows_the_home_directory_with_explicit_flag() {
    let p = Proj::at_home("init-home-ok");
    p.write("notes.txt", "private");
    let j = p.json(&["init", "--allow-broad-root"]);
    assert_eq!(j.p("baseline.entries").u64(), 1);
}

#[test]
fn init_refuses_the_filesystem_root() {
    let p = Proj::new("init-slash");
    let o = p.run(&["--json", "-C", "/", "init"]);
    assert_eq!(o.code, 2, "{}", o.all());
    assert_eq!(o.json().p("error.code").str(), "usage");
    assert!(!p.state.join("agent-undo").exists());
}

#[test]
fn init_max_file_size_marks_larger_files_as_too_large() {
    let p = Proj::new("init-maxsize");
    let j = p.json(&["init", "--max-file-size", "16"]);
    assert_eq!(j.p("max_file_size").u64(), 16);
    p.agent("printf '%0100d' 0 > big.txt; echo tiny > small.txt");
    let d = p.json(&["diff", "2"]);
    let changes = d.p("changes").arr();
    let big = changes
        .iter()
        .find(|c| c.p("path").str() == "big.txt")
        .unwrap();
    assert_eq!(big.p("after.kind").str(), "too-large");
    assert!(big.p("text_diff").is_null());
    assert!(big.p("withheld").str().contains("too-large"));
    let small = changes
        .iter()
        .find(|c| c.p("path").str() == "small.txt")
        .unwrap();
    assert_eq!(small.p("after.kind").str(), "file");
}

#[test]
fn undo_never_deletes_a_too_large_file_without_force() {
    let p = Proj::new("toolarge-undo");
    p.run(&["init", "--max-file-size", "16"]);
    p.agent("printf '%0100d' 0 > big.txt");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 3, "{}", o.all());
    assert!(
        o.stdout.contains("too-large") || o.stdout.contains("too large"),
        "{}",
        o.stdout
    );
    assert!(
        p.exists("big.txt"),
        "content cannot be saved, so the file must stay"
    );
    assert_eq!(p.count(), 2, "a refused undo records nothing");
}

#[test]
fn init_rejects_bad_size_values() {
    let p = Proj::new("init-badsize");
    assert_eq!(p.run(&["init", "--max-file-size", "lots"]).code, 2);
    assert_eq!(p.run(&["init", "--max-file-size", "5XB"]).code, 2);
    assert_eq!(p.run(&["init", "--max-file-size"]).code, 2);
    assert_eq!(p.run(&["init", "--bogus"]).code, 2);
    assert!(!p.state.join("agent-undo").exists());
}

#[test]
fn commands_before_init_exit_6_with_not_initialized() {
    let p = Proj::new("noinit");
    p.write("a.txt", "x");
    let cases: &[&[&str]] = &[
        &["log"],
        &["status"],
        &["verify"],
        &["checkpoint"],
        &["diff", "1"],
        &["undo", "--last"],
        &["undo", "2", "--apply"],
        &["restore", "a.txt", "--from", "1"],
        &["gc", "--keep", "1"],
        &["watch", "--timeout", "1s"],
    ];
    for args in cases {
        let j = p.json_err(args, 6, "not_initialized");
        assert!(
            j.p("error.message").str().contains("agent-undo init"),
            "{args:?}"
        );
    }
    let o = p.run(&["status"]);
    assert_eq!(o.code, 6);
    assert!(o.stderr.contains("agent-undo: error:"), "{}", o.stderr);
    assert!(
        !p.state.join("agent-undo").exists(),
        "failed commands create nothing"
    );
}

#[test]
fn run_before_init_fails_with_125_and_does_not_run_the_command() {
    let p = Proj::new("run-noinit");
    let o = p.run(&["run", "--", "sh", "-c", "echo ran > ran.txt"]);
    assert_eq!(o.code, 125, "{}", o.all());
    assert!(!p.exists("ran.txt"));
    let o = p.run(&["--json", "run", "--", "true"]);
    assert_eq!(o.code, 125);
    assert_eq!(
        o.stderr_last_json().p("error.code").str(),
        "not_initialized"
    );
}

#[test]
fn commands_find_the_project_from_a_subdirectory_and_with_dash_c() {
    let p = Proj::inited("subdir");
    fs::create_dir_all(p.path("a/b")).unwrap();
    let o = p.run_in(&p.path("a/b"), &["--json", "status"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.json().p("project").str(), p.root.to_str().unwrap());
    // -C before or after the command name, from an unrelated directory.
    let root = p.root.to_str().unwrap();
    let o = p.run_in(&p.home, &["-C", root, "--json", "status"]);
    assert_eq!(o.code, 0, "{}", o.all());
    let o = p.run_in(&p.home, &["status", "--project", root, "--json"]);
    assert_eq!(o.code, 0, "{}", o.all());
    let o = p.run_in(&p.home, &["--json", "status"]);
    assert_eq!(o.code, 6, "an unrelated directory has no store");
}

// ---------------------------------------------------------------------- run

#[test]
fn run_passes_through_exit_codes() {
    let p = Proj::inited("run-exit");
    for code in [0, 1, 3, 42] {
        let o = p.run(&["run", "--", "sh", "-c", &format!("exit {code}")]);
        assert_eq!(o.code, code, "{}", o.all());
        assert!(o.stderr.contains(&format!("exit {code}")), "{}", o.stderr);
    }
    // The exit status is recorded in the journal as well.
    let log = p.log();
    let exits: Vec<u64> = log
        .p("checkpoints")
        .arr()
        .iter()
        .filter(|c| c.p("kind").str() == "run")
        .map(|c| c.p("exit.code").u64())
        .collect();
    assert_eq!(exits, vec![0, 1, 3, 42]);
}

#[test]
fn run_reports_signal_deaths_as_128_plus_n() {
    let p = Proj::inited("run-signal");
    let o = p.run(&["--json", "run", "--", "sh", "-c", "kill -9 $$"]);
    assert_eq!(o.code, 137, "{}", o.all());
    let j = o.stderr_last_json();
    assert_eq!(j.p("exit_status").u64(), 137);
    let log = p.log();
    assert_eq!(log.p("checkpoints.1.exit.signal").u64(), 9);
    let human = p.run(&["log"]);
    assert!(human.stdout.contains("signal 9"), "{}", human.stdout);
}

#[test]
fn run_missing_command_exits_127() {
    let p = Proj::inited("run-127");
    let o = p.run(&["run", "--", "definitely-not-a-command-xyz"]);
    assert_eq!(o.code, 127, "{}", o.all());
    assert!(
        o.stderr
            .contains("command not found: definitely-not-a-command-xyz")
    );
    let o = p.run(&["--json", "run", "--", "definitely-not-a-command-xyz"]);
    assert_eq!(o.code, 127);
    let j = o.stderr_last_json();
    assert!(!j.p("ok").bool());
    assert_eq!(j.p("error.code").str(), "error");
}

#[test]
fn run_non_executable_file_exits_126() {
    let p = Proj::inited("run-126");
    p.write("script.sh", "#!/bin/sh\necho hi\n");
    p.chmod("script.sh", 0o644);
    let o = p.run(&["run", "--", "./script.sh"]);
    assert_eq!(o.code, 126, "{}", o.all());
    assert!(o.stderr.contains("cannot execute"), "{}", o.stderr);
    // A directory is not executable either.
    fs::create_dir_all(p.path("adir")).unwrap();
    assert_eq!(p.run(&["run", "--", "./adir"]).code, 126);
}

#[test]
fn run_with_a_corrupt_store_exits_125_while_other_commands_exit_1() {
    let p = Proj::inited("run-125-corrupt");
    fs::write(p.store().join("meta"), "garbage\n").unwrap();
    let o = p.run(&["--json", "run", "--", "sh", "-c", "echo ran > ran.txt"]);
    assert_eq!(o.code, 125, "{}", o.all());
    assert_eq!(o.stderr_last_json().p("error.code").str(), "format");
    assert!(
        !p.exists("ran.txt"),
        "the command must not run without a working store"
    );
    p.json_err(&["status"], 1, "format");
}

#[test]
fn run_with_an_unwritable_store_exits_125() {
    if is_root() {
        eprintln!("skipped: permission checks are bypassed for root");
        return;
    }
    let p = Proj::inited("run-125-perms");
    let store = p.store();
    let cps = store.join("checkpoints");
    fs::set_permissions(&cps, std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
    let o = p.run(&["run", "--", "sh", "-c", "echo x > f.txt"]);
    fs::set_permissions(&cps, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    assert_eq!(o.code, 125, "{}", o.all());
    assert!(o.stderr.contains("agent-undo: error:"), "{}", o.stderr);
}

#[test]
fn run_rejects_an_invalid_env_allow_name() {
    let p = Proj::inited("run-badenv");
    let o = p.run(&[
        "run",
        "--env-allow",
        "bad name",
        "--",
        "sh",
        "-c",
        "echo ran > ran.txt",
    ]);
    assert_eq!(o.code, 125, "{}", o.all());
    assert!(
        o.stderr.contains("invalid environment variable name"),
        "{}",
        o.stderr
    );
    assert!(!p.exists("ran.txt"));
}

#[test]
fn run_command_output_goes_to_stdout_and_the_report_to_stderr() {
    let p = Proj::inited("run-streams");
    let o = p.run(&[
        "run",
        "--",
        "sh",
        "-c",
        "echo to-out; echo to-err 1>&2; echo made > f.txt",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.stdout, "to-out\n");
    assert!(o.stderr.contains("to-err"));
    assert!(
        o.stderr.contains("agent-undo: checkpoint #2 (session"),
        "{}",
        o.stderr
    );
    assert!(o.stderr.contains("1 created"), "{}", o.stderr);
}

#[test]
fn run_json_report_is_the_last_stderr_line_and_stdout_stays_the_commands() {
    let p = Proj::inited("run-json");
    let o = p.run(&[
        "--json",
        "run",
        "--",
        "sh",
        "-c",
        "echo child-says-hi; echo made > f.txt",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.stdout, "child-says-hi\n");
    let j = o.stderr_last_json();
    assert_eq!(j.p("schema").u64(), 1);
    assert!(j.p("ok").bool());
    assert_eq!(j.p("command").str(), "run");
    assert_eq!(j.p("checkpoint.id").u64(), 2);
    assert_eq!(j.p("checkpoint.kind").str(), "run");
    assert_eq!(j.p("checkpoint.changes.created").u64(), 1);
    assert_eq!(j.p("exit_status").u64(), 0);
    assert!(j.p("external_checkpoint").is_null());
}

#[test]
fn run_records_label_command_and_exit_in_the_log() {
    let p = Proj::inited("run-label");
    p.agent_with(&["--label", "fix the bug"], "echo x > f.txt");
    let log = p.log();
    let c = log.p("checkpoints.1");
    assert_eq!(c.p("kind").str(), "run");
    assert_eq!(c.p("label").str(), "fix the bug");
    assert_eq!(c.p("command.0").str(), "sh");
    assert_eq!(c.p("command.1").str(), "-c");
    assert_eq!(c.p("command.2").str(), "echo x > f.txt");
    assert_eq!(c.p("exit.code").u64(), 0);
    assert_eq!(c.p("changes.created").u64(), 1);
    let human = p.run(&["log"]);
    assert!(
        human.stdout.contains("fix the bug: sh -c echo x > f.txt"),
        "{}",
        human.stdout
    );
}

#[test]
fn run_new_session_starts_a_new_session() {
    let p = Proj::inited("run-session");
    p.agent("echo 1 > a");
    p.agent("echo 2 > b");
    p.agent_with(&["--new-session"], "echo 3 > c");
    let log = p.log();
    let s: Vec<u64> = (1..=3)
        .map(|i| log.p(&format!("checkpoints.{i}.session")).u64())
        .collect();
    assert_eq!(s[0], s[1], "runs share a session by default");
    assert!(s[2] > s[1], "--new-session must start a new one: {s:?}");
    let only_new = p.json(&["log", "--session", &s[2].to_string()]);
    assert_eq!(only_new.p("checkpoints").arr().len(), 1);
}

#[test]
fn run_env_allow_hides_other_variables_but_keeps_agent_undo_ones() {
    let p = Proj::inited("run-envallow");
    let script = "echo \"FOO=$FOO BAR=$BAR BAZ=$BAZ HOME=${HOME-unset} ACTIVE=$AGENT_UNDO_ACTIVE SESSION=$AGENT_UNDO_SESSION CKPT=$AGENT_UNDO_CHECKPOINT\" > env.txt";
    let o = p.run_env(
        &[
            "--json",
            "run",
            "--env-allow",
            "FOO,BAR",
            "--",
            "sh",
            "-c",
            script,
        ],
        &[("FOO", "1"), ("BAR", "2"), ("BAZ", "3")],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let session = o.stderr_last_json().p("checkpoint.session").u64();
    let text = p.read("env.txt");
    assert_eq!(
        text.trim(),
        format!("FOO=1 BAR=2 BAZ= HOME=unset ACTIVE=1 SESSION={session} CKPT=2")
    );
}

#[test]
fn run_env_allow_can_be_repeated() {
    let p = Proj::inited("run-envallow2");
    let o = p.run_env(
        &[
            "run",
            "--env-allow",
            "FOO",
            "--env-allow",
            "BAR",
            "--",
            "sh",
            "-c",
            "echo \"$FOO-$BAR-${BAZ-none}\" > env.txt",
        ],
        &[("FOO", "a"), ("BAR", "b"), ("BAZ", "c")],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("env.txt"), "a-b-none\n");
}

#[test]
fn run_inherits_the_environment_by_default() {
    let p = Proj::inited("run-envinherit");
    let o = p.run_env(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "echo \"$FOO $HOME $AGENT_UNDO_ACTIVE $AGENT_UNDO_CHECKPOINT\" > env.txt",
        ],
        &[("FOO", "bar")],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("env.txt"), format!("bar {} 1 2\n", p.home.display()));
}

#[test]
fn run_executes_the_command_in_the_project_root_even_from_a_subdirectory() {
    let p = Proj::inited("run-cwd");
    fs::create_dir_all(p.path("deep/er")).unwrap();
    let o = p.run_in(
        &p.path("deep/er"),
        &["run", "--", "sh", "-c", "pwd -P > where.txt"],
    );
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("where.txt").trim(), p.root.to_str().unwrap());
    assert!(!p.exists("deep/er/where.txt"));
}

#[test]
fn run_needs_a_command() {
    let p = Proj::inited("run-nocmd");
    assert_eq!(p.run(&["run"]).code, 2);
    assert_eq!(p.run(&["run", "--"]).code, 2);
    assert_eq!(
        p.run(&["run", "echo", "hi"]).code,
        2,
        "the command must follow `--`"
    );
    assert_eq!(p.run(&["run", "--label"]).code, 2);
}

#[test]
fn run_records_earlier_hand_edits_as_an_external_checkpoint() {
    let p = Proj::inited("run-external");
    p.write("hand.txt", "typed by a human");
    let o = p.run(&["--json", "run", "--", "sh", "-c", "echo agent > agent.txt"]);
    assert_eq!(o.code, 0, "{}", o.all());
    let j = o.stderr_last_json();
    assert_eq!(j.p("external_checkpoint.kind").str(), "external");
    assert_eq!(j.p("external_checkpoint.changes.created").u64(), 1);
    assert_eq!(
        j.p("checkpoint.changes.created").u64(),
        1,
        "only the agent's file"
    );
    // The human's file is not part of the run's undo.
    assert_eq!(p.run(&["undo", "3", "--apply"]).code, 0);
    assert!(p.exists("hand.txt") && !p.exists("agent.txt"));
}

#[test]
fn run_failing_command_still_records_what_it_changed() {
    let p = Proj::inited("run-failing");
    let o = p.run(&["run", "--", "sh", "-c", "echo partial > half.txt; exit 3"]);
    assert_eq!(o.code, 3);
    let d = p.json(&["diff", "2"]);
    assert_eq!(d.p("changes.0.path").str(), "half.txt");
    assert_eq!(d.p("checkpoint.exit.code").u64(), 3);
}

// ------------------------------------------------------- checkpoint/log/diff

#[test]
fn checkpoint_records_manual_changes_with_a_label() {
    let p = Proj::inited("ckpt");
    p.write("a.txt", "one");
    p.write("b.txt", "two");
    let o = p.run(&["checkpoint", "--label", "my snapshot"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("checkpoint #2 recorded"), "{}", o.stdout);
    assert!(o.stdout.contains("2 created"), "{}", o.stdout);
    let j = p.json(&["checkpoint", "--label", "again"]);
    assert_eq!(j.p("command").str(), "checkpoint");
    assert_eq!(j.p("checkpoint.id").u64(), 3);
    assert_eq!(j.p("checkpoint.kind").str(), "manual");
    assert_eq!(j.p("checkpoint.label").str(), "again");
    assert_eq!(j.p("checkpoint.changes.total").u64(), 0);
    assert_eq!(p.log().p("checkpoints.1.label").str(), "my snapshot");
}

#[test]
fn checkpoint_new_session_changes_the_session() {
    let p = Proj::inited("ckpt-session");
    let a = p.json(&["checkpoint"]).p("checkpoint.session").u64();
    let b = p.json(&["checkpoint"]).p("checkpoint.session").u64();
    let c = p
        .json(&["checkpoint", "--new-session"])
        .p("checkpoint.session")
        .u64();
    assert_eq!(a, b);
    assert!(c > b);
}

#[test]
fn log_lists_every_checkpoint_in_human_form() {
    let p = Proj::inited("log-human");
    p.agent_with(&["--label", "first"], "echo 1 > a.txt");
    p.write("hand.txt", "x");
    p.run(&["checkpoint", "--label", "manual one"]);
    let o = p.run(&["log"]);
    assert_eq!(o.code, 0, "{}", o.all());
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert!(lines[0].starts_with("ID"), "{}", o.stdout);
    assert_eq!(lines.len(), 4, "{}", o.stdout);
    assert!(lines[1].contains("baseline"));
    assert!(lines[2].contains("run") && lines[2].contains("first: sh -c echo 1 > a.txt"));
    assert!(lines[2].contains("+1 ~0 -0 m0"));
    assert!(lines[3].contains("manual") && lines[3].contains("manual one"));
    assert!(!o.stdout.contains("(pruned)"));
}

#[test]
fn log_json_has_chain_fields() {
    let p = Proj::inited("log-json");
    p.agent("echo 1 > a.txt");
    let j = p.log();
    assert_eq!(j.p("command").str(), "log");
    let cps = j.p("checkpoints").arr();
    assert_eq!(cps.len(), 2);
    for c in cps {
        for k in ["hash", "prev", "manifest_sha256", "changes_sha256"] {
            assert_eq!(c.p(k).str().len(), 64, "{k}");
        }
        assert!(!c.p("pruned").bool());
        assert!(c.p("time").str().ends_with('Z'));
    }
    assert_eq!(cps[1].p("prev").str(), cps[0].p("hash").str(), "hash chain");
    assert_eq!(j.p("head_hash").str(), cps[1].p("hash").str());
}

#[test]
fn log_session_filter_limits_the_listing() {
    let p = Proj::inited("log-session");
    p.agent("echo 1 > a");
    p.agent_with(&["--new-session"], "echo 2 > b");
    let log = p.log();
    let s2 = log.p("checkpoints.2.session").u64();
    let j = p.json(&["log", "--session", &s2.to_string()]);
    let ids: Vec<u64> = j
        .p("checkpoints")
        .arr()
        .iter()
        .map(|c| c.p("id").u64())
        .collect();
    assert_eq!(ids, vec![3]);
    let human = p.run(&["log", "--session", &s2.to_string()]);
    assert_eq!(
        human.stdout.lines().count(),
        2,
        "header plus one row: {}",
        human.stdout
    );
    assert_eq!(p.run(&["log", "--session", "0"]).code, 2);
    assert_eq!(p.run(&["log", "--session", "x"]).code, 2);
    assert_eq!(p.run(&["log", "extra"]).code, 2);
}

#[test]
fn diff_shows_a_unified_text_diff_for_modified_files() {
    let p = Proj::new("diff-text");
    p.write("a.txt", "one\ntwo\nthree\n");
    p.run(&["init"]);
    p.agent("printf 'one\\nTWO\\nthree\\n' > a.txt");
    let o = p.run(&["diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("checkpoint #2 (run, session"),
        "{}",
        o.stdout
    );
    assert!(
        o.stdout
            .contains("changes: 0 created, 1 modified, 0 deleted, 0 mode-changed")
    );
    assert!(o.stdout.contains("M  a.txt"), "{}", o.stdout);
    assert!(
        o.stdout.contains("--- a/a.txt\n+++ b/a.txt\n"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.lines().any(|l| l == "-two"), "{}", o.stdout);
    assert!(o.stdout.lines().any(|l| l == "+TWO"), "{}", o.stdout);
    assert!(!o.stdout.lines().any(|l| l == "-one" || l == "+one"));
}

#[test]
fn diff_of_created_and_deleted_files_uses_dev_null() {
    let p = Proj::new("diff-created");
    p.write("old.txt", "bye\n");
    p.run(&["init"]);
    p.agent("echo hello > new.txt; rm old.txt");
    let o = p.run(&["diff", "2"]);
    assert!(o.stdout.contains("A  new.txt"), "{}", o.stdout);
    assert!(
        o.stdout.contains("--- /dev/null\n+++ b/new.txt\n"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.lines().any(|l| l == "+hello"));
    assert!(o.stdout.contains("D  old.txt"), "{}", o.stdout);
    assert!(
        o.stdout.contains("--- a/old.txt\n+++ /dev/null\n"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.lines().any(|l| l == "-bye"));
}

#[test]
fn diff_omits_binary_content() {
    let p = Proj::inited("diff-binary");
    p.agent("printf '\\000\\001\\002binary\\377' > bin.dat");
    let o = p.run(&["diff", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("A  bin.dat"), "{}", o.stdout);
    assert!(o.stdout.contains("(no text diff:"), "{}", o.stdout);
    assert!(!o.stdout.contains("binary\u{fffd}") && !o.stdout.contains("+\u{0}"));
    let j = p.json(&["diff", "2"]);
    assert!(j.p("changes.0.text_diff").is_null());
    assert!(!j.p("changes.0.diff_omitted").str().is_empty());
}

#[test]
fn diff_json_describes_each_change() {
    let p = Proj::new("diff-json");
    p.write("a.txt", "x\n");
    p.run(&["init"]);
    p.agent("echo y > a.txt; echo hello > b.txt");
    let j = p.json(&["diff", "2"]);
    assert_eq!(j.p("command").str(), "diff");
    assert_eq!(j.p("checkpoint.id").u64(), 2);
    assert!(!j.p("truncated").bool());
    let changes = j.p("changes").arr();
    assert_eq!(changes.len(), 2);
    let a = &changes[0];
    assert_eq!(a.p("path").str(), "a.txt");
    assert_eq!(a.p("change").str(), "modified");
    assert_eq!(a.p("before.kind").str(), "file");
    assert_eq!(a.p("after.kind").str(), "file");
    assert_eq!(a.p("after.sha256").str().len(), 64);
    assert_ne!(a.p("before.sha256").str(), a.p("after.sha256").str());
    assert!(a.p("text_diff").str().contains("+y"));
    let b = &changes[1];
    assert_eq!(b.p("change").str(), "created");
    assert!(b.p("before").is_null());
    assert_eq!(b.p("after.mode").str().len(), 4);
    assert_eq!(b.p("after.size").u64(), 6);
}

#[test]
fn diff_reports_renames() {
    let p = Proj::new("diff-rename");
    p.write("old.txt", "some content\n");
    p.run(&["init"]);
    p.agent("mv old.txt new.txt");
    let o = p.run(&["diff", "2"]);
    assert!(o.stdout.contains("R  old.txt -> new.txt"), "{}", o.stdout);
    let j = p.json(&["diff", "2"]);
    assert_eq!(j.p("renames.0.from").str(), "old.txt");
    assert_eq!(j.p("renames.0.to").str(), "new.txt");
}

#[test]
fn diff_rejects_bad_checkpoint_numbers() {
    let p = Proj::inited("diff-bad");
    assert_eq!(p.run(&["diff"]).code, 2);
    assert_eq!(p.run(&["diff", "0"]).code, 2);
    assert_eq!(p.run(&["diff", "abc"]).code, 2);
    assert_eq!(p.run(&["diff", "1", "2"]).code, 2);
    let (code, j) = p.json_code(&["diff", "99"]);
    assert_ne!(code, 0);
    assert!(!j.p("ok").bool());
    assert!(!j.p("error.message").str().is_empty());
}

#[test]
fn diff_accepts_the_hash_prefix_form() {
    let p = Proj::inited("diff-hash");
    p.agent("echo a > a.txt");
    assert_eq!(p.run(&["diff", "#2"]).code, 0);
}

// -------------------------------------------------------------------- undo

fn seed_three_files(name: &str) -> Proj {
    let p = Proj::new(name);
    p.write("a.txt", "orig-a\n");
    p.write("b.txt", "keep-b\n");
    assert_eq!(p.run(&["init"]).code, 0);
    p
}

#[test]
fn undo_dry_run_is_the_default_and_changes_nothing() {
    let p = seed_three_files("undo-dry");
    p.agent("echo new-a > a.txt; rm b.txt; echo c > c.txt");
    let before = p.count();
    let o = p.run(&["undo", "2"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("dry run - nothing was changed"),
        "{}",
        o.stdout
    );
    assert!(
        o.stdout.contains("summary: 3 ready, 0 conflicts"),
        "{}",
        o.stdout
    );
    assert_eq!(p.read("a.txt"), "new-a\n");
    assert!(!p.exists("b.txt"));
    assert!(p.exists("c.txt"));
    assert_eq!(p.count(), before, "a preview records nothing");
    // --dry-run spells the same thing.
    assert_eq!(p.run(&["undo", "2", "--dry-run"]).code, 0);
    assert_eq!(p.read("a.txt"), "new-a\n");
}

#[test]
fn undo_apply_restores_modified_deleted_and_created_paths() {
    let p = seed_three_files("undo-apply");
    p.agent("echo new-a > a.txt; rm b.txt; echo c > c.txt");
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("(applied)"), "{}", o.stdout);
    assert!(
        o.stdout.contains("Undo this with: agent-undo undo"),
        "{}",
        o.stdout
    );
    assert_eq!(p.read("a.txt"), "orig-a\n");
    assert_eq!(p.read("b.txt"), "keep-b\n");
    assert!(!p.exists("c.txt"));
    assert_eq!(p.run(&["verify"]).code, 0);
    // Nothing is pending after an undo: it recorded its own checkpoint.
    assert_eq!(p.json(&["status"]).p("pending.counts.total").u64(), 0);
}

#[test]
fn undo_json_reports_pre_undo_and_result_checkpoints() {
    let p = seed_three_files("undo-json");
    p.agent("echo new-a > a.txt");
    let j = p.json(&["undo", "2", "--apply"]);
    assert_eq!(j.p("command").str(), "undo");
    assert!(j.p("apply_requested").bool());
    assert!(j.p("applied").bool());
    assert!(j.p("refused").is_null());
    assert_eq!(j.p("applied_count").u64(), 1);
    assert_eq!(j.p("items.0.path").str(), "a.txt");
    assert_eq!(j.p("items.0.op").str(), "write");
    assert_eq!(j.p("items.0.outcome").str(), "applied");
    let pre = j.p("pre_undo_checkpoint").u64();
    let res = j.p("result_checkpoint").u64();
    assert_eq!((pre, res), (3, 4));
    let log = p.log();
    assert_eq!(log.p("checkpoints.2.kind").str(), "pre-undo");
    assert_eq!(log.p("checkpoints.2.reference").u64(), 2);
    assert_eq!(log.p("checkpoints.3.kind").str(), "undo");
    assert_eq!(log.p("checkpoints.3.changes.modified").u64(), 1);
}

#[test]
fn undo_dry_run_json_marks_it_as_not_applied() {
    let p = seed_three_files("undo-dry-json");
    p.agent("echo new-a > a.txt");
    let j = p.json(&["undo", "2"]);
    assert!(!j.p("apply_requested").bool());
    assert!(!j.p("applied").bool());
    assert_eq!(j.p("counts.ready").u64(), 1);
    assert_eq!(j.p("items.0.status").str(), "ready");
    assert!(j.try_p("items.0.outcome").is_none());
    assert!(j.try_p("pre_undo_checkpoint").is_none());
}

#[test]
fn undo_conflict_after_a_hand_edit_exits_3_and_changes_nothing() {
    let p = seed_three_files("undo-conflict");
    p.agent("echo agent > a.txt");
    p.write("a.txt", "hand edit after the agent\n");
    let before = p.count();

    let dry = p.run(&["undo", "2"]);
    assert_eq!(dry.code, 3, "{}", dry.all());
    assert!(dry.stdout.contains("conflict"), "{}", dry.stdout);
    assert!(dry.stdout.contains("conflicting paths need --force"));

    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 3, "{}", o.all());
    assert!(
        o.stdout.contains("refused: some paths were modified"),
        "{}",
        o.stdout
    );
    assert_eq!(p.read("a.txt"), "hand edit after the agent\n");
    assert_eq!(
        p.count(),
        before,
        "a refused undo records nothing, not even a pre-undo"
    );

    let (code, j) = p.json_code(&["undo", "2", "--apply"]);
    assert_eq!(code, 3);
    assert!(
        j.p("ok").bool(),
        "a refusal is a normal report, not an error"
    );
    assert!(!j.p("applied").bool());
    assert!(j.p("refused").str().contains("--force"));
    assert_eq!(j.p("counts.conflicts").u64(), 1);
    assert_eq!(j.p("items.0.status").str(), "conflict");
}

#[test]
fn undo_force_overrides_a_conflict_and_keeps_the_hand_edit_recoverable() {
    let p = seed_three_files("undo-force");
    p.agent("echo agent > a.txt");
    p.write("a.txt", "hand edit\n");
    let j = p.json(&["undo", "2", "--apply", "--force"]);
    assert!(j.p("applied").bool());
    assert_eq!(p.read("a.txt"), "orig-a\n");
    // The pre-undo checkpoint holds the hand edit, so the force is itself undoable.
    let pre = j.p("pre_undo_checkpoint").u64();
    let d = p.json(&["diff", &pre.to_string()]);
    assert_eq!(d.p("checkpoint.kind").str(), "pre-undo");
    assert_eq!(d.p("changes.0.path").str(), "a.txt");
    assert_eq!(
        p.run(&["restore", "a.txt", "--from", &pre.to_string(), "--apply"])
            .code,
        0
    );
    assert_eq!(p.read("a.txt"), "hand edit\n");
}

#[test]
fn undo_dry_run_with_force_does_not_fail_on_conflicts() {
    let p = seed_three_files("undo-dry-force");
    p.agent("echo agent > a.txt");
    p.write("a.txt", "hand\n");
    assert_eq!(p.run(&["undo", "2", "--force"]).code, 0);
    assert_eq!(p.read("a.txt"), "hand\n");
}

#[test]
fn undo_last_undoes_only_the_most_recent_change() {
    let p = seed_three_files("undo-last");
    p.agent("echo first > x.txt");
    p.agent("echo second > y.txt");
    let o = p.run(&["undo", "--last", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(p.exists("x.txt"));
    assert!(!p.exists("y.txt"));
}

#[test]
fn undo_session_undoes_every_checkpoint_of_the_session() {
    let p = seed_three_files("undo-session");
    p.agent("echo 1 > s1a.txt");
    p.agent("echo 2 > s1b.txt");
    p.agent_with(&["--new-session"], "echo 3 > s2.txt");
    let log = p.log();
    let s1 = log.p("checkpoints.1.session").u64();
    assert_eq!(log.p("checkpoints.2.session").u64(), s1);
    let dry = p.run(&["undo", "--session", &s1.to_string()]);
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert!(
        dry.stdout.contains("undo session (2 checkpoints: 2..3)"),
        "{}",
        dry.stdout
    );
    assert!(p.exists("s1a.txt"), "dry run");
    let o = p.run(&["undo", "--session", &s1.to_string(), "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(!p.exists("s1a.txt") && !p.exists("s1b.txt"));
    assert!(p.exists("s2.txt"), "the other session is untouched");
    // Bare `--session` means the current (newest) session.
    assert_eq!(p.run(&["undo", "--session", "--apply"]).code, 0);
    assert!(!p.exists("s2.txt"));
}

#[test]
fn undo_of_an_undo_restores_the_agents_work() {
    let p = seed_three_files("undo-undo");
    p.agent("echo agent-version > a.txt; echo new > n.txt");
    let res = p
        .json(&["undo", "2", "--apply"])
        .p("result_checkpoint")
        .u64();
    assert_eq!(p.read("a.txt"), "orig-a\n");
    assert!(!p.exists("n.txt"));
    let o = p.run(&["undo", &res.to_string(), "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("a.txt"), "agent-version\n");
    assert_eq!(p.read("n.txt"), "new\n");
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn undo_that_is_already_applied_does_nothing() {
    let p = seed_three_files("undo-twice");
    p.agent("echo agent > a.txt");
    assert_eq!(p.run(&["undo", "2", "--apply"]).code, 0);
    let before = p.count();
    let o = p.run(&["undo", "2", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("nothing to do"), "{}", o.stdout);
    assert!(o.stdout.contains("1 already done"), "{}", o.stdout);
    assert_eq!(p.count(), before);
}

#[test]
fn undo_rejects_the_baseline_and_unknown_checkpoints() {
    let p = seed_three_files("undo-bad-target");
    p.agent("echo agent > a.txt");
    let (code, j) = p.json_code(&["undo", "1", "--apply"]);
    assert_ne!(code, 0);
    assert!(!j.p("ok").bool());
    assert!(j.p("error.message").str().contains("baseline"), "{j:?}");
    let (code, j) = p.json_code(&["undo", "99", "--apply"]);
    assert_ne!(code, 0);
    assert!(!j.p("ok").bool());
    assert_eq!(p.read("a.txt"), "agent\n");
}

#[test]
fn undo_last_without_any_change_fails() {
    let p = seed_three_files("undo-last-none");
    let (code, j) = p.json_code(&["undo", "--last"]);
    assert_ne!(code, 0);
    assert!(
        j.p("error.message")
            .str()
            .contains("no checkpoint with recorded changes")
    );
}

// ----------------------------------------------------------------- restore

#[test]
fn restore_dry_run_then_apply_brings_a_path_back_from_a_checkpoint() {
    let p = seed_three_files("restore-basic");
    p.agent("echo changed > a.txt");
    p.agent("echo changed-more >> a.txt");
    let dry = p.run(&["restore", "a.txt", "--from", "1"]);
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert!(
        dry.stdout.contains("restore a.txt from checkpoint #1"),
        "{}",
        dry.stdout
    );
    assert!(dry.stdout.contains("dry run"), "{}", dry.stdout);
    assert_eq!(p.read("a.txt"), "changed\nchanged-more\n");
    let o = p.run(&["restore", "a.txt", "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("a.txt"), "orig-a\n");
    assert_eq!(p.read("b.txt"), "keep-b\n");
    let log = p.log();
    assert_eq!(log.p("checkpoints.4.kind").str(), "restore");
    assert_eq!(log.p("checkpoints.3.kind").str(), "pre-undo");
}

#[test]
fn restore_accepts_an_absolute_path_inside_the_project() {
    let p = seed_three_files("restore-abs");
    p.agent("echo changed > a.txt");
    let abs = p.path("a.txt");
    let o = p.run(&["restore", abs.to_str().unwrap(), "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("a.txt"), "orig-a\n");
}

#[test]
fn restore_of_a_directory_restores_everything_below_it() {
    let p = Proj::new("restore-dir");
    p.write("src/x.txt", "x1\n");
    p.write("src/deep/y.txt", "y1\n");
    p.write("other.txt", "o1\n");
    p.run(&["init"]);
    p.agent("echo x2 > src/x.txt; echo y2 > src/deep/y.txt; echo o2 > other.txt");
    let o = p.run(&["restore", "src", "--from", "1", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(p.read("src/x.txt"), "x1\n");
    assert_eq!(p.read("src/deep/y.txt"), "y1\n");
    assert_eq!(
        p.read("other.txt"),
        "o2\n",
        "paths outside the requested one are untouched"
    );
}

#[test]
fn restore_rejects_paths_outside_the_project() {
    let p = seed_three_files("restore-unsafe");
    p.agent("echo changed > a.txt");
    let outside = p.base.join("outside.txt");
    fs::write(&outside, "precious").unwrap();
    for bad in [
        "../outside.txt",
        "a/../../outside.txt",
        outside.to_str().unwrap(),
        "/etc/passwd",
    ] {
        p.json_err(
            &["restore", bad, "--from", "1", "--apply"],
            1,
            "unsafe_path",
        );
        p.json_err(&["restore", bad, "--from", "1"], 1, "unsafe_path");
    }
    assert_eq!(fs::read_to_string(&outside).unwrap(), "precious");
    assert_eq!(p.read("a.txt"), "changed\n");
    let o = p.run(&["restore", "../outside.txt", "--from", "1"]);
    assert_eq!(o.code, 1);
    assert!(
        o.stderr
            .contains("agent-undo: error: invalid project-relative path"),
        "{}",
        o.stderr
    );
    let o = p.run(&["restore", "/etc/passwd", "--from", "1"]);
    assert_eq!(o.code, 1);
    assert!(
        o.stderr.contains("outside the project root"),
        "{}",
        o.stderr
    );
}

#[test]
fn restore_usage_errors() {
    let p = seed_three_files("restore-usage");
    assert_eq!(p.run(&["restore", "a.txt"]).code, 2, "missing --from");
    assert_eq!(p.run(&["restore", "--from", "1"]).code, 2, "missing path");
    assert_eq!(p.run(&["restore", "a.txt", "b.txt", "--from", "1"]).code, 2);
    assert_eq!(p.run(&["restore", "a.txt", "--from", "0"]).code, 2);
    assert_eq!(
        p.run(&["restore", "a.txt", "--from", "1", "--apply", "--dry-run"])
            .code,
        2
    );
    assert_eq!(
        p.run(&["restore", "a.txt", "--from", "1", "--bogus"]).code,
        2
    );
    assert_eq!(p.run(&["restore", "a.txt", "--from"]).code, 2);
}

// ------------------------------------------------------------------ status

#[test]
fn status_counts_pending_changes() {
    let p = seed_three_files("status-pending");
    let clean = p.json(&["status"]);
    assert_eq!(clean.p("command").str(), "status");
    assert!(!clean.p("locked_by_other").bool());
    assert_eq!(clean.p("checkpoints").u64(), 1);
    assert_eq!(clean.p("pending.counts.total").u64(), 0);
    assert!(p.run(&["status"]).stdout.contains("pending changes: none"));

    p.write("a.txt", "edited\n");
    p.write("new1.txt", "n1");
    p.write("new2.txt", "n2");
    fs::remove_file(p.path("b.txt")).unwrap();
    let j = p.json(&["status"]);
    assert_eq!(j.p("pending.counts.created").u64(), 2);
    assert_eq!(j.p("pending.counts.modified").u64(), 1);
    assert_eq!(j.p("pending.counts.deleted").u64(), 1);
    assert_eq!(j.p("pending.counts.total").u64(), 4);
    assert_eq!(j.p("pending.sample").arr().len(), 4);
    assert_eq!(j.p("head.id").u64(), 1);
    assert_eq!(j.p("project").str(), p.root.to_str().unwrap());
    assert_eq!(j.p("store").str(), p.store().to_str().unwrap());
    let human = p.run(&["status"]);
    assert!(
        human.stdout.contains("pending changes: 2 created, 1 modified, 1 deleted, 0 mode-changed (not yet checkpointed)"),
        "{}",
        human.stdout
    );
    assert!(human.stdout.contains("checkpoints: 1"), "{}", human.stdout);
    // Status is read-only.
    assert_eq!(p.count(), 1);
    p.run(&["checkpoint"]);
    assert_eq!(p.json(&["status"]).p("pending.counts.total").u64(), 0);
}

#[test]
fn status_rejects_extra_arguments() {
    let p = Proj::inited("status-extra");
    assert_eq!(p.run(&["status", "now"]).code, 2);
    assert_eq!(p.run(&["verify", "now"]).code, 2);
    assert_eq!(p.run(&["doctor", "now"]).code, 2);
}

// ------------------------------------------------------------------ verify

fn store_with_content(name: &str) -> Proj {
    let p = Proj::new(name);
    p.write("a.txt", "content of a\n");
    p.run(&["init"]);
    p.agent("echo content of b > b.txt; echo changed a > a.txt");
    p
}

fn first_blob(p: &Proj) -> std::path::PathBuf {
    files_below(&p.store().join("blobs"))
        .into_iter()
        .next()
        .expect("a blob")
}

#[test]
fn verify_passes_on_a_healthy_store() {
    let p = store_with_content("verify-ok");
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout
            .contains("verify: ok - 2 checkpoints checked (0 pruned)"),
        "{}",
        o.stdout
    );
    let j = p.json(&["verify"]);
    assert!(j.p("verified").bool());
    assert_eq!(j.p("checkpoints_checked").u64(), 2);
    assert!(j.p("blobs_checked").u64() >= 3);
    assert!(j.p("problems").arr().is_empty());
}

#[test]
fn verify_detects_a_corrupted_blob() {
    let p = store_with_content("verify-blob");
    let blob = first_blob(&p);
    fs::set_permissions(&blob, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&blob, b"tampered bytes").unwrap();
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("PROBLEM: blob "), "{}", o.stdout);
    assert!(o.stdout.contains("corrupt"), "{}", o.stdout);
    assert!(o.stdout.contains("verify: FAILED"), "{}", o.stdout);
    let (code, j) = p.json_code(&["verify"]);
    assert_eq!(code, 5);
    assert!(!j.p("verified").bool());
    assert!(!j.p("problems").arr().is_empty());
}

#[test]
fn verify_detects_a_missing_blob() {
    let p = store_with_content("verify-missing-blob");
    fs::remove_file(first_blob(&p)).unwrap();
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("referenced but missing"), "{}", o.stdout);
}

#[test]
fn verify_detects_a_tampered_log_line() {
    let p = store_with_content("verify-log");
    let log = p.store().join("log");
    let text = fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut fields: Vec<String> = lines[0].split('\t').map(str::to_string).collect();
    fields[3].push('0'); // the timestamp no longer matches the record hash
    lines[0] = fields.join("\t");
    fs::write(&log, lines.join("\n") + "\n").unwrap();
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("PROBLEM: journal:"), "{}", o.stdout);
    // Other commands refuse to trust the journal as well.
    p.json_err(&["log"], 5, "integrity");
}

#[test]
fn verify_detects_a_deleted_manifest() {
    let p = store_with_content("verify-manifest");
    fs::remove_file(p.store().join("checkpoints/00000002.manifest")).unwrap();
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("PROBLEM: checkpoint #2"), "{}", o.stdout);
}

#[test]
fn verify_detects_a_modified_manifest() {
    let p = store_with_content("verify-manifest-mod");
    let m = p.store().join("checkpoints/00000002.manifest");
    let mut data = fs::read(&m).unwrap();
    data.extend_from_slice(b"extra\n");
    fs::set_permissions(&m, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&m, data).unwrap();
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("PROBLEM:"), "{}", o.stdout);
}

#[test]
fn undo_refuses_to_run_from_a_corrupted_checkpoint() {
    let p = store_with_content("undo-corrupt");
    let m = p.store().join("checkpoints/00000002.changes");
    fs::set_permissions(&m, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&m, b"garbage\n").unwrap();
    let before = p.read("a.txt");
    let (code, j) = p.json_code(&["undo", "2", "--apply"]);
    assert_ne!(code, 0);
    assert!(!j.p("ok").bool());
    assert_eq!(p.read("a.txt"), before);
}

// ---------------------------------------------------------------------- gc

fn project_with_history(name: &str) -> Proj {
    let p = Proj::new(name);
    p.write("a.txt", "v0\n");
    p.run(&["init"]);
    for v in 1..=4 {
        p.agent(&format!("echo v{v} > a.txt; echo file{v} > f{v}.txt"));
    }
    p
}

#[test]
fn gc_needs_exactly_one_policy() {
    let p = project_with_history("gc-usage");
    assert_eq!(p.run(&["gc"]).code, 2);
    assert_eq!(p.run(&["gc", "--keep", "0"]).code, 2);
    assert_eq!(p.run(&["gc", "--keep", "x"]).code, 2);
    assert_eq!(p.run(&["gc", "--keep", "1", "--older-than", "1d"]).code, 2);
    assert_eq!(p.run(&["gc", "--older-than", "5parsecs"]).code, 2);
    assert_eq!(
        p.run(&["gc", "--keep", "1", "--apply", "--dry-run"]).code,
        2
    );
    assert_eq!(p.count(), 5);
}

#[test]
fn gc_dry_run_is_the_default_and_changes_nothing() {
    let p = project_with_history("gc-dry");
    let store = p.store();
    let files_before = files_below(&store);
    let o = p.run(&["gc", "--keep", "1"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("gc dry run:"), "{}", o.stdout);
    assert!(o.stdout.contains("would be pruned"), "{}", o.stdout);
    assert!(o.stdout.contains("--apply"), "{}", o.stdout);
    let j = p.json(&["gc", "--keep", "1"]);
    assert!(!j.p("applied").bool());
    assert!(!j.p("checkpoints").arr().is_empty());
    assert_eq!(
        files_below(&store),
        files_before,
        "no file may be removed or added"
    );
    assert!(
        p.log()
            .p("checkpoints")
            .arr()
            .iter()
            .all(|c| !c.p("pruned").bool())
    );
}

#[test]
fn gc_apply_prunes_old_checkpoints_and_unused_blobs_and_verify_stays_ok() {
    let p = project_with_history("gc-apply");
    let blobs_before = files_below(&p.store().join("blobs")).len();
    let j = p.json(&["gc", "--keep", "2", "--apply"]);
    assert!(j.p("applied").bool());
    let pruned: Vec<u64> = j.p("checkpoints").arr().iter().map(J::u64).collect();
    assert!(!pruned.is_empty());
    assert!(
        !pruned.contains(&5),
        "the newest checkpoint is kept: {pruned:?}"
    );
    assert!(j.p("blobs").u64() > 0);
    assert_eq!(j.p("retained").u64() as usize, 5 - pruned.len());
    let log = p.log();
    for c in log.p("checkpoints").arr() {
        assert_eq!(c.p("pruned").bool(), pruned.contains(&c.p("id").u64()));
    }
    assert!(files_below(&p.store().join("blobs")).len() < blobs_before);
    for id in &pruned {
        assert!(
            !p.store()
                .join(format!("checkpoints/{id:08}.manifest"))
                .exists()
        );
    }
    let v = p.run(&["verify"]);
    assert_eq!(v.code, 0, "{}", v.all());
    assert!(v.stdout.contains("pruned)"), "{}", v.stdout);
    let human = p.run(&["log"]);
    assert!(human.stdout.contains("(pruned)"), "{}", human.stdout);
    // The kept history still works.
    assert_eq!(p.run(&["undo", "5", "--apply"]).code, 0);
    assert!(!p.exists("f4.txt"));
}

#[test]
fn undo_and_diff_of_a_pruned_checkpoint_are_refused() {
    let p = project_with_history("gc-pruned-undo");
    p.run(&["gc", "--keep", "1", "--apply"]);
    let before = p.count();
    let content = p.read("a.txt");
    let j = p.json_err(&["undo", "2", "--apply"], 3, "refused");
    assert!(j.p("error.message").str().contains("removed by gc"));
    p.json_err(&["undo", "2"], 3, "refused");
    p.json_err(&["diff", "2"], 3, "refused");
    p.json_err(&["restore", "a.txt", "--from", "2"], 3, "refused");
    assert_eq!(p.read("a.txt"), content);
    assert_eq!(p.count(), before);
}

#[test]
fn gc_older_than_keeps_recent_checkpoints() {
    let p = project_with_history("gc-older");
    let j = p.json(&["gc", "--older-than", "1d", "--apply"]);
    assert!(j.p("checkpoints").arr().is_empty());
    assert_eq!(j.p("retained").u64(), 5);
    assert_eq!(p.run(&["verify"]).code, 0);
    // Everything is older than 0 seconds... but the newest checkpoint must survive.
    std::thread::sleep(Duration::from_millis(30));
    let j = p.json(&["gc", "--older-than", "0s"]);
    assert!(
        !j.p("checkpoints").arr().iter().any(|c| c.u64() == 5),
        "{j:?}"
    );
}

// ------------------------------------------------------------------- watch

#[test]
fn watch_records_one_checkpoint_after_a_quiet_period() {
    let p = Proj::inited("watch-edit");
    let target = p.path("edited.txt");
    let editor = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        fs::write(target, "written while watching\n").unwrap();
    });
    let o = p.run(&[
        "watch",
        "--interval",
        "100ms",
        "--quiet",
        "300ms",
        "--exit-after",
        "1",
        "--timeout",
        "20s",
        "--label",
        "auto",
    ]);
    editor.join().unwrap();
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.starts_with("checkpoint #2: 1 created"),
        "{}",
        o.stdout
    );
    assert!(o.stderr.contains("agent-undo: watching"), "{}", o.stderr);
    let log = p.log();
    assert_eq!(log.p("checkpoints").arr().len(), 2);
    assert_eq!(log.p("checkpoints.1.kind").str(), "watch");
    assert_eq!(log.p("checkpoints.1.label").str(), "auto");
    assert_eq!(log.p("checkpoints.1.changes.created").u64(), 1);
    assert_eq!(p.json(&["status"]).p("pending.counts.total").u64(), 0);
}

#[test]
fn watch_json_prints_one_line_per_checkpoint() {
    let p = Proj::inited("watch-json");
    let target = p.path("edited.txt");
    let editor = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        fs::write(target, "x").unwrap();
    });
    let o = p.run(&[
        "--json",
        "watch",
        "--interval",
        "100ms",
        "--quiet",
        "300ms",
        "--exit-after",
        "1",
        "--timeout",
        "20s",
    ]);
    editor.join().unwrap();
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.stdout.lines().count(), 1, "{}", o.stdout);
    let j = o.json();
    assert_eq!(j.p("command").str(), "watch");
    assert_eq!(j.p("checkpoint.kind").str(), "watch");
}

#[test]
fn watch_timeout_without_changes_exits_0_and_records_nothing() {
    let p = Proj::inited("watch-idle");
    let o = p.run_limited(
        &[
            "watch",
            "--interval",
            "100ms",
            "--quiet",
            "300ms",
            "--timeout",
            "1s",
        ],
        Duration::from_secs(20),
    );
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(o.stdout, "");
    assert_eq!(p.count(), 1);
}

#[test]
fn watch_usage_errors() {
    let p = Proj::inited("watch-usage");
    assert_eq!(p.run(&["watch", "--interval", "0ms"]).code, 2);
    assert_eq!(p.run(&["watch", "--interval", "soon"]).code, 2);
    assert_eq!(p.run(&["watch", "--exit-after", "many"]).code, 2);
    assert_eq!(p.run(&["watch", "--bogus"]).code, 2);
    assert_eq!(p.run(&["watch", "--timeout"]).code, 2);
}

// ------------------------------------------------------------------ doctor

#[test]
fn doctor_is_healthy_on_a_fresh_store() {
    let p = Proj::inited("doctor-ok");
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("[ ok ] sha-256 self-test"),
        "{}",
        o.stdout
    );
    assert!(
        o.stdout
            .contains("[ ok ] store permissions: directories 0700, files 0600"),
        "{}",
        o.stdout
    );
    assert!(
        o.stdout
            .contains("[ ok ] journal: 1 checkpoints, hash chain intact"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("doctor: 0 failed"), "{}", o.stdout);
    let j = p.json(&["doctor"]);
    assert!(j.p("healthy").bool());
    assert!(
        j.p("checks")
            .arr()
            .iter()
            .all(|c| c.p("status").str() != "fail")
    );
}

#[test]
fn doctor_fails_when_the_key_file_is_group_readable() {
    let p = Proj::inited("doctor-key");
    fs::set_permissions(
        p.store().join("key"),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(
        o.stdout.contains("[FAIL] store permissions"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("key is 0644"), "{}", o.stdout);
    let (code, j) = p.json_code(&["doctor"]);
    assert_eq!(code, 5);
    assert!(
        j.p("ok").bool(),
        "the command ran; the health verdict is `healthy`"
    );
    assert!(!j.p("healthy").bool());
}

#[test]
fn doctor_fails_when_the_store_directory_is_world_accessible() {
    let p = Proj::inited("doctor-dir");
    fs::set_permissions(
        p.store(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 5, "{}", o.all());
    assert!(o.stdout.contains("(want 0700 or stricter)"), "{}", o.stdout);
}

#[test]
fn doctor_works_without_init_and_only_warns() {
    let p = Proj::new("doctor-noinit");
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("[warn] store: not initialized"),
        "{}",
        o.stdout
    );
    let j = p.json(&["doctor"]);
    assert!(j.p("healthy").bool());
    let store = j
        .p("checks")
        .arr()
        .iter()
        .find(|c| c.p("name").str() == "store")
        .unwrap();
    assert_eq!(store.p("status").str(), "warn");
    assert!(!p.state.join("agent-undo").exists());
}

#[test]
fn doctor_flags_a_missing_git_exclude_for_in_project_stores() {
    let p = Proj::new("doctor-exclude");
    fs::create_dir_all(p.path(".git")).unwrap();
    p.run(&["init", "--in-project"]);
    fs::write(p.path(".git/info/exclude"), "").unwrap();
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "a warning is not a failure: {}", o.all());
    assert!(o.stdout.contains("[warn] git exclude"), "{}", o.stdout);
}

#[test]
fn doctor_reports_a_broken_agent_undoignore() {
    let p = Proj::inited("doctor-ignore");
    p.write(".agent-undoignore", "# fine\n*.log\n");
    assert!(
        p.run(&["doctor"])
            .stdout
            .contains("[ ok ] .agent-undoignore")
    );
}

// ------------------------------------------------------------ usage errors

#[test]
fn unknown_command_and_options_exit_2() {
    let p = Proj::inited("usage-unknown");
    let o = p.run(&["frobnicate"]);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("unknown command"), "{}", o.stderr);
    assert_eq!(o.stdout, "");
    assert_eq!(p.run(&["--frobnicate"]).code, 2);
    assert_eq!(p.run(&["-C"]).code, 2);
    assert_eq!(p.run(&["init", "extra"]).code, 2);
    assert_eq!(p.run(&["checkpoint", "extra"]).code, 2);
    assert_eq!(p.run(&["checkpoint", "--label"]).code, 2);
}

#[test]
fn undo_usage_errors() {
    let p = seed_three_files("usage-undo");
    p.agent("echo x > x.txt");
    assert_eq!(p.run(&["undo"]).code, 2, "needs a target");
    assert_eq!(p.run(&["undo", "2", "--last"]).code, 2, "two targets");
    assert_eq!(p.run(&["undo", "2", "3"]).code, 2, "two targets");
    assert_eq!(
        p.run(&["undo", "--last", "--session"]).code,
        2,
        "two targets"
    );
    assert_eq!(p.run(&["undo", "2", "--apply", "--dry-run"]).code, 2);
    assert_eq!(p.run(&["undo", "--apply", "--dry-run", "--last"]).code, 2);
    assert_eq!(p.run(&["undo", "zero"]).code, 2);
    assert_eq!(p.run(&["undo", "0"]).code, 2);
    assert_eq!(p.run(&["undo", "2", "--frobnicate"]).code, 2);
    assert!(p.exists("x.txt"), "usage errors must not touch anything");
    assert_eq!(p.count(), 2);
}

#[test]
fn usage_errors_are_plain_text_on_stderr() {
    let p = Proj::inited("usage-text");
    let o = p.run(&["undo", "2", "--apply", "--dry-run"]);
    assert_eq!(o.code, 2);
    assert_eq!(o.stdout, "");
    assert!(
        o.stderr
            .contains("agent-undo: --apply and --dry-run cannot be combined"),
        "{}",
        o.stderr
    );
}

#[test]
fn help_and_version() {
    let p = Proj::new("help");
    for args in [
        &["--help"][..],
        &["-h"],
        &["help"],
        &[],
        &["undo", "--help"],
    ] {
        let o = p.run(args);
        assert_eq!(o.code, 0, "{args:?}: {}", o.all());
        assert!(o.stdout.contains("USAGE:"), "{args:?}");
        assert!(o.stdout.contains("EXIT CODES:"), "{args:?}");
        assert!(o.stdout.contains("4 store locked"), "{args:?}");
        assert!(o.stderr.is_empty(), "{args:?}: {}", o.stderr);
    }
    for args in [&["--version"][..], &["-V"]] {
        let o = p.run(args);
        assert_eq!(o.code, 0);
        assert_eq!(
            o.stdout,
            format!("agent-undo {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
    // Help needs no store and creates none.
    assert!(!p.state.join("agent-undo").exists());
}

#[test]
fn help_lists_every_command() {
    let p = Proj::new("help-cmds");
    let o = p.run(&["--help"]);
    for c in [
        "init",
        "run",
        "checkpoint",
        "log",
        "diff",
        "undo",
        "restore",
        "status",
        "verify",
        "gc",
        "watch",
        "doctor",
    ] {
        assert!(o.stdout.contains(&format!("\n  {c} ")), "help lacks `{c}`");
    }
}

// -------------------------------------------------------- lock contention

/// Starts `run -- sh -c 'touch marker; sleep 2'` and waits until the command is running,
/// i.e. until the run holds the exclusive store lock.
fn hold_the_lock(p: &Proj) -> std::process::Child {
    let marker = p.state.join("lock-marker");
    let child = p.spawn(
        &["run", "--", "sh", "-c", "touch \"$MARKER\"; sleep 2"],
        &[("MARKER", marker.to_str().unwrap())],
    );
    assert!(
        wait_for(&marker, Duration::from_secs(20)),
        "the background run never started"
    );
    child
}

#[test]
fn a_running_command_locks_the_store_for_checkpoint() {
    let p = Proj::inited("lock-ckpt");
    let child = hold_the_lock(&p);
    let (code, j) = p.json_code(&["checkpoint"]);
    assert_eq!(code, 4, "{j:?}");
    assert!(!j.p("ok").bool());
    assert_eq!(j.p("error.code").str(), "locked");
    let o = p.run(&["undo", "--last", "--apply"]);
    assert_eq!(o.code, 4, "{}", o.all());
    let o = p.run(&["gc", "--keep", "1", "--apply"]);
    assert_eq!(o.code, 4, "{}", o.all());
    let o = p.run(&["verify"]);
    assert_eq!(o.code, 4, "{}", o.all());
    let o = p.run(&["run", "--", "true"]);
    assert_eq!(
        o.code,
        125,
        "run reports internal failures as 125: {}",
        o.all()
    );
    assert!(o.stderr.contains("lock"), "{}", o.stderr);
    let done = child.wait_with_output().unwrap();
    assert_eq!(done.status.code(), Some(0));
    // Once the holder is gone everything works again.
    assert_eq!(p.run(&["checkpoint"]).code, 0);
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn status_reports_locked_by_other_instead_of_failing() {
    let p = Proj::inited("lock-status");
    let child = hold_the_lock(&p);
    let j = p.json(&["status"]);
    assert!(j.p("locked_by_other").bool());
    assert!(j.p("pending").is_null());
    let o = p.run(&["status"]);
    assert_eq!(o.code, 0);
    assert!(
        o.stdout
            .contains("lock: held by another agent-undo operation"),
        "{}",
        o.stdout
    );
    let _ = child.wait_with_output().unwrap();
    assert!(!p.json(&["status"]).p("locked_by_other").bool());
}

#[test]
fn doctor_survives_a_held_lock_with_a_warning() {
    let p = Proj::inited("lock-doctor");
    let child = hold_the_lock(&p);
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("[warn] lock: held by another operation"),
        "{}",
        o.stdout
    );
    let _ = child.wait_with_output().unwrap();
}

#[test]
fn watch_skips_ticks_while_the_store_is_busy_and_still_works_afterwards() {
    let p = Proj::inited("lock-watch");
    let child = hold_the_lock(&p);
    let o = p.run_limited(
        &[
            "watch",
            "--interval",
            "100ms",
            "--quiet",
            "200ms",
            "--timeout",
            "500ms",
        ],
        Duration::from_secs(20),
    );
    assert_eq!(o.code, 0, "{}", o.all());
    let _ = child.wait_with_output().unwrap();
}

// ------------------------------------------------------------ JSON contract

#[test]
fn every_command_emits_one_json_line_with_schema_ok_and_command() {
    let p = Proj::new("json-contract");
    p.write("a.txt", "one\n");
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("init", vec!["init"]),
        ("checkpoint", vec!["checkpoint", "--label", "m"]),
        ("log", vec!["log"]),
        ("status", vec!["status"]),
        ("verify", vec!["verify"]),
        ("doctor", vec!["doctor"]),
    ];
    for (name, args) in cases {
        let mut a = vec!["--json"];
        a.extend(args);
        let o = p.run(&a);
        assert_eq!(o.code, 0, "{name}: {}", o.all());
        check_envelope(&o.stdout, name);
    }
    let id = p.agent("echo two > a.txt; echo three > b.txt");
    let id = id.to_string();
    let more: Vec<(&str, Vec<&str>, i32)> = vec![
        ("diff", vec!["diff", &id], 0),
        ("undo", vec!["undo", &id], 0),
        ("undo", vec!["undo", &id, "--apply"], 0),
        ("restore", vec!["restore", "a.txt", "--from", "1"], 0),
        (
            "restore",
            vec!["restore", "a.txt", "--from", "1", "--apply"],
            0,
        ),
        ("gc", vec!["gc", "--keep", "3"], 0),
        ("gc", vec!["gc", "--keep", "3", "--apply"], 0),
    ];
    for (name, args, code) in more {
        let mut a = vec!["--json"];
        a.extend(args.iter().copied());
        let o = p.run(&a);
        assert_eq!(o.code, code, "{name} {args:?}: {}", o.all());
        check_envelope(&o.stdout, name);
    }
}

fn check_envelope(stdout: &str, name: &str) {
    assert!(stdout.ends_with('\n'), "{name}: no trailing newline");
    assert_eq!(
        stdout.lines().count(),
        1,
        "{name}: must be a single line: {stdout:?}"
    );
    let prefix = format!("{{\"schema\":1,\"ok\":true,\"command\":\"{name}\"");
    assert!(stdout.starts_with(&prefix), "{name}: {stdout}");
    let j = parse_json(stdout.trim_end()).unwrap();
    assert_eq!(j.p("schema").u64(), 1);
    assert!(j.p("ok").bool());
    assert_eq!(j.p("command").str(), name);
}

#[test]
fn json_errors_have_ok_false_and_a_stable_error_code() {
    let p = Proj::inited("json-errors");
    p.write("a.txt", "x");
    let cases: Vec<(Vec<&str>, i32, &str)> = vec![
        (vec!["init"], 1, "already_initialized"),
        (vec!["restore", "../x", "--from", "1"], 1, "unsafe_path"),
        (vec!["undo", "--last"], 2, "usage"),
        (vec!["diff", "42"], 2, "usage"),
    ];
    for (args, code, err) in cases {
        let mut a = vec!["--json"];
        a.extend(args.iter().copied());
        let o = p.run(&a);
        assert_eq!(o.stdout.lines().count(), 1, "{args:?}: {}", o.stdout);
        let j = o.json();
        assert_eq!(j.p("schema").u64(), 1);
        assert!(!j.p("ok").bool(), "{args:?}");
        assert!(
            j.try_p("command").is_none(),
            "errors carry no command: {args:?}"
        );
        assert!(!j.p("error.message").str().is_empty());
        assert_eq!(j.p("error.code").str(), err, "{args:?}: {}", o.stdout);
        assert_eq!(o.code, code, "{args:?}: {}", o.stdout);
        assert_eq!(o.stderr, "", "JSON errors go to stdout only: {args:?}");
    }
}

#[test]
fn json_mode_still_prints_nothing_but_json_on_stdout_for_dry_runs() {
    let p = Proj::inited("json-dry");
    p.agent("echo x > x.txt");
    let o = p.run(&["--json", "undo", "2"]);
    assert_eq!(o.code, 0);
    assert_eq!(o.stderr, "");
    assert!(
        !o.stdout.contains("dry run - nothing"),
        "human text must not leak into JSON"
    );
    assert!(o.json().p("ok").bool());
}
