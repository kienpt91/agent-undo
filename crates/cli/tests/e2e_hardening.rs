//! End-to-end tests for the findings of the security review (SU-001 .. SU-011),
//! exercised through the real binary.

mod common;

use common::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

const PLAIN_SECRET: &str = "hunter2\n";

// ------------------------------------------------------------------- SU-001

#[test]
fn a_copy_of_a_secret_file_is_never_stored_or_shown() {
    let p = Proj::new("su001-copy");
    p.write(".env", PLAIN_SECRET);
    assert_eq!(p.run(&["init"]).code, 0);
    let id = p.agent(
        "cp .env settings.txt; mkdir -p cfg; cp .env cfg/app.conf; echo ordinary > notes.txt",
    );
    assert!(
        !any_file_contains(&p.store(), b"hunter2"),
        "a copy of a secret file reached the store"
    );
    let d = p.run(&["diff", &id.to_string()]);
    assert_eq!(d.code, 0, "{}", d.all());
    assert!(
        !d.stdout.contains("hunter2"),
        "diff printed a secret: {}",
        d.stdout
    );
    assert!(
        d.stdout
            .contains("sensitive file: content is never stored or shown")
    );
    let j = p.json(&["diff", &id.to_string()]);
    let withheld = j
        .p("changes")
        .arr()
        .iter()
        .filter(|c| {
            c.try_p("withheld")
                .is_some_and(|w| w.str().contains("sensitive"))
        })
        .count();
    assert_eq!(withheld, 2, "settings.txt and cfg/app.conf");
    // the ordinary file is stored and diffed normally
    assert!(d.stdout.contains("+ordinary"));
}

#[test]
fn undo_leaves_copies_of_secrets_alone() {
    let p = Proj::new("su001-undo");
    p.write(".env", PLAIN_SECRET);
    assert_eq!(p.run(&["init"]).code, 0);
    p.agent("cp .env copy.txt");
    let o = p.run(&["undo", "--last", "--apply"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stdout.contains("not restorable by design"),
        "{}",
        o.stdout
    );
    assert!(
        p.exists("copy.txt"),
        "undo must not delete a file holding a secret"
    );
    assert_eq!(p.read("copy.txt"), PLAIN_SECRET);
    assert_eq!(p.run(&["verify"]).code, 0);
}

#[test]
fn a_renamed_secret_file_stays_sensitive_across_runs() {
    let p = Proj::new("su001-rename");
    p.write(".env", PLAIN_SECRET);
    assert_eq!(p.run(&["init"]).code, 0);
    p.agent("mv .env backup.txt");
    p.agent("cp backup.txt again.txt");
    assert!(!any_file_contains(&p.store(), b"hunter2"));
    let ids = p.store().join("sensitive-ids");
    assert_eq!(mode_of(&ids), 0o600);
    assert_eq!(fs::read_to_string(&ids).unwrap().lines().count(), 1);
}

#[test]
fn dotenv_style_secrets_under_innocent_names_are_detected_by_content() {
    let p = Proj::new("su001-content");
    assert_eq!(p.run(&["init"]).code, 0);
    p.agent("printf 'DB_PASSWORD=hunter2\\nPORT=5432\\n' > settings.txt; printf 'PORT=5432\\n' > ports.cfg");
    assert!(!any_file_contains(&p.store(), b"hunter2"));
    assert!(
        any_file_contains(&p.store(), b"PORT=5432"),
        "ordinary config is stored"
    );
}

// ------------------------------------------------------------------- SU-002

#[test]
fn a_hostile_ignore_file_cannot_stop_recording() {
    let p = Proj::inited("su002-ignore");
    let o = p.run(&[
        "run",
        "--",
        "sh",
        "-c",
        "head -c 6000 /dev/zero | tr '\\0' x > .agent-undoignore; echo hi > a.txt; exit 7",
    ]);
    assert_eq!(
        o.code,
        7,
        "the command's own status is preserved: {}",
        o.all()
    );
    assert!(o.stderr.contains("checkpoint #"), "{}", o.stderr);
    assert!(
        o.stderr.contains("warning") && o.stderr.contains(".agent-undoignore"),
        "{}",
        o.stderr
    );
    // later runs and checkpoints keep working
    let c = p.run(&["checkpoint"]);
    assert_eq!(c.code, 0, "{}", c.all());
    assert_eq!(p.run(&["status"]).code, 0);
}

#[test]
fn a_directory_tree_nested_beyond_the_depth_cap_does_not_fail_the_run() {
    let p = Proj::inited("su002-depth");
    let script = "d=n; i=0; while [ $i -lt 300 ]; do mkdir $d && cd $d || exit 9; i=$((i+1)); done; echo deep > f.txt";
    let o = p.run(&["--json", "run", "--", "sh", "-c", script]);
    assert_eq!(o.code, 0, "{}", o.all());
    let j = o.stderr_last_json();
    assert!(j.p("warnings.total").u64() >= 1, "{j:?}");
    assert!(j.p("checkpoint.changes.created").u64() >= 200);
    assert_eq!(p.run(&["verify"]).code, 0);
    let again = p.run(&["checkpoint"]);
    assert_eq!(again.code, 0, "{}", again.all());
    let undo = p.run(&["undo", "--last"]);
    assert_eq!(undo.code, 0, "{}", undo.all());
}

#[test]
fn checkpoint_json_reports_warnings_as_data() {
    let p = Proj::inited("su002-json");
    p.write(".agent-undoignore", &"y".repeat(6000));
    let j = p.json(&["checkpoint"]);
    assert!(j.p("warnings.total").u64() >= 1);
    assert!(j.p("warnings.items.0").str().contains(".agent-undoignore"));
}

// ------------------------------------------------------------------- SU-005

#[test]
fn killing_the_wrapper_loses_that_runs_checkpoint_but_the_next_checkpoint_catches_the_changes() {
    if !have_command("sleep") {
        return;
    }
    let p = Proj::inited("su005-kill");
    let mut child = p.spawn(
        &["run", "--", "sh", "-c", "sleep 1; echo late > late.txt"],
        &[],
    );
    std::thread::sleep(Duration::from_millis(300));
    child.kill().unwrap(); // SIGKILL: the wrapper cannot clean up or forward anything
    let _ = child.wait();
    assert!(
        wait_for(&p.path("late.txt"), Duration::from_secs(10)),
        "the orphaned command kept running"
    );
    // no run checkpoint exists for it...
    let log = p.log();
    assert!(
        !log.p("checkpoints")
            .arr()
            .iter()
            .any(|c| c.p("kind").str() == "run")
    );
    // ...but its changes are recorded (and undoable) by the next checkpoint or run
    let c = p.json(&["checkpoint"]);
    assert_eq!(c.p("checkpoint.changes.created").u64(), 1);
    assert_eq!(p.run(&["undo", "--last", "--apply"]).code, 0);
    assert!(!p.exists("late.txt"));
}

// ------------------------------------------------------------------- SU-006

#[test]
fn a_relative_program_runs_the_file_that_was_named_from_the_callers_directory() {
    let p = Proj::inited("su006-rel");
    fs::create_dir_all(p.path("sub")).unwrap();
    for (dir, who) in [(".", "root"), ("sub", "sub")] {
        let f = p.path(dir).join("tool");
        fs::write(&f, format!("#!/bin/sh\nprintf {who} > who.txt\n")).unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let o = p.run_in(&p.path("sub"), &["run", "--", "./tool"]);
    assert_eq!(o.code, 0, "{}", o.all());
    // the command ran in the project root, but it is the sub/tool that was started
    assert_eq!(p.read("who.txt"), "sub");
}

#[test]
fn a_missing_relative_program_is_reported_as_not_found() {
    let p = Proj::inited("su006-missing");
    fs::create_dir_all(p.path("sub")).unwrap();
    fs::write(p.path("tool"), "#!/bin/sh\ntrue\n").unwrap();
    fs::set_permissions(p.path("tool"), fs::Permissions::from_mode(0o755)).unwrap();
    // ./tool exists in the root but not in sub: it must NOT be found through the root cwd
    let o = p.run_in(
        &p.path("sub"),
        &["-C", p.root.to_str().unwrap(), "run", "--", "./tool"],
    );
    assert_eq!(o.code, 127, "{}", o.all());
}

// ------------------------------------------------------------------- SU-007

#[test]
fn secrets_in_command_arguments_and_labels_are_redacted_everywhere() {
    let p = Proj::inited("su007-args");
    let o = p.run(&[
        "--json",
        "run",
        "--label",
        "DB_PASSWORD=hunter2",
        "--",
        "sh",
        "-c",
        "true",
        "--password",
        "hunter2",
        "--api-key=hunter3x",
        "DB_TOKEN=hunter4y",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    let all = format!("{}{}", o.stdout, o.stderr);
    for secret in ["hunter2", "hunter3x", "hunter4y"] {
        assert!(!all.contains(secret), "{secret} printed by run: {all}");
    }
    let log = p.run(&["log"]);
    let jlog = p.run(&["--json", "log"]);
    let d = p.run(&["diff", "2"]);
    for text in [&log.stdout, &jlog.stdout, &d.stdout] {
        for secret in ["hunter2", "hunter3x", "hunter4y"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(text.contains("[redacted]"));
    }
    assert!(
        !any_file_contains(&p.store(), b"hunter2"),
        "the journal stores the command line"
    );
    assert!(!any_file_contains(&p.store(), b"hunter3x"));
}

#[test]
fn no_log_args_records_only_the_program_name() {
    let p = Proj::inited("su007-omit");
    let o = p.run(&[
        "run",
        "--no-log-args",
        "--",
        "sh",
        "-c",
        "true",
        "visible-arg",
    ]);
    assert_eq!(o.code, 0, "{}", o.all());
    let log = p.run(&["log"]);
    assert!(log.stdout.contains("sh [args omitted]"), "{}", log.stdout);
    assert!(!log.stdout.contains("visible-arg"));
    assert!(!any_file_contains(&p.store(), b"visible-arg"));
}

#[test]
fn ordinary_arguments_stay_visible() {
    let p = Proj::inited("su007-plain");
    p.run(&[
        "run",
        "--label",
        "fix tests",
        "--",
        "sh",
        "-c",
        "echo hello > f.txt",
    ]);
    let log = p.run(&["log"]);
    assert!(
        log.stdout.contains("fix tests: sh -c echo hello > f.txt"),
        "{}",
        log.stdout
    );
}

// ------------------------------------------------------------------- SU-008

#[test]
fn init_in_project_never_writes_through_a_planted_git_exclude_symlink() {
    let p = Proj::new("su008-git");
    let victim = p.base.join("victim");
    fs::write(&victim, "precious\n").unwrap();
    // .git/info/exclude is a symlink to a user file
    fs::create_dir_all(p.path(".git/info")).unwrap();
    symlink(&victim, p.path(".git/info/exclude")).unwrap();
    let o = p.run(&["init", "--in-project"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        o.stderr.contains("symlink"),
        "a note is printed: {}",
        o.stderr
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
}

#[test]
fn init_in_project_never_follows_a_symlinked_git_info_directory() {
    let p = Proj::new("su008-gitinfo");
    let outside = p.base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("exclude"), "keep\n").unwrap();
    fs::create_dir_all(p.path(".git")).unwrap();
    symlink(&outside, p.path(".git/info")).unwrap();
    let o = p.run(&["init", "--in-project"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert_eq!(
        fs::read_to_string(outside.join("exclude")).unwrap(),
        "keep\n"
    );
}

#[test]
fn init_in_project_refuses_a_planted_log_symlink() {
    let p = Proj::new("su008-log");
    let victim = p.base.join("victim");
    fs::write(&victim, "precious\n").unwrap();
    fs::create_dir_all(p.path(".agent-undo")).unwrap();
    symlink(&victim, p.path(".agent-undo/log")).unwrap();
    let (code, j) = p.json_code(&["init", "--in-project"]);
    assert_eq!(code, 1);
    assert_eq!(j.p("error.code").str(), "unsafe_path");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
}

#[test]
fn a_plain_in_project_init_still_works_and_excludes_the_store() {
    let p = Proj::new("su008-ok");
    fs::create_dir_all(p.path(".git/info")).unwrap();
    let o = p.run(&["init", "--in-project"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(
        fs::read_to_string(p.path(".git/info/exclude"))
            .unwrap()
            .contains(".agent-undo")
    );
}

// ------------------------------------------------------------------- SU-009

#[test]
fn a_store_that_is_not_private_is_refused_by_every_command_and_reported_by_doctor() {
    let p = Proj::inited("su009-mode");
    let store = p.store();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    let s = p.run(&["--json", "status"]);
    assert_eq!(s.code, 1, "{}", s.all());
    assert_eq!(s.json().p("error.code").str(), "unsafe_path");
    assert!(s.json().p("error.message").str().contains("chmod"));
    let u = p.run(&["run", "--", "sh", "-c", "echo ran > ran.txt"]);
    assert_ne!(u.code, 0);
    assert!(
        !p.exists("ran.txt"),
        "the command must not run against an untrusted store"
    );
    let d = p.run(&["doctor"]);
    assert_eq!(d.code, 5, "{}", d.all());
    assert!(
        d.stdout.contains("FAIL") && d.stdout.contains("mode 0755"),
        "{}",
        d.stdout
    );
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(p.run(&["status"]).code, 0);
}

#[test]
fn a_loose_key_file_is_refused() {
    let p = Proj::inited("su009-key");
    fs::set_permissions(p.store().join("key"), fs::Permissions::from_mode(0o644)).unwrap();
    p.json_err(&["log"], 1, "unsafe_path");
    let d = p.run(&["doctor"]);
    assert_eq!(d.code, 5, "{}", d.all());
}

#[test]
fn a_symlinked_store_file_is_refused() {
    let p = Proj::inited("su009-link");
    let store = p.store();
    let moved = p.base.join("moved-log");
    fs::rename(store.join("log"), &moved).unwrap();
    symlink(&moved, store.join("log")).unwrap();
    p.json_err(&["status"], 1, "unsafe_path");
}

// ------------------------------------------------------------------- SU-011

#[test]
fn doctor_runs_without_a_store_and_reports_the_user_check() {
    let p = Proj::new("su011-doctor");
    let o = p.run(&["doctor"]);
    assert_eq!(o.code, 0, "{}", o.all());
    assert!(o.stdout.contains("user:"), "{}", o.stdout);
}
