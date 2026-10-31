use super::*;
use agent_undo_infra::layout::DEFAULT_MAX_FILE_SIZE;

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("au-doctor-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    fs::canonicalize(&p).unwrap()
}

fn status_of(checks: &[Check], name: &str) -> Status {
    checks.iter().find(|c| c.name == name).unwrap().status
}

#[test]
fn healthy_store_has_no_failures() {
    let base = tmp("healthy");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
    // A fresh store has an empty log: the journal loads, with zero checkpoints.
    let checks = run_checks(&root, Some(&store));
    assert!(
        checks.iter().all(|c| c.status != Status::Fail),
        "{checks:?}"
    );
    assert_eq!(status_of(&checks, "store permissions"), Status::Ok);
    assert_eq!(status_of(&checks, "lock"), Status::Ok);
}

#[test]
fn loose_permissions_fail() {
    let base = tmp("perms");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
    fs::set_permissions(store.dir.join("key"), fs::Permissions::from_mode(0o644)).unwrap();
    let checks = run_checks(&root, Some(&store));
    assert_eq!(status_of(&checks, "store permissions"), Status::Fail);
    assert!(doctor_text(&checks).contains("FAIL"));
    assert!(
        doctor_json(&checks)
            .to_compact()
            .contains("\"healthy\":false")
    );
}

#[test]
fn missing_store_is_a_warning_not_a_failure() {
    let root = tmp("nostore");
    let checks = run_checks(&root, None);
    assert_eq!(status_of(&checks, "store"), Status::Warn);
    assert!(checks.iter().all(|c| c.status != Status::Fail));
}

#[test]
fn in_project_store_without_git_exclude_warns() {
    let base = tmp("exclude");
    let root = base.join("proj");
    fs::create_dir_all(root.join(".git/info")).unwrap();
    let store = StoreDir::create(
        &root.join(IN_PROJECT_DIR),
        &root,
        true,
        DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    assert_eq!(
        status_of(&run_checks(&root, Some(&store)), "git exclude"),
        Status::Warn
    );
    fs::write(root.join(".git/info/exclude"), ".agent-undo\n").unwrap();
    assert_eq!(
        status_of(&run_checks(&root, Some(&store)), "git exclude"),
        Status::Ok
    );
}

#[test]
fn corrupt_journal_fails() {
    let base = tmp("journal");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
    fs::write(store.log_path(), "garbage\n").unwrap();
    assert_eq!(
        status_of(&run_checks(&root, Some(&store)), "journal"),
        Status::Fail
    );
}

#[test]
fn stale_temp_files_and_bad_ignore_file_are_reported() {
    let base = tmp("stale");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
    fs::write(store.tmp_dir().join("leftover"), b"x").unwrap();
    fs::write(root.join(".agent-undoignore"), "a".repeat(5000)).unwrap();
    let checks = run_checks(&root, Some(&store));
    assert_eq!(status_of(&checks, "temp files"), Status::Warn);
    assert_eq!(status_of(&checks, ".agent-undoignore"), Status::Fail);
}

#[test]
fn json_and_text_render_every_check() {
    let checks = vec![
        check("a", Status::Ok, "fine"),
        check("b", Status::Warn, "hmm \x1b[0m"),
    ];
    let t = doctor_text(&checks);
    assert!(
        t.contains("[ ok ] a: fine") && t.contains("[warn] b: hmm \\x1b[0m") && !t.contains('\x1b')
    );
    let j = doctor_json(&checks).to_compact();
    assert!(j.contains("\"healthy\":true") && j.contains("\"name\":\"b\""));
}
