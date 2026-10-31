use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("au-fsutil-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn rp(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

#[test]
fn private_dirs_have_mode_0700() {
    let d = tmp("dirs").join("a/b/c");
    create_private_dir_all(&d).unwrap();
    for p in [d.clone(), d.parent().unwrap().to_path_buf()] {
        assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

#[test]
fn private_files_have_mode_0600_and_are_exclusive() {
    let d = tmp("files");
    let p = d.join("f");
    drop(create_new_private(&p).unwrap());
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(create_new_private(&p).is_err());
}

#[test]
fn exclusive_create_refuses_planted_symlink() {
    let d = tmp("symlink");
    let target = d.join("target");
    symlink(&target, d.join("link")).unwrap();
    assert!(create_new_private(&d.join("link")).is_err());
    assert!(!target.exists());
}

#[test]
fn atomic_write_replaces_content_and_leaves_no_temp_files() {
    let d = tmp("atomic");
    let f = d.join("out");
    write_atomic_private(&f, &d, b"one").unwrap();
    write_atomic_private(&f, &d, b"two").unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"two");
    assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
}

#[test]
fn unique_suffixes_differ() {
    assert_ne!(unique_suffix(), unique_suffix());
}

#[test]
fn random_bytes_differ() {
    let a = random_bytes(32).unwrap();
    assert_eq!(a.len(), 32);
    assert_ne!(a, random_bytes(32).unwrap());
}

#[test]
fn now_is_after_2020() {
    assert!(now_ns() > 1_577_836_800_000_000_000);
    assert!(system_time_ns(UNIX_EPOCH - std::time::Duration::from_secs(5)) < 0);
}

#[test]
fn check_parents_accepts_real_dirs_and_missing_tail() {
    let root = tmp("ok");
    fs::create_dir_all(root.join("a/b")).unwrap();
    check_parents(&root, &rp("a/b/file")).unwrap();
    check_parents(&root, &rp("a/missing/deeper/file")).unwrap();
    check_parents(&root, &rp("top")).unwrap();
}

#[test]
fn check_parents_rejects_symlinked_parent_even_nested() {
    let root = tmp("symparent");
    let outside = tmp("symparent-out");
    symlink(&outside, root.join("link")).unwrap();
    assert!(matches!(
        check_parents(&root, &rp("link/file")),
        Err(Error::Unsafe(_))
    ));
    fs::create_dir_all(root.join("a")).unwrap();
    symlink(&outside, root.join("a/b")).unwrap();
    assert!(check_parents(&root, &rp("a/b/c/file")).is_err());
}

#[test]
fn parent_problem_distinguishes_symlinks_from_files() {
    let root = tmp("problem");
    fs::write(root.join("f"), b"x").unwrap();
    symlink("/etc", root.join("l")).unwrap();
    assert!(matches!(
        parent_problem(&root, &rp("f/c")).unwrap(),
        Some(ParentProblem::NotDirectory(_))
    ));
    assert!(matches!(
        parent_problem(&root, &rp("l/c")).unwrap(),
        Some(ParentProblem::Symlink(_))
    ));
    assert_eq!(parent_problem(&root, &rp("ok/c")).unwrap(), None);
}

#[test]
fn check_parents_rejects_file_as_parent() {
    let root = tmp("fileparent");
    fs::write(root.join("f"), b"x").unwrap();
    assert!(check_parents(&root, &rp("f/child")).is_err());
}

#[test]
fn check_parents_allows_final_component_symlink() {
    let root = tmp("finallink");
    symlink("/etc", root.join("l")).unwrap();
    check_parents(&root, &rp("l")).unwrap();
}

#[test]
fn check_root_rejects_symlink_root() {
    let real = tmp("realroot");
    let link = std::env::temp_dir().join(format!("au-fsutil-linkroot-{}", std::process::id()));
    let _ = fs::remove_file(&link);
    symlink(&real, &link).unwrap();
    assert!(check_root(&link).is_err());
    assert!(check_root(&real).is_ok());
}

#[test]
fn open_regular_refuses_symlink_directory_and_identity_change() {
    let root = tmp("open");
    fs::write(root.join("a"), b"1").unwrap();
    fs::write(root.join("b"), b"2").unwrap();
    symlink(root.join("a"), root.join("link")).unwrap();
    assert!(open_regular(&root.join("a"), None).is_ok());
    assert!(
        open_regular(&root.join("link"), None).is_err(),
        "O_NOFOLLOW must refuse a symlink"
    );
    assert!(open_regular(&root, None).is_err());
    let ma = fs::symlink_metadata(root.join("a")).unwrap();
    assert!(open_regular(&root.join("a"), Some(&ma)).is_ok());
    assert!(open_regular(&root.join("b"), Some(&ma)).is_err());
}

#[test]
fn rel_from_arg_variants() {
    let root = Path::new("/proj");
    assert_eq!(rel_from_arg(root, OsStr::new("a/b")).unwrap(), rp("a/b"));
    assert_eq!(
        rel_from_arg(root, OsStr::new("./a//b/")).unwrap(),
        rp("a/b")
    );
    assert_eq!(
        rel_from_arg(root, OsStr::new("/proj/a/b")).unwrap(),
        rp("a/b")
    );
    for bad in ["/other/a", "/projx/a", "../a", "a/../../b", "", "/proj"] {
        assert!(rel_from_arg(root, OsStr::new(bad)).is_err(), "{bad}");
    }
}

#[test]
fn relativize_works() {
    let root = Path::new("/proj");
    assert_eq!(relativize(root, Path::new("/proj/a/b")), Some(rp("a/b")));
    assert_eq!(relativize(root, Path::new("/proj")), None);
    assert_eq!(relativize(root, Path::new("/elsewhere/a")), None);
}

#[test]
fn join_and_path_from_bytes() {
    assert_eq!(join(Path::new("/r"), &rp("a/b")), PathBuf::from("/r/a/b"));
    assert_eq!(path_from_bytes(b"x/y".to_vec()), PathBuf::from("x/y"));
}
