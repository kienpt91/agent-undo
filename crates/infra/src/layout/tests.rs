use super::*;
use std::os::unix::fs::PermissionsExt;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("au-layout-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    fs::canonicalize(&p).unwrap()
}

fn mk(name: &str) -> (PathBuf, StoreDir) {
    let base = tmp(name);
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let s = StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
    (base, s)
}

#[test]
fn project_id_is_stable_and_short() {
    let a = project_id(Path::new("/a/b"));
    assert_eq!(a.len(), 16);
    assert_eq!(a, project_id(Path::new("/a/b")));
    assert_ne!(a, project_id(Path::new("/a/c")));
}

#[test]
fn state_base_prefers_xdg_then_home() {
    let env = |pairs: Vec<(&'static str, &'static str)>| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(*v))
        }
    };
    assert_eq!(
        state_base_from(env(vec![("XDG_STATE_HOME", "/x"), ("HOME", "/h")])).unwrap(),
        PathBuf::from("/x")
    );
    assert_eq!(
        state_base_from(env(vec![("HOME", "/h")])).unwrap(),
        PathBuf::from("/h/.local/state")
    );
    assert_eq!(
        state_base_from(env(vec![("XDG_STATE_HOME", "rel"), ("HOME", "/h")])).unwrap(),
        PathBuf::from("/h/.local/state"),
        "relative XDG_STATE_HOME is ignored per the XDG spec"
    );
    assert!(state_base_from(env(vec![])).is_err());
    assert!(state_base_from(env(vec![("HOME", "relative")])).is_err());
}

#[test]
fn create_sets_up_private_layout() {
    let (_b, s) = mk("layout");
    for sub in ["blobs", "checkpoints", "tmp"] {
        assert_eq!(
            fs::metadata(s.dir.join(sub)).unwrap().permissions().mode() & 0o777,
            0o700,
            "{sub}"
        );
    }
    for f in ["meta", "key", "log"] {
        assert_eq!(
            fs::metadata(s.dir.join(f)).unwrap().permissions().mode() & 0o777,
            0o600,
            "{f}"
        );
    }
    assert_eq!(
        fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(s.meta.max_file_size, DEFAULT_MAX_FILE_SIZE);
    assert_eq!(s.blobs_dir(), s.dir.join("blobs"));
    assert_eq!(s.checkpoints_dir(), s.dir.join("checkpoints"));
    assert_eq!(s.tmp_dir(), s.dir.join("tmp"));
    assert_eq!(s.log_path(), s.dir.join("log"));
    assert_eq!(s.pruned_path(), s.dir.join("pruned"));
    assert_eq!(s.lock_path(), s.dir.join("lock"));
}

#[test]
fn create_twice_fails() {
    let (_b, s) = mk("twice");
    assert!(matches!(
        StoreDir::create(&s.dir, &s.root, false, 1),
        Err(Error::AlreadyInitialized(_))
    ));
}

#[test]
fn open_rejects_other_root_and_symlinked_store() {
    let (base, s) = mk("open");
    let other = base.join("other");
    fs::create_dir_all(&other).unwrap();
    assert!(StoreDir::open_at(&s.dir, &other).is_err());
    assert!(StoreDir::open_at(&s.dir, &s.root).is_ok());
    let link = base.join("linkstate");
    std::os::unix::fs::symlink(&s.dir, &link).unwrap();
    assert!(matches!(
        StoreDir::open_at(&link, &s.root),
        Err(Error::Unsafe(_))
    ));
}

#[test]
fn open_missing_or_corrupt_store() {
    let base = tmp("missing");
    assert!(matches!(
        StoreDir::open_at(&base.join("nope"), &base),
        Err(Error::NotInitialized(_))
    ));
    let (_b, s) = mk("corrupt");
    fs::write(s.dir.join("meta"), "garbage\n").unwrap();
    assert!(matches!(
        StoreDir::open_at(&s.dir, &s.root),
        Err(Error::Format(_))
    ));
    let (_b, s) = mk("corruptkey");
    fs::write(s.dir.join("key"), "nothex").unwrap();
    assert!(matches!(
        StoreDir::open_at(&s.dir, &s.root),
        Err(Error::Format(_))
    ));
    let (_b, s) = mk("nometa");
    fs::remove_file(s.dir.join("meta")).unwrap();
    assert!(matches!(
        StoreDir::open_at(&s.dir, &s.root),
        Err(Error::NotInitialized(_))
    ));
}

#[test]
fn locate_finds_external_store_from_a_subdirectory() {
    let base = tmp("locate");
    let root = base.join("proj");
    let sub = root.join("a/b");
    fs::create_dir_all(&sub).unwrap();
    let state = base.join("state");
    let ext = external_store_dir(&state, &root);
    StoreDir::create(&ext, &root, false, 1000).unwrap();
    assert_eq!(
        StoreDir::locate(&sub, false, Some(&state)).unwrap().dir,
        ext
    );
    assert!(StoreDir::locate(&sub, true, Some(&state)).is_err());
    assert_eq!(
        StoreDir::locate(&root, true, Some(&state))
            .unwrap()
            .meta
            .max_file_size,
        1000
    );
}

#[test]
fn in_project_store_is_found_first() {
    let base = tmp("inproj");
    let root = base.join("proj");
    let inner = root.join(IN_PROJECT_DIR);
    fs::create_dir_all(&root).unwrap();
    StoreDir::create(&inner, &root, true, 5).unwrap();
    let found = StoreDir::locate(&root, true, None).unwrap();
    assert!(found.meta.in_project);
    assert_eq!(found.dir, inner);
}

#[test]
fn locate_without_store_reports_not_initialized() {
    let base = tmp("nolocate");
    assert!(matches!(
        StoreDir::locate(&base, false, Some(&base.join("state"))),
        Err(Error::NotInitialized(_))
    ));
}

#[test]
fn read_file_capped_behaviour() {
    let d = tmp("capped");
    fs::write(d.join("f"), b"12345").unwrap();
    assert_eq!(
        read_file_capped(&d.join("f"), 10).unwrap(),
        Some(b"12345".to_vec())
    );
    assert!(matches!(
        read_file_capped(&d.join("f"), 4),
        Err(Error::Limit(_))
    ));
    assert_eq!(read_file_capped(&d.join("nope"), 10).unwrap(), None);
    std::os::unix::fs::symlink(d.join("f"), d.join("l")).unwrap();
    assert_eq!(
        read_file_capped(&d.join("l"), 10).unwrap(),
        None,
        "symlinks are not followed"
    );
}
