use super::*;
use crate::fsutil::create_private_dir_all;
use std::os::unix::fs::{PermissionsExt, symlink};

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

// ---- SU-008: init never follows planted symlinks

fn victim(base: &Path) -> PathBuf {
    let v = base.join("victim.txt");
    fs::write(&v, b"keep me").unwrap();
    v
}

#[test]
fn create_refuses_a_store_directory_that_is_a_symlink() {
    let base = tmp("create-symdir");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let real = base.join("real");
    fs::create_dir_all(&real).unwrap();
    symlink(&real, base.join("state")).unwrap();
    let r = StoreDir::create(&base.join("state"), &root, false, 1);
    assert!(matches!(r, Err(Error::Unsafe(_))), "{r:?}");
    assert!(
        fs::read_dir(&real).unwrap().next().is_none(),
        "nothing was created through the link"
    );
}

#[test]
fn create_refuses_planted_symlinks_inside_the_store_directory() {
    for name in [
        "log",
        "key",
        "tmp",
        "blobs",
        "checkpoints",
        "sensitive-ids",
        "pruned",
        "lock",
    ] {
        let base = tmp(&format!("create-plant-{name}"));
        let root = base.join("proj");
        fs::create_dir_all(&root).unwrap();
        let store = base.join("state");
        fs::create_dir_all(&store).unwrap();
        let v = victim(&base);
        let target: &Path = if matches!(name, "tmp" | "blobs" | "checkpoints") {
            &base
        } else {
            &v
        };
        symlink(target, store.join(name)).unwrap();
        let r = StoreDir::create(&store, &root, false, 1);
        assert!(matches!(r, Err(Error::Unsafe(_))), "{name}: {r:?}");
        assert_eq!(fs::read(&v).unwrap(), b"keep me", "{name}");
        assert!(
            !store.join("meta").exists(),
            "{name}: init must not complete"
        );
    }
}

#[test]
fn create_tolerates_plain_leftovers_of_an_interrupted_init() {
    let base = tmp("create-leftover");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let store = base.join("state");
    // what an interrupted init of this tool leaves behind: private dirs and files
    create_private_dir_all(&store.join("blobs")).unwrap();
    fs::write(store.join("key"), "stale").unwrap();
    fs::write(store.join("log"), "").unwrap();
    for f in ["key", "log"] {
        fs::set_permissions(store.join(f), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let s = StoreDir::create(&store, &root, false, 1).unwrap();
    assert_eq!(
        fs::read_to_string(store.join("key")).unwrap().len(),
        64,
        "key replaced"
    );
    assert_eq!(s.meta.max_file_size, 1);
}

// ---- SU-009: opening a store checks owner and permissions

fn assert_unsafe(r: Result<StoreDir>, what: &str) {
    assert!(matches!(r, Err(Error::Unsafe(_))), "{what}: {r:?}");
}

#[test]
fn open_refuses_a_store_that_is_not_private() {
    for (rel, mode) in [
        ("", 0o750),
        ("", 0o755),
        ("", 0o777),
        ("blobs", 0o755),
        ("checkpoints", 0o770),
        ("tmp", 0o777),
        ("key", 0o644),
        ("key", 0o640),
        ("meta", 0o666),
        ("log", 0o644),
    ] {
        let (_b, s) = mk(&format!("open-mode-{}-{mode:o}", rel.replace('/', "_")));
        let p = if rel.is_empty() {
            s.dir.clone()
        } else {
            s.dir.join(rel)
        };
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        let r = StoreDir::open_at(&s.dir, &s.root);
        assert_unsafe(r, &format!("{rel:?} {mode:o}"));
        fs::set_permissions(
            &p,
            fs::Permissions::from_mode(if p.is_dir() { 0o700 } else { 0o600 }),
        )
        .unwrap();
        assert!(
            StoreDir::open_at(&s.dir, &s.root).is_ok(),
            "{rel:?} fine again"
        );
    }
}

#[test]
fn open_refuses_a_store_owned_by_someone_else() {
    let (_b, s) = mk("open-owner");
    let me = crate::fsutil::effective_uid().unwrap();
    let other = me.wrapping_add(1);
    let r = StoreDir::open_at_as(&s.dir, &s.root, other);
    match r {
        Err(Error::Unsafe(m)) => assert!(m.contains("owned by"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(StoreDir::open_at_as(&s.dir, &s.root, me).is_ok());
}

#[test]
fn open_refuses_symlinked_children() {
    for name in ["meta", "key", "log", "tmp", "blobs", "checkpoints"] {
        let (b, s) = mk(&format!("open-symchild-{name}"));
        let real = s.dir.join(name);
        let moved = b.join(format!("moved-{name}"));
        fs::rename(&real, &moved).unwrap();
        symlink(&moved, &real).unwrap();
        assert_unsafe(StoreDir::open_at(&s.dir, &s.root), name);
    }
}

#[test]
fn open_refuses_optional_files_that_are_symlinks_or_loose() {
    for name in ["lock", "pruned", "sensitive-ids"] {
        let (b, s) = mk(&format!("open-opt-{name}"));
        let v = victim(&b);
        symlink(&v, s.dir.join(name)).unwrap();
        assert_unsafe(
            StoreDir::open_at(&s.dir, &s.root),
            &format!("{name} symlink"),
        );
        fs::remove_file(s.dir.join(name)).unwrap();
        fs::write(s.dir.join(name), b"").unwrap();
        fs::set_permissions(s.dir.join(name), fs::Permissions::from_mode(0o666)).unwrap();
        assert_unsafe(StoreDir::open_at(&s.dir, &s.root), &format!("{name} loose"));
        fs::set_permissions(s.dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(StoreDir::open_at(&s.dir, &s.root).is_ok(), "{name}");
    }
}

#[test]
fn an_external_store_in_a_directory_others_can_write_to_is_refused() {
    let base = tmp("open-parent");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let state = base.join("state");
    let ext = external_store_dir(&state, &root);
    StoreDir::create(&ext, &root, false, 1).unwrap();
    let parent = ext.parent().unwrap().to_path_buf();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert_unsafe(StoreDir::open_at(&ext, &root), "world-writable parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(
        StoreDir::open_at(&ext, &root).is_ok(),
        "sticky parents (like /tmp) are fine"
    );
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
    assert_unsafe(StoreDir::open_at(&ext, &root), "group-writable parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(StoreDir::open_at(&ext, &root).is_ok());
}

#[test]
fn an_in_project_store_may_live_in_a_group_writable_project() {
    let base = tmp("open-inproject-parent");
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
    let inner = root.join(IN_PROJECT_DIR);
    StoreDir::create(&inner, &root, true, 1).unwrap();
    assert!(StoreDir::open_at(&inner, &root).is_ok());
}

#[test]
fn read_small_refuses_symlinks() {
    let base = tmp("read-small");
    let v = victim(&base);
    symlink(&v, base.join("l")).unwrap();
    assert!(read_small(&base.join("l"), 100).is_err());
    assert_eq!(read_small(&v, 100).unwrap(), b"keep me");
}
