//! Filesystem helpers: private (`0700`/`0600`) creation, atomic writes, and the
//! symlink-aware path checks used before every read or write inside the project.
//!
//! Std has no `openat`, so the checks are `lstat`-based walks that are repeated
//! immediately before each write; see the README for the remaining race window.

use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_domain::esc;
use agent_undo_domain::path::RelPath;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// `O_NOFOLLOW | O_NONBLOCK` for the supported targets. `O_NOFOLLOW` makes
/// `open` fail with `ELOOP` if the final component is a symlink and
/// `O_NONBLOCK` keeps `open` from hanging if a FIFO is swapped in. On other
/// targets the flags are 0 and the post-open `fstat` identity check is the only
/// defence.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64")
))]
const OPEN_FLAGS: i32 = 0x20000 | 0x800;
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const OPEN_FLAGS: i32 = 0x8000 | 0x800;
#[cfg(target_os = "macos")]
const OPEN_FLAGS: i32 = 0x100 | 0x4;
#[cfg(not(any(
    all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64",
            target_arch = "aarch64",
            target_arch = "arm"
        )
    ),
    target_os = "macos"
)))]
const OPEN_FLAGS: i32 = 0;

/// Nanoseconds since the Unix epoch (saturating; 0 if the clock is before 1970).
pub fn now_ns() -> i64 {
    system_time_ns(SystemTime::now())
}

/// Converts a `SystemTime` to nanoseconds since the epoch (negative before 1970).
pub fn system_time_ns(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_nanos()).map_or(i64::MIN, |v| -v),
    }
}

/// Fills `n` bytes from the operating system's random source.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = File::open("/dev/urandom").ctx(|| "opening /dev/urandom".into())?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .ctx(|| "reading /dev/urandom".into())?;
    Ok(buf)
}

/// A temp-file suffix that is unique within and across processes.
pub fn unique_suffix() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        now_ns(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Escaped path for messages.
pub fn display_path(p: &Path) -> String {
    esc::display(p.as_os_str().as_bytes())
}

/// Creates a directory (and missing parents) with mode `0700`.
pub fn create_private_dir_all(path: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .ctx(|| format!("creating directory {}", display_path(path)))
}

/// Creates a new file with mode `0600`, failing if it exists (`O_EXCL`, which
/// also refuses to follow a pre-planted symlink).
pub fn create_new_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Writes `bytes` to `final_path` atomically: temp file in `tmp_dir` (same
/// filesystem), fsync, rename. The file has mode `0600`.
pub fn write_atomic_private(final_path: &Path, tmp_dir: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_dir.join(format!("w-{}", unique_suffix()));
    let mut f = create_new_private(&tmp).ctx(|| format!("creating {}", display_path(&tmp)))?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| fs::rename(&tmp, final_path));
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(
            format!("writing {}", display_path(final_path)),
            e,
        ));
    }
    Ok(())
}

/// Best-effort fsync of a directory so a rename is durable.
pub fn sync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

/// A temp path next to a restore target.
pub fn sibling_tmp(dir: &Path) -> PathBuf {
    dir.join(format!(".agent-undo-tmp-{}", unique_suffix()))
}

/// Joins a validated relative path onto the root.
pub fn join(root: &Path, rel: &RelPath) -> PathBuf {
    root.join(OsStr::from_bytes(rel.as_bytes()))
}

/// Builds a `PathBuf` from raw bytes (symlink targets, etc.).
pub fn path_from_bytes(b: Vec<u8>) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(b))
}

/// Verifies that `root` itself is a real directory (not a symlink).
pub fn check_root(root: &Path) -> Result<()> {
    let m =
        fs::symlink_metadata(root).ctx(|| format!("stat project root {}", display_path(root)))?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(Error::Unsafe(format!(
            "project root {} is not a plain directory",
            display_path(root)
        )));
    }
    Ok(())
}

/// Walks every ancestor directory of `rel` below `root` with `lstat` and fails
/// if any is a symlink or not a directory. Missing ancestors are fine (the walk
/// stops there); callers that create directories re-check each component as
/// they create it.
pub fn check_parents(root: &Path, rel: &RelPath) -> Result<()> {
    check_root(root)?;
    let mut cur = root.to_path_buf();
    let mut comps = rel.components().peekable();
    while let Some(comp) = comps.next() {
        if comps.peek().is_none() {
            break; // the final component is the target, not a parent
        }
        cur.push(OsStr::from_bytes(comp));
        match fs::symlink_metadata(&cur) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(Error::Unsafe(format!(
                        "refusing to traverse a symlink in parent directory of {:?}",
                        rel.display()
                    )));
                }
                if !m.is_dir() {
                    return Err(Error::Unsafe(format!(
                        "a parent of {:?} is not a directory",
                        rel.display()
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::io(format!("stat parent of {}", rel.display()), e)),
        }
    }
    Ok(())
}

/// Opens a regular file for reading without following a final symlink and
/// verifies with `fstat` that the opened object is a regular file and, if
/// `expect` is given, the same inode that a previous `lstat` saw.
pub fn open_regular(
    path: &Path,
    expect: Option<&fs::Metadata>,
) -> io::Result<(File, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_FLAGS)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    if let Some(e) = expect
        && (e.dev() != meta.dev() || e.ino() != meta.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file identity changed between lstat and open",
        ));
    }
    Ok((file, meta))
}

/// Converts a user-supplied path argument to a root-relative path. Absolute
/// paths must lie lexically under `root`; relative paths are taken relative to
/// `root`. Any `..` component is rejected rather than resolved.
pub fn rel_from_arg(root: &Path, arg: &OsStr) -> Result<RelPath> {
    let bytes = arg.as_bytes();
    let outside = || {
        Error::Unsafe(format!(
            "path {:?} is outside the project root",
            esc::display(bytes)
        ))
    };
    let rel: &[u8] = if bytes.first() == Some(&b'/') {
        let rest = bytes
            .strip_prefix(root.as_os_str().as_bytes())
            .ok_or_else(outside)?;
        match rest.first() {
            Some(b'/') => rest.get(1..).unwrap_or(&[]),
            None => &[],
            Some(_) => return Err(outside()),
        }
    } else {
        bytes
    };
    Ok(RelPath::normalized(rel)?)
}

/// Root-relative path of an absolute path below `root`, if any.
pub fn relativize(root: &Path, abs: &Path) -> Option<RelPath> {
    let rest = abs.strip_prefix(root).ok()?;
    RelPath::new(rest.as_os_str().as_bytes()).ok()
}

#[cfg(test)]
mod tests {
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
}
