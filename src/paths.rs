//! Path safety: relative-path validation, containment checks, and symlink-aware
//! opening.
//!
//! All paths that come from a manifest or from user input are validated here
//! before they are joined onto the project root. Std has no `openat`, so the
//! checks are `lstat`-based walks that are repeated immediately before each
//! write; see the README for the remaining race window.

use crate::error::{Ctx, Error, Result};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_COMPONENT_LEN: usize = 255;

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

/// Orders relative paths so that a directory's contents sort directly after the
/// directory and siblings sort by name: `/` compares lower than every other
/// byte. This is the order produced by a depth-first walk over sorted names.
pub fn cmp_paths(a: &[u8], b: &[u8]) -> Ordering {
    let key = |x: &u8| if *x == b'/' { 0u8 } else { *x };
    a.iter().map(key).cmp(b.iter().map(key))
}

/// Validates a project-relative path in the manifest encoding: non-empty,
/// no leading or trailing `/`, no empty, `.` or `..` components, no NUL, and
/// length limits.
pub fn validate_rel(p: &[u8]) -> Result<()> {
    let bad = |why: &str| {
        Error::Unsafe(format!(
            "invalid project-relative path {:?}: {why}",
            crate::esc::display(p)
        ))
    };
    if p.is_empty() {
        return Err(bad("empty"));
    }
    if p.len() > MAX_PATH_LEN {
        return Err(bad("too long"));
    }
    if p.first() == Some(&b'/') {
        return Err(bad("absolute"));
    }
    if p.contains(&0) {
        return Err(bad("contains NUL"));
    }
    for comp in p.split(|&b| b == b'/') {
        if comp.is_empty() {
            return Err(bad("empty component"));
        }
        if comp == b"." || comp == b".." {
            return Err(bad("'.' or '..' component"));
        }
        if comp.len() > MAX_COMPONENT_LEN {
            return Err(bad("component too long"));
        }
    }
    Ok(())
}

/// Joins a validated relative path onto the root.
pub fn join(root: &Path, rel: &[u8]) -> PathBuf {
    root.join(OsStr::from_bytes(rel))
}

/// Number of components in a relative path.
pub fn depth(rel: &[u8]) -> usize {
    rel.split(|&b| b == b'/').count()
}

/// Parent of a relative path (`None` for a top-level name).
pub fn parent_rel(rel: &[u8]) -> Option<&[u8]> {
    let i = rel.iter().rposition(|&b| b == b'/')?;
    rel.get(..i)
}

/// Verifies that `root` itself is a real directory (not a symlink).
pub fn check_root(root: &Path) -> Result<()> {
    let m = fs::symlink_metadata(root).ctx(|| {
        format!(
            "stat project root {}",
            crate::esc::display(root.as_os_str().as_bytes())
        )
    })?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(Error::Unsafe(format!(
            "project root {} is not a plain directory",
            crate::esc::display(root.as_os_str().as_bytes())
        )));
    }
    Ok(())
}

/// Walks every ancestor directory of `rel` below `root` with `lstat` and fails
/// if any is a symlink or not a directory. Missing ancestors are fine (the walk
/// stops there); callers that create directories re-check each component as
/// they create it.
pub fn check_parents(root: &Path, rel: &[u8]) -> Result<()> {
    validate_rel(rel)?;
    check_root(root)?;
    let mut cur = root.to_path_buf();
    let mut comps = rel.split(|&b| b == b'/').peekable();
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
                        crate::esc::display(rel)
                    )));
                }
                if !m.is_dir() {
                    return Err(Error::Unsafe(format!(
                        "a parent of {:?} is not a directory",
                        crate::esc::display(rel)
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(Error::io(
                    format!("stat parent of {}", crate::esc::display(rel)),
                    e,
                ));
            }
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
pub fn rel_from_arg(root: &Path, arg: &OsStr) -> Result<Vec<u8>> {
    let bytes = arg.as_bytes();
    let rel: Vec<u8> = if bytes.first() == Some(&b'/') {
        let root_b = root.as_os_str().as_bytes();
        let rest = bytes.strip_prefix(root_b).ok_or_else(|| {
            Error::Unsafe(format!(
                "path {:?} is outside the project root",
                crate::esc::display(bytes)
            ))
        })?;
        match rest.first() {
            Some(b'/') => rest.get(1..).unwrap_or(&[]).to_vec(),
            None => Vec::new(),
            Some(_) => {
                return Err(Error::Unsafe(format!(
                    "path {:?} is outside the project root",
                    crate::esc::display(bytes)
                )));
            }
        }
    } else {
        bytes.to_vec()
    };
    // Normalize harmless noise: leading "./", repeated and trailing slashes.
    let comps: Vec<&[u8]> = rel
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .collect();
    let joined = comps.join(&b'/');
    validate_rel(&joined)?;
    Ok(joined)
}

/// Root-relative path (bytes) of an absolute path below `root`, if any.
pub fn relativize(root: &Path, abs: &Path) -> Option<Vec<u8>> {
    let rest = abs.strip_prefix(root).ok()?;
    let b = rest.as_os_str().as_bytes();
    if b.is_empty() { None } else { Some(b.to_vec()) }
}

/// Builds a `PathBuf` from raw bytes (symlink targets, etc.).
pub fn path_from_bytes(b: Vec<u8>) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("au-paths-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn validate_accepts_normal_paths() {
        for p in ["a", "a/b/c.txt", ".hidden/x", "with space/ü"] {
            validate_rel(p.as_bytes()).unwrap();
        }
    }

    #[test]
    fn validate_rejects_bad_paths() {
        for p in [
            "", "/abs", "a//b", "a/", "../x", "a/../b", "./a", "a/./b", "a/..",
        ] {
            assert!(validate_rel(p.as_bytes()).is_err(), "{p}");
        }
        assert!(validate_rel(b"a\0b").is_err());
        assert!(validate_rel(&vec![b'a'; MAX_PATH_LEN + 1]).is_err());
        let long = format!("{}/x", "a".repeat(MAX_COMPONENT_LEN + 1));
        assert!(validate_rel(long.as_bytes()).is_err());
    }

    #[test]
    fn path_order_matches_depth_first_walk() {
        // "a/b" (inside dir a) must sort before "a-b" because a walk finishes dir `a` first.
        assert_eq!(cmp_paths(b"a/b", b"a-b"), Ordering::Less);
        assert_eq!(cmp_paths(b"a", b"a/b"), Ordering::Less);
        assert_eq!(cmp_paths(b"a", b"a-b"), Ordering::Less);
        assert_eq!(cmp_paths(b"a/z", b"b"), Ordering::Less);
        assert_eq!(cmp_paths(b"x", b"x"), Ordering::Equal);
    }

    #[test]
    fn depth_and_parent() {
        assert_eq!(depth(b"a"), 1);
        assert_eq!(depth(b"a/b/c"), 3);
        assert_eq!(parent_rel(b"a/b/c"), Some(&b"a/b"[..]));
        assert_eq!(parent_rel(b"a"), None);
    }

    #[test]
    fn check_parents_accepts_real_dirs_and_missing_tail() {
        let root = tmp("ok");
        fs::create_dir_all(root.join("a/b")).unwrap();
        check_parents(&root, b"a/b/file").unwrap();
        check_parents(&root, b"a/missing/deeper/file").unwrap();
        check_parents(&root, b"top").unwrap();
    }

    #[test]
    fn check_parents_rejects_symlinked_parent() {
        let root = tmp("symparent");
        let outside = tmp("symparent-out");
        symlink(&outside, root.join("link")).unwrap();
        let err = check_parents(&root, b"link/file").unwrap_err();
        assert!(matches!(err, Error::Unsafe(_)));
    }

    #[test]
    fn check_parents_rejects_nested_symlinked_parent() {
        let root = tmp("nested");
        let outside = tmp("nested-out");
        fs::create_dir_all(root.join("a")).unwrap();
        symlink(&outside, root.join("a/b")).unwrap();
        assert!(check_parents(&root, b"a/b/c/file").is_err());
    }

    #[test]
    fn check_parents_rejects_file_as_parent() {
        let root = tmp("fileparent");
        fs::write(root.join("f"), b"x").unwrap();
        assert!(check_parents(&root, b"f/child").is_err());
    }

    #[test]
    fn check_parents_allows_final_component_symlink() {
        // The target itself may be a symlink (it is replaced, never followed).
        let root = tmp("finallink");
        symlink("/etc", root.join("l")).unwrap();
        check_parents(&root, b"l").unwrap();
    }

    #[test]
    fn check_root_rejects_symlink_root() {
        let real = tmp("realroot");
        let link = std::env::temp_dir().join(format!("au-paths-linkroot-{}", std::process::id()));
        let _ = fs::remove_file(&link);
        symlink(&real, &link).unwrap();
        assert!(check_root(&link).is_err());
        assert!(check_root(&real).is_ok());
    }

    #[test]
    fn open_regular_refuses_symlink() {
        let root = tmp("openlink");
        fs::write(root.join("real"), b"data").unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        assert!(open_regular(&root.join("real"), None).is_ok());
        assert!(open_regular(&root.join("link"), None).is_err());
    }

    #[test]
    fn open_regular_refuses_directory_and_identity_change() {
        let root = tmp("openid");
        fs::write(root.join("a"), b"1").unwrap();
        fs::write(root.join("b"), b"2").unwrap();
        assert!(open_regular(&root, None).is_err());
        let ma = fs::symlink_metadata(root.join("a")).unwrap();
        assert!(open_regular(&root.join("a"), Some(&ma)).is_ok());
        assert!(open_regular(&root.join("b"), Some(&ma)).is_err());
    }

    #[test]
    fn rel_from_arg_variants() {
        let root = Path::new("/proj");
        assert_eq!(rel_from_arg(root, OsStr::new("a/b")).unwrap(), b"a/b");
        assert_eq!(rel_from_arg(root, OsStr::new("./a//b/")).unwrap(), b"a/b");
        assert_eq!(rel_from_arg(root, OsStr::new("/proj/a/b")).unwrap(), b"a/b");
        assert!(rel_from_arg(root, OsStr::new("/other/a")).is_err());
        assert!(rel_from_arg(root, OsStr::new("/projx/a")).is_err());
        assert!(rel_from_arg(root, OsStr::new("../a")).is_err());
        assert!(rel_from_arg(root, OsStr::new("a/../../b")).is_err());
        assert!(rel_from_arg(root, OsStr::new("")).is_err());
        assert!(rel_from_arg(root, OsStr::new("/proj")).is_err());
    }

    #[test]
    fn relativize_works() {
        let root = Path::new("/proj");
        assert_eq!(
            relativize(root, Path::new("/proj/a/b")),
            Some(b"a/b".to_vec())
        );
        assert_eq!(relativize(root, Path::new("/proj")), None);
        assert_eq!(relativize(root, Path::new("/elsewhere/a")), None);
    }
}
