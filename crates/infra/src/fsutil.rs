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

/// Raw `open(2)` flag values. std exposes `custom_flags` but no named constants,
/// so the values are fixed per supported target. They were read from the C library
/// of each target (Python's `os.O_*`, which wraps the platform header) and are
/// asserted again in the tests. Any other target does not compile: guessing here
/// would silently drop the protection against following symlinks and blocking on
/// FIFOs.
///
/// | target | `O_NOFOLLOW` | `O_NONBLOCK` | `O_DIRECTORY` |
/// |---|---|---|---|
/// | Linux x86_64 | `0x20000` | `0x800` | `0x10000` |
/// | Linux aarch64 | `0x8000` | `0x800` | `0x4000` |
/// | macOS (x86_64, aarch64) | `0x100` | `0x4` | `0x100000` |
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sysflags {
    pub const O_NOFOLLOW: i32 = 0x20000;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const O_DIRECTORY: i32 = 0x10000;
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sysflags {
    pub const O_NOFOLLOW: i32 = 0x8000;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const O_DIRECTORY: i32 = 0x4000;
}
#[cfg(target_os = "macos")]
mod sysflags {
    pub const O_NOFOLLOW: i32 = 0x100;
    pub const O_NONBLOCK: i32 = 0x4;
    pub const O_DIRECTORY: i32 = 0x100000;
}
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
compile_error!(
    "agent-undo supports Linux (x86_64, aarch64) and macOS only: the open(2) flag values that \
     keep it from following symlinks are defined per target in crates/infra/src/fsutil.rs and \
     must be verified for any new target"
);

/// Flags for reading a regular file: refuse a final symlink, never block on a FIFO.
pub const OPEN_FLAGS: i32 = sysflags::O_NOFOLLOW | sysflags::O_NONBLOCK;
/// Flags for opening a directory without following a final symlink.
pub const OPEN_DIR_FLAGS: i32 = sysflags::O_NOFOLLOW | sysflags::O_DIRECTORY;
/// Flag that makes `open` refuse a final symlink.
pub const O_NOFOLLOW: i32 = sysflags::O_NOFOLLOW;

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

/// Why a parent chain cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentProblem {
    /// An ancestor is a symlink: never traversed.
    Symlink(String),
    /// An ancestor exists but is not a directory.
    NotDirectory(String),
}

/// Walks every ancestor directory of `rel` below `root` with `lstat`. Missing
/// ancestors are fine (the walk stops there); callers that create directories
/// re-check each component as they create it.
pub fn parent_problem(root: &Path, rel: &RelPath) -> Result<Option<ParentProblem>> {
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
                    return Ok(Some(ParentProblem::Symlink(format!(
                        "refusing to traverse a symlink in parent directory of {:?}",
                        rel.display()
                    ))));
                }
                if !m.is_dir() {
                    return Ok(Some(ParentProblem::NotDirectory(format!(
                        "a parent of {:?} is not a directory",
                        rel.display()
                    ))));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::io(format!("stat parent of {}", rel.display()), e)),
        }
    }
    Ok(None)
}

/// Fails with `Error::Unsafe` if any ancestor of `rel` is a symlink or not a directory.
pub fn check_parents(root: &Path, rel: &RelPath) -> Result<()> {
    match parent_problem(root, rel)? {
        None => Ok(()),
        Some(ParentProblem::Symlink(m) | ParentProblem::NotDirectory(m)) => Err(Error::Unsafe(m)),
    }
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
mod tests;
