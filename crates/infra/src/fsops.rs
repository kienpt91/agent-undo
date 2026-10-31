//! Small filesystem helpers shared by the store and the restore engine:
//! private (`0700`/`0600`) creation, unique temp names and atomic replacement.

use crate::error::{Ctx, Error, Result};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temp-file suffix that is unique within and across processes.
pub fn unique_suffix() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        crate::util::now_ns(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
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
pub fn create_new_private(path: &Path) -> std::io::Result<File> {
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

/// Escaped path for messages.
pub fn display_path(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    agent_undo_domain::esc::display(p.as_os_str().as_bytes())
}

/// Returns a path inside `dir` for a temp file next to a restore target.
pub fn sibling_tmp(dir: &Path) -> PathBuf {
    dir.join(format!(".agent-undo-tmp-{}", unique_suffix()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("au-fsops-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
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
        std::os::unix::fs::symlink(&target, d.join("link")).unwrap();
        assert!(create_new_private(&d.join("link")).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn atomic_write_replaces_content() {
        let d = tmp("atomic");
        let f = d.join("out");
        write_atomic_private(&f, &d, b"one").unwrap();
        write_atomic_private(&f, &d, b"two").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"two");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1, "no temp files left");
    }

    #[test]
    fn unique_suffixes_differ() {
        assert_ne!(unique_suffix(), unique_suffix());
    }
}
