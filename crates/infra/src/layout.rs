//! Where a project's store lives on disk and how it is created and found.
//!
//! ```text
//! <store>/                  0700
//!   meta                    project root, id, size cap (text)
//!   key                     0600, random HMAC key for sensitive-file hashes
//!   lock                    flock target
//!   log                     append-only, hash-chained checkpoint records
//!   pruned                  checkpoint numbers removed by `gc`
//!   blobs/ab/<sha256>       content-addressed file contents
//!   checkpoints/NNNNNNNN.manifest   full post-state of checkpoint N
//!   checkpoints/NNNNNNNN.changes    change set of checkpoint N (before and after entries)
//!   tmp/                    in-flight writes
//! ```

use crate::fsutil::{
    create_new_private, create_private_dir_all, display_path, now_ns, random_bytes,
    write_atomic_private,
};
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_domain::esc::{display, pct_decode, pct_encode};
use agent_undo_domain::hash::{digest_from_hex, sha256, to_hex};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub const STORE_HEADER: &str = "agent-undo-store v1";
pub const DEFAULT_MAX_FILE_SIZE: u64 = 25 * 1024 * 1024;
pub const IN_PROJECT_DIR: &str = ".agent-undo";

#[derive(Debug, Clone)]
pub struct Meta {
    pub root: PathBuf,
    pub project_id: String,
    pub created_ns: i64,
    pub max_file_size: u64,
    pub in_project: bool,
}

/// First 16 hex characters of SHA-256 over the canonical project root path.
pub fn project_id(root: &Path) -> String {
    let d = sha256(root.as_os_str().as_bytes());
    to_hex(d.get(..8).unwrap_or(&d))
}

/// Resolves the state directory base: `$XDG_STATE_HOME` if absolute, else
/// `$HOME/.local/state`.
pub fn state_base_from(get: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    if let Some(x) = get("XDG_STATE_HOME")
        && !x.is_empty()
        && x.as_bytes().first() == Some(&b'/')
    {
        return Ok(PathBuf::from(x));
    }
    match get("HOME") {
        Some(h) if !h.is_empty() && h.as_bytes().first() == Some(&b'/') => Ok(PathBuf::from(h).join(".local").join("state")),
        _ => Err(Error::Usage(
            "cannot determine the state directory: set XDG_STATE_HOME or HOME to an absolute path, or use `init --in-project`".into(),
        )),
    }
}

pub fn state_base() -> Result<PathBuf> {
    state_base_from(|k| std::env::var_os(k))
}

/// Directory of the external store for a canonical project root.
pub fn external_store_dir(base: &Path, root: &Path) -> PathBuf {
    base.join("agent-undo").join(project_id(root))
}

fn parse_meta(text: &str, dir: &Path) -> Result<Meta> {
    let bad = |why: &str| {
        Error::Format(format!(
            "corrupt store metadata in {}: {why}",
            display_path(dir)
        ))
    };
    let mut lines = text.lines();
    if lines.next() != Some(STORE_HEADER) {
        return Err(bad("unrecognised header (different version?)"));
    }
    let (mut root, mut id, mut created, mut max, mut inp) = (None, None, None, None, None);
    for l in lines {
        let (k, v) = l.split_once('=').ok_or_else(|| bad("malformed line"))?;
        match k {
            "root" => root = pct_decode(v),
            "project_id" => id = Some(v.to_string()),
            "created" => created = v.parse::<i64>().ok(),
            "max_file_size" => max = v.parse::<u64>().ok(),
            "in_project" => inp = Some(v == "1"),
            _ => {}
        }
    }
    Ok(Meta {
        root: PathBuf::from(OsString::from_vec(root.ok_or_else(|| bad("root"))?)),
        project_id: id.ok_or_else(|| bad("project_id"))?,
        created_ns: created.ok_or_else(|| bad("created"))?,
        max_file_size: max.ok_or_else(|| bad("max_file_size"))?,
        in_project: inp.ok_or_else(|| bad("in_project"))?,
    })
}

fn encode_meta(m: &Meta) -> String {
    format!(
        "{STORE_HEADER}\nroot={}\nproject_id={}\ncreated={}\nmax_file_size={}\nin_project={}\n",
        pct_encode(m.root.as_os_str().as_bytes()),
        m.project_id,
        m.created_ns,
        m.max_file_size,
        u8::from(m.in_project)
    )
}

pub fn read_small(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let f = File::open(path).ctx(|| format!("opening {}", display_path(path)))?;
    let mut buf = Vec::new();
    f.take(cap + 1)
        .read_to_end(&mut buf)
        .ctx(|| format!("reading {}", display_path(path)))?;
    if buf.len() as u64 > cap {
        return Err(Error::Limit(format!(
            "{} is larger than {cap} bytes",
            display_path(path)
        )));
    }
    Ok(buf)
}

/// Reads a whole file under `cap` bytes if it is a regular file (symlinks are
/// not followed); `None` if it does not exist. Used for `.agent-undoignore`.
pub fn read_file_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => read_small(path, cap).map(Some),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(format!("stat {}", display_path(path)), e)),
    }
}

/// The directory layout of one project's store plus its metadata and key.
#[derive(Debug, Clone)]
pub struct StoreDir {
    pub dir: PathBuf,
    pub root: PathBuf,
    pub meta: Meta,
    key: [u8; 32],
}

impl StoreDir {
    /// Creates a new store for `root` (already canonical) in `dir`.
    pub fn create(
        dir: &Path,
        root: &Path,
        in_project: bool,
        max_file_size: u64,
    ) -> Result<StoreDir> {
        if dir.join("meta").exists() {
            return Err(Error::AlreadyInitialized(format!(
                "already initialized: {}",
                display_path(dir)
            )));
        }
        create_private_dir_all(dir)?;
        for sub in ["blobs", "checkpoints", "tmp"] {
            create_private_dir_all(&dir.join(sub))?;
        }
        let key = random_bytes(32)?;
        let key_path = dir.join("key");
        let mut kf = create_new_private(&key_path)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    // Leftover from an interrupted init: replace it.
                    fs::remove_file(&key_path).and_then(|()| create_new_private(&key_path))
                } else {
                    Err(e)
                }
            })
            .ctx(|| "creating key file".into())?;
        kf.write_all(to_hex(&key).as_bytes())
            .and_then(|()| kf.sync_all())
            .ctx(|| "writing key file".into())?;
        let log = dir.join("log");
        if !log.exists() {
            drop(create_new_private(&log).ctx(|| "creating log".into())?);
        }
        let meta = Meta {
            root: root.to_path_buf(),
            project_id: project_id(root),
            created_ns: now_ns(),
            max_file_size,
            in_project,
        };
        write_atomic_private(
            &dir.join("meta"),
            &dir.join("tmp"),
            encode_meta(&meta).as_bytes(),
        )?;
        StoreDir::open_at(dir, root)
    }

    /// Opens an existing store at `dir`, verifying it belongs to `root`.
    pub fn open_at(dir: &Path, root: &Path) -> Result<StoreDir> {
        let md = fs::symlink_metadata(dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotInitialized(format!("no store at {}", display_path(dir)))
            } else {
                Error::io(format!("stat {}", display_path(dir)), e)
            }
        })?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(Error::Unsafe(format!(
                "store path {} is not a plain directory (symlink?)",
                display_path(dir)
            )));
        }
        let text = match read_small(&dir.join("meta"), 64 * 1024) {
            Ok(t) => t,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotInitialized(format!(
                    "no store at {}",
                    display_path(dir)
                )));
            }
            Err(e) => return Err(e),
        };
        let text =
            String::from_utf8(text).map_err(|_| Error::Format("meta is not UTF-8".into()))?;
        let meta = parse_meta(&text, dir)?;
        if meta.root != root {
            return Err(Error::Unsafe(format!(
                "store {} belongs to a different project root ({}), not {}",
                display_path(dir),
                display(meta.root.as_os_str().as_bytes()),
                display(root.as_os_str().as_bytes())
            )));
        }
        let key_text = read_small(&dir.join("key"), 1024)?;
        let key_hex =
            String::from_utf8(key_text).map_err(|_| Error::Format("key is not UTF-8".into()))?;
        let key = digest_from_hex(key_hex.trim())
            .ok_or_else(|| Error::Format("corrupt key file".into()))?;
        Ok(StoreDir {
            dir: dir.to_path_buf(),
            root: root.to_path_buf(),
            meta,
            key,
        })
    }

    /// Finds the store for the project containing `start` (or exactly `start`
    /// if `explicit`). Checks `<ancestor>/.agent-undo` and the external state
    /// directory for each ancestor of the canonical start directory.
    pub fn locate(start: &Path, explicit: bool, state_base: Option<&Path>) -> Result<StoreDir> {
        let canon = fs::canonicalize(start).ctx(|| format!("resolving {}", display_path(start)))?;
        let mut cand = Some(canon.as_path());
        while let Some(dir) = cand {
            let inproj = dir.join(IN_PROJECT_DIR);
            if fs::symlink_metadata(inproj.join("meta")).is_ok() {
                return StoreDir::open_at(&inproj, dir);
            }
            if let Some(base) = state_base {
                let ext = external_store_dir(base, dir);
                if ext.join("meta").is_file() {
                    return StoreDir::open_at(&ext, dir);
                }
            }
            if explicit {
                break;
            }
            cand = dir.parent();
        }
        Err(Error::NotInitialized(format!(
            "no agent-undo store found for {} (run `agent-undo init`)",
            display_path(&canon)
        )))
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.dir.join("blobs")
    }

    pub fn checkpoints_dir(&self) -> PathBuf {
        self.dir.join("checkpoints")
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("log")
    }

    pub fn pruned_path(&self) -> PathBuf {
        self.dir.join("pruned")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("lock")
    }
}

#[cfg(test)]
mod tests;
