//! The on-disk store: layout, metadata, locking, content-addressed blobs and
//! the hash-chained checkpoint log.
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

use crate::entry::{MAX_LINE, read_capped_line};
use crate::error::{Ctx, Error, Result};
use crate::esc::{display, pct_decode, pct_encode};
use crate::fsops::{
    create_new_private, create_private_dir_all, display_path, unique_suffix, write_atomic_private,
};
use crate::hash::{Digest, Sha256, digest_from_hex, sha256, to_hex};
use crate::util::{now_ns, random_bytes};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const STORE_HEADER: &str = "agent-undo-store v1";
pub const DEFAULT_MAX_FILE_SIZE: u64 = 25 * 1024 * 1024;
pub const IN_PROJECT_DIR: &str = ".agent-undo";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_LOG_ENTRIES: usize = 1_000_000;
pub const MAX_LABEL_BYTES: usize = 200;
const MAX_COMMAND_BYTES: usize = 4096;

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
pub fn state_base_from(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Result<PathBuf> {
    if let Some(x) = get("XDG_STATE_HOME")
        && !x.is_empty()
        && x.as_bytes().first() == Some(&b'/')
    {
        return Ok(PathBuf::from(x));
    }
    match get("HOME") {
        Some(h) if !h.is_empty() && h.as_bytes().first() == Some(&b'/') => {
            Ok(PathBuf::from(h).join(".local").join("state"))
        }
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

// ---------------------------------------------------------------- log types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkptKind {
    Baseline,
    Run,
    Manual,
    /// Changes made outside any recorded run, found by the snapshot before a run.
    External,
    Watch,
    /// Automatic snapshot taken before `undo`/`restore` modifies anything.
    PreUndo,
    Undo,
    Restore,
}

impl CkptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CkptKind::Baseline => "baseline",
            CkptKind::Run => "run",
            CkptKind::Manual => "manual",
            CkptKind::External => "external",
            CkptKind::Watch => "watch",
            CkptKind::PreUndo => "pre-undo",
            CkptKind::Undo => "undo",
            CkptKind::Restore => "restore",
        }
    }

    pub fn parse(s: &str) -> Option<CkptKind> {
        Some(match s {
            "baseline" => CkptKind::Baseline,
            "run" => CkptKind::Run,
            "manual" => CkptKind::Manual,
            "external" => CkptKind::External,
            "watch" => CkptKind::Watch,
            "pre-undo" => CkptKind::PreUndo,
            "undo" => CkptKind::Undo,
            "restore" => CkptKind::Restore,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitInfo {
    Code(i32),
    Signal(i32),
}

impl ExitInfo {
    fn encode(self) -> String {
        match self {
            ExitInfo::Code(c) => format!("exit:{c}"),
            ExitInfo::Signal(s) => format!("signal:{s}"),
        }
    }

    fn decode(s: &str) -> Option<Option<ExitInfo>> {
        if s == "-" {
            return Some(None);
        }
        let (k, v) = s.split_once(':')?;
        let n: i32 = v.parse().ok()?;
        match k {
            "exit" => Some(Some(ExitInfo::Code(n))),
            "signal" => Some(Some(ExitInfo::Signal(n))),
            _ => None,
        }
    }

    /// Conventional shell-style status.
    pub fn status_code(self) -> i32 {
        match self {
            ExitInfo::Code(c) => c,
            ExitInfo::Signal(s) => 128 + s,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    pub mode_changed: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.created + self.modified + self.deleted + self.mode_changed
    }

    pub fn add(&mut self, kind: crate::entry::ChangeKind) {
        use crate::entry::ChangeKind::*;
        match kind {
            Created => self.created += 1,
            Modified => self.modified += 1,
            Deleted => self.deleted += 1,
            ModeChanged => self.mode_changed += 1,
        }
    }
}

/// One checkpoint record in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u64,
    pub session: u64,
    pub kind: CkptKind,
    pub time_ns: i64,
    pub exit: Option<ExitInfo>,
    pub label: Option<Vec<u8>>,
    /// Command line (arguments) for `run` checkpoints.
    pub command: Option<Vec<Vec<u8>>>,
    pub manifest: Digest,
    pub changes: Digest,
    pub counts: Counts,
    pub entries: u64,
    /// For `undo`/`restore`/`pre-undo`: the checkpoint this relates to.
    pub reference: Option<u64>,
    pub prev: Digest,
    pub hash: Digest,
}

fn enc_opt_bytes(b: Option<&[u8]>) -> String {
    match b {
        None => "-".to_string(),
        Some(b) => format!("={}", pct_encode(b)),
    }
}

fn dec_opt_bytes(s: &str) -> Option<Option<Vec<u8>>> {
    if s == "-" {
        return Some(None);
    }
    pct_decode(s.strip_prefix('=')?).map(Some)
}

/// Truncates a command line to a bounded size for the log.
pub fn bounded_command(args: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for a in args {
        total = total.saturating_add(a.len() + 1);
        if total > MAX_COMMAND_BYTES {
            out.push(b"...[truncated]".to_vec());
            break;
        }
        out.push(a.clone());
    }
    out
}

impl LogEntry {
    fn body(&self) -> String {
        let cmd = self.command.as_ref().map(|args| {
            args.iter()
                .map(|a| pct_encode(a))
                .collect::<Vec<_>>()
                .join(" ")
        });
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.seq,
            self.session,
            self.kind.as_str(),
            self.time_ns,
            self.exit.map_or_else(|| "-".to_string(), ExitInfo::encode),
            enc_opt_bytes(self.label.as_deref()),
            enc_opt_bytes(cmd.as_deref().map(str::as_bytes)),
            to_hex(&self.manifest),
            to_hex(&self.changes),
            self.counts.created,
            self.counts.modified,
            self.counts.deleted,
            self.counts.mode_changed,
            self.entries,
            self.reference
                .map_or_else(|| "-".to_string(), |r| r.to_string()),
            to_hex(&self.prev),
        )
    }

    /// Computes the chain hash over the record body (which includes `prev`).
    pub fn compute_hash(&self) -> Digest {
        sha256(self.body().as_bytes())
    }

    /// Serializes the record including its hash, without trailing newline.
    pub fn encode(&self) -> String {
        format!("{}\t{}", self.body(), to_hex(&self.hash))
    }

    pub fn decode(line: &str) -> Result<LogEntry> {
        let bad = |why: &str| Error::Format(format!("bad log record: {why}"));
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 17 {
            return Err(bad("wrong field count"));
        }
        let num = |i: usize, name: &str| -> Result<u64> {
            f.get(i)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| bad(name))
        };
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let command = match dec_opt_bytes(get(6)).ok_or_else(|| bad("command"))? {
            None => None,
            Some(joined) => {
                let s = String::from_utf8(joined).map_err(|_| bad("command text"))?;
                let mut args = Vec::new();
                for part in s.split(' ') {
                    args.push(pct_decode(part).ok_or_else(|| bad("command encoding"))?);
                }
                Some(args)
            }
        };
        let hex = |i: usize, name: &str| digest_from_hex(get(i)).ok_or_else(|| bad(name));
        Ok(LogEntry {
            seq: num(0, "seq")?,
            session: num(1, "session")?,
            kind: CkptKind::parse(get(2)).ok_or_else(|| bad("kind"))?,
            time_ns: get(3).parse().map_err(|_| bad("time"))?,
            exit: ExitInfo::decode(get(4)).ok_or_else(|| bad("exit"))?,
            label: dec_opt_bytes(get(5)).ok_or_else(|| bad("label"))?,
            command,
            manifest: hex(7, "manifest hash")?,
            changes: hex(8, "changes hash")?,
            counts: Counts {
                created: num(9, "created")?,
                modified: num(10, "modified")?,
                deleted: num(11, "deleted")?,
                mode_changed: num(12, "mode_changed")?,
            },
            entries: num(13, "entries")?,
            reference: match get(14) {
                "-" => None,
                s => Some(s.parse().map_err(|_| bad("reference"))?),
            },
            prev: hex(15, "prev")?,
            hash: hex(16, "hash")?,
        })
    }
}

// ------------------------------------------------------------------- locking

/// Holds the store lock until dropped.
#[derive(Debug)]
pub struct LockGuard {
    _file: File,
    pub exclusive: bool,
}

fn try_lock(file: &File, exclusive: bool) -> Result<()> {
    use std::fs::TryLockError;
    let r = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match r {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Error::Locked(
            "another agent-undo operation is using this store (lock held)".into(),
        )),
        Err(TryLockError::Error(e)) => Err(Error::io("locking store", e)),
    }
}

// --------------------------------------------------------------------- store

pub struct Store {
    pub dir: PathBuf,
    pub root: PathBuf,
    pub meta: Meta,
    key: [u8; 32],
    lock: Option<LockGuard>,
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
        root: PathBuf::from(std::ffi::OsString::from_vec(
            root.ok_or_else(|| bad("root"))?,
        )),
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

fn read_small(path: &Path, cap: u64) -> Result<Vec<u8>> {
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

impl Store {
    /// Creates a new store for `root` (already canonical) in `dir`.
    pub fn create(dir: &Path, root: &Path, in_project: bool, max_file_size: u64) -> Result<Store> {
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
        let mut kf = create_new_private(&dir.join("key"))
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    // Leftover from an interrupted init: replace it.
                    fs::remove_file(dir.join("key"))
                        .and_then(|()| create_new_private(&dir.join("key")))
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
        Store::open_at(dir, root)
    }

    /// Opens an existing store at `dir`, verifying it belongs to `root`.
    pub fn open_at(dir: &Path, root: &Path) -> Result<Store> {
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
        let meta_path = dir.join("meta");
        let text = match read_small(&meta_path, 64 * 1024) {
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
        Ok(Store {
            dir: dir.to_path_buf(),
            root: root.to_path_buf(),
            meta,
            key,
            lock: None,
        })
    }

    /// Finds the store for the project containing `start` (or exactly `explicit`).
    /// Checks `<ancestor>/.agent-undo` and the external state directory for each
    /// ancestor of the canonical start directory.
    pub fn locate(start: &Path, explicit: bool, state_base: Option<&Path>) -> Result<Store> {
        let canon = fs::canonicalize(start).ctx(|| format!("resolving {}", display_path(start)))?;
        let mut cand = Some(canon.as_path());
        while let Some(dir) = cand {
            let inproj = dir.join(IN_PROJECT_DIR);
            if fs::symlink_metadata(inproj.join("meta")).is_ok() {
                return Store::open_at(&inproj, dir);
            }
            if let Some(base) = state_base {
                let ext = external_store_dir(base, dir);
                if ext.join("meta").is_file() {
                    return Store::open_at(&ext, dir);
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

    // ------------------------------------------------------------- locking

    pub fn lock_exclusive(&mut self) -> Result<()> {
        self.lock_with(true)
    }

    pub fn lock_shared(&mut self) -> Result<()> {
        self.lock_with(false)
    }

    fn lock_with(&mut self, exclusive: bool) -> Result<()> {
        if self
            .lock
            .as_ref()
            .is_some_and(|l| l.exclusive || !exclusive)
        {
            return Ok(());
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.dir.join("lock"))
            .ctx(|| "opening lock file".into())?;
        try_lock(&f, exclusive)?;
        self.lock = Some(LockGuard {
            _file: f,
            exclusive,
        });
        Ok(())
    }

    pub fn unlock(&mut self) {
        self.lock = None;
    }

    pub fn holds_exclusive(&self) -> bool {
        self.lock.as_ref().is_some_and(|l| l.exclusive)
    }

    /// Mutating operations call this first; it is a guard against internal misuse.
    pub fn require_exclusive(&self) -> Result<()> {
        if self.holds_exclusive() {
            Ok(())
        } else {
            Err(Error::Other(
                "internal error: mutating operation without the exclusive store lock".into(),
            ))
        }
    }

    /// Whether another process currently holds an exclusive lock (non-blocking probe).
    pub fn is_locked_by_other(&self) -> bool {
        if self.lock.is_some() {
            return false;
        }
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("lock"))
        {
            Ok(f) => matches!(f.try_lock_shared(), Err(std::fs::TryLockError::WouldBlock)),
            Err(_) => false,
        }
    }

    // --------------------------------------------------------------- paths

    pub fn tmp_dir(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    pub fn tmp_path(&self, kind: &str) -> PathBuf {
        self.tmp_dir().join(format!("{kind}-{}", unique_suffix()))
    }

    pub fn manifest_path(&self, seq: u64) -> PathBuf {
        self.dir
            .join("checkpoints")
            .join(format!("{seq:08}.manifest"))
    }

    pub fn changes_path(&self, seq: u64) -> PathBuf {
        self.dir
            .join("checkpoints")
            .join(format!("{seq:08}.changes"))
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("log")
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Keyed hash-of-hash recorded for sensitive files.
    pub fn sensitive_id(&self, content_hash: &Digest) -> Digest {
        let mut msg = Vec::with_capacity(5 + 32);
        msg.extend_from_slice(b"sens\0");
        msg.extend_from_slice(content_hash);
        crate::hash::hmac_sha256(&self.key, &msg)
    }

    // --------------------------------------------------------------- blobs

    pub fn blob_path(&self, d: &Digest) -> PathBuf {
        let hex = to_hex(d);
        self.dir
            .join("blobs")
            .join(hex.get(..2).unwrap_or("00"))
            .join(&hex)
    }

    pub fn has_blob(&self, d: &Digest) -> bool {
        fs::symlink_metadata(self.blob_path(d)).is_ok_and(|m| m.is_file())
    }

    pub fn open_blob(&self, d: &Digest) -> Result<File> {
        let p = self.blob_path(d);
        File::open(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Integrity(format!("blob {} is missing from the store", to_hex(d)))
            } else {
                Error::io(format!("opening blob {}", to_hex(d)), e)
            }
        })
    }

    /// Reads a blob fully, refusing blobs larger than `cap` bytes.
    pub fn read_blob_capped(&self, d: &Digest, cap: u64) -> Result<Vec<u8>> {
        let f = self.open_blob(d)?;
        let mut buf = Vec::new();
        f.take(cap + 1)
            .read_to_end(&mut buf)
            .ctx(|| format!("reading blob {}", to_hex(d)))?;
        if buf.len() as u64 > cap {
            return Err(Error::Limit(format!(
                "blob {} larger than {cap} bytes",
                to_hex(d)
            )));
        }
        Ok(buf)
    }

    /// Starts writing a blob into the temp directory.
    pub fn begin_blob(&self) -> Result<BlobWriter> {
        let tmp = self.tmp_path("blob");
        let file = create_new_private(&tmp).ctx(|| "creating temp blob".into())?;
        Ok(BlobWriter {
            file: Some(file),
            tmp,
            hasher: Sha256::new(),
            len: 0,
        })
    }

    /// Re-hashes a stored blob; returns its actual digest.
    pub fn hash_blob(&self, d: &Digest) -> Result<Digest> {
        let mut f = self.open_blob(d)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .ctx(|| format!("reading blob {}", to_hex(d)))?;
            if n == 0 {
                break;
            }
            h.update(buf.get(..n).unwrap_or(&[]));
        }
        Ok(h.finalize())
    }

    /// Lists all blob digests present in the store (names that are not valid
    /// digests are reported through `on_bad`).
    pub fn for_each_blob(
        &self,
        mut on_blob: impl FnMut(Digest, &Path) -> Result<()>,
        mut on_bad: impl FnMut(&Path),
    ) -> Result<()> {
        let blobs = self.dir.join("blobs");
        let mut shards: Vec<_> = fs::read_dir(&blobs)
            .ctx(|| "listing blobs".into())?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .collect();
        shards.sort();
        for shard in shards {
            if !shard.is_dir() {
                on_bad(&shard);
                continue;
            }
            let mut files: Vec<_> = fs::read_dir(&shard)
                .ctx(|| "listing blob shard".into())?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .collect();
            files.sort();
            for f in files {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
                match digest_from_hex(name) {
                    Some(d)
                        if f.is_file()
                            && shard.file_name().and_then(|n| n.to_str()) == name.get(..2) =>
                    {
                        on_blob(d, &f)?;
                    }
                    _ => on_bad(&f),
                }
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------- log

    /// Streams the log, validating the hash chain and sequence numbers.
    pub fn for_each_log(&self, mut f: impl FnMut(&LogEntry) -> Result<()>) -> Result<()> {
        let file = File::open(self.log_path()).ctx(|| "opening log".into())?;
        let mut r = BufReader::new(file);
        let mut buf = Vec::new();
        let mut prev = [0u8; 32];
        let mut expect_seq = 1u64;
        let mut n = 0usize;
        while read_capped_line(&mut r, &mut buf).map_err(|e| Error::io("reading log", e))? {
            n += 1;
            if n > MAX_LOG_ENTRIES {
                return Err(Error::Limit("log has too many entries".into()));
            }
            let line = std::str::from_utf8(&buf)
                .map_err(|_| Error::Integrity("log contains non-UTF-8 data".into()))?;
            let e = LogEntry::decode(line)
                .map_err(|e| Error::Integrity(format!("log entry {n}: {e}")))?;
            if e.seq != expect_seq {
                return Err(Error::Integrity(format!(
                    "log entry {n}: sequence {} where {expect_seq} was expected",
                    e.seq
                )));
            }
            if e.prev != prev {
                return Err(Error::Integrity(format!(
                    "log entry {}: hash chain broken (previous hash does not match)",
                    e.seq
                )));
            }
            if e.compute_hash() != e.hash {
                return Err(Error::Integrity(format!(
                    "log entry {}: record hash mismatch (entry was modified)",
                    e.seq
                )));
            }
            prev = e.hash;
            expect_seq += 1;
            f(&e)?;
        }
        Ok(())
    }

    pub fn read_log(&self) -> Result<Vec<LogEntry>> {
        let mut v = Vec::new();
        self.for_each_log(|e| {
            v.push(e.clone());
            Ok(())
        })?;
        Ok(v)
    }

    pub fn last_entry(&self) -> Result<Option<LogEntry>> {
        let mut last = None;
        self.for_each_log(|e| {
            last = Some(e.clone());
            Ok(())
        })?;
        Ok(last)
    }

    /// Fills in `prev`/`hash` and appends the record (fsynced).
    pub fn append_log(&self, mut e: LogEntry, prev: Option<&LogEntry>) -> Result<LogEntry> {
        self.require_exclusive()?;
        e.prev = prev.map_or([0u8; 32], |p| p.hash);
        e.hash = e.compute_hash();
        let mut line = e.encode();
        line.push('\n');
        if line.len() > MAX_LINE {
            return Err(Error::Limit("log record too large".into()));
        }
        let mut f = OpenOptions::new()
            .append(true)
            .open(self.log_path())
            .ctx(|| "opening log for append".into())?;
        f.write_all(line.as_bytes())
            .and_then(|()| f.sync_all())
            .ctx(|| "appending to log".into())?;
        Ok(e)
    }

    // -------------------------------------------------------------- pruned

    pub fn read_pruned(&self) -> Result<BTreeSet<u64>> {
        let p = self.dir.join("pruned");
        let text = match read_small(&p, 16 * 1024 * 1024) {
            Ok(t) => t,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(e) => return Err(e),
        };
        let text = String::from_utf8(text)
            .map_err(|_| Error::Format("pruned list is not UTF-8".into()))?;
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.parse::<u64>()
                    .map_err(|_| Error::Format("bad pruned list".into()))
            })
            .collect()
    }

    pub fn append_pruned(&self, seqs: &[u64]) -> Result<()> {
        self.require_exclusive()?;
        if seqs.is_empty() {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dir.join("pruned"))
            .ctx(|| "opening pruned list".into())?;
        let mut text = String::new();
        for s in seqs {
            text.push_str(&format!("{s}\n"));
        }
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .ctx(|| "writing pruned list".into())
    }

    /// Opens a checkpoint's manifest for streaming.
    pub fn open_manifest(&self, seq: u64) -> Result<crate::entry::ManifestReader<BufReader<File>>> {
        let p = self.manifest_path(seq);
        let f = File::open(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Integrity(format!(
                    "manifest of checkpoint #{seq} is missing (pruned or deleted)"
                ))
            } else {
                Error::io(format!("opening manifest #{seq}"), e)
            }
        })?;
        crate::entry::ManifestReader::new(BufReader::new(f))
    }

    /// Opens a checkpoint's change set for streaming.
    pub fn open_changes(&self, seq: u64) -> Result<crate::entry::ChangesReader<BufReader<File>>> {
        let p = self.changes_path(seq);
        let f = File::open(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Integrity(format!(
                    "change set of checkpoint #{seq} is missing (pruned or deleted)"
                ))
            } else {
                Error::io(format!("opening changes #{seq}"), e)
            }
        })?;
        crate::entry::ChangesReader::new(BufReader::new(f))
    }
}

/// A blob being written; becomes visible only through [`BlobWriter::commit`].
pub struct BlobWriter {
    file: Option<File>,
    tmp: PathBuf,
    hasher: Sha256,
    len: u64,
}

impl BlobWriter {
    pub fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.hasher.update(chunk);
        self.len += chunk.len() as u64;
        match self.file.as_mut() {
            Some(f) => f.write_all(chunk).ctx(|| "writing blob".into()),
            None => Err(Error::Other("blob writer already finished".into())),
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Finishes the blob; it is stored under its actual digest, which must equal
    /// `expected` (otherwise the temp file is removed and `Ok(false)` returned).
    pub fn commit(mut self, store: &Store, expected: &Digest) -> Result<bool> {
        let actual = self.hasher.clone().finalize();
        let file = self.file.take();
        if let Some(f) = file {
            f.sync_all().ctx(|| "syncing blob".into())?;
        }
        if &actual != expected {
            let _ = fs::remove_file(&self.tmp);
            return Ok(false);
        }
        let dest = store.blob_path(&actual);
        if let Some(parent) = dest.parent() {
            create_private_dir_all(parent)?;
        }
        fs::rename(&self.tmp, &dest).ctx(|| "storing blob".into())?;
        Ok(true)
    }

    /// Discards the partially written blob.
    pub fn abort(mut self) {
        self.file = None;
        let _ = fs::remove_file(&self.tmp);
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.file = None;
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Reads a whole file under `cap` bytes (used for `.agent-undoignore`).
pub fn read_file_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => read_small(path, cap).map(Some),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(format!("stat {}", display_path(path)), e)),
    }
}

/// Utility for tests and doctor: lists names in a directory.
pub fn list_dir_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("au-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::canonicalize(&p).unwrap()
    }

    fn mk(name: &str) -> (PathBuf, Store) {
        let base = tmp(name);
        let root = base.join("proj");
        fs::create_dir_all(&root).unwrap();
        let dir = base.join("state");
        let mut s = Store::create(&dir, &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
        s.lock_exclusive().unwrap();
        (base, s)
    }

    fn sample_entry(seq: u64) -> LogEntry {
        LogEntry {
            seq,
            session: 1,
            kind: CkptKind::Run,
            time_ns: 5,
            exit: Some(ExitInfo::Code(3)),
            label: Some(b"my label\n".to_vec()),
            command: Some(vec![
                b"sh".to_vec(),
                b"-c".to_vec(),
                b"echo hi; \x1b[0m".to_vec(),
            ]),
            manifest: sha256(b"m"),
            changes: sha256(b"c"),
            counts: Counts {
                created: 1,
                modified: 2,
                deleted: 3,
                mode_changed: 4,
            },
            entries: 9,
            reference: Some(2),
            prev: [0; 32],
            hash: [0; 32],
        }
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
                    .map(|(_, v)| std::ffi::OsString::from(*v))
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
        // relative XDG_STATE_HOME is ignored per the XDG spec
        assert_eq!(
            state_base_from(env(vec![("XDG_STATE_HOME", "rel"), ("HOME", "/h")])).unwrap(),
            PathBuf::from("/h/.local/state")
        );
        assert!(state_base_from(env(vec![])).is_err());
        assert!(state_base_from(env(vec![("HOME", "relative")])).is_err());
    }

    #[test]
    fn create_sets_up_private_layout() {
        let (base, s) = mk("layout");
        for sub in ["blobs", "checkpoints", "tmp"] {
            let m = fs::metadata(s.dir.join(sub)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o700, "{sub}");
        }
        for f in ["meta", "key", "log"] {
            let m = fs::metadata(s.dir.join(f)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "{f}");
        }
        assert_eq!(
            fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(s.meta.max_file_size, DEFAULT_MAX_FILE_SIZE);
        drop(base);
    }

    #[test]
    fn create_twice_fails() {
        let (_b, s) = mk("twice");
        let r = Store::create(&s.dir, &s.root, false, 1);
        assert!(matches!(r, Err(Error::AlreadyInitialized(_))));
    }

    #[test]
    fn open_rejects_other_root() {
        let (base, s) = mk("otherroot");
        let other = base.join("other");
        fs::create_dir_all(&other).unwrap();
        assert!(Store::open_at(&s.dir, &other).is_err());
        assert!(Store::open_at(&s.dir, &s.root).is_ok());
    }

    #[test]
    fn open_rejects_symlinked_store_dir() {
        let (base, s) = mk("symstore");
        let link = base.join("linkstate");
        std::os::unix::fs::symlink(&s.dir, &link).unwrap();
        assert!(matches!(
            Store::open_at(&link, &s.root),
            Err(Error::Unsafe(_))
        ));
    }

    #[test]
    fn open_missing_is_not_initialized() {
        let base = tmp("missing");
        assert!(matches!(
            Store::open_at(&base.join("nope"), &base),
            Err(Error::NotInitialized(_))
        ));
    }

    #[test]
    fn locate_finds_store_from_subdirectory() {
        let (base, s) = mk("locate");
        let sub = s.root.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        let state_base = base.join("state").parent().unwrap().to_path_buf();
        // The store was created at base/state, not under the XDG layout; create one properly.
        let ext = external_store_dir(&state_base, &s.root);
        Store::create(&ext, &s.root, false, 1000).unwrap();
        let found = Store::locate(&sub, false, Some(&state_base)).unwrap();
        assert_eq!(found.dir, ext);
        assert!(Store::locate(&sub, true, Some(&state_base)).is_err());
        let found = Store::locate(&s.root, true, Some(&state_base)).unwrap();
        assert_eq!(found.meta.max_file_size, 1000);
    }

    #[test]
    fn in_project_store_is_found_before_external() {
        let base = tmp("inproj");
        let root = base.join("proj");
        let inner = root.join(IN_PROJECT_DIR);
        fs::create_dir_all(&root).unwrap();
        Store::create(&inner, &root, true, 5).unwrap();
        let found = Store::locate(&root, true, None).unwrap();
        assert!(found.meta.in_project);
        assert_eq!(found.dir, inner);
    }

    #[test]
    fn locate_without_store_reports_not_initialized() {
        let base = tmp("nolocate");
        assert!(matches!(
            Store::locate(&base, false, Some(&base.join("state"))),
            Err(Error::NotInitialized(_))
        ));
    }

    #[test]
    fn lock_is_exclusive_between_handles() {
        let (_b, s) = mk("lock");
        let mut other = Store::open_at(&s.dir, &s.root).unwrap();
        assert!(matches!(other.lock_exclusive(), Err(Error::Locked(_))));
        assert!(matches!(other.lock_shared(), Err(Error::Locked(_))));
        assert!(!s.is_locked_by_other());
        assert!(other.is_locked_by_other());
        drop(s);
        other.lock_exclusive().unwrap();
    }

    #[test]
    fn shared_locks_coexist_but_block_exclusive() {
        let (_b, mut s) = mk("shared");
        s.unlock();
        s.lock_shared().unwrap();
        let mut a = Store::open_at(&s.dir, &s.root).unwrap();
        a.lock_shared().unwrap();
        let mut b = Store::open_at(&s.dir, &s.root).unwrap();
        assert!(matches!(b.lock_exclusive(), Err(Error::Locked(_))));
    }

    #[test]
    fn lock_released_on_drop() {
        let (_b, mut s) = mk("unlock");
        s.unlock();
        let mut o = Store::open_at(&s.dir, &s.root).unwrap();
        o.lock_exclusive().unwrap();
        o.unlock();
        s.lock_exclusive().unwrap();
    }

    #[test]
    fn mutation_requires_lock() {
        let (_b, mut s) = mk("requirelock");
        s.unlock();
        assert!(s.append_log(sample_entry(1), None).is_err());
    }

    #[test]
    fn log_entry_round_trip_including_hostile_text() {
        let mut e = sample_entry(1);
        e.hash = e.compute_hash();
        let line = e.encode();
        assert!(!line.contains('\n'));
        let back = LogEntry::decode(&line).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.command.unwrap()[2], b"echo hi; \x1b[0m");
    }

    #[test]
    fn log_chain_append_and_read() {
        let (_b, s) = mk("chain");
        let e1 = s.append_log(sample_entry(1), None).unwrap();
        let e2 = s.append_log(sample_entry(2), Some(&e1)).unwrap();
        let all = s.read_log().unwrap();
        assert_eq!(all, vec![e1.clone(), e2]);
        assert_eq!(all[1].prev, e1.hash);
        assert_eq!(s.last_entry().unwrap().unwrap().seq, 2);
    }

    #[test]
    fn log_tamper_is_detected() {
        let (_b, s) = mk("tamper");
        let e1 = s.append_log(sample_entry(1), None).unwrap();
        s.append_log(sample_entry(2), Some(&e1)).unwrap();
        let text = fs::read_to_string(s.log_path()).unwrap();
        let tampered = text.replacen("\texit:3\t", "\texit:0\t", 1);
        assert_ne!(text, tampered);
        fs::write(s.log_path(), tampered).unwrap();
        assert!(matches!(s.read_log(), Err(Error::Integrity(_))));
    }

    #[test]
    fn log_deleted_middle_entry_is_detected() {
        let (_b, s) = mk("dropmiddle");
        let e1 = s.append_log(sample_entry(1), None).unwrap();
        let e2 = s.append_log(sample_entry(2), Some(&e1)).unwrap();
        s.append_log(sample_entry(3), Some(&e2)).unwrap();
        let text = fs::read_to_string(s.log_path()).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        fs::write(s.log_path(), kept.join("\n") + "\n").unwrap();
        assert!(matches!(s.read_log(), Err(Error::Integrity(_))));
    }

    #[test]
    fn log_reordered_entries_are_detected() {
        let (_b, s) = mk("reorder");
        let e1 = s.append_log(sample_entry(1), None).unwrap();
        s.append_log(sample_entry(2), Some(&e1)).unwrap();
        let text = fs::read_to_string(s.log_path()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(0, 1);
        fs::write(s.log_path(), lines.join("\n") + "\n").unwrap();
        assert!(s.read_log().is_err());
    }

    #[test]
    fn log_garbage_is_rejected() {
        let (_b, s) = mk("garbage");
        fs::write(s.log_path(), "not a record\n").unwrap();
        assert!(matches!(s.read_log(), Err(Error::Integrity(_))));
    }

    #[test]
    fn blob_commit_and_dedupe() {
        let (_b, s) = mk("blob");
        let data = b"hello blob";
        let d = sha256(data);
        let mut w = s.begin_blob().unwrap();
        w.write(data).unwrap();
        assert!(w.commit(&s, &d).unwrap());
        assert!(s.has_blob(&d));
        assert_eq!(s.read_blob_capped(&d, 100).unwrap(), data);
        assert_eq!(s.hash_blob(&d).unwrap(), d);
        assert_eq!(
            fs::metadata(s.blob_path(&d)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn blob_with_wrong_expected_hash_is_discarded() {
        let (_b, s) = mk("blobmismatch");
        let mut w = s.begin_blob().unwrap();
        w.write(b"abc").unwrap();
        assert!(!w.commit(&s, &sha256(b"other")).unwrap());
        assert!(list_dir_names(&s.tmp_dir()).is_empty());
        assert!(!s.has_blob(&sha256(b"abc")));
    }

    #[test]
    fn dropped_blob_writer_cleans_temp_file() {
        let (_b, s) = mk("blobdrop");
        {
            let mut w = s.begin_blob().unwrap();
            w.write(b"partial").unwrap();
        }
        assert!(list_dir_names(&s.tmp_dir()).is_empty());
    }

    #[test]
    fn read_blob_capped_enforces_cap() {
        let (_b, s) = mk("blobcap");
        let d = sha256(b"0123456789");
        let mut w = s.begin_blob().unwrap();
        w.write(b"0123456789").unwrap();
        w.commit(&s, &d).unwrap();
        assert!(s.read_blob_capped(&d, 9).is_err());
        assert!(s.read_blob_capped(&d, 10).is_ok());
    }

    #[test]
    fn missing_blob_is_an_integrity_error() {
        let (_b, s) = mk("blobmissing");
        assert!(matches!(
            s.open_blob(&sha256(b"zzz")),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn for_each_blob_lists_and_flags_strays() {
        let (_b, s) = mk("blobiter");
        for data in [&b"a"[..], b"b", b"c"] {
            let d = sha256(data);
            let mut w = s.begin_blob().unwrap();
            w.write(data).unwrap();
            w.commit(&s, &d).unwrap();
        }
        fs::write(s.dir.join("blobs").join("stray.txt"), b"x").unwrap();
        let mut seen = 0;
        let mut bad = 0;
        s.for_each_blob(
            |_, _| {
                seen += 1;
                Ok(())
            },
            |_| bad += 1,
        )
        .unwrap();
        assert_eq!(seen, 3);
        assert_eq!(bad, 1);
    }

    #[test]
    fn sensitive_id_is_keyed_and_not_the_plain_hash() {
        let (_b, s) = mk("sens");
        let h = sha256(b"secret content");
        let id = s.sensitive_id(&h);
        assert_ne!(id, h);
        assert_eq!(id, s.sensitive_id(&h));
        let (_b2, s2) = mk("sens2");
        assert_ne!(
            s2.sensitive_id(&h),
            id,
            "different stores use different keys"
        );
    }

    #[test]
    fn pruned_list_round_trip() {
        let (_b, s) = mk("pruned");
        assert!(s.read_pruned().unwrap().is_empty());
        s.append_pruned(&[1, 2]).unwrap();
        s.append_pruned(&[5]).unwrap();
        assert_eq!(
            s.read_pruned().unwrap().into_iter().collect::<Vec<_>>(),
            vec![1, 2, 5]
        );
    }

    #[test]
    fn bounded_command_truncates() {
        let args: Vec<Vec<u8>> = (0..1000).map(|_| vec![b'a'; 100]).collect();
        let b = bounded_command(&args);
        assert!(b.len() < 100);
        assert_eq!(b.last().unwrap(), b"...[truncated]");
        let small = vec![b"ls".to_vec()];
        assert_eq!(bounded_command(&small), small);
    }

    #[test]
    fn exit_info_status_codes() {
        assert_eq!(ExitInfo::Code(3).status_code(), 3);
        assert_eq!(ExitInfo::Signal(9).status_code(), 137);
    }
}
