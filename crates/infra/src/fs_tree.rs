//! The real project directory: a streaming, sorted walk that classifies every
//! path, and the safe executor for undo/restore plan items.
//!
//! Memory is bounded: files are read through one fixed 64 KiB buffer and the
//! only per-directory allocation is the list of names in the directory being
//! walked (capped by [`MAX_DIR_ENTRIES`]).
//!
//! Safety properties enforced here: symlinks are recorded as links and never
//! followed; files are opened with `O_NOFOLLOW` plus an `fstat` identity check;
//! secret-bearing files are classified before any byte is written anywhere;
//! restores go through a temp file and `rename`, after re-validating every parent
//! directory with `lstat` immediately before the rename.

use crate::fsutil::{check_parents, create_new_private, join, open_regular, sibling_tmp};
use crate::layout::read_file_capped;
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::{
    BlobStore, BlobWriter, ScanOptions, ScanStats, ScanVisitor, WorkingTree,
};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::esc::display;
use agent_undo_domain::hash::{Digest, Sha256, to_hex};
use agent_undo_domain::ignore::{IgnoreSet, MAX_IGNORE_FILE_BYTES};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Op, Outcome, PlanItem};
use agent_undo_domain::policy::{FileClass, cache_usable, classify_file, sensitive_id};
use agent_undo_domain::secrets::{Scanner, sensitive_name};
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const IGNORE_FILE: &str = ".agent-undoignore";
pub const MAX_DIR_ENTRIES: usize = 200_000;
pub const MAX_DEPTH: usize = 256;
const BUF_SIZE: usize = 64 * 1024;
const MAX_WARNINGS: usize = 20;
const MAX_ATTEMPTS: u32 = 3;

pub struct FsTree {
    root: PathBuf,
    store_dir: PathBuf,
    max_file_size: u64,
    key: [u8; 32],
    blobs: crate::fs_blobs::FsBlobs,
}

impl FsTree {
    pub fn new(
        root: PathBuf,
        store_dir: &Path,
        max_file_size: u64,
        key: [u8; 32],
        blobs: crate::fs_blobs::FsBlobs,
    ) -> FsTree {
        FsTree {
            store_dir: fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.to_path_buf()),
            root,
            max_file_size,
            key,
            blobs,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn load_ignore(&self) -> Result<IgnoreSet> {
        match read_file_capped(&self.root.join(IGNORE_FILE), MAX_IGNORE_FILE_BYTES)? {
            Some(t) => IgnoreSet::with_user_patterns(&t)
                .map_err(|e| Error::Format(format!("{IGNORE_FILE}: {e}"))),
            None => Ok(IgnoreSet::defaults()),
        }
    }
}

fn ts(secs: i64, nsec: i64) -> i64 {
    secs.saturating_mul(1_000_000_000).saturating_add(nsec)
}

fn systime(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

enum CopyResult {
    Stored,
    Sensitive,
    Changed,
}

/// Classifies single paths: reads files, scans content, optionally stores blobs.
struct Classifier<'a> {
    tree: &'a FsTree,
    capture: bool,
    cache_cutoff_ns: Option<i64>,
    buf: Vec<u8>,
    stats: ScanStats,
}

impl<'a> Classifier<'a> {
    fn new(tree: &'a FsTree, capture: bool, cache_cutoff_ns: Option<i64>) -> Classifier<'a> {
        Classifier {
            tree,
            capture,
            cache_cutoff_ns,
            buf: vec![0u8; BUF_SIZE],
            stats: ScanStats::default(),
        }
    }

    fn warn(&mut self, msg: String) {
        self.stats.warnings_total += 1;
        if self.stats.warnings.len() < MAX_WARNINGS {
            self.stats.warnings.push(msg);
        }
    }

    fn entry_for(
        &mut self,
        abs: &Path,
        rel: &RelPath,
        md: &fs::Metadata,
        cached: Option<&Entry>,
    ) -> Result<Option<Entry>> {
        let ft = md.file_type();
        let mtime_ns = ts(md.mtime(), md.mtime_nsec());
        let ctime_ns = ts(md.ctime(), md.ctime_nsec());
        let mode = md.mode() & 0o7777;
        if ft.is_symlink() {
            let target = match fs::read_link(abs) {
                Ok(t) => t.into_os_string().into_vec(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    self.warn(format!("cannot read link {:?}: {e}", rel.display()));
                    return Ok(Some(Entry::unreadable(mode, md.len(), mtime_ns, ctime_ns)));
                }
            };
            return Ok(Some(match Entry::symlink(target, mtime_ns, ctime_ns) {
                Ok(e) => e,
                Err(_) => {
                    self.warn(format!(
                        "symlink {:?} has an unsupported target",
                        rel.display()
                    ));
                    Entry::unreadable(mode, md.len(), mtime_ns, ctime_ns)
                }
            }));
        }
        if ft.is_dir() {
            return Ok(Some(Entry::dir(mode, mtime_ns, ctime_ns)));
        }
        if !ft.is_file() {
            return Ok(Some(Entry::special(mode, mtime_ns, ctime_ns)));
        }
        let size = md.len();
        if let (Some(c), Some(cutoff)) = (cached, self.cache_cutoff_ns)
            && cache_usable(c, size, mtime_ns, ctime_ns, cutoff)
            && (c.kind() != Kind::File
                || !self.capture
                || c.digest().is_some_and(|d| self.tree.blobs.contains(&d)))
        {
            self.stats.files_cached += 1;
            return Ok(Some(c.with_mode(mode)));
        }
        self.hash_file(abs, rel, md, mode, mtime_ns, ctime_ns)
    }

    fn hash_file(
        &mut self,
        abs: &Path,
        rel: &RelPath,
        md: &fs::Metadata,
        mode: u32,
        mtime_ns: i64,
        ctime_ns: i64,
    ) -> Result<Option<Entry>> {
        let name_sensitive = sensitive_name(rel.as_bytes()).is_some();
        let unreadable = |md: &fs::Metadata| Entry::unreadable(mode, md.len(), mtime_ns, ctime_ns);
        for _attempt in 0..MAX_ATTEMPTS {
            let (mut file, _) = match open_regular(abs, Some(md)) {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    self.warn(format!("cannot read {:?}: {e}", rel.display()));
                    return Ok(Some(unreadable(md)));
                }
            };
            // Pass 1: hash and scan; nothing is written anywhere yet.
            let mut hasher = Sha256::new();
            let mut scanner = Scanner::new();
            let mut total: u64 = 0;
            loop {
                let n = match file.read(&mut self.buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.warn(format!("error reading {:?}: {e}", rel.display()));
                        return Ok(Some(unreadable(md)));
                    }
                };
                if n == 0 {
                    break;
                }
                let chunk = self.buf.get(..n).unwrap_or(&[]);
                hasher.update(chunk);
                if !name_sensitive {
                    scanner.feed(chunk);
                }
                total = total.saturating_add(n as u64);
            }
            self.stats.files_hashed += 1;
            self.stats.bytes_hashed = self.stats.bytes_hashed.saturating_add(total);
            let digest = hasher.finalize();
            let sens = |d: &Digest| {
                Entry::hashed(
                    Kind::Sensitive,
                    &sensitive_id(&self.tree.key, d),
                    mode,
                    total,
                    mtime_ns,
                    ctime_ns,
                )
            };
            match classify_file(
                name_sensitive,
                scanner.result().is_some(),
                total,
                self.tree.max_file_size,
            ) {
                FileClass::Sensitive => return Ok(Some(sens(&digest)?)),
                FileClass::TooLarge => {
                    return Ok(Some(Entry::hashed(
                        Kind::TooLarge,
                        &digest,
                        mode,
                        total,
                        mtime_ns,
                        ctime_ns,
                    )?));
                }
                FileClass::Storable => {}
            }
            let file_entry = Entry::hashed(Kind::File, &digest, mode, total, mtime_ns, ctime_ns)?;
            if !self.capture || self.tree.blobs.contains(&digest) {
                return Ok(Some(file_entry));
            }
            match self.copy_blob(&mut file, &digest, total, rel)? {
                CopyResult::Stored => {
                    self.stats.blobs_written += 1;
                    self.stats.bytes_stored = self.stats.bytes_stored.saturating_add(total);
                    return Ok(Some(file_entry));
                }
                CopyResult::Sensitive => return Ok(Some(sens(&digest)?)),
                CopyResult::Changed => continue,
            }
        }
        self.warn(format!(
            "{:?} kept changing while being read; recorded as unreadable",
            rel.display()
        ));
        Ok(Some(unreadable(md)))
    }

    /// Pass 2: copies the content into a blob, re-scanning and re-hashing so the
    /// stored bytes are exactly the bytes that were classified.
    fn copy_blob(
        &mut self,
        file: &mut File,
        digest: &Digest,
        expect_len: u64,
        rel: &RelPath,
    ) -> Result<CopyResult> {
        file.seek(SeekFrom::Start(0))
            .ctx(|| format!("rewinding {}", rel.display()))?;
        let mut writer: Box<dyn BlobWriter> = self.tree.blobs.writer()?;
        let mut scanner = Scanner::new();
        let mut total = 0u64;
        loop {
            let n = match file.read(&mut self.buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Ok(CopyResult::Changed),
            };
            if n == 0 {
                break;
            }
            let chunk = self.buf.get(..n).unwrap_or(&[]);
            if scanner.feed(chunk).is_some() {
                return Ok(CopyResult::Sensitive);
            }
            total = total.saturating_add(n as u64);
            if total > expect_len.max(self.tree.max_file_size) {
                return Ok(CopyResult::Changed);
            }
            writer.write(chunk)?;
        }
        if total != expect_len {
            return Ok(CopyResult::Changed);
        }
        if writer.commit(digest)? {
            Ok(CopyResult::Stored)
        } else {
            Ok(CopyResult::Changed)
        }
    }
}

struct Walker<'a> {
    c: Classifier<'a>,
    ignore: IgnoreSet,
    root_dev: u64,
    use_cache: bool,
}

impl Walker<'_> {
    fn walk_dir(
        &mut self,
        dir_abs: &Path,
        dir_rel: Option<&RelPath>,
        depth: usize,
        visitor: &mut dyn ScanVisitor,
    ) -> Result<()> {
        let shown = dir_rel.map_or_else(String::new, RelPath::display);
        if depth > MAX_DEPTH {
            return Err(Error::Limit(format!(
                "directory nesting deeper than {MAX_DEPTH} levels below {shown:?}"
            )));
        }
        let rd = match fs::read_dir(dir_abs) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                self.c.warn(format!(
                    "cannot list directory {shown:?}: {e}; keeping its previous entries"
                ));
                return match dir_rel {
                    Some(d) => visitor.carry_forward(d),
                    None => Ok(()),
                };
            }
        };
        let mut names: Vec<OsString> = Vec::new();
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(e) => {
                    self.c.warn(format!("error listing {shown:?}: {e}"));
                    continue;
                }
            };
            if names.len() >= MAX_DIR_ENTRIES {
                return Err(Error::Limit(format!(
                    "directory {shown:?} has more than {MAX_DIR_ENTRIES} entries; add it to {IGNORE_FILE}"
                )));
            }
            names.push(ent.file_name());
        }
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in names {
            let rel = match dir_rel {
                Some(d) => d.join(name.as_bytes()),
                None => RelPath::from_name(name.as_bytes()),
            };
            let Ok(rel) = rel else {
                self.c
                    .warn(format!("skipping unsupported path below {shown:?}"));
                continue;
            };
            let abs = dir_abs.join(&name);
            if abs == self.c.tree.store_dir {
                continue;
            }
            let md = match fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.c.warn(format!("cannot stat {:?}: {e}", rel.display()));
                    continue;
                }
            };
            let is_dir = md.is_dir();
            if self.ignore.is_ignored(rel.as_bytes(), is_dir) {
                continue;
            }
            if is_dir && md.dev() != self.root_dev {
                continue; // do not cross filesystem boundaries
            }
            let cached = if self.use_cache {
                visitor.prev(&rel)?
            } else {
                None
            };
            let Some(entry) = self.c.entry_for(&abs, &rel, &md, cached.as_ref())? else {
                continue;
            };
            self.c.stats.entries += 1;
            visitor.visit(&rel, &entry)?;
            if is_dir {
                self.walk_dir(&abs, Some(&rel), depth + 1, visitor)?;
            }
        }
        Ok(())
    }
}

// ----------------------------------------------------------------- applying

fn io_err(what: &str, rel: &RelPath, e: std::io::Error) -> Error {
    Error::io(format!("{what} {}", rel.display()), e)
}

/// Creates missing directories of `rel`'s parent one component at a time,
/// verifying each existing component is a real directory.
fn ensure_parents(root: &Path, rel: &RelPath) -> Result<()> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut cur = root.to_path_buf();
    for comp in parent.components() {
        cur.push(OsStr::from_bytes(comp));
        match fs::symlink_metadata(&cur) {
            Ok(m) => {
                if m.file_type().is_symlink() || !m.is_dir() {
                    return Err(Error::Unsafe(format!(
                        "parent of {} is a symlink or not a directory",
                        rel.display()
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o755)
                    .create(&cur)
                    .map_err(|e| io_err("creating parent directory of", rel, e))?;
            }
            Err(e) => return Err(io_err("stat parent of", rel, e)),
        }
    }
    Ok(())
}

/// Fails if `path` is a directory (unless allowed) or special file.
fn check_destination(path: &Path, rel: &RelPath, allow_dir: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_dir() && !allow_dir {
                return Err(Error::Unsafe(format!("{} is a directory", rel.display())));
            }
            if !(ft.is_file() || ft.is_symlink() || ft.is_dir()) {
                return Err(Error::Unsafe(format!(
                    "{} is a special file",
                    rel.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("stat", rel, e)),
    }
}

impl FsTree {
    fn restore_file(&self, rel: &RelPath, blob: &Digest, entry: &Entry) -> Result<()> {
        ensure_parents(&self.root, rel)?;
        let dest = join(&self.root, rel);
        let parent_abs = dest
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        let tmp = sibling_tmp(&parent_abs);
        let mut src = File::open(self.blobs.path_of(blob)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Integrity(format!("blob {} is missing from the store", to_hex(blob)))
            } else {
                io_err("opening blob for", rel, e)
            }
        })?;
        let mut out =
            create_new_private(&tmp).map_err(|e| io_err("creating temp file for", rel, e))?;
        let res = (|| -> Result<()> {
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; BUF_SIZE];
            loop {
                let n = src
                    .read(&mut buf)
                    .map_err(|e| io_err("reading blob for", rel, e))?;
                if n == 0 {
                    break;
                }
                let chunk = buf.get(..n).unwrap_or(&[]);
                hasher.update(chunk);
                out.write_all(chunk)
                    .map_err(|e| io_err("writing", rel, e))?;
            }
            if &hasher.finalize() != blob {
                return Err(Error::Integrity(format!(
                    "stored blob {} is corrupt (content hash mismatch); {} was not modified",
                    to_hex(blob),
                    rel.display()
                )));
            }
            out.set_permissions(fs::Permissions::from_mode(entry.mode() & 0o777))
                .map_err(|e| io_err("setting mode of", rel, e))?;
            let _ = out.set_modified(systime(entry.mtime_ns()));
            out.sync_all().map_err(|e| io_err("syncing", rel, e))?;
            // Re-validate immediately before the rename.
            check_parents(&self.root, rel)?;
            check_destination(&dest, rel, false)?;
            fs::rename(&tmp, &dest).map_err(|e| io_err("replacing", rel, e))
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    fn restore_symlink(&self, rel: &RelPath, target: &[u8]) -> Result<()> {
        ensure_parents(&self.root, rel)?;
        let dest = join(&self.root, rel);
        let parent_abs = dest
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        let tmp = sibling_tmp(&parent_abs);
        std::os::unix::fs::symlink(OsStr::from_bytes(target), &tmp)
            .map_err(|e| io_err("creating symlink for", rel, e))?;
        let res = (|| -> Result<()> {
            check_parents(&self.root, rel)?;
            check_destination(&dest, rel, false)?;
            fs::rename(&tmp, &dest).map_err(|e| io_err("replacing", rel, e))
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }
}

fn set_mode(path: &Path, rel: &RelPath, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .map_err(|e| io_err("setting mode of", rel, e))
}

impl WorkingTree for FsTree {
    fn scan(&self, opts: &ScanOptions, visitor: &mut dyn ScanVisitor) -> Result<ScanStats> {
        let md = fs::symlink_metadata(&self.root).ctx(|| "stat project root".into())?;
        let cutoff = opts
            .cache_time_ns
            .map(|t| t.saturating_sub(opts.cache_margin_ns));
        let mut w = Walker {
            c: Classifier::new(self, opts.capture, cutoff),
            ignore: self.load_ignore()?,
            root_dev: md.dev(),
            use_cache: cutoff.is_some() && !opts.no_cache,
        };
        w.walk_dir(&self.root, None, 0, visitor)?;
        Ok(w.c.stats)
    }

    fn observe(&self, path: &RelPath) -> Result<Observation> {
        if let Err(Error::Unsafe(why)) = check_parents(&self.root, path) {
            return Ok(Observation::Unsafe(why));
        }
        let abs = join(&self.root, path);
        let md = match fs::symlink_metadata(&abs) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Observation::State(None));
            }
            Err(e) => return Err(io_err("stat", path, e)),
        };
        let mut c = Classifier::new(self, false, None);
        Ok(Observation::State(c.entry_for(&abs, path, &md, None)?))
    }

    fn apply(&self, item: &PlanItem, dir_modes: &mut Vec<(RelPath, u32)>) -> Result<Outcome> {
        let rel = &item.path;
        check_parents(&self.root, rel)?;
        let abs = join(&self.root, rel);
        if item.replace {
            // Remove an object of the other class first.
            let md = fs::symlink_metadata(&abs).map_err(|e| io_err("stat", rel, e))?;
            if md.is_dir() {
                if let Err(e) = fs::remove_dir(&abs) {
                    return Ok(Outcome::Skipped(format!(
                        "directory in the way could not be removed ({e})"
                    )));
                }
            } else {
                fs::remove_file(&abs).map_err(|e| io_err("removing", rel, e))?;
            }
        }
        match item.op {
            Op::None => Ok(Outcome::Skipped("nothing to do".into())),
            Op::Delete => {
                check_destination(&abs, rel, false)?;
                fs::remove_file(&abs).map_err(|e| io_err("removing", rel, e))?;
                Ok(Outcome::Applied)
            }
            Op::Rmdir => match fs::remove_dir(&abs) {
                Ok(()) => Ok(Outcome::Applied),
                Err(e) => Ok(Outcome::Skipped(format!(
                    "directory not removed ({e}); it may contain files that are not tracked"
                ))),
            },
            Op::Mkdir => {
                ensure_parents(&self.root, rel)?;
                let mode = item.target.as_ref().map_or(0o755, Entry::mode);
                DirBuilder::new()
                    .mode(0o700)
                    .create(&abs)
                    .map_err(|e| io_err("creating directory", rel, e))?;
                if mode & 0o777 != 0o700 {
                    dir_modes.push((rel.clone(), mode));
                }
                Ok(Outcome::Applied)
            }
            Op::Write => {
                let t = item
                    .target
                    .as_ref()
                    .ok_or_else(|| Error::Other("internal error: write without target".into()))?;
                let blob = t
                    .blob()
                    .ok_or_else(|| Error::Other("internal error: write without blob".into()))?;
                self.restore_file(rel, &blob, t)?;
                Ok(Outcome::Applied)
            }
            Op::Symlink => {
                let t = item
                    .target
                    .as_ref()
                    .and_then(Entry::target)
                    .ok_or_else(|| Error::Other("internal error: symlink without target".into()))?;
                self.restore_symlink(rel, t)?;
                Ok(Outcome::Applied)
            }
            Op::Chmod => {
                let mode = item.target.as_ref().map_or(0o644, Entry::mode);
                if item.target.as_ref().is_some_and(|t| t.kind() == Kind::Dir) {
                    dir_modes.push((rel.clone(), mode));
                } else {
                    set_mode(&abs, rel, mode)?;
                }
                Ok(Outcome::Applied)
            }
        }
    }

    fn set_dir_mode(&self, path: &RelPath, mode: u32) -> Result<()> {
        check_parents(&self.root, path)?;
        let abs = join(&self.root, path);
        let md = fs::symlink_metadata(&abs).map_err(|e| io_err("stat", path, e))?;
        if !md.is_dir() {
            return Err(Error::Unsafe(format!(
                "{} is no longer a directory",
                display(path.as_bytes())
            )));
        }
        set_mode(&abs, path, mode)
    }
}
