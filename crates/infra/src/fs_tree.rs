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

use crate::fs_sensitive::FsSensitiveIds;
use crate::fsutil::{
    ParentProblem, check_parents, chmod_dir_nofollow, chmod_file_nofollow, create_new_private,
    join, open_regular, parent_problem, sibling_tmp,
};
use crate::layout::read_file_capped;
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::{
    BlobStore, BlobWriter, ScanOptions, ScanStats, ScanVisitor, WorkingTree,
};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::hash::{Digest, Sha256, to_hex};
use agent_undo_domain::ignore::{IgnoreSet, MAX_IGNORE_FILE_BYTES};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Op, Outcome, PlanItem};
use agent_undo_domain::policy::{FileClass, Insert, cache_usable, classify_file, sensitive_id};
use agent_undo_domain::secrets::{Scanner, sensitive_name};
use std::cell::RefCell;
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

/// Where in a scan a test hook is called (see [`FsTree::set_scan_hook`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStage {
    /// A directory was listed; the hook receives its path.
    DirListed,
    /// A file is about to be opened for reading; the hook receives its path.
    BeforeFileRead,
}

type ScanHook = dyn Fn(ScanStage, &Path);

pub struct FsTree {
    root: PathBuf,
    store_dir: PathBuf,
    max_file_size: u64,
    key: [u8; 32],
    blobs: crate::fs_blobs::FsBlobs,
    sensitive: FsSensitiveIds,
    max_dir_entries: usize,
    max_depth: usize,
    hook: RefCell<Option<Box<ScanHook>>>,
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
            sensitive: FsSensitiveIds::new(store_dir.join("sensitive-ids")),
            root,
            max_file_size,
            key,
            blobs,
            max_dir_entries: MAX_DIR_ENTRIES,
            max_depth: MAX_DEPTH,
            hook: RefCell::new(None),
        }
    }

    /// Overrides the per-directory entry cap and the depth cap (tests use small
    /// values; production uses [`MAX_DIR_ENTRIES`] and [`MAX_DEPTH`]).
    pub fn with_limits(mut self, max_dir_entries: usize, max_depth: usize) -> FsTree {
        self.max_dir_entries = max_dir_entries;
        self.max_depth = max_depth;
        self
    }

    /// Fault-injection seam for tests: `f` runs at the given [`ScanStage`]s, where a
    /// concurrent process could modify the tree (for example swap a directory for a
    /// symlink). Not used by the binary.
    pub fn set_scan_hook(&self, f: impl Fn(ScanStage, &Path) + 'static) {
        *self.hook.borrow_mut() = Some(Box::new(f));
    }

    fn call_hook(&self, stage: ScanStage, path: &Path) {
        if let Some(h) = self.hook.borrow().as_ref() {
            h(stage, path);
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The ignore rules in force. A bad `.agent-undoignore` must not disable the
    /// recorder (a hostile tree could otherwise make every checkpoint fail), so the
    /// defaults apply and the problem comes back as a warning.
    fn load_ignore(&self) -> (IgnoreSet, Option<String>) {
        let loaded = read_file_capped(&self.root.join(IGNORE_FILE), MAX_IGNORE_FILE_BYTES)
            .map_err(|e| e.to_string())
            .and_then(|t| match t {
                Some(t) => IgnoreSet::with_user_patterns(&t),
                None => Ok(IgnoreSet::defaults()),
            });
        match loaded {
            Ok(set) => (set, None),
            Err(e) => (
                IgnoreSet::defaults(),
                Some(format!(
                    "{IGNORE_FILE} is invalid ({e}); using the default ignore rules"
                )),
            ),
        }
    }

    fn sid(&self, digest: &Digest) -> Digest {
        sensitive_id(&self.key, digest)
    }
}

/// Identity of a directory as it was when it was listed.
#[derive(Clone, Copy)]
struct DirId {
    dev: u64,
    ino: u64,
}

impl DirId {
    fn of(md: &fs::Metadata) -> DirId {
        DirId {
            dev: md.dev(),
            ino: md.ino(),
        }
    }

    /// Whether `path` still names the same real directory (not a symlink, not
    /// replaced). Narrows, but cannot close, the window against a concurrent
    /// process: std has no `openat`.
    fn still_at(&self, path: &Path) -> bool {
        fs::symlink_metadata(path)
            .is_ok_and(|m| m.is_dir() && m.dev() == self.dev && m.ino() == self.ino)
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
    /// The file could not be rewound or read again.
    Unreadable,
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
        parent: Option<(&Path, DirId)>,
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
            && !self.became_sensitive(c)?
        {
            self.stats.files_cached += 1;
            return Ok(Some(c.with_mode(mode)));
        }
        self.hash_file(abs, rel, md, mode, mtime_ns, ctime_ns, parent)
    }

    /// A cached regular-file entry whose content has since been recognised as
    /// sensitive (for example because a copy of it was found under a secret name)
    /// must be classified again.
    fn became_sensitive(&self, cached: &Entry) -> Result<bool> {
        match (cached.kind(), cached.digest()) {
            (Kind::File, Some(d)) => self.tree.sensitive.contains(&self.tree.sid(&d)),
            _ => Ok(false),
        }
    }

    fn remember(&mut self, sid: Digest) -> Result<()> {
        if self.tree.sensitive.remember(sid, self.capture)? == Insert::Full {
            self.warn(
                "the sensitive-content registry is full; copies of newly found secrets may be stored"
                    .into(),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn hash_file(
        &mut self,
        abs: &Path,
        rel: &RelPath,
        md: &fs::Metadata,
        mode: u32,
        mtime_ns: i64,
        ctime_ns: i64,
        parent: Option<(&Path, DirId)>,
    ) -> Result<Option<Entry>> {
        let name_sensitive = sensitive_name(rel.as_bytes()).is_some();
        let unreadable = |md: &fs::Metadata| Entry::unreadable(mode, md.len(), mtime_ns, ctime_ns);
        let parent_ok = |p: &Option<(&Path, DirId)>| p.is_none_or(|(dir, id)| id.still_at(dir));
        let swapped = |s: &mut Self| {
            s.warn(format!(
                "the directory of {:?} changed while it was being read; the file was not recorded",
                rel.display()
            ));
        };
        for _attempt in 0..MAX_ATTEMPTS {
            if !parent_ok(&parent) {
                swapped(self);
                return Ok(Some(unreadable(md)));
            }
            self.tree.call_hook(ScanStage::BeforeFileRead, abs);
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
            if !parent_ok(&parent) {
                swapped(self);
                return Ok(Some(unreadable(md)));
            }
            let digest = hasher.finalize();
            let sid = self.tree.sid(&digest);
            let known = self.tree.sensitive.contains(&sid)?;
            let sens =
                |d: &Digest| Entry::hashed(Kind::Sensitive, d, mode, total, mtime_ns, ctime_ns);
            match classify_file(
                name_sensitive,
                scanner.result().is_some(),
                known,
                total,
                self.tree.max_file_size,
            ) {
                FileClass::Sensitive => {
                    self.remember(sid)?;
                    return Ok(Some(sens(&sid)?));
                }
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
                    if !parent_ok(&parent) {
                        // The blob was new in this call, so removing it loses nothing.
                        let _ = self.tree.blobs.remove(&digest);
                        swapped(self);
                        return Ok(Some(unreadable(md)));
                    }
                    self.stats.blobs_written += 1;
                    self.stats.bytes_stored = self.stats.bytes_stored.saturating_add(total);
                    return Ok(Some(file_entry));
                }
                CopyResult::Sensitive => {
                    self.remember(sid)?;
                    return Ok(Some(sens(&sid)?));
                }
                CopyResult::Changed => continue,
                CopyResult::Unreadable => return Ok(Some(unreadable(md))),
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
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            self.warn(format!("cannot rewind {:?}: {e}", rel.display()));
            return Ok(CopyResult::Unreadable);
        }
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
    /// Relative path of a directory entry, or `None` (with a warning) if its name
    /// cannot be represented.
    fn child_rel(
        &mut self,
        dir_rel: Option<&RelPath>,
        name: &OsStr,
        shown: &str,
    ) -> Option<RelPath> {
        let rel = match dir_rel {
            Some(d) => d.join(name.as_bytes()),
            None => RelPath::from_name(name.as_bytes()),
        };
        if rel.is_err() {
            self.c
                .warn(format!("skipping unsupported path below {shown:?}"));
        }
        rel.ok()
    }

    /// Records the keyed id of every secret-by-name file before the real walk, so a
    /// copy of such a file that sorts earlier than the original is still recognised
    /// by content. Reads only files with secret names; everything else is metadata.
    fn remember_named_secrets(
        &mut self,
        dir_abs: &Path,
        dir_rel: Option<&RelPath>,
        depth: usize,
    ) -> Result<()> {
        if depth > self.c.tree.max_depth {
            return Ok(());
        }
        let Ok(rd) = fs::read_dir(dir_abs) else {
            return Ok(());
        };
        let shown = dir_rel.map_or_else(String::new, RelPath::display);
        for (seen, ent) in rd.enumerate() {
            let Ok(ent) = ent else { continue };
            if seen >= self.c.tree.max_dir_entries {
                break;
            }
            let Some(rel) = self.child_rel(dir_rel, &ent.file_name(), &shown) else {
                continue;
            };
            let abs = dir_abs.join(ent.file_name());
            if abs == self.c.tree.store_dir {
                continue;
            }
            let Ok(ft) = ent.file_type() else { continue };
            if self.ignore.is_ignored(rel.as_bytes(), ft.is_dir()) {
                continue;
            }
            if ft.is_dir() {
                self.remember_named_secrets(&abs, Some(&rel), depth + 1)?;
            } else if ft.is_file() && sensitive_name(rel.as_bytes()).is_some() {
                let Ok((mut file, _)) = open_regular(&abs, None) else {
                    continue;
                };
                let mut hasher = Sha256::new();
                loop {
                    match file.read(&mut self.c.buf) {
                        Ok(0) => break,
                        Ok(n) => hasher.update(self.c.buf.get(..n).unwrap_or(&[])),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let sid = self.c.tree.sid(&hasher.finalize());
                self.c.remember(sid)?;
            }
        }
        Ok(())
    }

    fn walk_dir(
        &mut self,
        dir_abs: &Path,
        dir_rel: Option<&RelPath>,
        dir_id: DirId,
        depth: usize,
        visitor: &mut dyn ScanVisitor,
    ) -> Result<()> {
        let shown = dir_rel.map_or_else(String::new, RelPath::display);
        let (max_entries, max_depth) = (self.c.tree.max_dir_entries, self.c.tree.max_depth);
        if depth > max_depth {
            self.c.warn(format!(
                "directory nesting deeper than {max_depth} levels at {shown:?}; its contents are not recorded"
            ));
            return visitor.carry_forward(dir_rel);
        }
        let rd = match fs::read_dir(dir_abs) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                self.c.warn(format!(
                    "cannot list directory {shown:?}: {e}; keeping its previous entries"
                ));
                return visitor.carry_forward(dir_rel);
            }
        };
        // Ignored names are dropped while listing, so a huge directory of ignored
        // files (build output, caches) neither counts against the cap nor uses memory.
        let mut names: Vec<(OsString, RelPath)> = Vec::new();
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(e) => {
                    self.c.warn(format!("error listing {shown:?}: {e}"));
                    continue;
                }
            };
            let name = ent.file_name();
            let Some(rel) = self.child_rel(dir_rel, &name, &shown) else {
                continue;
            };
            let is_dir = ent.file_type().is_ok_and(|t| t.is_dir());
            if self.ignore.is_ignored(rel.as_bytes(), is_dir) {
                continue;
            }
            if names.len() >= max_entries {
                self.c.warn(format!(
                    "directory {shown:?} has more than {max_entries} entries; its contents are not recorded (add it to {IGNORE_FILE})"
                ));
                return visitor.carry_forward(dir_rel);
            }
            names.push((name, rel));
        }
        self.c.tree.call_hook(ScanStage::DirListed, dir_abs);
        if !dir_id.still_at(dir_abs) {
            self.c.warn(format!(
                "directory {shown:?} changed while it was being listed; its contents are not recorded"
            ));
            return visitor.carry_forward(dir_rel);
        }
        names.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        for (name, rel) in names {
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
            let Some(entry) =
                self.c
                    .entry_for(&abs, &rel, &md, cached.as_ref(), Some((dir_abs, dir_id)))?
            else {
                continue;
            };
            self.c.stats.entries += 1;
            visitor.visit(&rel, &entry)?;
            if is_dir {
                self.walk_dir(&abs, Some(&rel), DirId::of(&md), depth + 1, visitor)?;
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

impl WorkingTree for FsTree {
    fn scan(&self, opts: &ScanOptions, visitor: &mut dyn ScanVisitor) -> Result<ScanStats> {
        let md = fs::symlink_metadata(&self.root).ctx(|| "stat project root".into())?;
        let cutoff = opts
            .cache_time_ns
            .map(|t| t.saturating_sub(opts.cache_margin_ns));
        let (ignore, ignore_warning) = self.load_ignore();
        let mut w = Walker {
            c: Classifier::new(self, opts.capture, cutoff),
            ignore,
            root_dev: md.dev(),
            use_cache: cutoff.is_some() && !opts.no_cache,
        };
        if let Some(why) = ignore_warning {
            w.c.warn(why);
        }
        w.remember_named_secrets(&self.root, None, 0)?;
        w.walk_dir(&self.root, None, DirId::of(&md), 0, visitor)?;
        Ok(w.c.stats)
    }

    fn observe(&self, path: &RelPath) -> Result<Observation> {
        match parent_problem(&self.root, path)? {
            Some(ParentProblem::Symlink(why)) => return Ok(Observation::Unsafe(why)),
            Some(ParentProblem::NotDirectory(why)) => return Ok(Observation::Obstructed(why)),
            None => {}
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
        Ok(Observation::State(
            c.entry_for(&abs, path, &md, None, None)?,
        ))
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
                    match chmod_file_nofollow(&abs, mode) {
                        Ok(()) => {}
                        // A file we may not open (mode 000): its content is unchanged and
                        // stored, so restore it through the temp-file-and-rename path.
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            let t = item.target.as_ref();
                            let blob = t.and_then(Entry::blob);
                            let (Some(t), Some(blob)) = (t, blob) else {
                                return Err(io_err("changing the mode of", rel, e));
                            };
                            self.restore_file(rel, &blob, t)?;
                        }
                        Err(e) => return Err(io_err("changing the mode of", rel, e)),
                    }
                }
                Ok(Outcome::Applied)
            }
        }
    }

    fn set_dir_mode(&self, path: &RelPath, mode: u32) -> Result<()> {
        check_parents(&self.root, path)?;
        let abs = join(&self.root, path);
        chmod_dir_nofollow(&abs, mode).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => Error::Other(format!(
                "cannot change the mode of {} safely (the directory is not readable)",
                path.display()
            )),
            std::io::ErrorKind::NotFound => io_err("changing the mode of", path, e),
            // A symlink, a file or anything else that is not a plain directory.
            _ => Error::Unsafe(format!("{} is not a plain directory", path.display())),
        })
    }
}
