//! In-memory implementations of every port.
//!
//! They are real implementations of the port contracts (the same contract test
//! suites run against them and against the filesystem adapters), used to drive
//! use cases in tests without touching a disk, a clock or a process.

use crate::error::{Error, Result};
use crate::events::Event;
use crate::ports::*;
use agent_undo_domain::change::{Change, EntrySource};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::esc::pct_encode;
use agent_undo_domain::hash::{Digest, Sha256, sha256, to_hex};
use agent_undo_domain::ignore::IgnoreSet;
use agent_undo_domain::journal::{CheckpointId, CheckpointRecord, Journal};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Op, Outcome, PlanItem};
use agent_undo_domain::policy::{FileClass, cache_usable, classify_file, sensitive_id};
use agent_undo_domain::secrets::{scan_bytes, sensitive_name};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

// ------------------------------------------------------------------- clock

/// A clock that only moves when told to.
pub struct FixedClock(Cell<i64>);

impl FixedClock {
    pub fn new(start_ns: i64) -> FixedClock {
        FixedClock(Cell::new(start_ns))
    }

    pub fn advance(&self, ns: i64) {
        self.0.set(self.0.get() + ns);
    }

    pub fn set(&self, ns: i64) {
        self.0.set(ns);
    }
}

impl Clock for FixedClock {
    fn now_ns(&self) -> i64 {
        self.0.get()
    }
}

/// A clock that advances by `step_ns` every time it is read, so successive
/// checkpoints get distinct times.
pub struct TickingClock {
    now: Cell<i64>,
    step: i64,
}

impl TickingClock {
    pub fn new(start_ns: i64, step_ns: i64) -> TickingClock {
        TickingClock {
            now: Cell::new(start_ns),
            step: step_ns,
        }
    }
}

impl Clock for TickingClock {
    fn now_ns(&self) -> i64 {
        let v = self.now.get();
        self.now.set(v + self.step);
        v
    }
}

// ------------------------------------------------------------------ events

#[derive(Default)]
pub struct RecordingSink(RefCell<Vec<Event>>);

impl RecordingSink {
    pub fn new() -> RecordingSink {
        RecordingSink::default()
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.borrow().clone()
    }

    pub fn clear(&self) {
        self.0.borrow_mut().clear();
    }
}

impl EventSink for RecordingSink {
    fn publish(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

// ------------------------------------------------------------------- locks

#[derive(Default)]
struct LockState {
    exclusive: bool,
    shared: usize,
}

#[derive(Default, Clone)]
pub struct MemLocker(Rc<RefCell<LockState>>);

struct MemGuard {
    state: Rc<RefCell<LockState>>,
    exclusive: bool,
}

impl LockGuard for MemGuard {}

impl Drop for MemGuard {
    fn drop(&mut self) {
        let mut s = self.state.borrow_mut();
        if self.exclusive {
            s.exclusive = false;
        } else {
            s.shared = s.shared.saturating_sub(1);
        }
    }
}

impl MemLocker {
    pub fn new() -> MemLocker {
        MemLocker::default()
    }

    pub fn is_exclusively_held(&self) -> bool {
        self.0.borrow().exclusive
    }
}

impl Locker for MemLocker {
    fn exclusive(&self) -> Result<Box<dyn LockGuard>> {
        let mut s = self.0.borrow_mut();
        if s.exclusive || s.shared > 0 {
            return Err(Error::Locked("another operation holds the lock".into()));
        }
        s.exclusive = true;
        Ok(Box::new(MemGuard {
            state: self.0.clone(),
            exclusive: true,
        }))
    }

    fn shared(&self) -> Result<Box<dyn LockGuard>> {
        let mut s = self.0.borrow_mut();
        if s.exclusive {
            return Err(Error::Locked("another operation holds the lock".into()));
        }
        s.shared += 1;
        Ok(Box::new(MemGuard {
            state: self.0.clone(),
            exclusive: false,
        }))
    }
}

// ----------------------------------------------------------------- journal

#[derive(Default)]
pub struct MemJournal {
    records: RefCell<Vec<CheckpointRecord>>,
    pruned: RefCell<BTreeSet<u64>>,
}

impl MemJournal {
    pub fn new() -> MemJournal {
        MemJournal::default()
    }

    /// Test hook: mutate a stored record in place (simulates on-disk tampering).
    pub fn tamper(&self, f: impl FnOnce(&mut Vec<CheckpointRecord>)) {
        f(&mut self.records.borrow_mut());
    }
}

impl JournalRepository for MemJournal {
    fn load(&self) -> Result<Journal> {
        Ok(Journal::from_records(
            self.records.borrow().clone(),
            self.pruned.borrow().clone(),
        )?)
    }

    fn append(&self, record: &CheckpointRecord) -> Result<()> {
        self.records.borrow_mut().push(record.clone());
        Ok(())
    }

    fn save_pruned(&self, ids: &[CheckpointId]) -> Result<()> {
        self.pruned.borrow_mut().extend(ids.iter().map(|i| i.get()));
        Ok(())
    }
}

// ------------------------------------------------------------------- blobs

#[derive(Default)]
pub struct MemBlobs {
    blobs: RefCell<BTreeMap<Digest, Vec<u8>>>,
    strays: RefCell<Vec<String>>,
}

impl MemBlobs {
    pub fn new() -> MemBlobs {
        MemBlobs::default()
    }

    /// Test hook: overwrite stored bytes without changing the key (corruption).
    pub fn corrupt(&self, digest: &Digest, bytes: Vec<u8>) {
        self.blobs.borrow_mut().insert(*digest, bytes);
    }

    /// Test hook: add a stray non-blob entry.
    pub fn add_stray(&self, name: &str) {
        self.strays.borrow_mut().push(name.to_string());
    }

    /// Test hook: every stored byte (to prove secrets never reach the store).
    pub fn all_bytes(&self) -> Vec<u8> {
        self.blobs.borrow().values().flatten().copied().collect()
    }

    pub fn count(&self) -> usize {
        self.blobs.borrow().len()
    }
}

struct MemBlobWriter {
    store: Rc<MemBlobs>,
    buf: Vec<u8>,
}

impl BlobWriter for MemBlobWriter {
    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    fn commit(self: Box<Self>, expected: &Digest) -> Result<bool> {
        if &sha256(&self.buf) != expected {
            return Ok(false);
        }
        self.store.blobs.borrow_mut().insert(*expected, self.buf);
        Ok(true)
    }
}

impl BlobStore for Rc<MemBlobs> {
    fn contains(&self, digest: &Digest) -> bool {
        self.blobs.borrow().contains_key(digest)
    }

    fn read(&self, digest: &Digest, cap: u64) -> Result<Vec<u8>> {
        let b = self.blobs.borrow();
        let data = b.get(digest).ok_or_else(|| {
            Error::Integrity(format!("blob {} is missing from the store", to_hex(digest)))
        })?;
        if data.len() as u64 > cap {
            return Err(Error::Limit(format!(
                "blob {} larger than {cap} bytes",
                to_hex(digest)
            )));
        }
        Ok(data.clone())
    }

    fn hash_stored(&self, digest: &Digest) -> Result<Digest> {
        let b = self.blobs.borrow();
        let data = b.get(digest).ok_or_else(|| {
            Error::Integrity(format!("blob {} is missing from the store", to_hex(digest)))
        })?;
        Ok(sha256(data))
    }

    fn list(&self) -> Result<BlobListing> {
        Ok(BlobListing {
            blobs: self
                .blobs
                .borrow()
                .iter()
                .map(|(d, v)| (*d, v.len() as u64))
                .collect(),
            strays: self.strays.borrow().clone(),
        })
    }

    fn remove(&self, digest: &Digest) -> Result<()> {
        self.blobs.borrow_mut().remove(digest);
        Ok(())
    }

    fn writer(&self) -> Result<Box<dyn BlobWriter>> {
        Ok(Box::new(MemBlobWriter {
            store: self.clone(),
            buf: Vec::new(),
        }))
    }
}

// --------------------------------------------------------------- snapshots

#[derive(Clone)]
struct StoredCheckpoint {
    entries: Vec<(RelPath, Entry)>,
    changes: Vec<Change>,
}

fn manifest_digest(entries: &[(RelPath, Entry)]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"agent-undo-manifest v1\n");
    for (p, e) in entries {
        h.update(format!("{}\t{}\n", pct_encode(p.as_bytes()), e.encode()).as_bytes());
    }
    h.finalize()
}

fn changes_digest(changes: &[Change]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"agent-undo-changes v1\n");
    for c in changes {
        h.update(format!("{}\n", c.encode()).as_bytes());
    }
    h.finalize()
}

#[derive(Default)]
pub struct MemSnapshots {
    stored: RefCell<BTreeMap<u64, StoredCheckpoint>>,
}

impl MemSnapshots {
    pub fn new() -> MemSnapshots {
        MemSnapshots::default()
    }

    /// Test hook: mutate a stored manifest in place (simulates corruption).
    pub fn tamper_manifest(&self, id: CheckpointId, f: impl FnOnce(&mut Vec<(RelPath, Entry)>)) {
        if let Some(s) = self.stored.borrow_mut().get_mut(&id.get()) {
            f(&mut s.entries);
        }
    }

    pub fn contains(&self, id: CheckpointId) -> bool {
        self.stored.borrow().contains_key(&id.get())
    }
}

struct VecManifest {
    items: VecDeque<(RelPath, Entry)>,
}

impl EntrySource for VecManifest {
    type Error = Error;
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>> {
        Ok(self.items.pop_front())
    }
}

struct VecChanges {
    items: VecDeque<Change>,
}

impl ChangeStream for VecChanges {
    fn next_change(&mut self) -> Result<Option<Change>> {
        Ok(self.items.pop_front())
    }
}

struct MemWriter {
    repo: Rc<MemSnapshots>,
    id: u64,
    entries: Vec<(RelPath, Entry)>,
    changes: Vec<Change>,
}

impl CheckpointWriter for MemWriter {
    fn write_entry(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        if let Some((last, _)) = self.entries.last()
            && last >= path
        {
            return Err(Error::Other(
                "internal error: manifest entries out of order".into(),
            ));
        }
        self.entries.push((path.clone(), entry.clone()));
        Ok(())
    }

    fn write_change(&mut self, change: &Change) -> Result<()> {
        self.changes.push(change.clone());
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<Written> {
        let w = Written {
            manifest: manifest_digest(&self.entries),
            changes: changes_digest(&self.changes),
            entries: self.entries.len() as u64,
        };
        self.repo.stored.borrow_mut().insert(
            self.id,
            StoredCheckpoint {
                entries: self.entries,
                changes: self.changes,
            },
        );
        Ok(w)
    }
}

impl SnapshotRepository for Rc<MemSnapshots> {
    fn open_manifest(&self, id: CheckpointId) -> Result<ManifestStream> {
        let s = self.stored.borrow();
        let c = s.get(&id.get()).ok_or_else(|| {
            Error::Integrity(format!(
                "manifest of checkpoint {id} is missing (pruned or deleted)"
            ))
        })?;
        Ok(Box::new(VecManifest {
            items: c.entries.clone().into(),
        }))
    }

    fn open_changes(&self, id: CheckpointId) -> Result<Box<dyn ChangeStream>> {
        let s = self.stored.borrow();
        let c = s.get(&id.get()).ok_or_else(|| {
            Error::Integrity(format!(
                "change set of checkpoint {id} is missing (pruned or deleted)"
            ))
        })?;
        Ok(Box::new(VecChanges {
            items: c.changes.clone().into(),
        }))
    }

    fn begin(&self, id: CheckpointId) -> Result<Box<dyn CheckpointWriter>> {
        Ok(Box::new(MemWriter {
            repo: self.clone(),
            id: id.get(),
            entries: Vec::new(),
            changes: Vec::new(),
        }))
    }

    fn remove(&self, id: CheckpointId) -> Result<()> {
        self.stored.borrow_mut().remove(&id.get());
        Ok(())
    }

    fn stored_digests(&self, id: CheckpointId) -> Result<StoredDigests> {
        let s = self.stored.borrow();
        let c = s
            .get(&id.get())
            .ok_or_else(|| Error::Integrity(format!("files of checkpoint {id} are missing")))?;
        Ok(StoredDigests {
            manifest: manifest_digest(&c.entries),
            changes: changes_digest(&c.changes),
        })
    }

    fn list(&self) -> Result<Vec<CheckpointId>> {
        Ok(self
            .stored
            .borrow()
            .keys()
            .filter_map(|k| CheckpointId::new(*k).ok())
            .collect())
    }
}

// ------------------------------------------------------------ working tree

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    File { content: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
    Symlink { target: Vec<u8> },
    Special,
}

#[derive(Debug, Clone)]
struct Stamped {
    node: Node,
    mtime: i64,
    ctime: i64,
}

/// An in-memory project directory with the same classification rules as the
/// filesystem adapter.
pub struct MemTree {
    nodes: RefCell<BTreeMap<RelPath, Stamped>>,
    blobs: Rc<MemBlobs>,
    key: Vec<u8>,
    max_file_size: u64,
    tick: Cell<i64>,
    /// Paths whose directory listing fails (to exercise carry-forward).
    unlistable: RefCell<BTreeSet<RelPath>>,
    observe_calls: Cell<usize>,
    observe_hook: RefCell<Option<Box<ObserveHook>>>,
}

/// Called before every `observe` with the tree and the 1-based call number.
pub type ObserveHook = dyn Fn(&MemTree, usize);

impl MemTree {
    pub fn new(blobs: Rc<MemBlobs>, max_file_size: u64) -> MemTree {
        MemTree {
            nodes: RefCell::new(BTreeMap::new()),
            blobs,
            key: b"fake-store-key-for-tests-only".to_vec(),
            max_file_size,
            tick: Cell::new(1_000_000_000),
            unlistable: RefCell::new(BTreeSet::new()),
            observe_calls: Cell::new(0),
            observe_hook: RefCell::new(None),
        }
    }

    /// Test hook: run `f` before each `observe` call (to swap files between
    /// planning and applying, like a racing process would).
    pub fn set_observe_hook(&self, f: impl Fn(&MemTree, usize) + 'static) {
        *self.observe_hook.borrow_mut() = Some(Box::new(f));
    }

    pub fn clear_observe_hook(&self) {
        *self.observe_hook.borrow_mut() = None;
    }

    fn stamp(&self) -> i64 {
        let t = self.tick.get() + 1_000_000_000;
        self.tick.set(t);
        t
    }

    fn insert(&self, path: &str, node: Node) {
        if let Ok(p) = RelPath::new(path.as_bytes()) {
            self.insert_rel(p, node);
        }
    }

    fn insert_rel(&self, p: RelPath, node: Node) {
        let t = self.stamp();
        // Missing parent directories are created implicitly.
        let mut parent = p.parent();
        while let Some(pp) = parent {
            self.nodes
                .borrow_mut()
                .entry(pp.clone())
                .or_insert_with(|| Stamped {
                    node: Node::Dir { mode: 0o755 },
                    mtime: t,
                    ctime: t,
                });
            parent = pp.parent();
        }
        self.nodes.borrow_mut().insert(
            p,
            Stamped {
                node,
                mtime: t,
                ctime: t,
            },
        );
    }

    // --- test helpers ------------------------------------------------------

    pub fn write(&self, path: &str, content: &[u8]) {
        self.write_mode(path, content, 0o644);
    }

    pub fn write_mode(&self, path: &str, content: &[u8], mode: u32) {
        self.insert(
            path,
            Node::File {
                content: content.to_vec(),
                mode,
            },
        );
    }

    pub fn mkdir(&self, path: &str, mode: u32) {
        self.insert(path, Node::Dir { mode });
    }

    pub fn symlink(&self, path: &str, target: &[u8]) {
        self.insert(
            path,
            Node::Symlink {
                target: target.to_vec(),
            },
        );
    }

    pub fn special(&self, path: &str) {
        self.insert(path, Node::Special);
    }

    pub fn chmod(&self, path: &str, new_mode: u32) {
        if let Ok(p) = RelPath::new(path.as_bytes()) {
            self.chmod_rel(&p, new_mode);
        }
    }

    fn chmod_rel(&self, p: &RelPath, new_mode: u32) {
        let t = self.stamp();
        if let Some(s) = self.nodes.borrow_mut().get_mut(p) {
            match &mut s.node {
                Node::File { mode, .. } | Node::Dir { mode } => *mode = new_mode,
                _ => {}
            }
            s.ctime = t;
        }
    }

    /// Removes a path and everything below it.
    pub fn remove(&self, path: &str) {
        let Ok(p) = RelPath::new(path.as_bytes()) else {
            return;
        };
        self.nodes.borrow_mut().retain(|k, _| !k.is_within(&p));
    }

    pub fn rename(&self, from: &str, to: &str) {
        if let Some(content) = self.read(from) {
            let mode = self.mode(from).unwrap_or(0o644);
            self.remove(from);
            self.write_mode(to, &content, mode);
        }
    }

    pub fn read(&self, path: &str) -> Option<Vec<u8>> {
        let p = RelPath::new(path.as_bytes()).ok()?;
        match &self.nodes.borrow().get(&p)?.node {
            Node::File { content, .. } => Some(content.clone()),
            _ => None,
        }
    }

    pub fn mode(&self, path: &str) -> Option<u32> {
        let p = RelPath::new(path.as_bytes()).ok()?;
        match &self.nodes.borrow().get(&p)?.node {
            Node::File { mode, .. } | Node::Dir { mode } => Some(*mode),
            _ => None,
        }
    }

    pub fn node(&self, path: &str) -> Option<Node> {
        let p = RelPath::new(path.as_bytes()).ok()?;
        self.nodes.borrow().get(&p).map(|s| s.node.clone())
    }

    pub fn exists(&self, path: &str) -> bool {
        self.node(path).is_some()
    }

    pub fn paths(&self) -> Vec<String> {
        self.nodes.borrow().keys().map(RelPath::display).collect()
    }

    pub fn set_unlistable(&self, dir: &str) {
        if let Ok(p) = RelPath::new(dir.as_bytes()) {
            self.unlistable.borrow_mut().insert(p);
        }
    }

    // --- classification ---------------------------------------------------

    fn entry_of(
        &self,
        path: &RelPath,
        s: &Stamped,
        capture: bool,
        cached: Option<&Entry>,
        cutoff: Option<i64>,
        stats: &mut ScanStats,
    ) -> Result<Entry> {
        let (m, c) = (s.mtime, s.ctime);
        match &s.node {
            Node::Dir { mode } => Ok(Entry::dir(*mode, m, c)),
            Node::Symlink { target } => Ok(Entry::symlink(target.clone(), m, c)?),
            Node::Special => Ok(Entry::special(0o600, m, c)),
            Node::File { content, mode } => {
                let size = content.len() as u64;
                if let (Some(ce), Some(cut)) = (cached, cutoff)
                    && cache_usable(ce, size, m, c, cut)
                    && (ce.kind() != Kind::File
                        || !capture
                        || ce.digest().is_some_and(|d| self.blobs.contains(&d)))
                {
                    stats.files_cached += 1;
                    return Ok(ce.with_mode(*mode));
                }
                stats.files_hashed += 1;
                stats.bytes_hashed += size;
                let digest = sha256(content);
                let name_sensitive = sensitive_name(path.as_bytes()).is_some();
                let flagged = !name_sensitive && scan_bytes(content).is_some();
                Ok(
                    match classify_file(name_sensitive, flagged, size, self.max_file_size) {
                        FileClass::Sensitive => Entry::hashed(
                            Kind::Sensitive,
                            &sensitive_id(&self.key, &digest),
                            *mode,
                            size,
                            m,
                            c,
                        )?,
                        FileClass::TooLarge => {
                            Entry::hashed(Kind::TooLarge, &digest, *mode, size, m, c)?
                        }
                        FileClass::Storable => {
                            if capture && !self.blobs.contains(&digest) {
                                self.blobs.put(content)?;
                                stats.blobs_written += 1;
                                stats.bytes_stored += size;
                            }
                            Entry::hashed(Kind::File, &digest, *mode, size, m, c)?
                        }
                    },
                )
            }
        }
    }

    fn ignore_set(&self) -> IgnoreSet {
        match self.read(".agent-undoignore") {
            Some(text) => {
                IgnoreSet::with_user_patterns(&text).unwrap_or_else(|_| IgnoreSet::defaults())
            }
            None => IgnoreSet::defaults(),
        }
    }

    /// `Err((true, why))`: a symlink is in the way (unsafe); `Err((false, why))`: a
    /// non-directory is in the way (obstruction).
    fn parents_are_safe(&self, path: &RelPath) -> std::result::Result<(), (bool, String)> {
        let mut cur = path.parent();
        while let Some(p) = cur {
            match self.nodes.borrow().get(&p).map(|s| &s.node) {
                Some(Node::Symlink { .. }) => {
                    return Err((
                        true,
                        format!(
                            "refusing to traverse a symlink in parent directory of {}",
                            path.display()
                        ),
                    ));
                }
                Some(Node::Dir { .. }) | None => {}
                Some(_) => {
                    return Err((
                        false,
                        format!("a parent of {} is not a directory", path.display()),
                    ));
                }
            }
            cur = p.parent();
        }
        Ok(())
    }
}

impl WorkingTree for Rc<MemTree> {
    fn scan(&self, opts: &ScanOptions, visitor: &mut dyn ScanVisitor) -> Result<ScanStats> {
        let ignore = self.ignore_set();
        let snapshot: Vec<(RelPath, Stamped)> = self
            .nodes
            .borrow()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let cutoff = if opts.no_cache {
            None
        } else {
            opts.cache_time_ns
                .map(|t| t.saturating_sub(opts.cache_margin_ns))
        };
        let mut stats = ScanStats::default();
        let mut skip_prefix: Option<RelPath> = None;
        let mut carried: Option<RelPath> = None;
        for (path, stamped) in snapshot {
            if let Some(sp) = &skip_prefix {
                if path.is_below(sp) {
                    continue;
                }
                skip_prefix = None;
            }
            if let Some(cp) = &carried {
                if path.is_below(cp) {
                    continue;
                }
                carried = None;
            }
            let is_dir = matches!(stamped.node, Node::Dir { .. });
            if ignore.is_ignored(path.as_bytes(), is_dir) {
                if is_dir {
                    skip_prefix = Some(path);
                }
                continue;
            }
            let cached = if cutoff.is_some() {
                visitor.prev(&path)?
            } else {
                None
            };
            let entry = self.entry_of(
                &path,
                &stamped,
                opts.capture,
                cached.as_ref(),
                cutoff,
                &mut stats,
            )?;
            stats.entries += 1;
            visitor.visit(&path, &entry)?;
            if is_dir && self.unlistable.borrow().contains(&path) {
                stats.warnings_total += 1;
                stats
                    .warnings
                    .push(format!("cannot list directory {}", path.display()));
                visitor.carry_forward(&path)?;
                carried = Some(path);
            }
        }
        Ok(stats)
    }

    fn observe(&self, path: &RelPath) -> Result<Observation> {
        let n = self.observe_calls.get() + 1;
        self.observe_calls.set(n);
        if let Some(hook) = self.observe_hook.borrow().as_ref() {
            hook(self, n);
        }
        match self.parents_are_safe(path) {
            Err((true, why)) => return Ok(Observation::Unsafe(why)),
            Err((false, why)) => return Ok(Observation::Obstructed(why)),
            Ok(()) => {}
        }
        let nodes = self.nodes.borrow();
        let Some(s) = nodes.get(path) else {
            return Ok(Observation::State(None));
        };
        let mut stats = ScanStats::default();
        Ok(Observation::State(Some(
            self.entry_of(path, s, false, None, None, &mut stats)?,
        )))
    }

    fn apply(&self, item: &PlanItem, dir_modes: &mut Vec<(RelPath, u32)>) -> Result<Outcome> {
        if let Err((_, why)) = self.parents_are_safe(&item.path) {
            return Err(Error::Unsafe(why));
        }
        let path = &item.path;
        let has_children =
            |nodes: &BTreeMap<RelPath, Stamped>| nodes.keys().any(|k| k.is_below(path));
        if item.replace {
            let is_dir = matches!(
                self.nodes.borrow().get(path).map(|s| &s.node),
                Some(Node::Dir { .. })
            );
            if is_dir {
                if has_children(&self.nodes.borrow()) {
                    return Ok(Outcome::Skipped(
                        "directory in the way could not be removed (not empty)".into(),
                    ));
                }
                self.nodes.borrow_mut().remove(path);
            } else {
                self.nodes.borrow_mut().remove(path);
            }
        }
        let t = self.stamp();
        match item.op {
            Op::None => Ok(Outcome::Skipped("nothing to do".into())),
            Op::Delete => {
                if matches!(
                    self.nodes.borrow().get(path).map(|s| &s.node),
                    Some(Node::Dir { .. })
                ) {
                    return Err(Error::Unsafe(format!("{} is a directory", path.display())));
                }
                self.nodes.borrow_mut().remove(path);
                Ok(Outcome::Applied)
            }
            Op::Rmdir => {
                if has_children(&self.nodes.borrow()) {
                    return Ok(Outcome::Skipped("directory not removed (not empty); it may contain files that are not tracked".into()));
                }
                self.nodes.borrow_mut().remove(path);
                Ok(Outcome::Applied)
            }
            Op::Mkdir => {
                let mode = item.target.as_ref().map_or(0o755, Entry::mode);
                self.insert_rel(path.clone(), Node::Dir { mode: 0o700 });
                if mode & 0o777 != 0o700 {
                    dir_modes.push((path.clone(), mode));
                }
                Ok(Outcome::Applied)
            }
            Op::Write => {
                let target = item
                    .target
                    .as_ref()
                    .ok_or_else(|| Error::Other("write without target".into()))?;
                let digest = target
                    .blob()
                    .ok_or_else(|| Error::Other("write without blob".into()))?;
                let content = self.blobs.read(&digest, u64::MAX)?;
                if sha256(&content) != digest {
                    return Err(Error::Integrity(format!(
                        "stored blob {} is corrupt (content hash mismatch); {} was not modified",
                        to_hex(&digest),
                        path.display()
                    )));
                }
                self.insert_rel(
                    path.clone(),
                    Node::File {
                        content,
                        mode: target.mode() & 0o777,
                    },
                );
                if let Some(s) = self.nodes.borrow_mut().get_mut(path) {
                    s.mtime = target.mtime_ns();
                    s.ctime = t;
                }
                Ok(Outcome::Applied)
            }
            Op::Symlink => {
                let target = item
                    .target
                    .as_ref()
                    .and_then(Entry::target)
                    .ok_or_else(|| Error::Other("symlink without target".into()))?
                    .to_vec();
                self.insert_rel(path.clone(), Node::Symlink { target });
                Ok(Outcome::Applied)
            }
            Op::Chmod => {
                let mode = item.target.as_ref().map_or(0o644, Entry::mode);
                if item.target.as_ref().is_some_and(|t| t.kind() == Kind::Dir) {
                    dir_modes.push((path.clone(), mode));
                } else {
                    self.chmod_rel(path, mode & 0o777);
                }
                Ok(Outcome::Applied)
            }
        }
    }

    fn set_dir_mode(&self, path: &RelPath, mode: u32) -> Result<()> {
        self.chmod_rel(path, mode & 0o777);
        Ok(())
    }
}

// ------------------------------------------------------------------ runner

type Action = dyn Fn(&RunRequest);

/// Runs a closure instead of a process (the closure plays the agent).
pub struct ScriptedRunner {
    action: Box<Action>,
    outcome: RefCell<RunOutcome>,
    requests: RefCell<Vec<RunRequest>>,
}

impl ScriptedRunner {
    pub fn new(action: impl Fn(&RunRequest) + 'static, outcome: RunOutcome) -> ScriptedRunner {
        ScriptedRunner {
            action: Box::new(action),
            outcome: RefCell::new(outcome),
            requests: RefCell::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<RunRequest> {
        self.requests.borrow().clone()
    }

    pub fn set_outcome(&self, o: RunOutcome) {
        *self.outcome.borrow_mut() = o;
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(&self, request: &RunRequest) -> Result<RunOutcome> {
        self.requests.borrow_mut().push(request.clone());
        let outcome = self.outcome.borrow().clone();
        if matches!(outcome, RunOutcome::Exited(_)) {
            (self.action)(request);
        }
        Ok(outcome)
    }
}

// ------------------------------------------------------------------- world

/// A complete in-memory environment: all fakes wired together.
pub struct World {
    pub clock: Rc<TickingClock>,
    pub events: Rc<RecordingSink>,
    pub locks: MemLocker,
    pub journal: MemJournal,
    pub snapshots: Rc<MemSnapshots>,
    pub blobs: Rc<MemBlobs>,
    pub tree: Rc<MemTree>,
    pub runner: ScriptedRunner,
}

impl World {
    pub fn new() -> World {
        World::with_runner(ScriptedRunner::new(
            |_| {},
            RunOutcome::Exited(agent_undo_domain::journal::ExitInfo::Code(0)),
        ))
    }

    pub fn with_runner(runner: ScriptedRunner) -> World {
        World::with_cap_and_runner(25 * 1024 * 1024, runner)
    }

    pub fn with_cap_and_runner(cap: u64, runner: ScriptedRunner) -> World {
        let blobs = Rc::new(MemBlobs::new());
        World {
            clock: Rc::new(TickingClock::new(1_700_000_000_000_000_000, 10_000_000_000)),
            events: Rc::new(RecordingSink::new()),
            locks: MemLocker::new(),
            journal: MemJournal::new(),
            snapshots: Rc::new(MemSnapshots::new()),
            tree: Rc::new(MemTree::new(blobs.clone(), cap)),
            blobs,
            runner,
        }
    }

    /// Runs `f` with the ports bundle.
    pub fn with_ports<T>(&self, f: impl FnOnce(&Ports<'_>) -> T) -> T {
        let blobs = self.blobs.clone();
        let snapshots = self.snapshots.clone();
        let tree = self.tree.clone();
        let ports = Ports {
            clock: self.clock.as_ref(),
            events: self.events.as_ref(),
            locks: &self.locks,
            journal: &self.journal,
            snapshots: &snapshots,
            blobs: &blobs,
            tree: &tree,
            runner: &self.runner,
        };
        f(&ports)
    }
}

impl Default for World {
    fn default() -> Self {
        World::new()
    }
}
