//! Ports: everything the use cases need from the outside world. Adapters in the
//! infrastructure crate implement them; in-memory fakes in [`crate::fakes`]
//! implement them for tests. All methods take `&self`; implementations use
//! interior mutability where they hold state.

use crate::error::{Error, Result};
use crate::events::Event;
use agent_undo_domain::change::{Change, EntrySource};
use agent_undo_domain::entry::Entry;
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::hash::{Digest, sha256};
use agent_undo_domain::journal::{CheckpointId, CheckpointRecord, ExitInfo, Journal};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Outcome, PlanItem};

/// Source of time (nanoseconds since the Unix epoch).
pub trait Clock {
    fn now_ns(&self) -> i64;
}

/// Receives events published by use cases.
pub trait EventSink {
    fn publish(&self, event: Event);
}

/// Held while a lock is owned; releasing happens on drop.
pub trait LockGuard {}

/// Serializes operations on one store (the transaction boundary).
pub trait Locker {
    /// Exclusive lock for mutating operations; `Error::Locked` if unavailable.
    fn exclusive(&self) -> Result<Box<dyn LockGuard>>;
    /// Shared lock for read-only operations; `Error::Locked` while a writer holds it.
    fn shared(&self) -> Result<Box<dyn LockGuard>>;
}

/// Persistence of the journal aggregate.
pub trait JournalRepository {
    /// Loads the journal; `Error::Integrity` if the recorded history is inconsistent.
    fn load(&self) -> Result<Journal>;
    /// Durably appends a sealed record.
    fn append(&self, record: &CheckpointRecord) -> Result<()>;
    /// Durably records that these checkpoints were pruned.
    fn save_pruned(&self, ids: &[CheckpointId]) -> Result<()>;
}

pub type ManifestStream = Box<dyn EntrySource<Error = Error>>;

pub trait ChangeStream {
    fn next_change(&mut self) -> Result<Option<Change>>;
}

/// Digests and entry count of a committed checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    pub manifest: Digest,
    pub changes: Digest,
    pub entries: u64,
}

/// Writes one checkpoint's manifest and change set. Dropping the writer without
/// committing discards everything.
pub trait CheckpointWriter {
    /// Entries must be written in increasing path order.
    fn write_entry(&mut self, path: &RelPath, entry: &Entry) -> Result<()>;
    fn write_change(&mut self, change: &Change) -> Result<()>;
    fn commit(self: Box<Self>) -> Result<Written>;
}

/// Digests recomputed from the stored bytes of a checkpoint (for `verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredDigests {
    pub manifest: Digest,
    pub changes: Digest,
}

/// Manifests and change sets of checkpoints.
pub trait SnapshotRepository {
    fn open_manifest(&self, id: CheckpointId) -> Result<ManifestStream>;
    fn open_changes(&self, id: CheckpointId) -> Result<Box<dyn ChangeStream>>;
    fn begin(&self, id: CheckpointId) -> Result<Box<dyn CheckpointWriter>>;
    fn remove(&self, id: CheckpointId) -> Result<()>;
    /// Recomputes digests from stored bytes; `Error::Integrity` if files are missing.
    fn stored_digests(&self, id: CheckpointId) -> Result<StoredDigests>;
    /// Ids that have stored files (including orphans).
    fn list(&self) -> Result<Vec<CheckpointId>>;
}

/// A blob being written; becomes visible only through `commit`.
pub trait BlobWriter {
    fn write(&mut self, chunk: &[u8]) -> Result<()>;
    /// Stores the blob if its digest equals `expected` (`Ok(false)` otherwise; nothing is kept).
    fn commit(self: Box<Self>, expected: &Digest) -> Result<bool>;
}

#[derive(Debug, Clone, Default)]
pub struct BlobListing {
    pub blobs: Vec<(Digest, u64)>,
    /// Names in the blob area that are not blobs.
    pub strays: Vec<String>,
}

/// Content-addressed file contents.
pub trait BlobStore {
    fn contains(&self, digest: &Digest) -> bool;
    /// Reads a blob; `Error::Integrity` if missing, `Error::Limit` above `cap`.
    fn read(&self, digest: &Digest, cap: u64) -> Result<Vec<u8>>;
    /// Re-hashes the stored bytes of a blob.
    fn hash_stored(&self, digest: &Digest) -> Result<Digest>;
    fn list(&self) -> Result<BlobListing>;
    fn remove(&self, digest: &Digest) -> Result<()>;
    fn writer(&self) -> Result<Box<dyn BlobWriter>>;

    /// Convenience: stores `data`, returning its digest.
    fn put(&self, data: &[u8]) -> Result<Digest> {
        let d = sha256(data);
        if !self.contains(&d) {
            let mut w = self.writer()?;
            w.write(data)?;
            w.commit(&d)?;
        }
        Ok(d)
    }
}

/// How a scan treats file content and the stat cache.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Store non-sensitive file contents as blobs.
    pub capture: bool,
    /// Start time of the snapshot behind the previous manifest (enables the stat cache).
    pub cache_time_ns: Option<i64>,
    pub cache_margin_ns: i64,
    pub no_cache: bool,
}

impl ScanOptions {
    pub fn capturing(cache_time_ns: Option<i64>) -> ScanOptions {
        ScanOptions {
            capture: true,
            cache_time_ns,
            cache_margin_ns: 2_000_000_000,
            no_cache: false,
        }
    }

    pub fn observing(cache_time_ns: Option<i64>) -> ScanOptions {
        ScanOptions {
            capture: false,
            ..ScanOptions::capturing(cache_time_ns)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub entries: u64,
    pub files_hashed: u64,
    pub files_cached: u64,
    pub bytes_hashed: u64,
    pub blobs_written: u64,
    pub bytes_stored: u64,
    pub warnings: Vec<String>,
    pub warnings_total: u64,
}

/// Receives entries in manifest order and answers stat-cache lookups.
pub trait ScanVisitor {
    /// Previous entry for `path`, if any.
    fn prev(&mut self, path: &RelPath) -> Result<Option<Entry>>;
    fn visit(&mut self, path: &RelPath, entry: &Entry) -> Result<()>;
    /// A directory could not be listed: keep the previous entries below it.
    fn carry_forward(&mut self, dir: &RelPath) -> Result<()>;
}

/// The project directory as seen and modified by agent-undo.
pub trait WorkingTree {
    /// Walks the project in manifest order (directories before their contents,
    /// siblings sorted by name), skipping ignored paths.
    fn scan(&self, opts: &ScanOptions, visitor: &mut dyn ScanVisitor) -> Result<ScanStats>;
    /// Current state of one path (ignore rules do not apply), or `Observation::Unsafe`
    /// if it cannot be inspected without leaving the project (symlinked parent).
    fn observe(&self, path: &RelPath) -> Result<Observation>;
    /// Executes one plan item. Must itself refuse to leave the project root or
    /// follow symlinks. Directory permission changes are returned in `dir_modes`
    /// and applied later through [`WorkingTree::set_dir_mode`].
    fn apply(&self, item: &PlanItem, dir_modes: &mut Vec<(RelPath, u32)>) -> Result<Outcome>;
    fn set_dir_mode(&self, path: &RelPath, mode: u32) -> Result<()>;
}

/// What to run.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub args: Vec<Vec<u8>>,
    pub env: EnvPolicy,
    /// Variables added to the child environment (`AGENT_UNDO_*`).
    pub extra_env: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Exited(ExitInfo),
    NotFound,
    CannotExecute(String),
}

/// Runs the wrapped command with inherited stdio, in the project directory.
pub trait CommandRunner {
    fn run(&self, request: &RunRequest) -> Result<RunOutcome>;
}

/// Bundle of ports handed to every use case.
pub struct Ports<'a> {
    pub clock: &'a dyn Clock,
    pub events: &'a dyn EventSink,
    pub locks: &'a dyn Locker,
    pub journal: &'a dyn JournalRepository,
    pub snapshots: &'a dyn SnapshotRepository,
    pub blobs: &'a dyn BlobStore,
    pub tree: &'a dyn WorkingTree,
    pub runner: &'a dyn CommandRunner,
}
