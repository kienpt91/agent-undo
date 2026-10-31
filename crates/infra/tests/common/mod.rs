//! Shared harness and generic contract suites for the adapter contract tests.
//!
//! Every contract is a generic function over a port trait. Each `contract_*.rs`
//! test file runs the very same function twice through `contract_suite!`: once
//! against the in-memory fake from `agent_undo_app::fakes` and once against the
//! real filesystem adapter in a fresh temp directory.
#![allow(dead_code, clippy::too_many_lines)]

use agent_undo_app::error::{Error, Result};
use agent_undo_app::fakes::{MemBlobs, MemJournal, MemLocker, MemSnapshots, MemTree, Node};
use agent_undo_app::ports::{
    BlobListing, BlobStore, BlobWriter, ChangeStream, CheckpointWriter, JournalRepository,
    LockGuard, Locker, ManifestStream, ScanOptions, ScanStats, ScanVisitor, SnapshotRepository,
    StoredDigests, WorkingTree, Written,
};
use agent_undo_domain::change::{Change, Counts, EntrySource};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::hash::{Digest, sha256};
use agent_undo_domain::journal::CkptKind;
use agent_undo_domain::journal::{
    ArgPolicy, CheckpointId, CheckpointRecord, CommandLine, ExitInfo, Journal, Label,
    MAX_LABEL_BYTES, NewCheckpoint,
};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Op, Outcome, PlanItem, Status, build_item};
use agent_undo_infra::fs_blobs::FsBlobs;
use agent_undo_infra::fs_journal::FsJournal;
use agent_undo_infra::fs_snapshots::FsSnapshots;
use agent_undo_infra::fs_tree::FsTree;
use agent_undo_infra::layout::StoreDir;
use agent_undo_infra::lock::FsLocker;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Runs every listed contract function against the fake and the real adapter.
/// Generates `fake::<name>` and `fs::<name>` tests from one body.
macro_rules! contract_suite {
    ($make_fake:expr, $make_fs:expr; $($test:ident),* $(,)?) => {
        mod fake {
            $( #[test] fn $test() { $crate::common::$test($make_fake) } )*
        }
        mod fs {
            $( #[test] fn $test() { $crate::common::$test($make_fs) } )*
        }
    };
}

// ------------------------------------------------------------------ helpers

pub const BIG_CAP: u64 = 25 * 1024 * 1024;
const T0: i64 = 1_700_000_000_000_000_000;

pub struct TempDir(PathBuf);

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = base.join(format!(
            "agent-undo-contract-{tag}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn rp(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

pub fn id(n: u64) -> CheckpointId {
    CheckpointId::new(n).unwrap()
}

/// The error of a failed result (the Ok types of several ports are not `Debug`).
pub fn err_of<T>(r: Result<T>) -> Error {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected an error, got Ok"),
    }
}

pub fn now_ns() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap()
}

/// Deterministic pseudo-random bytes.
pub fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

pub fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A token shape the content scanner flags (assembled at runtime).
pub fn secret_token() -> String {
    format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
}

pub fn private_key_block() -> String {
    format!(
        "-----BEGIN {} KEY-----\nbW9ja2JvZHktbm90LWEta2V5LWp1c3QtZmlsbGVy\n-----END {} KEY-----\n",
        "RSA PRIVATE", "RSA PRIVATE"
    )
}

pub fn dotenv_text() -> String {
    format!("{}={}\n", "TOKEN", "x9Kq2LmZ4vB7nR1tYw3Hs8Dc")
}

pub fn file_entry(content: &[u8], mode: u32) -> Entry {
    let m = T0;
    Entry::hashed(
        Kind::File,
        &sha256(content),
        mode,
        content.len() as u64,
        m,
        m,
    )
    .unwrap()
}

// ======================================================================
// Blob store
// ======================================================================

pub fn fake_blobs() -> Rc<MemBlobs> {
    Rc::new(MemBlobs::new())
}

pub struct FsBlobEnv {
    inner: FsBlobs,
    _tmp: TempDir,
}

pub fn fs_blobs() -> FsBlobEnv {
    let tmp = TempDir::new("blobs");
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&tmp.path().join("store"), &root, false, BIG_CAP).unwrap();
    FsBlobEnv {
        inner: FsBlobs::new(store.blobs_dir(), store.tmp_dir()),
        _tmp: tmp,
    }
}

impl BlobStore for FsBlobEnv {
    fn contains(&self, digest: &Digest) -> bool {
        self.inner.contains(digest)
    }
    fn read(&self, digest: &Digest, cap: u64) -> Result<Vec<u8>> {
        self.inner.read(digest, cap)
    }
    fn hash_stored(&self, digest: &Digest) -> Result<Digest> {
        self.inner.hash_stored(digest)
    }
    fn list(&self) -> Result<BlobListing> {
        self.inner.list()
    }
    fn remove(&self, digest: &Digest) -> Result<()> {
        self.inner.remove(digest)
    }
    fn writer(&self) -> Result<Box<dyn BlobWriter>> {
        self.inner.writer()
    }
}

fn sorted_blobs(s: &impl BlobStore) -> Vec<(Digest, u64)> {
    let mut v = s.list().unwrap().blobs;
    v.sort();
    v
}

fn commit_chunks(s: &impl BlobStore, chunks: &[&[u8]], expected: &Digest) -> bool {
    let mut w = s.writer().unwrap();
    for c in chunks {
        w.write(c).unwrap();
    }
    w.commit(expected).unwrap()
}

pub fn blob_put_read_roundtrip<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let data = b"hello blob".to_vec();
    let d = sha256(&data);
    assert!(!s.contains(&d));
    assert_eq!(s.put(&data).unwrap(), d);
    assert!(s.contains(&d));
    assert_eq!(s.read(&d, data.len() as u64).unwrap(), data);

    let empty = s.put(b"").unwrap();
    assert_eq!(empty, sha256(b""));
    assert!(s.contains(&empty));
    assert_eq!(s.read(&empty, 0).unwrap(), Vec::<u8>::new());

    let binary: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let bd = s.put(&binary).unwrap();
    assert_eq!(s.read(&bd, u64::MAX).unwrap(), binary);
    assert!(!s.contains(&sha256(b"something else")));
}

pub fn blob_read_cap_yields_limit_error<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let data = vec![7u8; 100];
    let d = s.put(&data).unwrap();
    assert!(matches!(s.read(&d, 99), Err(Error::Limit(_))));
    assert!(matches!(s.read(&d, 0), Err(Error::Limit(_))));
    assert_eq!(s.read(&d, 100).unwrap().len(), 100);
    assert_eq!(s.read(&d, u64::MAX).unwrap().len(), 100);
    // the blob is intact after a refused read
    assert_eq!(s.hash_stored(&d).unwrap(), d);
}

pub fn blob_missing_is_integrity_error<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let d = sha256(b"never stored");
    assert!(!s.contains(&d));
    assert!(matches!(s.read(&d, 1024), Err(Error::Integrity(_))));
    assert!(matches!(s.hash_stored(&d), Err(Error::Integrity(_))));
    // also after having existed
    let stored = s.put(b"temporary").unwrap();
    s.remove(&stored).unwrap();
    assert!(matches!(s.read(&stored, 1024), Err(Error::Integrity(_))));
    assert!(matches!(s.hash_stored(&stored), Err(Error::Integrity(_))));
}

pub fn blob_writer_wrong_digest_stores_nothing<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let wrong = sha256(b"not the content");
    let mut w = s.writer().unwrap();
    w.write(b"abc").unwrap();
    assert!(!w.commit(&wrong).unwrap());
    assert!(!s.contains(&wrong));
    assert!(!s.contains(&sha256(b"abc")));
    let l = s.list().unwrap();
    assert!(l.blobs.is_empty(), "{:?}", l.blobs);
    assert!(l.strays.is_empty(), "{:?}", l.strays);
    // the store is still usable afterwards, with the right digest
    assert!(commit_chunks(&s, &[b"abc"], &sha256(b"abc")));
    assert_eq!(s.read(&sha256(b"abc"), 10).unwrap(), b"abc");
}

pub fn blob_dropped_writer_stores_nothing<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    {
        let mut w = s.writer().unwrap();
        w.write(b"never committed").unwrap();
    }
    drop(s.writer().unwrap());
    assert!(!s.contains(&sha256(b"never committed")));
    let l = s.list().unwrap();
    assert!(l.blobs.is_empty());
    assert!(l.strays.is_empty(), "{:?}", l.strays);
}

pub fn blob_multichunk_writer_matches_put<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let data = noise(11, 10_000);
    let (a, rest) = data.split_at(1);
    let (b, c) = rest.split_at(4097);
    let d = sha256(&data);
    assert!(commit_chunks(&s, &[a, b, c, b""], &d));
    assert_eq!(s.read(&d, u64::MAX).unwrap(), data);
    // identical content through put() lands on the same blob
    assert_eq!(s.put(&data).unwrap(), d);
    assert_eq!(sorted_blobs(&s), vec![(d, data.len() as u64)]);
}

pub fn blob_hash_stored_equals_digest<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    for (i, len) in [0usize, 1, 64, 65_536, 65_537, 200_000]
        .into_iter()
        .enumerate()
    {
        let data = noise(i as u64 + 100, len);
        let d = s.put(&data).unwrap();
        assert_eq!(s.hash_stored(&d).unwrap(), d, "len {len}");
    }
}

pub fn blob_list_reports_blobs_and_sizes<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let l = s.list().unwrap();
    assert!(l.blobs.is_empty() && l.strays.is_empty());

    let contents: Vec<Vec<u8>> = vec![b"one".to_vec(), vec![9u8; 5000], Vec::new()];
    let mut expected: Vec<(Digest, u64)> = contents
        .iter()
        .map(|c| (s.put(c).unwrap(), c.len() as u64))
        .collect();
    expected.sort();
    let l = s.list().unwrap();
    let mut got = l.blobs.clone();
    got.sort();
    assert_eq!(got, expected);
    assert!(l.strays.is_empty(), "{:?}", l.strays);
}

pub fn blob_remove_is_idempotent<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let missing = sha256(b"missing");
    s.remove(&missing).unwrap();
    let keep = s.put(b"keep me").unwrap();
    let gone = s.put(b"remove me").unwrap();
    s.remove(&gone).unwrap();
    assert!(!s.contains(&gone));
    s.remove(&gone).unwrap();
    assert!(s.contains(&keep));
    assert_eq!(s.read(&keep, 100).unwrap(), b"keep me");
    assert_eq!(sorted_blobs(&s), vec![(keep, 7)]);
}

pub fn blob_put_is_idempotent_and_deduplicates<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let a = s.put(b"same bytes").unwrap();
    let b = s.put(b"same bytes").unwrap();
    assert_eq!(a, b);
    assert_eq!(s.list().unwrap().blobs.len(), 1);
    // committing a writer for content that already exists is fine and keeps one blob
    assert!(commit_chunks(&s, &[b"same bytes"], &a));
    assert_eq!(s.list().unwrap().blobs.len(), 1);
    assert_eq!(s.read(&a, 100).unwrap(), b"same bytes");
    assert_eq!(s.list().unwrap().strays.len(), 0);
}

pub fn blob_large_multichunk_roundtrip<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let data = noise(42, 300 * 1024);
    let d = s.put(&data).unwrap();
    assert_eq!(d, sha256(&data));
    assert_eq!(s.read(&d, data.len() as u64).unwrap(), data);
    assert!(matches!(
        s.read(&d, data.len() as u64 - 1),
        Err(Error::Limit(_))
    ));
    assert_eq!(s.hash_stored(&d).unwrap(), d);
    assert_eq!(sorted_blobs(&s), vec![(d, data.len() as u64)]);

    // the same content streamed through a writer in odd-sized chunks
    let other = noise(43, 300 * 1024 + 17);
    let od = sha256(&other);
    let chunks: Vec<&[u8]> = other.chunks(7001).collect();
    assert!(commit_chunks(&s, &chunks, &od));
    assert_eq!(s.read(&od, u64::MAX).unwrap(), other);
    assert_eq!(s.hash_stored(&od).unwrap(), od);
}

pub fn blob_independent_writers_do_not_interfere<S: BlobStore>(make: impl Fn() -> S) {
    let s = make();
    let mut w1 = s.writer().unwrap();
    let mut w2 = s.writer().unwrap();
    let mut w3 = s.writer().unwrap();
    w1.write(b"first-").unwrap();
    w2.write(b"second-").unwrap();
    w3.write(b"first-").unwrap();
    w1.write(b"blob").unwrap();
    w2.write(b"blob").unwrap();
    w3.write(b"blob").unwrap();
    assert!(w1.commit(&sha256(b"first-blob")).unwrap());
    assert!(w2.commit(&sha256(b"second-blob")).unwrap());
    // a writer of identical content to an existing blob also commits
    assert!(w3.commit(&sha256(b"first-blob")).unwrap());
    assert_eq!(s.list().unwrap().blobs.len(), 2);
    assert_eq!(s.read(&sha256(b"first-blob"), 100).unwrap(), b"first-blob");
    assert_eq!(
        s.read(&sha256(b"second-blob"), 100).unwrap(),
        b"second-blob"
    );
}

// ======================================================================
// Snapshot repository
// ======================================================================

pub fn fake_snapshots() -> Rc<MemSnapshots> {
    Rc::new(MemSnapshots::new())
}

pub struct FsSnapshotEnv {
    inner: FsSnapshots,
    pub tmp_dir: PathBuf,
    _tmp: TempDir,
}

pub fn fs_snapshots() -> FsSnapshotEnv {
    let tmp = TempDir::new("snaps");
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&tmp.path().join("store"), &root, false, BIG_CAP).unwrap();
    FsSnapshotEnv {
        inner: FsSnapshots::new(store.checkpoints_dir(), store.tmp_dir()),
        tmp_dir: store.tmp_dir(),
        _tmp: tmp,
    }
}

impl SnapshotRepository for FsSnapshotEnv {
    fn open_manifest(&self, id: CheckpointId) -> Result<ManifestStream> {
        self.inner.open_manifest(id)
    }
    fn open_changes(&self, id: CheckpointId) -> Result<Box<dyn ChangeStream>> {
        self.inner.open_changes(id)
    }
    fn begin(&self, id: CheckpointId) -> Result<Box<dyn CheckpointWriter>> {
        self.inner.begin(id)
    }
    fn remove(&self, id: CheckpointId) -> Result<()> {
        self.inner.remove(id)
    }
    fn stored_digests(&self, id: CheckpointId) -> Result<StoredDigests> {
        self.inner.stored_digests(id)
    }
    fn list(&self) -> Result<Vec<CheckpointId>> {
        self.inner.list()
    }
}

type Manifest = Vec<(RelPath, Entry)>;

fn sort_manifest(m: &mut Manifest) {
    m.sort_by(|a, b| a.0.cmp(&b.0));
}

fn hostile_names() -> Vec<Vec<u8>> {
    vec![
        b"line\nbreak".to_vec(),
        b"esc\x1b[31mred".to_vec(),
        b"with space/and  double".to_vec(),
        vec![b'b', 0xff, 0xfe, b'x'],
        b"tab\there".to_vec(),
        b"100%/%41/%".to_vec(),
        b"back\\slash".to_vec(),
        "\u{fc}n\u{ef}code/\u{65e5}\u{672c}".as_bytes().to_vec(),
        b"-leading-dash".to_vec(),
        b"quote\"s'".to_vec(),
        "bidi\u{202e}name".as_bytes().to_vec(),
        b"cr\rname".to_vec(),
        b"comma,name,x".to_vec(),
    ]
}

fn golden_manifest() -> Manifest {
    let mut m: Manifest = Vec::new();
    let mut add = |p: &[u8], e: Entry| m.push((RelPath::new(p.to_vec()).unwrap(), e));
    add(b"src", Entry::dir(0o755, 10, 11));
    add(b"src/main.rs", file_entry(b"fn main() {}", 0o644));
    add(b"src/a-b", file_entry(b"dash", 0o600));
    add(b"src/a.b", file_entry(b"dot", 0o600));
    add(b"src/a", Entry::dir(0o700, 1, 2));
    add(b"src/a/inner", file_entry(b"inner", 0o755));
    add(
        b"link",
        Entry::symlink(b"../t\narget\xff with space".to_vec(), 5, 6).unwrap(),
    );
    add(
        b"huge.bin",
        Entry::hashed(Kind::TooLarge, &sha256(b"huge"), 0o644, 1 << 40, 7, 8).unwrap(),
    );
    add(
        b".env",
        Entry::hashed(Kind::Sensitive, &sha256(b"keyed"), 0o600, 31, 9, 10).unwrap(),
    );
    add(b"fifo", Entry::special(0o600, 3, 4));
    add(b"locked", Entry::unreadable(0o000, 12, 13, 14));
    add(b"empty.txt", file_entry(b"", 0o644));
    for n in hostile_names() {
        add(&n, file_entry(&n, 0o644));
    }
    sort_manifest(&mut m);
    m.dedup_by(|a, b| a.0 == b.0);
    m
}

fn golden_changes(m: &Manifest) -> Vec<Change> {
    let find = |p: &str| {
        m.iter()
            .find(|(k, _)| k.as_bytes() == p.as_bytes())
            .unwrap()
            .1
            .clone()
    };
    let main = find("src/main.rs");
    let changed = file_entry(b"fn main() { changed }", 0o644);
    vec![
        Change::new(rp("src/main.rs"), Some(main.clone()), Some(changed)).unwrap(),
        Change::new(rp("src/new.rs"), None, Some(file_entry(b"new", 0o644))).unwrap(),
        Change::new(rp("src/gone.rs"), Some(file_entry(b"gone", 0o644)), None).unwrap(),
        Change::new(
            rp("src/a-b"),
            Some(file_entry(b"dash", 0o600)),
            Some(file_entry(b"dash", 0o755)),
        )
        .unwrap(),
        Change::new(
            RelPath::new(b"odd\nname\xff".to_vec()).unwrap(),
            None,
            Some(find("link")),
        )
        .unwrap(),
        Change::new(rp("src"), Some(Entry::dir(0o755, 1, 1)), None).unwrap(),
    ]
}

fn write_checkpoint(
    repo: &impl SnapshotRepository,
    n: u64,
    entries: &Manifest,
    changes: &[Change],
) -> Written {
    let mut w = repo.begin(id(n)).unwrap();
    for (p, e) in entries {
        w.write_entry(p, e).unwrap();
    }
    for c in changes {
        w.write_change(c).unwrap();
    }
    w.commit().unwrap()
}

fn read_manifest(repo: &impl SnapshotRepository, n: u64) -> Manifest {
    let mut s = repo.open_manifest(id(n)).unwrap();
    let mut out = Vec::new();
    while let Some(x) = s.next_entry().unwrap() {
        out.push(x);
    }
    out
}

fn read_changes(repo: &impl SnapshotRepository, n: u64) -> Vec<Change> {
    let mut s = repo.open_changes(id(n)).unwrap();
    let mut out = Vec::new();
    while let Some(x) = s.next_change().unwrap() {
        out.push(x);
    }
    out
}

fn many_entries(count: usize) -> Manifest {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut m: Manifest = (0..count)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let path = format!("d{:02}/sub{}/f{:05}", x % 37, x % 3, i);
            let body = i.to_string();
            (rp(&path), file_entry(body.as_bytes(), 0o644))
        })
        .collect();
    sort_manifest(&mut m);
    m
}

pub fn snapshot_commit_and_stream_roundtrip<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let entries = golden_manifest();
    let changes = golden_changes(&entries);
    let w = write_checkpoint(&repo, 1, &entries, &changes);
    assert_eq!(w.entries, entries.len() as u64);
    assert_eq!(read_manifest(&repo, 1), entries);
    assert_eq!(read_changes(&repo, 1), changes);
    assert_eq!(repo.list().unwrap(), vec![id(1)]);
}

pub fn snapshot_stored_digests_equal_written<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let entries = golden_manifest();
    let changes = golden_changes(&entries);
    let w = write_checkpoint(&repo, 4, &entries, &changes);
    let s = repo.stored_digests(id(4)).unwrap();
    assert_eq!(s.manifest, w.manifest);
    assert_eq!(s.changes, w.changes);
    assert_ne!(w.manifest, w.changes);
}

pub fn snapshot_digests_depend_only_on_their_own_stream<S: SnapshotRepository>(
    make: impl Fn() -> S,
) {
    let repo = make();
    let entries = golden_manifest();
    let changes = golden_changes(&entries);
    let base = write_checkpoint(&repo, 1, &entries, &changes);

    // different changes, same entries: manifest digest unchanged, changes digest differs
    let w2 = write_checkpoint(&repo, 2, &entries, &changes[..2]);
    assert_eq!(w2.manifest, base.manifest);
    assert_ne!(w2.changes, base.changes);

    // different entries, same changes
    let mut fewer = entries.clone();
    fewer.pop();
    let w3 = write_checkpoint(&repo, 3, &fewer, &changes);
    assert_ne!(w3.manifest, base.manifest);
    assert_eq!(w3.changes, base.changes);

    // an entry that differs only in mode changes the digest
    let mut moded = entries.clone();
    if let Some(slot) = moded.iter_mut().find(|(_, e)| e.kind() == Kind::File) {
        slot.1 = slot.1.with_mode(0o777);
    }
    let w4 = write_checkpoint(&repo, 5, &moded, &changes);
    assert_ne!(w4.manifest, base.manifest);

    // the same logical content in another checkpoint number gives the same digests
    let again = write_checkpoint(&repo, 6, &entries, &changes);
    assert_eq!(again.manifest, base.manifest);
    assert_eq!(again.changes, base.changes);
}

/// Digests of several logical checkpoints; the cross-implementation test
/// compares these between the fake and the real adapter.
pub fn snapshot_scenario_digests<S: SnapshotRepository>(make: impl Fn() -> S) -> Vec<Written> {
    let repo = make();
    let golden = golden_manifest();
    let golden_changes = golden_changes(&golden);
    let many = many_entries(500);
    vec![
        write_checkpoint(&repo, 1, &Vec::new(), &[]),
        write_checkpoint(&repo, 2, &golden, &golden_changes),
        write_checkpoint(&repo, 3, &many, &[]),
        write_checkpoint(&repo, 4, &Vec::new(), &golden_changes),
    ]
}

pub fn snapshot_empty_checkpoint<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let w = write_checkpoint(&repo, 1, &Vec::new(), &[]);
    assert_eq!(w.entries, 0);
    assert!(read_manifest(&repo, 1).is_empty());
    assert!(read_changes(&repo, 1).is_empty());
    assert_eq!(repo.list().unwrap(), vec![id(1)]);
    let s = repo.stored_digests(id(1)).unwrap();
    assert_eq!((s.manifest, s.changes), (w.manifest, w.changes));
}

pub fn snapshot_out_of_order_entries_are_rejected<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let e = file_entry(b"x", 0o644);
    {
        let mut w = repo.begin(id(1)).unwrap();
        w.write_entry(&rp("b"), &e).unwrap();
        assert!(w.write_entry(&rp("a"), &e).is_err(), "decreasing path");
    }
    {
        let mut w = repo.begin(id(2)).unwrap();
        w.write_entry(&rp("same"), &e).unwrap();
        assert!(w.write_entry(&rp("same"), &e).is_err(), "duplicate path");
    }
    {
        // a directory's contents must follow it, before later siblings ("/" sorts lowest)
        let mut w = repo.begin(id(3)).unwrap();
        w.write_entry(&rp("a-b"), &e).unwrap();
        assert!(w.write_entry(&rp("a/b"), &e).is_err());
    }
    assert!(repo.list().unwrap().is_empty());
}

pub fn snapshot_uncommitted_writer_leaves_nothing<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    {
        let mut w = repo.begin(id(1)).unwrap();
        w.write_entry(&rp("a"), &file_entry(b"a", 0o644)).unwrap();
        w.write_change(&Change::new(rp("a"), None, Some(file_entry(b"a", 0o644))).unwrap())
            .unwrap();
    }
    assert!(repo.list().unwrap().is_empty());
    assert!(matches!(
        err_of(repo.open_manifest(id(1))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.open_changes(id(1))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.stored_digests(id(1))),
        Error::Integrity(_)
    ));
    // a later committed checkpoint is unaffected
    write_checkpoint(&repo, 1, &golden_manifest(), &[]);
    assert_eq!(repo.list().unwrap(), vec![id(1)]);
}

pub fn snapshot_remove_then_open_is_integrity_error<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let entries = golden_manifest();
    write_checkpoint(&repo, 1, &entries, &[]);
    write_checkpoint(&repo, 2, &entries, &[]);
    repo.remove(id(1)).unwrap();
    assert!(matches!(
        err_of(repo.open_manifest(id(1))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.open_changes(id(1))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.stored_digests(id(1))),
        Error::Integrity(_)
    ));
    assert_eq!(repo.list().unwrap(), vec![id(2)]);
    assert_eq!(read_manifest(&repo, 2), entries);
    // removing again, or removing something that never existed, is fine
    repo.remove(id(1)).unwrap();
    repo.remove(id(99)).unwrap();
}

pub fn snapshot_unknown_checkpoint_is_integrity_error<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    assert!(matches!(
        err_of(repo.open_manifest(id(9))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.open_changes(id(9))),
        Error::Integrity(_)
    ));
    assert!(matches!(
        err_of(repo.stored_digests(id(9))),
        Error::Integrity(_)
    ));
    assert!(repo.list().unwrap().is_empty());
}

pub fn snapshot_list_returns_sorted_ids<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    for n in [3, 1, 2, 11] {
        write_checkpoint(&repo, n, &Vec::new(), &[]);
    }
    assert_eq!(repo.list().unwrap(), vec![id(1), id(2), id(3), id(11)]);
    repo.remove(id(2)).unwrap();
    assert_eq!(repo.list().unwrap(), vec![id(1), id(3), id(11)]);
}

pub fn snapshot_hostile_paths_roundtrip_in_order<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let mut m: Manifest = hostile_names()
        .into_iter()
        .map(|n| (RelPath::new(n.clone()).unwrap(), file_entry(&n, 0o644)))
        .collect();
    // plus symlinks whose targets are hostile
    for (i, t) in [
        b"new\nline".to_vec(),
        b"\x1b[2J".to_vec(),
        vec![0xc3, 0x28],
        b"a b  c".to_vec(),
    ]
    .into_iter()
    .enumerate()
    {
        m.push((
            rp(&format!("sym{i}")),
            Entry::symlink(t, i as i64, i as i64).unwrap(),
        ));
    }
    sort_manifest(&mut m);
    let w = write_checkpoint(&repo, 1, &m, &[]);
    assert_eq!(w.entries, m.len() as u64);
    let back = read_manifest(&repo, 1);
    assert_eq!(back, m);
    for (p, e) in &back {
        if e.kind() == Kind::File {
            // the path survived byte-for-byte (the content was derived from it)
            assert_eq!(e.digest().unwrap(), sha256(p.as_bytes()));
        }
    }
    // hostile change paths round trip as well
    let ch: Vec<Change> = m
        .iter()
        .map(|(p, e)| Change::new(p.clone(), None, Some(e.clone())).unwrap())
        .collect();
    let mut w2 = repo.begin(id(2)).unwrap();
    for c in &ch {
        w2.write_change(c).unwrap();
    }
    w2.commit().unwrap();
    assert_eq!(read_changes(&repo, 2), ch);
}

pub fn snapshot_many_entries_stream_back_sorted<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let m = many_entries(5000);
    assert!(m.windows(2).all(|w| w[0].0 < w[1].0), "fixture is sorted");
    let w = write_checkpoint(&repo, 1, &m, &[]);
    assert_eq!(w.entries, 5000);
    let back = read_manifest(&repo, 1);
    assert_eq!(back.len(), 5000);
    assert!(back.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(back, m);
    assert_eq!(repo.stored_digests(id(1)).unwrap().manifest, w.manifest);
}

pub fn snapshot_interleaved_writers_are_independent<S: SnapshotRepository>(make: impl Fn() -> S) {
    let repo = make();
    let a = file_entry(b"a", 0o644);
    let b = file_entry(b"b", 0o644);
    let mut w1 = repo.begin(id(1)).unwrap();
    let mut w2 = repo.begin(id(2)).unwrap();
    w1.write_entry(&rp("one"), &a).unwrap();
    w2.write_entry(&rp("two"), &b).unwrap();
    w1.write_entry(&rp("one2"), &a).unwrap();
    let r1 = w1.commit().unwrap();
    let r2 = w2.commit().unwrap();
    assert_eq!((r1.entries, r2.entries), (2, 1));
    assert_eq!(
        read_manifest(&repo, 1),
        vec![(rp("one"), a.clone()), (rp("one2"), a)]
    );
    assert_eq!(read_manifest(&repo, 2), vec![(rp("two"), b)]);
}

// ======================================================================
// Journal repository
// ======================================================================

/// A journal repository plus the ability to damage what it stored.
pub trait JournalFixture: JournalRepository {
    /// Alters stored record `index` (0-based) without re-sealing it.
    fn corrupt_record(&self, index: usize);
    /// Removes stored record `index` (0-based).
    fn remove_record_at(&self, index: usize);
}

impl JournalFixture for MemJournal {
    fn corrupt_record(&self, index: usize) {
        self.tamper(|r| r[index].time_ns += 1);
    }
    fn remove_record_at(&self, index: usize) {
        self.tamper(|r| {
            r.remove(index);
        });
    }
}

pub fn fake_journal() -> MemJournal {
    MemJournal::new()
}

pub struct FsJournalEnv {
    inner: FsJournal,
    pub log: PathBuf,
    _tmp: TempDir,
}

pub fn fs_journal() -> FsJournalEnv {
    let tmp = TempDir::new("journal");
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    let store = StoreDir::create(&tmp.path().join("store"), &root, false, BIG_CAP).unwrap();
    FsJournalEnv {
        inner: FsJournal::new(store.log_path(), store.pruned_path()),
        log: store.log_path(),
        _tmp: tmp,
    }
}

impl JournalRepository for FsJournalEnv {
    fn load(&self) -> Result<Journal> {
        self.inner.load()
    }
    fn append(&self, record: &CheckpointRecord) -> Result<()> {
        self.inner.append(record)
    }
    fn save_pruned(&self, ids: &[CheckpointId]) -> Result<()> {
        self.inner.save_pruned(ids)
    }
}

impl FsJournalEnv {
    fn lines(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn put_lines(&self, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(&self.log, text).unwrap();
    }

    pub fn append_raw_line(&self, line: &str) {
        let mut l = self.lines();
        l.push(line.to_string());
        self.put_lines(&l);
    }
}

impl JournalFixture for FsJournalEnv {
    fn corrupt_record(&self, index: usize) {
        let mut lines = self.lines();
        let mut fields: Vec<String> = lines[index].split('\t').map(str::to_string).collect();
        // field 3 is the checkpoint time
        let t: i64 = fields[3].parse().unwrap();
        fields[3] = (t + 1).to_string();
        lines[index] = fields.join("\t");
        self.put_lines(&lines);
    }

    fn remove_record_at(&self, index: usize) {
        let mut lines = self.lines();
        lines.remove(index);
        self.put_lines(&lines);
    }
}

fn seal(j: &mut Journal, new: NewCheckpoint) -> CheckpointRecord {
    j.record(new).unwrap().0
}

fn cp(kind: CkptKind, n: i64, counts: Counts, entries: u64) -> NewCheckpoint {
    NewCheckpoint::new(
        kind,
        T0 + n * 1_000,
        sha256(format!("manifest {n}").as_bytes()),
        sha256(format!("changes {n}").as_bytes()),
        counts,
        entries,
    )
}

/// Five sealed records covering every optional field.
fn chain() -> Vec<CheckpointRecord> {
    let mut j = Journal::empty();
    let mut out = Vec::new();
    out.push(seal(
        &mut j,
        cp(CkptKind::Baseline, 1, Counts::default(), 3),
    ));

    let mut run = cp(
        CkptKind::Run,
        2,
        Counts {
            created: 1,
            modified: 2,
            deleted: 3,
            mode_changed: 4,
        },
        7,
    );
    run.new_session = true;
    run.label = Some(Label::new(b"nightly run".to_vec()).unwrap());
    run.command = Some(CommandLine::recorded(
        &[b"echo".to_vec(), b"a b".to_vec()],
        ArgPolicy::Redact,
    ));
    run.exit = Some(ExitInfo::Code(3));
    out.push(seal(&mut j, run));

    let mut manual = cp(CkptKind::Manual, 3, Counts::default(), 7);
    manual.label = Some(Label::new(b"before refactor".to_vec()).unwrap());
    out.push(seal(&mut j, manual));

    let mut undo = cp(CkptKind::Undo, 4, Counts::default(), 6);
    undo.reference = Some(id(2));
    out.push(seal(&mut j, undo));

    let mut killed = cp(CkptKind::Run, 5, Counts::default(), 6);
    killed.exit = Some(ExitInfo::Signal(9));
    killed.command = Some(CommandLine::recorded(
        &[b"sleep".to_vec(), b"100".to_vec()],
        ArgPolicy::Redact,
    ));
    out.push(seal(&mut j, killed));
    out
}

fn journal_with_chain(repo: &impl JournalRepository, n: usize) -> Vec<CheckpointRecord> {
    let recs = chain();
    for r in &recs[..n] {
        repo.append(r).unwrap();
    }
    recs[..n].to_vec()
}

pub fn journal_empty_load_is_empty<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    let j = repo.load().unwrap();
    assert!(j.is_empty());
    assert!(j.records().is_empty());
    assert!(j.head().is_none());
    assert_eq!(j.next_id(), id(1));
    assert!(j.pruned().is_empty());
}

pub fn journal_append_then_load_returns_same_records<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    let recs = chain();
    for (i, r) in recs.iter().enumerate() {
        repo.append(r).unwrap();
        let loaded = repo.load().unwrap();
        assert_eq!(loaded.records(), &recs[..=i]);
    }
    let loaded = repo.load().unwrap();
    assert_eq!(loaded.next_id(), id(6));
    assert_eq!(loaded.head().unwrap().exit, Some(ExitInfo::Signal(9)));
    assert_eq!(loaded.find(id(4)).unwrap().reference, Some(id(2)));
    assert_eq!(loaded.find(id(2)).unwrap().exit, Some(ExitInfo::Code(3)));
    assert_eq!(loaded.find(id(3)).unwrap().counts, Counts::default());
    assert_eq!(loaded.find(id(2)).unwrap().counts.mode_changed, 4);
}

pub fn journal_append_after_load_keeps_chain_valid<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    journal_with_chain(&repo, 2);
    let mut loaded = repo.load().unwrap();
    let rec = seal(&mut loaded, cp(CkptKind::Manual, 3, Counts::default(), 7));
    repo.append(&rec).unwrap();
    let mut again = repo.load().unwrap();
    assert_eq!(again.records().len(), 3);
    assert_eq!(again.head().unwrap(), &rec);
    let next = seal(&mut again, cp(CkptKind::Manual, 4, Counts::default(), 8));
    repo.append(&next).unwrap();
    let last = repo.load().unwrap();
    assert_eq!(last.records().len(), 4);
    assert_eq!(last.records()[3].prev, last.records()[2].hash);
}

pub fn journal_save_pruned_persists<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    journal_with_chain(&repo, 5);
    assert!(repo.load().unwrap().pruned().is_empty());

    repo.save_pruned(&[]).unwrap();
    assert!(repo.load().unwrap().pruned().is_empty());

    repo.save_pruned(&[id(1), id(3)]).unwrap();
    let j = repo.load().unwrap();
    assert!(j.is_pruned(id(1)));
    assert!(!j.is_pruned(id(2)));
    assert!(j.is_pruned(id(3)));
    assert_eq!(j.pruned(), &BTreeSet::from([1, 3]));
    // records stay in the chain
    assert_eq!(j.records().len(), 5);

    // pruning accumulates across calls and survives further appends
    repo.save_pruned(&[id(2)]).unwrap();
    let j = repo.load().unwrap();
    assert_eq!(j.pruned(), &BTreeSet::from([1, 2, 3]));
}

pub fn journal_pruning_the_newest_record_is_rejected_on_load<J: JournalFixture>(
    make: impl Fn() -> J,
) {
    let repo = make();
    journal_with_chain(&repo, 3);
    repo.save_pruned(&[id(3)]).unwrap();
    assert!(matches!(err_of(repo.load()), Error::Integrity(_)));
}

pub fn journal_tampered_storage_is_detected<J: JournalFixture>(make: impl Fn() -> J) {
    for index in 0..5 {
        let repo = make();
        journal_with_chain(&repo, 5);
        assert!(repo.load().is_ok());
        repo.corrupt_record(index);
        let e = err_of(repo.load());
        assert!(
            matches!(e, Error::Integrity(_)),
            "record {index}: expected Integrity, got {e}"
        );
        assert_eq!(e.exit_code(), 5);
    }
}

pub fn journal_removed_record_is_detected<J: JournalFixture>(make: impl Fn() -> J) {
    for index in 0..4 {
        let repo = make();
        journal_with_chain(&repo, 5);
        repo.remove_record_at(index);
        assert!(
            matches!(err_of(repo.load()), Error::Integrity(_)),
            "removing record {index}"
        );
    }
}

pub fn journal_out_of_sequence_append_is_detected_on_load<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    let recs = chain();
    repo.append(&recs[0]).unwrap();
    repo.append(&recs[2]).unwrap(); // skips record 2
    assert!(matches!(err_of(repo.load()), Error::Integrity(_)));
}

pub fn journal_hostile_text_roundtrips<J: JournalFixture>(make: impl Fn() -> J) {
    let repo = make();
    let mut j = Journal::empty();
    let base = seal(&mut j, cp(CkptKind::Baseline, 1, Counts::default(), 0));
    repo.append(&base).unwrap();

    let labels: Vec<Vec<u8>> = vec![
        b"multi\nline\ttabbed\rlabel".to_vec(),
        b"esc \x1b[31m red \x1b[0m".to_vec(),
        vec![0xff, 0xfe, b'x', 0xc3, 0x28],
        b"100% done =sign - dash".to_vec(),
        "bidi \u{202e} and \u{65e5}\u{672c}".as_bytes().to_vec(),
        vec![b'\n'; MAX_LABEL_BYTES],
        Vec::new(),
    ];
    let commands: Vec<Vec<Vec<u8>>> = vec![
        vec![
            b"sh".to_vec(),
            b"-c".to_vec(),
            b"echo 'a b'\necho \"c\"".to_vec(),
        ],
        vec![vec![0xff, 0x01], b"\x1b[2J".to_vec(), b"tab\there".to_vec()],
        vec![b"x".to_vec(), Vec::new(), b"after empty".to_vec()],
        vec![b"100%".to_vec(), b"%41".to_vec(), b"=-".to_vec()],
    ];
    let mut expected = vec![base];
    for (i, label) in labels.iter().enumerate() {
        let mut n = cp(CkptKind::Manual, i as i64 + 2, Counts::default(), 1);
        n.label = Some(Label::new(label.clone()).unwrap());
        n.command = Some(CommandLine::recorded(
            &commands[i % commands.len()],
            ArgPolicy::Redact,
        ));
        let r = seal(&mut j, n);
        repo.append(&r).unwrap();
        expected.push(r);
    }
    let loaded = repo.load().unwrap();
    assert_eq!(loaded.records(), expected.as_slice());
    for (i, label) in labels.iter().enumerate() {
        let r = loaded.find(id(i as u64 + 2)).unwrap();
        assert_eq!(r.label.as_ref().unwrap().as_bytes(), label.as_slice());
        assert_eq!(
            r.command.as_ref().unwrap().args(),
            commands[i % commands.len()].as_slice()
        );
    }
}

// ======================================================================
// Locker
// ======================================================================

pub fn fake_locker() -> MemLocker {
    MemLocker::new()
}

pub struct FsLockerEnv {
    inner: FsLocker,
    pub lock_path: PathBuf,
    _tmp: TempDir,
}

pub fn fs_locker() -> FsLockerEnv {
    let tmp = TempDir::new("lock");
    let lock_path = tmp.path().join("lock");
    FsLockerEnv {
        inner: FsLocker::new(lock_path.clone()),
        lock_path,
        _tmp: tmp,
    }
}

impl Locker for FsLockerEnv {
    fn exclusive(&self) -> Result<Box<dyn LockGuard>> {
        self.inner.exclusive()
    }
    fn shared(&self) -> Result<Box<dyn LockGuard>> {
        self.inner.shared()
    }
}

fn assert_locked(r: Result<Box<dyn LockGuard>>, what: &str) {
    match r {
        Err(Error::Locked(_)) => {}
        Err(e) => panic!("{what}: expected Locked, got {e}"),
        Ok(_) => panic!("{what}: lock was granted but should be refused"),
    }
}

pub fn locker_exclusive_excludes_everything<L: Locker>(make: impl Fn() -> L) {
    let l = make();
    let g = l.exclusive().unwrap();
    assert_locked(l.exclusive(), "exclusive while exclusive");
    assert_locked(l.shared(), "shared while exclusive");
    drop(g);
}

pub fn locker_shared_allows_shared_but_excludes_exclusive<L: Locker>(make: impl Fn() -> L) {
    let l = make();
    let a = l.shared().unwrap();
    let b = l.shared().unwrap();
    let c = l.shared().unwrap();
    assert_locked(l.exclusive(), "exclusive while shared");
    drop((a, b, c));
}

pub fn locker_guard_drop_releases_exclusive<L: Locker>(make: impl Fn() -> L) {
    let l = make();
    for _ in 0..3 {
        let g = l.exclusive().unwrap();
        assert_locked(l.exclusive(), "second exclusive");
        drop(g);
    }
    let s = l.shared().unwrap();
    drop(s);
    drop(l.exclusive().unwrap());
}

pub fn locker_last_shared_guard_releases_the_lock<L: Locker>(make: impl Fn() -> L) {
    let l = make();
    let a = l.shared().unwrap();
    let b = l.shared().unwrap();
    drop(a);
    assert_locked(l.exclusive(), "one shared guard still held");
    drop(b);
    let e = l.exclusive().unwrap();
    assert_locked(l.shared(), "shared while exclusive again");
    drop(e);
    drop(l.shared().unwrap());
}

pub fn locker_refusal_is_the_locked_error_variant<L: Locker>(make: impl Fn() -> L) {
    let l = make();
    let _g = l.exclusive().unwrap();
    let e = err_of(l.exclusive());
    assert!(matches!(e, Error::Locked(_)));
    assert_eq!(e.code(), "locked");
    assert_eq!(e.exit_code(), 4);
    assert!(!e.to_string().is_empty());
    let e = err_of(l.shared());
    assert!(matches!(e, Error::Locked(_)));
}

// ======================================================================
// Working tree
// ======================================================================

/// A project directory (fake or real) plus the helpers tests need to arrange
/// and inspect it, and the blob store the tree writes into.
pub trait TreeFixture {
    fn tree(&self) -> &dyn WorkingTree;
    fn blobs(&self) -> &dyn BlobStore;

    fn write(&self, path: &str, content: &[u8]);
    fn write_mode(&self, path: &str, content: &[u8], mode: u32);
    fn mkdir(&self, path: &str, mode: u32);
    fn symlink(&self, path: &str, target: &[u8]);
    /// Removes a path and everything below it.
    fn remove(&self, path: &str);
    /// Content of a regular file (`None` for anything else; symlinks are not followed).
    fn read(&self, path: &str) -> Option<Vec<u8>>;
    /// Permission bits of a file or directory.
    fn mode(&self, path: &str) -> Option<u32>;
    /// Exists as any object, including a dangling symlink.
    fn exists(&self, path: &str) -> bool;
    fn is_dir(&self, path: &str) -> bool;
    fn link_target(&self, path: &str) -> Option<Vec<u8>>;
    /// Every path of the project, sorted.
    fn paths(&self) -> Vec<String>;
    /// A directory outside the project; it holds `keep.txt` from the start.
    fn outside_dir(&self) -> String;
    /// Creates `name` in the outside directory; returns its absolute path.
    fn outside_file(&self, name: &str, content: &[u8]) -> String;
    /// Everything in the outside directory (relative path, content or `<dir>`).
    fn outside_snapshot(&self) -> Vec<(String, Vec<u8>)>;
    /// Overwrites the stored bytes of a blob without changing its address.
    fn corrupt_blob(&self, d: &Digest, bytes: &[u8]);
    /// Makes a directory impossible to list; `false` if that cannot be arranged here.
    fn set_unlistable(&self, dir: &str) -> bool;
    fn set_listable(&self, dir: &str);
    /// Lowers the per-directory entry cap and the depth cap of the scanner.
    fn set_limits(&self, max_dir_entries: usize, max_depth: usize);
}

const OUTSIDE_KEEP: &[u8] = b"SENTINEL-OUTSIDE-THE-PROJECT";

// ---- fake fixture

pub struct FakeTreeEnv {
    tree: Rc<MemTree>,
    blobs: Rc<MemBlobs>,
    outside: RefCell<BTreeMap<String, Vec<u8>>>,
}

pub fn fake_tree(cap: u64) -> FakeTreeEnv {
    let blobs = Rc::new(MemBlobs::new());
    let mut outside = BTreeMap::new();
    outside.insert("keep.txt".to_string(), OUTSIDE_KEEP.to_vec());
    FakeTreeEnv {
        tree: Rc::new(MemTree::new(blobs.clone(), cap)),
        blobs,
        outside: RefCell::new(outside),
    }
}

impl TreeFixture for FakeTreeEnv {
    fn tree(&self) -> &dyn WorkingTree {
        &self.tree
    }
    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }
    fn write(&self, path: &str, content: &[u8]) {
        self.tree.write(path, content);
    }
    fn write_mode(&self, path: &str, content: &[u8], mode: u32) {
        self.tree.write_mode(path, content, mode);
    }
    fn mkdir(&self, path: &str, mode: u32) {
        self.tree.mkdir(path, mode);
    }
    fn symlink(&self, path: &str, target: &[u8]) {
        self.tree.symlink(path, target);
    }
    fn remove(&self, path: &str) {
        self.tree.remove(path);
    }
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.tree.read(path)
    }
    fn mode(&self, path: &str) -> Option<u32> {
        self.tree.mode(path)
    }
    fn exists(&self, path: &str) -> bool {
        self.tree.exists(path)
    }
    fn is_dir(&self, path: &str) -> bool {
        matches!(self.tree.node(path), Some(Node::Dir { .. }))
    }
    fn link_target(&self, path: &str) -> Option<Vec<u8>> {
        match self.tree.node(path) {
            Some(Node::Symlink { target }) => Some(target),
            _ => None,
        }
    }
    fn paths(&self) -> Vec<String> {
        let mut p = self.tree.paths();
        p.sort();
        p
    }
    fn outside_dir(&self) -> String {
        "/outside-the-project".to_string()
    }
    fn outside_file(&self, name: &str, content: &[u8]) -> String {
        self.outside
            .borrow_mut()
            .insert(name.to_string(), content.to_vec());
        format!("{}/{name}", self.outside_dir())
    }
    fn outside_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        self.outside
            .borrow()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
    fn corrupt_blob(&self, d: &Digest, bytes: &[u8]) {
        self.blobs.corrupt(d, bytes.to_vec());
    }
    fn set_unlistable(&self, dir: &str) -> bool {
        self.tree.set_unlistable(dir);
        true
    }
    fn set_listable(&self, _dir: &str) {}
    fn set_limits(&self, max_dir_entries: usize, max_depth: usize) {
        self.tree.set_limits(max_dir_entries, max_depth);
    }
}

// ---- real fixture

pub struct FsTreeEnv {
    tree: FsTree,
    blobs: FsBlobs,
    root: PathBuf,
    outside: PathBuf,
    _tmp: TempDir,
}

pub fn fs_tree(cap: u64) -> FsTreeEnv {
    let tmp = TempDir::new("tree");
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(&root).unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep.txt"), OUTSIDE_KEEP).unwrap();
    let store = StoreDir::create(&tmp.path().join("store"), &root, false, cap).unwrap();
    let blobs = FsBlobs::new(store.blobs_dir(), store.tmp_dir());
    let tree = FsTree::new(
        store.root.clone(),
        &store.dir,
        store.meta.max_file_size,
        *store.key(),
        blobs.clone(),
    );
    FsTreeEnv {
        tree,
        blobs,
        root,
        outside,
        _tmp: tmp,
    }
}

impl FsTreeEnv {
    fn abs(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }

    fn ensure_parent(&self, path: &str) {
        if let Some(p) = self.abs(path).parent() {
            fs::create_dir_all(p).unwrap();
        }
    }
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut names: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    for p in names {
        let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
        let md = fs::symlink_metadata(&p).unwrap();
        if md.is_dir() {
            out.push((rel, b"<dir>".to_vec()));
            walk(&p, base, out);
        } else if md.is_file() {
            out.push((rel, fs::read(&p).unwrap()));
        } else {
            out.push((rel, b"<other>".to_vec()));
        }
    }
}

impl TreeFixture for FsTreeEnv {
    fn tree(&self) -> &dyn WorkingTree {
        &self.tree
    }
    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }
    fn write(&self, path: &str, content: &[u8]) {
        self.ensure_parent(path);
        fs::write(self.abs(path), content).unwrap();
    }
    fn write_mode(&self, path: &str, content: &[u8], mode: u32) {
        self.write(path, content);
        fs::set_permissions(self.abs(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    fn mkdir(&self, path: &str, mode: u32) {
        fs::create_dir_all(self.abs(path)).unwrap();
        fs::set_permissions(self.abs(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    fn symlink(&self, path: &str, target: &[u8]) {
        self.ensure_parent(path);
        symlink(OsStr::from_bytes(target), self.abs(path)).unwrap();
    }
    fn remove(&self, path: &str) {
        let p = self.abs(path);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => fs::remove_dir_all(&p).unwrap(),
            Ok(_) => fs::remove_file(&p).unwrap(),
            Err(_) => {}
        }
    }
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        let p = self.abs(path);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() => Some(fs::read(&p).unwrap()),
            _ => None,
        }
    }
    fn mode(&self, path: &str) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        let m = fs::symlink_metadata(self.abs(path)).ok()?;
        if m.file_type().is_symlink() {
            None
        } else {
            Some(m.mode() & 0o7777)
        }
    }
    fn exists(&self, path: &str) -> bool {
        fs::symlink_metadata(self.abs(path)).is_ok()
    }
    fn is_dir(&self, path: &str) -> bool {
        fs::symlink_metadata(self.abs(path)).is_ok_and(|m| m.is_dir())
    }
    fn link_target(&self, path: &str) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStringExt;
        fs::read_link(self.abs(path))
            .ok()
            .map(|t| t.into_os_string().into_vec())
    }
    fn paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out);
        let mut p: Vec<String> = out.into_iter().map(|(k, _)| k).collect();
        p.sort();
        p
    }
    fn outside_dir(&self) -> String {
        self.outside.to_string_lossy().into_owned()
    }
    fn outside_file(&self, name: &str, content: &[u8]) -> String {
        let p = self.outside.join(name);
        fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn outside_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        walk(&self.outside, &self.outside, &mut out);
        out
    }
    fn corrupt_blob(&self, d: &Digest, bytes: &[u8]) {
        fs::write(self.blobs.path_of(d), bytes).unwrap();
    }
    fn set_unlistable(&self, dir: &str) -> bool {
        let p = self.abs(dir);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&p).is_ok() {
            // running with privileges that bypass permissions: cannot arrange this
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            return false;
        }
        true
    }
    fn set_listable(&self, dir: &str) {
        fs::set_permissions(self.abs(dir), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn set_limits(&self, max_dir_entries: usize, max_depth: usize) {
        self.tree.set_limits(max_dir_entries, max_depth);
    }
}

// ---- scan helpers

#[derive(Default)]
pub struct Collect {
    pub prev: BTreeMap<RelPath, Entry>,
    pub seen: Vec<(RelPath, Entry)>,
    pub carried: Vec<RelPath>,
    /// Set when the whole tree was carried forward.
    pub carried_all: bool,
}

impl ScanVisitor for Collect {
    fn prev(&mut self, path: &RelPath) -> Result<Option<Entry>> {
        Ok(self.prev.get(path).cloned())
    }
    fn visit(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        self.seen.push((path.clone(), entry.clone()));
        Ok(())
    }
    fn carry_forward(&mut self, dir: Option<&RelPath>) -> Result<()> {
        match dir {
            Some(d) => self.carried.push(d.clone()),
            None => self.carried_all = true,
        }
        Ok(())
    }
}

pub struct ScanResult {
    pub entries: Manifest,
    pub stats: ScanStats,
    pub carried: Vec<RelPath>,
    pub carried_all: bool,
}

impl ScanResult {
    pub fn paths(&self) -> Vec<String> {
        self.entries.iter().map(|(p, _)| p.display()).collect()
    }

    pub fn get(&self, path: &str) -> &Entry {
        &self
            .entries
            .iter()
            .find(|(p, _)| p.as_bytes() == path.as_bytes())
            .unwrap_or_else(|| panic!("{path:?} not in scan: {:?}", self.paths()))
            .1
    }

    pub fn has(&self, path: &str) -> bool {
        self.entries
            .iter()
            .any(|(p, _)| p.as_bytes() == path.as_bytes())
    }

    pub fn kinds(&self) -> Vec<(String, Kind)> {
        self.entries
            .iter()
            .map(|(p, e)| (p.display(), e.kind()))
            .collect()
    }

    pub fn digests(&self) -> Vec<(String, Option<Digest>)> {
        self.entries
            .iter()
            .map(|(p, e)| (p.display(), e.digest()))
            .collect()
    }
}

pub fn scan_with(
    fx: &impl TreeFixture,
    opts: &ScanOptions,
    prev: &[(RelPath, Entry)],
) -> ScanResult {
    let mut v = Collect {
        prev: prev.iter().cloned().collect(),
        ..Collect::default()
    };
    let stats = fx.tree().scan(opts, &mut v).unwrap();
    ScanResult {
        entries: v.seen,
        stats,
        carried: v.carried,
        carried_all: v.carried_all,
    }
}

pub fn scan_capture(fx: &impl TreeFixture) -> ScanResult {
    scan_with(fx, &ScanOptions::capturing(None), &[])
}

fn all_blob_bytes(b: &dyn BlobStore) -> Vec<Vec<u8>> {
    b.list()
        .unwrap()
        .blobs
        .iter()
        .map(|(d, _)| b.read(d, u64::MAX).unwrap())
        .collect()
}

fn assert_no_blob_contains(b: &dyn BlobStore, needle: &[u8]) {
    for bytes in all_blob_bytes(b) {
        assert!(
            !contains_sub(&bytes, needle),
            "a blob in the store contains secret bytes"
        );
    }
}

fn assert_strictly_increasing(entries: &Manifest) {
    for w in entries.windows(2) {
        assert!(
            w[0].0 < w[1].0,
            "not strictly increasing: {:?} then {:?}",
            w[0].0.display(),
            w[1].0.display()
        );
    }
}

// ---- scan contracts

pub fn tree_scan_empty_project<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let r = scan_capture(&fx);
    assert!(r.entries.is_empty());
    assert_eq!(r.stats.entries, 0);
    assert_eq!(r.stats.files_hashed, 0);
    assert!(fx.blobs().list().unwrap().blobs.is_empty());
}

pub fn tree_scan_order_and_kinds<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("a/b.txt", b"in a");
    fx.write("a-b", b"dash");
    fx.write("a.b", b"dot");
    fx.write("a0", b"zero");
    fx.write("B/inner/deep.txt", b"deep");
    fx.mkdir("empty", 0o755);
    fx.write("z", b"last");
    fx.write_mode("run.sh", b"#!/bin/sh\n", 0o755);
    fx.symlink("ln", b"a/b.txt");

    let r = scan_capture(&fx);
    assert_strictly_increasing(&r.entries);
    let mut expected: Vec<(String, Kind)> = vec![
        ("a", Kind::Dir),
        ("a/b.txt", Kind::File),
        ("a-b", Kind::File),
        ("a.b", Kind::File),
        ("a0", Kind::File),
        ("B", Kind::Dir),
        ("B/inner", Kind::Dir),
        ("B/inner/deep.txt", Kind::File),
        ("empty", Kind::Dir),
        ("ln", Kind::Symlink),
        ("run.sh", Kind::File),
        ("z", Kind::File),
    ]
    .into_iter()
    .map(|(p, k)| (p.to_string(), k))
    .collect();
    expected.sort_by_key(|a| rp(&a.0));
    assert_eq!(r.kinds(), expected);

    // a directory is always visited before anything inside it
    let mut seen_dirs: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (p, e) in &r.entries {
        if let Some(parent) = p.parent() {
            assert!(
                seen_dirs.contains(parent.as_bytes()),
                "{:?} visited before its directory",
                p.display()
            );
        }
        if e.kind() == Kind::Dir {
            seen_dirs.insert(p.as_bytes().to_vec());
        }
    }

    // entry details
    let f = r.get("a/b.txt");
    assert_eq!(f.digest(), Some(sha256(b"in a")));
    assert_eq!(f.size(), 4);
    assert_eq!(r.get("run.sh").mode(), 0o755);
    assert_eq!(r.get("ln").target(), Some(b"a/b.txt".as_slice()));
    assert_eq!(r.get("ln").size(), 7);
    assert_eq!(r.get("empty").size(), 0);
    assert_eq!(r.stats.entries, r.entries.len() as u64);
}

pub fn tree_scan_hostile_names<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let names = [
        "we ird/new\nline.txt",
        "esc\u{1b}[0m.txt",
        "sp ace.txt",
        "pct%41.txt",
        "-dash",
        "tab\tname",
        "\u{65e5}\u{672c}/\u{fc}.txt",
    ];
    for n in names {
        fx.write(n, n.as_bytes());
    }
    let r = scan_capture(&fx);
    assert_strictly_increasing(&r.entries);
    for n in names {
        assert_eq!(r.get(n).digest(), Some(sha256(n.as_bytes())), "{n:?}");
    }
    let files = r
        .entries
        .iter()
        .filter(|(_, e)| e.kind() == Kind::File)
        .count();
    assert_eq!(files, names.len());
}

pub fn tree_scan_never_follows_symlinks<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let secret = secret_token();
    let secret_text = format!("password manager export\n{secret}\n");
    let secret_path = fx.outside_file("secret.txt", secret_text.as_bytes());
    let plain_marker = b"PLAIN-OUTSIDE-CONTENT-NOT-IN-PROJECT";
    fx.outside_file("plain.txt", plain_marker);
    let outside = fx.outside_dir();

    fx.write("ok.txt", b"inside the project");
    fx.symlink("link_dir", outside.as_bytes());
    fx.symlink("link_file", secret_path.as_bytes());
    fx.symlink("sub/rel_link", b"../ok.txt");
    fx.symlink("dangling", b"/does/not/exist");

    let r = scan_capture(&fx);
    for l in ["link_dir", "link_file", "sub/rel_link", "dangling"] {
        assert_eq!(r.get(l).kind(), Kind::Symlink, "{l}");
    }
    assert_eq!(r.get("link_dir").target(), Some(outside.as_bytes()));
    assert_eq!(r.get("link_file").target(), Some(secret_path.as_bytes()));
    assert_eq!(
        r.get("sub/rel_link").target(),
        Some(b"../ok.txt".as_slice())
    );
    assert!(
        !r.paths().iter().any(|p| p.starts_with("link_dir/")),
        "descended into a symlinked directory: {:?}",
        r.paths()
    );
    // nothing reachable only through a link was read or stored
    let blobs = all_blob_bytes(fx.blobs());
    assert_eq!(blobs, vec![b"inside the project".to_vec()]);
    assert_no_blob_contains(fx.blobs(), secret.as_bytes());
    assert_no_blob_contains(fx.blobs(), plain_marker);
    assert_eq!(r.stats.blobs_written, 1);
    // scanning did not touch the outside
    assert_eq!(
        fx.outside_snapshot().len(),
        3,
        "outside dir gained or lost files"
    );
}

pub fn tree_scan_applies_default_ignores<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("src/main.rs", b"fn main() {}");
    fx.write(".git/config", b"[core]");
    fx.write(".git/objects/ab/cd", b"obj");
    fx.write("node_modules/dep/index.js", b"module");
    fx.write("a/node_modules/x.js", b"nested");
    fx.write("target/debug/app", b"bin");
    fx.write("src/__pycache__/m.pyc", b"pyc");
    fx.write(".agent-undo/state", b"state");
    fx.write(".DS_Store", b"junk");
    fx.write("targets/keep.txt", b"not the target dir");
    // "target/" only matches directories: a file with that name is kept
    fx.write("sub/target", b"a file named target");

    let r = scan_capture(&fx);
    let got: BTreeSet<String> = r.paths().into_iter().collect();
    let want: BTreeSet<String> = [
        "a",
        "src",
        "src/main.rs",
        "sub",
        "sub/target",
        "targets",
        "targets/keep.txt",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(got, want);
    // nothing inside ignored directories was stored
    assert_eq!(fx.blobs().list().unwrap().blobs.len(), 3);
}

pub fn tree_scan_applies_user_ignore_with_negation<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write(
        ".agent-undoignore",
        b"# comment\n*.log\n!keep.log\nsecrets_dir/\n/rootonly.txt\n!node_modules/\n",
    );
    fx.write("a.log", b"x");
    fx.write("deep/b.log", b"x");
    fx.write("keep.log", b"kept");
    fx.write("secrets_dir/x", b"x");
    fx.write("rootonly.txt", b"x");
    fx.write("src/rootonly.txt", b"anchored pattern only hits the root");
    fx.write("src/a.txt", b"x");
    fx.write("node_modules/m.js", b"re-included");

    let r = scan_capture(&fx);
    let got: BTreeSet<String> = r.paths().into_iter().collect();
    let want: BTreeSet<String> = [
        ".agent-undoignore",
        "deep",
        "keep.log",
        "node_modules",
        "node_modules/m.js",
        "src",
        "src/a.txt",
        "src/rootonly.txt",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(got, want);
}

/// A bad `.agent-undoignore` must not be able to stop recording: the default
/// ignore rules apply and the scan reports a warning instead of failing.
pub fn tree_oversized_ignore_pattern_degrades_to_defaults_with_a_warning<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    let mut text = vec![b'x'; 5000];
    text.push(b'\n');
    fx.write(".agent-undoignore", &text);
    fx.write("a.txt", b"a");
    fx.write("node_modules/dep/x.js", b"ignored by default");
    let r = scan_capture(&fx);
    let names: Vec<String> = r.entries.iter().map(|(p, _)| p.display()).collect();
    assert!(names.contains(&"a.txt".to_string()), "{names:?}");
    assert!(
        !names.iter().any(|n| n.starts_with("node_modules")),
        "default ignore rules still apply: {names:?}"
    );
    assert!(
        r.stats
            .warnings
            .iter()
            .any(|w| w.contains(".agent-undoignore")),
        "{:?}",
        r.stats.warnings
    );
}

pub fn tree_sensitive_files_are_recorded_but_never_stored<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let token = secret_token();
    let key_block = private_key_block();
    let dotenv = dotenv_text();
    let secret_files: Vec<(&str, Vec<u8>)> = vec![
        (".env", dotenv.clone().into_bytes()),
        ("id_rsa", b"harmless looking bytes in a key file".to_vec()),
        ("certs/server.pem", b"pem payload 12345".to_vec()),
        ("app/config.txt", format!("api = {token}\n").into_bytes()),
        ("notes.txt", format!("my key:\n{key_block}").into_bytes()),
    ];
    for (p, c) in &secret_files {
        fx.write(p, c);
    }
    fx.write("src/lib.rs", b"pub fn ordinary() {}");

    let r = scan_capture(&fx);
    for (p, c) in &secret_files {
        let e = r.get(p);
        assert_eq!(e.kind(), Kind::Sensitive, "{p}");
        assert_eq!(e.size(), c.len() as u64, "{p}");
        assert!(e.blob().is_none());
        // the recorded id is a keyed hash, not the plain content hash
        assert_ne!(e.digest(), Some(sha256(c)), "{p}");
        assert!(!fx.blobs().contains(&sha256(c)), "{p}");
    }
    assert_eq!(r.get("src/lib.rs").kind(), Kind::File);
    assert_eq!(r.stats.blobs_written, 1);
    for needle in [
        token.as_bytes(),
        key_block.as_bytes(),
        dotenv.as_bytes(),
        b"harmless looking bytes".as_slice(),
        b"pem payload".as_slice(),
        b"bW9ja2JvZHktbm90".as_slice(),
    ] {
        assert_no_blob_contains(fx.blobs(), needle);
    }
    let blobs = all_blob_bytes(fx.blobs());
    assert_eq!(blobs, vec![b"pub fn ordinary() {}".to_vec()]);

    // the keyed id is stable between scans and changes with the content
    let again = scan_capture(&fx);
    assert_eq!(again.get(".env").digest(), r.get(".env").digest());
    fx.write(".env", b"OTHER=value-that-differs-12345\n");
    let changed = scan_capture(&fx);
    assert_ne!(changed.get(".env").digest(), r.get(".env").digest());
    assert_eq!(changed.get(".env").kind(), Kind::Sensitive);

    // sensitive classification does not depend on capturing
    let observed = scan_with(&fx, &ScanOptions::observing(None), &[]);
    assert_eq!(observed.get("app/config.txt").kind(), Kind::Sensitive);
    assert_eq!(observed.get("id_rsa").kind(), Kind::Sensitive);
}

pub fn tree_sensitive_beats_size_cap<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(64);
    let big_secret = format!("{}\n{}", "x".repeat(200), secret_token());
    fx.write("huge.txt", big_secret.as_bytes());
    fx.write(".env", &vec![b'a'; 500]);
    let r = scan_capture(&fx);
    assert_eq!(r.get("huge.txt").kind(), Kind::Sensitive);
    assert_eq!(r.get(".env").kind(), Kind::Sensitive);
    assert!(fx.blobs().list().unwrap().blobs.is_empty());
}

pub fn tree_too_large_file_has_no_blob<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(1024);
    let big = vec![b'q'; 2000];
    let exact = vec![b'e'; 1024];
    fx.write("big.bin", &big);
    fx.write("exact.bin", &exact);
    fx.write("small.txt", b"small");
    let r = scan_capture(&fx);
    let e = r.get("big.bin");
    assert_eq!(e.kind(), Kind::TooLarge);
    assert_eq!(e.size(), 2000);
    assert_eq!(e.digest(), Some(sha256(&big)));
    assert!(e.blob().is_none());
    assert!(!fx.blobs().contains(&sha256(&big)));
    // exactly at the cap is still stored
    assert_eq!(r.get("exact.bin").kind(), Kind::File);
    assert!(fx.blobs().contains(&sha256(&exact)));
    assert_eq!(fx.blobs().list().unwrap().blobs.len(), 2);
    assert_eq!(r.stats.blobs_written, 2);
    // a too-large file is reported the same way by observe
    match fx.tree().observe(&rp("big.bin")).unwrap() {
        Observation::State(Some(o)) => assert_eq!(o.kind(), Kind::TooLarge),
        other => panic!("{other:?}"),
    }
}

pub fn tree_capture_false_writes_no_blobs<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("a.txt", b"alpha");
    fx.write("d/b.txt", b"bravo");
    fx.write(".env", dotenv_text().as_bytes());
    let obs = scan_with(&fx, &ScanOptions::observing(None), &[]);
    assert_eq!(obs.stats.blobs_written, 0);
    assert_eq!(obs.stats.bytes_stored, 0);
    assert!(fx.blobs().list().unwrap().blobs.is_empty());
    // digests and kinds are still computed
    assert_eq!(obs.get("a.txt").kind(), Kind::File);
    assert_eq!(obs.get("a.txt").digest(), Some(sha256(b"alpha")));
    assert_eq!(obs.get(".env").kind(), Kind::Sensitive);

    // and equal what a capturing scan reports
    let cap = scan_capture(&fx);
    assert_eq!(obs.digests(), cap.digests());
    assert_eq!(cap.stats.blobs_written, 2);
}

pub fn tree_scan_stats_and_blob_dedup<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("one.txt", b"identical content");
    fx.write("two.txt", b"identical content");
    fx.write("three.txt", b"different");
    let r = scan_capture(&fx);
    assert_eq!(r.stats.entries, 3);
    assert_eq!(r.stats.files_hashed, 3);
    assert_eq!(r.stats.files_cached, 0);
    assert_eq!(r.stats.blobs_written, 2);
    assert_eq!(
        r.stats.bytes_hashed,
        (b"identical content".len() * 2 + b"different".len()) as u64
    );
    assert_eq!(
        r.stats.bytes_stored,
        (b"identical content".len() + b"different".len()) as u64
    );
    assert_eq!(fx.blobs().list().unwrap().blobs.len(), 2);
    // a second capturing scan writes nothing new
    let again = scan_capture(&fx);
    assert_eq!(again.stats.blobs_written, 0);
    assert_eq!(fx.blobs().list().unwrap().blobs.len(), 2);
}

pub fn tree_stat_cache_reuses_unchanged_and_rehashes_modified<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.write("a.txt", b"alpha");
    fx.write("d/b.txt", b"bravo-bravo");
    fx.write("d/c.txt", b"charlie");
    let first = scan_capture(&fx);
    assert_eq!(first.stats.files_hashed, 3);
    assert_eq!(first.stats.files_cached, 0);

    let opts = ScanOptions {
        capture: true,
        cache_time_ns: Some(now_ns() + 10_000_000_000),
        cache_margin_ns: 0,
        no_cache: false,
    };
    let second = scan_with(&fx, &opts, &first.entries);
    assert_eq!(second.stats.files_cached, 3);
    assert_eq!(second.stats.files_hashed, 0);
    assert_eq!(second.stats.bytes_hashed, 0);
    assert_eq!(second.kinds(), first.kinds());
    assert_eq!(second.digests(), first.digests());

    // a modified file is re-hashed, the others stay cached
    fx.write("d/b.txt", b"bravo-changed-and-longer");
    let third = scan_with(&fx, &opts, &second.entries);
    assert_eq!(third.stats.files_hashed, 1);
    assert_eq!(third.stats.files_cached, 2);
    assert_eq!(
        third.get("d/b.txt").digest(),
        Some(sha256(b"bravo-changed-and-longer"))
    );
    assert!(fx.blobs().contains(&sha256(b"bravo-changed-and-longer")));
    assert_eq!(third.get("a.txt").digest(), first.get("a.txt").digest());
}

pub fn tree_stat_cache_is_not_used_when_not_allowed<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("a.txt", b"alpha");
    fx.write("b.txt", b"bravo");
    let first = scan_capture(&fx);
    let future = Some(now_ns() + 10_000_000_000);

    // no previous snapshot time
    let r = scan_with(&fx, &ScanOptions::capturing(None), &first.entries);
    assert_eq!(r.stats.files_cached, 0);
    assert_eq!(r.stats.files_hashed, 2);

    // explicitly disabled
    let r = scan_with(
        &fx,
        &ScanOptions {
            capture: true,
            cache_time_ns: future,
            cache_margin_ns: 0,
            no_cache: true,
        },
        &first.entries,
    );
    assert_eq!(r.stats.files_cached, 0);
    assert_eq!(r.stats.files_hashed, 2);

    // files newer than the cutoff are "racy" and must be re-read
    let r = scan_with(
        &fx,
        &ScanOptions {
            capture: true,
            cache_time_ns: Some(0),
            cache_margin_ns: 0,
            no_cache: false,
        },
        &first.entries,
    );
    assert_eq!(r.stats.files_cached, 0);
    assert_eq!(r.stats.files_hashed, 2);

    // no previous entry for the path: nothing to reuse
    let r = scan_with(
        &fx,
        &ScanOptions {
            capture: true,
            cache_time_ns: future,
            cache_margin_ns: 0,
            no_cache: false,
        },
        &[],
    );
    assert_eq!(r.stats.files_cached, 0);
    assert_eq!(r.stats.files_hashed, 2);
}

pub fn tree_stat_cache_does_not_hide_a_missing_blob<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("a.txt", b"alpha");
    fx.write("b.txt", b"bravo");
    let first = scan_capture(&fx);
    let opts = ScanOptions {
        capture: true,
        cache_time_ns: Some(now_ns() + 10_000_000_000),
        cache_margin_ns: 0,
        no_cache: false,
    };
    // the blob of a.txt disappears (gc, corruption): a capturing scan must restore it
    fx.blobs().remove(&sha256(b"alpha")).unwrap();
    let r = scan_with(&fx, &opts, &first.entries);
    assert!(fx.blobs().contains(&sha256(b"alpha")));
    assert_eq!(r.stats.files_hashed, 1);
    assert_eq!(r.stats.files_cached, 1);
    assert_eq!(r.stats.blobs_written, 1);
    // an observing scan does not need blobs and may use the cache
    fx.blobs().remove(&sha256(b"alpha")).unwrap();
    let obs = scan_with(
        &fx,
        &ScanOptions {
            capture: false,
            ..opts
        },
        &first.entries,
    );
    assert_eq!(obs.stats.files_cached, 2);
    assert!(!fx.blobs().contains(&sha256(b"alpha")));
}

pub fn tree_unlistable_directory_is_carried_forward<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("ok.txt", b"ok");
    fx.write("locked/inner.txt", b"inner");
    fx.write("locked/sub/deep.txt", b"deep");
    let first = scan_capture(&fx);
    assert!(first.has("locked/sub/deep.txt"));
    if !fx.set_unlistable("locked") {
        return;
    }
    let r = scan_with(&fx, &ScanOptions::capturing(None), &first.entries);
    fx.set_listable("locked");
    assert_eq!(r.carried, vec![rp("locked")]);
    assert_eq!(r.paths(), vec!["locked".to_string(), "ok.txt".to_string()]);
    assert!(r.stats.warnings_total >= 1);
    assert!(!r.stats.warnings.is_empty());
}

// ---- observe contracts

pub fn tree_observe_reports_states<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write_mode("f.txt", b"file body", 0o600);
    fx.mkdir("dir", 0o750);
    fx.symlink("ln", b"f.txt");
    fx.write("node_modules/ignored.js", b"observe ignores ignore rules");
    fx.write(".env", dotenv_text().as_bytes());

    let state = |p: &str| match fx.tree().observe(&rp(p)).unwrap() {
        Observation::State(s) => s,
        Observation::Unsafe(w) | Observation::Obstructed(w) => {
            panic!("{p}: unexpectedly not inspectable: {w}")
        }
    };
    assert_eq!(state("absent"), None);
    assert_eq!(state("dir/absent"), None);
    let f = state("f.txt").unwrap();
    assert_eq!(f.kind(), Kind::File);
    assert_eq!(f.digest(), Some(sha256(b"file body")));
    assert_eq!(f.size(), 9);
    assert_eq!(f.mode(), 0o600);
    let d = state("dir").unwrap();
    assert_eq!(d.kind(), Kind::Dir);
    assert_eq!(d.mode(), 0o750);
    let l = state("ln").unwrap();
    assert_eq!(l.kind(), Kind::Symlink);
    assert_eq!(l.target(), Some(b"f.txt".as_slice()));
    assert_eq!(state("node_modules/ignored.js").unwrap().kind(), Kind::File);
    assert_eq!(state(".env").unwrap().kind(), Kind::Sensitive);
    // observing never stores anything
    assert!(fx.blobs().list().unwrap().blobs.is_empty());
}

pub fn tree_observe_refuses_symlinked_and_non_directory_parents<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.write("f.txt", b"regular file");
    fx.symlink("link", fx.outside_dir().as_bytes());
    fx.write("real/x.txt", b"x");
    let unsafe_path =
        |p: &str| matches!(fx.tree().observe(&rp(p)).unwrap(), Observation::Unsafe(_));
    let obstructed = |p: &str| {
        matches!(
            fx.tree().observe(&rp(p)).unwrap(),
            Observation::Obstructed(_)
        )
    };
    assert!(unsafe_path("link/keep.txt"), "below symlinked dir");
    assert!(
        unsafe_path("link/deeper/er.txt"),
        "deep below symlinked dir"
    );
    assert!(!obstructed("link/keep.txt"));
    // a regular file in the way is an obstruction (it cannot hold the path), not an escape
    assert!(obstructed("f.txt/child"), "below a regular file");
    assert!(obstructed("f.txt/a/b"), "deep below a regular file");
    assert!(!unsafe_path("f.txt/child"));
    assert!(!unsafe_path("real/x.txt") && !obstructed("real/x.txt"));
    assert!(!unsafe_path("missing/child") && !obstructed("missing/child"));
    let item = plan_item(&fx, "f.txt/child", None, None);
    assert!(item.obstruction.is_some(), "{item:?}");
    // the symlink itself can be observed
    assert!(matches!(
        fx.tree().observe(&rp("link")).unwrap(),
        Observation::State(Some(e)) if e.kind() == Kind::Symlink
    ));
}

// ---- apply contracts

fn plan_item(
    fx: &impl TreeFixture,
    path: &str,
    target: Option<Entry>,
    expected: Option<Option<Entry>>,
) -> PlanItem {
    let p = rp(path);
    let obs = fx.tree().observe(&p).unwrap();
    build_item(p, target, expected, obs)
}

fn apply(fx: &impl TreeFixture, item: &PlanItem) -> (Outcome, Vec<(RelPath, u32)>) {
    let mut dm = Vec::new();
    let out = fx.tree().apply(item, &mut dm).unwrap();
    (out, dm)
}

fn stored_file(fx: &impl TreeFixture, content: &[u8], mode: u32) -> Entry {
    fx.blobs().put(content).unwrap();
    file_entry(content, mode)
}

fn assert_already_done(fx: &impl TreeFixture, path: &str, target: &Entry) {
    let item = plan_item(fx, path, Some(target.clone()), None);
    assert_eq!(item.status, Status::AlreadyDone, "{path}: {item:?}");
}

/// A hand-made item that bypasses the planner's safety status, to prove the
/// tree itself refuses.
fn raw_item(path: &str, op: Op, target: Option<Entry>) -> PlanItem {
    PlanItem {
        path: rp(path),
        target,
        expected: None,
        current: None,
        op,
        replace: false,
        status: Status::Ready,
        obstruction: None,
    }
}

pub fn tree_apply_write_restores_content_and_mode<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    // a new file below missing directories
    let t = stored_file(&fx, b"restored bytes", 0o640);
    let item = plan_item(&fx, "new/dir/f.txt", Some(t.clone()), None);
    assert_eq!(item.op, Op::Write);
    assert_eq!(item.status, Status::Ready);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(dm.is_empty());
    assert_eq!(fx.read("new/dir/f.txt").unwrap(), b"restored bytes");
    assert_eq!(fx.mode("new/dir/f.txt").unwrap() & 0o777, 0o640);
    assert!(fx.is_dir("new/dir"));
    assert_already_done(&fx, "new/dir/f.txt", &t);

    // overwriting a file with different content and an executable mode
    fx.write_mode("x.sh", b"old content", 0o644);
    let t2 = stored_file(&fx, b"#!/bin/sh\necho new\n", 0o755);
    let item = plan_item(&fx, "x.sh", Some(t2.clone()), None);
    assert_eq!(item.op, Op::Write);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.read("x.sh").unwrap(), b"#!/bin/sh\necho new\n");
    assert_eq!(fx.mode("x.sh").unwrap() & 0o777, 0o755);
    assert_already_done(&fx, "x.sh", &t2);

    // an empty file and binary content
    let empty = stored_file(&fx, b"", 0o644);
    assert_eq!(
        apply(&fx, &plan_item(&fx, "empty", Some(empty), None)).0,
        Outcome::Applied
    );
    assert_eq!(fx.read("empty").unwrap(), Vec::<u8>::new());
    let bin = noise(5, 70_000);
    let bt = stored_file(&fx, &bin, 0o600);
    assert_eq!(
        apply(&fx, &plan_item(&fx, "bin.dat", Some(bt), None)).0,
        Outcome::Applied
    );
    assert_eq!(fx.read("bin.dat").unwrap(), bin);

    // a file replaced over a symlink replaces the link, not what it points to
    fx.symlink("lnk", fx.outside_dir().as_bytes());
    let before_outside = fx.outside_snapshot();
    let t3 = stored_file(&fx, b"now a regular file", 0o644);
    let item = plan_item(&fx, "lnk", Some(t3), None);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.read("lnk").unwrap(), b"now a regular file");
    assert_eq!(fx.link_target("lnk"), None);
    assert_eq!(fx.outside_snapshot(), before_outside);
}

pub fn tree_apply_delete_removes_files_and_symlinks<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("gone.txt", b"bye");
    fx.write("keep.txt", b"stay");
    fx.symlink("gone_link", b"keep.txt");
    let item = plan_item(&fx, "gone.txt", None, None);
    assert_eq!(item.op, Op::Delete);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(dm.is_empty());
    assert!(!fx.exists("gone.txt"));
    assert_eq!(fx.read("keep.txt").unwrap(), b"stay");

    let item = plan_item(&fx, "gone_link", None, None);
    assert_eq!(item.op, Op::Delete);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert!(!fx.exists("gone_link"));
    assert_eq!(
        fx.read("keep.txt").unwrap(),
        b"stay",
        "link target untouched"
    );
}

pub fn tree_apply_delete_refuses_a_directory<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("d/inner.txt", b"inner");
    let item = raw_item("d", Op::Delete, None);
    let mut dm = Vec::new();
    let e = err_of(fx.tree().apply(&item, &mut dm));
    assert!(matches!(e, Error::Unsafe(_)), "{e}");
    assert!(fx.is_dir("d"));
    assert_eq!(fx.read("d/inner.txt").unwrap(), b"inner");
}

pub fn tree_apply_mkdir_defers_directory_mode<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let item = plan_item(&fx, "made/sub", Some(Entry::dir(0o755, 1, 1)), None);
    assert_eq!(item.op, Op::Mkdir);
    // parents are created implicitly
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(fx.is_dir("made"));
    assert!(fx.is_dir("made/sub"));
    assert_eq!(dm, vec![(rp("made/sub"), 0o755)]);
    // until the deferred mode is applied the directory stays traversable by the owner only
    assert_eq!(fx.mode("made/sub").unwrap() & 0o777, 0o700);
    fx.tree().set_dir_mode(&dm[0].0, dm[0].1).unwrap();
    assert_eq!(fx.mode("made/sub").unwrap() & 0o777, 0o755);
    assert_already_done(&fx, "made/sub", &Entry::dir(0o755, 9, 9));

    // a read-only target mode is applied last, after children could be created
    let item = plan_item(&fx, "ro", Some(Entry::dir(0o555, 1, 1)), None);
    let (_, dm) = apply(&fx, &item);
    assert_eq!(dm, vec![(rp("ro"), 0o555)]);
    let t = stored_file(&fx, b"child", 0o644);
    let child = plan_item(&fx, "ro/child.txt", Some(t), None);
    assert_eq!(apply(&fx, &child).0, Outcome::Applied);
    fx.tree().set_dir_mode(&dm[0].0, dm[0].1).unwrap();
    assert_eq!(fx.mode("ro").unwrap() & 0o777, 0o555);
    assert_eq!(fx.read("ro/child.txt").unwrap(), b"child");
    // leave it removable for cleanup
    fx.tree().set_dir_mode(&rp("ro"), 0o755).unwrap();

    // a 0o700 directory needs no deferred mode
    let item = plan_item(&fx, "private", Some(Entry::dir(0o700, 1, 1)), None);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(dm.is_empty());
    assert_eq!(fx.mode("private").unwrap() & 0o777, 0o700);
}

pub fn tree_set_dir_mode_refuses_a_file<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write_mode("f.txt", b"x", 0o644);
    let r = fx.tree().set_dir_mode(&rp("f.txt"), 0o700);
    assert!(
        matches!(r, Err(Error::Unsafe(_))),
        "set_dir_mode on a regular file must be refused"
    );
    assert_eq!(fx.mode("f.txt").unwrap() & 0o777, 0o644, "mode untouched");
}

pub fn tree_apply_rmdir_skips_non_empty_directories<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.mkdir("empty_dir", 0o755);
    fx.write("full/untracked.txt", b"not tracked");
    let item = plan_item(&fx, "empty_dir", None, None);
    assert_eq!(item.op, Op::Rmdir);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert!(!fx.exists("empty_dir"));

    let item = plan_item(&fx, "full", None, None);
    assert_eq!(item.op, Op::Rmdir);
    let (out, _) = apply(&fx, &item);
    assert!(matches!(out, Outcome::Skipped(_)), "{out:?}");
    assert!(fx.is_dir("full"));
    assert_eq!(fx.read("full/untracked.txt").unwrap(), b"not tracked");
}

pub fn tree_apply_symlink_creates_and_replaces<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    let link = |t: &[u8]| Entry::symlink(t.to_vec(), 1, 1).unwrap();
    let item = plan_item(&fx, "sub/new_link", Some(link(b"../target file")), None);
    assert_eq!(item.op, Op::Symlink);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.link_target("sub/new_link").unwrap(), b"../target file");
    assert_already_done(&fx, "sub/new_link", &link(b"../target file"));

    // a regular file in the way is replaced by the link
    fx.write("was_file", b"data");
    let item = plan_item(&fx, "was_file", Some(link(b"elsewhere")), None);
    assert_eq!(item.op, Op::Symlink);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.link_target("was_file").unwrap(), b"elsewhere");

    // an existing link with another target is retargeted
    let item = plan_item(&fx, "was_file", Some(link(b"other")), None);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.link_target("was_file").unwrap(), b"other");

    // an empty directory in the way is replaced
    fx.mkdir("was_dir", 0o755);
    let item = plan_item(&fx, "was_dir", Some(link(b"x")), None);
    assert!(item.replace);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.link_target("was_dir").unwrap(), b"x");

    // hostile target bytes survive
    let hostile = b"new\nline \x1b[0m %41".to_vec();
    let item = plan_item(&fx, "hostile", Some(link(&hostile)), None);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert_eq!(fx.link_target("hostile").unwrap(), hostile);
}

pub fn tree_apply_chmod_changes_only_the_mode<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write_mode("f.sh", b"same content", 0o644);
    let target = file_entry(b"same content", 0o755);
    let item = plan_item(&fx, "f.sh", Some(target.clone()), None);
    assert_eq!(item.op, Op::Chmod);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(dm.is_empty());
    assert_eq!(fx.mode("f.sh").unwrap() & 0o777, 0o755);
    assert_eq!(fx.read("f.sh").unwrap(), b"same content");
    assert_already_done(&fx, "f.sh", &target);

    // directories: the new mode is deferred to set_dir_mode
    fx.mkdir("d", 0o755);
    fx.write("d/child", b"c");
    let item = plan_item(&fx, "d", Some(Entry::dir(0o700, 1, 1)), None);
    assert_eq!(item.op, Op::Chmod);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert_eq!(dm, vec![(rp("d"), 0o700)]);
    fx.tree().set_dir_mode(&dm[0].0, dm[0].1).unwrap();
    assert_eq!(fx.mode("d").unwrap() & 0o777, 0o700);
    assert_eq!(fx.read("d/child").unwrap(), b"c");
}

pub fn tree_apply_replace_swaps_directories_and_files<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);

    // empty directory -> file
    fx.mkdir("swap1", 0o755);
    let t = stored_file(&fx, b"now a file", 0o644);
    let item = plan_item(&fx, "swap1", Some(t.clone()), None);
    assert_eq!(item.op, Op::Write);
    assert!(item.replace);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert!(!fx.is_dir("swap1"));
    assert_eq!(fx.read("swap1").unwrap(), b"now a file");
    assert_already_done(&fx, "swap1", &t);

    // file -> directory
    fx.write("swap2", b"was a file");
    let item = plan_item(&fx, "swap2", Some(Entry::dir(0o755, 1, 1)), None);
    assert_eq!(item.op, Op::Mkdir);
    assert!(item.replace);
    let (out, dm) = apply(&fx, &item);
    assert_eq!(out, Outcome::Applied);
    assert!(fx.is_dir("swap2"));
    assert_eq!(dm, vec![(rp("swap2"), 0o755)]);

    // symlink -> directory
    fx.symlink("swap3", b"whatever");
    let item = plan_item(&fx, "swap3", Some(Entry::dir(0o700, 1, 1)), None);
    assert!(item.replace);
    assert_eq!(apply(&fx, &item).0, Outcome::Applied);
    assert!(fx.is_dir("swap3"));
    assert_eq!(fx.link_target("swap3"), None);

    // a non-empty directory in the way is skipped, nothing is lost
    fx.write("busy/precious.txt", b"precious");
    let item = plan_item(&fx, "busy", Some(t), None);
    assert!(item.replace);
    let (out, _) = apply(&fx, &item);
    assert!(matches!(out, Outcome::Skipped(_)), "{out:?}");
    assert!(fx.is_dir("busy"));
    assert_eq!(fx.read("busy/precious.txt").unwrap(), b"precious");
}

pub fn tree_apply_refuses_to_leave_the_project<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("f.txt", b"a regular file");
    fx.symlink("link", fx.outside_dir().as_bytes());
    let blob_entry = stored_file(&fx, b"PWNED", 0o644);
    let outside_before = fx.outside_snapshot();
    let paths_before = fx.paths();

    let ops = [
        ("link/keep.txt", Op::Write, Some(blob_entry.clone())),
        ("link/new.txt", Op::Write, Some(blob_entry.clone())),
        ("link/keep.txt", Op::Delete, None),
        ("link/newdir", Op::Mkdir, Some(Entry::dir(0o755, 1, 1))),
        (
            "link/deep/er/newdir",
            Op::Mkdir,
            Some(Entry::dir(0o755, 1, 1)),
        ),
        (
            "link/sym",
            Op::Symlink,
            Some(Entry::symlink(b"x".to_vec(), 1, 1).unwrap()),
        ),
        (
            "link/keep.txt",
            Op::Chmod,
            Some(file_entry(OUTSIDE_KEEP, 0o777)),
        ),
        ("link/anything", Op::Rmdir, None),
        ("f.txt/child", Op::Write, Some(blob_entry.clone())),
        ("f.txt/child", Op::Delete, None),
        ("f.txt/dir", Op::Mkdir, Some(Entry::dir(0o755, 1, 1))),
    ];
    for (path, op, target) in ops {
        let item = raw_item(path, op, target);
        let mut dm = Vec::new();
        let r = fx.tree().apply(&item, &mut dm);
        assert!(
            matches!(r, Err(Error::Unsafe(_))),
            "{op:?} on {path}: expected Unsafe"
        );
        assert!(dm.is_empty());
    }
    // replace=true must not bypass the check either
    let mut item = raw_item("link/keep.txt", Op::Write, Some(blob_entry));
    item.replace = true;
    let mut dm = Vec::new();
    assert!(matches!(
        fx.tree().apply(&item, &mut dm),
        Err(Error::Unsafe(_))
    ));

    assert_eq!(
        fx.outside_snapshot(),
        outside_before,
        "outside was modified"
    );
    assert_eq!(
        fx.outside_snapshot()
            .iter()
            .find(|(k, _)| k == "keep.txt")
            .map(|(_, v)| v.clone()),
        Some(OUTSIDE_KEEP.to_vec())
    );
    assert_eq!(fx.paths(), paths_before, "project gained or lost paths");
    assert_eq!(fx.link_target("link").unwrap(), fx.outside_dir().as_bytes());
    assert_eq!(fx.read("f.txt").unwrap(), b"a regular file");
}

pub fn tree_planner_blocks_paths_below_symlinks<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.symlink("link", fx.outside_dir().as_bytes());
    let t = stored_file(&fx, b"x", 0o644);
    let item = plan_item(&fx, "link/keep.txt", Some(t), None);
    assert!(
        matches!(item.status, Status::Blocked(_)),
        "{:?}",
        item.status
    );
    assert_eq!(item.op, Op::None);
    assert!(!item.status.runnable(true));
}

pub fn tree_apply_write_with_corrupt_blob_leaves_target_untouched<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.write_mode("t.txt", b"old content", 0o644);
    let t = stored_file(&fx, b"the good content", 0o644);
    let d = t.blob().unwrap();
    fx.corrupt_blob(&d, b"the BAD content!!");
    let paths_before = fx.paths();

    // overwrite of an existing file
    let item = plan_item(&fx, "t.txt", Some(t.clone()), None);
    assert_eq!(item.op, Op::Write);
    let mut dm = Vec::new();
    let e = err_of(fx.tree().apply(&item, &mut dm));
    assert!(matches!(e, Error::Integrity(_)), "{e}");
    assert_eq!(fx.read("t.txt").unwrap(), b"old content");

    // creation of a new file: nothing appears (no partial or temp files either)
    let item = plan_item(&fx, "fresh.txt", Some(t), None);
    let e = err_of(fx.tree().apply(&item, &mut dm));
    assert!(matches!(e, Error::Integrity(_)), "{e}");
    assert!(!fx.exists("fresh.txt"));
    assert_eq!(fx.paths(), paths_before);
}

pub fn tree_apply_write_with_missing_blob_is_integrity_error<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.write("t.txt", b"old content");
    let missing = file_entry(b"content that was never stored", 0o644);
    let item = plan_item(&fx, "t.txt", Some(missing), None);
    assert_eq!(item.op, Op::Write);
    let mut dm = Vec::new();
    let e = err_of(fx.tree().apply(&item, &mut dm));
    assert!(matches!(e, Error::Integrity(_)), "{e}");
    assert_eq!(fx.read("t.txt").unwrap(), b"old content");
    assert_eq!(fx.paths(), vec!["t.txt".to_string()]);
}

// ---- SU-001: copies and renames of secret files stay sensitive

/// Content that no detector recognises: only the name `.env` makes it a secret.
const PLAIN_SECRET: &[u8] = b"hunter2\n";

fn assert_secret_not_in_store(fx: &impl TreeFixture, needle: &[u8]) {
    assert_no_blob_contains(fx.blobs(), needle);
    assert!(!fx.blobs().contains(&sha256(needle)));
}

pub fn tree_copy_of_a_secret_file_stays_sensitive<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write(".env", PLAIN_SECRET);
    fx.write("settings.txt", PLAIN_SECRET); // `cp .env settings.txt`
    fx.write("deep/dir/copy.cfg", PLAIN_SECRET);
    fx.write("notes.txt", b"ordinary text that is not a secret");
    let r = scan_capture(&fx);
    for p in [".env", "settings.txt", "deep/dir/copy.cfg"] {
        assert_eq!(r.get(p).kind(), Kind::Sensitive, "{p}");
        assert!(r.get(p).blob().is_none(), "{p}");
    }
    assert_eq!(r.get("notes.txt").kind(), Kind::File);
    assert_secret_not_in_store(&fx, PLAIN_SECRET);
    assert_eq!(
        all_blob_bytes(fx.blobs()),
        vec![b"ordinary text that is not a secret".to_vec()]
    );
}

pub fn tree_copy_sorted_before_the_secret_is_still_sensitive<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    // `-copy.txt` sorts before `.env`, so the walk meets the copy first.
    let fx = make(BIG_CAP);
    fx.write("-copy.txt", PLAIN_SECRET);
    fx.write(".a-copy", PLAIN_SECRET);
    fx.write(".env", PLAIN_SECRET);
    let r = scan_capture(&fx);
    for p in ["-copy.txt", ".a-copy", ".env"] {
        assert_eq!(r.get(p).kind(), Kind::Sensitive, "{p}");
    }
    assert_secret_not_in_store(&fx, PLAIN_SECRET);
    assert!(all_blob_bytes(fx.blobs()).is_empty());
}

pub fn tree_rename_of_a_secret_file_stays_sensitive<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write(".env", PLAIN_SECRET);
    let first = scan_capture(&fx);
    assert_eq!(first.get(".env").kind(), Kind::Sensitive);
    // the agent renames it to an innocent name and the original disappears
    fx.remove(".env");
    fx.write("config.sample", PLAIN_SECRET);
    let opts = ScanOptions {
        capture: true,
        cache_time_ns: Some(now_ns() + 10_000_000_000),
        cache_margin_ns: 0,
        no_cache: false,
    };
    let second = scan_with(&fx, &opts, &first.entries);
    assert_eq!(second.get("config.sample").kind(), Kind::Sensitive);
    assert!(!second.has(".env"));
    assert_secret_not_in_store(&fx, PLAIN_SECRET);
}

pub fn tree_content_stored_earlier_is_reclassified_once_it_is_known_to_be_secret<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.write("settings.txt", PLAIN_SECRET);
    let first = scan_capture(&fx);
    assert_eq!(
        first.get("settings.txt").kind(),
        Kind::File,
        "not known yet"
    );
    // later the same content shows up under a secret name
    fx.write(".env", PLAIN_SECRET);
    let opts = ScanOptions {
        capture: true,
        cache_time_ns: Some(now_ns() + 10_000_000_000),
        cache_margin_ns: 0,
        no_cache: false,
    };
    let second = scan_with(&fx, &opts, &first.entries);
    assert_eq!(second.get(".env").kind(), Kind::Sensitive);
    assert_eq!(
        second.get("settings.txt").kind(),
        Kind::Sensitive,
        "the stat cache must not keep an old File entry for content now known to be secret"
    );
    assert!(second.get("settings.txt").blob().is_none());
}

pub fn tree_observe_classifies_by_known_content<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write(".env", PLAIN_SECRET);
    fx.write("copy.txt", PLAIN_SECRET);
    fx.write("plain.txt", b"just text");
    scan_capture(&fx);
    for (p, kind) in [
        ("copy.txt", Kind::Sensitive),
        ("plain.txt", Kind::File),
        (".env", Kind::Sensitive),
    ] {
        match fx.tree().observe(&rp(p)).unwrap() {
            Observation::State(Some(e)) => assert_eq!(e.kind(), kind, "{p}"),
            other => panic!("{p}: {other:?}"),
        }
    }
}

pub fn tree_ordinary_duplicate_content_is_unaffected<F: TreeFixture>(make: impl Fn(u64) -> F) {
    let fx = make(BIG_CAP);
    fx.write("a.txt", b"same bytes");
    fx.write("b.txt", b"same bytes");
    fx.write(".env", PLAIN_SECRET);
    let r = scan_capture(&fx);
    assert_eq!(r.get("a.txt").kind(), Kind::File);
    assert_eq!(r.get("b.txt").kind(), Kind::File);
    assert_eq!(r.get("a.txt").digest(), r.get("b.txt").digest());
}

pub fn tree_dotenv_style_content_under_an_innocent_name_is_sensitive<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    let secret = b"DB_PASSWORD=hunter2\nPORT=5432\n";
    fx.write("settings.txt", secret);
    fx.write("app.cfg", b"PORT=5432\nLOG_LEVEL=debug\n");
    let r = scan_capture(&fx);
    assert_eq!(r.get("settings.txt").kind(), Kind::Sensitive);
    assert_eq!(r.get("app.cfg").kind(), Kind::File);
    assert_secret_not_in_store(&fx, b"hunter2");
}

pub fn tree_sensitive_content_is_remembered_by_scans_that_store_nothing<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    // A read-only scan (status) classifies with what is known and does not write blobs.
    let fx = make(BIG_CAP);
    fx.write(".env", PLAIN_SECRET);
    fx.write("copy.txt", PLAIN_SECRET);
    let r = scan_with(&fx, &ScanOptions::observing(None), &[]);
    assert_eq!(r.get("copy.txt").kind(), Kind::Sensitive);
    assert_eq!(r.stats.blobs_written, 0);
    assert!(all_blob_bytes(fx.blobs()).is_empty());
}

// ---- SU-002: hostile tree shapes degrade instead of failing the scan

pub fn tree_too_many_entries_in_one_directory_degrade_without_failing<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.set_limits(5, 256);
    for i in 0..6 {
        fx.write(&format!("big/f{i}.txt"), b"x");
    }
    fx.write("ok/a.txt", b"a");
    fx.write("top.txt", b"t");
    let r = scan_capture(&fx);
    assert!(r.has("big"), "the directory itself is still recorded");
    assert!(
        !r.paths().iter().any(|p| p.starts_with("big/")),
        "{:?}",
        r.paths()
    );
    assert!(r.has("ok/a.txt") && r.has("top.txt"), "{:?}", r.paths());
    assert!(
        r.carried.iter().any(|p| p.display() == "big"),
        "old entries are carried forward"
    );
    assert!(
        r.stats
            .warnings
            .iter()
            .any(|w| w.contains("more than 5 entries")),
        "{:?}",
        r.stats.warnings
    );
}

pub fn tree_ignored_names_do_not_count_against_the_entry_cap<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.set_limits(5, 256);
    fx.write(".agent-undoignore", b"*.tmp\n");
    for i in 0..40 {
        fx.write(&format!("d/junk{i}.tmp"), b"x");
    }
    for i in 0..3 {
        fx.write(&format!("d/real{i}.txt"), b"x");
    }
    let r = scan_capture(&fx);
    for i in 0..3 {
        assert!(r.has(&format!("d/real{i}.txt")), "{:?}", r.paths());
    }
    assert!(r.carried.is_empty() && !r.carried_all);
    assert!(r.stats.warnings.is_empty(), "{:?}", r.stats.warnings);
}

pub fn tree_nesting_beyond_the_depth_cap_degrades_without_failing<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.set_limits(1000, 3);
    fx.write("a/b/c/d/e/deep.txt", b"deep");
    fx.write("a/b/c/near.txt", b"near");
    let r = scan_capture(&fx);
    assert!(r.has("a/b/c/near.txt"));
    assert!(r.has("a/b/c/d"), "the directory at the cap is recorded");
    assert!(!r.has("a/b/c/d/e"), "{:?}", r.paths());
    assert!(r.carried.iter().any(|p| p.display() == "a/b/c/d"));
    assert!(
        r.stats.warnings.iter().any(|w| w.contains("deeper than 3")),
        "{:?}",
        r.stats.warnings
    );
}

pub fn tree_root_with_too_many_entries_degrades_without_failing<F: TreeFixture>(
    make: impl Fn(u64) -> F,
) {
    let fx = make(BIG_CAP);
    fx.set_limits(3, 256);
    for i in 0..5 {
        fx.write(&format!("f{i}.txt"), b"x");
    }
    let r = scan_capture(&fx);
    assert!(r.entries.is_empty());
    assert!(
        r.carried_all,
        "everything previously recorded is carried forward"
    );
    assert!(
        r.stats.warnings.iter().any(|w| w.contains("project root")),
        "{:?}",
        r.stats.warnings
    );
}
