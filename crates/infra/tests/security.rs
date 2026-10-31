//! Security and resource-safety tests against the real filesystem adapters.
//!
//! Everything runs inside per-test temp directories. Secret fixtures are built
//! at run time so no key-shaped literal appears in this source file.

use agent_undo_app::error::{Error, Result};
use agent_undo_app::ports::{Ports, ScanOptions, ScanStats, ScanVisitor, WorkingTree};
use agent_undo_app::usecases::checkpoint::{load_log, manual_checkpoint};
use agent_undo_app::usecases::gc::gc;
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::{apply_restore, apply_undo, plan_restore, plan_undo};
use agent_undo_app::usecases::verify::verify;
use agent_undo_domain::change::EntrySource;
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::hash::{sha256, to_hex};
use agent_undo_domain::journal::{CheckpointId, CheckpointRecord, RetentionPolicy, Selector};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Outcome, Plan, PlanItem, Status};
use agent_undo_infra::fs_blobs::FsBlobs;
use agent_undo_infra::fs_journal::FsJournal;
use agent_undo_infra::fs_snapshots::FsSnapshots;
use agent_undo_infra::fs_tree::FsTree;
use agent_undo_infra::layout::{DEFAULT_MAX_FILE_SIZE, StoreDir};
use agent_undo_infra::lock::FsLocker;
use agent_undo_infra::process::ProcessRunner;
use agent_undo_infra::project::Project;
use agent_undo_infra::support::{NullSink, SystemClock};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

// ------------------------------------------------------------------ fixtures

/// A temp directory with a project, an "outside" directory and a store location.
struct Env {
    base: PathBuf,
    root: PathBuf,
    outside: PathBuf,
    store_dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let base = std::env::temp_dir().join(format!("au-sec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("proj")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        let base = fs::canonicalize(&base).unwrap();
        Env {
            root: base.join("proj"),
            outside: base.join("outside"),
            store_dir: base.join("state").join("store"),
            base,
        }
    }

    fn store(&self) -> StoreDir {
        StoreDir::create(&self.store_dir, &self.root, false, DEFAULT_MAX_FILE_SIZE).unwrap()
    }

    fn project(&self) -> Project {
        Project::new(self.store(), Box::new(NullSink))
    }

    fn abs(&self, rel: impl AsRef<[u8]>) -> PathBuf {
        self.root.join(OsStr::from_bytes(rel.as_ref()))
    }

    fn write(&self, rel: impl AsRef<[u8]>, content: impl AsRef<[u8]>) {
        let p = self.abs(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    fn read(&self, rel: impl AsRef<[u8]>) -> Vec<u8> {
        fs::read(self.abs(rel)).unwrap()
    }

    fn mode(&self, rel: impl AsRef<[u8]>) -> u32 {
        fs::symlink_metadata(self.abs(rel)).unwrap().mode() & 0o7777
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Deterministic xorshift generator for run-time secret material.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Random alphanumeric string that always has a lower, an upper and a digit.
    fn token(&mut self, len: usize) -> String {
        const SET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut s: Vec<u8> = (0..len)
            .map(|_| SET[(self.next() % SET.len() as u64) as usize])
            .collect();
        s[0] = b'k';
        s[1] = b'Q';
        s[2] = b'7';
        String::from_utf8(s).unwrap()
    }

    fn upper_digits(&mut self, len: usize) -> String {
        const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| char::from(SET[(self.next() % SET.len() as u64) as usize]))
            .collect()
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn rp(s: &str) -> RelPath {
    RelPath::new(s).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn is_locked<T>(r: Result<T>) -> bool {
    matches!(r, Err(Error::Locked(_)))
}

fn err_of<T>(r: Result<T>) -> Error {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

fn baseline(p: &Ports<'_>) -> CheckpointRecord {
    record_baseline(p).unwrap().record
}

fn checkpoint(p: &Ports<'_>) -> CheckpointRecord {
    manual_checkpoint(p, None, false).unwrap().record
}

fn item<'a>(plan: &'a Plan, path: &str) -> (usize, &'a PlanItem) {
    plan.items
        .iter()
        .enumerate()
        .find(|(_, i)| i.path.as_bytes() == path.as_bytes())
        .unwrap_or_else(|| panic!("no plan item for {path}: {:?}", plan.items))
}

fn manifest(p: &Ports<'_>, id: CheckpointId) -> Vec<(RelPath, Entry)> {
    let mut m = p.snapshots.open_manifest(id).unwrap();
    let mut out = Vec::new();
    while let Some(e) = m.next_entry().unwrap() {
        out.push(e);
    }
    out
}

fn entry_of(p: &Ports<'_>, id: CheckpointId, path: impl AsRef<[u8]>) -> Option<Entry> {
    manifest(p, id)
        .into_iter()
        .find(|(rel, _)| rel.as_bytes() == path.as_ref())
        .map(|(_, e)| e)
}

fn journal_len(p: &Ports<'_>) -> usize {
    p.journal.load().unwrap().records().len()
}

/// Everything observable about a tree without following symlinks.
fn tree_state(root: &Path) -> BTreeMap<Vec<u8>, String> {
    fn go(dir: &Path, prefix: &[u8], out: &mut BTreeMap<Vec<u8>, String>) {
        for ent in fs::read_dir(dir).unwrap() {
            let ent = ent.unwrap();
            let name = ent.file_name();
            let path = ent.path();
            let mut rel = prefix.to_vec();
            if !rel.is_empty() {
                rel.push(b'/');
            }
            rel.extend_from_slice(name.as_bytes());
            let md = fs::symlink_metadata(&path).unwrap();
            let ft = md.file_type();
            let mode = md.mode() & 0o7777;
            let desc = if ft.is_symlink() {
                format!("link:{:?}", fs::read_link(&path).unwrap())
            } else if ft.is_dir() {
                format!("dir:{mode:o}")
            } else if ft.is_file() {
                let digest = fs::read(&path)
                    .map(|b| to_hex(&sha256(&b)))
                    .unwrap_or_else(|_| "unreadable".into());
                format!("file:{mode:o}:{digest}")
            } else {
                format!("special:{mode:o}")
            };
            out.insert(rel.clone(), desc);
            if ft.is_dir() {
                go(&path, &rel, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    go(root, b"", &mut out);
    out
}

/// Every entry below `dir` (directories and files), not following symlinks.
fn walk(dir: &Path) -> Vec<(PathBuf, fs::Metadata)> {
    let mut out = Vec::new();
    for ent in fs::read_dir(dir).unwrap() {
        let path = ent.unwrap().path();
        let md = fs::symlink_metadata(&path).unwrap();
        let is_dir = md.is_dir();
        out.push((path.clone(), md));
        if is_dir {
            out.extend(walk(&path));
        }
    }
    out
}

fn temp_leftovers(root: &Path) -> Vec<PathBuf> {
    walk(root)
        .into_iter()
        .map(|(p, _)| p)
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.as_bytes().starts_with(b".agent-undo-tmp-"))
        })
        .collect()
}

fn is_root_user() -> bool {
    let probe = std::env::temp_dir().join(format!("au-sec-rootprobe-{}", std::process::id()));
    fs::write(&probe, b"x").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::File::open(&probe).is_ok();
    let _ = fs::remove_file(&probe);
    readable
}

// ------------------------------------------------------- hooked working tree

type Hook = Box<dyn FnOnce()>;

/// The real `FsTree` plus closures that run just before the n-th `observe` of a
/// path or before the `apply` of a path: they model an attacker acting between
/// planning and applying (or between re-validation and the write).
struct HookTree {
    inner: FsTree,
    seen: RefCell<HashMap<Vec<u8>, usize>>,
    before_observe: RefCell<Vec<(Vec<u8>, usize, Hook)>>,
    before_apply: RefCell<Vec<(Vec<u8>, Hook)>>,
}

impl HookTree {
    fn on_observe(&self, path: &str, nth: usize, f: impl FnOnce() + 'static) {
        self.before_observe
            .borrow_mut()
            .push((path.as_bytes().to_vec(), nth, Box::new(f)));
    }

    fn on_apply(&self, path: &str, f: impl FnOnce() + 'static) {
        self.before_apply
            .borrow_mut()
            .push((path.as_bytes().to_vec(), Box::new(f)));
    }
}

impl WorkingTree for HookTree {
    fn scan(&self, opts: &ScanOptions, visitor: &mut dyn ScanVisitor) -> Result<ScanStats> {
        self.inner.scan(opts, visitor)
    }

    fn observe(&self, path: &RelPath) -> Result<Observation> {
        let n = {
            let mut seen = self.seen.borrow_mut();
            let c = seen.entry(path.as_bytes().to_vec()).or_insert(0);
            *c += 1;
            *c
        };
        let due: Vec<Hook> = {
            let mut hooks = self.before_observe.borrow_mut();
            let (due, keep): (Vec<_>, Vec<_>) = hooks
                .drain(..)
                .partition(|(p, nth, _)| p == path.as_bytes() && *nth == n);
            *hooks = keep;
            due.into_iter().map(|(_, _, f)| f).collect()
        };
        for f in due {
            f();
        }
        self.inner.observe(path)
    }

    fn apply(&self, item: &PlanItem, dir_modes: &mut Vec<(RelPath, u32)>) -> Result<Outcome> {
        let due: Vec<Hook> = {
            let mut hooks = self.before_apply.borrow_mut();
            let (due, keep): (Vec<_>, Vec<_>) = hooks
                .drain(..)
                .partition(|(p, _)| p == item.path.as_bytes());
            *hooks = keep;
            due.into_iter().map(|(_, f)| f).collect()
        };
        for f in due {
            f();
        }
        self.inner.apply(item, dir_modes)
    }

    fn set_dir_mode(&self, path: &RelPath, mode: u32) -> Result<()> {
        self.inner.set_dir_mode(path, mode)
    }
}

/// Ports assembled by hand from the real adapters (what `Project` does), with
/// the working tree wrapped in a [`HookTree`].
struct Rig {
    clock: SystemClock,
    sink: NullSink,
    locker: FsLocker,
    journal: FsJournal,
    snapshots: FsSnapshots,
    blobs: FsBlobs,
    tree: HookTree,
    runner: ProcessRunner,
}

impl Rig {
    fn new(env: &Env) -> Rig {
        let store = env.store();
        let blobs = FsBlobs::new(store.blobs_dir(), store.tmp_dir());
        let inner = FsTree::new(
            store.root.clone(),
            &store.dir,
            store.meta.max_file_size,
            *store.key(),
            blobs.clone(),
        );
        Rig {
            clock: SystemClock,
            sink: NullSink,
            locker: FsLocker::new(store.lock_path()),
            journal: FsJournal::new(store.log_path(), store.pruned_path()),
            snapshots: FsSnapshots::new(store.checkpoints_dir(), store.tmp_dir()),
            blobs,
            tree: HookTree {
                inner,
                seen: RefCell::default(),
                before_observe: RefCell::default(),
                before_apply: RefCell::default(),
            },
            runner: ProcessRunner::new(store.root.clone()),
        }
    }

    fn ports(&self) -> Ports<'_> {
        Ports {
            clock: &self.clock,
            events: &self.sink,
            locks: &self.locker,
            journal: &self.journal,
            snapshots: &self.snapshots,
            blobs: &self.blobs,
            tree: &self.tree,
            runner: &self.runner,
        }
    }
}

// ============================================================ 1. secrets

struct Secret {
    path: String,
    content: Vec<u8>,
    /// Substrings that must never appear anywhere in the store.
    needles: Vec<Vec<u8>>,
}

struct Plain {
    path: String,
    content: Vec<u8>,
}

fn private_key_block(rng: &mut Rng) -> (String, Vec<String>) {
    let header = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
    let footer = format!("-----END {} KEY-----", "RSA PRIVATE");
    let lines: Vec<String> = (0..6).map(|_| rng.token(64)).collect();
    let text = format!("{header}\n{}\n{footer}\n", lines.join("\n"));
    (text, lines)
}

/// One generation of secret-bearing files; `generation` grows the padding so that sizes
/// differ between generations (the stat cache must not hide a rewrite).
fn secret_files(rng: &mut Rng, generation: usize) -> Vec<Secret> {
    let pad = "#".repeat(generation * 11 + 1);
    let mut out: Vec<Secret> = Vec::new();
    let mut text = |path: &str, body: String, needles: Vec<String>| {
        out.push(Secret {
            path: path.to_string(),
            content: format!("{body}\n{pad}\n").into_bytes(),
            needles: needles.into_iter().map(String::into_bytes).collect(),
        });
    };

    // Secret by name.
    let t = rng.token(32);
    text(".env", format!("{}={t}\nDEBUG=1", "TOKEN"), vec![t]);
    let t = rng.token(32);
    text(".env.local", format!("{}={t}", "DB_PASS"), vec![t]);
    for name in ["id_rsa", "id_ed25519", "server.pem", "app.key"] {
        let (block, lines) = private_key_block(rng);
        text(name, block, lines);
    }
    let t = rng.token(40);
    text(
        ".npmrc",
        format!("//registry.example.org/:_authToken={t}"),
        vec![t],
    );
    let t = rng.token(28);
    text(
        ".netrc",
        format!("machine example.org login ci {} {t}", "password"),
        vec![t],
    );
    let (a, b) = (rng.token(20), rng.token(40));
    text(
        ".aws/credentials",
        format!("[default]\naws_access_key_id = {a}\naws_secret_access_key = {b}"),
        vec![a, b],
    );
    let t = rng.token(24);
    text(
        ".ssh/config",
        format!("Host build\n  User {t}\n  IdentityFile ~/.ssh/id_rsa"),
        vec![t],
    );
    let t = rng.token(36);
    text(
        "credentials.json",
        format!("{{\"client\": \"{t}\"}}"),
        vec![t],
    );

    // A binary keystore.
    let bin = rng.bytes(160 + generation * 13);
    let needle = bin.get(40..72).unwrap().to_vec();
    let keystore = Secret {
        path: "keystore.p12".into(),
        content: bin,
        needles: vec![needle],
    };

    // Secret by content under ordinary names.
    let (block, lines) = private_key_block(rng);
    text("notes/deploy.txt", format!("deploy notes\n{block}"), lines);
    let id = format!("{}{}", "AK", "IA") + &rng.upper_digits(16);
    text("cfg/aws-notes.txt", format!("key id: {id}"), vec![id]);
    let gh = format!("{}{}", "gh", "p_") + &rng.token(36);
    text(
        "scripts/ci.sh",
        format!("#!/bin/sh\nexport GH={gh}"),
        vec![gh],
    );
    let jwt = format!(
        "{}{}.{}{}.{}",
        "ey",
        "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "ey",
        "JzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ",
        rng.token(43)
    );
    text("docs/session.txt", format!("jwt: {jwt}"), vec![jwt]);
    let pw = rng.token(24);
    text(
        "conf/db.yml",
        format!("database: postgres://admin:{pw}@db.internal.example/app"),
        vec![pw],
    );
    let pw = rng.token(32);
    text(
        "src/settings.py",
        format!("{} = \"{pw}\"", "password"),
        vec![pw],
    );
    out.push(keystore);
    out
}

fn plain_files(generation: usize) -> Vec<Plain> {
    let mut v = vec![
        Plain {
            path: "src/main.rs".into(),
            content: format!(
                "fn main() {{ println!(\"ordinary program, revision {generation}\"); }}\n"
            )
            .into_bytes(),
        },
        Plain {
            path: "README.md".into(),
            content: format!("# Project\n\nOrdinary readme text, revision {generation}.\n")
                .into_bytes(),
        },
        Plain {
            path: "docs/guide.txt".into(),
            content: "Plain documentation without anything sensitive.\n"
                .repeat(3 + generation)
                .into_bytes(),
        },
    ];
    for p in &mut v {
        p.content.extend_from_slice(b"plain-marker-only\n");
    }
    v
}

struct History {
    project: Project,
    first_gen: Vec<Secret>,
    all_secrets: Vec<Secret>,
    all_plain: Vec<Plain>,
    ids: Vec<CheckpointId>,
}

/// Baseline plus three more checkpoints, rewriting, adding and deleting secrets.
fn record_secret_history(env: &Env) -> History {
    let project = env.project();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut all_secrets = Vec::new();
    let mut all_plain = Vec::new();
    let mut ids = Vec::new();

    let write_gen = |env: &Env, generation: usize, rng: &mut Rng| -> (Vec<Secret>, Vec<Plain>) {
        let s = secret_files(rng, generation);
        for f in &s {
            env.write(&f.path, &f.content);
        }
        let p = plain_files(generation);
        for f in &p {
            env.write(&f.path, &f.content);
        }
        (s, p)
    };

    let ports = project.ports();
    let (s1, p1) = write_gen(env, 1, &mut rng);
    ids.push(baseline(&ports).id);
    let first_gen: Vec<Secret> = s1
        .iter()
        .map(|s| Secret {
            path: s.path.clone(),
            content: s.content.clone(),
            needles: s.needles.clone(),
        })
        .collect();
    all_secrets.extend(s1);
    all_plain.extend(p1);

    let (s2, p2) = write_gen(env, 2, &mut rng);
    ids.push(checkpoint(&ports).id);
    all_secrets.extend(s2);
    all_plain.extend(p2);

    let (s3, p3) = write_gen(env, 3, &mut rng);
    let t = rng.token(32);
    let extra = Secret {
        path: ".env.production".into(),
        content: format!("{}={t}\n", "API_SECRET").into_bytes(),
        needles: vec![t.into_bytes()],
    };
    env.write(&extra.path, &extra.content);
    ids.push(checkpoint(&ports).id);
    all_secrets.extend(s3);
    all_secrets.push(extra);
    all_plain.extend(p3);

    // The agent deletes every other secret and adds an ordinary file.
    for s in all_secrets.iter().rev().take(10).step_by(2) {
        let _ = fs::remove_file(env.abs(&s.path));
    }
    env.write("src/extra.rs", "pub fn extra() {}\n");
    all_plain.push(Plain {
        path: "src/extra.rs".into(),
        content: b"pub fn extra() {}\n".to_vec(),
    });
    ids.push(checkpoint(&ports).id);

    History {
        project,
        first_gen,
        all_secrets,
        all_plain,
        ids,
    }
}

#[test]
fn secrets_never_reach_the_store() {
    let env = Env::new("secrets");
    let h = record_secret_history(&env);
    let ports = h.project.ports();
    assert_eq!(h.ids.len(), 4);

    // The fixtures really are classified as secrets (otherwise the test proves nothing).
    for s in &h.first_gen {
        let e = entry_of(&ports, h.ids[0], &s.path)
            .unwrap_or_else(|| panic!("{} missing from the baseline manifest", s.path));
        assert_eq!(e.kind(), Kind::Sensitive, "{} must be withheld", s.path);
        assert_eq!(e.size(), s.content.len() as u64);
        assert_ne!(
            e.id(),
            sha256(&s.content).as_slice(),
            "{}: the manifest id must be keyed, not the plain content hash",
            s.path
        );
        assert!(
            !ports.blobs.contains(&sha256(&s.content)),
            "{}: content must not be a blob",
            s.path
        );
    }

    // Collect everything that must not appear anywhere.
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for s in &h.all_secrets {
        for n in &s.needles {
            needles.push((format!("secret of {}", s.path), n.clone()));
        }
        needles.push((format!("whole content of {}", s.path), s.content.clone()));
        let digest = sha256(&s.content);
        needles.push((
            format!("sha256 hex of {}", s.path),
            to_hex(&digest).into_bytes(),
        ));
        needles.push((format!("raw sha256 of {}", s.path), digest.to_vec()));
        needles.push((
            format!("uppercase sha256 hex of {}", s.path),
            to_hex(&digest).to_uppercase().into_bytes(),
        ));
    }

    let mut files_read = 0;
    let mut total_bytes = 0;
    for (path, md) in walk(&env.store_dir) {
        if !md.is_file() {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        files_read += 1;
        total_bytes += bytes.len();
        for (what, needle) in &needles {
            assert!(
                !contains(&bytes, needle),
                "{what} found in store file {}",
                path.display()
            );
        }
    }
    assert!(
        files_read > 10,
        "walked the whole store ({files_read} files)"
    );
    assert!(total_bytes > 0);

    // Ordinary files are stored (content-addressed, in blobs/).
    for p in &h.all_plain {
        assert!(
            ports.blobs.contains(&sha256(&p.content)),
            "{} should be stored as a blob",
            p.path
        );
    }
    let listing = ports.blobs.list().unwrap();
    assert_eq!(
        listing.blobs.len(),
        {
            let mut d: Vec<_> = h.all_plain.iter().map(|p| sha256(&p.content)).collect();
            d.sort();
            d.dedup();
            d.len()
        },
        "the blob area holds exactly the ordinary file contents"
    );
    let mut blob_bytes = Vec::new();
    for (path, _) in walk(&env.store_dir.join("blobs")) {
        if path.is_file() {
            blob_bytes.extend(fs::read(path).unwrap());
        }
    }
    assert!(contains(&blob_bytes, b"plain-marker-only"));

    // Secrets stay recorded as withheld in every checkpoint they existed in.
    for s in &h.first_gen {
        let latest = entry_of(&ports, h.ids[2], &s.path).expect("still present at checkpoint 3");
        assert_eq!(latest.kind(), Kind::Sensitive);
    }
    assert!(verify(&ports).unwrap().ok());
}

#[test]
fn store_permissions_are_private_and_the_key_lives_only_in_the_key_file() {
    let env = Env::new("perms");
    let h = record_secret_history(&env);
    // A use case that takes the lock, so the lock file exists too.
    assert!(verify(&h.project.ports()).unwrap().ok());

    let key_hex = to_hex(h.project.store.key());
    let key_path = env.store_dir.join("key");
    assert_eq!(fs::read_to_string(&key_path).unwrap().trim(), key_hex);
    assert_eq!(fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);

    let root_md = fs::metadata(&env.store_dir).unwrap();
    assert_eq!(root_md.mode() & 0o777, 0o700, "store directory");
    let mut dirs = 0;
    let mut files = 0;
    for (path, md) in walk(&env.store_dir) {
        let mode = md.mode() & 0o7777;
        if md.is_dir() {
            dirs += 1;
            assert_eq!(mode, 0o700, "directory {}", path.display());
        } else if md.is_file() {
            files += 1;
            assert_eq!(mode, 0o600, "file {}", path.display());
            if path != key_path {
                assert!(
                    !contains(&fs::read(&path).unwrap(), key_hex.as_bytes()),
                    "the HMAC key appears in {}",
                    path.display()
                );
                assert!(
                    !contains(&fs::read(&path).unwrap(), h.project.store.key()),
                    "raw HMAC key bytes appear in {}",
                    path.display()
                );
            }
        } else {
            panic!("unexpected non-file/dir in the store: {}", path.display());
        }
    }
    assert!(
        dirs >= 4 && files >= 10,
        "walked {dirs} dirs and {files} files"
    );
    for name in ["meta", "log", "lock", "key"] {
        assert!(env.store_dir.join(name).is_file(), "{name} exists");
    }
    assert_eq!(fs::read_dir(env.store_dir.join("tmp")).unwrap().count(), 0);
}

// ===================================================== 2. undo and secrets

#[test]
fn undo_never_touches_secrets() {
    let env = Env::new("undo-secrets");
    let mut rng = Rng(42);
    let project = env.project();
    let ports = project.ports();

    let gh_old = format!("{}{}", "gh", "p_") + &rng.token(36);
    env.write(".env", format!("{}={}\n", "TOKEN", rng.token(32)));
    let (key_block, _) = private_key_block(&mut rng);
    env.write("id_rsa", &key_block);
    env.write("notes/plain.txt", "just some notes\n");
    env.write("config/leak.txt", format!("export GH={gh_old}\n"));
    env.write("src/app.rs", "fn app() { /* original */ }\n");
    let base = baseline(&ports);

    // The agent: edits, deletes and creates sensitive files, and edits real code.
    let new_env = format!("{}={}\n", "TOKEN", rng.token(40));
    env.write(".env", &new_env);
    fs::remove_file(env.abs("id_rsa")).unwrap();
    let prod = format!("{}={}\n", "PROD_SECRET", rng.token(32));
    env.write(".env.prod", &prod);
    let leaked = format!("token: {}{}{}\n", "gh", "p_", rng.token(36));
    env.write("notes/plain.txt", &leaked);
    fs::remove_file(env.abs("config/leak.txt")).unwrap();
    env.write("src/app.rs", "fn app() { /* agent was here */ }\n");
    let rec = checkpoint(&ports);
    assert!(rec.counts.total() >= 6);

    let sensitive_paths = [
        ".env",
        "id_rsa",
        ".env.prod",
        "notes/plain.txt",
        "config/leak.txt",
    ];
    let before = tree_state(&env.root);

    let plan = plan_undo(&ports, &Selector::Last).unwrap();
    for path in sensitive_paths {
        let (_, it) = item(&plan, path);
        assert!(
            matches!(it.status, Status::NotRestorable(_)),
            "{path}: expected not-restorable, got {:?}",
            it.status
        );
    }
    let (app_idx, app) = item(&plan, "src/app.rs");
    assert_eq!(app.status, Status::Ready);

    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(report.error.is_none() && report.refused.is_none());
    assert!(matches!(report.outcomes[app_idx], Outcome::Applied));
    for path in sensitive_paths {
        let (idx, _) = item(&report.plan, path);
        assert!(
            matches!(report.outcomes[idx], Outcome::Skipped(_)),
            "{path}: {:?}",
            report.outcomes[idx]
        );
    }
    // Real code was restored, every sensitive path is exactly as the agent left it.
    assert_eq!(env.read("src/app.rs"), b"fn app() { /* original */ }\n");
    let after = tree_state(&env.root);
    for path in sensitive_paths {
        assert_eq!(
            before.get(path.as_bytes()),
            after.get(path.as_bytes()),
            "{path} changed on disk"
        );
    }
    assert_eq!(env.read(".env"), new_env.as_bytes());
    assert!(
        !env.abs("id_rsa").exists(),
        "deleted key is not resurrected"
    );
    assert!(!env.abs("config/leak.txt").exists());
    assert_eq!(env.read(".env.prod"), prod.as_bytes());
    assert_eq!(env.read("notes/plain.txt"), leaked.as_bytes());

    // The same holds with --force.
    let newer = format!("{}={}\n", "TOKEN", rng.token(48));
    env.write(".env", &newer);
    env.write("src/app.rs", "fn app() { /* again */ }\n");
    checkpoint(&ports);
    let before = tree_state(&env.root);
    let report = apply_undo(&ports, &Selector::Last, true).unwrap();
    assert!(report.error.is_none());
    assert_eq!(env.read("src/app.rs"), b"fn app() { /* original */ }\n");
    let after = tree_state(&env.root);
    for path in sensitive_paths {
        assert_eq!(
            before.get(path.as_bytes()),
            after.get(path.as_bytes()),
            "{path} (force)"
        );
    }
    assert_eq!(env.read(".env"), newer.as_bytes());

    // A restore from the baseline refuses to touch them as well.
    let rep = apply_restore(&ports, &rp(".env"), base.id, true).unwrap();
    assert!(
        rep.pre_undo.is_none() && rep.result.is_none(),
        "nothing to do, nothing recorded"
    );
    assert!(
        rep.outcomes
            .iter()
            .all(|o| matches!(o, Outcome::NotAttempted))
    );
    assert_eq!(env.read(".env"), newer.as_bytes());
}

// ===================================================== 3. symlink attacks

#[test]
fn symlinks_are_recorded_as_links_and_never_followed_by_the_snapshot() {
    let env = Env::new("symlinks");
    let mut rng = Rng(7);
    let out_file_content = format!("outside file {}\n", rng.token(30));
    let out_inner_content = format!("outside inner {}\n", rng.token(30));
    fs::write(env.outside.join("out.txt"), &out_file_content).unwrap();
    fs::create_dir_all(env.outside.join("dir")).unwrap();
    fs::write(
        env.outside.join("dir").join("inner.txt"),
        &out_inner_content,
    )
    .unwrap();

    env.write("plain.txt", "inside the project\n");
    symlink(env.outside.join("out.txt"), env.abs("link_file")).unwrap();
    symlink(env.outside.join("dir"), env.abs("link_dir")).unwrap();
    symlink("../outside/out.txt", env.abs("rel_link")).unwrap();
    symlink("does-not-exist", env.abs("dangling")).unwrap();

    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);

    let link = |name: &str, target: &[u8]| {
        let e = entry_of(&ports, base.id, name).unwrap_or_else(|| panic!("{name} not recorded"));
        assert_eq!(e.kind(), Kind::Symlink, "{name}");
        assert_eq!(e.target(), Some(target), "{name}");
    };
    link(
        "link_file",
        env.outside.join("out.txt").as_os_str().as_bytes(),
    );
    link("link_dir", env.outside.join("dir").as_os_str().as_bytes());
    link("rel_link", b"../outside/out.txt");
    link("dangling", b"does-not-exist");
    let paths: Vec<Vec<u8>> = manifest(&ports, base.id)
        .into_iter()
        .map(|(p, _)| p.as_bytes().to_vec())
        .collect();
    assert!(
        !paths.iter().any(|p| p.starts_with(b"link_dir/")),
        "a directory behind a symlink must not be walked: {paths:?}"
    );

    // Only the in-project file became a blob; nothing from outside is in the store.
    assert_eq!(ports.blobs.list().unwrap().blobs.len(), 1);
    for (path, md) in walk(&env.store_dir) {
        if md.is_file() {
            let bytes = fs::read(&path).unwrap();
            for secret in [&out_file_content, &out_inner_content] {
                assert!(
                    !contains(&bytes, secret.as_bytes()),
                    "outside content found in {}",
                    path.display()
                );
            }
        }
    }

    // Changing what the links point to is not a change of the project.
    fs::write(env.outside.join("out.txt"), "rewritten outside\n").unwrap();
    fs::write(
        env.outside.join("dir").join("inner.txt"),
        "rewritten inner\n",
    )
    .unwrap();
    let rec = checkpoint(&ports);
    assert_eq!(rec.counts.total(), 0, "{:?}", rec.counts);
}

#[test]
fn undo_blocks_paths_below_a_directory_replaced_by_a_symlink() {
    let env = Env::new("symlinked-parent");
    let mut rng = Rng(11);
    let sentinel = env.outside.join("sentinel_dir");
    fs::create_dir_all(&sentinel).unwrap();
    fs::write(
        sentinel.join("sentinel.txt"),
        format!("sentinel {}", rng.token(20)),
    )
    .unwrap();

    env.write("d/x", "orig x\n");
    env.write("d/y", "orig y\n");
    env.write("keep.txt", "keep\n");
    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);

    fs::remove_dir_all(env.abs("d")).unwrap();
    symlink(&sentinel, env.abs("d")).unwrap();
    checkpoint(&ports);
    let outside_before = tree_state(&env.outside);

    let plan = plan_undo(&ports, &Selector::Last).unwrap();
    for path in ["d/x", "d/y"] {
        let (_, it) = item(&plan, path);
        assert!(
            matches!(it.status, Status::Blocked(_)),
            "{path}: {:?}",
            it.status
        );
    }
    assert_eq!(plan.counts().blocked, 2);
    let restore = plan_restore(&ports, &rp("d"), base.id).unwrap();
    for path in ["d/x", "d/y"] {
        let (_, it) = item(&restore, path);
        assert!(
            matches!(it.status, Status::Blocked(_)),
            "restore {path}: {:?}",
            it.status
        );
    }

    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    for path in ["d/x", "d/y"] {
        let (idx, _) = item(&report.plan, path);
        assert!(
            matches!(report.outcomes[idx], Outcome::Skipped(_)),
            "{path}"
        );
    }
    assert_eq!(
        tree_state(&env.outside),
        outside_before,
        "outside directory untouched"
    );
    assert!(!sentinel.join("x").exists() && !sentinel.join("y").exists());

    let rep = apply_restore(&ports, &rp("d"), base.id, false).unwrap();
    assert!(rep.error.is_none());
    assert_eq!(
        tree_state(&env.outside),
        outside_before,
        "outside untouched by restore"
    );
    assert!(!sentinel.join("x").exists());
}

#[test]
fn target_swapped_for_a_symlink_between_plan_and_apply_fails_that_item() {
    let env = Env::new("swap-file");
    let victim_content = "victim: must stay exactly like this\n";
    let victim = env.outside.join("victim.txt");
    fs::write(&victim, victim_content).unwrap();

    env.write("f.txt", "v1 original\n");
    env.write("g.txt", "g original\n");
    let rig = Rig::new(&env);
    let ports = rig.ports();
    baseline(&ports);
    env.write("f.txt", "v2 changed by the agent\n");
    env.write("g.txt", "g changed by the agent\n");
    let last = checkpoint(&ports);

    // Planning observes f.txt once; the second observation is the re-validation
    // right before the write. The attacker acts in between.
    let (f, v) = (env.abs("f.txt"), victim.clone());
    rig.tree.on_observe("f.txt", 2, move || {
        fs::remove_file(&f).unwrap();
        symlink(&v, &f).unwrap();
    });
    let before_len = journal_len(&ports);
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();

    let (idx, _) = item(&report.plan, "f.txt");
    assert!(
        matches!(report.outcomes[idx], Outcome::Failed(_)),
        "{:?}",
        report.outcomes
    );
    assert!(report.error.as_deref().unwrap().contains("f.txt"));
    assert_eq!(
        fs::read_to_string(&victim).unwrap(),
        victim_content,
        "outside file untouched"
    );
    assert!(
        fs::symlink_metadata(env.abs("f.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), victim_content);

    let pre = report
        .pre_undo
        .as_ref()
        .expect("pre-undo checkpoint exists");
    let post = report
        .result
        .as_ref()
        .expect("the result is recorded even after a failure");
    assert!(pre.id.get() > last.id.get() && post.id.get() > pre.id.get());
    assert_eq!(journal_len(&ports), before_len + 2);
    assert!(verify(&ports).unwrap().ok());
    // The pre-undo checkpoint saw the project before anything was touched.
    assert_eq!(
        entry_of(&ports, pre.id, "f.txt").unwrap().kind(),
        Kind::File
    );
    assert_eq!(
        entry_of(&ports, post.id, "f.txt").unwrap().kind(),
        Kind::Symlink
    );
}

#[test]
fn parent_swapped_for_a_symlink_between_plan_and_apply_fails_that_item() {
    let env = Env::new("swap-parent");
    let victim_dir = env.outside.join("victim_dir");
    fs::create_dir_all(&victim_dir).unwrap();
    fs::write(victim_dir.join("x"), "victim x\n").unwrap();

    env.write("d/x", "x v1\n");
    let rig = Rig::new(&env);
    let ports = rig.ports();
    baseline(&ports);
    env.write("d/x", "x v2 changed by the agent\n");
    checkpoint(&ports);
    let outside_before = tree_state(&env.outside);

    let (d, v) = (env.abs("d"), victim_dir.clone());
    rig.tree.on_observe("d/x", 2, move || {
        fs::remove_dir_all(&d).unwrap();
        symlink(&v, &d).unwrap();
    });
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    let (idx, _) = item(&report.plan, "d/x");
    assert!(
        matches!(report.outcomes[idx], Outcome::Failed(_)),
        "{:?}",
        report.outcomes
    );
    assert!(report.error.is_some());
    assert_eq!(
        tree_state(&env.outside),
        outside_before,
        "nothing written through the symlink"
    );
    assert!(report.pre_undo.is_some() && report.result.is_some());
    assert!(verify(&ports).unwrap().ok());
}

#[test]
fn parent_swapped_after_revalidation_is_caught_by_the_executor() {
    let env = Env::new("swap-parent-late");
    let victim_dir = env.outside.join("victim_dir");
    fs::create_dir_all(&victim_dir).unwrap();
    fs::write(victim_dir.join("x"), "victim x\n").unwrap();

    env.write("d/x", "x v1\n");
    let rig = Rig::new(&env);
    let ports = rig.ports();
    baseline(&ports);
    env.write("d/x", "x v2 changed by the agent\n");
    checkpoint(&ports);
    let outside_before = tree_state(&env.outside);

    // Swap after the use case re-validated the item, right before the write.
    let (d, v) = (env.abs("d"), victim_dir.clone());
    rig.tree.on_apply("d/x", move || {
        fs::remove_dir_all(&d).unwrap();
        symlink(&v, &d).unwrap();
    });
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    let (idx, _) = item(&report.plan, "d/x");
    assert!(
        matches!(report.outcomes[idx], Outcome::Failed(_)),
        "{:?}",
        report.outcomes
    );
    assert!(
        report.error.as_deref().unwrap().contains("symlink"),
        "{:?}",
        report.error
    );
    assert_eq!(tree_state(&env.outside), outside_before);
    assert!(report.result.is_some());
}

#[test]
fn restore_replaces_a_symlink_at_the_target_without_following_it() {
    let env = Env::new("restore-final-symlink");
    let victim = env.outside.join("victim.txt");
    fs::write(&victim, "victim content\n").unwrap();
    env.write("f.txt", "original content\n");
    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);

    fs::remove_file(env.abs("f.txt")).unwrap();
    symlink(&victim, env.abs("f.txt")).unwrap();
    checkpoint(&ports);

    let report = apply_restore(&ports, &rp("f.txt"), base.id, false).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.applied(), 1);
    let md = fs::symlink_metadata(env.abs("f.txt")).unwrap();
    assert!(md.is_file() && !md.file_type().is_symlink());
    assert_eq!(env.read("f.txt"), b"original content\n");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim content\n");
    assert!(temp_leftovers(&env.root).is_empty());
}

// ======================================================== path traversal

const HOSTILE_PATHS: &[&str] = &[
    "../escape.txt",
    "a/../../escape.txt",
    "a/..",
    "a//b",
    "a/./b",
    "./a",
    "a/",
    "x%00y",
    "%2E%2E/escape.txt",
];

#[test]
fn hostile_paths_in_a_manifest_are_rejected_and_nothing_outside_is_touched() {
    let env = Env::new("manifest-traversal");
    env.write("a.txt", "a v1\n");
    env.write("sub/b.txt", "b v1\n");
    fs::write(env.outside.join("canary.txt"), "canary\n").unwrap();
    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);
    env.write("a.txt", "a v2 changed\n");
    let second = checkpoint(&ports);

    let manifest_path = env
        .store_dir
        .join("checkpoints")
        .join(format!("{:08}.manifest", second.id.get()));
    let original = fs::read_to_string(&manifest_path).unwrap();
    let mut lines = original.lines();
    let header = lines.next().unwrap().to_string();
    let (_, entry_text) = lines.next().unwrap().split_once('\t').unwrap();
    let entry_text = entry_text.to_string();

    let abs_target = format!("{}/abs-escape.txt", env.outside.display());
    let long = format!("{}x", "a/".repeat(2100));
    let wide = "c".repeat(256);
    let mut hostile: Vec<String> = HOSTILE_PATHS.iter().map(|s| s.to_string()).collect();
    hostile.extend([abs_target.clone(), long, wide]);

    let project_before = tree_state(&env.root);
    let outside_before = tree_state(&env.outside);
    let len_before = journal_len(&ports);
    for bad in &hostile {
        fs::write(&manifest_path, format!("{header}\n{bad}\t{entry_text}\n")).unwrap();
        let r = ports
            .snapshots
            .open_manifest(second.id)
            .and_then(|mut m| m.next_entry());
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "{bad:?} must be rejected, got {r:?}"
        );
        let r = plan_restore(&ports, &rp("a.txt"), second.id);
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "plan_restore with {bad:?}: {:?}",
            r.as_ref().err()
        );
        let r = apply_restore(&ports, &rp("a.txt"), second.id, true);
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "apply_restore with {bad:?}: {:?}",
            r.as_ref().err()
        );
        assert!(
            !verify(&ports).unwrap().ok(),
            "verify must flag the tampered manifest ({bad:?})"
        );
    }
    assert_eq!(journal_len(&ports), len_before, "nothing was recorded");
    assert_eq!(tree_state(&env.root), project_before);
    assert_eq!(tree_state(&env.outside), outside_before);
    assert!(!env.base.join("escape.txt").exists());
    assert!(!Path::new(&abs_target).exists());
    // The untouched manifest of the baseline still works.
    assert!(
        ports
            .snapshots
            .open_manifest(base.id)
            .unwrap()
            .next_entry()
            .unwrap()
            .is_some()
    );
}

#[test]
fn hostile_paths_in_a_change_set_are_rejected_and_nothing_outside_is_touched() {
    let env = Env::new("changes-traversal");
    env.write("a.txt", "a v1\n");
    fs::write(env.outside.join("canary.txt"), "canary\n").unwrap();
    let project = env.project();
    let ports = project.ports();
    baseline(&ports);
    env.write("a.txt", "a v2 changed\n");
    let second = checkpoint(&ports);

    let changes_path = env
        .store_dir
        .join("checkpoints")
        .join(format!("{:08}.changes", second.id.get()));
    let original = fs::read_to_string(&changes_path).unwrap();
    let mut lines = original.lines();
    let header = lines.next().unwrap().to_string();
    let fields: Vec<String> = lines
        .next()
        .unwrap()
        .split('\t')
        .map(str::to_string)
        .collect();
    assert_eq!(fields.len(), 4, "{fields:?}");

    let abs_target = format!("{}/abs-escape.txt", env.outside.display());
    let mut hostile: Vec<String> = HOSTILE_PATHS.iter().map(|s| s.to_string()).collect();
    hostile.push(abs_target.clone());

    let project_before = tree_state(&env.root);
    let outside_before = tree_state(&env.outside);
    let len_before = journal_len(&ports);
    for bad in &hostile {
        let line = format!("{}\t{bad}\t{}\t{}", fields[0], fields[2], fields[3]);
        fs::write(&changes_path, format!("{header}\n{line}\n")).unwrap();
        let r = ports
            .snapshots
            .open_changes(second.id)
            .and_then(|mut c| c.next_change());
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "{bad:?} must be rejected, got {:?}",
            r.as_ref().err()
        );
        let r = plan_undo(&ports, &Selector::Checkpoint(second.id));
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "plan_undo with {bad:?}: {:?}",
            r.as_ref().err()
        );
        let r = apply_undo(&ports, &Selector::Checkpoint(second.id), true);
        assert!(
            matches!(r, Err(Error::Format(_) | Error::Unsafe(_))),
            "apply_undo with {bad:?}: {:?}",
            r.as_ref().err()
        );
        assert!(!verify(&ports).unwrap().ok());
    }
    assert_eq!(
        journal_len(&ports),
        len_before,
        "no pre-undo checkpoint was taken"
    );
    assert_eq!(tree_state(&env.root), project_before);
    assert_eq!(tree_state(&env.outside), outside_before);
    assert!(!env.base.join("escape.txt").exists());
    assert!(!Path::new(&abs_target).exists());
}

// ========================================================== hostile names

#[test]
fn hostile_file_names_snapshot_and_undo_correctly() {
    let env = Env::new("hostile-names");
    let long = "a".repeat(255);
    let names: Vec<Vec<u8>> = vec![
        b"line\nbreak.txt".to_vec(),
        b"esc\x1b[31mred.txt".to_vec(),
        "bidi\u{202e}txt.exe".as_bytes().to_vec(),
        long.as_bytes().to_vec(),
        b"bad\xff\xfename.bin".to_vec(),
        b"tab\tname".to_vec(),
        b"100%done and spaces".to_vec(),
        b"dir\nname/inner\x1bfile.txt".to_vec(),
        b"-leading-dash".to_vec(),
    ];
    for (i, n) in names.iter().enumerate() {
        env.write(n, format!("original content {i}\n"));
    }
    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);
    let original_state = tree_state(&env.root);

    // Every hostile name is in the manifest byte for byte.
    let recorded: Vec<Vec<u8>> = manifest(&ports, base.id)
        .into_iter()
        .map(|(p, _)| p.as_bytes().to_vec())
        .collect();
    for n in &names {
        assert!(
            recorded.contains(n),
            "{:?} not recorded",
            String::from_utf8_lossy(n)
        );
    }
    // Names cannot break the line-oriented store: one line per entry, no raw ESC or newline injection.
    let manifest_file = env
        .store_dir
        .join("checkpoints")
        .join(format!("{:08}.manifest", base.id.get()));
    let text = fs::read(&manifest_file).unwrap();
    assert_eq!(
        text.iter().filter(|&&b| b == b'\n').count() as u64,
        base.entries + 1,
        "one line per entry plus the header"
    );
    assert!(!text.contains(&0x1b));

    // The agent edits everything, deletes two files, and replaces one with a directory.
    for (i, n) in names.iter().enumerate() {
        env.write(n, format!("agent rewrote this, longer, {i}\n"));
    }
    fs::remove_file(env.abs(&long)).unwrap();
    fs::remove_file(env.abs(b"bad\xff\xfename.bin")).unwrap();
    let rec = checkpoint(&ports);
    for f in ["checkpoints", "."] {
        for (path, md) in walk(&env.store_dir.join(f)) {
            if md.is_file() && !path.ends_with("key") {
                assert!(
                    !fs::read(&path).unwrap().contains(&0x1b),
                    "ESC byte in {}",
                    path.display()
                );
            }
        }
    }
    assert!(rec.counts.total() >= 9);

    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(
        report.error.is_none() && report.refused.is_none(),
        "{:?} {:?}",
        report.error,
        report.refused
    );
    assert_eq!(
        tree_state(&env.root),
        original_state,
        "everything is back, names intact"
    );
    assert!(temp_leftovers(&env.root).is_empty());
    assert!(verify(&ports).unwrap().ok());
}

// ============================================================ special files

fn make_fifo(path: &Path) -> bool {
    matches!(Command::new("mkfifo").arg(path).status(), Ok(s) if s.success())
}

#[test]
fn fifo_never_blocks_the_snapshot_and_is_never_replaced_by_undo() {
    let probe = std::env::temp_dir().join(format!("au-sec-fifoprobe-{}", std::process::id()));
    let available = make_fifo(&probe);
    let _ = fs::remove_file(&probe);
    if !available {
        eprintln!("skipping: mkfifo is not available");
        return;
    }
    // A snapshot that opened the FIFO would hang forever: run with a deadline.
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let env = Env::new("fifo");
        env.write("data.txt", "regular\n");
        env.write("p", "a regular file that will become a FIFO\n");
        assert!(make_fifo(&env.abs("q")));
        let project = env.project();
        let ports = project.ports();
        let base = baseline(&ports);
        let q = entry_of(&ports, base.id, "q").unwrap();
        assert_eq!(q.kind(), Kind::Special);

        // Agent: replaces p with a FIFO and deletes the recorded FIFO q.
        fs::remove_file(env.abs("p")).unwrap();
        assert!(make_fifo(&env.abs("p")));
        fs::remove_file(env.abs("q")).unwrap();
        env.write("data.txt", "regular, edited\n");
        let rec = checkpoint(&ports);
        assert_eq!(entry_of(&ports, rec.id, "p").unwrap().kind(), Kind::Special);

        let plan = plan_undo(&ports, &Selector::Last).unwrap();
        assert!(
            matches!(item(&plan, "p").1.status, Status::Blocked(_)),
            "{:?}",
            item(&plan, "p").1
        );
        assert!(
            matches!(item(&plan, "q").1.status, Status::NotRestorable(_)),
            "{:?}",
            item(&plan, "q").1
        );
        let report = apply_undo(&ports, &Selector::Last, false).unwrap();
        assert!(report.error.is_none());
        assert!(
            fs::symlink_metadata(env.abs("p"))
                .unwrap()
                .file_type()
                .is_fifo(),
            "the FIFO is untouched"
        );
        assert!(!env.abs("q").exists(), "special files are never recreated");
        assert_eq!(env.read("data.txt"), b"regular\n");
        assert!(temp_leftovers(&env.root).is_empty());
        tx.send(()).unwrap();
    });
    match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(()) => worker.join().unwrap(),
        Err(_) => {
            if worker.is_finished() {
                worker.join().unwrap(); // propagate the panic
            }
            panic!("the snapshot hung on a FIFO");
        }
    }
}

// ============================================================== modes

#[test]
fn permission_bits_are_preserved_and_setuid_is_never_restored() {
    let env = Env::new("modes");
    let chmod = |rel: &str, mode: u32| {
        fs::set_permissions(env.abs(rel), fs::Permissions::from_mode(mode)).unwrap();
    };
    env.write("run.sh", "#!/bin/sh\necho hi\n");
    chmod("run.sh", 0o755);
    env.write("private.txt", "private v1\n");
    chmod("private.txt", 0o600);
    env.write("readonly.txt", "readonly v1\n");
    chmod("readonly.txt", 0o444);
    env.write("suid-bin", "binary v1\n");
    chmod("suid-bin", 0o4755);
    env.write("onlymode", "same content\n");
    chmod("onlymode", 0o6755);
    env.write("locked/inside.txt", "inside\n");
    chmod("locked", 0o750);

    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);
    let suid = entry_of(&ports, base.id, "suid-bin").unwrap();
    assert_ne!(
        suid.mode() & 0o7000,
        0,
        "the premise: the original had setuid recorded"
    );

    // The agent rewrites the files (and sets setuid on the file it changed),
    // flips the mode of `onlymode`, and removes the directory.
    for (rel, mode) in [
        ("run.sh", 0o644),
        ("private.txt", 0o644),
        ("readonly.txt", 0o644),
    ] {
        chmod(rel, mode);
        env.write(rel, "agent changed this file\n");
    }
    chmod("readonly.txt", 0o600);
    chmod("suid-bin", 0o644);
    env.write("suid-bin", "binary v2 changed by agent\n");
    chmod("suid-bin", 0o4755);
    chmod("onlymode", 0o644);
    fs::remove_dir_all(env.abs("locked")).unwrap_or_else(|_| {
        chmod("locked", 0o755);
        fs::remove_dir_all(env.abs("locked")).unwrap();
    });
    checkpoint(&ports);

    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(
        report.error.is_none() && report.refused.is_none(),
        "{:?} {:?}",
        report.error,
        report.refused
    );
    assert_eq!(env.mode("run.sh"), 0o755);
    assert_eq!(env.mode("private.txt"), 0o600);
    assert_eq!(env.mode("readonly.txt"), 0o444);
    assert_eq!(env.read("suid-bin"), b"binary v1\n");
    assert_eq!(
        env.mode("suid-bin") & 0o7000,
        0,
        "setuid/setgid/sticky are not restored (content write)"
    );
    assert_eq!(env.mode("suid-bin") & 0o777, 0o755);
    assert_eq!(env.read("onlymode"), b"same content\n");
    assert_eq!(
        env.mode("onlymode") & 0o7000,
        0,
        "setuid/setgid are not restored (chmod only)"
    );
    assert_eq!(env.mode("onlymode") & 0o777, 0o755);
    assert_eq!(env.mode("locked"), 0o750);
    assert_eq!(env.read("locked/inside.txt"), b"inside\n");
    assert!(temp_leftovers(&env.root).is_empty());
}

// ================================================ atomic restore / temp files

#[test]
fn successful_restores_leave_no_temp_files() {
    let env = Env::new("atomic-ok");
    for i in 0..5 {
        env.write(format!("dir/f{i}.txt"), format!("original {i}\n"));
    }
    let project = env.project();
    let ports = project.ports();
    baseline(&ports);
    for i in 0..5 {
        env.write(format!("dir/f{i}.txt"), format!("changed {i}!\n"));
    }
    fs::remove_file(env.abs("dir/f0.txt")).unwrap();
    symlink("f1.txt", env.abs("dir/link")).unwrap();
    checkpoint(&ports);
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(report.error.is_none());
    assert!(report.applied() >= 5);
    assert_eq!(env.read("dir/f3.txt"), b"original 3\n");
    assert!(
        temp_leftovers(&env.root).is_empty(),
        "{:?}",
        temp_leftovers(&env.root)
    );
    assert_eq!(fs::read_dir(env.store_dir.join("tmp")).unwrap().count(), 0);
}

#[test]
fn failed_restore_removes_its_temp_file_and_leaves_the_target_alone() {
    let env = Env::new("atomic-fail");
    env.write("f.txt", "original\n");
    env.write("other.txt", "other original\n");
    let rig = Rig::new(&env);
    let ports = rig.ports();
    baseline(&ports);
    env.write("f.txt", "changed by the agent\n");
    env.write("other.txt", "other changed\n");
    checkpoint(&ports);

    // Right before the write, the destination becomes a directory: the executor
    // has already written its temp file and must clean it up when it refuses.
    let f = env.abs("f.txt");
    rig.tree.on_apply("f.txt", move || {
        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();
        fs::write(f.join("agent-data.txt"), "precious").unwrap();
    });
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    let (idx, _) = item(&report.plan, "f.txt");
    assert!(
        matches!(report.outcomes[idx], Outcome::Failed(_)),
        "{:?}",
        report.outcomes
    );
    assert!(report.error.is_some());
    assert!(
        temp_leftovers(&env.root).is_empty(),
        "{:?}",
        temp_leftovers(&env.root)
    );
    assert!(env.abs("f.txt").is_dir());
    assert_eq!(env.read("f.txt/agent-data.txt"), b"precious");
    assert!(report.result.is_some());
}

#[test]
fn restore_of_a_corrupt_blob_fails_with_an_integrity_error_and_leaves_the_target() {
    let env = Env::new("corrupt-blob");
    let original = b"original content that will be corrupted in the store\n";
    env.write("f.txt", original);
    let project = env.project();
    let ports = project.ports();
    baseline(&ports);
    env.write("f.txt", "the agent's version, longer than before\n");
    checkpoint(&ports);

    let digest = sha256(original);
    let hex = to_hex(&digest);
    let blob = env.store_dir.join("blobs").join(&hex[..2]).join(&hex);
    assert!(blob.is_file());
    fs::write(&blob, b"tampered bytes").unwrap();

    // At the adapter level the failure is an Integrity error.
    let plan = plan_undo(&ports, &Selector::Last).unwrap();
    let (_, it) = item(&plan, "f.txt");
    assert_eq!(it.status, Status::Ready);
    let r = ports.tree.apply(it, &mut Vec::new());
    assert!(matches!(r, Err(Error::Integrity(_))), "{:?}", r.err());
    assert_eq!(
        env.read("f.txt"),
        b"the agent's version, longer than before\n"
    );
    assert!(temp_leftovers(&env.root).is_empty());

    // Through the use case the item fails, the target is untouched, the result is recorded.
    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    let (idx, _) = item(&report.plan, "f.txt");
    assert!(
        matches!(&report.outcomes[idx], Outcome::Failed(m) if m.contains("corrupt")),
        "{:?}",
        report.outcomes
    );
    assert_eq!(
        env.read("f.txt"),
        b"the agent's version, longer than before\n"
    );
    assert!(temp_leftovers(&env.root).is_empty());
    assert!(report.result.is_some());

    // verify notices the corruption.
    let v = verify(&ports).unwrap();
    assert!(!v.ok());
    assert!(
        v.problems.iter().any(|p| p.contains("corrupt")),
        "{:?}",
        v.problems
    );
}

#[test]
fn restore_of_a_missing_blob_fails_with_an_integrity_error() {
    let env = Env::new("missing-blob");
    let original = b"original content whose blob will be deleted\n";
    env.write("f.txt", original);
    let project = env.project();
    let ports = project.ports();
    baseline(&ports);
    env.write("f.txt", "changed\n");
    checkpoint(&ports);
    let hex = to_hex(&sha256(original));
    fs::remove_file(env.store_dir.join("blobs").join(&hex[..2]).join(&hex)).unwrap();

    let plan = plan_undo(&ports, &Selector::Last).unwrap();
    let (_, it) = item(&plan, "f.txt");
    let r = ports.tree.apply(it, &mut Vec::new());
    assert!(matches!(r, Err(Error::Integrity(_))), "{:?}", r.err());
    assert_eq!(env.read("f.txt"), b"changed\n");
    assert!(temp_leftovers(&env.root).is_empty());
    assert!(!verify(&ports).unwrap().ok());
}

// ============================================================ unreadable

#[test]
fn unreadable_files_are_recorded_as_unreadable_and_never_undone() {
    if is_root_user() {
        eprintln!("skipping: running as root, chmod 000 does not make files unreadable");
        return;
    }
    let env = Env::new("unreadable");
    let chmod = |rel: &str, mode: u32| {
        fs::set_permissions(env.abs(rel), fs::Permissions::from_mode(mode)).unwrap();
    };
    env.write("locked.txt", "was unreadable at the baseline\n");
    chmod("locked.txt", 0o000);
    env.write("b.txt", "readable original\n");
    env.write("a.txt", "a original\n");
    let project = env.project();
    let ports = project.ports();
    let base = baseline(&ports);
    assert_eq!(
        entry_of(&ports, base.id, "locked.txt").unwrap().kind(),
        Kind::Unreadable
    );
    assert_eq!(
        entry_of(&ports, base.id, "b.txt").unwrap().kind(),
        Kind::File
    );

    // The agent makes locked.txt readable and rewrites it, locks b.txt, edits a.txt.
    chmod("locked.txt", 0o644);
    env.write("locked.txt", "now readable, rewritten by the agent\n");
    env.write("a.txt", "a changed\n");
    chmod("b.txt", 0o000);
    let rec = checkpoint(&ports);
    assert_eq!(
        entry_of(&ports, rec.id, "b.txt").unwrap().kind(),
        Kind::Unreadable
    );

    let plan = plan_undo(&ports, &Selector::Last).unwrap();
    assert!(
        matches!(item(&plan, "locked.txt").1.status, Status::NotRestorable(_)),
        "{:?}",
        item(&plan, "locked.txt").1
    );
    assert!(
        matches!(item(&plan, "b.txt").1.status, Status::Blocked(_)),
        "{:?}",
        item(&plan, "b.txt").1
    );
    assert_eq!(item(&plan, "a.txt").1.status, Status::Ready);

    let report = apply_undo(&ports, &Selector::Last, false).unwrap();
    assert!(report.error.is_none());
    assert_eq!(env.read("a.txt"), b"a original\n");
    assert_eq!(
        env.read("locked.txt"),
        b"now readable, rewritten by the agent\n"
    );
    assert_eq!(
        env.mode("b.txt"),
        0o000,
        "the unreadable file is never touched"
    );
    chmod("b.txt", 0o644);
    assert_eq!(env.read("b.txt"), b"readable original\n");
}

// ============================================================ concurrency

#[test]
fn a_second_exclusive_lock_fails_with_locked_while_the_first_is_held() {
    let env = Env::new("lock-basic");
    let p1 = env.project();
    let p2 = Project::new(
        StoreDir::open_at(&env.store_dir, &env.root).unwrap(),
        Box::new(NullSink),
    );
    let (ports1, ports2) = (p1.ports(), p2.ports());

    let guard = ports1.locks.exclusive().unwrap();
    assert!(
        is_locked(ports2.locks.exclusive()),
        "second writer is refused"
    );
    assert!(
        is_locked(ports2.locks.shared()),
        "readers are refused while a writer holds the lock"
    );
    assert!(
        is_locked(ports1.locks.exclusive()),
        "a second handle of the same project is refused too"
    );
    drop(guard);

    let shared1 = ports1.locks.shared().unwrap();
    let shared2 = ports2.locks.shared().unwrap();
    assert!(
        is_locked(ports2.locks.exclusive()),
        "a writer is refused while readers hold the lock"
    );
    drop((shared1, shared2));
    let _again = ports2.locks.exclusive().unwrap();
}

#[test]
fn use_cases_fail_with_locked_and_change_nothing_while_the_lock_is_held() {
    let env = Env::new("lock-usecases");
    env.write("a.txt", "a v1\n");
    let p1 = env.project();
    let p2 = Project::new(
        StoreDir::open_at(&env.store_dir, &env.root).unwrap(),
        Box::new(NullSink),
    );
    let ports = p1.ports();
    let base = baseline(&ports);
    env.write("a.txt", "a v2 by the agent\n");
    let rec = checkpoint(&ports);

    let snapshot = |p: &Ports<'_>| {
        let mut names: Vec<String> = fs::read_dir(env.store_dir.join("checkpoints"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        (
            journal_len(p),
            names,
            p.blobs.list().unwrap().blobs.len(),
            tree_state(&env.root),
            fs::read(env.store_dir.join("log")).unwrap(),
        )
    };
    let before = snapshot(&ports);

    let ports2 = p2.ports();
    let guard = ports2.locks.exclusive().unwrap();
    assert!(is_locked(manual_checkpoint(&ports, None, false)));
    assert!(is_locked(record_baseline(&ports)));
    assert!(is_locked(apply_undo(&ports, &Selector::Last, true)));
    assert!(is_locked(apply_restore(
        &ports,
        &rp("a.txt"),
        base.id,
        true
    )));
    assert!(is_locked(gc(&ports, RetentionPolicy::KeepLast(1), true)));
    assert!(is_locked(verify(&ports)));
    assert!(is_locked(plan_undo(&ports, &Selector::Last)));
    assert!(is_locked(plan_restore(&ports, &rp("a.txt"), base.id)));
    assert!(is_locked(load_log(&ports)));
    assert_eq!(snapshot(&ports), before, "nothing changed while locked");
    assert_eq!(
        err_of(manual_checkpoint(&ports, None, false)).exit_code(),
        4
    );
    drop(guard);

    // Once the lock is released everything works again.
    let next = checkpoint(&ports);
    assert_eq!(next.id.get(), rec.id.get() + 1);
    assert!(verify(&ports).unwrap().ok());
}
