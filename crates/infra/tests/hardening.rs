//! Real-filesystem tests for the findings of the security review: scan-side
//! symlink races, chmod that must not follow links, persistence of the
//! sensitive-content registry, and hostile ignore files.
//!
//! Races are produced deterministically through `FsTree::set_scan_hook`, which
//! runs a closure at the points where a concurrent process could modify the tree.

use agent_undo_app::error::{Error, Result};
use agent_undo_app::ports::{BlobStore, ScanOptions, ScanStats, ScanVisitor, WorkingTree};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::hash::{sha256, to_hex};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Observation, Op, Outcome, build_item};
use agent_undo_infra::fs_blobs::FsBlobs;
use agent_undo_infra::fs_tree::{FsTree, ScanStage};
use agent_undo_infra::layout::{DEFAULT_MAX_FILE_SIZE, StoreDir};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct Env {
    base: PathBuf,
    root: PathBuf,
    outside: PathBuf,
    store: StoreDir,
    blobs: FsBlobs,
}

impl Env {
    fn new(name: &str) -> Env {
        let base = std::env::temp_dir().join(format!("au-hard-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("proj")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        let base = fs::canonicalize(&base).unwrap();
        let root = base.join("proj");
        let store =
            StoreDir::create(&base.join("state"), &root, false, DEFAULT_MAX_FILE_SIZE).unwrap();
        let blobs = FsBlobs::new(store.blobs_dir(), store.tmp_dir());
        Env {
            outside: base.join("outside"),
            root,
            base,
            store,
            blobs,
        }
    }

    fn tree(&self) -> FsTree {
        FsTree::new(
            self.root.clone(),
            &self.store.dir,
            self.store.meta.max_file_size,
            *self.store.key(),
            self.blobs.clone(),
        )
    }

    fn write(&self, rel: &str, content: &[u8]) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn all_blob_bytes(&self) -> Vec<Vec<u8>> {
        self.blobs
            .list()
            .unwrap()
            .blobs
            .iter()
            .map(|(d, _)| self.blobs.read(d, u64::MAX).unwrap())
            .collect()
    }

    fn blob_contains(&self, needle: &[u8]) -> bool {
        self.all_blob_bytes()
            .iter()
            .any(|b| b.windows(needle.len()).any(|w| w == needle))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // directories made read-only by a test must be removable
        let _ = fs::set_permissions(&self.outside, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[derive(Default)]
struct Seen {
    entries: Vec<(RelPath, Entry)>,
    carried: Vec<String>,
}

impl ScanVisitor for Seen {
    fn prev(&mut self, _: &RelPath) -> Result<Option<Entry>> {
        Ok(None)
    }
    fn visit(&mut self, p: &RelPath, e: &Entry) -> Result<()> {
        self.entries.push((p.clone(), e.clone()));
        Ok(())
    }
    fn carry_forward(&mut self, d: Option<&RelPath>) -> Result<()> {
        self.carried
            .push(d.map_or_else(|| "<root>".to_string(), RelPath::display));
        Ok(())
    }
}

impl Seen {
    fn has(&self, p: &str) -> bool {
        self.entries.iter().any(|(x, _)| x.display() == p)
    }
    fn kind(&self, p: &str) -> Kind {
        self.entries
            .iter()
            .find(|(x, _)| x.display() == p)
            .unwrap_or_else(|| panic!("{p} not scanned"))
            .1
            .kind()
    }
}

fn scan(tree: &FsTree, capture: bool) -> (Seen, ScanStats) {
    let mut v = Seen::default();
    let opts = if capture {
        ScanOptions::capturing(None)
    } else {
        ScanOptions::observing(None)
    };
    let stats = tree.scan(&opts, &mut v).unwrap();
    (v, stats)
}

fn rp(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

fn is_root() -> bool {
    fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

const OUTSIDE_SECRET: &[u8] = b"OUTSIDE-FILE-CONTENT-THAT-MUST-NOT-ENTER-THE-STORE-4242";

// ------------------------------------------------- SU-003: parent swapped during the scan

#[test]
fn a_directory_swapped_for_a_symlink_after_it_was_listed_is_not_followed() {
    let env = Env::new("swap-listed");
    env.write("d/a.txt", b"inside the project");
    fs::write(env.outside.join("a.txt"), OUTSIDE_SECRET).unwrap();
    let tree = env.tree();
    let (root, outside) = (env.root.clone(), env.outside.clone());
    tree.set_scan_hook(move |stage, path| {
        if stage == ScanStage::DirListed && path == root.join("d") {
            // a concurrent process replaces the directory right after it was listed
            fs::rename(root.join("d"), root.join("d.moved")).unwrap();
            symlink(&outside, root.join("d")).unwrap();
        }
    });
    let (seen, stats) = scan(&tree, true);
    assert!(
        seen.has("d"),
        "the directory entry itself was seen before the swap"
    );
    assert!(
        !seen.has("d/a.txt"),
        "nothing below the swapped directory is recorded"
    );
    assert!(
        !env.blob_contains(OUTSIDE_SECRET),
        "content of a file outside the project reached the blob store"
    );
    assert!(
        stats
            .warnings
            .iter()
            .any(|w| w.contains("changed while it was being listed")),
        "{:?}",
        stats.warnings
    );
    assert_eq!(
        seen.carried,
        vec!["d".to_string()],
        "previous entries below it are kept"
    );
}

#[test]
fn a_directory_swapped_for_a_symlink_before_a_file_is_opened_records_nothing_from_outside() {
    let env = Env::new("swap-open");
    env.write("d/a.txt", b"inside the project");
    fs::write(env.outside.join("a.txt"), OUTSIDE_SECRET).unwrap();
    let tree = env.tree();
    let (root, outside) = (env.root.clone(), env.outside.clone());
    tree.set_scan_hook(move |stage, path| {
        if stage == ScanStage::BeforeFileRead && path == root.join("d/a.txt") {
            fs::rename(root.join("d"), root.join("d.moved")).unwrap();
            symlink(&outside, root.join("d")).unwrap();
        }
    });
    let (seen, stats) = scan(&tree, true);
    assert!(!env.blob_contains(OUTSIDE_SECRET));
    assert!(
        !env.blob_contains(b"inside the project"),
        "nothing is stored for a file whose directory changed"
    );
    // the file is recorded as unreadable, never with outside content
    assert_eq!(seen.kind("d/a.txt"), Kind::Unreadable);
    assert!(stats.warnings_total >= 1);
}

#[test]
fn a_directory_replaced_before_the_file_read_is_detected_by_the_identity_check() {
    // The swap happens after the parent check and before the open: the hook runs
    // exactly there. The file identity check (dev/ino of lstat vs open) catches it.
    let env = Env::new("swap-identity");
    env.write("d/a.txt", b"original bytes");
    let tree = env.tree();
    let (root, outside) = (env.root.clone(), env.outside.clone());
    fs::write(outside.join("a.txt"), b"different file with other bytes").unwrap();
    tree.set_scan_hook(move |stage, path| {
        if stage == ScanStage::BeforeFileRead && path == root.join("d/a.txt") {
            fs::remove_file(root.join("d/a.txt")).unwrap();
            fs::remove_dir(root.join("d")).unwrap();
            symlink(&outside, root.join("d")).unwrap();
        }
    });
    let (seen, _) = scan(&tree, true);
    assert!(!env.blob_contains(b"different file with other bytes"));
    assert!(!seen.has("d/a.txt") || seen.kind("d/a.txt") == Kind::Unreadable);
}

#[test]
fn an_unswapped_scan_is_unaffected_by_the_hooks() {
    let env = Env::new("noswap");
    env.write("d/a.txt", b"fine");
    let tree = env.tree();
    let calls = Rc::new(std::cell::Cell::new(0));
    let c = calls.clone();
    tree.set_scan_hook(move |_, _| c.set(c.get() + 1));
    let (seen, stats) = scan(&tree, true);
    assert_eq!(seen.kind("d/a.txt"), Kind::File);
    assert!(stats.warnings.is_empty());
    assert!(
        calls.get() >= 3,
        "root listing, d listing and the file read"
    );
    assert!(env.blob_contains(b"fine"));
}

// ------------------------------------------------------------ SU-004: chmod never follows

fn chmod_item(
    env: &Env,
    rel: &str,
    content: &[u8],
    from_mode: u32,
    to_mode: u32,
) -> agent_undo_domain::plan::PlanItem {
    let d = sha256(content);
    let size = content.len() as u64;
    let current = Entry::hashed(Kind::File, &d, from_mode, size, 1, 1).unwrap();
    let target = Entry::hashed(Kind::File, &d, to_mode, size, 1, 1).unwrap();
    let _ = env;
    let item = build_item(
        rp(rel),
        Some(target),
        None,
        Observation::State(Some(current)),
    );
    assert_eq!(item.op, Op::Chmod, "same content, different mode");
    item
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

#[test]
fn chmod_of_a_file_replaced_by_a_symlink_does_not_touch_the_target() {
    let env = Env::new("chmod-link");
    let victim = env.outside.join("victim.txt");
    fs::write(&victim, b"not yours").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    // the planned file is swapped for a symlink to the victim before apply
    symlink(&victim, env.root.join("f.txt")).unwrap();
    let item = chmod_item(&env, "f.txt", b"content", 0o600, 0o755);
    let tree = env.tree();
    let mut dm = Vec::new();
    let r = tree.apply(&item, &mut dm);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(
        mode_of(&victim),
        0o600,
        "the mode of the symlink target was changed"
    );
    assert!(
        fs::symlink_metadata(env.root.join("f.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn chmod_of_a_directory_replaced_by_a_symlink_does_not_touch_the_target() {
    let env = Env::new("chmod-dirlink");
    let dir = env.outside.join("victimdir");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&dir, env.root.join("d")).unwrap();
    let tree = env.tree();
    let r = tree.set_dir_mode(&rp("d"), 0o755);
    assert!(matches!(r, Err(Error::Unsafe(_))), "{r:?}");
    assert_eq!(mode_of(&dir), 0o700);
}

#[test]
fn chmod_still_works_on_regular_files_and_directories() {
    let env = Env::new("chmod-ok");
    env.write("f.sh", b"#!/bin/sh\n");
    fs::set_permissions(env.root.join("f.sh"), fs::Permissions::from_mode(0o644)).unwrap();
    let item = chmod_item(&env, "f.sh", b"#!/bin/sh\n", 0o644, 0o755);
    let tree = env.tree();
    let mut dm = Vec::new();
    assert_eq!(tree.apply(&item, &mut dm).unwrap(), Outcome::Applied);
    assert_eq!(mode_of(&env.root.join("f.sh")), 0o755);
    fs::create_dir(env.root.join("dd")).unwrap();
    tree.set_dir_mode(&rp("dd"), 0o750).unwrap();
    assert_eq!(mode_of(&env.root.join("dd")), 0o750);
}

#[test]
fn chmod_never_applies_setuid_bits() {
    let env = Env::new("chmod-suid");
    env.write("f", b"x");
    let item = chmod_item(&env, "f", b"x", 0o644, 0o4755);
    let tree = env.tree();
    let mut dm = Vec::new();
    tree.apply(&item, &mut dm).unwrap();
    assert_eq!(mode_of(&env.root.join("f")) & 0o7000, 0);
}

#[test]
fn chmod_of_an_unreadable_file_falls_back_to_a_safe_rewrite_from_the_blob() {
    if is_root() {
        return; // root can open anything; the fallback is never needed
    }
    let env = Env::new("chmod-000");
    let content = b"locked down by the agent";
    env.write("f", content);
    env.blobs.put(content).unwrap();
    fs::set_permissions(env.root.join("f"), fs::Permissions::from_mode(0o000)).unwrap();
    let item = chmod_item(&env, "f", content, 0o000, 0o644);
    let tree = env.tree();
    let mut dm = Vec::new();
    assert_eq!(tree.apply(&item, &mut dm).unwrap(), Outcome::Applied);
    assert_eq!(mode_of(&env.root.join("f")), 0o644);
    assert_eq!(fs::read(env.root.join("f")).unwrap(), content);
    let leftovers: Vec<_> = fs::read_dir(&env.root).unwrap().collect();
    assert_eq!(leftovers.len(), 1, "no temp files left behind");
}

// -------------------------------------------- SU-001 persistence of sensitive content ids

const PLAIN_SECRET: &[u8] = b"hunter2\n";

#[test]
fn sensitive_ids_survive_a_new_process_and_hold_only_keyed_ids() {
    let env = Env::new("ids-persist");
    env.write(".env", PLAIN_SECRET);
    let (first, _) = scan(&env.tree(), true);
    assert_eq!(first.kind(".env"), Kind::Sensitive);
    let ids_path = env.store.dir.join("sensitive-ids");
    let text = fs::read_to_string(&ids_path).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert_eq!(mode_of(&ids_path), 0o600);
    assert!(
        !text.contains(&to_hex(&sha256(PLAIN_SECRET))),
        "plain hash of a secret in the store"
    );
    assert!(!text.contains("hunter2"));
    // the original is gone; only a copy remains, scanned by a brand new tree
    fs::remove_file(env.root.join(".env")).unwrap();
    env.write("copy.txt", PLAIN_SECRET);
    let (second, _) = scan(&env.tree(), true);
    assert_eq!(second.kind("copy.txt"), Kind::Sensitive);
    assert!(!env.blob_contains(b"hunter2"));
    assert_eq!(
        fs::read_to_string(&ids_path).unwrap(),
        text,
        "a known id is not appended twice"
    );
}

#[test]
fn read_only_scans_never_write_the_registry() {
    let env = Env::new("ids-readonly");
    env.write(".env", PLAIN_SECRET);
    let (seen, _) = scan(&env.tree(), false);
    assert_eq!(seen.kind(".env"), Kind::Sensitive);
    assert!(
        !env.store.dir.join("sensitive-ids").exists(),
        "a status/plan scan (shared lock) must not modify the store"
    );
}

#[test]
fn a_symlinked_registry_file_is_refused_and_its_target_untouched() {
    let env = Env::new("ids-symlink");
    let victim = env.outside.join("victim.txt");
    fs::write(&victim, b"keep me").unwrap();
    symlink(&victim, env.store.dir.join("sensitive-ids")).unwrap();
    env.write(".env", PLAIN_SECRET);
    let mut v = Seen::default();
    let r = env.tree().scan(&ScanOptions::capturing(None), &mut v);
    assert!(r.is_err(), "registry through a symlink must fail closed");
    assert_eq!(fs::read(&victim).unwrap(), b"keep me");
}

#[test]
fn a_corrupt_registry_fails_the_scan_instead_of_forgetting_secrets() {
    let env = Env::new("ids-corrupt");
    fs::write(env.store.dir.join("sensitive-ids"), "not a hex line\n").unwrap();
    env.write("a.txt", b"x");
    let mut v = Seen::default();
    let r = env.tree().scan(&ScanOptions::capturing(None), &mut v);
    assert!(matches!(r, Err(Error::Format(_))), "{r:?}");
}

// ------------------------------------------------------- SU-002: hostile ignore files, caps

#[test]
fn an_ignore_file_over_the_size_cap_degrades_to_the_defaults() {
    let env = Env::new("ignore-big");
    env.write(".agent-undoignore", &vec![b'#'; 2 * 1024 * 1024]);
    env.write("a.txt", b"a");
    env.write("node_modules/x.js", b"ignored by default");
    let (seen, stats) = scan(&env.tree(), true);
    assert!(seen.has("a.txt") && !seen.has("node_modules/x.js"));
    assert!(
        stats
            .warnings
            .iter()
            .any(|w| w.contains(".agent-undoignore"))
    );
}

#[test]
fn an_ignore_file_that_is_a_symlink_or_directory_is_not_followed() {
    let env = Env::new("ignore-link");
    fs::write(env.outside.join("rules"), "*\n").unwrap();
    symlink(
        env.outside.join("rules"),
        env.root.join(".agent-undoignore"),
    )
    .unwrap();
    env.write("a.txt", b"a");
    let (seen, _) = scan(&env.tree(), true);
    assert!(
        seen.has("a.txt"),
        "a symlinked ignore file must not hide the project"
    );
}

#[test]
fn a_huge_directory_of_ignored_files_does_not_trip_the_cap_or_the_memory() {
    let env = Env::new("ignored-flood");
    let tree = env.tree();
    tree.set_limits(50, 256);
    fs::create_dir_all(env.root.join("target")).unwrap();
    fs::create_dir_all(env.root.join("src")).unwrap();
    for i in 0..300 {
        fs::write(env.root.join(format!("src/f{i}.o")), b"x").unwrap();
    }
    env.write(".agent-undoignore", b"*.o\n");
    env.write("src/main.rs", b"fn main() {}");
    let (seen, stats) = scan(&tree, true);
    assert!(seen.has("src/main.rs"));
    assert!(stats.warnings.is_empty(), "{:?}", stats.warnings);
}
