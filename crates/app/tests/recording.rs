//! Application-layer tests for recording: baseline, manual checkpoints, `run`,
//! `status` and `watch`, driven through the in-memory fakes.

use agent_undo_app::error::Error;
use agent_undo_app::events::Event;
use agent_undo_app::fakes::{MemTree, ScriptedRunner, World};
use agent_undo_app::ports::{BlobStore, JournalRepository, Locker, RunOutcome, SnapshotRepository};
use agent_undo_app::usecases::checkpoint::{load_log, manual_checkpoint};
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::run::{RunCommand, RunFailure, RunReport, run_command};
use agent_undo_app::usecases::status::{scan_pending, status};
use agent_undo_app::usecases::watch::watch_tick;
use agent_undo_domain::change::{Change, ChangeKind, Counts, EntrySource};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::hash::sha256;
use agent_undo_domain::journal::{
    CheckpointId, CheckpointRecord, CkptKind, DomainEvent, ExitInfo, Label, SessionId,
};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::watch::{Debouncer, Tick};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

const S: i64 = 1_000_000_000;

// ------------------------------------------------------------------ helpers

fn setup() -> World {
    World::new()
}

fn cid(n: u64) -> CheckpointId {
    CheckpointId::new(n).unwrap()
}

fn sid(n: u64) -> SessionId {
    SessionId::new(n).unwrap()
}

fn counts(created: u64, modified: u64, deleted: u64, mode_changed: u64) -> Counts {
    Counts {
        created,
        modified,
        deleted,
        mode_changed,
    }
}

fn label(s: &str) -> Label {
    Label::new(s.as_bytes().to_vec()).unwrap()
}

/// Baseline over whatever is in the tree; clears the event log afterwards.
fn baseline(w: &World) -> CheckpointRecord {
    let b = w.with_ports(record_baseline).unwrap();
    w.events.clear();
    b.record
}

/// A baseline over a small project tree.
fn baseline_project(w: &World) -> CheckpointRecord {
    w.tree.write("README.md", b"# demo\n");
    w.tree.write("src/main.rs", b"fn main() {}\n");
    baseline(w)
}

fn cp(w: &World) -> CheckpointRecord {
    w.with_ports(|p| manual_checkpoint(p, None, false))
        .unwrap()
        .record
}

fn changes(w: &World, id: u64) -> Vec<Change> {
    let mut s = w.snapshots.open_changes(cid(id)).unwrap();
    let mut out = Vec::new();
    while let Some(c) = s.next_change().unwrap() {
        out.push(c);
    }
    out
}

fn manifest(w: &World, id: u64) -> Vec<(RelPath, Entry)> {
    let mut s = w.snapshots.open_manifest(cid(id)).unwrap();
    let mut out = Vec::new();
    while let Some(x) = s.next_entry().unwrap() {
        out.push(x);
    }
    out
}

fn entry(w: &World, id: u64, path: &str) -> Option<Entry> {
    let p = RelPath::new(path.as_bytes()).unwrap();
    manifest(w, id)
        .into_iter()
        .find(|(q, _)| *q == p)
        .map(|(_, e)| e)
}

fn manifest_paths(w: &World, id: u64) -> Vec<String> {
    manifest(w, id).iter().map(|(p, _)| p.display()).collect()
}

fn summary(w: &World, id: u64) -> Vec<(String, ChangeKind)> {
    let mut v: Vec<(String, ChangeKind)> = changes(w, id)
        .iter()
        .map(|c| (c.path().display(), c.kind()))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn withheld(w: &World) -> Vec<String> {
    w.events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::SensitiveContentWithheld { path } => Some(path.display()),
            _ => None,
        })
        .collect()
}

fn domain_events(w: &World) -> Vec<DomainEvent> {
    w.events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Domain(d) => Some(d),
            _ => None,
        })
        .collect()
}

fn recorded(id: u64, session: u64, kind: CkptKind, changes: u64) -> Event {
    Event::Domain(DomainEvent::CheckpointRecorded {
        id: cid(id),
        session: sid(session),
        kind,
        changes,
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn kinds(w: &World) -> Vec<CkptKind> {
    w.journal
        .load()
        .unwrap()
        .records()
        .iter()
        .map(|r| r.kind)
        .collect()
}

// Secret fixtures are assembled at runtime so no key-shaped literal is in source.
fn gh_token() -> String {
    format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8" + "I9j0K1l2M3n4O5p6Q7r8"
}

fn pem_marker() -> String {
    "bW9ja2JvZHk".to_string() + "tbm90LWEta2V5LWZpbGxlcg"
}

fn pem_file() -> String {
    format!(
        "-----BEGIN {} KEY-----\n{}\n-----END {} KEY-----\n",
        "RSA PRIVATE",
        pem_marker(),
        "RSA PRIVATE"
    )
}

fn env_marker() -> String {
    "hunter2".repeat(2) + "-zq9"
}

fn env_file() -> String {
    format!("DB_PASSWORD={}\n", env_marker())
}

fn token_file() -> String {
    format!("deploy_token = {}\n", gh_token())
}

// --------------------------------------------------------------- run helpers

type Slot = Rc<RefCell<Option<(Rc<MemTree>, agent_undo_app::fakes::MemLocker)>>>;

/// A world whose runner plays an agent: `action` edits the tree. The returned
/// cell records whether the exclusive lock was held while the command ran.
fn agent_world(
    action: impl Fn(&MemTree) + 'static,
    outcome: RunOutcome,
) -> (World, Rc<Cell<Option<bool>>>) {
    agent_world_cap(25 * 1024 * 1024, action, outcome)
}

fn agent_world_cap(
    cap: u64,
    action: impl Fn(&MemTree) + 'static,
    outcome: RunOutcome,
) -> (World, Rc<Cell<Option<bool>>>) {
    let slot: Slot = Rc::new(RefCell::new(None));
    let held = Rc::new(Cell::new(None));
    let (s2, h2) = (slot.clone(), held.clone());
    let runner = ScriptedRunner::new(
        move |_| {
            if let Some((tree, locks)) = s2.borrow().as_ref() {
                h2.set(Some(locks.is_exclusively_held()));
                action(tree);
            }
        },
        outcome,
    );
    let w = World::with_cap_and_runner(cap, runner);
    *slot.borrow_mut() = Some((w.tree.clone(), w.locks.clone()));
    (w, held)
}

fn exit0() -> RunOutcome {
    RunOutcome::Exited(ExitInfo::Code(0))
}

fn cmd(args: &[&str]) -> RunCommand {
    RunCommand {
        args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        label: None,
        new_session: false,
        env: EnvPolicy::Inherit,
        arg_policy: agent_undo_domain::journal::ArgPolicy::Redact,
    }
}

fn run(w: &World, c: RunCommand) -> Result<RunReport, RunFailure> {
    w.with_ports(|p| run_command(p, c))
}

fn quiet(secs: i64) -> Debouncer {
    Debouncer::new(secs * S).unwrap()
}

fn watch(w: &World, d: &mut Debouncer) -> agent_undo_app::usecases::watch::WatchStep {
    w.with_ports(|p| watch_tick(p, d, None)).unwrap()
}

// =================================================================== baseline

#[test]
fn baseline_is_recorded_once_with_session_one() {
    let w = setup();
    w.tree.write("README.md", b"# demo\n");
    w.tree.write("src/main.rs", b"fn main() {}\n");
    let b = w.with_ports(record_baseline).unwrap();
    let r = &b.record;
    assert_eq!(r.id, cid(1));
    assert_eq!(r.kind, CkptKind::Baseline);
    assert_eq!(r.session, sid(1));
    assert_eq!(r.label, Some(label("baseline")));
    assert_eq!(r.exit, None);
    assert_eq!(r.command, None);
    assert_eq!(r.reference, None);
    // README.md, src, src/main.rs are all new relative to nothing.
    assert_eq!(r.counts, counts(3, 0, 0, 0));
    assert_eq!(r.entries, 3);
    let j = w.journal.load().unwrap();
    assert_eq!(j.records().len(), 1);
    assert_eq!(j.records()[0], *r);
}

#[test]
fn baseline_emits_session_started_then_checkpoint_recorded() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    w.with_ports(record_baseline).unwrap();
    assert_eq!(
        w.events.events(),
        vec![
            Event::Domain(DomainEvent::SessionStarted { session: sid(1) }),
            recorded(1, 1, CkptKind::Baseline, 1),
        ]
    );
}

#[test]
fn second_baseline_is_already_initialized_and_changes_nothing() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    baseline(&w);
    w.tree.write("b.txt", b"b");
    let err = w.with_ports(record_baseline).err().unwrap();
    assert!(matches!(err, Error::AlreadyInitialized(_)), "{err:?}");
    assert_eq!(w.journal.load().unwrap().records().len(), 1);
    assert!(w.events.events().is_empty());
    assert!(!w.snapshots.contains(cid(2)));
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn baseline_of_empty_project_is_recorded_with_zero_changes() {
    let w = setup();
    let b = w.with_ports(record_baseline).unwrap();
    assert_eq!(b.record.counts, Counts::default());
    assert_eq!(b.record.entries, 0);
    assert_eq!(
        w.events.events().last(),
        Some(&recorded(1, 1, CkptKind::Baseline, 0))
    );
}

#[test]
fn baseline_stores_manifest_and_blobs_for_normal_files() {
    let w = setup();
    w.tree.write("a.txt", b"alpha");
    let b = w.with_ports(record_baseline).unwrap();
    let e = entry(&w, 1, "a.txt").unwrap();
    assert_eq!(e.kind(), Kind::File);
    assert_eq!(e.size(), 5);
    assert!(w.blobs.contains(&e.blob().unwrap()));
    assert_eq!(e.blob().unwrap(), sha256(b"alpha"));
    assert_eq!(b.stats.blobs_written, 1);
    assert_eq!(b.stats.bytes_stored, 5);
    assert_eq!(b.stats.files_hashed, 1);
    assert_eq!(b.stats.files_cached, 0);
}

#[test]
fn baseline_releases_the_lock_on_success_and_on_failure() {
    let w = setup();
    w.with_ports(record_baseline).unwrap();
    assert!(!w.locks.is_exclusively_held());
    w.with_ports(record_baseline).err().unwrap();
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn baseline_refuses_while_another_operation_holds_the_lock() {
    let w = setup();
    let _g = w.locks.exclusive().unwrap();
    let err = w.with_ports(record_baseline).err().unwrap();
    assert!(matches!(err, Error::Locked(_)), "{err:?}");
    assert!(w.journal.load().unwrap().is_empty());
    assert!(w.events.events().is_empty());
}

// ================================================================ checkpoints

#[test]
fn manual_checkpoint_on_uninitialized_world_is_not_initialized() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    let err = w
        .with_ports(|p| manual_checkpoint(p, None, false))
        .err()
        .unwrap();
    assert!(matches!(err, Error::NotInitialized(_)), "{err:?}");
    assert!(w.journal.load().unwrap().is_empty());
    assert!(w.events.events().is_empty());
    assert!(w.snapshots.list().unwrap().is_empty());
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn manual_checkpoint_refuses_while_locked() {
    let w = setup();
    baseline_project(&w);
    let _g = w.locks.exclusive().unwrap();
    let err = w
        .with_ports(|p| manual_checkpoint(p, None, false))
        .err()
        .unwrap();
    assert!(matches!(err, Error::Locked(_)), "{err:?}");
    assert_eq!(w.journal.load().unwrap().records().len(), 1);
    assert!(w.events.events().is_empty());
}

#[test]
fn created_modified_deleted_and_mode_changed_files_are_detected() {
    let w = setup();
    w.tree.write("keep.txt", b"same");
    w.tree.write("edit.txt", b"before");
    w.tree.write("gone.txt", b"bye");
    w.tree.write_mode("run.sh", b"#!/bin/sh\n", 0o644);
    baseline(&w);

    w.tree.write("new.txt", b"hello");
    w.tree.write("edit.txt", b"after!");
    w.tree.remove("gone.txt");
    w.tree.chmod("run.sh", 0o755);
    let r = cp(&w);

    assert_eq!(r.id, cid(2));
    assert_eq!(r.kind, CkptKind::Manual);
    assert_eq!(r.counts, counts(1, 1, 1, 1));
    assert_eq!(
        summary(&w, 2),
        vec![
            ("edit.txt".to_string(), ChangeKind::Modified),
            ("gone.txt".to_string(), ChangeKind::Deleted),
            ("new.txt".to_string(), ChangeKind::Created),
            ("run.sh".to_string(), ChangeKind::ModeChanged),
        ]
    );
    // before/after states are what the tree held.
    let all = changes(&w, 2);
    let edit = all
        .iter()
        .find(|c| c.path().display() == "edit.txt")
        .unwrap();
    assert_eq!(edit.before().unwrap().blob(), Some(sha256(b"before")));
    assert_eq!(edit.after().unwrap().blob(), Some(sha256(b"after!")));
    let run_sh = all.iter().find(|c| c.path().display() == "run.sh").unwrap();
    assert_eq!(run_sh.before().unwrap().mode() & 0o777, 0o644);
    assert_eq!(run_sh.after().unwrap().mode() & 0o777, 0o755);
    assert!(
        run_sh
            .before()
            .unwrap()
            .same_content(run_sh.after().unwrap())
    );
    let gone = all
        .iter()
        .find(|c| c.path().display() == "gone.txt")
        .unwrap();
    assert!(gone.after().is_none());
    assert!(gone.before().is_some());
}

#[test]
fn checkpoint_event_reports_the_total_change_count() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("a", b"1");
    w.tree.write("b", b"2");
    w.tree.write("README.md", b"changed");
    cp(&w);
    assert_eq!(w.events.events(), vec![recorded(2, 1, CkptKind::Manual, 3)]);
}

#[test]
fn moving_a_file_shows_as_deleted_plus_created_with_the_same_blob() {
    let w = setup();
    w.tree.write("old/name.txt", b"payload");
    baseline(&w);
    w.tree.rename("old/name.txt", "new_name.txt");
    let r = cp(&w);
    assert_eq!(r.counts, counts(1, 0, 1, 0));
    let all = changes(&w, 2);
    let del = all
        .iter()
        .find(|c| c.kind() == ChangeKind::Deleted)
        .unwrap();
    let cre = all
        .iter()
        .find(|c| c.kind() == ChangeKind::Created)
        .unwrap();
    assert_eq!(del.path().display(), "old/name.txt");
    assert_eq!(cre.path().display(), "new_name.txt");
    assert_eq!(
        del.before().unwrap().blob(),
        cre.after().unwrap().blob(),
        "same content on both sides of the move"
    );
    // Only one blob stored for the content (deduplicated).
    assert_eq!(w.blobs.count(), 1);
}

#[test]
fn symlink_created_and_retargeted_are_recorded_with_their_targets() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    baseline(&w);

    w.tree.symlink("link", b"a.txt");
    let r2 = cp(&w);
    assert_eq!(r2.counts, counts(1, 0, 0, 0));
    let e = entry(&w, 2, "link").unwrap();
    assert_eq!(e.kind(), Kind::Symlink);
    assert_eq!(e.target(), Some(&b"a.txt"[..]));
    assert_eq!(e.blob(), None);

    w.tree.symlink("link", b"elsewhere/b.txt");
    let r3 = cp(&w);
    assert_eq!(r3.counts, counts(0, 1, 0, 0));
    let ch = changes(&w, 3);
    assert_eq!(ch.len(), 1);
    assert_eq!(ch[0].kind(), ChangeKind::Modified);
    assert_eq!(ch[0].before().unwrap().target(), Some(&b"a.txt"[..]));
    assert_eq!(
        ch[0].after().unwrap().target(),
        Some(&b"elsewhere/b.txt"[..])
    );
}

#[test]
fn replacing_a_file_by_a_symlink_is_a_modification() {
    let w = setup();
    w.tree.write("x", b"data");
    baseline(&w);
    w.tree.remove("x");
    w.tree.symlink("x", b"y");
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 1, 0, 0));
    let ch = changes(&w, 2);
    assert_eq!(ch[0].before().unwrap().kind(), Kind::File);
    assert_eq!(ch[0].after().unwrap().kind(), Kind::Symlink);
}

#[test]
fn directories_created_and_deleted_are_changes_of_their_own() {
    let w = setup();
    w.tree.write("top.txt", b"t");
    baseline(&w);

    w.tree.mkdir("empty_dir", 0o755);
    w.tree.write("pkg/inner/f.txt", b"f");
    let r2 = cp(&w);
    // empty_dir, pkg, pkg/inner, pkg/inner/f.txt
    assert_eq!(r2.counts, counts(4, 0, 0, 0));
    assert_eq!(entry(&w, 2, "empty_dir").unwrap().kind(), Kind::Dir);
    assert_eq!(entry(&w, 2, "pkg/inner").unwrap().kind(), Kind::Dir);

    w.tree.remove("pkg");
    w.tree.remove("empty_dir");
    let r3 = cp(&w);
    assert_eq!(r3.counts, counts(0, 0, 4, 0));
    assert_eq!(manifest_paths(&w, 3), vec!["top.txt".to_string()]);
}

#[test]
fn directory_permission_change_is_a_mode_change() {
    let w = setup();
    w.tree.mkdir("d", 0o755);
    baseline(&w);
    w.tree.chmod("d", 0o700);
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 0, 0, 1));
    assert_eq!(entry(&w, 2, "d").unwrap().mode() & 0o777, 0o700);
}

#[test]
fn special_files_are_recorded_without_content() {
    let w = setup();
    w.tree.special("fifo");
    baseline(&w);
    let e = entry(&w, 1, "fifo").unwrap();
    assert_eq!(e.kind(), Kind::Special);
    assert_eq!(e.blob(), None);
    assert_eq!(w.blobs.count(), 0);
}

#[test]
fn unchanged_tree_still_records_a_checkpoint_with_zero_changes() {
    let w = setup();
    baseline_project(&w);
    let r2 = cp(&w);
    let r3 = cp(&w);
    assert_eq!(r2.counts, Counts::default());
    assert_eq!(r3.counts, Counts::default());
    assert_eq!((r2.id, r3.id), (cid(2), cid(3)));
    assert!(changes(&w, 2).is_empty());
    assert!(changes(&w, 3).is_empty());
    assert_eq!(w.journal.load().unwrap().records().len(), 3);
    assert_eq!(
        w.events.events(),
        vec![
            recorded(2, 1, CkptKind::Manual, 0),
            recorded(3, 1, CkptKind::Manual, 0)
        ]
    );
    // The manifest is carried over unchanged.
    assert_eq!(manifest_paths(&w, 1), manifest_paths(&w, 3));
}

#[test]
fn rewriting_a_file_with_identical_content_is_not_a_change() {
    let w = setup();
    w.tree.write("a.txt", b"same bytes");
    baseline(&w);
    w.tree.write("a.txt", b"same bytes"); // new mtime, same content
    let r = cp(&w);
    assert_eq!(r.counts, Counts::default());
    assert!(changes(&w, 2).is_empty());
}

#[test]
fn checkpoints_form_a_verifiable_chain_with_matching_stored_digests() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("x", b"1");
    cp(&w);
    cp(&w);
    let j = w.journal.load().unwrap();
    let recs = j.records();
    assert_eq!(recs.len(), 3);
    for pair in recs.windows(2) {
        assert_eq!(pair[1].prev, pair[0].hash);
        assert!(pair[1].time_ns > pair[0].time_ns);
    }
    for r in recs {
        assert_eq!(r.hash, r.compute_hash());
        let d = w.snapshots.stored_digests(r.id).unwrap();
        assert_eq!(d.manifest, r.manifest);
        assert_eq!(d.changes, r.changes);
        assert_eq!(CheckpointRecord::decode(&r.encode()).unwrap(), *r);
    }
}

#[test]
fn load_log_returns_the_recorded_journal() {
    let w = setup();
    assert!(w.with_ports(load_log).unwrap().is_empty());
    baseline_project(&w);
    cp(&w);
    let j = w.with_ports(load_log).unwrap();
    assert_eq!(j.records().len(), 2);
    assert_eq!(j.head().unwrap().kind, CkptKind::Manual);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn load_log_refuses_while_a_writer_holds_the_lock() {
    let w = setup();
    baseline_project(&w);
    let g = w.locks.exclusive().unwrap();
    let err = w.with_ports(load_log).err().unwrap();
    assert!(matches!(err, Error::Locked(_)), "{err:?}");
    drop(g);
    assert!(w.with_ports(load_log).is_ok());
}

#[test]
fn manual_checkpoint_releases_the_lock() {
    let w = setup();
    baseline_project(&w);
    cp(&w);
    assert!(!w.locks.is_exclusively_held());
}

// ==================================================================== sessions

#[test]
fn new_session_flag_opens_session_two_and_emits_session_started_only_then() {
    let w = setup();
    baseline_project(&w);

    let r2 = cp(&w);
    assert_eq!(r2.session, sid(1));
    assert!(
        domain_events(&w)
            .iter()
            .all(|e| !matches!(e, DomainEvent::SessionStarted { .. }))
    );
    w.events.clear();

    let r3 = w
        .with_ports(|p| manual_checkpoint(p, None, true))
        .unwrap()
        .record;
    assert_eq!(r3.session, sid(2));
    assert_eq!(
        w.events.events(),
        vec![
            Event::Domain(DomainEvent::SessionStarted { session: sid(2) }),
            recorded(3, 2, CkptKind::Manual, 0),
        ]
    );
    w.events.clear();

    // The session sticks for following checkpoints without a new flag.
    let r4 = cp(&w);
    assert_eq!(r4.session, sid(2));
    assert_eq!(w.events.events(), vec![recorded(4, 2, CkptKind::Manual, 0)]);
}

#[test]
fn labels_are_stored_verbatim_including_hostile_bytes() {
    let w = setup();
    baseline_project(&w);
    let hostile = "before refactor\n\x1b[31m\tünï %".as_bytes().to_vec();
    let r = w
        .with_ports(|p| manual_checkpoint(p, Some(Label::new(hostile.clone()).unwrap()), false))
        .unwrap()
        .record;
    assert_eq!(r.label.as_ref().unwrap().as_bytes(), &hostile[..]);
    let from_journal = w.journal.load().unwrap().records()[1].clone();
    assert_eq!(
        from_journal.label.as_ref().unwrap().as_bytes(),
        &hostile[..]
    );
    // Encodes to a single line and decodes back.
    let line = r.encode();
    assert!(!line.contains('\n'));
    assert_eq!(CheckpointRecord::decode(&line).unwrap(), r);
}

#[test]
fn checkpoint_without_label_has_none() {
    let w = setup();
    baseline_project(&w);
    assert_eq!(cp(&w).label, None);
}

// ===================================================================== names

#[test]
fn hostile_file_names_round_trip_through_a_checkpoint() {
    let w = setup();
    w.tree.write("seed", b"s");
    baseline(&w);
    let names = [
        "line\nbreak.txt",
        "esc\x1b[31mred.txt",
        "na\u{ef}ve \u{fc}n\u{ef}code.txt",
        "with space.txt",
        "tab\there.txt",
        "%percent%20.txt",
        "dir with space/\u{65e5}\u{672c}\u{8a9e}.txt",
        "-leading-dash",
    ];
    for (i, n) in names.iter().enumerate() {
        w.tree.write(n, format!("content {i}").as_bytes());
    }
    let r = cp(&w);
    let created_files = names.len() as u64 + 1; // + the implicit "dir with space"
    assert_eq!(r.counts, counts(created_files, 0, 0, 0));
    let paths: Vec<Vec<u8>> = manifest(&w, 2)
        .iter()
        .map(|(p, _)| p.as_bytes().to_vec())
        .collect();
    for n in names {
        assert!(paths.contains(&n.as_bytes().to_vec()), "missing {n:?}");
    }
    // Change records encode to single lines and decode back unchanged.
    for c in changes(&w, 2) {
        let line = c.encode();
        assert!(!line.contains('\n'), "{line:?}");
        assert_eq!(Change::decode(&line).unwrap(), c);
        // Display form is safe for a terminal.
        let shown = c.path().display();
        assert!(
            !shown.contains('\n') && !shown.contains('\x1b'),
            "{shown:?}"
        );
    }
    // Content of every hostile-named file was captured.
    for (i, n) in names.iter().enumerate() {
        let e = entry(&w, 2, n).unwrap();
        assert_eq!(e.blob(), Some(sha256(format!("content {i}").as_bytes())));
    }
}

#[test]
fn hostile_file_names_can_be_modified_and_deleted_across_checkpoints() {
    let w = setup();
    w.tree.write("a\nb", b"1");
    baseline(&w);
    w.tree.write("a\nb", b"22");
    let r2 = cp(&w);
    assert_eq!(r2.counts, counts(0, 1, 0, 0));
    w.tree.remove("a\nb");
    let r3 = cp(&w);
    assert_eq!(r3.counts, counts(0, 0, 1, 0));
}

// ==================================================================== ignores

#[test]
fn default_ignores_are_not_recorded() {
    let w = setup();
    w.tree.write("src/lib.rs", b"x");
    w.tree.write("node_modules/dep/index.js", b"x");
    w.tree.write("target/debug/app", b"x");
    w.tree.write(".git/config", b"x");
    w.tree.write(".git/HEAD", b"ref");
    w.tree.write("pkg/node_modules/y.js", b"x");
    w.tree.write(".DS_Store", b"x");
    w.tree.write("dist/bundle.js", b"x");
    w.tree.write("__pycache__/m.pyc", b"x");
    baseline(&w);
    let paths = manifest_paths(&w, 1);
    assert_eq!(
        paths,
        vec![
            "pkg".to_string(),
            "src".to_string(),
            "src/lib.rs".to_string()
        ]
    );
    assert_eq!(w.blobs.count(), 1);
    // Later edits inside ignored directories are invisible.
    w.tree.write("node_modules/dep/index.js", b"changed");
    w.tree.write("target/new", b"y");
    let r = cp(&w);
    assert_eq!(r.counts, Counts::default());
}

#[test]
fn ignore_patterns_from_agent_undoignore_apply_including_negation() {
    let w = setup();
    w.tree.write(
        ".agent-undoignore",
        b"# comment\n*.log\n!keep.log\nbuild/\n/secret_dir\n",
    );
    w.tree.write("app.log", b"l");
    w.tree.write("keep.log", b"k");
    w.tree.write("sub/deep.log", b"l");
    w.tree.write("build/out.o", b"o");
    w.tree.write("sub/build/out.o", b"o");
    w.tree.write("secret_dir/a", b"a");
    w.tree.write("sub/secret_dir/a", b"a");
    w.tree.write("main.rs", b"m");
    baseline(&w);
    let paths = manifest_paths(&w, 1);
    for want in [
        ".agent-undoignore",
        "keep.log",
        "main.rs",
        "sub",
        "sub/secret_dir",
        "sub/secret_dir/a",
    ] {
        assert!(
            paths.contains(&want.to_string()),
            "missing {want}: {paths:?}"
        );
    }
    for not in [
        "app.log",
        "sub/deep.log",
        "build",
        "build/out.o",
        "sub/build",
        "secret_dir",
        "secret_dir/a",
    ] {
        assert!(
            !paths.contains(&not.to_string()),
            "unexpected {not}: {paths:?}"
        );
    }
}

#[test]
fn files_created_under_ignored_patterns_after_baseline_are_not_changes() {
    let w = setup();
    w.tree.write(".agent-undoignore", b"*.tmp\n");
    baseline(&w);
    w.tree.write("scratch.tmp", b"t");
    w.tree.write("real.txt", b"r");
    let r = cp(&w);
    assert_eq!(r.counts, counts(1, 0, 0, 0));
    assert_eq!(
        summary(&w, 2),
        vec![("real.txt".to_string(), ChangeKind::Created)]
    );
}

#[test]
fn a_user_pattern_can_reinclude_a_default_ignored_directory() {
    let w = setup();
    w.tree.write(".agent-undoignore", b"!node_modules/\n");
    w.tree.write("node_modules/dep/index.js", b"x");
    baseline(&w);
    let paths = manifest_paths(&w, 1);
    assert!(
        paths.contains(&"node_modules/dep/index.js".to_string()),
        "{paths:?}"
    );
}

#[test]
fn sensitive_files_inside_ignored_directories_are_neither_recorded_nor_announced() {
    let w = setup();
    w.tree.write("node_modules/pkg/.env", env_file().as_bytes());
    w.tree.write("ok.txt", b"ok");
    w.with_ports(record_baseline).unwrap();
    assert!(withheld(&w).is_empty());
    assert!(!manifest_paths(&w, 1).iter().any(|p| p.contains(".env")));
}

// ================================================================== sensitive

#[test]
fn sensitive_names_are_recorded_as_sensitive_and_their_bytes_never_reach_the_blob_store() {
    let w = setup();
    w.tree
        .write("src/main.rs", b"fn main() { println!(\"hi\"); }\n");
    w.tree.write(".env", env_file().as_bytes());
    w.tree.write("id_rsa", pem_file().as_bytes());
    w.tree.write("certs/server.pem", pem_file().as_bytes());
    w.tree
        .write(".ssh/config", b"Host example\n  User deploy-user-xq\n");
    baseline(&w);

    for path in [".env", "id_rsa", "certs/server.pem", ".ssh/config"] {
        let e = entry(&w, 1, path).unwrap();
        assert_eq!(e.kind(), Kind::Sensitive, "{path}");
        assert_eq!(e.blob(), None, "{path}");
    }
    assert_eq!(entry(&w, 1, "src/main.rs").unwrap().kind(), Kind::File);

    let all = w.blobs.all_bytes();
    assert!(contains(&all, b"fn main()"), "normal content is stored");
    for secret in [
        env_marker().into_bytes(),
        pem_marker().into_bytes(),
        b"BEGIN".to_vec(),
        b"deploy-user-xq".to_vec(),
    ] {
        assert!(
            !contains(&all, &secret),
            "secret bytes {:?} leaked into the blob store",
            String::from_utf8_lossy(&secret)
        );
    }
    // Exactly one blob: the normal file.
    assert_eq!(w.blobs.count(), 1);
}

#[test]
fn sensitive_entries_hold_a_keyed_id_not_the_content_hash() {
    let w = setup();
    let content = env_file();
    w.tree.write(".env", content.as_bytes());
    baseline(&w);
    let e = entry(&w, 1, ".env").unwrap();
    assert_eq!(e.size(), content.len() as u64);
    assert_ne!(e.digest().unwrap(), sha256(content.as_bytes()));
    assert!(!w.blobs.contains(&sha256(content.as_bytes())));
    // The manifest bytes themselves do not contain the secret either.
    let d = w.snapshots.stored_digests(cid(1)).unwrap();
    assert_eq!(d.manifest, w.journal.load().unwrap().records()[0].manifest);
}

#[test]
fn a_sensitive_withheld_event_is_emitted_for_each_sensitive_file() {
    let w = setup();
    w.tree.write(".env", env_file().as_bytes());
    w.tree.write("id_rsa", pem_file().as_bytes());
    w.tree.write("keys/a.pem", pem_file().as_bytes());
    w.tree.write("plain.txt", b"plain");
    w.with_ports(record_baseline).unwrap();
    let mut got = withheld(&w);
    got.sort();
    assert_eq!(got, vec![".env", "id_rsa", "keys/a.pem"]);
    // They are published before the domain events of the checkpoint.
    let evs = w.events.events();
    let first_domain = evs
        .iter()
        .position(|e| matches!(e, Event::Domain(_)))
        .unwrap();
    let last_withheld = evs
        .iter()
        .rposition(|e| matches!(e, Event::SensitiveContentWithheld { .. }))
        .unwrap();
    assert!(last_withheld < first_domain);
}

#[test]
fn files_whose_content_matches_a_detector_are_sensitive_despite_an_innocent_name() {
    let w = setup();
    w.tree.write("notes.txt", pem_file().as_bytes());
    w.tree.write("deploy.sh", token_file().as_bytes());
    w.tree.write("fine.txt", b"nothing to see");
    w.with_ports(record_baseline).unwrap();
    assert_eq!(entry(&w, 1, "notes.txt").unwrap().kind(), Kind::Sensitive);
    assert_eq!(entry(&w, 1, "deploy.sh").unwrap().kind(), Kind::Sensitive);
    assert_eq!(entry(&w, 1, "fine.txt").unwrap().kind(), Kind::File);
    let mut got = withheld(&w);
    got.sort();
    assert_eq!(got, vec!["deploy.sh", "notes.txt"]);
    let all = w.blobs.all_bytes();
    assert!(!contains(&all, gh_token().as_bytes()));
    assert!(!contains(&all, pem_marker().as_bytes()));
    assert!(contains(&all, b"nothing to see"));
}

#[test]
fn a_normal_file_edited_to_contain_a_secret_becomes_sensitive_and_is_announced() {
    let w = setup();
    w.tree.write("config.txt", b"mode=dev\n");
    baseline(&w);
    w.tree.write(
        "config.txt",
        format!("mode=dev\n{}", token_file()).as_bytes(),
    );
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 1, 0, 0));
    assert_eq!(entry(&w, 2, "config.txt").unwrap().kind(), Kind::Sensitive);
    assert_eq!(withheld(&w), vec!["config.txt"]);
    assert!(!contains(&w.blobs.all_bytes(), gh_token().as_bytes()));
}

#[test]
fn unchanged_sensitive_files_are_not_announced_again_and_deleting_one_is_silent() {
    let w = setup();
    w.tree.write(".env", env_file().as_bytes());
    baseline(&w);
    cp(&w);
    assert!(withheld(&w).is_empty(), "no change, no event");
    w.tree.remove(".env");
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 0, 1, 0));
    assert!(withheld(&w).is_empty(), "a deletion withholds nothing");
}

#[test]
fn editing_a_sensitive_file_is_detected_as_modified_and_announced_again() {
    let w = setup();
    w.tree.write(".env", env_file().as_bytes());
    baseline(&w);
    let edited = format!("{}EXTRA={}\n", env_file(), "zz-extra-7");
    w.tree.write(".env", edited.as_bytes());
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 1, 0, 0));
    assert_eq!(withheld(&w), vec![".env"]);
    let all = w.blobs.all_bytes();
    assert!(!contains(&all, b"zz-extra-7"));
    assert!(!contains(&all, env_marker().as_bytes()));
}

#[test]
fn sensitive_files_are_withheld_in_run_checkpoints_too() {
    let (w, _) = agent_world(
        |t| {
            t.write(
                "agent_out/.env.local",
                format!("T={}\n", gh_token()).as_bytes(),
            )
        },
        exit0(),
    );
    baseline_project(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.checkpoint.counts, counts(2, 0, 0, 0)); // dir + file
    assert_eq!(withheld(&w), vec!["agent_out/.env.local"]);
    assert!(!contains(&w.blobs.all_bytes(), gh_token().as_bytes()));
}

// ==================================================================== too large

fn small_cap_world(cap: u64) -> World {
    World::with_cap_and_runner(cap, ScriptedRunner::new(|_| {}, exit0()))
}

#[test]
fn file_above_the_cap_is_recorded_as_too_large_with_hash_only_and_no_blob() {
    let w = small_cap_world(10);
    w.tree.write("small.txt", b"0123456789"); // exactly at the cap
    w.tree.write("big.bin", b"0123456789A"); // one byte over
    baseline(&w);
    let big = entry(&w, 1, "big.bin").unwrap();
    assert_eq!(big.kind(), Kind::TooLarge);
    assert_eq!(big.size(), 11);
    assert_eq!(big.digest(), Some(sha256(b"0123456789A")));
    assert_eq!(big.blob(), None);
    assert!(!w.blobs.contains(&sha256(b"0123456789A")));
    let small = entry(&w, 1, "small.txt").unwrap();
    assert_eq!(small.kind(), Kind::File);
    assert!(w.blobs.contains(&small.blob().unwrap()));
    assert_eq!(w.blobs.count(), 1);
    // Too-large is not a secret: no withheld event.
    assert!(withheld(&w).is_empty());
}

#[test]
fn too_large_file_edits_are_detected_by_hash() {
    let w = small_cap_world(4);
    w.tree.write("big", b"aaaaaaaa");
    baseline(&w);
    w.tree.write("big", b"bbbbbbbb"); // same size
    let r = cp(&w);
    assert_eq!(r.counts, counts(0, 1, 0, 0));
    let ch = changes(&w, 2);
    assert_eq!(ch[0].before().unwrap().digest(), Some(sha256(b"aaaaaaaa")));
    assert_eq!(ch[0].after().unwrap().digest(), Some(sha256(b"bbbbbbbb")));
    assert_eq!(w.blobs.count(), 0);
}

#[test]
fn a_file_growing_past_the_cap_changes_class_to_too_large() {
    let w = small_cap_world(4);
    w.tree.write("f", b"abcd");
    baseline(&w);
    w.tree.write("f", b"abcde");
    cp(&w);
    assert_eq!(entry(&w, 1, "f").unwrap().kind(), Kind::File);
    assert_eq!(entry(&w, 2, "f").unwrap().kind(), Kind::TooLarge);
}

#[test]
fn sensitivity_wins_over_the_size_cap() {
    let w = small_cap_world(4);
    w.tree.write(".env", env_file().as_bytes());
    w.with_ports(record_baseline).unwrap();
    assert_eq!(entry(&w, 1, ".env").unwrap().kind(), Kind::Sensitive);
    assert_eq!(withheld(&w), vec![".env"]);
    assert_eq!(w.blobs.count(), 0);
}

// ================================================================== stat cache

#[test]
fn first_capture_hashes_everything_and_second_capture_uses_the_stat_cache() {
    let w = setup();
    w.tree.write("a.txt", b"aaa");
    w.tree.write("d/b.txt", b"bbb");
    w.tree.write(".env", env_file().as_bytes());
    let b = w.with_ports(record_baseline).unwrap();
    assert_eq!(b.stats.files_cached, 0);
    assert_eq!(b.stats.files_hashed, 3);
    assert_eq!(b.stats.entries, 4); // 3 files + dir d

    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.stats.files_cached, 3);
    assert_eq!(c.stats.files_hashed, 0);
    assert_eq!(c.stats.bytes_hashed, 0);
    assert_eq!(c.stats.blobs_written, 0);
    assert_eq!(c.stats.entries, 4);
    assert_eq!(c.record.counts, Counts::default());
}

#[test]
fn a_modified_file_is_rehashed_so_a_stale_cache_never_hides_a_change() {
    let w = setup();
    w.tree.write("a.txt", b"aaaa");
    w.tree.write("b.txt", b"bbbb");
    w.tree.write("c.txt", b"cccc");
    baseline(&w);
    w.tree.write("b.txt", b"XXXX"); // same size, different bytes
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.stats.files_hashed, 1);
    assert_eq!(c.stats.files_cached, 2);
    assert_eq!(c.record.counts, counts(0, 1, 0, 0));
    assert_eq!(
        summary(&w, 2),
        vec![("b.txt".to_string(), ChangeKind::Modified)]
    );
    assert_eq!(c.stats.blobs_written, 1);
}

#[test]
fn rewriting_identical_content_rehashes_but_reports_no_change() {
    let w = setup();
    w.tree.write("a.txt", b"aaaa");
    baseline(&w);
    w.tree.write("a.txt", b"aaaa");
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.stats.files_hashed, 1);
    assert_eq!(c.stats.files_cached, 0);
    assert_eq!(c.record.counts, Counts::default());
    assert_eq!(c.stats.blobs_written, 0, "blob already present");
}

#[test]
fn a_mode_change_alone_is_not_hidden_by_the_cache() {
    let w = setup();
    w.tree.write("a.sh", b"echo");
    baseline(&w);
    w.tree.chmod("a.sh", 0o755);
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.record.counts, counts(0, 0, 0, 1));
    assert_eq!(entry(&w, 2, "a.sh").unwrap().mode() & 0o777, 0o755);
}

#[test]
fn a_cached_file_whose_blob_vanished_is_rehashed_and_the_blob_restored() {
    let w = setup();
    w.tree.write("a.txt", b"keep me");
    baseline(&w);
    w.blobs.remove(&sha256(b"keep me")).unwrap();
    assert_eq!(w.blobs.count(), 0);
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.stats.files_cached, 0);
    assert_eq!(c.stats.files_hashed, 1);
    assert_eq!(c.stats.blobs_written, 1);
    assert!(w.blobs.contains(&sha256(b"keep me")));
    assert_eq!(c.record.counts, Counts::default());
}

#[test]
fn the_stat_cache_is_not_used_for_new_files() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    baseline(&w);
    w.tree.write("b.txt", b"b");
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.stats.files_cached, 1);
    assert_eq!(c.stats.files_hashed, 1);
    assert_eq!(c.record.counts, counts(1, 0, 0, 0));
}

// =========================================================== unlistable dirs

#[test]
fn an_unlistable_directory_keeps_its_previous_entries() {
    let w = setup();
    w.tree.write("src/a.rs", b"a");
    w.tree.write("src/b.rs", b"b");
    w.tree.write("other.txt", b"o");
    baseline(&w);

    w.tree.set_unlistable("src");
    // Whatever happens below `src` is invisible while it cannot be listed.
    w.tree.remove("src/a.rs");
    w.tree.write("src/b.rs", b"changed");
    w.tree.write("src/c.rs", b"c");
    w.tree.write("other.txt", b"edited");
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();

    assert_eq!(c.record.counts, counts(0, 1, 0, 0), "{:?}", summary(&w, 2));
    assert_eq!(
        summary(&w, 2),
        vec![("other.txt".to_string(), ChangeKind::Modified)]
    );
    assert_eq!(c.stats.warnings_total, 1);
    assert!(c.stats.warnings[0].contains("src"));
    // Previous entries below `src` are carried into the new manifest unchanged.
    assert_eq!(entry(&w, 2, "src/a.rs"), entry(&w, 1, "src/a.rs"));
    assert_eq!(entry(&w, 2, "src/b.rs"), entry(&w, 1, "src/b.rs"));
    assert!(entry(&w, 2, "src/c.rs").is_none());
}

#[test]
fn an_unlistable_directory_does_not_hide_its_own_mode_change_or_others() {
    let w = setup();
    w.tree.write("src/a.rs", b"a");
    w.tree.write("z.txt", b"z");
    baseline(&w);
    w.tree.set_unlistable("src");
    w.tree.write("z.txt", b"zz");
    let c = w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
    assert_eq!(c.record.counts, counts(0, 1, 0, 0));
    assert_eq!(manifest_paths(&w, 2), manifest_paths(&w, 1));
}

// ========================================================================= run

#[test]
fn run_without_a_command_is_a_usage_error() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let err = run(&w, cmd(&[])).unwrap_err();
    assert!(
        matches!(err, RunFailure::Internal(Error::Usage(_))),
        "{err:?}"
    );
    assert!(w.runner.requests().is_empty());
    assert!(w.events.events().is_empty());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
}

#[test]
fn run_on_an_uninitialized_store_is_not_initialized() {
    let (w, held) = agent_world(|_| {}, exit0());
    let err = run(&w, cmd(&["agent"])).unwrap_err();
    assert!(
        matches!(err, RunFailure::Internal(Error::NotInitialized(_))),
        "{err:?}"
    );
    assert!(w.runner.requests().is_empty());
    assert_eq!(held.get(), None);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn run_records_a_run_checkpoint_with_command_exit_and_changes() {
    let (w, _) = agent_world(
        |t| {
            t.write("generated.txt", b"out");
            t.write("README.md", b"# rewritten\n");
        },
        RunOutcome::Exited(ExitInfo::Code(3)),
    );
    baseline_project(&w);
    let mut c = cmd(&["agent", "--flag", "two words"]);
    c.label = Some(label("try the thing"));
    let rep = run(&w, c).unwrap();

    assert!(rep.external.is_none());
    assert_eq!(rep.exit, ExitInfo::Code(3));
    let r = &rep.checkpoint;
    assert_eq!(r.id, cid(2));
    assert_eq!(r.kind, CkptKind::Run);
    assert_eq!(r.session, sid(1));
    assert_eq!(r.exit, Some(ExitInfo::Code(3)));
    assert_eq!(r.label, Some(label("try the thing")));
    assert_eq!(
        r.command.as_ref().unwrap().args(),
        &[b"agent".to_vec(), b"--flag".to_vec(), b"two words".to_vec()][..]
    );
    assert_eq!(r.counts, counts(1, 1, 0, 0));
    assert_eq!(w.journal.load().unwrap().records()[1], *r);
    assert_eq!(
        summary(&w, 2),
        vec![
            ("README.md".to_string(), ChangeKind::Modified),
            ("generated.txt".to_string(), ChangeKind::Created),
        ]
    );
    assert_eq!(
        w.events.events(),
        vec![
            Event::CommandFinished {
                exit: ExitInfo::Code(3)
            },
            recorded(2, 1, CkptKind::Run, 2),
        ]
    );
}

#[test]
fn run_records_signal_exits() {
    let (w, _) = agent_world(|_| {}, RunOutcome::Exited(ExitInfo::Signal(9)));
    baseline_project(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.exit, ExitInfo::Signal(9));
    assert_eq!(rep.checkpoint.exit, Some(ExitInfo::Signal(9)));
    assert_eq!(
        w.events.events()[0],
        Event::CommandFinished {
            exit: ExitInfo::Signal(9)
        }
    );
    // Survives the journal's text form.
    let line = rep.checkpoint.encode();
    assert_eq!(
        CheckpointRecord::decode(&line).unwrap().exit,
        Some(ExitInfo::Signal(9))
    );
}

#[test]
fn a_failing_exit_code_still_records_what_the_command_did() {
    let (w, _) = agent_world(
        |t| t.write("partial.txt", b"half"),
        RunOutcome::Exited(ExitInfo::Code(1)),
    );
    baseline_project(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.checkpoint.exit, Some(ExitInfo::Code(1)));
    assert_eq!(rep.checkpoint.counts, counts(1, 0, 0, 0));
}

#[test]
fn a_run_that_changes_nothing_is_still_recorded() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let rep = run(&w, cmd(&["true"])).unwrap();
    assert_eq!(rep.checkpoint.kind, CkptKind::Run);
    assert_eq!(rep.checkpoint.counts, Counts::default());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline, CkptKind::Run]);
}

#[test]
fn external_checkpoint_is_recorded_only_when_files_changed_outside_a_run() {
    let n = Rc::new(Cell::new(0u32));
    let (w, _) = agent_world(
        move |t| {
            n.set(n.get() + 1);
            t.write("by_agent.txt", format!("v{}", n.get()).as_bytes());
        },
        exit0(),
    );
    baseline_project(&w);

    // Nothing changed outside: no external checkpoint.
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert!(rep.external.is_none());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline, CkptKind::Run]);
    w.events.clear();

    // The human edits a file, then a run happens.
    w.tree.write("README.md", b"# edited by hand\n");
    w.tree.write("hand.txt", b"h");
    let rep = run(&w, cmd(&["agent"])).unwrap();
    let ext = rep.external.expect("external checkpoint");
    assert_eq!(ext.kind, CkptKind::External);
    assert_eq!(ext.id, cid(3));
    assert_eq!(ext.label, Some(label("changes outside recorded runs")));
    assert_eq!(ext.counts, counts(1, 1, 0, 0));
    assert_eq!(ext.command, None);
    assert_eq!(ext.exit, None);
    // The run's own checkpoint does not contain the human's edits.
    assert_eq!(rep.checkpoint.id, cid(4));
    assert_eq!(rep.checkpoint.kind, CkptKind::Run);
    assert_eq!(
        rep.checkpoint.counts,
        counts(0, 1, 0, 0),
        "{:?}",
        summary(&w, 4)
    );
    assert_eq!(
        kinds(&w),
        vec![
            CkptKind::Baseline,
            CkptKind::Run,
            CkptKind::External,
            CkptKind::Run
        ]
    );
    assert_eq!(
        w.events.events(),
        vec![
            recorded(3, 1, CkptKind::External, 2),
            Event::CommandFinished {
                exit: ExitInfo::Code(0)
            },
            recorded(4, 1, CkptKind::Run, 1),
        ]
    );
}

#[test]
fn run_passes_session_env_vars_in_extra_env() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    run(&w, cmd(&["agent", "x"])).unwrap();
    let req = &w.runner.requests()[0];
    assert_eq!(req.args, vec![b"agent".to_vec(), b"x".to_vec()]);
    let get = |k: &str| {
        req.extra_env
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("AGENT_UNDO_ACTIVE"), Some(b"1".to_vec()));
    assert_eq!(get("AGENT_UNDO_SESSION"), Some(b"1".to_vec()));
    assert_eq!(get("AGENT_UNDO_CHECKPOINT"), Some(b"2".to_vec()));
    assert_eq!(req.extra_env.len(), 3);
}

#[test]
fn checkpoint_env_var_names_the_run_checkpoint_after_an_external_one() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    w.tree.write("hand.txt", b"h");
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.external.as_ref().unwrap().id, cid(2));
    let req = &w.runner.requests()[0];
    let ck = req
        .extra_env
        .iter()
        .find(|(n, _)| n == "AGENT_UNDO_CHECKPOINT")
        .unwrap();
    assert_eq!(ck.1, b"3".to_vec());
    assert_eq!(rep.checkpoint.id, cid(3));
}

#[test]
fn new_session_without_external_changes_opens_the_session_on_the_run_checkpoint() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let mut c = cmd(&["agent"]);
    c.new_session = true;
    let rep = run(&w, c).unwrap();
    assert!(rep.external.is_none());
    assert_eq!(rep.checkpoint.session, sid(2));
    let req = &w.runner.requests()[0];
    assert!(
        req.extra_env
            .contains(&("AGENT_UNDO_SESSION".to_string(), b"2".to_vec()))
    );
    assert_eq!(
        w.events.events(),
        vec![
            Event::CommandFinished {
                exit: ExitInfo::Code(0)
            },
            Event::Domain(DomainEvent::SessionStarted { session: sid(2) }),
            recorded(2, 2, CkptKind::Run, 0),
        ]
    );
}

#[test]
fn new_session_with_external_changes_opens_the_session_on_the_external_checkpoint() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    w.tree.write("hand.txt", b"h");
    let mut c = cmd(&["agent"]);
    c.new_session = true;
    let rep = run(&w, c).unwrap();
    assert_eq!(rep.external.as_ref().unwrap().session, sid(2));
    assert_eq!(rep.checkpoint.session, sid(2));
    let started = domain_events(&w)
        .into_iter()
        .filter(|e| matches!(e, DomainEvent::SessionStarted { .. }))
        .count();
    assert_eq!(started, 1, "the session starts exactly once");
    let req = &w.runner.requests()[0];
    assert!(
        req.extra_env
            .contains(&("AGENT_UNDO_SESSION".to_string(), b"2".to_vec()))
    );
}

#[test]
fn run_without_new_session_stays_in_the_current_session() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.checkpoint.session, sid(1));
    assert!(
        domain_events(&w)
            .iter()
            .all(|e| !matches!(e, DomainEvent::SessionStarted { .. }))
    );
}

#[test]
fn env_policy_is_passed_through_to_the_runner() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let allow = EnvPolicy::allow(&["PATH,HOME".to_string(), "LANG".to_string()]).unwrap();
    let mut c = cmd(&["agent"]);
    c.env = allow.clone();
    run(&w, c).unwrap();
    run(&w, cmd(&["agent"])).unwrap();
    let reqs = w.runner.requests();
    assert_eq!(reqs[0].env, allow);
    assert_eq!(reqs[1].env, EnvPolicy::Inherit);
}

#[test]
fn the_exclusive_lock_is_held_while_the_command_runs_and_released_after() {
    let (w, held) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(held.get(), Some(true));
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn command_not_found_is_reported_and_records_no_run_checkpoint() {
    let (w, held) = agent_world(|_| {}, RunOutcome::NotFound);
    baseline_project(&w);
    let err = run(&w, cmd(&["no-such-tool"])).unwrap_err();
    assert!(matches!(err, RunFailure::NotFound), "{err:?}");
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    assert!(w.events.events().is_empty(), "{:?}", w.events.events());
    assert!(!w.snapshots.contains(cid(2)));
    assert_eq!(held.get(), None, "the runner script never ran");
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn cannot_execute_carries_the_reason_and_records_no_run_checkpoint() {
    let (w, _) = agent_world(
        |_| {},
        RunOutcome::CannotExecute("permission denied".into()),
    );
    baseline_project(&w);
    let err = run(&w, cmd(&["./not-executable"])).unwrap_err();
    match err {
        RunFailure::CannotExecute(why) => assert_eq!(why, "permission denied"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    assert!(
        !w.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::CommandFinished { .. }))
    );
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn failed_launch_still_keeps_the_external_checkpoint_of_the_before_snapshot() {
    let (w, _) = agent_world(|_| {}, RunOutcome::NotFound);
    baseline_project(&w);
    w.tree.write("hand.txt", b"h");
    let err = run(&w, cmd(&["nope"])).unwrap_err();
    assert!(matches!(err, RunFailure::NotFound));
    // The human's change was real and is recorded; no Run checkpoint exists.
    assert_eq!(kinds(&w), vec![CkptKind::Baseline, CkptKind::External]);
    assert!(
        !w.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::CommandFinished { .. }))
    );
}

#[test]
fn run_refuses_while_another_operation_holds_the_lock() {
    let (w, held) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let g = w.locks.exclusive().unwrap();
    let err = run(&w, cmd(&["agent"])).unwrap_err();
    assert!(
        matches!(err, RunFailure::Internal(Error::Locked(_))),
        "{err:?}"
    );
    assert!(w.runner.requests().is_empty());
    assert_eq!(held.get(), None);
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    drop(g);
    assert!(run(&w, cmd(&["agent"])).is_ok());
}

#[test]
fn run_command_line_with_hostile_arguments_round_trips_through_the_journal() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let args: Vec<Vec<u8>> = vec![
        b"sh".to_vec(),
        b"-c".to_vec(),
        "echo 'a b'\n\x1b[0m \u{fc}n\u{ef} %41\t"
            .as_bytes()
            .to_vec(),
        vec![0xff, 0xfe, b'x'],
    ];
    let c = RunCommand {
        args: args.clone(),
        label: None,
        new_session: false,
        env: EnvPolicy::Inherit,
        arg_policy: agent_undo_domain::journal::ArgPolicy::Redact,
    };
    let rep = run(&w, c).unwrap();
    assert_eq!(rep.checkpoint.command.as_ref().unwrap().args(), &args[..]);
    let line = rep.checkpoint.encode();
    assert!(!line.contains('\n'));
    let back = CheckpointRecord::decode(&line).unwrap();
    assert_eq!(back, rep.checkpoint);
    // The runner got the untouched arguments.
    assert_eq!(w.runner.requests()[0].args, args);
}

#[test]
fn an_oversized_command_line_is_truncated_in_the_record_but_not_for_the_runner() {
    let (w, _) = agent_world(|_| {}, exit0());
    baseline_project(&w);
    let big = "x".repeat(3000);
    let rep = run(&w, cmd(&["agent", &big, &big, &big])).unwrap();
    let recorded_args = rep.checkpoint.command.as_ref().unwrap().args().to_vec();
    assert_eq!(recorded_args.last().unwrap(), b"...[truncated]");
    assert!(recorded_args.len() < 4);
    assert_eq!(w.runner.requests()[0].args.len(), 4);
}

#[test]
fn run_after_run_chains_checkpoints_and_each_captures_only_its_own_changes() {
    let counter = Rc::new(Cell::new(0u32));
    let c2 = counter.clone();
    let (w, _) = agent_world(
        move |t| {
            let n = c2.get() + 1;
            c2.set(n);
            t.write(&format!("out{n}.txt"), b"o");
        },
        exit0(),
    );
    baseline_project(&w);
    let r1 = run(&w, cmd(&["agent"])).unwrap();
    let r2 = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(r1.checkpoint.counts, counts(1, 0, 0, 0));
    assert_eq!(r2.checkpoint.counts, counts(1, 0, 0, 0));
    assert!(r2.external.is_none());
    assert_eq!(
        summary(&w, 2),
        vec![("out1.txt".to_string(), ChangeKind::Created)]
    );
    assert_eq!(
        summary(&w, 3),
        vec![("out2.txt".to_string(), ChangeKind::Created)]
    );
}

#[test]
fn run_on_a_command_deleting_files_records_deletions_with_before_state() {
    let (w, _) = agent_world(|t| t.remove("src"), exit0());
    baseline_project(&w);
    let rep = run(&w, cmd(&["rm-agent"])).unwrap();
    assert_eq!(rep.checkpoint.counts, counts(0, 0, 2, 0));
    let ch = changes(&w, 2);
    let f = ch
        .iter()
        .find(|c| c.path().display() == "src/main.rs")
        .unwrap();
    assert_eq!(f.before().unwrap().blob(), Some(sha256(b"fn main() {}\n")));
    assert!(w.blobs.contains(&sha256(b"fn main() {}\n")));
}

#[test]
fn run_report_stats_describe_the_after_scan() {
    let (w, _) = agent_world(|t| t.write("n.txt", b"new"), exit0());
    baseline_project(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.stats.files_hashed, 1);
    assert_eq!(rep.stats.files_cached, 2);
    assert_eq!(rep.stats.blobs_written, 1);
}

#[test]
fn run_in_a_world_with_a_small_cap_records_too_large_output() {
    let (w, _) = agent_world_cap(4, |t| t.write("big.out", b"0123456789"), exit0());
    w.tree.write("s", b"abcd");
    baseline(&w);
    let rep = run(&w, cmd(&["agent"])).unwrap();
    assert_eq!(rep.checkpoint.counts, counts(1, 0, 0, 0));
    assert_eq!(entry(&w, 2, "big.out").unwrap().kind(), Kind::TooLarge);
    assert!(!w.blobs.contains(&sha256(b"0123456789")));
}

// ======================================================================= status

#[test]
fn status_on_an_empty_journal_has_no_head_and_no_pending_scan() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    let s = w.with_ports(status).unwrap();
    assert_eq!(s.checkpoints, 0);
    assert!(s.head.is_none());
    assert!(s.session.is_none());
    assert!(s.pending.is_none());
    assert!(!s.locked_by_other);
    assert_eq!(s.pruned, 0);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn status_reports_head_session_and_zero_pending_right_after_baseline() {
    let w = setup();
    let b = baseline_project(&w);
    let s = w.with_ports(status).unwrap();
    assert_eq!(s.checkpoints, 1);
    assert_eq!(s.head, Some(b));
    assert_eq!(s.session, Some(sid(1)));
    let pending = s.pending.unwrap();
    assert_eq!(pending.counts, Counts::default());
    assert!(pending.sample.is_empty());
    assert!(!s.locked_by_other);
}

#[test]
fn status_counts_pending_changes_after_edits_without_recording_anything() {
    let w = setup();
    w.tree.write("keep", b"k");
    w.tree.write("edit", b"e1");
    w.tree.write("gone", b"g");
    w.tree.write_mode("exec", b"x", 0o644);
    baseline(&w);
    w.tree.write("new1", b"n");
    w.tree.write("new2", b"n");
    w.tree.write("edit", b"e2");
    w.tree.remove("gone");
    w.tree.chmod("exec", 0o755);

    let blobs_before = w.blobs.count();
    let s = w.with_ports(status).unwrap();
    let pending = s.pending.unwrap();
    assert_eq!(pending.counts, counts(2, 1, 1, 1));
    assert_eq!(pending.sample.len(), 5);
    assert_ne!(pending.fingerprint, 0);
    // Read-only: nothing recorded, no events, no blobs written.
    assert_eq!(s.checkpoints, 1);
    assert_eq!(w.journal.load().unwrap().records().len(), 1);
    assert!(w.events.events().is_empty());
    assert_eq!(w.blobs.count(), blobs_before);
    assert_eq!(w.snapshots.list().unwrap(), vec![cid(1)]);
}

#[test]
fn status_pending_is_cleared_by_a_checkpoint() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("x", b"x");
    let before = w.with_ports(status).unwrap();
    assert_eq!(before.pending.unwrap().counts, counts(1, 0, 0, 0));
    cp(&w);
    let after = w.with_ports(status).unwrap();
    assert_eq!(after.pending.unwrap().counts, Counts::default());
    assert_eq!(after.checkpoints, 2);
    assert_eq!(after.head.unwrap().id, cid(2));
}

#[test]
fn status_fingerprint_is_stable_for_the_same_pending_set_and_differs_otherwise() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("x", b"x");
    let a = w.with_ports(status).unwrap().pending.unwrap();
    let b = w.with_ports(status).unwrap().pending.unwrap();
    assert_eq!(a.fingerprint, b.fingerprint);
    w.tree.write("y", b"y");
    let c = w.with_ports(status).unwrap().pending.unwrap();
    assert_ne!(a.fingerprint, c.fingerprint);
}

#[test]
fn status_reports_the_current_session() {
    let w = setup();
    baseline_project(&w);
    w.with_ports(|p| manual_checkpoint(p, None, true)).unwrap();
    let s = w.with_ports(status).unwrap();
    assert_eq!(s.session, Some(sid(2)));
    assert_eq!(s.checkpoints, 2);
}

#[test]
fn status_reports_locked_by_other_when_the_exclusive_lock_is_held() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("x", b"x");
    let g = w.locks.exclusive().unwrap();
    let s = w.with_ports(status).unwrap();
    assert!(s.locked_by_other);
    assert!(s.pending.is_none());
    assert!(s.head.is_none());
    assert_eq!(s.checkpoints, 0);
    drop(g);
    let s = w.with_ports(status).unwrap();
    assert!(!s.locked_by_other);
    assert_eq!(s.pending.unwrap().counts, counts(1, 0, 0, 0));
}

#[test]
fn status_works_next_to_another_reader() {
    let w = setup();
    baseline_project(&w);
    let _reader = w.locks.shared().unwrap();
    let s = w.with_ports(status).unwrap();
    assert!(!s.locked_by_other);
    assert!(s.pending.is_some());
}

#[test]
fn status_scan_uses_the_stat_cache_and_sees_sensitive_edits_without_storing_them() {
    let w = setup();
    w.tree.write("a.txt", b"a");
    w.tree.write(".env", env_file().as_bytes());
    baseline(&w);
    let s = w.with_ports(status).unwrap().pending.unwrap();
    assert_eq!(s.stats.files_cached, 2);
    assert_eq!(s.stats.files_hashed, 0);

    w.tree
        .write(".env", format!("{}X=1\n", env_file()).as_bytes());
    w.tree
        .write("new.txt", format!("{}\n", gh_token()).as_bytes());
    let s = w.with_ports(status).unwrap().pending.unwrap();
    assert_eq!(s.counts, counts(1, 1, 0, 0));
    assert!(withheld(&w).is_empty(), "status announces nothing");
    let all = w.blobs.all_bytes();
    assert!(!contains(&all, gh_token().as_bytes()));
    assert!(!contains(&all, env_marker().as_bytes()));
}

#[test]
fn status_observation_does_not_store_new_file_content() {
    let w = setup();
    baseline_project(&w);
    let n = w.blobs.count();
    w.tree.write("fresh.txt", b"fresh content");
    let s = w.with_ports(status).unwrap().pending.unwrap();
    assert_eq!(s.stats.blobs_written, 0);
    assert_eq!(w.blobs.count(), n);
}

#[test]
fn status_with_an_unlistable_directory_does_not_report_phantom_deletions() {
    let w = setup();
    w.tree.write("src/a.rs", b"a");
    w.tree.write("src/b.rs", b"b");
    baseline(&w);
    w.tree.set_unlistable("src");
    w.tree.remove("src/a.rs");
    let s = w.with_ports(status).unwrap().pending.unwrap();
    assert_eq!(s.counts, Counts::default());
    assert_eq!(s.stats.warnings_total, 1);
}

#[test]
fn scan_pending_requires_a_baseline() {
    let w = setup();
    let j = w.journal.load().unwrap();
    let err = w.with_ports(|p| scan_pending(p, &j)).unwrap_err();
    assert!(matches!(err, Error::NotInitialized(_)), "{err:?}");
}

#[test]
fn scan_pending_compares_against_the_newest_checkpoint() {
    let w = setup();
    baseline_project(&w);
    w.tree.write("one", b"1");
    cp(&w);
    w.tree.write("two", b"2");
    let j = w.journal.load().unwrap();
    let p = w.with_ports(|p| scan_pending(p, &j)).unwrap();
    assert_eq!(p.counts, counts(1, 0, 0, 0));
    assert_eq!(p.sample[0].path().display(), "two");
}

// ======================================================================== watch

#[test]
fn watch_is_idle_when_nothing_changed() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    for _ in 0..3 {
        let step = watch(&w, &mut d);
        assert_eq!(step.tick, Tick::Idle);
        assert!(step.committed.is_none());
        assert!(!step.skipped_busy);
    }
    assert!(w.events.events().is_empty());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn watch_waits_while_changes_settle_then_commits_exactly_once() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15); // the fake clock advances 10 s per read
    w.tree.write("new.txt", b"n");

    let t1 = watch(&w, &mut d);
    assert_eq!(
        t1.tick,
        Tick::Waiting {
            remaining_ns: 15 * S
        }
    );
    assert!(t1.committed.is_none());
    let t2 = watch(&w, &mut d);
    assert_eq!(
        t2.tick,
        Tick::Waiting {
            remaining_ns: 5 * S
        }
    );
    assert!(t2.committed.is_none());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline], "nothing recorded yet");
    assert!(w.events.events().is_empty());

    let t3 = watch(&w, &mut d);
    assert_eq!(t3.tick, Tick::Commit);
    let rec = t3.committed.expect("committed checkpoint");
    assert_eq!(rec.kind, CkptKind::Watch);
    assert_eq!(rec.id, cid(2));
    assert_eq!(rec.counts, counts(1, 0, 0, 0));
    assert_eq!(rec.session, sid(1));
    assert_eq!(kinds(&w), vec![CkptKind::Baseline, CkptKind::Watch]);
    assert_eq!(
        w.events.events(),
        vec![
            recorded(2, 1, CkptKind::Watch, 1),
            Event::WatchCommitted {
                checkpoint: cid(2),
                changes: counts(1, 0, 0, 0)
            },
        ]
    );

    // Afterwards the tree equals the last checkpoint: idle, no second commit.
    let t4 = watch(&w, &mut d);
    assert_eq!(t4.tick, Tick::Idle);
    assert!(t4.committed.is_none());
    let committed_events = w
        .events
        .events()
        .iter()
        .filter(|e| matches!(e, Event::WatchCommitted { .. }))
        .count();
    assert_eq!(committed_events, 1);
}

#[test]
fn further_changes_restart_the_quiet_period_and_are_batched_into_one_checkpoint() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    w.tree.write("a", b"1");
    assert_eq!(
        watch(&w, &mut d).tick,
        Tick::Waiting {
            remaining_ns: 15 * S
        }
    );
    w.tree.write("b", b"2"); // the change set differs: timer restarts
    assert_eq!(
        watch(&w, &mut d).tick,
        Tick::Waiting {
            remaining_ns: 15 * S
        }
    );
    assert_eq!(
        watch(&w, &mut d).tick,
        Tick::Waiting {
            remaining_ns: 5 * S
        }
    );
    let t = watch(&w, &mut d);
    assert_eq!(t.tick, Tick::Commit);
    assert_eq!(t.committed.unwrap().counts, counts(2, 0, 0, 0));
    assert_eq!(kinds(&w).len(), 2);
}

#[test]
fn reverting_the_change_cancels_the_pending_commit() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    w.tree.write("README.md", b"# changed\n");
    assert!(matches!(watch(&w, &mut d).tick, Tick::Waiting { .. }));
    w.tree.write("README.md", b"# demo\n"); // back to the recorded content
    assert_eq!(watch(&w, &mut d).tick, Tick::Idle);
    assert_eq!(watch(&w, &mut d).tick, Tick::Idle);
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    assert!(w.events.events().is_empty());
}

#[test]
fn watch_with_zero_quiet_period_commits_on_the_first_tick_with_changes() {
    let w = setup();
    baseline_project(&w);
    let mut d = Debouncer::new(0).unwrap();
    w.tree.write("x", b"x");
    let t = w.with_ports(|p| watch_tick(p, &mut d, None)).unwrap();
    assert_eq!(t.tick, Tick::Commit);
    assert_eq!(t.committed.unwrap().kind, CkptKind::Watch);
}

#[test]
fn watch_commit_carries_the_label() {
    let w = setup();
    baseline_project(&w);
    let mut d = Debouncer::new(0).unwrap();
    w.tree.write("x", b"x");
    let l = label("auto");
    let t = w.with_ports(|p| watch_tick(p, &mut d, Some(&l))).unwrap();
    assert_eq!(t.committed.unwrap().label, Some(l));
}

#[test]
fn watch_skips_the_tick_when_the_store_is_busy_and_feeds_nothing_to_the_debouncer() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    w.tree.write("x", b"x");
    {
        let _g = w.locks.exclusive().unwrap();
        let t = watch(&w, &mut d);
        assert!(t.skipped_busy);
        assert_eq!(t.tick, Tick::Idle);
        assert!(t.committed.is_none());
    }
    assert!(w.events.events().is_empty());
    assert_eq!(kinds(&w), vec![CkptKind::Baseline]);
    // The busy tick did not start the quiet timer: the next real tick starts it.
    let t = watch(&w, &mut d);
    assert!(!t.skipped_busy);
    assert_eq!(
        t.tick,
        Tick::Waiting {
            remaining_ns: 15 * S
        }
    );
}

#[test]
fn watch_while_a_shared_reader_holds_the_lock_is_skipped_as_busy() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    let _r = w.locks.shared().unwrap();
    assert!(watch(&w, &mut d).skipped_busy);
}

#[test]
fn watch_on_an_uninitialized_store_is_not_initialized_and_releases_the_lock() {
    let w = setup();
    let mut d = quiet(15);
    let err = w.with_ports(|p| watch_tick(p, &mut d, None)).err().unwrap();
    assert!(matches!(err, Error::NotInitialized(_)), "{err:?}");
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn watch_scans_without_storing_content_until_it_commits() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    let n = w.blobs.count();
    w.tree.write("fresh.txt", b"fresh");
    watch(&w, &mut d);
    assert_eq!(w.blobs.count(), n, "waiting ticks only observe");
    watch(&w, &mut d);
    watch(&w, &mut d);
    assert_eq!(w.blobs.count(), n + 1);
}

#[test]
fn watch_commit_announces_each_withheld_file_once_and_never_stores_its_bytes() {
    let w = setup();
    baseline_project(&w);
    let mut d = quiet(15);
    w.tree.write(".env", env_file().as_bytes());
    watch(&w, &mut d);
    watch(&w, &mut d);
    assert!(withheld(&w).is_empty(), "pending scans announce nothing");
    let t = watch(&w, &mut d);
    assert_eq!(t.tick, Tick::Commit);
    assert_eq!(withheld(&w), vec![".env"]);
    assert!(!contains(&w.blobs.all_bytes(), env_marker().as_bytes()));
}

#[test]
fn watch_commit_follows_the_session_of_the_head() {
    let w = setup();
    baseline_project(&w);
    w.with_ports(|p| manual_checkpoint(p, None, true)).unwrap();
    w.events.clear();
    let mut d = Debouncer::new(0).unwrap();
    w.tree.write("x", b"x");
    let t = w.with_ports(|p| watch_tick(p, &mut d, None)).unwrap();
    assert_eq!(t.committed.unwrap().session, sid(2));
    assert!(
        domain_events(&w)
            .iter()
            .all(|e| !matches!(e, DomainEvent::SessionStarted { .. }))
    );
}
