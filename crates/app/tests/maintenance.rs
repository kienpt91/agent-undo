//! Application-level tests of the maintenance use cases: `verify`, `gc` and
//! `diff_checkpoint`, plus how a tampered journal surfaces through the use cases.

use agent_undo_app::error::Error;
use agent_undo_app::events::Event;
use agent_undo_app::fakes::{ScriptedRunner, World};
use agent_undo_app::ports::{BlobStore, JournalRepository, Locker, RunOutcome, SnapshotRepository};
use agent_undo_app::usecases::checkpoint::{load_log, manual_checkpoint};
use agent_undo_app::usecases::gc::gc;
use agent_undo_app::usecases::history::{
    ChangeView, Content, DiffReport, MAX_TEXT_DIFFS, diff_checkpoint,
};
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::{apply_undo, plan_undo};
use agent_undo_app::usecases::run::{RunCommand, RunFailure, run_command};
use agent_undo_app::usecases::status::status;
use agent_undo_app::usecases::verify::{VerifyReport, verify};
use agent_undo_domain::change::{ChangeKind, Rename};
use agent_undo_domain::diff::DiffOutcome;
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::hash::sha256;
use agent_undo_domain::journal::{
    CheckpointId, CheckpointRecord, CkptKind, DomainEvent, ExitInfo, RetentionPolicy, Selector,
};
use agent_undo_domain::path::RelPath;

// ----------------------------------------------------------------- helpers

fn setup() -> World {
    World::new()
}

fn id(n: u64) -> CheckpointId {
    CheckpointId::new(n).unwrap()
}

fn p(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

fn baseline(w: &World) {
    w.with_ports(record_baseline).unwrap();
}

fn cp(w: &World) -> CheckpointRecord {
    w.with_ports(|p| manual_checkpoint(p, None, false))
        .unwrap()
        .record
}

fn run_noop(w: &World) -> agent_undo_app::usecases::run::RunReport {
    w.with_ports(|p| {
        run_command(
            p,
            RunCommand {
                args: vec![b"true".to_vec()],
                label: None,
                new_session: false,
                env: EnvPolicy::Inherit,
            },
        )
    })
    .unwrap()
}

/// Baseline (a.txt = "a0\n", b.txt = "b0\n") followed by `n` manual checkpoints,
/// checkpoint `i` rewriting a.txt to "a{i}\n". Blobs: a0..a{n} and b0.
fn linear(w: &World, n: usize) {
    w.tree.write("a.txt", b"a0\n");
    w.tree.write("b.txt", b"b0\n");
    baseline(w);
    for i in 1..=n {
        w.tree.write("a.txt", format!("a{i}\n").as_bytes());
        cp(w);
    }
    w.events.clear();
}

fn records(w: &World) -> Vec<CheckpointRecord> {
    w.journal.load().unwrap().records().to_vec()
}

fn pruned(w: &World) -> Vec<u64> {
    w.journal.load().unwrap().pruned().iter().copied().collect()
}

fn do_verify(w: &World) -> VerifyReport {
    w.with_ports(verify).unwrap()
}

fn problems_contain(r: &VerifyReport, needle: &str) -> bool {
    r.problems.iter().any(|p| p.contains(needle))
}

fn do_gc(
    w: &World,
    policy: RetentionPolicy,
    apply: bool,
) -> agent_undo_app::usecases::gc::GcReport {
    w.with_ports(|p| gc(p, policy, apply)).unwrap()
}

fn diff(w: &World, n: u64) -> DiffReport {
    w.with_ports(|p| diff_checkpoint(p, id(n))).unwrap()
}

fn view<'a>(r: &'a DiffReport, path: &str) -> &'a ChangeView {
    r.changes
        .iter()
        .find(|c| c.change.path().display() == path)
        .unwrap_or_else(|| panic!("no change for {path}"))
}

fn text_of(v: &ChangeView) -> &str {
    match &v.content {
        Content::Diff(DiffOutcome::Text(t)) => t,
        other => panic!("expected a text diff, got {other:?}"),
    }
}

fn github_token() -> String {
    format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
}

fn gc_events(w: &World) -> Vec<Event> {
    w.events
        .events()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                Event::GarbageCollected { .. }
                    | Event::Domain(DomainEvent::CheckpointsPruned { .. })
            )
        })
        .collect()
}

/// Observable store state: (snapshot ids, blob count, events, tree paths).
fn state(w: &World) -> (Vec<u64>, usize, usize, Vec<String>) {
    (
        w.snapshots
            .list()
            .unwrap()
            .into_iter()
            .map(CheckpointId::get)
            .collect(),
        w.blobs.count(),
        w.events.events().len(),
        w.tree.paths(),
    )
}

fn digest_of(content: &[u8]) -> agent_undo_domain::hash::Digest {
    sha256(content)
}

// ------------------------------------------------------------------ verify

#[test]
fn verify_healthy_world_after_runs_checkpoints_and_undo() {
    let w = setup();
    w.tree.write("a.txt", b"a0\n");
    w.tree.write("b.txt", b"b0\n");
    baseline(&w); // 1
    w.tree.write("a.txt", b"a1\n");
    cp(&w); // 2
    w.tree.write("c.txt", b"c0\n");
    let rep = run_noop(&w); // 3 external (c.txt), 4 run
    assert_eq!(rep.external.as_ref().unwrap().id, id(3));
    assert_eq!(rep.checkpoint.id, id(4));
    let undo = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(3)), false))
        .unwrap();
    assert!(undo.refused.is_none());
    assert!(!w.tree.exists("c.txt"));
    // 5 pre-undo, 6 undo
    assert_eq!(records(&w).len(), 6);

    let r = do_verify(&w);
    assert!(r.ok(), "{:?}", r.problems);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r.checkpoints_checked, 6);
    assert_eq!(r.checkpoints_pruned, 0);
    // a0, a1, b0, c0: every blob is referenced by some manifest or change.
    assert_eq!(r.blobs_checked, 4);
    assert_eq!(r.blobs_unreferenced, 0);
}

#[test]
fn verify_counts_match_journal_and_blob_store() {
    let w = setup();
    linear(&w, 3);
    let r = do_verify(&w);
    assert!(r.ok());
    assert_eq!(r.checkpoints_checked, 4);
    assert_eq!(r.blobs_checked, w.blobs.count() as u64);
    assert_eq!(r.blobs_checked, 5); // a0..a3, b0
    assert_eq!(r.blobs_unreferenced, 0);
}

#[test]
fn verify_reports_unreferenced_blobs_without_failing() {
    let w = setup();
    linear(&w, 1);
    w.blobs.put(b"nobody references this").unwrap();
    w.blobs.put(b"nor this").unwrap();
    let r = do_verify(&w);
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.blobs_unreferenced, 2);
    assert_eq!(r.blobs_checked, 5); // a0, a1, b0 + 2
    assert!(r.warnings.is_empty());
}

#[test]
fn verify_empty_journal_is_ok_with_zero_counts() {
    let w = setup();
    let r = do_verify(&w);
    assert!(r.ok());
    assert_eq!(r.checkpoints_checked, 0);
    assert_eq!(r.blobs_checked, 0);
}

#[test]
fn verify_journal_modified_counts_is_a_journal_problem() {
    let w = setup();
    linear(&w, 3);
    w.journal.tamper(|r| r[1].counts.created += 7);
    let r = do_verify(&w);
    assert!(!r.ok());
    assert_eq!(r.problems.len(), 1);
    assert!(r.problems[0].starts_with("journal:"), "{:?}", r.problems);
    assert!(
        r.problems[0].contains("record hash mismatch"),
        "{:?}",
        r.problems
    );
    // The journal is unusable, so nothing else was checked.
    assert_eq!(r.checkpoints_checked, 0);
}

#[test]
fn verify_journal_deleted_middle_record_is_detected() {
    let w = setup();
    linear(&w, 3);
    w.journal.tamper(|r| {
        r.remove(1);
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(r.problems[0].contains("sequence"), "{:?}", r.problems);
}

#[test]
fn verify_journal_swapped_records_are_detected() {
    let w = setup();
    linear(&w, 3);
    w.journal.tamper(|r| r.swap(1, 2));
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(r.problems[0].contains("sequence"), "{:?}", r.problems);
}

#[test]
fn verify_journal_changed_hash_is_detected() {
    let w = setup();
    linear(&w, 2);
    w.journal.tamper(|r| r[1].hash = [7; 32]);
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(
        r.problems[0].contains("record hash mismatch"),
        "{:?}",
        r.problems
    );
}

#[test]
fn verify_journal_changed_prev_hash_breaks_the_chain() {
    let w = setup();
    linear(&w, 2);
    w.journal.tamper(|r| {
        r[2].prev = [9; 32];
        r[2].hash = r[2].compute_hash();
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(
        r.problems[0].contains("hash chain broken"),
        "{:?}",
        r.problems
    );
}

#[test]
fn verify_journal_edit_with_recomputed_hash_breaks_the_next_link() {
    let w = setup();
    linear(&w, 3);
    // An attacker who fixes up the edited record's own hash still breaks the chain.
    w.journal.tamper(|r| {
        r[1].counts.deleted += 1;
        r[1].hash = r[1].compute_hash();
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(
        r.problems[0].contains("hash chain broken"),
        "{:?}",
        r.problems
    );
}

#[test]
fn verify_second_baseline_record_is_detected() {
    let w = setup();
    linear(&w, 2);
    w.journal.tamper(|r| {
        let last = r.len() - 1;
        r[last].kind = CkptKind::Baseline;
        r[last].hash = r[last].compute_hash();
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(r.problems[0].contains("baseline"), "{:?}", r.problems);
}

#[test]
fn verify_pruned_list_naming_the_head_is_a_journal_problem() {
    let w = setup();
    linear(&w, 2);
    w.journal.save_pruned(&[id(3)]).unwrap();
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(r.problems[0].contains("not prunable"), "{:?}", r.problems);
}

#[test]
fn verify_manifest_entry_removed_is_a_digest_mismatch() {
    let w = setup();
    linear(&w, 2);
    w.snapshots.tamper_manifest(id(2), |e| {
        e.pop();
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(
        problems_contain(&r, "manifest does not match the journal"),
        "{:?}",
        r.problems
    );
    assert!(problems_contain(&r, "2"));
    // The other checkpoints are still checked.
    assert_eq!(r.checkpoints_checked, 3);
}

#[test]
fn verify_manifest_entry_changed_is_a_digest_mismatch() {
    let w = setup();
    linear(&w, 2);
    w.snapshots.tamper_manifest(id(1), |e| {
        let (_, entry) = &mut e[0];
        *entry = entry.with_mode(0o600);
    });
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(problems_contain(
        &r,
        "manifest does not match the journal (modified or corrupt)"
    ));
}

#[test]
fn verify_untouched_checkpoints_report_no_problem_when_one_is_tampered() {
    let w = setup();
    linear(&w, 3);
    w.snapshots.tamper_manifest(id(3), |e| {
        e.clear();
    });
    let r = do_verify(&w);
    assert_eq!(r.problems.len(), 1, "{:?}", r.problems);
}

#[test]
fn verify_corrupt_blob_is_reported() {
    let w = setup();
    linear(&w, 1);
    w.blobs.corrupt(&digest_of(b"a1\n"), b"tampered".to_vec());
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(problems_contain(&r, "corrupt"), "{:?}", r.problems);
    assert!(problems_contain(
        &r,
        &agent_undo_domain::hash::to_hex(&digest_of(b"a1\n"))
    ));
    // Still referenced, so not reported as missing.
    assert!(!problems_contain(&r, "missing"));
}

#[test]
fn verify_missing_referenced_blob_is_reported() {
    let w = setup();
    linear(&w, 2);
    let d = digest_of(b"b0\n");
    w.blobs.remove(&d).unwrap();
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(
        problems_contain(&r, "referenced but missing"),
        "{:?}",
        r.problems
    );
    assert!(problems_contain(&r, &agent_undo_domain::hash::to_hex(&d)));
    assert_eq!(r.blobs_checked, 3); // a0, a1, a2 remain
}

#[test]
fn verify_blob_referenced_only_by_a_change_set_is_checked() {
    let w = setup();
    linear(&w, 1);
    // a0 is referenced by checkpoint 1's manifest and checkpoint 2's change `before`.
    // Delete b0 as a control and a0: both missing.
    w.blobs.remove(&digest_of(b"a0\n")).unwrap();
    let r = do_verify(&w);
    assert!(problems_contain(&r, "referenced but missing"));
    assert_eq!(
        r.problems
            .iter()
            .filter(|p| p.contains("referenced but missing"))
            .count(),
        1
    );
}

#[test]
fn verify_missing_checkpoint_files_is_a_problem() {
    let w = setup();
    linear(&w, 3);
    w.snapshots.remove(id(2)).unwrap();
    let r = do_verify(&w);
    assert!(!r.ok());
    assert!(
        problems_contain(&r, "files of checkpoint") && problems_contain(&r, "missing"),
        "{:?}",
        r.problems
    );
    assert_eq!(r.checkpoints_checked, 4);
}

#[test]
fn verify_stray_blob_area_entry_is_only_a_warning() {
    let w = setup();
    linear(&w, 1);
    w.blobs.add_stray("lost+found");
    let r = do_verify(&w);
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("lost+found"));
}

#[test]
fn verify_orphan_snapshot_files_are_only_a_warning() {
    let w = setup();
    linear(&w, 1);
    w.snapshots.begin(id(99)).unwrap().commit().unwrap();
    let r = do_verify(&w);
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("orphan files for checkpoint"));
    assert!(r.warnings[0].contains("99"));
    assert_eq!(r.checkpoints_checked, 2);
}

#[test]
fn verify_counts_pruned_checkpoints_and_stays_ok_after_gc() {
    let w = setup();
    linear(&w, 4);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    let r = do_verify(&w);
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.checkpoints_pruned, 3);
    assert_eq!(r.checkpoints_checked, 2);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r.blobs_unreferenced, 0);
}

#[test]
fn verify_multiple_problems_are_all_reported() {
    let w = setup();
    linear(&w, 2);
    w.blobs.corrupt(&digest_of(b"a2\n"), b"x".to_vec());
    w.blobs.remove(&digest_of(b"b0\n")).unwrap();
    w.snapshots.tamper_manifest(id(1), |e| {
        e.pop();
    });
    let r = do_verify(&w);
    assert!(problems_contain(&r, "corrupt"));
    assert!(problems_contain(&r, "referenced but missing"));
    assert!(problems_contain(&r, "manifest does not match"));
    assert!(r.problems.len() >= 3);
}

#[test]
fn verify_is_read_only() {
    let w = setup();
    linear(&w, 2);
    w.blobs.add_stray("junk");
    let before = state(&w);
    let recs = records(&w);
    do_verify(&w);
    assert_eq!(state(&w), before);
    assert_eq!(records(&w).len(), recs.len());
    assert!(w.events.events().is_empty());
}

#[test]
fn verify_works_while_another_shared_lock_is_held_and_releases_its_own() {
    let w = setup();
    linear(&w, 1);
    let other = w.locks.shared().unwrap();
    assert!(do_verify(&w).ok());
    drop(other);
    // verify released its shared lock, so an exclusive one can be taken.
    let g = w.locks.exclusive().unwrap();
    drop(g);
}

#[test]
fn verify_is_refused_while_an_exclusive_lock_is_held() {
    let w = setup();
    linear(&w, 1);
    let _g = w.locks.exclusive().unwrap();
    let e = w.with_ports(verify).unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
}

// ---------------------------------------------------------------------- gc

#[test]
fn gc_dry_run_reports_and_changes_nothing() {
    let w = setup();
    linear(&w, 5); // checkpoints 1..=6
    let before = state(&w);
    let r = do_gc(&w, RetentionPolicy::KeepLast(2), false);
    assert!(!r.applied);
    assert_eq!(r.checkpoints, vec![id(1), id(2), id(3), id(4)]);
    assert_eq!(r.blobs, 3); // a0, a1, a2
    assert_eq!(r.blob_bytes, 9);
    assert_eq!(r.retained, 2);
    assert_eq!(state(&w), before);
    assert!(pruned(&w).is_empty());
    assert!(w.events.events().is_empty());
    assert!(w.blobs.contains(&digest_of(b"a0\n")));
    assert!(w.snapshots.contains(id(1)));
}

#[test]
fn gc_apply_keep_last_prunes_the_oldest_and_never_the_head() {
    let w = setup();
    linear(&w, 5);
    let r = do_gc(&w, RetentionPolicy::KeepLast(2), true);
    assert!(r.applied);
    assert_eq!(r.checkpoints, vec![id(1), id(2), id(3), id(4)]);
    assert_eq!(r.retained, 2);
    assert_eq!(pruned(&w), vec![1, 2, 3, 4]);
    let recs = records(&w);
    assert_eq!(recs.len(), 6, "records stay in the chain");
    assert!(!w.journal.load().unwrap().is_pruned(id(6)));
    assert!(!w.journal.load().unwrap().is_pruned(id(5)));
}

#[test]
fn gc_apply_deletes_snapshot_files_of_pruned_checkpoints_only() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    for n in 1..=4 {
        assert!(!w.snapshots.contains(id(n)), "checkpoint {n} files remain");
    }
    assert!(w.snapshots.contains(id(5)));
    assert!(w.snapshots.contains(id(6)));
}

#[test]
fn gc_apply_deletes_unreferenced_blobs_and_keeps_referenced_ones() {
    let w = setup();
    linear(&w, 5);
    let r = do_gc(&w, RetentionPolicy::KeepLast(2), true);
    assert_eq!(r.blobs, 3);
    assert_eq!(r.blob_bytes, 9);
    for gone in [b"a0\n", b"a1\n", b"a2\n"] {
        assert!(!w.blobs.contains(&digest_of(gone)));
    }
    // a3 is only the `before` side of retained checkpoint 5's change; a4 and a5 are
    // in retained manifests; b0 is shared with the pruned baseline.
    for kept in [b"a3\n", b"a4\n", b"a5\n", b"b0\n"] {
        assert!(w.blobs.contains(&digest_of(kept)));
    }
    assert_eq!(w.blobs.count(), 4);
}

#[test]
fn gc_apply_emits_pruned_and_collected_events_exactly_once() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    assert_eq!(
        w.events.events(),
        vec![
            Event::Domain(DomainEvent::CheckpointsPruned {
                ids: vec![id(1), id(2), id(3), id(4)]
            }),
            Event::GarbageCollected {
                checkpoints: 4,
                blobs: 3
            },
        ]
    );
}

#[test]
fn gc_leaves_a_verifiable_store_and_the_newest_checkpoint_undoable() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    let v = do_verify(&w);
    assert!(v.ok(), "{:?}", v.problems);
    assert_eq!(v.blobs_unreferenced, 0);

    assert_eq!(w.tree.read("a.txt").unwrap(), b"a5\n");
    let rep = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(6)), false))
        .unwrap();
    assert!(rep.refused.is_none());
    assert_eq!(rep.applied(), 1);
    assert_eq!(w.tree.read("a.txt").unwrap(), b"a4\n");
    let v = do_verify(&w);
    assert!(v.ok(), "{:?}", v.problems);
}

#[test]
fn gc_keeps_the_blobs_needed_to_undo_the_oldest_retained_checkpoint() {
    let w = setup();
    linear(&w, 5);
    // Undo 5 needs a3, which only checkpoint 5's change set references.
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    w.tree.write("a.txt", b"a4\n"); // as if 6 were already undone
    let rep = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(5)), false))
        .unwrap();
    assert!(rep.refused.is_none(), "{:?}", rep.refused);
    assert_eq!(w.tree.read("a.txt").unwrap(), b"a3\n");
}

#[test]
fn gc_pruned_checkpoints_cannot_be_undone_or_diffed() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(2)), false))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    let e = w.with_ports(|p| diff_checkpoint(p, id(2))).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    let e = w
        .with_ports(|p| plan_undo(p, &Selector::Checkpoint(id(3))))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
}

#[test]
fn gc_second_run_is_a_noop_without_events() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    w.events.clear();
    let before = state(&w);
    let r = do_gc(&w, RetentionPolicy::KeepLast(2), true);
    assert!(r.checkpoints.is_empty());
    assert_eq!(r.blobs, 0);
    assert_eq!(r.blob_bytes, 0);
    assert_eq!(r.retained, 2);
    assert_eq!(state(&w).0, before.0);
    assert_eq!(state(&w).1, before.1);
    assert_eq!(pruned(&w), vec![1, 2, 3, 4]);
    assert!(
        w.events.events().is_empty(),
        "a gc that removed nothing must not announce anything: {:?}",
        w.events.events()
    );
}

#[test]
fn gc_keep_last_one_keeps_only_the_head() {
    let w = setup();
    linear(&w, 5);
    let r = do_gc(&w, RetentionPolicy::KeepLast(1), true);
    assert_eq!(r.checkpoints, vec![id(1), id(2), id(3), id(4), id(5)]);
    assert_eq!(r.retained, 1);
    assert_eq!(pruned(&w), vec![1, 2, 3, 4, 5]);
    assert!(w.snapshots.contains(id(6)));
    // Head manifest: a5, b0; head change a4 -> a5.
    assert_eq!(w.blobs.count(), 3);
    let v = do_verify(&w);
    assert!(v.ok(), "{:?}", v.problems);
    assert_eq!(v.checkpoints_checked, 1);
    assert_eq!(v.checkpoints_pruned, 5);
}

#[test]
fn gc_keep_last_more_than_exists_prunes_nothing() {
    let w = setup();
    linear(&w, 3);
    let before = state(&w);
    let r = do_gc(&w, RetentionPolicy::KeepLast(100), true);
    assert!(r.checkpoints.is_empty());
    assert_eq!(r.blobs, 0);
    assert_eq!(r.retained, 4);
    assert_eq!(state(&w).0, before.0);
    assert_eq!(state(&w).1, before.1);
    assert!(pruned(&w).is_empty());
    assert!(
        gc_events(&w)
            .iter()
            .all(|e| !matches!(e, Event::Domain(DomainEvent::CheckpointsPruned { .. })))
    );
}

#[test]
fn gc_single_checkpoint_journal_prunes_nothing() {
    let w = setup();
    w.tree.write("a.txt", b"only\n");
    baseline(&w);
    w.events.clear();
    for policy in [RetentionPolicy::KeepLast(1), RetentionPolicy::OlderThan(0)] {
        let r = do_gc(&w, policy, true);
        assert!(r.checkpoints.is_empty());
        assert_eq!(r.retained, 1);
    }
    assert!(w.snapshots.contains(id(1)));
    assert!(pruned(&w).is_empty());
    assert_eq!(w.blobs.count(), 1);
    assert!(
        !w.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::Domain(DomainEvent::CheckpointsPruned { .. })))
    );
    assert!(do_verify(&w).ok());
}

#[test]
fn gc_older_than_with_ticking_clock_splits_history() {
    let w = setup();
    linear(&w, 5); // checkpoints at T0, T0+10s, .. T0+50s; gc reads T0+60s
    let recs = records(&w);
    let t_now_estimate = recs[5].time_ns + 10_000_000_000;
    assert_eq!(recs[1].time_ns - recs[0].time_ns, 10_000_000_000);
    // cutoff = now - 25s = T0+35s: checkpoints at 0,10,20,30 are older.
    let age = t_now_estimate - (recs[3].time_ns + 5_000_000_000);
    let r = do_gc(&w, RetentionPolicy::OlderThan(age), true);
    assert_eq!(r.checkpoints, vec![id(1), id(2), id(3), id(4)]);
    assert_eq!(r.retained, 2);
    assert_eq!(pruned(&w), vec![1, 2, 3, 4]);
    assert_eq!(
        gc_events(&w),
        vec![
            Event::Domain(DomainEvent::CheckpointsPruned {
                ids: vec![id(1), id(2), id(3), id(4)]
            }),
            Event::GarbageCollected {
                checkpoints: 4,
                blobs: 3
            }
        ]
    );
    assert!(do_verify(&w).ok());
}

#[test]
fn gc_older_than_zero_still_keeps_the_head() {
    let w = setup();
    linear(&w, 3);
    let r = do_gc(&w, RetentionPolicy::OlderThan(0), true);
    assert_eq!(r.checkpoints, vec![id(1), id(2), id(3)]);
    assert_eq!(r.retained, 1);
    assert!(w.snapshots.contains(id(4)));
    assert!(do_verify(&w).ok());
}

#[test]
fn gc_older_than_huge_age_prunes_nothing() {
    let w = setup();
    linear(&w, 3);
    let r = do_gc(&w, RetentionPolicy::OlderThan(i64::MAX / 2), true);
    assert!(r.checkpoints.is_empty());
    assert_eq!(r.retained, 4);
    assert!(pruned(&w).is_empty());
}

#[test]
fn gc_older_than_dry_run_changes_nothing() {
    let w = setup();
    linear(&w, 4);
    let before = state(&w);
    let r = do_gc(&w, RetentionPolicy::OlderThan(0), false);
    assert_eq!(r.checkpoints.len(), 4);
    assert!(!r.applied);
    assert_eq!(state(&w), before);
    assert!(pruned(&w).is_empty());
}

#[test]
fn gc_successive_runs_prune_only_not_yet_pruned_checkpoints() {
    let w = setup();
    linear(&w, 5);
    do_gc(&w, RetentionPolicy::KeepLast(3), true);
    assert_eq!(pruned(&w), vec![1, 2, 3]);
    w.events.clear();
    let r = do_gc(&w, RetentionPolicy::KeepLast(1), true);
    assert_eq!(r.checkpoints, vec![id(4), id(5)]);
    assert_eq!(pruned(&w), vec![1, 2, 3, 4, 5]);
    assert_eq!(
        w.events.events()[0],
        Event::Domain(DomainEvent::CheckpointsPruned {
            ids: vec![id(4), id(5)]
        })
    );
}

#[test]
fn gc_removes_unreferenced_blobs_even_when_no_checkpoint_is_pruned() {
    let w = setup();
    linear(&w, 2);
    let junk = w.blobs.put(b"orphaned blob").unwrap();
    let r = do_gc(&w, RetentionPolicy::KeepLast(10), true);
    assert!(r.checkpoints.is_empty());
    assert_eq!(r.blobs, 1);
    assert_eq!(r.blob_bytes, b"orphaned blob".len() as u64);
    assert!(!w.blobs.contains(&junk));
    assert_eq!(
        w.events.events(),
        vec![Event::GarbageCollected {
            checkpoints: 0,
            blobs: 1
        }]
    );
    assert!(do_verify(&w).ok());
}

#[test]
fn gc_dry_run_reports_unreferenced_blobs_without_deleting_them() {
    let w = setup();
    linear(&w, 1);
    let junk = w.blobs.put(b"orphaned blob").unwrap();
    let r = do_gc(&w, RetentionPolicy::KeepLast(10), false);
    assert_eq!(r.blobs, 1);
    assert!(w.blobs.contains(&junk));
    assert!(w.events.events().is_empty());
}

#[test]
fn gc_on_empty_journal_has_nothing_to_do() {
    let w = setup();
    let r = do_gc(&w, RetentionPolicy::KeepLast(1), false);
    assert!(r.checkpoints.is_empty());
    assert_eq!(r.retained, 0);
    assert_eq!(r.blobs, 0);
}

#[test]
fn gc_is_refused_while_an_exclusive_lock_is_held() {
    let w = setup();
    linear(&w, 3);
    let before = state(&w);
    let _g = w.locks.exclusive().unwrap();
    let e = w
        .with_ports(|p| gc(p, RetentionPolicy::KeepLast(1), true))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    drop(_g);
    assert_eq!(state(&w), before);
    assert!(pruned(&w).is_empty());
}

#[test]
fn gc_is_refused_while_a_shared_lock_is_held() {
    let w = setup();
    linear(&w, 3);
    let _g = w.locks.shared().unwrap();
    let e = w
        .with_ports(|p| gc(p, RetentionPolicy::KeepLast(1), false))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    assert!(w.events.events().is_empty());
}

#[test]
fn gc_releases_its_exclusive_lock() {
    let w = setup();
    linear(&w, 3);
    do_gc(&w, RetentionPolicy::KeepLast(1), true);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn gc_fails_without_deleting_when_a_retained_checkpoint_is_missing_its_files() {
    let w = setup();
    linear(&w, 4);
    w.snapshots.remove(id(5)).unwrap(); // the head
    let blobs_before = w.blobs.count();
    for apply in [false, true] {
        let e = w
            .with_ports(|p| gc(p, RetentionPolicy::KeepLast(2), apply))
            .unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    }
    assert_eq!(w.blobs.count(), blobs_before);
    assert!(pruned(&w).is_empty());
    assert!(w.snapshots.contains(id(1)));
    assert!(gc_events(&w).is_empty());
}

#[test]
fn gc_after_undo_keeps_pre_undo_and_undo_checkpoints_consistent() {
    let w = setup();
    linear(&w, 3); // 1..=4
    w.with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap(); // 5 pre-undo, 6 undo
    assert_eq!(records(&w).len(), 6);
    do_gc(&w, RetentionPolicy::KeepLast(2), true);
    let v = do_verify(&w);
    assert!(v.ok(), "{:?}", v.problems);
    assert_eq!(v.checkpoints_checked, 2);
    // The undo itself is still undoable (redo).
    let rep = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(6)), false))
        .unwrap();
    assert!(rep.refused.is_none());
    assert_eq!(w.tree.read("a.txt").unwrap(), b"a3\n");
}

// ------------------------------------------------------------- diff: texts

#[test]
fn diff_created_modified_deleted_text_files_give_unified_diffs() {
    let w = setup();
    w.tree.write("mod.txt", b"one\ntwo\nthree\n");
    w.tree.write("del.txt", b"bye\n");
    baseline(&w);
    w.tree.write("mod.txt", b"one\nTWO\nthree\n");
    w.tree.remove("del.txt");
    w.tree.write("new.txt", b"hello\n");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(r.record.id, id(2));
    assert!(!r.truncated);
    assert_eq!(r.changes.len(), 3);

    let created = view(&r, "new.txt");
    assert_eq!(created.change.kind(), ChangeKind::Created);
    let t = text_of(created);
    assert!(t.starts_with("@@"), "{t}");
    assert!(t.contains("+hello"), "{t}");
    assert!(!t.lines().any(|l| l.starts_with('-')), "{t}");

    let modified = view(&r, "mod.txt");
    assert_eq!(modified.change.kind(), ChangeKind::Modified);
    let t = text_of(modified);
    assert!(t.contains("-two"), "{t}");
    assert!(t.contains("+TWO"), "{t}");
    assert!(t.contains(" one"), "context line expected: {t}");

    let deleted = view(&r, "del.txt");
    assert_eq!(deleted.change.kind(), ChangeKind::Deleted);
    let t = text_of(deleted);
    assert!(t.contains("-bye"), "{t}");
    assert!(!t.lines().any(|l| l.starts_with('+')), "{t}");
}

#[test]
fn diff_of_the_baseline_lists_every_file_as_created() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    w.tree.write("b.txt", b"b\n");
    baseline(&w);
    let r = diff(&w, 1);
    assert_eq!(r.changes.len(), 2);
    assert!(
        r.changes
            .iter()
            .all(|c| c.change.kind() == ChangeKind::Created)
    );
    assert!(text_of(view(&r, "a.txt")).contains("+a"));
    assert!(r.renames.is_empty());
    assert!(!r.truncated);
}

#[test]
fn diff_of_a_checkpoint_without_changes_is_empty() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    cp(&w);
    let r = diff(&w, 2);
    assert!(r.changes.is_empty());
    assert!(r.renames.is_empty());
    assert!(!r.truncated);
}

#[test]
fn diff_mode_change_reports_identical_content() {
    let w = setup();
    w.tree.write_mode("run.sh", b"#!/bin/sh\n", 0o644);
    baseline(&w);
    w.tree.chmod("run.sh", 0o755);
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(r.changes.len(), 1);
    let v = view(&r, "run.sh");
    assert_eq!(v.change.kind(), ChangeKind::ModeChanged);
    assert_eq!(v.content, Content::Diff(DiffOutcome::Identical));
}

#[test]
fn diff_only_describes_the_requested_checkpoint() {
    let w = setup();
    w.tree.write("a.txt", b"v0\n");
    baseline(&w);
    w.tree.write("a.txt", b"v1\n");
    cp(&w);
    w.tree.write("a.txt", b"v2\n");
    cp(&w);
    let t2 = diff(&w, 2);
    let t3 = diff(&w, 3);
    let (a, b) = (text_of(view(&t2, "a.txt")), text_of(view(&t3, "a.txt")));
    assert!(a.contains("-v0") && a.contains("+v1"), "{a}");
    assert!(b.contains("-v1") && b.contains("+v2"), "{b}");
}

#[test]
fn diff_binary_file_is_omitted() {
    let w = setup();
    w.tree.write("keep.txt", b"k\n");
    baseline(&w);
    w.tree
        .write("img.bin", &[0x89, b'P', b'N', b'G', 0, 1, 2, 3]);
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(
        view(&r, "img.bin").content,
        Content::Diff(DiffOutcome::Omitted("binary file"))
    );
}

#[test]
fn diff_modified_binary_file_is_omitted() {
    let w = setup();
    w.tree.write("img.bin", &[0, 1, 2]);
    baseline(&w);
    w.tree.write("img.bin", &[0, 1, 2, 3]);
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(
        view(&r, "img.bin").content,
        Content::Diff(DiffOutcome::Omitted("binary file"))
    );
}

#[test]
fn diff_invalid_utf8_is_omitted() {
    let w = setup();
    w.tree.write("latin1.txt", &[b'c', b'a', b'f', 0xE9, b'\n']);
    baseline(&w);
    let r = diff(&w, 1);
    assert_eq!(
        view(&r, "latin1.txt").content,
        Content::Diff(DiffOutcome::Omitted("not valid UTF-8 text"))
    );
}

#[test]
fn diff_large_text_over_the_limit_is_omitted() {
    let w = setup();
    w.tree.write("small.txt", b"s\n");
    baseline(&w);
    w.tree.write("big.txt", "x".repeat(100 * 1024).as_bytes());
    w.tree.write("small.txt", "y".repeat(100 * 1024).as_bytes());
    cp(&w);
    let r = diff(&w, 2);
    for name in ["big.txt", "small.txt"] {
        assert_eq!(
            view(&r, name).content,
            Content::Diff(DiffOutcome::Omitted("file too large for a text diff")),
            "{name}"
        );
    }
}

#[test]
fn diff_text_with_too_many_lines_is_omitted() {
    let w = setup();
    w.tree.write("long.txt", "x\n".repeat(5000).as_bytes());
    baseline(&w);
    let r = diff(&w, 1);
    assert_eq!(
        view(&r, "long.txt").content,
        Content::Diff(DiffOutcome::Omitted("too many lines for a text diff"))
    );
}

#[test]
fn diff_escapes_terminal_control_sequences_in_file_content() {
    let w = setup();
    w.tree.write("evil.txt", b"\x1b[31mred\x1b[0m\n\x07bell\n");
    baseline(&w);
    let r = diff(&w, 1);
    let t = text_of(view(&r, "evil.txt"));
    assert!(!t.contains('\u{1b}'), "raw ESC leaked: {t:?}");
    assert!(!t.contains('\u{7}'), "raw BEL leaked: {t:?}");
    assert!(t.contains("x1b"), "ESC should be shown escaped: {t:?}");
    assert!(t.contains("red"));
}

#[test]
fn diff_escapes_bidi_override_characters() {
    let w = setup();
    w.tree.write("bidi.txt", "a\u{202e}b\n".as_bytes());
    baseline(&w);
    let r = diff(&w, 1);
    let t = text_of(view(&r, "bidi.txt"));
    assert!(!t.contains('\u{202e}'), "{t:?}");
}

#[test]
fn diff_escapes_control_characters_on_the_removed_side_too() {
    let w = setup();
    w.tree.write("evil.txt", b"\x1b]0;title\x07\n");
    baseline(&w);
    w.tree.write("evil.txt", b"clean\n");
    cp(&w);
    let r = diff(&w, 2);
    let t = text_of(view(&r, "evil.txt"));
    assert!(!t.contains('\u{1b}') && !t.contains('\u{7}'), "{t:?}");
    assert!(t.contains("+clean"));
}

// --------------------------------------------------------- diff: withheld

#[test]
fn diff_dot_env_is_withheld_and_secret_never_appears() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    let secret = format!("{}{}", "hunter2-", "pass-value-for-tests");
    w.tree
        .write(".env", format!("PASSWORD={secret}\n").as_bytes());
    cp(&w);
    assert!(
        w.events
            .events()
            .contains(&Event::SensitiveContentWithheld { path: p(".env") })
    );
    let r = diff(&w, 2);
    match &view(&r, ".env").content {
        Content::Withheld(why) => assert!(why.contains("sensitive"), "{why}"),
        other => panic!("expected Withheld, got {other:?}"),
    }
    assert!(!format!("{r:?}").contains(&secret));
    assert!(
        !w.blobs
            .all_bytes()
            .windows(secret.len())
            .any(|x| x == secret.as_bytes())
    );
}

#[test]
fn diff_secret_detected_by_content_is_withheld_and_never_appears() {
    let w = setup();
    w.tree.write("notes.txt", b"nothing here\n");
    baseline(&w);
    let tok = github_token();
    w.tree
        .write("notes.txt", format!("token = {tok}\n").as_bytes());
    cp(&w);
    let r = diff(&w, 2);
    assert!(matches!(
        view(&r, "notes.txt").content,
        Content::Withheld(why) if why.contains("sensitive")
    ));
    let dump = format!("{r:?}");
    assert!(!dump.contains(&tok));
    assert!(!dump.contains("A1b2C3d4E5f6"));
    // The old, harmless text must not leak through a half-shown diff either.
    assert!(!matches!(
        view(&r, "notes.txt").content,
        Content::Diff(DiffOutcome::Text(_))
    ));
}

#[test]
fn diff_new_file_with_secret_content_is_withheld() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    let tok = github_token();
    w.tree
        .write("deploy.sh", format!("export T={tok}\n").as_bytes());
    cp(&w);
    let r = diff(&w, 2);
    assert!(matches!(
        view(&r, "deploy.sh").content,
        Content::Withheld(_)
    ));
    assert!(!format!("{r:?}").contains(&tok));
}

#[test]
fn diff_deleted_sensitive_file_is_withheld() {
    let w = setup();
    let tok = github_token();
    w.tree.write("creds.txt", format!("{tok}\n").as_bytes());
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    w.tree.remove("creds.txt");
    cp(&w);
    let r = diff(&w, 2);
    let v = view(&r, "creds.txt");
    assert_eq!(v.change.kind(), ChangeKind::Deleted);
    assert!(matches!(v.content, Content::Withheld(why) if why.contains("sensitive")));
    assert!(!format!("{r:?}").contains(&tok));
}

#[test]
fn diff_private_key_file_name_is_withheld() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    let header = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
    w.tree
        .write("id_rsa", format!("{header}\nQUJD\n").as_bytes());
    cp(&w);
    let r = diff(&w, 2);
    assert!(matches!(view(&r, "id_rsa").content, Content::Withheld(_)));
    assert!(!format!("{r:?}").contains(&header));
}

#[test]
fn diff_too_large_file_is_withheld() {
    let w = World::with_cap_and_runner(
        100,
        ScriptedRunner::new(|_| {}, RunOutcome::Exited(ExitInfo::Code(0))),
    );
    w.tree.write("small.txt", b"ok\n");
    baseline(&w);
    w.tree.write("huge.dat", &[b'x'; 200]);
    cp(&w);
    let r = diff(&w, 2);
    match &view(&r, "huge.dat").content {
        Content::Withheld(why) => assert!(why.contains("too-large"), "{why}"),
        other => panic!("expected Withheld, got {other:?}"),
    }
    // Deleting it is withheld too.
    w.tree.remove("huge.dat");
    cp(&w);
    let r = diff(&w, 3);
    assert!(matches!(
        view(&r, "huge.dat").content,
        Content::Withheld(why) if why.contains("too-large")
    ));
}

#[test]
fn diff_directories_and_symlinks_are_withheld_with_a_reason() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    w.tree.write("sub/inner.txt", b"inner\n");
    w.tree.symlink("link", b"a.txt");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(view(&r, "sub").content, Content::Withheld("directory"));
    assert_eq!(view(&r, "link").content, Content::Withheld("symlink"));
    assert!(text_of(view(&r, "sub/inner.txt")).contains("+inner"));
}

#[test]
fn diff_symlink_retarget_is_withheld() {
    let w = setup();
    w.tree.symlink("link", b"a.txt");
    baseline(&w);
    w.tree.symlink("link", b"b.txt");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(view(&r, "link").change.kind(), ChangeKind::Modified);
    assert_eq!(view(&r, "link").content, Content::Withheld("symlink"));
}

#[test]
fn diff_file_replaced_by_directory_is_withheld() {
    let w = setup();
    w.tree.write("thing", b"was a file\n");
    baseline(&w);
    w.tree.remove("thing");
    w.tree.mkdir("thing", 0o755);
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(view(&r, "thing").content, Content::Withheld("directory"));
    assert!(!format!("{r:?}").contains("was a file"));
}

#[test]
fn diff_special_files_are_withheld() {
    let w = setup();
    w.tree.write("a.txt", b"a\n");
    baseline(&w);
    w.tree.special("fifo");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(
        view(&r, "fifo").content,
        Content::Withheld("content was not recorded")
    );
}

// --------------------------------------------------------- diff: renames

#[test]
fn diff_detects_a_moved_file_as_a_rename() {
    let w = setup();
    w.tree.write("src/old.txt", b"same content\n");
    w.tree.write("other.txt", b"other\n");
    baseline(&w);
    w.tree.rename("src/old.txt", "dst/new.txt");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(
        r.renames,
        vec![Rename {
            from: p("src/old.txt"),
            to: p("dst/new.txt")
        }]
    );
    // Both sides are still listed as individual changes.
    assert_eq!(view(&r, "src/old.txt").change.kind(), ChangeKind::Deleted);
    assert_eq!(view(&r, "dst/new.txt").change.kind(), ChangeKind::Created);
}

#[test]
fn diff_move_with_edit_is_not_a_rename() {
    let w = setup();
    w.tree.write("old.txt", b"content\n");
    baseline(&w);
    w.tree.remove("old.txt");
    w.tree.write("new.txt", b"content edited\n");
    cp(&w);
    assert!(diff(&w, 2).renames.is_empty());
}

#[test]
fn diff_empty_files_are_never_renames() {
    let w = setup();
    w.tree.write("old.txt", b"");
    baseline(&w);
    w.tree.remove("old.txt");
    w.tree.write("new.txt", b"");
    cp(&w);
    assert!(diff(&w, 2).renames.is_empty());
}

#[test]
fn diff_several_moves_pair_up_in_path_order() {
    let w = setup();
    w.tree.write("a.txt", b"dup\n");
    w.tree.write("b.txt", b"dup\n");
    baseline(&w);
    w.tree.remove("a.txt");
    w.tree.remove("b.txt");
    w.tree.write("x.txt", b"dup\n");
    w.tree.write("y.txt", b"dup\n");
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(
        r.renames,
        vec![
            Rename {
                from: p("a.txt"),
                to: p("x.txt")
            },
            Rename {
                from: p("b.txt"),
                to: p("y.txt")
            },
        ]
    );
}

// ------------------------------------------------------ diff: limits/errors

#[test]
fn diff_caps_text_diffs_and_marks_the_rest_path_only() {
    let w = setup();
    w.tree.write("keep.txt", b"k\n");
    baseline(&w);
    let total = MAX_TEXT_DIFFS + 5;
    for i in 0..total {
        w.tree
            .write(&format!("f{i:04}.txt"), format!("content {i}\n").as_bytes());
    }
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(r.changes.len(), total);
    assert!(!r.truncated);
    let texts = r
        .changes
        .iter()
        .filter(|c| matches!(c.content, Content::Diff(DiffOutcome::Text(_))))
        .count();
    assert_eq!(texts, MAX_TEXT_DIFFS);
    let limit = Content::Diff(DiffOutcome::Omitted(
        "diff limit reached; showing paths only",
    ));
    let omitted: Vec<&ChangeView> = r.changes.iter().filter(|c| c.content == limit).collect();
    assert_eq!(omitted.len(), 5);
    // The first ones (in path order) got diffs, the last ones did not.
    assert!(matches!(
        r.changes[0].content,
        Content::Diff(DiffOutcome::Text(_))
    ));
    for v in &r.changes[MAX_TEXT_DIFFS..] {
        assert_eq!(v.content, limit);
    }
}

#[test]
fn diff_exactly_at_the_cap_has_no_omissions() {
    let w = setup();
    w.tree.write("keep.txt", b"k\n");
    baseline(&w);
    for i in 0..MAX_TEXT_DIFFS {
        w.tree.write(&format!("f{i:04}.txt"), b"x\n");
    }
    cp(&w);
    let r = diff(&w, 2);
    assert_eq!(r.changes.len(), MAX_TEXT_DIFFS);
    assert!(
        r.changes
            .iter()
            .all(|c| matches!(c.content, Content::Diff(DiffOutcome::Text(_))))
    );
}

#[test]
fn diff_withheld_changes_do_not_consume_the_text_diff_budget() {
    let w = setup();
    w.tree.write("keep.txt", b"k\n");
    baseline(&w);
    w.tree.symlink("0link-a", b"keep.txt");
    w.tree.symlink("0link-b", b"keep.txt");
    for i in 0..=MAX_TEXT_DIFFS {
        w.tree.write(&format!("f{i:04}.txt"), b"x\n");
    }
    cp(&w);
    let r = diff(&w, 2);
    let texts = r
        .changes
        .iter()
        .filter(|c| matches!(c.content, Content::Diff(DiffOutcome::Text(_))))
        .count();
    let withheld = r
        .changes
        .iter()
        .filter(|c| matches!(c.content, Content::Withheld("symlink")))
        .count();
    assert_eq!(texts, MAX_TEXT_DIFFS);
    assert_eq!(withheld, 2);
    assert_eq!(
        r.changes
            .iter()
            .filter(|c| matches!(c.content, Content::Diff(DiffOutcome::Omitted(_))))
            .count(),
        1
    );
}

#[test]
fn diff_unknown_checkpoint_is_a_usage_error() {
    let w = setup();
    linear(&w, 1);
    let e = w.with_ports(|p| diff_checkpoint(p, id(99))).unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
}

#[test]
fn diff_on_an_empty_journal_is_a_usage_error() {
    let w = setup();
    let e = w.with_ports(|p| diff_checkpoint(p, id(1))).unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
}

#[test]
fn diff_pruned_checkpoint_is_refused() {
    let w = setup();
    linear(&w, 3);
    do_gc(&w, RetentionPolicy::KeepLast(1), true);
    let e = w.with_ports(|p| diff_checkpoint(p, id(2))).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    // The head is still diffable.
    assert!(!diff(&w, 4).changes.is_empty());
}

#[test]
fn diff_missing_checkpoint_files_is_an_integrity_error() {
    let w = setup();
    linear(&w, 2);
    w.snapshots.remove(id(2)).unwrap();
    let e = w.with_ports(|p| diff_checkpoint(p, id(2))).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn diff_missing_blob_is_an_integrity_error() {
    let w = setup();
    linear(&w, 1);
    w.blobs.remove(&digest_of(b"a1\n")).unwrap();
    let e = w.with_ports(|p| diff_checkpoint(p, id(2))).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn diff_is_refused_while_an_exclusive_lock_is_held() {
    let w = setup();
    linear(&w, 1);
    let _g = w.locks.exclusive().unwrap();
    let e = w.with_ports(|p| diff_checkpoint(p, id(2))).unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
}

#[test]
fn diff_is_read_only() {
    let w = setup();
    linear(&w, 2);
    let before = state(&w);
    diff(&w, 2);
    diff(&w, 3);
    assert_eq!(state(&w), before);
    assert!(!w.locks.is_exclusively_held());
}

// ------------------------------------------ journal integrity via use cases

type Edit = fn(&mut Vec<CheckpointRecord>);

fn tampered() -> (World, Vec<CheckpointRecord>) {
    let w = setup();
    linear(&w, 2);
    let mut saved = Vec::new();
    w.journal.tamper(|r| saved = r.clone());
    w.journal.tamper(|r| r[1].counts.created += 1);
    assert!(matches!(w.journal.load(), Err(Error::Integrity(_))));
    (w, saved)
}

fn restore_journal(w: &World, saved: Vec<CheckpointRecord>) {
    w.journal.tamper(|r| *r = saved);
}

#[test]
fn journal_load_reports_integrity_for_each_kind_of_tampering() {
    let edits: Vec<(&str, Edit)> = vec![
        ("counts", |r| r[1].counts.modified += 1),
        ("remove", |r| {
            r.remove(1);
        }),
        ("swap", |r| r.swap(1, 2)),
        ("hash", |r| r[2].hash = [1; 32]),
        ("prev", |r| r[1].prev = [1; 32]),
        ("truncate-first", |r| {
            r.remove(0);
        }),
    ];
    for (name, edit) in edits {
        let w = setup();
        linear(&w, 2);
        w.journal.tamper(edit);
        assert!(
            matches!(w.journal.load(), Err(Error::Integrity(_))),
            "{name} was not detected"
        );
    }
}

#[test]
fn tampered_journal_makes_manual_checkpoint_fail_with_integrity() {
    let (w, saved) = tampered();
    let before = state(&w);
    let e = w
        .with_ports(|p| manual_checkpoint(p, None, false))
        .err()
        .unwrap();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    assert_eq!(e.exit_code(), agent_undo_app::error::exit::INTEGRITY);
    assert_eq!(state(&w), before);
    restore_journal(&w, saved);
    assert_eq!(records(&w).len(), 3, "nothing was appended");
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn tampered_journal_makes_run_fail_with_integrity_and_never_runs_the_command() {
    let (w, saved) = tampered();
    w.tree.write("c.txt", b"c\n");
    let before = state(&w);
    let e = w
        .with_ports(|p| {
            run_command(
                p,
                RunCommand {
                    args: vec![b"true".to_vec()],
                    label: None,
                    new_session: false,
                    env: EnvPolicy::Inherit,
                },
            )
        })
        .unwrap_err();
    assert!(
        matches!(e, RunFailure::Internal(Error::Integrity(_))),
        "{e:?}"
    );
    assert!(w.runner.requests().is_empty());
    assert_eq!(state(&w), before);
    restore_journal(&w, saved);
    assert_eq!(records(&w).len(), 3);
}

#[test]
fn tampered_journal_makes_undo_fail_with_integrity_and_leaves_the_tree_alone() {
    let (w, saved) = tampered();
    let before = state(&w);
    let tree_before = w.tree.read("a.txt");
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    assert_eq!(w.tree.read("a.txt"), tree_before);
    assert_eq!(state(&w), before);
    assert!(!w.events.events().iter().any(|e| matches!(
        e,
        Event::ReversalApplied { .. } | Event::ReversalRefused { .. }
    )));
    restore_journal(&w, saved);
    assert_eq!(records(&w).len(), 3, "no pre-undo checkpoint was recorded");
}

#[test]
fn tampered_journal_makes_plan_undo_fail_with_integrity() {
    let (w, _) = tampered();
    let e = w.with_ports(|p| plan_undo(p, &Selector::Last)).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn tampered_journal_makes_gc_fail_with_integrity_and_prunes_nothing() {
    let (w, saved) = tampered();
    let before = state(&w);
    for apply in [false, true] {
        let e = w
            .with_ports(|p| gc(p, RetentionPolicy::KeepLast(1), apply))
            .unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    }
    assert_eq!(state(&w), before);
    assert!(gc_events(&w).is_empty());
    restore_journal(&w, saved);
    assert!(pruned(&w).is_empty());
    assert!(w.snapshots.contains(id(1)));
}

#[test]
fn tampered_journal_makes_status_fail_with_integrity() {
    let (w, _) = tampered();
    let e = w.with_ports(status).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn tampered_journal_makes_log_and_diff_fail_with_integrity() {
    let (w, _) = tampered();
    let e = w.with_ports(load_log).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    let e = w.with_ports(|p| diff_checkpoint(p, id(1))).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn tampered_journal_makes_baseline_fail_with_integrity_not_already_initialized() {
    let (w, _) = tampered();
    let e = w.with_ports(record_baseline).err().unwrap();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn tampered_journal_is_reported_by_verify_not_raised() {
    let (w, _) = tampered();
    let r = w.with_ports(verify).unwrap();
    assert!(!r.ok());
    assert!(r.problems[0].starts_with("journal:"));
    assert!(w.events.events().is_empty());
}

#[test]
fn restoring_the_journal_makes_every_use_case_work_again() {
    let (w, saved) = tampered();
    restore_journal(&w, saved);
    assert!(do_verify(&w).ok());
    cp(&w);
    assert_eq!(records(&w).len(), 4);
    assert!(w.with_ports(status).is_ok());
}

#[test]
fn journal_repository_round_trips_appended_records_and_pruned_ids() {
    let w = setup();
    linear(&w, 3);
    let j = w.journal.load().unwrap();
    assert_eq!(j.records().len(), 4);
    assert_eq!(j.head().unwrap().id, id(4));
    assert!(j.pruned().is_empty());
    w.journal.save_pruned(&[id(1), id(2)]).unwrap();
    let j = w.journal.load().unwrap();
    assert!(j.is_pruned(id(1)) && j.is_pruned(id(2)));
    assert!(!j.is_pruned(id(3)));
    assert_eq!(j.records().len(), 4);
}
