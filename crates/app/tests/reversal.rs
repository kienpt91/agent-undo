//! Application-level tests for `usecases::reversal` (undo and restore), driven
//! through the in-memory fakes. They assert on the resulting tree, the journal,
//! the emitted events and the returned reports.

use agent_undo_app::error::Error;
use agent_undo_app::events::Event;
use agent_undo_app::fakes::{Node, ScriptedRunner, World};
use agent_undo_app::ports::{BlobStore, JournalRepository, Locker, RunOutcome, SnapshotRepository};
use agent_undo_app::usecases::checkpoint::manual_checkpoint;
use agent_undo_app::usecases::gc::gc;
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::{
    ReversalReport, apply_restore, apply_undo, plan_restore, plan_undo,
};
use agent_undo_domain::change::EntrySource;
use agent_undo_domain::entry::Entry;
use agent_undo_domain::hash::sha256;
use agent_undo_domain::journal::{
    CheckpointId, CheckpointRecord, CkptKind, DomainEvent, ExitInfo, Journal, RetentionPolicy,
    Selector, SessionId,
};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Op, Outcome, Plan, PlanItem, Status};

// ------------------------------------------------------------------ helpers

fn setup() -> World {
    World::new()
}

fn setup_with_cap(cap: u64) -> World {
    World::with_cap_and_runner(
        cap,
        ScriptedRunner::new(|_| {}, RunOutcome::Exited(ExitInfo::Code(0))),
    )
}

fn id(n: u64) -> CheckpointId {
    CheckpointId::new(n).unwrap()
}

fn rp(s: &str) -> RelPath {
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

fn cp_new_session(w: &World) -> CheckpointRecord {
    w.with_ports(|p| manual_checkpoint(p, None, true))
        .unwrap()
        .record
}

fn journal(w: &World) -> Journal {
    w.journal.load().unwrap()
}

fn jlen(w: &World) -> usize {
    journal(w).records().len()
}

fn kinds(w: &World) -> Vec<CkptKind> {
    journal(w).records().iter().map(|r| r.kind).collect()
}

fn undo(w: &World, sel: Selector, force: bool) -> ReversalReport {
    w.with_ports(|p| apply_undo(p, &sel, force)).unwrap()
}

fn undo_last(w: &World) -> ReversalReport {
    undo(w, Selector::Last, false)
}

fn plan(w: &World, sel: Selector) -> Plan {
    w.with_ports(|p| plan_undo(p, &sel)).unwrap()
}

fn restore(w: &World, path: &str, from: u64, force: bool) -> ReversalReport {
    w.with_ports(|p| apply_restore(p, &rp(path), id(from), force))
        .unwrap()
}

fn restore_plan(w: &World, path: &str, from: u64) -> Plan {
    w.with_ports(|p| plan_restore(p, &rp(path), id(from)))
        .unwrap()
}

fn tree_state(w: &World) -> Vec<(String, Node)> {
    w.tree
        .paths()
        .into_iter()
        .map(|p| {
            let n = w.tree.node(&p).unwrap();
            (p, n)
        })
        .collect()
}

fn item<'a>(p: &'a Plan, path: &str) -> &'a PlanItem {
    p.items
        .iter()
        .find(|i| i.path.as_bytes() == path.as_bytes())
        .unwrap_or_else(|| panic!("no plan item for {path}"))
}

fn outcome<'a>(r: &'a ReversalReport, path: &str) -> &'a Outcome {
    let idx = r
        .plan
        .items
        .iter()
        .position(|i| i.path.as_bytes() == path.as_bytes())
        .unwrap_or_else(|| panic!("no plan item for {path}"));
    r.outcomes.get(idx).unwrap()
}

fn item_paths(p: &Plan) -> Vec<String> {
    p.items.iter().map(|i| i.path.display()).collect()
}

fn manifest_entry(w: &World, cp_id: CheckpointId, path: &str) -> Option<Entry> {
    let mut s = w.snapshots.open_manifest(cp_id).unwrap();
    while let Some((p, e)) = s.next_entry().unwrap() {
        if p.as_bytes() == path.as_bytes() {
            return Some(e);
        }
    }
    None
}

fn applied_events(w: &World) -> Vec<(CkptKind, CheckpointId, u64, u64)> {
    w.events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::ReversalApplied {
                kind,
                checkpoint,
                applied,
                skipped,
            } => Some((kind, checkpoint, applied, skipped)),
            _ => None,
        })
        .collect()
}

fn refused_events(w: &World) -> usize {
    w.events
        .events()
        .iter()
        .filter(|e| matches!(e, Event::ReversalRefused { .. }))
        .count()
}

fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// baseline (a = v0) then checkpoint 2 (a = v1); events cleared.
fn simple() -> World {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    w.tree.write("a", b"v1");
    cp(&w);
    w.events.clear();
    w
}

struct Case {
    w: World,
    pre: Vec<(String, Node)>,
    post: Vec<(String, Node)>,
}

/// `init` builds the project, a baseline is recorded, `agent` plays the agent
/// and a checkpoint (#2) records what it did. Events are cleared.
fn case(init: impl FnOnce(&World), agent: impl FnOnce(&World)) -> Case {
    let w = setup();
    init(&w);
    baseline(&w);
    let pre = tree_state(&w);
    agent(&w);
    let post = tree_state(&w);
    let rec = cp(&w);
    assert!(rec.counts.total() > 0, "the scenario must change something");
    w.events.clear();
    Case { w, pre, post }
}

/// Undo goes back to the pre-change tree; undoing the undo goes forward again.
fn assert_round_trip(c: &Case) {
    let first = undo_last(&c.w);
    assert!(first.refused.is_none(), "{:?}", first.refused);
    assert!(first.error.is_none(), "{:?}", first.error);
    assert_eq!(tree_state(&c.w), c.pre, "undo restores the pre-change tree");
    let second = undo_last(&c.w);
    assert!(second.refused.is_none(), "{:?}", second.refused);
    assert!(second.error.is_none(), "{:?}", second.error);
    assert_eq!(
        tree_state(&c.w),
        c.post,
        "undo of the undo restores the post-agent tree"
    );
}

// ------------------------------------------------------- undo per change type

#[test]
fn undo_of_modification_restores_old_content() {
    let w = simple();
    let r = undo_last(&w);
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(r.plan.items.len(), 1);
    let i = item(&r.plan, "a");
    assert_eq!((i.op, &i.status), (Op::Write, &Status::Ready));
    assert_eq!(r.outcomes, vec![Outcome::Applied]);
}

#[test]
fn undo_of_creation_removes_the_file() {
    let c = case(
        |w| w.tree.write("keep", b"k"),
        |w| w.tree.write("new.txt", b"n"),
    );
    let p = plan(&c.w, Selector::Last);
    assert_eq!(item(&p, "new.txt").op, Op::Delete);
    assert_round_trip(&c);
}

#[test]
fn undo_of_deletion_recreates_file_with_content_and_mode() {
    let c = case(
        |w| w.tree.write_mode("tool.sh", b"#!/bin/sh", 0o755),
        |w| w.tree.remove("tool.sh"),
    );
    let r = undo_last(&c.w);
    assert_eq!(c.w.tree.read("tool.sh"), Some(b"#!/bin/sh".to_vec()));
    assert_eq!(c.w.tree.mode("tool.sh"), Some(0o755));
    assert_eq!(tree_state(&c.w), c.pre);
    assert_eq!(r.outcomes, vec![Outcome::Applied]);
}

#[test]
fn undo_of_rename_moves_the_file_back() {
    let c = case(
        |w| w.tree.write("mv.txt", b"moveme"),
        |w| w.tree.rename("mv.txt", "moved.txt"),
    );
    let p = plan(&c.w, Selector::Last);
    assert_eq!(item(&p, "moved.txt").op, Op::Delete);
    assert_eq!(item(&p, "mv.txt").op, Op::Write);
    assert_round_trip(&c);
    // Both directions of the round trip ended with the content in the right place.
    assert_eq!(c.w.tree.read("moved.txt"), Some(b"moveme".to_vec()));
    assert!(!c.w.tree.exists("mv.txt"));
}

#[test]
fn undo_of_file_mode_change_restores_mode_only() {
    let c = case(
        |w| w.tree.write_mode("run.sh", b"x", 0o755),
        |w| w.tree.chmod("run.sh", 0o644),
    );
    let p = plan(&c.w, Selector::Last);
    assert_eq!(item(&p, "run.sh").op, Op::Chmod);
    let r = undo_last(&c.w);
    assert_eq!(c.w.tree.mode("run.sh"), Some(0o755));
    assert_eq!(c.w.tree.read("run.sh"), Some(b"x".to_vec()));
    assert_eq!(r.outcomes, vec![Outcome::Applied]);
    assert_eq!(tree_state(&c.w), c.pre);
}

#[test]
fn undo_of_file_mode_change_round_trips() {
    let c = case(
        |w| w.tree.write_mode("run.sh", b"x", 0o755),
        |w| w.tree.chmod("run.sh", 0o600),
    );
    assert_round_trip(&c);
    assert_eq!(c.w.tree.mode("run.sh"), Some(0o600));
}

#[test]
fn undo_of_directory_mode_change_restores_mode() {
    let c = case(
        |w| {
            w.tree.mkdir("d", 0o755);
            w.tree.write("d/f", b"f");
        },
        |w| w.tree.chmod("d", 0o700),
    );
    let p = plan(&c.w, Selector::Last);
    assert_eq!(item(&p, "d").op, Op::Chmod);
    assert_round_trip(&c);
}

#[test]
fn undo_of_symlink_retarget_restores_old_target() {
    let c = case(
        |w| {
            w.tree.write("a", b"a");
            w.tree.symlink("link", b"a");
        },
        |w| {
            w.tree.remove("link");
            w.tree.symlink("link", b"b");
        },
    );
    let r = undo_last(&c.w);
    assert_eq!(
        c.w.tree.node("link"),
        Some(Node::Symlink {
            target: b"a".to_vec()
        })
    );
    assert_eq!(r.outcomes, vec![Outcome::Applied]);
    assert_eq!(tree_state(&c.w), c.pre);
}

#[test]
fn undo_of_symlink_creation_removes_it() {
    let c = case(
        |w| w.tree.write("a", b"a"),
        |w| w.tree.symlink("link", b"a"),
    );
    assert_round_trip(&c);
    assert!(c.w.tree.node("link").is_some());
}

#[test]
fn undo_of_symlink_deletion_recreates_it() {
    let c = case(
        |w| {
            w.tree.write("a", b"a");
            w.tree.symlink("link", b"a");
        },
        |w| w.tree.remove("link"),
    );
    let p = plan(&c.w, Selector::Last);
    assert_eq!(item(&p, "link").op, Op::Symlink);
    assert_round_trip(&c);
}

#[test]
fn undo_of_file_replaced_by_symlink_and_back() {
    let c = case(
        |w| {
            w.tree.write("a", b"content");
            w.tree.symlink("l", b"a");
        },
        |w| {
            w.tree.remove("a");
            w.tree.symlink("a", b"l");
            w.tree.remove("l");
            w.tree.write("l", b"now a file");
        },
    );
    assert_round_trip(&c);
}

#[test]
fn undo_of_created_directory_with_nested_files_removes_everything() {
    let c = case(
        |w| w.tree.write("keep", b"k"),
        |w| {
            w.tree.write("new/c.txt", b"c");
            w.tree.write("new/deep/d.txt", b"d");
            w.tree.mkdir("new/empty", 0o755);
        },
    );
    let r = undo_last(&c.w);
    assert_eq!(tree_state(&c.w), c.pre);
    assert!(!c.w.tree.exists("new"));
    assert!(r.outcomes.iter().all(|o| *o == Outcome::Applied));
    assert_eq!(r.outcomes.len(), 5);
}

#[test]
fn undo_of_created_directory_round_trips() {
    let c = case(
        |w| w.tree.write("keep", b"k"),
        |w| {
            w.tree.write("new/c.txt", b"c");
            w.tree.write("new/deep/d.txt", b"d");
        },
    );
    assert_round_trip(&c);
}

#[test]
fn undo_of_deleted_directory_with_files_restores_the_subtree() {
    let c = case(
        |w| {
            w.tree.mkdir("old", 0o750);
            w.tree.write("old/a.txt", b"a");
            w.tree.mkdir("old/deep", 0o700);
            w.tree.write_mode("old/deep/b.txt", b"b", 0o600);
            w.tree.write("other", b"o");
        },
        |w| w.tree.remove("old"),
    );
    let r = undo_last(&c.w);
    assert_eq!(tree_state(&c.w), c.pre);
    assert_eq!(c.w.tree.mode("old"), Some(0o750));
    assert_eq!(c.w.tree.mode("old/deep"), Some(0o700));
    assert_eq!(c.w.tree.mode("old/deep/b.txt"), Some(0o600));
    assert_eq!(r.outcomes.len(), 4);
    assert!(r.outcomes.iter().all(|o| *o == Outcome::Applied));
}

#[test]
fn undo_of_deleted_directory_round_trips() {
    let c = case(
        |w| {
            w.tree.write("old/a.txt", b"a");
            w.tree.write("old/deep/b.txt", b"b");
        },
        |w| w.tree.remove("old"),
    );
    assert_round_trip(&c);
}

#[test]
fn undo_of_file_replaced_by_directory() {
    let c = case(
        |w| w.tree.write("swap", b"was a file"),
        |w| {
            w.tree.remove("swap");
            w.tree.write("swap/inner", b"inner");
        },
    );
    let p = plan(&c.w, Selector::Last);
    let swap = item(&p, "swap");
    assert_eq!(swap.op, Op::Write);
    assert!(swap.replace);
    undo_last(&c.w);
    assert_eq!(tree_state(&c.w), c.pre);
}

#[test]
fn undo_of_the_undo_of_a_file_replaced_by_directory_restores_the_directory() {
    let c = case(
        |w| w.tree.write("swap", b"was a file"),
        |w| {
            w.tree.remove("swap");
            w.tree.write("swap/inner", b"inner");
        },
    );
    assert_round_trip(&c);
}

#[test]
fn undo_of_directory_replaced_by_file() {
    let c = case(
        |w| {
            w.tree.write("dswap/x", b"x");
            w.tree.write("dswap/y/z", b"z");
        },
        |w| {
            w.tree.remove("dswap");
            w.tree.write("dswap", b"now a file");
        },
    );
    let p = plan(&c.w, Selector::Last);
    let d = item(&p, "dswap");
    assert_eq!(d.op, Op::Mkdir);
    assert!(d.replace);
    assert_round_trip(&c);
}

#[test]
fn undo_of_a_rich_mixture_of_changes_round_trips() {
    let c = case(
        |w| {
            w.tree.write("src/main.rs", b"fn main(){}");
            w.tree.write("src/lib.rs", b"lib");
            w.tree.write("README.md", b"readme");
            w.tree.write_mode("run.sh", b"#!/bin/sh", 0o755);
            w.tree.symlink("link", b"README.md");
            w.tree.write("old/a.txt", b"a");
            w.tree.write("old/deep/b.txt", b"b");
            w.tree.write("mv.txt", b"moveme");
            w.tree.write("swap", b"was-file");
            w.tree.write("dswap/x", b"x");
        },
        |w| {
            w.tree.write("src/main.rs", b"fn main(){ changed }");
            w.tree.write("new/c.txt", b"c");
            w.tree.write("new/deep/d.txt", b"d");
            w.tree.remove("old");
            w.tree.rename("mv.txt", "moved.txt");
            w.tree.chmod("run.sh", 0o644);
            w.tree.remove("link");
            w.tree.symlink("link", b"src/lib.rs");
            w.tree.remove("swap");
            w.tree.write("swap/inner", b"i");
            w.tree.remove("dswap");
            w.tree.write("dswap", b"f");
            w.tree.remove("README.md");
        },
    );
    assert_round_trip(&c);
    // and a second full cycle
    assert_eq!(undo_last(&c.w).error, None);
    assert_eq!(tree_state(&c.w), c.pre);
    assert_eq!(undo_last(&c.w).error, None);
    assert_eq!(tree_state(&c.w), c.post);
}

// ------------------------------------------------- directory mode and orders

#[test]
fn restrictive_directory_mode_is_applied_after_children_are_written() {
    let c = case(
        |w| {
            w.tree.mkdir("ro", 0o555);
            w.tree.write("ro/f", b"fixed");
            w.tree.write("ro/g", b"gixed");
        },
        |w| w.tree.remove("ro"),
    );
    let r = undo_last(&c.w);
    assert!(r.error.is_none(), "{:?}", r.error);
    assert_eq!(c.w.tree.mode("ro"), Some(0o555));
    assert_eq!(c.w.tree.read("ro/f"), Some(b"fixed".to_vec()));
    assert_eq!(c.w.tree.read("ro/g"), Some(b"gixed".to_vec()));
    assert_eq!(tree_state(&c.w), c.pre);
}

#[test]
fn nested_restrictive_directory_modes_are_all_restored() {
    let c = case(
        |w| {
            w.tree.mkdir("ro", 0o555);
            w.tree.mkdir("ro/sub", 0o500);
            w.tree.write("ro/sub/f", b"deep");
        },
        |w| w.tree.remove("ro"),
    );
    let r = undo_last(&c.w);
    assert!(r.error.is_none(), "{:?}", r.error);
    assert_eq!(c.w.tree.mode("ro"), Some(0o555));
    assert_eq!(c.w.tree.mode("ro/sub"), Some(0o500));
    assert_eq!(c.w.tree.read("ro/sub/f"), Some(b"deep".to_vec()));
}

#[test]
fn restored_directory_with_mode_0700_keeps_that_mode() {
    let c = case(
        |w| {
            w.tree.mkdir("priv", 0o700);
            w.tree.write("priv/f", b"f");
        },
        |w| w.tree.remove("priv"),
    );
    undo_last(&c.w);
    assert_eq!(c.w.tree.mode("priv"), Some(0o700));
    assert_eq!(tree_state(&c.w), c.pre);
}

#[test]
fn removing_a_directory_with_untracked_content_is_skipped_not_forced() {
    let w = setup();
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.mkdir("n", 0o755);
    let agent_cp = cp(&w);
    w.tree.write("n/mine", b"untracked, written by hand");
    w.events.clear();

    let r = undo_last(&w);
    assert!(r.error.is_none() && r.refused.is_none());
    assert_eq!(item(&r.plan, "n").op, Op::Rmdir);
    assert!(matches!(outcome(&r, "n"), Outcome::Skipped(_)));
    assert_eq!(
        w.tree.read("n/mine"),
        Some(b"untracked, written by hand".to_vec())
    );
    assert!(w.tree.exists("n"));
    let result = r.result.unwrap();
    assert_eq!(applied_events(&w), vec![(CkptKind::Undo, result.id, 0, 1)]);
    // The untracked file was captured by the pre-undo checkpoint, never lost.
    let pre = r.pre_undo.unwrap();
    assert!(manifest_entry(&w, pre.id, "n/mine").is_some());
    assert_eq!(agent_cp.id, id(2));
}

#[test]
fn directory_in_the_way_with_untracked_children_is_skipped() {
    let w = setup();
    w.tree.write("a", b"was a file");
    baseline(&w);
    w.tree.remove("a");
    w.tree.write("a/x", b"x");
    cp(&w);
    w.tree.write("a/mine", b"hand");
    w.events.clear();

    let r = undo_last(&w);
    assert_eq!(*outcome(&r, "a/x"), Outcome::Applied);
    assert!(matches!(outcome(&r, "a"), Outcome::Skipped(_)));
    assert!(!w.tree.exists("a/x"));
    assert_eq!(w.tree.read("a/mine"), Some(b"hand".to_vec()));
    assert!(matches!(w.tree.node("a"), Some(Node::Dir { .. })));
}

// --------------------------------------------------- read-only plan, apply

#[test]
fn plan_undo_never_mutates_tree_journal_snapshots_blobs_or_events() {
    let w = simple();
    let tree = tree_state(&w);
    let n = jlen(&w);
    let snaps = w.snapshots.list().unwrap();
    let blobs = w.blobs.count();
    let events = w.events.events();

    let p = plan(&w, Selector::Last);
    assert_eq!(p.kind, CkptKind::Undo);
    assert_eq!(p.sources, vec![id(2)]);
    assert_eq!(p.items.len(), 1);
    assert_eq!(item(&p, "a").status, Status::Ready);

    assert_eq!(tree_state(&w), tree);
    assert_eq!(jlen(&w), n);
    assert_eq!(w.snapshots.list().unwrap(), snaps);
    assert_eq!(w.blobs.count(), blobs);
    assert_eq!(w.events.events(), events);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn plan_undo_reports_conflicts_without_refusing_or_emitting() {
    let w = simple();
    w.tree.write("a", b"hand");
    let n = jlen(&w);
    let p = plan(&w, Selector::Last);
    assert!(p.has_conflicts());
    assert!(matches!(item(&p, "a").status, Status::NeedsForce(_)));
    assert_eq!(jlen(&w), n);
    assert_eq!(refused_events(&w), 0);
    assert_eq!(w.tree.read("a"), Some(b"hand".to_vec()));
}

#[test]
fn apply_writes_pre_undo_then_undo_checkpoint_with_references() {
    let w = simple();
    let r = undo_last(&w);
    assert_eq!(
        kinds(&w),
        vec![
            CkptKind::Baseline,
            CkptKind::Manual,
            CkptKind::PreUndo,
            CkptKind::Undo
        ]
    );
    let pre = r.pre_undo.clone().unwrap();
    let res = r.result.clone().unwrap();
    assert_eq!(
        (pre.id, pre.kind, pre.reference),
        (id(3), CkptKind::PreUndo, Some(id(2)))
    );
    assert_eq!(
        (res.id, res.kind, res.reference),
        (id(4), CkptKind::Undo, Some(id(2)))
    );
    let j = journal(&w);
    assert_eq!(j.records().get(2), Some(&pre));
    assert_eq!(j.records().get(3), Some(&res));
}

#[test]
fn pre_undo_snapshots_the_state_before_and_undo_the_state_after() {
    let w = simple();
    let r = undo_last(&w);
    let pre = r.pre_undo.unwrap();
    let res = r.result.unwrap();
    let digest = |c: CheckpointId| manifest_entry(&w, c, "a").unwrap().digest().unwrap();
    assert_eq!(digest(pre.id), sha256(b"v1"));
    assert_eq!(digest(res.id), sha256(b"v0"));
    assert_eq!(pre.counts.total(), 0, "nothing changed since checkpoint 2");
    assert_eq!(res.counts.modified, 1);
    assert_eq!(res.counts.total(), 1);
}

#[test]
fn undo_checkpoints_stay_in_the_current_session() {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    w.tree.write("a", b"v1");
    cp(&w);
    w.tree.write("a", b"v2");
    let s2 = cp_new_session(&w);
    assert_eq!(s2.session, SessionId::new(2).unwrap());
    let r = undo_last(&w);
    assert_eq!(r.pre_undo.unwrap().session, s2.session);
    assert_eq!(r.result.unwrap().session, s2.session);
    assert_eq!(journal(&w).current_session(), Some(s2.session));
}

#[test]
fn apply_emits_reversal_applied_once_with_exact_counts() {
    let w = simple();
    let r = undo_last(&w);
    let res = r.result.clone().unwrap();
    assert_eq!(applied_events(&w), vec![(CkptKind::Undo, res.id, 1, 0)]);
    assert_eq!(refused_events(&w), 0);
    assert_eq!((r.applied(), r.skipped()), (1, 0));
}

#[test]
fn apply_emits_checkpoint_events_in_order_before_reversal_applied() {
    let w = simple();
    undo_last(&w);
    let events = w.events.events();
    let pos = |pred: &dyn Fn(&Event) -> bool| events.iter().position(pred).unwrap();
    let pre = pos(&|e| {
        matches!(
            e,
            Event::Domain(DomainEvent::CheckpointRecorded {
                kind: CkptKind::PreUndo,
                ..
            })
        )
    });
    let post = pos(&|e| {
        matches!(
            e,
            Event::Domain(DomainEvent::CheckpointRecorded {
                kind: CkptKind::Undo,
                ..
            })
        )
    });
    let applied = pos(&|e| matches!(e, Event::ReversalApplied { .. }));
    assert!(pre < post && post < applied, "{events:?}");
}

#[test]
fn journal_still_verifies_after_apply_and_snapshots_exist() {
    let w = simple();
    let r = undo_last(&w);
    let j = w.journal.load().unwrap();
    assert_eq!(j.records().len(), 4);
    assert!(w.snapshots.contains(r.pre_undo.unwrap().id));
    assert!(w.snapshots.contains(r.result.unwrap().id));
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn skipped_items_are_counted_separately_from_applied() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    w.tree.write(".env", b"K=1");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    w.tree.write(".env", b"K=2");
    cp(&w);
    // b was already put back by hand.
    w.tree.write("b", b"b0");
    w.events.clear();

    let r = undo_last(&w);
    assert_eq!(*outcome(&r, "a"), Outcome::Applied);
    assert!(matches!(outcome(&r, "b"), Outcome::Skipped(_)));
    assert!(matches!(outcome(&r, ".env"), Outcome::Skipped(_)));
    assert_eq!((r.applied(), r.skipped()), (1, 2));
    assert_eq!(
        applied_events(&w),
        vec![(CkptKind::Undo, r.result.unwrap().id, 1, 2)]
    );
}

#[test]
fn undo_of_undo_round_trips_content_exactly_twice() {
    let w = simple();
    for _ in 0..2 {
        undo_last(&w);
        assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
        let r = undo_last(&w);
        assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
        assert!(r.error.is_none());
    }
    assert_eq!(jlen(&w), 2 + 4 * 2);
}

#[test]
fn last_selects_the_undo_checkpoint_after_an_undo() {
    let w = simple();
    let first = undo_last(&w);
    let res = first.result.unwrap();
    let p = plan(&w, Selector::Last);
    assert_eq!(p.sources, vec![res.id]);
    assert_eq!(item(&p, "a").status, Status::Ready);
    assert_eq!(item(&p, "a").op, Op::Write);
}

#[test]
fn nothing_to_do_records_no_checkpoint_and_emits_nothing() {
    let w = simple();
    w.tree.write("a", b"v0"); // already back at the old state
    w.events.clear();
    let n = jlen(&w);
    let r = undo_last(&w);
    assert_eq!(item(&r.plan, "a").status, Status::AlreadyDone);
    assert!(r.refused.is_none() && r.pre_undo.is_none() && r.result.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
}

#[test]
fn lock_contention_fails_with_locked_and_changes_nothing() {
    let w = simple();
    let tree = tree_state(&w);
    let n = jlen(&w);
    let guard = w.locks.exclusive().unwrap();
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    let e = w.with_ports(|p| plan_undo(p, &Selector::Last)).unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    drop(guard);
    assert_eq!(tree_state(&w), tree);
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    // After the contention is gone the same call succeeds.
    assert!(undo_last(&w).error.is_none());
}

#[test]
fn shared_lock_held_by_a_reader_blocks_apply() {
    let w = simple();
    let guard = w.locks.shared().unwrap();
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    drop(guard);
}

#[test]
fn lock_is_released_after_a_refused_apply() {
    let w = simple();
    w.tree.write("a", b"hand");
    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert!(!w.locks.is_exclusively_held());
}

// ----------------------------------------------------------------- conflicts

#[test]
fn hand_edit_after_the_agent_refuses_and_changes_nothing() {
    let w = simple();
    w.tree.write("a", b"hand");
    w.events.clear();
    let tree = tree_state(&w);
    let n = jlen(&w);

    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert!(r.pre_undo.is_none() && r.result.is_none() && r.error.is_none());
    assert!(r.outcomes.iter().all(|o| *o == Outcome::NotAttempted));
    assert!(matches!(item(&r.plan, "a").status, Status::NeedsForce(_)));
    assert_eq!(tree_state(&w), tree);
    assert_eq!(jlen(&w), n, "no pre-undo checkpoint when refusing");
    assert_eq!(refused_events(&w), 1);
    assert!(applied_events(&w).is_empty());
    assert_eq!(w.events.events().len(), 1, "only the refusal is published");
}

#[test]
fn refusal_event_carries_the_reason_that_is_reported() {
    let w = simple();
    w.tree.write("a", b"hand");
    w.events.clear();
    let r = undo_last(&w);
    let reason = r.refused.unwrap();
    assert_eq!(w.events.events(), vec![Event::ReversalRefused { reason }]);
}

#[test]
fn a_conflict_anywhere_refuses_the_whole_plan() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.tree.write("b", b"hand");
    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert_eq!(
        w.tree.read("a"),
        Some(b"a1".to_vec()),
        "clean path is not touched either"
    );
    assert_eq!(w.tree.read("b"), Some(b"hand".to_vec()));
}

#[test]
fn force_overwrites_hand_edit_and_preserves_it_in_the_pre_undo_checkpoint() {
    let w = simple();
    w.tree.write("a", b"hand");
    w.events.clear();

    let r = undo(&w, Selector::Last, true);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    assert_eq!(refused_events(&w), 0);
    let pre = r.pre_undo.unwrap();
    assert_eq!(pre.kind, CkptKind::PreUndo);
    assert_eq!(pre.counts.modified, 1, "the hand edit shows up as a change");
    assert_eq!(
        manifest_entry(&w, pre.id, "a").unwrap().digest().unwrap(),
        sha256(b"hand")
    );
    assert_eq!(
        applied_events(&w),
        vec![(CkptKind::Undo, r.result.unwrap().id, 1, 0)]
    );
}

#[test]
fn undoing_a_forced_undo_brings_the_hand_edit_back() {
    let w = simple();
    w.tree.write("a", b"hand");
    undo(&w, Selector::Last, true);
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));

    let r = undo_last(&w);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"hand".to_vec()));
}

#[test]
fn last_skips_the_pre_undo_checkpoint_even_when_it_recorded_changes() {
    let w = setup();
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.mkdir("n", 0o755);
    cp(&w);
    w.tree.write("n/mine", b"hand");
    let r = undo_last(&w);
    // pre-undo (#3) recorded the hand-made file; the undo (#4) recorded nothing.
    assert_eq!(r.pre_undo.as_ref().unwrap().counts.created, 1);
    assert_eq!(r.result.as_ref().unwrap().counts.total(), 0);
    assert_eq!(plan(&w, Selector::Last).sources, vec![id(2)]);
}

#[test]
fn deleted_after_the_checkpoint_is_a_conflict_that_force_overrides() {
    let w = simple();
    w.tree.remove("a");
    w.events.clear();
    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, "a").status, Status::NeedsForce(_)));
    let refused = undo_last(&w);
    assert!(refused.refused.is_some());
    assert!(!w.tree.exists("a"));
    assert_eq!(refused_events(&w), 1);

    let forced = undo(&w, Selector::Last, true);
    assert!(forced.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
}

#[test]
fn mode_change_after_the_checkpoint_is_a_conflict() {
    let w = simple();
    w.tree.chmod("a", 0o600);
    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert_eq!(w.tree.mode("a"), Some(0o600));
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));

    let forced = undo(&w, Selector::Last, true);
    assert!(forced.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    assert_eq!(w.tree.mode("a"), Some(0o644));
}

#[test]
fn hand_chmod_over_an_agent_chmod_is_a_conflict() {
    let w = setup();
    w.tree.write_mode("run.sh", b"x", 0o755);
    baseline(&w);
    w.tree.chmod("run.sh", 0o644);
    cp(&w);
    w.tree.chmod("run.sh", 0o700);
    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert_eq!(w.tree.mode("run.sh"), Some(0o700));
    let forced = undo(&w, Selector::Last, true);
    assert!(forced.refused.is_none());
    assert_eq!(w.tree.mode("run.sh"), Some(0o755));
}

#[test]
fn file_created_by_the_agent_and_edited_by_hand_needs_force_and_is_then_deleted() {
    let w = setup();
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.write("new", b"agent");
    cp(&w);
    w.tree.write("new", b"hand edit");
    let r = undo_last(&w);
    assert!(r.refused.is_some());
    assert_eq!(w.tree.read("new"), Some(b"hand edit".to_vec()));
    let forced = undo(&w, Selector::Last, true);
    assert!(forced.refused.is_none());
    assert!(!w.tree.exists("new"));
    assert_eq!(
        manifest_entry(&w, forced.pre_undo.unwrap().id, "new")
            .unwrap()
            .digest()
            .unwrap(),
        sha256(b"hand edit")
    );
}

#[test]
fn path_already_at_the_target_is_reported_already_done_and_skipped() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.tree.write("a", b"a0");
    w.events.clear();

    let p = plan(&w, Selector::Last);
    assert_eq!(item(&p, "a").status, Status::AlreadyDone);
    assert_eq!(item(&p, "a").op, Op::None);
    assert_eq!(item(&p, "b").status, Status::Ready);
    assert!(!p.has_conflicts());

    let r = undo_last(&w);
    assert!(matches!(outcome(&r, "a"), Outcome::Skipped(_)));
    assert_eq!(*outcome(&r, "b"), Outcome::Applied);
    assert_eq!(w.tree.read("a"), Some(b"a0".to_vec()));
    assert_eq!(w.tree.read("b"), Some(b"b0".to_vec()));
    assert_eq!((r.applied(), r.skipped()), (1, 1));
}

#[test]
fn creation_already_removed_by_hand_is_already_done_not_a_conflict() {
    let w = setup();
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.write("new", b"n");
    w.tree.write("other", b"o");
    cp(&w);
    w.tree.remove("new");
    let p = plan(&w, Selector::Last);
    assert_eq!(item(&p, "new").status, Status::AlreadyDone);
    let r = undo_last(&w);
    assert!(r.refused.is_none());
    assert!(!w.tree.exists("other"));
}

#[test]
fn undoing_an_older_checkpoint_that_a_later_one_overwrote_conflicts() {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    w.tree.write("a", b"v1");
    cp(&w);
    w.tree.write("a", b"v2");
    cp(&w);
    w.events.clear();

    let r = undo(&w, Selector::Checkpoint(id(2)), false);
    assert!(r.refused.is_some());
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
    assert_eq!(refused_events(&w), 1);

    let ok = undo(&w, Selector::Checkpoint(id(3)), false);
    assert!(ok.refused.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    assert_eq!(ok.pre_undo.unwrap().reference, Some(id(3)));
}

// ----------------------------------------------------------------- selectors

#[test]
fn session_undo_composes_checkpoints_a_to_b_to_c_back_to_a() {
    let w = setup();
    w.tree.write("a", b"A");
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.write("a", b"B");
    w.tree.write("tmp", b"temporary");
    let c2 = cp(&w);
    w.tree.write("a", b"C");
    w.tree.remove("tmp");
    w.tree.write("c", b"created later");
    let c3 = cp(&w);
    let pre_state = {
        let mut s = tree_state(&w);
        s.retain(|(p, _)| p != "a" && p != "c");
        s
    };
    w.events.clear();

    let p = plan(&w, Selector::Session(None));
    assert_eq!(p.sources, vec![c2.id, c3.id]);
    assert_eq!(item_paths(&p), vec!["a", "c"], "tmp nets out to nothing");

    let r = undo(&w, Selector::Session(None), false);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"A".to_vec()));
    assert!(!w.tree.exists("c"));
    assert!(!w.tree.exists("tmp"));
    assert_eq!(w.tree.read("keep"), Some(b"k".to_vec()));
    let mut now = tree_state(&w);
    now.retain(|(p, _)| p != "a");
    assert_eq!(now, pre_state);
    assert_eq!(r.pre_undo.unwrap().reference, Some(c2.id));
    assert_eq!(
        applied_events(&w),
        vec![(CkptKind::Undo, r.result.unwrap().id, 2, 0)]
    );
}

#[test]
fn session_undo_round_trips() {
    let c = case(
        |w| {
            w.tree.write("a", b"A");
            w.tree.write("gone", b"g");
        },
        |w| {
            w.tree.write("a", b"B");
            w.tree.remove("gone");
        },
    );
    // a second checkpoint in the same session
    c.w.tree.write("a", b"C");
    c.w.tree.write("extra", b"e");
    let post = tree_state(&c.w);
    cp(&c.w);
    let r = undo(&c.w, Selector::Session(None), false);
    assert!(r.error.is_none() && r.refused.is_none());
    assert_eq!(tree_state(&c.w), c.pre);
    undo_last(&c.w);
    assert_eq!(tree_state(&c.w), post);
}

#[test]
fn session_selector_with_an_id_undoes_only_that_session() {
    let w = setup();
    w.tree.write("s1", b"s1-0");
    w.tree.write("s2", b"s2-0");
    baseline(&w);
    w.tree.write("s1", b"s1-1");
    cp(&w);
    w.tree.write("s2", b"s2-1");
    cp_new_session(&w);

    let s1 = SessionId::new(1).unwrap();
    let p = plan(&w, Selector::Session(Some(s1)));
    assert_eq!(p.sources, vec![id(2)]);
    let r = undo(&w, Selector::Session(Some(s1)), false);
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("s1"), Some(b"s1-0".to_vec()));
    assert_eq!(w.tree.read("s2"), Some(b"s2-1".to_vec()));
}

#[test]
fn session_none_means_the_current_session_only() {
    let w = setup();
    w.tree.write("s1", b"s1-0");
    w.tree.write("s2", b"s2-0");
    baseline(&w);
    w.tree.write("s1", b"s1-1");
    cp(&w);
    w.tree.write("s2", b"s2-1");
    let c3 = cp_new_session(&w);
    let p = plan(&w, Selector::Session(None));
    assert_eq!(p.sources, vec![c3.id]);
    undo(&w, Selector::Session(None), false);
    assert_eq!(w.tree.read("s1"), Some(b"s1-1".to_vec()));
    assert_eq!(w.tree.read("s2"), Some(b"s2-0".to_vec()));
}

#[test]
fn session_undo_after_a_plain_undo_is_a_net_no_op() {
    let w = simple();
    undo_last(&w);
    let n = jlen(&w);
    w.events.clear();
    let p = plan(&w, Selector::Session(None));
    assert_eq!(p.sources.len(), 3);
    assert!(p.items.is_empty(), "{:?}", item_paths(&p));
    let r = undo(&w, Selector::Session(None), false);
    assert!(r.result.is_none() && r.pre_undo.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
}

#[test]
fn session_without_checkpoints_is_a_usage_error() {
    let w = simple();
    let sel = Selector::Session(Some(SessionId::new(9).unwrap()));
    let e = w.with_ports(|p| plan_undo(p, &sel)).unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    // A journal holding only the baseline has nothing to undo in session 1.
    let only = setup();
    baseline(&only);
    let e = only
        .with_ports(|p| plan_undo(p, &Selector::Session(None)))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
}

#[test]
fn last_skips_baseline_and_empty_checkpoints() {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    w.tree.write("a", b"v1");
    let c2 = cp(&w);
    let empty = cp(&w);
    assert_eq!(empty.counts.total(), 0);
    assert_eq!(plan(&w, Selector::Last).sources, vec![c2.id]);
}

#[test]
fn last_with_nothing_but_baseline_and_empty_checkpoints_is_a_usage_error() {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    cp(&w);
    w.events.clear();
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2);
    assert_eq!(jlen(&w), 2);
    assert!(w.events.events().is_empty());
}

#[test]
fn last_on_an_empty_journal_is_a_usage_error() {
    let w = setup();
    let e = w.with_ports(|p| plan_undo(p, &Selector::Last)).unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    let e = w
        .with_ports(|p| plan_undo(p, &Selector::Session(None)))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
}

#[test]
fn checkpoint_selector_on_the_baseline_is_a_usage_error() {
    let w = simple();
    let n = jlen(&w);
    let e = w
        .with_ports(|p| plan_undo(p, &Selector::Checkpoint(id(1))))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(1)), true))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    assert_eq!(jlen(&w), n);
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    assert!(w.events.events().is_empty());
}

#[test]
fn checkpoint_selector_with_unknown_id_is_a_usage_error() {
    let w = simple();
    let n = jlen(&w);
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(99)), false))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    let e = w
        .with_ports(|p| plan_undo(p, &Selector::Checkpoint(id(99))))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    assert_eq!(jlen(&w), n);
}

#[test]
fn undoing_a_checkpoint_that_changed_nothing_does_nothing() {
    let w = simple();
    let empty = cp(&w);
    let n = jlen(&w);
    w.events.clear();
    let p = plan(&w, Selector::Checkpoint(empty.id));
    assert!(p.items.is_empty());
    let r = undo(&w, Selector::Checkpoint(empty.id), false);
    assert!(r.pre_undo.is_none() && r.result.is_none() && r.refused.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
}

// -------------------------------------------------------------------- pruned

/// baseline (1), changes in #2 and #3, an empty #4; then `gc` keeps `keep`.
fn pruned_world(keep: usize) -> World {
    let w = setup();
    w.tree.write("a", b"v0");
    baseline(&w);
    w.tree.write("a", b"v1");
    cp(&w);
    w.tree.write("a", b"v2");
    cp(&w);
    cp(&w);
    let rep = w
        .with_ports(|p| gc(p, RetentionPolicy::KeepLast(keep), true))
        .unwrap();
    assert!(rep.applied);
    w.events.clear();
    w
}

#[test]
fn undo_of_a_pruned_checkpoint_is_refused() {
    let w = pruned_world(2);
    let n = jlen(&w);
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Checkpoint(id(2)), false))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    assert_eq!(e.exit_code(), 3);
    let e = w
        .with_ports(|p| plan_undo(p, &Selector::Checkpoint(id(2))))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    assert_eq!(jlen(&w), n);
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
    assert!(w.events.events().is_empty());
}

#[test]
fn session_containing_a_pruned_checkpoint_is_refused() {
    let w = pruned_world(2);
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Session(None), true))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e:?}");
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
}

#[test]
fn last_skips_pruned_checkpoints_and_picks_the_newest_live_one_with_changes() {
    let w = pruned_world(2);
    // #1 and #2 are pruned; #3 has changes; #4 is empty.
    let p = plan(&w, Selector::Last);
    assert_eq!(p.sources, vec![id(3)]);
    let r = undo_last(&w);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
}

#[test]
fn last_with_only_pruned_changes_left_is_a_usage_error() {
    let w = pruned_world(1);
    let e = w.with_ports(|p| plan_undo(p, &Selector::Last)).unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
}

#[test]
fn undo_data_missing_without_a_pruned_mark_is_an_integrity_error() {
    let w = simple();
    w.snapshots.remove(id(2)).unwrap();
    let n = jlen(&w);
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    assert_eq!(e.exit_code(), 5);
    assert_eq!(jlen(&w), n);
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
}

#[test]
fn a_tampered_journal_makes_planning_and_applying_fail_with_integrity() {
    let w = simple();
    w.journal.tamper(|r| {
        if let Some(rec) = r.get_mut(1) {
            rec.entries += 1;
        }
    });
    let e = w.with_ports(|p| plan_undo(p, &Selector::Last)).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    let e = w
        .with_ports(|p| apply_undo(p, &Selector::Last, true))
        .unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    assert_eq!(jlen_raw(&w), 2);
}

fn jlen_raw(w: &World) -> usize {
    // The journal is tampered with, so count through the repository records.
    let mut n = 0;
    w.journal.tamper(|r| n = r.len());
    n
}

// ----------------------------------------------------------------- sensitive

fn token() -> String {
    format!("{}{}", "gh", "p_") + &"aB3dE6gH9k".repeat(4)
}

#[test]
fn undo_never_restores_a_modified_env_file_but_undoes_the_rest() {
    let w = setup();
    w.tree.write(".env", b"KEY=old");
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.write(".env", b"KEY=agent");
    w.tree.write("app", b"v1");
    cp(&w);
    w.events.clear();

    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, ".env").status, Status::NotRestorable(_)));
    assert!(!p.has_conflicts());

    let r = undo_last(&w);
    assert!(r.refused.is_none());
    assert_eq!(w.tree.read(".env"), Some(b"KEY=agent".to_vec()));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(matches!(outcome(&r, ".env"), Outcome::Skipped(_)));
    assert_eq!(*outcome(&r, "app"), Outcome::Applied);
    assert_eq!(
        applied_events(&w),
        vec![(CkptKind::Undo, r.result.unwrap().id, 1, 1)]
    );
}

#[test]
fn deleted_env_file_is_not_recreated() {
    let w = setup();
    w.tree.write(".env", b"KEY=old");
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.remove(".env");
    w.tree.write("app", b"v1");
    cp(&w);
    let r = undo_last(&w);
    assert!(!w.tree.exists(".env"));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(matches!(outcome(&r, ".env"), Outcome::Skipped(_)));
}

#[test]
fn created_env_file_is_not_deleted_by_undo() {
    let w = setup();
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.write(".env", b"KEY=agent-made");
    w.tree.write("app", b"v1");
    cp(&w);
    let r = undo_last(&w);
    assert_eq!(w.tree.read(".env"), Some(b"KEY=agent-made".to_vec()));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(matches!(outcome(&r, ".env"), Outcome::Skipped(_)));
}

#[test]
fn force_does_not_override_sensitive_files() {
    let w = setup();
    w.tree.write(".env", b"KEY=old");
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.write(".env", b"KEY=agent");
    w.tree.write("app", b"v1");
    cp(&w);
    let r = undo(&w, Selector::Last, true);
    assert_eq!(w.tree.read(".env"), Some(b"KEY=agent".to_vec()));
    assert!(matches!(outcome(&r, ".env"), Outcome::Skipped(_)));
}

#[test]
fn only_sensitive_changes_means_nothing_runs_and_nothing_is_recorded() {
    let w = setup();
    w.tree.write(".env", b"KEY=old");
    baseline(&w);
    w.tree.write(".env", b"KEY=agent");
    cp(&w);
    w.events.clear();
    let n = jlen(&w);
    let r = undo_last(&w);
    assert!(r.refused.is_none() && r.pre_undo.is_none() && r.result.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    assert_eq!(w.tree.read(".env"), Some(b"KEY=agent".to_vec()));
}

#[test]
fn secret_in_a_normal_file_is_never_restored_or_overwritten() {
    let w = setup();
    w.tree.write("notes.txt", b"clean notes");
    w.tree.write("app", b"v0");
    baseline(&w);
    let secret_body = format!("token = {}\n", token());
    w.tree.write("notes.txt", secret_body.as_bytes());
    w.tree.write("app", b"v1");
    cp(&w);

    let p = plan(&w, Selector::Last);
    assert!(matches!(
        item(&p, "notes.txt").status,
        Status::NotRestorable(_)
    ));
    let r = undo_last(&w);
    assert_eq!(
        w.tree.read("notes.txt"),
        Some(secret_body.clone().into_bytes())
    );
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(matches!(outcome(&r, "notes.txt"), Outcome::Skipped(_)));
    // The pre-undo checkpoint must not have stored the secret either.
    assert!(!contains_sub(&w.blobs.all_bytes(), token().as_bytes()));
}

#[test]
fn private_key_created_by_the_agent_survives_undo() {
    let w = setup();
    w.tree.write("app", b"v0");
    baseline(&w);
    let key = format!("-----BEGIN {} KEY-----\nabc\n", "RSA PRIVATE");
    w.tree.write("deploy.txt", key.as_bytes());
    w.tree.write("app", b"v1");
    cp(&w);
    let r = undo_last(&w);
    assert_eq!(w.tree.read("deploy.txt"), Some(key.into_bytes()));
    assert!(matches!(outcome(&r, "deploy.txt"), Outcome::Skipped(_)));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(!contains_sub(&w.blobs.all_bytes(), b"PRIVATE"));
}

// ---------------------------------------------------------------- too large

fn big() -> Vec<u8> {
    vec![b'x'; 64]
}

#[test]
fn too_large_before_state_is_not_restorable() {
    let w = setup_with_cap(16);
    w.tree.write("big.bin", &big());
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.write("big.bin", b"tiny");
    w.tree.write("app", b"v1");
    cp(&w);
    let p = plan(&w, Selector::Last);
    assert!(matches!(
        item(&p, "big.bin").status,
        Status::NotRestorable(_)
    ));
    let r = undo_last(&w);
    assert_eq!(w.tree.read("big.bin"), Some(b"tiny".to_vec()));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
    assert!(matches!(outcome(&r, "big.bin"), Outcome::Skipped(_)));
}

#[test]
fn deleted_too_large_file_is_not_recreated() {
    let w = setup_with_cap(16);
    w.tree.write("big.bin", &big());
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.remove("big.bin");
    w.tree.write("app", b"v1");
    cp(&w);
    undo_last(&w);
    assert!(!w.tree.exists("big.bin"));
    assert_eq!(w.tree.read("app"), Some(b"v0".to_vec()));
}

#[test]
fn overwriting_a_current_too_large_file_needs_force() {
    let w = setup_with_cap(16);
    w.tree.write("f", b"small");
    baseline(&w);
    w.tree.write("f", &big());
    cp(&w);
    w.events.clear();

    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, "f").status, Status::NeedsForce(_)));
    let refused = undo_last(&w);
    assert!(refused.refused.is_some());
    assert_eq!(w.tree.read("f"), Some(big()));
    assert_eq!(refused_events(&w), 1);

    let forced = undo(&w, Selector::Last, true);
    assert!(forced.error.is_none());
    assert_eq!(w.tree.read("f"), Some(b"small".to_vec()));
    assert_eq!(applied_events(&w).len(), 1);
}

// ------------------------------------------------------- blocked / hostile

#[test]
fn special_file_in_the_way_is_blocked_even_with_force() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.tree.remove("a");
    w.tree.special("a");
    w.events.clear();

    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, "a").status, Status::Blocked(_)));
    let r = undo(&w, Selector::Last, false);
    // blocked items do not make the plan need --force; the rest is undone
    assert!(r.refused.is_none());
    assert!(matches!(outcome(&r, "a"), Outcome::Skipped(_)));
    assert_eq!(w.tree.node("a"), Some(Node::Special));
    assert_eq!(w.tree.read("b"), Some(b"b0".to_vec()));
}

#[test]
fn special_file_in_the_way_stays_untouched_under_force() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.tree.remove("a");
    w.tree.special("a");
    let r = undo(&w, Selector::Last, true);
    assert!(matches!(outcome(&r, "a"), Outcome::Skipped(_)));
    assert_eq!(w.tree.node("a"), Some(Node::Special));
    assert_eq!(w.tree.read("b"), Some(b"b0".to_vec()));
}

#[test]
fn undo_of_a_mixture_without_type_swaps_round_trips() {
    let c = case(
        |w| {
            w.tree.write("src/main.rs", b"fn main(){}");
            w.tree.write("README.md", b"readme");
            w.tree.write_mode("run.sh", b"#!/bin/sh", 0o755);
            w.tree.symlink("link", b"README.md");
            w.tree.write("old/a.txt", b"a");
            w.tree.write("old/deep/b.txt", b"b");
            w.tree.write("mv.txt", b"moveme");
        },
        |w| {
            w.tree.write("src/main.rs", b"fn main(){ changed }");
            w.tree.write("new/c.txt", b"c");
            w.tree.write("new/deep/d.txt", b"d");
            w.tree.remove("old");
            w.tree.rename("mv.txt", "moved.txt");
            w.tree.chmod("run.sh", 0o644);
            w.tree.remove("link");
            w.tree.symlink("link", b"src/main.rs");
            w.tree.remove("README.md");
        },
    );
    assert_round_trip(&c);
    assert_eq!(undo_last(&c.w).error, None);
    assert_eq!(tree_state(&c.w), c.pre);
    assert_eq!(undo_last(&c.w).error, None);
    assert_eq!(tree_state(&c.w), c.post);
}

#[test]
fn only_a_blocked_item_means_nothing_runs() {
    let w = setup();
    w.tree.write("a", b"a0");
    baseline(&w);
    w.tree.write("a", b"a1");
    cp(&w);
    w.tree.remove("a");
    w.tree.special("a");
    w.events.clear();
    let n = jlen(&w);
    let r = undo(&w, Selector::Last, true);
    assert!(r.pre_undo.is_none() && r.result.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    assert_eq!(w.tree.node("a"), Some(Node::Special));
}

#[test]
fn symlinked_parent_blocks_the_item_and_nothing_is_written_through_it() {
    let w = setup();
    w.tree.write("d/f", b"old");
    w.tree.write("g", b"g0");
    baseline(&w);
    w.tree.write("d/f", b"new");
    w.tree.write("g", b"g1");
    cp(&w);
    // `d` is swapped for a symlink after the agent ran.
    w.tree.remove("d");
    w.tree.symlink("d", b"../outside");
    let before_paths = w.tree.paths();
    w.events.clear();

    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, "d/f").status, Status::Blocked(_)));

    let r = undo(&w, Selector::Last, true);
    assert!(matches!(outcome(&r, "d/f"), Outcome::Skipped(_)));
    assert_eq!(*outcome(&r, "g"), Outcome::Applied);
    assert_eq!(
        w.tree.node("d"),
        Some(Node::Symlink {
            target: b"../outside".to_vec()
        })
    );
    assert!(!w.tree.exists("d/f"));
    // The tree gained no path other than ones the plan lists.
    let plan_paths = item_paths(&r.plan);
    for path in w.tree.paths() {
        assert!(
            before_paths.contains(&path) || plan_paths.contains(&path),
            "unexpected path {path}"
        );
    }
    assert_eq!(
        applied_events(&w),
        vec![(CkptKind::Undo, r.result.unwrap().id, 1, 1)]
    );
}

#[test]
fn parent_replaced_by_a_regular_file_blocks_the_item() {
    let w = setup();
    w.tree.write("g", b"g0");
    baseline(&w);
    w.tree.write("x/y", b"agent");
    w.tree.write("g", b"g1");
    cp(&w);
    w.tree.remove("x");
    w.tree.write("x", b"now a file");
    let p = plan(&w, Selector::Last);
    assert!(matches!(item(&p, "x/y").status, Status::Blocked(_)));
    let r = undo(&w, Selector::Last, true);
    assert!(matches!(outcome(&r, "x/y"), Outcome::Skipped(_)));
    assert!(!w.tree.exists("x/y"));
    assert!(
        !matches!(w.tree.node("x"), Some(Node::Dir { .. })),
        "nothing may be created under a path that is a regular file"
    );
}

#[test]
fn applying_never_adds_paths_outside_the_plan() {
    let c = case(
        |w| {
            w.tree.write("src/a.rs", b"a");
            w.tree.write("old/b", b"b");
            w.tree.symlink("l", b"src/a.rs");
        },
        |w| {
            w.tree.write("src/a.rs", b"aa");
            w.tree.remove("old");
            w.tree.write("new/c", b"c");
        },
    );
    let before: Vec<String> = c.w.tree.paths();
    let r = undo_last(&c.w);
    let plan_paths = item_paths(&r.plan);
    for p in c.w.tree.paths() {
        assert!(
            before.contains(&p) || plan_paths.contains(&p),
            "unexpected path {p}"
        );
    }
}

#[test]
fn paths_that_could_escape_the_project_cannot_even_be_requested() {
    assert!(RelPath::new(b"../etc/passwd".to_vec()).is_err());
    assert!(RelPath::new(b"/etc/passwd".to_vec()).is_err());
    assert!(RelPath::new(b"a/../../b".to_vec()).is_err());
    assert!(RelPath::normalized(b"a/../b").is_err());
}

// --------------------------------------------------- races and bad blobs

#[test]
fn path_swapped_between_plan_and_apply_fails_that_item_and_stops() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.events.clear();
    // calls 1 and 2 plan a and b; call 3 is the re-validation of the first item.
    w.tree.set_observe_hook(|t, n| {
        if n == 3 {
            t.write("a", b"raced");
        }
    });

    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "a"), Outcome::Failed(_)));
    assert_eq!(*outcome(&r, "b"), Outcome::NotAttempted);
    assert_eq!(
        w.tree.read("a"),
        Some(b"raced".to_vec()),
        "swapped content kept"
    );
    assert_eq!(w.tree.read("b"), Some(b"b1".to_vec()));
    assert!(r.pre_undo.is_some());
    let res = r.result.clone().unwrap();
    assert_eq!(res.kind, CkptKind::Undo);
    assert_eq!(applied_events(&w), vec![(CkptKind::Undo, res.id, 0, 0)]);
    assert_eq!(kinds(&w).len(), 4);
    assert!(!w.locks.is_exclusively_held());
}

#[test]
fn race_on_the_second_item_keeps_the_first_applied() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    cp(&w);
    w.events.clear();
    w.tree.set_observe_hook(|t, n| {
        if n == 4 {
            t.write("b", b"raced");
        }
    });
    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert_eq!(*outcome(&r, "a"), Outcome::Applied);
    assert!(matches!(outcome(&r, "b"), Outcome::Failed(_)));
    assert!(r.error.as_deref().unwrap().contains('b'));
    assert_eq!(w.tree.read("a"), Some(b"a0".to_vec()));
    assert_eq!(w.tree.read("b"), Some(b"raced".to_vec()));
    let res = r.result.unwrap();
    assert_eq!(applied_events(&w), vec![(CkptKind::Undo, res.id, 1, 0)]);
    // The recorded Undo checkpoint captured the partial effect, so it is undoable.
    assert_eq!(
        res.counts.modified, 2,
        "a restored, b raced (both differ from pre-undo)"
    );
}

#[test]
fn path_swapped_for_a_directory_between_plan_and_apply_fails() {
    let w = simple();
    w.tree.set_observe_hook(|t, n| {
        if n == 2 {
            t.remove("a");
            t.mkdir("a", 0o755);
        }
    });
    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "a"), Outcome::Failed(_)));
    assert!(matches!(w.tree.node("a"), Some(Node::Dir { .. })));
    assert!(r.result.is_some());
}

#[test]
fn path_removed_between_plan_and_apply_fails_and_is_not_recreated() {
    let w = simple();
    w.tree.set_observe_hook(|t, n| {
        if n == 2 {
            t.remove("a");
        }
    });
    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "a"), Outcome::Failed(_)));
    assert!(!w.tree.exists("a"));
}

#[test]
fn parent_turned_into_a_symlink_after_planning_writes_nothing_through_it() {
    let w = setup();
    w.tree.write("d/f", b"old");
    baseline(&w);
    w.tree.write("d/f", b"new");
    cp(&w);
    w.tree.set_observe_hook(|t, n| {
        if n == 2 {
            t.remove("d");
            t.symlink("d", b"elsewhere");
        }
    });
    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "d/f"), Outcome::Failed(_)));
    assert!(matches!(w.tree.node("d"), Some(Node::Symlink { .. })));
    assert!(!w.tree.exists("d/f"));
}

#[test]
fn unrelated_change_during_apply_does_not_disturb_the_undo() {
    let w = simple();
    w.tree.set_observe_hook(|t, n| {
        if n == 2 {
            t.write("unrelated", b"z");
        }
    });
    let r = undo_last(&w);
    w.tree.clear_observe_hook();
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    assert_eq!(w.tree.read("unrelated"), Some(b"z".to_vec()));
}

#[test]
fn corrupt_blob_fails_with_integrity_and_does_not_modify_the_target() {
    let w = simple();
    w.blobs.corrupt(&sha256(b"v0"), b"tampered".to_vec());
    w.events.clear();
    let r = undo_last(&w);
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    assert!(
        r.error
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("corrupt")
    );
    match outcome(&r, "a") {
        Outcome::Failed(m) => assert!(m.to_lowercase().contains("corrupt"), "{m}"),
        o => panic!("unexpected {o:?}"),
    }
    assert!(r.pre_undo.is_some() && r.result.is_some());
    assert_eq!(r.result.as_ref().unwrap().counts.total(), 0);
}

#[test]
fn corrupt_blob_does_not_stop_earlier_items_and_skips_later_ones() {
    let w = setup();
    w.tree.write("a", b"a0");
    w.tree.write("b", b"b0");
    w.tree.write("c", b"c0");
    baseline(&w);
    w.tree.write("a", b"a1");
    w.tree.write("b", b"b1");
    w.tree.write("c", b"c1");
    cp(&w);
    w.blobs.corrupt(&sha256(b"b0"), b"junk".to_vec());
    let r = undo_last(&w);
    assert_eq!(*outcome(&r, "a"), Outcome::Applied);
    assert!(matches!(outcome(&r, "b"), Outcome::Failed(_)));
    assert_eq!(*outcome(&r, "c"), Outcome::NotAttempted);
    assert_eq!(w.tree.read("a"), Some(b"a0".to_vec()));
    assert_eq!(w.tree.read("b"), Some(b"b1".to_vec()));
    assert_eq!(w.tree.read("c"), Some(b"c1".to_vec()));
}

#[test]
fn missing_blob_fails_without_a_partial_write() {
    let w = setup();
    w.tree.write("a", b"content that will be deleted");
    w.tree.write("b", b"b0");
    baseline(&w);
    w.tree.remove("a");
    w.tree.write("b", b"b1");
    cp(&w);
    w.blobs
        .remove(&sha256(b"content that will be deleted"))
        .unwrap();
    w.events.clear();

    let r = undo_last(&w);
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "a"), Outcome::Failed(_)));
    assert_eq!(*outcome(&r, "b"), Outcome::NotAttempted);
    assert!(!w.tree.exists("a"), "no partial file left behind");
    assert_eq!(w.tree.read("b"), Some(b"b1".to_vec()));
    assert!(r.pre_undo.is_some());
    assert!(r.result.is_some());
    assert_eq!(applied_events(&w).len(), 1);
}

// ------------------------------------------------------------------- restore

/// baseline #1 (a = v0), #2 (a = v1), #3 (a = v2).
fn history() -> World {
    let w = setup();
    w.tree.write("a", b"v0");
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.write("a", b"v1");
    cp(&w);
    w.tree.write("a", b"v2");
    cp(&w);
    w.events.clear();
    w
}

#[test]
fn restore_file_from_an_older_checkpoint() {
    let w = history();
    let r = restore(&w, "a", 2, false);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
    assert_eq!(w.tree.read("keep"), Some(b"k".to_vec()));
    assert_eq!(r.outcomes, vec![Outcome::Applied]);
}

#[test]
fn restore_writes_pre_undo_and_restore_checkpoints_and_emits_restore_event() {
    let w = history();
    let r = restore(&w, "a", 2, false);
    assert_eq!(r.plan.kind, CkptKind::Restore);
    assert_eq!(r.plan.sources, vec![id(2)]);
    let pre = r.pre_undo.unwrap();
    let res = r.result.unwrap();
    assert_eq!(
        (pre.id, pre.kind, pre.reference),
        (id(4), CkptKind::PreUndo, Some(id(2)))
    );
    assert_eq!(
        (res.id, res.kind, res.reference),
        (id(5), CkptKind::Restore, Some(id(2)))
    );
    assert_eq!(
        kinds(&w),
        vec![
            CkptKind::Baseline,
            CkptKind::Manual,
            CkptKind::Manual,
            CkptKind::PreUndo,
            CkptKind::Restore
        ]
    );
    assert_eq!(applied_events(&w), vec![(CkptKind::Restore, res.id, 1, 0)]);
    assert_eq!(refused_events(&w), 0);
    assert_eq!(
        manifest_entry(&w, pre.id, "a").unwrap().digest().unwrap(),
        sha256(b"v2")
    );
    assert_eq!(
        manifest_entry(&w, res.id, "a").unwrap().digest().unwrap(),
        sha256(b"v1")
    );
}

#[test]
fn restore_recreates_a_file_deleted_since() {
    let w = history();
    w.tree.remove("keep");
    cp(&w);
    w.events.clear();
    let r = restore(&w, "keep", 1, false);
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("keep"), Some(b"k".to_vec()));
    assert_eq!(item(&r.plan, "keep").op, Op::Write);
}

#[test]
fn restore_of_a_path_absent_at_the_checkpoint_plans_a_delete() {
    let w = history();
    w.tree.write("late", b"created after the baseline");
    cp(&w);
    w.events.clear();
    let p = restore_plan(&w, "late", 1);
    assert_eq!(p.items.len(), 1);
    assert_eq!(item(&p, "late").op, Op::Delete);
    assert_eq!(item(&p, "late").target, None);
    let r = restore(&w, "late", 1, false);
    assert!(r.error.is_none());
    assert!(!w.tree.exists("late"));
    assert_eq!(applied_events(&w).len(), 1);
}

#[test]
fn restore_of_a_path_absent_both_then_and_now_does_nothing() {
    let w = history();
    let n = jlen(&w);
    let r = restore(&w, "never/existed", 1, false);
    assert_eq!(item(&r.plan, "never/existed").status, Status::AlreadyDone);
    assert!(r.pre_undo.is_none() && r.result.is_none() && r.refused.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
}

#[test]
fn restore_when_current_state_already_equals_the_target_writes_no_checkpoints() {
    let w = history();
    let n = jlen(&w);
    let r = restore(&w, "a", 3, false);
    assert_eq!(item(&r.plan, "a").status, Status::AlreadyDone);
    assert!(r.pre_undo.is_none() && r.result.is_none());
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    assert_eq!(w.snapshots.list().unwrap().len(), n);
}

#[test]
fn restore_of_a_directory_touches_only_entries_within_it() {
    let w = setup();
    for (p, c) in [
        ("d/a", "a0"),
        ("d/b", "b0"),
        ("d/sub/c", "c0"),
        ("d-x", "x0"),
        ("dd", "dd0"),
        ("e/x", "e0"),
    ] {
        w.tree.write(p, c.as_bytes());
    }
    baseline(&w);
    for (p, c) in [
        ("d/a", "a1"),
        ("d/b", "b1"),
        ("d/sub/c", "c1"),
        ("d-x", "x1"),
        ("dd", "dd1"),
        ("e/x", "e1"),
    ] {
        w.tree.write(p, c.as_bytes());
    }
    cp(&w);
    w.events.clear();

    let p = restore_plan(&w, "d", 1);
    assert_eq!(item_paths(&p), vec!["d", "d/a", "d/b", "d/sub", "d/sub/c"]);

    let r = restore(&w, "d", 1, false);
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("d/a"), Some(b"a0".to_vec()));
    assert_eq!(w.tree.read("d/b"), Some(b"b0".to_vec()));
    assert_eq!(w.tree.read("d/sub/c"), Some(b"c0".to_vec()));
    assert_eq!(w.tree.read("d-x"), Some(b"x1".to_vec()));
    assert_eq!(w.tree.read("dd"), Some(b"dd1".to_vec()));
    assert_eq!(w.tree.read("e/x"), Some(b"e1".to_vec()));
    assert_eq!((r.applied(), r.skipped()), (3, 2));
}

#[test]
fn restore_recreates_a_deleted_directory_subtree_with_modes() {
    let w = setup();
    w.tree.mkdir("d", 0o555);
    w.tree.write("d/a", b"a");
    w.tree.write("d/sub/b", b"b");
    baseline(&w);
    let pre = tree_state(&w);
    w.tree.remove("d");
    cp(&w);
    let r = restore(&w, "d", 1, false);
    assert!(r.error.is_none());
    assert_eq!(tree_state(&w), pre);
    assert_eq!(w.tree.mode("d"), Some(0o555));
}

#[test]
fn restore_path_is_normalized_by_relpath() {
    let w = history();
    let root = RelPath::normalized(b"./a//").unwrap();
    assert_eq!(root, rp("a"));
    let r = w
        .with_ports(|p| apply_restore(p, &root, id(2), false))
        .unwrap();
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v1".to_vec()));
}

#[test]
fn restore_from_an_unknown_checkpoint_is_a_usage_error() {
    let w = history();
    let n = jlen(&w);
    let e = w
        .with_ports(|p| apply_restore(p, &rp("a"), id(42), false))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    let e = w
        .with_ports(|p| plan_restore(p, &rp("a"), id(42)))
        .unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    assert_eq!(jlen(&w), n);
    assert!(w.events.events().is_empty());
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
}

#[test]
fn restore_from_a_pruned_checkpoint_is_refused() {
    let w = pruned_world(2);
    let n = jlen(&w);
    for from in [1, 2] {
        let e = w
            .with_ports(|p| apply_restore(p, &rp("a"), id(from), true))
            .unwrap_err();
        assert!(matches!(e, Error::Refused(_)), "{e:?}");
        let e = w
            .with_ports(|p| plan_restore(p, &rp("a"), id(from)))
            .unwrap_err();
        assert!(matches!(e, Error::Refused(_)), "{e:?}");
    }
    assert_eq!(jlen(&w), n);
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
    assert!(w.events.events().is_empty());
}

#[test]
fn restore_from_a_surviving_checkpoint_works_after_gc() {
    let w = pruned_world(2);
    // #3 holds a = v2 ; hand edit then restore it.
    w.tree.write("a", b"hand");
    let r = restore(&w, "a", 3, false);
    assert!(r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
}

#[test]
fn restore_plan_is_read_only() {
    let w = history();
    let tree = tree_state(&w);
    let n = jlen(&w);
    let snaps = w.snapshots.list().unwrap();
    let p = restore_plan(&w, "a", 1);
    assert_eq!(p.kind, CkptKind::Restore);
    assert_eq!(item(&p, "a").status, Status::Ready);
    assert_eq!(tree_state(&w), tree);
    assert_eq!(jlen(&w), n);
    assert_eq!(w.snapshots.list().unwrap(), snaps);
    assert!(w.events.events().is_empty());
}

#[test]
fn restore_overwrites_hand_edits_without_force_but_keeps_them_in_pre_undo() {
    let w = history();
    w.tree.write("a", b"hand");
    w.events.clear();
    let r = restore(&w, "a", 1, false);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    let pre = r.pre_undo.unwrap();
    assert_eq!(
        manifest_entry(&w, pre.id, "a").unwrap().digest().unwrap(),
        sha256(b"hand")
    );
    assert_eq!(refused_events(&w), 0);
}

#[test]
fn restore_is_itself_undoable() {
    let w = history();
    restore(&w, "a", 1, false);
    assert_eq!(w.tree.read("a"), Some(b"v0".to_vec()));
    let p = plan(&w, Selector::Last);
    assert_eq!(p.sources, vec![id(5)]);
    let r = undo_last(&w);
    assert!(r.refused.is_none() && r.error.is_none());
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
}

#[test]
fn restore_never_restores_sensitive_files() {
    let w = setup();
    w.tree.write(".env", b"KEY=old");
    w.tree.write("app", b"v0");
    baseline(&w);
    w.tree.write(".env", b"KEY=new");
    w.tree.write("app", b"v1");
    cp(&w);
    let rr = restore(&w, ".env", 1, false);
    assert!(matches!(
        item(&rr.plan, ".env").status,
        Status::NotRestorable(_)
    ));
    assert_eq!(w.tree.read(".env"), Some(b"KEY=new".to_vec()));
    assert!(rr.result.is_none());
}

#[test]
fn restore_of_a_too_large_file_is_not_restorable() {
    let w = setup_with_cap(16);
    w.tree.write("big.bin", &big());
    baseline(&w);
    w.tree.write("big.bin", b"tiny");
    cp(&w);
    let r = restore(&w, "big.bin", 1, true);
    assert!(matches!(
        item(&r.plan, "big.bin").status,
        Status::NotRestorable(_)
    ));
    assert_eq!(w.tree.read("big.bin"), Some(b"tiny".to_vec()));
}

#[test]
fn restore_of_a_file_over_a_directory_with_untracked_children_is_skipped() {
    let w = setup();
    w.tree.write("x", b"was a file");
    baseline(&w);
    w.tree.remove("x");
    w.tree.write("x/y", b"mine");
    cp(&w);
    w.events.clear();
    let r = restore(&w, "x", 1, false);
    assert!(matches!(outcome(&r, "x"), Outcome::Skipped(_)));
    assert_eq!(w.tree.read("x/y"), Some(b"mine".to_vec()));
    assert_eq!(applied_events(&w).len(), 1);
}

#[test]
fn restore_of_a_directory_absent_at_the_checkpoint_is_skipped_when_not_empty() {
    let w = setup();
    w.tree.write("keep", b"k");
    baseline(&w);
    w.tree.write("late/file", b"f");
    cp(&w);
    w.events.clear();
    let p = restore_plan(&w, "late", 1);
    assert_eq!(item(&p, "late").op, Op::Rmdir);
    let r = restore(&w, "late", 1, false);
    assert!(matches!(outcome(&r, "late"), Outcome::Skipped(_)));
    assert_eq!(w.tree.read("late/file"), Some(b"f".to_vec()));
}

#[test]
fn restore_lock_contention_fails_with_locked_and_changes_nothing() {
    let w = history();
    let n = jlen(&w);
    let guard = w.locks.exclusive().unwrap();
    let e = w
        .with_ports(|p| apply_restore(p, &rp("a"), id(1), false))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    assert_eq!(e.exit_code(), 4);
    let e = w
        .with_ports(|p| plan_restore(p, &rp("a"), id(1)))
        .unwrap_err();
    assert!(matches!(e, Error::Locked(_)), "{e:?}");
    drop(guard);
    assert_eq!(jlen(&w), n);
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
    assert!(w.events.events().is_empty());
}

#[test]
fn restore_race_stops_with_an_error_and_still_records_the_result() {
    let w = history();
    w.tree.set_observe_hook(|t, n| {
        if n == 2 {
            t.write("a", b"raced");
        }
    });
    let r = restore(&w, "a", 1, false);
    w.tree.clear_observe_hook();
    assert!(r.error.is_some());
    assert!(matches!(outcome(&r, "a"), Outcome::Failed(_)));
    assert_eq!(w.tree.read("a"), Some(b"raced".to_vec()));
    assert_eq!(r.result.unwrap().kind, CkptKind::Restore);
    assert!(r.pre_undo.is_some());
}

#[test]
fn restore_with_a_missing_snapshot_is_an_integrity_error() {
    let w = history();
    w.snapshots.remove(id(2)).unwrap();
    let e = w
        .with_ports(|p| apply_restore(p, &rp("a"), id(2), false))
        .unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
    assert_eq!(w.tree.read("a"), Some(b"v2".to_vec()));
}

#[test]
fn restore_kinds_in_listing_are_distinct_from_undo() {
    let w = history();
    restore(&w, "a", 1, false);
    undo_last(&w);
    let ks = kinds(&w);
    assert_eq!(ks.iter().filter(|k| **k == CkptKind::Restore).count(), 1);
    assert_eq!(ks.iter().filter(|k| **k == CkptKind::Undo).count(), 1);
    assert_eq!(ks.iter().filter(|k| **k == CkptKind::PreUndo).count(), 2);
}
