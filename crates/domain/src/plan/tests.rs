use super::*;
use crate::hash::sha256;

fn p(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

fn file(content: &[u8], mode: u32) -> Option<Entry> {
    Some(
        Entry::hashed(
            Kind::File,
            &sha256(content),
            mode,
            content.len() as u64,
            1,
            1,
        )
        .unwrap(),
    )
}

fn hashed(kind: Kind) -> Option<Entry> {
    Some(Entry::hashed(kind, &sha256(b"s"), 0o600, 1, 1, 1).unwrap())
}

fn dir(mode: u32) -> Option<Entry> {
    Some(Entry::dir(mode, 1, 1))
}

fn link(t: &[u8]) -> Option<Entry> {
    Some(Entry::symlink(t.to_vec(), 1, 1).unwrap())
}

#[test]
fn undo_of_modification_writes_old_content() {
    let (op, replace, st) = decide(
        &file(b"old", 0o644),
        Some(&file(b"new", 0o644)),
        &file(b"new", 0o644),
    );
    assert_eq!((op, replace, st), (Op::Write, false, Status::Ready));
}

#[test]
fn undo_of_creation_deletes() {
    let (op, _, st) = decide(&None, Some(&file(b"new", 0o644)), &file(b"new", 0o644));
    assert_eq!((op, st), (Op::Delete, Status::Ready));
}

#[test]
fn undo_of_deletion_recreates() {
    let (op, _, st) = decide(&file(b"old", 0o644), Some(&None), &None);
    assert_eq!((op, st), (Op::Write, Status::Ready));
}

#[test]
fn already_at_target_is_a_no_op_even_if_unexpected() {
    let (op, _, st) = decide(
        &file(b"old", 0o644),
        Some(&file(b"new", 0o644)),
        &file(b"old", 0o644),
    );
    assert_eq!((op, st), (Op::None, Status::AlreadyDone));
    let (op, _, st) = decide(&None, Some(&file(b"x", 0o644)), &None);
    assert_eq!((op, st), (Op::None, Status::AlreadyDone));
}

#[test]
fn modification_after_the_checkpoint_is_a_conflict() {
    let (op, _, st) = decide(
        &file(b"old", 0o644),
        Some(&file(b"new", 0o644)),
        &file(b"edited by hand", 0o644),
    );
    assert_eq!(op, Op::Write);
    assert!(matches!(&st, Status::NeedsForce(r) if r.contains("modified since")));
    assert!(!st.runnable(false));
    assert!(st.runnable(true));
}

#[test]
fn deletion_after_the_checkpoint_is_a_conflict() {
    let (_, _, st) = decide(&file(b"old", 0o644), Some(&file(b"new", 0o644)), &None);
    assert!(matches!(st, Status::NeedsForce(_)));
}

#[test]
fn mode_only_difference_is_a_conflict_for_expectation_and_chmod_for_target() {
    let (op, _, st) = decide(
        &file(b"x", 0o644),
        Some(&file(b"x", 0o755)),
        &file(b"x", 0o755),
    );
    assert_eq!((op, st), (Op::Chmod, Status::Ready));
    let (_, _, st) = decide(
        &file(b"x", 0o644),
        Some(&file(b"x", 0o755)),
        &file(b"x", 0o700),
    );
    assert!(matches!(st, Status::NeedsForce(_)));
}

#[test]
fn restore_has_no_expectation_so_never_conflicts() {
    let (op, _, st) = decide(&file(b"old", 0o644), None, &file(b"anything", 0o600));
    assert_eq!((op, st), (Op::Write, Status::Ready));
}

#[test]
fn sensitive_anywhere_is_not_restorable() {
    let s = hashed(Kind::Sensitive);
    for (t, e, c) in [
        (s.clone(), Some(None), None),
        (None, Some(s.clone()), s.clone()),
        (file(b"x", 0o644), None, s.clone()),
    ] {
        let (op, _, st) = decide(&t, e.as_ref(), &c);
        assert_eq!(op, Op::None);
        assert!(
            matches!(&st, Status::NotRestorable(r) if r.contains("by design")),
            "{st:?}"
        );
        assert!(
            !st.runnable(true),
            "force never overrides by-design refusals"
        );
    }
}

#[test]
fn too_large_target_is_not_restorable_and_current_too_large_needs_force() {
    let (_, _, st) = decide(&hashed(Kind::TooLarge), Some(&None), &None);
    assert!(matches!(st, Status::NotRestorable(_)));
    let (op, _, st) = decide(
        &file(b"old", 0o644),
        Some(&hashed(Kind::TooLarge)),
        &hashed(Kind::TooLarge),
    );
    assert_eq!(op, Op::Write);
    assert!(matches!(&st, Status::NeedsForce(r) if r.contains("cannot be saved")));
    let (op, _, st) = decide(
        &None,
        Some(&hashed(Kind::TooLarge)),
        &hashed(Kind::TooLarge),
    );
    assert_eq!(op, Op::Delete);
    assert!(matches!(st, Status::NeedsForce(_)));
}

#[test]
fn special_and_unreadable_objects_block() {
    let special = Some(Entry::special(0o600, 1, 1));
    let unreadable = Some(Entry::unreadable(0, 1, 1, 1));
    for cur in [special.clone(), unreadable.clone()] {
        let (op, _, st) = decide(&file(b"x", 0o644), Some(&cur), &cur);
        assert_eq!(op, Op::None);
        assert!(matches!(st, Status::Blocked(_)));
        assert!(!st.runnable(true));
    }
    let (_, _, st) = decide(&special, Some(&None), &None);
    assert!(
        matches!(st, Status::NotRestorable(_)),
        "never recreate special files"
    );
}

#[test]
fn directories() {
    assert_eq!(decide(&dir(0o755), Some(&None), &None).0, Op::Mkdir);
    assert_eq!(decide(&None, Some(&dir(0o755)), &dir(0o755)).0, Op::Rmdir);
    assert_eq!(
        decide(&dir(0o700), Some(&dir(0o755)), &dir(0o755)).0,
        Op::Chmod
    );
    // a file is where the directory should be: remove it, then create the dir
    let (op, replace, _) = decide(&dir(0o755), None, &file(b"x", 0o644));
    assert_eq!((op, replace), (Op::Mkdir, true));
    // a directory is where a file should be
    let (op, replace, _) = decide(&file(b"x", 0o644), None, &dir(0o755));
    assert_eq!((op, replace), (Op::Write, true));
}

#[test]
fn symlinks() {
    assert_eq!(decide(&link(b"a"), Some(&None), &None).0, Op::Symlink);
    assert_eq!(
        decide(&link(b"a"), Some(&link(b"b")), &link(b"b")).0,
        Op::Symlink
    );
    let (op, replace, _) = decide(&link(b"a"), None, &dir(0o755));
    assert_eq!((op, replace), (Op::Symlink, true));
    assert_eq!(decide(&None, Some(&link(b"b")), &link(b"b")).0, Op::Delete);
    let (_, _, st) = decide(&link(b"a"), None, &link(b"a"));
    assert_eq!(st, Status::AlreadyDone);
}

#[test]
fn type_change_file_to_symlink() {
    let (op, replace, st) = decide(&file(b"x", 0o644), Some(&link(b"t")), &link(b"t"));
    assert_eq!((op, replace, st), (Op::Write, false, Status::Ready));
}

#[test]
fn unsafe_observation_blocks_the_item() {
    let it = build_item(
        p("a/b"),
        file(b"x", 0o644),
        None,
        Observation::Unsafe("symlinked parent".into()),
    );
    assert_eq!(it.op, Op::None);
    assert!(matches!(&it.status, Status::Blocked(r) if r.contains("symlinked")));
    let ok = build_item(p("a/b"), file(b"x", 0o644), None, Observation::State(None));
    assert_eq!(ok.op, Op::Write);
    assert_eq!(ok.status, Status::Ready);
}

#[test]
fn plan_counts_and_flags() {
    let items = vec![
        build_item(p("a"), file(b"x", 0o644), None, Observation::State(None)),
        build_item(
            p("b"),
            file(b"x", 0o644),
            None,
            Observation::State(file(b"x", 0o644)),
        ),
        build_item(
            p("c"),
            file(b"x", 0o644),
            Some(file(b"y", 0o644)),
            Observation::State(file(b"z", 0o644)),
        ),
        build_item(
            p("d"),
            hashed(Kind::Sensitive),
            None,
            Observation::State(None),
        ),
        build_item(p("e"), None, None, Observation::Unsafe("x".into())),
    ];
    let plan = Plan {
        kind: CkptKind::Undo,
        description: String::new(),
        sources: vec![],
        items,
    };
    assert_eq!(
        plan.counts(),
        PlanCounts {
            ready: 1,
            already_done: 1,
            conflicts: 1,
            not_restorable: 1,
            blocked: 1
        }
    );
    assert!(plan.has_work());
    assert!(plan.has_conflicts());
    let empty = Plan {
        kind: CkptKind::Undo,
        description: String::new(),
        sources: vec![],
        items: vec![],
    };
    assert!(!empty.has_work() && !empty.has_conflicts());
}

#[test]
fn inputs_for_undo_and_restore() {
    let net = vec![NetChange {
        path: p("a"),
        before: file(b"1", 0o644),
        after: None,
    }];
    let inputs = undo_inputs(net);
    assert_eq!(inputs[0].0, p("a"));
    assert_eq!(inputs[0].2, Some(None));

    let entries = vec![
        (p("d"), Entry::dir(0o755, 1, 1)),
        (p("d/x"), file(b"x", 0o644).unwrap()),
        (p("dd"), file(b"y", 0o644).unwrap()),
    ];
    let got = restore_inputs(&p("d"), entries.clone());
    assert_eq!(
        got.iter().map(|g| g.0.display()).collect::<Vec<_>>(),
        vec!["d", "d/x"]
    );
    assert!(got.iter().all(|g| g.2.is_none()));
    let none = restore_inputs(&p("zzz"), entries);
    assert_eq!(none.len(), 1);
    assert!(
        none[0].1.is_none(),
        "absent at the checkpoint means removal"
    );
}

fn item(path: &str, op: Op) -> PlanItem {
    PlanItem {
        path: p(path),
        target: None,
        expected: None,
        current: None,
        op,
        replace: false,
        status: Status::Ready,
        obstruction: None,
    }
}

#[test]
fn obstructed_item_is_planned_as_if_absent_until_resolved() {
    let it = build_item(
        p("d/x"),
        file(b"x", 0o644),
        None,
        Observation::Obstructed("a parent is a file".into()),
    );
    assert_eq!(it.op, Op::Write);
    assert_eq!(it.current, None);
    assert_eq!(it.obstruction.as_deref(), Some("a parent is a file"));
}

#[test]
fn obstruction_is_cleared_when_an_ancestor_directory_replaces_the_file() {
    let mut items = vec![
        build_item(
            p("d"),
            dir(0o755),
            None,
            Observation::State(file(b"in the way", 0o644)),
        ),
        build_item(
            p("d/x"),
            file(b"x", 0o644),
            None,
            Observation::Obstructed("parent is a file".into()),
        ),
        build_item(
            p("d/sub/y"),
            file(b"y", 0o644),
            None,
            Observation::Obstructed("parent is a file".into()),
        ),
    ];
    assert!(items[0].replace && items[0].op == Op::Mkdir);
    resolve_obstructions(&mut items);
    assert!(items.iter().all(|i| i.obstruction.is_none()));
    assert_eq!(items[1].status, Status::Ready);
    assert_eq!(
        items[2].status,
        Status::Ready,
        "deeper descendants are covered too"
    );
}

#[test]
fn unresolved_obstruction_blocks_the_item() {
    let mut items = vec![build_item(
        p("f/x"),
        file(b"x", 0o644),
        None,
        Observation::Obstructed("parent is a file".into()),
    )];
    resolve_obstructions(&mut items);
    assert!(matches!(&items[0].status, Status::Blocked(r) if r.contains("parent is a file")));
    assert_eq!(items[0].op, Op::None);
}

#[test]
fn a_non_replacing_ancestor_does_not_resolve_the_obstruction() {
    let mut items = vec![
        build_item(p("d"), dir(0o755), None, Observation::State(None)),
        build_item(
            p("d/x"),
            file(b"x", 0o644),
            None,
            Observation::Obstructed("why".into()),
        ),
    ];
    resolve_obstructions(&mut items);
    assert!(matches!(items[1].status, Status::Blocked(_)));
}

#[test]
fn execution_order_phases() {
    let items = vec![
        item("w", Op::Write),
        item("d/sub", Op::Mkdir),
        item("d", Op::Mkdir),
        item("rm/a/b", Op::Rmdir),
        item("rm", Op::Rmdir),
        item("del", Op::Delete),
        item("c", Op::Chmod),
        item("deep/er/c", Op::Chmod),
        item("l", Op::Symlink),
    ];
    let order: Vec<String> = execution_order(&items)
        .iter()
        .map(|&i| items[i].path.display())
        .collect();
    assert_eq!(
        order,
        vec![
            "del",
            "rm/a/b",
            "rm",
            "d",
            "d/sub",
            "l",
            "w",
            "deep/er/c",
            "c"
        ]
    );
}

#[test]
fn dir_modes_apply_deepest_first() {
    let mut v = vec![
        (p("a"), 0o700),
        (p("a/b/c"), 0o500),
        (p("a/b"), 0o755),
        (p("z"), 0o700),
    ];
    sort_dir_modes(&mut v);
    assert_eq!(
        v.iter().map(|x| x.0.display()).collect::<Vec<_>>(),
        vec!["a/b/c", "a/b", "a", "z"]
    );
}

#[test]
fn status_and_outcome_names() {
    assert_eq!(Status::Ready.as_str(), "ready");
    assert_eq!(Status::AlreadyDone.as_str(), "already-done");
    assert_eq!(Status::NeedsForce("x".into()).as_str(), "conflict");
    assert_eq!(Status::NotRestorable("x".into()).reason(), Some("x"));
    assert_eq!(Status::Ready.reason(), None);
    assert_eq!(Outcome::Applied.as_str(), "applied");
    assert_eq!(Outcome::Skipped("x".into()).as_str(), "skipped");
    assert_eq!(Outcome::Failed("x".into()).as_str(), "failed");
    assert_eq!(Outcome::NotAttempted.as_str(), "not-attempted");
    assert_eq!(Op::Chmod.as_str(), "chmod");
    assert_eq!(Op::None.as_str(), "none");
    for (op, name) in [
        (Op::Delete, "delete"),
        (Op::Rmdir, "rmdir"),
        (Op::Mkdir, "mkdir"),
        (Op::Write, "write"),
        (Op::Symlink, "symlink"),
    ] {
        assert_eq!(op.as_str(), name);
    }
}
