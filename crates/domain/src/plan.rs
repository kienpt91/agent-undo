//! Undo and restore planning: the rules that decide, for every affected path,
//! what to do, whether it is safe, and in which order to do it.
//!
//! A plan item has a `target` (the state to restore), an optional `expected`
//! state (what the recorded change left behind, used for conflict detection) and
//! the `current` state observed on disk. [`decide`] turns those three into an
//! operation and a status. Nothing here touches the filesystem.

use crate::change::NetChange;
use crate::entry::{Entry, Kind};
use crate::journal::{CheckpointId, CkptKind};
use crate::path::RelPath;
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    None,
    Delete,
    Rmdir,
    Mkdir,
    Write,
    Symlink,
    Chmod,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::None => "none",
            Op::Delete => "delete",
            Op::Rmdir => "rmdir",
            Op::Mkdir => "mkdir",
            Op::Write => "write",
            Op::Symlink => "symlink",
            Op::Chmod => "chmod",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ready,
    /// The path already has the target state.
    AlreadyDone,
    /// Applying needs `--force` (modified since the checkpoint, or unsaved data would be lost).
    NeedsForce(String),
    /// Cannot be restored by design (sensitive, too large, special).
    NotRestorable(String),
    /// Refused for safety (symlinked parent, special file in the way).
    Blocked(String),
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ready => "ready",
            Status::AlreadyDone => "already-done",
            Status::NeedsForce(_) => "conflict",
            Status::NotRestorable(_) => "not-restorable",
            Status::Blocked(_) => "blocked",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Status::NeedsForce(r) | Status::NotRestorable(r) | Status::Blocked(r) => Some(r),
            _ => None,
        }
    }

    /// Whether the item is executed given the `force` flag.
    pub fn runnable(&self, force: bool) -> bool {
        match self {
            Status::Ready => true,
            Status::NeedsForce(_) => force,
            _ => false,
        }
    }
}

/// What was observed for a path when the plan was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The state on disk (`None` = absent).
    State(Option<Entry>),
    /// The path could not be inspected safely (for example a symlinked parent).
    Unsafe(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    pub path: RelPath,
    pub target: Option<Entry>,
    /// `Some(state)` when a recorded change defines what the path should look like now.
    pub expected: Option<Option<Entry>>,
    pub current: Option<Entry>,
    pub op: Op,
    /// The current object is of a different class (dir vs non-dir) and must be removed first.
    pub replace: bool,
    pub status: Status,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub kind: CkptKind,
    pub description: String,
    pub sources: Vec<CheckpointId>,
    pub items: Vec<PlanItem>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanCounts {
    pub ready: u64,
    pub already_done: u64,
    pub conflicts: u64,
    pub not_restorable: u64,
    pub blocked: u64,
}

impl Plan {
    pub fn counts(&self) -> PlanCounts {
        let mut c = PlanCounts::default();
        for i in &self.items {
            match i.status {
                Status::Ready => c.ready += 1,
                Status::AlreadyDone => c.already_done += 1,
                Status::NeedsForce(_) => c.conflicts += 1,
                Status::NotRestorable(_) => c.not_restorable += 1,
                Status::Blocked(_) => c.blocked += 1,
            }
        }
        c
    }

    /// Whether applying would change anything (with or without force).
    pub fn has_work(&self) -> bool {
        self.items
            .iter()
            .any(|i| matches!(i.status, Status::Ready | Status::NeedsForce(_)))
    }

    /// Whether any item needs `--force`.
    pub fn has_conflicts(&self) -> bool {
        self.items
            .iter()
            .any(|i| matches!(i.status, Status::NeedsForce(_)))
    }
}

/// Whether two observed states are semantically equal (both absent counts as equal).
pub fn same_state(a: &Option<Entry>, b: &Option<Entry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.semantic_eq(y),
        _ => false,
    }
}

fn kind_name(e: &Option<Entry>) -> &'static str {
    e.as_ref().map_or("absent", |e| e.kind().as_str())
}

/// Decides the operation and status for one path.
pub fn decide(
    target: &Option<Entry>,
    expected: Option<&Option<Entry>>,
    current: &Option<Entry>,
) -> (Op, bool, Status) {
    let sens = |e: &Option<Entry>| e.as_ref().is_some_and(|e| e.kind() == Kind::Sensitive);
    if sens(target) || sens(current) || expected.is_some_and(sens) {
        return (
            Op::None,
            false,
            Status::NotRestorable(
                "sensitive file: not restorable by design (content is never stored)".into(),
            ),
        );
    }
    if let Some(t) = target
        && matches!(t.kind(), Kind::TooLarge | Kind::Special | Kind::Unreadable)
    {
        return (
            Op::None,
            false,
            Status::NotRestorable(format!(
                "{} file: content was not recorded",
                t.kind().as_str()
            )),
        );
    }
    if let Some(c) = current
        && matches!(c.kind(), Kind::Special | Kind::Unreadable)
    {
        return (
            Op::None,
            false,
            Status::Blocked(format!(
                "a {} file is in the way; it is never touched",
                c.kind().as_str()
            )),
        );
    }
    if same_state(target, current) {
        return (Op::None, false, Status::AlreadyDone);
    }
    let mut reasons: Vec<String> = Vec::new();
    if let Some(exp) = expected
        && !same_state(exp, current)
    {
        reasons.push(format!(
            "modified since the checkpoint (expected {}, found {})",
            kind_name(exp),
            kind_name(current)
        ));
    }
    if current.as_ref().is_some_and(|c| c.kind() == Kind::TooLarge) {
        reasons.push("would overwrite a too-large file whose content cannot be saved".into());
    }
    let cur_is_dir = current.as_ref().is_some_and(|c| c.kind() == Kind::Dir);
    let (op, replace) = match target {
        None => {
            if cur_is_dir {
                (Op::Rmdir, false)
            } else {
                (Op::Delete, false)
            }
        }
        Some(t) => match t.kind() {
            Kind::Dir => match current {
                None => (Op::Mkdir, false),
                Some(c) if c.kind() == Kind::Dir => (Op::Chmod, false),
                Some(_) => (Op::Mkdir, true),
            },
            Kind::Symlink => (Op::Symlink, cur_is_dir),
            _ => match current {
                Some(c) if c.kind() == Kind::File && c.same_content(t) => (Op::Chmod, false),
                _ => (Op::Write, cur_is_dir),
            },
        },
    };
    let status = if reasons.is_empty() {
        Status::Ready
    } else {
        Status::NeedsForce(reasons.join("; "))
    };
    (op, replace, status)
}

/// Builds a plan item from the three states (or an unsafe observation).
pub fn build_item(
    path: RelPath,
    target: Option<Entry>,
    expected: Option<Option<Entry>>,
    observed: Observation,
) -> PlanItem {
    match observed {
        Observation::Unsafe(why) => PlanItem {
            path,
            target,
            expected,
            current: None,
            op: Op::None,
            replace: false,
            status: Status::Blocked(why),
        },
        Observation::State(current) => {
            let (op, replace, status) = decide(&target, expected.as_ref(), &current);
            PlanItem {
                path,
                target,
                expected,
                current,
                op,
                replace,
                status,
            }
        }
    }
}

/// Plan input for undoing: restore `before`, expect `after`.
pub fn undo_inputs(net: Vec<NetChange>) -> Vec<(RelPath, Option<Entry>, Option<Option<Entry>>)> {
    net.into_iter()
        .map(|n| (n.path, n.before, Some(n.after)))
        .collect()
}

/// Plan input for restoring entries of a manifest that lie within `root`
/// (`root` itself and everything below it). If the manifest has nothing there,
/// the single path is planned for removal.
pub fn restore_inputs(
    root: &RelPath,
    entries: impl IntoIterator<Item = (RelPath, Entry)>,
) -> Vec<(RelPath, Option<Entry>, Option<Option<Entry>>)> {
    let mut out: Vec<_> = entries
        .into_iter()
        .filter(|(p, _)| p.is_within(root))
        .map(|(p, e)| (p, Some(e), None))
        .collect();
    if out.is_empty() {
        out.push((root.clone(), None, None));
    }
    out
}

fn phase(op: Op) -> u8 {
    match op {
        Op::Delete => 1,
        Op::Rmdir => 2,
        Op::Mkdir => 3,
        Op::Write | Op::Symlink => 4,
        Op::Chmod | Op::None => 5,
    }
}

/// Order in which plan items are executed: deletions, then directory removals
/// (deepest first), directory creations (shallowest first), file and symlink
/// writes, finally permission changes (deepest first).
pub fn execution_order(items: &[PlanItem]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by(|&a, &b| {
        let (ia, ib) = match (items.get(a), items.get(b)) {
            (Some(x), Some(y)) => (x, y),
            _ => return Ordering::Equal,
        };
        let (pa, pb) = (phase(ia.op), phase(ib.op));
        pa.cmp(&pb).then_with(|| match pa {
            2 | 5 => ib
                .path
                .depth()
                .cmp(&ia.path.depth())
                .then_with(|| ia.path.cmp(&ib.path)),
            _ => ia.path.cmp(&ib.path),
        })
    });
    order
}

/// Directory modes are applied after everything else, deepest first, so a
/// restrictive mode never blocks the creation of children.
pub fn sort_dir_modes(modes: &mut [(RelPath, u32)]) {
    modes.sort_by(|a, b| b.0.depth().cmp(&a.0.depth()).then_with(|| a.0.cmp(&b.0)));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Skipped(String),
    Failed(String),
    NotAttempted,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Applied => "applied",
            Outcome::Skipped(_) => "skipped",
            Outcome::Failed(_) => "failed",
            Outcome::NotAttempted => "not-attempted",
        }
    }
}

#[cfg(test)]
mod tests {
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
        }
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
}
