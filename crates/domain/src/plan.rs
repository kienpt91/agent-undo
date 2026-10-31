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
    /// An ancestor exists but is not a directory (so the path cannot exist now).
    /// The plan may still be executable if another item replaces that ancestor
    /// with a directory first.
    Obstructed(String),
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
    /// Set while an ancestor of this path is a non-directory; resolved by
    /// [`resolve_obstructions`].
    pub obstruction: Option<String>,
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
            obstruction: None,
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
                obstruction: None,
            }
        }
        Observation::Obstructed(why) => {
            let (op, replace, status) = decide(&target, expected.as_ref(), &None);
            PlanItem {
                path,
                target,
                expected,
                current: None,
                op,
                replace,
                status,
                obstruction: Some(why),
            }
        }
    }
}

/// Clears obstructions that another item resolves (an ancestor that is a file
/// now but is restored as a directory, replacing the file first) and blocks the
/// rest. Call once after all items are built.
pub fn resolve_obstructions(items: &mut [PlanItem]) {
    let replaced: std::collections::HashSet<RelPath> = items
        .iter()
        .filter(|i| i.op == Op::Mkdir && i.replace && i.status.runnable(true))
        .map(|i| i.path.clone())
        .collect();
    for item in items.iter_mut() {
        let Some(why) = item.obstruction.take() else {
            continue;
        };
        let mut anc = item.path.parent();
        let mut fixed = false;
        while let Some(a) = anc {
            if replaced.contains(&a) {
                fixed = true;
                break;
            }
            anc = a.parent();
        }
        if !fixed {
            item.op = Op::None;
            item.replace = false;
            item.status = Status::Blocked(why);
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
mod tests;
